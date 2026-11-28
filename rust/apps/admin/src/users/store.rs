//! 利用者の状態の読み出し（Postgres の `user_state_current`・`user_state_event`）。Python の
//! `services/user_state_service.py` の `list_recent_user_states`・`count_user_states`・`get_user_state_detail`・
//! `_apply_state_filter`・`_row_to_state_payload`・`_event_to_payload`・`_safe_json_loads`・`_try_db_self_heal` と、
//! `services/user_state_db.py` の `ensure_user_state_db`。
//!
//! - 表が無ければ作る（最初の 1 回。形は sycs-core の [`sycs_core::user_state::DDL`]。Bot と同じ）。作れなければ
//!   呼んだ側へそのまま返す（500）。Python も `ensure_user_state_db` は try の外
//! - 読み出しが SQLSTATE 42 系（表が無いなど）で落ちたら、表を作り直して 1 回だけやり直す。ほかの失敗と 2 回目の
//!   失敗は、ログに残して空（一覧は `[]`、件数は 0、詳細は `None`）
//! - 絞り込み（[`filter_of`]。`_apply_state_filter`）: 前後の空白を落として空なら絞らない。全部が数字
//!   （`str.isdigit()`）なら `user_id = int(q)` か `CAST(user_id AS VARCHAR) LIKE 'q%'`、ほかは `lower(username)` か
//!   `lower(display_name)` が `'%' || q.lower() || '%'` に当たる（`%`・`_`・`\` は逃がさない。Python と同じ）
//! - 並び: `last_event_at DESC NULLS LAST, updated_at DESC NULLS LAST, id DESC`。件数は 1〜200、飛ばす数は 0 以上に
//!   丸める。履歴は `event_at DESC, id DESC` で 1〜500 件
//! - JSON の列（`roles_json`・`abilities_json`・`payload_json`）は、空か読めなければ既定（`[]`・`{}`・`{}`）。
//!   `payload_json` は辞書でなければ `{}`
//!
//! 突き合わせは基準 `users_state_db`（空の Postgres に同じ行を入れ、Python の 3 つの関数の答えを書いたもの）。
//!
//! Python と違うところ:
//!
//! - Python は Postgres の bigint に収まらない数（サーバー・利用者の ID、`int(q)`）もそのまま渡し、asyncpg が断って
//!   ログを残し空を返す。Rust は問い合わせる前に同じ答え（空）にする（ログも残す）。飛ばす数も同じ
//! - `str.isdigit()` が真なのに `int()` が読めない文字（上付きの ² など）は、Python は例外で空。Rust も空
//! - 検索語の小文字は Rust の `to_lowercase`（Python の `str.lower` と同じ規則。Unicode の版だけが違いうる）
//! - JSON の列の読み方は serde_json。Python の `json.loads` が読めて serde_json が読めないもの（`NaN`・`Infinity`・
//!   単独のサロゲート・128 段より深い入れ子）は、読めない扱い（既定の値）。Python はそれを答えに書こうとして 500 に
//!   なるか、読めたまま返す。64 ビットを超える整数は小数になる（Python は整数のまま）。どれも Bot が書かない値
//! - 失敗の型の名前（インシデントの見出し）は、sqlx の失敗から近いものにする（[`crash_of`]）

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use sycs_core::user_state::{DDL, is_repairable};
use tracing::{error, info, warn};

use crate::errors::Crash;
use crate::python;
use crate::users::{
    Detail, EventRow, MAX_EVENT_LIMIT, MAX_LIMIT, StateRow, StoreFuture, UserStates,
};

/// 最新状態の行を読む列（時刻は UNIX マイクロ秒の整数で受ける。Bot の `user_state_sync` と同じ読み方）。
macro_rules! select_current {
    ($($part:literal),+ $(,)?) => {
        concat!(
            "SELECT guild_id, user_id, username, display_name, avatar_url, status, \
             is_in_guild, is_banned, is_timed_out, \
             (EXTRACT(EPOCH FROM timed_out_until) * 1000000)::bigint, \
             roles_json, abilities_json, last_event_type, \
             (EXTRACT(EPOCH FROM last_event_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM first_seen_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM last_joined_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM last_left_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint FROM user_state_current ",
            $($part),+
        )
    };
}

/// 一覧（絞らない）。`$1` サーバー、`$2` 件数、`$3` 飛ばす数。
const LIST_ALL: &str = select_current!(
    "WHERE guild_id = $1 ",
    "ORDER BY last_event_at DESC NULLS LAST, updated_at DESC NULLS LAST, id DESC ",
    "LIMIT $2 OFFSET $3",
);
/// 一覧（ID で絞る）。`$4` は `int(q)`、`$5` は `q%`。
const LIST_ID: &str = select_current!(
    "WHERE guild_id = $1 AND (user_id = $4 OR CAST(user_id AS VARCHAR) LIKE $5) ",
    "ORDER BY last_event_at DESC NULLS LAST, updated_at DESC NULLS LAST, id DESC ",
    "LIMIT $2 OFFSET $3",
);
/// 一覧（名前で絞る）。`$4` は `%q.lower()%`。
const LIST_TEXT: &str = select_current!(
    "WHERE guild_id = $1 AND (lower(username) LIKE $4 OR lower(display_name) LIKE $4) ",
    "ORDER BY last_event_at DESC NULLS LAST, updated_at DESC NULLS LAST, id DESC ",
    "LIMIT $2 OFFSET $3",
);
/// 件数（絞らない）。
const COUNT_ALL: &str = "SELECT count(id) FROM user_state_current WHERE guild_id = $1";
/// 件数（ID で絞る）。
const COUNT_ID: &str = "SELECT count(id) FROM user_state_current \
    WHERE guild_id = $1 AND (user_id = $2 OR CAST(user_id AS VARCHAR) LIKE $3)";
/// 件数（名前で絞る）。
const COUNT_TEXT: &str = "SELECT count(id) FROM user_state_current \
    WHERE guild_id = $1 AND (lower(username) LIKE $2 OR lower(display_name) LIKE $2)";
/// 1 人の最新状態（一意の制約があるので多くて 1 行）。
const DETAIL_CURRENT: &str = select_current!("WHERE guild_id = $1 AND user_id = $2");
/// 1 人の履歴（新しい順に `$3` 件まで）。
const DETAIL_EVENTS: &str = "SELECT id, event_type, status_after, actor_user_id, actor_name, \
    reason, payload_json, (EXTRACT(EPOCH FROM event_at) * 1000000)::bigint FROM user_state_event \
    WHERE guild_id = $1 AND user_id = $2 ORDER BY event_at DESC, id DESC LIMIT $3";

/// `str.isdigit()` が真で `str.isdecimal()` が偽の文字の範囲（Unicode の Numeric_Type=Digit。上付き・丸囲みの数字
/// など。Python 3.13 の表と同じことを、基準 `users_state_db` の `digit_only` が確かめる）。`int()` は読めない。
pub const DIGIT_ONLY: &[(u32, u32)] = &[
    (0x00B2, 0x00B3),
    (0x00B9, 0x00B9),
    (0x1369, 0x1371),
    (0x19DA, 0x19DA),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247C),
    (0x2488, 0x2490),
    (0x24EA, 0x24EA),
    (0x24F5, 0x24FD),
    (0x24FF, 0x24FF),
    (0x2776, 0x277E),
    (0x2780, 0x2788),
    (0x278A, 0x2792),
    (0x10A40, 0x10A43),
    (0x10E60, 0x10E68),
    (0x11052, 0x1105A),
    (0x1E8C7, 0x1E8CF),
    (0x1F100, 0x1F10C),
];

/// 絞り込み（`_apply_state_filter`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// 絞らない。
    All,
    /// ID（`user_id = id` か、10 進の文字が `prefix` に当たる）。`prefix` は `q%`。
    Id {
        /// `int(q)`。
        id: i64,
        /// `f"{q}%"`。
        prefix: String,
    },
    /// 名前（`lower(username)` か `lower(display_name)` が `needle` に当たる）。`needle` は `%q.lower()%`。
    Text {
        /// `f"%{q.lower()}%"`。
        needle: String,
    },
}

/// Python の `str.isdigit()`（1 文字）。
fn is_python_digit(c: char) -> bool {
    let code = u32::from(c);
    let digit_only = DIGIT_ONLY
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&code));
    digit_only || python::decimal_value(c).is_some()
}

/// 全部が数字の `q` の `int(q)`。`int()` が読めない（Numeric_Type=Digit の文字がある）か、bigint に収まらなければ、
/// Python の失敗の文。
fn int_of_digits(q: &str) -> Result<i64, String> {
    let mut value: i64 = 0;
    for c in q.chars() {
        let Some(digit) = python::decimal_value(c) else {
            let shown = python::repr(&Value::String(q.to_string()));
            return Err(format!("invalid literal for int() with base 10: {shown}"));
        };
        let next = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(digit)));
        let Some(next) = next else {
            return Err(format!("int(q) is out of int64 range: {q}"));
        };
        value = next;
    }
    Ok(value)
}

/// `_apply_state_filter` の絞り込み。Python が例外になるもの（`int(q)` が読めない・bigint に収まらない）は `Err`。
pub fn filter_of(query: Option<&str>) -> Result<Filter, String> {
    let q = python::strip(query.unwrap_or_default());
    if q.is_empty() {
        return Ok(Filter::All);
    }
    if q.chars().all(is_python_digit) {
        let id = int_of_digits(q)?;
        let prefix = format!("{q}%");
        return Ok(Filter::Id { id, prefix });
    }
    let needle = format!("%{}%", q.to_lowercase());
    Ok(Filter::Text { needle })
}

/// `_safe_json_loads`。空か読めなければ `fallback`。
pub fn safe_json_loads(raw: &str, fallback: Value) -> Value {
    if raw.is_empty() {
        return fallback;
    }
    serde_json::from_str(raw).unwrap_or(fallback)
}

/// UNIX マイクロ秒を時刻に。
fn from_micros(value: Option<i64>) -> Option<DateTime<Utc>> {
    value.and_then(DateTime::from_timestamp_micros)
}

/// 最新状態の 1 行（`_row_to_state_payload`）。
fn decode_current(row: &PgRow) -> Result<StateRow, sqlx::Error> {
    let roles: String = row.try_get(10)?;
    let abilities: String = row.try_get(11)?;
    Ok(StateRow {
        guild_id: row.try_get(0)?,
        user_id: row.try_get(1)?,
        username: row.try_get(2)?,
        display_name: row.try_get(3)?,
        avatar_url: row.try_get(4)?,
        status: Some(row.try_get(5)?),
        is_in_guild: row.try_get(6)?,
        is_banned: row.try_get(7)?,
        is_timed_out: row.try_get(8)?,
        timed_out_until: from_micros(row.try_get(9)?),
        roles: safe_json_loads(&roles, Value::Array(Vec::new())),
        abilities: safe_json_loads(&abilities, Value::Object(Map::new())),
        last_event_type: row.try_get(12)?,
        last_event_at: from_micros(row.try_get(13)?),
        first_seen_at: from_micros(row.try_get(14)?),
        last_joined_at: from_micros(row.try_get(15)?),
        last_left_at: from_micros(row.try_get(16)?),
        updated_at: from_micros(row.try_get(17)?),
    })
}

/// 履歴の 1 行（`_event_to_payload`。行の ID は SERIAL＝32 ビット）。
fn decode_event(row: &PgRow) -> Result<EventRow, sqlx::Error> {
    let id: i32 = row.try_get(0)?;
    let payload: String = row.try_get(6)?;
    let payload = match safe_json_loads(&payload, Value::Null) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    Ok(EventRow {
        id: i64::from(id),
        event_type: Some(row.try_get(1)?),
        status_after: Some(row.try_get(2)?),
        actor_user_id: row.try_get(3)?,
        actor_name: row.try_get(4)?,
        reason: row.try_get(5)?,
        event_at: from_micros(row.try_get(7)?),
        payload,
    })
}

/// 読み出しの失敗。
#[derive(Debug)]
enum ReadError {
    /// Postgres が断った（自己修復を試すかは SQLSTATE で決める）。
    Database(sqlx::Error),
    /// Python が問い合わせの前後で例外になるもの（bigint に収まらない数・`int()` が読めない文字）。
    Value(String),
}

impl From<sqlx::Error> for ReadError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "{error}"),
            Self::Value(message) => f.write_str(message),
        }
    }
}

impl ReadError {
    /// 自己修復で直りうるか（`_is_repairable_db_error`）。
    fn is_repairable(&self) -> bool {
        matches!(self, Self::Database(error) if is_repairable(error))
    }
}

/// Postgres の bigint に（収まらなければ、Python で asyncpg が断るのと同じ失敗）。
fn bigint(value: i128, what: &str) -> Result<i64, ReadError> {
    let Ok(fitted) = i64::try_from(value) else {
        let message = format!("{what} {value} is out of int64 range");
        return Err(ReadError::Value(message));
    };
    Ok(fitted)
}

/// 表を作れなかったとき（Python で拾われない例外）の型の名前と文。名前は、Python で同じことが起きたときに近いもの
/// （接続できない → `OSError`、束が空かない → SQLAlchemy の `TimeoutError`、42 系 → `ProgrammingError`、
/// ほかの Postgres の失敗 → `DBAPIError`）。
pub fn crash_of(error: &sqlx::Error) -> Crash {
    let kind = match error {
        sqlx::Error::Io(_) => "OSError",
        sqlx::Error::PoolTimedOut => "TimeoutError",
        _ if is_repairable(error) => "ProgrammingError",
        _ => "DBAPIError",
    };
    Crash::new(kind, error.to_string())
}

/// Postgres から読む利用者の状態（[`UserStates`] の本番）。1 つを使い回す（表を作ったかを覚えている）。
pub struct PgUserStates {
    pool: PgPool,
    ready: tokio::sync::Mutex<bool>,
}

impl std::fmt::Debug for PgUserStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUserStates").finish_non_exhaustive()
    }
}

impl PgUserStates {
    /// 作る（まだ表は作らない）。
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ready: tokio::sync::Mutex::new(false),
        }
    }

    /// 表があることを確かめる（無ければ作る）。最初の 1 回だけ動き、あとはすぐ戻る。`force` ならもう一度作りにいく
    /// （自己修復）。Python の `ensure_user_state_db`（同じ文をログに残す）。
    pub async fn ensure_tables(&self, force: bool) -> Result<(), sqlx::Error> {
        let mut ready = self.ready.lock().await;
        if *ready && !force {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for ddl in DDL {
            sqlx::query(*ddl).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        *ready = true;
        if force {
            warn!("User state DB self-heal completed (force recheck).");
        } else {
            info!("User state DB initialized.");
        }
        Ok(())
    }

    /// `_try_db_self_heal`。直りうる失敗なら表を作り直し、やり直してよければ真。
    async fn heal(&self, context: &str, failure: &ReadError) -> bool {
        if !failure.is_repairable() {
            return false;
        }
        warn!("[user_state_service] {context} failed with DB error. trying self-heal: {failure}");
        match self.ensure_tables(true).await {
            Ok(()) => true,
            Err(e) => {
                error!("[user_state_service] DB self-heal failed at {context}: {e}");
                false
            }
        }
    }

    /// `list_recent_user_states`。
    pub async fn list_recent(
        &self,
        guild_id: i128,
        query: Option<&str>,
        limit: i64,
        offset: i128,
    ) -> Result<Vec<StateRow>, Crash> {
        self.ensure_tables(false).await.map_err(|e| crash_of(&e))?;
        let limit = limit.clamp(1, MAX_LIMIT);
        let offset = offset.max(0);
        let mut first = true;
        loop {
            match self.list_once(guild_id, query, limit, offset).await {
                Ok(rows) => return Ok(rows),
                Err(failure) => {
                    if first && self.heal("list_recent_user_states", &failure).await {
                        first = false;
                        continue;
                    }
                    error!(
                        "[user_state_service] list_recent_user_states failed guild_id={guild_id}: {failure}"
                    );
                    return Ok(Vec::new());
                }
            }
        }
    }

    async fn list_once(
        &self,
        guild_id: i128,
        query: Option<&str>,
        limit: i64,
        offset: i128,
    ) -> Result<Vec<StateRow>, ReadError> {
        let guild = bigint(guild_id, "guild_id")?;
        let filter = filter_of(query).map_err(ReadError::Value)?;
        let offset = bigint(offset, "offset")?;
        let rows = match &filter {
            Filter::All => {
                let sql = sqlx::query(LIST_ALL).bind(guild).bind(limit).bind(offset);
                sql.fetch_all(&self.pool).await?
            }
            Filter::Id { id, prefix } => {
                let sql = sqlx::query(LIST_ID).bind(guild).bind(limit).bind(offset);
                let sql = sql.bind(*id).bind(prefix.as_str());
                sql.fetch_all(&self.pool).await?
            }
            Filter::Text { needle } => {
                let sql = sqlx::query(LIST_TEXT).bind(guild).bind(limit).bind(offset);
                let sql = sql.bind(needle.as_str());
                sql.fetch_all(&self.pool).await?
            }
        };
        let rows: Result<Vec<StateRow>, sqlx::Error> = rows.iter().map(decode_current).collect();
        Ok(rows?)
    }

    /// `count_user_states`。
    pub async fn count_states(&self, guild_id: i128, query: Option<&str>) -> Result<i64, Crash> {
        self.ensure_tables(false).await.map_err(|e| crash_of(&e))?;
        let mut first = true;
        loop {
            match self.count_once(guild_id, query).await {
                Ok(count) => return Ok(count),
                Err(failure) => {
                    if first && self.heal("count_user_states", &failure).await {
                        first = false;
                        continue;
                    }
                    error!(
                        "[user_state_service] count_user_states failed guild_id={guild_id}: {failure}"
                    );
                    return Ok(0);
                }
            }
        }
    }

    async fn count_once(&self, guild_id: i128, query: Option<&str>) -> Result<i64, ReadError> {
        let guild = bigint(guild_id, "guild_id")?;
        let filter = filter_of(query).map_err(ReadError::Value)?;
        let count = match &filter {
            Filter::All => {
                let sql = sqlx::query_scalar::<_, i64>(COUNT_ALL).bind(guild);
                sql.fetch_one(&self.pool).await?
            }
            Filter::Id { id, prefix } => {
                let sql = sqlx::query_scalar::<_, i64>(COUNT_ID).bind(guild);
                let sql = sql.bind(*id).bind(prefix.as_str());
                sql.fetch_one(&self.pool).await?
            }
            Filter::Text { needle } => {
                let sql = sqlx::query_scalar::<_, i64>(COUNT_TEXT).bind(guild);
                sql.bind(needle.as_str()).fetch_one(&self.pool).await?
            }
        };
        Ok(count)
    }

    /// `get_user_state_detail`。
    pub async fn user_detail(
        &self,
        guild_id: i128,
        user_id: i128,
        event_limit: i64,
    ) -> Result<Option<Detail>, Crash> {
        self.ensure_tables(false).await.map_err(|e| crash_of(&e))?;
        let limit = event_limit.clamp(1, MAX_EVENT_LIMIT);
        let mut first = true;
        loop {
            match self.detail_once(guild_id, user_id, limit).await {
                Ok(detail) => return Ok(detail),
                Err(failure) => {
                    if first && self.heal("get_user_state_detail", &failure).await {
                        first = false;
                        continue;
                    }
                    error!(
                        "[user_state_service] get_user_state_detail failed guild_id={guild_id} user_id={user_id}: {failure}"
                    );
                    return Ok(None);
                }
            }
        }
    }

    async fn detail_once(
        &self,
        guild_id: i128,
        user_id: i128,
        limit: i64,
    ) -> Result<Option<Detail>, ReadError> {
        let guild = bigint(guild_id, "guild_id")?;
        let user = bigint(user_id, "user_id")?;
        let mut conn = self.pool.acquire().await?;
        let sql = sqlx::query(DETAIL_CURRENT).bind(guild).bind(user);
        let current = match sql.fetch_optional(&mut *conn).await? {
            Some(row) => Some(decode_current(&row)?),
            None => None,
        };
        let sql = sqlx::query(DETAIL_EVENTS)
            .bind(guild)
            .bind(user)
            .bind(limit);
        let rows = sql.fetch_all(&mut *conn).await?;
        let events: Result<Vec<EventRow>, sqlx::Error> = rows.iter().map(decode_event).collect();
        let events = events?;
        if current.is_none() && events.is_empty() {
            return Ok(None);
        }
        Ok(Some(Detail { current, events }))
    }
}

impl UserStates for PgUserStates {
    fn list<'a>(
        &'a self,
        guild_id: i128,
        query: Option<&'a str>,
        limit: i64,
        offset: i128,
    ) -> StoreFuture<'a, Vec<StateRow>> {
        Box::pin(self.list_recent(guild_id, query, limit, offset))
    }

    fn count<'a>(&'a self, guild_id: i128, query: Option<&'a str>) -> StoreFuture<'a, i64> {
        Box::pin(self.count_states(guild_id, query))
    }

    fn detail(
        &self,
        guild_id: i128,
        user_id: i128,
        event_limit: i64,
    ) -> StoreFuture<'_, Option<Detail>> {
        Box::pin(self.user_detail(guild_id, user_id, event_limit))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn id(id: i64, prefix: &str) -> Result<Filter, String> {
        let prefix = prefix.to_string();
        Ok(Filter::Id { id, prefix })
    }

    fn text(needle: &str) -> Result<Filter, String> {
        let needle = needle.to_string();
        Ok(Filter::Text { needle })
    }

    /// 絞り込みは Python の `_apply_state_filter` と同じ（空白・数字・全角の数字・上付き・大きすぎる数・小文字）。
    #[test]
    fn filters_follow_python() {
        assert_eq!(filter_of(None), Ok(Filter::All));
        assert_eq!(filter_of(Some(" \u{3000} ")), Ok(Filter::All));
        assert_eq!(filter_of(Some(" 12 ")), id(12, "12%"));
        assert_eq!(filter_of(Some("0012")), id(12, "0012%"));
        assert_eq!(filter_of(Some("１２")), id(12, "１２%"));
        let max = i64::MAX.to_string();
        let want = id(i64::MAX, &format!("{max}%"));
        assert_eq!(filter_of(Some(max.as_str())), want);
        assert!(filter_of(Some("9223372036854775808")).is_err());
        assert!(filter_of(Some("²")).is_err());
        assert!(filter_of(Some("1²")).is_err());
        assert_eq!(filter_of(Some("-5")), text("%-5%"));
        assert_eq!(filter_of(Some("ABC_d%")), text("%abc_d%%"));
        assert_eq!(filter_of(Some("ΣΑΣ")), text("%σας%"));
    }

    /// JSON の列は、空と読めないものだけ既定になる（null や文字はそのまま）。
    #[test]
    fn json_columns_fall_back_like_python() {
        let empty = || json!([]);
        assert_eq!(safe_json_loads("", empty()), json!([]));
        assert_eq!(safe_json_loads("not json", empty()), json!([]));
        assert_eq!(safe_json_loads("[1] x", empty()), json!([]));
        assert_eq!(safe_json_loads("null", empty()), Value::Null);
        assert_eq!(safe_json_loads(" \"text\" ", empty()), json!("text"));
        let dup = safe_json_loads(r#"{"a": 1, "b": 2, "a": 3}"#, empty());
        assert_eq!(serde_json::to_string(&dup).unwrap(), r#"{"a":3,"b":2}"#);
    }

    /// 自己修復を試すのは Postgres の 42 系だけ（値の失敗や接続の失敗ではしない）。
    #[test]
    fn only_schema_errors_heal() {
        assert!(!ReadError::Value("x".to_string()).is_repairable());
        let timeout = ReadError::Database(sqlx::Error::PoolTimedOut);
        assert!(!timeout.is_repairable());
        assert_eq!(crash_of(&sqlx::Error::PoolTimedOut).kind, "TimeoutError");
    }
}
