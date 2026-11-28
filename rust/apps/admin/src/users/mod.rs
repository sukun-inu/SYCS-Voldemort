//! 利用者の状態の API（rust-06 の A4）。Python の `webapp_admin/api/users.py`（`list_states`・`user_detail`・`_row`）。
//!
//! | 経路 | 確かめ | 入力 → 出力 |
//! |---|---|---|
//! | `GET /admin/api/users/state` | `check_guild` | `q`（128 文字まで）・`limit`（1〜200、既定 25）・`offset`（0 以上、既定 0）→ `{"rows", "total", "limit", "offset", "has_more"}` |
//! | `GET /admin/api/users/state/{user_id}` | `check_guild` | `event_limit`（1〜500、既定 100）→ `{"found", "user_id", "current", "events"}`。記録が無ければ 404 `{"found": false, "user_id"}` |
//!
//! どちらもルーターの中の経路（既定の回数の制限は掛からない）で、デコレータの制限も無い。順は Python と同じ:
//! `check_guild`（303）→ 引数の検証（422。[`crate::params`]）→ `int(session["guild_id"])`（読めなければ拾われない
//! 例外＝500）→ 読み出し（一覧は行 → 件数の順）。答えは `SafeJSONResponse`（[`crate::jsonsafe`]。2^53 を超える整数は文字）。
//!
//! 読み出し（Python の `services/user_state_service.py` の `list_recent_user_states`・`count_user_states`・
//! `get_user_state_detail`）は [`UserStates`] の向こう。本番は [`store::PgUserStates`]（Postgres）、テストは偽物
//! （A0 の基準 `users_state` の例の service を返す）。[`AdminApp::with_users`] で差し込む。
//! services が返すもの（[`StateRow`]・[`EventRow`]）は、Python の `_row_to_state_payload`・`_event_to_payload` の
//! 辞書と同じ中身を型で持つ。表示用に整えるのは [`labels`]（状態・イベント・権限の日本語、JST の時刻、ロールの名前、
//! いまタイムアウト中か＝記録の旗ではなく期限と今の時刻。Python の `_timed_out_now`。ec10a3e）。
//!
//! Python と違うところ（どれも Postgres の services からは来ない値で、Python には分岐として残っている）:
//!
//! - 時刻の欄に、時差の無い datetime・文字・数が入っていたときの分岐（`format_jst`・`_timed_out_now` の
//!   `isinstance` の枝）は無い。Rust の型は Postgres の `timestamptz` だけを持つ
//! - services の答えの `current` が辞書でない・`events` の要素が辞書でない、の枝も無い
//! - 基準の例のうち、それに当たるもの（`rust_skip` を付けた例）は、テストが飛ばす
//! - Postgres の bigint に収まらない数（ID・飛ばす数）を、Python はそのまま services へ渡す（services が失敗して
//!   空か `None` になる）。Rust も `i128` に収まるものは渡す（読み出しが同じ答えにする）。`i128` にも収まらない
//!   もの（39 桁より長い）は、services を呼ばずに同じ答え（行は空・件数は 0・詳細は 404）にする

pub mod labels;
pub mod store;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::Method;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use tracing::warn;

use crate::app::{AdminApp, Reply, Req, handler};
use crate::errors::{Crash, Failure};
use crate::jsonsafe;
use crate::params::{self, Bounds, Field, Int, QueryParams};
use crate::python;
use crate::routing::Route;

/// 一覧の経路。
pub const LIST_PATH: &str = "/admin/api/users/state";
/// 詳細の経路。
pub const DETAIL_PATH: &str = "/admin/api/users/state/{user_id}";
/// 検索語の長さの上限（文字。`Query(max_length=128)`）。
pub const MAX_QUERY_CHARS: usize = 128;
/// 一覧の件数の既定。
pub const DEFAULT_LIMIT: i64 = 25;
/// 一覧の件数の上限。
pub const MAX_LIMIT: i64 = 200;
/// 履歴の件数の既定。
pub const DEFAULT_EVENT_LIMIT: i64 = 100;
/// 履歴の件数の上限。
pub const MAX_EVENT_LIMIT: i64 = 500;

/// 最新状態の 1 行（Python の `_row_to_state_payload` の辞書）。表で NULL になりえない欄も、Python の辞書の
/// `get` が `None` を返しうるものは `Option`（Postgres からはいつも `Some`）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StateRow {
    /// サーバーの ID。
    pub guild_id: i64,
    /// 利用者の ID。
    pub user_id: i64,
    /// ユーザー名。
    pub username: Option<String>,
    /// 表示名。
    pub display_name: Option<String>,
    /// アバターの URL。
    pub avatar_url: Option<String>,
    /// 状態（`active`・`left`・`kicked`・`banned`・`unbanned`・`unknown`）。
    pub status: Option<String>,
    /// サーバーに居るか。
    pub is_in_guild: bool,
    /// BAN されているか。
    pub is_banned: bool,
    /// 記録のタイムアウトの旗（表示には使わない。[`labels::timed_out_now`]）。
    pub is_timed_out: bool,
    /// タイムアウトの期限。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// ロールの控え（`roles_json` を読んだもの。読めなければ `[]`。並びとは限らない）。
    pub roles: Value,
    /// 権限の控え（`abilities_json` を読んだもの。読めなければ `{}`。辞書とは限らない）。
    pub abilities: Value,
    /// 最後のイベントの種類。
    pub last_event_type: Option<String>,
    /// 最後のイベントの時刻。
    pub last_event_at: Option<DateTime<Utc>>,
    /// 最初に見た時刻。
    pub first_seen_at: Option<DateTime<Utc>>,
    /// 最後に入った時刻。
    pub last_joined_at: Option<DateTime<Utc>>,
    /// 最後に抜けた時刻。
    pub last_left_at: Option<DateTime<Utc>>,
    /// 最後に書き換えた時刻。
    pub updated_at: Option<DateTime<Utc>>,
}

/// 履歴の 1 行（Python の `_event_to_payload` の辞書）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EventRow {
    /// 行の ID。
    pub id: i64,
    /// イベントの種類。
    pub event_type: Option<String>,
    /// そのあとの状態。
    pub status_after: Option<String>,
    /// 実行者の ID。
    pub actor_user_id: Option<i64>,
    /// 実行者の名前。
    pub actor_name: Option<String>,
    /// 理由。
    pub reason: Option<String>,
    /// 時刻。
    pub event_at: Option<DateTime<Utc>>,
    /// 中身（`payload_json` を読んだもの。辞書でなければ空の辞書）。
    pub payload: Map<String, Value>,
}

/// 1 人の詳細（`get_user_state_detail` の答え。最新状態も履歴も無ければ、答えそのものが `None`）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Detail {
    /// 最新状態（無ければ `None`。履歴だけ残ることがある）。
    pub current: Option<StateRow>,
    /// 履歴（新しい順）。
    pub events: Vec<EventRow>,
}

/// 読み出しの future（失敗は、Python で拾われずに 500 になる例外だけ）。
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Crash>> + Send + 'a>>;

/// 利用者の状態の読み出し（Python の `services/user_state_service.py` の 3 つ。引数も同じ）。
///
/// 数は Python の `int`（大きさに限りが無い）の代わりに `i128`。Postgres の bigint に収まらないものの扱いは
/// 読み出しの側が決める（Python と同じく、失敗として空か `None`）。
pub trait UserStates: Send + Sync {
    /// `list_recent_user_states(guild_id, query=…, limit=…, offset=…)`。
    fn list<'a>(
        &'a self,
        guild_id: i128,
        query: Option<&'a str>,
        limit: i64,
        offset: i128,
    ) -> StoreFuture<'a, Vec<StateRow>>;

    /// `count_user_states(guild_id, query=…)`。
    fn count<'a>(&'a self, guild_id: i128, query: Option<&'a str>) -> StoreFuture<'a, i64>;

    /// `get_user_state_detail(guild_id, user_id, event_limit=…)`。
    fn detail(
        &self,
        guild_id: i128,
        user_id: i128,
        event_limit: i64,
    ) -> StoreFuture<'_, Option<Detail>>;
}

/// 読み出し口を差し込んでいないときのもの（読むたびに 500。[`AdminApp::with_users`] の書き忘れに気づくため）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Unconfigured;

impl Unconfigured {
    fn crash() -> Crash {
        let message = "利用者の状態の読み出し口がつながっていません（AdminApp::with_users）";
        Crash::new("RuntimeError", message)
    }
}

impl UserStates for Unconfigured {
    fn list<'a>(
        &'a self,
        _guild_id: i128,
        _query: Option<&'a str>,
        _limit: i64,
        _offset: i128,
    ) -> StoreFuture<'a, Vec<StateRow>> {
        Box::pin(async { Err(Self::crash()) })
    }

    fn count<'a>(&'a self, _guild_id: i128, _query: Option<&'a str>) -> StoreFuture<'a, i64> {
        Box::pin(async { Err(Self::crash()) })
    }

    fn detail(
        &self,
        _guild_id: i128,
        _user_id: i128,
        _event_limit: i64,
    ) -> StoreFuture<'_, Option<Detail>> {
        Box::pin(async { Err(Self::crash()) })
    }
}

/// この塊の経路（Python の `api/users.py` の登録の順）。[`crate::routes::default_routes`] のルーターの中に入れる。
pub fn routes() -> Vec<Route> {
    vec![
        Route::new(LIST_PATH, &[Method::GET], handler(list_states)),
        Route::new(DETAIL_PATH, &[Method::GET], handler(user_detail)),
    ]
}

/// `int(request.session["guild_id"])`（`check_guild` のあとなので鍵はある）。読めなければ Python と同じ例外（500）。
fn session_guild_id(req: &Req) -> Result<Int, Failure> {
    let value = req
        .session
        .with(|session| session.get("guild_id").cloned())
        .unwrap_or(Value::Null);
    let text = python::int_text(&value).ok_or_else(|| int_error(&value))?;
    match Int::from_decimal(&text) {
        Some(id) => Ok(id),
        None => Err(int_error(&value).into()),
    }
}

/// `int(value)` が投げる例外（文字は `ValueError`、文字でも数でもないものは `TypeError`）。
fn int_error(value: &Value) -> Crash {
    if let Value::String(_) = value {
        let shown = python::repr(value);
        let message = format!("invalid literal for int() with base 10: {shown}");
        return Crash::new("ValueError", message);
    }
    let kind = python::type_name(value);
    let message = format!(
        "int() argument must be a string, a bytes-like object or a real number, not '{kind}'"
    );
    Crash::new("TypeError", message)
}

/// いまの時刻（`datetime.now(timezone.utc)`。アプリの時計から。マイクロ秒まで）。
fn now_utc(app: &AdminApp) -> DateTime<Utc> {
    let micros = (app.now() * 1_000_000.0).round() as i64;
    DateTime::from_timestamp_micros(micros).unwrap_or_default()
}

/// 検証の通った件数（`i64`。範囲の中なので必ず収まる）。
fn checked_limit(value: &Int, default: i64) -> i64 {
    value
        .get()
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(default)
}

/// 文字か `null`。
fn text_or_null(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.to_string()))
}

/// 文字の並び。
fn texts(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

/// `_row`（一覧と詳細で同じ 1 人分）。`now` は `_timed_out_now` の今。
pub fn row(state: &StateRow, now: DateTime<Utc>) -> Map<String, Value> {
    let roles = labels::roles(&state.roles);
    let status = state.status.as_deref();
    let timed_out = labels::timed_out_now(state.timed_out_until, now);
    let event = labels::event_label(state.last_event_type.as_deref());
    let at = labels::format_jst(state.last_event_at);
    let mut map = Map::new();
    let mut put = |key: &str, value: Value| {
        map.insert(key.to_string(), value);
    };
    put("user_id", Value::String(state.user_id.to_string()));
    put("username", text_or_null(state.username.as_deref()));
    put("display_name", text_or_null(state.display_name.as_deref()));
    put("avatar_url", text_or_null(state.avatar_url.as_deref()));
    put("status", text_or_null(status));
    put("status_label", Value::String(labels::status_label(status)));
    put("status_tone", Value::from(labels::status_tone(status)));
    put("is_in_guild", Value::Bool(state.is_in_guild));
    put("is_banned", Value::Bool(state.is_banned));
    put("is_timed_out", Value::Bool(timed_out));
    put("last_event_label", Value::String(event));
    put("last_event_at", Value::String(at));
    put("roles", texts(labels::role_names(&roles)));
    let abilities = labels::enabled_abilities(&state.abilities);
    put("abilities", texts(abilities));
    map
}

/// 詳細の `current`（`_row` に時刻 5 つとロールの中身を足したもの）。
pub fn current(state: &StateRow, now: DateTime<Utc>) -> Map<String, Value> {
    let mut map = row(state, now);
    let times = [
        ("timed_out_until", state.timed_out_until),
        ("first_seen_at", state.first_seen_at),
        ("last_joined_at", state.last_joined_at),
        ("last_left_at", state.last_left_at),
        ("updated_at", state.updated_at),
    ];
    for (key, value) in times {
        map.insert(key.to_string(), Value::String(labels::format_jst(value)));
    }
    let details = labels::roles(&state.roles).into_iter().map(Value::Object);
    map.insert("role_details".to_string(), Value::Array(details.collect()));
    map
}

/// 詳細の `events` の 1 件。
pub fn event(event: &EventRow) -> Value {
    let event_type = event.event_type.as_deref();
    let status_after = event.status_after.as_deref();
    let label = labels::event_label(event_type);
    let at = labels::format_jst(event.event_at);
    let status_label = labels::status_label(status_after);
    let status_tone = labels::status_tone(status_after);
    let mut map = Map::new();
    let mut put = |key: &str, value: Value| {
        map.insert(key.to_string(), value);
    };
    put("id", Value::from(event.id));
    put("event_label", Value::String(label));
    put("event_type", text_or_null(event_type));
    put("event_at", Value::String(at));
    put("status_after_label", Value::String(status_label));
    put("status_after_tone", Value::from(status_tone));
    put("actor_name", text_or_null(event.actor_name.as_deref()));
    put("reason", text_or_null(event.reason.as_deref()));
    put("payload", Value::Object(event.payload.clone()));
    Value::Object(map)
}

/// `list_states`（`GET /admin/api/users/state`）。
pub async fn list_states(app: Arc<AdminApp>, req: Req) -> Result<Reply, Failure> {
    req.check_guild()?;
    let query = QueryParams::parse(req.query.as_deref());
    let mut errors = Vec::new();
    let field = Field::query("q");
    let raw = query.get("q");
    let q = params::str_value(&mut errors, field, raw, "", Some(MAX_QUERY_CHARS));
    let field = Field::query("limit");
    let range = Bounds::between(1, i128::from(MAX_LIMIT));
    let default = Some(i128::from(DEFAULT_LIMIT));
    let limit = params::int_value(&mut errors, field, query.get("limit"), default, range);
    let field = Field::query("offset");
    let range = Bounds::at_least(0);
    let offset = params::int_value(&mut errors, field, query.get("offset"), Some(0), range);
    let (Some(q), Some(limit), Some(offset)) = (q, limit, offset) else {
        return Err(Failure::Validation(errors));
    };
    let guild_id = session_guild_id(&req)?;
    let keyword = Some(python::strip(&q)).filter(|k| !k.is_empty());
    let limit = checked_limit(&limit, DEFAULT_LIMIT);
    let users = app.users();
    let rows = match (guild_id.get(), offset.get()) {
        (Some(guild), Some(skip)) => users.list(guild, keyword, limit, skip).await?,
        _ => {
            warn!("利用者の状態の一覧: ID か飛ばす数が大きすぎます（行は空）");
            Vec::new()
        }
    };
    let total = match guild_id.get() {
        Some(guild) => users.count(guild, keyword).await?,
        None => 0,
    };
    // 行が返らなかったページの先に「次へ」を出さない（total は別の問い合わせなので、食い違うことがある）。
    let shown = i128::try_from(rows.len()).unwrap_or(i128::MAX);
    let next = offset.get().map(|skip| skip.saturating_add(shown));
    let has_more = !rows.is_empty() && next.is_some_and(|next| next < i128::from(total));
    let now = now_utc(&app);
    let rows: Vec<Value> = rows
        .iter()
        .map(|state| Value::Object(row(state, now)))
        .collect();
    let mut body = Map::new();
    body.insert("rows".to_string(), Value::Array(rows));
    body.insert("total".to_string(), Value::from(total));
    body.insert("limit".to_string(), Value::from(limit));
    body.insert("offset".to_string(), offset.to_json());
    body.insert("has_more".to_string(), Value::Bool(has_more));
    Ok(jsonsafe::reply(200, Value::Object(body)))
}

/// `user_detail`（`GET /admin/api/users/state/{user_id}`）。
pub async fn user_detail(app: Arc<AdminApp>, req: Req) -> Result<Reply, Failure> {
    req.check_guild()?;
    let query = QueryParams::parse(req.query.as_deref());
    let mut errors = Vec::new();
    let field = Field::path("user_id");
    let raw = req.param("user_id");
    let user_id = params::int_value(&mut errors, field, raw, None, Bounds::none());
    let field = Field::query("event_limit");
    let range = Bounds::between(1, i128::from(MAX_EVENT_LIMIT));
    let default = Some(i128::from(DEFAULT_EVENT_LIMIT));
    let raw = query.get("event_limit");
    let event_limit = params::int_value(&mut errors, field, raw, default, range);
    let (Some(user_id), Some(event_limit)) = (user_id, event_limit) else {
        return Err(Failure::Validation(errors));
    };
    let guild_id = session_guild_id(&req)?;
    let event_limit = checked_limit(&event_limit, DEFAULT_EVENT_LIMIT);
    let detail = match (guild_id.get(), user_id.get()) {
        (Some(guild), Some(user)) => app.users().detail(guild, user, event_limit).await?,
        _ => {
            warn!("利用者の状態の詳細: ID が大きすぎます（記録が無い扱い）");
            None
        }
    };
    let mut body = Map::new();
    let Some(detail) = detail else {
        body.insert("found".to_string(), Value::Bool(false));
        body.insert("user_id".to_string(), Value::String(user_id.decimal()));
        return Ok(jsonsafe::reply(404, Value::Object(body)));
    };
    let now = now_utc(&app);
    let current = match &detail.current {
        Some(state) => Value::Object(current(state, now)),
        None => Value::Null,
    };
    let events: Vec<Value> = detail.events.iter().map(event).collect();
    body.insert("found".to_string(), Value::Bool(true));
    body.insert("user_id".to_string(), Value::String(user_id.decimal()));
    body.insert("current".to_string(), current);
    body.insert("events".to_string(), Value::Array(events));
    Ok(jsonsafe::reply(200, Value::Object(body)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    fn dumped(value: &Value) -> String {
        python::dumps(value, python::COMPACT)
    }

    /// 一覧の 1 行と詳細の current が、Python の `_row` と同じ鍵の順・同じ値（期限は今と比べ、記録の旗は見ない）。
    #[test]
    fn rows_are_shaped_like_python() {
        let now = at("2027-01-01T00:00:00Z");
        let state = StateRow {
            user_id: 555,
            username: Some("member".to_string()),
            status: Some("banned".to_string()),
            is_banned: true,
            is_timed_out: false,
            timed_out_until: Some(at("2999-01-01T00:00:00Z")),
            roles: json!([{"id": 1, "name": "常連"}, "x"]),
            abilities: json!({"ban_members": true, "administrator": false}),
            last_event_type: Some("member_ban".to_string()),
            last_event_at: Some(at("2026-08-21T03:30:00Z")),
            ..StateRow::default()
        };
        let want = json!({
            "user_id": "555", "username": "member", "display_name": null, "avatar_url": null,
            "status": "banned", "status_label": "BAN中", "status_tone": "danger",
            "is_in_guild": false, "is_banned": true, "is_timed_out": true,
            "last_event_label": "BAN", "last_event_at": "2026/08/21 12:30:00",
            "roles": ["常連"], "abilities": ["メンバーをBAN"],
        });
        let got = Value::Object(row(&state, now));
        assert_eq!(dumped(&got), dumped(&want));
        let want = json!({
            "user_id": "555", "username": "member", "display_name": null, "avatar_url": null,
            "status": "banned", "status_label": "BAN中", "status_tone": "danger",
            "is_in_guild": false, "is_banned": true, "is_timed_out": true,
            "last_event_label": "BAN", "last_event_at": "2026/08/21 12:30:00",
            "roles": ["常連"], "abilities": ["メンバーをBAN"],
            "timed_out_until": "2999/01/01 09:00:00", "first_seen_at": "-", "last_joined_at": "-",
            "last_left_at": "-", "updated_at": "-", "role_details": [{"id": 1, "name": "常連"}],
        });
        let got = Value::Object(current(&state, now));
        assert_eq!(dumped(&got), dumped(&want));
    }

    /// 履歴の 1 件は Python の詳細の events と同じ鍵の順・同じ値。
    #[test]
    fn events_are_shaped_like_python() {
        let row = EventRow {
            id: 8,
            event_type: Some("sync_member_on_ready".to_string()),
            status_after: Some("active".to_string()),
            actor_name: Some("管理者".to_string()),
            event_at: Some(at("2026-08-21T00:00:00Z")),
            ..EventRow::default()
        };
        let want = json!({
            "id": 8, "event_label": "メンバー状態を同期（起動時）",
            "event_type": "sync_member_on_ready",
            "event_at": "2026/08/21 09:00:00", "status_after_label": "在籍",
            "status_after_tone": "success", "actor_name": "管理者", "reason": null, "payload": {},
        });
        assert_eq!(dumped(&event(&row)), dumped(&want));
    }

    /// session の guild_id は Python の int() と同じに読む（読めなければ ValueError・TypeError）。
    #[test]
    fn guild_ids_fail_like_python_int() {
        let crash = int_error(&json!("abc"));
        assert_eq!(crash.kind, "ValueError");
        let message = "invalid literal for int() with base 10: 'abc'";
        assert_eq!(crash.message, message);
        let crash = int_error(&Value::Null);
        assert_eq!(crash.kind, "TypeError");
        assert!(
            crash.message.ends_with("not 'NoneType'"),
            "{}",
            crash.message
        );
    }
}
