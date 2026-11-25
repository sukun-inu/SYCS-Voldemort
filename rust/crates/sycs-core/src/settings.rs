//! ギルドごとの設定を Postgres で読み書きする。Python の `services/settings_pg.py` と同じ表・同じ合図。
//!
//! 移行中は Python（管理画面）と Rust（Bot）の両方が書き、両方が読む。表の形と、変わったことの
//! 知らせ方と、書き込みの排他を揃えておけば、どちらの言語が書いても、もう片方に数十ミリ秒で届き、
//! 同時に書いても取りこぼさない。
//!
//! | 表 | 中身 |
//! |---|---|
//! | `bot_settings_guild` | ギルドごとに 1 行（`guild_key` 文字列, `data` JSONB） |
//! | `bot_settings_state` | 1 行だけ（`id = 1`）。`version`（書くたびに 1 増える）と `root`（guilds 以外のキー） |
//!
//! # 読み込み
//!
//! 全体をメモリに持つ（設定はメッセージのたびに読まれるので、毎回 Postgres へ行くと往復のぶん
//! 処理が止まる）。新しく保つ合図は Python と同じく 2 つ。
//!
//! - `LISTEN bot_settings_changed`: 書いた側がコミットと同時に版番号を流す。受けたら、
//!   手元より新しければ読み直す。接続が切れたら sqlx がつなぎ直し、その間の分を読み直す
//! - 版番号の確認: 一定の間隔で版番号だけを見る（LISTEN を取りこぼしたときの保険）
//!
//! # 書き込み
//!
//! [`SettingsCache::transact`] が Python の `settings_store._mutate_settings` ＋
//! `settings_pg._transact` と同じことをする。
//!
//! 1. advisory lock（[`LOCK_KEY`]、Python と同じ鍵）を取る。Python と Rust が同時に書いても
//!    1 人ずつになり、読み直してから書くので他方の変更を上書きしない
//! 2. 読み直す（手元の写しではなく表から。手元は他のプロセスの直前の変更を知らないことがある）
//! 3. null を落とし、控えを取り、書き換え、また null を落とし、中身が変わったギルドにだけ
//!    「最後に触られた時刻」（[`TOUCHED_AT_KEY`]）を押す
//! 4. 変わったギルドの行だけを書き、消えたギルドの行を消し、版番号を上げて通知する。
//!    何も変わらなければ書かない（版番号も上げず、通知も出さない）
//!
//! 表を作るのは今は Python 側（最初に使ったときに作る）。Rust は表がある前提で読み書きする。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};
use sqlx::postgres::PgListener;
use sqlx::{PgConnection, PgPool};
use tracing::{debug, info, warn};

/// 変更を知らせる通知の名前。Python の `settings_pg.CHANNEL`。
pub const CHANNEL: &str = "bot_settings_changed";

/// 書き込みを 1 人に絞る advisory lock の鍵。Python の `settings_pg.LOCK_KEY`。
///
/// **Python と同じ値であること。** 違うと、Python と Rust が別々の鍵を取って同時に書き、
/// 後から書いた方が先の変更を消す（テストで Python のソースと突き合わせている）。
pub const LOCK_KEY: i64 = 0x5E77_1165;

/// 「最後に触られた時刻」の鍵。Python の `settings_store.TOUCHED_AT_KEY`。
///
/// 放棄された設定の掃除（Python の `services/guild_retention.py`）がこれを読む。値は
/// ISO 8601 の UTC（`2026-11-25T09:44:26.553123+00:00`）。Python の `fromisoformat` で読める。
pub const TOUCHED_AT_KEY: &str = "_updated_at";

/// 書き込みの待ち時間の既定。Python の `SETTINGS_LOCK_TIMEOUT_SECONDS` の既定と同じ。
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// ある時点の設定の全体。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Settings {
    /// 版番号。書かれるたびに 1 増える。表が空なら 0。
    pub version: i64,
    /// guilds 以外のトップレベルのキー。
    pub root: Map<String, Value>,
    /// ギルドの鍵（数字の文字列）→ そのギルドの設定。
    pub guilds: BTreeMap<String, Value>,
}

impl Settings {
    /// 1 ギルドの設定。無ければ `None`（「未設定」として既定値を使うこと）。
    pub fn guild(&self, guild_id: u64) -> Option<&Value> {
        self.guilds.get(&guild_id.to_string())
    }
}

/// 全体を 1 回読む。
pub async fn load(pool: &PgPool) -> Result<Settings, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    load_on(&mut conn).await
}

/// 渡された接続で全体を読む（書き込みでは、排他を取ったトランザクションの中で読むため）。
async fn load_on(conn: &mut PgConnection) -> Result<Settings, sqlx::Error> {
    let state: Option<(i64, Value)> =
        sqlx::query_as("SELECT version, root FROM bot_settings_state WHERE id = 1")
            .fetch_optional(&mut *conn)
            .await?;
    let rows: Vec<(String, Value)> =
        sqlx::query_as("SELECT guild_key, data FROM bot_settings_guild")
            .fetch_all(&mut *conn)
            .await?;
    let (version, root) = match state {
        Some((version, Value::Object(root))) => (version, root),
        Some((version, _)) => (version, Map::new()),
        None => (0, Map::new()),
    };
    Ok(Settings {
        version,
        root,
        guilds: rows.into_iter().collect(),
    })
}

/// [`SettingsCache`] の動かし方。
#[derive(Debug, Clone)]
pub struct CacheOptions {
    /// 版番号を確かめる間隔（LISTEN を取りこぼしたときの保険）。1 秒より短くはしない。
    pub poll_interval: Duration,
    /// LISTEN を張るか。偽なら版番号の確認だけで追う。
    ///
    /// LISTEN が使えない接続（PgBouncer の transaction モードなど）のための口。テストでも、
    /// 版番号の確認が効いていることを LISTEN と切り離して確かめるのに使う（通知はデータベース
    /// 全体に届くので、他のテストの通知で読み直してしまい、確認の効き目を見分けられない）。
    pub listen: bool,
    /// 書き込みの排他を待つ上限。過ぎたら [`WriteError::Timeout`]（書かない）。
    pub write_timeout: Duration,
}

impl CacheOptions {
    /// 版番号を確かめる間隔だけを決め、ほかは既定（LISTEN を張る・待ちは 10 秒）。
    pub fn new(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            listen: true,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }
}

/// 書き込みが失敗した理由。どれも**何も書いていない**（トランザクションごと取り消した）。
#[derive(Debug)]
pub enum WriteError {
    /// 排他を待ちきれなかった（他のプロセスが書き込み中のまま止まっているなど）。
    Timeout(Duration),
    /// データベースの誤り（つながらない・表が無いなど）。
    Database(sqlx::Error),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(limit) => write!(
                f,
                "設定の保存が {:.1} 秒以内に始められませんでした（他のプロセスが書き込み中）",
                limit.as_secs_f64()
            ),
            Self::Database(e) => write!(f, "設定を保存できませんでした: {e}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Timeout(_) => None,
            Self::Database(e) => Some(e),
        }
    }
}

/// 手元に持っている設定。読むのはロック 1 つと参照の複製だけで、Postgres へは行かない。
pub struct SettingsCache {
    pool: PgPool,
    current: RwLock<Arc<Settings>>,
    write_timeout: Duration,
}

impl SettingsCache {
    /// 最初の読み込みをして、通知の受け取りと版番号の確認を動かし始める。
    ///
    /// **最初に読めなければエラーを返す。** 空の設定で動き出すと、セキュリティ機能が全部
    /// 切れたように振る舞い、誰も気づかない（Python も空では動かない）。読めないときに
    /// 待つかやめるかは呼び出し側が決める。
    pub async fn start(pool: PgPool, poll_interval: Duration) -> Result<Arc<Self>, sqlx::Error> {
        Self::start_with(pool, CacheOptions::new(poll_interval)).await
    }

    /// [`SettingsCache::start`] と同じだが、動かし方を細かく決める。
    pub async fn start_with(pool: PgPool, options: CacheOptions) -> Result<Arc<Self>, sqlx::Error> {
        let initial = load(&pool).await?;
        info!(
            guilds = initial.guilds.len(),
            version = initial.version,
            "Postgres から設定を読み込みました"
        );
        let cache = Arc::new(Self {
            pool,
            current: RwLock::new(Arc::new(initial)),
            write_timeout: options.write_timeout,
        });
        if options.listen {
            tokio::spawn(Arc::clone(&cache).listen_forever());
        }
        tokio::spawn(
            Arc::clone(&cache).poll_forever(options.poll_interval.max(Duration::from_secs(1))),
        );
        Ok(cache)
    }

    /// いまの設定。返すのは読み込んだ時点の写しで、あとから変わらない。
    pub fn snapshot(&self) -> Arc<Settings> {
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// 手元の版番号。
    pub fn version(&self) -> i64 {
        self.snapshot().version
    }

    /// 設定を書き換える。Python の `settings_store._mutate_settings` と同じ規則で保存する。
    ///
    /// `mutate` には**表から読み直した**全体が渡る（手元の写しではない）。`mutate` は排他を
    /// 持ったまま呼ばれるので、待つ処理（Discord への問い合わせなど）を中に書かないこと。
    /// `version` を書き換えても無視する（版番号はこちらで上げる）。
    ///
    /// - null は「未設定」であって保存する値ではない。書き換えの前後で落とす（[`drop_nulls`]）
    /// - 中身が変わったギルドにだけ [`TOUCHED_AT_KEY`] にいまの時刻を押す（[`stamp_touched`]）
    ///
    /// 保存できたら手元の写しもすぐ差し替える（通知を待たない）。
    pub async fn transact<T>(
        &self,
        mutate: impl FnOnce(&mut Settings) -> T,
    ) -> Result<T, WriteError> {
        self.write(|data| {
            // 控えを取る前にも落とす。控えに null が残っていると、書き換え後に null を
            // 落としただけで「変わった」と読まれ、触っていないギルドに時刻が押される。
            drop_nulls_in_guilds(&mut data.guilds);
            let before: BTreeMap<String, Map<String, Value>> = data
                .guilds
                .iter()
                .filter_map(|(key, value)| Some((key.clone(), value.as_object()?.clone())))
                .collect();
            let result = mutate(data);
            drop_nulls_in_guilds(&mut data.guilds);
            stamp_touched(&mut data.guilds, &before, &now_iso());
            result
        })
        .await
    }

    /// 保存済みの null を取り除く。取り除いた数を返す。Python の `settings_store.drop_stored_nulls`。
    ///
    /// 書き換えのたびにも落としているが、誰も書き換えないギルドには古い null が残り続けるので、
    /// 起動時にまとめて揃える。取り除くものが無ければ書かない。
    ///
    /// **時刻は押さない。** 形を揃えただけで、利用者が設定を触ったわけではない。押すと、
    /// 放棄された設定の掃除が「最近触られた」と読んで永久に動かなくなる。
    pub async fn drop_stored_nulls(&self) -> Result<usize, WriteError> {
        self.write(|data| drop_nulls_in_guilds(&mut data.guilds))
            .await
    }

    /// 排他を取り、読み直し、`apply` を当て、変わったところだけを保存する。
    async fn write<T>(&self, apply: impl FnOnce(&mut Settings) -> T) -> Result<T, WriteError> {
        let timeout = self.write_timeout;
        let db = |e: sqlx::Error| {
            // 55P03 = lock_not_available。下の lock_timeout が切れたときに返る。
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("55P03") {
                WriteError::Timeout(timeout)
            } else {
                WriteError::Database(e)
            }
        };

        // ここから先で失敗して `?` で抜けると、tx が捨てられて取り消される（書きかけは残らない）。
        let mut tx = self.pool.begin().await.map_err(db)?;
        // 排他の待ちに上限を付ける。付けないと、排他を持ったまま止まったプロセスが 1 つあるだけで、
        // 書き込みが全部いつまでも返らなくなる。トランザクションの中だけで効く（true）。
        // 0 は「上限なし」の意味になるので、1 ms より短くはしない。
        let limit_ms = timeout.as_millis().max(1);
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(format!("{limit_ms}ms"))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        let before = load_on(&mut tx).await.map_err(db)?;
        let mut data = before.clone();
        let result = apply(&mut data);
        data.version = before.version;

        let changed: Vec<(&String, &Value)> = data
            .guilds
            .iter()
            .filter(|(key, value)| before.guilds.get(*key) != Some(*value))
            .collect();
        let removed: Vec<&String> = before
            .guilds
            .keys()
            .filter(|key| !data.guilds.contains_key(*key))
            .collect();
        if changed.is_empty() && removed.is_empty() && data.root == before.root {
            tx.rollback().await.map_err(db)?;
            self.install(data);
            return Ok(result);
        }

        for (key, value) in changed {
            sqlx::query(
                "INSERT INTO bot_settings_guild (guild_key, data) VALUES ($1, $2) \
                 ON CONFLICT (guild_key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        for key in removed {
            sqlx::query("DELETE FROM bot_settings_guild WHERE guild_key = $1")
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        let version = before.version + 1;
        sqlx::query(
            "INSERT INTO bot_settings_state (id, version, root) VALUES (1, $1, $2) \
             ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, root = EXCLUDED.root, \
             updated_at = now()",
        )
        .bind(version)
        .bind(Value::Object(data.root.clone()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        // 通知はコミットした瞬間に届く（取り消せば届かない）。中身は版番号の文字列。
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(version.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;

        data.version = version;
        self.install(data);
        Ok(result)
    }

    /// 読んだ・書いた全体を手元へ入れる。手元の方が新しければ戻さない。
    fn install(&self, fresh: Settings) {
        let mut guard = self.current.write().unwrap_or_else(|p| p.into_inner());
        if fresh.version >= guard.version {
            *guard = Arc::new(fresh);
        }
    }

    /// 手元より新しい版があれば、読み直して差し替える。`hint` は通知で届いた版番号。
    pub async fn refresh_if_newer(&self, hint: Option<i64>) {
        let current = self.version();
        if hint.is_some_and(|v| v <= current) {
            return;
        }
        match load(&self.pool).await {
            Ok(fresh) if fresh.version > current => {
                debug!(
                    from = current,
                    to = fresh.version,
                    "他のプロセスの変更を読み直しました"
                );
                let mut guard = self.current.write().unwrap_or_else(|p| p.into_inner());
                // 読んでいる間に、もっと新しい版が入っていたら戻さない。
                if fresh.version > guard.version {
                    *guard = Arc::new(fresh);
                }
            }
            Ok(_) => {}
            Err(e) => warn!("設定を読み直せませんでした（手元の設定で続けます）: {e}"),
        }
    }

    async fn listen_forever(self: Arc<Self>) {
        let mut delay = Duration::from_secs(1);
        loop {
            match self.listen_once().await {
                Ok(()) => delay = Duration::from_secs(1),
                Err(e) => warn!(
                    "設定の変更の通知を受けられません（{} 秒後につなぎ直します）: {e}",
                    delay.as_secs()
                ),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    /// つないで聞き続ける。返ってくるのはエラーのときだけ。
    async fn listen_once(&self) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen(CHANNEL).await?;
        // つないでいなかった間の書き込みを拾う。
        self.refresh_if_newer(None).await;
        loop {
            match listener.try_recv().await? {
                Some(notification) => {
                    self.refresh_if_newer(notification.payload().parse().ok())
                        .await;
                }
                // 接続が切れた。sqlx が次の呼び出しでつなぎ直して LISTEN し直す。切れていた
                // 間の通知は届かないので、ここで読み直して追いつく。
                None => self.refresh_if_newer(None).await,
            }
        }
    }

    async fn poll_forever(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            let row: Result<Option<(i64,)>, _> =
                sqlx::query_as("SELECT version FROM bot_settings_state WHERE id = 1")
                    .fetch_optional(&self.pool)
                    .await;
            match row {
                Ok(Some((version,))) => self.refresh_if_newer(Some(version)).await,
                Ok(None) => {}
                Err(e) => {
                    warn!("設定の版番号を確かめられませんでした（手元の設定で続けます）: {e}")
                }
            }
        }
    }
}

/// いまの時刻（UTC、マイクロ秒まで）。Python の `datetime.now(timezone.utc).isoformat()` と同じ形。
///
/// Python はマイクロ秒がちょうど 0 のとき小数部を省くが、こちらは常に付ける。読む側の
/// `fromisoformat` はどちらも読める。
fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

/// 値が null の鍵を、入れ子の奥まで取り除く。取り除いた数を返す。Python の `settings_store._drop_nulls`。
///
/// **null は「未設定」であって、保存する値ではない。** 読む側は鍵が無ければ既定値へ倒れる
/// ように書かれているが、null が入っていると既定値ではなく null が返り、数として読む箇所で落ちる。
///
/// - null を取り除いた結果で空になった辞書も消す（`{"welcome": {"channel_id": null}}` を
///   `{"welcome": {}}` として残さない）。もとから空だった辞書は残す
/// - 配列の要素は位置に意味があるので、null でも消さない（中の辞書だけ掃除する）
pub fn drop_nulls(node: &mut Value) -> usize {
    match node {
        Value::Object(map) => {
            let before = map.len();
            map.retain(|_, value| !value.is_null());
            let mut removed = before - map.len();
            let mut emptied = Vec::new();
            for (key, value) in map.iter_mut() {
                if !(value.is_object() || value.is_array()) {
                    continue;
                }
                let inner = drop_nulls(value);
                removed += inner;
                if inner > 0 && value.as_object().is_some_and(Map::is_empty) {
                    emptied.push(key.clone());
                }
            }
            for key in emptied {
                // 残りの鍵の並びを崩さない（remove は末尾の鍵を空いた位置へ動かす）。
                map.shift_remove(&key);
            }
            removed
        }
        Value::Array(items) => items.iter_mut().map(drop_nulls).sum(),
        _ => 0,
    }
}

/// 全ギルドの設定から null を取り除く。ギルドの入れ物そのものは、空になっても消さない。
/// Python の `settings_store._drop_nulls_in_guilds`。
fn drop_nulls_in_guilds(guilds: &mut BTreeMap<String, Value>) -> usize {
    guilds
        .values_mut()
        .filter(|settings| settings.is_object())
        .map(drop_nulls)
        .sum()
}

/// この書き込みで中身が変わったギルドに `now` を押す。Python の `settings_store._stamp_touched`。
///
/// **変わっていないギルドには押さない。** 全ギルドへ毎回押すと「長く触られていない」が
/// どのギルドについても成立しなくなり、放棄された設定を見分けられなくなる。比較は時刻の鍵を
/// 除いた中身で行う（押した時刻を比較に入れると、書くたびに差が出る）。
fn stamp_touched(
    guilds: &mut BTreeMap<String, Value>,
    before: &BTreeMap<String, Map<String, Value>>,
    now: &str,
) {
    let empty = Map::new();
    for (key, current) in guilds.iter_mut() {
        let Some(current) = current.as_object_mut() else {
            continue;
        };
        let was = before.get(key).unwrap_or(&empty);
        if !same_without_stamp(current, was) {
            current.insert(TOUCHED_AT_KEY.to_string(), Value::String(now.to_string()));
        }
    }
}

/// 時刻の鍵を除いて同じ中身か。鍵の並びは問わない。
fn same_without_stamp(a: &Map<String, Value>, b: &Map<String, Value>) -> bool {
    let a_len = a.len() - usize::from(a.contains_key(TOUCHED_AT_KEY));
    let b_len = b.len() - usize::from(b.contains_key(TOUCHED_AT_KEY));
    a_len == b_len
        && a.iter()
            .filter(|(key, _)| key.as_str() != TOUCHED_AT_KEY)
            .all(|(key, value)| b.get(key) == Some(value))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn dropped(mut value: Value) -> (Value, usize) {
        let n = drop_nulls(&mut value);
        (value, n)
    }

    /// null の鍵を奥まで落とし、落とした数を返すこと。
    #[test]
    fn drop_nulls_removes_null_keys_at_every_depth() {
        let (v, n) = dropped(json!({"a": null, "b": 1, "c": {"d": null, "e": 2}}));
        assert_eq!(v, json!({"b": 1, "c": {"e": 2}}));
        assert_eq!(n, 2);
    }

    /// null を落として空になった辞書は消し、もとから空だった辞書は残すこと。
    #[test]
    fn drop_nulls_removes_dicts_it_emptied_but_keeps_ones_that_were_empty() {
        let (v, n) = dropped(json!({"welcome": {"channel_id": null}, "kept": {}}));
        assert_eq!(v, json!({"kept": {}}));
        assert_eq!(n, 1);
        // 2 段で空になる場合も、外側まで消える。
        let (v, n) = dropped(json!({"a": {"b": {"c": null}}, "x": 1}));
        assert_eq!(v, json!({"x": 1}));
        assert_eq!(n, 1);
    }

    /// 配列の null は位置に意味があるので残し、配列の中の辞書は掃除すること。
    #[test]
    fn drop_nulls_keeps_nulls_in_lists_but_cleans_dicts_inside_them() {
        let (v, n) = dropped(json!({"list": [null, 1, {"k": null, "j": 2}]}));
        assert_eq!(v, json!({"list": [null, 1, {"j": 2}]}));
        assert_eq!(n, 1);
    }

    /// 残った鍵の並びを崩さないこと（管理画面の表示や差分の見た目が変わらないように）。
    #[test]
    fn drop_nulls_keeps_the_order_of_the_remaining_keys() {
        let (v, _) = dropped(json!({"a": 1, "gone": {"x": null}, "b": 2, "c": 3}));
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["a", "b", "c"]);
    }

    /// ギルドの入れ物は、空になっても消さないこと（ギルドがある前提で書かれた処理が落ちる）。
    #[test]
    fn drop_nulls_in_guilds_keeps_the_guild_itself() {
        let mut guilds = BTreeMap::from([
            ("1".to_string(), json!({"only": null})),
            ("2".to_string(), json!("not a dict")),
        ]);
        assert_eq!(drop_nulls_in_guilds(&mut guilds), 1);
        assert_eq!(guilds["1"], json!({}));
        assert_eq!(guilds["2"], json!("not a dict"));
    }

    fn objects(guilds: &BTreeMap<String, Value>) -> BTreeMap<String, Map<String, Value>> {
        guilds
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.as_object()?.clone())))
            .collect()
    }

    /// 中身が変わったギルドにだけ時刻を押すこと。
    #[test]
    fn stamp_touched_marks_only_changed_guilds() {
        let before = BTreeMap::from([
            ("1".to_string(), json!({"a": 1})),
            ("2".to_string(), json!({"a": 1, TOUCHED_AT_KEY: "old"})),
        ]);
        let mut after = before.clone();
        after.get_mut("1").unwrap()["a"] = json!(2);
        stamp_touched(&mut after, &objects(&before), "NOW");
        assert_eq!(after["1"][TOUCHED_AT_KEY], "NOW");
        // 触っていないギルドの時刻はそのまま。
        assert_eq!(after["2"][TOUCHED_AT_KEY], "old");
    }

    /// 時刻だけが違うのは「変わった」に数えないこと（数えると書くたびに押し直す）。
    /// 鍵の並びが違うだけのものも同じ中身とみなすこと。
    #[test]
    fn stamp_touched_ignores_the_stamp_itself_and_key_order() {
        let before = BTreeMap::from([("1".to_string(), json!({"a": 1, "b": 2}))]);
        let mut after = BTreeMap::from([(
            "1".to_string(),
            json!({"b": 2, "a": 1, TOUCHED_AT_KEY: "x"}),
        )]);
        stamp_touched(&mut after, &objects(&before), "NOW");
        assert_eq!(after["1"][TOUCHED_AT_KEY], "x");
    }

    /// 新しく足されたギルドは、中身があれば押し、空なら押さないこと（Python と同じ）。
    #[test]
    fn stamp_touched_treats_a_new_guild_as_previously_empty() {
        let mut after = BTreeMap::from([
            ("new".to_string(), json!({"a": 1})),
            ("blank".to_string(), json!({})),
        ]);
        stamp_touched(&mut after, &BTreeMap::new(), "NOW");
        assert_eq!(after["new"][TOUCHED_AT_KEY], "NOW");
        assert!(after["blank"].get(TOUCHED_AT_KEY).is_none());
    }

    /// 鍵が消えただけでも「変わった」に数えること。
    #[test]
    fn stamp_touched_counts_a_removed_key_as_a_change() {
        let before = BTreeMap::from([("1".to_string(), json!({"a": 1, "b": 2}))]);
        let mut after = BTreeMap::from([("1".to_string(), json!({"a": 1}))]);
        stamp_touched(&mut after, &objects(&before), "NOW");
        assert_eq!(after["1"][TOUCHED_AT_KEY], "NOW");
    }

    /// 時刻の形が Python の isoformat と同じ（UTC・マイクロ秒・+00:00）であること。
    #[test]
    fn the_stamp_looks_like_python_isoformat() {
        let s = now_iso();
        assert_eq!(s.len(), "2026-11-25T09:44:26.553123+00:00".len(), "{s}");
        assert!(s.ends_with("+00:00"), "{s}");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], ".");
    }

    /// 排他の鍵と時刻の鍵が Python のソースの値と同じであること。
    ///
    /// 鍵が違うと、Python と Rust が別々の排他を取って同時に書き、片方の変更が消える。
    /// 時刻の鍵が違うと、放棄された設定の掃除が Rust の書いた時刻を読めず、消してよいか
    /// 判断できない。
    #[test]
    fn the_lock_key_and_the_stamp_key_match_python() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../services/");
        let pg = std::fs::read_to_string(format!("{root}settings_pg.py")).unwrap();
        let store = std::fs::read_to_string(format!("{root}settings_store.py")).unwrap();
        let lock = pg
            .lines()
            .find_map(|l| l.strip_prefix("LOCK_KEY = "))
            .expect("settings_pg.py に LOCK_KEY が無い");
        let lock = lock.split('#').next().unwrap().trim();
        let lock = i64::from_str_radix(lock.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(lock, LOCK_KEY);
        assert!(
            store.contains(&format!("TOUCHED_AT_KEY = \"{TOUCHED_AT_KEY}\"")),
            "settings_store.py の TOUCHED_AT_KEY が違う"
        );
        let channel = format!("CHANNEL = \"{CHANNEL}\"");
        assert!(pg.contains(&channel), "settings_pg.py の CHANNEL が違う");
    }
}
