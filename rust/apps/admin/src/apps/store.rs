//! 設定の置き場（読む側と書く側）。Bot と同じ `sycs_core::settings::SettingsCache`（Postgres の `bot_settings_guild`・
//! `bot_settings_state`。変更は LISTEN と版番号で追う）を使い回す。
//!
//! Python の管理画面（`settings_store.start_backend` → `settings_pg.PostgresSettings`）と同じ動き:
//!
//! - 起動では待たない。裏で読み込みを始め、読めるまで間を空けて繰り返す（1 秒から倍にして 30 秒まで。
//!   `_bootstrap_forever`）
//! - 読む人は、最初の読み込みが済むまで `SETTINGS_LOAD_TIMEOUT_SECONDS`（既定 30 秒、下限 1 秒）待つ。待ちきれなければ
//!   `SettingsNotLoaded`（「設定を Postgres から 30 秒以内に読み込めませんでした。…」）
//! - 書く人（A6。[`SettingsStore::transact`]）も同じだけ待ってから、Bot と同じ `SettingsCache::transact` で書く
//!   （Python の `settings_store._mutate_settings` → `settings_pg._transact` と同じ: 排他〔advisory lock〕を取って
//!   表から読み直し、null を落として書き換え、変わったギルドにだけ時刻を押し、変わった行だけを書いて版番号を上げ、
//!   `bot_settings_changed` に新しい版番号を流す。**これが Bot に設定の変更がすぐ届く仕組み**で、Bot の Rust も Python の
//!   Bot も、この通知で読み直す。何も変わらなければ書かず、版番号も上げず、通知も出さない）
//!
//! Python と違うところ:
//!
//! - Python は値を 1 つ読むたびに待つ（パネルの入力欄が 8 つなら最長 8 回）。Rust は 1 回の要求で 1 回だけ待つ
//!   （答えは同じ。読めなければどの欄も同じ文の誤り）
//! - 公開トップのサーバー数のフォールバック（設定のあるサーバーの数）は待たない（[`SettingsStore::try_snapshot`]。
//!   Python はイベントループを止めて待つ）。起動の直後だけ、Python なら数が出るところで 0 になりうる
//! - 表は作らない・`settings.json` から取り込まない（Bot の Rust と同じ。表は Python が先に作っている）。
//!   `SETTINGS_BACKEND` が `postgres` でなくても Postgres を読む（Rust はファイルの置き場を持たない）
//! - 書き込みの待ちの上限（`SETTINGS_LOCK_TIMEOUT_SECONDS`）は、Python は書き込み全体に、Rust は排他を取るまでに掛かる
//!   （`SettingsCache` の `lock_timeout`）。切れたときの文は Python と同じにする（[`write_crash`]）
//!
//! テストと基準の突き合わせには、Postgres を使わない置き場（[`SettingsStore::memory`]）を使う。書き換えの規則は
//! 本番と同じ `sycs_core::settings::apply_mutation`、版番号の上げ方（変わったギルド・消えたギルド・guilds 以外の鍵が
//! あるときだけ 1 上げる）は `SettingsCache` の書き込みと同じで、書くたびの版番号を控える（[`SettingsStore::take_writes`]）。

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sycs_core::env::Env;
use sycs_core::settings::{
    CacheOptions, Settings, SettingsCache, WriteError, apply_mutation, now_iso,
};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::apps::getters::NOT_LOADED;
use crate::errors::Crash;
use crate::python;

/// 読み直しの間の上限（`_bootstrap_forever` の 30 秒）。
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// 設定を書き換える関数（排他を持ったまま呼ばれる。待つ処理を中に書かないこと）。戻り値は Python の書き換えの関数が
/// 返すもの（`delete_guild_settings` の消したか、など）。
pub type Mutation = Box<dyn FnOnce(&mut Settings) -> Value + Send>;

/// 設定の置き場の動かし方（環境変数。Bot と同じ名前・同じ読み方）。
#[derive(Clone, Debug, PartialEq)]
pub struct StoreConfig {
    /// 版番号を確かめる間隔（`SETTINGS_PG_POLL_SECONDS`。既定 30 秒、下限 1 秒）。
    pub poll_interval: Duration,
    /// 書き込みの排他を待つ上限（`SETTINGS_LOCK_TIMEOUT_SECONDS`。既定 10 秒、下限 0.2 秒）。
    pub write_timeout: Duration,
    /// 最初の読み込みを待つ上限（`SETTINGS_LOAD_TIMEOUT_SECONDS`。既定 30 秒、下限 1 秒）。
    pub load_timeout: Duration,
}

/// 秒の小数を長さにする（大きすぎる値は止まらずに一番長い長さ）。
fn seconds(value: f64) -> Duration {
    Duration::try_from_secs_f64(value).unwrap_or(Duration::MAX)
}

impl StoreConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        Self {
            poll_interval: seconds(env.float("SETTINGS_PG_POLL_SECONDS", 30.0, Some(1.0), None)),
            write_timeout: seconds(env.float(
                "SETTINGS_LOCK_TIMEOUT_SECONDS",
                10.0,
                Some(0.2),
                None,
            )),
            load_timeout: seconds(env.float(
                "SETTINGS_LOAD_TIMEOUT_SECONDS",
                30.0,
                Some(1.0),
                None,
            )),
        }
    }
}

/// `SettingsNotLoaded` の文（`settings_pg._wait_until_loaded`。秒は `:.0f`）。
pub fn not_loaded_message(load_timeout: Duration) -> String {
    format!(
        "設定を Postgres から {:.0} 秒以内に読み込めませんでした。接続先と、ログの [settings] の警告を確かめてください。",
        load_timeout.as_secs_f64()
    )
}

/// 書き込みの失敗を Python の例外にする（型の名前と `str(exc)`）。
///
/// 待ちきれなかったときは `settings_pg.transact` の `TimeoutError`（「設定の保存が 10 秒以内に終わりませんでした。」。
/// 秒は `:.0f`）。データベースの失敗は利用者の状態の読み出しと同じ名前の付け方（[`crate::users::store::crash_of`]）。
pub fn write_crash(error: &WriteError) -> Crash {
    match error {
        WriteError::Timeout(limit) => Crash::new(
            "TimeoutError",
            format!(
                "設定の保存が {:.0} 秒以内に終わりませんでした。",
                limit.as_secs_f64()
            ),
        ),
        WriteError::Database(e) => crate::users::store::crash_of(e),
    }
}

/// 書き込みを呼んだことのログ（Python の `settings_store.awrite` の `[settings] 関数 guild=…`。値は書かない）。
pub fn log_write(function: &str, guild_id: &str) {
    info!("[settings] {function} guild={guild_id}");
}

/// Postgres を使わない置き場の中身。
struct Memory {
    /// いまの全体（読み込めない置き場は `SettingsNotLoaded` の文）。
    settings: Result<Arc<Settings>, String>,
    /// 押す時刻（`None` ならいまの時刻）。基準と比べるテストは、Python の道具と同じ時刻に決める。
    stamp: Option<String>,
    /// 書くたびの、書いたあとの版番号（読み込めない置き場は 0）。
    writes: Vec<i64>,
}

impl Memory {
    /// `SettingsCache::transact` と同じ規則で書く（読み直し → `apply_mutation` → 変わっていれば版番号を 1 上げる）。
    fn transact(&mut self, mutate: Mutation) -> Result<Value, Crash> {
        let current = match &self.settings {
            Ok(settings) => Arc::clone(settings),
            Err(message) => {
                self.writes.push(0);
                return Err(Crash::new(NOT_LOADED, message.clone()));
            }
        };
        let before: Settings = (*current).clone();
        let mut data = before.clone();
        let now = self.stamp.clone().unwrap_or_else(now_iso);
        let result = apply_mutation(&mut data, &now, mutate);
        data.version = before.version;
        let changed = data
            .guilds
            .iter()
            .any(|(key, value)| before.guilds.get(key) != Some(value));
        let removed = before
            .guilds
            .keys()
            .any(|key| !data.guilds.contains_key(key));
        if changed || removed || data.root != before.root {
            data.version = before.version + 1;
        }
        self.writes.push(data.version);
        self.settings = Ok(Arc::new(data));
        Ok(result)
    }
}

enum Source {
    Memory(Mutex<Memory>),
    Postgres(watch::Receiver<Option<Arc<SettingsCache>>>),
}

/// 設定の置き場。
pub struct SettingsStore {
    source: Source,
    load_timeout: Duration,
}

impl std::fmt::Debug for SettingsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.source {
            Source::Memory(memory) => match Self::memory_settings(memory) {
                Ok(_) => "memory",
                Err(_) => "failing",
            },
            Source::Postgres(_) => "postgres",
        };
        f.debug_struct("SettingsStore")
            .field("source", &kind)
            .field("load_timeout", &self.load_timeout)
            .finish()
    }
}

impl SettingsStore {
    /// 決まった中身（テストと確かめ用。書けば中身が変わる。押す時刻はいまの時刻）。
    pub fn fixed(settings: Settings) -> Self {
        Self::in_memory(Ok(Arc::new(settings)), None)
    }

    /// 決まった中身で始め、書けば変わる置き場（基準と比べるテスト用）。押す時刻は `stamp` に決める。
    pub fn memory(settings: Settings, stamp: &str) -> Self {
        Self::in_memory(Ok(Arc::new(settings)), Some(stamp.to_string()))
    }

    /// いつも読めない置き場（読むたび・書くたびに `message` の `SettingsNotLoaded`）。
    pub fn failing(message: &str) -> Self {
        Self::in_memory(Err(message.to_string()), None)
    }

    fn in_memory(settings: Result<Arc<Settings>, String>, stamp: Option<String>) -> Self {
        Self {
            source: Source::Memory(Mutex::new(Memory {
                settings,
                stamp,
                writes: Vec::new(),
            })),
            load_timeout: Duration::from_secs(30),
        }
    }

    /// どこにもつないでいない置き場（`--self-check` と、設定を使わないテスト）。
    pub fn unconfigured() -> Self {
        Self::failing("設定の置き場につないでいません")
    }

    /// Postgres（Bot と同じ `SettingsCache`）。裏で読み込みを始め、読めるまで繰り返す（待たない）。
    /// tokio の中で呼ぶこと。
    pub fn start_postgres(pool: PgPool, config: &StoreConfig) -> Self {
        let (sender, receiver) = watch::channel(None);
        let options = CacheOptions {
            write_timeout: config.write_timeout,
            ..CacheOptions::new(config.poll_interval)
        };
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                // 読めたときのログ（ギルドの数と版番号）は SettingsCache が残す。
                match SettingsCache::start_with(pool.clone(), options.clone()).await {
                    Ok(cache) => {
                        let _ = sender.send(Some(cache));
                        return;
                    }
                    Err(e) => {
                        warn!(
                            "[settings] Postgres から読み込めませんでした（{} 秒後にやり直します）: {e}",
                            delay.as_secs()
                        );
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                    }
                }
            }
        });
        Self {
            source: Source::Postgres(receiver),
            load_timeout: config.load_timeout,
        }
    }

    fn memory_lock(memory: &Mutex<Memory>) -> std::sync::MutexGuard<'_, Memory> {
        memory.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Postgres を使わない置き場のいまの中身（錠は返す前に外す。async の中で錠を持ち越さない）。
    fn memory_settings(memory: &Mutex<Memory>) -> Result<Arc<Settings>, String> {
        Self::memory_lock(memory).settings.clone()
    }

    /// Postgres を使わない置き場に書く（錠は返す前に外す）。
    fn memory_transact(memory: &Mutex<Memory>, mutate: Mutation) -> Result<Value, Crash> {
        Self::memory_lock(memory).transact(mutate)
    }

    /// 最初の読み込みが済むまで待ち（上限は `SETTINGS_LOAD_TIMEOUT_SECONDS`）、Postgres の置き場を返す。
    async fn loaded_cache(
        &self,
        receiver: &watch::Receiver<Option<Arc<SettingsCache>>>,
    ) -> Option<Arc<SettingsCache>> {
        let mut receiver = receiver.clone();
        let waited =
            tokio::time::timeout(self.load_timeout, receiver.wait_for(Option::is_some)).await;
        match waited {
            Ok(Ok(cache)) => (*cache).clone(),
            _ => None,
        }
    }

    /// いまの設定の全体。最初の読み込みが済むまでは待つ（上限は `SETTINGS_LOAD_TIMEOUT_SECONDS`）。
    pub async fn snapshot(&self) -> Result<Arc<Settings>, String> {
        match &self.source {
            Source::Memory(memory) => Self::memory_settings(memory),
            Source::Postgres(receiver) => {
                let loaded = self.loaded_cache(receiver).await;
                loaded
                    .map(|cache| cache.snapshot())
                    .ok_or_else(|| not_loaded_message(self.load_timeout))
            }
        }
    }

    /// 待たずに読む（読み込めていなければ `SettingsNotLoaded` の文）。
    pub fn try_snapshot(&self) -> Result<Arc<Settings>, String> {
        match &self.source {
            Source::Memory(memory) => Self::memory_settings(memory),
            Source::Postgres(receiver) => {
                let loaded = (*receiver.borrow()).as_ref().map(|cache| cache.snapshot());
                loaded.ok_or_else(|| not_loaded_message(self.load_timeout))
            }
        }
    }

    /// 設定を書き換える（Python の `settings_store._mutate_settings`）。読み込めていなければ、読むときと同じだけ待って
    /// `SettingsNotLoaded`。書けたら、次に読む人はすぐ新しい中身を読む（通知を待たない）。
    pub async fn transact(&self, mutate: Mutation) -> Result<Value, Crash> {
        match &self.source {
            Source::Memory(memory) => Self::memory_transact(memory, mutate),
            Source::Postgres(receiver) => {
                let Some(cache) = self.loaded_cache(receiver).await else {
                    return Err(Crash::new(
                        NOT_LOADED,
                        not_loaded_message(self.load_timeout),
                    ));
                };
                cache
                    .transact(mutate)
                    .await
                    .map_err(|e| write_crash(&e))
            }
        }
    }

    /// Postgres を使わない置き場に書いた、書くたびの版番号（書いたあとの版。変わらなければ前と同じ。読み込めない
    /// 置き場は 0）。取り出すと空になる。Postgres の置き場は控えないので、いつも空。
    pub fn take_writes(&self) -> Vec<i64> {
        match &self.source {
            Source::Memory(memory) => std::mem::take(&mut Self::memory_lock(memory).writes),
            Source::Postgres(_) => Vec::new(),
        }
    }
}

/// 環境変数から置き場を作る（Bot と同じ接続先 `sycs_core::db::user_state_url`。つなぐのは最初に使うとき）。
///
/// 接続先が読めないときは、読むたびにその理由で失敗する置き場にする（管理画面はほかの画面のために起動を続ける。
/// Python も設定を読むところだけが失敗する）。
pub fn from_env(env: &Env) -> SettingsStore {
    let backend = env.string("SETTINGS_BACKEND", "file").to_lowercase();
    if backend != "postgres" {
        warn!(
            "SETTINGS_BACKEND={backend} ですが、Rust の管理画面は Postgres の設定（bot_settings_guild）だけを読みます"
        );
    }
    let config = StoreConfig::from_env(env);
    match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy(&sycs_core::db::user_state_url(env))
    {
        Ok(pool) => SettingsStore::start_postgres(pool, &config),
        Err(e) => {
            error!("設定のデータベースの接続先が読めません: {e}");
            SettingsStore::failing(&format!("設定のデータベースの接続先が読めません: {e}"))
        }
    }
}

/// 設定のあるサーバーの数（`len(settings_store.get_all_guild_ids())`。鍵を `int()` できるものだけ数える）。
pub fn guild_count(settings: &Settings) -> usize {
    settings
        .guilds
        .keys()
        .filter(|key| python::int_text(&Value::String((*key).clone())).is_some())
        .count()
}

/// `{"guilds": {鍵: 設定}}` の形の JSON から設定の全体を作る（基準の例とテスト用。ほかの鍵は root に入れる）。
pub fn settings_from_document(document: &Value) -> Settings {
    let mut settings = Settings::default();
    if let Value::Object(map) = document {
        for (key, value) in map {
            if key == "guilds" {
                if let Value::Object(guilds) = value {
                    for (guild, data) in guilds {
                        settings.guilds.insert(guild.clone(), data.clone());
                    }
                }
            } else {
                settings.root.insert(key.clone(), value.clone());
            }
        }
    }
    settings
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 読み込めないときの文が Python と同じ書き方であること（秒は四捨五入した整数。Python の `:.0f` と同じ偶数への丸め）。
    #[test]
    fn the_not_loaded_message_matches_python() {
        let source = include_str!("../../../../../services/settings_pg.py");
        assert!(source.contains(
            "f\"設定を Postgres から {self._load_timeout:.0f} 秒以内に読み込めませんでした。\""
        ));
        assert!(source.contains("\"接続先と、ログの [settings] の警告を確かめてください。\""));
        assert_eq!(
            not_loaded_message(Duration::from_secs(30)),
            "設定を Postgres から 30 秒以内に読み込めませんでした。接続先と、ログの [settings] の警告を確かめてください。"
        );
        assert!(not_loaded_message(Duration::from_secs_f64(2.5)).contains(" 2 秒"));
    }

    /// 書き込みが待ちきれなかったときの文が、Python の `transact` の `TimeoutError` と同じ書き方であること。
    #[test]
    fn the_write_timeout_message_matches_python() {
        let source = include_str!("../../../../../services/settings_pg.py");
        assert!(source.contains(
            "raise TimeoutError(f\"設定の保存が {self._write_timeout:.0f} 秒以内に終わりませんでした。\")"
        ));
        let crash = write_crash(&WriteError::Timeout(Duration::from_secs(10)));
        assert_eq!(
            crash,
            Crash::new(
                "TimeoutError",
                "設定の保存が 10 秒以内に終わりませんでした。"
            )
        );
    }

    /// 設定のあるサーバーの数は、`int()` できる鍵だけ（空白・全角の数字も数え、文字は数えない）。
    #[test]
    fn stored_guilds_are_counted_like_get_all_guild_ids() {
        let settings = settings_from_document(&json!({
            "guilds": {"1": {}, " 2": {}, "３": {}, "x": {}, "-4": null},
            "other": 1
        }));
        assert_eq!(guild_count(&settings), 4);
        assert_eq!(settings.root.get("other"), Some(&json!(1)));
    }

    /// 決まった中身の置き場は、待たずに同じものを返し、読めない置き場はその文を返すこと。
    #[tokio::test]
    async fn fixed_stores_answer_at_once() {
        let store = SettingsStore::fixed(settings_from_document(&json!({"guilds": {"1": {}}})));
        assert_eq!(store.snapshot().await.unwrap().guilds.len(), 1);
        assert_eq!(store.try_snapshot().unwrap().guilds.len(), 1);
        let failing = SettingsStore::failing("読めない");
        assert_eq!(failing.snapshot().await.unwrap_err(), "読めない");
        assert_eq!(failing.try_snapshot().unwrap_err(), "読めない");
    }

    /// Postgres を使わない置き場の書き込み: 変われば版番号を 1 上げて時刻を押し、変わらなければ上げず、次に読む人は
    /// 書いたあとの中身を読む。読めない置き場は `SettingsNotLoaded` で、版番号の控えは 0。
    #[tokio::test]
    async fn memory_stores_write_like_the_settings_cache() {
        let mut settings = settings_from_document(&json!({"guilds": {"1": {"a": 1}}}));
        settings.version = 4;
        let store = SettingsStore::memory(settings, "STAMP");
        let set = |value: i64| -> Mutation {
            Box::new(move |data: &mut Settings| {
                let guild = data.guilds.get_mut("1").and_then(Value::as_object_mut);
                if let Some(guild) = guild {
                    guild.insert("a".to_string(), json!(value));
                }
                json!("done")
            })
        };
        assert_eq!(store.transact(set(2)).await, Ok(json!("done")));
        assert_eq!(store.transact(set(2)).await, Ok(json!("done")));
        let now = store.snapshot().await.unwrap();
        assert_eq!(now.guilds["1"], json!({"a": 2, "_updated_at": "STAMP"}));
        assert_eq!(now.version, 5);
        assert_eq!(store.take_writes(), [5, 5]);
        assert!(store.take_writes().is_empty());
        let removed = store
            .transact(Box::new(|data: &mut Settings| {
                json!(data.guilds.remove("1").is_some())
            }))
            .await;
        assert_eq!(removed, Ok(json!(true)));
        assert_eq!(store.take_writes(), [6]);
        let failing = SettingsStore::failing("読めない");
        let crash = failing.transact(set(1)).await.unwrap_err();
        assert_eq!(crash, Crash::new(NOT_LOADED, "読めない"));
        assert_eq!(failing.take_writes(), [0]);
    }

    /// 環境変数の読み方（Bot と同じ名前・既定・下限）。
    #[test]
    fn the_config_is_read_like_python() {
        let defaults = StoreConfig::from_env(&Env::from_fn(|_| None));
        assert_eq!(defaults.poll_interval, Duration::from_secs(30));
        assert_eq!(defaults.write_timeout, Duration::from_secs(10));
        assert_eq!(defaults.load_timeout, Duration::from_secs(30));
        let short = StoreConfig::from_env(&Env::from_fn(|key| {
            Some(
                match key {
                    "SETTINGS_PG_POLL_SECONDS" => "0.1",
                    "SETTINGS_LOCK_TIMEOUT_SECONDS" => "0.01",
                    _ => "0",
                }
                .to_string(),
            )
        }));
        assert_eq!(short.poll_interval, Duration::from_secs(1));
        assert_eq!(short.write_timeout, Duration::from_millis(200));
        assert_eq!(short.load_timeout, Duration::from_secs(1));
    }
}
