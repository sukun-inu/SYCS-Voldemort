//! 設定の置き場（読む側）。Bot と同じ `sycs_core::settings::SettingsCache`（Postgres の `bot_settings_guild`・
//! `bot_settings_state`。変更は LISTEN と版番号で追う）を使い回す。
//!
//! Python の管理画面（`settings_store.start_backend` → `settings_pg.PostgresSettings`）と同じ動き:
//!
//! - 起動では待たない。裏で読み込みを始め、読めるまで間を空けて繰り返す（1 秒から倍にして 30 秒まで。
//!   `_bootstrap_forever`）
//! - 読む人は、最初の読み込みが済むまで `SETTINGS_LOAD_TIMEOUT_SECONDS`（既定 30 秒、下限 1 秒）待つ。待ちきれなければ
//!   `SettingsNotLoaded`（「設定を Postgres から 30 秒以内に読み込めませんでした。…」）
//!
//! Python と違うところ:
//!
//! - Python は値を 1 つ読むたびに待つ（パネルの入力欄が 8 つなら最長 8 回）。Rust は 1 回の要求で 1 回だけ待つ
//!   （答えは同じ。読めなければどの欄も同じ文の誤り）
//! - 公開トップのサーバー数のフォールバック（設定のあるサーバーの数）は待たない（[`SettingsStore::try_snapshot`]。
//!   Python はイベントループを止めて待つ）。起動の直後だけ、Python なら数が出るところで 0 になりうる
//! - 表は作らない・`settings.json` から取り込まない（Bot の Rust と同じ。表は Python が先に作っている）。
//!   `SETTINGS_BACKEND` が `postgres` でなくても Postgres を読む（Rust はファイルの置き場を持たない）

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sycs_core::env::Env;
use sycs_core::settings::{CacheOptions, Settings, SettingsCache};
use tokio::sync::watch;
use tracing::{error, warn};

use crate::python;

/// 読み直しの間の上限（`_bootstrap_forever` の 30 秒）。
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// 設定の置き場の動かし方（環境変数。Bot と同じ名前・同じ読み方）。
#[derive(Clone, Debug, PartialEq)]
pub struct StoreConfig {
    /// 版番号を確かめる間隔（`SETTINGS_PG_POLL_SECONDS`。既定 30 秒、下限 1 秒）。
    pub poll_interval: Duration,
    /// 書き込みの排他を待つ上限（`SETTINGS_LOCK_TIMEOUT_SECONDS`。既定 10 秒、下限 0.2 秒。A6 が書く）。
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

enum Source {
    Fixed(Result<Arc<Settings>, String>),
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
            Source::Fixed(Ok(_)) => "fixed",
            Source::Fixed(Err(_)) => "failing",
            Source::Postgres(_) => "postgres",
        };
        f.debug_struct("SettingsStore")
            .field("source", &kind)
            .field("load_timeout", &self.load_timeout)
            .finish()
    }
}

impl SettingsStore {
    /// 決まった中身（テストと確かめ用）。
    pub fn fixed(settings: Settings) -> Self {
        Self {
            source: Source::Fixed(Ok(Arc::new(settings))),
            load_timeout: Duration::from_secs(30),
        }
    }

    /// いつも読めない置き場（読むたびに `message` の `SettingsNotLoaded`）。
    pub fn failing(message: &str) -> Self {
        Self {
            source: Source::Fixed(Err(message.to_string())),
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

    /// いまの設定の全体。最初の読み込みが済むまでは待つ（上限は `SETTINGS_LOAD_TIMEOUT_SECONDS`）。
    pub async fn snapshot(&self) -> Result<Arc<Settings>, String> {
        match &self.source {
            Source::Fixed(result) => result.clone(),
            Source::Postgres(receiver) => {
                let mut receiver = receiver.clone();
                let waited =
                    tokio::time::timeout(self.load_timeout, receiver.wait_for(Option::is_some))
                        .await;
                let loaded = match waited {
                    Ok(Ok(cache)) => (*cache).as_ref().map(|cache| cache.snapshot()),
                    _ => None,
                };
                loaded.ok_or_else(|| not_loaded_message(self.load_timeout))
            }
        }
    }

    /// 待たずに読む（読み込めていなければ `SettingsNotLoaded` の文）。
    pub fn try_snapshot(&self) -> Result<Arc<Settings>, String> {
        match &self.source {
            Source::Fixed(result) => result.clone(),
            Source::Postgres(receiver) => {
                let loaded = (*receiver.borrow()).as_ref().map(|cache| cache.snapshot());
                loaded.ok_or_else(|| not_loaded_message(self.load_timeout))
            }
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
        assert!(source.contains("f\"設定を Postgres から {self._load_timeout:.0f} 秒以内に読み込めませんでした。\""));
        assert!(source.contains("\"接続先と、ログの [settings] の警告を確かめてください。\""));
        assert_eq!(
            not_loaded_message(Duration::from_secs(30)),
            "設定を Postgres から 30 秒以内に読み込めませんでした。接続先と、ログの [settings] の警告を確かめてください。"
        );
        assert!(not_loaded_message(Duration::from_secs_f64(2.5)).contains(" 2 秒"));
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
