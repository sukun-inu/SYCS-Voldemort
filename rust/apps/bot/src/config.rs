//! Bot の設定。すべて環境変数から読む（読み方は `sycs_core::env`、Python の envutil と同じ規則）。
//!
//! 変数の名前は Python の Bot と同じにしてある。切り替えるときに compose の環境変数を
//! そのまま渡せるようにするため。

use std::path::PathBuf;
use std::time::Duration;

use serenity::all::GatewayIntents;
use sycs_core::env::Env;

/// Bot を動かすのに要る設定。
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Discord のトークン。
    pub token: String,
    /// ログのファイル名とメトリクスのアプリ名（`bot` なら `bot.log` と `sycs_up{app="bot"}`）。
    ///
    /// 既定は Python の Bot と同じ `bot`。切り替えたときに、管理画面のログの画面と
    /// Netdata の系列がそのまま続くようにするため。手元で育てている間は `bot-rs` にして、
    /// 本番の Python の Bot と混ざらないようにする。
    pub process_name: String,
    /// Valkey（メトリクスの送り先）。未設定なら送らない。
    pub valkey_url: Option<String>,
    /// メトリクスを送る間隔。
    pub metrics_interval: Duration,
    /// 設定の版番号を確かめる間隔（LISTEN を取りこぼしたときの保険）。
    pub settings_poll_interval: Duration,
    /// 起動時に設定を読めるまで待つ時間。過ぎたら止まる（空の設定では動かない）。
    pub settings_load_timeout: Duration,
    /// 設定を書くときに、他のプロセスの書き込みが終わるのを待つ上限。過ぎたら書かずに諦める。
    pub settings_write_timeout: Duration,
    /// 管理画面から Bot への依頼を取り出すか。
    ///
    /// **本番の Python の Bot と並べて動かすときは偽にすること。** 取り出すと表から消える
    /// ので、Rust 側が取った依頼は Python 側に届かない。
    pub dev_signals_enabled: bool,
}

impl BotConfig {
    /// 環境変数から読む。トークンが無ければ `Err`（それ以外は既定値で埋める）。
    pub fn from_env(env: &Env) -> Result<Self, String> {
        let token = env
            .raw("DISCORD_BOT_TOKEN")
            .ok_or_else(|| "DISCORD_BOT_TOKEN が設定されていません".to_string())?;
        let (_, process_name) = log_target(env);
        Ok(Self {
            token,
            process_name,
            valkey_url: env.raw("VALKEY_URL"),
            metrics_interval: seconds(env.float(
                "METRICS_REPORT_INTERVAL_SECONDS",
                30.0,
                Some(1.0),
                None,
            )),
            settings_poll_interval: seconds(env.float(
                "SETTINGS_PG_POLL_SECONDS",
                30.0,
                Some(1.0),
                None,
            )),
            settings_load_timeout: seconds(env.float(
                "SETTINGS_LOAD_TIMEOUT_SECONDS",
                30.0,
                Some(1.0),
                None,
            )),
            // 名前と既定（10 秒）・下限（0.2 秒）は Python（settings_store）と同じ。
            settings_write_timeout: seconds(env.float(
                "SETTINGS_LOCK_TIMEOUT_SECONDS",
                10.0,
                Some(0.2),
                None,
            )),
            dev_signals_enabled: env.boolean("BOT_DEV_SIGNALS_ENABLED", true),
        })
    }
}

/// ログの置き場とプロセスの名前。トークンが無くても決まる（無いことをログに残してから止まるため）。
pub fn log_target(env: &Env) -> (PathBuf, String) {
    let settings_dir = env.path("SETTINGS_DIR", "/app/data");
    (
        settings_dir.join("logs"),
        env.string("BOT_PROCESS_NAME", "bot"),
    )
}

fn seconds(value: f64) -> Duration {
    Duration::from_secs_f64(value)
}

/// Discord へ申し出る intent。Python の Bot（bot_setup.create_bot）と同じ組み合わせ。
///
/// discord.py の `Intents.default()` は特権の要らないもの全部。そこへ message_content
/// （チャットの応答・スパムの検査）と members（入退室のログ）を足している。intent は
/// Discord の開発者ポータル側でも有効にしておく必要があり、片方だけだと該当のイベントが
/// 黙って届かない（例外は出ない）。
pub fn intents() -> GatewayIntents {
    GatewayIntents::non_privileged()
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::MESSAGE_CONTENT
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    /// トークンが無ければ起動しないこと（空文字も無いのと同じ）。
    #[test]
    fn a_missing_or_empty_token_is_an_error() {
        assert!(BotConfig::from_env(&env(&[])).is_err());
        assert!(BotConfig::from_env(&env(&[("DISCORD_BOT_TOKEN", "  ")])).is_err());
    }

    /// 既定値が Python の Bot と同じであること。
    ///
    /// 名前が違うと、切り替えた瞬間に管理画面のログの画面と Netdata の系列が途切れる。
    #[test]
    fn the_defaults_match_the_python_bot() {
        let c = BotConfig::from_env(&env(&[("DISCORD_BOT_TOKEN", "t")])).unwrap();
        assert_eq!(c.process_name, "bot");
        assert_eq!(log_target(&env(&[])).0, PathBuf::from("/app/data/logs"));
        assert_eq!(c.metrics_interval, Duration::from_secs(30));
        assert_eq!(c.settings_write_timeout, Duration::from_secs(10));
        assert!(c.dev_signals_enabled);
        let short = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("SETTINGS_LOCK_TIMEOUT_SECONDS", "0.01"),
        ]))
        .unwrap();
        assert_eq!(short.settings_write_timeout, Duration::from_millis(200));
    }

    /// 特権の intent は members と message_content だけで、presences は申し出ないこと。
    ///
    /// presences は使っていない。申し出ると、Discord の審査（100 サーバーを超えたとき）で
    /// 理由を説明しなければならない。
    #[test]
    fn only_members_and_message_content_are_privileged() {
        let i = intents();
        assert!(i.contains(GatewayIntents::GUILD_MEMBERS));
        assert!(i.contains(GatewayIntents::MESSAGE_CONTENT));
        assert!(!i.contains(GatewayIntents::GUILD_PRESENCES));
        assert!(i.contains(GatewayIntents::GUILD_VOICE_STATES));
        assert!(i.contains(GatewayIntents::GUILD_MODERATION));
        assert!(i.contains(GatewayIntents::GUILD_MESSAGE_REACTIONS));
    }
}
