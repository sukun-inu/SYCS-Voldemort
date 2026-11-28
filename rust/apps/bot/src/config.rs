//! Bot の設定。すべて環境変数から読む（読み方は `sycs_core::env`、Python の envutil と同じ規則）。
//!
//! 変数の名前は Python の Bot と同じにしてある。切り替えるときに compose の環境変数を
//! そのまま渡せるようにするため。

use std::path::PathBuf;
use std::time::Duration;

use serenity::all::GatewayIntents;
use sycs_core::env::Env;

use crate::commands::overview::DEFAULT_ADMIN_SITE_URL;
use crate::groq::GroqConfig;
use crate::message_security::DEFAULT_SCAN_CONCURRENCY;
use crate::metal::MetalConfig;
use crate::news::NewsConfig;
use crate::user_state::UserStateConfig;
use crate::user_state_sync::SyncConfig as UserStateSyncConfig;
use crate::virustotal::VtConfig;

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
    /// このサーバーのイベントだけを扱う（`BOT_ONLY_GUILD_ID`）。未設定なら全部。
    ///
    /// **本番の Bot のトークンで手元から確かめるときの柵。** 本番の Bot は複数のサーバーに
    /// 入っているので、絞らないと、確かめている間に他のサーバーの出入りへ反応して、本番の
    /// 利用者がいるチャンネルへ書いてしまう。本番では設定しない。
    pub only_guild_id: Option<u64>,
    /// 常駐の仕事（スティッキーの巡回・ニュース・地震の電文の受け取り）をこのプロセスが持つか
    /// （`BOT_BACKGROUND_WORKER`、既定は真）。
    ///
    /// Python の Bot と同じ変数。Bot を複数並べるときは 1 つだけ真にする（全部が受け取ると、同じ地震を
    /// 台数ぶん通知する）。**本番の Python の Bot と並べて動かすときも偽にすること**（二重に通知する）。
    pub background_worker: bool,
    /// 利用者の状態の記録（履歴を残す日数・掃除の間隔）。
    pub user_state: UserStateConfig,
    /// 利用者の状態の同期・定期の修復・Bot が抜けたサーバーの設定の掃除（`USER_STATE_SYNC_ON_READY` など）。
    ///
    /// Python と同じく `BOT_BACKGROUND_WORKER` では止まらない。**本番の Python の Bot と並べて動かすときは
    /// `USER_STATE_SYNC_ON_READY` と `USER_STATE_AUTO_REPAIR_ENABLED` を偽にすること**（同じ表へ両方が同期を
    /// 書き、起動のたびに同期の履歴が二重に積まれる）。
    pub user_state_sync: UserStateSyncConfig,
    /// スラッシュコマンドに応えるか（`BOT_COMMANDS_ENABLED`、既定は応える）。
    ///
    /// **本番の Python の Bot と並べて動かすときは偽にすること。** 同じトークンで 2 つつなぐと、打たれた
    /// コマンドは両方に届く。両方が応えると片方の応答が失敗し、設定を書くコマンドは二重に書く。
    pub commands_enabled: bool,
    /// 起動時にスラッシュコマンドの定義を Discord に登録し直すか（`BOT_SYNC_COMMANDS`、既定はしない）。
    ///
    /// 登録は全体の置き換え。Python の Bot は起動のたびに行っている。Rust の Bot は、切り替え（B11）で
    /// 既定を「する」に変える。それまでは、確かめたいときだけ明示して使う。
    pub sync_commands: bool,
    /// 管理画面の場所（`ADMIN_SITE_URL`。`/bot settings`・`/bot help` のリンクのボタン）。
    pub admin_site_url: String,
    /// VirusTotal（鍵・待ち時間・上限）。
    pub vt: VtConfig,
    /// VirusTotal を同時に走らせる数（`VT_SCAN_CONCURRENCY`、既定 4・下限 1）。
    pub vt_scan_concurrency: usize,
    /// Groq（鍵・同時に送る数・間隔・再試行）。
    pub groq: GroqConfig,
    /// ニュース（要約のモデル）。
    pub news: NewsConfig,
    /// 投稿の判定を覚えておく秒数（`MODERATION_CACHE_TTL_SECONDS`、既定 300・下限 10）。
    pub moderation_cache_ttl: f64,
    /// 貴金属の値段の API（鍵・覚えておく秒数・場所）。
    pub metal: MetalConfig,
    /// 貴金属トラッカーの場所（`METALS_SITE_URL`。/metal のリンクのボタン。末尾の `/` は 1 つにそろえる）。
    pub metals_site_url: String,
    /// 合成の API の場所（`TTS_BASE_URL`。既定 `http://localhost:8080`。末尾の `/` は落とす）。
    pub tts_base_url: String,
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
            only_guild_id: u64::try_from(env.int("BOT_ONLY_GUILD_ID", 0, Some(0), None))
                .ok()
                .filter(|id| *id > 0),
            background_worker: env.boolean("BOT_BACKGROUND_WORKER", true),
            user_state: UserStateConfig::from_env(env),
            user_state_sync: UserStateSyncConfig::from_env(env),
            commands_enabled: env.boolean("BOT_COMMANDS_ENABLED", true),
            sync_commands: env.boolean("BOT_SYNC_COMMANDS", false),
            admin_site_url: env.string("ADMIN_SITE_URL", DEFAULT_ADMIN_SITE_URL),
            vt: VtConfig::from_env(env),
            vt_scan_concurrency: usize::try_from(env.int(
                "VT_SCAN_CONCURRENCY",
                DEFAULT_SCAN_CONCURRENCY as i64,
                Some(1),
                None,
            ))
            .unwrap_or(1),
            groq: GroqConfig::from_env(env),
            news: NewsConfig::from_env(env),
            moderation_cache_ttl: env.int("MODERATION_CACHE_TTL_SECONDS", 300, Some(10), None)
                as f64,
            metal: MetalConfig::from_env(env),
            metals_site_url: crate::commands::metal::normalize_site_url(
                env.raw("METALS_SITE_URL").as_deref(),
            ),
            tts_base_url: env
                .raw("TTS_BASE_URL")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| crate::tts::DEFAULT_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// このサーバーのイベントを扱うか。
    pub fn handles(&self, guild_id: u64) -> bool {
        self.only_guild_id.is_none_or(|only| only == guild_id)
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
        assert!(c.background_worker);
        assert_eq!(c.only_guild_id, None);
        assert_eq!(c.user_state, UserStateConfig::default());
        assert_eq!(c.user_state_sync, UserStateSyncConfig::default());
        assert!(c.handles(1) && c.handles(2));
        assert!(c.commands_enabled, "切り替えたら既定でコマンドに応える");
        assert!(
            !c.sync_commands,
            "切り替え（B11）までは、明示しない限り登録し直さない"
        );
        assert_eq!(
            c.admin_site_url,
            "https://vol.kawasaki-n3t.f5.si/admin/login"
        );
        let moved = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("ADMIN_SITE_URL", "https://admin.example/login"),
        ]))
        .unwrap();
        assert_eq!(moved.admin_site_url, "https://admin.example/login");
        assert_eq!(c.vt_scan_concurrency, 4);
        assert_eq!(c.moderation_cache_ttl, 300.0);
        assert_eq!(c.vt.api_key, None);
        assert_eq!(c.groq.api_key, None);
        assert_eq!(c.metal.api_key, None);
        assert_eq!(c.metal.cache_ttl_seconds, 1800.0);
        assert_eq!(c.metals_site_url, "https://metals.kawasaki-n3t.f5.si/");
        assert_eq!(c.tts_base_url, "http://localhost:8080");
        let tts = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("TTS_BASE_URL", "http://tts.example:9000//"),
        ]))
        .unwrap();
        assert_eq!(tts.tts_base_url, "http://tts.example:9000");
        let short = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("SETTINGS_LOCK_TIMEOUT_SECONDS", "0.01"),
        ]))
        .unwrap();
        assert_eq!(short.settings_write_timeout, Duration::from_millis(200));
        let low = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("VT_SCAN_CONCURRENCY", "0"),
            ("MODERATION_CACHE_TTL_SECONDS", "1"),
        ]))
        .unwrap();
        assert_eq!(
            (low.vt_scan_concurrency, low.moderation_cache_ttl),
            (1, 10.0)
        );
    }

    /// BOT_ONLY_GUILD_ID を設定したら、そのサーバーのイベントだけを扱うこと。
    #[test]
    fn only_guild_limits_the_handled_guilds() {
        let c = BotConfig::from_env(&env(&[
            ("DISCORD_BOT_TOKEN", "t"),
            ("BOT_ONLY_GUILD_ID", "1399617700363370556"),
        ]))
        .unwrap();
        assert!(c.handles(1_399_617_700_363_370_556));
        assert!(!c.handles(701_798_768_294_756_383));
        // 0 と読めない値は「絞らない」。
        for v in ["0", "abc"] {
            let c = BotConfig::from_env(&env(&[
                ("DISCORD_BOT_TOKEN", "t"),
                ("BOT_ONLY_GUILD_ID", v),
            ]))
            .unwrap();
            assert_eq!(c.only_guild_id, None, "{v}");
        }
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
