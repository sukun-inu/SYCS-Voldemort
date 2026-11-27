//! `/greeting`（入退室のあいさつ）と `/vcnotify`（VC の入退室通知）。Python の
//! `commands/server/welcome_goodbye.py`・`commands/server/vcnotify.py`。
//!
//! 書く先はサーバーの設定の `welcome`・`goodbye`（`channel_id` と `message`）と `vc_notify_channel_id`。
//! 読むのは [`crate::welcome`]（参加・退出のとき）と [`crate::vc_notify`]（VC の出入りのとき）。

use serde_json::{Map, Value, json};
use serenity::all::CreateEmbed;
use sycs_core::settings::Settings;

use super::python::dict_setting;
use super::{child, guild_entry};
use crate::commands::reply::Reply;
use crate::commands::settings::{python_truthy, update_guild};
use crate::commands::{CommandError, overview};
use crate::log_channel::python_str;
use crate::welcome::Kind;

/// `/greeting status` の Embed の色（discord.py の `Color.green()`）。
pub const GREEN: u32 = 0x2E_CC_71;

/// 設定の鍵（`welcome`・`goodbye`）。[`crate::welcome::settings_for`] が読む鍵と同じ。
fn key(kind: Kind) -> &'static str {
    match kind {
        Kind::Welcome => "welcome",
        Kind::Goodbye => "goodbye",
    }
}

/// 返事の文に出す呼び名。
fn label(kind: Kind) -> &'static str {
    match kind {
        Kind::Welcome => "ウェルカム",
        Kind::Goodbye => "グッバイ",
    }
}

/// `/greeting welcome channel`・`/greeting goodbye channel`: 送り先を決める。Python の `set_welcome_channel`・
/// `set_goodbye_channel`（`_update_nested`。文面はそのまま残す）。
pub fn set_channel(settings: &mut Settings, guild_id: u64, kind: Kind, channel_id: u64) -> Reply {
    child(guild_entry(settings, guild_id), key(kind))
        .insert("channel_id".into(), json!(channel_id));
    Reply::ephemeral(format!(
        "<#{channel_id}> を{}チャンネルと定めた。",
        label(kind)
    ))
}

/// `/greeting welcome message`・`/greeting goodbye message`: 文面を決める。Python の `set_welcome_message`・
/// `set_goodbye_message`。
///
/// 差し込みの名前（`{user}` など）は確かめない（送るときは置き換えるだけなので、知らない名前はそのまま出る）。
pub fn set_message(settings: &mut Settings, guild_id: u64, kind: Kind, message: &str) -> Reply {
    child(guild_entry(settings, guild_id), key(kind)).insert("message".into(), json!(message));
    Reply::ephemeral(format!("{}メッセージを定めた。\n> {message}", label(kind)))
}

/// `/greeting status`: いまのあいさつの設定。管理者でなくても見られる。Python の `welcome_settings_cmd`。
pub fn status(guild: Option<&Value>, admin_site_url: &str) -> Result<Reply, CommandError> {
    let welcome = dict_setting(guild, "welcome")?;
    let goodbye = dict_setting(guild, "goodbye")?;
    // Python の `f"<#{s.get('channel_id')}>" if s.get("channel_id") else "未設定"`。
    let channel = |block: &Map<String, Value>| match block.get("channel_id") {
        Some(id) if python_truthy(Some(id)) => format!("<#{}>", python_str(id)),
        _ => "未設定".to_string(),
    };
    // Python の `s.get("message") or "(デフォルト)"`。
    let message = |block: &Map<String, Value>| match block.get("message") {
        Some(text) if python_truthy(Some(text)) => python_str(text),
        _ => "(デフォルト)".to_string(),
    };
    let embed = CreateEmbed::new()
        .title("ウェルカム/グッバイ設定")
        .colour(GREEN)
        .field("ウェルカムチャンネル", channel(welcome), true)
        .field("ウェルカムメッセージ", message(welcome), false)
        .field("グッバイチャンネル", channel(goodbye), true)
        .field("グッバイメッセージ", message(goodbye), false);
    Ok(Reply {
        content: None,
        embeds: vec![embed],
        components: overview::admin_site_row(admin_site_url),
        ephemeral: true,
    })
}

/// 設定の鍵: VC の通知を送るチャンネル。[`crate::vc_notify`] が読む鍵と同じ。
pub const VC_NOTIFY_KEY: &str = "vc_notify_channel_id";

/// `/vcnotify set`: VC の通知を送るチャンネルを決める。Python の `set_vc_notify_channel_id`。
pub fn vc_notify_set(settings: &mut Settings, guild_id: u64, channel_id: u64) -> Reply {
    update_guild(settings, guild_id, [(VC_NOTIFY_KEY, json!(channel_id))]);
    Reply::ephemeral(format!("<#{channel_id}> をVC通知チャンネルと定めた。"))
}

/// `/vcnotify clear`: VC の通知を止める（null を書く。保存のときに鍵ごと落ちる）。
pub fn vc_notify_clear(settings: &mut Settings, guild_id: u64) -> Reply {
    update_guild(settings, guild_id, [(VC_NOTIFY_KEY, Value::Null)]);
    Reply::ephemeral("VC通知チャンネルを解除した。")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::welcome;

    /// コマンドが書いたものを、あいさつを送る側（[`crate::welcome`]）がそのまま読めること。
    #[test]
    fn what_the_command_writes_is_what_the_greeter_reads() {
        for kind in [Kind::Welcome, Kind::Goodbye] {
            let mut settings = Settings::default();
            set_channel(&mut settings, 7, kind, 123);
            set_message(&mut settings, 7, kind, "やあ {user}");
            assert_eq!(
                welcome::settings_for(settings.guild(7), kind),
                (Some(123), "やあ {user}".to_string()),
                "{kind:?}"
            );
        }
    }

    /// 歓迎とお別れは別の鍵に書くこと（取り違えると、退出のときに歓迎の文が出る）。
    #[test]
    fn welcome_and_goodbye_are_separate() {
        let mut settings = Settings::default();
        set_channel(&mut settings, 7, Kind::Welcome, 1);
        set_message(&mut settings, 7, Kind::Goodbye, "さらば");
        assert_eq!(
            settings.guilds["7"],
            json!({"welcome": {"channel_id": 1}, "goodbye": {"message": "さらば"}})
        );
    }

    /// VC の通知の鍵が、通知する側（[`crate::vc_notify`]）の読む鍵と同じであること。
    #[test]
    fn the_vc_notify_key_is_the_one_the_notifier_reads() {
        let source = include_str!("../../vc_notify.rs");
        assert!(source.contains(&format!("int_of(\"{VC_NOTIFY_KEY}\")")));
        let mut settings = Settings::default();
        vc_notify_set(&mut settings, 7, 500);
        assert_eq!(settings.guilds["7"], json!({VC_NOTIFY_KEY: 500}));
        vc_notify_clear(&mut settings, 7);
        assert_eq!(settings.guilds["7"], json!({VC_NOTIFY_KEY: null}));
    }
}
