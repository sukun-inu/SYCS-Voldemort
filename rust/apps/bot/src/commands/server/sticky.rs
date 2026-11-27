//! `/sticky`（チャンネルの一番下に貼り付けるメッセージ）。Python の `commands/server/sticky.py` と、
//! `services/settings_store.py` の `set_sticky_message`・`remove_sticky_message`、
//! `services/sticky_service.py` の `delete_sticky`。
//!
//! set と clear は、コマンドが打たれたチャンネルに効く（テキストチャンネルでだけ使える）。どちらも**返事を
//! 返してから**、貼る・剥がす（Discord への送信が遅くても、3 秒の応答期限に響かないように）。貼る側の本体は
//! [`crate::sticky`]（発言のたびの貼り直しと同じ排他を通る）。

use serde_json::{Value, json};
use serenity::all::{ChannelId, Http, MessageId};
use sycs_core::settings::{Settings, SettingsCache};
use tracing::warn;

use super::python::{dict_setting, first_chars};
use super::{child, guild_entry};
use crate::commands::CommandError;
use crate::commands::reply::{MESSAGE_BUDGET, Reply, cap_list_for_message};

/// テキストチャンネルでないところで set・clear を打ったときの文。
pub const TEXT_CHANNEL_ONLY: &str = "テキストチャンネルでのみ使えるぞ。";
/// `/sticky clear` の返事（剥がすのは、これを返したあと）。
pub const CLEARED: &str = "スティッキーメッセージを取り除いた。";
/// 設定の鍵。[`crate::sticky`] が読む鍵と同じ。
const TABLE: &str = "sticky_messages";
/// 一覧で、内容を何文字まで出すか。
const LIST_CONTENT_CHARS: usize = 50;
/// 一覧に並べる件数の上限（文字数の上限とは別に）。
const LIST_LIMIT: usize = 25;

/// `/sticky set` の書き込み。Python の `set_sticky_message`。
///
/// 内容を差し替え、「貼り直す」の指示（`pending: "post"`）を立てる。置いてある固定メッセージの ID は残す
/// （貼り直すときに、それを消すため）。そのチャンネルの設定にあったほかの鍵は残さない。
///
/// 内容の中の `\n`（バックスラッシュと n の 2 文字）は改行にする。コマンドの入力欄では改行を打ちにくいための
/// 救済（Python の `content.replace("\\n", "\n")`）。
pub fn set(settings: &mut Settings, guild_id: u64, channel_id: u64, content: &str) -> Reply {
    let table = child(guild_entry(settings, guild_id), TABLE);
    let key = channel_id.to_string();
    let message_id = table
        .get(&key)
        .and_then(Value::as_object)
        .and_then(|entry| entry.get("message_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let entry = json!({
        "content": content.replace("\\n", "\n"),
        "message_id": message_id,
        "pending": "post",
    });
    table.insert(key, entry);
    Reply::ephemeral("スティッキーメッセージを刻んだ。")
}

/// 設定から外す。Python の `remove_sticky_message`（/sticky clear が、固定メッセージを消したあとで呼ぶ）。
///
/// **表が無くても、空の表を作って残す**（Python が、取り出した表を必ず書き戻すため）。表が辞書でなければ
/// 触らない。
pub fn remove(settings: &mut Settings, guild_id: u64, channel_id: u64) {
    let guild = guild_entry(settings, guild_id);
    if guild.get(TABLE).is_some_and(|table| !table.is_object()) {
        return;
    }
    child(guild, TABLE).shift_remove(&channel_id.to_string());
}

/// `/sticky list`: スティッキーの一覧。管理者でなくても見られる。Python の `list_stickies_cmd`。
pub fn list(guild: Option<&Value>) -> Result<Reply, CommandError> {
    let table = dict_setting(guild, TABLE)?;
    if table.is_empty() {
        return Ok(Reply::ephemeral(
            "スティッキーメッセージは設定されておらぬ。",
        ));
    }
    let mut lines = Vec::with_capacity(table.len());
    for (channel, entry) in table {
        // Python の `v.get('content', '')[:50]`。辞書でない設定・文字列でない内容は、Python では例外になる。
        let entry = entry
            .as_object()
            .ok_or(CommandError::BrokenSetting(TABLE))?;
        let content = match entry.get("content") {
            None => "",
            Some(Value::String(text)) => text.as_str(),
            Some(_) => return Err(CommandError::BrokenSetting(TABLE)),
        };
        lines.push(format!(
            "<#{channel}>: {}",
            first_chars(content, LIST_CONTENT_CHARS)
        ));
    }
    // チャンネルの数に上限が無いので、件数と文字数の両方で打ち切る（何件省いたかは出す）。
    let header = "**スティッキー一覧**\n";
    let body = cap_list_for_message(&lines, MESSAGE_BUDGET, "件", "\n", Some(LIST_LIMIT), header);
    Ok(Reply::ephemeral(format!("{header}{body}")))
}

/// 剥がすときに消す固定メッセージ（置いてあれば）。
pub fn message_to_delete(guild: Option<&Value>, channel_id: u64) -> Option<u64> {
    crate::sticky::entry_for(guild, channel_id)?.message_id
}

/// 固定メッセージを消し、設定からも外す。Python の `delete_sticky`（/sticky clear が、返事のあとで呼ぶ）。
///
/// 固定メッセージがもう無い（手で消された）・消せない（権限が無い）ときも、設定からは外す。Python と同じく、
/// 貼り直しの排他は通らない。
pub async fn delete(http: &Http, settings: &SettingsCache, guild_id: u64, channel_id: u64) {
    let snapshot = settings.snapshot();
    if let Some(old) = message_to_delete(snapshot.guild(guild_id), channel_id) {
        let _ = ChannelId::new(channel_id)
            .delete_message(http, MessageId::new(old))
            .await;
    }
    let removed = settings.transact(|s| remove(s, guild_id, channel_id)).await;
    if let Err(e) = removed {
        warn!(channel_id, "スティッキーの設定を消せませんでした: {e}");
    }
}

#[cfg(test)]
mod tests {
    use sycs_core::settings::drop_nulls;

    use super::*;
    use crate::sticky::{self as poster, StickyEntry};

    const GUILD: u64 = 7;
    const CHANNEL: u64 = 10;

    fn settings(guild: Value) -> Settings {
        let mut s = Settings::default();
        s.guilds.insert(GUILD.to_string(), guild);
        s
    }

    /// コマンドが書いたものを、貼る側（[`crate::sticky`]）がそのまま読めること。貼る指示として拾われること。
    #[test]
    fn what_the_command_writes_is_what_the_poster_reads() {
        let mut s =
            settings(json!({"sticky_messages": {"10": {"content": "古い", "message_id": 555}}}));
        set(&mut s, GUILD, CHANNEL, "一行目\\n二行目");
        assert_eq!(
            poster::entry_for(s.guild(GUILD), CHANNEL),
            Some(StickyEntry {
                content: "一行目\n二行目".into(),
                message_id: Some(555),
                pending: Some("post".into()),
            })
        );
        assert_eq!(poster::pending_entries(&s).len(), 1);
        assert_eq!(message_to_delete(s.guild(GUILD), CHANNEL), Some(555));
        assert_eq!(message_to_delete(s.guild(GUILD), 11), None);
    }

    /// はじめて貼るときは、固定メッセージの ID は null（保存のときに落ちる）で、消すものは無いこと。
    #[test]
    fn the_first_set_has_no_message_to_delete() {
        let mut s = Settings::default();
        set(&mut s, GUILD, CHANNEL, "ルール");
        assert_eq!(
            s.guilds["7"],
            json!({"sticky_messages": {"10": {"content": "ルール", "message_id": null, "pending": "post"}}})
        );
        let mut saved = s.guilds["7"].clone();
        drop_nulls(&mut saved);
        assert_eq!(
            serde_json::to_string(&saved).unwrap(),
            r#"{"sticky_messages":{"10":{"content":"ルール","pending":"post"}}}"#
        );
        assert_eq!(message_to_delete(Some(&saved), CHANNEL), None);
    }

    /// 外すと、そのチャンネルだけ消えること。表が無ければ空の表ができ、辞書でない表には触らないこと。
    #[test]
    fn removing_keeps_other_channels_and_creates_an_empty_table() {
        let mut s =
            settings(json!({"sticky_messages": {"10": {"content": "a"}, "11": {"content": "b"}}}));
        remove(&mut s, GUILD, CHANNEL);
        assert_eq!(
            s.guilds["7"],
            json!({"sticky_messages": {"11": {"content": "b"}}})
        );
        let mut empty = Settings::default();
        remove(&mut empty, GUILD, CHANNEL);
        assert_eq!(empty.guilds["7"], json!({"sticky_messages": {}}));
        let mut broken = settings(json!({"sticky_messages": "壊れた値"}));
        remove(&mut broken, GUILD, CHANNEL);
        assert_eq!(broken.guilds["7"], json!({"sticky_messages": "壊れた値"}));
    }
}
