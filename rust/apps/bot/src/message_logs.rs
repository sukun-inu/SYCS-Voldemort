//! メッセージの削除・編集をログにする。Python の `events/messages.py` の `_log_deleted`・`_log_edited`。
//!
//! 中身（本文・項目の名前と順・切り詰め）は Python と同じ。控え（`message_cache`）にあった
//! メッセージのときだけ呼ぶ（discord.py も控えにある件のときだけイベントを出す）。
//!
//! **Bot 自身のメッセージも除かない**（Python と同じ。2026-11-27 に本人が「出す仕様で OK」と決めた）。
//! スティッキーを貼り直すたびに古い固定メッセージの削除もログに出るが、代わりに、他の人が Bot の
//! 発言を消したときにも気づける。

use serenity::all::ImageHash;

use crate::compat;
use crate::log_channel::{Author, Level};
use crate::members::{LogEntry, snowflake_jst};
use crate::message_cache::CachedMessage;

fn take_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// 削除。Python の `_deleted_fields` と同じ項目（添付があれば最後に URL の一覧）。
///
/// 本文は 1024 文字で切る（Python と同じく印は付けない）。添付の一覧は切らずに渡し、
/// 送るときに上限の内側で切る。
pub fn deleted_entry(m: &CachedMessage) -> LogEntry {
    let content = if m.content.is_empty() {
        "(内容なし)".to_string()
    } else {
        take_chars(&m.content, 1024)
    };
    let mut fields = vec![
        ("送信日時".to_string(), snowflake_jst(m.id.get())),
        ("内容".to_string(), content),
        ("ユーザーID".to_string(), m.author.id.to_string()),
        ("メッセージID".to_string(), m.id.to_string()),
    ];
    if !m.attachments.is_empty() {
        fields.push(("添付ファイル".to_string(), m.attachments.join("\n")));
    }
    LogEntry {
        level: Level::Info,
        message: format!(
            "{} のメッセージが削除されました。",
            compat::mention(m.author.id)
        ),
        fields,
        colour: None,
    }
}

/// 編集。本文が変わっていなければ `None`（埋め込みの展開やピン留めでも編集のイベントが来る）。
pub fn edited_entry(before: &CachedMessage, after: &CachedMessage) -> Option<LogEntry> {
    if before.content == after.content {
        return None;
    }
    let shown = |text: &str| {
        if text.is_empty() {
            "(なし)".to_string()
        } else {
            take_chars(text, 1000)
        }
    };
    Some(LogEntry {
        level: Level::Info,
        message: format!(
            "{} のメッセージが編集されました。",
            compat::mention(before.author.id)
        ),
        fields: vec![
            (
                "チャンネル".to_string(),
                format!("<#{}>", before.channel_id),
            ),
            ("編集前".to_string(), shown(&before.content)),
            ("編集後".to_string(), shown(&after.content)),
            ("メッセージID".to_string(), before.id.to_string()),
        ],
        colour: None,
    })
}

/// メッセージを送った人を Embed の作者にする（メンバーならサーバーごとのアバター）。
pub fn author_of(m: &CachedMessage) -> Author {
    let mut author = Author::from_user(&m.author);
    if let (Some(guild_id), Some(hash)) = (m.guild_id, m.member_avatar.as_ref()) {
        author.avatar_url = guild_avatar(guild_id.get(), m.author.id.get(), hash);
    }
    author
}

fn guild_avatar(guild_id: u64, user_id: u64, hash: &ImageHash) -> String {
    let format = if hash.is_animated() { "gif" } else { "png" };
    format!(
        "{}/guilds/{guild_id}/users/{user_id}/avatars/{hash}.{format}?size=1024",
        compat::CDN
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serenity::all::{ChannelId, GuildId, MessageId};

    use super::*;

    fn message(content: &str, attachments: &[&str]) -> CachedMessage {
        CachedMessage {
            id: MessageId::new(1_574_968_686_299_586_642),
            channel_id: ChannelId::new(1_505_310_388_051_251_261),
            guild_id: Some(GuildId::new(1_399_617_700_363_370_556)),
            author: serde_json::from_value(json!({
                "id": "80351110224678912", "username": "nelly", "discriminator": "0",
                "avatar": null, "global_name": null
            }))
            .unwrap(),
            member_avatar: None,
            content: content.into(),
            attachments: attachments.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 削除のログは、送信日時・内容・ユーザーID・メッセージID の順、添付があれば最後に足す。
    #[test]
    fn a_deletion_lists_the_fields_in_python_order() {
        let e = deleted_entry(&message("こんにちは", &[]));
        let names: Vec<&str> = e.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["送信日時", "内容", "ユーザーID", "メッセージID"]);
        assert_eq!(
            e.message,
            "<@80351110224678912> のメッセージが削除されました。"
        );
        // メッセージ ID から出した送信日時（Python で同じ式で計算した値）。
        assert_eq!(e.fields[0].1, "2026/11/25 11:03");
        let with = deleted_entry(&message("", &["https://a", "https://b"]));
        assert_eq!(with.fields[1].1, "(内容なし)");
        assert_eq!(
            with.fields[4],
            ("添付ファイル".into(), "https://a\nhttps://b".into())
        );
    }

    /// 削除の本文は 1024 文字、編集の本文は 1000 文字で切る（どちらも印なし）。
    #[test]
    fn long_texts_are_cut_without_a_mark() {
        let long = "あ".repeat(1500);
        assert_eq!(
            deleted_entry(&message(&long, &[])).fields[1]
                .1
                .chars()
                .count(),
            1024
        );
        let e = edited_entry(&message("短い", &[]), &message(&long, &[])).unwrap();
        assert_eq!(e.fields[2].1.chars().count(), 1000);
    }

    /// 本文が同じ編集は書かず、空の本文は「(なし)」と書く。
    #[test]
    fn edits_need_a_changed_body() {
        let a = message("同じ", &[]);
        assert!(edited_entry(&a, &a).is_none());
        let e = edited_entry(&a, &message("", &[])).unwrap();
        assert_eq!(
            e.fields,
            [
                ("チャンネル".into(), "<#1505310388051251261>".into()),
                ("編集前".into(), "同じ".into()),
                ("編集後".into(), "(なし)".into()),
                ("メッセージID".into(), "1574968686299586642".into()),
            ]
        );
    }

    /// サーバーごとのアバターがあれば、作者のアイコンはそちら。
    #[test]
    fn the_author_uses_the_guild_avatar_when_set() {
        let mut m = message("x", &[]);
        assert!(author_of(&m).avatar_url.contains("/embed/avatars/"));
        m.member_avatar = Some("fedcba9876543210fedcba9876543210".parse().unwrap());
        assert_eq!(
            author_of(&m).avatar_url,
            "https://cdn.discordapp.com/guilds/1399617700363370556/users/80351110224678912/avatars/fedcba9876543210fedcba9876543210.png?size=1024"
        );
    }
}
