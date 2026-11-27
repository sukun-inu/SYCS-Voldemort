//! スティッキー（チャンネルの一番下に、決まったメッセージを置き続ける）。Python の
//! `services/sticky_service.py`。
//!
//! 設定はギルドの `sticky_messages`（チャンネル ID の文字列 → `content`・`message_id`・`pending`）。
//! 誰かが発言するたびに、古い固定メッセージを消して「📌 内容」を送り直し、新しいメッセージ ID を
//! 設定へ書き戻す。管理画面は `pending`（`post`・`delete`）を立てるだけで、実際の投稿・削除は
//! Bot が 30 秒ごと（と、管理画面からの依頼 `sticky`）に行う。
//!
//! 送り直しは「消してから送る」の 2 段なので、同じチャンネルで重なると二重投稿や消し忘れになる。
//! チャンネルごとに 1 人ずつにし、連投で重なったときは 1 回だけ後から送り直す（Python と同じ）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use serenity::all::{Cache, ChannelId, GuildId, Http, MessageId};
use sycs_core::settings::{Settings, SettingsCache};
use tracing::warn;

use crate::log_channel;

/// 管理画面からの指示を見る間隔。Python の pending_sticky_task と同じ 30 秒。
pub const PENDING_INTERVAL: Duration = Duration::from_secs(30);

/// 1 チャンネルぶんの設定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickyEntry {
    /// 固定する内容（送るときは頭に「📌 」を付ける）。
    pub content: String,
    /// いま置いてある固定メッセージ。
    pub message_id: Option<u64>,
    /// 管理画面からの指示（`post`・`delete`）。
    pub pending: Option<String>,
}

fn entry_from(value: &Value) -> Option<StickyEntry> {
    let obj = value.as_object().filter(|o| !o.is_empty())?;
    let content = match obj.get("content") {
        None => String::new(),
        Some(v) => log_channel::python_str(v),
    };
    Some(StickyEntry {
        content,
        message_id: obj.get("message_id").and_then(log_channel::as_channel_id),
        pending: obj
            .get("pending")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(str::to_string),
    })
}

/// そのチャンネルの設定。無い（空も含む）なら `None`。
pub fn entry_for(guild: Option<&Value>, channel_id: u64) -> Option<StickyEntry> {
    entry_from(guild?.get("sticky_messages")?.get(channel_id.to_string())?)
}

/// 指示（`pending`）の立っているもの: (ギルド, チャンネル, 設定)。
pub fn pending_entries(settings: &Settings) -> Vec<(u64, u64, StickyEntry)> {
    let mut out = Vec::new();
    for (guild_key, guild) in &settings.guilds {
        let Ok(guild_id) = guild_key.parse::<u64>() else {
            continue;
        };
        let Some(stickies) = guild.get("sticky_messages").and_then(Value::as_object) else {
            continue;
        };
        for (channel_key, value) in stickies {
            let (Ok(channel_id), Some(entry)) = (channel_key.parse::<u64>(), entry_from(value))
            else {
                continue;
            };
            if guild_id > 0 && channel_id > 0 && entry.pending.is_some() {
                out.push((guild_id, channel_id, entry));
            }
        }
    }
    out
}

fn sticky_object(s: &mut Settings, guild_id: u64) -> Option<&mut serde_json::Map<String, Value>> {
    s.guilds
        .get_mut(&guild_id.to_string())?
        .get_mut("sticky_messages")?
        .as_object_mut()
}

/// 送ったメッセージ ID を書き戻し、指示を消す。Python の `update_sticky_message_id`。
///
/// 設定が無くなっていたら何もしない（削除と行き違ったとき、消えた設定を作り直さない）。
pub fn record_posted(s: &mut Settings, guild_id: u64, channel_id: u64, message_id: u64) {
    let Some(entry) = sticky_object(s, guild_id)
        .and_then(|st| st.get_mut(&channel_id.to_string()))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    entry.insert("message_id".into(), json!(message_id));
    entry.shift_remove("pending");
}

/// 設定から消す。Python の `remove_sticky_message`。
pub fn forget(s: &mut Settings, guild_id: u64, channel_id: u64) {
    if let Some(stickies) = sticky_object(s, guild_id) {
        stickies.shift_remove(&channel_id.to_string());
    }
}

/// チャンネルごとの排他と「後でもう 1 回」の印。Python の `_locks`・`_pending`。
#[derive(Default)]
pub struct StickyLocks {
    locks: Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    again: Mutex<HashMap<u64, bool>>,
}

impl StickyLocks {
    fn lock_for(&self, channel_id: u64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(locks.entry(channel_id).or_default())
    }

    fn set_again(&self, channel_id: u64, value: bool) {
        self.again
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(channel_id, value);
    }

    fn take_again(&self, channel_id: u64) -> bool {
        let mut again = self.again.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::replace(again.entry(channel_id).or_default(), false)
    }
}

/// 送り直しに要るもの。
pub struct StickyCtx<'a> {
    /// Discord へ送る口。
    pub http: &'a Http,
    /// serenity のキャッシュ（チャンネルを確かめる）。
    pub cache: &'a Cache,
    /// ギルドごとの設定（読み、メッセージ ID を書き戻す）。
    pub settings: &'a SettingsCache,
    /// チャンネルごとの排他。
    pub locks: &'a StickyLocks,
}

/// 発言があったら一番下へ送り直す。Python の `handle_sticky`（Bot の発言・DM は呼ぶ側で除く）。
///
/// ほかの送り直しが走っている間に来た発言は、印だけ付けて自分では送らない。走っていた方が
/// 終わったら 1 回だけ送り直す（連投 1 回ごとに消して送るのを繰り返さない）。
pub async fn handle_message(c: &StickyCtx<'_>, guild_id: u64, channel_id: u64) {
    let snapshot = c.settings.snapshot();
    if !reposts_on_message(entry_for(snapshot.guild(guild_id), channel_id).as_ref()) {
        return;
    }
    let lock = c.locks.lock_for(channel_id);
    let Ok(guard) = lock.try_lock() else {
        c.locks.set_again(channel_id, true);
        return;
    };
    c.locks.set_again(channel_id, false);
    post_latest(c, guild_id, channel_id).await;
    drop(guard);
    if c.locks.take_again(channel_id) {
        let _guard = lock.lock().await;
        post_latest(c, guild_id, channel_id).await;
    }
}

/// 発言があったときに送り直すか。設定があって、消す指示が立っていないときだけ。
pub fn reposts_on_message(entry: Option<&StickyEntry>) -> bool {
    entry.is_some_and(|e| e.pending.as_deref() != Some("delete"))
}

/// いまの設定で送り直す（排他は呼ぶ側で取っている）。Python の `_post_latest` ＋ `_post_once`。
async fn post_latest(c: &StickyCtx<'_>, guild_id: u64, channel_id: u64) {
    let snapshot = c.settings.snapshot();
    let Some(entry) = entry_for(snapshot.guild(guild_id), channel_id) else {
        return;
    };
    let channel = ChannelId::new(channel_id);
    if let Some(old) = entry.message_id {
        // もう無い（手で消された）ときも送り直しは続ける。
        let _ = channel.delete_message(c.http, MessageId::new(old)).await;
    }
    match channel.say(c.http, format!("📌 {}", entry.content)).await {
        Ok(sent) => {
            let written = c
                .settings
                .transact(|s| record_posted(s, guild_id, channel_id, sent.id.get()))
                .await;
            if let Err(e) = written {
                warn!(
                    channel_id,
                    "スティッキーのメッセージ ID を書き戻せませんでした: {e}"
                );
            }
        }
        Err(e) => warn!(channel_id, "スティッキーを送れませんでした: {e}"),
    }
}

/// いますぐ貼り直す（/sticky set が、返事を返したあとで呼ぶ）。Python の `post_sticky`。
///
/// 発言のたびの貼り直しと同じ排他を通る。走っている貼り直しがあれば、終わるのを待ってから貼る。
pub async fn post_now(c: &StickyCtx<'_>, guild_id: u64, channel_id: u64) {
    let lock = c.locks.lock_for(channel_id);
    let _guard = lock.lock().await;
    c.locks.set_again(channel_id, false);
    post_latest(c, guild_id, channel_id).await;
}

/// 管理画面からの指示（貼る・消す）を片付ける。Python の `process_pending_stickies`。
/// `handles` が偽のギルドは飛ばす（`BOT_ONLY_GUILD_ID`）。
pub async fn process_pending(c: &StickyCtx<'_>, handles: impl Fn(u64) -> bool) {
    let snapshot = c.settings.snapshot();
    for (guild_id, channel_id, entry) in pending_entries(&snapshot) {
        if !handles(guild_id)
            || log_channel::text_channel(c.cache, GuildId::new(guild_id), Some(channel_id))
                .is_none()
        {
            continue;
        }
        let lock = c.locks.lock_for(channel_id);
        match entry.pending.as_deref() {
            Some("post") => {
                let _guard = lock.lock().await;
                c.locks.set_again(channel_id, false);
                // 排他を待つ間に、発言のほうで送り直し済みなら二重に送らない。
                let fresh = c.settings.snapshot();
                let still = entry_for(fresh.guild(guild_id), channel_id)
                    .and_then(|e| e.pending)
                    .is_some_and(|p| p == "post");
                if still {
                    post_latest(c, guild_id, channel_id).await;
                }
            }
            Some("delete") => {
                let _guard = lock.lock().await;
                c.locks.set_again(channel_id, false);
                if let Some(old) = entry.message_id {
                    let _ = ChannelId::new(channel_id)
                        .delete_message(c.http, MessageId::new(old))
                        .await;
                }
                if let Err(e) = c
                    .settings
                    .transact(|s| forget(s, guild_id, channel_id))
                    .await
                {
                    warn!(channel_id, "スティッキーの設定を消せませんでした: {e}");
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn settings(guilds: Value) -> Settings {
        Settings {
            version: 1,
            root: Default::default(),
            guilds: guilds
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    /// チャンネルの設定を読み、空や無いものは「無し」とすること。
    #[test]
    fn entries_are_read_per_channel() {
        let g = json!({"sticky_messages": {
            "10": {"content": "ルール", "message_id": 555, "pending": "post"},
            "11": {},
            "12": {"content": 42},
        }});
        assert_eq!(
            entry_for(Some(&g), 10),
            Some(StickyEntry {
                content: "ルール".into(),
                message_id: Some(555),
                pending: Some("post".into())
            })
        );
        assert_eq!(entry_for(Some(&g), 11), None);
        assert_eq!(entry_for(Some(&g), 99), None);
        // Python は f"📌 {content}" なので、文字列でない内容もそのまま文字にする。
        assert_eq!(entry_for(Some(&g), 12).unwrap().content, "42");
    }

    /// 指示の立っているものだけを、どのギルドのどのチャンネルかと一緒に拾うこと。
    #[test]
    fn only_entries_with_an_instruction_are_pending() {
        let s = settings(json!({
            "1": {"sticky_messages": {"10": {"content": "a", "pending": "post"}, "11": {"content": "b"}}},
            "2": {"sticky_messages": {"20": {"content": "c", "pending": "delete", "message_id": 7}}},
            "not-a-guild": {"sticky_messages": {"30": {"content": "d", "pending": "post"}}},
        }));
        let got: Vec<(u64, u64, Option<String>)> = pending_entries(&s)
            .into_iter()
            .map(|(g, c, e)| (g, c, e.pending))
            .collect();
        assert_eq!(
            got,
            [(1, 10, Some("post".into())), (2, 20, Some("delete".into()))]
        );
    }

    /// 送ったら ID を書き戻して指示を消し、設定が無くなっていれば作り直さないこと。
    #[test]
    fn posting_records_the_id_and_clears_the_instruction() {
        let mut s = settings(
            json!({"1": {"sticky_messages": {"10": {"content": "a", "message_id": null, "pending": "post"}}}}),
        );
        record_posted(&mut s, 1, 10, 999);
        assert_eq!(
            s.guilds["1"]["sticky_messages"]["10"],
            json!({"content": "a", "message_id": 999})
        );
        let before = s.clone();
        record_posted(&mut s, 1, 11, 5);
        record_posted(&mut s, 2, 10, 5);
        assert_eq!(s, before, "無い設定を作った");
    }

    /// 消すと設定から無くなり、ほかのチャンネルは残ること。
    #[test]
    fn forgetting_removes_only_that_channel() {
        let mut s = settings(
            json!({"1": {"sticky_messages": {"10": {"content": "a"}, "11": {"content": "b"}}}}),
        );
        forget(&mut s, 1, 10);
        assert_eq!(
            s.guilds["1"]["sticky_messages"],
            json!({"11": {"content": "b"}})
        );
        forget(&mut s, 9, 10);
    }

    /// 発言で送り直すのは、設定があって消す指示が立っていないときだけ。
    #[test]
    fn a_message_reposts_unless_deletion_is_pending() {
        let entry = |pending: Option<&str>| StickyEntry {
            content: "a".into(),
            message_id: None,
            pending: pending.map(str::to_string),
        };
        assert!(reposts_on_message(Some(&entry(None))));
        assert!(reposts_on_message(Some(&entry(Some("post")))));
        assert!(!reposts_on_message(Some(&entry(Some("delete")))));
        assert!(!reposts_on_message(None));
    }

    /// 印は 1 回取ったら消えること（後からの送り直しは 1 回だけ）。
    #[test]
    fn the_again_mark_is_taken_once() {
        let locks = StickyLocks::default();
        assert!(!locks.take_again(1));
        locks.set_again(1, true);
        assert!(locks.take_again(1));
        assert!(!locks.take_again(1));
    }
}
