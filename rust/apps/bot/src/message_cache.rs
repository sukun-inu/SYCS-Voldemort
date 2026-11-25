//! 最近のメッセージの控え。discord.py の `max_messages`（既定 1000 件）と同じ働き。
//!
//! 削除・編集のログは、消える前・変わる前の中身が要る。Discord は削除のイベントに中身を
//! 付けてこないので、届いたメッセージを控えておく。
//!
//! **数え方を discord.py と同じにする。** discord.py は全チャンネル・DM・Bot 自身の発言まで含めて
//! 届いた順に 1000 件を持ち、あふれたら古いものから捨てる。控えにある件のときだけ削除・編集の
//! イベントを出す。serenity のキャッシュはチャンネルごとの件数で持つので、そのまま使うと
//! 「どの件のログが出るか」が Python とずれる。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serenity::all::{ChannelId, GuildId, ImageHash, Message, MessageId, User};

/// 持つ件数。discord.py の `max_messages` の既定。
pub const MAX_MESSAGES: usize = 1000;

/// 控えておくメッセージ（ログに要るものだけ）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedMessage {
    /// メッセージ ID（送った時刻もここから出る）。
    pub id: MessageId,
    /// チャンネル。
    pub channel_id: ChannelId,
    /// サーバー（DM なら `None`）。
    pub guild_id: Option<GuildId>,
    /// 送った人。
    pub author: User,
    /// サーバーごとのアバター（送った人がメンバーで、設定していれば）。
    pub member_avatar: Option<ImageHash>,
    /// 本文。
    pub content: String,
    /// 添付ファイルの URL。
    pub attachments: Vec<String>,
}

impl CachedMessage {
    /// 届いたメッセージから。
    pub fn from_message(m: &Message) -> Self {
        Self {
            id: m.id,
            channel_id: m.channel_id,
            guild_id: m.guild_id,
            author: m.author.clone(),
            member_avatar: m.member.as_ref().and_then(|pm| pm.avatar),
            content: m.content.clone(),
            attachments: m.attachments.iter().map(|a| a.url.clone()).collect(),
        }
    }
}

/// 控え。届いた順に [`MAX_MESSAGES`] 件まで。
#[derive(Default)]
pub struct MessageCache {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    order: VecDeque<MessageId>,
    messages: HashMap<MessageId, CachedMessage>,
}

impl MessageCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 届いたメッセージを控える。あふれたら一番古いものを捨てる。
    pub fn insert(&self, message: CachedMessage) {
        let mut inner = self.lock();
        if let Some(existing) = inner.messages.get_mut(&message.id) {
            *existing = message;
            return;
        }
        if inner.order.len() >= MAX_MESSAGES
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.messages.remove(&oldest);
        }
        inner.order.push_back(message.id);
        inner.messages.insert(message.id, message);
    }

    /// 削除されたメッセージを取り出す（控えになければ `None`。discord.py はそのときイベントを出さない）。
    pub fn remove(&self, id: MessageId) -> Option<CachedMessage> {
        let mut inner = self.lock();
        let message = inner.messages.remove(&id)?;
        inner.order.retain(|m| *m != id);
        Some(message)
    }

    /// 編集を当てて、(変わる前, 変わった後) を返す。控えになければ `None`。
    ///
    /// 届いた項目だけを書き換える（Discord は変わった項目だけを送ることがある）。
    pub fn update(
        &self,
        id: MessageId,
        content: Option<String>,
        attachments: Option<Vec<String>>,
    ) -> Option<(CachedMessage, CachedMessage)> {
        let mut inner = self.lock();
        let current = inner.messages.get_mut(&id)?;
        let before = current.clone();
        if let Some(content) = content {
            current.content = content;
        }
        if let Some(attachments) = attachments {
            current.attachments = attachments;
        }
        Some((before, current.clone()))
    }

    /// 控えている件数。
    pub fn len(&self) -> usize {
        self.lock().order.len()
    }

    /// 控えが空か。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn message(id: u64, content: &str) -> CachedMessage {
        CachedMessage {
            id: MessageId::new(id),
            channel_id: ChannelId::new(1),
            guild_id: Some(GuildId::new(2)),
            author: serde_json::from_value(json!({
                "id": "3", "username": "u", "discriminator": "0", "avatar": null, "global_name": null
            }))
            .unwrap(),
            member_avatar: None,
            content: content.into(),
            attachments: vec![],
        }
    }

    /// 1000 件を超えたら、一番古いものから捨てること（discord.py の deque と同じ）。
    ///
    /// 件数は数字で確かめる（discord.py の max_messages の既定が 1000。違うと、どの件の削除・
    /// 編集がログになるかが Python とずれる）。
    #[test]
    fn the_oldest_message_is_dropped_past_the_limit() {
        assert_eq!(MAX_MESSAGES, 1000);
        let c = MessageCache::default();
        for id in 1..=1001 {
            c.insert(message(id, "x"));
        }
        assert_eq!(c.len(), 1000);
        assert!(
            c.remove(MessageId::new(1)).is_none(),
            "一番古いものが残っている"
        );
        assert!(c.remove(MessageId::new(2)).is_some());
    }

    /// 削除で取り出したら、もう控えに無いこと（2 回目の削除はイベントにならない）。
    #[test]
    fn a_removed_message_is_gone() {
        let c = MessageCache::default();
        c.insert(message(5, "本文"));
        assert_eq!(c.remove(MessageId::new(5)).unwrap().content, "本文");
        assert!(c.remove(MessageId::new(5)).is_none());
        assert!(c.is_empty());
    }

    /// 編集は届いた項目だけを書き換え、変わる前と後を返すこと。控えに無ければ何も返さない。
    #[test]
    fn an_edit_returns_before_and_after() {
        let c = MessageCache::default();
        let mut m = message(7, "前");
        m.attachments = vec!["a".into()];
        c.insert(m);
        let (before, after) = c
            .update(MessageId::new(7), Some("後".into()), None)
            .unwrap();
        assert_eq!(
            (before.content.as_str(), after.content.as_str()),
            ("前", "後")
        );
        assert_eq!(after.attachments, ["a"], "届いていない項目を消した");
        let (_, after) = c.update(MessageId::new(7), None, Some(vec![])).unwrap();
        assert_eq!(after.content, "後");
        assert!(after.attachments.is_empty());
        assert!(
            c.update(MessageId::new(8), Some("x".into()), None)
                .is_none()
        );
    }
}
