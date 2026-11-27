//! `/news`（ニュースの配信の設定）と、remove の補完。Python の `commands/server/news.py` と、
//! `services/settings_store.py` の `add_news_feed`・`remove_news_feed`。
//!
//! 書く先はサーバーの設定の `news_feeds`（フィードの ID → `channel_id`・`query`・`interval`〔分〕・`last_run`・
//! `seen_hashes`）。読むのは [`crate::news`]（5 分ごとの巡回）。

use serde_json::{Value, json};
use sycs_core::settings::Settings;

use super::python::{dict_setting, first_chars, lookup_id, strip};
use super::{CHOICE_LIMIT, CHOICE_NAME_CHARS, Choice, child, guild_entry};
use crate::commands::CommandError;
use crate::commands::reply::{MESSAGE_BUDGET, Reply, cap_list_for_message};
use crate::commands::settings::python_truthy;
use crate::log_channel::python_str;

/// 1 つのサーバーに登録できるフィードの数。一覧を本文の上限（2000 文字）に収めるための決まり。
pub const MAX_FEEDS: usize = 10;
/// 巡回の間隔の下限（分）。
pub const MIN_INTERVAL_MINUTES: i64 = 5;
/// 間隔を書かなかったときの値（分）。Python の `interval: int = 60`。
pub const DEFAULT_INTERVAL_MINUTES: i64 = 60;
/// 設定の鍵。[`crate::news`] が読む鍵と同じ。
const TABLE: &str = "news_feeds";
/// 一覧で、検索の語を何文字まで出すか（上限を入れる前に登録されたフィードは、もっと長いことがある）。
const LIST_QUERY_CHARS: usize = 60;

/// `/news add` を断るなら、その文。Python の `_apply_add` の先頭（間隔 → 件数の順に見る）。
///
/// 件数は、いま手元にある設定で数える（Python も、書き込みの排他の外で数える）。
pub fn refusal_for_add(
    guild: Option<&Value>,
    interval: i64,
) -> Result<Option<String>, CommandError> {
    if interval < MIN_INTERVAL_MINUTES {
        return Ok(Some(format!(
            "間隔は{MIN_INTERVAL_MINUTES}分以上で指定せよ。"
        )));
    }
    if dict_setting(guild, TABLE)?.len() >= MAX_FEEDS {
        return Ok(Some(format!(
            "フィードは最大{MAX_FEEDS}件までだ。余の力にも限りがある。"
        )));
    }
    Ok(None)
}

/// 新しいフィードの ID（16 進 8 文字の乱数）。Python の `uuid.uuid4().hex[:8]`。
pub fn new_feed_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    // 乱数の crate を足さずに済むよう、標準ライブラリのハッシュの鍵（プロセスごと・呼ぶたびに変わる乱数）を使う。
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    format!("{:08x}", hasher.finish() & 0xFFFF_FFFF)
}

/// `/news add`: フィードを足す。Python の `add_news_feed`。
///
/// 最後に巡回した時刻（`last_run`）は 0、送った記事の印（`seen_hashes`）は空から始める。
pub fn add(
    settings: &mut Settings,
    guild_id: u64,
    feed_id: &str,
    channel_id: u64,
    query: &str,
    interval: i64,
) -> Reply {
    let feed = json!({
        "channel_id": channel_id,
        "query": query,
        "interval": interval,
        "last_run": 0.0,
        "seen_hashes": [],
    });
    child(guild_entry(settings, guild_id), TABLE).insert(feed_id.to_string(), feed);
    Reply::ephemeral(format!(
        "ニュースフィードを加えた。\nID: `{feed_id}` | クエリ: `{query}` | チャンネル: <#{channel_id}> | 間隔: {interval}分"
    ))
}

/// `/news remove`: フィードを消す。Python の `_apply_remove`・`remove_news_feed`。
///
/// ID は候補から選ばずに手で打てるので、前後の空白を落としてから照らす。返事には、入れたままを出す。
pub fn remove(settings: &mut Settings, guild_id: u64, feed_id: &str) -> Reply {
    let removed = guild_entry(settings, guild_id)
        .get_mut(TABLE)
        .and_then(Value::as_object_mut)
        .is_some_and(|feeds| feeds.shift_remove(strip(feed_id)).is_some());
    if removed {
        Reply::ephemeral(format!("フィード `{feed_id}` を抹消した。"))
    } else {
        Reply::ephemeral("そのようなフィードは見つからなかった。")
    }
}

/// `/news list`: フィードの一覧。管理者でなくても見られる。Python の `_apply_list`。
pub fn list(guild: Option<&Value>) -> Result<Reply, CommandError> {
    let feeds = dict_setting(guild, TABLE)?;
    if feeds.is_empty() {
        return Ok(Reply::ephemeral("ニュースフィードは登録されておらぬ。"));
    }
    let mut lines = Vec::with_capacity(feeds.len());
    for (feed_id, feed) in feeds {
        let feed = feed.as_object().ok_or(CommandError::BrokenSetting(TABLE))?;
        // Python の `(f.get('query') or '')[:60]`。文字列でない「真」の値は、Python では例外になる。
        let query = match feed.get("query") {
            Some(Value::String(text)) => first_chars(text, LIST_QUERY_CHARS),
            Some(other) if python_truthy(Some(other)) => {
                return Err(CommandError::BrokenSetting(TABLE));
            }
            _ => String::new(),
        };
        // Python の `f"{f.get('channel_id')}"`（無ければ None と書く）。
        let written = |key: &str| feed.get(key).map_or_else(|| "None".to_string(), python_str);
        lines.push(format!(
            "`{feed_id}` | {query} | <#{}> | {}分",
            written("channel_id"),
            written("interval")
        ));
    }
    let header = "**ニュースフィード一覧**\n";
    let body = cap_list_for_message(&lines, MESSAGE_BUDGET, "件", "\n", Some(MAX_FEEDS), header);
    Ok(Reply::ephemeral(format!("{header}{body}")))
}

/// remove の `feed_id` の候補。Python の `_feed_id_choices`。
///
/// 入力中の文字を ID か検索の語に含むフィードだけを（大文字と小文字は区別しない）、設定の順に 25 件まで。
/// 名前には、検索の語と送り先のチャンネルの名前を添える。
pub fn feed_id_choices(
    guild: Option<&Value>,
    current: &str,
    channel_name: &dyn Fn(u64) -> Option<String>,
) -> Result<Vec<Choice>, CommandError> {
    let feeds = dict_setting(guild, TABLE)?;
    let needle = current.to_lowercase();
    let mut choices = Vec::new();
    for (feed_id, feed) in feeds {
        let feed = feed.as_object().ok_or(CommandError::BrokenSetting(TABLE))?;
        let query = feed.get("query").map_or_else(String::new, python_str);
        if !needle.is_empty()
            && !feed_id.to_lowercase().contains(&needle)
            && !query.to_lowercase().contains(&needle)
        {
            continue;
        }
        let channel = lookup_id(feed.get("channel_id"), TABLE)?
            .and_then(channel_name)
            .map_or_else(|| "不明なチャンネル".to_string(), |name| format!("#{name}"));
        let name = format!("{query} ({channel}) [{feed_id}]");
        choices.push(Choice {
            name: first_chars(&name, CHOICE_NAME_CHARS),
            value: feed_id.clone(),
        });
    }
    choices.truncate(CHOICE_LIMIT);
    Ok(choices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::news::{self as reader, FeedTurn};

    /// コマンドが書いたものを、巡回する側（[`crate::news`]）がそのまま読めること。足した直後は巡回の番になること。
    #[test]
    fn what_the_command_writes_is_what_the_reader_reads() {
        let mut settings = Settings::default();
        add(&mut settings, 7, "feedc0de", 500, "AI技術", 30);
        let feed = &settings.guilds["7"]["news_feeds"]["feedc0de"];
        assert_eq!(
            serde_json::to_string(feed).unwrap(),
            r#"{"channel_id":500,"query":"AI技術","interval":30,"last_run":0.0,"seen_hashes":[]}"#
        );
        match reader::feed_turn(feed, 30.0 * 60.0) {
            FeedTurn::Due(due) => {
                assert_eq!((due.channel_id, due.query.as_str()), (500, "AI技術"));
                assert!(due.seen.is_empty());
            }
            _ => panic!("足したフィードが巡回の番にならない"),
        }
        assert!(matches!(
            reader::feed_turn(feed, 30.0 * 60.0 - 1.0),
            FeedTurn::NotDue
        ));
    }

    /// ID は 16 進 8 文字で、呼ぶたびに違うこと。
    #[test]
    fn feed_ids_are_eight_random_hex_characters() {
        let ids: std::collections::BTreeSet<String> = (0..64).map(|_| new_feed_id()).collect();
        assert!(ids.len() >= 63, "同じ ID が続いて出る: {ids:?}");
        for id in &ids {
            assert_eq!(id.len(), 8, "{id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{id}"
            );
        }
    }

    /// 間隔の下限と件数の上限の境。
    #[test]
    fn the_interval_and_count_limits_sit_at_5_and_10() {
        let with = |count: usize| {
            let feeds: serde_json::Map<String, Value> =
                (0..count).map(|i| (i.to_string(), json!({}))).collect();
            json!({ "news_feeds": feeds })
        };
        assert_eq!(refusal_for_add(None, 5).unwrap(), None);
        assert!(refusal_for_add(None, 4).unwrap().is_some());
        assert_eq!(refusal_for_add(Some(&with(9)), 60).unwrap(), None);
        assert!(refusal_for_add(Some(&with(10)), 60).unwrap().is_some());
    }
}
