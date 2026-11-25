//! リアクションロール（決まったメッセージに決まった絵文字を付けると、ロールが付く・外れる）。
//! Python の `services/reaction_role_service.py`。
//!
//! 設定はギルドの `reaction_roles`（メッセージ ID の文字列 → {絵文字 → ロール ID}）。メッセージの
//! 控えに頼らないイベントで受けるので、Bot を起動する前に貼られたメッセージにも反応する。
//! Bot 自身のリアクションには反応しない。
//!
//! 絵文字の比べ方は Python と同じ。カスタム絵文字は ID（数字）に寄せ、Unicode の絵文字はそのまま
//! 使う。保存されている鍵は `<:name:123>`・`<a:name:123>`・`name:123`・`123` のどれでも同じ絵文字と
//! みなす（管理画面・スラッシュコマンドから入る形がまちまちなため）。

use serde_json::{Map, Value};
use serenity::all::{Cache, GuildId, Http, ReactionType, RoleId, UserId};
use sycs_core::settings::SettingsCache;
use tracing::{debug, info, warn};

use crate::log_channel;

/// 文字列で書かれた絵文字を、比べるための鍵にする。Python の `emoji_key`（文字列のとき）。
///
/// 前後の空白を落とし、`<:name:123>`・`<a:name:123>`・`name:123`・`123` なら ID を、
/// それ以外はそのまま返す。
pub fn emoji_key_text(text: &str) -> String {
    let text = text.trim();
    custom_emoji_id(text).unwrap_or(text).to_string()
}

/// Python の `_CUSTOM_EMOJI` と同じ正規表現。**書き換えるときは Python と同時に。**
///
/// regex の `\d` は Python と同じく Unicode の数字（全角も）を含む。手で書いた比べ方では
/// 全角の数字だけ答えが違ったので、同じ式をそのまま使う（テストで Python のソースと突き合わせる）。
const CUSTOM_EMOJI: &str = r"^<a?:[^:]+:(\d+)>$|^[^:]+:(\d+)$|^(\d+)$";

/// 当てはまったら ID の部分を返す（Python と同じく、最初に値の入ったグループ）。
fn custom_emoji_id(text: &str) -> Option<&str> {
    static PATTERN: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(CUSTOM_EMOJI).expect("正しい正規表現"));
    let caps = PATTERN.captures(text)?;
    caps.iter().skip(1).flatten().next().map(|m| m.as_str())
}

/// 付いたリアクションの絵文字を鍵にする。Python の `emoji_key`（PartialEmoji のとき）。
pub fn emoji_key(emoji: &ReactionType) -> String {
    match emoji {
        ReactionType::Custom { id, .. } => id.to_string(),
        ReactionType::Unicode(text) => emoji_key_text(text),
        other => emoji_key_text(&other.to_string()),
    }
}

/// そのメッセージの対応表（空も無いのと同じ）。
pub fn mapping_for(guild: Option<&Value>, message_id: u64) -> Option<&Map<String, Value>> {
    guild?
        .get("reaction_roles")?
        .get(message_id.to_string())?
        .as_object()
        .filter(|m| !m.is_empty())
}

/// この鍵に割り当てられたロール（保存された値のまま）。Python の `_role_id_for`。
///
/// まず鍵そのもので引き、無ければ保存された鍵を同じ規則で寄せて、保存の順に比べる
/// （過去に `<:name:123>` の形で保存された設定を、入れ直さずに動かすため）。
pub fn role_for<'a>(mapping: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    mapping.get(key).or_else(|| {
        mapping
            .iter()
            .find(|(stored, _)| emoji_key_text(stored) == key)
            .map(|(_, role)| role)
    })
}

/// 付けるか外すか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// リアクションが付いた → ロールを付ける。
    Add,
    /// リアクションが外れた → ロールを外す。
    Remove,
}

/// 決めたこと。Discord へは何もしない（テストと突き合わせから呼べるように分けてある）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// このメッセージには対応表が無い。
    NotWatched,
    /// 対応表はあるが、この絵文字は割り当てられていない（鍵を持つ）。
    NoRoleFor(String),
    /// 割り当てられたロールがサーバーに無い（保存された値を文字にしたもの）。
    MissingRole(String),
    /// このロールを付ける・外す。
    Role(RoleId, String),
}

/// 設定とサーバーのロールから、何をするかを決める。
pub fn decide(
    guild_settings: Option<&Value>,
    guild_roles: &std::collections::HashMap<RoleId, serenity::all::Role>,
    message_id: u64,
    emoji: &ReactionType,
) -> Decision {
    let Some(mapping) = mapping_for(guild_settings, message_id) else {
        return Decision::NotWatched;
    };
    let key = emoji_key(emoji);
    let Some(value) = role_for(mapping, &key) else {
        return Decision::NoRoleFor(key);
    };
    let role = log_channel::as_channel_id(value)
        .map(RoleId::new)
        .and_then(|id| guild_roles.get(&id));
    match role {
        Some(r) => Decision::Role(r.id, r.name.clone()),
        None => Decision::MissingRole(log_channel::python_str(value)),
    }
}

/// 付いた・外れたリアクション 1 つ。
pub struct ReactionEvent<'a> {
    /// サーバー。
    pub guild_id: GuildId,
    /// 付けた・外した人。
    pub user_id: UserId,
    /// その人の名前（ログ用。`str(member)` と同じ形）。
    pub user_tag: String,
    /// リアクションの付いたメッセージ。
    pub message_id: u64,
    /// 絵文字。
    pub emoji: &'a ReactionType,
    /// 付いたか外れたか。
    pub change: Change,
}

/// リアクションに応じてロールを付ける・外す。失敗はログに残して終わる。
pub async fn apply(cache: &Cache, http: &Http, settings: &SettingsCache, event: ReactionEvent<'_>) {
    let ReactionEvent {
        guild_id,
        user_id,
        user_tag,
        message_id,
        emoji,
        change,
    } = event;
    let snapshot = settings.snapshot();
    let roles = cache
        .guild(guild_id)
        .map(|g| g.roles.clone())
        .unwrap_or_default();
    match decide(snapshot.guild(guild_id.get()), &roles, message_id, emoji) {
        Decision::NotWatched => {}
        Decision::NoRoleFor(key) => {
            debug!(message_id, key, "[reaction_role] 割り当ての無い絵文字");
        }
        Decision::MissingRole(role_id) => warn!(
            "[reaction_role] 設定されたロールが見つかりません guild={guild_id} role_id={role_id}"
        ),
        Decision::Role(role_id, role_name) => {
            let result = match change {
                Change::Add => {
                    http.add_member_role(guild_id, user_id, role_id, Some("リアクションロール"))
                        .await
                }
                Change::Remove => {
                    http.remove_member_role(
                        guild_id,
                        user_id,
                        role_id,
                        Some("リアクションロール解除"),
                    )
                    .await
                }
            };
            match (result, change) {
                (Ok(()), Change::Add) => {
                    info!("[reaction_role] add role={role_name} user={user_tag}")
                }
                (Ok(()), Change::Remove) => {
                    info!("[reaction_role] remove role={role_name} user={user_tag}")
                }
                (Err(e), _) => warn!("[reaction_role] {change:?} のロールの変更に失敗: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;
    use serenity::all::{EmojiId, Role};

    use super::*;

    /// 書き方の違うカスタム絵文字が、どれも ID に寄ること。Unicode の絵文字はそのまま。
    #[test]
    fn custom_emoji_spellings_become_the_id() {
        for text in [
            "<:name:123>",
            "<a:name:123>",
            "name:123",
            "123",
            "  <:name:123>  ",
        ] {
            assert_eq!(emoji_key_text(text), "123", "{text}");
        }
        for text in [
            "👍",
            "a:name:123",
            "<:name:>",
            "<::123>",
            ":123",
            "<a:name:12x>",
            "name:",
        ] {
            assert_eq!(emoji_key_text(text), text.trim(), "{text}");
        }
    }

    /// 正規表現が Python のソースと同じであること（片方だけ直すと、照合が言語で食い違う）。
    #[test]
    fn the_pattern_matches_python() {
        let python = include_str!("../../../../services/reaction_role_service.py");
        assert!(
            python.contains(&format!("re.compile(r\"{CUSTOM_EMOJI}\")")),
            "services/reaction_role_service.py の _CUSTOM_EMOJI と違う"
        );
        // 全角の数字も Python と同じく ID とみなす。
        assert_eq!(emoji_key_text("<:name:１２３>"), "１２３");
    }

    /// 付いたリアクションの絵文字も同じ規則で鍵になること。
    #[test]
    fn reactions_become_keys() {
        let custom = ReactionType::Custom {
            animated: true,
            id: EmojiId::new(456),
            name: Some("x".into()),
        };
        assert_eq!(emoji_key(&custom), "456");
        assert_eq!(emoji_key(&ReactionType::Unicode("👍".into())), "👍");
    }

    /// まず鍵そのもので引き、無ければ保存された鍵を寄せて保存の順に比べること。
    #[test]
    fn stored_keys_are_normalised_in_order() {
        let mapping = json!({"<:a:123>": 1, "b:123": 2, "👍": 3, "123x": 4});
        let m = mapping.as_object().unwrap();
        assert_eq!(role_for(m, "👍"), Some(&json!(3)));
        // 123 そのものは無い → 保存の順に寄せて最初に当たった <:a:123>。
        assert_eq!(role_for(m, "123"), Some(&json!(1)));
        assert_eq!(role_for(m, "999"), None);
        let direct = json!({"b:123": 2, "123": 9});
        assert_eq!(
            role_for(direct.as_object().unwrap(), "123"),
            Some(&json!(9))
        );
    }

    fn roles() -> HashMap<RoleId, Role> {
        let r: Role = serde_json::from_value(json!({
            "id": "77", "name": "参加者", "color": 0,
            "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
            "hoist": false, "position": 1, "permissions": "0", "managed": false,
            "mentionable": false, "flags": 0, "guild_id": "1",
        }))
        .unwrap();
        [(r.id, r)].into_iter().collect()
    }

    /// 対応表・絵文字・ロールの有無で、何をするかが決まること。
    #[test]
    fn decisions_follow_the_settings() {
        let g = json!({"reaction_roles": {"10": {"👍": 77, "✅": "88", "❌": "abc"}, "11": {}}});
        let thumb = ReactionType::Unicode("👍".into());
        assert_eq!(
            decide(Some(&g), &roles(), 10, &thumb),
            Decision::Role(RoleId::new(77), "参加者".into())
        );
        assert_eq!(decide(Some(&g), &roles(), 11, &thumb), Decision::NotWatched);
        assert_eq!(decide(Some(&g), &roles(), 12, &thumb), Decision::NotWatched);
        assert_eq!(
            decide(Some(&g), &roles(), 10, &ReactionType::Unicode("🎉".into())),
            Decision::NoRoleFor("🎉".into())
        );
        assert_eq!(
            decide(Some(&g), &roles(), 10, &ReactionType::Unicode("✅".into())),
            Decision::MissingRole("88".into())
        );
        assert_eq!(
            decide(Some(&g), &roles(), 10, &ReactionType::Unicode("❌".into())),
            Decision::MissingRole("abc".into())
        );
    }
}
