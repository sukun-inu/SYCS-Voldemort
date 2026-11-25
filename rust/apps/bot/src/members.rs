//! メンバーの参加・退出・変更（ニックネーム・ロール・タイムアウト）・BAN をログにする。
//! Python の `events/members.py` のうち、ログチャンネルへ書く中身。
//!
//! ここは「何を書くか」だけを決める（Discord にもキャッシュにも触らない）。送るのは
//! `handler`、送り方は `log_channel`。利用者の状態の記録（Python の `record_user_state_event`）は
//! 別の塊（利用者の状態）で同じイベントに足す。
//!
//! 文面・項目の名前と順・時刻の書き方・色は Python と同じ。一致は、同じ Discord の JSON を
//! discord.py と serenity に読ませ、Python の処理が log_action に渡した中身と突き合わせて
//! 確かめた（変更のコミットに記録）。

use std::collections::{HashMap, HashSet};

use chrono::DateTime;
use serenity::all::{GuildId, Member, Role, RoleId, Timestamp, User, UserId};

use crate::compat;
use crate::log_channel::{self, Level};

/// discord.py の `Color.orange()`（タイムアウトのログの色）。
pub const ORANGE: u32 = 0xE6_7E_22;
/// discord.py の `Color.red()`（BAN のログの色）。
pub const RED: u32 = 0xE7_4C_3C;
/// Discord の ID が数え始める時刻（2015-01-01 UTC、ミリ秒）。
const DISCORD_EPOCH_MS: i64 = 1_420_070_400_000;

/// ログチャンネルへ書く 1 件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// レベル（送るかどうかの判断と題に使う）。
    pub level: Level,
    /// 本文。
    pub message: String,
    /// 項目（名前, 値）。並びのまま出る。
    pub fields: Vec<(String, String)>,
    /// 決まった色。`None` なら作者のアバターの色（取れなければレベルの色）。
    pub colour: Option<u32>,
}

impl LogEntry {
    fn new(level: Level, message: String) -> Self {
        Self {
            level,
            message,
            fields: Vec::new(),
            colour: None,
        }
    }

    fn field(mut self, name: &str, value: impl Into<String>) -> Self {
        self.fields.push((name.to_string(), value.into()));
        self
    }
}

/// 日本時間の「年/月/日 時:分」（Python の `astimezone(JST).strftime("%Y/%m/%d %H:%M")`）。
pub fn jst_minutes(ts: Timestamp) -> String {
    let utc = DateTime::from_timestamp(ts.unix_timestamp(), 0).unwrap_or_default();
    utc.with_timezone(&log_channel::jst())
        .format("%Y/%m/%d %H:%M")
        .to_string()
}

/// ID に入っている作られた時刻を、日本時間の「年/月/日 時:分」で。discord.py の `created_at`
/// （ユーザーならアカウントの作成日、メッセージなら送った時刻）。
pub fn snowflake_jst(id: u64) -> String {
    let ms = (id >> 22) as i64 + DISCORD_EPOCH_MS;
    let utc = DateTime::from_timestamp_millis(ms).unwrap_or_default();
    utc.with_timezone(&log_channel::jst())
        .format("%Y/%m/%d %H:%M")
        .to_string()
}

fn role_mention(id: RoleId) -> String {
    format!("<@&{id}>")
}

/// メンバーのロールを、discord.py の `member.roles` と同じ順に並べる（@everyone は除く）。
///
/// 並びは位置の低い順、同じ位置なら ID の大きい順（discord.py の `Role.__lt__`）。サーバーに
/// もう無いロールは落とす（discord.py は `guild.get_role` で引けないものを入れない）。
pub fn sorted_roles(
    member_roles: &[RoleId],
    guild_roles: &HashMap<RoleId, Role>,
    guild_id: GuildId,
) -> Vec<RoleId> {
    let mut roles: Vec<&Role> = member_roles
        .iter()
        .filter(|id| id.get() != guild_id.get())
        .filter_map(|id| guild_roles.get(id))
        .collect();
    roles.sort_by_key(|r| (r.position, std::cmp::Reverse(r.id.get())));
    roles.into_iter().map(|r| r.id).collect()
}

/// 参加。Python の `_on_member_join` のログ。
pub fn join_entry(member: &Member, member_count: u64) -> LogEntry {
    let joined = member
        .joined_at
        .map_or_else(|| "(不明)".to_string(), jst_minutes);
    LogEntry::new(
        Level::Info,
        format!(
            "{} がサーバーに参加しました。",
            compat::mention(member.user.id)
        ),
    )
    .field("ユーザーID", member.user.id.to_string())
    .field("アカウント作成日", snowflake_jst(member.user.id.get()))
    .field("参加日時", joined)
    .field("メンバー数", member_count.to_string())
}

/// 退出。Python の `_on_member_remove` のログ。`roles` は [`sorted_roles`] で並べたもの。
pub fn removal_entry(user: &User, roles: &[RoleId], member_count: u64) -> LogEntry {
    let held = if roles.is_empty() {
        "なし".to_string()
    } else {
        roles
            .iter()
            .map(|r| role_mention(*r))
            .collect::<Vec<_>>()
            .join(" ")
    };
    LogEntry::new(
        Level::Info,
        format!("{} がサーバーから退出しました。", compat::mention(user.id)),
    )
    .field("ユーザーID", user.id.to_string())
    .field("保有ロール", held)
    .field("メンバー数", member_count.to_string())
}

/// ニックネームの変更。変わっていなければ `None`。
pub fn nickname_entry(before: &Member, after: &Member) -> Option<LogEntry> {
    if before.nick == after.nick {
        return None;
    }
    let shown = |nick: &Option<String>| {
        nick.as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or("(なし)")
            .to_string()
    };
    Some(
        LogEntry::new(
            Level::Info,
            format!(
                "{} のニックネームが変更されました。",
                compat::mention(after.user.id)
            ),
        )
        .field("旧", shown(&before.nick))
        .field("新", shown(&after.nick)),
    )
}

/// ロールの変更。`before`・`after` は [`sorted_roles`] で並べたもの。変わっていなければ `None`。
pub fn role_entry(user_id: UserId, before: &[RoleId], after: &[RoleId]) -> Option<LogEntry> {
    let before_set: HashSet<RoleId> = before.iter().copied().collect();
    let after_set: HashSet<RoleId> = after.iter().copied().collect();
    let added: Vec<String> = after
        .iter()
        .filter(|r| !before_set.contains(r))
        .map(|r| role_mention(*r))
        .collect();
    let removed: Vec<String> = before
        .iter()
        .filter(|r| !after_set.contains(r))
        .map(|r| role_mention(*r))
        .collect();
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    let mut entry = LogEntry::new(
        Level::Info,
        format!("{} のロールが変更されました。", compat::mention(user_id)),
    );
    if !added.is_empty() {
        entry = entry.field("追加されたロール", added.join(" "));
    }
    if !removed.is_empty() {
        entry = entry.field("削除されたロール", removed.join(" "));
    }
    Some(entry)
}

/// タイムアウトの付与・解除。変わっていなければ `None`。
///
/// 付与は ERROR（橙）、解除は INFO。Python と同じく、終わった時刻が過去でも「付与」として扱う
/// （Discord から届いた値をそのまま比べる）。
pub fn timeout_entry(
    user_id: UserId,
    before: Option<Timestamp>,
    after: Option<Timestamp>,
) -> Option<LogEntry> {
    if before == after {
        return None;
    }
    let mention = compat::mention(user_id);
    Some(match after {
        Some(until) => {
            let mut e = LogEntry::new(
                Level::Error,
                format!("{mention} がタイムアウトされました。"),
            )
            .field("解除日時 (JST)", jst_minutes(until));
            e.colour = Some(ORANGE);
            e
        }
        None => LogEntry::new(
            Level::Info,
            format!("{mention} のタイムアウトが解除されました。"),
        ),
    })
}

/// BAN。ERROR（赤）。
pub fn ban_entry(user: &User) -> LogEntry {
    let mut e = LogEntry::new(
        Level::Error,
        format!("{} が BAN されました。", compat::mention(user.id)),
    )
    .field("ユーザーID", user.id.to_string())
    .field("ユーザー名", compat::user_tag(user));
    e.colour = Some(RED);
    e
}

/// BAN の解除。INFO（色は作者のアバター）。
pub fn unban_entry(user: &User) -> LogEntry {
    LogEntry::new(
        Level::Info,
        format!("{} の BAN が解除されました。", compat::mention(user.id)),
    )
    .field("ユーザーID", user.id.to_string())
    .field("ユーザー名", compat::user_tag(user))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const GUILD: u64 = 1_399_617_700_363_370_556;

    fn member(extra: Value) -> Member {
        let mut data = json!({
            "guild_id": GUILD.to_string(),
            "user": {"id": "80351110224678912", "username": "nelly", "discriminator": "0",
                     "avatar": null, "global_name": null},
            "nick": null, "avatar": null, "roles": [],
            "joined_at": "2026-11-25T00:05:00+00:00", "deaf": false, "mute": false, "flags": 0,
        });
        data.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(data).unwrap()
    }

    fn role(id: u64, position: i64) -> (RoleId, Role) {
        let r: Role = serde_json::from_value(json!({
            "id": id.to_string(), "name": format!("r{id}"), "color": 0, "hoist": false,
            "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
            "position": position, "permissions": "0", "managed": false, "mentionable": false,
            "flags": 0, "guild_id": GUILD.to_string(),
        }))
        .unwrap();
        (r.id, r)
    }

    fn ids(v: &[u64]) -> Vec<RoleId> {
        v.iter().map(|&i| RoleId::new(i)).collect()
    }

    /// 参加のログは、ID・作成日・参加日時（日本時間）・メンバー数の順。
    #[test]
    fn a_join_lists_id_creation_join_time_and_count() {
        let e = join_entry(&member(json!({})), 42);
        assert_eq!(e.level, Level::Info);
        assert_eq!(e.message, "<@80351110224678912> がサーバーに参加しました。");
        let names: Vec<&str> = e.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["ユーザーID", "アカウント作成日", "参加日時", "メンバー数"]
        );
        // ID から出る作成日（discord.py の snowflake_time と同じ式で Python で計算した値）。
        assert_eq!(e.fields[1].1, "2015/08/11 02:26");
        // 00:05 UTC は 09:05 JST。
        assert_eq!(e.fields[2].1, "2026/11/25 09:05");
        assert_eq!(e.fields[3].1, "42");
        let unknown = join_entry(&member(json!({"joined_at": null})), 0);
        assert_eq!(unknown.fields[2].1, "(不明)");
    }

    /// ロールは位置の低い順、同じ位置なら ID の大きい順。@everyone とサーバーに無いロールは除く。
    #[test]
    fn roles_are_ordered_like_discord_py() {
        let guild_roles: HashMap<RoleId, Role> = [
            role(GUILD, 0),
            role(10, 3),
            role(20, 1),
            role(30, 1),
            role(40, 2),
        ]
        .into_iter()
        .collect();
        let sorted = sorted_roles(
            &ids(&[10, GUILD, 99, 20, 40, 30]),
            &guild_roles,
            GuildId::new(GUILD),
        );
        assert_eq!(sorted, ids(&[30, 20, 40, 10]));
    }

    /// 退出のログは保有ロールを並べ、無ければ「なし」。
    #[test]
    fn a_removal_lists_held_roles_or_none() {
        let user = member(json!({})).user;
        let e = removal_entry(&user, &ids(&[30, 20]), 7);
        assert_eq!(e.fields[1], ("保有ロール".into(), "<@&30> <@&20>".into()));
        assert_eq!(e.fields[2].1, "7");
        assert_eq!(removal_entry(&user, &[], 7).fields[1].1, "なし");
    }

    /// ニックネームが同じなら書かず、無い・空は「(なし)」と書く。
    #[test]
    fn nickname_changes_show_none_for_missing_names() {
        let a = member(json!({"nick": null}));
        let b = member(json!({"nick": "新しい名前"}));
        assert!(nickname_entry(&a, &a).is_none());
        let e = nickname_entry(&a, &b).unwrap();
        assert_eq!(
            e.fields,
            [
                ("旧".into(), "(なし)".into()),
                ("新".into(), "新しい名前".into())
            ]
        );
        let empty = member(json!({"nick": ""}));
        assert_eq!(nickname_entry(&b, &empty).unwrap().fields[1].1, "(なし)");
    }

    /// 増えたロール・減ったロールを分けて書き、どちらも無ければ書かない。
    #[test]
    fn role_changes_split_added_and_removed() {
        let user = UserId::new(1);
        assert!(role_entry(user, &ids(&[1, 2]), &ids(&[1, 2])).is_none());
        let e = role_entry(user, &ids(&[1, 2]), &ids(&[2, 3, 4])).unwrap();
        assert_eq!(
            e.fields,
            [
                ("追加されたロール".into(), "<@&3> <@&4>".into()),
                ("削除されたロール".into(), "<@&1>".into())
            ]
        );
        let only_added = role_entry(user, &[], &ids(&[5])).unwrap();
        assert_eq!(only_added.fields.len(), 1);
    }

    /// タイムアウトの付与は ERROR・橙で解除日時つき、解除は INFO で項目なし。
    #[test]
    fn timeouts_are_errors_and_clearing_is_info() {
        let user = UserId::new(1);
        let until: Timestamp = "2026-11-25T03:30:00+00:00".parse().unwrap();
        assert!(timeout_entry(user, Some(until), Some(until)).is_none());
        let set = timeout_entry(user, None, Some(until)).unwrap();
        assert_eq!(set.level, Level::Error);
        assert_eq!(set.colour, Some(ORANGE));
        assert_eq!(
            set.fields,
            [("解除日時 (JST)".into(), "2026/11/25 12:30".into())]
        );
        let cleared = timeout_entry(user, Some(until), None).unwrap();
        assert_eq!(cleared.level, Level::Info);
        assert!(cleared.fields.is_empty());
        assert_eq!(cleared.colour, None);
    }

    /// BAN は ERROR・赤、解除は INFO・色はアバター。どちらも ID と名前を書く。
    #[test]
    fn bans_are_red_errors_and_unbans_are_info() {
        let user = member(json!({})).user;
        let ban = ban_entry(&user);
        assert_eq!((ban.level, ban.colour), (Level::Error, Some(RED)));
        assert_eq!(ban.fields[1], ("ユーザー名".into(), "nelly".into()));
        let unban = unban_entry(&user);
        assert_eq!((unban.level, unban.colour), (Level::Info, None));
        assert_eq!(
            unban.message,
            "<@80351110224678912> の BAN が解除されました。"
        );
    }

    /// 色が discord.py の Color.orange()・Color.red() と同じ値であること。
    #[test]
    fn colours_match_discord_py() {
        assert_eq!(ORANGE, 0xE67E22);
        assert_eq!(RED, 0xE74C3C);
    }
}
