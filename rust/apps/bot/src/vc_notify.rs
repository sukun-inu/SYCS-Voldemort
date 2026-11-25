//! VC の参加・退出・移動を、ログチャンネルと VC 通知チャンネルへ書く。Python の `events/voice.py` の
//! `_compute_vc_transition`・`_log_vc_transition`・`_passes_vc_notify_filter`・`_vc_notify_handler`。
//!
//! 読み上げ（TTS）と利用者の状態の記録は、それぞれの塊で同じイベントに足す。
//!
//! - 在室時間: 参加した時刻を覚え、退出で「時:分:秒」にする。移動しても参加の時刻は引き継ぐ。
//!   退出を取り逃した記録が増え続けないよう、256 件を超えたら 24 時間より古いものを捨てる
//! - 通知の絞り込み: フィルターのロールから見える（view_channel）VC の出入りだけを通知する。
//!   **ロールが見つからなければ通知しない**（消えたロールで絞り込みが外れ、非公開の VC の出入りが
//!   全員に漏れるのを防ぐ。Python で一度起きて直したもの）。移動は移動元・移動先のどちらかが見えれば通知する
//! - ロールのメンション: 参加・移動のときだけ、同じサーバーで 10 分に 1 回まで
//!
//! 「ロールから見えるか」の計算は discord.py の `GuildChannel.permissions_for(role)` と同じ順:
//! @everyone の権限 ＋ そのロールの権限 → 管理者なら全部 → @everyone の上書き → そのロールの上書き。

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Datelike, Timelike};
use serenity::all::{
    CreateEmbed, CreateEmbedAuthor, GuildChannel, GuildId, PermissionOverwriteType, Permissions,
    Role, RoleId, Timestamp,
};

use crate::compat;
use crate::log_channel::{self, Level};
use crate::members::LogEntry;

/// 参加の時刻を覚えておく長さ（退出を取り逃した記録を捨てる目安）。Python と同じ 24 時間。
const JOIN_TTL_SECONDS: f64 = 24.0 * 3600.0;
/// これを超えたら古い記録を間引く。
const JOIN_PRUNE_ABOVE: usize = 256;
/// ロールのメンションの間隔（秒）。
const MENTION_INTERVAL_SECONDS: f64 = 600.0;
const WEEKDAYS: [&str; 7] = [
    "月曜日",
    "火曜日",
    "水曜日",
    "木曜日",
    "金曜日",
    "土曜日",
    "日曜日",
];

/// discord.py の `Color.green()`・`Color.red()`・`Color.blurple()`。
pub const GREEN: u32 = 0x2E_CC_71;
/// 退出の色。
pub const RED: u32 = 0xE7_4C_3C;
/// 移動の色。
pub const BLURPLE: u32 = 0x58_65_F2;

/// 何が起きたか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// VC に入った。
    Join,
    /// VC から出た。
    Leave,
    /// 別の VC へ移った。
    Move,
}

/// 前後のチャンネルから、何が起きたかを決める（ミュートなど同じチャンネルのままなら `None`）。
pub fn change_of(before: Option<u64>, after: Option<u64>) -> Option<Change> {
    match (before, after) {
        (None, Some(_)) => Some(Change::Join),
        (Some(_), None) => Some(Change::Leave),
        (Some(b), Some(a)) if b != a => Some(Change::Move),
        _ => None,
    }
}

/// 在室時間を「時:分:秒」に（時が 100 を超えても桁を切らない）。
pub fn duration_text(seconds: i64) -> String {
    let (h, r) = (seconds / 3600, seconds % 3600);
    format!("{h:02}:{:02}:{:02}", r / 60, r % 60)
}

/// 呼び出しをまたいで持つもの（参加の時刻・最後のメンション・フィルターのロールの警告）。
#[derive(Default)]
pub struct VcTracker {
    joined: Mutex<HashMap<(u64, u64), f64>>,
    last_mention: Mutex<HashMap<u64, f64>>,
    warned_missing_role: Mutex<HashMap<u64, i64>>,
}

impl VcTracker {
    /// 参加の時刻を覚え、退出なら在室時間（秒・文字）を返す。Python の `_compute_vc_transition`。
    pub fn track(&self, key: (u64, u64), now: f64, change: Change) -> Option<(i64, String)> {
        let mut joined = self.joined.lock().unwrap_or_else(|p| p.into_inner());
        match change {
            Change::Join => {
                joined.insert(key, now);
                if joined.len() > JOIN_PRUNE_ABOVE {
                    let cutoff = now - JOIN_TTL_SECONDS;
                    joined.retain(|_, at| *at >= cutoff);
                }
                None
            }
            Change::Leave => joined.remove(&key).map(|at| {
                // Python の int() は 0 へ向けて切り捨てる。
                let seconds = (now - at) as i64;
                (seconds, duration_text(seconds))
            }),
            Change::Move => None,
        }
    }

    /// このサーバーでロールのメンションを付けてよいか（10 分に 1 回）。付けるなら時刻を覚える。
    pub fn take_mention(&self, guild_id: u64, now: f64) -> bool {
        let mut last = self.last_mention.lock().unwrap_or_else(|p| p.into_inner());
        if now - last.get(&guild_id).copied().unwrap_or(0.0) >= MENTION_INTERVAL_SECONDS {
            last.insert(guild_id, now);
            true
        } else {
            false
        }
    }

    /// フィルターのロールが見つからないことを、ギルド・ロールごとに 1 回だけ警告するか。
    fn should_warn_missing(&self, guild_id: u64, role_id: i64) -> bool {
        let mut warned = self
            .warned_missing_role
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        warned.insert(guild_id, role_id) != Some(role_id)
    }

    fn found_role(&self, guild_id: u64) {
        self.warned_missing_role
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&guild_id);
    }
}

/// ログチャンネルへ書く中身。Python の `_log_vc_transition`。
pub fn log_entry(
    change: Change,
    user_mention: &str,
    before: Option<u64>,
    after: Option<u64>,
) -> LogEntry {
    let ch = |id: Option<u64>| format!("<#{}>", id.unwrap_or_default());
    let (message, fields) = match change {
        Change::Join => (
            format!("{user_mention} が VC に参加しました。"),
            vec![("チャンネル".to_string(), ch(after))],
        ),
        Change::Leave => (
            format!("{user_mention} が VC から退出しました。"),
            vec![("チャンネル".to_string(), ch(before))],
        ),
        Change::Move => (
            format!("{user_mention} が VC を移動しました。"),
            vec![
                ("移動前".to_string(), ch(before)),
                ("移動後".to_string(), ch(after)),
            ],
        ),
    };
    LogEntry {
        level: Level::Info,
        message,
        fields,
        colour: None,
    }
}

/// 通知に出す時刻（日本時間）。「2026年11月25日 水曜日 9:05」の形。
pub fn time_text(now: f64) -> String {
    let utc = DateTime::from_timestamp(now.floor() as i64, 0).unwrap_or_default();
    let t = utc.with_timezone(&log_channel::jst());
    format!(
        "{}年{}月{}日 {} {}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        WEEKDAYS[t.weekday().num_days_from_monday() as usize],
        t.hour(),
        t.minute()
    )
}

/// 通知に出す人。
pub struct Person<'a> {
    /// 表示名（ニックネーム → 表示名 → ユーザー名）。
    pub display_name: &'a str,
    /// アバター（サーバーごとのものがあればそちら）。
    pub avatar_url: &'a str,
}

/// VC 通知の Embed。Python の `_vc_notify_handler` の Embed。
pub fn notify_embed(
    change: Change,
    who: &Person<'_>,
    before_name: &str,
    after_name: &str,
    time: &str,
    duration: Option<&str>,
    at: Timestamp,
) -> CreateEmbed {
    let (title, description, colour) = match change {
        Change::Join => (
            "VCに参加しました",
            format!("🔊 **{after_name}** に参加しました\n\n{time}"),
            GREEN,
        ),
        Change::Leave => {
            let mut text = format!("🔊 **{before_name}** から退出しました\n\n{time}");
            if let Some(d) = duration.filter(|d| !d.is_empty()) {
                text.push_str(&format!("\n通話時間: {d}"));
            }
            ("VCから切断しました", text, RED)
        }
        Change::Move => (
            "VCを移動しました",
            format!("🔊 **{before_name}** → **{after_name}**\n\n{time}"),
            BLURPLE,
        ),
    };
    CreateEmbed::new()
        .title(title)
        .description(description)
        .colour(colour)
        .timestamp(at)
        .author(CreateEmbedAuthor::new(who.display_name).icon_url(who.avatar_url))
        .thumbnail(who.avatar_url)
}

/// discord.py の `display_name`（ニックネーム → 表示名 → ユーザー名。空の文字は飛ばす）。
pub fn display_name<'a>(
    nick: Option<&'a str>,
    global_name: Option<&'a str>,
    name: &'a str,
) -> &'a str {
    nick.filter(|n| !n.is_empty())
        .or(global_name.filter(|n| !n.is_empty()))
        .unwrap_or(name)
}

/// そのロールの人から、このチャンネルが見えるか。discord.py の `permissions_for(role).view_channel`。
pub fn visible_to_role(
    channel: &GuildChannel,
    role: &Role,
    everyone: Option<&Role>,
    guild_id: GuildId,
) -> bool {
    let mut base = everyone.map_or(Permissions::empty(), |e| e.permissions) | role.permissions;
    if base.contains(Permissions::ADMINISTRATOR) {
        return true;
    }
    let apply = |base: &mut Permissions, allow: Permissions, deny: Permissions| {
        *base = (*base & !deny) | allow;
    };
    let everyone_id = RoleId::new(guild_id.get());
    let role_overwrite = |id: RoleId| {
        channel
            .permission_overwrites
            .iter()
            .find(|o| o.kind == PermissionOverwriteType::Role(id))
    };
    if let Some(o) = role_overwrite(everyone_id) {
        apply(&mut base, o.allow, o.deny);
    }
    if role.id != everyone_id
        && let Some(o) = role_overwrite(role.id)
    {
        apply(&mut base, o.allow, o.deny);
    }
    base.contains(Permissions::VIEW_CHANNEL)
}

/// 絞り込みの結果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// 通知してよい（絞り込みが無い・見える）。
    Pass,
    /// 見えないので通知しない。
    Hidden,
    /// フィルターのロールが見つからないので通知しない（警告を出すべきなら `true`）。
    MissingRole(bool),
}

/// 通知してよいか。Python の `_passes_vc_notify_filter`。
///
/// `filter_role_id` は設定の値を Python の `int()` と同じく読んだもの（0 なら絞り込み無し）。
pub fn passes_filter(
    tracker: &VcTracker,
    guild_id: GuildId,
    filter_role_id: i64,
    roles: &HashMap<RoleId, Role>,
    change: Change,
    before: Option<&GuildChannel>,
    after: Option<&GuildChannel>,
) -> Filter {
    if filter_role_id == 0 {
        return Filter::Pass;
    }
    let role = u64::try_from(filter_role_id)
        .ok()
        .filter(|id| *id > 0)
        .and_then(|id| roles.get(&RoleId::new(id)));
    let Some(role) = role else {
        return Filter::MissingRole(tracker.should_warn_missing(guild_id.get(), filter_role_id));
    };
    tracker.found_role(guild_id.get());
    let everyone = roles.get(&RoleId::new(guild_id.get()));
    let related: Vec<Option<&GuildChannel>> = match change {
        Change::Move => vec![before, after],
        Change::Join => vec![after],
        Change::Leave => vec![before],
    };
    let visible = related
        .into_iter()
        .flatten()
        .any(|c| visible_to_role(c, role, everyone, guild_id));
    if visible {
        Filter::Pass
    } else {
        Filter::Hidden
    }
}

/// ロールのメンションを付けるなら、その本文（`<@&ロールID>`）。退出には付けない。
pub fn mention_content(
    tracker: &VcTracker,
    guild_id: u64,
    role_id: i64,
    change: Change,
    now: f64,
) -> Option<String> {
    (role_id != 0 && change != Change::Leave && tracker.take_mention(guild_id, now))
        .then(|| format!("<@&{role_id}>"))
}

/// 通知を組むのに要るもの（1 回の出入りぶん）。
pub struct NoticeInput<'a> {
    /// サーバー。
    pub guild_id: GuildId,
    /// 出入りした人。
    pub member: &'a serenity::all::Member,
    /// 何が起きたか。
    pub change: Change,
    /// 前のチャンネル。
    pub before: Option<&'a GuildChannel>,
    /// 後のチャンネル。
    pub after: Option<&'a GuildChannel>,
    /// サーバーのロール（絞り込みに使う）。
    pub roles: &'a HashMap<RoleId, Role>,
    /// いまの時刻（UNIX 秒）。
    pub now: f64,
    /// 在室時間（退出のとき）。
    pub stay: Option<&'a str>,
    /// Embed に付ける時刻。
    pub at: Timestamp,
}

/// 何を送るか。
pub enum Plan {
    /// 送らない（通知チャンネルが未設定・テキストチャンネルでない）。
    Nothing,
    /// 絞り込みで止めた。
    Filtered(Filter),
    /// このチャンネルへ送る。
    Send {
        /// 送り先。
        channel_id: u64,
        /// ロールのメンション（付けるときだけ）。
        content: Option<String>,
        /// 通知の Embed。
        embed: Box<CreateEmbed>,
    },
}

/// 設定を読んで、何を送るかを決める。Python の `_vc_notify_handler`（送る手前まで）。
///
/// 設定の数は Python の `_get_int_setting`（`int()` で読み、読めなければ 0）と同じく読む。
/// `is_text_channel` は、そのサーバーのテキストチャンネルかを答える。
pub fn plan(
    tracker: &VcTracker,
    guild_settings: Option<&serde_json::Value>,
    is_text_channel: impl Fn(u64) -> bool,
    input: &NoticeInput<'_>,
) -> Plan {
    let int_of = |key: &str| {
        guild_settings
            .and_then(|g| g.get(key))
            .and_then(log_channel::python_int)
            .unwrap_or(0)
    };
    let channel_id = u64::try_from(int_of("vc_notify_channel_id"))
        .ok()
        .filter(|id| *id > 0 && is_text_channel(*id));
    let Some(channel_id) = channel_id else {
        return Plan::Nothing;
    };
    let filter = passes_filter(
        tracker,
        input.guild_id,
        int_of("vc_notify_filter_role_id"),
        input.roles,
        input.change,
        input.before,
        input.after,
    );
    if filter != Filter::Pass {
        return Plan::Filtered(filter);
    }
    let (display_name, avatar_url) = person_parts(input.member);
    let who = Person {
        display_name: &display_name,
        avatar_url: &avatar_url,
    };
    let embed = notify_embed(
        input.change,
        &who,
        input.before.map_or("", |c| c.name.as_str()),
        input.after.map_or("", |c| c.name.as_str()),
        &time_text(input.now),
        input.stay,
        input.at,
    );
    let content = mention_content(
        tracker,
        input.guild_id.get(),
        int_of("vc_notify_role_id"),
        input.change,
        input.now,
    );
    Plan::Send {
        channel_id,
        content,
        embed: Box::new(embed),
    }
}

/// 通知に出す人の表示名とアイコン。
pub fn person_parts(member: &serenity::all::Member) -> (String, String) {
    let name = display_name(
        member.nick.as_deref(),
        member.user.global_name.as_deref(),
        &member.user.name,
    )
    .to_string();
    (name, compat::member_avatar_url(member))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serenity::all::Permissions as P;

    use super::*;

    const GUILD: u64 = 1_399_617_700_363_370_556;

    fn role(id: u64, permissions: u64) -> Role {
        serde_json::from_value(json!({
            "id": id.to_string(), "name": format!("r{id}"), "color": 0,
            "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
            "hoist": false, "position": 1, "permissions": permissions.to_string(),
            "managed": false, "mentionable": false, "flags": 0, "guild_id": GUILD.to_string(),
        }))
        .unwrap()
    }

    fn channel(id: u64, overwrites: serde_json::Value) -> GuildChannel {
        serde_json::from_value(json!({
            "id": id.to_string(), "type": 2, "guild_id": GUILD.to_string(), "name": format!("vc{id}"),
            "position": 0, "permission_overwrites": overwrites, "nsfw": false, "bitrate": 64000,
            "user_limit": 0, "rate_limit_per_user": 0,
        }))
        .unwrap()
    }

    fn ow(id: u64, allow: u64, deny: u64) -> serde_json::Value {
        json!({"id": id.to_string(), "type": 0, "allow": allow.to_string(), "deny": deny.to_string()})
    }

    const VIEW: u64 = 1 << 10;

    /// 参加・退出・移動を前後のチャンネルで決め、同じチャンネルのままなら何も起きない。
    #[test]
    fn changes_follow_the_channels() {
        assert_eq!(change_of(None, Some(1)), Some(Change::Join));
        assert_eq!(change_of(Some(1), None), Some(Change::Leave));
        assert_eq!(change_of(Some(1), Some(2)), Some(Change::Move));
        assert_eq!(change_of(Some(1), Some(1)), None);
        assert_eq!(change_of(None, None), None);
    }

    /// 退出で在室時間を出し、移動をはさんでも参加の時刻から数えること。
    #[test]
    fn the_stay_is_counted_from_the_join_across_moves() {
        let t = VcTracker::default();
        assert_eq!(t.track((1, 2), 100.0, Change::Join), None);
        assert_eq!(t.track((1, 2), 200.0, Change::Move), None);
        assert_eq!(
            t.track((1, 2), 100.0 + 3723.9, Change::Leave),
            Some((3723, "01:02:03".into()))
        );
        // 2 回目の退出（参加を見ていない）は時間なし。
        assert_eq!(t.track((1, 2), 5000.0, Change::Leave), None);
        assert_eq!(duration_text(360_000), "100:00:00");
    }

    /// 記録が 256 件を超えたら、24 時間より古いものを捨てること。
    #[test]
    fn stale_joins_are_pruned_past_256() {
        // Python の _VC_JOIN_TTL_SECONDS（24 時間）と 256 件。
        assert_eq!(JOIN_TTL_SECONDS, 86_400.0);
        assert_eq!(JOIN_PRUNE_ABOVE, 256);
        let t = VcTracker::default();
        for u in 0..256 {
            t.track((1, u), 0.0, Change::Join);
        }
        let now = JOIN_TTL_SECONDS + 10.0;
        t.track((1, 999), now, Change::Join);
        assert_eq!(t.joined.lock().unwrap().len(), 1);
        assert!(t.track((1, 0), now, Change::Leave).is_none());
    }

    /// メンションは 10 分に 1 回、退出には付けないこと。
    #[test]
    fn mentions_are_rate_limited_and_skip_leaves() {
        let t = VcTracker::default();
        assert_eq!(mention_content(&t, 1, 0, Change::Join, 1000.0), None);
        assert_eq!(mention_content(&t, 1, 55, Change::Leave, 1000.0), None);
        assert_eq!(
            mention_content(&t, 1, 55, Change::Join, 1000.0).as_deref(),
            Some("<@&55>")
        );
        assert_eq!(mention_content(&t, 1, 55, Change::Move, 1599.0), None);
        assert!(mention_content(&t, 1, 55, Change::Move, 1600.0).is_some());
        // ほかのサーバーは別に数える。
        assert!(mention_content(&t, 2, 55, Change::Join, 1600.0).is_some());
    }

    /// ロールから見えるかを discord.py と同じ順で計算すること。
    #[test]
    fn visibility_follows_discord_py_order() {
        let g = GuildId::new(GUILD);
        let everyone = role(GUILD, VIEW);
        let member_role = role(7, 0);
        // 上書きが無ければ @everyone の権限のまま見える。
        assert!(visible_to_role(
            &channel(1, json!([])),
            &member_role,
            Some(&everyone),
            g
        ));
        // @everyone の上書きで隠すと見えない。
        let hidden = channel(2, json!([ow(GUILD, 0, VIEW)]));
        assert!(!visible_to_role(&hidden, &member_role, Some(&everyone), g));
        // そのロールの上書きで許せば見える（@everyone の上書きより後に当てる）。
        let allowed = channel(3, json!([ow(GUILD, 0, VIEW), ow(7, VIEW, 0)]));
        assert!(visible_to_role(&allowed, &member_role, Some(&everyone), g));
        // 管理者は上書きに関係なく見える。
        let admin = role(8, P::ADMINISTRATOR.bits());
        assert!(visible_to_role(&hidden, &admin, Some(&everyone), g));
        // ほかのロールの上書きは関係ない。
        let other = channel(4, json!([ow(GUILD, 0, VIEW), ow(9, VIEW, 0)]));
        assert!(!visible_to_role(&other, &member_role, Some(&everyone), g));
    }

    /// 絞り込み: 無ければ通す、ロールが無ければ止める（警告は 1 回）、移動はどちらかが見えれば通す。
    #[test]
    fn the_filter_fails_closed() {
        let t = VcTracker::default();
        let g = GuildId::new(GUILD);
        let roles: HashMap<RoleId, Role> = [role(GUILD, VIEW), role(7, 0)]
            .into_iter()
            .map(|r| (r.id, r))
            .collect();
        let open = channel(1, json!([]));
        let hidden = channel(2, json!([ow(GUILD, 0, VIEW)]));
        assert_eq!(
            passes_filter(&t, g, 0, &roles, Change::Join, None, Some(&hidden)),
            Filter::Pass
        );
        assert_eq!(
            passes_filter(&t, g, 99, &roles, Change::Join, None, Some(&open)),
            Filter::MissingRole(true)
        );
        assert_eq!(
            passes_filter(&t, g, 99, &roles, Change::Join, None, Some(&open)),
            Filter::MissingRole(false),
            "同じロールの警告を繰り返した"
        );
        assert_eq!(
            passes_filter(&t, g, -5, &roles, Change::Join, None, Some(&open)),
            Filter::MissingRole(true)
        );
        assert_eq!(
            passes_filter(&t, g, 7, &roles, Change::Join, None, Some(&hidden)),
            Filter::Hidden
        );
        assert_eq!(
            passes_filter(&t, g, 7, &roles, Change::Move, Some(&hidden), Some(&open)),
            Filter::Pass
        );
        assert_eq!(
            passes_filter(&t, g, 7, &roles, Change::Leave, Some(&hidden), Some(&open)),
            Filter::Hidden
        );
        // 移動は移動元だけが見えても通知する（移動先だけで決めると、見える VC から見えない VC への
        // 移動が漏れる…のではなく、見える VC からの移動が通知されなくなる）。
        assert_eq!(
            passes_filter(&t, g, 7, &roles, Change::Move, Some(&open), Some(&hidden)),
            Filter::Pass
        );
        assert_eq!(
            passes_filter(&t, g, 7, &roles, Change::Move, Some(&hidden), Some(&hidden)),
            Filter::Hidden
        );
    }

    /// 時刻の書き方（日本時間・曜日・分は 2 桁・時は 0 埋めしない）。
    #[test]
    fn the_time_text_looks_like_python() {
        // 2026-11-25 00:05:09 UTC = 09:05 JST の水曜日
        let now = 1_795_565_109.7;
        assert_eq!(time_text(now), "2026年11月25日 水曜日 9:05");
    }

    /// 表示名はニックネーム → 表示名 → ユーザー名の順（空は飛ばす）。
    #[test]
    fn display_names_fall_back_in_order() {
        assert_eq!(display_name(Some("ニック"), Some("表示"), "user"), "ニック");
        assert_eq!(display_name(Some(""), Some("表示"), "user"), "表示");
        assert_eq!(display_name(None, None, "user"), "user");
    }

    fn member() -> serenity::all::Member {
        serde_json::from_value(json!({
            "guild_id": GUILD.to_string(),
            "user": {"id": "80351110224678912", "username": "nelly", "discriminator": "0",
                     "avatar": null, "global_name": "表示"},
            "nick": null, "avatar": null, "roles": [], "joined_at": "2026-01-01T00:00:00+00:00",
            "deaf": false, "mute": false, "flags": 0,
        }))
        .unwrap()
    }

    /// 設定の鍵（vc_notify_channel_id・vc_notify_filter_role_id・vc_notify_role_id）から、何を送るかを決めること。
    #[test]
    fn the_plan_reads_the_settings() {
        let g = GuildId::new(GUILD);
        let roles: HashMap<RoleId, Role> = [
            role(GUILD, VIEW),
            role(7, 0),
            role(8, P::ADMINISTRATOR.bits()),
        ]
        .into_iter()
        .map(|r| (r.id, r))
        .collect();
        let m = member();
        let hidden = channel(2, json!([ow(GUILD, 0, VIEW)]));
        let input = NoticeInput {
            guild_id: g,
            member: &m,
            change: Change::Join,
            before: None,
            after: Some(&hidden),
            roles: &roles,
            now: 1_000.0,
            stay: None,
            at: Timestamp::now(),
        };
        let is_text = |id: u64| id == 500;
        let t = VcTracker::default();
        let plan_for = |settings: serde_json::Value| plan(&t, Some(&settings), is_text, &input);
        assert!(matches!(plan_for(json!({})), Plan::Nothing));
        assert!(matches!(
            plan_for(json!({"vc_notify_channel_id": 501})),
            Plan::Nothing
        ));
        match plan_for(json!({"vc_notify_channel_id": "500", "vc_notify_role_id": 77})) {
            Plan::Send {
                channel_id,
                content,
                embed,
            } => {
                assert_eq!(channel_id, 500);
                assert_eq!(content.as_deref(), Some("<@&77>"));
                let v = serde_json::to_value(*embed).unwrap();
                assert_eq!(v["author"]["name"], "表示");
                assert_eq!(v["title"], "VCに参加しました");
            }
            _ => panic!("送るはず"),
        }
        assert!(matches!(
            plan_for(json!({"vc_notify_channel_id": 500, "vc_notify_filter_role_id": 7})),
            Plan::Filtered(Filter::Hidden)
        ));
        // 小数は切り捨てて読む（8.9 → 8 の管理者なら見える。四捨五入の 9 は無いロール）。
        assert!(matches!(
            plan_for(json!({"vc_notify_channel_id": 500, "vc_notify_filter_role_id": 8.9})),
            Plan::Send { .. }
        ));
    }

    /// 退出の通知は在室時間があれば最後の行に書くこと。
    #[test]
    fn a_leave_notice_ends_with_the_stay() {
        let who = Person {
            display_name: "nelly",
            avatar_url: "https://a",
        };
        let at = Timestamp::now();
        let v = serde_json::to_value(notify_embed(
            Change::Leave,
            &who,
            "雑談",
            "",
            "T",
            Some("00:01:02"),
            at,
        ))
        .unwrap();
        assert_eq!(
            v["description"],
            "🔊 **雑談** から退出しました\n\nT\n通話時間: 00:01:02"
        );
        assert_eq!(v["color"], RED);
        assert_eq!(v["thumbnail"]["url"], "https://a");
        let none =
            serde_json::to_value(notify_embed(Change::Leave, &who, "雑談", "", "T", None, at))
                .unwrap();
        assert_eq!(none["description"], "🔊 **雑談** から退出しました\n\nT");
    }
}
