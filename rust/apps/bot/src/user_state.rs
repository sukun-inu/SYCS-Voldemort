//! 利用者の状態の記録。入退室・キック・BAN・ニックネーム／ロール／タイムアウトの変更・VC の出入りを、
//! 履歴（`user_state_event`）と最新状態（`user_state_current`）の 2 つの表に書く。
//!
//! Python の `services/user_state_service.py` の `record_user_state_event` と、それを呼ぶ側
//! （`events/members.py`・`events/voice.py`）が組み立てる中身、キック・BAN の実行者を監査ログから探す
//! `events/user_state_sync.py` の `_find_recent_audit_entry`。
//!
//! 揃えてあるもの（本物の Python と同じイベントを同じ Postgres に書いて、行を比べて確かめた）:
//!
//! - 表の形（列・型・既定値・索引・制約）。無ければ作る（Python の `ensure_user_state_db`）
//! - 履歴の 1 行: 種類・状態・実行者・理由・中身の JSON（**文字まで同じ**。Python の `json.dumps` と同じく
//!   区切りは `", "` と `": "`、ASCII 以外はそのまま。鍵の並びも同じ）・時刻
//! - 最新状態の 1 行: 名前とアバターは分かるときだけ上書き、在室・BAN の旗、タイムアウトの期限と旗、
//!   ロールと権限の控え、最後に入った・抜けた時刻
//! - メンバーのときだけ、ロール（位置の高い順）と権限（`guild_permissions` と同じ計算。所有者と管理者は
//!   全部、タイムアウト中は閲覧だけ）・信頼ユーザー・バイパスロール・Bot かを控える
//! - 退出（キックも）のとき、いま BAN 中（最新状態の BAN の旗が立っている）なら BAN を残す。状態は `banned`
//!   のまま（同期が BAN 一覧から直すときと同じ形）で、履歴の状態も同じ（Python の `_keep_ban_on_leave`）。
//!   BAN の直後に届く退出が、最新状態を「left・BAN でない」で上書きしていたのを直したもの
//! - 履歴と最新状態は 1 つのトランザクションで書く。失敗しても呼んだ側（イベントの処理）は止めない
//! - 表が無いなどの失敗（SQLSTATE 42 系）は、表を作り直して 1 回だけやり直す（自己修復）
//! - 保管期間（既定 10 年。短くはできない）を過ぎた履歴の掃除を、6 時間に 1 回、記録のついでにする。
//!   掃除の失敗で記録は止めない
//!
//! Python と変えたところ（どちらも、取りこぼしを無くす側）:
//!
//! - 最新状態の行が無い人のイベントが同時に 2 つ来ても、両方残す。Python は両方が行を作ろうとして片方が
//!   一意制約で落ち、そのイベントは履歴にも残らない
//! - 同じ人のイベントが重なっても、最新状態は 1 件ずつ順に当たる（行の錠で待つ）。Python は読んでから書く
//!   ので、重なると後から書いた方が先の変更を古い値で上書きしうる
//!
//! 起動時と定期の同期は [`crate::user_state_sync`]、整合性の修復とギルドのデータの削除は
//! [`crate::user_state_repair`] が持つ（どちらもここの部品を使う）。

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Map, Value, json};
use serenity::all::{
    Cache, GuildId, Http, Member, Permissions, Role, RoleId, Timestamp, User, UserId,
};
use serenity::model::guild::audit_log::{Action, MemberAction};
use sqlx::{PgConnection, PgPool};
use sycs_core::env::Env;
use tracing::{debug, error, info, warn};

use crate::groq::python_is_space;
use crate::log_channel::python_int;
use crate::vc_notify::Change;
use crate::{compat, members, vc_notify};

/// 履歴を残す日数の既定と下限（10 年）。**短くはできない**（監査の履歴を 10 年残すのは機能としての約束で、
/// 誤って短い値を入れただけで早く消える事故を防ぐ）。伸ばす方向だけ受け付ける。
pub const RETENTION_DAYS: i64 = 3650;
/// 掃除の間隔の既定（秒）。
pub const CLEANUP_INTERVAL_SECONDS: i64 = 21_600;
/// Discord の ID が数え始める時刻（2015-01-01 UTC、ミリ秒）。
const DISCORD_EPOCH_MS: i64 = 1_420_070_400_000;
/// 監査ログで、イベントと同じものとみなす秒数。
pub const AUDIT_WINDOW_SECONDS: i64 = 20;
/// 監査ログを探し直す回数（最初の 1 回のあと）。
pub const AUDIT_RETRIES: u32 = 2;
/// 監査ログを探し直すまでの待ち。Discord 側の反映が数百ミリ秒〜数秒遅れることがある。
pub const AUDIT_RETRY_DELAY: Duration = Duration::from_millis(600);
/// 監査ログを 1 回に読む件数。Python の `_AUDIT_LOG_LIMIT`（50）。以前は 10 件で、短い間にキックや BAN が 10 件を
/// 超えると実行者が分からなくなっていた（本人の決定 2026-11-28、rust-10 の (c)・決めごとの U2）。時間の枠は変えない。
const AUDIT_LIMIT: u8 = 50;

/// 表と索引を作る文。Python（SQLAlchemy）が作るものと同じ形（突き合わせで確かめた）。
pub const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS user_state_current (\
        id SERIAL NOT NULL, \
        guild_id BIGINT NOT NULL, \
        user_id BIGINT NOT NULL, \
        username VARCHAR(128), \
        display_name VARCHAR(128), \
        avatar_url VARCHAR(512), \
        status VARCHAR(32) NOT NULL, \
        is_in_guild BOOLEAN NOT NULL, \
        is_banned BOOLEAN NOT NULL, \
        is_timed_out BOOLEAN NOT NULL, \
        timed_out_until TIMESTAMP WITH TIME ZONE, \
        roles_json TEXT NOT NULL, \
        abilities_json TEXT NOT NULL, \
        last_event_type VARCHAR(48), \
        last_event_at TIMESTAMP WITH TIME ZONE, \
        first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        last_joined_at TIMESTAMP WITH TIME ZONE, \
        last_left_at TIMESTAMP WITH TIME ZONE, \
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        PRIMARY KEY (id), \
        CONSTRAINT uq_user_state_current_guild_user UNIQUE (guild_id, user_id))",
    "CREATE INDEX IF NOT EXISTS ix_user_state_current_guild_last_event_at \
        ON user_state_current (guild_id, last_event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_current_guild_status \
        ON user_state_current (guild_id, status)",
    "CREATE TABLE IF NOT EXISTS user_state_event (\
        id SERIAL NOT NULL, \
        guild_id BIGINT NOT NULL, \
        user_id BIGINT NOT NULL, \
        event_type VARCHAR(48) NOT NULL, \
        status_after VARCHAR(32) NOT NULL, \
        actor_user_id BIGINT, \
        actor_name VARCHAR(128), \
        reason TEXT, \
        payload_json TEXT NOT NULL, \
        event_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        PRIMARY KEY (id))",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_event_at ON user_state_event (event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_guild_event_type_event_at \
        ON user_state_event (guild_id, event_type, event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_guild_user_event_at \
        ON user_state_event (guild_id, user_id, event_at)",
];

const INSERT_EVENT: &str = "INSERT INTO user_state_event \
    (guild_id, user_id, event_type, status_after, actor_user_id, actor_name, reason, payload_json, event_at) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz)";

/// 最新状態の空の行。中身は直後の [`UPDATE_CURRENT`] が埋める。
const INSERT_BLANK_CURRENT: &str = "INSERT INTO user_state_current \
    (guild_id, user_id, status, is_in_guild, is_banned, is_timed_out, roles_json, abilities_json) \
    VALUES ($1, $2, 'unknown', FALSE, FALSE, FALSE, '[]', '{}') \
    ON CONFLICT (guild_id, user_id) DO NOTHING";

/// 最新状態を、渡された新しい状態で書き換える。Python の `_update_current_state_fields`。
///
/// NULL を渡した項目は「今回のイベントでは分からない」で、今の値を残す。タイムアウトは、期限を渡されたら
/// それで、解除のイベントなら消し、どちらでもなければ今の期限から旗だけ数え直す。
const UPDATE_CURRENT: &str = "UPDATE user_state_current SET \
    username = COALESCE($3, username), \
    display_name = COALESCE($4, display_name), \
    avatar_url = COALESCE($5, avatar_url), \
    status = $6, \
    last_event_type = $7, \
    last_event_at = $8::timestamptz, \
    updated_at = $8::timestamptz, \
    is_in_guild = COALESCE($9, is_in_guild), \
    is_banned = COALESCE($10, is_banned), \
    is_timed_out = CASE \
        WHEN $11::timestamptz IS NOT NULL THEN $11::timestamptz > $8::timestamptz \
        WHEN $12 THEN FALSE \
        WHEN timed_out_until IS NOT NULL THEN timed_out_until > $8::timestamptz \
        ELSE is_timed_out END, \
    timed_out_until = CASE \
        WHEN $11::timestamptz IS NOT NULL THEN $11::timestamptz \
        WHEN $12 THEN NULL \
        ELSE timed_out_until END, \
    roles_json = COALESCE($13, roles_json), \
    abilities_json = COALESCE($14, abilities_json), \
    last_joined_at = CASE WHEN $15 THEN $8::timestamptz ELSE last_joined_at END, \
    last_left_at = CASE WHEN $16 THEN $8::timestamptz ELSE last_left_at END \
    WHERE guild_id = $1 AND user_id = $2";

/// いま BAN 中かを読み、行の錠を取る（退出・キックのとき。[`Write::keep_ban`]）。
const SELECT_BANNED_FOR_UPDATE: &str =
    "SELECT is_banned FROM user_state_current WHERE guild_id = $1 AND user_id = $2 FOR UPDATE";

const DELETE_OLD_EVENTS: &str = "DELETE FROM user_state_event WHERE event_at < $1::timestamptz";

/// 設定。環境変数の名前・既定・下限は Python と同じ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserStateConfig {
    /// 履歴を残す日数（`USER_STATE_RETENTION_DAYS`、既定も下限も 3650）。
    pub retention_days: i64,
    /// 掃除の間隔（秒、`USER_STATE_CLEANUP_INTERVAL_SECONDS`、既定 21600・下限 300）。
    pub cleanup_interval_seconds: i64,
}

impl UserStateConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        Self {
            retention_days: env.int(
                "USER_STATE_RETENTION_DAYS",
                RETENTION_DAYS,
                Some(RETENTION_DAYS),
                None,
            ),
            cleanup_interval_seconds: env.int(
                "USER_STATE_CLEANUP_INTERVAL_SECONDS",
                CLEANUP_INTERVAL_SECONDS,
                Some(300),
                None,
            ),
        }
    }
}

impl Default for UserStateConfig {
    fn default() -> Self {
        Self {
            retention_days: RETENTION_DAYS,
            cleanup_interval_seconds: CLEANUP_INTERVAL_SECONDS,
        }
    }
}

/// 記録に残すロール 1 つ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleInfo {
    /// ロールの ID。
    pub id: u64,
    /// 名前。
    pub name: String,
    /// 位置（大きいほど上）。
    pub position: i64,
}

impl RoleInfo {
    fn to_json(&self) -> Value {
        json!({"id": self.id, "name": self.name, "position": self.position})
    }
}

/// メンバーとして分かること。discord.py の `Member` のときだけある（ユーザーには無い）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberFacts {
    /// サーバー（@everyone のロールの ID でもある）。
    pub guild_id: u64,
    /// 持っているロール（@everyone を除く。discord.py の `member.roles` と同じく位置の低い順）。
    pub roles: Vec<RoleInfo>,
    /// サーバーでの権限（discord.py の `guild_permissions`）。
    pub permissions: Permissions,
    /// Bot か。
    pub is_bot: bool,
}

/// 記録する相手、または実行した人。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    /// ユーザーの ID。
    pub id: u64,
    /// ユーザー名（`user.name`）。
    pub username: String,
    /// 表示名（メンバーならニックネーム → 表示名 → ユーザー名。ユーザーなら表示名 → ユーザー名）。
    pub display_name: String,
    /// アバターの URL（`display_avatar.url`）。
    pub avatar_url: String,
    /// メンバーとして分かること。
    pub member: Option<MemberFacts>,
}

/// サーバーのうち、記録に要るもの。
#[derive(Clone, Copy, Debug)]
pub struct GuildView<'a> {
    /// サーバー。
    pub id: GuildId,
    /// 所有者（キャッシュに無ければ分からない）。
    pub owner_id: Option<UserId>,
    /// サーバーにあるロール。
    pub roles: &'a HashMap<RoleId, Role>,
}

/// serenity の時刻を chrono の UTC に（小数の秒もそのまま）。
pub fn to_utc(ts: Timestamp) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&ts.to_rfc3339()?)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// マイクロ秒より細かいところを落とす（Python の datetime はマイクロ秒まで）。
pub(crate) fn micros(dt: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(dt.timestamp_micros()).unwrap_or(dt)
}

/// Python の `datetime.isoformat()`（UTC）。マイクロ秒が 0 なら小数を書かない。
pub fn isoformat(dt: DateTime<Utc>) -> String {
    let dt = micros(dt);
    if dt.timestamp_subsec_micros() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }
}

/// Postgres に渡す時刻の文字（マイクロ秒まで必ず書く）。
pub(crate) fn pg_time(dt: DateTime<Utc>) -> String {
    micros(dt).format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
}

/// ID に入っている作られた時刻。discord.py の `snowflake_time`（ミリ秒まで）。
pub fn snowflake_time(id: u64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis((id >> 22) as i64 + DISCORD_EPOCH_MS).unwrap_or_default()
}

/// Python の `text[:n]`（文字で数える）。
pub(crate) fn head(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// Python の `json.dumps(value, ensure_ascii=False)` と同じ文字にする。
///
/// 区切りは `", "` と `": "`。最新状態のロール・権限と履歴の中身は文字のまま表に入るので、書き方が違うと
/// Python の整合性の修復（書き方を揃え直す）が「直した」と数え続ける。
pub fn python_json(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (i, (key, item)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    // 文字の逃がし方は serde_json と Python で同じ（`"`・`\`・制御文字だけ）。
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push_str(": ");
                    write(item, out);
                }
                out.push('}');
            }
            // 数・文字・真偽・null は、区切りを含まないのでそのまま。
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

/// サーバーでの権限。discord.py の `Member.guild_permissions`。
///
/// 所有者は全部。持っているロール（@everyone も）の権限を合わせ、管理者が入っていれば全部。
/// タイムアウト中は、チャンネルの閲覧と履歴の閲覧だけが残る。
pub fn guild_permissions(
    is_owner: bool,
    role_permissions: impl IntoIterator<Item = Permissions>,
    timed_out: bool,
) -> Permissions {
    if is_owner {
        return Permissions::all();
    }
    let base = role_permissions
        .into_iter()
        .fold(Permissions::empty(), |acc, p| acc | p);
    if base.contains(Permissions::ADMINISTRATOR) {
        return Permissions::all();
    }
    if timed_out {
        return base & (Permissions::VIEW_CHANNEL | Permissions::READ_MESSAGE_HISTORY);
    }
    base
}

impl Person {
    /// サーバーのメンバーから。`now` はタイムアウト中かを見るための今の時刻。
    pub fn from_member(member: &Member, guild: &GuildView<'_>, now: DateTime<Utc>) -> Self {
        let held = members::sorted_roles(&member.roles, guild.roles, guild.id);
        let roles: Vec<RoleInfo> = held
            .iter()
            .filter_map(|id| guild.roles.get(id))
            .map(|r| RoleInfo {
                id: r.id.get(),
                name: r.name.clone(),
                position: i64::from(r.position),
            })
            .collect();
        let everyone = RoleId::new(guild.id.get());
        let permissions = guild_permissions(
            guild.owner_id == Some(member.user.id),
            held.iter()
                .chain(std::iter::once(&everyone))
                .filter_map(|id| guild.roles.get(id))
                .map(|r| r.permissions),
            member
                .communication_disabled_until
                .and_then(to_utc)
                .is_some_and(|until| now < until),
        );
        Self {
            id: member.user.id.get(),
            username: member.user.name.clone(),
            display_name: vc_notify::display_name(
                member.nick.as_deref(),
                member.user.global_name.as_deref(),
                &member.user.name,
            )
            .to_string(),
            avatar_url: compat::member_avatar_url(member),
            member: Some(MemberFacts {
                guild_id: guild.id.get(),
                roles,
                permissions,
                is_bot: member.user.bot,
            }),
        }
    }

    /// ユーザーから（サーバーにいない人。ロールと権限は控えない）。
    pub fn from_user(user: &User) -> Self {
        Self {
            id: user.id.get(),
            username: user.name.clone(),
            display_name: vc_notify::display_name(None, user.global_name.as_deref(), &user.name)
                .to_string(),
            avatar_url: compat::user_avatar_url(user),
            member: None,
        }
    }
}

/// 記録する 1 件。Python の `record_user_state_event` の引数。
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    /// サーバー。
    pub guild_id: u64,
    /// 相手。
    pub user_id: u64,
    /// 種類（`member_join` など）。
    pub event_type: String,
    /// このイベントのあとの状態（`active`・`left`・`kicked`・`banned`・`unbanned`）。
    pub status_after: String,
    /// 相手の名前など（分かるとき）。
    pub user: Option<Person>,
    /// 実行した人（キック・BAN で、監査ログから分かったとき）。
    pub actor: Option<Person>,
    /// 理由（監査ログから）。
    pub reason: Option<String>,
    /// サーバーにいるか。`None` は状態から決める。
    pub in_guild: Option<bool>,
    /// BAN されているか。`None` は状態から決める。
    pub is_banned: Option<bool>,
    /// タイムアウトの期限。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// 種類ごとの中身。
    pub payload: Map<String, Value>,
}

/// 監査ログから分かった実行者と理由。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuditHit {
    /// 実行した人（キャッシュにも監査ログの応答にもいなければ分からない）。
    pub actor: Option<Person>,
    /// 理由。
    pub reason: Option<String>,
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn roles_json(roles: &[&RoleInfo]) -> Value {
    Value::Array(roles.iter().map(|r| r.to_json()).collect())
}

fn timeout_of(member: &Member) -> Option<DateTime<Utc>> {
    member.communication_disabled_until.and_then(to_utc)
}

impl Event {
    fn about_member(
        event_type: &str,
        member: &Member,
        guild: &GuildView<'_>,
        now: DateTime<Utc>,
        payload: Value,
    ) -> Self {
        Self {
            guild_id: guild.id.get(),
            user_id: member.user.id.get(),
            event_type: event_type.into(),
            status_after: "active".into(),
            user: Some(Person::from_member(member, guild, now)),
            actor: None,
            reason: None,
            in_guild: Some(true),
            is_banned: Some(false),
            timed_out_until: timeout_of(member),
            payload: object(payload),
        }
    }

    /// 参加。Python の `_on_member_join`。
    pub fn member_join(
        member: &Member,
        guild: &GuildView<'_>,
        member_count: u64,
        now: DateTime<Utc>,
    ) -> Self {
        let joined = member.joined_at.and_then(to_utc).map(isoformat);
        let payload = json!({
            "joined_at": joined,
            "account_created_at": isoformat(snowflake_time(member.user.id.get())),
            "member_count": member_count,
        });
        Self::about_member("member_join", member, guild, now, payload)
    }

    /// 退出、またはキック（監査ログにキックがあったとき）。Python の `_on_member_remove`。
    pub fn member_removal(
        member: &Member,
        guild: &GuildView<'_>,
        member_count: u64,
        kick: Option<AuditHit>,
        now: DateTime<Utc>,
    ) -> Self {
        let person = Person::from_member(member, guild, now);
        // 呼ぶ側の並び（低い順）。メンバーのときは、あとで控えの並び（高い順）に置き換わる。
        let held: Vec<&RoleInfo> = person.member.iter().flat_map(|m| &m.roles).collect();
        let payload = json!({"member_count": member_count, "roles": roles_json(&held)});
        let (event_type, status_after) = if kick.is_some() {
            ("member_kick", "kicked")
        } else {
            ("member_leave", "left")
        };
        let kick = kick.unwrap_or_default();
        Self {
            guild_id: guild.id.get(),
            user_id: member.user.id.get(),
            event_type: event_type.into(),
            status_after: status_after.into(),
            user: Some(person),
            actor: kick.actor,
            reason: kick.reason,
            in_guild: Some(false),
            is_banned: Some(false),
            timed_out_until: timeout_of(member),
            payload: object(payload),
        }
    }

    /// ニックネームの変更。変わっていなければ `None`。Python の `_handle_nickname_change`。
    pub fn nickname_changed(
        before: &Member,
        after: &Member,
        guild: &GuildView<'_>,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        if before.nick == after.nick {
            return None;
        }
        let payload = json!({"before_nickname": before.nick, "after_nickname": after.nick});
        Some(Self::about_member(
            "member_nickname_changed",
            after,
            guild,
            now,
            payload,
        ))
    }

    /// ロールの変更。変わっていなければ `None`。Python の `_handle_role_change`。
    ///
    /// 足されたロールは変更後の並び、外されたロールは変更前の並び（どちらも位置の低い順）。
    pub fn role_changed(
        before: &Member,
        after: &Member,
        guild: &GuildView<'_>,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        let was = Person::from_member(before, guild, now);
        let is = Person::from_member(after, guild, now);
        let roles = |p: &Person| -> Vec<RoleInfo> {
            p.member
                .as_ref()
                .map(|m| m.roles.clone())
                .unwrap_or_default()
        };
        let (was_roles, is_roles) = (roles(&was), roles(&is));
        let was_ids: HashSet<u64> = was_roles.iter().map(|r| r.id).collect();
        let is_ids: HashSet<u64> = is_roles.iter().map(|r| r.id).collect();
        let added: Vec<&RoleInfo> = is_roles
            .iter()
            .filter(|r| !was_ids.contains(&r.id))
            .collect();
        let removed: Vec<&RoleInfo> = was_roles
            .iter()
            .filter(|r| !is_ids.contains(&r.id))
            .collect();
        if added.is_empty() && removed.is_empty() {
            return None;
        }
        let payload = json!({
            "added_roles": roles_json(&added),
            "removed_roles": roles_json(&removed),
        });
        Some(Self::about_member(
            "member_role_changed",
            after,
            guild,
            now,
            payload,
        ))
    }

    /// タイムアウトの付与・解除。変わっていなければ `None`。Python の `_handle_timeout_change`。
    pub fn timeout_changed(
        before: &Member,
        after: &Member,
        guild: &GuildView<'_>,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        if before.communication_disabled_until == after.communication_disabled_until {
            return None;
        }
        Some(match timeout_of(after) {
            Some(until) => Self::about_member(
                "member_timeout_set",
                after,
                guild,
                now,
                json!({"timed_out_until": isoformat(until)}),
            ),
            None => Self::about_member("member_timeout_cleared", after, guild, now, json!({})),
        })
    }

    /// BAN。Python の `_on_member_ban`。`cached` は、まだキャッシュに残っているメンバー（discord.py は
    /// 残っていればメンバーを渡すので、ロールと権限も控えに入る）。
    pub fn member_ban(
        user: &User,
        cached: Option<&Member>,
        guild: &GuildView<'_>,
        audit: Option<AuditHit>,
        now: DateTime<Utc>,
    ) -> Self {
        let audit = audit.unwrap_or_default();
        Self {
            guild_id: guild.id.get(),
            user_id: user.id.get(),
            event_type: "member_ban".into(),
            status_after: "banned".into(),
            user: Some(match cached {
                Some(member) => Person::from_member(member, guild, now),
                None => Person::from_user(user),
            }),
            actor: audit.actor,
            reason: audit.reason,
            in_guild: Some(false),
            is_banned: Some(true),
            timed_out_until: None,
            payload: Map::new(),
        }
    }

    /// BAN の解除。Python の `_on_member_unban`。
    pub fn member_unban(user: &User, guild_id: GuildId, audit: Option<AuditHit>) -> Self {
        let audit = audit.unwrap_or_default();
        Self {
            guild_id: guild_id.get(),
            user_id: user.id.get(),
            event_type: "member_unban".into(),
            status_after: "unbanned".into(),
            user: Some(Person::from_user(user)),
            actor: audit.actor,
            reason: audit.reason,
            in_guild: Some(false),
            is_banned: Some(false),
            timed_out_until: None,
            payload: Map::new(),
        }
    }

    /// VC の参加・退出・移動。Python の `_persist_vc_transition`。
    ///
    /// `before`・`after` はチャンネルの（ID, 名前）。`stay` は退出のときの在室時間（秒, 文字）。
    pub fn voice(
        change: Change,
        member: &Member,
        guild: &GuildView<'_>,
        before: Option<(u64, &str)>,
        after: Option<(u64, &str)>,
        stay: Option<(i64, &str)>,
        now: DateTime<Utc>,
    ) -> Self {
        fn id(channel: Option<(u64, &str)>) -> Option<u64> {
            channel.map(|(id, _)| id)
        }
        fn name(channel: Option<(u64, &str)>) -> Option<&str> {
            channel.map(|(_, name)| name)
        }
        let (event_type, payload) = match change {
            Change::Join => (
                "voice_join",
                json!({
                    "channel_before_id": null,
                    "channel_before_name": null,
                    "channel_after_id": id(after),
                    "channel_after_name": name(after),
                    "duration_seconds": null,
                }),
            ),
            Change::Leave => (
                "voice_leave",
                json!({
                    "channel_before_id": id(before),
                    "channel_before_name": name(before),
                    "channel_after_id": null,
                    "channel_after_name": null,
                    "duration_seconds": stay.map(|(seconds, _)| seconds),
                    // Python の `duration_str or None`（空の文字は無いのと同じ）。
                    "duration_hms": stay.map(|(_, text)| text).filter(|t| !t.is_empty()),
                }),
            ),
            Change::Move => (
                "voice_move",
                json!({
                    "channel_before_id": id(before),
                    "channel_before_name": name(before),
                    "channel_after_id": id(after),
                    "channel_after_name": name(after),
                }),
            ),
        };
        Self::about_member(event_type, member, guild, now, payload)
    }
}

/// Python の `_parse_id_list`: リストでなければ空、`int()` で読めない要素は捨てる。
fn id_set(value: Option<&Value>) -> HashSet<i64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(python_int).collect())
        .unwrap_or_default()
}

/// ロールの控え（位置の高い順。同じ位置は元の並びのまま）。Python の `_extract_role_snapshot`。
pub fn role_snapshot(facts: &MemberFacts) -> Value {
    let mut rows: Vec<&RoleInfo> = facts.roles.iter().collect();
    // Python の sort(reverse=True) は、同じ位置のものの並びを保つ。
    rows.sort_by_key(|r| std::cmp::Reverse(r.position));
    roles_json(&rows)
}

/// 権限と扱いの控え。Python の `_extract_ability_snapshot`。
///
/// あとから設定を変えても、この控えは変わらない（「当時どんな扱いだったか」を残す）。
pub fn ability_snapshot(
    user_id: u64,
    facts: &MemberFacts,
    guild_settings: Option<&Value>,
) -> Value {
    let get = |key: &str| guild_settings.and_then(|g| g.get(key));
    let trusted = id_set(get("trusted_user_ids"));
    let bypass = id_set(get("bypass_role_ids"));
    let as_i64 = |id: u64| i64::try_from(id).unwrap_or(-1);
    let p = facts.permissions;
    // バイパスは @everyone のロール（ID はサーバーと同じ）も見る（discord.py の member.roles に入っている）。
    let has_bypass_role = facts
        .roles
        .iter()
        .map(|r| r.id)
        .chain(std::iter::once(facts.guild_id))
        .any(|id| bypass.contains(&as_i64(id)));
    json!({
        "administrator": p.contains(Permissions::ADMINISTRATOR),
        "manage_guild": p.contains(Permissions::MANAGE_GUILD),
        "kick_members": p.contains(Permissions::KICK_MEMBERS),
        "ban_members": p.contains(Permissions::BAN_MEMBERS),
        "moderate_members": p.contains(Permissions::MODERATE_MEMBERS),
        "manage_roles": p.contains(Permissions::MANAGE_ROLES),
        "trusted_user": trusted.contains(&as_i64(user_id)),
        "bypass_role": has_bypass_role,
        "is_bot": facts.is_bot,
    })
}

/// 状態を保存用にそろえる。Python の `_sanitize_status`（前後の空白を落として小文字に。空なら
/// `unknown`。32 文字まで）。
pub fn sanitize_status(status: &str) -> String {
    let normalized = status.trim_matches(python_is_space).to_lowercase();
    if normalized.is_empty() {
        "unknown".into()
    } else {
        head(&normalized, 32)
    }
}

/// 表に書く中身（1 件ぶん）。[`plan`] が作り、[`Recorder`] が書く。
#[derive(Clone, Debug, PartialEq)]
pub struct Write {
    /// サーバー。
    pub guild_id: i64,
    /// 相手。
    pub user_id: i64,
    /// 種類（小文字、48 文字まで）。
    pub event_type: String,
    /// 状態（[`sanitize_status`] のあと）。
    pub status_after: String,
    /// 実行した人の ID。
    pub actor_user_id: Option<i64>,
    /// 実行した人の名前（表示名、無ければユーザー名）。
    pub actor_name: Option<String>,
    /// 理由（2000 文字まで）。
    pub reason: Option<String>,
    /// 履歴の中身（JSON の文字）。
    pub payload_json: String,
    /// イベントの時刻。
    pub at: DateTime<Utc>,
    /// ユーザー名（分かるときだけ上書き）。
    pub username: Option<String>,
    /// 表示名（分かるときだけ上書き）。
    pub display_name: Option<String>,
    /// アバターの URL（分かるときだけ上書き）。
    pub avatar_url: Option<String>,
    /// サーバーにいるか（`None` は今の値を残す）。
    pub in_guild: Option<bool>,
    /// BAN されているか（`None` は今の値を残す）。
    pub is_banned: Option<bool>,
    /// タイムアウトの期限（`None` は今の値を残す。ただし解除のイベントは消す）。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// タイムアウトの解除のイベントか。
    pub clears_timeout: bool,
    /// ロールの控え（メンバーのときだけ）。
    pub roles_json: Option<String>,
    /// 権限と扱いの控え（メンバーのときだけ）。
    pub abilities_json: Option<String>,
    /// 参加のイベントか（最後に入った時刻を書く）。
    pub joined: bool,
    /// 退出・キック・BAN のイベントか（最後に抜けた時刻を書く）。
    pub left: bool,
    /// 退出・キックのイベントか（いま BAN 中なら BAN を残す。[`Write::keep_ban`]）。
    pub keeps_ban: bool,
}

impl Write {
    /// いま BAN 中（最新状態の BAN の旗が立っている）の人の退出なら、状態を `banned`・BAN の旗を立てたままに
    /// する。Python の `_keep_ban_on_leave`。
    ///
    /// BAN すると Discord は BAN と退出の 2 つを送り、退出は（キックかを監査ログで見分ける待ちのぶん）たいてい
    /// あとに届く。そのまま書くと最新状態が「left・BAN でない」に戻る。形は同期が BAN 一覧から直すときと同じ
    /// （`banned`・BAN 中）にする（違う形だと、同期がまた直しに来て履歴が増える）。履歴の状態も同じ値になる。
    /// 種類と、最後に抜けた時刻はそのまま。
    pub fn keep_ban(&mut self, currently_banned: bool) {
        if self.keeps_ban && currently_banned {
            self.status_after = "banned".into();
            self.is_banned = Some(true);
        }
    }
}

fn truthy(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

/// 1 件のイベントから、表に書く中身を決める。Python の `record_user_state_event` のうち、DB に触る前まで
/// （`_member_snapshot`・`_event_payload_for`・`_extract_user_fields`・`_update_current_state_fields` の
/// 決め方）。
pub fn plan(event: &Event, guild_settings: Option<&Value>, now: DateTime<Utc>) -> Write {
    let now = micros(now);
    let status_after = sanitize_status(&event.status_after);
    let event_type = head(
        &event
            .event_type
            .trim_matches(python_is_space)
            .to_lowercase(),
        48,
    );
    let facts = event.user.as_ref().and_then(|u| u.member.as_ref());
    let snapshot = facts.map(|f| {
        let user_id = event.user.as_ref().map_or(event.user_id, |u| u.id);
        (
            role_snapshot(f),
            ability_snapshot(user_id, f, guild_settings),
        )
    });

    // 履歴の中身。呼ぶ側の中身に、メンバーの控えとタイムアウトの期限を重ねる（同じ鍵は置き換える）。
    let mut payload = event.payload.clone();
    if let Some((roles, abilities)) = &snapshot {
        payload.insert("roles".into(), roles.clone());
        payload.insert("abilities".into(), abilities.clone());
    }
    if let Some(until) = event.timed_out_until {
        payload.insert("timed_out_until".into(), Value::String(isoformat(until)));
    }

    let name_of =
        |p: &Person| truthy(head(&p.display_name, 128)).or_else(|| truthy(head(&p.username, 128)));
    let user = event.user.as_ref();
    // 渡されなかった旗は、状態から決められるときだけ決める。
    let in_guild = event.in_guild.or(match status_after.as_str() {
        "active" => Some(true),
        "left" | "kicked" | "banned" => Some(false),
        _ => None,
    });
    let is_banned = event.is_banned.or(match status_after.as_str() {
        "banned" => Some(true),
        "active" | "left" | "kicked" | "unbanned" => Some(false),
        _ => None,
    });
    Write {
        guild_id: i64::try_from(event.guild_id).unwrap_or(i64::MAX),
        user_id: i64::try_from(event.user_id).unwrap_or(i64::MAX),
        actor_user_id: event
            .actor
            .as_ref()
            .and_then(|a| i64::try_from(a.id).ok())
            .filter(|id| *id != 0),
        actor_name: event.actor.as_ref().and_then(name_of),
        reason: event
            .reason
            .as_deref()
            .filter(|r| !r.is_empty())
            .map(|r| head(r, 2000)),
        payload_json: python_json(&Value::Object(payload)),
        at: now,
        username: user.and_then(|u| truthy(head(&u.username, 128))),
        // Python は表示名が無ければユーザー名を使う。
        display_name: user.and_then(name_of),
        avatar_url: user.and_then(|u| truthy(head(&u.avatar_url, 512))),
        in_guild,
        is_banned,
        timed_out_until: event.timed_out_until.map(micros),
        clears_timeout: event.timed_out_until.is_none() && event_type == "member_timeout_cleared",
        roles_json: snapshot.as_ref().map(|(roles, _)| python_json(roles)),
        abilities_json: snapshot.as_ref().map(|(_, a)| python_json(a)),
        joined: event_type == "member_join",
        left: matches!(
            event_type.as_str(),
            "member_leave" | "member_kick" | "member_ban"
        ),
        keeps_ban: matches!(event_type.as_str(), "member_leave" | "member_kick"),
        event_type,
        status_after,
    }
}

/// いま BAN 中か（最新状態の BAN の旗）を、行の錠を取って読む。行が無ければ空の行を足してから読む（同時に来た
/// BAN が行を作っている最中なら、それを待ってから読む）。
async fn currently_banned(conn: &mut PgConnection, w: &Write) -> Result<bool, sqlx::Error> {
    if let Some(banned) = read_banned(conn, w).await? {
        return Ok(banned);
    }
    sqlx::query(INSERT_BLANK_CURRENT)
        .bind(w.guild_id)
        .bind(w.user_id)
        .execute(&mut *conn)
        .await?;
    Ok(read_banned(conn, w).await?.unwrap_or(false))
}

/// 最新状態の BAN の旗を、行の錠を取って読む（行が無ければ `None`）。
async fn read_banned(conn: &mut PgConnection, w: &Write) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(SELECT_BANNED_FOR_UPDATE)
        .bind(w.guild_id)
        .bind(w.user_id)
        .fetch_optional(conn)
        .await
}

/// 自己修復（表の作り直し）で直りうる失敗か。Python の `_is_repairable_db_error`。
///
/// Python（SQLAlchemy ＋ asyncpg）で実際に当たるのは、SQLSTATE 42 系（表や列が無い・権限が無いなど）
/// だけ。接続の失敗などは当たらず、そのまま失敗になる。
pub fn is_repairable(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| code.starts_with("42"))
}

/// 利用者の状態を書く口。1 つを使い回す（表を作ったか・最後に掃除した時刻を覚えている）。
pub struct Recorder {
    pool: PgPool,
    config: UserStateConfig,
    ready: tokio::sync::Mutex<bool>,
    last_cleanup: std::sync::Mutex<Option<DateTime<Utc>>>,
}

impl Recorder {
    /// 作る。
    pub fn new(pool: PgPool, config: UserStateConfig) -> Self {
        Self {
            pool,
            config,
            ready: tokio::sync::Mutex::new(false),
            last_cleanup: std::sync::Mutex::new(None),
        }
    }

    /// 書き込み先の接続の束（同期・修復が同じ表を読み書きする）。
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// 表があることを確かめる（無ければ作る）。最初の 1 回だけ動き、あとはすぐ戻る。`force` なら
    /// もう一度作りにいく（自己修復）。Python の `ensure_user_state_db`。
    pub async fn ensure_tables(&self, force: bool) -> Result<(), sqlx::Error> {
        let mut ready = self.ready.lock().await;
        if *ready && !force {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for ddl in DDL {
            sqlx::query(*ddl).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        *ready = true;
        if force {
            warn!("User state DB self-heal completed (force recheck).");
        } else {
            info!("User state DB initialized.");
        }
        Ok(())
    }

    /// 1 件を、今の時刻で記録する。失敗しても戻り値は無く、ログに残すだけ（イベントの処理を止めない）。
    pub async fn record(&self, event: &Event, guild_settings: Option<&Value>) {
        self.record_at(event, guild_settings, Utc::now()).await;
    }

    /// 1 件を、渡した時刻で記録する。Python の `record_user_state_event`。
    pub async fn record_at(
        &self,
        event: &Event,
        guild_settings: Option<&Value>,
        now: DateTime<Utc>,
    ) {
        if let Err(e) = self.ensure_tables(false).await {
            error!("[user_state_service] 表を用意できませんでした: {e}");
            return;
        }
        let write = plan(event, guild_settings, now);
        // 掃除は付随の処理。ここで止まると、掃除が失敗している間じゅう BAN も入退室も 1 件も残らない。
        if let Err(e) = self.cleanup_if_needed(write.at).await {
            error!("[user_state_service] retention cleanup failed: {e}");
        }
        for attempt in 0..2 {
            match self.write(&write).await {
                Ok(()) => return,
                Err(e) => {
                    if attempt == 0 && self.try_self_heal("record_user_state_event", &e).await {
                        continue;
                    }
                    error!(
                        "[user_state_service] failed to record event guild_id={} user_id={} event_type={}: {e}",
                        write.guild_id, write.user_id, write.event_type
                    );
                    return;
                }
            }
        }
    }

    /// 履歴と最新状態を 1 つのトランザクションで書く。Python の `_write_state_event`。
    ///
    /// **2 つを同じコミットに入れること。** 別々にすると、あいだで落ちたときに、履歴には残っているのに
    /// 最新状態が古いまま、という食い違いが残る（管理画面はこの 2 つを並べて出す）。
    ///
    /// 退出・キックのときは、先に最新状態の行の錠を取って、いま BAN 中かを読む（[`Write::keep_ban`]。履歴の
    /// 状態もそれで決まる）。
    async fn write(&self, w: &Write) -> Result<(), sqlx::Error> {
        let at = pg_time(w.at);
        let until = w.timed_out_until.map(pg_time);
        let mut tx = self.pool.begin().await?;
        let settled: Write;
        let w = if w.keeps_ban {
            let banned = currently_banned(&mut tx, w).await?;
            let mut kept = w.clone();
            kept.keep_ban(banned);
            settled = kept;
            &settled
        } else {
            w
        };
        sqlx::query(INSERT_EVENT)
            .bind(w.guild_id)
            .bind(w.user_id)
            .bind(&w.event_type)
            .bind(&w.status_after)
            .bind(w.actor_user_id)
            .bind(&w.actor_name)
            .bind(&w.reason)
            .bind(&w.payload_json)
            .bind(&at)
            .execute(&mut *tx)
            .await?;
        let update = || {
            sqlx::query(UPDATE_CURRENT)
                .bind(w.guild_id)
                .bind(w.user_id)
                .bind(&w.username)
                .bind(&w.display_name)
                .bind(&w.avatar_url)
                .bind(&w.status_after)
                .bind(&w.event_type)
                .bind(&at)
                .bind(w.in_guild)
                .bind(w.is_banned)
                .bind(&until)
                .bind(w.clears_timeout)
                .bind(&w.roles_json)
                .bind(&w.abilities_json)
                .bind(w.joined)
                .bind(w.left)
        };
        // ほとんどは行がもうある。無いときだけ空の行を足してから書く（同時に来ても片方が落ちない）。
        if update().execute(&mut *tx).await?.rows_affected() == 0 {
            sqlx::query(INSERT_BLANK_CURRENT)
                .bind(w.guild_id)
                .bind(w.user_id)
                .execute(&mut *tx)
                .await?;
            update().execute(&mut *tx).await?;
        }
        tx.commit().await
    }

    /// 保管期間を過ぎた履歴を消す。間隔が経っていなければ何もしない。Python の
    /// `_cleanup_old_events_if_needed`（最後に掃除した時刻はメモリにだけ持つので、起動の直後は必ず 1 回動く）。
    pub(crate) async fn cleanup_if_needed(&self, now: DateTime<Utc>) -> Result<(), sqlx::Error> {
        let last = *self.last_cleanup.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(last) = last
            && (now - last) < TimeDelta::seconds(self.config.cleanup_interval_seconds)
        {
            return Ok(());
        }
        let cutoff = pg_time(now - TimeDelta::days(self.config.retention_days));
        let mut attempt = 0;
        loop {
            match sqlx::query(DELETE_OLD_EVENTS)
                .bind(&cutoff)
                .execute(&self.pool)
                .await
            {
                Ok(_) => {
                    *self.last_cleanup.lock().unwrap_or_else(|p| p.into_inner()) = Some(now);
                    return Ok(());
                }
                Err(e) => {
                    if attempt == 0 && self.try_self_heal("cleanup_old_events", &e).await {
                        attempt += 1;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// 直りうる失敗なら、表を作り直して「やり直してよい」と伝える。Python の `_try_db_self_heal`。
    pub(crate) async fn try_self_heal(&self, context: &str, error: &sqlx::Error) -> bool {
        if !is_repairable(error) {
            return false;
        }
        warn!("[user_state_service] {context} failed with DB error. trying self-heal: {error}");
        match self.ensure_tables(true).await {
            Ok(()) => true,
            Err(e) => {
                error!("[user_state_service] DB self-heal failed at {context}: {e}");
                false
            }
        }
    }
}

/// 監査ログの 1 件（選ぶのに要るものだけ）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// 監査ログの ID（作られた時刻が入っている）。
    pub id: u64,
    /// 対象。
    pub target_id: Option<u64>,
    /// 実行した人（キャッシュか応答にいたとき）。
    pub actor: Option<Person>,
    /// 理由。
    pub reason: Option<String>,
}

/// 監査ログの並び（新しい順）から、この相手への、今から 20 秒以内のものを選ぶ。
///
/// 20 秒の枠は、たまたま近い時刻に起きた別の同じ種類の操作を取り違えないため。
pub fn pick_audit_entry(rows: &[AuditRow], target: u64, now: DateTime<Utc>) -> Option<&AuditRow> {
    rows.iter().find(|row| {
        if row.target_id != Some(target) {
            return false;
        }
        let age = micros(now) - snowflake_time(row.id);
        age >= TimeDelta::zero() && age <= TimeDelta::seconds(AUDIT_WINDOW_SECONDS)
    })
}

/// 監査ログを読んで、当てはまるものを探す。見つからなければ間を空けて読み直す。Python の
/// `_find_recent_audit_entry` の繰り返しの部分（読むのに失敗しても、次の回へ進む）。
pub async fn find_recent_audit_entry<F, Fut, E>(
    mut fetch: F,
    target: u64,
    clock: impl Fn() -> DateTime<Utc>,
    retries: u32,
    retry_delay: Duration,
) -> Option<AuditRow>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<AuditRow>, E>>,
    E: Display,
{
    for attempt in 0..=retries {
        let now = clock();
        match fetch().await {
            Ok(rows) => {
                if let Some(hit) = pick_audit_entry(&rows, target, now) {
                    return Some(hit.clone());
                }
            }
            Err(e) => debug!("[BOT_SETUP] audit log lookup failed target={target} err={e}"),
        }
        if attempt < retries {
            tokio::time::sleep(retry_delay).await;
        }
    }
    None
}

/// キック・BAN・BAN の解除の実行者と理由を、監査ログから探す。Python の `_find_recent_audit_entry`。
///
/// Bot に監査ログを見る権限が無ければ、読みに行かずに `None`（読んでも 403 が返るだけ）。
pub async fn audit_lookup(
    cache: &Cache,
    http: &Http,
    guild_id: GuildId,
    action: MemberAction,
    target: UserId,
) -> Option<AuditHit> {
    let allowed = {
        let guild = cache.guild(guild_id)?;
        let me = guild.members.get(&cache.current_user().id)?;
        let view = GuildView {
            id: guild_id,
            owner_id: Some(guild.owner_id),
            roles: &guild.roles,
        };
        Person::from_member(me, &view, Utc::now())
            .member
            .is_some_and(|m| m.permissions.contains(Permissions::VIEW_AUDIT_LOG))
    };
    if !allowed {
        return None;
    }
    let fetch = || async {
        let logs = guild_id
            .audit_logs(
                http,
                Some(Action::Member(action)),
                None,
                None,
                Some(AUDIT_LIMIT),
            )
            .await?;
        // 実行者は、キャッシュのメンバー、いなければ応答に入っているユーザー（discord.py の entry.user）。
        let guild = cache.guild(guild_id);
        let rows = logs
            .entries
            .iter()
            .map(|entry| {
                let member = guild.as_ref().and_then(|g| {
                    let view = GuildView {
                        id: guild_id,
                        owner_id: Some(g.owner_id),
                        roles: &g.roles,
                    };
                    g.members
                        .get(&entry.user_id)
                        .map(|m| Person::from_member(m, &view, Utc::now()))
                });
                AuditRow {
                    id: entry.id.get(),
                    target_id: entry.target_id.map(|t| t.get()),
                    actor: member.or_else(|| logs.users.get(&entry.user_id).map(Person::from_user)),
                    reason: entry.reason.clone(),
                }
            })
            .collect::<Vec<_>>();
        Ok::<_, serenity::Error>(rows)
    };
    find_recent_audit_entry(
        fetch,
        target.get(),
        Utc::now,
        AUDIT_RETRIES,
        AUDIT_RETRY_DELAY,
    )
    .await
    .map(|row| AuditHit {
        actor: row.actor,
        reason: row.reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    /// Python の isoformat と同じ形（マイクロ秒が 0 なら小数なし、あれば 6 桁）。
    #[test]
    fn isoformat_matches_python() {
        assert_eq!(
            isoformat(at("2026-11-25T00:05:00Z")),
            "2026-11-25T00:05:00+00:00"
        );
        assert_eq!(
            isoformat(at("2026-11-25T00:05:00.25Z")),
            "2026-11-25T00:05:00.250000+00:00"
        );
        // マイクロ秒より細かいところは落とす。
        assert_eq!(
            isoformat(at("2026-11-25T00:05:00.000000999Z")),
            "2026-11-25T00:05:00+00:00"
        );
        assert_eq!(
            pg_time(at("2026-11-25T00:05:00Z")),
            "2026-11-25T00:05:00.000000+00:00"
        );
    }

    /// ID から作られた時刻（ミリ秒まで）。discord.py の snowflake_time と同じ値。
    #[test]
    fn snowflake_time_matches_discord_py() {
        // 175928847299117063 → 2016-04-30 11:18:25.796 UTC（Discord の文書の例）。
        assert_eq!(
            isoformat(snowflake_time(175_928_847_299_117_063)),
            "2016-04-30T11:18:25.796000+00:00"
        );
    }

    /// Python の json.dumps(ensure_ascii=False) と同じ文字（区切り・並び・ASCII 以外・制御文字）。
    #[test]
    fn json_text_matches_python() {
        let v = json!({"b": 1, "a": [true, null, "日本語 \"q\" \\ \n\u{1f}"], "c": {}, "d": []});
        assert_eq!(
            python_json(&v),
            "{\"b\": 1, \"a\": [true, null, \"日本語 \\\"q\\\" \\\\ \\n\\u001f\"], \"c\": {}, \"d\": []}"
        );
    }

    /// 権限: 所有者と管理者は全部。タイムアウト中は閲覧だけ。それ以外はロールの合計。
    #[test]
    fn guild_permissions_follow_discord_py() {
        let kick = Permissions::KICK_MEMBERS;
        let view = Permissions::VIEW_CHANNEL;
        assert_eq!(guild_permissions(true, [], false), Permissions::all());
        assert_eq!(
            guild_permissions(false, [Permissions::ADMINISTRATOR], true),
            Permissions::all(),
            "管理者はタイムアウト中でも全部"
        );
        assert_eq!(guild_permissions(false, [kick, view], false), kick | view);
        assert_eq!(guild_permissions(false, [kick, view], true), view);
        assert_eq!(guild_permissions(false, [], false), Permissions::empty());
    }

    fn facts(roles: &[(u64, i64)], permissions: Permissions) -> MemberFacts {
        MemberFacts {
            guild_id: 1,
            roles: roles
                .iter()
                .map(|&(id, position)| RoleInfo {
                    id,
                    name: format!("r{id}"),
                    position,
                })
                .collect(),
            permissions,
            is_bot: false,
        }
    }

    /// ロールの控えは位置の高い順。同じ位置は元の並びのまま。
    #[test]
    fn role_snapshot_is_highest_first_and_stable() {
        let f = facts(&[(30, 1), (20, 1), (10, 5), (40, 3)], Permissions::empty());
        let ids: Vec<u64> = role_snapshot(&f)
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, [10, 40, 30, 20]);
        assert_eq!(
            python_json(&role_snapshot(&facts(&[(7, 2)], Permissions::empty()))),
            "[{\"id\": 7, \"name\": \"r7\", \"position\": 2}]"
        );
    }

    /// 権限と扱いの控え: 鍵の並び、信頼ユーザー、バイパスロール（@everyone も見る）。
    #[test]
    fn ability_snapshot_has_python_keys_in_order() {
        let f = facts(
            &[(10, 1)],
            Permissions::MANAGE_ROLES | Permissions::BAN_MEMBERS,
        );
        let settings = json!({"trusted_user_ids": ["5", "x"], "bypass_role_ids": [10]});
        assert_eq!(
            python_json(&ability_snapshot(5, &f, Some(&settings))),
            "{\"administrator\": false, \"manage_guild\": false, \"kick_members\": false, \
             \"ban_members\": true, \"moderate_members\": false, \"manage_roles\": true, \
             \"trusted_user\": true, \"bypass_role\": true, \"is_bot\": false}"
        );
        let none = ability_snapshot(6, &f, None);
        assert_eq!(none["trusted_user"], false);
        assert_eq!(none["bypass_role"], false);
        // @everyone（サーバーと同じ ID）がバイパスに入っていれば、全員が当たる。
        let everyone = json!({"bypass_role_ids": [1]});
        assert_eq!(
            ability_snapshot(6, &facts(&[], Permissions::empty()), Some(&everyone))["bypass_role"],
            true
        );
    }

    /// 状態のそろえ方（前後の空白・小文字・空なら unknown・32 文字まで）。
    #[test]
    fn statuses_are_normalised() {
        assert_eq!(sanitize_status("  Active \n"), "active");
        assert_eq!(sanitize_status(""), "unknown");
        assert_eq!(sanitize_status(" \u{1f} "), "unknown");
        assert_eq!(sanitize_status(&"X".repeat(40)).len(), 32);
    }

    fn bare(event_type: &str, status: &str) -> Event {
        Event {
            guild_id: 1,
            user_id: 2,
            event_type: event_type.into(),
            status_after: status.into(),
            user: None,
            actor: None,
            reason: None,
            in_guild: None,
            is_banned: None,
            timed_out_until: None,
            payload: Map::new(),
        }
    }

    /// 旗を渡さなければ状態から決める。決められない状態は今の値を残す（None）。
    #[test]
    fn flags_follow_the_status_when_not_given() {
        let now = at("2026-11-25T00:05:00Z");
        let flags = |status: &str| {
            let w = plan(&bare("x", status), None, now);
            (w.in_guild, w.is_banned)
        };
        assert_eq!(flags("active"), (Some(true), Some(false)));
        assert_eq!(flags("left"), (Some(false), Some(false)));
        assert_eq!(flags("kicked"), (Some(false), Some(false)));
        assert_eq!(flags("banned"), (Some(false), Some(true)));
        assert_eq!(flags("unbanned"), (None, Some(false)));
        assert_eq!(flags("something"), (None, None));
        // 渡された旗はそのまま。
        let mut e = bare("x", "active");
        e.in_guild = Some(false);
        e.is_banned = Some(true);
        let w = plan(&e, None, now);
        assert_eq!((w.in_guild, w.is_banned), (Some(false), Some(true)));
    }

    /// 種類は小文字・48 文字まで。参加・退出の時刻を書く種類。タイムアウトの解除。
    #[test]
    fn event_types_drive_the_timestamps() {
        let now = at("2026-11-25T00:05:00Z");
        let w = plan(&bare("  Member_JOIN ", "active"), None, now);
        assert_eq!(w.event_type, "member_join");
        assert!(w.joined && !w.left);
        for t in ["member_leave", "member_kick", "member_ban"] {
            let w = plan(&bare(t, "left"), None, now);
            assert!(w.left && !w.joined, "{t}");
        }
        assert!(!plan(&bare("member_unban", "unbanned"), None, now).left);
        assert_eq!(
            plan(&bare(&"t".repeat(60), "active"), None, now)
                .event_type
                .len(),
            48
        );
        assert!(plan(&bare("member_timeout_cleared", "active"), None, now).clears_timeout);
        assert!(!plan(&bare("member_role_changed", "active"), None, now).clears_timeout);
        // 期限を渡されたら、解除の種類でも消さない（期限が勝つ）。
        let mut e = bare("member_timeout_cleared", "active");
        e.timed_out_until = Some(at("2026-11-26T00:00:00Z"));
        assert!(!plan(&e, None, now).clears_timeout);
    }

    /// 退出・キックのときだけ、いま BAN 中なら状態を banned・BAN の旗を立てたままにする（Python の
    /// `_keep_ban_on_leave`）。BAN 中でなければ、渡されたとおり。
    #[test]
    fn a_leave_keeps_the_ban_only_while_banned() {
        let now = at("2026-11-25T00:05:00Z");
        let settled = |event_type: &str, status: &str, banned_now: bool| {
            let mut e = bare(event_type, status);
            e.in_guild = Some(false);
            e.is_banned = Some(false);
            let mut w = plan(&e, None, now);
            w.keep_ban(banned_now);
            (
                w.status_after,
                w.is_banned,
                w.in_guild,
                w.event_type,
                w.left,
            )
        };
        let kept = |t: &str| {
            (
                String::from("banned"),
                Some(true),
                Some(false),
                t.to_string(),
                true,
            )
        };
        assert_eq!(settled("member_leave", "left", true), kept("member_leave"));
        assert_eq!(settled("Member_Kick", "kicked", true), kept("member_kick"));
        assert_eq!(
            settled("member_leave", "left", false),
            (
                "left".into(),
                Some(false),
                Some(false),
                "member_leave".into(),
                true
            )
        );
        // 退出でない種類は、BAN 中でもそのまま（BAN の解除・参加・VC など）。
        for (t, status) in [
            ("member_unban", "unbanned"),
            ("member_join", "active"),
            ("voice_leave", "active"),
            ("member_ban", "banned"),
        ] {
            let (got, banned, ..) = settled(t, status, true);
            assert_eq!((got.as_str(), banned), (status, Some(false)), "{t}");
        }
    }

    fn person(display: &str, username: &str) -> Person {
        Person {
            id: 9,
            username: username.into(),
            display_name: display.into(),
            avatar_url: "https://cdn.discordapp.com/embed/avatars/0.png".into(),
            member: None,
        }
    }

    /// 名前・理由・実行者の扱い（空は無いのと同じ、長さの上限）。
    #[test]
    fn names_reasons_and_actors_are_trimmed_like_python() {
        let now = at("2026-11-25T00:05:00Z");
        let mut e = bare("member_kick", "kicked");
        e.user = Some(person("", "nelly"));
        e.actor = Some(person(&"あ".repeat(200), "mod"));
        e.reason = Some("x".repeat(2500));
        let w = plan(&e, None, now);
        assert_eq!(w.username.as_deref(), Some("nelly"));
        assert_eq!(
            w.display_name.as_deref(),
            Some("nelly"),
            "表示名が無ければユーザー名"
        );
        assert_eq!(w.actor_user_id, Some(9));
        assert_eq!(w.actor_name.unwrap().chars().count(), 128);
        assert_eq!(w.reason.unwrap().len(), 2000);
        // ユーザーには控えが無い。
        assert_eq!((w.roles_json, w.abilities_json), (None, None));
        let mut e = bare("member_ban", "banned");
        e.reason = Some(String::new());
        let w = plan(&e, None, now);
        assert_eq!(
            (w.reason, w.actor_user_id, w.actor_name, w.username),
            (None, None, None, None)
        );
        assert_eq!(w.payload_json, "{}");
    }

    /// 履歴の中身: 呼ぶ側の中身に、メンバーの控えとタイムアウトの期限を重ねる（同じ鍵はその場で置き換える）。
    #[test]
    fn the_payload_layers_the_snapshot_over_the_caller_payload() {
        let now = at("2026-11-25T00:05:00Z");
        let mut e = bare("member_leave", "left");
        let mut who = person("n", "n");
        who.member = Some(facts(&[(10, 1), (20, 2)], Permissions::empty()));
        e.user = Some(who);
        e.payload = object(json!({"member_count": 3, "roles": "呼ぶ側の値", "last": 1}));
        e.timed_out_until = Some(at("2026-11-26T00:00:00.5Z"));
        let w = plan(&e, None, now);
        let v: Value = serde_json::from_str(&w.payload_json).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "member_count",
                "roles",
                "last",
                "abilities",
                "timed_out_until"
            ]
        );
        assert_eq!(v["roles"][0]["id"], 20, "控えの並び（高い順）に置き換わる");
        assert_eq!(v["timed_out_until"], "2026-11-26T00:00:00.500000+00:00");
        assert_eq!(
            w.roles_json.as_deref(),
            Some(
                "[{\"id\": 20, \"name\": \"r20\", \"position\": 2}, {\"id\": 10, \"name\": \"r10\", \"position\": 1}]"
            )
        );
    }

    fn row(id_at: &str, target: Option<u64>) -> AuditRow {
        let ms = at(id_at).timestamp_millis() - DISCORD_EPOCH_MS;
        AuditRow {
            id: (ms as u64) << 22,
            target_id: target,
            actor: None,
            reason: None,
        }
    }

    /// 監査ログは、この相手への、0〜20 秒前のものだけ。新しい順の最初に当たったもの。
    #[test]
    fn audit_entries_must_match_the_target_within_twenty_seconds() {
        let now = at("2026-11-25T00:05:20Z");
        let rows = [
            row("2026-11-25T00:05:21Z", Some(7)), // 未来
            row("2026-11-25T00:05:19Z", Some(8)), // 別の相手
            row("2026-11-25T00:05:10Z", None),    // 相手なし
            row("2026-11-25T00:05:00Z", Some(7)), // ちょうど 20 秒前
            row("2026-11-25T00:04:59Z", Some(7)),
        ];
        assert_eq!(
            pick_audit_entry(&rows, 7, now).map(|r| r.id),
            Some(rows[3].id)
        );
        assert_eq!(pick_audit_entry(&rows[4..], 7, now), None, "21 秒前は古い");
        assert_eq!(
            pick_audit_entry(&[row("2026-11-25T00:05:20Z", Some(7))], 7, now).map(|r| r.id),
            Some(row("2026-11-25T00:05:20Z", Some(7)).id),
            "ちょうど今のものは入る"
        );
        assert_eq!(pick_audit_entry(&rows, 9, now), None);
    }

    /// 見つからなければ 2 回まで読み直し、そのたびに間を空ける。読むのに失敗しても次の回へ進む。
    #[tokio::test]
    async fn the_audit_lookup_retries_twice() {
        let now = at("2026-11-25T00:05:20Z");
        let calls = std::sync::atomic::AtomicU32::new(0);
        let hit = row("2026-11-25T00:05:15Z", Some(7));
        let started = std::time::Instant::now();
        let found = find_recent_audit_entry(
            || {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rows = vec![hit.clone()];
                async move {
                    match n {
                        0 => Err("読めなかった"),
                        1 => Ok(Vec::new()),
                        _ => Ok(rows),
                    }
                }
            },
            7,
            || now,
            AUDIT_RETRIES,
            Duration::from_millis(30),
        )
        .await;
        assert_eq!(found, Some(hit));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(
            started.elapsed() >= Duration::from_millis(60),
            "間を空けていない"
        );

        let calls = std::sync::atomic::AtomicU32::new(0);
        let started = std::time::Instant::now();
        let none = find_recent_audit_entry(
            || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok::<_, &str>(Vec::new()) }
            },
            7,
            || now,
            AUDIT_RETRIES,
            Duration::from_millis(30),
        )
        .await;
        assert_eq!(none, None);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // 最後の回のあとは待たない（待ちは 2 回ぶん）。上限は見ない（遅い環境がある）。
        assert!(started.elapsed() >= Duration::from_millis(60));
    }

    /// 既定値と下限が Python と同じであること（保管期間は短くできない）。
    #[test]
    fn the_defaults_match_python() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            Env::from_fn(move |k| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.to_string())
            })
        };
        assert_eq!(
            UserStateConfig::from_env(&env(&[])),
            UserStateConfig::default()
        );
        let c = UserStateConfig::from_env(&env(&[
            ("USER_STATE_RETENTION_DAYS", "30"),
            ("USER_STATE_CLEANUP_INTERVAL_SECONDS", "1"),
        ]));
        assert_eq!((c.retention_days, c.cleanup_interval_seconds), (3650, 300));
        let c = UserStateConfig::from_env(&env(&[("USER_STATE_RETENTION_DAYS", "4000")]));
        assert_eq!(c.retention_days, 4000);
        let python = include_str!("../../../../services/user_state_service.py");
        assert!(python.contains("env_int(\"USER_STATE_RETENTION_DAYS\", 3650, minimum=3650)"));
        assert!(python.contains("\"USER_STATE_CLEANUP_INTERVAL_SECONDS\","));
        assert!(python.contains("    21600,") && python.contains("    minimum=300,"));
    }

    /// 表を作る文が、Python の列の名前を全部持っていること（形そのものは Postgres のテストで比べる）。
    #[test]
    fn the_ddl_names_the_python_tables() {
        let python = include_str!("../../../../webapp/models.py");
        assert!(python.contains("__tablename__ = \"user_state_current\""));
        assert!(python.contains("__tablename__ = \"user_state_event\""));
        let ddl = DDL.join("\n");
        for name in [
            "uq_user_state_current_guild_user",
            "ix_user_state_current_guild_status",
            "ix_user_state_current_guild_last_event_at",
            "ix_user_state_event_guild_user_event_at",
            "ix_user_state_event_guild_event_type_event_at",
            "ix_user_state_event_event_at",
        ] {
            assert!(python.contains(name) && ddl.contains(name), "{name}");
        }
        assert!(DDL.iter().all(|d| d.contains("IF NOT EXISTS")));
    }

    /// 自己修復するのは SQLSTATE 42 系だけ（接続の失敗などはしない）。
    #[test]
    fn only_schema_errors_are_repairable() {
        assert!(!is_repairable(&sqlx::Error::PoolTimedOut));
        assert!(!is_repairable(&sqlx::Error::RowNotFound));
    }
}
