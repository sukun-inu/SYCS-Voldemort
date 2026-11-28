//! 利用者の状態の同期と、定期の修復・掃除の巡回。Bot が止まっていた間の入退室・BAN を拾い、表
//! （`user_state_current` と履歴の `user_state_event`）を Discord の今の様子に揃える。
//!
//! Python の `events/user_state_sync.py`（`_sync_user_state_on_ready`・`_user_state_auto_repair_loop`・
//! `_sync_user_state_all_guilds`・`_sync_one_guild`・`_fetch_guild_members_for_sync`・
//! `_fetch_guild_bans_for_sync`・`_log_sync_completed`・`_purge_abandoned_guild_settings`）と、
//! `services/user_state_service.py` の `sync_guild_user_states`（`_SyncContext`・`_new_state_row`・
//! `_sync_members`・`_sync_bans`・`_reconcile_absent`・`_run_sync_attempt`・`_update_current_state_fields`）。
//!
//! 揃えてあるもの（本物の Python に同じ入力を与えて、表の行と数えた結果を比べて確かめた）:
//!
//! - 1 サーバーの同期: 表の今の行を読み、メンバー一覧 → BAN 一覧 → どちらにも居ない人（退出とみなす）の順に
//!   書き換えて、1 つのトランザクションで書く。**順に意味がある**（両方に居る人は BAN が勝つ）
//! - 行の書き方: 新しい行を作った順に足し、変わった行だけを ID の順に、変わった列だけ書き換える（SQLAlchemy の
//!   書き方と同じ。他の列は、あいだに来たイベントの書いた値を残す）。履歴は足した順
//! - 履歴を書くのは、新しく見つけた人・BAN に変わった人・退出とみなした人だけ（同期のたびに同じ BAN を
//!   積まない）
//! - タイムアウトは、メンバー一覧の期限（`communication_disabled_until`）に揃える。期限の無い人はタイムアウト中を
//!   下ろす（Bot が止まっていた間に早めに解かれたものが、期限まで残っていたのを直したもの）。BAN 一覧の人には
//!   触らない
//! - 失敗したら取り消し、表が無いなどなら作り直して 1 回だけやり直す。それでも駄目なら 0 件として返す
//! - Discord からの取り方: メンバーも BAN も 1000 件ずつ、`after` で続きを取る。メンバーは 1 ページの中を逆順に
//!   並べる（discord.py と同じ）。メンバーの上限（`USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD`）が 1000 未満なら
//!   その件数の 1 ページだけ、1000 以上なら上限なしと同じになる（discord.py の `fetch_members` が件数を数え
//!   減らさないため）。上限があるときと、取れずにキャッシュで代わりにしたときは、退出の突き合わせをしない
//!   （一覧が全部とは限らない）。BAN が取れなければ、取れた分だけで続ける
//! - 巡回: 起動して 20 秒後に 1 回（履歴も書く）。180 秒後から 30 分ごとに、同期（既定では履歴を書かない）・
//!   修復・Bot が抜けたサーバーの設定の掃除。両方が同時に走らないよう、1 つの錠で囲む。サーバーの間は 1 秒
//!   空ける（失敗したときも）。1 つのサーバーが失敗しても、他は続ける。`BOT_BACKGROUND_WORKER` が真の
//!   プロセスだけが受け持つ（[`tasks_to_start`]。Bot を並べても、同期は 1 つのプロセスだけが書く）
//!
//! Python と変えたところ:
//!
//! - サーバーの順は ID の小さい順（discord.py は受け取った順。どちらも順に意味は無い）。キャッシュで
//!   代わりにするときのメンバーの順も ID の順（discord.py はキャッシュに入った順）
//! - `BOT_ONLY_GUILD_ID` があれば、そのサーバーだけを同期する（Python には無い柵。イベントの記録も
//!   そのサーバーだけなので、他を同期すると、記録していない間の出入りを同期だけが拾うことになる）。掃除に
//!   渡す「居るサーバー」は、柵にかかわらず全部
//! - 巡回はプロセスが終わるまで回る（discord.py は接続が閉じたら抜ける）

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use serenity::all::{Cache, Context, GuildId, Http, Member, Role, RoleId, User, UserId};
use serenity::http::{HttpError, LightMethod, Request, Route};
use serenity::model::guild::Ban;
use sqlx::{PgConnection, Row};
use sycs_core::env::Env;
use sycs_core::settings::SettingsCache;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::BotConfig;
use crate::guild_retention;
use crate::handler::AppState;
use crate::user_state::{self, GuildView, Person, Recorder};
use crate::user_state_repair::{self, RepairStats};

/// Discord から 1 回に取る件数（メンバーも BAN も）。discord.py と同じ。
pub const PAGE_SIZE: usize = 1000;

/// 設定。環境変数の名前・既定・下限は Python（`events/user_state_sync.py`・`services/guild_retention.py`）と同じ。
#[derive(Clone, Debug, PartialEq)]
pub struct SyncConfig {
    /// 起動の後に 1 回同期するか（`USER_STATE_SYNC_ON_READY`、既定は真）。
    pub sync_on_ready: bool,
    /// 起動から同期までの待ち（`USER_STATE_SYNC_DELAY_SECONDS`、既定 20 秒・下限 0）。
    pub sync_delay: Duration,
    /// サーバーとサーバーの間の待ち（`USER_STATE_SYNC_GUILD_PAUSE_SECONDS`、既定 1.0 秒・下限 0）。
    pub guild_pause: Duration,
    /// メンバーを取る上限（`USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD`、既定 0 = 上限なし・下限 0）。
    pub max_members_per_guild: i64,
    /// 定期の同期と修復をするか（`USER_STATE_AUTO_REPAIR_ENABLED`、既定は真）。
    pub auto_repair: bool,
    /// 定期の同期と修復の間隔（`USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS`、既定 1800 秒・下限 300）。
    pub repair_interval: Duration,
    /// 起動から最初の定期の同期までの待ち（`USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS`、既定 180 秒・下限 0）。
    pub repair_start_delay: Duration,
    /// 1 サーバーの修復で見る行の上限（`USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD`、既定 50000・下限 100）。
    pub repair_max_rows: i64,
    /// 定期の同期でも履歴を書くか（`USER_STATE_AUTO_REPAIR_WRITE_EVENTS`、既定は真）。書くのは見つけた違いだけ
    /// （起動の後の同期と同じ）。以前の既定は偽で、取りこぼした退出や BAN が履歴に残らなかった（本人の決定
    /// 2026-11-28、rust-10 の (j)・決めごとの U6）。
    pub repair_write_events: bool,
    /// Bot が抜けたサーバーの設定を消すまでの日数（`GUILD_SETTINGS_ABANDONED_AFTER_DAYS`、既定 3650・下限 1）。
    pub abandoned_after_days: i64,
}

impl SyncConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        let secs = |v: i64| Duration::from_secs(u64::try_from(v).unwrap_or(0));
        Self {
            sync_on_ready: env.boolean("USER_STATE_SYNC_ON_READY", true),
            sync_delay: secs(env.int("USER_STATE_SYNC_DELAY_SECONDS", 20, Some(0), None)),
            guild_pause: Duration::try_from_secs_f64(env.float(
                "USER_STATE_SYNC_GUILD_PAUSE_SECONDS",
                1.0,
                Some(0.0),
                None,
            ))
            .unwrap_or(Duration::MAX),
            max_members_per_guild: env.int(
                "USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD",
                0,
                Some(0),
                None,
            ),
            auto_repair: env.boolean("USER_STATE_AUTO_REPAIR_ENABLED", true),
            repair_interval: secs(env.int(
                "USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS",
                1800,
                Some(300),
                None,
            )),
            repair_start_delay: secs(env.int(
                "USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS",
                180,
                Some(0),
                None,
            )),
            repair_max_rows: env.int(
                "USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD",
                50_000,
                Some(100),
                None,
            ),
            repair_write_events: env.boolean("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", true),
            abandoned_after_days: env.int(
                "GUILD_SETTINGS_ABANDONED_AFTER_DAYS",
                guild_retention::ABANDONED_AFTER_DAYS,
                Some(1),
                None,
            ),
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self::from_env(&Env::from_fn(|_| None))
    }
}

/// 1 サーバーの同期で数えたもの。Python の `sync_guild_user_states` が返す辞書。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncStats {
    /// メンバー一覧に居た人の数（同じ人が 2 回居れば 2）。
    pub members_seen: u64,
    /// BAN 一覧に居た人の数。
    pub bans_seen: u64,
    /// 新しく作った行。
    pub created: u64,
    /// 既にあった行を書き換えた数（メンバーと BAN の両方に居れば 2）。
    pub updated: u64,
    /// どちらの一覧にも居ないので退出とみなした数。
    pub left_reconciled: u64,
    /// 書いた履歴の数。
    pub events_written: u64,
}

/// 1 サーバーぶん（と全体の合計）で数えたもの。Python の `_sync_one_guild` が返す辞書。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuildTotals {
    /// 同期で数えたもの。
    pub sync: SyncStats,
    /// 修復で見た行。
    pub repair_rows: u64,
    /// 修復で直した行。
    pub repair_fixed: u64,
}

impl GuildTotals {
    fn add(&mut self, other: &Self) {
        let (a, b) = (&mut self.sync, &other.sync);
        a.members_seen += b.members_seen;
        a.bans_seen += b.bans_seen;
        a.created += b.created;
        a.updated += b.updated;
        a.left_reconciled += b.left_reconciled;
        a.events_written += b.events_written;
        self.repair_rows += other.repair_rows;
        self.repair_fixed += other.repair_fixed;
    }
}

/// 最新状態の表の 1 行（読み書きするところだけ）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentRow {
    /// 行の ID（まだ表に無い新しい行は `None`）。
    pub id: Option<i64>,
    /// 相手。
    pub user_id: i64,
    /// ユーザー名。
    pub username: Option<String>,
    /// 表示名。
    pub display_name: Option<String>,
    /// アバターの URL。
    pub avatar_url: Option<String>,
    /// 状態（`active`・`left`・`kicked`・`banned` など）。
    pub status: String,
    /// サーバーに居るか。
    pub is_in_guild: bool,
    /// BAN されているか。
    pub is_banned: bool,
    /// タイムアウト中か。
    pub is_timed_out: bool,
    /// タイムアウトの期限。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// ロールの控え（JSON の文字）。
    pub roles_json: String,
    /// 権限と扱いの控え（JSON の文字）。
    pub abilities_json: String,
    /// 最後のイベントの種類。
    pub last_event_type: Option<String>,
    /// 最後のイベントの時刻。
    pub last_event_at: Option<DateTime<Utc>>,
    /// 最後に入った時刻。
    pub last_joined_at: Option<DateTime<Utc>>,
    /// 最後に抜けた時刻。
    pub last_left_at: Option<DateTime<Utc>>,
    /// 最後に書き換えた時刻（新しい行で、まだ書いていなければ `None`。表に足すときに今の時刻になる）。
    pub updated_at: Option<DateTime<Utc>>,
}

impl CurrentRow {
    /// まだ行が無い人のための空の行。Python の `_new_state_row`（状態は `unknown`。埋める前に落ちても
    /// 「居る」ように見えないため）。
    pub fn blank(user_id: i64, is_banned: bool) -> Self {
        Self {
            id: None,
            user_id,
            username: None,
            display_name: None,
            avatar_url: None,
            status: "unknown".into(),
            is_in_guild: false,
            is_banned,
            is_timed_out: false,
            timed_out_until: None,
            roles_json: "[]".into(),
            abilities_json: "{}".into(),
            last_event_type: None,
            last_event_at: None,
            last_joined_at: None,
            last_left_at: None,
            updated_at: None,
        }
    }
}

/// 最新状態の書き換え 1 回ぶん。Python の `_update_current_state_fields` の引数。
#[derive(Clone, Debug)]
pub struct Update<'a> {
    /// 種類（`sync_member_on_ready` など）。
    pub event_type: &'a str,
    /// このあとの状態。
    pub status_after: &'a str,
    /// 時刻。
    pub now: DateTime<Utc>,
    /// ユーザー名（分かるときだけ上書き）。
    pub username: Option<&'a str>,
    /// 表示名（分かるときだけ上書き）。
    pub display_name: Option<&'a str>,
    /// アバターの URL（分かるときだけ上書き）。
    pub avatar_url: Option<&'a str>,
    /// サーバーに居るか（`None` は状態から決める）。
    pub in_guild: Option<bool>,
    /// BAN されているか（`None` は状態から決める）。
    pub is_banned: Option<bool>,
    /// タイムアウトの期限（`None` は今の期限を残して旗だけ数え直す）。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// ロールの控え（`None` は今のまま）。
    pub roles_json: Option<&'a str>,
    /// 権限と扱いの控え（`None` は今のまま）。
    pub abilities_json: Option<&'a str>,
}

/// 最新状態の行を、渡された新しい状態でその場で書き換える。Python の `_update_current_state_fields`。
pub fn apply_update(row: &mut CurrentRow, u: &Update<'_>) {
    // 名前とアバターは、分かったときだけ（空でないときだけ）上書きする。
    if let Some(v) = u.username.filter(|v| !v.is_empty()) {
        row.username = Some(v.to_string());
    }
    if let Some(v) = u.display_name.filter(|v| !v.is_empty()) {
        row.display_name = Some(v.to_string());
    }
    if let Some(v) = u.avatar_url.filter(|v| !v.is_empty()) {
        row.avatar_url = Some(v.to_string());
    }
    row.status = u.status_after.to_string();
    row.last_event_type = Some(u.event_type.to_string());
    row.last_event_at = Some(u.now);
    row.updated_at = Some(u.now);
    match u.in_guild {
        Some(v) => row.is_in_guild = v,
        None => match u.status_after {
            "active" => row.is_in_guild = true,
            "left" | "kicked" | "banned" => row.is_in_guild = false,
            _ => {}
        },
    }
    match u.is_banned {
        Some(v) => row.is_banned = v,
        None => match u.status_after {
            "banned" => row.is_banned = true,
            "active" | "left" | "kicked" | "unbanned" => row.is_banned = false,
            _ => {}
        },
    }
    if let Some(until) = u.timed_out_until {
        row.timed_out_until = Some(until);
        row.is_timed_out = until > u.now;
    } else if u.event_type == "member_timeout_cleared" {
        row.timed_out_until = None;
        row.is_timed_out = false;
    } else if let Some(until) = row.timed_out_until {
        row.is_timed_out = until > u.now;
    }
    if let Some(v) = u.roles_json {
        row.roles_json = v.to_string();
    }
    if let Some(v) = u.abilities_json {
        row.abilities_json = v.to_string();
    }
    match u.event_type {
        "member_join" => row.last_joined_at = Some(u.now),
        "member_leave" | "member_kick" | "member_ban" => row.last_left_at = Some(u.now),
        _ => {}
    }
}

/// 同期に渡す 1 人（メンバー一覧か BAN 一覧から）。Python の `_extract_user_fields` などで抜き出したもの。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// 相手。
    pub user_id: i64,
    /// ユーザー名（128 文字まで）。
    pub username: String,
    /// 表示名（128 文字まで）。
    pub display_name: String,
    /// アバターの URL（512 文字まで）。
    pub avatar_url: String,
    /// タイムアウトの期限（メンバーのとき。過ぎていてもそのまま）。
    pub timed_out_until: Option<DateTime<Utc>>,
    /// ロールと権限の控え（JSON の文字。メンバーのときだけ）。
    pub snapshot: Option<(String, String)>,
}

impl Seen {
    fn from_person(p: &Person) -> Self {
        Self {
            user_id: i64::try_from(p.id).unwrap_or(i64::MAX),
            username: user_state::head(&p.username, 128),
            display_name: user_state::head(&p.display_name, 128),
            avatar_url: user_state::head(&p.avatar_url, 512),
            timed_out_until: None,
            snapshot: None,
        }
    }

    /// メンバー一覧の 1 人。`now` はタイムアウト中かを見る時刻（権限の控えに効く）。
    pub fn member(
        member: &Member,
        guild: &GuildView<'_>,
        guild_settings: Option<&Value>,
        now: DateTime<Utc>,
    ) -> Self {
        let person = Person::from_member(member, guild, now);
        let mut seen = Self::from_person(&person);
        seen.timed_out_until = member
            .communication_disabled_until
            .and_then(user_state::to_utc)
            .map(user_state::micros);
        seen.snapshot = person.member.as_ref().map(|facts| {
            (
                user_state::python_json(&user_state::role_snapshot(facts)),
                user_state::python_json(&user_state::ability_snapshot(
                    person.id,
                    facts,
                    guild_settings,
                )),
            )
        });
        seen
    }

    /// BAN 一覧の 1 人。
    pub fn banned(user: &User) -> Self {
        Self::from_person(&Person::from_user(user))
    }
}

/// 同期 1 回ぶんの、どの段でも同じ値。Python の `_SyncContext`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncContext {
    /// サーバー。
    pub guild_id: i64,
    /// きっかけ（`on_ready`・`auto_repair`。32 文字まで）。
    pub source: String,
    /// 時刻（3 つの段で同じ）。
    pub now: DateTime<Utc>,
    /// 履歴を書くか。
    pub write_events: bool,
}

/// 同期で足す履歴の 1 行（実行者・理由は無い）。Python の `_build_state_event`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewEvent {
    /// 相手。
    pub user_id: i64,
    /// 種類（`sync_discovered_member`・`sync_discovered_ban`・`sync_mark_left`）。
    pub event_type: String,
    /// このあとの状態。
    pub status_after: String,
    /// 中身（`{"source": "…"}`）。
    pub payload_json: String,
}

/// 同期で書く行の 1 つ（読んだときの形と、書き換えたあとの形）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedRow {
    /// 読んだときの形（新しい行は `None`）。
    pub before: Option<CurrentRow>,
    /// 書き換えたあとの形。
    pub after: CurrentRow,
}

/// 同期 1 回ぶんで書くもの。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    /// 行（読んだ順、そのあとに新しく作った順）。
    pub rows: Vec<PlannedRow>,
    /// 足す履歴（足す順）。
    pub events: Vec<NewEvent>,
    /// 数えたもの。
    pub stats: SyncStats,
}

impl SyncContext {
    fn event(&self, user_id: i64, event_type: &str, status_after: &str) -> NewEvent {
        NewEvent {
            user_id,
            event_type: user_state::head(event_type, 48),
            status_after: user_state::sanitize_status(status_after),
            payload_json: user_state::python_json(&json!({"source": self.source})),
        }
    }
}

/// 表の今の行と、メンバー一覧・BAN 一覧から、書くものを決める（表には触らない）。Python の `_run_sync_attempt`
/// の中の 3 段（`_sync_members` → `_sync_bans` → `_reconcile_absent`）。
///
/// **順に意味がある。** メンバー → BAN の順なので、同じ人が両方に居れば BAN が勝つ。退出の突き合わせは
/// 最後で、前の 2 段が見た人を除いて回す。
pub fn plan_sync(
    existing: Vec<CurrentRow>,
    members: &[Seen],
    banned: &[Seen],
    reconcile_missing: bool,
    ctx: &SyncContext,
) -> Planned {
    let mut rows: Vec<PlannedRow> = existing
        .into_iter()
        .map(|r| PlannedRow {
            before: Some(r.clone()),
            after: r,
        })
        .collect();
    let mut index: HashMap<i64, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.after.user_id, i))
        .collect();
    let mut events = Vec::new();
    let mut stats = SyncStats::default();
    // 行を取り出す。無ければ空の行を作って足す。返すのは（位置, 作ったか）。
    let mut row_of = |rows: &mut Vec<PlannedRow>, user_id: i64, is_banned: bool| {
        if let Some(&i) = index.get(&user_id) {
            return (i, false);
        }
        rows.push(PlannedRow {
            before: None,
            after: CurrentRow::blank(user_id, is_banned),
        });
        index.insert(user_id, rows.len() - 1);
        (rows.len() - 1, true)
    };

    // メンバー一覧（Python の `_sync_members`）。
    let member_type = format!("sync_member_{}", ctx.source);
    let mut present = HashSet::new();
    for m in members {
        present.insert(m.user_id);
        stats.members_seen += 1;
        let (i, created) = row_of(&mut rows, m.user_id, false);
        if created {
            stats.created += 1;
        } else {
            stats.updated += 1;
        }
        let snapshot = m.snapshot.as_ref();
        apply_update(
            &mut rows[i].after,
            &Update {
                event_type: &member_type,
                status_after: "active",
                now: ctx.now,
                username: Some(&m.username),
                display_name: Some(&m.display_name),
                avatar_url: Some(&m.avatar_url),
                in_guild: Some(true),
                is_banned: Some(false),
                timed_out_until: m.timed_out_until,
                roles_json: snapshot.map(|s| s.0.as_str()),
                abilities_json: snapshot.map(|s| s.1.as_str()),
            },
        );
        // 一覧に期限が無い＝いまはタイムアウトされていない。Bot が止まっていた間に早めに解かれたタイムアウトを
        // 下ろす（[`apply_update`] は期限なしを「分からない」として古い期限を残すため）。変わった列だけ書く。
        if m.timed_out_until.is_none() {
            let row = &mut rows[i].after;
            row.timed_out_until = None;
            row.is_timed_out = false;
        }
        if created && ctx.write_events {
            events.push(ctx.event(m.user_id, "sync_discovered_member", "active"));
            stats.events_written += 1;
        }
    }

    // BAN 一覧（Python の `_sync_bans`）。
    let ban_type = format!("sync_ban_{}", ctx.source);
    let mut banned_ids = HashSet::new();
    for b in banned {
        banned_ids.insert(b.user_id);
        stats.bans_seen += 1;
        let (i, created) = row_of(&mut rows, b.user_id, true);
        let before = (!created).then(|| (rows[i].after.status.clone(), rows[i].after.is_banned));
        if created {
            stats.created += 1;
        } else {
            stats.updated += 1;
        }
        apply_update(
            &mut rows[i].after,
            &Update {
                event_type: &ban_type,
                status_after: "banned",
                now: ctx.now,
                username: Some(&b.username),
                display_name: Some(&b.display_name),
                avatar_url: Some(&b.avatar_url),
                in_guild: Some(false),
                is_banned: Some(true),
                timed_out_until: None,
                roles_json: None,
                abilities_json: None,
            },
        );
        // 既に BAN だった人に、同期のたびに履歴を積まない（何回 BAN されたかが読めなくなる）。
        let changed = match &before {
            None => true,
            Some((status, was_banned)) => status != "banned" || !was_banned,
        };
        if ctx.write_events && changed {
            events.push(ctx.event(b.user_id, "sync_discovered_ban", "banned"));
            stats.events_written += 1;
        }
    }

    // どちらの一覧にも居ない人を退出にする（Python の `_reconcile_absent`）。BAN の人は触らない。
    if reconcile_missing {
        let left_type = format!("sync_left_{}", ctx.source);
        for row in &mut rows {
            let user_id = row.after.user_id;
            if present.contains(&user_id) || banned_ids.contains(&user_id) || row.after.is_banned {
                continue;
            }
            let should_mark_left =
                row.after.is_in_guild || matches!(row.after.status.as_str(), "active" | "unknown");
            if !should_mark_left {
                continue;
            }
            apply_update(
                &mut row.after,
                &Update {
                    event_type: &left_type,
                    status_after: "left",
                    now: ctx.now,
                    username: None,
                    display_name: None,
                    avatar_url: None,
                    in_guild: Some(false),
                    is_banned: Some(false),
                    timed_out_until: None,
                    roles_json: None,
                    abilities_json: None,
                },
            );
            stats.left_reconciled += 1;
            if ctx.write_events {
                events.push(ctx.event(user_id, "sync_mark_left", "left"));
                stats.events_written += 1;
            }
        }
    }
    Planned {
        rows,
        events,
        stats,
    }
}

/// 最新状態の行を読む列（時刻は UNIX マイクロ秒の整数で受ける）。
macro_rules! select_rows {
    ($tail:literal) => {
        concat!(
            "SELECT id, user_id, username, display_name, avatar_url, status, is_in_guild, is_banned, \
             is_timed_out, (EXTRACT(EPOCH FROM timed_out_until) * 1000000)::bigint, roles_json, abilities_json, \
             last_event_type, (EXTRACT(EPOCH FROM last_event_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM last_joined_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM last_left_at) * 1000000)::bigint, \
             (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint FROM user_state_current ",
            $tail
        )
    };
}

/// 1 サーバーの行を全部（並びは指定しない。Python と同じく、表に入っている順）。
const SELECT_GUILD_ROWS: &str = select_rows!("WHERE guild_id = $1");
/// 修復で見る行（1 サーバー、ID の順に上限まで）。
pub(crate) const SELECT_REPAIR_GUILD_ROWS: &str =
    select_rows!("WHERE guild_id = $1 ORDER BY id ASC LIMIT $2");
/// 修復で見る行（全部のサーバー、ID の順に上限まで）。
pub(crate) const SELECT_REPAIR_ALL_ROWS: &str = select_rows!("ORDER BY id ASC LIMIT $1");

const INSERT_ROW: &str = "INSERT INTO user_state_current \
    (guild_id, user_id, username, display_name, avatar_url, status, is_in_guild, is_banned, is_timed_out, \
     timed_out_until, roles_json, abilities_json, last_event_type, last_event_at, last_joined_at, last_left_at, \
     updated_at) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11, $12, $13, $14::timestamptz, \
     $15::timestamptz, $16::timestamptz, COALESCE($17::timestamptz, now()))";

/// 変わった列だけを書き換える（旗が偽の列は今の値のまま）。`updated_at` を書かないときは、今の時刻にする
/// （SQLAlchemy の `onupdate=func.now()` と同じ）。
const UPDATE_CHANGED: &str = "UPDATE user_state_current SET \
    username = CASE WHEN $2 THEN $3 ELSE username END, \
    display_name = CASE WHEN $4 THEN $5 ELSE display_name END, \
    avatar_url = CASE WHEN $6 THEN $7 ELSE avatar_url END, \
    status = CASE WHEN $8 THEN $9 ELSE status END, \
    is_in_guild = CASE WHEN $10 THEN $11 ELSE is_in_guild END, \
    is_banned = CASE WHEN $12 THEN $13 ELSE is_banned END, \
    is_timed_out = CASE WHEN $14 THEN $15 ELSE is_timed_out END, \
    timed_out_until = CASE WHEN $16 THEN $17::timestamptz ELSE timed_out_until END, \
    roles_json = CASE WHEN $18 THEN $19 ELSE roles_json END, \
    abilities_json = CASE WHEN $20 THEN $21 ELSE abilities_json END, \
    last_event_type = CASE WHEN $22 THEN $23 ELSE last_event_type END, \
    last_event_at = CASE WHEN $24 THEN $25::timestamptz ELSE last_event_at END, \
    last_joined_at = CASE WHEN $26 THEN $27::timestamptz ELSE last_joined_at END, \
    last_left_at = CASE WHEN $28 THEN $29::timestamptz ELSE last_left_at END, \
    updated_at = CASE WHEN $30 THEN $31::timestamptz ELSE now() END \
    WHERE id = $1";

const INSERT_EVENT: &str = "INSERT INTO user_state_event \
    (guild_id, user_id, event_type, status_after, actor_user_id, actor_name, reason, payload_json, event_at) \
    VALUES ($1, $2, $3, $4, NULL, NULL, NULL, $5, $6::timestamptz)";

fn from_micros(value: Option<i64>) -> Option<DateTime<Utc>> {
    value.and_then(DateTime::from_timestamp_micros)
}

fn pg(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(user_state::pg_time)
}

/// 読んだ 1 行を [`CurrentRow`] に。
pub(crate) fn decode_row(row: &sqlx::postgres::PgRow) -> Result<CurrentRow, sqlx::Error> {
    Ok(CurrentRow {
        // 行の ID は SERIAL（32 ビット）。
        id: Some(i64::from(row.try_get::<i32, _>(0)?)),
        user_id: row.try_get(1)?,
        username: row.try_get(2)?,
        display_name: row.try_get(3)?,
        avatar_url: row.try_get(4)?,
        status: row.try_get(5)?,
        is_in_guild: row.try_get(6)?,
        is_banned: row.try_get(7)?,
        is_timed_out: row.try_get(8)?,
        timed_out_until: from_micros(row.try_get(9)?),
        roles_json: row.try_get(10)?,
        abilities_json: row.try_get(11)?,
        last_event_type: row.try_get(12)?,
        last_event_at: from_micros(row.try_get(13)?),
        last_joined_at: from_micros(row.try_get(14)?),
        last_left_at: from_micros(row.try_get(15)?),
        updated_at: from_micros(row.try_get(16)?),
    })
}

/// 新しい行を表に足す。
async fn insert_row(
    conn: &mut PgConnection,
    guild_id: i64,
    row: &CurrentRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(INSERT_ROW)
        .bind(guild_id)
        .bind(row.user_id)
        .bind(&row.username)
        .bind(&row.display_name)
        .bind(&row.avatar_url)
        .bind(&row.status)
        .bind(row.is_in_guild)
        .bind(row.is_banned)
        .bind(row.is_timed_out)
        .bind(pg(row.timed_out_until))
        .bind(&row.roles_json)
        .bind(&row.abilities_json)
        .bind(&row.last_event_type)
        .bind(pg(row.last_event_at))
        .bind(pg(row.last_joined_at))
        .bind(pg(row.last_left_at))
        .bind(pg(row.updated_at))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// 読んだときから変わった列だけを書き換える。何も変わっていなければ何もせず `false`。
///
/// 書き換える行が無くなっていたら（あいだで消された）失敗にする。
pub(crate) async fn update_changed(
    conn: &mut PgConnection,
    before: &CurrentRow,
    after: &CurrentRow,
) -> Result<bool, sqlx::Error> {
    let changed = [
        before.username != after.username,
        before.display_name != after.display_name,
        before.avatar_url != after.avatar_url,
        before.status != after.status,
        before.is_in_guild != after.is_in_guild,
        before.is_banned != after.is_banned,
        before.is_timed_out != after.is_timed_out,
        before.timed_out_until != after.timed_out_until,
        before.roles_json != after.roles_json,
        before.abilities_json != after.abilities_json,
        before.last_event_type != after.last_event_type,
        before.last_event_at != after.last_event_at,
        before.last_joined_at != after.last_joined_at,
        before.last_left_at != after.last_left_at,
        before.updated_at != after.updated_at,
    ];
    if !changed.contains(&true) {
        return Ok(false);
    }
    let Some(id) = before.id else {
        return Err(sqlx::Error::RowNotFound);
    };
    let result = sqlx::query(UPDATE_CHANGED)
        .bind(id)
        .bind(changed[0])
        .bind(&after.username)
        .bind(changed[1])
        .bind(&after.display_name)
        .bind(changed[2])
        .bind(&after.avatar_url)
        .bind(changed[3])
        .bind(&after.status)
        .bind(changed[4])
        .bind(after.is_in_guild)
        .bind(changed[5])
        .bind(after.is_banned)
        .bind(changed[6])
        .bind(after.is_timed_out)
        .bind(changed[7])
        .bind(pg(after.timed_out_until))
        .bind(changed[8])
        .bind(&after.roles_json)
        .bind(changed[9])
        .bind(&after.abilities_json)
        .bind(changed[10])
        .bind(&after.last_event_type)
        .bind(changed[11])
        .bind(pg(after.last_event_at))
        .bind(changed[12])
        .bind(pg(after.last_joined_at))
        .bind(changed[13])
        .bind(pg(after.last_left_at))
        .bind(changed[14])
        .bind(pg(after.updated_at))
        .execute(&mut *conn)
        .await?;
    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(true)
}

/// 決めたものを表に書く。SQLAlchemy と同じ順（新しい行を作った順に足し、既にある行を ID の順に書き換え、
/// 履歴を足した順に）。
async fn write_planned(
    conn: &mut PgConnection,
    ctx: &SyncContext,
    planned: &Planned,
) -> Result<(), sqlx::Error> {
    for row in planned.rows.iter().filter(|r| r.before.is_none()) {
        insert_row(conn, ctx.guild_id, &row.after).await?;
    }
    let mut existing: Vec<(&CurrentRow, &CurrentRow)> = planned
        .rows
        .iter()
        .filter_map(|r| r.before.as_ref().map(|b| (b, &r.after)))
        .collect();
    existing.sort_by_key(|(before, _)| before.id);
    for (before, after) in existing {
        update_changed(conn, before, after).await?;
    }
    let at = user_state::pg_time(ctx.now);
    for event in &planned.events {
        sqlx::query(INSERT_EVENT)
            .bind(ctx.guild_id)
            .bind(event.user_id)
            .bind(&event.event_type)
            .bind(&event.status_after)
            .bind(&event.payload_json)
            .bind(&at)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// 同期 1 回ぶん（読む → 決める → 書く → 確定）。失敗はそのまま返す（取り消しとやり直しは呼んだ側）。
async fn run_sync_attempt(
    recorder: &Recorder,
    ctx: &SyncContext,
    members: &[Seen],
    banned: &[Seen],
    reconcile_missing: bool,
) -> Result<SyncStats, sqlx::Error> {
    let mut tx = recorder.pool().begin().await?;
    let rows = sqlx::query(SELECT_GUILD_ROWS)
        .bind(ctx.guild_id)
        .fetch_all(&mut *tx)
        .await?;
    let existing = rows.iter().map(decode_row).collect::<Result<Vec<_>, _>>()?;
    let planned = plan_sync(existing, members, banned, reconcile_missing, ctx);
    write_planned(&mut tx, ctx, &planned).await?;
    tx.commit().await?;
    Ok(planned.stats)
}

/// 同期に渡すもの。Python の `sync_guild_user_states` の引数。
#[derive(Clone, Copy, Debug)]
pub struct SyncRequest<'a> {
    /// サーバー（ロールと所有者。メンバーのロールと権限の控えに使う）。
    pub guild: GuildView<'a>,
    /// メンバー一覧。
    pub members: &'a [Member],
    /// BAN 一覧。
    pub banned_users: &'a [User],
    /// きっかけ（空なら `startup_sync`）。
    pub source: &'a str,
    /// どちらの一覧にも居ない人を退出にするか（一覧が全部そろっているときだけ）。
    pub reconcile_missing: bool,
    /// 履歴を書くか。
    pub write_events: bool,
}

/// 1 サーバーぶんを、Discord の一覧に揃える（今の時刻で）。
pub async fn sync_guild_user_states(
    recorder: &Recorder,
    guild_settings: Option<&Value>,
    request: SyncRequest<'_>,
) -> Result<SyncStats, sqlx::Error> {
    sync_guild_user_states_at(recorder, guild_settings, request, Utc::now()).await
}

/// 1 サーバーぶんを、Discord の一覧に揃える（渡した時刻で）。Python の `sync_guild_user_states`。
///
/// 表を用意できなければ `Err`（Python も例外を上げる。呼んだ側がそのサーバーの失敗として残す）。書く段で
/// 失敗したら、取り消して（直りうる失敗なら表を作り直して 1 回だけやり直して）、**0 件**を返す。数えかけの
/// 値を返すと、まるごと失敗した同期が「一部成功」に見える。
pub async fn sync_guild_user_states_at(
    recorder: &Recorder,
    guild_settings: Option<&Value>,
    request: SyncRequest<'_>,
    now: DateTime<Utc>,
) -> Result<SyncStats, sqlx::Error> {
    recorder.ensure_tables(false).await?;
    let now = user_state::micros(now);
    let source = if request.source.is_empty() {
        "startup_sync"
    } else {
        request.source
    };
    let ctx = SyncContext {
        guild_id: i64::try_from(request.guild.id.get()).unwrap_or(i64::MAX),
        source: user_state::head(source, 32),
        now,
        write_events: request.write_events,
    };
    let members: Vec<Seen> = request
        .members
        .iter()
        .map(|m| Seen::member(m, &request.guild, guild_settings, now))
        .collect();
    let banned: Vec<Seen> = request.banned_users.iter().map(Seen::banned).collect();
    // 保管期間の掃除は付随の処理。失敗しても同期は続ける。
    if let Err(e) = recorder.cleanup_if_needed(now).await {
        error!("[user_state_service] retention cleanup failed before sync: {e}");
    }
    for attempt in 0..2 {
        match run_sync_attempt(recorder, &ctx, &members, &banned, request.reconcile_missing).await {
            Ok(stats) => return Ok(stats),
            Err(e) => {
                if attempt == 0 && recorder.try_self_heal("sync_guild_user_states", &e).await {
                    continue;
                }
                error!(
                    "[user_state_service] sync_guild_user_states failed guild_id={}: {e}",
                    ctx.guild_id
                );
                return Ok(SyncStats::default());
            }
        }
    }
    Ok(SyncStats::default())
}

/// 403（権限が無い）か。
fn is_forbidden(error: &serenity::Error) -> bool {
    matches!(
        error,
        serenity::Error::Http(HttpError::UnsuccessfulRequest(r)) if r.status_code.as_u16() == 403
    )
}

/// メンバー一覧を取る。返すのは（一覧, 全部取れたか）。Python の `_fetch_guild_members_for_sync`
/// （と discord.py の `Guild.fetch_members`）。
///
/// 取れなければ（403 もそれ以外も）キャッシュのメンバーで代わりにし、「全部ではない」とする。不完全な一覧で
/// 突き合わせると、まだ居る人を退出にしてしまう。上限（`max_members`）があるときも「全部ではない」。
pub async fn fetch_members(
    http: &Http,
    guild_id: GuildId,
    max_members: i64,
    cached: impl FnOnce() -> Vec<Member>,
) -> (Vec<Member>, bool) {
    let limit = (max_members > 0).then_some(max_members);
    let mut members = Vec::new();
    let mut after: Option<u64> = None;
    let result: Result<(), serenity::Error> = async {
        loop {
            // discord.py は件数を数え減らさない。上限が 1000 以上なら、1000 件ずつ最後まで取る。
            let retrieve = limit.map_or(PAGE_SIZE as u64, |l| l.min(PAGE_SIZE as i64) as u64);
            let page = http
                .get_guild_members(guild_id, Some(retrieve), after)
                .await?;
            let Some(last) = page.last() else {
                return Ok(());
            };
            after = Some(last.user.id.get());
            let short = page.len() < PAGE_SIZE;
            // 1 ページの中は逆順に渡す（discord.py の `reversed(data)`）。
            members.extend(page.into_iter().rev());
            if short {
                return Ok(());
            }
        }
    }
    .await;
    match result {
        Ok(()) => (members, limit.is_none()),
        Err(e) if is_forbidden(&e) => {
            warn!(
                "[BOT_SETUP] user_state sync: fetch_members forbidden guild={guild_id}. Fallback to cache."
            );
            (cached(), false)
        }
        Err(e) => {
            error!("[BOT_SETUP] user_state sync: fetch_members error guild={guild_id} err={e}");
            (cached(), false)
        }
    }
}

/// BAN 一覧を取る。Python の `_fetch_guild_bans_for_sync`（と discord.py の `Guild.bans(limit=None)`）。
///
/// BAN 一覧には代わりになる手元の控えが無い。取れなければ、取れた分だけを返す（403 なら空。BAN の同期だけを
/// 飛ばす）。
pub async fn fetch_bans(http: &Http, guild_id: GuildId) -> Vec<User> {
    let mut users = Vec::new();
    let mut after: Option<u64> = None;
    let result: Result<(), serenity::Error> = async {
        loop {
            // serenity の get_bans は件数を u8（255 まで）でしか渡せないので、要求を自分で組む。
            let mut params = vec![("limit", PAGE_SIZE.to_string())];
            if let Some(after) = after {
                params.push(("after", after.to_string()));
            }
            let request =
                Request::new(Route::GuildBans { guild_id }, LightMethod::Get).params(Some(params));
            let page: Vec<Ban> = http.fire(request).await?;
            if let Some(last) = page.last() {
                after = Some(last.user.id.get());
            }
            let short = page.len() < PAGE_SIZE;
            users.extend(page.into_iter().map(|ban| ban.user));
            if short {
                return Ok(());
            }
        }
    }
    .await;
    match result {
        Ok(()) => {}
        Err(e) if is_forbidden(&e) => {
            warn!("[BOT_SETUP] user_state sync: bans forbidden guild={guild_id}. Skip ban sync.");
        }
        Err(e) => {
            error!("[BOT_SETUP] user_state sync: bans fetch error guild={guild_id} err={e}");
        }
    }
    users
}

/// Python の真偽の書き方（ログに出す）。
fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// 終わりの 1 行。Python の `_log_sync_completed`（無人で回るので、あとから読めるのはここだけ）。
fn log_sync_completed(source: &str, totals: &GuildTotals) {
    let s = &totals.sync;
    info!(
        "[BOT_SETUP] user_state sync completed source={source} members={} bans={} created={} updated={} \
         left={} events={} repaired_rows={} repaired_fixed={}",
        s.members_seen,
        s.bans_seen,
        s.created,
        s.updated,
        s.left_reconciled,
        s.events_written,
        totals.repair_rows,
        totals.repair_fixed
    );
}

/// 全部のサーバーの同期に要るもの。
#[derive(Clone, Copy)]
pub struct Syncer<'a> {
    /// Discord（メンバー一覧・BAN 一覧を取る）。
    pub http: &'a Http,
    /// キャッシュ（サーバーの一覧・ロール・所有者、取れなかったときのメンバー）。
    pub cache: &'a Cache,
    /// 表に書く口（表を作ったか・最後に掃除した時刻を、イベントの記録と分け合う）。
    pub recorder: &'a Recorder,
    /// ギルドごとの設定（信頼ユーザー・バイパスロールの控えと、抜けたサーバーの設定の掃除）。
    pub settings: &'a SettingsCache,
    /// 設定。
    pub config: &'a SyncConfig,
    /// このサーバーだけを同期する（`BOT_ONLY_GUILD_ID`）。
    pub only_guild_id: Option<u64>,
}

impl Syncer<'_> {
    /// 同期するサーバー（ID の順）。
    fn guilds(&self) -> Vec<GuildId> {
        let mut guilds: Vec<GuildId> = self
            .cache
            .guilds()
            .into_iter()
            .filter(|g| self.only_guild_id.is_none_or(|only| only == g.get()))
            .collect();
        guilds.sort();
        guilds.dedup();
        guilds
    }

    /// 1 サーバーぶんを同期し、頼まれたら修復もする。Python の `_sync_one_guild`。
    ///
    /// 修復は全部の行を見るので、頼まれたときだけ回す。
    pub async fn sync_one_guild(
        &self,
        guild_id: GuildId,
        source: &str,
        write_events: bool,
        run_integrity_repair: bool,
    ) -> Result<GuildTotals, sqlx::Error> {
        // キャッシュから写す（錠を持ったまま待たない）。
        let (roles, owner_id): (HashMap<RoleId, Role>, Option<UserId>) =
            match self.cache.guild(guild_id) {
                Some(g) => (g.roles.clone(), Some(g.owner_id)),
                None => (HashMap::new(), None),
            };
        let cache = self.cache;
        let cached = move || -> Vec<Member> {
            let mut members: Vec<Member> = cache
                .guild(guild_id)
                .map(|g| g.members.values().cloned().collect())
                .unwrap_or_default();
            members.sort_by_key(|m| m.user.id);
            members
        };
        let (members, fetched_all) = fetch_members(
            self.http,
            guild_id,
            self.config.max_members_per_guild,
            cached,
        )
        .await;
        let banned_users = fetch_bans(self.http, guild_id).await;
        let settings = self.settings.snapshot();
        let stats = sync_guild_user_states(
            self.recorder,
            settings.guild(guild_id.get()),
            SyncRequest {
                guild: GuildView {
                    id: guild_id,
                    owner_id,
                    roles: &roles,
                },
                members: &members,
                banned_users: &banned_users,
                source,
                reconcile_missing: fetched_all,
                write_events,
            },
        )
        .await?;
        let repair = if run_integrity_repair {
            user_state_repair::repair_user_state_integrity(
                self.recorder,
                Some(guild_id.get()),
                self.config.repair_max_rows,
            )
            .await?
        } else {
            RepairStats::default()
        };
        info!(
            "[BOT_SETUP] user_state sync guild={guild_id} source={source} members={} bans={} created={} \
             updated={} left={} events={} fetched_all={} repaired_rows={} repaired_fixed={}",
            stats.members_seen,
            stats.bans_seen,
            stats.created,
            stats.updated,
            stats.left_reconciled,
            stats.events_written,
            py_bool(fetched_all),
            repair.rows_scanned,
            repair.rows_fixed
        );
        Ok(GuildTotals {
            sync: stats,
            repair_rows: repair.rows_scanned,
            repair_fixed: repair.rows_fixed,
        })
    }

    /// 全部のサーバーを 1 つずつ順に同期する。Python の `_sync_user_state_all_guilds`。
    ///
    /// 錠で全体を囲む（起動の後の同期と定期の同期が同時に走って、同じ表へ二重に書かないため）。1 つの
    /// サーバーが失敗しても他は続ける。**サーバーの間の待ちは、失敗したときも挟む**（調子が悪いときに限って
    /// 最速で叩き続けないため）。
    pub async fn sync_all_guilds(
        &self,
        source: &str,
        write_events: bool,
        run_integrity_repair: bool,
        lock: &Mutex<()>,
    ) -> GuildTotals {
        let _guard = lock.lock().await;
        let guilds = self.guilds();
        info!(
            "[BOT_SETUP] user_state sync started source={source} guilds={}",
            guilds.len()
        );
        let mut totals = GuildTotals::default();
        for guild_id in guilds {
            match self
                .sync_one_guild(guild_id, source, write_events, run_integrity_repair)
                .await
            {
                Ok(counted) => totals.add(&counted),
                Err(e) => {
                    error!(
                        "[BOT_SETUP] user_state sync failed guild={guild_id} source={source} err={e}"
                    );
                }
            }
            if !self.config.guild_pause.is_zero() {
                tokio::time::sleep(self.config.guild_pause).await;
            }
        }
        log_sync_completed(source, &totals);
        totals
    }

    /// Bot が抜けたサーバーの設定を掃除する。消したサーバーを返す。Python の `_purge_abandoned_guild_settings`。
    ///
    /// **居るサーバーは 1 つも渡さない**ように、キャッシュにある全部（`BOT_ONLY_GUILD_ID` にかかわらず）を
    /// 「居る」として渡す。失敗しても巡回は止めない（掃除は付随の処理）。
    pub async fn purge_abandoned_guild_settings(&self) -> Vec<String> {
        let present: HashSet<u64> = self.cache.guilds().iter().map(|g| g.get()).collect();
        match guild_retention::purge_abandoned_guilds(
            self.settings,
            &present,
            self.config.abandoned_after_days,
            Utc::now(),
        )
        .await
        {
            Ok(removed) => removed,
            Err(e) => {
                error!("[BOT_SETUP] 放棄ギルドの設定掃除に失敗: {e}");
                Vec::new()
            }
        }
    }

    /// 起動の後の同期。待ってから、履歴も書いて全部のサーバーを同期し、修復もする。Python の
    /// `_sync_user_state_on_ready`。
    pub async fn run_on_ready(&self, lock: &Mutex<()>) {
        if !self.config.sync_delay.is_zero() {
            tokio::time::sleep(self.config.sync_delay).await;
        }
        self.sync_all_guilds("on_ready", true, true, lock).await;
    }

    /// 定期の同期・修復・掃除。待ってから、決めた間隔でずっと回す。Python の `_user_state_auto_repair_loop`。
    pub async fn run_auto_repair(&self, lock: &Mutex<()>) {
        if !self.config.repair_start_delay.is_zero() {
            tokio::time::sleep(self.config.repair_start_delay).await;
        }
        loop {
            self.sync_all_guilds("auto_repair", self.config.repair_write_events, true, lock)
                .await;
            self.purge_abandoned_guild_settings().await;
            tokio::time::sleep(self.config.repair_interval).await;
        }
    }
}

/// 別のタスクで動かし、途中で落ちたら（パニック）ログに残す（Python の `except Exception` の
/// 「fatal error」と同じ行）。
fn spawn_logged(label: &'static str, work: impl Future<Output = ()> + Send + 'static) {
    let inner = tokio::spawn(work);
    tokio::spawn(async move {
        if let Err(e) = inner.await {
            error!("{label}: {e}");
        }
    });
}

/// このプロセスで動かすもの（起動の後の同期, 定期の同期・修復・掃除）。Python の on_ready の条件。
///
/// **`BOT_BACKGROUND_WORKER` が偽のプロセスは、どちらも動かさない。** Bot を並べたとき、全部のプロセスが同じ表へ
/// 同期を書き、起動のたびに同期の履歴が台数ぶん積まれ、設定の掃除も台数ぶん回るのを防ぐ。受け持つプロセスの
/// 中では、`USER_STATE_SYNC_ON_READY`・`USER_STATE_AUTO_REPAIR_ENABLED` がそのまま効く。
pub fn tasks_to_start(config: &BotConfig) -> (bool, bool) {
    let sync = &config.user_state_sync;
    (
        config.background_worker && sync.sync_on_ready,
        config.background_worker && sync.auto_repair,
    )
}

/// 起動の後の同期と、定期の同期・修復・掃除を、設定に従って動かし始める（[`tasks_to_start`]）。Python の
/// on_ready のうち利用者の状態のところ。1 プロセスで 1 回だけ呼ぶこと（呼ぶ側の ready が守っている）。
pub fn start(ctx: &Context, state: &Arc<AppState>) {
    let config = &state.config.user_state_sync;
    let (on_ready, auto_repair) = tasks_to_start(&state.config);
    let lock = Arc::new(Mutex::new(()));
    let launch = |label: &'static str, repair: bool| {
        let (http, cache, state, lock) = (
            Arc::clone(&ctx.http),
            Arc::clone(&ctx.cache),
            Arc::clone(state),
            Arc::clone(&lock),
        );
        spawn_logged(label, async move {
            let syncer = Syncer {
                http: &http,
                cache: &cache,
                recorder: &state.user_state,
                settings: &state.settings,
                config: &state.config.user_state_sync,
                only_guild_id: state.config.only_guild_id,
            };
            if repair {
                syncer.run_auto_repair(&lock).await;
            } else {
                syncer.run_on_ready(&lock).await;
            }
        });
    };
    if on_ready {
        launch("[BOT_SETUP] user_state sync fatal error", false);
        info!(
            "[BOT] USER_STATE_SYNC_ON_READY=true: background sync task started (delay={}s)",
            config.sync_delay.as_secs()
        );
    }
    if auto_repair {
        launch("[BOT_SETUP] user_state auto_repair fatal error", true);
        info!(
            "[BOT] USER_STATE_AUTO_REPAIR_ENABLED=true: periodic repair started (interval={}s)",
            config.repair_interval.as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as Map;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: Map<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// 既定値と下限が Python（events/user_state_sync.py・services/guild_retention.py）と同じこと。
    #[test]
    fn the_defaults_and_floors_match_python() {
        let c = SyncConfig::default();
        assert!(c.sync_on_ready && c.auto_repair && c.repair_write_events);
        assert_eq!(c.sync_delay, Duration::from_secs(20));
        assert_eq!(c.guild_pause, Duration::from_secs(1));
        assert_eq!(c.max_members_per_guild, 0);
        assert_eq!(c.repair_interval, Duration::from_secs(1800));
        assert_eq!(c.repair_start_delay, Duration::from_secs(180));
        assert_eq!(c.repair_max_rows, 50_000);
        assert_eq!(c.abandoned_after_days, 3650);
        let low = SyncConfig::from_env(&env(&[
            ("USER_STATE_SYNC_DELAY_SECONDS", "-5"),
            ("USER_STATE_SYNC_GUILD_PAUSE_SECONDS", "-1.5"),
            ("USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", "-3"),
            ("USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS", "10"),
            ("USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS", "-1"),
            ("USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD", "5"),
            ("GUILD_SETTINGS_ABANDONED_AFTER_DAYS", "0"),
            ("USER_STATE_SYNC_ON_READY", "false"),
            ("USER_STATE_AUTO_REPAIR_ENABLED", "0"),
            ("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", "no"),
        ]));
        assert!(!low.sync_on_ready && !low.auto_repair && !low.repair_write_events);
        assert_eq!(low.sync_delay, Duration::ZERO);
        assert_eq!(low.guild_pause, Duration::ZERO);
        assert_eq!(low.max_members_per_guild, 0);
        assert_eq!(low.repair_interval, Duration::from_secs(300));
        assert_eq!(low.repair_start_delay, Duration::ZERO);
        assert_eq!(low.repair_max_rows, 100);
        assert_eq!(low.abandoned_after_days, 1);
        let pause = SyncConfig::from_env(&env(&[("USER_STATE_SYNC_GUILD_PAUSE_SECONDS", "0.25")]));
        assert_eq!(pause.guild_pause, Duration::from_millis(250));
    }

    fn update<'a>(event_type: &'a str, status: &'a str, now: DateTime<Utc>) -> Update<'a> {
        Update {
            event_type,
            status_after: status,
            now,
            username: None,
            display_name: None,
            avatar_url: None,
            in_guild: None,
            is_banned: None,
            timed_out_until: None,
            roles_json: None,
            abilities_json: None,
        }
    }

    /// 名前は空でなければ上書きし、旗は渡されなければ状態から決め、タイムアウトは期限から数え直すこと
    /// （Python の `_update_current_state_fields`）。
    #[test]
    fn the_update_follows_the_python_rules() {
        let now = at("2026-11-28T00:00:00Z");
        let mut row = CurrentRow::blank(1, false);
        row.username = Some("old".into());
        row.timed_out_until = Some(at("2026-11-29T00:00:00Z"));
        let mut u = update("sync_member_x", "active", now);
        u.username = Some("");
        u.display_name = Some("disp");
        apply_update(&mut row, &u);
        assert_eq!(row.username.as_deref(), Some("old"));
        assert_eq!(row.display_name.as_deref(), Some("disp"));
        assert!(row.is_in_guild && !row.is_banned && row.is_timed_out);
        assert_eq!(row.last_event_at, Some(now));
        assert_eq!(row.updated_at, Some(now));
        // 期限が過ぎていれば旗を下ろす。期限そのものは残す。
        apply_update(&mut row, &update("x", "left", at("2026-11-30T00:00:00Z")));
        assert!(!row.is_in_guild && !row.is_timed_out);
        assert!(row.timed_out_until.is_some());
        // 分からない状態では旗に触らない。
        row.is_in_guild = true;
        row.is_banned = true;
        apply_update(&mut row, &update("x", "weird", now));
        assert!(row.is_in_guild && row.is_banned);
        apply_update(&mut row, &update("x", "unbanned", now));
        assert!(row.is_in_guild && !row.is_banned);
        apply_update(&mut row, &update("member_timeout_cleared", "active", now));
        assert_eq!(row.timed_out_until, None);
        apply_update(&mut row, &update("member_join", "active", now));
        assert_eq!(row.last_joined_at, Some(now));
        assert_eq!(row.last_left_at, None);
        apply_update(&mut row, &update("member_ban", "banned", now));
        assert_eq!(row.last_left_at, Some(now));
        assert!(row.is_banned && !row.is_in_guild);
        apply_update(&mut row, &update("member_kick", "kicked", now));
        assert!(!row.is_banned);
    }

    fn seen(user_id: i64) -> Seen {
        Seen {
            user_id,
            username: format!("u{user_id}"),
            display_name: format!("d{user_id}"),
            avatar_url: format!("https://a/{user_id}"),
            timed_out_until: None,
            snapshot: Some(("[]".into(), "{}".into())),
        }
    }

    fn ctx(write_events: bool) -> SyncContext {
        SyncContext {
            guild_id: 9,
            source: "on_ready".into(),
            now: at("2026-11-28T00:00:00Z"),
            write_events,
        }
    }

    fn existing(user_id: i64, id: i64, status: &str, in_guild: bool, banned: bool) -> CurrentRow {
        let mut row = CurrentRow::blank(user_id, banned);
        row.id = Some(id);
        row.status = status.into();
        row.is_in_guild = in_guild;
        row
    }

    /// メンバー → BAN → 退出の順に決め、BAN が勝ち、BAN の人と抜けた人には触らないこと。
    #[test]
    fn the_three_stages_run_in_order() {
        let rows = vec![
            existing(1, 10, "active", true, false),
            existing(2, 11, "left", false, false),
            existing(3, 12, "banned", false, true),
            existing(4, 13, "unknown", false, false),
            existing(5, 14, "kicked", true, false),
        ];
        let p = plan_sync(
            rows,
            &[seen(6), seen(7)],
            &[seen(7), seen(3)],
            true,
            &ctx(true),
        );
        let by: Map<i64, &CurrentRow> =
            p.rows.iter().map(|r| (r.after.user_id, &r.after)).collect();
        assert_eq!(by[&7].status, "banned");
        assert!(by[&7].is_banned && !by[&7].is_in_guild);
        assert_eq!(by[&1].status, "left");
        assert_eq!(by[&2].last_event_type, None, "抜けた人には触らない");
        assert_eq!(by[&3].last_event_type.as_deref(), Some("sync_ban_on_ready"));
        assert_eq!(by[&4].status, "left");
        assert_eq!(by[&5].status, "left", "在室の旗が立っていれば退出にする");
        let kinds: Vec<(i64, &str)> = p
            .events
            .iter()
            .map(|e| (e.user_id, e.event_type.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (6, "sync_discovered_member"),
                (7, "sync_discovered_member"),
                (7, "sync_discovered_ban"),
                (1, "sync_mark_left"),
                (4, "sync_mark_left"),
                (5, "sync_mark_left"),
            ],
            "既に BAN の人（3）には履歴を積まない"
        );
        assert_eq!(
            p.stats,
            SyncStats {
                members_seen: 2,
                bans_seen: 2,
                created: 2,
                updated: 2,
                left_reconciled: 3,
                events_written: 6,
            }
        );
        assert_eq!(p.events[0].payload_json, r#"{"source": "on_ready"}"#);
        // 突き合わせない・履歴を書かないときは、退出も履歴も無い。
        let q = plan_sync(
            vec![existing(1, 10, "active", true, false)],
            &[],
            &[],
            false,
            &ctx(false),
        );
        assert_eq!(q.stats, SyncStats::default());
        assert!(q.events.is_empty());
        assert_eq!(q.rows[0].before.as_ref(), Some(&q.rows[0].after));
    }

    /// BAN の旗だけが落ちている BAN の人には、もう一度 BAN の履歴を書くこと（Python の
    /// `before_banned is False`）。同じ人がメンバー一覧に 2 回居れば、2 回目は書き換えとして数えること。
    #[test]
    fn a_ban_with_a_dropped_flag_is_written_again() {
        let p = plan_sync(
            vec![existing(3, 12, "banned", false, false)],
            &[seen(8), seen(8)],
            &[seen(3)],
            true,
            &ctx(true),
        );
        let kinds: Vec<&str> = p.events.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(kinds, vec!["sync_discovered_member", "sync_discovered_ban"]);
        assert_eq!((p.stats.created, p.stats.updated), (1, 2));
    }

    /// タイムアウトはメンバー一覧の期限に揃えること: 期限の無い人はタイムアウト中を下ろし（Bot が止まっていた
    /// 間に早めに解かれたもの）、期限のある人はその期限にする（過ぎていれば旗だけ下ろす）。BAN 一覧の人には
    /// 触らない。
    #[test]
    fn the_timeout_follows_the_member_list() {
        let until = at("2026-12-31T00:00:00Z");
        let past = at("2026-11-01T00:00:00Z");
        let timed = |user_id: i64| {
            let mut row = existing(user_id, 20 + user_id, "active", true, false);
            row.is_timed_out = true;
            row.timed_out_until = Some(until);
            row
        };
        let mut still = seen(2);
        still.timed_out_until = Some(until);
        let mut over = seen(3);
        over.timed_out_until = Some(past);
        let p = plan_sync(
            vec![timed(1), timed(2), timed(3), timed(4)],
            &[seen(1), still, over],
            &[seen(4)],
            true,
            &ctx(false),
        );
        let by: Map<i64, &CurrentRow> =
            p.rows.iter().map(|r| (r.after.user_id, &r.after)).collect();
        let timeout = |id: i64| (by[&id].is_timed_out, by[&id].timed_out_until);
        assert_eq!(timeout(1), (false, None), "一覧に期限が無い人");
        assert_eq!(timeout(2), (true, Some(until)));
        assert_eq!(timeout(3), (false, Some(past)));
        assert_eq!(timeout(4), (true, Some(until)), "BAN 一覧の人には触らない");
    }

    /// 起動の後の同期と定期の同期・修復は、`BOT_BACKGROUND_WORKER` が真のプロセスだけが受け持ち、その中で
    /// それぞれの旗で決まること（Python の on_ready の条件）。
    #[test]
    fn only_the_background_worker_syncs() {
        let tasks = |pairs: &[(&str, &str)]| {
            let mut all = vec![("DISCORD_BOT_TOKEN", "t")];
            all.extend_from_slice(pairs);
            tasks_to_start(&BotConfig::from_env(&env(&all)).unwrap())
        };
        // 何も設定しなければ（本番の 1 プロセス）、両方を動かす。
        assert_eq!(tasks(&[]), (true, true));
        assert_eq!(tasks(&[("BOT_BACKGROUND_WORKER", "false")]), (false, false));
        let flags_on = [
            ("USER_STATE_SYNC_ON_READY", "true"),
            ("USER_STATE_AUTO_REPAIR_ENABLED", "true"),
        ];
        let mut worker_off = flags_on.to_vec();
        worker_off.push(("BOT_BACKGROUND_WORKER", "0"));
        assert_eq!(tasks(&worker_off), (false, false), "旗が真でも止める");
        assert_eq!(
            tasks(&[("USER_STATE_SYNC_ON_READY", "false")]),
            (false, true)
        );
        assert_eq!(
            tasks(&[("USER_STATE_AUTO_REPAIR_ENABLED", "false")]),
            (true, false)
        );
    }
}
