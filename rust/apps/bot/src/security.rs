//! セキュリティの部品（スパム・VC の荒らしの判定、URL の抜き出し、バイパス、措置〔タイムアウト・ロールの剥奪〕、
//! 結果の Embed）と、VC に入ったときの荒らし対策。Python の `services/spam_detection.py`・`raid_detection.py`・
//! `security_service.py` のうち、外部のサービス（VirusTotal・Groq）に頼らないところ。
//!
//! メッセージの検査の流れ（判定を集める → 措置する → 報告する）は [`crate::message_security`]。
//!
//! 判定と措置は、本人が 2026-11-28 に決めた形（rust-09 の S1〜S8）を Python と同じに写した:
//!
//! - 措置はタイムアウト（危険は 24 時間、スパムだけなら 10 分）。Bot に「メンバーをタイムアウト」の権限が無い
//!   サーバーでは、危険ならいまどおり全ロールを外し、スパムなら消すだけ（S1・S2）
//! - スパムは「同じ内容の繰り返し」と「量の多さ」の 2 つの条件（S3）
//! - VC の荒らしは「入って間もない人」（入って 24 時間未満か、アカウントを作って 7 日未満）で数える（S4・S5）
//! - URL は Discord の書き方（隠しリンク・括弧・飾りの記号・招待）を読み解いて抜き出す（S6）
//! - 管理者は検査を飛ばす（S7）。報告の見出しと色は、取った措置から決める（S8）
//!
//! 秒・回数・日数は環境変数で変えられる（[`SecurityConfig`]。名前・既定・下限は Python と同じ）。
//!
//! Python には「バイパスの判定に失敗したら措置を見送る」分岐がある。設定の読み取りが失敗した
//! ときの備えで、Rust の設定は起動時に読み終えてメモリから引くので、ここが失敗することはない
//! （Python も Postgres 版では起動後は同じ）。そのため Rust には持ち込んでいない。

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, OnceLock};

use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use regex::Regex;
use serde_json::Value;
use serenity::all::{
    CreateEmbed, CreateEmbedFooter, Guild, GuildId, Http, Permissions, Role, RoleId, Timestamp,
    UserId,
};
use serenity::http::{HttpError, StatusCode};
use sycs_core::env::Env;
use tracing::{info, warn};
use unicode_normalization::UnicodeNormalization;

use crate::commands::reply::cap_list_for_message;
use crate::groq::python_is_space;
use crate::log_channel::{self, Author, Level, LogSink};
use crate::python_chars;

const SPAM_CLEANUP_INTERVAL: u32 = 100;
const RAID_CLEANUP_INTERVAL: u32 = 50;
/// 新規メンバーとみなす日数。
pub const NEW_MEMBER_THRESHOLD_DAYS: i64 = 7;
/// リンク数過多とみなす本数。
pub const MAX_LINKS: usize = 5;
/// 措置のタイムアウトの長さの上限（Discord が受け付ける 28 日）。
pub const TIMEOUT_MAX_SECONDS: i64 = 28 * 24 * 3600;
/// タイムアウト・ロールの剥奪の理由（監査ログに出る）。
pub const ENFORCEMENT_REASON: &str = "セキュリティ違反";
/// Discord の ID（snowflake）の時刻の起点（2015-01-01、ミリ秒）。
const DISCORD_EPOCH_MS: i64 = 1_420_070_400_000;
/// 危険の色（discord.py の `Color.red()`）。
pub const RED: u32 = 0xE7_4C_3C;
/// スパム・見送りの色（`Color.orange()`）。
pub const ORANGE: u32 = 0xE6_7E_22;
/// 注意の材料ありの色（`Color.gold()`。serenity の `Colour` の定数は discord.py と違うことがあるので値で持つ）。
pub const GOLD: u32 = 0xF1_C4_0F;
/// 問題なしの色（`Color.green()`）。
pub const GREEN: u32 = 0x2E_CC_71;

/// スパムの数え方（S3）。Python の `SPAM_REPEAT_COUNT` など。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpamRules {
    /// 繰り返し: 同じ内容をこの回数（この投稿を含む。`SPAM_REPEAT_COUNT`、既定 3・下限 2）。
    pub repeat_count: usize,
    /// 繰り返しを数える秒数（`SPAM_REPEAT_WINDOW_SECONDS`、既定 60・下限 1）。
    pub repeat_window: i64,
    /// 量: 内容を問わずこの回数（`SPAM_FLOOD_COUNT`、既定 8・下限 2）。
    pub flood_count: usize,
    /// 量を数える秒数（`SPAM_FLOOD_WINDOW_SECONDS`、既定 10・下限 1）。
    pub flood_window: i64,
}

impl Default for SpamRules {
    fn default() -> Self {
        Self {
            repeat_count: 3,
            repeat_window: 60,
            flood_count: 8,
            flood_window: 10,
        }
    }
}

/// VC の荒らしの数え方（S4）。Python の `VC_RAID_WINDOW_SECONDS` など。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaidRules {
    /// 数える秒数（`VC_RAID_WINDOW_SECONDS`、既定 20・下限 1）。措置済みの覚えも、措置してからこの秒数。
    pub window: i64,
    /// 入って間もない人が何人入ったら荒らしか（`VC_RAID_THRESHOLD`、既定 5・下限 2）。
    pub threshold: usize,
    /// サーバーに入ってから何時間未満なら「入って間もない人」か（`VC_RAID_NEW_JOIN_HOURS`、既定 24・下限 1）。
    pub new_join_hours: i64,
}

impl Default for RaidRules {
    fn default() -> Self {
        Self {
            window: 20,
            threshold: 5,
            new_join_hours: 24,
        }
    }
}

/// 検査の秒・回数・日数（環境変数。名前・既定・下限は Python と同じ）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityConfig {
    /// 危険なときのタイムアウト（`SECURITY_TIMEOUT_DANGER_SECONDS`、既定 86400・下限 60・上限 28 日）。
    pub timeout_danger_seconds: i64,
    /// スパムだけのときのタイムアウト（`SECURITY_TIMEOUT_SPAM_SECONDS`、既定 600・下限 60・上限 28 日）。
    pub timeout_spam_seconds: i64,
    /// スパムの数え方。
    pub spam: SpamRules,
    /// VC の荒らしの数え方。
    pub raid: RaidRules,
    /// 「新しいアカウント」とみなす日数（`NEW_ACCOUNT_THRESHOLD_DAYS`、既定 7・下限 1。S5）。
    pub new_account_days: i64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            timeout_danger_seconds: 86_400,
            timeout_spam_seconds: 600,
            spam: SpamRules::default(),
            raid: RaidRules::default(),
            new_account_days: 7,
        }
    }
}

impl SecurityConfig {
    /// 環境変数から読む（読めない値は既定、範囲の外は丸める。Python の `env_int` と同じ）。
    pub fn from_env(env: &Env) -> Self {
        let count = |key: &str, default: i64| {
            let n = env.int(key, default, Some(2), None);
            usize::try_from(n).unwrap_or(2)
        };
        let positive = |key: &str, default: i64| env.int(key, default, Some(1), None);
        let timeout = |key: &str, default: i64| {
            env.int(key, default, Some(60), Some(TIMEOUT_MAX_SECONDS))
        };
        Self {
            timeout_danger_seconds: timeout("SECURITY_TIMEOUT_DANGER_SECONDS", 86_400),
            timeout_spam_seconds: timeout("SECURITY_TIMEOUT_SPAM_SECONDS", 600),
            spam: SpamRules {
                repeat_count: count("SPAM_REPEAT_COUNT", 3),
                repeat_window: positive("SPAM_REPEAT_WINDOW_SECONDS", 60),
                flood_count: count("SPAM_FLOOD_COUNT", 8),
                flood_window: positive("SPAM_FLOOD_WINDOW_SECONDS", 10),
            },
            raid: RaidRules {
                window: positive("VC_RAID_WINDOW_SECONDS", 20),
                threshold: count("VC_RAID_THRESHOLD", 5),
                new_join_hours: positive("VC_RAID_NEW_JOIN_HOURS", 24),
            },
            new_account_days: positive("NEW_ACCOUNT_THRESHOLD_DAYS", 7),
        }
    }
}

/// 同じ内容かを比べる鍵（揃えた本文, （ファイル名, 大きさ）の並び）。Python の `ContentKey`。
pub type ContentKey = (String, Vec<(String, u64)>);

/// 記録した投稿 1 件。`taken` は、スパムと数えて一度返したか（二度は返さない）。
struct SpamPost {
    at: f64,
    channel: u64,
    message: u64,
    key: Option<ContentKey>,
    taken: bool,
}

/// (ギルド, ユーザー) → 投稿。
type SpamHistory = HashMap<(u64, u64), Vec<SpamPost>>;

/// スパムの記録に入れる投稿 1 件。
#[derive(Clone, Copy, Debug)]
pub struct SpamInput<'a> {
    /// サーバー。
    pub guild_id: u64,
    /// 発言した人。
    pub user_id: u64,
    /// チャンネル（あとで消すため）。
    pub channel_id: u64,
    /// メッセージ（あとで消すため）。
    pub message_id: u64,
    /// 本文。
    pub content: &'a str,
    /// 添付（ファイル名, 大きさ）。
    pub attachments: &'a [(String, u64)],
}

/// 1 人の投稿を数えて、スパムかどうかを決める。Python の `check_spam`（S3）。
///
/// - 繰り返し: 同じ内容（[`content_key`]）を 60 秒に 3 回。チャンネルをまたいでも数える
/// - 量: 内容が違っても 10 秒に 8 回
///
/// 本文も添付も空の投稿は、繰り返しには数えず、量にだけ数える。スパムと数えた投稿は [`SpamCheck::posts`] で返す
/// （一度返した投稿は二度返さないが、回数には数え続ける）。
pub struct SpamDetector {
    rules: SpamRules,
    inner: Mutex<(SpamHistory, u32)>,
}

impl Default for SpamDetector {
    fn default() -> Self {
        Self::new(SpamRules::default())
    }
}

/// スパムの判定の結果。Python の `SpamCheck`。
#[derive(Clone, Debug, PartialEq)]
pub struct SpamCheck {
    /// 繰り返しの条件に当たったか。
    pub repeat: bool,
    /// 量の条件に当たったか。
    pub flood: bool,
    /// 同じ内容の回数（この投稿を含む。本文も添付も空なら 0）。
    pub repeat_count: usize,
    /// 同じ内容がまたがったチャンネルの数。
    pub repeat_channels: usize,
    /// 量の窓の中の回数（この投稿を含む）。
    pub flood_count: usize,
    /// 量の窓の中の、いちばん短い間隔（秒）。1 回だけなら無限大。
    pub min_interval: f64,
    /// スパムと数えた投稿の数（当たった条件の投稿を合わせたもの。スパムでなければ 0）。
    pub counted: usize,
    /// 今回はじめてスパムと数えた投稿（チャンネル, メッセージ）。記録の順（この投稿は最後）。
    pub posts: Vec<(u64, u64)>,
    /// 繰り返しを数えた秒数（AI に渡す文とログの文に書く）。
    pub repeat_window: i64,
    /// 量を数えた秒数。
    pub flood_window: i64,
}

impl Default for SpamCheck {
    /// 「スパムではない、この投稿 1 件だけ」。
    fn default() -> Self {
        let rules = SpamRules::default();
        Self {
            repeat: false,
            flood: false,
            repeat_count: 0,
            repeat_channels: 0,
            flood_count: 1,
            min_interval: f64::INFINITY,
            counted: 0,
            posts: Vec::new(),
            repeat_window: rules.repeat_window,
            flood_window: rules.flood_window,
        }
    }
}

impl SpamCheck {
    /// どちらかの条件に当たったか。
    pub fn is_spam(&self) -> bool {
        self.repeat || self.flood
    }

    /// 報告の「スパム回数」に出す数（スパムなら数えた投稿の数、でなければ量の窓の中の回数）。
    pub fn display_count(&self) -> usize {
        if self.is_spam() {
            self.counted
        } else {
            self.flood_count
        }
    }
}

impl SpamDetector {
    /// 数え方を決めて作る。
    pub fn new(rules: SpamRules) -> Self {
        Self {
            rules,
            inner: Mutex::default(),
        }
    }

    /// 投稿を 1 件記録して、スパムかどうかを返す。
    pub fn check(&self, post: &SpamInput<'_>, now: f64) -> SpamCheck {
        let rules = self.rules;
        let key = content_key(post.content, post.attachments);
        let keep = rules.repeat_window.max(rules.flood_window) as f64;
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (history, counter) = &mut *guard;
        let posts = history.entry((post.guild_id, post.user_id)).or_default();
        posts.push(SpamPost {
            at: now,
            channel: post.channel_id,
            message: post.message_id,
            key: key.clone(),
            taken: false,
        });
        posts.retain(|p| now - p.at < keep);
        let check = judge_spam(posts, key.as_ref(), now, rules);
        // 100 回に 1 回、最近の投稿の無い人を忘れる（毎回全員を見ない）。
        *counter += 1;
        if *counter >= SPAM_CLEANUP_INTERVAL {
            *counter = 0;
            history.retain(|_, ps| ps.iter().any(|p| now - p.at < keep));
        }
        check
    }
}

/// 記録からスパムかを決め、数えた投稿のうち、まだ返していないものに印を付けて返す。
fn judge_spam(
    posts: &mut [SpamPost],
    key: Option<&ContentKey>,
    now: f64,
    rules: SpamRules,
) -> SpamCheck {
    let in_flood = |p: &SpamPost| now - p.at < rules.flood_window as f64;
    let in_repeat = |p: &SpamPost| {
        key.is_some() && p.key.as_ref() == key && now - p.at < rules.repeat_window as f64
    };
    let flood_count = posts.iter().filter(|p| in_flood(p)).count();
    let repeat_count = posts.iter().filter(|p| in_repeat(p)).count();
    let repeat_channels = posts
        .iter()
        .filter(|p| in_repeat(p))
        .map(|p| p.channel)
        .collect::<HashSet<_>>()
        .len();
    let flood = flood_count >= rules.flood_count;
    let repeat = repeat_count >= rules.repeat_count;
    let mut times: Vec<f64> = posts
        .iter()
        .filter(|p| in_flood(p))
        .map(|post| post.at)
        .collect();
    times.sort_by(f64::total_cmp);
    let min_interval = times
        .windows(2)
        .map(|w| w[1] - w[0])
        .fold(f64::INFINITY, f64::min);
    let mut counted = 0;
    let mut fresh = Vec::new();
    for p in posts.iter_mut() {
        if (flood && in_flood(p)) || (repeat && in_repeat(p)) {
            counted += 1;
            if !p.taken {
                p.taken = true;
                fresh.push((p.channel, p.message));
            }
        }
    }
    SpamCheck {
        repeat,
        flood,
        repeat_count,
        repeat_channels,
        flood_count,
        min_interval,
        counted,
        posts: fresh,
        repeat_window: rules.repeat_window,
        flood_window: rules.flood_window,
    }
}

/// Python の `str.casefold()` が `str.lower()` と違う文字の表（`tests/fixtures/message_security/generate_casefold.py`
/// が Python 3.13 から作る。1 行に 1 つ、f・元・先〔空白区切り〕。16 進）。
const CASEFOLD_TSV: &str = include_str!("security_casefold.tsv");

fn casefold_table() -> &'static HashMap<char, String> {
    static TABLE: OnceLock<HashMap<char, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let hex = |s: &str| u32::from_str_radix(s, 16).ok().and_then(char::from_u32);
        CASEFOLD_TSV
            .lines()
            .filter_map(|line| {
                let mut parts = line.trim_end().split('\t');
                if parts.next()? != "f" {
                    return None;
                }
                let from = hex(parts.next()?)?;
                let to: String = parts.next()?.split(' ').filter_map(hex).collect();
                Some((from, to))
            })
            .collect()
    })
}

/// Python の `str.casefold()`（Python 3.13 の表どおり）。lower と違う文字は表から、ほかは 1 文字ずつの
/// `str.lower()`（[`python_chars::lower`]。1 文字なので `Σ` は語の終わりの形にならず `σ`、casefold と同じ）。
pub fn casefold(text: &str) -> String {
    let folds = casefold_table();
    let mut out = String::with_capacity(text.len());
    let mut buf = [0u8; 4];
    for c in text.chars() {
        if let Some(folded) = folds.get(&c) {
            out.push_str(folded);
        } else if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push_str(&python_chars::lower(c.encode_utf8(&mut buf)));
        }
    }
    out
}

/// 同じ内容かを比べる鍵。本文も添付も空なら `None`（繰り返しには数えない）。Python の `content_key`。
///
/// 本文は NFKC にして casefold し、空白の並び（Python の `str.split()` の空白）を 1 つに縮めて前後を落とす。
/// 添付は（ファイル名, 大きさ）の並び。本文と添付の両方が同じなら同じ内容。
pub fn content_key(content: &str, attachments: &[(String, u64)]) -> Option<ContentKey> {
    let folded = casefold(&content.nfkc().collect::<String>());
    let text = folded
        .split(python_is_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() && attachments.is_empty() {
        return None;
    }
    Some((text, attachments.to_vec()))
}

/// チャンネル → 参加（時刻, ユーザー）と、措置した人（ユーザー → 時刻）。
#[derive(Default)]
struct RaidState {
    joins: HashMap<u64, Vec<(f64, u64)>>,
    enforced: HashMap<u64, HashMap<u64, f64>>,
    counter: u32,
}

/// VC に「入って間もない人」が続けて入るのを数える。Python の `check_vc_raid`・`is_vc_raid_ongoing`・
/// `was_enforced`（S4）。
///
/// 名前は見ない。入って間もない人（[`is_fresh_joiner`]。呼ぶ側が決める）の参加だけを記録し、同じ VC に 20 秒の間に
/// 5 人入ったら荒らし。同じ人は何度入り直しても 1 人。当たったら、数に入った全員を措置する人として返す（同じ窓の
/// 中で後から入った人も。同じ人は二度返さない）。
///
/// **記録に入れるのは VC への参加だけ**（[`RaidDetector::check`]）。メッセージの検査（VC にいる人の発言）は、記録を
/// 足さずに [`RaidDetector::peek`] で見る（rust-09 の (e)）。
pub struct RaidDetector {
    rules: RaidRules,
    inner: Mutex<RaidState>,
}

impl Default for RaidDetector {
    fn default() -> Self {
        Self::new(RaidRules::default())
    }
}

/// メッセージの検査から見た、発言した人と VC の荒らし。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaidStatus {
    /// 荒らしの数に入っていない（荒らしの形でない VC、または入って間もなくない人）。
    NotCounted,
    /// 荒らしの数に入っている。`enforced` は、VC の経路で措置済みか（二重に措置しない）。
    Counted {
        /// VC の経路で措置済みか。
        enforced: bool,
    },
}

/// 直近の窓の中で数に入る人（同じ人は 1 人、最初に入った順）。
fn counted_people(joins: &[(f64, u64)], now: f64, window: f64) -> Vec<u64> {
    let mut people: Vec<u64> = Vec::new();
    for &(t, user) in joins {
        if now - t < window && !people.contains(&user) {
            people.push(user);
        }
    }
    people
}

impl RaidDetector {
    /// 数え方を決めて作る。
    pub fn new(rules: RaidRules) -> Self {
        Self {
            rules,
            inner: Mutex::default(),
        }
    }

    /// 入って間もない人の VC への参加を 1 回記録して、荒らしなら、数に入った人のうちまだ措置していない人を、
    /// 最初に入った順に返す（返した人は措置済みとして覚える）。荒らしでなければ空。Python の `check_vc_raid`
    /// （VC に入ったときだけ呼ぶ）。
    pub fn check(&self, channel_id: u64, user_id: u64, now: f64) -> Vec<u64> {
        let window = self.rules.window as f64;
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let state = &mut *guard;
        let joins = state.joins.entry(channel_id).or_default();
        joins.push((now, user_id));
        joins.retain(|(t, _)| now - t < window);
        let people = counted_people(joins, now, window);
        // 50 回に 1 回、最近の参加も措置の覚えも無いチャンネルを忘れる。
        state.counter += 1;
        if state.counter >= RAID_CLEANUP_INTERVAL {
            state.counter = 0;
            state
                .joins
                .retain(|_, js| js.iter().any(|(t, _)| now - t < window));
            state
                .enforced
                .retain(|_, done| done.values().any(|at| now - at < window));
        }
        if people.len() < self.rules.threshold {
            return Vec::new();
        }
        let done = state.enforced.entry(channel_id).or_default();
        done.retain(|_, at| now - *at < window);
        let targets: Vec<u64> = people
            .iter()
            .copied()
            .filter(|u| !done.contains_key(u))
            .collect();
        for user in &people {
            done.entry(*user).or_insert(now);
        }
        targets
    }

    /// 記録を足さずに、そのチャンネルがいま荒らしの形で、その人自身が数に入っているか（と、措置済みか）。
    /// Python の `is_vc_raid_ongoing`・`was_enforced`（メッセージの検査から呼ぶ。発言は数えない）。
    pub fn peek(&self, channel_id: u64, user_id: u64, now: f64) -> RaidStatus {
        let window = self.rules.window as f64;
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let people = guard
            .joins
            .get(&channel_id)
            .map(|joins| counted_people(joins, now, window))
            .unwrap_or_default();
        if people.len() < self.rules.threshold || !people.contains(&user_id) {
            return RaidStatus::NotCounted;
        }
        let enforced = guard
            .enforced
            .get(&channel_id)
            .and_then(|done| done.get(&user_id))
            .is_some_and(|at| now - at < window);
        RaidStatus::Counted { enforced }
    }
}

/// 正規表現を作る（どれも決まった文なので、作れなければ書き間違い）。
fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("正しい正規表現")
}

// Python の `\s`（`str.isspace`）は、Rust の正規表現の `\s` に区切りの制御文字 U+001C〜U+001F を足したもの。
// 下の正規表現では `[\s\x1C-\x1F]` と書く（Python と同じところで URL を切る）。

/// Python の `URL_REGEX`（`https?://[^\s]+`、大文字・小文字を問わない）。
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| compile(r"(?i)https?://[^\s\x1C-\x1F]+"));

/// Python の `MASKED_LINK_REGEX`（隠しリンク `[文](https://…)`。括弧の中の URL だけを取る。URL の中の対になった
/// 括弧は 1 段まで。`<>` で囲んだものも読む）。
static MASKED_LINK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(concat!(
        r"(?i)\[[^\[\]]*\]\([\s\x1C-\x1F]*<?",
        r"(https?://(?:[^\s\x1C-\x1F()<>]|\([^\s\x1C-\x1F()<>]*\))+)",
        r">?[\s\x1C-\x1F]*\)",
    ))
});

/// Python の `INVITE_REGEX`（https:// の無い招待。大文字小文字は文字の組で書く〔Python と Rust で、大文字小文字を
/// 問わないときに英字に重ねる文字が食い違うので〕）。
static INVITE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(concat!(
        r"[Dd][Ii][Ss][Cc][Oo][Rr][Dd]",
        r"(?:\.[Gg][Gg]|(?:[Aa][Pp][Pp])?\.[Cc][Oo][Mm]/[Ii][Nn][Vv][Ii][Tt][Ee])",
        r"/[A-Za-z0-9-]+",
    ))
});

/// URL の末尾から、記号を 1 回ぶん落とす（[`normalize_url`] が、変わらなくなるまで繰り返す）。Python の
/// `_trim_once`。
///
/// 前後の `<>`・末尾の句読点を落とし、そのあと末尾の Discord の飾りの記号（`||` `~~` は 2 文字、`*` `_` `` ` `` は
/// 1 文字）か、URL の中の `(` `[` と対にならない `)` `]` を 1 つ落とす。
fn trim_once(u: &str) -> &str {
    let u = u
        .trim_matches(|c| c == '<' || c == '>')
        .trim_end_matches(['.', ',', '!', '?', ';', ':']);
    if u.ends_with("||") || u.ends_with("~~") {
        return &u[..u.len() - 2];
    }
    if u.ends_with(['*', '_', '`']) {
        return &u[..u.len() - 1];
    }
    if u.ends_with(')') && u.matches('(').count() < u.matches(')').count() {
        return &u[..u.len() - 1];
    }
    if u.ends_with(']') && u.matches('[').count() < u.matches(']').count() {
        return &u[..u.len() - 1];
    }
    u
}

/// 抜き出した URL の前後の記号を落とす。Python の `normalize_url`。
///
/// `<https://example.com>`（Discord のリンクを開かせない書き方）や、文の終わりの句読点、末尾の Discord の飾りの
/// 記号（ネタバレ・強調など）、URL の中の括弧と対にならない末尾の `)` `]` を落とす（S6）。句読点と組み合わさっても
/// 落ちきるよう、変わらなくなるまで繰り返す。
pub fn normalize_url(url: &str) -> String {
    let mut u = url.trim_matches(python_is_space);
    if u.starts_with('<') && u.ends_with('>') && u.len() >= 2 {
        u = u[1..u.len() - 1].trim_matches(python_is_space);
    }
    loop {
        let trimmed = trim_once(u);
        if trimmed == u {
            return u.to_string();
        }
        u = trimmed;
    }
}

/// `text` の `start..end`（バイト）を空白で塗る（長さは変えない。位置で並べ直すため）。Python の `_blank`。
fn blank(text: &mut String, start: usize, end: usize) {
    text.replace_range(start..end, &" ".repeat(end - start));
}

/// 本文から URL を重複なしで、出た順に抜き出す（落としたあとの形で重複を見る）。Python の `extract_links`。
///
/// 隠しリンク `[文](https://例)` は括弧の中の URL だけを取る（文の中は見ない）。https:// の無い招待
/// （`discord.gg/コード` など）は https:// を付けた形にする（https:// 付きの URL の中のものは拾い直さない。別の
/// ドメインの一部〔直前が英数字か `._-/@`〕は拾わない）。`www.` で始まるもの・ドメインらしい文字列は拾わない。
pub fn extract_links(text: &str) -> Vec<String> {
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut rest = text.to_string();
    for caps in MASKED_LINK_REGEX.captures_iter(text) {
        let (Some(whole), Some(url)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        found.push((whole.start(), url.as_str().to_string()));
        blank(&mut rest, whole.start(), whole.end());
    }
    let plain = rest.clone();
    for m in URL_REGEX.find_iter(&plain) {
        found.push((m.start(), m.as_str().to_string()));
        blank(&mut rest, m.start(), m.end());
    }
    for m in INVITE_REGEX.find_iter(&rest) {
        let glued = rest[..m.start()]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || "._-/@".contains(c));
        if !glued {
            found.push((m.start(), format!("https://{}", m.as_str())));
        }
    }
    found.sort_by_key(|(at, _)| *at);
    let mut links: Vec<String> = Vec::new();
    for (_, raw) in found {
        let u = normalize_url(&raw);
        if !u.is_empty() && !links.contains(&u) {
            links.push(u);
        }
    }
    links
}

/// 文字の向きを入れ替える制御文字（U+202A〜U+202E・U+2066〜U+2069）が入っているか。
/// Python の `UNICODE_TRICK_REGEX`（ファイル名や URL の見た目を偽るのに使われる）。
pub fn has_unicode_trick(text: &str) -> bool {
    text.chars()
        .any(|c| ('\u{202A}'..='\u{202E}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c))
}

/// 参加して 7 日未満のメンバーか。参加日時が分からなければ「新規ではない」（Python と同じ）。
///
/// Python の `(utcnow - joined_at).days`（日数は切り捨て。未来の参加日時なら負になり、新規に入る）。
pub fn is_new_member(joined_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    let Some(joined) = joined_at else {
        return false;
    };
    let seconds = (now - joined).num_seconds();
    seconds.div_euclid(86_400) < NEW_MEMBER_THRESHOLD_DAYS
}

/// アカウントを作った日時。ID（snowflake）から取る（serenity の `UserId::created_at`・discord.py の
/// `snowflake_time` と同じ計算。ミリ秒まで）。
pub fn account_created(user_id: u64) -> DateTime<Utc> {
    let ms = i64::try_from(user_id >> 22).unwrap_or(0) + DISCORD_EPOCH_MS;
    DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

/// アカウントを作ってから `days` 日未満か。Python の `is_new_account`（S5。日数の数え方は [`is_new_member`] と同じ）。
pub fn is_new_account(user_id: u64, now: DateTime<Utc>, days: i64) -> bool {
    let seconds = (now - account_created(user_id)).num_seconds();
    seconds.div_euclid(86_400) < days
}

/// VC の荒らしに数える「入って間もない人」か。Python の `is_fresh_joiner`（S4）。
///
/// サーバーに入って 24 時間未満か、アカウントを作って 7 日未満の人。参加日時が分からない人は「入って間もない人
/// ではない」（[`is_new_member`] と同じく無害側に倒す）。
pub fn is_fresh_joiner(
    joined_at: Option<DateTime<Utc>>,
    user_id: u64,
    now: DateTime<Utc>,
    config: &SecurityConfig,
) -> bool {
    let Some(joined) = joined_at else {
        return false;
    };
    let hours = config.raid.new_join_hours;
    let fresh = TimeDelta::try_hours(hours).unwrap_or(TimeDelta::MAX);
    now - joined < fresh || is_new_account(user_id, now, config.new_account_days)
}

/// serenity の時刻を chrono の時刻に（小数の秒まで）。
pub fn timestamp_utc(ts: Timestamp) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&ts.to_rfc3339()?)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Python の `_parse_id_list`: リストでなければ空、`int()` で読めない要素は捨てる。
pub(crate) fn id_list(value: Option<&Value>) -> Vec<i64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(log_channel::python_int).collect())
        .unwrap_or_default()
}

/// 検査を飛ばす理由（管理者・信頼ユーザー・バイパスロール）。飛ばさないなら `None`。Python の
/// `is_security_bypassed`。
///
/// 管理者（`is_admin`。オーナーも管理者）は、設定を読む前に見る（理由は `administrator`。S7）。
/// `roles` はサーバーにあるロールだけ（discord.py の `member.roles` と同じく @everyone を含む）。
pub fn bypass_reason(
    guild_settings: Option<&Value>,
    user_id: UserId,
    roles: &[RoleId],
    is_admin: bool,
) -> Option<&'static str> {
    if is_admin {
        return Some("administrator");
    }
    let get = |key: &str| guild_settings.and_then(|g| g.get(key));
    let as_i64 = |id: u64| i64::try_from(id).unwrap_or(-1);
    if id_list(get("trusted_user_ids")).contains(&as_i64(user_id.get())) {
        return Some("trusted_user");
    }
    let bypass = id_list(get("bypass_role_ids"));
    roles
        .iter()
        .any(|r| bypass.contains(&as_i64(r.get())))
        .then_some("bypass_role")
}

/// 検査を飛ばしたことを、ログファイル（security のカテゴリ）に 1 行書く。Python の `_log_bypass`（S7。ログ
/// チャンネルには出さない）。`route` は経路（メッセージか VC か）。
pub fn log_bypass(guild_id: u64, user_id: u64, reason: &str, route: &str) {
    info!(guild_id, user_id, "[SECURITY] 検査を飛ばしました（{reason}） 経路={route}");
}

/// Bot がそのサーバーで「メンバーをタイムアウト」の権限を持っているか（discord.py の
/// `guild.me.guild_permissions.moderate_members`）。Bot のメンバーがキャッシュに無ければ持っていない扱い
/// （いまどおり全ロールを外す側に倒す）。
pub fn bot_can_timeout(guild: &Guild, bot_id: UserId, now: DateTime<Utc>) -> bool {
    let Some(me) = guild.members.get(&bot_id) else {
        return false;
    };
    let timed_out = me
        .communication_disabled_until
        .and_then(timestamp_utc)
        .is_some_and(|until| until > now);
    can_moderate(
        guild.owner_id == bot_id,
        &me.roles,
        &guild.roles,
        guild.id,
        timed_out,
    )
}

/// discord.py の `guild_permissions.moderate_members` の決め方。オーナーと管理者は全部の権限。持っているロールと
/// @everyone の権限を合わせる。タイムアウト中なら（閲覧のほかは）無い。
pub fn can_moderate(
    is_owner: bool,
    roles: &[RoleId],
    guild_roles: &HashMap<RoleId, Role>,
    guild_id: GuildId,
    timed_out: bool,
) -> bool {
    if is_owner {
        return true;
    }
    let everyone = RoleId::new(guild_id.get());
    let permissions = roles
        .iter()
        .chain(std::iter::once(&everyone))
        .filter_map(|id| guild_roles.get(id))
        .fold(Permissions::empty(), |acc, role| acc | role.permissions);
    if permissions.contains(Permissions::ADMINISTRATOR) {
        return true;
    }
    !timed_out && permissions.contains(Permissions::MODERATE_MEMBERS)
}

/// 1 つの措置（ロールの剥奪・タイムアウト）を Discord に断られた理由。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StripFailure {
    /// 権限が足りなかった。
    Forbidden,
    /// ほかの失敗（Discord の誤りの文。ログにだけ残す）。
    Failed(String),
}

/// 剥がした結果。Python の `strip_roles` の戻り値（`StripResult`）。
///
/// どのロールを剥がせて、どれが残ったか（失敗したロールと、そのあと試さなかったロール）を持つ。ログチャンネルの
/// 報告に出す（rust-09 の (i)）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stripped {
    /// 剥がしたロール（剥がした順）。
    pub removed: Vec<RoleId>,
    /// 残ったロール（失敗したものと、その後ろ）。
    pub kept: Vec<RoleId>,
    /// 止まった理由（全部剥がせた・剥がすロールが無かったなら `None`）。
    pub failure: Option<StripFailure>,
}

/// ロールを 1 つずつ剥がし、失敗したらそこで止める。Python の `strip_roles` の流れ（discord.py の
/// `remove_roles`〔atomic〕と同じく 1 つずつ送り、失敗で止まる）。`remove` が 1 つを剥がす。
pub async fn strip_each<F, Fut>(roles: &[RoleId], mut remove: F) -> Stripped
where
    F: FnMut(RoleId) -> Fut,
    Fut: std::future::Future<Output = Result<(), StripFailure>>,
{
    let mut out = Stripped::default();
    for (i, role) in roles.iter().enumerate() {
        if let Err(failure) = remove(*role).await {
            out.kept = roles[i..].to_vec();
            out.failure = Some(failure);
            return out;
        }
        out.removed.push(*role);
    }
    out
}

/// @everyone 以外のロールを全部剥がす。Python の `strip_roles`（discord.py の `remove_roles` と同じく、
/// 1 つずつ外し、失敗したらそこで止まる）。
pub async fn strip_roles(
    http: &Http,
    guild_id: GuildId,
    user_id: UserId,
    roles: &[RoleId],
) -> Stripped {
    let removable = removable_roles(roles, guild_id);
    strip_each(&removable, |role| async move {
        remove_role(http, guild_id, user_id, role).await
    })
    .await
}

/// Discord が返した状態（HTTP の応答の失敗のときだけ）。
fn http_status(error: &serenity::Error) -> Option<StatusCode> {
    match error {
        serenity::Error::Http(HttpError::UnsuccessfulRequest(r)) => Some(r.status_code),
        _ => None,
    }
}

/// Discord が「もう無い」（404）と答えたか（消そうとした投稿が既に消えていた、など）。
pub fn is_not_found(error: &serenity::Error) -> bool {
    http_status(error) == Some(StatusCode::NOT_FOUND)
}

/// ロールを 1 つ剥がす（理由は「セキュリティ違反」）。権限不足（403）は [`StripFailure::Forbidden`]。
pub async fn remove_role(
    http: &Http,
    guild_id: GuildId,
    user_id: UserId,
    role: RoleId,
) -> Result<(), StripFailure> {
    let Err(e) = http
        .remove_member_role(guild_id, user_id, role, Some(ENFORCEMENT_REASON))
        .await
    else {
        return Ok(());
    };
    if http_status(&e) == Some(StatusCode::FORBIDDEN) {
        return Err(StripFailure::Forbidden);
    }
    tracing::error!("[SECURITY] strip roles failed: {e}");
    Err(StripFailure::Failed(e.to_string()))
}

/// メンバーを `seconds` 秒タイムアウトする（理由は「セキュリティ違反」）。Python の `timeout_member`（discord.py の
/// `member.timeout`。`PATCH /guilds/{g}/members/{u}` の `communication_disabled_until`）。
///
/// 断られたとき（相手のロールが Bot より上など）は失敗として返す（ロールを外すことは試さない。同じ理由で失敗する）。
/// 権限不足（403）は [`StripFailure::Forbidden`]。
pub async fn timeout_member(
    http: &Http,
    guild_id: GuildId,
    user_id: UserId,
    seconds: i64,
) -> Result<(), StripFailure> {
    let until = Utc::now() + TimeDelta::seconds(seconds);
    let mut body = serde_json::Map::new();
    let until = until.to_rfc3339_opts(SecondsFormat::Micros, false);
    body.insert("communication_disabled_until".into(), Value::String(until));
    let Err(e) = http
        .edit_member(guild_id, user_id, &body, Some(ENFORCEMENT_REASON))
        .await
    else {
        return Ok(());
    };
    if http_status(&e) == Some(StatusCode::FORBIDDEN) {
        return Err(StripFailure::Forbidden);
    }
    tracing::error!("[SECURITY] timeout failed: {e}");
    Err(StripFailure::Failed(e.to_string()))
}

/// タイムアウトの結果。Python の `TimeoutResult`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedOut {
    /// かけた（かけようとした）長さ（秒）。
    pub seconds: i64,
    /// 断られた理由（かけられたなら `None`）。
    pub failure: Option<StripFailure>,
}

/// 取った措置の種類。Python の `Enforcement.action`（Rust にはバイパスの判定の失敗が無いので、見送りは無い）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    /// 措置なし。
    #[default]
    None,
    /// 危険で措置した（24 時間のタイムアウト。権限が無ければロールを外す）。
    Danger,
    /// スパムだけで措置した（10 分のタイムアウト。権限が無ければ消すだけ）。
    Spam,
}

/// 取った措置。報告の見出し・色・項目は、これで決める（S8）。Python の `Enforcement`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enforcement {
    /// 種類。
    pub action: Action,
    /// 消した投稿（既に消えていたものも含む）。
    pub deleted: usize,
    /// 消せなかった投稿。
    pub delete_failed: usize,
    /// タイムアウトを試した結果（タイムアウトの権限が無ければ `None`）。
    pub timeout: Option<TimedOut>,
    /// ロールを外した結果（危険で、タイムアウトの権限が無いサーバー）。
    pub stripped: Option<Stripped>,
    /// 危険だが、VC の荒らしの経路で措置済みなので、人への措置はしなかった（二重に措置しない。S4）。
    pub vc_done: bool,
}

/// 危険なときの、人への措置（S1）。タイムアウトの権限があれば `seconds` 秒のタイムアウト、無ければ全ロールを外す。
/// Python の `_punish`（タイムアウトが断られても、ロールを外すことは試さない）。
pub async fn punish(
    http: &Http,
    guild_id: GuildId,
    user_id: UserId,
    roles: &[RoleId],
    can_timeout: bool,
    seconds: i64,
) -> Enforcement {
    let mut out = Enforcement {
        action: Action::Danger,
        ..Enforcement::default()
    };
    if can_timeout {
        let sent = timeout_member(http, guild_id, user_id, seconds).await;
        out.timeout = Some(TimedOut {
            seconds,
            failure: sent.err(),
        });
    } else {
        out.stripped = Some(strip_roles(http, guild_id, user_id, roles).await);
    }
    out
}

/// VC の荒らしで数えた 1 人（措置して報告する相手）。
#[derive(Clone, Debug)]
pub struct RaidTarget {
    /// その人。
    pub user_id: UserId,
    /// 持っているロール（サーバーにあるものだけ、低い順。@everyone は含めない）。
    pub roles: Vec<RoleId>,
    /// ログの作者。
    pub author: Author,
}

/// VC の荒らしの数に入った人に、最初に入った順に 1 人ずつ措置して報告する。Python の
/// `handle_security_for_voice_join` の後半（`_enforce_vc_raid`）。
///
/// 措置は 24 時間のタイムアウト（Bot に権限が無ければ全ロールを外す）。報告は 1 人ずつ「VCレイド検出」（チャンネルと、
/// タイムアウト・剥がした結果）。
pub async fn act_on_vc_raid(
    sink: &LogSink<'_>,
    guild_id: GuildId,
    channel_id: u64,
    targets: &[RaidTarget],
    can_timeout: bool,
    seconds: i64,
) {
    for target in targets {
        let user_id = target.user_id;
        let roles = &target.roles;
        let done = punish(sink.http, guild_id, user_id, roles, can_timeout, seconds).await;
        warn!(%guild_id, %user_id, ?done, "[SECURITY] VCレイド検出");
        let fields = vc_raid_fields(channel_id, &done);
        let sent = log_channel::log_action(
            sink,
            guild_id,
            Level::Error,
            "VCレイド検出",
            Some(&target.author),
            &fields,
            Some(RED),
        )
        .await;
        if let Err(e) = sent {
            warn!(%guild_id, "VCレイドのログを送れませんでした: {e}");
        }
    }
}

/// VC の荒らしを見つけたときのログの項目。Python の `_enforce_vc_raid` の
/// `{"チャンネル": channel.mention, **enforcement_fields(...)}`（タイムアウトか、剥がした結果）。
pub fn vc_raid_fields(channel_id: u64, enforcement: &Enforcement) -> Vec<(String, String)> {
    let mut fields = vec![("チャンネル".to_string(), format!("<#{channel_id}>"))];
    fields.extend(enforcement_fields(enforcement));
    fields
}

/// 1 つの項目に入れる文字数（Discord の上限）。
const FIELD_VALUE_LIMIT: usize = 1024;

/// 剥がした結果を、ログチャンネルの報告に足す項目にする。Python の `strip_fields`。
///
/// 「剥がしたロール」は必ず出す（無ければ「なし」）。残ったロールがあれば「剥がせなかったロール（権限不足）」か
/// 「剥がせなかったロール（失敗）」を足す（失敗の文は項目に出さず、ログにだけ残す）。ロールはメンションで並べ、
/// 1 つの項目の上限（1024 文字）に収める（はみ出す分は「…他N個」）。
pub fn strip_fields(stripped: &Stripped) -> Vec<(String, String)> {
    let mentions = |roles: &[RoleId]| {
        let items: Vec<String> = roles.iter().map(|r| format!("<@&{}>", r.get())).collect();
        cap_list_for_message(&items, FIELD_VALUE_LIMIT, "個", " ", None, "")
    };
    let removed = if stripped.removed.is_empty() {
        "なし".to_string()
    } else {
        mentions(&stripped.removed)
    };
    let mut fields = vec![("剥がしたロール".to_string(), removed)];
    if !stripped.kept.is_empty() {
        let why = match stripped.failure {
            Some(StripFailure::Forbidden) => "権限不足",
            _ => "失敗",
        };
        fields.push((
            format!("剥がせなかったロール（{why}）"),
            mentions(&stripped.kept),
        ));
    }
    fields
}

/// タイムアウトの長さの書き方（86400 → 「24 時間」、600 → 「10 分」、割り切れなければ秒）。Python の
/// `duration_text`。
pub fn duration_text(seconds: i64) -> String {
    if seconds % 3600 == 0 {
        format!("{} 時間", seconds / 3600)
    } else if seconds % 60 == 0 {
        format!("{} 分", seconds / 60)
    } else {
        format!("{seconds} 秒")
    }
}

/// タイムアウトの結果を、報告に足す項目にする。Python の `timeout_fields`（[`strip_fields`] と同じ作法）。
pub fn timeout_fields(timed_out: &TimedOut) -> Vec<(String, String)> {
    let length = duration_text(timed_out.seconds);
    let name = match timed_out.failure {
        None => "タイムアウト".to_string(),
        Some(StripFailure::Forbidden) => "タイムアウトできなかった（権限不足）".to_string(),
        Some(StripFailure::Failed(_)) => "タイムアウトできなかった（失敗）".to_string(),
    };
    vec![(name, length)]
}

/// 取った措置を、報告に足す項目にする（消した投稿・タイムアウト・剥がしたロール）。Python の
/// `enforcement_fields`。
pub fn enforcement_fields(enforcement: &Enforcement) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    if enforcement.deleted > 0 || enforcement.delete_failed > 0 {
        let deleted = format!("{}件", enforcement.deleted);
        fields.push(("消した投稿".to_string(), deleted));
        if enforcement.delete_failed > 0 {
            let failed = format!("{}件", enforcement.delete_failed);
            fields.push(("消せなかった投稿".to_string(), failed));
        }
    }
    if let Some(timed_out) = &enforcement.timeout {
        fields.extend(timeout_fields(timed_out));
    }
    if let Some(stripped) = &enforcement.stripped {
        fields.extend(strip_fields(stripped));
    }
    fields
}

/// 措置の一部が失敗したか（消せなかった投稿がある・タイムアウトが断られた・外せないロールが残った）。
fn partly_failed(enforcement: &Enforcement) -> bool {
    let refused = matches!(&enforcement.timeout, Some(t) if t.failure.is_some());
    let kept = matches!(&enforcement.stripped, Some(s) if s.failure.is_some());
    enforcement.delete_failed > 0 || refused || kept
}

/// 措置しなかったときに「注意の材料あり」（黄）にする印（AI の SUSPICIOUS・UNKNOWN も入る。S8）。
const CAUTION: [&str; 3] = ["VT_SUSPICIOUS", "TOO_MANY_LINKS", "UNICODE_TRICK"];

/// 注意の材料（VirusTotal の疑わしい・AI の SUSPICIOUS/UNKNOWN・リンク過多・ユニコードトリック）があるか。
/// Python の `has_caution`（措置しなかったときの黄の見出し）。
pub fn has_caution(reasons: &[String], gpt_result: &str) -> bool {
    let flagged = reasons.iter().any(|r| CAUTION.contains(&r.as_str()));
    matches!(gpt_result, "SUSPICIOUS" | "UNKNOWN") || flagged
}

/// 報告の見出しと色を、実際に取った措置から決める。Python の `outcome_heading`（S8）。
///
/// 危険で措置した → 赤「消して 24 時間のタイムアウト」（ロールを外したときは「消してロールを外した」）。
/// スパムだけで措置した → 橙「消して 10 分のタイムアウト」（権限が無いときは「消した」）。措置なしで注意の材料
/// あり → 黄「記録だけ（注意の材料あり）」。何も無ければ緑。措置の一部が失敗したら「（一部失敗）」を足す。
pub fn heading(enforcement: &Enforcement, caution: bool) -> (String, u32) {
    let colour = match enforcement.action {
        Action::None if caution => return ("記録だけ（注意の材料あり）".into(), GOLD),
        Action::None => return ("記録だけ（問題なし）".into(), GREEN),
        Action::Danger => RED,
        Action::Spam => ORANGE,
    };
    let mut title = if let Some(timed_out) = &enforcement.timeout {
        format!("消して {}のタイムアウト", duration_text(timed_out.seconds))
    } else if enforcement.stripped.is_some() {
        "消してロールを外した".to_string()
    } else if enforcement.vc_done {
        "消した（VC の荒らしで措置済み）".to_string()
    } else {
        "消した".to_string()
    };
    if partly_failed(enforcement) {
        title.push_str("（一部失敗）");
    }
    (title, colour)
}

/// 剥がすロール（@everyone は剥がせないので除く）。
pub fn removable_roles(roles: &[RoleId], guild_id: GuildId) -> Vec<RoleId> {
    roles
        .iter()
        .copied()
        .filter(|r| r.get() != guild_id.get())
        .collect()
}

/// 安全。
pub const SAFE_ICON: &str = "[SAFE]";
/// 注意。
pub const WARN_ICON: &str = "[WARN]";
/// 危険。
pub const ALERT_ICON: &str = "[ALERT]";

/// 理由の種類ごとの印。知らない種類は `[INFO]`。Python の `reason_icon`。
pub fn reason_icon(reason: &str) -> &'static str {
    match reason.split(':').next().unwrap_or("") {
        "SPAM" => "[SPAM]",
        "TOO_MANY_LINKS" => "[LINKS]",
        "UNICODE_TRICK" => "[UNICODE]",
        "NEW_MEMBER" => "[NEW]",
        "NEW_ACCOUNT" => "[ACCOUNT]",
        "GPT" => "[GPT]",
        "VT_DANGEROUS" | "VT_SUSPICIOUS" => "[VT]",
        "VC_RAID" => "[VC]",
        _ => "[INFO]",
    }
}

/// VirusTotal の結果の印。走査できなかった（error・skip）は安全ではなく注意。Python の `vt_icon`。
pub fn vt_icon(malicious: i64, suspicious: i64, status: Option<&str>) -> &'static str {
    if matches!(status, Some("error" | "skip")) {
        WARN_ICON
    } else if malicious > 0 {
        ALERT_ICON
    } else if suspicious > 0 {
        WARN_ICON
    } else {
        SAFE_ICON
    }
}

/// GPT の判定の印。判定できなかった（UNKNOWN）は安全ではなく注意。Python の `gpt_icon`。
pub fn gpt_icon(result: &str) -> &'static str {
    match result {
        "DANGEROUS" => ALERT_ICON,
        "SUSPICIOUS" | "UNKNOWN" => WARN_ICON,
        _ => SAFE_ICON,
    }
}

/// 進み具合の棒（`[###-------] 3/10`）。Python の `build_progress_bar`。
pub fn progress_bar(current: usize, total: usize, length: usize) -> String {
    let filled = (length * current)
        .checked_div(total)
        .unwrap_or(0)
        .min(length);
    format!(
        "[{}{}] {current}/{total}",
        "#".repeat(filled),
        "-".repeat(length - filled)
    )
}

/// VirusTotal の 1 件の結果（Embed に出すもの）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    /// 種類（`url`・`file` など）。
    pub kind: String,
    /// 状態（`ok`・`error`・`skip` など）。
    pub status: String,
    /// 危険と判定したエンジンの数。
    pub malicious: i64,
    /// 疑わしいと判定したエンジンの数。
    pub suspicious: i64,
}

/// Embed の説明の上限（Discord）。
pub const EMBED_DESCRIPTION_LIMIT: usize = 4096;
/// Embed の項目の数の上限。
pub const EMBED_FIELD_COUNT_LIMIT: usize = 25;
/// Embed 全体（題・説明・項目の名前と値・足元）の文字数の上限。
pub const EMBED_TOTAL_LIMIT: usize = 6000;

/// 印の重さ（危険 > 注意 > 安全）。畳んだ走査の結果の印に使う。
fn icon_weight(icon: &str) -> u8 {
    match icon {
        ALERT_ICON => 2,
        WARN_ICON => 1,
        _ => 0,
    }
}

/// 走査の結果を 1 件 1 項目にする。`room` 個を超えるなら、最後の 1 項目に残りを畳む。Python の `_target_fields`。
///
/// 畳んだ項目は「{印} ターゲット {最初}〜{最後}」と「…他N件」。印は隠れた結果の中でいちばん重いもの。
fn target_fields(scans: &[ScanResult], room: usize) -> Vec<(String, String)> {
    let icon = |r: &ScanResult| vt_icon(r.malicious, r.suspicious, Some(&r.status));
    let mut fields: Vec<(String, String)> = scans
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                format!("{} ターゲット {} ({})", icon(r), i + 1, r.kind),
                format!(
                    "Status: `{}` | Malicious: `{}` | Suspicious: `{}`",
                    r.status, r.malicious, r.suspicious
                ),
            )
        })
        .collect();
    if fields.len() <= room {
        return fields;
    }
    let shown = room.saturating_sub(1);
    let hidden = &scans[shown..];
    let worst = hidden
        .iter()
        .map(icon)
        .max_by_key(|i| icon_weight(i))
        .unwrap_or(SAFE_ICON);
    fields.truncate(shown);
    fields.push((
        format!("{worst} ターゲット {}〜{}", shown + 1, scans.len()),
        format!("…他{}件", hidden.len()),
    ));
    fields
}

/// 検査の結果の Embed。Python の `build_final_embed`（時刻は渡す）。
///
/// 題と色は、実際に取った措置から決める（[`heading`]。S8）。判定の材料（VirusTotal・AI・スパム・新規・新しい
/// アカウント）は、これまでどおり項目に並べる。
///
/// Discord の上限（項目 25 個・説明 4096 文字・全体 6000 文字）に収める（rust-09 の (c)）。走査の結果の項目は、
/// GPT 判定と判定理由の項目を残して入るだけ並べ、残りを最後の 1 項目に「…他N件」で畳む。説明（ログの行）は、
/// 題・項目・足元を引いた残り（4096 文字まで）に収め、はみ出す行を「…他N行」で畳む。文字はコードポイントで
/// 数える（Python の `len`）。
pub fn final_embed(
    scans: &[ScanResult],
    gpt_result: &str,
    reasons: &[String],
    logs: &[String],
    enforcement: &Enforcement,
    now: DateTime<chrono::FixedOffset>,
) -> CreateEmbed {
    let (title, colour) = heading(enforcement, has_caution(reasons, gpt_result));
    let mut tail = vec![(
        format!("{} GPT判定", gpt_icon(gpt_result)),
        format!("結果: `{gpt_result}`"),
    )];
    if !reasons.is_empty() {
        let joined = reasons
            .iter()
            .map(|r| format!("{}{r}", reason_icon(r)))
            .collect::<Vec<_>>()
            .join(" / ");
        tail.push(("判定理由".to_string(), joined));
    }
    let mut fields = target_fields(scans, EMBED_FIELD_COUNT_LIMIT - tail.len());
    fields.extend(tail);
    let footer = format!("実行時間: {}", now.format("%Y-%m-%d %H:%M:%S"));

    // 説明に使えるのは、題・項目・足元を引いた残り（説明そのものの上限 4096 文字まで）。
    let len = |s: &str| s.chars().count();
    let used = len(&title)
        + len(&footer)
        + fields
            .iter()
            .map(|(name, value)| len(name) + len(value))
            .sum::<usize>();
    let budget = EMBED_DESCRIPTION_LIMIT.min(EMBED_TOTAL_LIMIT.saturating_sub(used));
    let description = cap_list_for_message(logs, budget, "行", "\n", None, "");

    let mut embed = CreateEmbed::new().title(title).colour(colour);
    // 空の説明は付けない（discord.py も空なら付けない）。
    if !description.is_empty() {
        embed = embed.description(description);
    }
    for (name, value) in fields {
        embed = embed.field(name, value, false);
    }
    embed.footer(CreateEmbedFooter::new(footer))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    /// 既定は Python と同じ（危険 24 時間・スパム 10 分・60 秒に 3 回・10 秒に 8 回・20 秒に 5 人・24 時間・7 日）。
    /// 下限・上限で丸める（タイムアウトは 60 秒〜28 日、回数は 2 から、秒・時間・日は 1 から）。
    #[test]
    fn the_settings_match_python() {
        let defaults = SecurityConfig::from_env(&env(&[]));
        assert_eq!(defaults, SecurityConfig::default());
        assert_eq!(
            (defaults.timeout_danger_seconds, defaults.timeout_spam_seconds),
            (86_400, 600)
        );
        assert_eq!(defaults.spam, SpamRules::default());
        assert_eq!(
            (defaults.spam.repeat_count, defaults.spam.repeat_window),
            (3, 60)
        );
        assert_eq!(
            (defaults.spam.flood_count, defaults.spam.flood_window),
            (8, 10)
        );
        assert_eq!((defaults.raid.window, defaults.raid.threshold), (20, 5));
        assert_eq!(
            (defaults.raid.new_join_hours, defaults.new_account_days),
            (24, 7)
        );
        let low = SecurityConfig::from_env(&env(&[
            ("SECURITY_TIMEOUT_DANGER_SECONDS", "1"),
            ("SECURITY_TIMEOUT_SPAM_SECONDS", "99999999"),
            ("SPAM_REPEAT_COUNT", "1"),
            ("SPAM_FLOOD_WINDOW_SECONDS", "0"),
            ("VC_RAID_THRESHOLD", "0"),
            ("NEW_ACCOUNT_THRESHOLD_DAYS", "-3"),
        ]));
        assert_eq!(low.timeout_danger_seconds, 60);
        assert_eq!(low.timeout_spam_seconds, TIMEOUT_MAX_SECONDS);
        assert_eq!(low.spam.repeat_count, 2);
        assert_eq!(low.spam.flood_window, 1);
        assert_eq!(low.raid.threshold, 2);
        assert_eq!(low.new_account_days, 1);
    }

    fn spam_post(content: &str, channel: u64, message: u64) -> SpamInput<'_> {
        SpamInput {
            guild_id: 1,
            user_id: 2,
            channel_id: channel,
            message_id: message,
            content,
            attachments: &[],
        }
    }

    /// 繰り返し: 同じ内容が 60 秒に 3 回で当たり、数えた投稿を記録の順に返す。一度返した投稿は二度返さない。
    #[test]
    fn a_repeat_is_three_same_posts_in_a_minute() {
        let d = SpamDetector::default();
        assert!(!d.check(&spam_post("買って", 10, 1), 100.0).is_spam());
        assert!(!d.check(&spam_post("買って", 11, 2), 130.0).is_spam());
        let third = d.check(&spam_post("買って", 12, 3), 159.0);
        assert!(third.repeat && !third.flood);
        assert_eq!((third.repeat_count, third.repeat_channels), (3, 3));
        assert_eq!(third.posts, [(10, 1), (11, 2), (12, 3)]);
        assert_eq!((third.counted, third.display_count()), (3, 3));
        // 4 回目は、回数には数え続けるが、前の 3 件は返さない（消し直さない）。
        let fourth = d.check(&spam_post("買って", 10, 4), 159.5);
        assert_eq!(fourth.repeat_count, 4);
        assert_eq!(fourth.posts, [(10, 4)]);
        // 60 秒ちょうど前のものは数えない（now - t < 60）。
        let d = SpamDetector::default();
        d.check(&spam_post("x", 10, 1), 0.0);
        d.check(&spam_post("x", 10, 2), 1.0);
        let later = d.check(&spam_post("x", 10, 3), 60.0);
        assert_eq!(later.repeat_count, 2);
        assert!(!later.is_spam());
    }

    /// 量: 内容が違っても 10 秒に 8 回で当たる。いちばん短い間隔は量の窓の中で見る。
    #[test]
    fn a_flood_is_eight_posts_in_ten_seconds() {
        let d = SpamDetector::default();
        for i in 0..7u32 {
            let text = format!("文{i}");
            let c = d.check(&spam_post(&text, 10, u64::from(i)), 100.0 + f64::from(i));
            assert!(!c.is_spam(), "{i}");
        }
        let eighth = d.check(&spam_post("最後", 10, 7), 106.5);
        assert!(eighth.flood && !eighth.repeat);
        assert_eq!(eighth.flood_count, 8);
        assert_eq!(eighth.posts.len(), 8);
        assert_eq!(eighth.min_interval, 0.5);
        // 10 秒ちょうど前のものは数えない。
        let d = SpamDetector::default();
        d.check(&spam_post("a", 10, 1), 0.0);
        let c = d.check(&spam_post("b", 10, 2), 10.0);
        assert_eq!(c.flood_count, 1);
        assert!(c.min_interval.is_infinite());
        assert_eq!(c.display_count(), 1);
    }

    /// 本文も添付も空の投稿は、繰り返しには数えず、量にだけ数える。ほかの人・サーバーは別に数える。
    #[test]
    fn empty_posts_and_other_people_are_counted_apart() {
        let d = SpamDetector::default();
        for i in 0..3 {
            d.check(&spam_post("", 10, i), i as f64);
        }
        let c = d.check(&spam_post("", 10, 9), 3.0);
        assert_eq!((c.repeat_count, c.flood_count), (0, 4));
        let other = SpamInput {
            user_id: 3,
            ..spam_post("", 10, 10)
        };
        assert_eq!(d.check(&other, 3.0).flood_count, 1);
        let other_guild = SpamInput {
            guild_id: 9,
            ..spam_post("", 10, 11)
        };
        assert_eq!(d.check(&other_guild, 3.0).flood_count, 1);
    }

    /// 同じ内容の比べ方: NFKC → casefold → 空白の並びを 1 つに。添付は（ファイル名, 大きさ）。
    #[test]
    fn the_same_content_is_compared_like_python() {
        let key = |s: &str| content_key(s, &[]);
        assert_eq!(key("ＦＲＥＥ　　ＮＩＴＲＯ"), key("  free\tnitro "));
        assert_eq!(key("STRASSE"), key("straße"), "ß は casefold で ss");
        assert_eq!(key("ΣΑΣ"), key("σας"), "語の終わりの ς も σ");
        assert_ne!(key("free nitro"), key("free nitro!"));
        assert_ne!(key("free nitro"), key("free nitr0"));
        assert_eq!(key(" \u{1F} "), None, "Python の空白（U+001F）だけなら空");
        let file = |name: &str, size: u64| vec![(name.to_string(), size)];
        assert_eq!(
            content_key("", &file("a.png", 10)),
            content_key("", &file("a.png", 10))
        );
        assert_ne!(
            content_key("", &file("a.png", 10)),
            content_key("", &file("a.png", 11))
        );
        assert_ne!(content_key("x", &file("a.png", 10)), key("x"));
    }

    /// casefold の表は Python 3.13 の答えどおり（lower と違うものだけを表から引く）。
    #[test]
    fn casefold_follows_python() {
        assert!(casefold_table().len() > 250);
        assert_eq!(casefold("Straße ẞ"), "strasse ss");
        assert_eq!(casefold("ΣΑΣ ς"), "σασ σ");
        assert_eq!(casefold("\u{130}"), "i\u{307}");
        assert_eq!(
            casefold("\u{13A0}\u{AB70}"),
            "\u{13A0}\u{13A0}",
            "チェロキーは大文字へ"
        );
        assert_eq!(casefold("\u{FB03}"), "ffi");
        assert_eq!(casefold("\u{1F88}"), "\u{1F00}\u{3B9}");
        assert_eq!(casefold("\u{212A}ABC"), "kabc");
    }

    /// 入って間もない人が 20 秒に 5 人で荒らし。名前は見ず、同じ人は何度入り直しても 1 人。全員を入った順に返す。
    #[test]
    fn a_raid_is_five_fresh_people_in_twenty_seconds() {
        let r = RaidDetector::default();
        for _ in 0..6 {
            assert!(r.check(7, 100, 0.0).is_empty(), "入り直しを数えた");
        }
        for (i, user) in [101, 102, 103].iter().enumerate() {
            assert!(r.check(7, *user, 1.0 + i as f64).is_empty());
        }
        assert_eq!(r.check(7, 104, 5.0), [100, 101, 102, 103, 104]);
        // 同じ窓の中で後から入った人にも措置する。同じ人には二度措置しない。
        assert_eq!(r.check(7, 105, 6.0), [105]);
        assert!(r.check(7, 105, 6.5).is_empty());
        assert!(r.check(7, 100, 7.0).is_empty());
        // 別のチャンネルは別に数える。
        assert!(r.check(8, 106, 7.0).is_empty());
        // 20 秒ちょうど前の参加は数えない。
        let r = RaidDetector::default();
        for user in 0..4 {
            r.check(7, user, 0.0);
        }
        assert!(r.check(7, 9, 20.0).is_empty());
        // 20 秒の少し内側なら数える。
        let r = RaidDetector::default();
        for user in 0..4 {
            r.check(7, user, 0.0);
        }
        assert_eq!(r.check(7, 9, 19.9).len(), 5);
    }

    /// 記録を足さずに見るだけ（発言は数えない）。数に入った人だけが荒らし。措置済みは措置してから 20 秒覚える。
    #[test]
    fn peeking_sees_only_counted_people() {
        let r = RaidDetector::default();
        // 記録の無いチャンネル。
        assert_eq!(r.peek(7, 1, 0.0), RaidStatus::NotCounted);
        for user in 1..5 {
            r.check(7, user, user as f64);
        }
        // 4 人は荒らしでない（何度見ても記録は増えない）。
        for _ in 0..10 {
            assert_eq!(r.peek(7, 1, 4.0), RaidStatus::NotCounted);
        }
        assert_eq!(r.check(7, 5, 5.0).len(), 5);
        assert_eq!(r.peek(7, 1, 5.0), RaidStatus::Counted { enforced: true });
        // 数に入っていない人と、別のチャンネル。
        assert_eq!(r.peek(7, 77, 5.0), RaidStatus::NotCounted);
        assert_eq!(r.peek(8, 1, 5.0), RaidStatus::NotCounted);
        // 1 秒の参加は 21 秒で外れ、4 人になる。
        assert_eq!(r.peek(7, 2, 21.0), RaidStatus::NotCounted);
        assert_eq!(r.peek(7, 2, 20.9), RaidStatus::Counted { enforced: true });
    }

    /// 入って間もない人: 入って 24 時間未満か、アカウントを作って 7 日未満。参加日時が無ければ数えない。
    #[test]
    fn fresh_joiners_are_new_members_of_a_day_or_new_accounts() {
        let now: DateTime<Utc> = "2026-11-27T00:00:00Z".parse().unwrap();
        let config = SecurityConfig::default();
        let at = |s: &str| Some(s.parse::<DateTime<Utc>>().unwrap());
        let old_user = 80_351_110_224_678_912;
        assert!(is_fresh_joiner(at("2026-11-26T00:00:01Z"), old_user, now, &config));
        assert!(!is_fresh_joiner(at("2026-11-26T00:00:00Z"), old_user, now, &config));
        let fresh_account = snowflake("2026-11-24T00:00:00Z");
        assert!(is_fresh_joiner(at("2026-01-01T00:00:00Z"), fresh_account, now, &config));
        assert!(!is_fresh_joiner(None, fresh_account, now, &config));
    }

    fn snowflake(at: &str) -> u64 {
        let ms = at.parse::<DateTime<Utc>>().unwrap().timestamp_millis();
        u64::try_from(ms - DISCORD_EPOCH_MS).unwrap() << 22
    }

    /// アカウントの作成日は ID（snowflake）から。7 日未満が新しいアカウント（日数は切り捨て）。
    #[test]
    fn new_accounts_are_read_from_the_id() {
        let now: DateTime<Utc> = "2026-11-27T00:00:00Z".parse().unwrap();
        let id = snowflake("2026-11-20T00:00:00.250Z");
        assert_eq!(
            account_created(id).to_rfc3339(),
            "2026-11-20T00:00:00.250+00:00"
        );
        assert!(is_new_account(id, now, 7));
        assert!(!is_new_account(snowflake("2026-11-20T00:00:00Z"), now, 7));
        assert!(!is_new_account(80_351_110_224_678_912, now, 7));
    }

    /// URL の前後の記号を落とし、重複なしで抜き出すこと。
    #[test]
    fn links_are_normalised_and_deduplicated() {
        assert_eq!(normalize_url("<https://a.example>"), "https://a.example");
        assert_eq!(normalize_url("https://a.example/x."), "https://a.example/x");
        assert_eq!(
            normalize_url("https://a.example/?q=1!?"),
            "https://a.example/?q=1"
        );
        assert_eq!(normalize_url("<<https://a.example>>"), "https://a.example");
        let text = "見て <https://a.example> と https://a.example. と HTTP://B.example/x、https://c.example";
        assert_eq!(
            extract_links(text),
            ["https://a.example", "HTTP://B.example/x、https://c.example"]
        );
    }

    /// 隠しリンクは括弧の中の URL だけ。対にならない ) ] と Discord の飾りの記号を落とす（S6）。
    #[test]
    fn discord_markup_is_read() {
        assert_eq!(
            extract_links("見て [公式](https://masked.example/p) だよ"),
            ["https://masked.example/p"]
        );
        assert_eq!(
            extract_links("[https://shown.example](https://hidden.example/x)"),
            ["https://hidden.example/x"]
        );
        assert_eq!(
            extract_links("[t](<https://angle.example/a>)"),
            ["https://angle.example/a"]
        );
        let wiki = "https://ja.wikipedia.org/wiki/Y_(Z)";
        assert_eq!(extract_links(&format!("[w]({wiki})")), [wiki]);
        let kept = "https://ja.wikipedia.org/wiki/X_(曖昧さ回避)";
        assert_eq!(normalize_url(kept), kept);
        assert_eq!(normalize_url("https://a.ex/(x))"), "https://a.ex/(x)");
        assert_eq!(normalize_url("https://b.ex/b]"), "https://b.ex/b");
        for raw in [
            "https://a.example/x||",
            "https://a.example/x**",
            "https://a.example/x__",
            "https://a.example/x~~",
            "https://a.example/x*",
            "https://a.example/x`",
            "https://a.example/x||.",
            "https://a.example/x**!?",
            "https://a.example/x).",
            "https://a.example/x>.",
        ] {
            assert_eq!(normalize_url(raw), "https://a.example/x", "{raw}");
        }
        assert_eq!(normalize_url("https://a.ex/x~"), "https://a.ex/x~");
        // Python の空白（U+001F）で切る。
        assert_eq!(
            extract_links("https://s.example/a\u{1F}https://s.example/b"),
            ["https://s.example/a", "https://s.example/b"]
        );
    }

    /// 招待は https:// が無くても拾い、https:// を付ける。https:// 付きと重なったら 1 つ。別の名前の一部は拾わない。
    #[test]
    fn invites_without_a_scheme_are_picked_once() {
        let text = "discord.gg/AbC123 と DISCORD.COM/invite/xyz と discordapp.com/INVITE/q-1 と \
                    https://discord.gg/AbC123";
        assert_eq!(
            extract_links(text),
            [
                "https://discord.gg/AbC123",
                "https://DISCORD.COM/invite/xyz",
                "https://discordapp.com/INVITE/q-1"
            ]
        );
        assert_eq!(
            extract_links("http://discord.gg/abc"),
            ["http://discord.gg/abc"]
        );
        assert_eq!(
            extract_links("[discord.gg/fake](https://real.example/x)"),
            ["https://real.example/x"]
        );
        let glued = "evil-discord.gg/abc mydiscord.gg/x example.com/path 見てdiscord.gg/ok";
        assert_eq!(extract_links(glued), ["https://discord.gg/ok"]);
        assert!(extract_links("www.example.com example.com/path").is_empty());
        let wide = "ｈｔｔｐｓ：／／ｆｕｌｌ．ｅｘａｍｐｌｅ と https://日本語.example/パス。";
        assert_eq!(extract_links(wide), ["https://日本語.example/パス。"]);
    }

    /// 向きを入れ替える制御文字を見つけること。
    #[test]
    fn unicode_tricks_are_found() {
        assert!(has_unicode_trick("file\u{202E}gnp.exe"));
        assert!(has_unicode_trick("a\u{2066}b"));
        // 範囲の両端も見つけること（U+202A〜U+202E・U+2066〜U+2069）。
        for c in ['\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}'] {
            assert!(has_unicode_trick(&c.to_string()), "{:X}", c as u32);
        }
        assert!(!has_unicode_trick("ふつうの文"));
        // 範囲のすぐ外は見つけないこと。
        for c in ['\u{2029}', '\u{202F}', '\u{2065}', '\u{206A}'] {
            assert!(!has_unicode_trick(&c.to_string()), "{:X}", c as u32);
        }
    }

    /// 7 日未満は新規。日数は切り捨て。参加日時が無ければ新規ではない。
    #[test]
    fn new_members_joined_within_seven_days() {
        let now: DateTime<Utc> = "2026-11-27T00:00:00Z".parse().unwrap();
        let at = |s: &str| Some(s.parse::<DateTime<Utc>>().unwrap());
        assert!(is_new_member(at("2026-11-20T00:00:01Z"), now));
        assert!(!is_new_member(at("2026-11-20T00:00:00Z"), now));
        assert!(
            is_new_member(at("2026-11-28T00:00:00Z"), now),
            "未来の参加日時は新規"
        );
        assert!(!is_new_member(None, now));
    }

    /// 信頼ユーザー・バイパスロールを読み、読めない要素は捨てること。@everyone も数える。管理者は設定を見ずに飛ばす。
    #[test]
    fn bypass_reads_trusted_users_and_roles() {
        let g =
            json!({"trusted_user_ids": ["5", 6, "x"], "bypass_role_ids": [10, "20", null, 1.9]});
        let roles = |ids: &[u64]| ids.iter().map(|&i| RoleId::new(i)).collect::<Vec<_>>();
        let reason = |settings: Option<&Value>, user: u64, held: &[RoleId]| {
            bypass_reason(settings, UserId::new(user), held, false)
        };
        assert_eq!(reason(Some(&g), 5, &[]), Some("trusted_user"));
        assert_eq!(reason(Some(&g), 6, &[]), Some("trusted_user"));
        assert_eq!(reason(Some(&g), 7, &roles(&[20])), Some("bypass_role"));
        // 1.9 は int() で 1（@everyone が 1 のサーバーなら全員が飛ばされる、Python と同じ）。
        assert_eq!(reason(Some(&g), 7, &roles(&[1])), Some("bypass_role"));
        assert_eq!(reason(Some(&g), 7, &roles(&[30])), None);
        let text = json!({"trusted_user_ids": "5"});
        assert_eq!(reason(Some(&text), 5, &[]), None);
        assert_eq!(reason(None, 5, &[]), None);
        // 管理者は、設定が無くても・信頼ユーザーでもまず管理者（S7）。
        let admin = bypass_reason(None, UserId::new(7), &[], true);
        assert_eq!(admin, Some("administrator"));
        let both = bypass_reason(Some(&g), UserId::new(5), &[], true);
        assert_eq!(both, Some("administrator"));
    }

    fn role(id: u64, permissions: Permissions) -> (RoleId, Role) {
        let role: Role = serde_json::from_value(json!({
            "id": id.to_string(), "name": format!("r{id}"), "color": 0,
            "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
            "hoist": false, "position": 1, "permissions": permissions.bits().to_string(),
            "managed": false, "mentionable": false, "flags": 0, "guild_id": "1",
        }))
        .unwrap();
        (RoleId::new(id), role)
    }

    /// Bot のタイムアウトの権限（discord.py の guild_permissions.moderate_members）。オーナー・管理者は持つ。
    /// タイムアウト中は持たない。
    #[test]
    fn the_bot_may_time_out_with_the_permission() {
        let guild = GuildId::new(1);
        let roles: HashMap<RoleId, Role> = [
            role(1, Permissions::empty()),
            role(10, Permissions::MODERATE_MEMBERS),
            role(11, Permissions::ADMINISTRATOR),
            role(12, Permissions::MANAGE_ROLES),
        ]
        .into();
        let held = |ids: &[u64]| ids.iter().map(|&i| RoleId::new(i)).collect::<Vec<_>>();
        assert!(can_moderate(false, &held(&[10]), &roles, guild, false));
        assert!(can_moderate(false, &held(&[11]), &roles, guild, true));
        assert!(can_moderate(true, &[], &roles, guild, false));
        assert!(!can_moderate(false, &held(&[12]), &roles, guild, false));
        assert!(!can_moderate(false, &held(&[10]), &roles, guild, true));
        assert!(!can_moderate(false, &held(&[99]), &roles, guild, false));
        let everyone: HashMap<RoleId, Role> = [role(1, Permissions::MODERATE_MEMBERS)].into();
        assert!(can_moderate(false, &[], &everyone, guild, false));
    }

    /// @everyone は剥がすロールに入れないこと。
    #[test]
    fn everyone_is_never_stripped() {
        let g = GuildId::new(1);
        let roles: Vec<RoleId> = [1, 5, 6].iter().map(|&i| RoleId::new(i)).collect();
        assert_eq!(removable_roles(&roles, g), [RoleId::new(5), RoleId::new(6)]);
        assert!(removable_roles(&[RoleId::new(1)], g).is_empty());
    }

    fn embed_with(
        scans: &[ScanResult],
        gpt: &str,
        reasons: &[&str],
        logs: &[&str],
        enforcement: &Enforcement,
    ) -> Value {
        let at = chrono::FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 27, 9, 0, 0)
            .unwrap();
        let reasons: Vec<String> = reasons.iter().map(|s| s.to_string()).collect();
        let logs: Vec<String> = logs.iter().map(|s| s.to_string()).collect();
        serde_json::to_value(final_embed(scans, gpt, &reasons, &logs, enforcement, at)).unwrap()
    }

    fn embed(scans: &[ScanResult], gpt: &str, reasons: &[&str], logs: &[&str]) -> Value {
        embed_with(scans, gpt, reasons, logs, &Enforcement::default())
    }

    fn timed_out(seconds: i64, failure: Option<StripFailure>) -> Option<TimedOut> {
        Some(TimedOut { seconds, failure })
    }

    /// 見出しと色は取った措置から（S8 の表のとおり。色は discord.py の Color の値）。
    #[test]
    fn the_heading_follows_the_enforcement() {
        let danger = Enforcement {
            action: Action::Danger,
            deleted: 1,
            timeout: timed_out(86_400, None),
            ..Enforcement::default()
        };
        let stripped = Enforcement {
            action: Action::Danger,
            deleted: 1,
            stripped: Some(Stripped::default()),
            ..Enforcement::default()
        };
        let spam = Enforcement {
            action: Action::Spam,
            deleted: 3,
            timeout: timed_out(600, None),
            ..Enforcement::default()
        };
        let spam_only_deleted = Enforcement {
            action: Action::Spam,
            deleted: 3,
            ..Enforcement::default()
        };
        let vc = Enforcement {
            action: Action::Danger,
            deleted: 1,
            vc_done: true,
            ..Enforcement::default()
        };
        let none = Enforcement::default();
        assert_eq!(heading(&danger, false).0, "消して 24 時間のタイムアウト");
        assert_eq!(heading(&stripped, false).0, "消してロールを外した");
        assert_eq!(heading(&spam, false).0, "消して 10 分のタイムアウト");
        assert_eq!(heading(&spam_only_deleted, false).0, "消した");
        assert_eq!(heading(&vc, false).0, "消した（VC の荒らしで措置済み）");
        assert_eq!(heading(&none, true).0, "記録だけ（注意の材料あり）");
        assert_eq!(heading(&none, false).0, "記録だけ（問題なし）");
        let cases = [&danger, &stripped, &spam, &spam_only_deleted, &vc];
        let colours: Vec<u32> = cases.iter().map(|e| heading(e, false).1).collect();
        assert_eq!(colours, [RED, RED, ORANGE, ORANGE, RED]);
        assert_eq!(heading(&none, true).1, GOLD);
        assert_eq!(heading(&none, false).1, GREEN);
        assert_eq!(
            (RED, ORANGE, GOLD, GREEN),
            (0xE74C3C, 0xE67E22, 0xF1C40F, 0x2ECC71)
        );
    }

    /// 措置の一部が失敗したら（消せなかった・タイムアウトが断られた・外せないロール）見出しに「（一部失敗）」。
    #[test]
    fn a_partial_failure_is_marked() {
        let refused = Enforcement {
            action: Action::Danger,
            deleted: 1,
            timeout: timed_out(86_400, Some(StripFailure::Forbidden)),
            ..Enforcement::default()
        };
        let title = heading(&refused, false).0;
        assert_eq!(title, "消して 24 時間のタイムアウト（一部失敗）");
        let kept = Enforcement {
            action: Action::Danger,
            stripped: Some(Stripped {
                kept: vec![RoleId::new(11)],
                failure: Some(StripFailure::Forbidden),
                ..Stripped::default()
            }),
            ..Enforcement::default()
        };
        let title = heading(&kept, false).0;
        assert_eq!(title, "消してロールを外した（一部失敗）");
        let undeleted = Enforcement {
            action: Action::Spam,
            deleted: 2,
            delete_failed: 1,
            ..Enforcement::default()
        };
        assert_eq!(heading(&undeleted, false).0, "消した（一部失敗）");
    }

    /// 注意の材料は VirusTotal の疑わしい・AI の SUSPICIOUS/UNKNOWN・リンク過多・ユニコードトリック。
    #[test]
    fn caution_materials_match_python() {
        let r = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for flag in ["VT_SUSPICIOUS", "TOO_MANY_LINKS", "UNICODE_TRICK"] {
            assert!(has_caution(&r(&[flag]), "SAFE"), "{flag}");
        }
        assert!(has_caution(&[], "SUSPICIOUS"));
        assert!(has_caution(&[], "UNKNOWN"));
        let plain = r(&["NEW_MEMBER", "NEW_ACCOUNT", "GPT:SAFE"]);
        assert!(!has_caution(&plain, "SAFE"));
    }

    /// 報告の項目: 消した投稿・タイムアウト（できた・断られた）・剥がしたロール。長さの書き方。
    #[test]
    fn enforcement_fields_match_python() {
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            (duration_text(86_400), duration_text(600), duration_text(90)),
            ("24 時間".into(), "10 分".into(), "90 秒".into())
        );
        let spam = Enforcement {
            action: Action::Spam,
            deleted: 2,
            delete_failed: 1,
            timeout: timed_out(600, None),
            ..Enforcement::default()
        };
        assert_eq!(
            enforcement_fields(&spam),
            [
                pair("消した投稿", "2件"),
                pair("消せなかった投稿", "1件"),
                pair("タイムアウト", "10 分")
            ]
        );
        let refused = timed_out(86_400, Some(StripFailure::Failed("boom".into())));
        assert_eq!(
            timeout_fields(&refused.unwrap()),
            [pair("タイムアウトできなかった（失敗）", "24 時間")]
        );
        assert!(enforcement_fields(&Enforcement::default()).is_empty());
    }

    /// 項目: 走査の結果ごと → GPT 判定 → 理由（あれば）。説明はログの行、空なら付けない。時刻は足元。
    #[test]
    fn the_result_embed_lists_scans_gpt_and_reasons() {
        let scan = ScanResult {
            kind: "url".into(),
            status: "error".into(),
            malicious: 0,
            suspicious: 0,
        };
        let v = embed(&[scan], "SAFE", &["GPT:SAFE", "NEW_MEMBER"], &["a", "b"]);
        assert_eq!(
            v["description"],
            "a
b"
        );
        let fields = v["fields"].as_array().unwrap();
        assert_eq!(fields[0]["name"], "[WARN] ターゲット 1 (url)");
        assert_eq!(
            fields[0]["value"],
            "Status: `error` | Malicious: `0` | Suspicious: `0`"
        );
        assert_eq!(fields[1]["name"], "[SAFE] GPT判定");
        assert_eq!(fields[2]["value"], "[GPT]GPT:SAFE / [NEW]NEW_MEMBER");
        assert_eq!(v["footer"]["text"], "実行時間: 2026-11-27 09:00:00");
        assert_eq!(v["title"], "記録だけ（問題なし）");
        let empty = embed(&[], "SAFE", &[], &[]);
        assert!(empty.get("description").is_none(), "空の説明を付けた");
        assert_eq!(
            empty["fields"].as_array().unwrap().len(),
            1,
            "理由が無いのに理由の項目を付けた"
        );
        // 題と色は措置から（判定の材料が危険でも、措置しなければ赤にしない）。
        let plain = embed(&[], "SAFE", &["VT_DANGEROUS"], &["x"]);
        assert_eq!(plain["title"], "記録だけ（問題なし）");
        assert_eq!(plain["color"], 0x2ECC71);
        let acted = Enforcement {
            action: Action::Danger,
            deleted: 1,
            timeout: timed_out(86_400, None),
            ..Enforcement::default()
        };
        let red = embed_with(&[], "DANGEROUS", &["GPT:DANGEROUS"], &["x"], &acted);
        assert_eq!(red["title"], "消して 24 時間のタイムアウト");
        assert_eq!(red["color"], 0xE74C3C);
        let unknown = embed(&[], "UNKNOWN", &["GPT:UNKNOWN"], &["x"]);
        // 判定できなかったものを緑にしない（黄）。
        assert_eq!(unknown["color"], 0xF1C40F);
    }

    /// 印の決め方（判定できなかったものを安全にしない）。
    #[test]
    fn icons_never_turn_unknown_into_safe() {
        assert_eq!(vt_icon(0, 0, Some("error")), WARN_ICON);
        assert_eq!(vt_icon(0, 0, Some("skip")), WARN_ICON);
        assert_eq!(vt_icon(1, 0, Some("ok")), ALERT_ICON);
        assert_eq!(vt_icon(0, 1, None), WARN_ICON);
        assert_eq!(vt_icon(0, 0, Some("ok")), SAFE_ICON);
        assert_eq!(gpt_icon("UNKNOWN"), WARN_ICON);
        assert_eq!(gpt_icon("DANGEROUS"), ALERT_ICON);
        assert_eq!(gpt_icon("SAFE"), SAFE_ICON);
        assert_eq!(reason_icon("GPT:DANGEROUS"), "[GPT]");
        assert_eq!(reason_icon("VT_SUSPICIOUS"), "[VT]");
        assert_eq!(reason_icon("NEW_ACCOUNT"), "[ACCOUNT]");
        assert_eq!(reason_icon("なにか"), "[INFO]");
        assert_eq!(progress_bar(3, 10, 10), "[###-------] 3/10");
        assert_eq!(progress_bar(2, 3, 10), "[######----] 2/3");
    }

    /// 1 つずつ剥がし、失敗したところで止める。剥がせたものと、残ったもの（失敗した 1 つとその後ろ）を返す。
    #[tokio::test]
    async fn stripping_stops_at_the_first_failure() {
        let roles: Vec<RoleId> = [11, 12, 13].iter().map(|&i| RoleId::new(i)).collect();
        let tried = Mutex::new(Vec::new());
        let out = strip_each(&roles, |r| {
            tried.lock().unwrap().push(r.get());
            async move {
                if r.get() == 12 {
                    Err(StripFailure::Forbidden)
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(*tried.lock().unwrap(), [11, 12]);
        assert_eq!(out.removed, [RoleId::new(11)]);
        assert_eq!(out.kept, [RoleId::new(12), RoleId::new(13)]);
        assert_eq!(out.failure, Some(StripFailure::Forbidden));
        let all = strip_each(&roles, |_| async { Ok(()) }).await;
        assert_eq!(
            (all.removed.len(), all.kept.len(), all.failure),
            (3, 0, None)
        );
        assert_eq!(
            strip_each(&[], |_| async { Ok(()) }).await,
            Stripped::default()
        );
    }

    /// 報告の項目（Python の strip_fields と同じ）: 剥がしたロール（無ければ「なし」）と、残ったロール（理由つき）。
    #[test]
    fn strip_fields_match_python() {
        let ids = |v: &[u64]| v.iter().map(|&i| RoleId::new(i)).collect::<Vec<_>>();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        let forbidden = Stripped {
            removed: ids(&[11]),
            kept: ids(&[12, 13]),
            failure: Some(StripFailure::Forbidden),
        };
        assert_eq!(
            strip_fields(&forbidden),
            [
                pair("剥がしたロール", "<@&11>"),
                pair("剥がせなかったロール（権限不足）", "<@&12> <@&13>")
            ]
        );
        let failed = Stripped {
            removed: Vec::new(),
            kept: ids(&[11]),
            failure: Some(StripFailure::Failed("boom".into())),
        };
        assert_eq!(
            strip_fields(&failed),
            [
                pair("剥がしたロール", "なし"),
                pair("剥がせなかったロール（失敗）", "<@&11>")
            ]
        );
        assert_eq!(
            strip_fields(&Stripped::default()),
            [pair("剥がしたロール", "なし")]
        );
        // 多ければ 1 つの項目（1024 文字）に収め、はみ出す分は「…他N個」。
        let many = Stripped {
            removed: (0..60)
                .map(|i| RoleId::new(1_100_000_000_000_000_000 + i))
                .collect(),
            ..Stripped::default()
        };
        let value = &strip_fields(&many)[0].1;
        assert!(value.chars().count() <= 1024);
        assert!(value.ends_with("個") && value.contains(" …他"), "{value}");
    }

    /// VC の荒らしのログの項目: チャンネルと、タイムアウトか剥がした結果（Python の _enforce_vc_raid と同じ）。
    #[test]
    fn vc_raid_fields_match_python() {
        let stripped = Enforcement {
            action: Action::Danger,
            stripped: Some(Stripped {
                removed: Vec::new(),
                kept: vec![RoleId::new(11), RoleId::new(12)],
                failure: Some(StripFailure::Forbidden),
            }),
            ..Enforcement::default()
        };
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            vc_raid_fields(777, &stripped),
            [
                pair("チャンネル", "<#777>"),
                pair("剥がしたロール", "なし"),
                pair("剥がせなかったロール（権限不足）", "<@&11> <@&12>"),
            ]
        );
        let timed = Enforcement {
            action: Action::Danger,
            timeout: timed_out(86_400, None),
            ..Enforcement::default()
        };
        assert_eq!(
            vc_raid_fields(777, &timed),
            [
                pair("チャンネル", "<#777>"),
                pair("タイムアウト", "24 時間")
            ]
        );
    }

    fn scan(malicious: i64, suspicious: i64) -> ScanResult {
        ScanResult {
            kind: "url".into(),
            status: "ok".into(),
            malicious,
            suspicious,
        }
    }

    /// 走査の結果が多ければ、GPT 判定と理由の項目を残して 25 個に収め、残りを「…他N件」に畳む（rust-09 の (c)）。
    #[test]
    fn many_targets_are_folded_into_the_last_field() {
        let mut scans = vec![scan(0, 0); 30];
        scans.push(scan(12, 0));
        let v = embed(&scans, "SAFE", &["VT_DANGEROUS", "GPT:SAFE"], &["x"]);
        let fields = v["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 25);
        assert_eq!(fields[21]["name"], "[SAFE] ターゲット 22 (url)");
        assert_eq!(fields[22]["name"], "[ALERT] ターゲット 23〜31");
        assert_eq!(fields[22]["value"], "…他9件");
        assert_eq!(fields[23]["name"], "[SAFE] GPT判定");
        assert_eq!(fields[24]["name"], "判定理由");
        // ちょうど 25 個に収まるなら畳まない。
        let v = embed(&vec![scan(0, 0); 24], "SAFE", &[], &["x"]);
        assert_eq!(v["fields"].as_array().unwrap().len(), 25);
        assert_eq!(v["fields"][23]["name"], "[SAFE] ターゲット 24 (url)");
    }

    /// ログの行が長ければ、説明を 4096 文字・全体を 6000 文字に収め、はみ出す行を「…他N行」に畳む。
    #[test]
    fn long_logs_are_folded_to_fit() {
        let mut logs = vec!["[2026-11-28 09:00:00] スキャン開始".to_string()];
        logs.extend((0..40).map(|i| {
            format!(
                "[SAFE] https://example.com/{}/{i} をスキャン: status=ok Malicious=0 Suspicious=0",
                "a".repeat(150)
            )
        }));
        let logs: Vec<&str> = logs.iter().map(String::as_str).collect();
        // 項目も長め（落とせなかったファイル）にして、説明の 4096 文字と項目を足すと 6000 文字を超える形にする。
        let long = ScanResult {
            kind: "image".into(),
            status: "conflict_fallback".into(),
            malicious: -1,
            suspicious: -1,
        };
        let v = embed(&vec![long; 40], "SAFE", &["TOO_MANY_LINKS"], &logs);
        let len = |v: &Value| v.as_str().unwrap_or("").chars().count();
        let description = v["description"].as_str().unwrap();
        assert!(len(&v["description"]) <= 4096);
        let total = len(&v["title"])
            + len(&v["description"])
            + len(&v["footer"]["text"])
            + v["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| len(&f["name"]) + len(&f["value"]))
                .sum::<usize>();
        assert!(total <= 6000, "{total}");
        assert!(description.starts_with("[2026-11-28 09:00:00] スキャン開始\n"));
        assert!(description.ends_with("行") && description.contains("\n…他"));
    }
}
