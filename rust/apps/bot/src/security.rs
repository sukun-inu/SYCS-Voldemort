//! セキュリティの部品（スパム・VC の荒らしの判定、URL の抜き出し、バイパス、ロールの剥奪、結果の Embed）と、
//! VC に入ったときの荒らし対策。Python の `services/spam_detection.py`・`raid_detection.py`・
//! `security_service.py` のうち、外部のサービス（VirusTotal・Groq）に頼らないところ。
//!
//! メッセージの検査の流れ（判定を集める → 消して剥がす → 報告する）は [`crate::message_security`]。
//!
//! **ロールの剥奪は元に戻せない。** 判定の数（回数・秒数・人数）と、バイパス（信頼ユーザー・
//! バイパスロール）の読み方は Python と同じにしてある（突き合わせで確かめた）。
//!
//! Python には「バイパスの判定に失敗したら措置を見送る」分岐がある。設定の読み取りが失敗した
//! ときの備えで、Rust の設定は起動時に読み終えてメモリから引くので、ここが失敗することはない
//! （Python も Postgres 版では起動後は同じ）。そのため Rust には持ち込んでいない。

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;
use serenity::all::{CreateEmbed, CreateEmbedFooter, GuildId, Http, RoleId, UserId};

use crate::log_channel;

/// スパムとみなす回数（この秒数の中で）。Python の `SPAM_REPEAT_THRESHOLD`。
pub const SPAM_REPEAT_THRESHOLD: usize = 4;
/// スパムを数える秒数。Python の `SPAM_TIME_WINDOW`。
pub const SPAM_TIME_WINDOW: f64 = 15.0;
const SPAM_CLEANUP_INTERVAL: u32 = 100;
/// VC の荒らしを数える秒数。
pub const VC_RAID_WINDOW_SEC: f64 = 20.0;
/// 名前の先頭の何文字が同じなら「似た名前」とみなすか。
pub const VC_RAID_SIMILAR_PREFIX: usize = 4;
/// 似た名前が何人入ったら荒らしとみなすか。
pub const VC_RAID_THRESHOLD: usize = 5;
const RAID_CLEANUP_INTERVAL: u32 = 50;
/// 新規メンバーとみなす日数。
pub const NEW_MEMBER_THRESHOLD_DAYS: i64 = 7;
/// リンク数過多とみなす本数。
pub const MAX_LINKS: usize = 5;

/// (ギルド, ユーザー) → 発言の時刻。
type SpamHistory = HashMap<(u64, u64), Vec<f64>>;
/// チャンネル → (参加の時刻, 名前の先頭)。
type RaidHistory = HashMap<u64, Vec<(f64, String)>>;

/// 1 人の連投を数える。Python の `check_spam`。
#[derive(Default)]
pub struct SpamDetector {
    inner: Mutex<(SpamHistory, u32)>,
}

/// スパムの判定の結果。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpamCheck {
    /// スパムか（秒数の中で [`SPAM_REPEAT_THRESHOLD`] 回以上）。
    pub is_spam: bool,
    /// 秒数の中の回数。
    pub count: usize,
    /// いちばん短い間隔（秒）。1 回だけなら無限大。
    pub min_interval: f64,
}

impl SpamDetector {
    /// 発言を 1 回数えて判定する。
    pub fn check(&self, guild_id: u64, user_id: u64, now: f64) -> SpamCheck {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (history, counter) = &mut *guard;
        let times = history.entry((guild_id, user_id)).or_default();
        times.push(now);
        times.retain(|t| now - t < SPAM_TIME_WINDOW);
        let mut sorted = times.clone();
        let count = sorted.len();
        // 100 回に 1 回、最近の発言の無い人を忘れる（毎回全員を見ない）。
        *counter += 1;
        if *counter >= SPAM_CLEANUP_INTERVAL {
            *counter = 0;
            history.retain(|_, ts| ts.iter().any(|t| now - t < SPAM_TIME_WINDOW));
        }
        sorted.sort_by(f64::total_cmp);
        let min_interval = sorted
            .windows(2)
            .map(|w| w[1] - w[0])
            .fold(f64::INFINITY, f64::min);
        SpamCheck {
            is_spam: count >= SPAM_REPEAT_THRESHOLD,
            count,
            min_interval,
        }
    }
}

/// VC に似た名前の人が続けて入るのを数える。Python の `check_vc_raid`。
///
/// メッセージの検査（VC にいる人の発言）と VC への参加の両方から呼ばれ、同じ記録を使う。
#[derive(Default)]
pub struct RaidDetector {
    inner: Mutex<(RaidHistory, u32)>,
}

impl RaidDetector {
    /// 1 回数えて、似た名前（先頭 4 文字が同じ）が 20 秒以内に 5 回以上なら `true`。
    ///
    /// 数えるのは人数ではなく回数（Python と同じ。同じ人が出入りを繰り返しても数える）。
    pub fn check(&self, channel_id: u64, display_name: &str, now: f64) -> bool {
        let prefix: String = display_name.chars().take(VC_RAID_SIMILAR_PREFIX).collect();
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (history, counter) = &mut *guard;
        let joins = history.entry(channel_id).or_default();
        joins.push((now, prefix));
        joins.retain(|(t, _)| now - t < VC_RAID_WINDOW_SEC);
        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut raid = false;
        for (_, p) in joins.iter() {
            let n = counts.entry(p.as_str()).or_default();
            *n += 1;
            if *n >= VC_RAID_THRESHOLD {
                raid = true;
                break;
            }
        }
        *counter += 1;
        if *counter >= RAID_CLEANUP_INTERVAL {
            *counter = 0;
            history.retain(|_, js| js.iter().any(|(t, _)| now - t < VC_RAID_WINDOW_SEC));
        }
        raid
    }
}

/// Python の `URL_REGEX`（`https?://[^\s]+`、大文字・小文字を問わない）。
static URL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https?://[^\s]+").expect("正しい正規表現"));

/// 抜き出した URL の前後の記号を落とす。Python の `normalize_url`。
///
/// `<https://example.com>`（Discord のリンクを開かせない書き方）や、文の終わりの句読点を落とす。
pub fn normalize_url(url: &str) -> String {
    let mut u = url.trim();
    if u.starts_with('<') && u.ends_with('>') && u.len() >= 2 {
        u = u[1..u.len() - 1].trim();
    }
    let u = u.trim_matches(|c| c == '<' || c == '>');
    u.trim_end_matches(['.', ',', '!', '?', ';', ':'])
        .to_string()
}

/// 本文から URL を重複なしで抜き出す（落としたあとの形で重複を見る）。Python の `extract_links`。
pub fn extract_links(text: &str) -> Vec<String> {
    let mut links: Vec<String> = Vec::new();
    for m in URL_REGEX.find_iter(text) {
        let u = normalize_url(m.as_str());
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

/// Python の `_parse_id_list`: リストでなければ空、`int()` で読めない要素は捨てる。
pub(crate) fn id_list(value: Option<&Value>) -> Vec<i64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(log_channel::python_int).collect())
        .unwrap_or_default()
}

/// 検査を飛ばす理由（信頼ユーザー・バイパスロール）。飛ばさないなら `None`。Python の
/// `is_security_bypassed`。
///
/// `roles` はサーバーにあるロールだけ（discord.py の `member.roles` と同じく @everyone を含む）。
pub fn bypass_reason(
    guild_settings: Option<&Value>,
    user_id: UserId,
    roles: &[RoleId],
) -> Option<&'static str> {
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

/// 剥がした結果。Python の `strip_roles` の戻り値。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stripped {
    /// 剥がした。
    Removed,
    /// 剥がすロールが無かった。
    NoRoles,
    /// 権限が足りなかった（途中まで剥がしていることがある）。
    Forbidden,
    /// ほかの失敗。
    Failed(String),
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
    if removable.is_empty() {
        return Stripped::NoRoles;
    }
    for role in removable {
        if let Err(e) = http
            .remove_member_role(guild_id, user_id, role, Some("セキュリティ違反"))
            .await
        {
            let forbidden = matches!(
                &e,
                serenity::Error::Http(serenity::http::HttpError::UnsuccessfulRequest(r))
                    if r.status_code == serenity::http::StatusCode::FORBIDDEN
            );
            if forbidden {
                return Stripped::Forbidden;
            }
            tracing::error!("[SECURITY] strip roles failed: {e}");
            return Stripped::Failed(e.to_string());
        }
    }
    Stripped::Removed
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

/// 検査の結果の Embed。Python の `build_final_embed`（時刻は渡す）。
pub fn final_embed(
    scans: &[ScanResult],
    gpt_result: &str,
    reasons: &[String],
    logs: &[String],
    now: DateTime<chrono::FixedOffset>,
) -> CreateEmbed {
    let has = |r: &str| reasons.iter().any(|x| x == r);
    let (colour, title) = if has("VT_DANGEROUS") || gpt_result == "DANGEROUS" || has("VC_RAID") {
        (0xE7_4C_3C, "危険な投稿を検出")
    } else if has("VT_SUSPICIOUS") || gpt_result == "SUSPICIOUS" || has("SPAM") {
        (0xE6_7E_22, "注意：スパム/不審な投稿の可能性")
    } else if gpt_result == "UNKNOWN" {
        // 判定できなかったことを「問題なし」の緑にしない。
        (0xE6_7E_22, "注意：GPT判定に失敗しました")
    } else {
        (0x2E_CC_71, "検査完了：問題なし")
    };
    let mut embed = CreateEmbed::new().title(title).colour(colour);
    // 空の説明は付けない（discord.py も空なら付けない）。
    if !logs.is_empty() {
        embed = embed.description(logs.join("\n"));
    }
    for (i, r) in scans.iter().enumerate() {
        embed = embed.field(
            format!(
                "{} ターゲット {} ({})",
                vt_icon(r.malicious, r.suspicious, Some(&r.status)),
                i + 1,
                r.kind
            ),
            format!(
                "Status: `{}` | Malicious: `{}` | Suspicious: `{}`",
                r.status, r.malicious, r.suspicious
            ),
            false,
        );
    }
    embed = embed.field(
        format!("{} GPT判定", gpt_icon(gpt_result)),
        format!("結果: `{gpt_result}`"),
        false,
    );
    if !reasons.is_empty() {
        let joined = reasons
            .iter()
            .map(|r| format!("{}{r}", reason_icon(r)))
            .collect::<Vec<_>>()
            .join(" / ");
        embed = embed.field("判定理由", joined, false);
    }
    embed.footer(CreateEmbedFooter::new(format!(
        "実行時間: {}",
        now.format("%Y-%m-%d %H:%M:%S")
    )))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    /// 15 秒の中で 4 回目からスパム。間隔はいちばん短いもの。15 秒より前は数えない。
    #[test]
    fn spam_is_four_posts_in_fifteen_seconds() {
        assert_eq!((SPAM_REPEAT_THRESHOLD, SPAM_TIME_WINDOW), (4, 15.0));
        let d = SpamDetector::default();
        let first = d.check(1, 2, 100.0);
        assert_eq!((first.is_spam, first.count), (false, 1));
        assert!(first.min_interval.is_infinite());
        d.check(1, 2, 103.0);
        d.check(1, 2, 104.5);
        let fourth = d.check(1, 2, 110.0);
        assert!(fourth.is_spam);
        assert_eq!(fourth.count, 4);
        assert_eq!(fourth.min_interval, 1.5);
        // 15 秒ちょうど前のものは数えない（now - t < 15）。
        let later = d.check(1, 2, 115.0);
        assert_eq!(later.count, 4, "100 秒のものが残っている");
        // ほかの人・ほかのサーバーは別に数える。
        assert_eq!(d.check(1, 3, 115.0).count, 1);
        assert_eq!(d.check(9, 2, 115.0).count, 1);
    }

    /// 似た名前（先頭 4 文字）が 20 秒以内に 5 回で荒らし。違う名前・古いものは数えない。
    #[test]
    fn a_raid_is_five_similar_names_in_twenty_seconds() {
        assert_eq!(
            (
                VC_RAID_WINDOW_SEC,
                VC_RAID_SIMILAR_PREFIX,
                VC_RAID_THRESHOLD
            ),
            (20.0, 4, 5)
        );
        let r = RaidDetector::default();
        for (i, name) in ["bot_01", "bot_02", "bot_03", "別人です", "bot_04"]
            .iter()
            .enumerate()
        {
            assert!(!r.check(7, name, i as f64), "{name}");
        }
        assert!(r.check(7, "bot_05", 5.0));
        // 別のチャンネルは別に数える。
        assert!(!r.check(8, "bot_06", 5.0));
        // 20 秒たつと最初のものは数えない。
        let r = RaidDetector::default();
        for i in 0..4 {
            r.check(7, "abcd", f64::from(i));
        }
        assert!(!r.check(7, "abcdX", 20.0), "0 秒のものを数えた");
        // 名前の先頭は文字（コードポイント）で数える。
        let r = RaidDetector::default();
        for i in 0..4 {
            r.check(7, "荒らし用１", f64::from(i));
        }
        assert!(r.check(7, "荒らし用２", 4.0));
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

    /// 信頼ユーザー・バイパスロールを読み、読めない要素は捨てること。@everyone も数える。
    #[test]
    fn bypass_reads_trusted_users_and_roles() {
        let g =
            json!({"trusted_user_ids": ["5", 6, "x"], "bypass_role_ids": [10, "20", null, 1.9]});
        let roles = |ids: &[u64]| ids.iter().map(|&i| RoleId::new(i)).collect::<Vec<_>>();
        assert_eq!(
            bypass_reason(Some(&g), UserId::new(5), &[]),
            Some("trusted_user")
        );
        assert_eq!(
            bypass_reason(Some(&g), UserId::new(6), &[]),
            Some("trusted_user")
        );
        assert_eq!(
            bypass_reason(Some(&g), UserId::new(7), &roles(&[20])),
            Some("bypass_role")
        );
        // 1.9 は int() で 1（@everyone が 1 のサーバーなら全員が飛ばされる、Python と同じ）。
        assert_eq!(
            bypass_reason(Some(&g), UserId::new(7), &roles(&[1])),
            Some("bypass_role")
        );
        assert_eq!(bypass_reason(Some(&g), UserId::new(7), &roles(&[30])), None);
        assert_eq!(
            bypass_reason(Some(&json!({"trusted_user_ids": "5"})), UserId::new(5), &[]),
            None
        );
        assert_eq!(bypass_reason(None, UserId::new(5), &[]), None);
    }

    /// @everyone は剥がすロールに入れないこと。
    #[test]
    fn everyone_is_never_stripped() {
        let g = GuildId::new(1);
        let roles: Vec<RoleId> = [1, 5, 6].iter().map(|&i| RoleId::new(i)).collect();
        assert_eq!(removable_roles(&roles, g), [RoleId::new(5), RoleId::new(6)]);
        assert!(removable_roles(&[RoleId::new(1)], g).is_empty());
    }

    fn embed(scans: &[ScanResult], gpt: &str, reasons: &[&str], logs: &[&str]) -> Value {
        let at = chrono::FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 27, 9, 0, 0)
            .unwrap();
        let reasons: Vec<String> = reasons.iter().map(|s| s.to_string()).collect();
        let logs: Vec<String> = logs.iter().map(|s| s.to_string()).collect();
        serde_json::to_value(final_embed(scans, gpt, &reasons, &logs, at)).unwrap()
    }

    /// 題と色: 危険 → 赤、不審・スパム → 橙、判定できなかった → 橙（緑にしない）、それ以外 → 緑。
    #[test]
    fn the_result_embed_never_shows_unknown_as_safe() {
        let title = |gpt: &str, reasons: &[&str]| {
            let v = embed(&[], gpt, reasons, &["x"]);
            (
                v["title"].as_str().unwrap().to_string(),
                v["color"].as_u64().unwrap(),
            )
        };
        assert_eq!(
            title("SAFE", &["VC_RAID"]),
            ("危険な投稿を検出".into(), 0xE74C3C)
        );
        assert_eq!(title("DANGEROUS", &[]).1, 0xE74C3C);
        assert_eq!(title("SAFE", &["VT_DANGEROUS"]).1, 0xE74C3C);
        assert_eq!(
            title("SAFE", &["SPAM"]),
            ("注意：スパム/不審な投稿の可能性".into(), 0xE67E22)
        );
        assert_eq!(title("SUSPICIOUS", &[]).1, 0xE67E22);
        assert_eq!(title("SAFE", &["VT_SUSPICIOUS"]).1, 0xE67E22);
        assert_eq!(
            title("UNKNOWN", &[]),
            ("注意：GPT判定に失敗しました".into(), 0xE67E22)
        );
        assert_eq!(title("SAFE", &[]), ("検査完了：問題なし".into(), 0x2ECC71));
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
        let empty = embed(&[], "SAFE", &[], &[]);
        assert!(empty.get("description").is_none(), "空の説明を付けた");
        assert_eq!(
            empty["fields"].as_array().unwrap().len(),
            1,
            "理由が無いのに理由の項目を付けた"
        );
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
        assert_eq!(reason_icon("なにか"), "[INFO]");
        assert_eq!(progress_bar(3, 10, 10), "[###-------] 3/10");
        assert_eq!(progress_bar(2, 3, 10), "[######----] 2/3");
    }
}
