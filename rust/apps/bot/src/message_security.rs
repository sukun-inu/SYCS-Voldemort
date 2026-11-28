//! メッセージ 1 件の検査。Python の `services/security_service.py` の `handle_security_for_message`。
//!
//! 流れは Python と同じ:
//!
//! 1. AI の応答チャンネルへの、リンクも添付も無い発言は見ない（会話は数が多い）
//! 2. 信頼ユーザー・バイパスロールなら、飛ばしたことをログに残して終わる
//! 3. 判定を集める（[`collect_findings`]。ここでは何もしない）: スパム・リンク数過多・文字の向きの細工 →
//!    VirusTotal（リンクと添付を 4 本ずつ並べて。進み具合をログチャンネルの Embed に出す）→ Groq の判定 →
//!    新規メンバー → VC にいれば VC の荒らし（参加の記録を見るだけ。発言は数えない）
//! 4. 危険なら、メッセージを消して @everyone 以外のロールを全部剥がす（**元に戻せない**）
//! 5. 結果をログチャンネルへ送る（進み具合の Embed を結果に書き換える。リンクも添付も無く危険でもなければ
//!    結果の Embed は出さない。Embed は Discord の上限に収める）。最後に「メッセージセキュリティ検査」の
//!    ログを 1 件（途中の送信・書き換えが失敗しても出す。剥がしたら、剥がせたロールと残ったロールも出す）
//!
//! 危険とみなすのは、スパム（15 秒で 4 回）・VirusTotal で 10 以上・Groq の DANGEROUS・VC の荒らし。
//! この決め方は Python のまま写した（見直しは移行のあと。トラッカーの rust-09）。
//!
//! Python には「バイパスの判定に失敗したら措置を見送る」分岐がある。Rust の設定はメモリから引くので
//! 判定が失敗することはなく、持ち込んでいない（[`crate::security`] の説明を参照）。
//!
//! Discord への書き込みは [`Effects`] に、VirusTotal と Groq は [`Judges`] に分けてある。テストと
//! Python との突き合わせで、記録するだけの偽物に差し替えるため。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Utc};
use serde_json::Value;
use serenity::all::{
    Cache, ChannelId, CreateEmbed, EditMessage, GuildId, Message, MessageId, RoleId, Timestamp,
    UserId,
};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::log_channel::{self, Author, Level, LogSink};
use crate::moderation::{AssessInput, Moderation, Verdict};
use crate::security::{
    self, MAX_LINKS, RaidDetector, SPAM_TIME_WINDOW, ScanResult, SpamDetector, StripFailure,
    Stripped,
};
use crate::virustotal::{MALICIOUS_THRESHOLD, VirusTotal, VtResult};
use crate::{compat, members, vc_notify};

/// VirusTotal を同時に走らせる数の既定（`VT_SCAN_CONCURRENCY`、下限 1）。
pub const DEFAULT_SCAN_CONCURRENCY: usize = 4;
/// 進み具合の Embed の色（discord.py の `Color.blurple()`）。
pub const BLURPLE: u32 = 0x58_65_F2;
/// 危険の色（`Color.red()`）。
pub const RED: u32 = 0xE7_4C_3C;
/// 問題なしの色（`Color.green()`）。
pub const GREEN: u32 = 0x2E_CC_71;

/// 検査するメッセージ（serenity のメッセージとキャッシュから写したもの）。
#[derive(Clone, Debug)]
pub struct Post {
    /// サーバー。
    pub guild_id: GuildId,
    /// チャンネル（スレッドならスレッド）。
    pub channel_id: ChannelId,
    /// メッセージ。
    pub message_id: MessageId,
    /// 発言した人。
    pub user_id: UserId,
    /// 本文。
    pub content: String,
    /// 添付ファイルの URL（並びのまま）。
    pub attachments: Vec<String>,
    /// 持っているロール（サーバーにあるものだけ、discord.py と同じ並び。@everyone は含めない）。
    pub roles: Vec<RoleId>,
    /// 参加日時。
    pub joined_at: Option<DateTime<Utc>>,
    /// いま入っている VC（キャッシュにあるチャンネルだけ）。
    pub voice_channel: Option<u64>,
    /// 表示名（ニックネーム → 表示名 → ユーザー名）。
    pub display_name: String,
    /// ログの作者。
    pub author: Author,
}

impl Post {
    /// バイパスの判定に使うロール（discord.py の `member.roles` と同じく @everyone を含む）。
    fn roles_with_everyone(&self) -> Vec<RoleId> {
        let mut roles = vec![RoleId::new(self.guild_id.get())];
        roles.extend(self.roles.iter().copied());
        roles
    }
}

fn to_utc(ts: Timestamp) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&ts.to_rfc3339()?)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// メッセージから検査の中身を作る。検査しないもの（DM・Bot の発言・作者がメンバーでない）は `None`。
/// Python の `_is_examinable`。
///
/// 作者の組み立て方は discord.py と同じ: メッセージに付いてくるメンバーの情報で、ロール・ニックネーム・
/// 参加日時を上書きする（読み込み済みのメンバーがいれば、アバターはそのもの）。どちらも無ければメンバーで
/// ないので外す（**黙って外さない**。危険な投稿を見つける経路なので、素通りに気づけるようにする）。
pub fn post_from_message(cache: &Cache, msg: &Message) -> Option<Post> {
    let guild_id = msg.guild_id?;
    if msg.author.bot {
        return None;
    }
    let guild = cache.guild(guild_id)?;
    let cached = guild.members.get(&msg.author.id);
    let (roles, joined_at, nick, guild_avatar) = match (msg.member.as_deref(), cached) {
        (Some(pm), cached) => (
            pm.roles.clone(),
            pm.joined_at,
            pm.nick.clone(),
            cached.map_or(pm.avatar, |m| m.avatar),
        ),
        (None, Some(m)) => (m.roles.clone(), m.joined_at, m.nick.clone(), m.avatar),
        (None, None) => {
            warn!(
                "[security] author が Member ではないため検査を飛ばします guild={guild_id} channel={} author={}(User)",
                msg.channel_id,
                compat::user_tag(&msg.author)
            );
            return None;
        }
    };
    // VC は、キャッシュにあるチャンネルのときだけ「入っている」（discord.py の member.voice.channel）。
    let voice_channel = guild
        .voice_states
        .get(&msg.author.id)
        .and_then(|v| v.channel_id)
        .filter(|c| guild.channels.contains_key(c))
        .map(|c| c.get());
    let avatar_url = match guild_avatar {
        Some(hash) => compat::guild_avatar_url(guild_id, msg.author.id, &hash),
        None => compat::user_avatar_url(&msg.author),
    };
    Some(Post {
        guild_id,
        channel_id: msg.channel_id,
        message_id: msg.id,
        user_id: msg.author.id,
        content: msg.content.clone(),
        attachments: msg.attachments.iter().map(|a| a.url.clone()).collect(),
        roles: members::sorted_roles(&roles, &guild.roles, guild_id),
        joined_at: joined_at.and_then(to_utc),
        voice_channel,
        display_name: vc_notify::display_name(
            nick.as_deref(),
            msg.author.global_name.as_deref(),
            &msg.author.name,
        )
        .to_string(),
        author: Author {
            id: msg.author.id.get(),
            name: compat::user_tag(&msg.author),
            avatar_url,
        },
    })
}

/// ログチャンネルに送ったメッセージ（あとで書き換える）。
pub type LogMessage = (ChannelId, MessageId);

/// 検査の出口（Discord への書き込み）。
pub trait Effects: Sync {
    /// ログチャンネルへ Embed を送る（送らなかった・送れなかったら `None`）。Python の `send_log_embed`。
    fn send_log_embed(
        &self,
        level: Level,
        embed: CreateEmbed,
    ) -> impl Future<Output = Option<LogMessage>> + Send;
    /// 送った Embed を書き換える。
    fn edit_log_embed(
        &self,
        message: LogMessage,
        embed: CreateEmbed,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// 検査したメッセージを消す。
    fn delete_message(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// 発言した人のロールを 1 つ剥がす（剥がす順と、失敗で止めるのは [`security::strip_each`]）。
    fn remove_role(&self, role: RoleId) -> impl Future<Output = Result<(), StripFailure>> + Send;
    /// ログを 1 件送る（作者は発言した人）。Python の `log_action`（失敗はここで飲み込む）。
    fn log_action(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
        colour: Option<u32>,
    ) -> impl Future<Output = ()> + Send;
}

/// URL を 1 つ調べる（VirusTotal）。
pub type Scan = Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = VtResult> + Send>> + Send + Sync>;

/// Groq の判定に渡すもの（持ち運べる形）。
#[derive(Clone, Debug, PartialEq)]
pub struct AssessRequest {
    /// 本文。
    pub text: String,
    /// VirusTotal の結果。
    pub vt_results: Vec<VtResult>,
    /// 直近 15 秒の発言の回数。
    pub spam_count: usize,
    /// 発言のいちばん短い間隔（秒）。
    pub min_interval: f64,
    /// 新規メンバーか。
    pub is_new_member: bool,
}

/// 投稿を判定する（Groq）。
pub type Assess =
    Arc<dyn Fn(AssessRequest) -> Pin<Box<dyn Future<Output = Verdict> + Send>> + Send + Sync>;

/// 判定に使う外のサービス。
#[derive(Clone)]
pub struct Judges {
    /// VirusTotal。
    pub scan: Scan,
    /// Groq。
    pub assess: Assess,
    /// VirusTotal を同時に走らせる数。
    pub scan_concurrency: usize,
}

impl Judges {
    /// 本物の VirusTotal と Groq で作る。
    pub fn new(vt: Arc<VirusTotal>, moderation: Arc<Moderation>, scan_concurrency: usize) -> Self {
        let scan: Scan = Arc::new(move |url: String| {
            let vt = Arc::clone(&vt);
            Box::pin(async move { vt.scan_target(&url).await })
        });
        let assess: Assess = Arc::new(move |r: AssessRequest| {
            let m = Arc::clone(&moderation);
            Box::pin(async move {
                m.assess(&AssessInput {
                    text: &r.text,
                    vt_results: &r.vt_results,
                    spam_count: r.spam_count,
                    min_interval: r.min_interval,
                    is_new_member: r.is_new_member,
                })
                .await
            })
        });
        Self {
            scan,
            assess,
            scan_concurrency: scan_concurrency.max(1),
        }
    }
}

/// 時刻（UNIX 秒、小数つき）。テストで固定する。
pub type Clock = fn() -> f64;

/// いまの時刻（UNIX 秒）。Python の `time.time()`。
pub fn system_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn utc(unix: f64) -> DateTime<Utc> {
    let secs = unix.floor();
    DateTime::from_timestamp(secs as i64, ((unix - secs) * 1e9) as u32).unwrap_or_default()
}

fn jst(unix: f64) -> DateTime<FixedOffset> {
    utc(unix).with_timezone(&log_channel::jst())
}

fn jst_text(unix: f64) -> String {
    jst(unix).format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 検査に要るもの（サーバーの設定と、連投・VC の荒らしの記録）。
pub struct Context<'a> {
    /// そのサーバーの設定。
    pub settings: Option<&'a Value>,
    /// 連投の記録。
    pub spam: &'a SpamDetector,
    /// VC の荒らしの記録。
    pub raid: &'a RaidDetector,
    /// VirusTotal と Groq。
    pub judges: &'a Judges,
    /// 時刻。
    pub clock: Clock,
}

/// 集めた判定の材料。Python の `_Findings`（結論と、その根拠の印を一緒に持つ）。
#[derive(Clone, Debug)]
pub struct Findings {
    /// 危険か（消して剥がす）。
    pub danger: bool,
    /// 根拠の印（`SPAM`・`VT_DANGEROUS`・`GPT:SAFE` など）。
    pub reason_flags: Vec<String>,
    /// VirusTotal の結果（リンク・添付の順）。
    pub vt_results: Vec<VtResult>,
    /// 進み具合の Embed（書き換えに失敗したら無くなる）。
    pub progress: Option<LogMessage>,
    /// Groq の判定。
    pub gpt: Verdict,
    /// 直近 15 秒の発言の回数。
    pub spam_count: usize,
}

/// AI の応答チャンネルへの、リンクも添付も無い発言か。Python の `_is_plain_chat_post`。
pub fn is_plain_chat_post(
    settings: Option<&Value>,
    channel_id: ChannelId,
    links: usize,
    attachments: usize,
) -> bool {
    let response_channel = settings
        .and_then(|g| g.get("response_channel_id"))
        .and_then(log_channel::python_int)
        .unwrap_or(0);
    response_channel != 0
        && i64::try_from(channel_id.get()) == Ok(response_channel)
        && links == 0
        && attachments == 0
}

fn progress_embed(description: String) -> CreateEmbed {
    CreateEmbed::new()
        .title("セキュリティ検査中")
        .description(description)
        .colour(BLURPLE)
}

/// メッセージ 1 件を検査する。Python の `handle_security_for_message`（Bot の発言・DM・メンバーで
/// ない作者は、呼ぶ側が [`Post`] を作らずに外す）。
pub async fn check_message<E: Effects>(fx: &E, cx: &Context<'_>, post: &Post) {
    let links = security::extract_links(&post.content);
    if is_plain_chat_post(
        cx.settings,
        post.channel_id,
        links.len(),
        post.attachments.len(),
    ) {
        return;
    }
    let mut logs = vec![format!("[{}] スキャン開始", jst_text((cx.clock)()))];
    let roles = post.roles_with_everyone();
    if let Some(reason) = security::bypass_reason(cx.settings, post.user_id, &roles) {
        logs.push(format!("バイパス適用: {reason}"));
        fx.log_action(
            Level::Info,
            "セキュリティ検査スキップ",
            &[("理由".into(), reason.into())],
            None,
        )
        .await;
        return;
    }
    let findings = collect_findings(fx, cx, post, &links, &mut logs).await;
    let stripped = enforce(fx, post, &findings).await;
    report(
        fx,
        cx,
        &findings,
        &links,
        post.attachments.len(),
        &logs,
        stripped.as_ref(),
    )
    .await;
}

/// スパム・リンク・VirusTotal・Groq・新規・VC の荒らしを順に見て、材料をそろえる。Python の
/// `_collect_findings`。**判定するだけで、何もしない**（消す・剥がすは [`enforce`]）。
pub async fn collect_findings<E: Effects>(
    fx: &E,
    cx: &Context<'_>,
    post: &Post,
    links: &[String],
    logs: &mut Vec<String>,
) -> Findings {
    let is_new = security::is_new_member(post.joined_at, utc((cx.clock)()));
    let spam = cx
        .spam
        .check(post.guild_id.get(), post.user_id.get(), (cx.clock)());
    let mut flags: Vec<String> = Vec::new();
    if spam.is_spam {
        flags.push("SPAM".into());
        logs.push(format!(
            "スパム検出（{}回/{}秒、最短間隔{:.1}秒）",
            spam.count, SPAM_TIME_WINDOW as i64, spam.min_interval
        ));
    }
    if links.len() >= MAX_LINKS {
        flags.push("TOO_MANY_LINKS".into());
        logs.push("リンク数過多".into());
    }
    if security::has_unicode_trick(&post.content) {
        flags.push("UNICODE_TRICK".into());
        logs.push("ユニコードトリック検出".into());
    }
    // スパムだけでも危険（Python と同じ。見直しの候補）。
    let mut danger = spam.is_spam;

    let scanned = run_vt_scans(fx, cx.judges, links, &post.attachments, logs).await;
    flags.extend(scanned.flags);
    danger |= scanned.danger;

    let gpt = (cx.judges.assess)(AssessRequest {
        text: post.content.clone(),
        vt_results: scanned.results.clone(),
        spam_count: spam.count,
        min_interval: spam.min_interval,
        is_new_member: is_new,
    })
    .await;
    flags.push(format!("GPT:{}", gpt.as_str()));
    logs.push(format!("GPT判定: {}", gpt.as_str()));
    if gpt == Verdict::Dangerous {
        danger = true;
    }

    if is_new {
        flags.push("NEW_MEMBER".into());
        logs.push("新規メンバー".into());
    }

    // VC にいる人の発言は、VC の荒らしの記録に入れない（数えるのは VC への参加だけ）。参加の記録がいま荒らしの
    // 形になっているかだけを見る（Python の is_vc_raid_ongoing。rust-09 の (e)）。
    if let Some(channel) = post.voice_channel
        && cx.raid.peek(channel, (cx.clock)())
    {
        danger = true;
        flags.push("VC_RAID".into());
        logs.push("VCレイド検出".into());
    }

    Findings {
        danger,
        reason_flags: flags,
        vt_results: scanned.results,
        progress: scanned.progress,
        gpt,
        spam_count: spam.count,
    }
}

struct Scanned {
    results: Vec<VtResult>,
    progress: Option<LogMessage>,
    flags: Vec<String>,
    danger: bool,
}

/// リンクと添付を VirusTotal に回す。Python の `_run_vt_scans`。
///
/// 1 件ずつ別のタスクで走らせる。1 件が落ちても（パニック）、その件を「走査できなかった」にして検査を
/// 続ける（Python の `scan_one` の受け止めと同じ。止めると、落ちる URL を混ぜるだけで危険な投稿が素通り
/// する）。結果は渡した順に並べる（ログの行と結果の対応を崩さない）。
async fn run_vt_scans<E: Effects>(
    fx: &E,
    judges: &Judges,
    links: &[String],
    attachments: &[String],
    logs: &mut Vec<String>,
) -> Scanned {
    if links.is_empty() && attachments.is_empty() {
        return Scanned {
            results: Vec::new(),
            progress: None,
            flags: Vec::new(),
            danger: false,
        };
    }
    let mut progress = fx
        .send_log_embed(Level::Info, progress_embed("VirusTotal解析中…".into()))
        .await;
    let targets: Vec<String> = links.iter().chain(attachments).cloned().collect();
    let gate = Arc::new(Semaphore::new(judges.scan_concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    let mut index_of = HashMap::new();
    for (i, url) in targets.iter().cloned().enumerate() {
        let scan = Arc::clone(&judges.scan);
        let gate = Arc::clone(&gate);
        let handle = set.spawn(async move {
            let _permit = gate.acquire_owned().await;
            scan(url).await
        });
        index_of.insert(handle.id(), i);
    }
    let mut results: Vec<Option<VtResult>> = vec![None; targets.len()];
    let mut done = 0;
    while let Some(joined) = set.join_next_with_id().await {
        let (id, result) = match joined {
            Ok((id, result)) => (id, result),
            Err(e) => {
                error!("[SECURITY] VirusTotal の走査で予期しない失敗: {e}");
                let reason = if e.is_panic() { "panic" } else { "cancelled" };
                let failed = VtResult {
                    status: "error".into(),
                    kind: "url".into(),
                    malicious: 0,
                    suspicious: 0,
                    reason: Some(format!("scan_failed:{reason}")),
                };
                (e.id(), failed)
            }
        };
        if let Some(&i) = index_of.get(&id) {
            results[i] = Some(result);
        }
        done += 1;
        if let Some(message) = progress {
            // 何本終わったかだけを出す（並べて走るので、どの行まで進んだかは終わるまで分からない）。
            let bar = security::progress_bar(done, targets.len(), 10);
            let embed = progress_embed(format!("VirusTotal解析中… {bar}"));
            if let Err(e) = fx.edit_log_embed(message, embed).await {
                debug!("[SECURITY] プログレスメッセージ更新に失敗: {e}");
                progress = None;
            }
        }
    }
    let results: Vec<VtResult> = results.into_iter().flatten().collect();

    let (mut max_malicious, mut max_suspicious) = (0, 0);
    for (url, r) in targets.iter().zip(&results) {
        let status = if r.status.is_empty() {
            "unknown"
        } else {
            r.status.as_str()
        };
        max_malicious = max_malicious.max(r.malicious);
        max_suspicious = max_suspicious.max(r.suspicious);
        let mut line = format!(
            "{} {url} をスキャン: status={status} Malicious={} Suspicious={}",
            security::vt_icon(r.malicious, r.suspicious, Some(status)),
            r.malicious,
            r.suspicious
        );
        if let Some(reason) = r.reason.as_deref().filter(|s| !s.is_empty()) {
            line.push_str(&format!(" reason={reason}"));
        }
        logs.push(line);
    }
    let mut flags = Vec::new();
    let mut danger = false;
    if max_malicious >= MALICIOUS_THRESHOLD {
        danger = true;
        flags.push("VT_DANGEROUS".into());
    } else if max_malicious > 0 || max_suspicious > 0 {
        flags.push("VT_SUSPICIOUS".into());
    }
    Scanned {
        results,
        progress,
        flags,
        danger,
    }
}

/// 危険なら、メッセージを消してロールを剥がす。Python の `_enforce_or_withhold`。
///
/// 消すのに失敗しても剥がす（Python と同じ）。剥がしたら、その結果を返す（報告に出す。rust-09 の (i)）。
/// 剥がさなかったら `None`。
pub async fn enforce<E: Effects>(fx: &E, post: &Post, findings: &Findings) -> Option<Stripped> {
    if !findings.danger {
        return None;
    }
    if let Err(e) = fx.delete_message().await {
        warn!("[security] message delete failed: {e}");
    }
    let removable = security::removable_roles(&post.roles, post.guild_id);
    let stripped = security::strip_each(&removable, |role| fx.remove_role(role)).await;
    debug!(?stripped, "[security] ロールの剥奪");
    Some(stripped)
}

/// 結果をログチャンネルへ送る。Python の `_report_result`（テキストチャンネルには送らない）。
///
/// 最後の「メッセージセキュリティ検査」のログは、途中の送信・書き換えがどう失敗しても必ず出す。剥がしたときは、
/// 剥がした結果の項目を足す（[`security::strip_fields`]）。
pub async fn report<E: Effects>(
    fx: &E,
    cx: &Context<'_>,
    findings: &Findings,
    links: &[String],
    attachments: usize,
    logs: &[String],
    stripped: Option<&Stripped>,
) {
    let scans: Vec<ScanResult> = findings
        .vt_results
        .iter()
        .map(|r| ScanResult {
            kind: r.kind.clone(),
            status: r.status.clone(),
            malicious: r.malicious,
            suspicious: r.suspicious,
        })
        .collect();
    let embed = security::final_embed(
        &scans,
        findings.gpt.as_str(),
        &findings.reason_flags,
        logs,
        jst((cx.clock)()),
    );
    let level = if findings.danger {
        Level::Error
    } else {
        Level::Info
    };
    if !links.is_empty() || attachments > 0 {
        match findings.progress {
            Some(message) => {
                if let Err(e) = fx.edit_log_embed(message, embed).await {
                    warn!("[security] progress_msg edit failed: {e}");
                }
            }
            None => {
                fx.send_log_embed(level, embed).await;
            }
        }
    } else if findings.danger {
        fx.send_log_embed(Level::Error, embed).await;
    }
    let reasons = if findings.reason_flags.is_empty() {
        "なし".to_string()
    } else {
        findings.reason_flags.join(", ")
    };
    let spam = if findings.spam_count > 1 {
        findings.spam_count.to_string()
    } else {
        "なし".into()
    };
    let mut fields = vec![
        ("理由".to_string(), reasons),
        ("GPT判定".to_string(), findings.gpt.as_str().to_string()),
        ("リンク数".to_string(), links.len().to_string()),
        ("スパム回数".to_string(), spam),
    ];
    if let Some(stripped) = stripped {
        fields.extend(security::strip_fields(stripped));
    }
    let colour = if findings.danger { RED } else { GREEN };
    fx.log_action(level, "メッセージセキュリティ検査", &fields, Some(colour))
        .await;
    if findings.danger {
        info!("[SECURITY] DANGER");
    } else {
        info!("[SECURITY] SAFE");
    }
}

/// 本物の Discord への書き込み。
pub struct DiscordEffects<'a> {
    /// ログの送り先。
    pub sink: LogSink<'a>,
    /// 検査したメッセージの場所と作者。
    pub post: &'a Post,
}

impl Effects for DiscordEffects<'_> {
    async fn send_log_embed(&self, level: Level, embed: CreateEmbed) -> Option<LogMessage> {
        log_channel::send_log_embed(&self.sink, self.post.guild_id, level, embed).await
    }

    async fn edit_log_embed(&self, message: LogMessage, embed: CreateEmbed) -> Result<(), String> {
        let (channel, id) = message;
        channel
            .edit_message(self.sink.http, id, EditMessage::new().embed(embed))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn delete_message(&self) -> Result<(), String> {
        self.sink
            .http
            .delete_message(self.post.channel_id, self.post.message_id, None)
            .await
            .map_err(|e| e.to_string())
    }

    async fn remove_role(&self, role: RoleId) -> Result<(), StripFailure> {
        security::remove_role(self.sink.http, self.post.guild_id, self.post.user_id, role).await
    }

    async fn log_action(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
        colour: Option<u32>,
    ) {
        let sent = log_channel::log_action(
            &self.sink,
            self.post.guild_id,
            level,
            message,
            Some(&self.post.author),
            fields,
            colour,
        )
        .await;
        if let Err(e) = sent {
            debug!("log_action failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 応答チャンネルの判定: 数・数の文字列で読み、読めない値・0 は「無い」。リンクか添付があれば検査する。
    #[test]
    fn plain_chat_posts_are_only_in_the_response_channel() {
        let ch = ChannelId::new(5);
        for setting in [json!(5), json!("5"), json!(" 5 "), json!(5.7)] {
            let g = json!({ "response_channel_id": setting });
            assert!(is_plain_chat_post(Some(&g), ch, 0, 0), "{g}");
        }
        let g = json!({"response_channel_id": 5});
        assert!(!is_plain_chat_post(Some(&g), ch, 1, 0));
        assert!(!is_plain_chat_post(Some(&g), ch, 0, 1));
        assert!(!is_plain_chat_post(Some(&g), ChannelId::new(6), 0, 0));
        for setting in [json!(0), json!("abc"), json!(null), json!([5])] {
            let g = json!({ "response_channel_id": setting });
            assert!(!is_plain_chat_post(Some(&g), ch, 0, 0), "{g}");
        }
        assert!(!is_plain_chat_post(None, ch, 0, 0));
    }

    /// 参加日時は小数の秒まで写すこと（7 日の境を Python と同じに見る）。
    #[test]
    fn timestamps_keep_their_fraction() {
        let ts = Timestamp::parse("2026-11-18T00:05:00.250000+00:00").unwrap();
        let utc = to_utc(ts).unwrap();
        assert_eq!(utc.timestamp(), 1_794_960_300);
        assert_eq!(utc.timestamp_subsec_millis(), 250);
    }

    /// バイパスには @everyone も入れて見ること（剥がすロールには入れない）。
    #[test]
    fn bypass_sees_everyone_but_stripping_does_not() {
        let post = Post {
            guild_id: GuildId::new(1),
            channel_id: ChannelId::new(2),
            message_id: MessageId::new(3),
            user_id: UserId::new(4),
            content: String::new(),
            attachments: Vec::new(),
            roles: vec![RoleId::new(10), RoleId::new(11)],
            joined_at: None,
            voice_channel: None,
            display_name: "x".into(),
            author: Author {
                id: 4,
                name: "x".into(),
                avatar_url: String::new(),
            },
        };
        assert_eq!(
            post.roles_with_everyone(),
            [RoleId::new(1), RoleId::new(10), RoleId::new(11)]
        );
        assert!(!post.roles.contains(&RoleId::new(1)));
    }

    /// 時刻の書き方（日本時間、秒まで）。
    #[test]
    fn times_are_written_in_jst() {
        assert_eq!(jst_text(1_795_565_100.25), "2026-11-25 09:05:00");
        assert_eq!(utc(1_795_565_100.25).timestamp_subsec_millis(), 250);
    }
}
