//! 投稿を DANGEROUS・SUSPICIOUS・SAFE・UNKNOWN に判定する。Python の `services/content_moderation.py`。
//!
//! 決め方は Python と同じ:
//!
//! 1. VirusTotal の結果のうち、いちばん重いもので決める: 危険（10 以上）が 1 つでもあれば DANGEROUS、少しでも
//!    引っかかったものがあれば SUSPICIOUS（Groq には回さない。以前は最初に当たった結果で決めていて、後ろに危険が
//!    あっても SUSPICIOUS になっていた。rust-09 の (f)）
//! 2. Groq の鍵が無ければ SAFE（判定の機能が無い、という扱い。「疑わしい」にはしない）
//! 3. 本文が空白だけで、VirusTotal の結果も無ければ SAFE（尋ねる材料が無い）
//! 4. 同じ材料（本文・状況・VirusTotal の数）の判定を 5 分覚えておき、覚えていればそれ
//! 5. Groq に尋ねる。答えに DANGEROUS があれば DANGEROUS、SUSPICIOUS か WARNING があれば SUSPICIOUS、
//!    それ以外は SAFE。**呼び出しが失敗したら UNKNOWN**（「安全」と混ぜない。覚えもしない）

use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sycs_core::env::Env;
use sycs_core::ttl_cache::TtlCache;
use tracing::warn;

use crate::groq::{Groq, python_is_space};
use crate::security::SpamCheck;
use crate::virustotal::{MALICIOUS_THRESHOLD, VtResult};

/// Groq の用途の名前（同時に送る数・間隔をこの用途で数える）。
pub const BUCKET: &str = "moderation";
/// 判定に使うモデル。
pub const MODEL: &str = "openai/gpt-oss-20b";
/// 1 回の送信の上限（Python の `get_groq_client(timeout=20.0)`）。
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// 覚えておく判定の数。
const CACHE_MAX: usize = 2000;
/// システムへの指示。
pub const SYSTEM_PROMPT: &str =
    "You are a security moderation AI. Reply with only one word: DANGEROUS, SUSPICIOUS, or SAFE.";

/// 判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// 危険。
    Dangerous,
    /// 疑わしい。
    Suspicious,
    /// 安全（または判定の機能が無い）。
    Safe,
    /// 判定できなかった（Groq の呼び出しの失敗）。
    Unknown,
}

impl Verdict {
    /// 表示の名前（理由の印 `GPT:…` とログに使う）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dangerous => "DANGEROUS",
            Self::Suspicious => "SUSPICIOUS",
            Self::Safe => "SAFE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// 判定に渡す材料。
pub struct AssessInput<'a> {
    /// 本文。
    pub text: &'a str,
    /// VirusTotal の結果（リンク・添付の順）。
    pub vt_results: &'a [VtResult],
    /// スパムの判定の結果（当たった条件・回数・いちばん短い間隔）。
    pub spam: &'a SpamCheck,
    /// 参加して 7 日未満か。
    pub is_new_member: bool,
    /// 新しいアカウントなら、その日数のしきい値（「【新しいアカウント】…」の行に書く）。でなければ `None`。
    pub new_account_days: Option<i64>,
}

/// VirusTotal の結果だけで決まる判定。決まらなければ `None`（Groq に尋ねる）。Python の `_vt_verdict`。
///
/// いちばん重い結果で決める。重さの決め方は検査の印（`VT_DANGEROUS`・`VT_SUSPICIOUS`）と同じ: 危険と判定した
/// エンジンの最大が 10 以上なら危険、危険・疑わしいのどちらかが 1 つでもあれば疑わしい。
pub fn vt_verdict(results: &[VtResult]) -> Option<Verdict> {
    let max_malicious = results.iter().map(|r| r.malicious).max()?;
    let max_suspicious = results.iter().map(|r| r.suspicious).max()?;
    if max_malicious >= MALICIOUS_THRESHOLD {
        Some(Verdict::Dangerous)
    } else if max_malicious > 0 || max_suspicious > 0 {
        Some(Verdict::Suspicious)
    } else {
        None
    }
}

/// 状況の行（スパム・高頻度・新規・新しいアカウント）。無ければ空。あれば最後に空行を 1 つ足す。Python の
/// `_context_lines`。
///
/// スパムは、当たった条件ごとに 1 行（何の条件で・何回か。繰り返しは、またがったチャンネルの数も。S3）。
pub fn context_block(
    spam: &SpamCheck,
    is_new_member: bool,
    new_account_days: Option<i64>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    if spam.repeat {
        lines.push(format!(
            "【スパム警告】直近{}秒間に同じ内容を{}回投稿しています（{}チャンネル）。",
            spam.repeat_window, spam.repeat_count, spam.repeat_channels
        ));
    }
    if spam.flood {
        lines.push(format!(
            "【スパム警告】直近{}秒間に{}回メッセージを送信しています。",
            spam.flood_window, spam.flood_count
        ));
    }
    let min_interval = spam.min_interval;
    if min_interval.is_finite() && min_interval < 2.0 {
        lines.push(format!(
            "【高頻度】メッセージ送信間隔が最短{min_interval:.1}秒と非常に短いです。"
        ));
    }
    if is_new_member {
        lines.push("【新規】このユーザーはサーバー参加から7日未満の新規メンバーです。".into());
    }
    if let Some(days) = new_account_days {
        lines.push(format!(
            "【新しいアカウント】このユーザーのアカウントは作成から{days}日未満です。"
        ));
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n\n", lines.join("\n"))
    }
}

/// 利用者としての問い。
pub fn prompt(context_block: &str, text: &str) -> String {
    format!(
        "あなたはDiscordサーバーのセキュリティモデレーションAIです。\n\
         以下の情報をもとに投稿を判定し、DANGEROUS / SUSPICIOUS / SAFE のいずれか1語のみで回答してください。\n\n\
         判定基準:\n\
         - DANGEROUS: フィッシング詐欺、マルウェア拡散、レイド攻撃、明確な規約違反\n\
         - SUSPICIOUS: スパム行動、不審なリンク、新規メンバーによる一方的な宣伝、疑わしい内容\n\
         - SAFE: 通常のコミュニケーション\n\n\
         {context_block}\
         投稿内容:\n{text}"
    )
}

/// Groq へ送る本文。
pub fn request_body(context_block: &str, text: &str) -> Value {
    json!({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt(context_block, text)},
        ],
    })
}

/// 判定を使い回してよい範囲の鍵。本文だけでなく、状況と VirusTotal の数も混ぜる（同じ文でも
/// 状況が違えば別の答えが出うる）。Python の `_verdict_key`。
pub fn verdict_key(text: &str, vt_results: &[VtResult], context_block: &str) -> String {
    let vt_digest = vt_results
        .iter()
        .map(|r| format!("{}/{}", r.malicious, r.suspicious))
        .collect::<Vec<_>>()
        .join("|");
    let material = [context_block, &vt_digest, text].join("\0");
    hex::encode(Sha256::digest(material.as_bytes()))
}

/// Groq の答えを判定にする。大文字にそろえてから、語が含まれるかで見る。
pub fn verdict_of(reply: &str) -> Verdict {
    let upper = reply.to_uppercase();
    if upper.contains("DANGEROUS") {
        Verdict::Dangerous
    } else if upper.contains("SUSPICIOUS") || upper.contains("WARNING") {
        Verdict::Suspicious
    } else {
        Verdict::Safe
    }
}

/// 応答から答えの文を取り出す。Python の `response.choices[0].message.content`（文字列でなければ
/// `.upper()` で落ちて UNKNOWN になる）。
pub fn reply_of(response: &Value) -> Option<&str> {
    response["choices"][0]["message"]["content"].as_str()
}

/// プロセスの中の時刻（秒）。Python の `time.monotonic()`。
fn monotonic() -> f64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_secs_f64()
}

/// 判定する口。1 つを使い回す（判定を覚えておくため）。
pub struct Moderation {
    groq: Arc<Groq>,
    cache: Mutex<TtlCache<String, Verdict>>,
}

impl Moderation {
    /// 作る。`cache_ttl_seconds` は判定を覚えておく長さ。
    pub fn new(groq: Arc<Groq>, cache_ttl_seconds: f64) -> Self {
        Self {
            groq,
            cache: Mutex::new(TtlCache::new(cache_ttl_seconds, CACHE_MAX)),
        }
    }

    /// 環境変数（`MODERATION_CACHE_TTL_SECONDS`、既定 300・下限 10）から作る。
    pub fn from_env(groq: Arc<Groq>, env: &Env) -> Self {
        let ttl = env.int("MODERATION_CACHE_TTL_SECONDS", 300, Some(10), None);
        Self::new(groq, ttl as f64)
    }

    /// 判定する。Python の `gpt_assess`。
    pub async fn assess(&self, input: &AssessInput<'_>) -> Verdict {
        if let Some(verdict) = vt_verdict(input.vt_results) {
            return verdict;
        }
        if !self.groq.has_key() {
            return Verdict::Safe;
        }
        let context = context_block(input.spam, input.is_new_member, input.new_account_days);
        // 判じるものが何も無いなら呼ばない（画像だけの投稿など）。
        if input.text.chars().all(python_is_space) && input.vt_results.is_empty() {
            return Verdict::Safe;
        }
        let key = verdict_key(input.text, input.vt_results, &context);
        if let Some(cached) = self.lock().get(&key, monotonic()) {
            return cached;
        }
        let body = request_body(&context, input.text);
        let reply = match self.groq.chat_completion(BUCKET, TIMEOUT, &body).await {
            Ok(response) => reply_of(&response).map(str::to_string),
            Err(e) => {
                warn!("[SECURITY] Groq判定失敗: {e}");
                // 失敗は覚えない。覚えると、次の同じ投稿も判定されないまま通る。
                return Verdict::Unknown;
            }
        };
        let Some(reply) = reply else {
            warn!("[SECURITY] Groq判定失敗: 応答に答えの文がありません");
            return Verdict::Unknown;
        };
        let verdict = verdict_of(&reply);
        self.lock().set(key, verdict, monotonic());
        verdict
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TtlCache<String, Verdict>> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groq::GroqConfig;

    fn vt(malicious: i64, suspicious: i64) -> VtResult {
        VtResult {
            status: "ok".into(),
            kind: "url".into(),
            malicious,
            suspicious,
            reason: None,
        }
    }

    /// VirusTotal の結果は、いちばん重いもので決まること（後ろの危険も見る、Python の `_vt_verdict`）。
    #[test]
    fn virustotal_decides_by_the_heaviest() {
        assert_eq!(vt_verdict(&[vt(10, 0)]), Some(Verdict::Dangerous));
        assert_eq!(vt_verdict(&[vt(9, 0)]), Some(Verdict::Suspicious));
        assert_eq!(vt_verdict(&[vt(0, 1)]), Some(Verdict::Suspicious));
        assert_eq!(
            vt_verdict(&[vt(0, 0), vt(0, 1), vt(20, 0)]),
            Some(Verdict::Dangerous)
        );
        assert_eq!(
            vt_verdict(&[vt(3, 0), vt(0, 0), vt(10, 2)]),
            Some(Verdict::Dangerous)
        );
        assert_eq!(
            vt_verdict(&[vt(0, 0), vt(-1, -1), vt(9, 0)]),
            Some(Verdict::Suspicious)
        );
        // ダウンロードの失敗（-1）は引っかかっていない。
        assert_eq!(vt_verdict(&[vt(-1, -1), vt(0, 0)]), None);
        assert_eq!(vt_verdict(&[]), None);
    }

    fn spam(min_interval: f64) -> SpamCheck {
        SpamCheck {
            min_interval,
            ..SpamCheck::default()
        }
    }

    /// 状況の行の書き方と条件（当たった条件ごとのスパム・2 秒未満・新規・新しいアカウント）。
    #[test]
    fn the_context_lines_match_python() {
        let quiet = SpamCheck {
            repeat_count: 2,
            flood_count: 7,
            ..SpamCheck::default()
        };
        assert_eq!(context_block(&quiet, false, None), "");
        let both = SpamCheck {
            repeat: true,
            repeat_count: 3,
            repeat_channels: 2,
            flood: true,
            flood_count: 8,
            min_interval: 1.25,
            ..SpamCheck::default()
        };
        assert_eq!(
            context_block(&both, true, Some(7)),
            "【スパム警告】直近60秒間に同じ内容を3回投稿しています（2チャンネル）。\n\
             【スパム警告】直近10秒間に8回メッセージを送信しています。\n\
             【高頻度】メッセージ送信間隔が最短1.2秒と非常に短いです。\n\
             【新規】このユーザーはサーバー参加から7日未満の新規メンバーです。\n\
             【新しいアカウント】このユーザーのアカウントは作成から7日未満です。\n\n"
        );
        assert_eq!(context_block(&spam(2.0), false, None), "");
        assert_eq!(
            context_block(&spam(1.95), false, None),
            "【高頻度】メッセージ送信間隔が最短1.9秒と非常に短いです。\n\n"
        );
    }

    /// 小数 1 桁の丸めが Python の `f"{x:.1f}"` と同じこと（Python 3.13 の出力。ちょうど半分は偶数へ）。
    #[test]
    fn one_decimal_rounds_like_python() {
        for (x, want) in [
            (1.25, "1.2"),
            (1.95, "1.9"),
            (0.25, "0.2"),
            (0.75, "0.8"),
            (1.75, "1.8"),
            (0.05, "0.1"),
            (0.15, "0.1"),
            (0.35, "0.3"),
            (1.45, "1.4"),
            (0.45, "0.5"),
            (0.85, "0.8"),
            (1.05, "1.1"),
        ] {
            assert_eq!(format!("{x:.1}"), want, "{x}");
        }
    }

    /// 問いの形（状況の行は「投稿内容」の前）。
    #[test]
    fn the_prompt_matches_python() {
        let p = prompt("【新規】x\n\n", "本文");
        assert!(p.starts_with(
            "あなたはDiscordサーバーのセキュリティモデレーションAIです。\n以下の情報"
        ));
        assert!(p.ends_with("- SAFE: 通常のコミュニケーション\n\n【新規】x\n\n投稿内容:\n本文"));
        let body = request_body("", "hi");
        assert_eq!(body["model"], "openai/gpt-oss-20b");
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["content"], prompt("", "hi"));
    }

    /// 答えの読み方（大文字にそろえて、含まれるかで見る）。
    #[test]
    fn replies_become_verdicts() {
        assert_eq!(verdict_of("dangerous"), Verdict::Dangerous);
        assert_eq!(verdict_of("NOT DANGEROUS, SAFE"), Verdict::Dangerous);
        assert_eq!(verdict_of("Suspicious."), Verdict::Suspicious);
        assert_eq!(verdict_of("warning"), Verdict::Suspicious);
        assert_eq!(verdict_of("ſuſpiciouſ"), Verdict::Suspicious);
        assert_eq!(verdict_of("SAFE"), Verdict::Safe);
        assert_eq!(verdict_of(""), Verdict::Safe);
        assert_eq!(verdict_of("わかりません"), Verdict::Safe);
    }

    /// 答えの文は choices[0].message.content の文字列だけ。
    #[test]
    fn the_reply_is_the_first_choice_content() {
        let ok = json!({"choices": [{"message": {"content": "SAFE"}}]});
        assert_eq!(reply_of(&ok), Some("SAFE"));
        for bad in [
            json!({"choices": []}),
            json!({"choices": "abc"}),
            json!({"choices": [{"message": {"content": null}}]}),
            json!({"choices": [{"message": {"content": 1}}]}),
            json!({"choices": [{"message": "SAFE"}]}),
            json!(null),
            json!([1]),
        ] {
            assert_eq!(reply_of(&bad), None, "{bad}");
        }
    }

    /// 鍵は本文・状況・VirusTotal の数のどれが違っても変わること。
    #[test]
    fn the_cache_key_covers_every_material() {
        let base = verdict_key("a", &[vt(0, 0)], "");
        assert_eq!(base, verdict_key("a", &[vt(0, 0)], ""));
        assert_ne!(base, verdict_key("b", &[vt(0, 0)], ""));
        assert_ne!(base, verdict_key("a", &[vt(0, 1)], ""));
        assert_ne!(base, verdict_key("a", &[], ""));
        assert_ne!(base, verdict_key("a", &[vt(0, 0)], "x"));
        // 区切りが入るので、境目をずらしても同じにならない。
        assert_ne!(verdict_key("ab", &[], "c"), verdict_key("b", &[], "ca"));
    }

    fn moderation(key: Option<&str>) -> Moderation {
        let groq = Groq::new(GroqConfig {
            api_key: key.map(str::to_string),
            // 呼んだら必ず失敗する場所（呼ばないはずの経路で呼んだら UNKNOWN になって分かる）。
            base_url: "http://127.0.0.1:9".into(),
            max_concurrent: 3,
            min_interval: 0.0,
            max_retries: 0,
            retry_base_delay: 0.5,
            retry_max_delay: 0.5,
            max_retry_after: 30.0,
        });
        Moderation::new(Arc::new(groq), 300.0)
    }

    static QUIET: LazyLock<SpamCheck> = LazyLock::new(SpamCheck::default);

    fn input<'a>(text: &'a str, vt_results: &'a [VtResult]) -> AssessInput<'a> {
        AssessInput {
            text,
            vt_results,
            spam: &QUIET,
            is_new_member: false,
            new_account_days: None,
        }
    }

    /// 鍵が無ければ SAFE、VirusTotal で決まれば呼ばない、空白だけの本文は呼ばないこと。
    #[tokio::test]
    async fn some_paths_never_call_groq() {
        assert_eq!(
            moderation(None).assess(&input("危ないかも", &[])).await,
            Verdict::Safe
        );
        let m = moderation(Some("k"));
        assert_eq!(
            m.assess(&input("x", &[vt(12, 0)])).await,
            Verdict::Dangerous
        );
        // Python の strip() は U+001C〜U+001F も落とす。
        for blank in ["", "  \n", "\u{1C}\u{3000}"] {
            assert_eq!(
                m.assess(&input(blank, &[])).await,
                Verdict::Safe,
                "{blank:?}"
            );
        }
        // 材料があれば呼ぶ（ここでは呼べないので UNKNOWN）。
        assert_eq!(m.assess(&input("x", &[])).await, Verdict::Unknown);
        assert_eq!(m.assess(&input(" ", &[vt(0, 0)])).await, Verdict::Unknown);
    }

    /// 失敗（UNKNOWN）は覚えないこと。
    #[tokio::test]
    async fn failures_are_not_remembered() {
        let m = moderation(Some("k"));
        assert_eq!(m.assess(&input("x", &[])).await, Verdict::Unknown);
        assert!(m.lock().is_empty());
    }
}
