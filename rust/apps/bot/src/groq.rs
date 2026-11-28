//! Groq（チャットの補完）の呼び出し。Python の `services/groq_client.py` と、Python が使う groq SDK 1.7.0
//! の送り方。
//!
//! Groq の鍵は、投稿の判定・会話・ニュースの要約・相場の予測で共有している。用途（bucket）ごとに
//! 同時に送る数と、送る間隔の下限を守る（ある用途の連打が、他の用途を回数制限に巻き込まないように）。
//!
//! 再試行はここだけで受け持つ（Python と同じ。Python は groq SDK の再試行を切ってある〔`max_retries=0`〕）:
//!
//! - 回数制限（429）は必ず再試行する
//! - ほかは、SDK が再試行していたもの: 接続の失敗・時間切れ、`x-should-retry` が true のもの、無ければ
//!   408・409・5xx（`x-should-retry` が false なら再試行しない）
//! - 待ちは `retry-after`（秒。上限 `GROQ_MAX_RETRY_AFTER_SECONDS`、既定 30 秒）、無い・読めないなら 2 秒・
//!   4 秒…（上限 20 秒）。どちらにも 0〜0.5 秒の揺らぎを足す
//!
//! 1 回の呼び出しで送るのは、最大 `GROQ_MAX_RETRIES` + 1 回（既定 3 回）。以前は SDK の再試行（2 回）と
//! こちらの再試行が掛け算になり、回数制限が続くと 1 回で 9 回送っていた。`retry-after` にも上限が無く、
//! 極端な値が来ると枠を持ったまま待ち続けた（rust-09 の (g)）。待っている間も同時に送る数の枠は持ったまま
//! （Python と同じ）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use sycs_core::env::Env;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// 本番の API の場所（groq SDK の既定）。
pub const DEFAULT_BASE_URL: &str = "https://api.groq.com";

/// 設定。環境変数の名前・既定・下限は Python と同じ。
#[derive(Clone)]
pub struct GroqConfig {
    /// API の鍵（`GROQ_API_KEY`）。無ければ呼ばない。
    pub api_key: Option<String>,
    /// API の場所（`GROQ_BASE_URL`、groq SDK と同じ変数。テストで偽物に向ける）。
    pub base_url: String,
    /// 用途ごとに同時に送る数（`GROQ_MAX_CONCURRENT_REQUESTS`、既定 3・下限 1）。
    pub max_concurrent: usize,
    /// 用途ごとの送る間隔の下限（秒、`GROQ_MIN_REQUEST_INTERVAL_SECONDS`、既定 0.25・下限 0）。
    pub min_interval: f64,
    /// 再試行の回数（`GROQ_MAX_RETRIES`、既定 2・下限 0）。1 回の呼び出しで送るのは、これ + 1 回まで。
    pub max_retries: u32,
    /// 再試行の待ちの始まり（秒、`GROQ_RETRY_BASE_DELAY_SECONDS`、既定 2・下限 0.5）。
    pub retry_base_delay: f64,
    /// 再試行の待ちの上限（秒、`GROQ_RETRY_MAX_DELAY_SECONDS`、既定 20・下限は始まりの値）。
    pub retry_max_delay: f64,
    /// `retry-after` に従って待つ長さの上限（秒、`GROQ_MAX_RETRY_AFTER_SECONDS`、既定 30・下限 0）。
    pub max_retry_after: f64,
}

/// 鍵は表示しない（設定をログに出しても漏れないように）。
impl std::fmt::Debug for GroqConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroqConfig")
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .field("base_url", &self.base_url)
            .field("max_concurrent", &self.max_concurrent)
            .finish_non_exhaustive()
    }
}

impl GroqConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        let base = env.float("GROQ_RETRY_BASE_DELAY_SECONDS", 2.0, Some(0.5), None);
        Self {
            api_key: env.raw("GROQ_API_KEY"),
            // SDK は空文字をそのまま場所にする（送れずに失敗する）。こちらは既定へ倒す。
            base_url: env
                .raw("GROQ_BASE_URL")
                .unwrap_or_else(|| DEFAULT_BASE_URL.into()),
            max_concurrent: usize::try_from(env.int(
                "GROQ_MAX_CONCURRENT_REQUESTS",
                3,
                Some(1),
                None,
            ))
            .unwrap_or(1),
            min_interval: env.float("GROQ_MIN_REQUEST_INTERVAL_SECONDS", 0.25, Some(0.0), None),
            max_retries: u32::try_from(env.int("GROQ_MAX_RETRIES", 2, Some(0), None)).unwrap_or(0),
            retry_base_delay: base,
            retry_max_delay: env.float("GROQ_RETRY_MAX_DELAY_SECONDS", 20.0, Some(base), None),
            max_retry_after: env.float("GROQ_MAX_RETRY_AFTER_SECONDS", 30.0, Some(0.0), None),
        }
    }
}

/// 呼び出しの失敗。
#[derive(Debug)]
pub enum GroqError {
    /// 鍵が無い。
    NoKey,
    /// 4xx・5xx（再試行のあと）。
    Status {
        /// 状態の番号。
        status: u16,
        /// `retry-after` の値（再試行の待ちに使う）。
        retry_after: Option<String>,
        /// `x-should-retry` の値（再試行するかに使う。SDK と同じ）。
        should_retry: Option<String>,
        /// 本文。
        body: String,
    },
    /// 時間切れ（再試行のあと）。
    Timeout,
    /// 接続などの失敗（再試行のあと）。
    Connection(String),
    /// 応答を JSON として読めなかった。
    Decode(String),
}

impl std::fmt::Display for GroqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKey => f.write_str("GROQ_API_KEY が設定されていない。"),
            // SDK の APIStatusError と同じ書き方。
            Self::Status { status, body, .. } => write!(f, "Error code: {status} - {body}"),
            Self::Timeout => f.write_str("Request timed out."),
            Self::Connection(e) => write!(f, "Connection error. ({e})"),
            Self::Decode(e) => write!(f, "応答を読めませんでした: {e}"),
        }
    }
}

impl GroqError {
    /// こちらで再試行する失敗か。Python の `_is_retryable`。
    ///
    /// 回数制限（429）は必ず再試行する。ほかは SDK の再試行を切る前に SDK が再試行していたもの（groq SDK の
    /// `_should_retry`）: 接続の失敗・時間切れ、`x-should-retry` が true のもの、無ければ 408・409・5xx。
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Status { status: 429, .. } | Self::Timeout | Self::Connection(_) => true,
            Self::Status {
                status,
                should_retry,
                ..
            } => sdk_should_retry(*status, should_retry.as_deref()),
            Self::NoKey | Self::Decode(_) => false,
        }
    }
}

/// 用途ごとの枠と、最後に送った時刻。
struct Bucket {
    gate: Semaphore,
    last_call: tokio::sync::Mutex<Option<Instant>>,
}

/// Groq を呼ぶ口。1 つを使い回す（用途ごとの枠を共有するため）。
pub struct Groq {
    config: GroqConfig,
    http: reqwest::Client,
    buckets: Mutex<HashMap<String, Arc<Bucket>>>,
}

impl Groq {
    /// 作る。
    pub fn new(config: GroqConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("sycs-bot (groq)")
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// 鍵があるか（無ければ呼べない）。
    pub fn has_key(&self) -> bool {
        self.config.api_key.is_some()
    }

    fn bucket(&self, name: &str) -> Arc<Bucket> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(buckets.entry(name.to_string()).or_insert_with(|| {
            Arc::new(Bucket {
                gate: Semaphore::new(self.config.max_concurrent),
                last_call: tokio::sync::Mutex::new(None),
            })
        }))
    }

    /// チャットの補完を呼ぶ。Python の `create_chat_completion`。`timeout` は 1 回の送信の上限
    /// （SDK の `timeout`。用途ごとに違う）。
    ///
    /// 送るのは最大 `max_retries` + 1 回（再試行は [`GroqError::is_retryable`] が真の失敗だけ）。
    pub async fn chat_completion(
        &self,
        bucket: &str,
        timeout: Duration,
        body: &Value,
    ) -> Result<Value, GroqError> {
        let Some(api_key) = self.config.api_key.as_deref() else {
            return Err(GroqError::NoKey);
        };
        let slot = self.bucket(bucket);
        // 待っている間も枠は持ったまま（Python の `async with semaphore` と同じ）。
        let _permit = slot.gate.acquire().await;
        let mut attempt = 0;
        loop {
            self.respect_min_interval(&slot).await;
            let error = match self.send_once(api_key, timeout, body).await {
                Err(error) if attempt < self.config.max_retries && error.is_retryable() => error,
                other => return other,
            };
            let retry_after = match &error {
                GroqError::Status { retry_after, .. } => retry_after.as_deref(),
                _ => None,
            };
            let delay = rate_limit_delay(
                attempt,
                retry_after,
                self.config.retry_base_delay,
                self.config.retry_max_delay,
                self.config.max_retry_after,
            ) + 0.5 * unit_random();
            if matches!(error, GroqError::Status { status: 429, .. }) {
                warn!(
                    "Groq APIレート制限を検知。{delay:.1}秒待機してリトライ bucket={bucket} attempt={}/{}",
                    attempt + 1,
                    self.config.max_retries
                );
            } else {
                warn!(
                    "Groq APIの一時的な失敗を検知（{}）。{delay:.1}秒待機してリトライ bucket={bucket} attempt={}/{}",
                    failure_kind(&error),
                    attempt + 1,
                    self.config.max_retries
                );
            }
            debug!("再試行する失敗: {error}");
            tokio::time::sleep(seconds(delay)).await;
            attempt += 1;
        }
    }

    /// 前に送ってから間隔の下限が経つまで待つ。Python の `_respect_min_interval`。
    ///
    /// 「経った時間を見る」と「待って時刻を書く」を 1 つの錠の中でする。分けると、同時に来た
    /// 呼び出しが全員「もう十分経った」を見て素通りする。
    ///
    /// 返すのは「送ってよくなった時刻」（次の呼び出しはここから間隔を数える）。
    async fn respect_min_interval(&self, slot: &Bucket) -> Instant {
        if self.config.min_interval <= 0.0 {
            return Instant::now();
        }
        let mut last = slot.last_call.lock().await;
        if let Some(at) = *last {
            let wait = self.config.min_interval - at.elapsed().as_secs_f64();
            if wait > 0.0 {
                tokio::time::sleep(seconds(wait)).await;
            }
        }
        let now = Instant::now();
        *last = Some(now);
        now
    }

    /// 1 回だけ送る（SDK の再試行は無い。Python の `AsyncGroq(max_retries=0)` の `create`）。
    async fn send_once(
        &self,
        api_key: &str,
        timeout: Duration,
        body: &Value,
    ) -> Result<Value, GroqError> {
        let url = format!(
            "{}/openai/v1/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );
        let sent = self
            .http
            .post(&url)
            .bearer_auth(api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .timeout(timeout)
            .body(body.to_string())
            .send()
            .await;
        // SDK は本文まで読み終えてから状態を見る（本文の途中の失敗も、接続の失敗として再試行する）。
        let outcome = match sent {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                response.bytes().await.map(|b| (status, headers, b))
            }
            Err(e) => Err(e),
        };
        let (status, headers, bytes) = outcome.map_err(|e| {
            if e.is_timeout() {
                GroqError::Timeout
            } else {
                GroqError::Connection(e.to_string())
            }
        })?;
        if status >= 400 {
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            return Err(GroqError::Status {
                status,
                retry_after: header("retry-after"),
                should_retry: header("x-should-retry"),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|e| GroqError::Decode(e.to_string()))
    }
}

/// 再試行のログに出す、失敗の種類。
fn failure_kind(error: &GroqError) -> String {
    match error {
        GroqError::Status { status, .. } => format!("状態 {status}"),
        GroqError::Timeout => "時間切れ".into(),
        GroqError::Connection(_) => "接続の失敗".into(),
        GroqError::NoKey | GroqError::Decode(_) => "再試行しない失敗".into(),
    }
}

/// SDK が再試行していた応答か。groq SDK の `_should_retry`（`x-should-retry` があればそれに従う）。
pub fn sdk_should_retry(status: u16, x_should_retry: Option<&str>) -> bool {
    match x_should_retry {
        Some("true") => return true,
        Some("false") => return false,
        _ => {}
    }
    matches!(status, 408 | 409 | 429) || status >= 500
}

/// 再試行の待ち（秒、揺らぎの前）。Python の `create_chat_completion` の待ち方と `_retry_after_seconds`。
///
/// `retry-after`（秒）があればそれ（負・NaN は 0、`max_retry_after` で頭打ち）。無い・読めないなら始まりの値から
/// 倍々で、上限まで。
pub fn rate_limit_delay(
    attempt: u32,
    retry_after: Option<&str>,
    base: f64,
    max: f64,
    max_retry_after: f64,
) -> f64 {
    match retry_after.and_then(python_float) {
        // Python の min(上限, max(0.0, x))（NaN も 0 になる）。
        Some(after) => {
            if after > 0.0 {
                after.min(max_retry_after)
            } else {
                0.0
            }
        }
        None => (base * 2f64.powi(attempt.min(1000) as i32)).min(max),
    }
}

/// Python の `float(text)`（ASCII の範囲）。前後の ASCII の空白（`\v` も含む）を許し、`_` は数字の間だけ
/// 許す。`inf`・`infinity`・`nan`（大文字・小文字を問わず、符号つきも）を読む。
///
/// ASCII 以外は読まない（Python は全角の数字なども読む）。ヘッダーの値は ASCII しか届かない
/// （reqwest の `to_str` が ASCII 以外を拒む）ので、ここで差は出ない。
pub fn python_float(text: &str) -> Option<f64> {
    let t = text.trim_matches([' ', '\t', '\n', '\u{0B}', '\u{0C}', '\r']);
    let chars: Vec<char> = t.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_' {
            let digit = |j: Option<usize>| {
                j.and_then(|j| chars.get(j))
                    .is_some_and(|c| c.is_ascii_digit())
            };
            if !digit(i.checked_sub(1)) || !digit(Some(i + 1)) {
                return None;
            }
        }
    }
    let cleaned: String = chars.iter().filter(|c| **c != '_').collect();
    // Rust の f64 の読み方は、Python の float の文法（符号・小数点・指数・inf・nan）と同じ。
    if cleaned.is_empty() || !cleaned.is_ascii() {
        return None;
    }
    cleaned.parse().ok()
}

/// Python の `str.isspace`（`str.strip()` が落とす文字）。Rust の空白に、区切りの制御文字
/// （U+001C〜U+001F）を足したもの。
pub fn python_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1C}'..='\u{1F}').contains(&c)
}

/// 0 以上 1 未満の乱数（揺らぎに使う。暗号には使わない）。
fn unit_random() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// 秒数を待ち時間にする。大きすぎる・無限大は「ずっと」（Python の `asyncio.sleep(inf)` と同じ）。
fn seconds(value: f64) -> Duration {
    Duration::try_from_secs_f64(value.max(0.0)).unwrap_or(Duration::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Python の float() と同じものを読み、同じものを拒むこと（Python 3.13 で確かめた値）。
    #[test]
    fn python_float_reads_what_python_reads() {
        let ok: &[(&str, f64)] = &[
            ("1", 1.0),
            (" 2.5 ", 2.5),
            ("+3", 3.0),
            ("-0.5", -0.5),
            ("1_000", 1000.0),
            ("1_0.2_5", 10.25),
            ("1e3", 1000.0),
            ("1E-2", 0.01),
            (".5", 0.5),
            ("5.", 5.0),
            ("\t7\n", 7.0),
            ("\u{0B}8\u{0C}", 8.0),
            ("1e1_0", 1e10),
        ];
        for (text, want) in ok {
            assert_eq!(python_float(text), Some(*want), "{text:?}");
        }
        for text in ["inf", "-Infinity", "+INF"] {
            assert!(python_float(text).unwrap().is_infinite(), "{text}");
        }
        assert!(python_float("nan").unwrap().is_nan());
        for text in [
            "",
            " ",
            "abc",
            "1__0",
            "_1",
            "1_",
            "1_.5",
            "1._5",
            "0x10",
            "1,5",
            "1 2",
            "e5",
            "inf_",
            "1_e5",
            // str.strip() は落とすが、float() は落とさない区切りの制御文字。
            "\u{1C}8\u{1F}",
        ] {
            assert_eq!(python_float(text), None, "{text:?}");
        }
    }

    /// x-should-retry に従い、無ければ 408・409・429・5xx だけ再試行すること。
    #[test]
    fn the_sdk_retries_the_same_statuses() {
        for s in [408, 409, 429, 500, 502, 503, 599] {
            assert!(sdk_should_retry(s, None), "{s}");
        }
        for s in [400, 401, 403, 404, 422] {
            assert!(!sdk_should_retry(s, None), "{s}");
        }
        assert!(sdk_should_retry(400, Some("true")));
        assert!(!sdk_should_retry(500, Some("false")));
        // true・false 以外は無いのと同じ。
        assert!(sdk_should_retry(500, Some("TRUE")));
        assert!(!sdk_should_retry(400, Some("yes")));
    }

    /// こちらで再試行する失敗: 回数制限は x-should-retry に関わらず必ず、時間切れ・接続の失敗も。ほかは SDK と同じ。
    #[test]
    fn retryable_failures_follow_python() {
        let status = |status: u16, should: Option<&str>| GroqError::Status {
            status,
            retry_after: None,
            should_retry: should.map(str::to_string),
            body: String::new(),
        };
        assert!(status(429, Some("false")).is_retryable());
        assert!(status(503, None).is_retryable());
        assert!(status(408, None).is_retryable());
        assert!(!status(500, Some("false")).is_retryable());
        assert!(status(400, Some("true")).is_retryable());
        assert!(!status(400, None).is_retryable());
        assert!(!status(401, None).is_retryable());
        assert!(GroqError::Timeout.is_retryable());
        assert!(GroqError::Connection("reset".into()).is_retryable());
        assert!(!GroqError::Decode("eof".into()).is_retryable());
        assert!(!GroqError::NoKey.is_retryable());
    }

    /// 再試行の待ち: retry-after（負・NaN は 0、上限 30 秒で頭打ち）か、始まりの値から倍々で上限まで。
    #[test]
    fn retries_wait_like_the_python_wrapper() {
        assert_eq!(rate_limit_delay(0, Some("7"), 2.0, 20.0, 30.0), 7.0);
        assert_eq!(rate_limit_delay(0, Some("30"), 2.0, 20.0, 30.0), 30.0);
        assert_eq!(rate_limit_delay(0, Some("120"), 2.0, 20.0, 30.0), 30.0);
        assert_eq!(rate_limit_delay(0, Some("100000"), 2.0, 20.0, 30.0), 30.0);
        assert_eq!(rate_limit_delay(0, Some("inf"), 2.0, 20.0, 30.0), 30.0);
        assert_eq!(rate_limit_delay(0, Some("120"), 2.0, 20.0, 0.0), 0.0);
        assert_eq!(rate_limit_delay(0, Some("-3"), 2.0, 20.0, 30.0), 0.0);
        assert_eq!(rate_limit_delay(0, Some("nan"), 2.0, 20.0, 30.0), 0.0);
        assert_eq!(rate_limit_delay(0, None, 2.0, 20.0, 30.0), 2.0);
        assert_eq!(rate_limit_delay(1, Some("soon"), 2.0, 20.0, 30.0), 4.0);
        assert_eq!(rate_limit_delay(4, None, 2.0, 20.0, 30.0), 20.0);
    }

    /// 既定値が Python と同じであること。上限の下限は始まりの値。
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
        let c = GroqConfig::from_env(&env(&[]));
        assert_eq!(c.api_key, None);
        assert_eq!(c.base_url, "https://api.groq.com");
        assert_eq!(
            (c.max_concurrent, c.min_interval, c.max_retries),
            (3, 0.25, 2)
        );
        assert_eq!((c.retry_base_delay, c.retry_max_delay), (2.0, 20.0));
        assert_eq!(c.max_retry_after, 30.0);
        let c = GroqConfig::from_env(&env(&[
            ("GROQ_RETRY_BASE_DELAY_SECONDS", "30"),
            ("GROQ_MAX_CONCURRENT_REQUESTS", "0"),
            ("GROQ_API_KEY", " k "),
            ("GROQ_MAX_RETRY_AFTER_SECONDS", "-5"),
        ]));
        assert_eq!((c.retry_base_delay, c.retry_max_delay), (30.0, 30.0));
        assert_eq!(c.max_retry_after, 0.0, "下限は 0");
        assert_eq!(c.max_concurrent, 1);
        assert_eq!(c.api_key.as_deref(), Some("k"));
        let set = GroqConfig::from_env(&env(&[("GROQ_MAX_RETRY_AFTER_SECONDS", "7.5")]));
        assert_eq!(set.max_retry_after, 7.5);
    }

    fn groq(min_interval: f64) -> Arc<Groq> {
        Arc::new(Groq::new(GroqConfig {
            api_key: None,
            base_url: String::new(),
            max_concurrent: 3,
            min_interval,
            max_retries: 0,
            retry_base_delay: 0.5,
            retry_max_delay: 0.5,
            max_retry_after: 30.0,
        }))
    }

    /// 同時に来た呼び出しも、送る間隔の下限だけ空けて通すこと。
    ///
    /// 送ってよくなった時刻そのもので確かめる。偽物のサーバーに届いた時刻で測ると、遅い環境（CI は
    /// 本番の CPU のふりで動かす）では、送り出しが空いていても届く間隔が詰まって見える。
    #[tokio::test]
    async fn calls_are_spaced_by_the_minimum_interval() {
        let groq = groq(0.05);
        let slot = groq.bucket("t");
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let (groq, slot) = (Arc::clone(&groq), Arc::clone(&slot));
            set.spawn(async move { groq.respect_min_interval(&slot).await });
        }
        let mut passed = Vec::new();
        while let Some(at) = set.join_next().await {
            passed.push(at.unwrap());
        }
        passed.sort();
        for pair in passed.windows(2) {
            let gap = pair[1] - pair[0];
            // タイマーの刻み（1 ミリ秒）のぶんだけ余裕を見る。
            assert!(gap >= Duration::from_millis(48), "間隔が詰まった: {gap:?}");
        }
    }

    /// 間隔の下限が 0 なら待たないこと。
    #[tokio::test]
    async fn no_minimum_interval_means_no_waiting() {
        let groq = groq(0.0);
        let slot = groq.bucket("t");
        groq.respect_min_interval(&slot).await;
        groq.respect_min_interval(&slot).await;
        // 待たない経路は、最後に送った時刻にも触らない。
        assert!(slot.last_call.lock().await.is_none());
    }

    /// 枠と間隔は用途ごとに別で、同じ用途では使い回すこと。
    #[test]
    fn buckets_are_per_purpose() {
        let groq = groq(0.25);
        assert!(Arc::ptr_eq(
            &groq.bucket("moderation"),
            &groq.bucket("moderation")
        ));
        assert!(!Arc::ptr_eq(
            &groq.bucket("moderation"),
            &groq.bucket("chat")
        ));
        assert_eq!(groq.bucket("chat").gate.available_permits(), 3);
    }

    /// 乱数は 0 以上 1 未満で、毎回同じではないこと。
    #[test]
    fn the_jitter_is_a_unit_random() {
        let values: Vec<f64> = (0..50).map(|_| unit_random()).collect();
        assert!(values.iter().all(|v| (0.0..1.0).contains(v)));
        assert!(values.windows(2).any(|w| w[0] != w[1]));
    }

    /// 無限大の待ちで落ちないこと（「ずっと」になる）。
    #[test]
    fn infinite_waits_do_not_panic() {
        assert_eq!(seconds(f64::INFINITY), Duration::MAX);
        assert_eq!(seconds(-1.0), Duration::ZERO);
        assert_eq!(seconds(0.25), Duration::from_millis(250));
    }
}
