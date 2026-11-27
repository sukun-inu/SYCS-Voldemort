//! VirusTotal でリンクと添付ファイルを調べる。Python の `services/virustotal_service.py`（と、Python が使う
//! vt-py 0.22.0 の送り方）。
//!
//! 流れは Python と同じ:
//!
//! 1. 取りに行く前に公開アドレスかを確かめる（だめなら `skip`・`unsafe_url:…`）
//! 2. 種類（Content-Type）を HEAD で、だめなら GET で確かめる。リダイレクトは 1 段ずつ、そのたびに確かめる
//! 3. 画像（`image/`）は調べない。ファイル（`application/` など）は大きさの上限つきで落としてファイルとして
//!    調べる（先にハッシュで照会し、無ければアップロード、同時にスキャン中なら既存の結果を取り直す）。
//!    それ以外は URL として調べる
//! 4. URL の結果は覚えておく（成功は 6 時間、失敗は短く。到達できない相手をメッセージのたびに叩き直さない）
//!
//! 解析は終わるまで間隔を空けて問い合わせ続ける（vt-py と同じく全体の上限は無い。見直しの候補として
//! 控えてある）。失敗はどれも `status=error` の結果として返し、呼ぶ側の検査を止めない。
//!
//! 結果の `reason` の書き方（`('QuotaExceededError', 'quota')` など）も Python と同じ形にしてある。

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sycs_core::env::Env;
use sycs_core::ttl_cache::TtlCache;
use sycs_core::url_safety::{self, UrlSafetyError};
use tracing::{error, info, warn};

/// これ以上のエンジンが危険と判定したら「危険」。Python の `MALICIOUS_THRESHOLD`。
pub const MALICIOUS_THRESHOLD: i64 = 10;
/// URL の結果を覚えておく長さ（6 時間）と件数。
const CACHE_TTL_SECONDS: f64 = 6.0 * 3600.0;
const CACHE_MAX: usize = 5000;
const FAILURE_CACHE_MAX: usize = 1000;
/// 種類の確認とダウンロードの待ち時間。Python が使う aiohttp の既定（全体で 5 分）と同じ。
const WEB_TIMEOUT: Duration = Duration::from_secs(300);
/// vt-py が解析の終わりを問い合わせる間隔。
pub const POLL_INTERVAL: Duration = Duration::from_secs(20);

/// 設定。環境変数の名前・既定・下限は Python と同じ。
#[derive(Clone, Debug)]
pub struct VtConfig {
    /// API の鍵（`VIRUSTOTAL_API_KEY`）。無ければ調べずに `skip`。
    pub api_key: Option<String>,
    /// API の 1 回の要求の待ち時間（`VT_SCAN_TIMEOUT_SECONDS`、既定 30・下限 5）。
    pub scan_timeout: Duration,
    /// 失敗を覚えておく長さ（`VT_FAILURE_CACHE_TTL_SECONDS`、既定 300・下限 10）。
    pub failure_ttl_seconds: f64,
    /// たどるリダイレクトの数（`VT_MAX_REDIRECTS`、既定 5・下限 0）。
    pub max_redirects: u32,
    /// 落とすファイルの上限（`VT_MAX_DOWNLOAD_BYTES`、既定 20MiB・下限 1）。
    pub max_download_bytes: u64,
    /// API の場所（本番は `https://www.virustotal.com`。テストで偽物に向ける）。
    pub api_base: String,
    /// 解析の終わりを問い合わせる間隔（本番は 20 秒。テストで短くする）。
    pub poll_interval: Duration,
}

impl VtConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        let int = |key: &str, default: i64, min: i64| env.int(key, default, Some(min), None);
        Self {
            api_key: env.raw("VIRUSTOTAL_API_KEY"),
            scan_timeout: Duration::from_secs(int("VT_SCAN_TIMEOUT_SECONDS", 30, 5) as u64),
            failure_ttl_seconds: int("VT_FAILURE_CACHE_TTL_SECONDS", 300, 10) as f64,
            max_redirects: int("VT_MAX_REDIRECTS", 5, 0) as u32,
            max_download_bytes: int("VT_MAX_DOWNLOAD_BYTES", 20 * 1024 * 1024, 1) as u64,
            api_base: "https://www.virustotal.com".into(),
            poll_interval: POLL_INTERVAL,
        }
    }
}

/// 1 件の結果。Python の結果の辞書と同じ中身。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VtResult {
    /// `ok`・`cached`・`conflict_fallback`・`skip`・`error`。
    pub status: String,
    /// `url`・`file`・`image`。
    pub kind: String,
    /// 危険と判定したエンジンの数（ダウンロードの失敗は -1）。
    pub malicious: i64,
    /// 疑わしいと判定したエンジンの数。
    pub suspicious: i64,
    /// `skip`・`error` の理由。
    pub reason: Option<String>,
}

impl VtResult {
    fn new(
        status: &str,
        kind: &str,
        malicious: i64,
        suspicious: i64,
        reason: Option<String>,
    ) -> Self {
        Self {
            status: status.into(),
            kind: kind.into(),
            malicious,
            suspicious,
            reason,
        }
    }

    fn stats(status: &str, kind: &str, stats: &Value) -> Self {
        let n = |k: &str| stats.get(k).and_then(Value::as_i64).unwrap_or(0);
        Self::new(status, kind, n("malicious"), n("suspicious"), None)
    }
}

/// 取りに行く前の安全確認。本番は公開アドレスの検査（`url_safety`）。
pub type AddressCheck = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<(), UrlSafetyError>> + Send>>
        + Send
        + Sync,
>;

/// 本番の安全確認（外向けの http(s) で、行き先が全部公開アドレス）。
pub fn public_only() -> AddressCheck {
    Arc::new(|url: String| {
        Box::pin(async move { url_safety::validate_public_http_url(&url, true).await })
    })
}

/// VirusTotal の API の失敗。表示は Python の `str(APIError(code, message))` と同じ形。
#[derive(Debug)]
enum ApiError {
    Api { code: String, message: String },
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api { code, message } => write!(f, "('{code}', '{message}')"),
            Self::Other(text) => f.write_str(text),
        }
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        Self::Other(e.to_string())
    }
}

/// 種類を確かめる途中の失敗。
enum ProbeError {
    Unsafe(UrlSafetyError),
    Other,
}

/// VirusTotal で調べる口。1 つを使い回す（結果を覚えておくため）。
pub struct VirusTotal {
    config: VtConfig,
    api: reqwest::Client,
    web: reqwest::Client,
    check: AddressCheck,
    cache: Mutex<TtlCache<String, VtResult>>,
    failures: Mutex<TtlCache<String, VtResult>>,
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// ファイルとして送る種類か。Python の `is_file_content_type`。
pub fn is_file_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("application/") || ct == "binary/octet-stream"
}

impl VirusTotal {
    /// 本番の安全確認で作る。
    pub fn new(config: VtConfig) -> Self {
        Self::with_address_check(config, public_only())
    }

    /// 安全確認を差し替えて作る（テストと突き合わせで、手元の偽物のサーバーへ向けるため）。
    pub fn with_address_check(config: VtConfig, check: AddressCheck) -> Self {
        let api = reqwest::Client::builder()
            .timeout(config.scan_timeout)
            .user_agent("sycs-bot (security scan)")
            .build()
            .unwrap_or_default();
        let web = reqwest::Client::builder()
            .timeout(WEB_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("sycs-bot (security scan)")
            .build()
            .unwrap_or_default();
        let failures = TtlCache::new(config.failure_ttl_seconds, FAILURE_CACHE_MAX);
        Self {
            config,
            api,
            web,
            check,
            cache: Mutex::new(TtlCache::new(CACHE_TTL_SECONDS, CACHE_MAX)),
            failures: Mutex::new(failures),
        }
    }

    /// 1 つの URL（リンクか添付ファイル）を調べる。Python の `vt_scan_target`。
    pub async fn scan_target(&self, url: &str) -> VtResult {
        if let Err(e) = (self.check)(url.to_string()).await {
            warn!("[VT] unsafe URL blocked: {url} ({e})");
            return VtResult::new("skip", "url", 0, 0, Some(format!("unsafe_url:{e}")));
        }
        let content_type = self.content_type(url).await;
        info!("[VT] Content-Type {url} -> {content_type}");
        // Python と同じく大文字・小文字を区別する（Image/PNG は画像として飛ばさない）。
        if content_type.starts_with("image/") {
            return VtResult::new("skip", "image", 0, 0, Some("image".into()));
        }
        if is_file_content_type(&content_type) {
            return match self.download(url).await {
                Ok(data) => self.check_file(&data).await,
                Err(result) => result,
            };
        }
        self.check_url(url).await
    }

    /// 種類を確かめる。HEAD で取れなければ GET。安全でない行き先に当たったら空。Python の `fetch_content_type`。
    async fn content_type(&self, url: &str) -> String {
        match self.probe(reqwest::Method::HEAD, url).await {
            Ok((status, ct)) if status < 400 && !ct.is_empty() => return ct,
            Ok(_) | Err(ProbeError::Other) => {}
            Err(ProbeError::Unsafe(e)) => {
                warn!("[VT] unsafe URL blocked in content-type probe: {url} ({e})");
                return String::new();
            }
        }
        match self.probe(reqwest::Method::GET, url).await {
            Ok((_, ct)) => ct,
            Err(ProbeError::Unsafe(e)) => {
                warn!("[VT] unsafe URL blocked in content-type fallback: {url} ({e})");
                String::new()
            }
            Err(ProbeError::Other) => String::new(),
        }
    }

    /// リダイレクトを 1 段ずつ、そのたびに安全を確かめながらたどり、(状態, 種類) を得る。
    async fn probe(&self, method: reqwest::Method, url: &str) -> Result<(u16, String), ProbeError> {
        let mut current = url.to_string();
        for _ in 0..=self.config.max_redirects {
            (self.check)(current.clone())
                .await
                .map_err(ProbeError::Unsafe)?;
            let response = self
                .web
                .request(method.clone(), &current)
                .send()
                .await
                .map_err(|_| ProbeError::Other)?;
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                let Some(location) = header(&response, "location") else {
                    return Ok((status, String::new()));
                };
                current = join(&current, &location).ok_or(ProbeError::Other)?;
                continue;
            }
            return Ok((
                status,
                header(&response, "content-type").unwrap_or_default(),
            ));
        }
        Ok((310, String::new()))
    }

    /// ファイルを大きさの上限つきで落とす。だめなら返す結果（Python と同じ理由と数）を `Err` で。
    async fn download(&self, url: &str) -> Result<Vec<u8>, VtResult> {
        let failed = |reason: String| VtResult::new("error", "file", -1, -1, Some(reason));
        let too_large = || {
            VtResult::new(
                "skip",
                "file",
                0,
                0,
                Some(format!("file_too_large>{}", self.config.max_download_bytes)),
            )
        };
        let mut current = url.to_string();
        for _ in 0..=self.config.max_redirects {
            if let Err(e) = (self.check)(current.clone()).await {
                error!("[VT] file download failed: {e}");
                return Err(failed(e.to_string()));
            }
            let mut response = match self.web.get(&current).send().await {
                Ok(r) => r,
                Err(e) => {
                    error!("[VT] file download failed: {e}");
                    return Err(failed(e.to_string()));
                }
            };
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                let Some(location) = header(&response, "location") else {
                    return Err(failed("redirect_without_location".into()));
                };
                match join(&current, &location) {
                    Some(next) => current = next,
                    None => return Err(failed(format!("invalid redirect: {location}"))),
                }
                continue;
            }
            if status >= 400 {
                return Err(failed(format!("http_status_{status}")));
            }
            if let Some(length) =
                header(&response, "content-length").and_then(|v| v.trim().parse::<i64>().ok())
                && length > self.config.max_download_bytes as i64
            {
                return Err(too_large());
            }
            let mut data = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        data.extend_from_slice(&chunk);
                        if data.len() as u64 > self.config.max_download_bytes {
                            return Err(too_large());
                        }
                    }
                    Ok(None) => return Ok(data),
                    Err(e) => {
                        error!("[VT] file download failed: {e}");
                        return Err(failed(e.to_string()));
                    }
                }
            }
        }
        Err(failed("too_many_redirects".into()))
    }

    /// URL を調べる（結果は覚えておく）。Python の `vt_check_url`。
    pub async fn check_url(&self, url: &str) -> VtResult {
        let key = sha256_hex(url.as_bytes());
        let at = now();
        let cached = self.lock(&self.cache).get(&key, at);
        if let Some(hit) = cached.or_else(|| self.lock(&self.failures).get(&key, at)) {
            return hit;
        }
        let Some(api_key) = self.config.api_key.as_deref() else {
            return VtResult::new("skip", "url", 0, 0, Some("no_api_key".into()));
        };
        let result = match self.scan_url(api_key, url).await {
            Ok(stats) => VtResult::stats("ok", "url", &stats),
            Err(e) => {
                error!("[VT] URL scan exception: {e}");
                VtResult::new("error", "url", 0, 0, Some(e.to_string()))
            }
        };
        let target = if result.status == "error" {
            &self.failures
        } else {
            &self.cache
        };
        self.lock(target).set(key, result.clone(), now());
        result
    }

    /// ファイルの中身を調べる。Python の `vt_check_file`（f50dfa6 で直した形）。
    pub async fn check_file(&self, content: &[u8]) -> VtResult {
        let Some(api_key) = self.config.api_key.as_deref() else {
            return VtResult::new("skip", "file", 0, 0, Some("no_api_key".into()));
        };
        let sha256 = sha256_hex(content);
        let path = format!("/files/{sha256}");
        // 既に調べられたファイルなら、アップロードせずにその結果を使う。API の失敗（無い）なら次へ。
        match self.get_object(api_key, &path).await {
            Ok(attrs) => {
                return VtResult::stats("cached", "file", &attrs["last_analysis_stats"]);
            }
            Err(ApiError::Api { .. }) => {}
            Err(e) => {
                error!("[VT] File scan exception: {e}");
                return VtResult::new("error", "file", 0, 0, Some(e.to_string()));
            }
        }
        match self.scan_file(api_key, content).await {
            Ok(stats) => VtResult::stats("ok", "file", &stats),
            Err(ApiError::Api { code, .. }) if code == "ConflictError" => {
                // 同時にスキャン中。既存の解析結果を取り直す。
                match self.get_object(api_key, &path).await {
                    Ok(attrs) => {
                        VtResult::stats("conflict_fallback", "file", &attrs["last_analysis_stats"])
                    }
                    Err(e) => {
                        error!("[VT] File scan conflict fallback failed: {e}");
                        VtResult::new("error", "file", 0, 0, Some(e.to_string()))
                    }
                }
            }
            Err(e @ ApiError::Api { .. }) => {
                error!("[VT] File scan API error: {e}");
                VtResult::new("error", "file", 0, 0, Some(e.to_string()))
            }
            Err(e) => {
                error!("[VT] File scan exception: {e}");
                VtResult::new("error", "file", 0, 0, Some(e.to_string()))
            }
        }
    }

    fn lock<'a>(
        &self,
        cache: &'a Mutex<TtlCache<String, VtResult>>,
    ) -> std::sync::MutexGuard<'a, TtlCache<String, VtResult>> {
        cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}/api/v3{path}", self.config.api_base)
        }
    }

    /// 応答を読み、`data` を返す。200 以外は vt-py と同じく API の失敗にする。
    async fn data(response: reqwest::Response) -> Result<Value, ApiError> {
        let status = response.status().as_u16();
        if status == 200 {
            let body = response.bytes().await?;
            let json: Value =
                serde_json::from_slice(&body).map_err(|e| ApiError::Other(e.to_string()))?;
            return json
                .get("data")
                .cloned()
                .ok_or_else(|| ApiError::Other("response does not returns a data field".into()));
        }
        let is_json = header(&response, "content-type").is_some_and(|ct| {
            ct.split(';')
                .next()
                .is_some_and(|t| t.trim() == "application/json")
        });
        let text = response.text().await.unwrap_or_default();
        if (400..=499).contains(&status) {
            if is_json
                && let Ok(json) = serde_json::from_str::<Value>(&text)
                && let Some(error) = json.get("error")
            {
                return Err(ApiError::Api {
                    code: error["code"].as_str().unwrap_or("").to_string(),
                    message: error.get("message").map_or("None".into(), python_str),
                });
            }
            return Err(ApiError::Api {
                code: "ClientError".into(),
                message: text,
            });
        }
        Err(ApiError::Api {
            code: "ServerError".into(),
            message: text,
        })
    }

    async fn get_object(&self, api_key: &str, path: &str) -> Result<Value, ApiError> {
        let response = self
            .api
            .get(self.url(path))
            .header("X-Apikey", api_key)
            .send()
            .await?;
        Ok(Self::data(response).await?["attributes"].clone())
    }

    /// 解析が終わるまで問い合わせ、`stats` を返す（vt-py の `_wait_for_analysis_completion`）。
    async fn wait_for_analysis(&self, api_key: &str, analysis: &Value) -> Result<Value, ApiError> {
        let id = analysis["id"]
            .as_str()
            .ok_or_else(|| ApiError::Other("analysis has no id".into()))?
            .to_string();
        loop {
            let attrs = self.get_object(api_key, &format!("/analyses/{id}")).await?;
            if attrs["status"] == "completed" {
                return Ok(attrs["stats"].clone());
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn scan_url(&self, api_key: &str, url: &str) -> Result<Value, ApiError> {
        let response = self
            .api
            .post(self.url("/urls"))
            .header("X-Apikey", api_key)
            .form(&[("url", url)])
            .send()
            .await?;
        let analysis = Self::data(response).await?;
        self.wait_for_analysis(api_key, &analysis).await
    }

    async fn scan_file(&self, api_key: &str, content: &[u8]) -> Result<Value, ApiError> {
        let upload = self
            .api
            .get(self.url("/files/upload_url"))
            .header("X-Apikey", api_key)
            .send()
            .await?;
        let upload_url = Self::data(upload)
            .await?
            .as_str()
            .ok_or_else(|| ApiError::Other("upload_url is not a string".into()))?
            .to_string();
        let part = reqwest::multipart::Part::bytes(content.to_vec()).file_name("upload");
        let form = reqwest::multipart::Form::new().part("file", part);
        let response = self
            .api
            .post(upload_url)
            .header("X-Apikey", api_key)
            .multipart(form)
            .send()
            .await?;
        let analysis = Self::data(response).await?;
        self.wait_for_analysis(api_key, &analysis).await
    }
}

fn header(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn join(base: &str, location: &str) -> Option<String> {
    reqwest::Url::parse(base)
        .ok()?
        .join(location)
        .ok()
        .map(|u| u.to_string())
}

fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ファイルとして送る種類（application/* と binary/octet-stream）。大文字・小文字は問わない。
    #[test]
    fn file_content_types_follow_python() {
        for ct in [
            "application/zip",
            "Application/Octet-Stream",
            "binary/octet-stream",
        ] {
            assert!(is_file_content_type(ct), "{ct}");
        }
        for ct in ["", "text/html", "image/png", "binary/x"] {
            assert!(!is_file_content_type(ct), "{ct}");
        }
    }

    /// API の失敗の書き方が Python の str(APIError(code, message)) と同じ形であること。
    #[test]
    fn api_errors_read_like_python() {
        let e = ApiError::Api {
            code: "QuotaExceededError".into(),
            message: "quota".into(),
        };
        assert_eq!(e.to_string(), "('QuotaExceededError', 'quota')");
    }

    /// 既定の数（鍵・待ち時間・失敗を覚える長さ・リダイレクト・大きさ・場所・間隔）が Python と同じ。
    #[test]
    fn defaults_match_python() {
        let c = VtConfig::from_env(&Env::from_fn(|_| None));
        assert!(c.api_key.is_none());
        assert_eq!(c.scan_timeout, Duration::from_secs(30));
        assert_eq!(c.failure_ttl_seconds, 300.0);
        assert_eq!(c.max_redirects, 5);
        assert_eq!(c.max_download_bytes, 20 * 1024 * 1024);
        assert_eq!(c.api_base, "https://www.virustotal.com");
        assert_eq!(c.poll_interval, Duration::from_secs(20));
        assert_eq!(MALICIOUS_THRESHOLD, 10);
        // 下限（5 秒・10 秒）を下回る値は下限に丸める。
        let low = VtConfig::from_env(&Env::from_fn(|k| match k {
            "VT_SCAN_TIMEOUT_SECONDS" => Some("1".into()),
            "VT_FAILURE_CACHE_TTL_SECONDS" => Some("1".into()),
            _ => None,
        }));
        assert_eq!(low.scan_timeout, Duration::from_secs(5));
        assert_eq!(low.failure_ttl_seconds, 10.0);
    }
}
