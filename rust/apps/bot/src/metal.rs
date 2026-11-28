//! 貴金属の値段を外の API（MetalpriceAPI）から取る。Python の `services/metal_service.py`。
//!
//! Bot のコマンド（/metal）が使うのは「1 つの金属の、1 グラムあたりの円」だけなので、移したのはその道
//! （`calculate_metal_value` → `fetch_metal_price_per_gram` → `_fetch_metal_prices_live`）。複数の金属を
//! 1 回の要求でまとめて取る道（日次の記録が使う）は、Web の側のものなので移していない。
//!
//! - 取った値段は金属ごとに覚えておく（`METALPRICE_CACHE_TTL_SECONDS`、既定 30 分）。無料枠は月に 100 回しか
//!   呼べないので、コマンドの連打で使い切らないようにする
//! - API へは 1 つずつ行く（同時に来た要求は並んで待ち、待っている間に他が取っていればそれを使う）
//! - 失敗の文は Python の例外の文と同じにしてある（ログチャンネルの「エラー内容」に出る）
//!
//! **鍵は URL に入る**（`?api_key=…`）。失敗の文に URL を入れない（[`MetalError`] の文はログチャンネルへ出る）。

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;
use sycs_core::env::Env;
use tracing::debug;

use crate::commands::settings::python_truthy;
use crate::python_repr::{python_repr, python_str};

/// 1 トロイオンスのグラム数。Python の `TROY_OUNCE_GRAMS`。
pub const TROY_OUNCE_GRAMS: f64 = 31.1035;
/// API の場所の既定。Python の `METALPRICE_BASE_URL`。
pub const DEFAULT_BASE_URL: &str = "https://api.metalpriceapi.com/v1/latest";
/// 1 回の要求の待ち時間。Python の `aiohttp.ClientTimeout(total=12)`。
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
/// 値段を覚えておく秒数の既定（30 分）。
pub const DEFAULT_CACHE_TTL_SECONDS: i64 = 1800;

/// 設定。環境変数の名前・既定・下限は Python（config.py）と同じ。
#[derive(Clone)]
pub struct MetalConfig {
    /// API の鍵（`METALPRICE_API_KEY`）。無ければ取りに行かずに失敗にする。
    pub api_key: Option<String>,
    /// 値段を覚えておく秒数（`METALPRICE_CACHE_TTL_SECONDS`、既定 1800・下限 0。0 なら覚えない）。
    pub cache_ttl_seconds: f64,
    /// API の場所（`METALPRICE_BASE_URL`。Python では定数。テストや手元の確認で偽物に向ける）。
    pub base_url: String,
    /// 1 回の要求の待ち時間（本番は 12 秒。テストで短くする）。
    pub timeout: Duration,
}

/// 鍵は表示しない（設定をログに出しても漏れないように）。
impl std::fmt::Debug for MetalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetalConfig")
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .field("cache_ttl_seconds", &self.cache_ttl_seconds)
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl MetalConfig {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        Self {
            api_key: env.raw("METALPRICE_API_KEY"),
            cache_ttl_seconds: env.int(
                "METALPRICE_CACHE_TTL_SECONDS",
                DEFAULT_CACHE_TTL_SECONDS,
                Some(0),
                None,
            ) as f64,
            base_url: env.string("METALPRICE_BASE_URL", DEFAULT_BASE_URL),
            timeout: REQUEST_TIMEOUT,
        }
    }
}

/// 値段を取れなかった理由。表示は Python の `str(例外)` と同じ形（揃えられないものは下に書いた）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetalError {
    /// Python の `MetalPriceError`（API が断った・値段が入っていない・鍵が無い）。
    Price(String),
    /// Python の `ValueError`（JSON として読めない応答など）。**文は Python の json の文と揃えていない。**
    Value(String),
    /// それ以外（つながらない・時間切れ・応答が思わぬ形）。Python では `aiohttp` の例外や `TypeError` など。
    ///
    /// 時間切れの文は空（Python の `str(asyncio.TimeoutError())` と同じ）。つながらないときの文は
    /// aiohttp の文と揃えていない。
    Other(String),
}

impl MetalError {
    /// Python の `except (ValueError, MetalPriceError)` に入るか（金属 1 種のコマンドは、これだけを
    /// 「値段を取れなかった」として扱い、ほかはコマンドの失敗にする）。
    pub fn is_expected(&self) -> bool {
        matches!(self, Self::Price(_) | Self::Value(_))
    }
}

impl std::fmt::Display for MetalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Price(text) | Self::Value(text) | Self::Other(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for MetalError {}

/// 覚えている値段と、取った時刻。
#[derive(Clone, Copy)]
struct Cached {
    price: f64,
    at: Instant,
}

/// 貴金属の値段の取り口。プロセスに 1 つだけ作って使い回す（覚えた値段を共有する）。
pub struct MetalPrices {
    config: MetalConfig,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>,
    /// API へ 1 つずつ行くための順番待ち。Python の `_price_cache_lock`。
    gate: tokio::sync::Mutex<()>,
}

impl MetalPrices {
    /// 作る。
    pub fn new(config: MetalConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            cache: Mutex::new(HashMap::new()),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Cached>> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 期限の内側の覚えがあればそれ。Python の `_cached_price`。
    fn cached(&self, code: &str) -> Option<f64> {
        let cached = *self.lock().get(code)?;
        (cached.at.elapsed().as_secs_f64() < self.config.cache_ttl_seconds).then_some(cached.price)
    }

    /// 金属 1 つの、1 グラムあたりの円。Python の `fetch_metal_price_per_gram`（覚えがあれば API を呼ばない）。
    pub async fn price_per_gram(&self, code: &str) -> Result<f64, MetalError> {
        if code.is_empty() {
            return Err(MetalError::Price(format!("{code} の価格取得に失敗した。")));
        }
        if let Some(price) = self.cached(code) {
            return Ok(price);
        }
        let _turn = self.gate.lock().await;
        // 待っている間に、他の要求が取っているかもしれない。
        if let Some(price) = self.cached(code) {
            return Ok(price);
        }
        let price = self.fetch_live(code).await?;
        self.lock().insert(
            code.to_string(),
            Cached {
                price,
                at: Instant::now(),
            },
        );
        Ok(price)
    }

    /// API から 1 つ取る。Python の `_fetch_metal_prices_live`（金属 1 つで呼んだとき）。
    async fn fetch_live(&self, code: &str) -> Result<f64, MetalError> {
        let Some(key) = self.config.api_key.as_deref() else {
            return Err(MetalError::Price(
                "METALPRICE_API_KEY が設定されていない。".into(),
            ));
        };
        let response = self
            .http
            .get(&self.config.base_url)
            .query(&[("api_key", key), ("base", "JPY"), ("currencies", code)])
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let body = response.bytes().await.map_err(transport_error)?;
        let data = parse_body(status, &content_type, &body)?;
        debug!("金属APIレスポンス({code}): {data}");
        price_from_response(status, &data, code)
    }

    /// グラム数から、純度ごとの値段（円。小数は切り捨て）。Python の `calculate_metal_value`。
    pub async fn value(
        &self,
        grams: f64,
        code: &str,
        purity: &[(&'static str, f64)],
    ) -> Result<Vec<(&'static str, f64)>, MetalError> {
        if grams <= 0.0 {
            return Err(MetalError::Price("グラム数は正の値で指定せよ。".into()));
        }
        let price = self.price_per_gram(code).await?;
        purity
            .iter()
            .map(|(grade, ratio)| python_int(price * grams * ratio).map(|yen| (*grade, yen)))
            .collect()
    }
}

/// つながらない・時間切れ。**URL は文に入れない**（鍵が入っている）。
fn transport_error(error: reqwest::Error) -> MetalError {
    if error.is_timeout() {
        // Python の `str(asyncio.TimeoutError())` は空。
        return MetalError::Other(String::new());
    }
    MetalError::Other(error.without_url().to_string())
}

/// aiohttp が JSON として読む種類か（`application/json` か `application/…+json`）。
pub(crate) fn is_json_content_type(content_type: &str) -> bool {
    static JSON: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^application/(?:[\w.+-]+?\+)?json").expect("正しい正規表現"));
    JSON.is_match(content_type)
}

/// 応答の本文を JSON として読む。Python の `await resp.json()` と、読めなかったときの扱い。
///
/// - 種類が JSON でなければ `金属APIレスポンスが不正: 状態 本文の先頭 200 文字`
/// - 空（空白だけ）の本文は None（Python の aiohttp と同じ）
/// - JSON として読めなければ Python では `ValueError`
fn parse_body(status: u16, content_type: &str, body: &[u8]) -> Result<Value, MetalError> {
    if !is_json_content_type(content_type) {
        let text = String::from_utf8_lossy(body);
        let head: String = text.chars().take(200).collect();
        return Err(MetalError::Price(format!(
            "金属APIレスポンスが不正: {status} {head}"
        )));
    }
    let stripped = body.trim_ascii();
    if stripped.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(stripped).map_err(|e| MetalError::Value(e.to_string()))
}

/// 応答から 1 グラムあたりの円を取り出す。Python の `_fetch_metal_prices_live` の後ろ半分。
fn price_from_response(status: u16, data: &Value, code: &str) -> Result<f64, MetalError> {
    let object = data.as_object();
    // Python: `data.get("success", True) if isinstance(data, dict) else False`
    let succeeded = object.is_some_and(|o| o.get("success").is_none_or(|v| python_truthy(Some(v))));
    if status != 200 || !succeeded {
        let message = match object {
            // Python: `data.get("error", {}).get("message") or str(data)`
            Some(o) => {
                let message = match o.get("error") {
                    None => None,
                    Some(Value::Object(error)) => error.get("message"),
                    Some(other) => return Err(no_attribute_get(other)),
                };
                match message {
                    Some(text) if python_truthy(message) => python_str(text),
                    _ => python_repr(data),
                }
            }
            None => String::new(),
        };
        return Err(MetalError::Price(format!(
            "金属API呼び出しに失敗 ({status}): {message}"
        )));
    }
    // ここへ来るのは辞書だけ。
    let rates = match object.and_then(|o| o.get("rates")) {
        None => None,
        Some(Value::Object(rates)) => Some(rates),
        Some(other) => return Err(no_attribute_get(other)),
    };
    // Python: `rate = rates.get(f"JPY{code}") or 0` → `if rate:`
    let rate = rates.and_then(|r| r.get(&format!("JPY{code}")));
    let price = match rate {
        Some(value) if python_truthy(rate) => match value {
            Value::Number(n) => n.as_f64().map(|rate| rate / TROY_OUNCE_GRAMS),
            Value::Bool(_) => Some(1.0 / TROY_OUNCE_GRAMS),
            other => {
                return Err(MetalError::Other(format!(
                    "unsupported operand type(s) for /: '{}' and 'float'",
                    python_type_name(other)
                )));
            }
        },
        _ => None,
    };
    price.ok_or_else(|| MetalError::Price(format!("{code} の価格取得に失敗した。")))
}

/// Python の `int(小数)`（0 へ向けて切り捨て）。数でない値は Python と同じ文の失敗にする。
fn python_int(value: f64) -> Result<f64, MetalError> {
    if value.is_nan() {
        return Err(MetalError::Value(
            "cannot convert float NaN to integer".into(),
        ));
    }
    if value.is_infinite() {
        return Err(MetalError::Other(
            "cannot convert float infinity to integer".into(),
        ));
    }
    Ok(value.trunc())
}

/// 辞書でない値に `.get` したときの Python の文（`AttributeError`）。
fn no_attribute_get(value: &Value) -> MetalError {
    MetalError::Other(format!(
        "'{}' object has no attribute 'get'",
        python_type_name(value)
    ))
}

/// JSON から読んだ値の、Python での型の名前。
fn python_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn price(status: u16, data: Value) -> Result<f64, MetalError> {
        price_from_response(status, &data, "XAU")
    }

    /// 値段は「1 トロイオンスの円 ÷ 31.1035」。
    #[test]
    fn the_price_is_the_rate_per_troy_ounce_divided_into_grams() {
        let got = price(
            200,
            json!({"success": true, "rates": {"JPYXAU": 622_070.0}}),
        )
        .unwrap();
        assert_eq!(got, 622_070.0 / 31.1035);
        // success が無くても成功として扱う（Python の `data.get("success", True)`）。
        assert!(price(200, json!({"rates": {"JPYXAU": 31.1035}})).is_ok());
        // 別の金属の値段しか無ければ失敗。
        assert_eq!(
            price(200, json!({"rates": {"JPYXAG": 1.0}})),
            Err(MetalError::Price("XAU の価格取得に失敗した。".into()))
        );
        assert_eq!(
            price(200, json!({"rates": {"JPYXAU": 0}})),
            Err(MetalError::Price("XAU の価格取得に失敗した。".into()))
        );
    }

    /// API が断ったときの文: 理由の文があればそれ、無ければ応答の全体（Python の書き方）。
    #[test]
    fn refusals_carry_the_api_message_or_the_whole_response() {
        let refused =
            json!({"success": false, "error": {"statusCode": 101, "message": "Invalid API Key"}});
        assert_eq!(
            price(401, refused),
            Err(MetalError::Price(
                "金属API呼び出しに失敗 (401): Invalid API Key".into()
            ))
        );
        assert_eq!(
            price(200, json!({"success": false, "error": {"statusCode": 101}})),
            Err(MetalError::Price(
                "金属API呼び出しに失敗 (200): {'success': False, 'error': {'statusCode': 101}}"
                    .into()
            ))
        );
        // 辞書でない応答は、文なし。
        assert_eq!(
            price(200, json!([1, 2])),
            Err(MetalError::Price("金属API呼び出しに失敗 (200): ".into()))
        );
        assert_eq!(
            price(500, Value::Null),
            Err(MetalError::Price("金属API呼び出しに失敗 (500): ".into()))
        );
    }

    /// 思わぬ形の応答は、Python と同じ文の「それ以外」の失敗（金属 1 種のコマンドでは、コマンドの失敗になる）。
    #[test]
    fn unexpected_shapes_are_not_price_errors() {
        let text_rate = price(200, json!({"rates": {"JPYXAU": "1.5"}})).unwrap_err();
        assert_eq!(
            text_rate,
            MetalError::Other("unsupported operand type(s) for /: 'str' and 'float'".into())
        );
        assert!(!text_rate.is_expected());
        assert_eq!(
            price(200, json!({"rates": [1]})),
            Err(MetalError::Other(
                "'list' object has no attribute 'get'".into()
            ))
        );
        assert_eq!(
            price(400, json!({"error": "bad"})),
            Err(MetalError::Other(
                "'str' object has no attribute 'get'".into()
            ))
        );
        assert!(MetalError::Price(String::new()).is_expected());
        assert!(MetalError::Value(String::new()).is_expected());
    }

    /// 種類が JSON でない応答・空の応答・壊れた JSON。
    #[test]
    fn bodies_are_read_like_aiohttp() {
        let long = "x".repeat(300);
        assert_eq!(
            parse_body(502, "text/html; charset=utf-8", long.as_bytes()),
            Err(MetalError::Price(format!(
                "金属APIレスポンスが不正: 502 {}",
                "x".repeat(200)
            )))
        );
        assert_eq!(
            parse_body(200, "application/json", b"  \n"),
            Ok(Value::Null)
        );
        assert_eq!(
            parse_body(200, "application/problem+json", b"{\"a\":1}"),
            Ok(json!({"a": 1}))
        );
        assert!(matches!(
            parse_body(200, "application/json", b"{oops"),
            Err(MetalError::Value(_))
        ));
        for (content_type, json) in [
            ("application/json", true),
            ("application/json; charset=utf-8", true),
            ("application/vnd.api+json", true),
            ("text/json", false),
            ("", false),
            ("text/plain", false),
        ] {
            assert_eq!(is_json_content_type(content_type), json, "{content_type}");
        }
    }

    /// 小数は切り捨て。数でないものは失敗。
    #[test]
    fn values_truncate_toward_zero() {
        assert_eq!(python_int(1234.99), Ok(1234.0));
        assert_eq!(python_int(-0.5), Ok(-0.0));
        assert!(python_int(f64::NAN).unwrap_err().is_expected());
        assert!(!python_int(f64::INFINITY).unwrap_err().is_expected());
    }

    /// 既定は Python と同じ（鍵なし・30 分・本物の API）。下限は 0（覚えない）。
    #[test]
    fn the_defaults_match_python() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            Env::from_fn(move |key| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v.to_string())
            })
        };
        let config = MetalConfig::from_env(&env(&[]));
        assert_eq!(config.api_key, None);
        assert_eq!(config.cache_ttl_seconds, 1800.0);
        assert_eq!(config.base_url, "https://api.metalpriceapi.com/v1/latest");
        assert_eq!(config.timeout, Duration::from_secs(12));
        let config = MetalConfig::from_env(&env(&[
            ("METALPRICE_API_KEY", "secret"),
            ("METALPRICE_CACHE_TTL_SECONDS", "-5"),
            ("METALPRICE_BASE_URL", "http://127.0.0.1:9/v1/latest"),
        ]));
        assert_eq!(config.cache_ttl_seconds, 0.0);
        assert_eq!(config.base_url, "http://127.0.0.1:9/v1/latest");
        let shown = format!("{config:?}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}
