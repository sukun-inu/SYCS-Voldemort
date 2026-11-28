//! 読み上げの声の一覧（TTS の API）。Python の `services/tts_service.fetch_voices` と、`webapp_admin/schema/choices.py`
//! の `_tts_voices`（3 秒で見切る）の写し。
//!
//! - `GET {TTS_BASE_URL}/api/v1/voices?locale=ja`（1 回 10 秒）。200 以外・JSON でない・つながらないときは空
//! - 答えが並びならそのまま、辞書なら `voices` の並び。要素が辞書で `name` が真のものの `name`（**値はそのまま**。
//!   Python は `str()` しない）
//! - 選択肢は `{"value": 名前, "label": 名前}`。3 秒（`_VOICES_TIMEOUT`）で答えが無ければ見切る（その供給元は空）
//!
//! Bot にも同じ API の口（`sycs_bot::tts::TtsApi`）があるが、管理画面は Bot の crate に依存しない（serenity と
//! songbird がイメージに入る）。名前を `str()` しないところも Bot（スラッシュコマンドの補完）と違う。

use std::time::Duration;

use serde_json::Value;
use sycs_core::env::Env;
use tracing::error;

use crate::auth;
use crate::python;

/// `TTS_BASE_URL` の既定（`config.py`）。
pub const DEFAULT_BASE_URL: &str = "http://localhost:8080";
/// 1 回の問い合わせの待ち時間（`fetch_voices` の `ClientTimeout(total=10)`）。
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// 選択肢として待つ時間（`choices._VOICES_TIMEOUT`）。
pub const VOICES_TIMEOUT: Duration = Duration::from_secs(3);

/// 声の一覧を取る口。
pub struct Voices {
    target: Option<(String, reqwest::Client)>,
    timeout: Duration,
}

impl std::fmt::Debug for Voices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Voices")
            .field("base_url", &self.target.as_ref().map(|(base, _)| base))
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Voices {
    /// 場所（末尾の `/` は落とす）と、選択肢として待つ時間を決めて作る。環境変数のプロキシは使わない（aiohttp の
    /// 既定 `trust_env=False`）。
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .build()?;
        Ok(Self {
            target: Some((base_url.trim_end_matches('/').to_string(), http)),
            timeout,
        })
    }

    /// 環境変数 `TTS_BASE_URL`（`env_raw`。無ければ `http://localhost:8080`）から作る。
    pub fn from_env(env: &Env) -> Result<Self, reqwest::Error> {
        let base = env
            .raw("TTS_BASE_URL")
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        Self::new(&base, VOICES_TIMEOUT)
    }

    /// どこにも問い合わせない口（選択肢はいつも空。テストと `--self-check` 用）。
    pub fn disabled() -> Self {
        Self {
            target: None,
            timeout: VOICES_TIMEOUT,
        }
    }

    /// `fetch_voices()`（取れなければ空。失敗はログに残す）。
    pub async fn fetch_voices(&self) -> Vec<Value> {
        let Some((base, http)) = &self.target else {
            return Vec::new();
        };
        let sent = http
            .get(format!("{base}/api/v1/voices"))
            .query(&[("locale", "ja")])
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(e) => {
                error!("[TTS] fetch_voices error: {}", e.without_url());
                return Vec::new();
            }
        };
        let status = response.status().as_u16();
        if status != 200 {
            return Vec::new();
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(e) => {
                error!("[TTS] fetch_voices error: {}", e.without_url());
                return Vec::new();
            }
        };
        match auth::aiohttp_json(status, content_type.as_deref(), &body) {
            Ok(data) => voice_names(&data),
            Err(e) => {
                error!("[TTS] fetch_voices error: {e}");
                Vec::new()
            }
        }
    }

    /// `_tts_voices`（`fetch_voices()` を待つ時間で見切り、`{"value": 名前, "label": 名前}` の並びにする）。
    pub async fn choices(&self) -> Result<Vec<Value>, String> {
        match tokio::time::timeout(self.timeout, self.fetch_voices()).await {
            Ok(names) => Ok(names
                .into_iter()
                .map(|name| python::object(vec![("value", name.clone()), ("label", name)]))
                .collect()),
            Err(_) => Err(format!(
                "タイムアウト（{} 秒以内に応答なし）",
                self.timeout.as_secs_f64()
            )),
        }
    }
}

/// `fetch_voices` の後ろ半分（並びならそのまま、辞書なら `voices` の並び。要素が辞書で `name` が真のものの `name`）。
///
/// Python は `data.get("voices", [])` を並べるので、`voices` が文字なら 1 文字ずつ（どれも辞書でないので空）、数なら
/// TypeError（拾って空）。答えが辞書でも並びでもなければ AttributeError（拾って空）。どれも空になる。
pub fn voice_names(data: &Value) -> Vec<Value> {
    let voices = match data {
        Value::Array(items) => items.as_slice(),
        Value::Object(map) => match map.get("voices") {
            Some(Value::Array(items)) => items.as_slice(),
            _ => &[],
        },
        _ => &[],
    };
    voices
        .iter()
        .filter_map(|voice| voice.as_object()?.get("name"))
        .filter(|name| python::truthy(name))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 名前の取り出し方（並び・辞書の voices・偽の名前・辞書でない要素・名前はそのまま）。
    #[test]
    fn names_are_taken_like_fetch_voices() {
        assert_eq!(
            voice_names(&json!([{"name": "Kyoko"}, {"name": ""}, "x", {"id": 1}, {"name": 7}])),
            vec![json!("Kyoko"), json!(7)]
        );
        assert_eq!(
            voice_names(&json!({"voices": [{"name": "Otoya", "locale": "ja_JP"}]})),
            vec![json!("Otoya")]
        );
        assert!(voice_names(&json!({"voices": "Kyoko"})).is_empty());
        assert!(voice_names(&json!({"name": "Kyoko"})).is_empty());
        assert!(voice_names(&Value::Null).is_empty());
    }

    /// 待つ時間が Python の `_VOICES_TIMEOUT`（3.0 秒）と同じで、どこにも問い合わせない口は空を返すこと。
    #[tokio::test]
    async fn the_timeout_matches_python_and_disabled_is_empty() {
        let source = include_str!("../../../../../webapp_admin/schema/choices.py");
        assert!(source.contains("_VOICES_TIMEOUT = 3.0"), "choices.py の _VOICES_TIMEOUT が違う");
        assert_eq!(VOICES_TIMEOUT, Duration::from_secs_f64(3.0));
        assert_eq!(Voices::disabled().choices().await, Ok(Vec::new()));
    }
}
