//! 管理画面の結合テストで共通に使う道具: テストの中に立てる偽物の Discord、基準に書いた要求の作り直し、答えの比べ方。
//!
//! 偽物の Discord は、基準を作った Python の偽物（`fixtures/fake_discord.py`）と同じ決まりで答える: 例に書いた
//! 「メソッド パス 認証の種類」（無ければ「メソッド パス」）の答えを返し、届いた要求（メソッド・パス・
//! Authorization・Content-Type・本文）を控える。例に無い要求には 500 を返し、控えに `unexpected` を付ける。
//!
//! 使わない道具があるテストもあるので、未使用の警告は止めてある。
#![allow(dead_code)]

use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use serde_json::{Map, Value, json};
use sycs_admin::app::{Incoming, Reply};

/// Python の偽物と同じ、API の前置き（`/api/v10`）。控えるパスはこれを落としたもの。
pub const API_PREFIX: &str = "/api/v10";

#[derive(Default)]
struct Script {
    answers: Map<String, Value>,
    seen: Vec<Value>,
}

type Shared = Arc<Mutex<Script>>;

/// テストの中に立てる偽物の Discord。
pub struct FakeDiscord {
    api_base: String,
    script: Shared,
}

impl FakeDiscord {
    /// 127.0.0.1 の空いた口で待ち受ける。
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let script: Shared = Arc::default();
        let app = Router::new()
            .fallback(answer)
            .with_state(Arc::clone(&script));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            api_base: format!("http://{addr}{API_PREFIX}"),
            script,
        }
    }

    /// Discord の口に渡す API の場所（`http://127.0.0.1:口/api/v10`）。
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// 答え方を決める（`{"GET /users/@me Bearer": {...}}`）。控えは空にする。
    pub fn script(&self, answers: &Value) {
        let mut script = self.script.lock().unwrap_or_else(PoisonError::into_inner);
        script.answers = answers.as_object().cloned().unwrap_or_default();
        script.seen.clear();
    }

    /// 届いた要求（控えは空にする）。
    pub fn take(&self) -> Vec<Value> {
        let mut script = self.script.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut script.seen)
    }
}

/// 例の答え方を引く（認証の種類つき → 無し の順）。
fn lookup<'a>(
    answers: &'a Map<String, Value>,
    method: &str,
    path: &str,
    authorization: Option<&str>,
) -> Option<&'a Value> {
    if let Some(scheme) = authorization.and_then(|value| value.split(' ').next())
        && let Some(found) = answers.get(&format!("{method} {path} {scheme}"))
    {
        return Some(found);
    }
    answers.get(&format!("{method} {path}"))
}

/// 答え方から答えを作る（Python の `fake_discord.response_of` と同じ）。
fn response_of(spec: Option<&Value>) -> Response {
    let Some(spec) = spec else {
        return reply(500, Some("text/plain"), b"unexpected".to_vec());
    };
    let status = spec["status"].as_u64().unwrap_or(200);
    let (mut content_type, body) = if let Some(value) = spec.get("json") {
        (
            Some("application/json".to_string()),
            serde_json::to_vec(value).unwrap(),
        )
    } else if let Some(text) = spec.get("body") {
        (None, text.as_str().unwrap_or_default().as_bytes().to_vec())
    } else {
        (None, Vec::new())
    };
    if let Some(value) = spec.get("content_type") {
        content_type = value.as_str().map(str::to_string);
    }
    reply(u16::try_from(status).unwrap(), content_type.as_deref(), body)
}

fn reply(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    if let Some(content_type) = content_type {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
    }
    response
}

fn header_text(headers: &HeaderMap, name: &str) -> Value {
    headers.get(name).map_or(Value::Null, |value| {
        Value::String(String::from_utf8_lossy(value.as_bytes()).into_owned())
    })
}

async fn answer(State(script): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap_or_default();
    let target = parts
        .uri
        .path_and_query()
        .map_or("/", |target| target.as_str());
    let path = target.strip_prefix(API_PREFIX).unwrap_or(target);
    let authorization = header_text(&parts.headers, "authorization");
    let mut record = json!({
        "method": parts.method.as_str(),
        "path": path,
        "authorization": authorization,
        "content_type": header_text(&parts.headers, "content-type"),
        "body": String::from_utf8_lossy(&body),
    });
    let spec = {
        let mut script = script.lock().unwrap_or_else(PoisonError::into_inner);
        let spec = lookup(
            &script.answers,
            parts.method.as_str(),
            path,
            authorization.as_str(),
        )
        .cloned();
        if spec.is_none() {
            record["unexpected"] = Value::Bool(true);
        }
        script.seen.push(record);
        spec
    };
    response_of(spec.as_ref())
}

/// 届いた要求の並びを、順番に頼らずに比べられる形にする（Python は 2 つの一覧を並べて取るので、届く順は決まらない）。
pub fn sorted_requests(requests: &[Value]) -> Vec<String> {
    let mut texts: Vec<String> = requests.iter().map(Value::to_string).collect();
    texts.sort();
    texts
}

/// 文字を latin-1 のバイトにする（基準の見出しは latin-1 で読んだ文字で書いてある）。
pub fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 の外の文字"))
        .collect()
}

/// 16 進の文字をバイトにする。
pub fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 基準に書いた、Python が実際に送った要求（パス・見出し・本文）を作り直す。接続元は TestClient の `testclient`。
pub fn incoming(request: &Value) -> Incoming {
    let target = request["target"].as_str().unwrap();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = HeaderMap::new();
    for pair in request["headers"].as_array().unwrap() {
        let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(&latin1_bytes(pair[1].as_str().unwrap())).unwrap();
        headers.append(name, value);
    }
    let body = request["body_hex"]
        .as_str()
        .map(hex_bytes)
        .unwrap_or_default();
    Incoming {
        method: Method::from_bytes(request["method"].as_str().unwrap().as_bytes()).unwrap(),
        path,
        query,
        headers,
        body: Bytes::from(body),
        peer: Some("testclient".to_string()),
    }
}

fn sorted_allow(value: &str) -> String {
    let mut words: Vec<&str> = value.split(',').map(str::trim).collect();
    words.sort_unstable();
    words.join(", ")
}

/// 1 つの答えを Python の答えと比べ、違うところを並べる（状態・見出し〔名前の順。同じ名前の中は足した順〕・本文を
/// バイトまで。HEAD は本文を比べない。`allow` は語の並びを決めてから）。
pub fn compare_reply(want: &Value, got: &Reply, head: bool) -> Vec<String> {
    let mut wrong = Vec::new();
    let status = want["status"].as_u64().unwrap();
    if u64::from(got.status) != status {
        wrong.push(format!("状態: Python {status} / Rust {}", got.status));
    }
    let python: Vec<(String, String)> = want["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut rust = got.headers.clone();
    rust.sort_by(|a, b| a.0.cmp(&b.0));
    let rust: Vec<(String, String)> = rust
        .into_iter()
        .map(|(name, value)| {
            let value = if name == "allow" {
                sorted_allow(&value)
            } else {
                value
            };
            (name, value)
        })
        .collect();
    if python != rust {
        wrong.push(format!(
            "見出し:\n    Python {python:?}\n    Rust   {rust:?}"
        ));
    }
    let body = want["body"].as_str().unwrap();
    if !head && got.body != body.as_bytes() {
        let got_text = String::from_utf8_lossy(&got.body);
        wrong.push(format!(
            "本文（{}）:\n    Python {body:?}\n    Rust   {got_text:?}",
            first_difference(body, &got_text)
        ));
    }
    wrong
}

/// 最初に違う文字のあたり（長い HTML のどこが違うかを読むため）。
pub fn first_difference(want: &str, got: &str) -> String {
    let at = want
        .chars()
        .zip(got.chars())
        .take_while(|(a, b)| a == b)
        .count();
    let around =
        |text: &str| -> String { text.chars().skip(at.saturating_sub(40)).take(80).collect() };
    format!(
        "{at} 文字目から。Python …{:?}… / Rust …{:?}…",
        around(want),
        around(got)
    )
}

/// 違うところが無ければ通す。
pub fn finish(wrong: &[String]) {
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
