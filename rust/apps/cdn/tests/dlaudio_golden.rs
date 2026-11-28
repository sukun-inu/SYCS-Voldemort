//! 配信（`/dlaudio/`）が、本物の Python（本番で `/dlaudio/` を返している管理画面のアプリ）と同じ答えを返すこと。
//!
//! 基準は `fixtures/dlaudio/expected.json`（generate.py が、本物の `webapp_admin.app` を starlette の TestClient で
//! 回して作った。例は cases.json）。例ごとに、Python が置いたのと同じバイトのファイルを一時ディレクトリに置き、
//! 同じ時刻・同じリクエスト（メソッド・httpx が整えたあとのパス・見出し）を [`App::respond`] に渡して、
//! 状態・見出し・本文と、例が終わったときに置き場に残ったファイルを比べる。
//!
//! ファイルを返す答えだけは形が違う: Python は中身を送り、Rust は中身を送らずに `X-Accel-Redirect` で nginx の
//! 内側の場所を指す。そこで、指した先のファイルの中身が Python の本文と同じかを見る。ファイルの大きさ・日付・
//! ETag・Range の見出しは nginx が付けるので比べない。
//!
//! もう 1 つ、印と guild_id の確かめに使う Python の `str.isalnum()`・`str.isdigit()` を、全部の文字で比べる。

use std::path::Path;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::Value;
use sycs_cdn::app::{ACCEL_PREFIX, App, Config, Incoming, Reply};
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

/// Python の見出しのうち比べないもの（大きさ・日付・ETag・Range は nginx が付ける）。
const NGINX_OWNS: [&str; 6] = [
    "content-length",
    "etag",
    "last-modified",
    "accept-ranges",
    "date",
    "server",
];
/// Rust だけが付けてよい見出し。
const RUST_ONLY: [&str; 2] = ["content-length", "x-accel-redirect"];

fn expected() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dlaudio/expected.json");
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること")
    });
    serde_json::from_str(&text).unwrap()
}

/// Python が置いたのと同じものを置く（ファイルは 16 進のバイト、ディレクトリは空で作る）。
fn place(dir: &Path, placed: &Value) {
    for file in placed.as_array().unwrap() {
        let path = dir.join(file["name"].as_str().unwrap());
        if file["dir"].as_bool() == Some(true) {
            std::fs::create_dir_all(&path).unwrap();
        } else {
            std::fs::write(&path, hex::decode(file["hex"].as_str().unwrap()).unwrap()).unwrap();
        }
    }
}

/// 置き場に残っているものの名前（名前の順）。
fn remaining(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Python が実際に送ったリクエスト（httpx が整えたあとのパスと、TestClient が付けた見出し）。
fn incoming(request: &Value) -> Incoming {
    let target = request["target"].as_str().unwrap();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = HeaderMap::new();
    for pair in request["headers"].as_array().unwrap() {
        let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(pair[1].as_str().unwrap().as_bytes()).unwrap();
        headers.append(name, value);
    }
    Incoming {
        method: Method::from_bytes(request["method"].as_str().unwrap().as_bytes()).unwrap(),
        path,
        query,
        headers,
        peer: None,
    }
}

/// 1 つの答えを比べ、違うところを並べる。
fn compare(want: &Value, got: &Reply, dir: &Path, head: bool) -> Vec<String> {
    let mut wrong = Vec::new();
    let status = want["status"].as_u64().unwrap();
    if u64::from(got.status) != status {
        wrong.push(format!("状態: Python {status} / Rust {}", got.status));
    }
    let mut python_headers: Vec<(String, String)> = want["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .filter(|(name, _)| !NGINX_OWNS.contains(&name.as_str()))
        .collect();
    python_headers.sort();
    let mut rust_headers: Vec<(String, String)> = got
        .headers
        .iter()
        .filter(|(name, _)| !RUST_ONLY.contains(name))
        .map(|(name, value)| ((*name).to_string(), value.clone()))
        .collect();
    rust_headers.sort();
    if python_headers != rust_headers {
        wrong.push(format!(
            "見出し:\n    Python {python_headers:?}\n    Rust   {rust_headers:?}"
        ));
    }
    if let Some(body_hex) = want["body_hex"].as_str() {
        let body = hex::decode(body_hex).unwrap();
        match got.header("x-accel-redirect").and_then(|v| v.strip_prefix(ACCEL_PREFIX)) {
            Some(name) => match std::fs::read(dir.join(name)) {
                Ok(content) if content == body => {}
                Ok(_) => wrong.push(format!(
                    "X-Accel-Redirect の指すファイル {name} の中身が、Python の本文と違う"
                )),
                Err(e) => wrong.push(format!(
                    "X-Accel-Redirect の指すファイル {name} を読めない: {e}"
                )),
            },
            None => wrong.push("ファイルを返すのに X-Accel-Redirect が無い".to_string()),
        }
        if !got.body.is_empty() {
            wrong.push("Rust が本文を送った（中身は nginx に送らせること）".to_string());
        }
    } else {
        if got.header("x-accel-redirect").is_some() {
            wrong.push("ファイルでない答えに X-Accel-Redirect が付いた".to_string());
        }
        if let Some(text) = want["body"].as_str()
            && !head
            && got.body != text.as_bytes()
        {
            wrong.push(format!(
                "本文:\n    Python {text:?}\n    Rust   {:?}",
                String::from_utf8_lossy(&got.body)
            ));
        }
    }
    wrong
}

fn config(dir: &Path, secure_cookies: bool) -> Config {
    Config {
        cache_dir: dir.to_path_buf(),
        secure_cookies,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
    }
}

#[test]
fn every_route_answers_like_python() {
    let data = expected();
    let now = data["now"].as_f64().unwrap();
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 40, "基準の例が足りない（{}）", cases.len());
    let mut wrong = Vec::new();
    let mut requests = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        place(dir.path(), &case["placed"]);
        let secure = case["secure_cookies"].as_bool().unwrap_or(false);
        let app = App::new(
            config(dir.path(), secure),
            Arc::new(move || now),
            Arc::new(Reporter::new("test", None)),
        );
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let request = incoming(&step["request"]);
            let repeat = step["repeat"].as_u64().unwrap_or(1);
            let mut reply = app.respond(&request);
            for _ in 1..repeat {
                reply = app.respond(&request);
            }
            requests += 1;
            let head = request.method == Method::HEAD;
            for problem in compare(&step["response"], &reply, dir.path(), head) {
                wrong.push(format!(
                    "「{name}」の {i} 番目（{} {}）: {problem}",
                    request.method, step["request"]["target"]
                ));
            }
        }
        let want: Vec<String> = case["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let got = remaining(dir.path());
        if want != got {
            wrong.push(format!("「{name}」: 残ったファイル Python {want:?} / Rust {got:?}"));
        }
    }
    assert!(requests >= 100, "基準のリクエストが足りない（{requests}）");
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// その判定が真になる文字の範囲（サロゲートは文字でないので偽）。
fn ranges_of(test: fn(char) -> bool) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut start: Option<u32> = None;
    for code in 0..=0x10_FFFF_u32 {
        let hit = char::from_u32(code).is_some_and(test);
        match (hit, start) {
            (true, None) => start = Some(code),
            (false, Some(first)) => {
                out.push((u64::from(first), u64::from(code - 1)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(first) = start {
        out.push((u64::from(first), 0x10_FFFF));
    }
    out
}

#[test]
fn python_character_classes_match() {
    let data = expected();
    let tests: [(&str, fn(char) -> bool); 2] = [
        ("isalnum", sycs_cdn::python::is_alnum_char),
        ("isdigit", sycs_cdn::python::is_digit_char),
    ];
    for (name, test) in tests {
        let want: Vec<(u64, u64)> = data["chars"][name]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_u64().unwrap(), r[1].as_u64().unwrap()))
            .collect();
        assert!(want.len() > 10, "{name} の基準が足りない");
        let got = ranges_of(test);
        let missing: Vec<&(u64, u64)> = want.iter().filter(|r| !got.contains(r)).take(20).collect();
        let extra: Vec<&(u64, u64)> = got.iter().filter(|r| !want.contains(r)).take(20).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{name} が Python と違う（16 進ではなく 10 進）:\n  Python にだけある範囲 {missing:?}\n  Rust にだけある範囲 {extra:?}"
        );
    }
}
