//! 信頼するプロキシの読み方が、本物の Python（`services/log_setup.trusted_proxies()` と uvicorn の
//! `ProxyHeadersMiddleware`）と同じ答えを出すこと。
//!
//! 基準は `fixtures/proxy/expected.json`（generate.py が本物の Python で作った）。`TRUSTED_PROXY_CIDRS` の値から
//! 一覧を作り、直接つないできた相手と `X-Forwarded-For`・`X-Forwarded-Proto` から、アプリに渡る接続元と scheme を
//! 決めるところまでを突き合わせる。
//!
//! ここがずれると、Python と Rust のアプリで、レート制限とログに出る接続元が食い違う（片方だけ nginx の IP で
//! 数える、外から付けた `X-Forwarded-For` を片方だけ信じる、など）。

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use sycs_web::proxy::{self, TrustedHosts};

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/proxy/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// JSON の文字（latin-1 の範囲）を、見出しの値のバイトにする（Python の `str.encode("latin-1")`）。
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("基準の見出しは latin-1 の範囲"))
        .collect()
}

#[test]
fn forwarded_headers_are_read_like_uvicorn() {
    let data = expected();
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 40, "基準の例が足りない（{}）", cases.len());
    let mut wrong = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let env = case["env"].as_str();
        let setting = proxy::trusted_proxies_setting(env);
        if Some(setting.as_str()) != case["setting"].as_str() {
            wrong.push(format!(
                "{i}: 一覧の文字 Python {} / Rust {setting:?}（TRUSTED_PROXY_CIDRS={env:?}）",
                case["setting"]
            ));
            continue;
        }
        let trusted = TrustedHosts::parse(&setting);
        let mut headers = HeaderMap::new();
        for pair in case["headers"].as_array().unwrap() {
            let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
            let value = HeaderValue::from_bytes(&latin1_bytes(pair[1].as_str().unwrap())).unwrap();
            headers.append(name, value);
        }
        let got = proxy::resolve(&trusted, case["peer"].as_str(), &headers);
        let want_client = case["client"].as_str();
        let want_scheme = case["scheme"].as_str().unwrap();
        if got.client.as_deref() != want_client || got.scheme != want_scheme {
            wrong.push(format!(
                "{i}: 一覧 {setting:?}・相手 {}・見出し {}: Python ({want_client:?}, {want_scheme}) / Rust ({:?}, {})",
                case["peer"], case["headers"], got.client, got.scheme
            ));
        }
    }
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
}
