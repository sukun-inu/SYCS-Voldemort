//! URL の安全確認が、本番の Python 3.13（services/url_safety.py）と同じ答えを出すこと。
//!
//! 基準は `fixtures/url_safety/expected.json`（generate.py が本物の Python で作った）。公開アドレスの
//! 表の各範囲の端と乱数のアドレス、URL の分解と拒否の理由を、名前を引かずに突き合わせる。
//!
//! ここがずれると、Python では弾く内部のアドレスへ Rust が取りに行く（あるいはその逆）。

use serde_json::Value;
use sycs_core::url_safety::{self, Target};

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/url_safety/expected.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn public_addresses_match_python() {
    let data = expected();
    let ips = data["ips"].as_array().unwrap();
    assert!(
        ips.len() >= 300,
        "基準のアドレスが足りない（{}）",
        ips.len()
    );
    let wrong: Vec<String> = ips
        .iter()
        .filter_map(|pair| {
            let ip = pair[0].as_str().unwrap();
            let want = pair[1].as_bool().unwrap();
            let got = url_safety::is_public_ip(ip.parse().unwrap());
            (got != want).then(|| format!("{ip}: Python {want} / Rust {got}"))
        })
        .collect();
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
}

#[test]
fn url_codes_match_python() {
    let data = expected();
    let urls = data["urls"].as_array().unwrap();
    assert!(urls.len() >= 60, "基準の URL が足りない（{}）", urls.len());
    let wrong: Vec<String> = urls
        .iter()
        .filter_map(|pair| {
            let url = pair[0].as_str().unwrap();
            let want = pair[1].as_str().unwrap();
            let got = match url_safety::parse_target(url, true) {
                Ok(Target::Host(h)) => format!("host:{h}"),
                Ok(Target::Address(ip)) => match url_safety::reject_non_public(&[ip]) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.code().to_string(),
                },
                Err(e) => e.code().to_string(),
            };
            (got != want).then(|| format!("{url:?}: Python {want} / Rust {got}"))
        })
        .collect();
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
}
