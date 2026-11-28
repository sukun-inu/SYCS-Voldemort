//! VirusTotal の呼び出しを、テストの中で立てた偽物の VirusTotal と配布元に当てて確かめる。
//!
//! 本物の Python（services/virustotal_service.py ＋ vt-py 0.22.0）とは、同じ形の偽物に両方を当てて
//! 26 例とも一致することを確かめた（変更のコミットに記録）。終わらない解析（URL・ファイル）の例は rust-09 の (b) で
//! 足し、直した Python とも同じ結果（`analysis_timeout>1`）になることを確かめた。ここではその流れを CI で毎回回す。
//!
//! 偽物は `127.0.0.1` に立つ（内部のアドレス）ので、安全確認だけ差し替える（`blocked.example` を拒否する）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sycs_bot::virustotal::{AddressCheck, VirusTotal, VtConfig, VtResult};
use sycs_core::env::Env;
use sycs_core::url_safety::UrlSafetyError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 偽物が受けた要求の回数（道すじごと）。
type Hits = Arc<Mutex<HashMap<String, usize>>>;

struct Fake {
    base: String,
    hits: Hits,
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn response(
    status: u16,
    ctype: Option<&str>,
    headers: &[(&str, String)],
    body: &[u8],
    head: bool,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(ct) = ctype {
        out.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if !head {
        bytes.extend_from_slice(body);
    }
    bytes
}

fn json(status: u16, body: serde_json::Value) -> Vec<u8> {
    response(
        status,
        Some("application/json"),
        &[],
        body.to_string().as_bytes(),
        false,
    )
}

fn stats(malicious: i64, suspicious: i64) -> serde_json::Value {
    serde_json::json!({"malicious": malicious, "suspicious": suspicious})
}

/// 1 つの要求に答える。Python の確かめに使った偽物（fakevt.py）と同じ答え。
fn route(method: &str, path: &str, body: &[u8], base: &str, hits: &Hits) -> Vec<u8> {
    let count = {
        let mut h = hits.lock().unwrap();
        let key = format!("{method} {path}");
        *h.entry(key).or_default() += 1;
        h[&format!("{method} {path}")]
    };
    let head = method == "HEAD";
    let analyses = |id: &str| format!("{{\"data\":{{\"type\":\"analysis\",\"id\":\"{id}\"}}}}");
    if let Some(name) = path.strip_prefix("/t/") {
        let file = |ct: &str, data: &[u8]| response(200, Some(ct), &[], data, head);
        return match name {
            "image.png" => file("image/png", b"png"),
            "page.html" | "malicious.html" | "vt-error.html" | "vt-quota.html" | "never.html" => {
                file("text/html; charset=utf-8", b"<html></html>")
            }
            "upper.png" => file("Image/PNG", b"png"),
            "file.exe" => file("application/octet-stream", b"evil payload"),
            "known.bin" => file("application/octet-stream", b"known file"),
            "never.bin" => file("application/octet-stream", b"never ending"),
            "conflict.bin" => file("application/x-msdownload", b"conflict data"),
            "big.bin" => file("application/octet-stream", &[b'x'; 1500]),
            "bigchunked.bin" if !head => {
                let mut out = b"HTTP/1.1 200 X\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                for _ in 0..3 {
                    out.extend_from_slice(b"1f4\r\n");
                    out.extend_from_slice(&[b'y'; 500]);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
                out
            }
            "bigchunked.bin" => file("application/octet-stream", b""),
            "redir" => response(302, None, &[("Location", "/t/file.exe".into())], b"", head),
            "loop" => response(302, None, &[("Location", "/t/loop".into())], b"", head),
            "redir-noloc" => response(302, None, &[], b"", head),
            "redir-to-bad-file" => response(
                302,
                None,
                &[("Location", "/t/blocked-file.exe".into())],
                b"",
                head,
            ),
            "blocked-file.exe" => file("application/octet-stream", b"evil payload"),
            "head-ok-get-redir-bad" if head => file("application/octet-stream", b""),
            "head-ok-get-redir-bad" => response(
                302,
                None,
                &[("Location", "/t/blocked-file.exe".into())],
                b"",
                false,
            ),
            "redir-elsewhere" => response(
                302,
                None,
                &[("Location", "http://blocked.example/x".into())],
                b"",
                head,
            ),
            "nohead.bin" if head => response(405, None, &[], b"", true),
            "nohead.bin" => file("application/octet-stream", b"nohead body"),
            "404.bin" => response(404, Some("application/octet-stream"), &[], b"no", head),
            _ => response(404, Some("text/plain"), &[], b"unknown", head),
        };
    }
    match (method, path) {
        ("POST", "/api/v3/urls") => {
            let url = String::from_utf8_lossy(body).to_string();
            if url.contains("vt-error") {
                response(500, Some("text/plain"), &[], b"boom", false)
            } else if url.contains("vt-quota") {
                json(
                    429,
                    serde_json::json!({"error": {"code": "QuotaExceededError", "message": "quota"}}),
                )
            } else if url.contains("never") {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("u-never").as_bytes(),
                    false,
                )
            } else if url.contains("malicious") {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("u-mal").as_bytes(),
                    false,
                )
            } else {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("u-ok").as_bytes(),
                    false,
                )
            }
        }
        ("GET", "/api/v3/files/upload_url") => {
            json(200, serde_json::json!({"data": format!("{base}/upload")}))
        }
        ("POST", "/upload") => {
            let text = String::from_utf8_lossy(body);
            if text.contains("conflict data") {
                json(
                    409,
                    serde_json::json!({"error": {"code": "ConflictError", "message": "already being scanned"}}),
                )
            } else if text.contains("never ending") {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("f-never").as_bytes(),
                    false,
                )
            } else if text.contains("evil") {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("f-evil").as_bytes(),
                    false,
                )
            } else {
                response(
                    200,
                    Some("application/json"),
                    &[],
                    analyses("f-clean").as_bytes(),
                    false,
                )
            }
        }
        ("GET", p) if p.starts_with("/api/v3/analyses/") => {
            let id = p.rsplit('/').next().unwrap();
            let s = match id {
                "u-mal" => stats(12, 0),
                "f-evil" => stats(20, 1),
                _ => stats(0, 0),
            };
            // 1 回目は待ち、2 回目で終わる（問い合わせを続けることを確かめる）。`-never` は終わらない。
            if count < 2 || id.ends_with("-never") {
                json(
                    200,
                    serde_json::json!({"data": {"type": "analysis", "id": id, "attributes": {"status": "queued"}}}),
                )
            } else {
                json(
                    200,
                    serde_json::json!({"data": {"type": "analysis", "id": id, "attributes": {"status": "completed", "stats": s}}}),
                )
            }
        }
        ("GET", p) if p.starts_with("/api/v3/files/") => {
            let hash = p.rsplit('/').next().unwrap();
            let file = |s: serde_json::Value| {
                json(
                    200,
                    serde_json::json!({"data": {"type": "file", "id": hash, "attributes": {"last_analysis_stats": s}}}),
                )
            };
            if hash == sha(b"known file") {
                file(stats(5, 1))
            } else if hash == sha(b"conflict data") && count >= 2 {
                file(stats(7, 0))
            } else {
                json(
                    404,
                    serde_json::json!({"error": {"code": "NotFoundError", "message": "File not found"}}),
                )
            }
        }
        _ => response(404, Some("text/plain"), &[], b"unknown", false),
    }
}

async fn start_fake() -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Hits = Arc::default();
    let (b, h) = (base.clone(), Arc::clone(&hits));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (b, h) = (b.clone(), Arc::clone(&h));
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut lines = head.lines();
                let mut first = lines.next().unwrap_or("").split(' ');
                let (method, path) = (
                    first.next().unwrap_or("").to_string(),
                    first.next().unwrap_or("").to_string(),
                );
                let length: usize = lines
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + length {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = buf[header_end..].to_vec();
                let out = route(&method, &path, &body, &b, &h);
                let _ = sock.write_all(&out).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Fake { base, hits }
}

fn client(fake: &Fake, key: Option<&str>) -> VirusTotal {
    let mut config = VtConfig::from_env(&Env::from_fn(|k| {
        (k == "VT_MAX_DOWNLOAD_BYTES").then(|| "1000".to_string())
    }));
    config.api_key = key.map(String::from);
    config.api_base = fake.base.clone();
    config.poll_interval = Duration::from_millis(20);
    config.analysis_timeout = Duration::from_secs(1);
    let check: AddressCheck = Arc::new(|url: String| {
        Box::pin(async move {
            if url.contains("blocked") {
                Err(UrlSafetyError("non_public_ip:blocked".into()))
            } else {
                Ok(())
            }
        })
    });
    VirusTotal::with_address_check(config, check)
}

fn r(status: &str, kind: &str, malicious: i64, suspicious: i64, reason: Option<&str>) -> VtResult {
    VtResult {
        status: status.into(),
        kind: kind.into(),
        malicious,
        suspicious,
        reason: reason.map(String::from),
    }
}

/// 種類ごとの振り分け（画像は飛ばす・ページは URL・ファイルは落としてファイル）と、解析を終わるまで待つこと。
#[tokio::test]
async fn targets_are_routed_by_content_type() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    assert_eq!(
        vt.scan_target(&t("image.png")).await,
        r("skip", "image", 0, 0, Some("image"))
    );
    assert_eq!(
        vt.scan_target(&t("page.html")).await,
        r("ok", "url", 0, 0, None)
    );
    assert_eq!(
        vt.scan_target(&t("malicious.html")).await,
        r("ok", "url", 12, 0, None)
    );
    // 大文字の Image/PNG は画像として飛ばさない（Python と同じ）。ファイルでもないので URL。
    assert_eq!(vt.scan_target(&t("upper.png")).await.kind, "url");
    assert_eq!(
        vt.scan_target(&t("file.exe")).await,
        r("ok", "file", 20, 1, None)
    );
    assert_eq!(
        vt.scan_target(&t("nohead.bin")).await,
        r("ok", "file", 0, 0, None)
    );
}

/// ハッシュで既に調べられたファイルはアップロードせず、同時にスキャン中なら既存の結果を取り直すこと。
#[tokio::test]
async fn known_files_are_not_uploaded_and_conflicts_fall_back() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    assert_eq!(
        vt.scan_target(&t("known.bin")).await,
        r("cached", "file", 5, 1, None)
    );
    assert_eq!(
        fake.hits.lock().unwrap().get("POST /upload"),
        None,
        "既知のファイルをアップロードした"
    );
    assert_eq!(
        vt.scan_target(&t("conflict.bin")).await,
        r("conflict_fallback", "file", 7, 0, None)
    );
}

/// 失敗は結果として返し（API の失敗は Python と同じ書き方）、URL の失敗は覚えて叩き直さないこと。
#[tokio::test]
async fn failures_are_results_and_url_failures_are_remembered() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    let first = vt.scan_target(&t("vt-error.html")).await;
    assert_eq!(
        first,
        r("error", "url", 0, 0, Some("('ServerError', 'boom')"))
    );
    assert_eq!(vt.scan_target(&t("vt-error.html")).await, first);
    assert_eq!(
        fake.hits.lock().unwrap()["POST /api/v3/urls"],
        1,
        "失敗した URL を叩き直した"
    );
    assert_eq!(
        vt.scan_target(&t("vt-quota.html")).await,
        r(
            "error",
            "url",
            0,
            0,
            Some("('QuotaExceededError', 'quota')")
        )
    );
    assert_eq!(
        vt.scan_target(&t("404.bin")).await,
        r("error", "file", -1, -1, Some("http_status_404"))
    );
}

/// 大きすぎるファイルは、長さが付いていても・流れてくる途中でも、読み切る前に諦めること。
#[tokio::test]
async fn oversized_files_are_skipped() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    let too_large = r("skip", "file", 0, 0, Some("file_too_large>1000"));
    assert_eq!(vt.scan_target(&t("big.bin")).await, too_large);
    assert_eq!(vt.scan_target(&t("bigchunked.bin")).await, too_large);
}

/// リダイレクトは 1 段ずつ安全を確かめてたどり、終わらない・行き先が無い・安全でない行き先なら種類は空（URL として調べる）。
#[tokio::test]
async fn redirects_are_followed_safely() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    assert_eq!(
        vt.scan_target(&t("redir")).await,
        r("ok", "file", 20, 1, None)
    );
    for name in ["loop", "redir-noloc", "redir-elsewhere"] {
        assert_eq!(vt.scan_target(&t(name)).await.kind, "url", "{name}");
    }
    // 種類の確認でたどった先が安全でなければ、種類は空（URL として調べる）。ファイルとして落としに行かない。
    assert_eq!(vt.scan_target(&t("redir-to-bad-file")).await.kind, "url");
    // 種類の確認は通っても、落とすときにたどった先が安全でなければ落とさない（Python と同じ理由と数）。
    assert_eq!(
        vt.scan_target(&t("head-ok-get-redir-bad")).await,
        r("error", "file", -1, -1, Some("non_public_ip:blocked"))
    );
    assert_eq!(
        vt.scan_target("http://blocked.example/t/page.html").await,
        r(
            "skip",
            "url",
            0,
            0,
            Some("unsafe_url:non_public_ip:blocked")
        )
    );
}

/// 終わらない解析は、全体の上限（ここでは 1 秒）で諦めて「走査できなかった」にすること（Python の
/// `_wait_for_analysis`。rust-09 の (b)）。すぐに 1 回、間隔（0.02 秒）を空けて問い合わせ直し続け、上限のあとは
/// 問い合わせない。
#[tokio::test]
async fn analyses_that_never_end_are_given_up() {
    let fake = start_fake().await;
    let vt = client(&fake, Some("k"));
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    let given_up = |kind: &str| r("error", kind, 0, 0, Some("analysis_timeout>1"));
    assert_eq!(vt.scan_target(&t("never.html")).await, given_up("url"));
    assert_eq!(vt.scan_target(&t("never.bin")).await, given_up("file"));
    let polls = |id: &str| fake.hits.lock().unwrap()[&format!("GET /api/v3/analyses/{id}")];
    for id in ["u-never", "f-never"] {
        // 1 秒・0.02 秒おきなら、多くても 52 回（遅い環境では減るだけで、増えはしない）。少なくとも 3 回は
        // 問い合わせる（間隔を空けて問い合わせ直し続ける。1 秒あれば遅い環境でも届く）。
        assert!((3..=52).contains(&polls(id)), "{id}: {} 回", polls(id));
    }
    // 終わらない URL の失敗も、ほかの失敗と同じく覚えて叩き直さない。
    let before = polls("u-never");
    assert_eq!(vt.scan_target(&t("never.html")).await, given_up("url"));
    assert_eq!(polls("u-never"), before, "失敗を覚えずに問い合わせ直した");
}

/// 鍵が無ければ API を呼ばずに skip（URL もファイルも）。
#[tokio::test]
async fn without_a_key_nothing_is_sent() {
    let fake = start_fake().await;
    let vt = client(&fake, None);
    let t = |name: &str| format!("{}/t/{name}", fake.base);
    assert_eq!(
        vt.scan_target(&t("page.html")).await,
        r("skip", "url", 0, 0, Some("no_api_key"))
    );
    assert_eq!(
        vt.scan_target(&t("file.exe")).await,
        r("skip", "file", 0, 0, Some("no_api_key"))
    );
    let hits = fake.hits.lock().unwrap();
    assert!(
        hits.keys()
            .all(|k| !k.contains("/api/") && !k.contains("/upload")),
        "{hits:?}"
    );
}
