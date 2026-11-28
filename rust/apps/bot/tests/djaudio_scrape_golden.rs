//! SoundCloud の client_id をページから探す段が、本物の Python と同じ順にスクリプトを取りに行き、同じ ID を見つけること。
//!
//! 基準（`fixtures/djaudio/scrape_expected.jsonl`）は、本物の `_scrape_sc_client_id_via_aiohttp` を、台本どおりに答える
//! 偽物のセッションで動かしたもの（`generate_scrape.py`）。ここでは同じ台本をテストの中の偽物のサーバーで答え、
//! [`scrape_client_id`] に探させる。比べるのは、サーバーに届いた要求の順（ページ → スクリプトを後ろから 12 個まで）と
//! 見つけた ID。台本で中身の無いスクリプトは、つないだまま答えずに切る（通信の失敗）。
//!
//! Python が相対の URL（`/rel.js`）を取りに行って失敗するところは、Rust では要求を組む段で失敗し、サーバーには
//! 届かない。なので届いた要求は、Python の並びから相対の URL を除いたものと比べる（どちらも、その URL を飛ばして
//! 次へ進むことは同じ）。

use std::sync::{Arc, Mutex};

use serde_json::Value;
use sycs_bot::djaudio::download::scrape_client_id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const EXPECTED: &str = include_str!("fixtures/djaudio/scrape_expected.jsonl");
const FAKE_BASE: &str = "http://fake.invalid";
const PAGE: &str = "https://soundcloud.com";

/// 台本どおりに答える偽物のサーバー。届いた要求の道すじを順に記録する。
async fn start(case: Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let (shared, base_for_task) = (Arc::clone(&seen), base.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (seen, case, base) = (Arc::clone(&shared), case.clone(), base_for_task.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                seen.lock().unwrap().push(path.clone());
                let body = if path == "/" {
                    case["page"].as_str().map(|p| p.replace(FAKE_BASE, &base))
                } else {
                    case["scripts"][format!("{FAKE_BASE}{path}")]
                        .as_str()
                        .map(str::to_string)
                };
                // 中身が無ければ答えずに切る（取りに行った側では通信の失敗になる）。
                if let Some(body) = body {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                }
            });
        }
    });
    (base, seen)
}

/// 全部の例で、届いた要求の順と見つけた ID が Python と同じであること。
#[tokio::test]
async fn scraping_follows_python() {
    let mut count = 0;
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let (base, seen) = start(row[0].clone()).await;
        let found = scrape_client_id(&format!("{base}/")).await;
        let want_paths: Vec<String> = row[1]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .filter(|u| u.starts_with("http"))
            .map(|u| {
                if u == PAGE {
                    "/".to_string()
                } else {
                    u.replacen(FAKE_BASE, "", 1)
                }
            })
            .collect();
        let got_paths = seen.lock().unwrap().clone();
        let want_id = row[2].as_str().map(str::to_string);
        if got_paths != want_paths || found != want_id {
            wrong.push(format!(
                "{}\n  Python: {want_paths:?} {want_id:?}\n  Rust:   {got_paths:?} {found:?}",
                row[0]["id"]
            ));
        }
        count += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 10, "例が少ない: {count}");
}
