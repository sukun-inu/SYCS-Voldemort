//! DJAudio のメタデータの補い（`services/djaudio_isrc_meta.py`）を、本物の Python で作った基準と突き合わせる。
//!
//! 基準は `tests/fixtures/djaudio_meta/generate.py`（python:3.13-slim ＋ 本番と同じ依存 ＋ apt の ffmpeg）で作った:
//! - `table_digests.json`: 文字の表（小文字・NFKD・語末の Σ・数字の値）を全部の符号位置で並べたもののハッシュ
//! - `text_cases.json`: `_clean_title`・`_normalize_for_compare`・`_TOPIC_SUFFIX`・`_DASH_SPLIT`・`_similarity`
//!   （ビットまで）・`_score_result`・`_build_search_queries`
//! - `tags_cases.json` と `tags_out/`: mutagen 1.48.1 の `_write_tags` で書いたあとの MP3（バイト列が全部同じ）
//! - `flow_cases.json` と `flow_out/`: 偽物の Deezer に当てた `enrich_metadata`（届いた要求の行・順番・結果・
//!   書いたあとの MP3）。偽物はこのテストの中に同じ台本で立てる
//!
//! 要求の行は、Python（aiohttp・yarl）が送ったバイト列と、Rust が作った行（yarl の写し）が同じこと、
//! reqwest が実際に送った行は「クエリの `'` が `%27` になる」ことだけが違うことを確かめる。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sycs_bot::djaudio_meta::{self, Deezer, EnrichError, id3, pyint, text};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/djaudio_meta")
}

fn read_json(name: &str) -> Value {
    let text = std::fs::read_to_string(fixtures().join(name)).expect("基準のファイル");
    serde_json::from_str(&text).expect("基準の JSON")
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// テストごとの作業場所（終わったら消す）。
struct WorkDir(PathBuf);

impl WorkDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "djaudio_meta_{tag}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 小さな base64 の読み手（画像と台本の本文）。
fn b64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes().filter_map(value) {
        acc = (acc << 6) | c;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn bits(value: f64) -> u64 {
    value.to_bits()
}

// ---- 文字の表 ----

/// 全部の符号位置で、Python と同じ小文字・NFKD・語末の Σ の性質・数字の値になること。
#[test]
fn unicode_tables_match_python_for_every_code_point() {
    let digests = read_json("table_digests.json");
    assert_eq!(digests["unicode_version"], "15.1.0");
    let mut lower = Sha256::new();
    let mut strip = Sha256::new();
    let mut sigma = Sha256::new();
    let mut decimal = Sha256::new();
    for code in (0..0x11_0000u32).filter(|c| !(0xD800..=0xDFFF).contains(c)) {
        let c = char::from_u32(code).unwrap();
        lower.update(text::digest_parts::lower(c).as_bytes());
        lower.update([0xFF]);
        strip.update(text::digest_parts::strip(c).as_bytes());
        strip.update([0xFF]);
        sigma.update(text::digest_parts::sigma(c));
        sigma.update([0xFF]);
        decimal.update([pyint::decimal_value(c).map_or(255, |d| d as u8)]);
        decimal.update([0xFF]);
    }
    assert_eq!(
        hex::encode(lower.finalize()),
        digests["lower"],
        "str.lower()"
    );
    assert_eq!(
        hex::encode(strip.finalize()),
        digests["strip_marks"],
        "NFKD と combining"
    );
    assert_eq!(
        hex::encode(sigma.finalize()),
        digests["sigma"],
        "語末の Σ の判定"
    );
    assert_eq!(
        hex::encode(decimal.finalize()),
        digests["decimal"],
        "unicodedata.decimal"
    );
}

// ---- 文の整え方・点・検索語 ----

fn report(kind: &str, failures: &[String], total: usize) {
    assert!(
        failures.is_empty(),
        "{kind}: {} / {total} 例が Python と違う。最初の例:\n{}",
        failures.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// `_clean_title`・`_normalize_for_compare`・`_TOPIC_SUFFIX`・`_DASH_SPLIT` が Python と同じ。
#[test]
fn clean_title_and_normalize_match_python() {
    let cases = read_json("text_cases.json");
    let clean = cases["clean"].as_array().unwrap();
    assert!(clean.len() >= 2000, "{}", clean.len());
    let mut failures = Vec::new();
    for case in clean {
        let input = case[0].as_str().unwrap();
        let got = serde_json::json!([
            input,
            text::clean_title(input),
            text::normalize_for_compare(input),
            text::remove_topic_suffix(input),
            text::has_dash(input),
            text::dash_split_once(input),
        ]);
        if &got != case {
            failures.push(format!("Python {case}\nRust   {got}"));
        }
    }
    report("clean", &failures, clean.len());
}

/// `_similarity`（difflib.SequenceMatcher の ratio。autojunk を含む）が最後のビットまで Python と同じ。
#[test]
fn similarity_matches_python_bit_for_bit() {
    let cases = read_json("text_cases.json");
    let pairs = cases["similarity"].as_array().unwrap();
    assert!(pairs.len() >= 1000, "{}", pairs.len());
    let mut failures = Vec::new();
    for case in pairs {
        let (a, b) = (case[0].as_str().unwrap(), case[1].as_str().unwrap());
        let got = bits(djaudio_meta::similarity(a, b));
        if got != case[2].as_u64().unwrap() {
            failures.push(format!("{a:?} / {b:?}: Python {} Rust {got}", case[2]));
        }
    }
    report("similarity", &failures, pairs.len());
}

fn error_kind(name: &str) -> &'static str {
    match name {
        "TypeError" | "AttributeError" | "KeyError" => "type",
        "JSONDecodeError" | "UnicodeDecodeError" | "ValueError" => "json",
        other => panic!("基準に知らない例外: {other}"),
    }
}

fn rust_kind(e: &EnrichError) -> &'static str {
    match e {
        EnrichError::Type(_) => "type",
        EnrichError::Json(_) => "json",
    }
}

/// `_score_result`（項目の型の違いで Python が例外を出す所も）が Python と同じ。
#[test]
fn score_result_matches_python() {
    let cases = read_json("text_cases.json");
    let list = cases["score"].as_array().unwrap();
    let mut failures = Vec::new();
    for case in list {
        let got = djaudio_meta::score_result(&case[0], case[1].as_str().unwrap(), &case[2]);
        let want = &case[3];
        let same = match (&got, want.get("ok"), want.get("error")) {
            (Ok(v), Some(w), _) => bits(*v) == w.as_u64().unwrap(),
            (Err(e), _, Some(name)) => rust_kind(e) == error_kind(name.as_str().unwrap()),
            _ => false,
        };
        if !same {
            failures.push(format!("{case}: Rust {got:?}"));
        }
    }
    report("score", &failures, list.len());
}

/// `_build_search_queries`（媒体ごとの組み立て・重複の除き方）が Python と同じ。
#[test]
fn search_queries_match_python() {
    let cases = read_json("text_cases.json");
    let list = cases["queries"].as_array().unwrap();
    assert!(list.len() >= 1000);
    let mut failures = Vec::new();
    for case in list {
        let info = case[3].as_object().unwrap();
        let got = djaudio_meta::build_search_queries(
            case[0].as_str().unwrap(),
            &case[1],
            case[2].as_str().unwrap(),
            info,
        );
        if serde_json::json!(got) != case[4] {
            failures.push(format!("{case}\nRust {got:?}"));
        }
    }
    report("queries", &failures, list.len());
}

/// `_fetch_by_search` が `_score_result` に渡す比べる相手（題が「アーティスト - 曲名」なら分け、info に
/// アーティストがあればそちらを使う）が Python と同じ。基準は本物の関数に偽物の ClientSession を渡して取った。
#[test]
fn search_reference_matches_python() {
    let cases = read_json("text_cases.json");
    let list = cases["reference"].as_array().unwrap();
    assert!(list.len() >= 200, "{}", list.len());
    let mut failures = Vec::new();
    for case in list {
        let (ref_title, ref_artist) = djaudio_meta::reference(case[0].as_str().unwrap(), &case[1]);
        if ref_title != case[2].as_str().unwrap() || ref_artist != case[3] {
            failures.push(format!("{case}\nRust {ref_title:?} {ref_artist}"));
        }
    }
    report("reference", &failures, list.len());
}

// ---- ID3 タグ ----

fn cover_bytes(images: &Value, name: &str) -> Option<Vec<u8>> {
    match name {
        "jpeg" | "jpeg2" | "png" => Some(b64(images[name].as_str().unwrap())),
        "short" => Some(b"\xff\xd8".to_vec()),
        "magic_only" => Some(b"\xff\xd8\xff".to_vec()),
        "empty" => Some(Vec::new()),
        _ => None,
    }
}

/// mutagen の `_write_tags` で書いたあとの MP3 と、バイト列が全部同じ（書けない入力では、同じく失敗してファイルを変えない）。
#[test]
fn write_tags_matches_mutagen_byte_for_byte() {
    let images = read_json("images.json");
    let cases = read_json("tags_cases.json");
    let list = cases.as_array().unwrap();
    assert!(list.len() >= 200, "{}", list.len());
    let work = WorkDir::new("tags");
    let mut failures = Vec::new();
    for case in list {
        let id = case["id"].as_str().unwrap();
        let input = fixtures()
            .join("mp3")
            .join(format!("{}.mp3", case["input"].as_str().unwrap()));
        let path = work.0.join(format!("{id}.mp3"));
        std::fs::copy(&input, &path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let cover = cover_bytes(&images, case["cover"].as_str().unwrap());
        let got = id3::write_tags(&path, &case["data"], cover.as_deref());
        let after = std::fs::read(&path).unwrap();
        let want_ok = case["result"] == "ok";
        if got.is_ok() != want_ok {
            failures.push(format!("{id}: Python {} Rust {got:?}", case["result"]));
            continue;
        }
        let changed = after != before;
        if changed != case["changed"].as_bool().unwrap() {
            failures.push(format!(
                "{id}: 書き換えたか Python {} Rust {changed}",
                case["changed"]
            ));
            continue;
        }
        if changed {
            let want =
                std::fs::read(fixtures().join("tags_out").join(format!("{id}.mp3"))).unwrap();
            if want != after {
                let at = want
                    .iter()
                    .zip(&after)
                    .position(|(a, b)| a != b)
                    .unwrap_or(want.len().min(after.len()));
                failures.push(format!(
                    "{id}: {at} バイト目から違う（長さ Python {} Rust {}）",
                    want.len(),
                    after.len()
                ));
            }
        }
    }
    report("tags", &failures, list.len());
}

// ---- Deezer の呼び方（偽物の Deezer） ----

/// parse_qs の値の読み方（`+` は空白、`%XX` はバイト、UTF-8 で読めないところは U+FFFD）。
fn unquote_plus(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 台本の規則のうち、要求に当たる最初のもの（fake_deezer.py の `match_rule` と同じ）。
fn match_rule<'a>(rules: &'a [Value], target: &str) -> Option<&'a Value> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let q = query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (unquote_plus(k) == "q").then(|| unquote_plus(v))
        })
        .next();
    rules.iter().find(|rule| {
        if let Some(p) = rule.get("path").and_then(Value::as_str)
            && p != path
        {
            return false;
        }
        if let Some(p) = rule.get("path_prefix").and_then(Value::as_str)
            && !path.starts_with(p)
        {
            return false;
        }
        match rule.get("q") {
            Some(want) => q.as_deref() == want.as_str(),
            None => true,
        }
    })
}

/// 偽物の Deezer（fake_deezer.py と同じ台本の読み方）。
struct Fake {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn start_fake(rules: Vec<Value>) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (rules, base_c, requests_c) = (Arc::new(rules), base.clone(), requests.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (rules, base, requests) = (rules.clone(), base_c.clone(), requests_c.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let target = line.split(' ').nth(1).unwrap_or("").to_string();
                requests.lock().unwrap().push(target.clone());
                let empty = serde_json::json!({"status": 404, "body": ""});
                let response = match_rule(&rules, &target).map_or(&empty, |r| &r["response"]);
                if response.get("close").and_then(Value::as_bool) == Some(true) {
                    return;
                }
                if let Some(d) = response.get("delay").and_then(Value::as_f64) {
                    tokio::time::sleep(Duration::from_secs_f64(d)).await;
                }
                let body = match response.get("body_b64").and_then(Value::as_str) {
                    Some(b) => b64(b),
                    None => response["body"]
                        .as_str()
                        .unwrap_or("")
                        .replace("{BASE}", &base)
                        .into_bytes(),
                };
                let mut out = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response
                        .get("status")
                        .and_then(Value::as_u64)
                        .unwrap_or(200),
                    body.len()
                );
                let default_headers = serde_json::json!({"Content-Type": "application/json"});
                let headers = response.get("headers").unwrap_or(&default_headers);
                for (k, v) in headers.as_object().unwrap() {
                    out.push_str(&format!(
                        "{k}: {}\r\n",
                        v.as_str().unwrap().replace("{BASE}", &base)
                    ));
                }
                out.push_str("\r\n");
                if sock.write_all(out.as_bytes()).await.is_err() {
                    return;
                }
                if let Some(d) = response.get("body_delay").and_then(Value::as_f64) {
                    tokio::time::sleep(Duration::from_secs_f64(d)).await;
                }
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Fake { base, requests }
}

/// 台本に必ず足すカバー画像の規則（gen_flow.py の `cover_rules` と同じ）。
fn cover_rules(images: &Value) -> Vec<Value> {
    let image = |name: &str, ctype: &str| serde_json::json!({"status": 200, "body_b64": images[name], "headers": {"Content-Type": ctype}});
    vec![
        serde_json::json!({"path": "/cover/xl.jpg", "response": image("jpeg", "image/jpeg")}),
        serde_json::json!({"path": "/cover/big.jpg", "response": image("jpeg2", "image/jpeg")}),
        serde_json::json!({"path": "/cover/small.jpg", "response": image("png", "image/png")}),
        serde_json::json!({"path": "/cover/final.jpg", "response": image("jpeg2", "image/jpeg")}),
    ]
}

/// Python が送った行を、reqwest（url crate）が送る形にする: クエリの `'` だけが `%27` になる。
fn as_reqwest_sends(target: &str) -> String {
    match target.split_once('?') {
        Some((path, query)) => format!("{path}?{}", query.replace('\'', "%27")),
        None => target.to_string(),
    }
}

/// Python の基準の結果（True・False・例外の名前）と Rust の結果が同じか。
fn same_result(want: &Value, got: &Result<bool, EnrichError>) -> bool {
    match (want, got) {
        (Value::Bool(w), Ok(g)) => w == g,
        (Value::String(name), Err(e)) => error_kind(name) == rust_kind(e),
        _ => false,
    }
}

/// 偽物の Deezer に当てた `enrich_metadata` が、要求の行・順番・結果・書いたあとの MP3 まで Python と同じ。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrich_metadata_matches_python_against_fake_deezer() {
    let images = read_json("images.json");
    let flows = read_json("flow_cases.json");
    let scale = flows["scale"].as_f64().unwrap();
    // 時間切れは Python と同じ値（10 秒・15 秒）を、基準と同じ割合で縮めて試す。
    assert_eq!(djaudio_meta::API_TIMEOUT, Duration::from_secs(10));
    assert_eq!(djaudio_meta::COVER_TIMEOUT, Duration::from_secs(15));
    let api = djaudio_meta::API_TIMEOUT.mul_f64(scale);
    let cover = djaudio_meta::COVER_TIMEOUT.mul_f64(scale);
    let cases = flows["cases"].as_array().unwrap();
    assert!(cases.len() >= 90, "{}", cases.len());
    let work = WorkDir::new("flow");
    let mut failures = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        for t in case["timeouts"].as_array().unwrap() {
            let t = t.as_f64().unwrap();
            assert!(t == 10.0 || t == 15.0, "{id}: Python の時間切れ {t}");
        }
        let mut rules: Vec<Value> = case["rules"].as_array().unwrap().clone();
        rules.extend(cover_rules(&images));
        let fake = start_fake(rules).await;
        let deezer = Deezer::new(&fake.base).with_timeouts(api, cover);
        let input = fixtures()
            .join("mp3")
            .join(format!("{}.mp3", case["mp3"].as_str().unwrap()));
        let path = work.0.join(format!("flow_{id}.mp3"));
        std::fs::copy(&input, &path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let site = case["site"].as_str().unwrap();
        let got = djaudio_meta::enrich_metadata(&deezer, &path, &case["info"], site).await;
        let after = std::fs::read(&path).unwrap();
        *counts
            .entry(format!("{got:?}").chars().take(12).collect())
            .or_default() += 1;
        if !same_result(&case["result"], &got) {
            failures.push(format!("{id}: 結果 Python {} Rust {got:?}", case["result"]));
        }
        let python_requests: Vec<String> = case["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        for r in &python_requests {
            let query = r.split_once('?').map_or("", |(_, q)| q);
            assert!(
                !query.contains("%27"),
                "{id}: Python のクエリに %27 がある（比べ方の前提が崩れる）: {r}"
            );
        }
        let want: Vec<String> = python_requests
            .iter()
            .map(|r| as_reqwest_sends(r))
            .collect();
        let sent = fake.requests.lock().unwrap().clone();
        if sent != want {
            failures.push(format!(
                "{id}: 要求 Python {python_requests:?}\n  Rust {sent:?}"
            ));
        }
        // Rust が組み立てた行（yarl の写し）は、Python が送ったバイト列そのものと同じ。
        if let Some(info) = case["info"].as_object() {
            let isrc = info.get("isrc").cloned().unwrap_or(Value::Null);
            if djaudio_meta::truthy(&isrc) {
                let line = deezer
                    .isrc_url(&isrc)
                    .map(|u| u.raw_path_qs())
                    .unwrap_or_default();
                if python_requests.first() != Some(&line) {
                    failures.push(format!(
                        "{id}: ISRC の行 Python {:?} Rust {line:?}",
                        python_requests.first()
                    ));
                }
            }
            for r in python_requests.iter().filter(|r| r.starts_with("/search?")) {
                let q = match_q(r);
                let line = deezer
                    .search_url(&q)
                    .map(|u| u.raw_path_qs())
                    .unwrap_or_default();
                if &line != r {
                    failures.push(format!("{id}: 検索の行 Python {r:?} Rust {line:?}"));
                }
            }
        }
        let changed = after != before;
        if changed != case["changed"].as_bool().unwrap() {
            failures.push(format!(
                "{id}: 書き換えたか Python {} Rust {changed}",
                case["changed"]
            ));
        } else if changed {
            let want =
                std::fs::read(fixtures().join("flow_out").join(format!("{id}.mp3"))).unwrap();
            if want != after {
                failures.push(format!("{id}: 書いたあとの MP3 が違う"));
            }
        }
    }
    eprintln!("結果の数: {counts:?}");
    report("flow", &failures, cases.len());
}

/// 検索の行から q を取り出す（偽物と同じ読み方）。
fn match_q(target: &str) -> String {
    let query = target.split_once('?').map_or("", |(_, q)| q);
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("q=").map(unquote_plus))
        .unwrap_or_default()
}
