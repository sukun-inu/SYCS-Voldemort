//! Groq の呼び出しと投稿の判定を、テストの中で立てた偽物の Groq に当てて確かめる。
//!
//! 本物の Python（services/content_moderation.py ＋ groq SDK 1.7.0）とは、同じ形の偽物に両方を当てて
//! 30 例とも一致することを確かめた（変更のコミットに記録）。ここではその流れを CI で毎回回す。
//!
//! 偽物は本文の `case=名前` で答え方を変える（Python の確かめに使った fakegroq.py と同じ）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sycs_bot::groq::{Groq, GroqConfig, GroqError};
use sycs_bot::moderation::{self, AssessInput, Moderation, Verdict};
use sycs_bot::virustotal::VtResult;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 偽物が見たもの。
#[derive(Default)]
struct Seen {
    total: usize,
    inflight: usize,
    max_inflight: usize,
    counts: HashMap<String, usize>,
    bodies: Vec<Value>,
    auth_ok: bool,
}

type Shared = Arc<Mutex<Seen>>;

fn http(status: u16, ctype: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn completion(content: Value) -> Vec<u8> {
    let body =
        json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": content}}]});
    http(200, "application/json", &[], body.to_string().as_bytes())
}

fn error(status: u16, headers: &[(&str, &str)]) -> Vec<u8> {
    http(
        status,
        "application/json",
        headers,
        br#"{"error":{"message":"fake"}}"#,
    )
}

/// 名前と、その印（`#…` まで）で何回目かから答えを決める。
fn answer(name: &str, n: usize) -> Vec<u8> {
    let rl = [("retry-after-ms", "1"), ("retry-after", "0")];
    match name {
        "safe" | "prompt" | "slow" => completion(json!("SAFE")),
        "dangerous" => completion(json!("This is DANGEROUS.")),
        "suspicious" => completion(json!("suspicious")),
        "warning" => completion(json!("Warning: maybe")),
        "longs" => completion(json!("ſuſpiciouſ")),
        "other" => completion(json!("I cannot decide")),
        "empty" => completion(json!("")),
        "nullcontent" => completion(Value::Null),
        "emptychoices" => http(200, "application/json", &[], br#"{"choices": []}"#),
        "notjson" => http(200, "text/plain", &[], b"SAFE"),
        "badjson" => http(200, "application/json", &[], b"{"),
        "flaky500" if n == 1 => error(500, &[]),
        "flaky500" => completion(json!("DANGEROUS")),
        "bad400" => error(400, &[]),
        "nore500" => error(500, &[("x-should-retry", "false")]),
        "xretry400" if n == 1 => error(400, &[("x-should-retry", "true")]),
        "xretry400" => completion(json!("SAFE")),
        "retry408" if n == 1 => error(408, &[]),
        "retry408" => completion(json!("SUSPICIOUS")),
        "ratelimit" => error(429, &rl),
        "rl2" if n <= 2 => error(429, &rl),
        "rl2" => completion(json!("SUSPICIOUS")),
        "rl3" if n <= 3 => error(429, &rl),
        "rl3" => completion(json!("DANGEROUS")),
        _ => error(404, &[]),
    }
}

/// 本文から `case=名前#印` を読む。無ければ safe。
fn marker(user: &str) -> (String, String) {
    let Some(start) = user.find("case=") else {
        return ("safe".into(), "-".into());
    };
    let rest = &user[start + 5..];
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    let tail: String = rest[name.len()..]
        .chars()
        .take_while(|c| *c == '#' || !c.is_whitespace())
        .collect();
    let tail = if tail.starts_with('#') {
        tail
    } else {
        String::new()
    };
    (name.clone(), format!("case={name}{tail}"))
}

async fn start_fake() -> (String, Shared) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Shared = Arc::new(Mutex::new(Seen {
        auth_ok: true,
        ..Seen::default()
    }));
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
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
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let length: usize = header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + length {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                if path != "/openai/v1/chat/completions" {
                    let _ = sock.write_all(&error(404, &[])).await;
                    return;
                }
                let body: Value = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                let user = body["messages"][1]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let (name, mark) = marker(&user);
                let n = {
                    let mut s = seen.lock().unwrap();
                    s.total += 1;
                    s.inflight += 1;
                    s.max_inflight = s.max_inflight.max(s.inflight);
                    if header("authorization").as_deref() != Some("Bearer test-key") {
                        s.auth_ok = false;
                    }
                    s.bodies.push(body);
                    let c = s.counts.entry(mark).or_default();
                    *c += 1;
                    *c
                };
                match name.as_str() {
                    // 遅い環境でも 3 つ目が届く前に 1 つ目が終わらないよう、長めに待つ。
                    "slow" => tokio::time::sleep(Duration::from_secs(2)).await,
                    // 答えない（時間切れを確かめる）。
                    "hang" => tokio::time::sleep(Duration::from_secs(30)).await,
                    _ => {}
                }
                // 答える前に数を減らす（答えを受けた側が次を送るのと競わないように）。
                seen.lock().unwrap().inflight -= 1;
                let _ = sock.write_all(&answer(&name, n)).await;
            });
        }
    });
    (base, seen)
}

fn config(base: &str, key: Option<&str>) -> GroqConfig {
    GroqConfig {
        api_key: key.map(str::to_string),
        base_url: base.into(),
        max_concurrent: 3,
        min_interval: 0.25,
        max_retries: 2,
        retry_base_delay: 2.0,
        retry_max_delay: 20.0,
    }
}

fn moderation(base: &str) -> Arc<Moderation> {
    Arc::new(Moderation::new(
        Arc::new(Groq::new(config(base, Some("test-key")))),
        300.0,
    ))
}

fn vt(pairs: &[(i64, i64)]) -> Vec<VtResult> {
    pairs
        .iter()
        .map(|&(malicious, suspicious)| VtResult {
            status: "ok".into(),
            kind: "url".into(),
            malicious,
            suspicious,
            reason: None,
        })
        .collect()
}

async fn assess(m: &Moderation, text: &str) -> Verdict {
    assess_with(m, text, &[], 1, f64::INFINITY, false).await
}

async fn assess_with(
    m: &Moderation,
    text: &str,
    vt_results: &[VtResult],
    spam_count: usize,
    min_interval: f64,
    is_new_member: bool,
) -> Verdict {
    m.assess(&AssessInput {
        text,
        vt_results,
        spam_count,
        min_interval,
        is_new_member,
    })
    .await
}

fn total(seen: &Shared) -> usize {
    seen.lock().unwrap().total
}

/// 答えの読み方と、SDK の再試行・回数制限の再試行で送る回数が Python と同じであること。
#[tokio::test]
async fn verdicts_and_retries_match_python() {
    let (base, seen) = start_fake().await;
    let m = moderation(&base);
    // (本文, 判定, 送る回数)。Python の突き合わせで得た値。
    let cases: &[(&str, Verdict, usize)] = &[
        ("case=safe", Verdict::Safe, 1),
        ("case=dangerous", Verdict::Dangerous, 1),
        ("case=suspicious", Verdict::Suspicious, 1),
        ("case=warning", Verdict::Suspicious, 1),
        ("case=longs", Verdict::Suspicious, 1),
        ("case=other", Verdict::Safe, 1),
        ("case=empty", Verdict::Safe, 1),
        ("case=emptychoices", Verdict::Unknown, 1),
        ("case=notjson", Verdict::Unknown, 1),
        ("case=badjson", Verdict::Unknown, 1),
        ("case=flaky500", Verdict::Dangerous, 2),
        ("case=bad400", Verdict::Unknown, 1),
        ("case=nore500", Verdict::Unknown, 1),
        ("case=xretry400", Verdict::Safe, 2),
        ("case=retry408", Verdict::Suspicious, 2),
        ("case=ratelimit", Verdict::Unknown, 9),
        ("case=rl2", Verdict::Suspicious, 3),
        ("case=rl3", Verdict::Dangerous, 4),
    ];
    for (text, want, sends) in cases {
        let before = total(&seen);
        assert_eq!(assess(&m, text).await, *want, "{text}");
        assert_eq!(total(&seen) - before, *sends, "{text} の送った回数");
    }
    assert!(seen.lock().unwrap().auth_ok, "鍵を Bearer で送っていない");
}

/// 成功した判定は覚え、失敗は覚えないこと。鍵には状況と VirusTotal の数も入ること。
#[tokio::test]
async fn verdicts_are_cached_but_failures_are_not() {
    let (base, seen) = start_fake().await;
    let m = moderation(&base);
    assert_eq!(assess(&m, "case=safe#c").await, Verdict::Safe);
    assert_eq!(assess(&m, "case=safe#c").await, Verdict::Safe);
    assert_eq!(total(&seen), 1, "同じ投稿を 2 回尋ねた");
    assert_eq!(assess(&m, "case=nullcontent").await, Verdict::Unknown);
    assert_eq!(assess(&m, "case=nullcontent").await, Verdict::Unknown);
    assert_eq!(total(&seen), 3, "失敗を覚えた");
    let before = total(&seen);
    let t = "case=safe#k";
    assess_with(&m, t, &[], 1, f64::INFINITY, false).await;
    assess_with(&m, t, &[], 5, f64::INFINITY, false).await;
    assess_with(&m, t, &[], 1, f64::INFINITY, true).await;
    assess_with(&m, t, &[], 1, 1.5, false).await;
    assess_with(&m, t, &vt(&[(0, 0)]), 1, f64::INFINITY, false).await;
    assert_eq!(total(&seen) - before, 5, "状況の違いを同じ鍵にした");
}

/// VirusTotal で決まるとき・鍵が無いとき・本文が空白だけのときは呼ばないこと。
#[tokio::test]
async fn some_inputs_never_reach_groq() {
    let (base, seen) = start_fake().await;
    let m = moderation(&base);
    let d = assess_with(&m, "case=safe#v", &vt(&[(0, 0), (12, 0)]), 1, 1e9, false).await;
    assert_eq!(d, Verdict::Dangerous);
    let s = assess_with(&m, "case=safe#v", &vt(&[(0, 1), (30, 0)]), 1, 1e9, false).await;
    assert_eq!(s, Verdict::Suspicious, "最初に当たった結果で決める");
    assert_eq!(
        assess(&m, "  \n\u{1C}\u{3000}").await,
        Verdict::Safe,
        "空白だけ"
    );
    assert_eq!(total(&seen), 0);
    // 走査の結果があれば、本文が空白でも尋ねる。引っかからなかった結果（-1 を含む）も尋ねる。
    assess_with(&m, " ", &vt(&[(0, 0)]), 1, 1e9, false).await;
    assess_with(&m, "case=safe#w", &vt(&[(0, 0), (-1, -1)]), 1, 1e9, false).await;
    assert_eq!(total(&seen), 2);
    let no_key = Moderation::new(Arc::new(Groq::new(config(&base, None))), 300.0);
    assert_eq!(assess(&no_key, "case=dangerous#n").await, Verdict::Safe);
    assert_eq!(total(&seen), 2, "鍵が無いのに送った");
}

/// 送る中身が Python と同じ形であること（モデル・システムへの指示・状況の行・本文）。
#[tokio::test]
async fn the_request_has_the_python_shape() {
    let (base, seen) = start_fake().await;
    let m = moderation(&base);
    let text = "case=prompt\n本文😀 <https://a.example>";
    assess_with(&m, text, &[], 5, 0.75, true).await;
    let body = seen.lock().unwrap().bodies[0].clone();
    let context = moderation::context_block(5, 0.75, true);
    assert_eq!(body, moderation::request_body(&context, text));
    assert_eq!(body["model"], "openai/gpt-oss-20b");
    assert_eq!(
        body["messages"][1]["content"].as_str().unwrap(),
        format!(
            "{}【スパム警告】このユーザーは直近15秒間に5回メッセージを送信しています。\n\
             【高頻度】メッセージ送信間隔が最短0.8秒と非常に短いです。\n\
             【新規】このユーザーはサーバー参加から7日未満の新規メンバーです。\n\n投稿内容:\n{text}",
            moderation::prompt("", "").trim_end_matches("投稿内容:\n")
        )
    );
}

/// 用途ごとに同時に 3 つまで送ること。
///
/// 送る間隔（0.25 秒）は、ここでは確かめない。偽物に届いた時刻で測ると、遅い環境では送り出しが空いていても
/// 届く間隔が詰まって見える（CI で実際に落ちた）。間隔は `groq.rs` の単体テストが、送ってよくなった時刻
/// そのもので確かめる。
#[tokio::test]
async fn three_at_a_time() {
    let (base, seen) = start_fake().await;
    let m = moderation(&base);
    let mut set = tokio::task::JoinSet::new();
    for i in 0..6 {
        let m = Arc::clone(&m);
        set.spawn(async move { assess(&m, &format!("case=slow#{i}")).await });
    }
    while let Some(v) = set.join_next().await {
        assert_eq!(v.unwrap(), Verdict::Safe);
    }
    let s = seen.lock().unwrap();
    assert_eq!(s.total, 6);
    assert_eq!(s.max_inflight, 3, "同時に送る数の枠が効いていない");
}

/// 時間切れも SDK が 2 回まで再試行し、そのあと失敗にすること（回数制限の再試行はしない）。
#[tokio::test]
async fn timeouts_are_retried_by_the_sdk_only() {
    let (base, seen) = start_fake().await;
    let groq = Groq::new(config(&base, Some("test-key")));
    let body = moderation::request_body("", "case=hang");
    let started = Instant::now();
    let result = groq
        .chat_completion(moderation::BUCKET, Duration::from_secs(1), &body)
        .await;
    assert!(matches!(result, Err(GroqError::Timeout)), "{result:?}");
    // 時間切れは、遅い環境でも送信が届いてから切れる長さ（1 秒）にしてある。
    assert_eq!(total(&seen), 3);
    // 1 秒 × 3 回と、0.5 秒・1 秒（0.75〜1 倍）の待ち。
    assert!(started.elapsed() >= Duration::from_millis(4100));
}

/// 鍵が無ければ送らずに失敗にすること。
#[tokio::test]
async fn no_key_means_no_request() {
    let (base, seen) = start_fake().await;
    let groq = Groq::new(config(&base, None));
    let result = groq
        .chat_completion(moderation::BUCKET, Duration::from_secs(1), &json!({}))
        .await;
    assert!(matches!(result, Err(GroqError::NoKey)));
    assert_eq!(total(&seen), 0);
}
