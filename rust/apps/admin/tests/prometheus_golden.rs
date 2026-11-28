//! Netdata が読む `/metrics`（A7）が、本物の Python（uvicorn の `ProxyHeadersMiddleware` → 管理画面の app）と同じ
//! 答えを返すこと。いちばん大事なのは接続元の判定（信頼するプロキシで直したあとの接続元で見る。TCP の相手〔nginx〕で
//! 見ない）。
//!
//! 基準は `fixtures/prometheus/expected.json`（generate.py が本物の Python で作った。例は cases.json）:
//!
//! - requests: 例ごとに、直接つないできた相手・見出し・環境変数（`METRICS_ALLOWED_CIDRS`・`TRUSTED_PROXY_CIDRS`・
//!   `METRICS_STALE_AFTER_SECONDS`）・Valkey の中身・時刻・バックアップの状態のファイルを決めて送った答え（状態・見出し・
//!   本文をバイトまで）。Rust は、Python の Valkey が読めたもの（基準の scan）を返す偽物の置き場を差し込んだ app に、
//!   同じ要求を [`AdminApp::respond`] で渡す
//! - 同じ例の Valkey を、RESP を話す偽物の Valkey（このテストの中で立てる）に置き、本物の [`ValkeyStore`] で読んだもの・
//!   読んだあとに使えるか・届いた `SCAN`・`MGET` が、Python の `SharedCache.scan_values` と同じこと（途中で切れる・
//!   UTF-8 でない値・値の無い鍵も）
//! - functions: `METRICS_PATH` の読み方、許す帯域 × 接続元 → 通すか、値の読み方（`float()`）と書き方

mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Incoming, OsRandom};
use sycs_admin::auth::{Discord, DiscordConfig};
use sycs_admin::errors::PlainPages;
use sycs_admin::monitor::host::ProcFs;
use sycs_admin::monitor::prometheus;
use sycs_admin::monitor::pyfloat;
use sycs_admin::monitor::valkey::{MetricsStore, Scan, ScanFuture, ValkeyStore};
use sycs_admin::monitor::{Monitor, Settings};
use sycs_admin::python;
use sycs_admin::routes;
use sycs_admin::templates::{Pages, PagesConfig};
use sycs_admin::views::Site;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{self, TrustedHosts};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/prometheus");

fn read(name: &str) -> Value {
    let path = format!("{DIR}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{path} が読めません: {e}。CI の「基準」が作ったものを取ってきてコミットすること")
    });
    serde_json::from_str(&text).unwrap()
}

/// repr の文字の小数。
fn float(value: &Value) -> f64 {
    value.as_str().unwrap().parse().unwrap()
}

/// 例の valkey（valkey_specs の名前か、その場で書いた中身）。generate.py の valkey_spec。
fn valkey_spec<'a>(case: &'a Value, document: &'a Value) -> &'a Value {
    match &case["valkey"] {
        Value::String(name) => &document["valkey_specs"][name.as_str()],
        other => other,
    }
}

/// Python の Valkey が読めたもの（基準の scan）を返す偽物の置き場。
struct Recorded(Scan);

impl MetricsStore for Recorded {
    fn scan(&self) -> ScanFuture<'_> {
        let scan = self.0.clone();
        Box::pin(async move { scan })
    }
}

/// 基準の scan（items と available）を [`Scan`] にする。
fn recorded_scan(scan: &Value) -> Scan {
    Scan {
        items: scan["items"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
            .collect(),
        available: scan["available"].as_bool().unwrap(),
    }
}

/// 例の環境変数を引く関数。
fn lookup(env: &Value) -> impl Fn(&str) -> Option<String> + Clone + Send + Sync + 'static {
    let map = env.as_object().cloned().unwrap_or_default();
    move |key: &str| map.get(key).and_then(Value::as_str).map(str::to_string)
}

/// 例の backup のとおりにバックアップの状態のファイルを置き、そのパスを返す（generate.py の write_backup）。
fn write_backup(dir: &Path, spec: &Value) -> std::path::PathBuf {
    let folder = dir.join("backups");
    if let Value::Object(map) = spec {
        std::fs::create_dir(&folder).unwrap();
        if let Some(text) = map.get("text").and_then(Value::as_str) {
            std::fs::write(folder.join("status.json"), text).unwrap();
        } else if let Some(hex) = map.get("hex").and_then(Value::as_str) {
            std::fs::write(folder.join("status.json"), support::hex_bytes(hex)).unwrap();
        }
    }
    folder.join("status.json")
}

fn site() -> Arc<Site> {
    let config = PagesConfig {
        templates_dir: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../webapp_admin/templates"),
        static_dir: std::path::PathBuf::from("/nonexistent-admin-fixture-static"),
        asset_version: "admin".to_string(),
    };
    let pages = Arc::new(Pages::load(&config).unwrap());
    let discord = Discord::new(
        DiscordConfig::from_lookup(|_| None),
        "http://127.0.0.1:9/api/v10",
    )
    .unwrap();
    Arc::new(Site::new(
        pages,
        Arc::new(discord),
        Arc::new(|| Ok(0)),
        Arc::new(|| "unused-state".to_string()),
    ))
}

/// 例の要求（見出しは並びのまま。2 つある名前は 2 つとも送る）。
fn incoming(case: &Value) -> Incoming {
    let target = case.get("target").and_then(Value::as_str).unwrap_or("/metrics");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = HeaderMap::new();
    for pair in case["headers"].as_array().into_iter().flatten() {
        let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(&support::latin1_bytes(pair[1].as_str().unwrap())).unwrap();
        headers.append(name, value);
    }
    let method = case.get("method").and_then(Value::as_str).unwrap_or("GET");
    Incoming {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path,
        query,
        headers,
        body: Bytes::new(),
        peer: case["peer"].as_str().map(str::to_string),
    }
}

/// 例ごとの app（信頼するプロキシ・許す帯域・時刻・起きた時刻・要求の時刻・Valkey の中身・バックアップの置き場）。
fn app(case: &Value, scan: Scan, dir: &Path, site: &Arc<Site>) -> Arc<AdminApp> {
    let env = lookup(&case["env"]);
    let now = case.get("now").map_or(0.0, float);
    let started = case.get("started").map_or(0.0, float);
    let config = Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(&proxy::trusted_proxies_setting(env("TRUSTED_PROXY_CIDRS").as_deref())),
        dev_user_id: String::new(),
        monitor_dir: dir.join("monitor"),
    };
    let deps = Deps {
        clock: Arc::new(move || now),
        random: Arc::new(OsRandom),
        pages: Arc::new(PlainPages),
        reporter: Arc::new(Reporter::new("test", None)),
    };
    let backup = write_backup(dir, &case["backup"]);
    let backup_text = backup.to_string_lossy().into_owned();
    let settings = Settings::from_lookup(move |key: &str| {
        if key == "BACKUP_STATUS_FILE" {
            return Some(backup_text.clone());
        }
        env(key)
    });
    let monitor = Monitor::new(
        settings,
        Arc::new(ProcFs::new("/nonexistent-proc", "/nonexistent-cpu-online")),
        Arc::new(Recorded(scan)),
        Arc::new(move || now),
    )
    .with_started_at(started);
    let admin = AdminApp::new(config, "prometheus-fixture-secret", deps, routes::default_routes(site))
        .with_monitor(Arc::new(monitor));
    for t in case["requests"].as_array().into_iter().flatten() {
        admin.metrics().record_request(float(t));
    }
    Arc::new(admin)
}

#[tokio::test]
async fn metrics_answer_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    let site = site();
    let mut wrong = Vec::new();
    let cases = document["requests"].as_array().unwrap();
    let answers = data["requests"].as_array().unwrap();
    assert_eq!(cases.len(), answers.len(), "基準が例の文書と食い違う");
    let mut allowed = 0;
    let mut forbidden = 0;
    for (case, answer) in cases.iter().zip(answers) {
        let name = case["name"].as_str().unwrap();
        assert_eq!(answer["name"], case["name"]);
        let dir = tempfile::tempdir().unwrap();
        let app = app(case, recorded_scan(&answer["scan"]), dir.path(), &site);
        let request = incoming(case);
        let head = request.method == Method::HEAD;
        let reply = app.respond(request).await;
        match reply.status {
            200 => allowed += 1,
            403 => forbidden += 1,
            _ => {}
        }
        for problem in support::compare_reply(&answer["response"], &reply, head) {
            wrong.push(format!("「{name}」: {problem}"));
        }
    }
    assert!(allowed >= 20 && forbidden >= 10, "通した {allowed}・断った {forbidden}");
    support::finish(&wrong);
}

#[test]
fn functions_match_python() {
    let data = read("expected.json");
    let functions = &data["functions"];
    let mut wrong = Vec::new();
    for row in functions["metrics_path"].as_array().unwrap() {
        let got = prometheus::metrics_path(row[0].as_str());
        if got != row[1].as_str().unwrap() {
            wrong.push(format!("metrics_path({}): Python {} / Rust {got:?}", row[0], row[1]));
        }
    }
    let mut checked = 0;
    for row in functions["client_allowed"].as_array().unwrap() {
        let networks = prometheus::allowed_networks(row[0].as_str());
        let got = prometheus::client_allowed(row[1].as_str(), &networks);
        checked += 1;
        if got != row[2].as_bool().unwrap() {
            wrong.push(format!(
                "client_allowed(METRICS_ALLOWED_CIDRS={}, 接続元 {}): Python {} / Rust {got}",
                row[0], row[1], row[2]
            ));
        }
    }
    assert!(checked >= 500, "接続元の表が足りない（{checked}）");
    for row in functions["parse_float"].as_array().unwrap() {
        let got = pyfloat::py_float(row[0].as_str().unwrap()).map(python::float_repr);
        if got.as_deref() != row[1].as_str() {
            wrong.push(format!("float({}): Python {} / Rust {got:?}", row[0], row[1]));
        }
    }
    for row in functions["format_value"].as_array().unwrap() {
        let input: f64 = row[0].as_str().unwrap().parse().unwrap();
        let got = match pyfloat::format_value(input) {
            Ok(text) => json!({"value": text}),
            Err(crash) => json!({"error": crash.kind, "message": crash.message}),
        };
        if got != row[1] {
            wrong.push(format!("_format_value({}): Python {} / Rust {got}", row[0], row[1]));
        }
    }
    support::finish(&wrong);
}

/// 偽物の Valkey に届いた SCAN・MGET（Python の偽物の控えと同じ形）。
type Calls = Arc<Mutex<Vec<Value>>>;

/// RESP の要求を 1 つ読む（`*N\r\n$len\r\narg\r\n…`）。切れたら `None`。
async fn read_command<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Option<Vec<Vec<u8>>> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let count: usize = line.trim_end().strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = String::new();
        reader.read_line(&mut header).await.ok()?;
        let len: usize = header.trim_end().strip_prefix('$')?.parse().ok()?;
        let mut arg = vec![0u8; len + 2];
        reader.read_exact(&mut arg).await.ok()?;
        arg.truncate(len);
        args.push(arg);
    }
    Some(args)
}

fn bulk(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(format!("${}\r\n", bytes.len()).as_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
}

/// 例の valkey のとおりに答える（generate.py の FakeRedis と同じ決まり）。fail_at 番目の SCAN・MGET では答えずに切る。
async fn serve_connection(stream: tokio::net::TcpStream, spec: Value, calls: Calls) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let pages: Vec<Vec<String>> = spec["pages"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|page| page.as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect())
        .collect();
    while let Some(args) = read_command(&mut reader).await {
        let command = String::from_utf8_lossy(&args[0]).to_uppercase();
        let text = |i: usize| String::from_utf8_lossy(&args[i]).into_owned();
        let mut out = Vec::new();
        match command.as_str() {
            "SCAN" => {
                let cursor: usize = text(1).parse().unwrap();
                let count: u64 = text(5).parse().unwrap();
                let index = {
                    let mut calls = calls.lock().unwrap_or_else(PoisonError::into_inner);
                    calls.push(json!(["scan", cursor, text(3), count]));
                    calls.len() - 1
                };
                if spec["fail_at"].as_u64() == Some(index as u64) {
                    return;
                }
                let keys = pages.get(cursor).cloned().unwrap_or_default();
                let next = if cursor + 1 < pages.len() { cursor + 1 } else { 0 };
                out.extend_from_slice(b"*2\r\n");
                bulk(&mut out, next.to_string().as_bytes());
                out.extend_from_slice(format!("*{}\r\n", keys.len()).as_bytes());
                for key in &keys {
                    bulk(&mut out, key.as_bytes());
                }
            }
            "MGET" => {
                let keys: Vec<String> = (1..args.len()).map(text).collect();
                let index = {
                    let mut calls = calls.lock().unwrap_or_else(PoisonError::into_inner);
                    calls.push(json!(["mget", keys]));
                    calls.len() - 1
                };
                if spec["fail_at"].as_u64() == Some(index as u64) {
                    return;
                }
                out.extend_from_slice(format!("*{}\r\n", keys.len()).as_bytes());
                for key in &keys {
                    if let Some(hex) = spec["hex_values"].get(key).and_then(Value::as_str) {
                        bulk(&mut out, &support::hex_bytes(hex));
                    } else if let Some(value) = spec["values"].get(key).and_then(Value::as_str) {
                        bulk(&mut out, value.as_bytes());
                    } else {
                        out.extend_from_slice(b"$-1\r\n");
                    }
                }
            }
            "PING" => out.extend_from_slice(b"+PONG\r\n"),
            // つないだときの設定（CLIENT SETINFO など）は、何であっても受け付ける。
            _ => out.extend_from_slice(b"+OK\r\n"),
        }
        if write_half.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// 偽物の Valkey を立て、つなぎ先の URL を返す（何度つなぎ直しても同じ答え方）。
async fn fake_valkey(spec: Value, calls: Calls) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_connection(stream, spec.clone(), Arc::clone(&calls)));
        }
    });
    format!("redis://{addr}/0")
}

#[tokio::test]
async fn valkey_is_scanned_like_shared_cache() {
    let data = read("expected.json");
    let document = read("cases.json");
    let mut wrong = Vec::new();
    let mut seen = BTreeSet::new();
    for (case, answer) in document["requests"]
        .as_array()
        .unwrap()
        .iter()
        .zip(data["requests"].as_array().unwrap())
    {
        let spec = valkey_spec(case, &document).clone();
        // 同じ valkey の例は 1 回だけ確かめる。
        if !seen.insert(spec.to_string()) {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let calls: Calls = Arc::default();
        let url = match spec.get("url").and_then(Value::as_str).unwrap_or("") {
            "" => String::new(),
            _ if spec["factory_raises"].as_bool() == Some(true) => "not-a-url".to_string(),
            _ => fake_valkey(spec.clone(), Arc::clone(&calls)).await,
        };
        let store = ValkeyStore::new(&url, Duration::from_secs(2), Duration::from_secs(30));
        let got = store.scan().await;
        let want = recorded_scan(&answer["scan"]);
        if got != want {
            wrong.push(format!("「{name}」の読めたもの:\n    Python {want:?}\n    Rust   {got:?}"));
        }
        let got_calls = Value::Array(calls.lock().unwrap().clone());
        if got_calls != answer["scan"]["calls"] {
            wrong.push(format!(
                "「{name}」の SCAN・MGET:\n    Python {}\n    Rust   {got_calls}",
                answer["scan"]["calls"]
            ));
        }
        // 失敗したあとは、遮断器が開いている間は Valkey へ行かない（Python の遮断器と同じ）。
        if !got.available && store.configured() {
            let before = calls.lock().unwrap().len();
            let again = store.scan().await;
            if again.available || !again.items.is_empty() || calls.lock().unwrap().len() != before {
                wrong.push(format!("「{name}」: 遮断器が開いているのに Valkey へ行った"));
            }
        }
    }
    assert!(seen.len() >= 12, "確かめた valkey の例が足りない（{}）", seen.len());
    support::finish(&wrong);
}
