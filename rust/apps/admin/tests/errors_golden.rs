//! 管理画面の骨組み（エラーの答え・見出し・経路・旧 URL・4 つの確かめ・回数の制限・数とインシデント）が、本物の
//! Python の管理画面と同じ答えを返すこと。
//!
//! 基準は `fixtures/errors/expected.json`（generate.py が、本物の `webapp_admin.app` に基準のためだけの経路を足して、
//! starlette の TestClient で回して作った。例は cases.json）。ここでも同じ形の経路（[`probes`]）を同じ順に足し、例ごとに
//! 新しい app（数・回数の制限・インシデントの置き場が空）を作って、同じ要求を [`AdminApp::respond`] に渡す。
//!
//! 比べるもの: 状態・見出し（名前の順。同じ名前の中は足した順）・本文（バイトまで。HTML のエラーのページも、本物の
//! テンプレート〔A2〕で描いて比べる。資材の URL は Python と同じく static の置き場を無い場所にした `?v=admin` の形）、
//! 例ごとに足した数と、`incidents.jsonl` に足された行。

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Incoming, Random, Reply, Req, handler};
use sycs_admin::auth::{Discord, DiscordConfig};
use sycs_admin::errors::{Crash, Failure, HttpError};
use sycs_admin::metrics::INCIDENTS_FILE;
use sycs_admin::python;
use sycs_admin::routes;
use sycs_admin::routing::Route;
use sycs_admin::templates::{Pages, PagesConfig};
use sycs_admin::views::Site;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

const API: &str = "/admin/api/__a1";
const PAGE: &str = "/__a1";

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/errors/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// 例ごとに 1 から数える、決まった並びの乱数（generate.py の Sequence と同じ）。
struct Sequence {
    token_base: u64,
    id_base: u64,
    tokens: AtomicU64,
    ids: AtomicU64,
}

impl Random for Sequence {
    fn token_hex(&self, _nbytes: usize) -> String {
        let n = self.tokens.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{:064x}", self.token_base + n)
    }

    fn uuid_hex(&self) -> String {
        let n = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{:032x}", self.id_base + n)
    }
}

/// 問い合わせを starlette の `request.query_params` と同じに読む（最後の値が勝つ）。
fn query_param(req: &Req, name: &str) -> Option<String> {
    let query = req.query.as_deref()?;
    let mut found = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if python::form_unquote(key.as_bytes()) == name {
            found = Some(python::form_unquote(value.as_bytes()));
        }
    }
    found
}

fn ok() -> Result<Reply, Failure> {
    Ok(Reply::json(200, &json!({"ok": true})))
}

fn code(req: &Req) -> u16 {
    req.param("code").and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// generate.py の make_probes と同じ経路を、同じ順に（どれも app に直に足したもの。最後の 1 つだけルーターの中）。
fn probes() -> Vec<Route> {
    let get = [Method::GET];
    let post = [Method::POST];
    let http = || {
        handler(|_app, req: Req| async move {
            let status = code(&req);
            let mut error = if query_param(&req, "dict").is_some() {
                HttpError::without_text(status)
            } else {
                match query_param(&req, "detail") {
                    Some(detail) => HttpError::with_detail(status, &detail),
                    None => HttpError::new(status),
                }
            };
            if let Some(header) = query_param(&req, "header") {
                let (name, value) = header.split_once(':').unwrap_or((header.as_str(), ""));
                error = error.header(name, value);
            }
            Err::<Reply, Failure>(error.into())
        })
    };
    let crash = || {
        handler(|_app, req: Req| async move {
            let kind = query_param(&req, "type").unwrap_or_else(|| "RuntimeError".to_string());
            let repeat: usize = query_param(&req, "repeat")
                .and_then(|r| r.parse().ok())
                .unwrap_or(1);
            let message = query_param(&req, "message")
                .unwrap_or_default()
                .repeat(repeat);
            Err::<Reply, Failure>(Crash::new(&kind, message).into())
        })
    };
    let limited = || {
        handler(|app: Arc<AdminApp>, req: Req| async move {
            app.check_route_limit(&req, 2)?;
            ok()
        })
    };
    vec![
        Route::top_level(&format!("{API}/http/{{code}}"), &get, http()),
        Route::top_level(&format!("{PAGE}/http/{{code}}"), &get, http()),
        Route::top_level(&format!("{API}/crash"), &get, crash()),
        Route::top_level(&format!("{PAGE}/crash"), &get, crash()),
        Route::top_level(
            &format!("{API}/status/{{code}}"),
            &get,
            handler(|_app, req: Req| async move {
                Ok::<Reply, Failure>(Reply::json(code(&req), &json!({"ok": true})))
            }),
        ),
        // デコレータの付いた経路は、既定の制限が掛からず、係の中で数える。
        Route::new(&format!("{API}/limited"), &get, limited()),
        Route::new(&format!("{PAGE}/limited"), &get, limited()),
        Route::new(
            &format!("{API}/limited-login"),
            &get,
            handler(|app: Arc<AdminApp>, req: Req| async move {
                req.check_login()?;
                app.check_route_limit(&req, 2)?;
                ok()
            }),
        ),
        Route::top_level(
            &format!("{API}/login"),
            &get,
            handler(|_app, req: Req| async move {
                req.check_login()?;
                ok()
            }),
        ),
        Route::top_level(
            &format!("{API}/guild"),
            &get,
            handler(|_app, req: Req| async move {
                req.check_guild()?;
                ok()
            }),
        ),
        Route::top_level(
            &format!("{API}/dev"),
            &get,
            handler(|app: Arc<AdminApp>, req: Req| async move {
                let user = app.check_dev(&req)?;
                Ok::<Reply, Failure>(Reply::json(200, &json!({"ok": true, "user": user})))
            }),
        ),
        Route::top_level(
            &format!("{API}/csrf"),
            &post,
            handler(|app: Arc<AdminApp>, req: Req| async move {
                app.check_csrf(&req)?;
                ok()
            }),
        ),
        Route::top_level(
            &format!("{API}/guild-csrf"),
            &post,
            handler(|app: Arc<AdminApp>, req: Req| async move {
                req.check_guild()?;
                app.check_csrf(&req)?;
                ok()
            }),
        ),
        Route::top_level(
            &format!("{API}/csrf-any"),
            &[
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ],
            handler(|app: Arc<AdminApp>, req: Req| async move {
                app.check_csrf(&req)?;
                ok()
            }),
        ),
        Route::new(
            &format!("{API}/router-guild"),
            &get,
            handler(|_app, req: Req| async move {
                req.check_guild()?;
                ok()
            }),
        ),
    ]
}

/// 文字を latin-1 のバイトにする（基準の見出しは latin-1 で読んだ文字で書いてある）。
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 の外の文字"))
        .collect()
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// 例の body（つなぎ方）から本文を作る（generate.py の _body と同じ）。
fn pieces_body(pieces: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    for piece in pieces.as_array().unwrap() {
        if let Some(hex) = piece["hex"].as_str() {
            body.extend(hex_bytes(hex));
        } else {
            let unit = latin1_bytes(piece[0].as_str().unwrap());
            for _ in 0..piece[1].as_u64().unwrap() {
                body.extend_from_slice(&unit);
            }
        }
    }
    body
}

/// Python が実際に送った要求（httpx が整えたあとのパスと見出し・本文）。接続元は TestClient の `testclient`。
fn incoming(request: &Value) -> Incoming {
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
    let body = match request["body_hex"].as_str() {
        Some(hex) => hex_bytes(hex),
        None => pieces_body(&request["body"]),
    };
    Incoming {
        method: Method::from_bytes(request["method"].as_str().unwrap().as_bytes()).unwrap(),
        path,
        query,
        headers,
        body: Bytes::from(body),
        peer: Some("testclient".to_string()),
    }
}

fn pairs(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut sorted = headers.to_vec();
    // 名前の順（同じ名前の中は足した順のまま。Python の基準と同じ並べ方）。
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
}

fn sorted_allow(value: &str) -> String {
    let mut words: Vec<&str> = value.split(',').map(str::trim).collect();
    words.sort_unstable();
    words.join(", ")
}

/// 1 つの答えを比べ、違うところを並べる。
fn compare(want: &Value, got: &Reply, head: bool) -> Vec<String> {
    let mut wrong = Vec::new();
    let status = want["status"].as_u64().unwrap();
    if u64::from(got.status) != status {
        wrong.push(format!("状態: Python {status} / Rust {}", got.status));
    }
    let python: Vec<(String, String)> = want["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_string(),
                p[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let rust: Vec<(String, String)> = pairs(&got.headers)
        .into_iter()
        .map(|(n, v)| {
            let v = if n == "allow" { sorted_allow(&v) } else { v };
            (n, v)
        })
        .collect();
    if python != rust {
        wrong.push(format!(
            "見出し:\n    Python {python:?}\n    Rust   {rust:?}"
        ));
    }
    let body = want["body"].as_str().unwrap();
    if !head && got.body != body.as_bytes() {
        wrong.push(format!(
            "本文:\n    Python {body:?}\n    Rust   {:?}",
            String::from_utf8_lossy(&got.body)
        ));
    }
    wrong
}

/// 本物のテンプレート（リポジトリの `webapp_admin/templates`。static は無い場所）と、経路の係が使うもの
/// （Discord にはつながない。この基準の例は Discord を呼ぶ経路を踏まない）。
fn shared_site() -> (Arc<Pages>, Arc<Site>) {
    let config = PagesConfig {
        templates_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../webapp_admin/templates"),
        static_dir: PathBuf::from("/nonexistent-admin-fixture-static"),
        asset_version: "admin".to_string(),
    };
    let pages = Arc::new(Pages::load(&config).unwrap());
    let discord = Discord::new(
        DiscordConfig::from_lookup(|_| None),
        "http://127.0.0.1:9/api/v10",
    )
    .unwrap();
    let site = Site::new(
        Arc::clone(&pages),
        Arc::new(discord),
        Arc::new(|| Ok(0)),
        Arc::new(|| "unused-state".to_string()),
    );
    (pages, Arc::new(site))
}

/// 例ごとの app（数・回数の制限・インシデントの置き場が空。乱数は 1 から）。
fn app(
    data: &Value,
    case: &Value,
    dir: &std::path::Path,
    shared: &(Arc<Pages>, Arc<Site>),
) -> Arc<AdminApp> {
    let now = data["now"].as_f64().unwrap() + data["now_fraction"].as_f64().unwrap();
    let config = Config {
        secure_cookies: case["secure"].as_bool().unwrap_or(false),
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: python::strip(case["dev_user_id"].as_str().unwrap_or("")).to_string(),
        monitor_dir: dir.to_path_buf(),
    };
    let deps = Deps {
        clock: Arc::new(move || now),
        random: Arc::new(Sequence {
            token_base: data["token_base"].as_u64().unwrap(),
            id_base: data["id_base"].as_u64().unwrap(),
            tokens: AtomicU64::new(0),
            ids: AtomicU64::new(0),
        }),
        pages: shared.0.clone(),
        reporter: Arc::new(Reporter::new("test", None)),
    };
    let mut table = routes::default_routes(&shared.1);
    table.extend(probes());
    Arc::new(AdminApp::new(
        config,
        data["secret"].as_str().unwrap(),
        deps,
        table,
    ))
}

/// 足した数（名前とラベルの順）。
fn counters(app: &AdminApp) -> Value {
    let mut drained = app.metrics().http().reporter().counters().drain();
    drained.sort();
    Value::Array(
        drained
            .into_iter()
            .map(|(name, labels, amount)| json!([name, labels, amount]))
            .collect(),
    )
}

#[tokio::test]
async fn the_skeleton_answers_like_python() {
    let data = expected();
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 50, "基準の例が足りない（{}）", cases.len());
    let shared = shared_site();
    let mut wrong = Vec::new();
    let mut requests = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        if let Some(reason) = case["rust_skip"].as_str() {
            eprintln!("飛ばす: {name}（{reason}）");
            continue;
        }
        let dir = tempfile::tempdir().unwrap();
        let app = app(&data, case, dir.path(), &shared);
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let request = incoming(&step["request"]);
            let repeat = step["repeat"].as_u64().unwrap_or(1);
            let mut reply = Reply::default();
            for _ in 0..repeat {
                reply = app.respond(request.clone()).await;
            }
            requests += 1;
            let head = request.method == Method::HEAD;
            for problem in compare(&step["response"], &reply, head) {
                wrong.push(format!(
                    "「{name}」の {i} 番目（{} {}）: {problem}",
                    request.method, step["request"]["target"]
                ));
            }
        }
        let got = counters(&app);
        if got != case["counters"] {
            wrong.push(format!(
                "「{name}」の数:\n    Python {}\n    Rust   {got}",
                case["counters"]
            ));
        }
        let text = std::fs::read_to_string(dir.path().join(INCIDENTS_FILE)).unwrap_or_default();
        let lines: Vec<Value> = text
            .split('\n')
            .filter(|l| !l.is_empty())
            .map(|l| json!(l))
            .collect();
        if Value::Array(lines.clone()) != case["incidents"] {
            wrong.push(format!(
                "「{name}」のインシデント:\n    Python {}\n    Rust   {}",
                case["incidents"],
                json!(lines)
            ));
        }
    }
    assert!(requests >= 150, "基準の要求が足りない（{requests}）");
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
