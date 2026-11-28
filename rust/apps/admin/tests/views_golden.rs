//! ログイン・サーバー選択・公開ページの経路（`sycs_admin::views`）と、Discord の確かめ（`sycs_admin::auth`）が、
//! 本物の Python の管理画面と同じ答えを返すこと。
//!
//! 基準は 3 つ（どれも本物の Python から作った）:
//!
//! - `fixtures/auth/expected.json`: 本物の管理画面を偽物の Discord に当てて、ログイン・認可・戻り・ログアウト・
//!   `/admin/`・サーバー選択・シェル・`/`（サーバー数の 5 分の使い回し）を回した答え。要求ごとに、状態・見出しの
//!   全部・本文（HTML もバイトまで）・偽物の Discord に届いた要求・設定のあるサーバーの数を聞いた回数を、例ごとに
//!   足した数と `incidents.jsonl` の行を比べる。ここでも同じ答え方の偽物の Discord（`support::FakeDiscord`）を立て、
//!   時刻・CSRF の印・認可の state・インシデントの ID を同じ並びにして、同じ要求を [`AdminApp::respond`] に渡す
//! - `fixtures/admin_check/expected.json`: `user_still_admin` に Discord の答え方を与えた答え（真・偽・null・例外）と
//!   届いた要求
//! - `fixtures/templates/expected.json`（A2）の経路の例: つないだ経路に通して、状態・見出しの全部・本文を比べる
//!   （A2 のテストはページの関数を直に呼んで本文とセッションだけを比べていた）

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use axum::http::Method;
use serde_json::{Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Random, Reply};
use sycs_admin::auth::{Discord, DiscordConfig, StoredGuildCount};
use sycs_admin::metrics::INCIDENTS_FILE;
use sycs_admin::routes;
use sycs_admin::templates::{Pages, PagesConfig};
use sycs_admin::views::{Site, StateToken};
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

use support::{FakeDiscord, compare_reply, finish, incoming, sorted_requests};

fn expected(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/{name}/expected.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn repository_templates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../webapp_admin/templates")
}

fn pages(static_dir: &Path) -> Arc<Pages> {
    let config = PagesConfig {
        templates_dir: repository_templates(),
        static_dir: static_dir.to_path_buf(),
        asset_version: "admin".to_string(),
    };
    Arc::new(Pages::load(&config).unwrap_or_else(|e| panic!("テンプレートを読めません: {e}")))
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

/// いつも同じ印を返す乱数（A2 の基準は CSRF の印を 1 つに決めて作った）。
struct Fixed(String);

impl Random for Fixed {
    fn token_hex(&self, _nbytes: usize) -> String {
        self.0.clone()
    }

    fn uuid_hex(&self) -> String {
        "0".repeat(32)
    }
}

/// 要求ごとに決める時刻。
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);

impl Clock {
    fn new(now: f64) -> Self {
        Self(Arc::new(AtomicU64::new(now.to_bits())))
    }

    fn set(&self, now: f64) {
        self.0.store(now.to_bits(), Ordering::SeqCst);
    }

    fn source(&self) -> Arc<dyn Fn() -> f64 + Send + Sync> {
        let bits = Arc::clone(&self.0);
        Arc::new(move || f64::from_bits(bits.load(Ordering::SeqCst)))
    }
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_string()
}

/// 例の Discord の設定（文書の discord に例の config を上書きしたもの。generate.py が書いた）。
fn discord_config(config: &Value) -> DiscordConfig {
    DiscordConfig {
        client_id: text(&config["client_id"]),
        client_secret: text(&config["client_secret"]),
        redirect_uri: text(&config["redirect_uri"]),
        bot_token: text(&config["bot_token"]),
        prompt: text(&config["prompt"]),
        guilds_max_age: config["guilds_max_age"].as_i64().unwrap(),
    }
}

/// 設定のあるサーバーの数の偽物（例の stored_guilds。`$raise` なら失敗）。呼ばれた回数を数える。
fn stored_guilds(spec: &Value, calls: &Arc<AtomicU64>) -> StoredGuildCount {
    let answer: Result<usize, String> = match spec.get("$raise") {
        Some(_) => Err(text(&spec["message"])),
        None => Ok(usize::try_from(spec.as_u64().unwrap()).unwrap()),
    };
    let calls = Arc::clone(calls);
    Arc::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        answer.clone()
    })
}

/// generate.py の Sequence.token_urlsafe と同じ並びの state。
fn state_tokens(base: u64) -> StateToken {
    let count = Arc::new(AtomicU64::new(0));
    Arc::new(move || {
        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{:043x}", base + n)
    })
}

fn admin_config(monitor_dir: &Path) -> Config {
    Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: String::new(),
        monitor_dir: monitor_dir.to_path_buf(),
    }
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

fn incident_lines(dir: &Path) -> Value {
    let text = std::fs::read_to_string(dir.join(INCIDENTS_FILE)).unwrap_or_default();
    Value::Array(
        text.split('\n')
            .filter(|line| !line.is_empty())
            .map(|line| json!(line))
            .collect(),
    )
}

/// 1 つの例の要求を順に送り、違うところを並べる。
async fn run_auth_case(
    data: &Value,
    case: &Value,
    pages: &Arc<Pages>,
    fake: &FakeDiscord,
) -> Vec<String> {
    let name = case["name"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = Clock::new(data["now"].as_f64().unwrap());
    let stored_calls = Arc::new(AtomicU64::new(0));
    let discord = Discord::new(discord_config(&case["config"]), fake.api_base()).unwrap();
    let site = Arc::new(Site::new(
        Arc::clone(pages),
        Arc::new(discord),
        stored_guilds(&case["stored_guilds"], &stored_calls),
        state_tokens(data["state_base"].as_u64().unwrap()),
    ));
    let deps = Deps {
        clock: clock.source(),
        random: Arc::new(Sequence {
            token_base: data["token_base"].as_u64().unwrap(),
            id_base: data["id_base"].as_u64().unwrap(),
            tokens: AtomicU64::new(0),
            ids: AtomicU64::new(0),
        }),
        pages: pages.clone(),
        reporter: Arc::new(Reporter::new("test", None)),
    };
    let app = Arc::new(AdminApp::new(
        admin_config(dir.path()),
        data["secret"].as_str().unwrap(),
        deps,
        routes::default_routes(&site),
    ));
    let mut wrong = Vec::new();
    for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
        clock.set(step["now"].as_f64().unwrap());
        fake.script(&step["discord_responses"]);
        let request = incoming(&step["request"]);
        let label = format!(
            "「{name}」の {i} 番目（{} {}）",
            request.method, step["request"]["target"]
        );
        let mut reply = Reply::default();
        for _ in 0..step["repeat"].as_u64().unwrap_or(1) {
            reply = app.respond(request.clone()).await;
        }
        for problem in compare_reply(&step["response"], &reply, request.method == Method::HEAD) {
            wrong.push(format!("{label}: {problem}"));
        }
        let got = sorted_requests(&fake.take());
        let want = sorted_requests(step["discord"].as_array().unwrap());
        if got != want {
            wrong.push(format!(
                "{label}: Discord に届いた要求:\n    Python {want:?}\n    Rust   {got:?}"
            ));
        }
        let calls = stored_calls.swap(0, Ordering::SeqCst);
        if Some(calls) != step["stored_guild_calls"].as_u64() {
            wrong.push(format!(
                "{label}: 設定のあるサーバーの数を聞いた回数: Python {} / Rust {calls}",
                step["stored_guild_calls"]
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
    let lines = incident_lines(dir.path());
    if lines != case["incidents"] {
        wrong.push(format!(
            "「{name}」のインシデント:\n    Python {}\n    Rust   {lines}",
            case["incidents"]
        ));
    }
    wrong
}

/// ログイン・認可・戻り・ログアウト・サーバー選択・シェル・公開トップが、Python と同じ答えを返すこと。
#[tokio::test]
async fn logins_and_guild_selection_answer_like_python() {
    let data = expected("auth");
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 80, "基準の例が足りない（{}）", cases.len());
    let pages = pages(Path::new("/nonexistent-admin-fixture-static"));
    let fake = FakeDiscord::start().await;
    let mut wrong = Vec::new();
    let mut requests = 0;
    for case in cases {
        requests += case["steps"].as_array().unwrap().len();
        wrong.extend(run_auth_case(&data, case, &pages, &fake).await);
    }
    assert!(requests >= 100, "基準の要求が足りない（{requests}）");
    finish(&wrong);
}

/// `user_still_admin` の答え（真・偽・分からない・例外）と、Discord に聞いたものが Python と同じであること。
#[tokio::test]
async fn admin_checks_answer_like_python() {
    let data = expected("admin_check");
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "基準の例が足りない（{}）", cases.len());
    let fake = FakeDiscord::start().await;
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        fake.script(&case["discord_responses"]);
        let config = DiscordConfig {
            bot_token: text(&case["bot_token"]),
            ..DiscordConfig::from_lookup(|_| None)
        };
        let discord = Discord::new(config, fake.api_base()).unwrap();
        let guild_id = case["guild_id"].as_u64().unwrap().to_string();
        let user_id = case["user_id"].as_u64().unwrap().to_string();
        let got = match discord.user_still_admin(&guild_id, &user_id).await {
            Ok(value) => json!({"value": value}),
            Err(crash) => json!({"raises": {"type": crash.kind, "message": crash.message}}),
        };
        if got != case["result"] {
            wrong.push(format!(
                "「{name}」: Python {} / Rust {got}",
                case["result"]
            ));
        }
        let seen = sorted_requests(&fake.take());
        let want = sorted_requests(case["discord"].as_array().unwrap());
        if seen != want {
            wrong.push(format!(
                "「{name}」: Discord に届いた要求:\n    Python {want:?}\n    Rust   {seen:?}"
            ));
        }
    }
    finish(&wrong);
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map(Vec::as_slice).unwrap_or_default()
}

/// A2 の基準の static を、Python（templates/generate.py の `_make_static`）と同じに作り直す。返すのは static のパス。
fn build_static(spec: &Value, base: &Path) -> PathBuf {
    let root = base.join("static");
    std::fs::create_dir_all(&root).unwrap();
    let default_mtime = spec["mtime_ns"].as_u64().unwrap();
    let mut placed: Vec<(PathBuf, u64)> = Vec::new();
    for (dir, key) in [(root.clone(), "files"), (base.to_path_buf(), "outside")] {
        for item in items(spec, key) {
            let path = dir.join(item["path"].as_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let size = usize::try_from(item["size"].as_u64().unwrap()).unwrap();
            std::fs::write(&path, vec![b'x'; size]).unwrap();
            placed.push((path, item["mtime_ns"].as_u64().unwrap_or(default_mtime)));
        }
    }
    for item in items(spec, "symlinks") {
        let link = root.join(item["path"].as_str().unwrap());
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(item["target"].as_str().unwrap(), link).unwrap();
    }
    for (path, mtime) in placed {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(UNIX_EPOCH + Duration::from_nanos(mtime))
            .unwrap();
    }
    root
}

/// A2 の基準の経路の例（`/`・文書・301・ログイン画面・ログアウトの確認・サーバー選択・シェル・404・405・403）を、
/// つないだ経路に通した答えが、Python と同じであること（状態・見出しの全部・本文）。
///
/// Python はサーバー数の関数を偽物に替えて作った（例の service の guild_count）。ここでは偽物の Discord がその数の
/// サーバーを返し、例ごとに新しい app（数の使い回しは空）にする。CSRF の印は基準の issued_token。
#[tokio::test]
async fn template_routes_answer_like_python_over_http() {
    let data = expected("templates");
    let dir = tempfile::tempdir().unwrap();
    let static_dir = build_static(&data["static"], dir.path());
    let pages = pages(&static_dir);
    let fake = FakeDiscord::start().await;
    let now = data["now"].as_f64().unwrap();
    let cases = items(&data, "cases");
    assert!(cases.len() >= 25, "cases の例が足りない");
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let count = case["service"]["guild_count"].as_u64().unwrap_or(0);
        let guilds: Vec<Value> = (0..count).map(|_| Value::Null).collect();
        fake.script(&json!({"GET /users/@me/guilds?limit=200 Bot": {"json": guilds}}));
        let config = DiscordConfig {
            client_id: text(&data["client_id"]),
            bot_token: "a2-fixture-bot-token".to_string(),
            ..DiscordConfig::from_lookup(|_| None)
        };
        let site = Arc::new(Site::new(
            Arc::clone(&pages),
            Arc::new(Discord::new(config, fake.api_base()).unwrap()),
            Arc::new(|| Ok(0)),
            Arc::new(|| "unused-state".to_string()),
        ));
        let monitor = tempfile::tempdir().unwrap();
        let deps = Deps {
            clock: Arc::new(move || now),
            random: Arc::new(Fixed(text(&data["issued_token"]))),
            pages: pages.clone(),
            reporter: Arc::new(Reporter::new("test", None)),
        };
        let app = Arc::new(AdminApp::new(
            admin_config(monitor.path()),
            data["secret"].as_str().unwrap(),
            deps,
            routes::default_routes(&site),
        ));
        let request = incoming(&case["request"]);
        let reply = app.respond(request.clone()).await;
        for problem in compare_reply(&case["response"], &reply, request.method == Method::HEAD) {
            wrong.push(format!(
                "「{name}」（{} {}）: {problem}",
                request.method, case["request"]["target"]
            ));
        }
        let _ = fake.take();
    }
    finish(&wrong);
}
