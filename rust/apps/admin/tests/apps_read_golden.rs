//! 設定パネルの読む側の経路（`sycs_admin::apps`。GET /admin/api/apps・/admin/api/apps/{id}）と、公開トップの
//! サーバー数のフォールバック（設定のあるサーバーの数）が、本物の Python の管理画面と同じ答えを返すこと。
//!
//! 基準は `fixtures/apps_read/expected.json`（本物の管理画面を偽物の Discord・読み上げの API に当て、設定を決めて
//! 回した答え）。ここでも同じ答え方の偽物（`support::FakeDiscord` を 2 つ）を立て、時刻・CSRF の印・インシデントの ID
//! を同じ並びにし、例の設定を置き場に入れて、同じ要求を [`AdminApp::respond`] に渡す。比べるのは要求ごとの状態・
//! 見出しの全部・本文（バイトまで）・偽物に届いた要求と、例ごとに足した数と `incidents.jsonl` の行。

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::http::Method;
use serde_json::{Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Random, Reply};
use sycs_admin::apps::getters::DjaudioDefaults;
use sycs_admin::apps::store::{self, SettingsStore};
use sycs_admin::apps::voices::Voices;
use sycs_admin::apps::{self, Panels};
use sycs_admin::auth::{Discord, DiscordConfig};
use sycs_admin::metrics::INCIDENTS_FILE;
use sycs_admin::routes;
use sycs_admin::templates::{Pages, PagesConfig};
use sycs_admin::views::Site;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

use support::{API_PREFIX, FakeDiscord, compare_reply, finish, incoming, sorted_requests};

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/apps_read/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn pages() -> Arc<Pages> {
    let config = PagesConfig {
        templates_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../webapp_admin/templates"),
        static_dir: PathBuf::from("/nonexistent-admin-fixture-static"),
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

/// 例の設定の置き場（`{"$raise": …}` なら読み込めない置き場）。
fn settings_store(spec: &Value) -> SettingsStore {
    match spec.get("$raise") {
        Some(_) => SettingsStore::failing(&text(&spec["message"])),
        None => SettingsStore::fixed(store::settings_from_document(spec)),
    }
}

fn admin_config(monitor_dir: &Path, dev_user_id: &str) -> Config {
    Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: dev_user_id.to_string(),
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

/// 偽物の 2 つ（Discord と読み上げの API）。
struct Fakes {
    discord: FakeDiscord,
    tts: FakeDiscord,
}

/// 届いた要求を比べる（順番は見ない）。
fn compare_requests(label: &str, what: &str, want: &Value, got: &[Value], wrong: &mut Vec<String>) {
    let want = sorted_requests(want.as_array().unwrap());
    let got = sorted_requests(got);
    if got != want {
        wrong.push(format!(
            "{label}: {what}に届いた要求:\n    Python {want:?}\n    Rust   {got:?}"
        ));
    }
}

/// 1 つの例の要求を順に送り、違うところを並べる。
async fn run_case(data: &Value, case: &Value, pages: &Arc<Pages>, fakes: &Fakes) -> Vec<String> {
    let name = case["name"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = Clock::new(data["now"].as_f64().unwrap());
    let settings = Arc::new(settings_store(&case["settings"]));
    let tts_base = fakes.tts.api_base().strip_suffix(API_PREFIX).unwrap();
    let timeout = Duration::from_secs_f64(case["voices_timeout"].as_f64().unwrap());
    let djaudio = DjaudioDefaults {
        cache_ttl: data["djaudio"]["cache_ttl"].as_i64().unwrap(),
        cooldown: data["djaudio"]["cooldown"].as_i64().unwrap(),
        max_urls: data["djaudio"]["max_urls"].as_i64().unwrap(),
    };
    let panels = Panels::new(
        Arc::clone(&settings),
        Voices::new(tts_base, timeout).unwrap(),
        djaudio,
    );
    let config = DiscordConfig {
        client_id: text(&data["discord"]["client_id"]),
        bot_token: text(&data["discord"]["bot_token"]),
        ..DiscordConfig::from_lookup(|_| None)
    };
    let site = Arc::new(
        Site::new(
            Arc::clone(pages),
            Arc::new(Discord::new(config, fakes.discord.api_base()).unwrap()),
            apps::stored_guild_count(&settings),
            Arc::new(|| "unused-state".to_string()),
        )
        .with_panels(Arc::new(panels)),
    );
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
        admin_config(dir.path(), case["dev_user_id"].as_str().unwrap()),
        data["secret"].as_str().unwrap(),
        deps,
        routes::default_routes(&site),
    ));
    let mut wrong = Vec::new();
    for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
        clock.set(step["now"].as_f64().unwrap());
        fakes.discord.script(&step["discord_responses"]);
        fakes.tts.script(&step["tts_responses"]);
        let request = incoming(&step["request"]);
        let label = format!(
            "「{name}」の {i} 番目（{} {}）",
            request.method, step["request"]["target"]
        );
        let reply: Reply = app.respond(request.clone()).await;
        for problem in compare_reply(&step["response"], &reply, request.method == Method::HEAD) {
            wrong.push(format!("{label}: {problem}"));
        }
        compare_requests(
            &label,
            "Discord ",
            &step["discord"],
            &fakes.discord.take(),
            &mut wrong,
        );
        compare_requests(
            &label,
            "読み上げの API ",
            &step["tts"],
            &fakes.tts.take(),
            &mut wrong,
        );
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

/// タイルの一覧・1 枚のパネル（宣言・選択肢・値・一覧・誤り）・選択肢の使い回しと 429 の待ち・声の見切り・公開トップの
/// サーバー数のフォールバックが、Python と同じ答えを返すこと。
#[tokio::test]
async fn panels_answer_like_python() {
    let data = expected();
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 70, "基準の例が足りない（{}）", cases.len());
    let pages = pages();
    let fakes = Fakes {
        discord: FakeDiscord::start().await,
        tts: FakeDiscord::start().await,
    };
    let mut wrong = Vec::new();
    for case in cases {
        wrong.extend(run_case(&data, case, &pages, &fakes).await);
    }
    finish(&wrong);
}
