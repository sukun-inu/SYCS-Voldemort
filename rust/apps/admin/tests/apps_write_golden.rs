//! 設定パネルの書く側の経路（`sycs_admin::apps::write`。PUT /admin/api/apps/{id}・一覧の追加・更新・削除・
//! DELETE /admin/api/guild-data）が、本物の Python の管理画面と同じ答えを返し、同じ設定を書くこと。
//!
//! 基準は `fixtures/apps_write/expected.json`（本物の管理画面を偽物の Discord・読み上げの API に当て、本物の
//! `settings_pg.PostgresSettings` を SQLite に向けた置き場で回した答え）。ここでも同じ答え方の偽物
//! （`support::FakeDiscord` を 2 つ）を立て、時刻・CSRF の印・ID を同じ並びにし、例の設定を Postgres を使わない
//! 置き場（[`SettingsStore::memory`]。書き換えの規則は本番と同じ `sycs_core::settings::apply_mutation`）に入れて、
//! 同じ要求を [`AdminApp::respond`] に渡す。要求ごとに比べるのは:
//!
//! - 状態・見出しの全部・本文（バイトまで）・偽物に届いた要求
//! - 書いたあとの設定（ギルドの鍵の順。ギルドの中は**鍵の並びまで**）と版番号
//! - その要求で書き換えを呼んだ回数ぶんの「書いたあとの版番号」（変わったときだけ 1 上がる＝Bot に知らせが出る）
//! - サーバーのデータの削除で、利用者の状態を消す口に届いたサーバーの ID
//!
//! と、例ごとに足した数と `incidents.jsonl` の行。

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::http::Method;
use serde_json::{Map, Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Random, Reply};
use sycs_admin::apps::getters::DjaudioDefaults;
use sycs_admin::apps::guild_data::{Counts, EraseFuture, UserStateEraser};
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
        "/tests/fixtures/apps_write/expected.json"
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

/// 例ごとに 1 から数える、決まった並びの乱数（generate.py の Sequence と同じ。ID はインシデントとニュースの
/// フィードが同じ並びを引く）。
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
        format!("{:08x}{}", self.id_base + n, "0".repeat(24))
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

/// 利用者の状態を消す口の偽物（例の答えを返し、届いたサーバーの ID を控える）。
struct FakeEraser {
    answer: Value,
    calls: Mutex<Vec<String>>,
}

impl FakeEraser {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl UserStateEraser for FakeEraser {
    fn delete_guild(&self, guild_id: &str) -> EraseFuture<'_> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(guild_id.to_string());
        let answer = if self.answer.get("$raise").is_some() {
            Err(self.answer["message"].as_str().unwrap_or_default().to_string())
        } else {
            Ok(Counts {
                events: self.answer["events"].as_i64().unwrap(),
                states: self.answer["states"].as_i64().unwrap(),
            })
        };
        Box::pin(async move { answer })
    }
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_string()
}

/// 例の設定の置き場（`{"$raise": …}` なら読み込めない置き場。版番号は Python が取り込んだあとの版）。
fn settings_store(case: &Value, stamp: &str) -> SettingsStore {
    let spec = &case["settings"];
    if spec.get("$raise").is_some() {
        return SettingsStore::failing(&text(&spec["message"]));
    }
    let mut settings = store::settings_from_document(spec);
    settings.version = case["initial_version"].as_i64().unwrap();
    SettingsStore::memory(settings, stamp)
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

/// いまの手元の設定のギルド（鍵の順。ギルドの中は鍵の並びのまま）と版番号。読み込めない置き場は null と 0。
fn current(store: &SettingsStore) -> (Value, i64) {
    match store.try_snapshot() {
        Ok(settings) => {
            let guilds: Map<String, Value> = settings
                .guilds
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            (Value::Object(guilds), settings.version)
        }
        Err(_) => (Value::Null, 0),
    }
}

/// 鍵の並びまで同じか（serde_json の文字にして比べる）。
fn same(want: &Value, got: &Value) -> bool {
    serde_json::to_string(want).unwrap() == serde_json::to_string(got).unwrap()
}

/// 1 つの例の要求を順に送り、違うところを並べる。
async fn run_case(data: &Value, case: &Value, pages: &Arc<Pages>, fakes: &Fakes) -> Vec<String> {
    let name = case["name"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = Clock::new(data["now"].as_f64().unwrap());
    let settings = Arc::new(settings_store(case, data["stamp"].as_str().unwrap()));
    let eraser = Arc::new(FakeEraser {
        answer: case["user_states"].clone(),
        calls: Mutex::new(Vec::new()),
    });
    let tts_base = fakes.tts.api_base().strip_suffix(API_PREFIX).unwrap();
    let timeout = Duration::from_secs_f64(data["voices_timeout"].as_f64().unwrap());
    let djaudio = DjaudioDefaults {
        cache_ttl: data["djaudio"]["cache_ttl"].as_i64().unwrap(),
        cooldown: data["djaudio"]["cooldown"].as_i64().unwrap(),
        max_urls: data["djaudio"]["max_urls"].as_i64().unwrap(),
    };
    let panels = Panels::new(
        Arc::clone(&settings),
        Voices::new(tts_base, timeout).unwrap(),
        djaudio,
    )
    .with_user_state_eraser(Arc::clone(&eraser) as Arc<dyn UserStateEraser>);
    let config = DiscordConfig {
        client_id: text(&data["discord"]["client_id"]),
        bot_token: text(&case["bot_token"]),
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
        let (guilds, version) = current(&settings);
        if !same(&step["settings"], &guilds) {
            wrong.push(format!(
                "{label}: 書いたあとの設定:\n    Python {}\n    Rust   {guilds}",
                step["settings"]
            ));
        }
        if step["version"].as_i64() != Some(version) {
            wrong.push(format!(
                "{label}: 版番号: Python {} / Rust {version}",
                step["version"]
            ));
        }
        let writes = json!(settings.take_writes());
        if writes != step["writes"] {
            wrong.push(format!(
                "{label}: 書くたびの版番号（Bot への知らせ）: Python {} / Rust {writes}",
                step["writes"]
            ));
        }
        let erased = json!(eraser.take());
        if erased != step["user_states"] {
            wrong.push(format!(
                "{label}: 利用者の状態を消す口: Python {} / Rust {erased}",
                step["user_states"]
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

/// 入力欄の保存（検証・選択肢・1 項目ずつの保存と失敗）・一覧の追加・更新・削除・サーバーのデータの削除が、Python と
/// 同じ答えを返し、同じ設定を同じ鍵の並びで書き、同じ回数だけ版番号を上げる（Bot に知らせる）こと。
#[tokio::test]
async fn writes_answer_and_store_like_python() {
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

/// 基準の例が、書く関数（入力欄の set・一覧の add・update・remove）を全部 1 回は通っていること（宣言に関数が
/// 増えたのに例を足し忘れる、を CI で気づく）。通ったかは、その関数の入力欄・一覧に書く要求が 200 を返したかで見る。
#[test]
fn the_fixture_reaches_every_setter() {
    let data = expected();
    let mut reached = std::collections::BTreeSet::new();
    for case in data["cases"].as_array().unwrap() {
        for step in case["steps"].as_array().unwrap() {
            if step["response"]["status"] != 200 {
                continue;
            }
            let method = step["request"]["method"].as_str().unwrap();
            let target = step["request"]["target"].as_str().unwrap();
            let path = target.split('?').next().unwrap_or_default();
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let saved = &step["response"]["json"]["saved"];
            match (method, parts.as_slice()) {
                ("PUT", ["admin", "api", "apps", panel]) => {
                    for key in saved.as_array().into_iter().flatten() {
                        reached.insert(format!("set {panel}.{}", key.as_str().unwrap()));
                    }
                }
                ("POST", ["admin", "api", "apps", panel, "collections", key]) => {
                    reached.insert(format!("add {panel}.{key}"));
                }
                ("PUT", ["admin", "api", "apps", panel, "collections", key, _]) => {
                    reached.insert(format!("update {panel}.{key}"));
                }
                ("DELETE", ["admin", "api", "apps", panel, "collections", key, _]) => {
                    reached.insert(format!("remove {panel}.{key}"));
                }
                _ => {}
            }
        }
    }
    let mut wanted = std::collections::BTreeSet::new();
    for panel in &sycs_admin::apps::schema::schema().panels {
        for field in &panel.fields {
            if field.set.is_some() {
                wanted.insert(format!("set {}.{}", panel.id, field.key));
            }
        }
        for collection in &panel.collections {
            for (kind, name) in [
                ("add", &collection.add),
                ("update", &collection.update),
                ("remove", &collection.remove),
            ] {
                if name.is_some() {
                    wanted.insert(format!("{kind} {}.{}", panel.id, collection.key));
                }
            }
        }
    }
    let missing: Vec<&String> = wanted.difference(&reached).collect();
    assert!(missing.is_empty(), "基準の例が通っていない書く関数: {missing:?}");
}
