//! 監視（A7）が本物の Python（`webapp_admin/metrics.py` と psutil 7.2.2）と同じ答えを出すこと。
//!
//! 基準は `fixtures/monitor/expected.json`（generate.py が本物の Python で作った。例は cases.json）。6 つの節を比べる:
//!
//! - cases: `GET /admin/api/metrics`・`/admin/api/incidents` の答え（状態・見出し・本文をバイトまで）。Python と同じ
//!   ホストの値を返す偽物の [`HostProbe`]・例の時刻・起きた時刻・要求の時刻・インシデントのファイルで app を組み、
//!   Python が送ったのと同じ要求を [`AdminApp::respond`] に渡す（署名の時計は基準の `now`）
//! - functions: 整形の関数と、Python の小数の書き方（`.Nf`・`g`）・丸め方（`round`）・足し方（`sum`）
//! - procfs: 偽物の `/proc` の読み方（メモリ・起動の時刻・CPU の割合）
//! - downtime・heartbeat・alerts: 監視の巡回が書くインシデントの行と心拍のファイル

mod support;

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Map, Value};
use sycs_admin::app::{AdminApp, Config, Deps, Incoming, OsRandom};
use sycs_admin::auth::{Discord, DiscordConfig};
use sycs_admin::errors::{Crash, PlainPages};
use sycs_admin::metrics::{INCIDENTS_FILE, Incidents};
use sycs_admin::monitor::dashboard::{self, Meter};
use sycs_admin::monitor::host::{self, HostProbe, HostSample, Memory, SampleFuture};
use sycs_admin::monitor::pyfloat;
use sycs_admin::monitor::valkey::Unconfigured;
use sycs_admin::monitor::watch::{self, Alerts};
use sycs_admin::monitor::{Monitor, Settings};
use sycs_admin::python;
use sycs_admin::routes;
use sycs_admin::templates::{Pages, PagesConfig};
use sycs_admin::views::Site;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/monitor");

fn read(name: &str) -> Value {
    let path = format!("{DIR}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{path} が読めません: {e}。CI の「基準」が作ったものを取ってきてコミットすること")
    });
    serde_json::from_str(&text).unwrap()
}

/// repr の文字の小数（例の書き方）。
fn float(value: &Value) -> f64 {
    value
        .as_str()
        .unwrap_or_else(|| panic!("小数は文字で書く: {value}"))
        .parse()
        .unwrap()
}

/// 例の環境変数（`{"名前": "値"}`）を引く関数。
fn lookup(env: &Value) -> impl Fn(&str) -> Option<String> + Clone + Send + Sync + 'static {
    let map: Map<String, Value> = env.as_object().cloned().unwrap_or_default();
    move |key: &str| map.get(key).and_then(Value::as_str).map(str::to_string)
}

/// 例のファイルの中身（null は置かない・文字・`{"lines": [...]}`・`{"hex": …}`）を書く。generate.py の write_input。
fn write_input(path: &Path, spec: &Value) {
    let bytes = match spec {
        Value::Null => return,
        Value::String(text) => text.as_bytes().to_vec(),
        Value::Object(map) if map.contains_key("lines") => map["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| format!("{}\n", line.as_str().unwrap()))
            .collect::<String>()
            .into_bytes(),
        Value::Object(map) => support::hex_bytes(map["hex"].as_str().unwrap()),
        other => panic!("ファイルの書き方が分からない: {other}"),
    };
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// インシデントのファイルの行（無ければ空。空の行は落とす）。
fn read_lines(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    Value::Array(
        text.split('\n')
            .filter(|line| !line.is_empty())
            .map(|line| Value::String(line.to_string()))
            .collect(),
    )
}

/// 例の ID（generate.py の IdSequence と同じ並び）。
fn ids(base: u64) -> Arc<dyn Fn() -> String + Send + Sync> {
    let count = Arc::new(Mutex::new(0u64));
    Arc::new(move || {
        let mut count = count.lock().unwrap_or_else(PoisonError::into_inner);
        *count += 1;
        format!("{:032x}", base + *count)
    })
}

/// 例の host を返す偽物の psutil（`$raise` なら例外）。
struct FakeHost(Value);

impl FakeHost {
    fn value(&self, name: &str, default: Value) -> Result<Value, Crash> {
        let value = self.0.get(name).cloned().unwrap_or(default);
        if let Some(kind) = value.get("$raise").and_then(Value::as_str) {
            let message = value.get("message").and_then(Value::as_str).unwrap_or("");
            return Err(Crash::new(kind, message));
        }
        Ok(value)
    }

    fn sample_now(&self) -> Result<HostSample, Crash> {
        let cpu = self.value("cpu_percent", Value::String("0.0".into()))?;
        let memory = self.value(
            "memory",
            serde_json::json!({"percent": "0.0", "used": 0, "total": 0}),
        )?;
        let count = self.value("cpu_count", Value::from(1))?;
        let boot = self.value("boot_time", Value::String("0.0".into()))?;
        Ok(HostSample {
            cpu_percent: float(&cpu),
            memory: Memory {
                total: memory["total"].as_i64().unwrap(),
                used: memory["used"].as_i64().unwrap(),
                percent: float(&memory["percent"]),
            },
            cpu_count: count.as_u64(),
            boot_time: float(&boot),
        })
    }
}

impl HostProbe for FakeHost {
    fn sample(&self) -> SampleFuture<'_> {
        let sample = self.sample_now();
        Box::pin(async move { sample })
    }
}

/// 経路の表を組むための、経路の係が使うもの（この基準は Discord を呼ぶ経路を踏まない）。
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

/// TestClient が送った要求（例の見出しと Cookie に、TestClient が足す見出し）。接続元は `testclient`。
fn incoming(request: &Value) -> Incoming {
    let target = request["target"].as_str().unwrap();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("host", "testserver"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate"),
        ("connection", "keep-alive"),
        ("user-agent", "testclient"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    for pair in request["headers"].as_array().unwrap() {
        let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
        let value =
            HeaderValue::from_bytes(&support::latin1_bytes(pair[1].as_str().unwrap())).unwrap();
        headers.insert(name, value);
    }
    Incoming {
        method: Method::from_bytes(request["method"].as_str().unwrap().as_bytes()).unwrap(),
        path,
        query,
        headers,
        body: Bytes::new(),
        peer: Some("testclient".to_string()),
    }
}

/// 例の service から app を組む（インシデントのファイルは `dir`、要求の時刻は数え口に入れる）。
fn app(data: &Value, service: &Value, dir: &Path, site: &Arc<Site>) -> Arc<AdminApp> {
    let signed = data["now"].as_f64().unwrap();
    let config = Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: String::new(),
        monitor_dir: dir.to_path_buf(),
    };
    let deps = Deps {
        clock: Arc::new(move || signed),
        random: Arc::new(OsRandom),
        pages: Arc::new(PlainPages),
        reporter: Arc::new(Reporter::new("test", None)),
    };
    write_input(&dir.join(INCIDENTS_FILE), &service["incidents"]);
    let now = service.get("now").map_or(0.0, float);
    let started = service.get("started").map_or(0.0, float);
    let monitor = Monitor::new(
        Settings::from_lookup(lookup(&service["env"])),
        Arc::new(FakeHost(
            service
                .get("host")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
        )),
        Arc::new(Unconfigured),
        Arc::new(move || now),
    )
    .with_started_at(started);
    let admin = AdminApp::new(
        config,
        data["secret"].as_str().unwrap(),
        deps,
        routes::default_routes(site),
    )
    .with_monitor(Arc::new(monitor));
    for t in service["requests"].as_array().into_iter().flatten() {
        admin.metrics().record_request(float(t));
    }
    Arc::new(admin)
}

fn names(cases: &Value) -> Vec<String> {
    cases
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn the_monitor_api_answers_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    assert_eq!(
        names(&data["cases"]),
        names(&document["cases"]),
        "基準が例の文書と食い違う（cases.json を変えたら、CI の「基準」が作り直した expected.json をコミットする）"
    );
    let site = site();
    let mut wrong = Vec::new();
    for (case, source) in data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(document["cases"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let app = app(&data, &source["service"], dir.path(), &site);
        let reply = app.respond(incoming(&case["request"])).await;
        for problem in support::compare_reply(&case["response"], &reply, false) {
            wrong.push(format!("「{name}」: {problem}"));
        }
    }
    assert!(data["cases"].as_array().unwrap().len() >= 20);
    support::finish(&wrong);
}

#[test]
fn formatting_matches_python() {
    let data = read("expected.json");
    let functions = &data["functions"];
    let mut wrong = Vec::new();
    let mut check = |what: &str, input: &Value, want: &str, got: String| {
        if got != want {
            wrong.push(format!("{what}({input}): Python {want:?} / Rust {got:?}"));
        }
    };
    let rows = |name: &str| functions[name].as_array().unwrap().clone();
    for row in rows("format_duration") {
        check(
            "format_duration",
            &row[0],
            row[1].as_str().unwrap(),
            dashboard::format_duration(float(&row[0])),
        );
    }
    for row in rows("format_bytes") {
        check(
            "format_bytes",
            &row[0],
            row[1].as_str().unwrap(),
            dashboard::format_bytes(float(&row[0])),
        );
    }
    for row in rows("load_tone") {
        let got = dashboard::load_tone(float(&row[0]), float(&row[1])).to_string();
        check("load_tone", &row, row[2].as_str().unwrap(), got);
    }
    for row in rows("sla_tone") {
        check(
            "sla_tone",
            &row[0],
            row[1].as_str().unwrap(),
            dashboard::sla_tone(float(&row[0])).to_string(),
        );
    }
    for row in rows("clamp_percent") {
        let got = python::float_repr(dashboard::clamp_percent(float(&row[0])));
        check("clamp_percent", &row[0], row[1].as_str().unwrap(), got);
    }
    for row in rows("fixed") {
        let places = usize::try_from(row[1].as_u64().unwrap()).unwrap();
        check(
            "fixed",
            &row,
            row[2].as_str().unwrap(),
            pyfloat::fixed(float(&row[0]), places),
        );
    }
    for row in rows("general") {
        check(
            "general",
            &row[0],
            row[1].as_str().unwrap(),
            pyfloat::general(float(&row[0])),
        );
    }
    for row in rows("round") {
        let places = usize::try_from(row[1].as_u64().unwrap()).unwrap();
        let got = python::float_repr(pyfloat::round(float(&row[0]), places));
        check("round", &row, row[2].as_str().unwrap(), got);
    }
    for row in rows("sum") {
        let values: Vec<f64> = row[0].as_array().unwrap().iter().map(float).collect();
        check(
            "sum",
            &row[0],
            row[1].as_str().unwrap(),
            python::float_repr(pyfloat::pysum(&values)),
        );
    }
    support::finish(&wrong);
}

/// 読めたなら `{"value": …}`、読めなければ `{"error": 型}` の形にする（基準と同じ）。
fn outcome<T>(result: Result<T, Crash>, value: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(got) => serde_json::json!({"value": value(got)}),
        Err(crash) => serde_json::json!({"error": crash.kind}),
    }
}

#[test]
fn proc_files_are_read_like_psutil() {
    let data = read("expected.json");
    let document = read("cases.json");
    let mut wrong = Vec::new();
    for (case, source) in data["procfs"]
        .as_array()
        .unwrap()
        .iter()
        .zip(document["procfs"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let stat = source["stat"].as_str().unwrap();
        let after = source
            .get("stat_after")
            .and_then(Value::as_str)
            .unwrap_or(stat);
        let memory = outcome(
            host::virtual_memory(
                source["meminfo"].as_str().unwrap(),
                source["zoneinfo"].as_str(),
            ),
            |memory| {
                serde_json::json!({
                    "total": memory.total,
                    "used": memory.used,
                    "percent": python::float_repr(memory.percent),
                })
            },
        );
        let boot = outcome(host::boot_time(stat), |boot| {
            Value::String(python::float_repr(boot))
        });
        let cpu = outcome(
            host::parse_cpu_times(stat).and_then(|first| {
                host::parse_cpu_times(after).map(|second| host::cpu_percent(&first, &second))
            }),
            |cpu| Value::String(python::float_repr(cpu)),
        );
        for (what, got) in [
            ("memory", memory),
            ("boot_time", boot),
            ("cpu_percent", cpu),
        ] {
            if got != case[what] {
                wrong.push(format!(
                    "「{name}」の {what}: Python {} / Rust {got}",
                    case[what]
                ));
            }
        }
    }
    assert!(data["procfs"].as_array().unwrap().len() >= 15);
    support::finish(&wrong);
}

/// 時刻を差し替えられるインシデントの書き手と、その時計。
fn writer(dir: &Path, base: u64) -> (Incidents, Arc<Mutex<f64>>) {
    let now = Arc::new(Mutex::new(0.0));
    let clock = Arc::clone(&now);
    let incidents = Incidents::new(
        dir.to_path_buf(),
        Arc::new(move || *clock.lock().unwrap_or_else(PoisonError::into_inner)),
        ids(base),
    );
    (incidents, now)
}

#[test]
fn startup_downtime_is_recorded_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    let base = data["id_base"].as_u64().unwrap();
    let mut wrong = Vec::new();
    for (case, source) in data["downtime"]
        .as_array()
        .unwrap()
        .iter()
        .zip(document["downtime"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        write_input(
            &dir.path().join(watch::HEARTBEAT_FILE),
            &source["heartbeat"],
        );
        let now = float(&source["now"]);
        let (incidents, clock) = writer(dir.path(), base);
        *clock.lock().unwrap() = now;
        let grace = Settings::from_lookup(lookup(&source["env"])).downtime_grace_seconds;
        let result = watch::record_startup_downtime(&incidents, dir.path(), now, grace);
        if result.is_err() != !case["error"].is_null() {
            wrong.push(format!(
                "「{name}」の失敗: Python {} / Rust {result:?}",
                case["error"]
            ));
        }
        let lines = read_lines(&dir.path().join(INCIDENTS_FILE));
        if lines != case["lines"] {
            wrong.push(format!(
                "「{name}」の行:\n    Python {}\n    Rust   {lines}",
                case["lines"]
            ));
        }
    }
    support::finish(&wrong);
}

#[test]
fn the_heartbeat_is_written_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    let mut wrong = Vec::new();
    for (case, source) in data["heartbeat"]
        .as_array()
        .unwrap()
        .iter()
        .zip(document["heartbeat"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("monitor");
        let pid = u32::try_from(source["pid"].as_u64().unwrap()).unwrap();
        watch::write_heartbeat(
            &target,
            float(&source["now"]),
            float(&source["started"]),
            pid,
        )
        .unwrap();
        let text = std::fs::read_to_string(target.join(watch::HEARTBEAT_FILE)).unwrap();
        if text != case["text"].as_str().unwrap() {
            wrong.push(format!(
                "「{name}」の中身:\n    Python {}\n    Rust   {text:?}",
                case["text"]
            ));
        }
        let mut files: Vec<String> = std::fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        if Value::from(files.clone()) != case["files"] {
            wrong.push(format!(
                "「{name}」のファイル: Python {} / Rust {files:?}",
                case["files"]
            ));
        }
    }
    support::finish(&wrong);
}

fn meter(value: &Value) -> Meter {
    Meter {
        label: value["label"].as_str().unwrap().to_string(),
        percent: float(&value["percent"]),
        display: String::new(),
        detail: value["detail"].as_str().unwrap().to_string(),
        tone: String::new(),
    }
}

#[test]
fn threshold_alerts_are_recorded_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    let base = data["id_base"].as_u64().unwrap();
    let mut wrong = Vec::new();
    for (case, source) in data["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .zip(document["alerts"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (incidents, clock) = writer(dir.path(), base);
        let settings = Settings::from_lookup(lookup(&source["env"]));
        let alerts = Alerts::default();
        for tick in source["ticks"].as_array().unwrap() {
            let now = float(&tick["now"]);
            *clock.lock().unwrap() = now;
            let meters = &tick["meters"];
            let (cpu, memory, tps) = (
                meter(&meters["cpu"]),
                meter(&meters["memory"]),
                meter(&meters["tps"]),
            );
            alerts.record(
                &incidents,
                [("cpu", &cpu), ("memory", &memory), ("tps", &tps)],
                &settings,
                now,
            );
        }
        let lines = read_lines(&dir.path().join(INCIDENTS_FILE));
        if lines != case["lines"] {
            wrong.push(format!(
                "「{name}」の行:\n    Python {}\n    Rust   {lines}",
                case["lines"]
            ));
        }
    }
    support::finish(&wrong);
}
