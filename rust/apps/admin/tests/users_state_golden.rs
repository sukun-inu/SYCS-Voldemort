//! 利用者の状態の 2 本の API（`GET /admin/api/users/state`・`/admin/api/users/state/{user_id}`）が、本物の Python の
//! 管理画面と同じ答えを返すこと。
//!
//! 基準は `fixtures/users_state/expected.json`（A0 の generate.py が、本物の `webapp_admin.app` に、services の 3 つを
//! 偽物に差し替えて starlette の TestClient で回したもの。例は cases.json）。ここでも、例の service を返す偽物の
//! [`UserStates`]（届いた呼び出しを控える）を差し込んだ app に、Python が送ったのと同じ要求を
//! [`AdminApp::respond`] で渡す。署名の時計は基準の `now`。
//!
//! 比べるもの: 状態・見出し（名前の順。同じ名前の中は足した順）・本文（バイトまで）・偽物に届いた呼び出し
//! （関数の名前と引数）。cases.json で `rust_skip` を付けた例（Postgres の services からは来ない値。時差の無い時刻・
//! 辞書でない行など）は飛ばす。飛ばす例は「Rust の型にできない例」とちょうど同じであることも確かめる。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sycs_admin::app::{AdminApp, Config, Deps, Incoming, OsRandom, Reply};
use sycs_admin::errors::{Crash, PlainPages};
use sycs_admin::routes;
use sycs_admin::users::{Detail, EventRow, StateRow, StoreFuture, UserStates};
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/users_state");

fn read(name: &str) -> Value {
    let path = format!("{DIR}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{path} が読めません: {e}。CI の「基準」が作ったものを取ってきてコミットすること")
    });
    serde_json::from_str(&text).unwrap()
}

/// `{"$ref": 名前}` か `{"$ref": 名前, "with": {...}}` か。
fn is_ref(map: &Map<String, Value>) -> bool {
    map.contains_key("$ref") && map.keys().all(|k| k == "$ref" || k == "with")
}

/// 例の値の `$ref`・`with` を library で解く（admin_harness.py の decode と同じ。`$datetime`・`$int`・`$raise` は残す）。
fn resolve(value: &Value, library: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| resolve(v, library)).collect()),
        Value::Object(map) if is_ref(map) => {
            let name = map["$ref"].as_str().unwrap();
            let mut base = resolve(&library[name], library);
            let extra = map.get("with").map(|with| resolve(with, library));
            if let (Some(Value::Object(extra)), Value::Object(target)) = (extra, &mut base) {
                target.extend(extra);
            }
            base
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), resolve(item, library)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// JSON の中身（ロール・権限・中身）。印（`$datetime` など）が入っていれば Rust の Value にはできない。
fn plain(value: &Value) -> Result<Value, String> {
    let text = value.to_string();
    if text.contains("\"$datetime\"") || text.contains("\"$int\"") {
        return Err(format!("JSON の中に印がある: {text}"));
    }
    Ok(value.clone())
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

fn text(map: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match field(map, key) {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        other => Err(format!("{key} が文字でない: {other}")),
    }
}

fn flag(map: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match field(map, key) {
        Value::Null => Ok(false),
        Value::Bool(flag) => Ok(*flag),
        other => Err(format!("{key} が真偽でない: {other}")),
    }
}

fn integer(map: &Map<String, Value>, key: &str) -> Result<i64, String> {
    field(map, key)
        .as_i64()
        .ok_or_else(|| format!("{key} が 64 ビットの整数でない: {}", field(map, key)))
}

/// `{"$datetime": "…+00:00"}`（時差のあるもの）か null。
fn time(map: &Map<String, Value>, key: &str) -> Result<Option<DateTime<Utc>>, String> {
    let value = field(map, key);
    if value.is_null() {
        return Ok(None);
    }
    let Some(text) = value.get("$datetime").and_then(Value::as_str) else {
        return Err(format!("{key} が datetime でない: {value}"));
    };
    match DateTime::parse_from_rfc3339(text) {
        Ok(at) => Ok(Some(at.with_timezone(&Utc))),
        Err(_) => Err(format!("{key} が時差の無い datetime: {text}")),
    }
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{what} が辞書でない: {value}"))
}

/// 例の 1 行を [`StateRow`] に（Postgres の services が返しうる値だけ）。
fn state_row(value: &Value) -> Result<StateRow, String> {
    let map = object(value, "行")?;
    Ok(StateRow {
        guild_id: field(map, "guild_id").as_i64().unwrap_or_default(),
        user_id: integer(map, "user_id")?,
        username: text(map, "username")?,
        display_name: text(map, "display_name")?,
        avatar_url: text(map, "avatar_url")?,
        status: text(map, "status")?,
        is_in_guild: flag(map, "is_in_guild")?,
        is_banned: flag(map, "is_banned")?,
        is_timed_out: flag(map, "is_timed_out")?,
        timed_out_until: time(map, "timed_out_until")?,
        roles: plain(field(map, "roles"))?,
        abilities: plain(field(map, "abilities"))?,
        last_event_type: text(map, "last_event_type")?,
        last_event_at: time(map, "last_event_at")?,
        first_seen_at: time(map, "first_seen_at")?,
        last_joined_at: time(map, "last_joined_at")?,
        last_left_at: time(map, "last_left_at")?,
        updated_at: time(map, "updated_at")?,
    })
}

/// 例の履歴の 1 件を [`EventRow`] に。
fn event_row(value: &Value) -> Result<EventRow, String> {
    let map = object(value, "履歴")?;
    let payload = match plain(field(map, "payload"))? {
        Value::Object(payload) => payload,
        other => return Err(format!("履歴の中身が辞書でない: {other}")),
    };
    let actor_user_id = match field(map, "actor_user_id") {
        Value::Null => None,
        _ => Some(integer(map, "actor_user_id")?),
    };
    Ok(EventRow {
        id: integer(map, "id")?,
        event_type: text(map, "event_type")?,
        status_after: text(map, "status_after")?,
        actor_user_id,
        actor_name: text(map, "actor_name")?,
        reason: text(map, "reason")?,
        event_at: time(map, "event_at")?,
        payload,
    })
}

/// 例の詳細（null か `{"current", "events"}`）。
fn detail(value: &Value) -> Result<Option<Detail>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let map = object(value, "詳細")?;
    let current = match field(map, "current") {
        Value::Null => None,
        other => Some(state_row(other)?),
    };
    let events = match field(map, "events") {
        Value::Null => Vec::new(),
        Value::Array(items) => items.iter().map(event_row).collect::<Result<_, _>>()?,
        other => return Err(format!("events が並びでない: {other}")),
    };
    Ok(Some(Detail { current, events }))
}

/// `{"$raise": "RuntimeError", "message": "…"}` なら、その例外。
fn raised(value: &Value) -> Option<Crash> {
    let kind = value.get("$raise")?.as_str()?;
    let message = value.get("message").and_then(Value::as_str).unwrap_or("");
    Some(Crash::new(kind, message))
}

/// 例の service の 1 つ（書いていなければ `None`、`$raise` なら例外、ほかは `parse` で読む）。
fn convert<T>(
    value: Option<&Value>,
    parse: impl Fn(&Value) -> Result<T, String>,
) -> Result<Option<Result<T, Crash>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(crash) = raised(value) {
        return Ok(Some(Err(crash)));
    }
    Ok(Some(Ok(parse(value)?)))
}

/// 例の service（偽物が返すもの。書いていない関数は `None`）。
#[derive(Default)]
struct Service {
    list: Option<Result<Vec<StateRow>, Crash>>,
    count: Option<Result<i64, Crash>>,
    detail: Option<Result<Option<Detail>, Crash>>,
}

fn rows(value: &Value) -> Result<Vec<StateRow>, String> {
    let Value::Array(items) = value else {
        return Err(format!("一覧が並びでない: {value}"));
    };
    items.iter().map(state_row).collect()
}

fn count(value: &Value) -> Result<i64, String> {
    value.as_i64().ok_or_else(|| format!("件数が整数でない: {value}"))
}

/// 例の service を Rust の型にする（Postgres の services が返さない値なら `Err`）。
fn service_of(case: &Value, library: &Value) -> Result<Service, String> {
    let service = resolve(&case["service"], library);
    let pick = |key: &str| service.get(key);
    Ok(Service {
        list: convert(pick("list"), rows)?,
        count: convert(pick("count"), count)?,
        detail: convert(pick("detail"), detail)?,
    })
}

/// Python の int の書き方（harness の encode。64 ビットに収まらなければ `{"$int": …}`）。
fn int_json(value: i128) -> Value {
    if let Ok(small) = i64::try_from(value) {
        return Value::from(small);
    }
    if let Ok(unsigned) = u64::try_from(value) {
        return Value::from(unsigned);
    }
    json!({"$int": value.to_string()})
}

/// 例の service を返し、届いた呼び出しを控える偽物。
struct Fake {
    service: Service,
    calls: Mutex<Vec<Value>>,
}

impl Fake {
    fn answer<T: Clone + Send + 'static>(
        &self,
        call: Value,
        answer: &Option<Result<T, Crash>>,
    ) -> StoreFuture<'static, T> {
        let name = call["fn"].as_str().unwrap_or_default().to_string();
        self.calls.lock().unwrap().push(call);
        let message = format!("例に書いていない {name} が呼ばれた");
        let answer = answer
            .clone()
            .unwrap_or_else(|| Err(Crash::new("RuntimeError", message)));
        Box::pin(async move { answer })
    }
}

impl UserStates for Fake {
    fn list<'a>(
        &'a self,
        guild_id: i128,
        query: Option<&'a str>,
        limit: i64,
        offset: i128,
    ) -> StoreFuture<'a, Vec<StateRow>> {
        let args = json!([int_json(guild_id)]);
        let kwargs = json!({"query": query, "limit": limit, "offset": int_json(offset)});
        let call = json!({"fn": "list_recent_user_states", "args": args, "kwargs": kwargs});
        self.answer(call, &self.service.list)
    }

    fn count<'a>(&'a self, guild_id: i128, query: Option<&'a str>) -> StoreFuture<'a, i64> {
        let args = json!([int_json(guild_id)]);
        let kwargs = json!({"query": query});
        let call = json!({"fn": "count_user_states", "args": args, "kwargs": kwargs});
        self.answer(call, &self.service.count)
    }

    fn detail(
        &self,
        guild_id: i128,
        user_id: i128,
        event_limit: i64,
    ) -> StoreFuture<'_, Option<Detail>> {
        let args = json!([int_json(guild_id), int_json(user_id)]);
        let kwargs = json!({"event_limit": event_limit});
        let call = json!({"fn": "get_user_state_detail", "args": args, "kwargs": kwargs});
        self.answer(call, &self.service.detail)
    }
}

/// 文字を latin-1 のバイトにする（基準の見出しは latin-1 で読んだ文字で書いてある）。
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 の外の文字"))
        .collect()
}

/// Python が送った要求（パスと問い合わせ、例の見出しと Cookie）。TestClient が足す見出しも足す（付け替えの 307 は
/// Host から URL を組む）。接続元は TestClient の `testclient`。
fn incoming(request: &Value) -> Incoming {
    let target = request["target"].as_str().unwrap();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.to_string(), None),
    };
    let mut headers = HeaderMap::new();
    let defaults = [
        ("host", "testserver"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate"),
        ("connection", "keep-alive"),
        ("user-agent", "testclient"),
    ];
    for (name, value) in defaults {
        headers.insert(name, HeaderValue::from_static(value));
    }
    for pair in request["headers"].as_array().unwrap() {
        let name = HeaderName::from_bytes(pair[0].as_str().unwrap().as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(&latin1_bytes(pair[1].as_str().unwrap())).unwrap();
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

fn sorted_allow(value: &str) -> String {
    let mut words: Vec<&str> = value.split(',').map(str::trim).collect();
    words.sort_unstable();
    words.join(", ")
}

/// 1 つの答えを比べ、違うところを並べる。
fn compare(want: &Value, got: &Reply) -> Vec<String> {
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
    let mut rust = got.headers.clone();
    // 名前の順（同じ名前の中は足した順のまま。Python の基準と同じ並べ方）。
    rust.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &mut rust {
        if name == "allow" {
            *value = sorted_allow(value);
        }
    }
    if python != rust {
        wrong.push(format!(
            "見出し:\n    Python {python:?}\n    Rust   {rust:?}"
        ));
    }
    let body = want["body"].as_str().unwrap();
    if got.body != body.as_bytes() {
        let rust = String::from_utf8_lossy(&got.body);
        wrong.push(format!("本文:\n    Python {body}\n    Rust   {rust}"));
    }
    wrong
}

/// 例ごとの app（偽物を差し込む。インシデントの置き場は例ごとの一時ディレクトリ）。
fn app(data: &Value, fake: Arc<Fake>, dir: &std::path::Path) -> Arc<AdminApp> {
    let now = data["now"].as_f64().unwrap();
    let config = Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: String::new(),
        monitor_dir: dir.to_path_buf(),
    };
    let deps = Deps {
        clock: Arc::new(move || now),
        random: Arc::new(OsRandom),
        pages: Arc::new(PlainPages),
        reporter: Arc::new(Reporter::new("test", None)),
    };
    let secret = data["secret"].as_str().unwrap();
    let admin = AdminApp::new(config, secret, deps, routes::default_routes());
    Arc::new(admin.with_users(fake))
}

fn names(document: &Value) -> Vec<String> {
    document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn the_users_api_answers_like_python() {
    let data = read("expected.json");
    let document = read("cases.json");
    assert_eq!(
        names(&data),
        names(&document),
        "基準が例の文書と食い違う（cases.json を変えたら、CI の「基準」が作り直した expected.json をコミットする）"
    );
    let library = &document["library"];
    let sources: HashMap<String, &Value> = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| (case["name"].as_str().unwrap().to_string(), case))
        .collect();
    let mut wrong = Vec::new();
    let mut compared = 0;
    let mut skipped = Vec::new();
    for case in data["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let source = sources[name];
        let service = service_of(source, library);
        let service = match (source["rust_skip"].as_str(), service) {
            (Some(reason), Err(why)) => {
                eprintln!("飛ばす: {name}（{reason}。{why}）");
                skipped.push(name.to_string());
                continue;
            }
            (Some(_), Ok(_)) => {
                wrong.push(format!("「{name}」は飛ばさなくてよい"));
                continue;
            }
            (None, Err(why)) => {
                wrong.push(format!("「{name}」を型にできない: {why}"));
                continue;
            }
            (None, Ok(service)) => service,
        };
        let fake = Arc::new(Fake {
            service,
            calls: Mutex::new(Vec::new()),
        });
        let dir = tempfile::tempdir().unwrap();
        let app = app(&data, Arc::clone(&fake), dir.path());
        let request = incoming(&case["request"]);
        let reply = app.respond(request).await;
        compared += 1;
        for problem in compare(&case["response"], &reply) {
            wrong.push(format!("「{name}」: {problem}"));
        }
        let calls = Value::Array(fake.calls.lock().unwrap().clone());
        if calls != case["calls"] {
            let want = &case["calls"];
            wrong.push(format!(
                "「{name}」の呼び出し:\n    Python {want}\n    Rust   {calls}"
            ));
        }
    }
    assert!(compared >= 70, "比べた例が足りない（{compared}）");
    assert_eq!(skipped.len(), 3, "飛ばした例: {skipped:?}");
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
