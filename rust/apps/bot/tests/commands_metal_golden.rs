//! 貴金属のコマンド（/metal gold・silver・platinum・all）が、本物の Python と同じことをすること。
//!
//! 基準（`fixtures/commands/metal_expected.jsonl`）は、本物の Python のコマンドの中身を、記録するだけの偽物の
//! interaction で呼び、値段の API を偽物（例ごとに決めた応答を返す）に向けて動かしたもの（`generate_metal.py`）。
//! ここでも同じ偽物の API をテストの中に立て、Rust の /metal（[`metal::handle`]）を、外への働きかけを覚えるだけの
//! 出口（[`Outlet`]）で動かして比べる:
//!
//! - 外への働きかけの順番と中身（考え中・最初の応答・あとからの送信・ログチャンネルへの記録。それぞれ成功したか）
//! - API が受けた要求（場所と問い合わせ。覚えた値段を使ったときは送らない）
//! - コマンドが失敗で終わったか（その文）
//!
//! Discord への送信の失敗は、例が決めたとおりに起こす（文は discord.py の `str(HTTPException)` と同じ形）。
//! Discord へ実際に送る形（種類 5 の考え中・あとからの送信の場所）は `commands_discord.rs` が見る。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, TimeZone};
use serde_json::{Value, json};
use sycs_bot::commands::metal::{self, GOLD, Kind, Outlet, PLATINUM, Request, SILVER};
use sycs_bot::commands::reply::Reply;
use sycs_bot::log_channel::{Level, jst};
use sycs_bot::metal::{MetalConfig, MetalPrices};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CHANNEL: u64 = 1_505_310_388_051_251_000;
const API_KEY: &str = "test-key";
const METALS_SITE_URL: &str = "https://metals.example/";

/// 偽物の API が返すものと、受けた要求。
#[derive(Default)]
struct Api {
    canned: HashMap<String, Value>,
    default_rates: HashMap<String, Value>,
    hits: Vec<String>,
}

type SharedApi = Arc<Mutex<Api>>;

/// 金属ごとに決めた応答（無ければ既定の値段）を、HTTP の応答にする（`generate_metal.py` の `FakeApi.handle`）。
fn api_reply(api: &Api, code: &str) -> Vec<u8> {
    let canned = api.canned.get(code).cloned().unwrap_or_else(|| {
        let rate = api.default_rates[code].clone();
        json!({"json": {"success": true, "base": "JPY", "rates": {format!("JPY{code}"): rate}}})
    });
    let body = match canned.get("json") {
        Some(value) => value.to_string(),
        None => canned["body"].as_str().unwrap_or("").to_string(),
    };
    let status = canned["status"].as_u64().unwrap_or(200);
    let content_type = canned["type"].as_str().unwrap_or("application/json");
    let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    if !content_type.is_empty() {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// 偽物の値段の API を立てる。受けた要求の場所と問い合わせ（`/v1/latest?…`）を順に覚える。
async fn start_fake_api() -> (String, SharedApi) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1/latest", listener.local_addr().unwrap());
    let api: SharedApi = Arc::default();
    let shared = Arc::clone(&api);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let api = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let target = head.split(' ').nth(1).unwrap_or("").to_string();
                let code = target
                    .split_once("currencies=")
                    .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string())
                    .unwrap_or_default();
                let reply = {
                    let mut api = api.lock().unwrap();
                    api.hits.push(target);
                    api_reply(&api, &code)
                };
                let _ = sock.write_all(&reply).await;
            });
        }
    });
    (base, api)
}

/// discord.py の `str(HTTPException)`（`403 Forbidden (error code: 50013): Missing Permissions`）。
fn http_error(parts: &Value) -> String {
    format!(
        "{} {} (error code: {}): {}",
        parts[0],
        parts[1].as_str().unwrap(),
        parts[2],
        parts[3].as_str().unwrap()
    )
}

/// 部品を、比べる項目だけにする（行ごと）。
fn components_json(reply: &Reply) -> Value {
    let rows = serde_json::to_value(&reply.components).unwrap();
    rows.as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            row["components"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| json!({"type": c["type"], "style": c["style"], "label": c["label"], "url": c["url"]}))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// 送ったものを、比べる形にする（`generate_metal.py` の `reply_json`）。
fn reply_json(reply: &Reply) -> Value {
    let embeds: Vec<Value> = reply
        .embeds
        .iter()
        .map(|embed| {
            let v = serde_json::to_value(embed).unwrap();
            let fields: Vec<Value> = v["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| {
                    json!([
                        f["name"],
                        f["value"],
                        f["inline"].as_bool().unwrap_or(false)
                    ])
                })
                .collect();
            json!({
                "title": v["title"], "description": v["description"], "color": v["color"],
                "footer": v["footer"]["text"], "fields": fields,
            })
        })
        .collect();
    json!({
        "content": reply.content,
        "ephemeral": reply.ephemeral,
        "embeds": embeds,
        "components": components_json(reply),
    })
}

/// 外への働きかけを順に覚えるだけの出口。失敗させるところは例が決める（`generate_metal.py` の `Recorder`）。
struct Recorder {
    fail: Value,
    events: Mutex<Vec<Value>>,
    followups: Mutex<u32>,
}

impl Recorder {
    fn new(fail: &Value) -> Self {
        Self {
            fail: fail.clone(),
            events: Mutex::default(),
            followups: Mutex::new(0),
        }
    }

    fn push(&self, event: Value) {
        self.events.lock().unwrap().push(event);
    }

    /// 決めた失敗があれば、その文で失敗にする。
    fn outcome(failure: &Value) -> Result<(), String> {
        if failure.is_null() {
            Ok(())
        } else {
            Err(http_error(failure))
        }
    }
}

impl Outlet for Recorder {
    async fn defer(&self) -> Result<(), String> {
        let failure = &self.fail["defer"];
        self.push(json!(["defer", failure.is_null()]));
        Self::outcome(failure)
    }

    async fn respond(&self, reply: Reply) -> Result<(), String> {
        let failure = &self.fail["respond"];
        self.push(json!(["respond", reply_json(&reply), failure.is_null()]));
        Self::outcome(failure)
    }

    async fn followup(&self, reply: Reply) -> Result<(), String> {
        let nth = {
            let mut count = self.followups.lock().unwrap();
            *count += 1;
            *count
        };
        let failure = &self.fail["followup"][nth.to_string()];
        self.push(json!(["followup", reply_json(&reply), failure.is_null()]));
        Self::outcome(failure)
    }

    async fn log(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
    ) -> Result<(), String> {
        let failure = &self.fail["log"][level.name()];
        let pairs: Vec<Value> = fields
            .iter()
            .map(|(name, value)| json!([name, value]))
            .collect();
        self.push(json!([
            "log",
            level.name(),
            message,
            pairs,
            failure.is_null()
        ]));
        Self::outcome(failure)
    }
}

/// Embed の下に書く時刻（`generate_metal.py` の `FrozenDatetime`）。
fn frozen_clock() -> DateTime<FixedOffset> {
    jst().with_ymd_and_hms(2026, 11, 27, 12, 34, 56).unwrap()
}

fn kind_of(name: &str) -> Kind {
    match name {
        "gold" => Kind::Single(&GOLD),
        "silver" => Kind::Single(&SILVER),
        "platinum" => Kind::Single(&PLATINUM),
        "all" => Kind::All,
        other => panic!("知らない /metal: {other}"),
    }
}

/// コマンドを 1 つ回して、外への働きかけと、失敗で終わったか（その文）を返す。
async fn run_command(prices: &MetalPrices, command: &Value, in_guild: bool) -> Value {
    let recorder = Recorder::new(&command["fail"]);
    let request = Request {
        kind: kind_of(command["kind"].as_str().unwrap()),
        // discord.py は数の引数を必ず小数にして渡す。
        grams: command["g"].as_f64().unwrap(),
        in_guild,
        channel_label: format!("<#{CHANNEL}>"),
        metals_site_url: METALS_SITE_URL,
    };
    let outcome = metal::handle(&recorder, prices, &request, frozen_clock).await;
    let events = recorder.events.into_inner().unwrap();
    json!({"events": events, "error": outcome.err()})
}

/// 例を 1 つ回す（続けて打つコマンドがあれば、覚えた値段を共有したまま回す）。
async fn run(spec: &Value, case: &Value) -> Value {
    let (base, api) = start_fake_api().await;
    {
        let mut api = api.lock().unwrap();
        api.default_rates = serde_json::from_value(spec["default_rates"].clone()).unwrap();
        api.canned = serde_json::from_value(case["api"].clone()).unwrap_or_default();
    }
    let prices = MetalPrices::new(MetalConfig {
        api_key: (case["no_key"] != true).then(|| API_KEY.to_string()),
        cache_ttl_seconds: 1800.0,
        base_url: base,
        timeout: Duration::from_secs(10),
    });
    let in_guild = case["who"] != "dm";
    let mut outcomes = Vec::new();
    let then = case["then"].as_array().cloned().unwrap_or_default();
    for command in std::iter::once(case.clone()).chain(then) {
        outcomes.push(run_command(&prices, &command, in_guild).await);
    }
    if case["loose_error"] == true {
        // JSON として読めない応答の文は、Python の json の文なので Rust と揃えられない。あることだけ比べる。
        for outcome in &mut outcomes {
            for event in outcome["events"].as_array_mut().unwrap() {
                if event[0] == "log" && event[1] == "ERROR" {
                    let pairs: Vec<Value> = event[3]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|pair| json!([pair[0], "<読めない JSON の文>"]))
                        .collect();
                    event[3] = Value::Array(pairs);
                }
            }
        }
    }
    let hits = api.lock().unwrap().hits.clone();
    json!([case["id"], outcomes, hits])
}

#[tokio::test]
async fn metal_commands_match_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    let spec: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/metal_cases.json")).unwrap())
            .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/metal_expected.jsonl")).unwrap();
    let expected: Vec<Value> = expected
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let cases = spec["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let got = run(&spec, case).await;
        if &got != want {
            wrong.push(format!("{}\n  py {want}\n  rs {got}", case["id"]));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
