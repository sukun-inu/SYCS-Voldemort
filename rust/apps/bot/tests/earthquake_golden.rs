//! 地震の通知（電文の読み方・Embed・送り先の判定・送る流れ）が、本物の Python と同じ結果になること。
//!
//! 基準（`fixtures/earthquake/expected.jsonl`）は、本物の Python の `services/earthquake_service.py` に
//! `cases.json` の例を 1 つずつ与えたもの（`generate.py`。Discord・画像・気象庁の一覧は記録するだけの
//! 偽物）。ここでは同じ例を Rust に与えて、1 行ずつ比べる。

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use chrono::DateTime;
use serde_json::{Map, Value, json};
use serenity::all::CreateEmbed;
use sycs_bot::earthquake::{
    self, Deps, DetailUrls, Directory, Evaluation, Images, MapRequest, Notice, NotifyType, Outbox,
    ScoreTarget,
};
use sycs_core::settings::Settings;

const G1: u64 = 1_399_617_700_363_370_556;

/// Python の `norm(embed)` と同じ形。
fn embed_json(embed: &CreateEmbed) -> Value {
    let v = serde_json::to_value(embed).unwrap();
    let timestamp = v["timestamp"].as_str().map(|t| {
        DateTime::parse_from_rfc3339(t)
            .unwrap_or_else(|e| panic!("時刻を読めない: {t} ({e})"))
            .timestamp()
    });
    let fields: Vec<Value> = v["fields"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|f| {
                    json!([
                        f["name"],
                        f["value"],
                        f["inline"].as_bool().unwrap_or(false)
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "title": v["title"],
        "description": v["description"],
        "color": v["color"],
        "timestamp": timestamp,
        "fields": fields,
        "footer": [v["footer"]["text"], v["footer"]["icon_url"]],
        "thumbnail": v["thumbnail"]["url"],
        "image": v["image"]["url"],
    })
}

/// サーバーごとのチャンネル（id → 種類）。読めていないサーバーは `None`。
struct FakeDirectory(HashMap<u64, Option<HashMap<i64, String>>>);

impl FakeDirectory {
    fn of(guilds: &Map<String, Value>) -> Self {
        let mut table = HashMap::new();
        for (gid, g) in guilds {
            let channels = g["cached"].as_bool().unwrap_or(true).then(|| {
                g["channels"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(cid, kind)| (cid.parse().unwrap(), kind.as_str().unwrap().to_string()))
                    .collect()
            });
            table.insert(gid.parse().unwrap(), channels);
        }
        Self(table)
    }
}

impl Directory for FakeDirectory {
    fn has_guild(&self, guild_id: u64) -> bool {
        matches!(self.0.get(&guild_id), Some(Some(_)))
    }

    fn is_text_channel(&self, guild_id: u64, channel_id: i64) -> bool {
        self.0
            .get(&guild_id)
            .and_then(Option::as_ref)
            .and_then(|channels| channels.get(&channel_id))
            .is_some_and(|kind| kind == "text" || kind == "news")
    }
}

fn settings_of(guilds: &Map<String, Value>) -> Settings {
    let mut map = BTreeMap::new();
    for (gid, g) in guilds {
        if !g["settings"].is_null() {
            map.insert(gid.clone(), g["settings"].clone());
        }
    }
    Settings {
        guilds: map,
        ..Settings::default()
    }
}

struct FakeOutbox<'a> {
    guilds: &'a Map<String, Value>,
    sent: Mutex<Vec<Value>>,
}

impl Outbox for FakeOutbox<'_> {
    async fn send(&self, guild_id: u64, channel_id: u64, notice: &Notice) -> Result<(), String> {
        let fails = self.guilds[&guild_id.to_string()]["send_fails"]
            .as_array()
            .is_some_and(|f| f.iter().any(|c| c.as_u64() == Some(channel_id)));
        // ボタンは、本物の組み立て（detail_button）を通して確かめる。
        let button = notice.detail_url.as_ref().map(|url| {
            let row = serde_json::to_value(earthquake::detail_button(url)).unwrap();
            let b = &row["components"][0];
            assert_eq!(
                (&row["type"], &b["type"], &b["style"]),
                (&json!(1), &json!(2), &json!(5))
            );
            json!([b["label"], b["url"]])
        });
        let files: Vec<Value> = notice
            .attachments
            .iter()
            .map(|(name, data)| json!([name, String::from_utf8_lossy(data)]))
            .collect();
        self.sent.lock().unwrap().push(json!([
            guild_id,
            channel_id,
            !fails,
            embed_json(&notice.embed),
            button,
            files
        ]));
        if fails {
            Err("403 Forbidden".into())
        } else {
            Ok(())
        }
    }
}

struct FakeImages<'a> {
    badge: &'a str,
    map: &'a str,
    badge_calls: Mutex<Vec<i64>>,
    map_calls: Mutex<Vec<Value>>,
}

impl Images for FakeImages<'_> {
    async fn badge(&self, scale: i64) -> Option<Vec<u8>> {
        self.badge_calls.lock().unwrap().push(scale);
        (self.badge == "ok").then(|| format!("BADGE{scale}").into_bytes())
    }

    async fn map(&self, request: &MapRequest) -> Option<Vec<u8>> {
        self.map_calls.lock().unwrap().push(json!([
            request.lat,
            request.lon,
            request.points.len(),
            request.title,
            request.subtitle
        ]));
        (self.map == "ok").then(|| b"MAP".to_vec())
    }
}

struct FakeUrls<'a>(&'a [Value]);

impl DetailUrls for FakeUrls<'_> {
    async fn resolve(&self, event: &Value, max_scale: i64) -> String {
        earthquake::best_detail_url(self.0, event, max_scale)
    }
}

fn notify_type(name: &str) -> NotifyType {
    match name {
        "quake_info" => NotifyType::QuakeInfo,
        "tsunami" => NotifyType::Tsunami,
        "eew_warning" => NotifyType::EewWarning,
        "eew_forecast" => NotifyType::EewForecast,
        other => panic!("知らない種類: {other}"),
    }
}

async fn notify(case: &Value) -> Value {
    let guilds = case["guilds"].as_object().unwrap();
    let settings = settings_of(guilds);
    let directory = FakeDirectory::of(guilds);
    let outbox = FakeOutbox {
        guilds,
        sent: Mutex::default(),
    };
    let images = FakeImages {
        badge: case["badge"].as_str().unwrap(),
        map: case["map"].as_str().unwrap(),
        badge_calls: Mutex::default(),
        map_calls: Mutex::default(),
    };
    let empty = Vec::new();
    let urls = FakeUrls(case["jma"].as_array().unwrap_or(&empty));
    let deps = Deps {
        settings: &settings,
        directory: &directory,
        outbox: &outbox,
        images: &images,
        urls: &urls,
        handles: &|_| true,
    };
    let event = &case["event"];
    let count = match case["kind"].as_str().unwrap() {
        "quake" => {
            earthquake::notify_quake(
                &deps,
                event,
                case["only_guild"].as_u64(),
                case["override_channel"].as_i64(),
            )
            .await
        }
        "tsunami" => earthquake::notify_tsunami(&deps, event).await,
        kind => earthquake::notify_eew(&deps, event, notify_type(kind)).await,
    };
    let mut sent = outbox.sent.into_inner().unwrap();
    sent.sort_by_key(|s| (s[0].as_u64(), s[1].as_u64()));
    json!({
        "count": count,
        "sent": sent,
        "badge": images.badge_calls.lock().unwrap().first(),
        "map": images.map_calls.lock().unwrap().first(),
    })
}

fn evaluate(case: &Value) -> Value {
    let guild = json!({
        "settings": case["settings"],
        "cached": case["guild"] == "cached",
        "channels": case["channels"],
    });
    let mut guilds = Map::new();
    guilds.insert(G1.to_string(), guild);
    let settings = settings_of(&guilds);
    let directory = FakeDirectory::of(&guilds);
    let kind = notify_type(case["notify_type"].as_str().unwrap());
    let max_scale = case["max_scale"].as_i64().unwrap();
    let apply = case["apply_min_scale"].as_bool().unwrap();
    let eval = match earthquake::evaluate_guild(
        settings.guild(G1),
        &directory,
        G1,
        kind,
        max_scale,
        apply,
    ) {
        Evaluation::Target(channel) => json!(["target", channel]),
        Evaluation::Skip(reason) => json!(["skip", reason]),
        Evaluation::Broken(_) => json!(["broken"]),
    };
    let mut diagnose =
        earthquake::diagnose_no_target(&settings, &directory, G1, kind, max_scale, apply);
    // 壊れた設定の理由は、例外の文（言語ごとに違う）を含むので、前置きだけを比べる。
    let marker = "設定の読み取りに失敗しました（";
    if diagnose.starts_with(marker) {
        diagnose = marker.into();
    }
    json!({"eval": eval, "diagnose": diagnose})
}

/// Python の `str(text or "")`。
fn text_or_empty(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        v if earthquake::truthy(v) => v.to_string(),
        _ => String::new(),
    }
}

fn finite(value: f64) -> Value {
    if value.is_finite() {
        json!(value)
    } else {
        Value::Null
    }
}

async fn run(case: &Value) -> Value {
    let event = &case["event"];
    match case["op"].as_str().unwrap() {
        "max_scale" => json!(earthquake::max_scale(event)),
        "parse_coord" => json!(earthquake::parse_coord(&case["raw"])),
        "parse_depth" => json!(earthquake::parse_depth(&case["raw"])),
        "parse_magnitude" => {
            let (label, value) = earthquake::parse_magnitude(&case["raw"]);
            json!([label, finite(value)])
        }
        "format_time" => {
            let (label, at) = earthquake::format_time(case["text"].as_str().unwrap());
            json!([label, at.map(|d| d.timestamp())])
        }
        "embed" => embed_json(&earthquake::build_embed(
            event,
            earthquake::max_scale(event),
            case["has_badge"].as_bool().unwrap(),
        )),
        "eew_embed" => embed_json(&earthquake::build_eew_embed(event)),
        "tsunami_embed" => embed_json(&earthquake::build_tsunami_embed(event)),
        "scale_from_text" => json!(earthquake::scale_from_text(&text_or_empty(&case["text"]))),
        "magnitude_value" => {
            earthquake::parse_magnitude_value(&case["raw"]).map_or(Value::Null, finite)
        }
        "any_time" => json!(earthquake::parse_any_time(&case["raw"])),
        "score" => json!(ScoreTarget::of(event, earthquake::max_scale(event)).score(&case["item"])),
        "detail_url" => {
            let scale = earthquake::max_scale(event);
            json!({
                "url": earthquake::best_detail_url(case["items"].as_array().unwrap(), event, scale),
                "key": earthquake::cache_key_for_event(event, scale),
            })
        }
        "evaluate" => evaluate(case),
        "notify" => notify(case).await,
        "map_subtitle" => json!(earthquake::map_subtitle(event)),
        "replay" => match earthquake::parse_replay(case["payload"].as_str().unwrap()) {
            Ok(r) => json!([r.event, r.guild_id, r.channel_id]),
            Err(_) => json!("error"),
        },
        other => panic!("知らない op: {other}"),
    }
}

/// 数は値で比べる（Python の 40 と Rust の 40.0 を同じとみなす）。それ以外は形ごと同じであること。
///
/// 小数はごくわずかな差を許す。基準のファイルを読む serde_json は、桁の多い小数（点数の
/// `121.16666666666667` など）を最後の 1 桁まで正確には読まない（計算した側の値は Python と同じだった）。
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(p), Some(q)) => (p - q).abs() <= 1e-12 * p.abs().max(q.abs()).max(1.0),
            _ => false,
        },
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| same(p, q)))
        }
        _ => a == b,
    }
}

#[tokio::test]
async fn the_results_match_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/earthquake");
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/cases.json")).unwrap())
            .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/expected.jsonl")).unwrap();
    let expected: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    assert!(cases.len() >= 800, "例が減っている: {}", cases.len());
    let mut wrong = Vec::new();
    for (i, (case, want)) in cases.iter().zip(expected).enumerate() {
        let want: Value = serde_json::from_str(want).unwrap();
        // Python が例外で終わる例は比べない（こちらは読めるところだけで続ける）。
        if want.get("raises").is_some() {
            continue;
        }
        let got = run(case).await;
        if !same(&got, &want) {
            wrong.push(format!("#{i} {case}\n  py {want}\n  rs {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が Python と違う:\n{}",
        wrong.len(),
        wrong
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
