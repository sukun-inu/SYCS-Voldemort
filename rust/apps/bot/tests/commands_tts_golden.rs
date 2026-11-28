//! 読み上げの設定のコマンド（/tts・/voice・/dict）と声の補完が、本物の Python と同じであること。
//!
//! 基準（`fixtures/tts/commands_expected.jsonl`）は `generate_commands.py` が作る:
//!
//! - commands: 本物のコマンドの中身を、記録するだけの偽物の interaction で呼んだもの。返事（本文・Embed・本人に
//!   だけ見せるか）と、書き換えたあとの設定（鍵の並びまで）。Python が例外で終わる例は `{"error": true}`
//! - voices: 本物の声の補完を、偽物の合成の API につないで呼んだもの。候補（名前と値）
//!
//! 声の補完は、同じ台本の偽物の API をテストの中に立てて比べる。

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use serenity::all::{CommandDataOption, GuildId};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::reply::Reply;
use sycs_bot::commands::tts::{self, Input, Plan};
use sycs_bot::commands::{self, Route};
use sycs_bot::tts as speech;
use sycs_core::settings::{Settings, drop_nulls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const GUILD: u64 = 1_399_617_700_363_370_556;
const USER: u64 = 80_351_110_224_678_912;

/// 例の中の印（長い辞書）を広げる（`generate_commands.py` の `expand`）。
fn expand(before: &Value) -> Value {
    let mut before = before.clone();
    if before["tts"]["dictionary"] == "LONG" {
        let entries: serde_json::Map<String, Value> = (0..120)
            .map(|i| {
                (
                    format!("語{i:03}{}", "あ".repeat(40)),
                    json!("読み".repeat(40)),
                )
            })
            .collect();
        before["tts"]["dictionary"] = Value::Object(entries);
    }
    before
}

/// 引数を、Discord から届く形（種類の番号つき）にする。
fn options(case: &Value) -> Vec<CommandDataOption> {
    let list: Vec<Value> = case["options"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| match name.as_str() {
            // 7 はチャンネル（ID は文字列で届く）、4 は整数、3 は文字列。
            "channel" => json!({"name": name, "type": 7, "value": value.to_string()}),
            "rate" => json!({"name": name, "type": 4, "value": value}),
            _ => json!({"name": name, "type": 3, "value": value}),
        })
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

/// Python の `embed.to_dict()` から取り出すものと同じ形。
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
                .map(|f| json!([f["name"], f["value"], f["inline"].as_bool().unwrap_or(false)]))
                .collect();
            json!({"title": v["title"], "description": v["description"], "color": v["color"], "fields": fields})
        })
        .collect();
    json!({"content": reply.content, "ephemeral": reply.ephemeral, "embeds": embeds})
}

fn run_command(case: &Value) -> Value {
    let before = expand(&case["before"]);
    let mut settings = Settings::default();
    settings.guilds.insert(GUILD.to_string(), before.clone());
    let (standing, guild_id) = match case["who"].as_str().unwrap() {
        "admin" => (Standing::Admin, Some(GuildId::new(GUILD))),
        "member" => (Standing::Member, Some(GuildId::new(GUILD))),
        _ => (Standing::OutsideGuild, None),
    };
    let path = case["path"].as_str().unwrap();
    let Some(Route::Tts(route)) = commands::route(path) else {
        panic!("読み上げの設定のコマンドでない: {path}");
    };
    let channels: Vec<u64> = case["channels"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| c.as_u64().unwrap())
        .collect();
    let channel_exists = |id: u64| channels.contains(&id);
    let options = options(case);
    let input = Input {
        standing,
        guild_id,
        user_id: USER,
        options: &options,
        guild_settings: Some(&before),
        channel_exists: &channel_exists,
    };
    let reply = match tts::plan(route, &input) {
        Ok(Plan::Reply(reply)) => reply_json(&reply),
        Ok(Plan::Write(write)) => reply_json(&write(&mut settings)),
        Err(_) => json!({"error": true}),
    };
    // 保存のときと同じく、null は落とす。
    let mut after = settings.guilds[&GUILD.to_string()].clone();
    drop_nulls(&mut after);
    json!(["commands", case["id"], reply, after])
}

/// 台本どおりに答える偽物の合成の API（声の一覧）を立てる。
async fn start_fake_tts(response: Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            shared
                .lock()
                .unwrap()
                .push(head.split(' ').nth(1).unwrap_or("").to_string());
            let body = match response.get("json") {
                Some(v) => v.to_string(),
                None => response["body"].as_str().unwrap_or("").to_string(),
            };
            let status = response["status"].as_u64().unwrap_or(200);
            let kind = response["type"].as_str().unwrap_or("application/json");
            let reply = format!(
                "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
        }
    });
    (base, seen)
}

async fn run_voices(case: &Value) -> Value {
    let mut response = case["response"].clone();
    if response["json"] == "MANY" {
        response["json"] = (0..40)
            .map(|i| json!({"name": format!("voice{i:02}")}))
            .collect();
    }
    let (base, seen) = start_fake_tts(response).await;
    let api = speech::TtsApi::new(&base);
    let voices = api.fetch_voices().await;
    let choices: Vec<Value> = speech::voice_choices(&voices, case["current"].as_str().unwrap())
        .into_iter()
        .map(|v| json!([v, v]))
        .collect();
    // Python と同じ場所に、同じ問い合わせで取りに行くこと。
    assert_eq!(*seen.lock().unwrap(), ["/api/v1/voices?locale=ja"]);
    json!(["voices", case["id"], choices])
}

fn fixtures() -> (Value, Vec<Value>) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tts");
    let cases = serde_json::from_str(
        &std::fs::read_to_string(format!("{dir}/commands_cases.json")).unwrap(),
    )
    .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/commands_expected.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (cases, expected)
}

fn report(kind: &str, results: Vec<(Value, Value)>) {
    let wrong: Vec<String> = results
        .iter()
        .filter(|(got, want)| got != want)
        .map(|(got, want)| format!("{}\n  py {want}\n  rs {got}", want[1]))
        .collect();
    assert!(
        wrong.is_empty(),
        "{kind}: {} 例が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn tts_commands_answer_and_write_like_python() {
    let (cases, expected) = fixtures();
    let want: Vec<&Value> = expected.iter().filter(|l| l[0] == "commands").collect();
    let cases = cases["commands"].as_array().unwrap();
    assert_eq!(cases.len(), want.len(), "基準と例の数が違う");
    let results = cases
        .iter()
        .zip(want)
        .map(|(case, want)| (run_command(case), want.clone()))
        .collect();
    report("commands", results);
}

#[tokio::test]
async fn voice_choices_match_python() {
    let (cases, expected) = fixtures();
    let want: Vec<&Value> = expected.iter().filter(|l| l[0] == "voices").collect();
    let cases = cases["voices"].as_array().unwrap();
    assert_eq!(cases.len(), want.len(), "基準と例の数が違う");
    let mut results = Vec::new();
    for (case, want) in cases.iter().zip(want) {
        results.push((run_voices(case).await, want.clone()));
    }
    report("voices", results);
}

/// 合成の API を、Python と同じ場所に同じ本文で呼び、同じ音声の場所を返すこと（`generate_synth.py` の基準）。
#[tokio::test]
async fn synthesis_is_requested_like_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tts");
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/synth_cases.json")).unwrap())
            .unwrap();
    let expected: Vec<Value> = std::fs::read_to_string(format!("{dir}/synth_expected.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let (base, seen) = start_fake_synth(case["reply"].clone()).await;
        // Python の基準は、末尾に `/` を付けた場所で作った（設定で落とされる）。
        let api = speech::TtsApi::new(&format!("{base}/"));
        let (url, _) = api
            .synthesize(
                case["text"].as_str().unwrap(),
                case["voice"].as_str().unwrap(),
                case["rate"].as_i64().unwrap(),
            )
            .await;
        let url = url.map(|u| u.replacen(&base, "http://127.0.0.1:18090", 1));
        let seen = seen.lock().unwrap().clone();
        let got = json!([case["id"], seen, url]);
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

/// 台本どおりに答える偽物の合成の API。受けた要求（場所と本文の JSON）を覚える。
async fn start_fake_synth(reply: Value) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
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
            let length: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            while buf.len() < header_end + length {
                let n = sock.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let path = head.split(' ').nth(1).unwrap_or("").to_string();
            let body: Value = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
            shared
                .lock()
                .unwrap()
                .push(json!({"path": path, "body": body}));
            let text = match reply.get("json") {
                Some(v) => v.to_string(),
                None => reply["body"].as_str().unwrap_or("").to_string(),
            };
            let status = reply["status"].as_u64().unwrap_or(200);
            let kind = reply["type"].as_str().unwrap_or("application/json");
            let response = format!(
                "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\r\n{text}",
                text.len()
            );
            let _ = sock.write_all(response.as_bytes()).await;
        }
    });
    (base, seen)
}

/// VC の出入りに応じた読み上げの決め方が、Python と同じであること（`generate_voice.py` の基準）。
#[test]
fn voice_events_are_handled_like_python() {
    use sycs_bot::tts_voice::{VoiceEvent, VoiceSettings, VoiceStep, voice_plan};
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tts");
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/voice_cases.json")).unwrap())
            .unwrap();
    let expected: Vec<Value> = std::fs::read_to_string(format!("{dir}/voice_expected.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let guild = json!({"tts": case["settings"]});
        let tts = speech::settings(Some(&guild)).unwrap();
        let temp = case["temp"].as_u64();
        let settings = VoiceSettings {
            enabled: sycs_bot::commands::settings::python_truthy(tts.get("enabled")),
            notify: sycs_bot::commands::settings::python_truthy(tts.get("vc_notify")),
            watched: speech::effective_vc_watch(tts, temp).ok().map(|(vc, _)| vc),
            configured: speech::vc_channel_id(tts).ok(),
            has_temp: temp.is_some(),
        };
        let event = VoiceEvent {
            is_bot: case["bot"] == true,
            before: case["before"].as_u64(),
            after: case["after"].as_u64(),
            before_has_no_humans: case["humans_before"].as_u64().unwrap_or(0) == 0,
        };
        let steps: Vec<Value> = voice_plan(&event, &settings)
            .into_iter()
            .map(|step| match step {
                VoiceStep::Disconnect => json!(["disconnect"]),
                VoiceStep::Announce { joined } => {
                    json!(["announce", if joined { "join" } else { "leave" }])
                }
                VoiceStep::AutoJoin(vc) => json!(["auto_join", vc]),
            })
            .collect();
        let got = json!([case["id"], steps]);
        if &got != want {
            wrong.push(format!("py {want}\n  rs {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
