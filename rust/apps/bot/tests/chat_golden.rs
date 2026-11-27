//! AI の会話（応答チャンネルでの受け答え）が、本物の Python と同じに動くこと。
//!
//! 基準（`fixtures/chat/expected.jsonl`）は、本物の Python（`ChatGPT.input_message`・`send_large_message`・
//! `handle_chatgpt_message`）を、台本どおりに答える偽物の Groq につないで動かしたもの（`generate.py`）。
//! ここでも同じ台本の偽物を立て、Rust に同じことをさせて比べる:
//!
//! - talk: Groq に届く依頼の数（SDK の再試行まで含む）と最後の依頼の中身、返事、履歴
//! - split: 長い文をどこで切って送るか
//! - flow: 入力中の表示・送る文・ログに残すものと、その順
//!
//! あわせて、Discord へ実際に送るもの（HTTP の形と順番）を、偽物の Discord で確かめる（入力中の表示 →
//! 返事 → ログ。ログは DEBUG のときだけ。返事を送れなければログも残さない）。こちらは設定のキャッシュに
//! Postgres が要る（`SYCS_TEST_DATABASE_URL`）ので、手元の `cargo test` では飛ばし、CI は必ず回す。

mod support;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, TimeZone};
use serde_json::{Value, json};
use serenity::all::{ChannelId, GuildId};
use sycs_bot::chat::{self, Chats, DiscordOutlet, Incoming, Outlet};
use sycs_bot::groq::{Groq, GroqConfig};
use sycs_bot::log_channel::{Author, AvatarColours, LogSink, jst};
use sycs_core::settings::SettingsCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use support::Seen;

/// これより長い文は、同じ文字の並びを数にまとめて比べる（`generate.py` の `COMPACT_OVER`）。
const COMPACT_OVER: usize = 200;

/// 台本と、届いた依頼。
#[derive(Default)]
struct Stage {
    script: VecDeque<Value>,
    seen: Vec<Value>,
}

type Shared = Arc<Mutex<Stage>>;

/// `[["あ", 3], ["\n", 1]]` のような作り方から、文を作る。
fn text_of(parts: &Value) -> String {
    parts
        .as_array()
        .into_iter()
        .flatten()
        .map(|part| {
            part[0]
                .as_str()
                .unwrap()
                .repeat(usize::try_from(part[1].as_u64().unwrap()).unwrap())
        })
        .collect()
}

/// 台本の応答 1 つから、HTTP の応答を作る（`generate.py` の `FakeGroq.do_POST` と同じ）。
fn http_reply(reply: &Value) -> Vec<u8> {
    let status = reply["status"].as_u64().unwrap_or(200);
    let (body, content_type) = if let Some(text) = reply["text"].as_str() {
        (text.to_string(), "text/plain; charset=utf-8")
    } else if let Some(body) = reply.get("json") {
        (body.to_string(), "application/json")
    } else {
        let content = match reply.get("content_parts") {
            Some(parts) => Value::String(text_of(parts)),
            None => reply["content"].clone(),
        };
        let answer = json!({
            "id": "x", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        });
        (answer.to_string(), "application/json")
    };
    let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    if status >= 400 {
        // 再試行の待ちを短くする（SDK は retry-after-ms、その外側の再試行は retry-after を読む）。
        head.push_str("retry-after-ms: 1\r\nretry-after: 0\r\n");
    }
    head.push_str(&format!(
        "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// 台本どおりに答える偽物の Groq を立てる。
async fn start_fake_groq() -> (String, Shared) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let stage: Shared = Arc::default();
    let shared = Arc::clone(&stage);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let stage = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
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
                let body = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                let reply = {
                    let mut stage = stage.lock().unwrap();
                    stage.seen.push(body);
                    // 台本が尽きたら、最後の応答をくり返す。
                    if stage.script.len() > 1 {
                        stage.script.pop_front().unwrap()
                    } else {
                        stage.script[0].clone()
                    }
                };
                let _ = sock.write_all(&http_reply(&reply)).await;
            });
        }
    });
    (base, stage)
}

/// 偽物につないだ会話の覚え。再試行の待ちは Python の基準を作るときと同じ（下限の 0.5 秒）。
fn chats_for(base: &str, with_key: bool) -> Chats {
    Chats::new(Arc::new(Groq::new(GroqConfig {
        api_key: with_key.then(|| "test-key".to_string()),
        base_url: base.into(),
        max_concurrent: 3,
        min_interval: 0.0,
        max_retries: 2,
        retry_base_delay: 0.5,
        retry_max_delay: 20.0,
    })))
}

/// 止めた時刻（`generate.py` の `FIXED_NOW`）。
fn now() -> DateTime<FixedOffset> {
    jst().with_ymd_and_hms(2026, 11, 27, 21, 5, 9).unwrap()
}

/// 同じ文字の並びを `[文字, 数]` にまとめる。
fn run_length(text: &str) -> Value {
    let mut runs: Vec<(char, u64)> = Vec::new();
    for c in text.chars() {
        match runs.last_mut() {
            Some((last, count)) if *last == c => *count += 1,
            _ => runs.push((c, 1)),
        }
    }
    runs.into_iter()
        .map(|(c, n)| json!([c.to_string(), n]))
        .collect()
}

/// 長い文は、同じ文字の並びを数にまとめた形で比べる。
fn compact(text: &str) -> Value {
    if text.chars().count() > COMPACT_OVER {
        json!({"runs": run_length(text)})
    } else {
        json!(text)
    }
}

/// 届いた依頼を、比べる形にする。最初の文（毎回同じ）は `<system>` と書く（中身は別のテストが比べる）。
fn compact_request(body: &Value) -> Value {
    let system = chat::system_content(now());
    let messages: Vec<Value> = body["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            let content = m["content"].as_str().expect("content は文字列");
            if m["role"] == "system" && content == system {
                json!(["system", "<system>"])
            } else {
                json!([m["role"], compact(content)])
            }
        })
        .collect();
    let mut rest = body.as_object().cloned().unwrap_or_default();
    rest.remove("messages");
    json!({"messages": messages, "rest": rest})
}

fn set_script(stage: &Shared, replies: &Value) {
    let mut stage = stage.lock().unwrap();
    stage.script = replies.as_array().unwrap().iter().cloned().collect();
    stage.seen.clear();
}

async fn talk(case: &Value) -> Value {
    let (base, stage) = start_fake_groq().await;
    let chats = chats_for(&base, case["no_key"] != true);
    let mut turns = Vec::new();
    for turn in case["turns"].as_array().unwrap() {
        set_script(&stage, &turn["replies"]);
        let reply = chats.say(1, 7, turn["text"].as_str().unwrap(), now()).await;
        let (requests, last) = {
            let stage = stage.lock().unwrap();
            (
                stage.seen.len(),
                stage.seen.last().map_or(Value::Null, compact_request),
            )
        };
        let history: Vec<Value> = chats
            .history(1, 7)
            .iter()
            .map(|t| json!([t.role.as_str(), compact(&t.content)]))
            .collect();
        turns.push(json!({"requests": requests, "last": last, "final": reply, "history": history}));
    }
    Value::Array(turns)
}

fn split(case: &Value) -> Value {
    chat::split_large_message(&text_of(&case["parts"]))
        .iter()
        .map(|chunk| run_length(chunk))
        .collect()
}

/// 起きたことを順に覚えるだけの出口。
struct Recorder {
    events: Mutex<Vec<Value>>,
    guild_id: u64,
    channel_id: i64,
    user_id: u64,
    typing_fails: bool,
}

impl Outlet for Recorder {
    async fn typing(&self) {
        if !self.typing_fails {
            self.events
                .lock()
                .unwrap()
                .push(json!(["typing", self.channel_id]));
        }
    }

    async fn send(&self, text: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .push(json!(["send", compact(text)]));
        true
    }

    async fn log(&self, fields: &[(String, String)]) {
        let shown: Vec<Value> = fields
            .iter()
            .map(|(name, value)| json!([name, compact(value)]))
            .collect();
        // 本物の出口（`DiscordOutlet`）は、この題を DEBUG で送る（下の偽物の Discord のテストが見る）。
        self.events.lock().unwrap().push(json!([
            "log",
            self.guild_id,
            "DEBUG",
            chat::LOG_TITLE,
            self.user_id,
            shown
        ]));
    }
}

async fn flow(case: &Value) -> Value {
    let (base, stage) = start_fake_groq().await;
    let chats = chats_for(&base, true);
    let settings = &case["settings"];
    let mut at = 0.0;
    let mut results = Vec::new();
    for spec in case["messages"].as_array().unwrap() {
        let times = spec["repeat"].as_u64().unwrap_or(1);
        at = spec["at"].as_f64().unwrap_or(at);
        let content = match spec.get("content_parts") {
            Some(parts) => text_of(parts),
            None => spec["content"].as_str().unwrap().to_string(),
        };
        let channel = spec["channel"].as_i64().unwrap();
        let mut last = Value::Null;
        for _ in 0..times {
            set_script(&stage, &spec["replies"]);
            let recorder = Recorder {
                events: Mutex::default(),
                guild_id: spec["guild"].as_u64().unwrap_or(1),
                channel_id: channel,
                user_id: spec["user"].as_u64().unwrap(),
                typing_fails: spec["typing_fails"] == true,
            };
            let incoming = Incoming {
                guild_id: recorder.guild_id,
                // 負の番号のチャンネルは無い（Python の例は「0 以下は無効」を見るためのもの）。
                channel_id: channel.unsigned_abs(),
                user_id: recorder.user_id,
                content: &content,
                from_self: spec["self"] == true,
            };
            // DM は、イベントの入口（handler の `message`）がここまで持ってこない。
            if spec["dm"] != true {
                chat::handle(&chats, Some(settings), &incoming, &recorder, at, now()).await;
            }
            let asked = stage
                .lock()
                .unwrap()
                .seen
                .last()
                .map(|body| body["messages"].as_array().map_or(0, Vec::len));
            let events = recorder.events.into_inner().unwrap();
            last = json!({"events": events, "asked_with": asked});
        }
        // くり返した投稿は、最後の 1 回だけを比べる。
        results.push(json!({"times": times, "last": last}));
    }
    Value::Array(results)
}

fn fixtures() -> (Value, Vec<Value>) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chat");
    let cases =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/cases.json")).unwrap())
            .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/expected.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (cases, expected)
}

/// 種類ごとの例を回して、基準と比べる。違いは全部まとめて出す。
async fn compare(kind: &str) {
    let (cases, expected) = fixtures();
    let cases = cases[kind].as_array().unwrap();
    let expected: Vec<&Value> = expected.iter().filter(|line| line[0] == kind).collect();
    assert_eq!(cases.len(), expected.len(), "{kind}: 基準と例の数が違う");
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(expected) {
        assert_eq!(case["id"], want[1], "{kind}: 例の並びが基準と違う");
        let got = match kind {
            "talk" => talk(case).await,
            "split" => split(case),
            _ => flow(case).await,
        };
        if got != want[2] {
            wrong.push(format!("{}\n  py {}\n  rs {got}", case["id"], want[2]));
        }
    }
    assert!(
        wrong.is_empty(),
        "{kind}: {} 例が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Groq に渡す最初の文（役どころの決まり・口調の念押し・現在の日時）が、Python と 1 文字も違わないこと。
#[test]
fn the_system_message_matches_python() {
    let (_, expected) = fixtures();
    let line = expected
        .iter()
        .find(|line| line[0] == "system")
        .expect("基準に最初の文が無い");
    assert_eq!(line[2], chat::system_content(now()));
}

#[tokio::test]
async fn conversations_match_python() {
    compare("talk").await;
}

#[tokio::test]
async fn long_messages_are_split_like_python() {
    compare("split").await;
}

#[tokio::test]
async fn the_flow_in_the_response_channel_matches_python() {
    compare("flow").await;
}

const GUILD: &str = "1399617700363370556";
const USER: &str = "80351110224678912";
const CHANNEL: &str = "1505310388051251000";
const LOG_CHANNEL: &str = "1505310388051251261";

/// 偽物の Discord の答え方: 入力中の表示は 204、メッセージの送信にはメッセージを返す。
fn respond(method: &str, path: &str) -> (u16, String) {
    match method {
        "POST" if path.ends_with("/typing") => (204, String::new()),
        "POST" if path.ends_with("/messages") => (200, support::sent_message(CHANNEL)),
        _ => (404, r#"{"message": "unknown", "code": 0}"#.into()),
    }
}

/// 応答チャンネルへの送信だけ断る（権限が無い）。
fn respond_without_send_permission(method: &str, path: &str) -> (u16, String) {
    if method == "POST" && path.ends_with(&format!("/channels/{CHANNEL}/messages")) {
        return (
            403,
            r#"{"message": "Missing Permissions", "code": 50013}"#.into(),
        );
    }
    respond(method, path)
}

/// 入力中の表示だけ断る。
fn respond_without_typing(method: &str, path: &str) -> (u16, String) {
    if method == "POST" && path.ends_with("/typing") {
        return (
            403,
            r#"{"message": "Missing Permissions", "code": 50013}"#.into(),
        );
    }
    respond(method, path)
}

/// 応答チャンネルに「やあ」と書かれたときに、偽物の Discord が受けた要求を返す。Groq の答えは `answer`。
async fn post_in_the_response_channel(
    log_level: &str,
    answer: Value,
    respond: support::Responder,
) -> Vec<Seen> {
    let (discord, seen) = support::start_fake_discord(respond).await;
    let (groq, stage) = start_fake_groq().await;
    set_script(&stage, &json!([answer]));
    let chats = chats_for(&groq, true);
    let http = support::http_to(&discord);
    let cache = support::cache_with(support::guild(
        GUILD,
        "1",
        json!([support::role(GUILD, 0, 0)]),
        json!([]),
        json!([
            support::text_channel(GUILD, CHANNEL, "chat"),
            support::text_channel(GUILD, LOG_CHANNEL, "log"),
        ]),
        json!([]),
    ));
    let guild_settings = json!({
        // 応答チャンネルは数、ログチャンネルは文字列で入っていても読む。
        "response_channel_id": CHANNEL.parse::<u64>().unwrap(),
        "log_channel_id": LOG_CHANNEL,
        "log_level": log_level,
    });
    let pool = support::settings_pool(GUILD, &guild_settings).await;
    let settings = SettingsCache::start(pool, Duration::from_secs(60))
        .await
        .unwrap();
    let colours = AvatarColours::new();
    let guild_id: u64 = GUILD.parse().unwrap();
    let channel_id: u64 = CHANNEL.parse().unwrap();
    let user_id: u64 = USER.parse().unwrap();
    let outlet = DiscordOutlet {
        sink: LogSink {
            cache: &cache,
            http: &http,
            settings: &settings,
            colours: &colours,
        },
        guild_id: GuildId::new(guild_id),
        channel_id: ChannelId::new(channel_id),
        author: Author {
            id: user_id,
            name: "nelly".into(),
            // 代表色を取りに外へ出ないよう、アバターも偽物に向ける（404 が返り、色はレベルの色になる）。
            avatar_url: format!("{discord}/avatar.png"),
        },
    };
    let incoming = Incoming {
        guild_id,
        channel_id,
        user_id,
        content: "やあ",
        from_self: false,
    };
    let snapshot = settings.snapshot();
    chat::handle(
        &chats,
        snapshot.guild(guild_id),
        &incoming,
        &outlet,
        0.0,
        now(),
    )
    .await;
    // アバターの取得（GET）は、ここで見たいものではない。
    let seen = seen.lock().unwrap();
    seen.iter()
        .filter(|s| s.method == "POST")
        .cloned()
        .collect()
}

/// 2 通に分かれる長さの答え。
fn long_answer() -> Value {
    json!({"content_parts": [["あ", 1500], ["\n", 1], ["い", 1500]]})
}

/// 入力中の表示 → 返事（切った順に）→ ログ、の順に送ること。返事は本文だけ（返信の形にも、メンションの
/// 絞り込みにもしない。Python の `channel.send(chunk)` と同じ）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_answer_goes_out_as_typing_then_messages_then_a_debug_log() {
    let seen = post_in_the_response_channel("DEBUG", long_answer(), respond).await;
    let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            format!("/api/v10/channels/{CHANNEL}/typing"),
            format!("/api/v10/channels/{CHANNEL}/messages"),
            format!("/api/v10/channels/{CHANNEL}/messages"),
            format!("/api/v10/channels/{LOG_CHANNEL}/messages"),
        ]
    );
    assert_eq!(seen[1].body["content"], "あ".repeat(1500));
    assert_eq!(seen[2].body["content"], "い".repeat(1500));
    for sent in &seen[1..3] {
        assert!(
            sent.body.get("message_reference").is_none(),
            "{}",
            sent.body
        );
        assert!(sent.body.get("allowed_mentions").is_none(), "{}", sent.body);
    }
    let embed = &seen[3].body["embeds"][0];
    assert_eq!(embed["title"], "[DEBUG] ボットログ");
    assert_eq!(embed["description"], "ChatGPT出力");
    assert_eq!(embed["author"]["name"], "nelly");
    let fields: Vec<(&str, &str)> = embed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap(), f["value"].as_str().unwrap()))
        .collect();
    assert_eq!(fields[0], ("チャンネル", format!("<#{CHANNEL}>").as_str()));
    assert_eq!(fields[1], ("入力", "やあ"));
    assert_eq!(fields[2].0, "出力プレビュー");
    assert_eq!(fields[2].1.chars().count(), 1024);
}

/// ログは DEBUG のサーバーだけに残すこと（既定の INFO では残さない）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_log_is_left_only_at_debug() {
    let seen = post_in_the_response_channel("INFO", json!({"content": "ふむ。"}), respond).await;
    let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            format!("/api/v10/channels/{CHANNEL}/typing"),
            format!("/api/v10/channels/{CHANNEL}/messages"),
        ]
    );
    assert_eq!(seen[1].body["content"], "ふむ。");
}

/// 返事を送れなかったら、続きも送らず、ログも残さないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_failed_send_stops_there() {
    let seen =
        post_in_the_response_channel("DEBUG", long_answer(), respond_without_send_permission).await;
    let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            format!("/api/v10/channels/{CHANNEL}/typing"),
            format!("/api/v10/channels/{CHANNEL}/messages"),
        ]
    );
}

/// 入力中の表示を出せなくても、返事は送ること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_failed_typing_indicator_does_not_stop_the_answer() {
    let seen =
        post_in_the_response_channel("INFO", json!({"content": "ふむ。"}), respond_without_typing)
            .await;
    assert_eq!(seen.len(), 2, "{seen:#?}");
    assert_eq!(
        seen[1].path,
        format!("/api/v10/channels/{CHANNEL}/messages")
    );
    assert_eq!(seen[1].body["content"], "ふむ。");
}
