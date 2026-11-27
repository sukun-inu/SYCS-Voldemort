//! ニュースの巡回の流れが、本物の Python と同じものを同じ順に送り、同じ設定を書き戻すこと。
//!
//! 基準（`fixtures/news/flow_expected.jsonl`）は、本物の Python の `run_news_feeds` を、偽物の配信元と偽物の
//! Groq に当てた結果（`generate.py flow`）。Discord への送信と設定の書き戻しは、記録するだけの偽物に
//! 差し替えてある。比べるのは、送った Embed・書き戻した設定・配信元に届いた行き先・Groq に届いた問い。
//!
//! 偽物の配信元と Groq は、このテストの中に立てる（決め方は Python の確かめに使った偽物と同じ）。
//! `NEWS_FAKE_RSS`・`NEWS_FAKE_GROQ` を設定すると、テストの中の偽物の代わりに外の偽物（Python の確かめに
//! 使ったものそのもの）に当てる。
//!
//! 壊れた設定は、Python では例外で巡回ごと止まる。こちらはそのフィードだけ飛ばすので、結果は「壊れた
//! フィードが無いとき」の Python の結果と同じになる（例の `rust_like`）。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use serenity::all::CreateEmbed;
use sycs_bot::groq::{Groq, GroqConfig};
use sycs_bot::news::{self, NaiveZone, News, NewsConfig, Outlet};
use sycs_core::settings::Settings;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NOW: f64 = 1_795_565_100.25;

fn fixtures() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/news")
}

/// 偽物が受けた要求。
#[derive(Default)]
struct Seen {
    /// 配信元に届いた行き先と名乗り。
    rss: Vec<(String, String)>,
    /// Groq に届いた鍵と本文。
    groq: Vec<(String, Value)>,
}

type Shared = Arc<Mutex<Seen>>;
/// 受けた要求のまとめ: (行き先, 名乗り, Groq の本文, Groq の鍵)。
type Log = (Vec<String>, Vec<String>, Vec<Value>, Vec<String>);
/// 配信元に届いたもの（行き先, 名乗り）と、Groq に届いたもの（鍵, 本文）。
type Raw = (Vec<(String, String)>, Vec<(String, Value)>);

fn http(status: u16, ctype: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Groq の答え。利用者の文に入っている印で決める（Python の偽物 fake_b8.py の groq_answer と同じ）。
fn groq_answer(user: &str) -> Vec<u8> {
    let ok = |content: Value| {
        let body = json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": content}}]});
        http(200, "application/json", &[], body.to_string().as_bytes())
    };
    let err = br#"{"error": {"message": "fake"}}"#;
    if user.contains("G-500") {
        let headers = [("x-should-retry", "false".to_string())];
        return http(500, "application/json", &headers, err);
    }
    if user.contains("G-400") {
        return http(400, "application/json", &[], err);
    }
    if user.contains("G-NULL") {
        return ok(Value::Null);
    }
    if user.contains("G-EMPTY") {
        return ok(json!(""));
    }
    if user.contains("G-NUM") {
        return ok(json!(123));
    }
    if user.contains("G-NOCHOICE") {
        return http(200, "application/json", &[], br#"{"choices": []}"#);
    }
    if user.contains("G-LONG") {
        return ok(json!("長い要約です。".repeat(80)));
    }
    if user.contains("G-PREFIX") {
        return ok(json!(
            "  要約：  一行目です。  \t 続き。\n\n\n\n二段落目です。  "
        ));
    }
    let title = user.split('\n').next().unwrap_or("");
    ok(json!(format!("「{title}」を短くまとめました。")))
}

/// 行き先の `q=` を読む（`+` は空白、`%XX` は戻す。Python の parse_qs と同じ）。
fn query_of(target: &str) -> String {
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let raw = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("q="))
        .unwrap_or("")
        .replace('+', " ");
    percent_encoding::percent_decode_str(&raw)
        .decode_utf8_lossy()
        .into_owned()
}

/// 配信元の答え。`None` は「何も返さずに切る」（Python の偽物 fake_b8.py と同じ決め方）。
async fn rss_answer(target: &str) -> Option<Vec<u8>> {
    let q = query_of(target);
    let (kind, name) = q.split_once(':').unwrap_or((q.as_str(), ""));
    match kind {
        "status" => Some(http(
            name.parse().unwrap_or(500),
            "text/plain",
            &[],
            b"nope",
        )),
        // 状態は 200 以外で、中身は正しい RSS（状態を見ずに読んでしまう作りを見分ける）。
        "errfeed" => {
            let body = std::fs::read(format!("{}/rss/basic.xml", fixtures())).unwrap_or_default();
            Some(http(
                name.parse().unwrap_or(500),
                "application/xml",
                &[],
                &body,
            ))
        }
        "redirect" => {
            let to = format!("/rss/search?q=feed:{name}&hl=ja&gl=JP&ceid=JP:ja");
            Some(http(302, "text/plain", &[("Location", to)], b""))
        }
        "close" => None,
        // 答えない（時間切れを確かめる。Python の偽物には無い）。
        "hang" => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            None
        }
        _ => {
            let name = if kind == "feed" { name } else { "basic" };
            match std::fs::read(format!("{}/rss/{name}.xml", fixtures())) {
                Ok(body) => Some(http(200, "application/xml", &[], &body)),
                Err(_) => Some(http(404, "text/plain", &[], b"no such feed")),
            }
        }
    }
}

async fn start_fake() -> (String, Shared) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Shared = Arc::default();
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&shared);
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
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let mut first = head.lines().next().unwrap_or("").split(' ');
                let (method, target) = (
                    first.next().unwrap_or("").to_string(),
                    first.next().unwrap_or("").to_string(),
                );
                let length: usize = header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + length {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let answer = if method == "GET" && target.starts_with("/rss/search") {
                    let ua = header("user-agent").unwrap_or_default();
                    seen.lock().unwrap().rss.push((target.clone(), ua));
                    rss_answer(&target).await
                } else if method == "POST" && target == "/openai/v1/chat/completions" {
                    let body: Value =
                        serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                    let user = body["messages"][1]["content"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let auth = header("authorization").unwrap_or_default();
                    seen.lock().unwrap().groq.push((auth, body));
                    Some(groq_answer(&user))
                } else {
                    Some(http(404, "text/plain", &[], b"unknown"))
                };
                if let Some(bytes) = answer {
                    let _ = sock.write_all(&bytes).await;
                }
            });
        }
    });
    (base, seen)
}

/// 偽物（テストの中のものか、外に立てたもの）。
enum Fakes {
    Inside { base: String, seen: Shared },
    Outside { rss: String, groq: String },
}

impl Fakes {
    async fn start() -> Self {
        match (
            std::env::var("NEWS_FAKE_RSS"),
            std::env::var("NEWS_FAKE_GROQ"),
        ) {
            (Ok(rss), Ok(groq)) if !rss.is_empty() && !groq.is_empty() => {
                Self::Outside { rss, groq }
            }
            _ => {
                let (base, seen) = start_fake().await;
                Self::Inside { base, seen }
            }
        }
    }

    fn rss_base(&self) -> &str {
        match self {
            Self::Inside { base, .. } => base,
            Self::Outside { rss, .. } => rss,
        }
    }

    fn groq_base(&self) -> &str {
        match self {
            Self::Inside { base, .. } => base,
            Self::Outside { groq, .. } => groq,
        }
    }

    async fn reset(&self) {
        match self {
            Self::Inside { seen, .. } => *seen.lock().unwrap() = Seen::default(),
            Self::Outside { rss, .. } => {
                let client = reqwest::Client::new();
                client
                    .post(format!("{rss}/_reset"))
                    .body("")
                    .send()
                    .await
                    .unwrap();
            }
        }
    }

    /// 受けた要求を、Python の基準と同じ形で返す: (行き先, 名乗り, Groq の本文, Groq の鍵)。
    async fn log(&self) -> Log {
        let (rss, groq): Raw = match self {
            Self::Inside { seen, .. } => {
                let s = seen.lock().unwrap();
                (s.rss.clone(), s.groq.clone())
            }
            Self::Outside { rss, .. } => {
                let bytes = reqwest::get(format!("{rss}/_log"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                let log: Value = serde_json::from_slice(&bytes).unwrap();
                let text = |v: &Value| v.as_str().unwrap_or("").to_string();
                (
                    log["rss"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| (text(&r["target"]), text(&r["ua"])))
                        .collect(),
                    log["groq"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|g| (text(&g["auth"]), g["body"].clone()))
                        .collect(),
                )
            }
        };
        let sorted = |items: Vec<String>| {
            let mut unique: Vec<String> = items
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            unique.sort();
            unique
        };
        (
            // `'` は Python が生で、こちらが %27 で送る（意味は同じ）。比べるときはそろえる。
            rss.iter().map(|(t, _)| t.replace("%27", "'")).collect(),
            sorted(rss.iter().map(|(_, ua)| ua.clone()).collect()),
            groq.iter().map(|(_, body)| body.clone()).collect(),
            sorted(groq.iter().map(|(auth, _)| auth.clone()).collect()),
        )
    }
}

/// Python の `embed.to_dict()`（種類と flags を除いたもの）と同じ形。
fn embed_json(embed: &CreateEmbed) -> Value {
    let mut v = serde_json::to_value(embed).unwrap();
    drop_nulls(&mut v);
    let map = v.as_object_mut().unwrap();
    map.remove("type");
    if map
        .get("fields")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        map.remove("fields");
    }
    v
}

/// null の項目を落とす（serenity は、サムネイルの幅や高さなどを null で書き出す。Discord は無視する）。
fn drop_nulls(value: &mut Value) {
    if let Some(map) = value.as_object_mut() {
        map.retain(|_, v| !v.is_null());
        map.values_mut().for_each(drop_nulls);
    }
}

/// 記録するだけの出口。
struct Recorder {
    text_channels: HashMap<u64, HashSet<u64>>,
    send_fails: HashSet<u64>,
    state: Mutex<Settings>,
    sends: Mutex<Vec<Value>>,
    writes: Mutex<Vec<Value>>,
}

impl Outlet for Recorder {
    fn is_text_channel(&self, guild_id: u64, channel_id: u64) -> bool {
        self.text_channels
            .get(&guild_id)
            .is_some_and(|channels| channels.contains(&channel_id))
    }

    async fn send(&self, channel_id: u64, embed: CreateEmbed) -> Result<(), String> {
        self.sends
            .lock()
            .unwrap()
            .push(json!({"channel": channel_id, "embed": embed_json(&embed)}));
        if self.send_fails.contains(&channel_id) {
            Err("400 Bad Request".into())
        } else {
            Ok(())
        }
    }

    async fn save_state(&self, guild_id: u64, feed_id: &str, last_run: f64, seen: &[Value]) {
        let mut state = self.state.lock().unwrap();
        let before = state.clone();
        news::apply_feed_state(&mut state, guild_id, feed_id, last_run, seen);
        let row = state
            .guild(guild_id)
            .and_then(|g| g.get("news_feeds"))
            .and_then(Value::as_object)
            .and_then(|feeds| feeds.get(feed_id))
            .cloned()
            .unwrap_or(Value::Null);
        self.writes.lock().unwrap().push(json!({
            "guild": guild_id,
            "feed": feed_id,
            "changed": *state != before,
            "row": row,
        }));
    }
}

fn settings(guilds: &Value) -> Settings {
    Settings {
        version: 1,
        root: Default::default(),
        guilds: guilds
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn channels(case: &Value, key: &str) -> HashMap<u64, HashSet<u64>> {
    case[key]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(guild, ids)| {
            let ids = ids
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_u64)
                .collect();
            (guild.parse().unwrap(), ids)
        })
        .collect()
}

fn recorder(case: &Value) -> Recorder {
    Recorder {
        text_channels: channels(case, "text_channels"),
        send_fails: case["send_fails"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .collect(),
        state: Mutex::new(settings(&case["guilds"])),
        sends: Mutex::default(),
        writes: Mutex::default(),
    }
}

fn news_for(fakes: &Fakes, key: Option<&str>, fetch_timeout: Duration) -> News {
    let groq = Groq::new(GroqConfig {
        api_key: key.map(str::to_string),
        base_url: fakes.groq_base().into(),
        max_concurrent: 3,
        min_interval: 0.0,
        max_retries: 2,
        retry_base_delay: 2.0,
        retry_max_delay: 20.0,
    });
    let config = NewsConfig {
        summary_model: news::DEFAULT_SUMMARY_MODEL.into(),
        rss_base: fakes.rss_base().into(),
        fetch_timeout,
        naive_zone: NaiveZone::Utc,
    };
    News::new(config, Arc::new(groq))
}

/// 1 つの例を回して、Python の基準と同じ形にまとめる。
async fn run(fakes: &Fakes, case: &Value) -> Value {
    fakes.reset().await;
    let key = (!case["no_key"].as_bool().unwrap_or(false)).then_some("test-key");
    // 要約の覚えは、例ごとに空から始める（Python の基準も例ごとに作り直している）。
    let news = news_for(fakes, key, news::FETCH_TIMEOUT);
    let outlet = recorder(case);
    let snapshot = || Arc::new(outlet.state.lock().unwrap().clone());
    news::run_news_feeds(&news, &outlet, snapshot, |_| true, NOW).await;
    let (rss, ua, groq, groq_auth) = fakes.log().await;
    json!({
        "sends": *outlet.sends.lock().unwrap(),
        "writes": *outlet.writes.lock().unwrap(),
        "rss": rss,
        "ua": ua,
        "groq": groq,
        "groq_auth": groq_auth,
    })
}

/// 全部の例で、送るもの・書き戻すもの・配信元と Groq に届くものが Python と同じであること。
#[tokio::test(flavor = "multi_thread")]
async fn the_rounds_agree_with_python() {
    let read = |name: &str| std::fs::read_to_string(format!("{}/{name}", fixtures())).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&read("flow_cases.json")).unwrap();
    let expected: HashMap<String, Value> = read("flow_expected.jsonl")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .map(|v| (v["id"].as_str().unwrap().to_string(), v))
        .collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let fakes = Fakes::start().await;
    let mut wrong = Vec::new();
    let mut pinned = 0;
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let python = &expected[id];
        // 壊れた設定: Python は例外で巡回ごと止まる。こちらは、壊れたフィードが無いときの Python と同じ。
        let like = match case["rust_like"].as_str() {
            Some(other) => {
                pinned += 1;
                assert!(
                    !python["aborted"].is_null(),
                    "{id}: Python が止まらなくなった（違えてあるところを見直す）"
                );
                &expected[other]
            }
            None => {
                assert!(python["aborted"].is_null(), "{id}: Python が止まった");
                python
            }
        };
        let got = run(&fakes, case).await;
        for key in ["sends", "writes", "rss", "ua", "groq", "groq_auth"] {
            let (mut rs, mut py) = (got[key].clone(), like[key].clone());
            // 読めない文字コードの例は、壊れたフィードも取りには行く（中身が空になるだけ）。行き先と書き戻しは、
            // 最後の 1 つ（良いフィードのぶん）だけを比べる。
            if case["rust_like_tail"].as_bool().unwrap_or(false) && matches!(key, "rss" | "writes")
            {
                let last = |v: &Value| v.as_array().and_then(|a| a.last()).cloned();
                (rs, py) = (json!(last(&rs)), json!(last(&py)));
            }
            if rs != py {
                wrong.push(format!("{id} の {key}\n  py {py}\n  rs {rs}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 件が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(pinned >= 8, "壊れた設定の例が減っている: {pinned}");
}

fn one_feed(query: &str) -> Value {
    json!({
        "guilds": {"1": {"news_feeds": {"f1": {"channel_id": 10, "query": query, "interval": 30}}}},
        "text_channels": {"1": [10]},
    })
}

/// `BOT_ONLY_GUILD_ID` で外したギルドは、取りにも行かず書き戻しもしないこと。
#[tokio::test(flavor = "multi_thread")]
async fn guilds_that_are_not_handled_are_left_alone() {
    let (base, seen) = start_fake().await;
    let fakes = Fakes::Inside { base, seen };
    let news = news_for(&fakes, Some("test-key"), news::FETCH_TIMEOUT);
    let outlet = recorder(&one_feed("feed:basic"));
    let snapshot = || Arc::new(outlet.state.lock().unwrap().clone());
    news::run_news_feeds(&news, &outlet, snapshot, |guild| guild != 1, NOW).await;
    let (rss, _, groq, _) = fakes.log().await;
    assert!(
        rss.is_empty() && groq.is_empty(),
        "外したギルドの RSS を取りに行った"
    );
    assert!(outlet.sends.lock().unwrap().is_empty());
    assert!(outlet.writes.lock().unwrap().is_empty());
    // 外していなければ送る。
    news::run_news_feeds(&news, &outlet, snapshot, |guild| guild == 1, NOW).await;
    assert_eq!(outlet.sends.lock().unwrap().len(), 3);
}

/// 配信元が答えなければ時間切れで諦め、送らずに時刻だけ書き戻すこと（送り直しはしない）。
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_source_times_out() {
    let (base, seen) = start_fake().await;
    let fakes = Fakes::Inside { base, seen };
    let news = news_for(&fakes, Some("test-key"), Duration::from_millis(1500));
    let outlet = recorder(&one_feed("hang"));
    let snapshot = || Arc::new(outlet.state.lock().unwrap().clone());
    let started = Instant::now();
    news::run_news_feeds(&news, &outlet, snapshot, |_| true, NOW).await;
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "待たずに諦めた"
    );
    let (rss, _, _, _) = fakes.log().await;
    assert_eq!(rss.len(), 1, "時間切れのあとで送り直した");
    assert!(outlet.sends.lock().unwrap().is_empty());
    let writes = outlet.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0]["row"]["last_run"], NOW);
}

/// 要約は覚えておき、同じ記事を次の巡回で送り直すときは Groq に尋ねないこと。
#[tokio::test(flavor = "multi_thread")]
async fn summaries_are_remembered_between_rounds() {
    let (base, seen) = start_fake().await;
    let fakes = Fakes::Inside { base, seen };
    let news = news_for(&fakes, Some("test-key"), news::FETCH_TIMEOUT);
    // 送信が失敗するチャンネル: 記事は「送った」にならず、次の巡回でまた送ろうとする。
    let mut case = one_feed("feed:basic");
    case["send_fails"] = json!([10]);
    let outlet = recorder(&case);
    let snapshot = || Arc::new(outlet.state.lock().unwrap().clone());
    news::run_news_feeds(&news, &outlet, snapshot, |_| true, NOW).await;
    news::run_news_feeds(&news, &outlet, snapshot, |_| true, NOW + 1800.0).await;
    let (rss, _, groq, _) = fakes.log().await;
    assert_eq!(rss.len(), 2);
    assert_eq!(outlet.sends.lock().unwrap().len(), 6, "送り直していない");
    assert_eq!(groq.len(), 3, "覚えた要約を使わずに尋ね直した");
    // 2 回目は interval が経っているから走る。経っていなければ走らない。
    news::run_news_feeds(&news, &outlet, snapshot, |_| true, NOW + 1800.0 + 1799.0).await;
    assert_eq!(fakes.log().await.0.len(), 2, "interval の前に取りに行った");
}
