//! メッセージの検査の流れが、本物の Python と同じ順に同じものを書き込むこと。
//!
//! 基準（`fixtures/message_security/expected.jsonl`）は、本物の Python の `handle_security_for_message` を
//! 同じ偽物（Discord・VirusTotal・Groq を記録するだけ）に差し替えて回したもの（`generate.py`）。
//! Discord への書き込み（送る・書き換える・消す・タイムアウト・剥がす・ログ）と Groq に渡したものを、順に比べる。
//! 例の書き方（前の投稿・VC への参加・権限・失敗のさせ方）は `generate.py` の先頭の説明のとおり。
//!
//! 走査が落ちたときの理由の名前だけは言語で違う（Python は例外の型、Rust は panic）ので、比べる前に
//! そろえる。

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::DateTime;
use regex::Regex;
use serde_json::{Value, json};
use serenity::all::{ChannelId, CreateEmbed, GuildId, MessageId, RoleId, UserId};
use sycs_bot::log_channel::{Author, Level};
use sycs_bot::message_security::{
    self, Assess, AssessRequest, Context, DeleteFailure, Effects, Judges, LogMessage, Post, Scan,
};
use sycs_bot::moderation::Verdict;
use sycs_bot::security::{RaidDetector, SecurityConfig, SpamDetector, SpamInput, StripFailure};
use sycs_bot::virustotal::VtResult;

const GUILD: u64 = 1_399_617_700_363_370_556;
const USER: u64 = 80_351_110_224_678_912;
const CHANNEL: u64 = 1_505_310_388_051_251_261;
/// 検査するメッセージ（Python の基準の `MESSAGE`）。前の投稿は 100 から順に振る。
const MESSAGE: u64 = 2;
const NOW: f64 = 1_795_565_100.25;
const DISCORD_EPOCH_MS: i64 = 1_420_070_400_000;

fn clock() -> f64 {
    NOW
}

type Calls = Arc<Mutex<Vec<Value>>>;

/// Python の `embed.to_dict()` から取り出すものと同じ形。
fn embed_json(embed: &CreateEmbed) -> Value {
    let v = serde_json::to_value(embed).unwrap();
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
        "fields": fields,
        "footer": v["footer"]["text"],
    })
}

struct Fake {
    calls: Calls,
    log_channel: bool,
    edit_fail_at: HashSet<usize>,
    edits: AtomicUsize,
    /// この ID の投稿を消すと、ほかの失敗にする。
    delete_fail: HashSet<u64>,
    /// この ID の投稿は、既に消えていたことにする。
    delete_gone: HashSet<u64>,
    /// タイムアウトの断り方（`forbidden`・`error`）。
    timeout_fail: Option<String>,
    /// このロールで権限不足にする。
    strip_fail_at: Option<u64>,
    /// このロールでほかの失敗にする。
    strip_error_at: Option<u64>,
}

impl Fake {
    /// 例から作る（消す・タイムアウト・剥がすの失敗のさせ方）。
    fn new(case: &Value, calls: &Calls) -> Self {
        let ids = |key: &str| -> HashSet<u64> {
            let listed = case[key].as_array().into_iter().flatten();
            listed.filter_map(Value::as_u64).collect()
        };
        let mut delete_fail = ids("delete_fail_ids");
        let mut delete_gone = ids("delete_gone_ids");
        if case["delete_fails"].as_bool().unwrap_or(false) {
            delete_fail.insert(MESSAGE);
        }
        if case["delete_gone"].as_bool().unwrap_or(false) {
            delete_gone.insert(MESSAGE);
        }
        Self {
            calls: Arc::clone(calls),
            log_channel: case["log_channel"].as_bool().unwrap_or(true),
            edit_fail_at: case["edit_fail_at"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|n| n.as_u64().unwrap() as usize)
                .collect(),
            edits: AtomicUsize::new(0),
            delete_fail,
            delete_gone,
            timeout_fail: case["timeout_fail"].as_str().map(str::to_string),
            strip_fail_at: case["strip_fail_at"].as_u64(),
            strip_error_at: case["strip_error_at"].as_u64(),
        }
    }
}

impl Effects for Fake {
    async fn send_log_embed(&self, level: Level, embed: CreateEmbed) -> Option<LogMessage> {
        self.calls
            .lock()
            .unwrap()
            .push(json!(["send", level.name(), embed_json(&embed)]));
        self.log_channel
            .then(|| (ChannelId::new(1), MessageId::new(1)))
    }

    async fn edit_log_embed(&self, _message: LogMessage, embed: CreateEmbed) -> Result<(), String> {
        let n = self.edits.fetch_add(1, Ordering::SeqCst) + 1;
        self.calls
            .lock()
            .unwrap()
            .push(json!(["edit", embed_json(&embed)]));
        if self.edit_fail_at.contains(&n) {
            Err("404 Unknown Message".into())
        } else {
            Ok(())
        }
    }

    async fn delete_message(
        &self,
        channel: ChannelId,
        message: MessageId,
    ) -> Result<(), DeleteFailure> {
        let record = json!(["delete", channel.get(), message.get()]);
        self.calls.lock().unwrap().push(record);
        // Python の基準と同じ順に見る（ほかの失敗が先）。
        if self.delete_fail.contains(&message.get()) {
            return Err(DeleteFailure::Failed("404 Unknown Message".into()));
        }
        if self.delete_gone.contains(&message.get()) {
            return Err(DeleteFailure::Gone);
        }
        Ok(())
    }

    async fn timeout(&self, seconds: i64) -> Result<(), StripFailure> {
        let record = json!(["timeout", seconds, "セキュリティ違反"]);
        self.calls.lock().unwrap().push(record);
        match self.timeout_fail.as_deref() {
            Some("forbidden") => Err(StripFailure::Forbidden),
            Some(_) => Err(StripFailure::Failed("404 Unknown Member".into())),
            None => Ok(()),
        }
    }

    async fn remove_role(&self, role: RoleId) -> Result<(), StripFailure> {
        // Python の基準も 1 つずつ記録する（discord.py の remove_roles を 1 つずつ呼ぶ）。
        self.calls
            .lock()
            .unwrap()
            .push(json!(["strip", [role.get()], "セキュリティ違反"]));
        if self.strip_fail_at == Some(role.get()) {
            return Err(StripFailure::Forbidden);
        }
        if self.strip_error_at == Some(role.get()) {
            return Err(StripFailure::Failed("404 Unknown Role".into()));
        }
        Ok(())
    }

    async fn log_action(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
        colour: Option<u32>,
    ) {
        let fields: Vec<Value> = fields.iter().map(|(k, v)| json!([k, v])).collect();
        self.calls
            .lock()
            .unwrap()
            .push(json!(["log", level.name(), message, fields, colour]));
    }
}

fn vt_result(v: &Value) -> VtResult {
    VtResult {
        status: v["status"].as_str().unwrap().into(),
        kind: v["type"].as_str().unwrap().into(),
        malicious: v["malicious"].as_i64().unwrap(),
        suspicious: v["suspicious"].as_i64().unwrap(),
        reason: v["reason"].as_str().map(str::to_string),
    }
}

fn judges(case: &Value, calls: &Calls, scanned: &Arc<Mutex<Vec<String>>>) -> Judges {
    let vt = case["vt"].clone();
    let seen = Arc::clone(scanned);
    let scan: Scan = Arc::new(move |url: String| {
        let r = vt[&url].clone();
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.lock().unwrap().push(url);
            if r == "raise" {
                panic!("走査の中で予期しない失敗（テスト）");
            }
            if r.is_null() {
                VtResult {
                    status: "ok".into(),
                    kind: "url".into(),
                    malicious: 0,
                    suspicious: 0,
                    reason: None,
                }
            } else {
                vt_result(&r)
            }
        })
    });
    let verdict = match case["gpt"].as_str().unwrap_or("SAFE") {
        "DANGEROUS" => Verdict::Dangerous,
        "SUSPICIOUS" => Verdict::Suspicious,
        "UNKNOWN" => Verdict::Unknown,
        _ => Verdict::Safe,
    };
    let log = Arc::clone(calls);
    let assess: Assess = Arc::new(move |r: AssessRequest| {
        let vt: Vec<Value> = r
            .vt_results
            .iter()
            .map(|v| json!([v.malicious, v.suspicious]))
            .collect();
        let interval = if r.spam.min_interval.is_infinite() {
            json!("inf")
        } else {
            json!(r.spam.min_interval)
        };
        let s = &r.spam;
        let spam = json!([
            s.repeat,
            s.repeat_count,
            s.repeat_channels,
            s.flood,
            s.flood_count
        ]);
        log.lock().unwrap().push(json!([
            "assess",
            r.text,
            vt,
            spam,
            interval,
            r.is_new_member,
            r.new_account_days.is_some()
        ]));
        Box::pin(async move { verdict })
    });
    Judges {
        scan,
        assess,
        scan_concurrency: message_security::DEFAULT_SCAN_CONCURRENCY,
    }
}

/// 発言した人の ID。`account_days_ago` があれば、その日時に作ったアカウントの ID（Python の基準の `member_id`）。
fn member_id(case: &Value) -> u64 {
    let Some(days) = case["account_days_ago"].as_f64() else {
        return USER;
    };
    let ms = ((NOW - days * 86_400.0) * 1000.0) as i64;
    u64::try_from(ms - DISCORD_EPOCH_MS).unwrap() << 22
}

/// 添付 1 つ（URL・ファイル名・大きさ）。URL だけなら、ファイル名は URL の最後、大きさは 0（Python の基準と同じ）。
fn attachment(entry: &Value) -> (String, String, u64) {
    if let Some(url) = entry.as_str() {
        let name = url.rsplit('/').next().unwrap_or("").to_string();
        return (url.to_string(), name, 0);
    }
    let url = entry[0].as_str().unwrap().to_string();
    let name = entry[1].as_str().unwrap().to_string();
    (url, name, entry[2].as_u64().unwrap())
}

fn attachments(list: &Value) -> Vec<(String, String, u64)> {
    list.as_array()
        .map(|a| a.iter().map(attachment).collect())
        .unwrap_or_default()
}

fn post(case: &Value) -> Post {
    let joined_at = match &case["joined_days_ago"] {
        Value::Null if case.get("joined_days_ago").is_some() => None,
        v => {
            let days = v.as_f64().unwrap_or(400.0);
            let at = NOW - days * 86_400.0;
            DateTime::from_timestamp(at.floor() as i64, ((at - at.floor()) * 1e9) as u32)
        }
    };
    let files = attachments(&case["attachments"]);
    Post {
        guild_id: GuildId::new(GUILD),
        channel_id: ChannelId::new(case["channel"].as_u64().unwrap_or(CHANNEL)),
        message_id: MessageId::new(MESSAGE),
        user_id: UserId::new(member_id(case)),
        content: case["content"].as_str().unwrap_or("").into(),
        attachments: files.iter().map(|(url, _, _)| url.clone()).collect(),
        attachment_files: files.into_iter().map(|(_, n, s)| (n, s)).collect(),
        roles: case["roles"]
            .as_array()
            .map(|a| a.iter().map(|r| RoleId::new(r.as_u64().unwrap())).collect())
            .unwrap_or_default(),
        joined_at,
        voice_channel: case["voice"].as_u64(),
        display_name: case["name"].as_str().unwrap_or("nelly").into(),
        is_admin: case["admin"].as_bool().unwrap_or(false),
        bot_can_timeout: case["can_timeout"].as_bool().unwrap_or(true),
        author: Author {
            id: USER,
            name: "nelly".into(),
            avatar_url: String::new(),
        },
    }
}

/// 前の投稿を、スパムの記録に入れる（Python の基準の `record_prior`）。数なら秒（この投稿と同じ本文・添付・
/// チャンネル）、`{"dt", "content", "channel", "attachments"}` なら中身を変えられる。ID は 100 から順に振る。
fn record_prior_posts(case: &Value, spam: &SpamDetector) {
    let empty = Vec::new();
    let priors = case["prior_posts"].as_array().unwrap_or(&empty);
    for (i, entry) in priors.iter().enumerate() {
        let (dt, prior) = match entry.as_f64() {
            Some(dt) => (dt, &Value::Null),
            None => (entry["dt"].as_f64().unwrap(), entry),
        };
        let pick = |key: &str| {
            if prior.get(key).is_some() {
                prior[key].clone()
            } else {
                case[key].clone()
            }
        };
        let content = pick("content").as_str().unwrap_or("").to_string();
        let files: Vec<(String, u64)> = attachments(&pick("attachments"))
            .into_iter()
            .map(|(_, name, size)| (name, size))
            .collect();
        let input = SpamInput {
            guild_id: GUILD,
            user_id: member_id(case),
            channel_id: pick("channel").as_u64().unwrap_or(CHANNEL),
            message_id: 100 + i as u64,
            content: &content,
            attachments: &files,
        };
        spam.check(&input, NOW + dt);
    }
}

async fn run(case: &Value) -> Value {
    let calls: Calls = Arc::default();
    let scanned: Arc<Mutex<Vec<String>>> = Arc::default();
    let spam = SpamDetector::default();
    let raid = RaidDetector::default();
    record_prior_posts(case, &spam);
    let voice = case["voice"].as_u64().unwrap_or(0);
    for j in case["prior_joins"].as_array().into_iter().flatten() {
        let who = j[1].as_u64().unwrap_or_else(|| member_id(case));
        raid.check(voice, who, NOW + j[0].as_f64().unwrap());
    }
    let judges = judges(case, &calls, &scanned);
    let settings = case.get("settings").cloned().unwrap_or(json!({}));
    let config = SecurityConfig::default();
    let cx = Context {
        settings: Some(&settings),
        config: &config,
        spam: &spam,
        raid: &raid,
        judges: &judges,
        clock,
    };
    let fx = Fake::new(case, &calls);
    message_security::check_message(&fx, &cx, &post(case)).await;
    let mut scanned = scanned.lock().unwrap().clone();
    scanned.sort();
    let calls = calls.lock().unwrap().clone();
    json!([case["id"], calls, scanned])
}

#[tokio::test]
async fn the_check_writes_what_python_writes() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/message_security"
    );
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/cases.json")).unwrap())
            .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/expected.jsonl")).unwrap();
    let expected: Vec<&str> = expected.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let failed_scan = Regex::new(r"scan_failed:\w+").unwrap();
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(expected) {
        let got = run(case).await.to_string();
        let got = failed_scan.replace_all(&got, "scan_failed:*");
        let got: Value = serde_json::from_str(&got).unwrap();
        let want: Value = serde_json::from_str(want).unwrap();
        if got != want {
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

/// VirusTotal は同時に 4 本まで走らせ、終わる順がばらばらでも結果は渡した順に並べること。
#[tokio::test]
async fn scans_run_four_at_a_time_and_keep_their_order() {
    let urls: Vec<String> = (0..6).map(|i| format!("https://{i}.example")).collect();
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (now, top) = (Arc::clone(&inflight), Arc::clone(&peak));
    let scan: Scan = Arc::new(move |url: String| {
        let (now, top) = (Arc::clone(&now), Arc::clone(&top));
        Box::pin(async move {
            let n = now.fetch_add(1, Ordering::SeqCst) + 1;
            top.fetch_max(n, Ordering::SeqCst);
            // 先に渡したものほど遅く終わる。
            let i: u64 = url[8..9].parse().unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(40 * (6 - i))).await;
            now.fetch_sub(1, Ordering::SeqCst);
            VtResult {
                status: "ok".into(),
                kind: "url".into(),
                malicious: i as i64,
                suspicious: 0,
                reason: None,
            }
        })
    });
    let assess: Assess = Arc::new(|_| Box::pin(async { Verdict::Safe }));
    let judges = Judges {
        scan,
        assess,
        scan_concurrency: message_security::DEFAULT_SCAN_CONCURRENCY,
    };
    let (spam, raid) = (SpamDetector::default(), RaidDetector::default());
    let settings = json!({});
    let config = SecurityConfig::default();
    let cx = Context {
        settings: Some(&settings),
        config: &config,
        spam: &spam,
        raid: &raid,
        judges: &judges,
        clock,
    };
    let calls: Calls = Arc::default();
    let fx = Fake::new(&json!({}), &calls);
    let mut p = post(&json!({"content": urls.join(" ")}));
    p.content = urls.join(" ");
    message_security::check_message(&fx, &cx, &p).await;
    assert_eq!(
        peak.load(Ordering::SeqCst),
        4,
        "同時に走らせる数が 4 でない"
    );
    let calls = calls.lock().unwrap();
    // 進み具合は 1/6 から 6/6 まで順に進む。
    let bars: Vec<String> = calls
        .iter()
        .filter(|c| c[0] == "edit" && c[1]["title"] == "セキュリティ検査中")
        .map(|c| c[1]["description"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(bars.len(), 6);
    assert!(bars[5].ends_with("6/6"), "{bars:?}");
    // 結果の行は渡した順（0 から 5）。
    let last = calls.iter().rev().find(|c| c[0] == "edit").unwrap().clone();
    let description = last[1]["description"].as_str().unwrap();
    let order: Vec<&str> = description
        .lines()
        .filter(|l| l.contains("をスキャン"))
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    assert_eq!(order, urls.iter().map(String::as_str).collect::<Vec<_>>());
    let targets: Vec<Value> = last[1]["fields"].as_array().unwrap()[..6].to_vec();
    for (i, f) in targets.iter().enumerate() {
        assert!(
            f[1].as_str()
                .unwrap()
                .contains(&format!("Malicious: `{i}`")),
            "{i}: {f}"
        );
    }
}
