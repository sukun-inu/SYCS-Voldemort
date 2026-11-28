//! DJAudio の期限切れの掃除が、本物の Python と同じファイルを消し、同じ Discord のメッセージを取りに行って消すこと。
//!
//! 基準（`fixtures/djaudio/cleanup_expected.jsonl`）は、本物の `_cleanup_expired` を、置き場に例のファイルを置き、
//! 記録するだけの偽物の Bot で 1 回回したもの（`generate_cleanup.py`）。ここでは同じファイルを置き、serenity の
//! キャッシュに同じチャンネルを入れ、送り先をテストの中の偽物の Discord に向けて [`cleanup_expired`] を回す。
//! Discord にしたこと（メッセージを取りに行く GET・消す DELETE）と、残ったファイルを比べる。期限の読み方（無い・
//! 真偽・0）、ID の読み方（全角・空白・数・空・0・数でない）、チャンネルが無い・送れない種類、取りに行けない（404）・
//! 消せない（403）、印の無い情報・壊れた JSON、ほかの拡張子、書きかけの一時ファイルの古さまで。

use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use sycs_bot::djaudio::cache::{self, Cache};
use sycs_bot::djaudio::cleanup_expired;

mod support;

const GUILD: &str = "1399617700363370556";
const EXPECTED: &str = include_str!("fixtures/djaudio/cleanup_expected.jsonl");

/// 偽物の Discord の答え（取りに行く 4040 は 404、消す 4030 は 403、ほかは成功）。
fn respond(method: &str, path: &str) -> (u16, String) {
    let parts: Vec<&str> = path.trim_start_matches("/api/v10/").split('/').collect();
    let (channel, message) = (
        parts.get(1).copied().unwrap_or(""),
        parts.get(3).copied().unwrap_or(""),
    );
    match (method, message) {
        ("GET", "4040") => (
            404,
            json!({"message": "Unknown Message", "code": 10008}).to_string(),
        ),
        ("DELETE", "4030") => (
            403,
            json!({"message": "Missing Permissions", "code": 50013}).to_string(),
        ),
        ("GET", _) => {
            let mut v: Value = serde_json::from_str(&support::sent_message(channel)).unwrap();
            v["id"] = json!(message);
            (200, v.to_string())
        }
        _ => (204, String::new()),
    }
}

fn place_files(dir: &std::path::Path, case: &Value) {
    let now = cache::now_timestamp();
    for (name, content) in case["files"].as_object().into_iter().flatten() {
        let text = match content {
            Value::Object(meta) => {
                let mut meta = meta.clone();
                if let Some(seconds) = meta.shift_remove("expires_in") {
                    meta.insert("expires_at".into(), json!(now + seconds.as_f64().unwrap()));
                }
                sycs_bot::user_state::python_json(&Value::Object(meta))
            }
            other => other.as_str().unwrap().to_string(),
        };
        std::fs::write(dir.join(name), text).unwrap();
    }
    for (name, age) in case["tmp"].as_object().into_iter().flatten() {
        let path = dir.join(name);
        std::fs::write(&path, "{}").unwrap();
        let stamp = SystemTime::now() - Duration::from_secs(age.as_u64().unwrap());
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(stamp)
            .unwrap();
    }
}

fn serenity_cache(case: &Value) -> serenity::cache::Cache {
    let channels: Vec<Value> = case["channels"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, kind)| {
            let mut c = support::text_channel(GUILD, id, &format!("c{id}"));
            if kind.as_str() == Some("category") {
                c["type"] = json!(4);
            }
            c
        })
        .collect();
    let guild = support::guild(
        GUILD,
        "1",
        json!([support::role(GUILD, 0, 0)]),
        json!([]),
        json!(channels),
        json!([]),
    );
    support::cache_with(guild)
}

/// 全部の例で、Discord にしたことと残ったファイルが Python と同じであること。
#[tokio::test]
async fn djaudio_cleanup_matches_python() {
    let (base, seen) = support::start_fake_discord(respond).await;
    let http = support::http_to(&base);
    let mut count = 0;
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let case = &row[0];
        let root = tempfile::tempdir().unwrap();
        let cache = Cache::new(root.path());
        place_files(root.path(), case);
        let serenity_cache = serenity_cache(case);
        seen.lock().unwrap().clear();
        cleanup_expired(&cache, Some((&http, &serenity_cache)), |_| true).await;
        let mut effects: Vec<Value> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.path.trim_start_matches("/api/v10/").split('/').collect();
                let kind = if s.method == "GET" { "fetch" } else { "delete" };
                json!([
                    kind,
                    parts[1].parse::<u64>().unwrap(),
                    parts[3].parse::<u64>().unwrap()
                ])
            })
            .collect();
        effects.sort_by_key(Value::to_string);
        let mut want = row[1].as_array().unwrap().clone();
        want.sort_by_key(Value::to_string);
        let mut left: Vec<String> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        if Value::Array(effects.clone()) != Value::Array(want.clone()) || json!(left) != row[2] {
            wrong.push(format!(
                "{}\n  Python: {} {}\n  Rust:   {} {}",
                case["id"],
                Value::Array(want),
                row[2],
                Value::Array(effects),
                json!(left)
            ));
        }
        count += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 25, "例が少ない: {count}");
}

/// Python では掃除の巡回ごと止まる壊れた情報（辞書でない・期限が数でない）を、Rust は飛ばして、ほかの期限切れは消すこと。
#[tokio::test]
async fn broken_meta_is_skipped_instead_of_stopping() {
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::new(root.path());
    let (a, b, c) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));
    std::fs::write(root.path().join(format!("{a}.json")), "[1, 2]").unwrap();
    std::fs::write(
        root.path().join(format!("{b}.json")),
        format!("{{\"token\": \"{b}\", \"expires_at\": \"soon\"}}"),
    )
    .unwrap();
    std::fs::write(
        root.path().join(format!("{c}.json")),
        format!("{{\"token\": \"{c}\", \"expires_at\": 1}}"),
    )
    .unwrap();
    std::fs::write(root.path().join(format!("{c}.mp3")), "x").unwrap();
    cleanup_expired(&cache, None, |_| true).await;
    let mut left: Vec<String> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, [format!("{a}.json"), format!("{b}.json")]);
}
