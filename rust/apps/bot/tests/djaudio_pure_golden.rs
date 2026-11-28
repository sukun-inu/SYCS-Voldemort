//! DJAudio の部品（Discord にも yt-dlp にも触らない関数）が、本物の Python と同じ答えを返すこと。
//!
//! 基準（`fixtures/djaudio/pure_expected.jsonl`）は `generate_pure.py` が本物の Python に答えさせたもの。1 行に 1 例で、
//! `[種類, 入力, Python の答え]`。種類ごとに、Rust の同じ働きの関数に同じ入力を渡して比べる:
//! 実行のときの設定（新旧の置き場・数の読み方と丸め方・既定）、落とせないサービスと受け付けるドメイン、info.json の
//! サービスの見分け、SoundCloud の URL か、URL の拾い方、題の組み立て、ファイル名の整え方、`str.lower()`、
//! `Path.stem` と info.json の名前、client_id の探し方、スクリプトの URL の拾い方、リンクの Embed。

use std::path::Path;

use serde_json::{Map, Value, json};
use sycs_bot::djaudio::settings::{self, Defaults};
use sycs_bot::djaudio::{cache, download, flow, site};
use sycs_bot::python_chars;

const GUILD: u64 = 1_399_617_700_363_370_556;
const EXPECTED: &str = include_str!("fixtures/djaudio/pure_expected.jsonl");

fn map(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().expect("辞書の入力")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("文字の入力")
}

fn runtime(given: &Value) -> Value {
    let d = &given[1];
    let defaults = Defaults {
        cache_ttl: d[0].as_i64().unwrap(),
        cooldown: d[1].as_i64().unwrap(),
        max_urls: d[2].as_i64().unwrap(),
    };
    let r = settings::runtime(Some(&given[0]), defaults);
    json!([
        r.watch_channel
            .as_ref()
            .map_or("0".to_string(), |c| c.text().to_string()),
        r.cache_ttl as i64,
        r.cooldown as i64,
        r.max_urls as i64,
        r.output_channel.as_ref().map(|c| c.text().to_string()),
    ])
}

fn embed(given: &Value) -> Value {
    let results: flow::Results = given[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (text(&r[0]).to_string(), text(&r[1]).to_string()))
        .collect();
    let e = flow::result_embed(
        &results,
        text(&given[1]),
        GUILD,
        i128::from(given[2].as_i64().unwrap()),
    );
    let v = serde_json::to_value(&e).unwrap();
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
    json!({"title": v["title"], "description": v["description"], "color": v["color"], "fields": fields})
}

fn answer(kind: &str, given: &Value) -> Value {
    match kind {
        "runtime" => runtime(given),
        "site" => json!([
            site::is_unsupported_url(text(given)),
            site::is_djaudio_allowed_url(text(given))
        ]),
        "detect" => json!(site::detect_site(&map(given))),
        "soundcloud" => json!(download::is_soundcloud_url(text(given))),
        "extract" => json!(download::extract_urls(
            text(&given[0]),
            usize::try_from(given[1].as_u64().unwrap()).unwrap()
        )),
        "title" => json!(download::format_title(&map(given))),
        "sanitize" => json!(cache::sanitize_filename(text(&given[0]), text(&given[1]))),
        "lower" => json!(python_chars::lower(text(given))),
        "stem" => {
            let path = Path::new("/tmp/d").join(text(given));
            let info = download::info_json_path(&path);
            json!([
                download::stem(&path),
                info.file_name().unwrap().to_string_lossy()
            ])
        }
        "client_id" => json!(download::find_client_id(text(given))),
        "scripts" => json!(download::script_urls(text(given))),
        "embed" => embed(given),
        other => panic!("知らない種類: {other}"),
    }
}

/// 全部の例で、Rust の答えが本物の Python と同じであること。
#[test]
fn every_part_answers_like_python() {
    let mut count = 0;
    let mut kinds = std::collections::BTreeMap::new();
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let kind = text(&row[0]);
        let got = answer(kind, &row[1]);
        if got != row[2] {
            wrong.push(format!(
                "{kind} {}\n  Python: {}\n  Rust:   {got}",
                row[1], row[2]
            ));
        }
        count += 1;
        *kinds.entry(kind.to_string()).or_insert(0) += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 600, "例が少ない: {count}");
    // 種類がどれも入っていること（基準を作り直して、ある種類が丸ごと落ちたら気づけるように）。
    assert_eq!(kinds.len(), 12, "{kinds:?}");
}
