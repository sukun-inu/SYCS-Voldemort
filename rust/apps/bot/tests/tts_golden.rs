//! 読み上げる文の作り方が、本物の Python と同じであること。
//!
//! 基準（`fixtures/tts/text_expected.json`）は、本物の `services/tts_service.py` の関数を呼んだもの
//! （`generate_text.py`）:
//!
//! - clean: `_clean_text`（URL・メンション・絵文字の置き換え、前後の空白、長さの切り方）。Python の `re` の
//!   `\w`・`\d`・`\S` と Rust の正規表現の違いが出る文字（結合文字・つなぎの記号・区切りの制御文字）を含む
//! - dictionary: `_apply_dictionary`（長い語が先・置き換えた結果にはもう当てない）
//! - speak: `enqueue_message` が合成を頼む文・声・速度（読まないときは null）
//! - vc_event: `enqueue_vc_event` が合成を頼む文・声・速度

use serde_json::{Value, json};
use sycs_bot::tts;

const USER: u64 = 80_351_110_224_678_912;

fn fixtures() -> (Value, Value) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tts");
    let read = |name: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{name}")).unwrap()).unwrap()
    };
    (read("text_cases.json"), read("text_expected.json"))
}

/// 種類ごとに、例と基準を並べて比べる。違いは全部まとめて出す。
fn compare(kind: &str, run: impl Fn(&Value) -> Value) {
    let (cases, expected) = fixtures();
    let cases = cases[kind].as_array().unwrap();
    let expected = expected[kind].as_array().unwrap();
    assert_eq!(cases.len(), expected.len(), "{kind}: 基準と例の数が違う");
    let wrong: Vec<String> = cases
        .iter()
        .zip(expected)
        .filter_map(|(case, want)| {
            let got = run(case);
            (&got != want).then(|| format!("{case}\n  py {want}\n  rs {got}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{kind}: {} 例が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

fn utterance_json(found: Option<tts::Utterance>) -> Value {
    found.map_or(Value::Null, |u| json!([u.text, u.voice, u.rate]))
}

#[test]
fn text_is_cleaned_like_python() {
    compare("clean", |case| {
        json!(tts::clean_text(
            case["text"].as_str().unwrap(),
            case["max"].as_i64().unwrap()
        ))
    });
}

#[test]
fn the_dictionary_is_applied_like_python() {
    compare("dictionary", |case| {
        let entries: Vec<(String, String)> = case["dict"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(word, reading)| (word.clone(), reading.as_str().unwrap().to_string()))
            .collect();
        json!(tts::apply_dictionary(
            case["text"].as_str().unwrap(),
            &entries
        ))
    });
}

#[test]
fn messages_are_spoken_like_python() {
    compare("speak", |case| {
        let mut settings = case["settings"].clone();
        settings["user_settings"] = json!({USER.to_string(): case["user"]});
        let guild = json!({"tts": settings});
        let found = tts::message_utterance(
            Some(&guild),
            None,
            USER,
            case["name"].as_str().unwrap(),
            case["text"].as_str().unwrap(),
        )
        .unwrap();
        utterance_json(found)
    });
}

#[test]
fn vc_events_are_spoken_like_python() {
    compare("vc_event", |case| {
        let guild = json!({"tts": case["settings"]});
        let found = tts::vc_event_utterance(
            Some(&guild),
            None,
            case["name"].as_str().unwrap(),
            // Python の `str(member)`（`generate_text.py` の `Member.__str__`）。
            "nelly",
            case["event"] == "join",
        )
        .unwrap();
        utterance_json(found)
    });
}
