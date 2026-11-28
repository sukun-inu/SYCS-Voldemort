//! 設定パネルの入力の検証（`sycs_admin::apps::validation`）が、本物の Python の `webapp_admin/schema/validation.py` と
//! 同じ答えを返すこと。
//!
//! 基準は `fixtures/validation/expected.json`（宣言の入力欄を全部、例の入力と選択肢の組の組み合わせで `validate_field`
//! に通した答えの表と、`validate_values`・`validate_item`・`humanize` の例）。答えは「値」「利用者に見せる誤りの文」
//! 「拾われない例外の型と文」のどれか。値は admin_harness の encode と同じ書き方（64 ビットを超える整数は
//! `{"$int": "…"}`）にして比べる。

use serde_json::{Map, Value, json};
use sycs_admin::apps::schema::schema;
use sycs_admin::apps::validation::{
    Clean, Cleaned, Refused, Rule, humanize, panel_rules, validate_field, validate_item,
    validate_values,
};
use sycs_admin::errors::Crash;

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/validation/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// admin_harness の `encode` と同じ整数の書き方（64 ビットに収まれば数、収まらなければ `{"$int": "…"}`）。
fn encode_int(text: &str) -> Value {
    if let Ok(i) = text.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(u) = text.parse::<u64>() {
        return Value::from(u);
    }
    json!({"$int": text})
}

fn encode(clean: &Clean) -> Value {
    match clean {
        Clean::Null => Value::Null,
        Clean::Bool(b) => Value::Bool(*b),
        Clean::Int(text) => encode_int(text),
        Clean::Text(text) => Value::String(text.clone()),
        Clean::List(items) => Value::Array(items.iter().cloned().map(Value::String).collect()),
    }
}

fn crashed(crash: &Crash) -> Value {
    json!({"raises": {"type": crash.kind, "message": crash.message}})
}

fn field_outcome(result: &Result<Clean, Refused>) -> Value {
    match result {
        Ok(clean) => json!({"value": encode(clean)}),
        Err(Refused::Invalid(message)) => json!({"invalid": message}),
        Err(Refused::Crash(crash)) => crashed(crash),
    }
}

/// `validate_values`・`validate_item` の答え（`[clean, errors]`）。
fn pair_outcome(result: &Result<(Cleaned, Map<String, Value>), Crash>) -> Value {
    match result {
        Ok((clean, errors)) => {
            let clean: Map<String, Value> = clean
                .iter()
                .map(|(key, value)| (key.clone(), encode(value)))
                .collect();
            json!({"value": [clean, errors]})
        }
        Err(crash) => crashed(crash),
    }
}

/// 基準の入力欄 1 つの規則（パネルの直下か、一覧の入力欄）。
fn rule_of(field: &Value) -> &'static Rule {
    let panel = panel_rules(field["panel"].as_str().unwrap()).unwrap();
    let key = field["key"].as_str().unwrap();
    let found = match field["collection"].as_str() {
        None => panel.field(key),
        Some(collection) => panel.collection(collection).unwrap().field(key),
    };
    found.unwrap_or_else(|| panic!("規則が無い: {field}"))
}

/// 鍵の並びまで同じか（serde_json の文字にして比べる）。
fn same(want: &Value, got: &Value) -> bool {
    serde_json::to_string(want).unwrap() == serde_json::to_string(got).unwrap()
}

/// 入力欄 × 選択肢の組 × 入力の表が、全部 Python と同じ答えであること。
#[test]
fn every_field_answers_like_python() {
    let data = expected();
    let raws = data["raws"].as_array().unwrap();
    let fields = data["fields"].as_array().unwrap();
    let rows = data["rows"].as_array().unwrap();
    assert!(rows.len() >= 4000, "表が足りない（{}）", rows.len());
    let mut wrong = Vec::new();
    for row in rows {
        let field = &fields[usize::try_from(row["f"].as_u64().unwrap()).unwrap()];
        let raw = &raws[usize::try_from(row["r"].as_u64().unwrap()).unwrap()];
        let name = row["c"].as_str().unwrap();
        let choices = data["choices"][name].as_object().unwrap();
        let rule = rule_of(field);
        assert_eq!(rule.widget.as_str(), field["widget"].as_str().unwrap());
        let got = field_outcome(&validate_field(rule, raw, choices));
        if !same(&row["result"], &got) {
            wrong.push(format!(
                "{}.{}.{} に {raw}（選択肢 {name}）:\n    Python {}\n    Rust   {got}",
                field["panel"], field["collection"], field["key"], row["result"]
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// 基準の入力欄が、宣言の入力欄（パネルの直下と一覧）をちょうど全部含むこと（宣言に入力欄が増えたら作り直す）。
#[test]
fn the_fixture_covers_every_field() {
    let data = expected();
    let listed: Vec<String> = data["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| format!("{} {} {}", field["panel"], field["collection"], field["key"]))
        .collect();
    let mut ours = Vec::new();
    for panel in &schema().panels {
        let rules = panel_rules(&panel.id).unwrap();
        for rule in &rules.fields {
            ours.push(format!("\"{}\" null \"{}\"", panel.id, rule.key));
        }
        for collection in &rules.collections {
            for rule in &collection.fields {
                ours.push(format!(
                    "\"{}\" \"{}\" \"{}\"",
                    panel.id, collection.key, rule.key
                ));
            }
        }
    }
    assert_eq!(listed, ours);
}

/// `validate_values`（知らない鍵・届いた順の誤り・拾われない例外）と `validate_item`（必須の欠け・知らない鍵）の例。
#[test]
fn values_and_items_answer_like_python() {
    let data = expected();
    let mut wrong = Vec::new();
    for case in data["values_cases"].as_array().unwrap() {
        let panel = schema().panel(case["panel"].as_str().unwrap()).unwrap();
        let choices = data["choices"][case["choices"].as_str().unwrap()]
            .as_object()
            .unwrap();
        let incoming = case["incoming"].as_object().unwrap();
        let got = pair_outcome(&validate_values(panel, incoming, choices));
        if !same(&case["result"], &got) {
            wrong.push(format!(
                "{}:\n    Python {}\n    Rust   {got}",
                case["name"], case["result"]
            ));
        }
    }
    for case in data["item_cases"].as_array().unwrap() {
        let rules = panel_rules(case["panel"].as_str().unwrap())
            .unwrap()
            .collection(case["collection"].as_str().unwrap())
            .unwrap();
        let choices = data["choices"][case["choices"].as_str().unwrap()]
            .as_object()
            .unwrap();
        let incoming = case["incoming"].as_object().unwrap();
        let got = pair_outcome(&validate_item(rules, incoming, choices));
        if !same(&case["result"], &got) {
            wrong.push(format!(
                "{}:\n    Python {}\n    Rust   {got}",
                case["name"], case["result"]
            ));
        }
    }
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
    assert!(data["values_cases"].as_array().unwrap().len() >= 8);
    assert!(data["item_cases"].as_array().unwrap().len() >= 8);
}

/// 期間の書き方（`duration.humanize`）が Python と同じこと。
#[test]
fn durations_are_humanized_like_python() {
    let data = expected();
    for pair in data["humanize"].as_array().unwrap() {
        let seconds = pair[0].as_i64().unwrap();
        assert_eq!(humanize(seconds), pair[1].as_str().unwrap(), "{seconds}");
    }
}
