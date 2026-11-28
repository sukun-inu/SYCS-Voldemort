//! 設定パネルの値を読む関数（`sycs_admin::apps::getters`）と `to_json_value`（`sycs_admin::apps::schema`）が、
//! 本物の Python と同じ答えを返すこと。
//!
//! 基準は `fixtures/getters/expected.json`（`generate.py` が、例の設定の JSON ごとに Python の読む関数を全部呼んだ
//! 答え。値か、例外の型の名前と文。入力欄の関数は `to_json_value` に通した値も）。同じ設定を Rust の関数に渡して
//! 比べる。関数の名前は `schema.json` と同じ付け方なので、Rust の表（`getters::GETTERS`）でそのまま引ける。

use std::sync::Arc;

use serde_json::{Value, json};
use sycs_admin::apps::getters::{self, Ctx, DjaudioDefaults};
use sycs_admin::apps::schema::{self, Widget};
use sycs_admin::apps::store;
use sycs_core::settings::Settings;

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/getters/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn djaudio(data: &Value) -> DjaudioDefaults {
    DjaudioDefaults {
        cache_ttl: data["djaudio"]["cache_ttl"].as_i64().unwrap(),
        cooldown: data["djaudio"]["cooldown"].as_i64().unwrap(),
        max_urls: data["djaudio"]["max_urls"].as_i64().unwrap(),
    }
}

/// 例の設定（`{"$raise": …}` なら読み込めない）。
fn settings_of(spec: &Value) -> Result<Arc<Settings>, String> {
    match spec.get("$raise") {
        Some(_) => Err(spec["message"].as_str().unwrap().to_string()),
        None => Ok(Arc::new(store::settings_from_document(spec))),
    }
}

/// Rust の答えを基準と同じ形にする（値と、入力欄なら to_json_value に通したもの。例外は型の名前と文）。
fn answer(name: &str, kind: &str, ctx: &Ctx<'_>) -> Value {
    match getters::call(name, ctx) {
        Ok(value) => {
            let mut result = json!({"value": value.clone()});
            if kind == "get" {
                let field = schema::schema()
                    .panels
                    .iter()
                    .flat_map(|panel| panel.fields.iter())
                    .find(|field| field.get.as_deref() == Some(name))
                    .unwrap_or_else(|| panic!("{name} を使う入力欄が無い"));
                result["json"] = schema::to_json_value(field.widget, &field.default, &value);
            }
            result
        }
        Err(crash) => json!({"raises": {"type": crash.kind, "message": crash.message}}),
    }
}

/// 例の設定ごとに、読む関数を全部呼んだ答え（値・to_json_value・例外の型と文）が Python と同じであること。
#[test]
fn getters_answer_like_python() {
    let data = expected();
    let defaults = djaudio(&data);
    let functions = data["functions"].as_object().unwrap();
    assert_eq!(
        functions.len(),
        getters::GETTERS.len(),
        "Python の読む関数の数と Rust の表の数が違う"
    );
    let cases = data["cases"].as_array().unwrap();
    assert!(cases.len() >= 25, "基準の例が足りない（{}）", cases.len());
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let settings = settings_of(&case["settings"]);
        let guild_id = case["guild_id"].as_str().unwrap();
        let ctx = Ctx {
            settings: &settings,
            guild_id,
            djaudio: &defaults,
        };
        for (function, want) in case["results"].as_object().unwrap() {
            let kind = functions[function].as_str().unwrap();
            let got = answer(function, kind, &ctx);
            if &got != want {
                wrong.push(format!(
                    "「{name}」の {function}:\n    Python {want}\n    Rust   {got}"
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// 入力欄の種類 × 値の表で、`to_json_value` の答えが Python と同じであること。
#[test]
fn to_json_value_answers_like_python() {
    let data = expected();
    let rows = data["to_json"].as_array().unwrap();
    assert_eq!(rows.len() % Widget::ALL.len(), 0);
    assert!(rows.len() >= 11 * 20, "表が足りない（{}）", rows.len());
    let mut wrong = Vec::new();
    for row in rows {
        let widget = Widget::parse(row["widget"].as_str().unwrap()).unwrap();
        let got = schema::to_json_value(widget, &row["default"], &row["value"]);
        if got != row["result"] {
            wrong.push(format!(
                "{} の {}: Python {} / Rust {got}",
                row["widget"], row["value"], row["result"]
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

/// 基準が扱う関数の名前が、Rust の表の名前とちょうど同じであること（基準を作り直したのに Rust の表が古い、を落とす）。
#[test]
fn the_fixture_covers_every_rust_getter() {
    let data = expected();
    let mut python: Vec<&str> = data["functions"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    python.sort_unstable();
    let rust: Vec<&str> = getters::GETTERS.iter().map(|(name, _)| *name).collect();
    assert_eq!(python, rust);
}
