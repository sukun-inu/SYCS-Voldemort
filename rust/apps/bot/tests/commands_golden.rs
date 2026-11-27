//! 設定のコマンド（/log・/chat）が、本物の Python と同じ返事をし、設定を同じに書き換えること。
//!
//! 基準（`fixtures/commands/settings_expected.jsonl`）は、本物の Python のコマンドの中身を、記録するだけの
//! 偽物の interaction で呼んだもの（`generate_settings.py`）。返事の本文・本人にだけ見せるか・書き換えた
//! あとの設定（鍵の並びまで）を比べる。

use serde_json::{Value, json};
use serenity::all::{CommandDataOption, GuildId};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::{self, Planned};
use sycs_core::settings::{Settings, drop_nulls};

const GUILD: u64 = 1_399_617_700_363_370_556;

/// 引数を、Discord から届く形（種類の番号つき）にする。
fn options(case: &Value) -> Vec<CommandDataOption> {
    let list: Vec<Value> = case["options"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| match name.as_str() {
            // 7 はチャンネル（ID は文字列で届く）、3 は文字列。
            "channel" => json!({"name": name, "type": 7, "value": value.to_string()}),
            _ => json!({"name": name, "type": 3, "value": value}),
        })
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

fn run(case: &Value) -> Value {
    let mut settings = Settings::default();
    settings
        .guilds
        .insert(GUILD.to_string(), case["before"].clone());
    let (standing, guild_id) = match case["who"].as_str().unwrap() {
        "admin" => (Standing::Admin, Some(GuildId::new(GUILD))),
        "member" => (Standing::Member, Some(GuildId::new(GUILD))),
        _ => (Standing::OutsideGuild, None),
    };
    let path = case["path"].as_str().unwrap();
    let route = commands::route(path).unwrap_or_else(|| panic!("移していないコマンド: {path}"));
    let reply = match commands::plan(route, standing, guild_id, &options(case)).unwrap() {
        Planned::Reply(reply) => *reply,
        Planned::Write(write) => write(&mut settings),
    };
    // 保存のときと同じく、null は落とす（「未設定」は鍵ごと消える）。
    let mut after = settings.guilds[&GUILD.to_string()].clone();
    drop_nulls(&mut after);
    json!([
        case["id"],
        {"content": reply.content, "ephemeral": reply.ephemeral},
        after
    ])
}

#[test]
fn settings_commands_answer_and_write_like_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    let cases: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(format!("{dir}/settings_cases.json")).unwrap(),
    )
    .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/settings_expected.jsonl")).unwrap();
    let expected: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(expected) {
        // 文字列で比べる（設定の鍵の並びまで同じであること）。
        let got = run(case).to_string();
        let want = serde_json::from_str::<Value>(want).unwrap().to_string();
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

/// 必須の引数が届いていなければ、書かずに失敗にすること（定義と食い違ったときの備え）。
#[test]
fn a_missing_required_option_is_an_error() {
    let none: Vec<CommandDataOption> = Vec::new();
    for path in ["log channel", "log level", "chat set"] {
        let route = commands::route(path).unwrap();
        let planned = commands::plan(route, Standing::Admin, Some(GuildId::new(GUILD)), &none);
        assert!(planned.is_err(), "{path}");
    }
    // 管理者でなければ、引数を見る前に断る。
    let route = commands::route("log channel").unwrap();
    let planned = commands::plan(route, Standing::Member, Some(GuildId::new(GUILD)), &none);
    assert!(matches!(planned, Ok(Planned::Reply(_))));
}
