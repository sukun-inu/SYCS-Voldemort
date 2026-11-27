//! 設定のコマンド（/log・/chat・/trusted・/bypass・/bot）が、本物の Python と同じ返事をし、設定を同じに
//! 書き換えること。
//!
//! 基準（`fixtures/commands/settings_expected.jsonl`）は、本物の Python のコマンドの中身を、記録するだけの
//! 偽物の interaction で呼んだもの（`generate_settings.py`）。返事（本文・Embed・部品・本人にだけ見せるか）と、
//! 書き換えたあとの設定（鍵の並びまで）を比べる。選択の画面（/trusted・/bypass の追加と削除）は、選ぶ・確定を
//! 押す、の手順ごとの応答も比べる。

use serde_json::{Value, json};
use serenity::all::{CommandDataOption, GuildId};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::picker::{self, Pickers, Step};
use sycs_bot::commands::reply::Reply;
use sycs_bot::commands::{self, PlanInput, Planned, settings};
use sycs_core::settings::{Settings, drop_nulls};

const GUILD: u64 = 1_399_617_700_363_370_556;
const USER: u64 = 80_351_110_224_678_912;
const OTHER: u64 = 4242;
const ADMIN_SITE_URL: &str = "https://admin.example/login";

/// 引数を、Discord から届く形（種類の番号つき）にする。
fn options(case: &Value) -> Vec<CommandDataOption> {
    let list: Vec<Value> = case["options"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| match name.as_str() {
            // 7 はチャンネル（ID は文字列で届く）、3 は文字列。
            "channel" => json!({"name": name, "type": 7, "value": value.to_string()}),
            _ => json!({"name": name, "type": 3, "value": value}),
        })
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

/// Python の `embed.to_dict()` から取り出すものと同じ形。
fn embeds_json(reply: &Reply) -> Value {
    let list: Vec<Value> = reply
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
    Value::Array(list)
}

/// 部品を、比べる項目だけにする（ID は毎回違うので、あるかどうかだけ）。Python の `view.to_components()`
/// から取り出すものと同じ形。
fn components_json(rows: &[serenity::all::CreateActionRow]) -> Value {
    let rows = serde_json::to_value(rows).unwrap();
    let out: Vec<Value> = rows
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            let items: Vec<Value> = row["components"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| {
                    json!({
                        "type": c["type"],
                        "style": c["style"],
                        "label": c["label"],
                        "disabled": c["disabled"].as_bool().unwrap_or(false),
                        "placeholder": c["placeholder"],
                        "min_values": c["min_values"],
                        "max_values": c["max_values"],
                        "url": c["url"],
                        "has_id": c["custom_id"].is_string(),
                    })
                })
                .collect();
            Value::Array(items)
        })
        .collect();
    Value::Array(out)
}

fn reply_json(reply: &Reply) -> Value {
    json!({
        "content": reply.content,
        "ephemeral": reply.ephemeral,
        "embeds": embeds_json(reply),
        "components": components_json(&reply.components),
    })
}

/// 返事の部品から、選択の画面の印を取り出す。
fn token_of(reply: &Reply) -> Option<String> {
    let rows = serde_json::to_value(&reply.components).unwrap();
    let id = rows[0]["components"][0]["custom_id"].as_str()?.to_string();
    picker::parse_custom_id(&id).map(|(token, _)| token.to_string())
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
    let pickers = Pickers::default();
    let options = options(case);
    let before = case["before"].clone();
    let input = PlanInput {
        standing,
        guild_id,
        user_id: USER,
        options: &options,
        guild_settings: Some(&before),
        pickers: &pickers,
        admin_site_url: ADMIN_SITE_URL,
    };
    let reply = match commands::plan(route, &input).unwrap() {
        Planned::Reply(reply) => *reply,
        Planned::Write(write) => write(&mut settings),
    };
    // 選択の画面: 選ぶ・確定を押す、の手順ごとの応答。
    let token = token_of(&reply);
    let mut steps = Vec::new();
    for step in case["steps"].as_array().into_iter().flatten() {
        let token = token.as_deref().expect("選択の画面が開いていない");
        let user = if step["by"] == "other" { OTHER } else { USER };
        let taken = match step["select"].as_array() {
            Some(values) => pickers.select(
                token,
                user,
                values.iter().map(|v| v.as_u64().unwrap()).collect(),
            ),
            None => pickers.confirm(token, user),
        };
        steps.push(match taken {
            Step::Ignore => json!({"kind": "ignored"}),
            Step::NotYours => {
                json!({"kind": "message", "content": picker::NOT_YOURS, "ephemeral": true})
            }
            Step::NothingPicked => {
                json!({"kind": "message", "content": picker::NOTHING_PICKED, "ephemeral": true})
            }
            Step::Redraw { kind, picked } => json!({
                "kind": "update",
                "content": null,
                "components": components_json(&picker::components(token, kind, picked)),
            }),
            Step::Confirm { kind, picked } => {
                let updated = settings::change_ids(
                    &mut settings,
                    GUILD,
                    kind.settings_key(),
                    &picked,
                    kind.adds(),
                );
                pickers.close(token);
                json!({
                    "kind": "update",
                    "content": picker::confirmed_text(kind, &picked, updated.len()),
                    "components": [],
                })
            }
        });
    }
    // 保存のときと同じく、null は落とす（「未設定」は鍵ごと消える）。
    let mut after = settings.guilds[&GUILD.to_string()].clone();
    drop_nulls(&mut after);
    json!([case["id"], reply_json(&reply), steps, after])
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
    let pickers = Pickers::default();
    let input = |standing| PlanInput {
        standing,
        guild_id: Some(GuildId::new(GUILD)),
        user_id: USER,
        options: &none,
        guild_settings: None,
        pickers: &pickers,
        admin_site_url: ADMIN_SITE_URL,
    };
    for path in ["log channel", "log level", "chat set"] {
        let route = commands::route(path).unwrap();
        assert!(
            commands::plan(route, &input(Standing::Admin)).is_err(),
            "{path}"
        );
    }
    // 管理者でなければ、引数を見る前に断る。
    let route = commands::route("log channel").unwrap();
    let planned = commands::plan(route, &input(Standing::Member));
    assert!(matches!(planned, Ok(Planned::Reply(_))));
}
