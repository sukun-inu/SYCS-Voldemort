//! 地震アラートのコマンド（/quake channel・min_scale・status・type）が、本物の Python と同じ返事をし、設定を
//! 同じに書き換えること。
//!
//! 基準（`fixtures/commands/quake_expected.jsonl`）は、本物の Python のコマンドの中身を、記録するだけの偽物の
//! interaction で呼んだもの（`generate_quake.py`）。返事（本文・Embed・部品・本人にだけ見せるか）と、書き換えた
//! あとの設定（鍵の並びまで）を比べる。通知の種類の画面（/quake type）は、入・切のボタンを押す・保存を押す、の
//! 手順ごとの応答も比べる。部品の ID は Python と書き方が違うので、押したときの働き（どの種類の入・切か、保存か）で
//! 比べる。保存されている設定が読めない形のとき、Python は例外で止まる。その例は、Rust も失敗になることを比べる。

use serde_json::{Value, json};
use serenity::all::{CommandDataOption, CreateActionRow, GuildId};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::picker::NOT_YOURS;
use sycs_bot::commands::quake::{self, Command, Input, Part, Plan, Screens, Step};
use sycs_bot::commands::reply::Reply;
use sycs_bot::commands::{self, CommandError};
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
            // 7 はチャンネル（ID は文字列で届く）、4 は整数。
            "channel" => json!({"name": name, "type": 7, "value": value.to_string()}),
            _ => json!({"name": name, "type": 4, "value": value}),
        })
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

/// Python の `embed.to_dict()` から取り出すものと同じ形。
fn embeds_json(embeds: &[serenity::all::CreateEmbed]) -> Value {
    let list: Vec<Value> = embeds
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

/// 部品の ID から、押したときの働きを読む（Python の `action_of` と同じ書き方）。
fn action_of(custom_id: &Value) -> Value {
    let Some(id) = custom_id.as_str() else {
        return Value::Null;
    };
    match quake::parse_custom_id(id) {
        Some((_, Part::Save)) => json!("save"),
        Some((_, Part::Toggle(index))) => json!(format!("toggle:{}", quake::NOTIFY_TYPES[index].0)),
        None => json!("?"),
    }
}

/// 部品を、比べる項目だけにする。Python の `view.to_components()` から取り出すものと同じ形。
fn components_json(rows: &[CreateActionRow]) -> Value {
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
                        "url": c["url"],
                        "action": action_of(&c["custom_id"]),
                    })
                })
                .collect();
            Value::Array(items)
        })
        .collect();
    Value::Array(out)
}

fn reply_json(reply: &Reply, with_timeout: bool) -> Value {
    let mut out = json!({
        "content": reply.content,
        "ephemeral": reply.ephemeral,
        "embeds": embeds_json(&reply.embeds),
        "components": components_json(&reply.components),
    });
    if with_timeout {
        out["timeout"] = json!(quake::TIMEOUT_SECONDS);
    }
    out
}

/// 返事の部品から、画面の印を取り出す。
fn token_of(reply: &Reply) -> Option<String> {
    let rows = serde_json::to_value(&reply.components).unwrap();
    let id = rows[0]["components"][0]["custom_id"].as_str()?.to_string();
    quake::parse_custom_id(&id).map(|(token, _)| token.to_string())
}

/// 設定を書き換える。保存のときと同じく、前後で null を落とす（「未設定」は鍵ごと消える）。
fn write<T>(settings: &mut Settings, mutate: impl FnOnce(&mut Settings) -> T) -> T {
    let key = GUILD.to_string();
    if let Some(guild) = settings.guilds.get_mut(&key) {
        drop_nulls(guild);
    }
    let out = mutate(settings);
    if let Some(guild) = settings.guilds.get_mut(&key) {
        drop_nulls(guild);
    }
    out
}

fn command_of(path: &str) -> Command {
    let route = commands::route(path).unwrap_or_else(|| panic!("移していないコマンド: {path}"));
    quake::command_of(route).unwrap_or_else(|| panic!("/quake でない: {path}"))
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
    let command = command_of(case["path"].as_str().unwrap());
    let screens = Screens::default();
    let options = options(case);
    let before = case["before"].clone();
    let input = Input {
        standing,
        guild_id,
        user_id: USER,
        options: &options,
        guild_settings: Some(&before),
        screens: &screens,
        admin_site_url: ADMIN_SITE_URL,
    };
    let reply = match quake::plan(command, &input) {
        Ok(Plan::Reply(reply)) => *reply,
        Ok(Plan::Write(apply)) => write(&mut settings, apply),
        // Python は例外で止まる（設定には触らない）。
        Err(CommandError::BrokenSetting(_)) => {
            return json!([case["id"], {"failed": true}, [], case["before"]]);
        }
        Err(e) => panic!("{}: {e}", case["id"]),
    };
    // 通知の種類の画面: 入・切のボタンを押す・保存を押す、の手順ごとの応答。
    let token = token_of(&reply);
    let mut steps = Vec::new();
    for step in case["steps"].as_array().into_iter().flatten() {
        let token = token.as_deref().expect("画面が開いていない");
        let user = if step["by"] == "other" { OTHER } else { USER };
        let taken = match step["toggle"].as_str() {
            Some(key) => {
                let index = quake::NOTIFY_TYPES
                    .iter()
                    .position(|(k, _)| *k == key)
                    .unwrap();
                screens.toggle(token, user, index)
            }
            None => screens.save(token, user),
        };
        steps.push(match taken {
            Step::Ignore => json!({"kind": "ignored"}),
            Step::NotYours => json!({"kind": "message", "content": NOT_YOURS, "ephemeral": true}),
            Step::Redraw { types } => json!({
                "kind": "update",
                "content": null,
                "embeds": embeds_json(&[quake::notify_type_embed(types)]),
                "components": components_json(&quake::components(token, types)),
            }),
            Step::Save { guild, types } => {
                assert_eq!(guild, GUILD, "画面を開いたサーバーに書くこと");
                write(&mut settings, |s| quake::save_notify_types(s, guild, types));
                screens.close(token);
                json!({
                    "kind": "update",
                    "content": quake::SAVED,
                    "embeds": embeds_json(&[quake::notify_type_embed(types)]),
                    "components": [],
                })
            }
        });
    }
    let opened_screen = command == Command::Type && token.is_some();
    let after = settings.guilds[&GUILD.to_string()].clone();
    json!([case["id"], reply_json(&reply, opened_screen), steps, after])
}

#[test]
fn quake_commands_answer_and_write_like_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/quake_cases.json")).unwrap())
            .unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/quake_expected.jsonl")).unwrap();
    let expected: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    assert!(cases.len() >= 55, "例が減っている: {}", cases.len());
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

/// 必須の引数が届いていなければ、書かずに失敗にすること（定義と食い違ったときの備え）。権限の無い人は、
/// 引数を見る前に断ること。
#[test]
fn a_missing_required_option_is_an_error() {
    let none: Vec<CommandDataOption> = Vec::new();
    let screens = Screens::default();
    let input = |standing| Input {
        standing,
        guild_id: Some(GuildId::new(GUILD)),
        user_id: USER,
        options: &none,
        guild_settings: None,
        screens: &screens,
        admin_site_url: ADMIN_SITE_URL,
    };
    for command in [Command::Channel, Command::MinScale] {
        assert!(
            matches!(
                quake::plan(command, &input(Standing::Admin)),
                Err(CommandError::MissingOption(_))
            ),
            "{command:?}"
        );
        assert!(matches!(
            quake::plan(command, &input(Standing::Member)),
            Ok(Plan::Reply(_))
        ));
    }
    // 種類の違う値（文字）が届いても、数として読まない。
    let text: Vec<CommandDataOption> =
        serde_json::from_value(json!([{"name": "scale", "type": 3, "value": "45"}])).unwrap();
    let wrong_kind = Input {
        options: &text,
        ..input(Standing::Admin)
    };
    assert!(quake::plan(Command::MinScale, &wrong_kind).is_err());
}

/// ほかのコマンドの入口（`commands::plan`）には載せていないこと（権限の見方が違うので、先に分ける）。
#[test]
fn quake_is_not_planned_by_the_common_planner() {
    use sycs_bot::commands::picker::Pickers;
    use sycs_bot::commands::{PlanInput, plan};
    let none: Vec<CommandDataOption> = Vec::new();
    let pickers = Pickers::default();
    let input = PlanInput {
        standing: Standing::Admin,
        guild_id: Some(GuildId::new(GUILD)),
        user_id: USER,
        options: &none,
        guild_settings: None,
        pickers: &pickers,
        admin_site_url: ADMIN_SITE_URL,
        place: sycs_bot::commands::server::Place::default(),
    };
    for path in [
        "quake channel",
        "quake min_scale",
        "quake status",
        "quake type",
        "info server",
        "info user",
    ] {
        let route = commands::route(path).unwrap_or_else(|| panic!("移していない: {path}"));
        assert!(
            matches!(plan(route, &input), Err(CommandError::NotPlanned)),
            "{path}"
        );
    }
}
