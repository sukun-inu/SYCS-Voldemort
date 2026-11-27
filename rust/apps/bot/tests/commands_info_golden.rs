//! 情報のコマンド（/info server・/info user）が、本物の Python（discord.py）と同じ返事をすること。
//!
//! 基準（`fixtures/commands/info_expected.jsonl`）は、Discord から届く形の JSON（`info_cases.json`）を discord.py の
//! 本物の Guild・Role・Member に読ませ、本物のコマンドの中身を、記録するだけの偽物の interaction で呼んだもの
//! （`generate_info.py`）。こちらは同じ JSON を serenity に読ませる（サーバーはキャッシュへ、メンバーは打たれた
//! コマンドへ）。比べるのは、返事の本文・本人にだけ見せるか・Embed（題・色・小さい画像・項目）・部品。時刻の
//! 書き方（日本時間）・ロールの並びと数・表示の色・アバターとアイコンの URL が、discord.py と同じであること。

mod support;

use serde_json::{Value, json};
use serenity::all::{CommandInteraction, CreateActionRow};
use sycs_bot::commands;
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::info;
use sycs_bot::commands::reply::Reply;

const APP: &str = "1350672236612288633";
const ADMIN_SITE_URL: &str = "https://admin.example/login";

/// 名前で引いたメンバーの JSON（`user` は名前から中身に置き換える）。
fn member(spec: &Value, name: &str) -> Value {
    let mut payload = spec["members"][name].clone();
    assert!(payload.is_object(), "知らないメンバー: {name}");
    let user = spec["users"][payload["user"].as_str().unwrap()].clone();
    payload["user"] = user;
    payload
}

/// その例のサーバーの JSON（共通のものに、例ごとの上書きを重ねる）。
fn guild(spec: &Value, case: &Value) -> Value {
    let mut payload = spec["guild"].clone();
    for (key, value) in case["guild_patch"].as_object().into_iter().flatten() {
        payload[key] = value.clone();
    }
    let members: Vec<Value> = payload["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| member(spec, name.as_str().unwrap()))
        .collect();
    payload["members"] = Value::Array(members);
    payload
}

/// ゲートウェイから届く形の、打たれたコマンド。選んだ人の情報は `resolved` に入る（サーバーにいる人だけ
/// `members` にも入る）。
fn interaction(spec: &Value, case: &Value) -> CommandInteraction {
    let sub = case["path"].as_str().unwrap().rsplit(' ').next().unwrap();
    let mut leaf = Vec::new();
    let mut resolved = json!({});
    if let Some(name) = case["target"].as_str() {
        let mut picked = member(spec, name);
        let user = picked["user"].take();
        picked.as_object_mut().unwrap().remove("user");
        let id = user["id"].as_str().unwrap().to_string();
        leaf.push(json!({"name": "member", "type": 6, "value": id}));
        resolved = json!({"users": {id.clone(): user}, "members": {id: picked}});
    } else if let Some(name) = case["target_user"].as_str() {
        let user = spec["users"][name].clone();
        let id = user["id"].as_str().unwrap().to_string();
        leaf.push(json!({"name": "member", "type": 6, "value": id}));
        resolved = json!({"users": {id: user}});
    }
    let mut payload = json!({
        "id": "7000", "application_id": APP, "type": 2,
        "data": {
            "id": "8000", "name": "info", "type": 1,
            "options": [{"name": sub, "type": 1, "options": leaf}],
            "resolved": resolved,
        },
        "channel_id": "300", "token": "tok", "version": 1, "app_permissions": "0", "locale": "ja",
        "entitlements": [], "authorizing_integration_owners": {}, "attachment_size_limit": 10485760,
    });
    let invoker = member(spec, case["invoker"].as_str().unwrap());
    if case["who"] == "dm" {
        payload["user"] = invoker["user"].clone();
    } else {
        payload["guild_id"] = spec["guild"]["id"].clone();
        payload["guild_locale"] = json!("ja");
        payload["member"] = invoker;
    }
    serde_json::from_value(payload).expect("コマンドの JSON")
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
                .map(|f| {
                    json!([
                        f["name"],
                        f["value"],
                        f["inline"].as_bool().unwrap_or(false)
                    ])
                })
                .collect();
            json!({
                "title": v["title"],
                "description": v["description"],
                "color": v["color"],
                "thumbnail": v["thumbnail"]["url"],
                "fields": fields,
            })
        })
        .collect();
    Value::Array(list)
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
                .map(|c| json!({"type": c["type"], "style": c["style"], "label": c["label"], "url": c["url"]}))
                .collect();
            Value::Array(items)
        })
        .collect();
    Value::Array(out)
}

fn run(spec: &Value, case: &Value) -> Value {
    let cache = support::cache_with(guild(spec, case));
    let command = interaction(spec, case);
    let (path, leaf) = commands::command_path(&command.data.name, &command.data.options);
    assert_eq!(path, case["path"].as_str().unwrap());
    let route = commands::route(&path).unwrap_or_else(|| panic!("移していないコマンド: {path}"));
    let which = info::command_of(route).unwrap_or_else(|| panic!("/info でない: {path}"));
    // 立場は、ほかのコマンドと同じ決め方（サーバーの外・Bot が覚えていないサーバーは「外」）。
    let standing = commands::standing_of(&cache, &command);
    // 管理者かどうかは、このコマンドでは見ない（持ち主が打つ例もある）。
    assert_eq!(
        standing == Standing::OutsideGuild,
        case["who"] == "dm",
        "{}",
        case["id"]
    );
    let reply = info::answer(which, standing, &cache, &command, leaf, ADMIN_SITE_URL);
    json!([case["id"], {
        "content": reply.content,
        "ephemeral": reply.ephemeral,
        "embeds": embeds_json(&reply),
        "components": components_json(&reply.components),
    }])
}

fn spec() -> Value {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/info_cases.json")).unwrap())
        .unwrap()
}

#[test]
fn info_commands_answer_like_python() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    let spec = spec();
    let cases = spec["cases"].as_array().unwrap();
    let expected = std::fs::read_to_string(format!("{dir}/info_expected.jsonl")).unwrap();
    let expected: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    assert!(cases.len() >= 35, "例が減っている: {}", cases.len());
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(expected) {
        let got = run(&spec, case).to_string();
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

/// Bot が覚えていないサーバーで打たれたら、サーバーの外として断ること（キャッシュに無いと情報を出せない）。
#[test]
fn an_uncached_guild_is_refused() {
    let spec = spec();
    let case = json!({"id": "x", "path": "info server", "who": "member", "invoker": "plain"});
    let command = interaction(&spec, &case);
    let empty = serenity::all::Cache::new();
    let standing = commands::standing_of(&empty, &command);
    assert_eq!(standing, Standing::OutsideGuild);
    for which in [info::Command::Server, info::Command::User] {
        let reply = info::answer(which, standing, &empty, &command, &[], ADMIN_SITE_URL);
        assert_eq!(reply.content.as_deref(), Some("ギルド内でのみ使えるぞ。"));
        assert!(reply.ephemeral && reply.embeds.is_empty());
    }
    // 立場だけ「中」と言われても、キャッシュに無ければ出せない。
    let reply = info::answer(
        info::Command::Server,
        Standing::Member,
        &empty,
        &command,
        &[],
        ADMIN_SITE_URL,
    );
    assert_eq!(reply.content.as_deref(), Some("ギルド内でのみ使えるぞ。"));
}

/// 打った人のメンバーとしての情報が届いていなければ、その旨を返すこと（Python の `isinstance` の枝）。
#[test]
fn a_missing_invoker_member_is_reported() {
    let spec = spec();
    let case = json!({"id": "x", "path": "info user", "who": "member", "invoker": "plain"});
    let cache = support::cache_with(guild(&spec, &case));
    let mut command = interaction(&spec, &case);
    command.member = None;
    let reply = info::answer(
        info::Command::User,
        Standing::Member,
        &cache,
        &command,
        &[],
        ADMIN_SITE_URL,
    );
    assert_eq!(
        reply.content.as_deref(),
        Some("そのメンバーの情報を取得できなかった。")
    );
    assert!(reply.ephemeral);
}
