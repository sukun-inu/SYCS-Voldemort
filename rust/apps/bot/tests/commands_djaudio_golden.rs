//! /djaudio channel・output・status が、本物の Python と同じものを送り、設定を同じに書き換えること。
//!
//! 基準（`fixtures/djaudio/commands_expected.jsonl`）は、本物の Python のコマンドを discord.py と同じ順（コマンドの
//! 確かめ → 中身 → コマンドの受け皿 → 全体の受け皿）に動かし、送ったもの（最初の応答・あとからの送信）を順に
//! 記録したもの（`generate_commands.py`）。権限が無いとき・設定を書けないとき・返事を送れないときに 2 通になる
//! ところ、管理者でない人・DM の断り方、状況の Embed（チャンネルが見つからないときの書き方・localhost の注意）、
//! 書き換えたあとの設定（新旧の置き場・鍵の並び）まで比べる。

use serde_json::{Value, json};
use serenity::all::{CreateActionRow, CreateEmbed};
use sycs_bot::commands::djaudio::{self, Command, Input, Plan};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::reply::Reply;
use sycs_bot::djaudio::Config;
use sycs_core::env::Env;
use sycs_core::settings::{Settings, drop_nulls};

const GUILD: u64 = 1_399_617_700_363_370_556;
const ADMIN_SITE_URL: &str = "https://admin.example/login";
const EXPECTED: &str = include_str!("fixtures/djaudio/commands_expected.jsonl");

fn embed_json(embeds: &[CreateEmbed]) -> Value {
    let Some(embed) = embeds.first() else {
        return Value::Null;
    };
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
    json!({"title": v["title"], "description": v["description"], "color": v["color"], "fields": fields})
}

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

fn sent(kind: &str, reply: &Reply) -> Value {
    json!([
        kind,
        reply.content,
        embed_json(&reply.embeds),
        components_json(&reply.components),
        reply.ephemeral
    ])
}

/// 本文だけを並べて送ったもの（最初が応答、残りは応答のあとから）。
fn messages(texts: &[&str]) -> Vec<Value> {
    texts
        .iter()
        .enumerate()
        .map(|(i, t)| {
            sent(
                if i == 0 { "response" } else { "followup" },
                &Reply::ephemeral(*t),
            )
        })
        .collect()
}

fn config(case: &Value) -> Config {
    let base = case["base_url"]
        .as_str()
        .unwrap_or("https://dl.example")
        .to_string();
    let defaults = case["defaults"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![json!(600), json!(30), json!(3)]);
    let env = Env::from_fn(move |key| match key {
        "DJAUDIO_BASE_URL" => Some(base.clone()),
        "DJAUDIO_CACHE_TTL_SECONDS" => Some(defaults[0].to_string()),
        "DJAUDIO_COOLDOWN_SECONDS" => Some(defaults[1].to_string()),
        "DJAUDIO_MAX_URLS_PER_MSG" => Some(defaults[2].to_string()),
        _ => None,
    });
    Config::from_env(&env)
}

fn command_of(path: &str) -> Command {
    let route = sycs_bot::commands::route(path).unwrap_or_else(|| panic!("移していない: {path}"));
    djaudio::command_of(route).unwrap_or_else(|| panic!("/djaudio でない: {path}"))
}

/// 例を 1 つ回して、送ったものと、終わったあとの設定を返す。
fn run(case: &Value) -> (Vec<Value>, Value) {
    let mut settings = Settings::default();
    let before = case.get("before").cloned().unwrap_or_else(|| json!({}));
    settings.guilds.insert(GUILD.to_string(), before.clone());
    let who = case["who"].as_str().unwrap();
    let channels: Vec<u64> = case["channels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect();
    let exists = |id: u64| channels.contains(&id);
    let config = config(case);
    let input = Input {
        standing: match who {
            "admin" => Standing::Admin,
            "member" => Standing::Member,
            _ => Standing::OutsideGuild,
        },
        manage_channels: case["manage_channels"].as_bool().unwrap_or(false),
        guild_id: (who != "dm").then_some(GUILD),
        channel: case["channel"].as_u64(),
        guild_settings: Some(&before),
        config: &config,
        admin_site_url: ADMIN_SITE_URL,
        channel_exists: &exists,
    };
    let fail = case["fail"].as_str();
    let which = command_of(case["path"].as_str().unwrap());
    let failed = || messages(djaudio::failure_messages(which));
    let out = match djaudio::plan(which, &input) {
        Plan::Messages(texts) => messages(&texts),
        Plan::Reply(reply) if fail == Some("send") => {
            let _ = reply;
            failed()
        }
        Plan::Reply(reply) => vec![sent("response", &reply)],
        Plan::Write(_, _) if fail == Some("write") => failed(),
        Plan::Write(write, reply) => {
            let key = GUILD.to_string();
            if let Some(guild) = settings.guilds.get_mut(&key) {
                drop_nulls(guild);
            }
            write(&mut settings);
            if let Some(guild) = settings.guilds.get_mut(&key) {
                drop_nulls(guild);
            }
            if fail == Some("send") {
                failed()
            } else {
                vec![sent("response", &reply)]
            }
        }
    };
    // 書かなかった例は、置いた設定のまま（null も残る。Python も書いていないので、ファイルのまま読む）。
    (out, settings.guilds[&GUILD.to_string()].clone())
}

/// 全部の例で、送ったもの（順・応答かあとからか・本文・Embed・部品）と、終わったあとの設定が Python と同じであること。
#[test]
fn djaudio_commands_answer_like_python() {
    let mut count = 0;
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let (got_sent, got_after) = run(&row[0]);
        if Value::Array(got_sent.clone()) != row[1] {
            wrong.push(format!(
                "{} 送ったもの\n  Python: {}\n  Rust:   {}",
                row[0]["id"],
                row[1],
                Value::Array(got_sent)
            ));
        }
        if got_after != row[2] {
            wrong.push(format!(
                "{} 設定\n  Python: {}\n  Rust:   {got_after}",
                row[0]["id"], row[2]
            ));
        }
        count += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 件が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 70, "例が少ない: {count}");
}
