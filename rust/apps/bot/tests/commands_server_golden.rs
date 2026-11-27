//! サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）と補完が、本物の Python と同じ
//! 返事をし、設定を同じに書き換え、同じ候補を出すこと。
//!
//! 基準（`fixtures/commands/server_expected.jsonl`）は、本物の Python のコマンドと補完の関数を、記録するだけの
//! 偽物の interaction で呼んだもの（`generate_server.py`）。コマンドは、返事（本文・Embed・部品・本人にだけ
//! 見せるか）・返事の時点の設定・返事のあとの仕事（/sticky の貼る・剥がす）・すべて終わったあとの設定
//! （鍵の並びまで）を比べる。Python が例外で終わる設定（辞書のはずのところが文字列、など）では、Rust も
//! 失敗にすること（本物の Bot では、どちらも「処理できなかった」と返す）。
//!
//! 返事のあとの仕事のうち、Discord へ送るところ（固定メッセージを消して送り直す）は、ここでは同じ部品で
//! なぞるだけにして、本物の流れは `commands_server_discord.rs` が同じ基準と比べる。

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value, json};
use serenity::all::{ChannelType, CommandDataOption, CommandDataOptionValue, GuildId};
use sycs_bot::commands::guards::Standing;
use sycs_bot::commands::picker::Pickers;
use sycs_bot::commands::reply::Reply;
use sycs_bot::commands::server::{self, After, ChoiceInput, Place, python};
use sycs_bot::commands::{self, PlanInput, Planned};
use sycs_bot::sticky;
use sycs_core::settings::{Settings, drop_nulls};

const GUILD: u64 = 1_399_617_700_363_370_556;
const USER: u64 = 80_351_110_224_678_912;
/// コマンドが打たれたチャンネル（`generate_server.py` の `CHANNEL`）。
const CHANNEL: u64 = 1_505_310_388_051_251_000;
/// Bot が新しく送った固定メッセージ（`generate_server.py` の `NEW_MESSAGE`）。
const NEW_MESSAGE: u64 = 900;
/// 基準の中の、/news add が振った ID（本物は乱数）。
const FEED_ID: &str = "feedc0de";
const ADMIN_SITE_URL: &str = "https://admin.example/login";

fn fixture(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    std::fs::read_to_string(format!("{dir}/{name}")).unwrap()
}

/// 例の中の `{"repeat": "1", "times": 4300, "suffix": ""}` を、その長さの文字列に広げる。
fn expand(value: &Value) -> Value {
    let Some(unit) = value.get("repeat").and_then(Value::as_str) else {
        return value.clone();
    };
    let times = value["times"].as_u64().unwrap() as usize;
    let suffix = value["suffix"].as_str().unwrap_or("");
    json!(format!("{}{suffix}", unit.repeat(times)))
}

/// 引数を、Discord から届く形（種類の番号つき）にする。
fn options(case: &Value) -> Vec<CommandDataOption> {
    let mut list: Vec<Value> = case["options"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| match name.as_str() {
            // 7 はチャンネル、8 はロール（どちらも ID は文字列で届く）、4 は整数、3 は文字列。
            "channel" => json!({"name": name, "type": 7, "value": value.to_string()}),
            "role" => json!({"name": name, "type": 8, "value": value.to_string()}),
            "interval" => json!({"name": name, "type": 4, "value": value}),
            _ => json!({"name": name, "type": 3, "value": expand(value)}),
        })
        .collect();
    // 補完: 入力中の引数は、focused の印つきで届く。
    if let Some(focused) = case["focused"].as_str() {
        list.push(json!({"name": focused, "type": 3, "value": case["current"], "focused": true}));
    }
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

/// 部品を、比べる項目だけにする。Python の `view.to_components()` から取り出すものと同じ形。
fn components_json(reply: &Reply) -> Value {
    let rows = serde_json::to_value(&reply.components).unwrap();
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
                        "url": c["url"],
                        "disabled": c["disabled"].as_bool().unwrap_or(false),
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
        "components": components_json(reply),
    })
}

/// 設定を書き換える。`SettingsCache::transact` と同じ順（null を落とす → 書き換える → null を落とす）。
///
/// 先に落とすのは、鍵の並びに効く（null だった鍵は消えてから、末尾に足し直される）。
fn transact<T>(settings: &mut Settings, write: impl FnOnce(&mut Settings) -> T) -> T {
    let clean = |settings: &mut Settings| {
        for guild in settings.guilds.values_mut().filter(|g| g.is_object()) {
            drop_nulls(guild);
        }
    };
    clean(settings);
    let out = write(settings);
    clean(settings);
    out
}

fn stored(settings: &Settings) -> Value {
    settings.guilds[&GUILD.to_string()].clone()
}

/// 返事のあとの仕事をなぞる。したこと（古い固定メッセージを消す・新しく送る）と、仕事の名前を返す。
///
/// 貼る側の本体（`sticky::post_now`）は Discord に送るので、同じ部品（`entry_for`・`record_posted`）でなぞる。
fn after_work(settings: &mut Settings, after: After) -> (&'static str, Vec<Value>) {
    let mut effects = Vec::new();
    match after {
        After::PostSticky {
            guild_id,
            channel_id,
        } => {
            assert_eq!((guild_id, channel_id), (GUILD, CHANNEL));
            if let Some(entry) = sticky::entry_for(settings.guild(GUILD), CHANNEL) {
                if let Some(old) = entry.message_id {
                    effects.push(json!(["delete_old", old.to_string()]));
                }
                effects.push(json!(["send", format!("📌 {}", entry.content)]));
                transact(settings, |s| {
                    sticky::record_posted(s, GUILD, CHANNEL, NEW_MESSAGE)
                });
            }
            ("post", effects)
        }
        After::DeleteSticky {
            guild_id,
            channel_id,
        } => {
            assert_eq!((guild_id, channel_id), (GUILD, CHANNEL));
            if let Some(old) = server::sticky::message_to_delete(settings.guild(GUILD), CHANNEL) {
                effects.push(json!(["delete_old", old.to_string()]));
            }
            transact(settings, |s| server::sticky::remove(s, GUILD, CHANNEL));
            ("delete", effects)
        }
    }
}

/// /news add が振った ID（乱数）を、基準の中の決まった ID に置き換える。振った ID を返す。
fn pin_feed_id(before: &Value, reply: &mut Reply, snapshots: [&mut Value; 2]) -> Option<String> {
    let known: BTreeSet<&String> = before["news_feeds"]
        .as_object()
        .into_iter()
        .flat_map(Map::keys)
        .collect();
    let feeds = snapshots[1]["news_feeds"].as_object()?;
    let new_id = feeds.keys().find(|id| !known.contains(id))?.clone();
    for snapshot in snapshots {
        let Some(feeds) = snapshot["news_feeds"].as_object_mut() else {
            continue;
        };
        *feeds = std::mem::take(feeds)
            .into_iter()
            .map(|(id, feed)| {
                (
                    if id == new_id {
                        FEED_ID.to_string()
                    } else {
                        id
                    },
                    feed,
                )
            })
            .collect();
    }
    let content = reply.content.as_mut()?;
    *content = content.replace(&format!("ID: `{new_id}`"), &format!("ID: `{FEED_ID}`"));
    Some(new_id)
}

fn run_command(case: &Value) -> Value {
    let before = case["before"].clone();
    let mut settings = Settings::default();
    settings.guilds.insert(GUILD.to_string(), before.clone());
    let (standing, guild_id) = match case["who"].as_str().unwrap() {
        "admin" => (Standing::Admin, Some(GuildId::new(GUILD))),
        "member" => (Standing::Member, Some(GuildId::new(GUILD))),
        _ => (Standing::OutsideGuild, None),
    };
    let path = case["path"].as_str().unwrap();
    let route = commands::route(path).unwrap_or_else(|| panic!("移していないコマンド: {path}"));
    // 打たれたチャンネルの種類（番号）。テキストチャンネルかどうかは、本物と同じ関数で決める。
    let kind = ChannelType::from(case["channel_type"].as_u64().unwrap_or(0) as u8);
    let pickers = Pickers::default();
    let options = options(case);
    let input = PlanInput {
        standing,
        guild_id,
        user_id: USER,
        options: &options,
        guild_settings: Some(&before),
        pickers: &pickers,
        admin_site_url: ADMIN_SITE_URL,
        place: Place {
            channel_id: CHANNEL,
            is_text: server::is_text_kind(kind),
        },
    };
    let planned = match commands::plan(route, &input) {
        Ok(planned) => planned,
        // Python は例外で終わる（本物の Bot では、受け皿が「処理できなかった」と返す）。
        Err(_) => return json!([case["id"], {"error": true}, null, null, [], before]),
    };
    let (mut reply, after) = match planned {
        Planned::Reply(reply) => (*reply, None),
        Planned::Write(write) => (transact(&mut settings, write), None),
        Planned::ReplyThen(reply, after) => (*reply, Some(after)),
        Planned::WriteThen(write, after) => (transact(&mut settings, write), Some(after)),
    };
    let mut at_reply = stored(&settings);
    let (work, effects) = match after {
        Some(after) => {
            let (work, effects) = after_work(&mut settings, after);
            (json!(work), effects)
        }
        None => (Value::Null, Vec::new()),
    };
    let mut end = stored(&settings);
    if path == "news add"
        && let Some(id) = pin_feed_id(&before, &mut reply, [&mut at_reply, &mut end])
    {
        let hex = id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        assert!(id.len() == 8 && hex, "ID が 16 進 8 文字でない: {id}");
    }
    json!([case["id"], reply_json(&reply), at_reply, work, effects, end])
}

/// 例に書いた名前の表（ID → 名前）から引く関数。
fn names<'a>(table: &'a Value) -> impl Fn(u64) -> Option<String> + 'a {
    move |id| table.get(id.to_string())?.as_str().map(str::to_string)
}

fn run_autocomplete(case: &Value) -> Value {
    let options = options(case);
    // 入力中の引数は、ほかの引数と見分けられる形で読めていること（先に入れた引数として引かないように）。
    let focused = options.last().unwrap();
    assert!(
        matches!(focused.value, CommandDataOptionValue::Autocomplete { .. }),
        "{focused:?}"
    );
    let (role_name, channel_name) = (names(&case["roles"]), names(&case["channels"]));
    let input = ChoiceInput {
        in_guild: case["who"] != "dm",
        guild_settings: Some(&case["before"]),
        options: &options,
        role_name: &role_name,
        channel_name: &channel_name,
    };
    let path = case["path"].as_str().unwrap();
    let (name, current) = (
        case["focused"].as_str().unwrap(),
        case["current"].as_str().unwrap(),
    );
    match server::choices(path, name, current, &input) {
        Ok(Some(found)) => {
            let list: Vec<Value> = found.iter().map(|c| json!([c.name, c.value])).collect();
            json!([case["id"], list])
        }
        Ok(None) => panic!("補完を出さない引数: {path} {name}"),
        // Python は例外で終わる（何も返さない）。
        Err(_) => json!([case["id"], {"error": true}]),
    }
}

#[test]
fn server_commands_answer_write_and_suggest_like_python() {
    let cases: Vec<Value> = serde_json::from_str(&fixture("server_cases.json")).unwrap();
    let expected = fixture("server_expected.jsonl");
    let expected: Vec<&str> = expected.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(cases.len(), expected.len(), "基準と例の数が違う");
    let (mut commands, mut completions) = (0, 0);
    let mut wrong = Vec::new();
    for (case, want) in cases.iter().zip(expected) {
        let got = if case["focused"].is_string() {
            completions += 1;
            run_autocomplete(case)
        } else {
            commands += 1;
            run_command(case)
        };
        // 文字列で比べる（設定の鍵の並びまで同じであること）。
        let got = got.to_string();
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
    // 例が黙って減っていないこと（基準を作り直したときに、どちらかが空になっていないか）。
    assert!(
        commands >= 200 && completions >= 60,
        "{commands} {completions}"
    );
}

/// どの文字を空白・10 進の数字と見るかが、全部の文字について Python と同じであること。
///
/// 基準（`server_tables.json`）は、本物の Python に全部の文字を答えさせたもの（`generate_server_tables.py`）。
#[test]
fn spaces_and_digits_match_python_for_every_character() {
    let tables: Value = serde_json::from_str(&fixture("server_tables.json")).unwrap();
    let codes = |key: &str| -> Vec<u32> {
        let list = tables[key].as_array().unwrap();
        list.iter().map(|v| v.as_u64().unwrap() as u32).collect()
    };
    let spaces: BTreeSet<u32> = codes("spaces").into_iter().collect();
    let digits: HashMap<u32, u32> = codes("decimal_zeros")
        .into_iter()
        .flat_map(|zero| (0..10).map(move |value| (zero + value, value)))
        .collect();
    assert!(spaces.len() >= 29 && digits.len() >= 680);
    let mut checked = 0;
    for code in 0..=0x10_FFFF_u32 {
        // サロゲートは Rust の文字にならない（Python でも、空白でも数字でもない）。
        let Some(c) = char::from_u32(code) else {
            assert!(!spaces.contains(&code) && !digits.contains_key(&code));
            continue;
        };
        assert_eq!(python::is_space(c), spaces.contains(&code), "U+{code:04X}");
        assert_eq!(
            python::decimal_value(c),
            digits.get(&code).copied(),
            "U+{code:04X}"
        );
        checked += 1;
    }
    assert_eq!(checked, 0x11_0000 - 0x800);
}

/// 必須の引数が届いていなければ、書かずに失敗にすること（定義と食い違ったときの備え）。権限の無い人は、
/// 引数を見る前に断ること。
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
        place: Place {
            channel_id: CHANNEL,
            is_text: true,
        },
    };
    for path in [
        "greeting welcome channel",
        "greeting welcome message",
        "greeting goodbye channel",
        "greeting goodbye message",
        "vcnotify set",
        "sticky set",
        "reactionrole add",
        "reactionrole remove",
        "news add",
        "news remove",
    ] {
        let route = commands::route(path).unwrap();
        assert!(
            commands::plan(route, &input(Standing::Admin)).is_err(),
            "{path}"
        );
        let refused = commands::plan(route, &input(Standing::Member));
        assert!(matches!(refused, Ok(Planned::Reply(_))), "{path}");
    }
}

/// /reactionrole add は、引数が 1 つ欠けても書かないこと（どの引数も必須）。
#[test]
fn reactionrole_add_needs_all_three_options() {
    let all = json!([
        {"name": "message_id", "type": 3, "value": "111"},
        {"name": "emoji", "type": 3, "value": "👍"},
        {"name": "role", "type": 8, "value": "20"},
    ]);
    let pickers = Pickers::default();
    let plan = |options: &[CommandDataOption]| {
        let input = PlanInput {
            standing: Standing::Admin,
            guild_id: Some(GuildId::new(GUILD)),
            user_id: USER,
            options,
            guild_settings: None,
            pickers: &pickers,
            admin_site_url: ADMIN_SITE_URL,
            place: Place::default(),
        };
        commands::plan(commands::route("reactionrole add").unwrap(), &input)
    };
    let complete: Vec<CommandDataOption> = serde_json::from_value(all.clone()).unwrap();
    assert!(matches!(plan(&complete), Ok(Planned::Write(_))));
    for missing in 0..3 {
        let mut list = all.as_array().unwrap().clone();
        list.remove(missing);
        let partial: Vec<CommandDataOption> = serde_json::from_value(json!(list)).unwrap();
        assert!(plan(&partial).is_err(), "{missing} 番目が無い");
    }
}
