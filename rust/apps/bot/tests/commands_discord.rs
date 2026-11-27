//! スラッシュコマンドが Discord へ実際に返すもの（HTTP の形）と、設定の表への書き込みを確かめる。
//!
//! 本物の Discord では試せない: 本番の Bot（Python）も同じコマンドに応えるので、打つと本番の設定が
//! 書き換わる。serenity の送り先をテストの中の偽物の Discord に向けて確かめる（`support`）。
//!
//! 設定のキャッシュに Postgres が要る（`SYCS_TEST_DATABASE_URL`）。手元の `cargo test` では飛ばし、CI は
//! `--include-ignored` で必ず回す。

mod support;

use std::time::Duration;

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use serenity::all::{ApplicationId, Cache, CommandInteraction, ComponentInteraction, Http};
use sycs_bot::commands;
use sycs_bot::commands::picker::Pickers;
use sycs_core::settings::SettingsCache;

use support::{Seen, user};

const GUILD: &str = "1399617700363370556";
const OWNER: &str = "80351110224678912";
const SOMEONE: &str = "4242";
const CHANNEL: &str = "1505310388051251000";
const LOG_CHANNEL: &str = "1505310388051251261";
const APP: &str = "1350672236612288633";
const ADMINISTRATOR: u64 = 1 << 3;

fn respond(method: &str, path: &str) -> (u16, String) {
    match method {
        "POST" if path.contains("/interactions/") => (204, String::new()),
        "PUT" if path.ends_with("/commands") => (200, "[]".into()),
        _ => (404, r#"{"message": "unknown", "code": 0}"#.into()),
    }
}

/// サーバー。20 は管理者のロール、21 は何の権限も無いロール。
fn guild() -> Value {
    support::guild(
        GUILD,
        OWNER,
        json!([
            support::role(GUILD, 0, 0),
            support::role("20", 2, ADMINISTRATOR),
            support::role("21", 1, 0)
        ]),
        json!([]),
        json!([
            support::text_channel(GUILD, CHANNEL, "general"),
            support::text_channel(GUILD, LOG_CHANNEL, "log")
        ]),
        json!([]),
    )
}

/// ゲートウェイから届く形の、打たれたコマンド。
fn interaction(user_id: &str, roles: Value, data: Value) -> CommandInteraction {
    serde_json::from_value(json!({
        "id": "7000", "application_id": APP, "type": 2, "data": data,
        "guild_id": GUILD, "channel_id": CHANNEL,
        "member": {
            "user": user(user_id, false), "roles": roles, "nick": "ニック",
            "joined_at": "2026-01-01T00:00:00+00:00", "deaf": false, "mute": false,
            "flags": 0, "permissions": "0",
        },
        "token": "tok", "version": 1, "app_permissions": "0", "locale": "ja",
        "guild_locale": "ja", "entitlements": [], "authorizing_integration_owners": {},
        "attachment_size_limit": 10485760,
    }))
    .expect("コマンドの JSON")
}

fn log_channel_data() -> Value {
    json!({
        "id": "8000", "name": "log", "type": 1,
        "options": [{"name": "channel", "type": 1, "options": [
            {"name": "channel", "type": 7, "value": LOG_CHANNEL}
        ]}],
        "resolved": {"channels": {LOG_CHANNEL: {
            "id": LOG_CHANNEL, "name": "log", "type": 0, "permissions": "0"
        }}},
    })
}

/// 偽物の Discord・キャッシュ・設定の表をそろえた場。コマンドと部品の応答を続けて流せる。
struct Stage {
    http: Http,
    cache: Cache,
    settings: Arc<SettingsCache>,
    pickers: Pickers,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Stage {
    async fn new(before: &Value) -> Self {
        let (base, seen) = support::start_fake_discord(respond).await;
        let pool = support::settings_pool(GUILD, before).await;
        Self {
            http: support::http_to(&base),
            cache: support::cache_with(guild()),
            settings: SettingsCache::start(pool, Duration::from_secs(60))
                .await
                .unwrap(),
            pickers: Pickers::default(),
            seen,
        }
    }

    fn deps(&self) -> commands::Deps<'_> {
        commands::Deps {
            settings: &self.settings,
            cache: &self.cache,
            http: &self.http,
            pickers: &self.pickers,
            admin_site_url: "https://admin.example/login",
        }
    }

    /// 偽物の Discord が受けた要求（これまでの全部）。
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// そのサーバーのいまの設定。
    fn guild_settings(&self) -> Value {
        self.settings
            .snapshot()
            .guild(GUILD.parse().unwrap())
            .cloned()
            .unwrap_or(Value::Null)
    }
}

/// コマンドを 1 つ打って、偽物の Discord が受けた要求と、そのあとのサーバーの設定を返す。
async fn dispatch(command: CommandInteraction, before: Value) -> (Vec<Seen>, Value) {
    let stage = Stage::new(&before).await;
    commands::dispatch(&stage.deps(), &command).await;
    (stage.seen(), stage.guild_settings())
}

/// ゲートウェイから届く形の、触られた部品（`component_type` 5 はユーザーの選択、2 はボタン）。
fn component(
    id: &str,
    user_id: &str,
    custom_id: &str,
    kind: u8,
    values: Value,
) -> ComponentInteraction {
    let mut data = json!({"custom_id": custom_id, "component_type": kind});
    if !values.is_null() {
        data["values"] = values;
    }
    serde_json::from_value(json!({
        "id": id, "application_id": APP, "type": 3, "data": data,
        "guild_id": GUILD, "channel_id": CHANNEL,
        "member": {
            "user": user(user_id, false), "roles": [], "nick": null,
            "joined_at": "2026-01-01T00:00:00+00:00", "deaf": false, "mute": false,
            "flags": 0, "permissions": "0",
        },
        "message": serde_json::from_str::<Value>(&support::sent_message(CHANNEL)).unwrap(),
        "token": "tok", "version": 1, "app_permissions": "0", "locale": "ja",
        "guild_locale": "ja", "entitlements": [], "authorizing_integration_owners": {},
        "attachment_size_limit": 10485760,
    }))
    .expect("部品の JSON")
}

/// 返事は 1 回だけ、最初の応答（種類 4）として、本人にだけ見える形（flags 64）で送ること。
fn only_reply(seen: &[Seen]) -> &Value {
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/api/v10/interactions/7000/tok/callback");
    assert_eq!(seen[0].body["type"], 4);
    assert_eq!(seen[0].body["data"]["flags"], 64);
    &seen[0].body["data"]["content"]
}

/// 持ち主が打つと、設定を書いて返事すること。書いたギルドには時刻が押されること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn an_admin_command_writes_the_setting_and_replies() {
    let command = interaction(OWNER, json!([]), log_channel_data());
    let (seen, after) = dispatch(command, json!({"log_level": "debug"})).await;
    assert_eq!(
        only_reply(&seen),
        &json!(format!(
            "<#{LOG_CHANNEL}> を余のログチャンネルと定めた。ログレベル: DEBUG"
        ))
    );
    assert_eq!(after["log_channel_id"], LOG_CHANNEL.parse::<u64>().unwrap());
    assert_eq!(after["log_level"], "debug");
    assert!(after["_updated_at"].is_string(), "{after}");
}

/// 管理者のロールを持つ人も打てること。権限の無い人は断り、設定に触らないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn only_administrators_may_change_settings() {
    let by_role = interaction(SOMEONE, json!(["21", "20"]), log_channel_data());
    let (seen, after) = dispatch(by_role, json!({})).await;
    assert!(
        only_reply(&seen)
            .as_str()
            .unwrap()
            .contains("ログチャンネルと定めた"),
        "{seen:#?}"
    );
    assert_eq!(after["log_channel_id"], LOG_CHANNEL.parse::<u64>().unwrap());

    let before = json!({"log_level": "INFO"});
    let no_right = interaction(SOMEONE, json!(["21"]), log_channel_data());
    let (seen, after) = dispatch(no_right, before.clone()).await;
    assert_eq!(
        only_reply(&seen),
        "管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。"
    );
    assert_eq!(after, before, "断ったのに設定を書いた");
}

/// まだ移していないコマンドには、その旨を返して何も書かないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn commands_not_ported_yet_say_so() {
    let data = json!({
        "id": "8001", "name": "sticky", "type": 1,
        "options": [{"name": "list", "type": 1, "options": []}],
    });
    let before = json!({"sticky": {}});
    let (seen, after) = dispatch(interaction(OWNER, json!([]), data), before.clone()).await;
    assert_eq!(
        only_reply(&seen),
        "❌ このコマンドはまだ使えぬ。しばし待て。"
    );
    assert_eq!(after, before);
}

/// 登録は、定義の全体をそのまま送ること（Python の Bot が同期しているものと同じ中身）。
#[tokio::test]
async fn sync_sends_the_whole_definitions() {
    let (base, seen) = support::start_fake_discord(respond).await;
    let http = support::http_to(&base);
    http.set_application_id(ApplicationId::new(APP.parse().unwrap()));
    assert_eq!(commands::sync(&http).await.unwrap(), 0);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(
        seen[0].path,
        format!("/api/v10/applications/{APP}/commands")
    );
    assert_eq!(seen[0].body, commands::definitions());
    assert_eq!(seen[0].body.as_array().unwrap().len(), 17);
}

/// 選択の画面: 開く → 選ぶ（確定のボタンに件数が出る）→ 確定で設定を書いて、画面を結果に置き換えること。
/// 本人でない人が触っても選べないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_picker_writes_only_on_confirm() {
    let stage = Stage::new(&json!({"trusted_user_ids": [20]})).await;
    let open = json!({
        "id": "8002", "name": "trusted", "type": 1,
        "options": [{"name": "add", "type": 1, "options": []}],
    });
    commands::dispatch(&stage.deps(), &interaction(OWNER, json!([]), open)).await;
    let opened = stage.seen();
    let rows = &opened[0].body["data"]["components"];
    assert_eq!(opened[0].body["data"]["flags"], 64);
    assert_eq!(rows[0]["components"][0]["type"], 5, "ユーザーの選択の部品");
    assert_eq!(
        rows[1]["components"][0]["disabled"], true,
        "選ぶ前は確定を押せない"
    );
    let select_id = rows[0]["components"][0]["custom_id"]
        .as_str()
        .unwrap()
        .to_string();
    let confirm_id = rows[1]["components"][0]["custom_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 本人でない人が選んでも、本人にだけ見える断りが返るだけ。
    let intruder = component("7001", SOMEONE, &select_id, 5, json!(["99"]));
    commands::component(&stage.deps(), &intruder).await;
    let refused = &stage.seen()[1];
    assert_eq!(refused.path, "/api/v10/interactions/7001/tok/callback");
    assert_eq!(refused.body["type"], 4);
    assert_eq!(
        refused.body["data"]["flags"], 64,
        "断りの文は、触った本人にだけ見せる"
    );
    assert_eq!(
        refused.body["data"]["content"],
        "貴様にその操作の権限はない。"
    );

    // 選ぶ: 画面を書き換える（種類 7）。確定のボタンに件数が出て、押せるようになる。まだ書かない。
    let select = component("7002", OWNER, &select_id, 5, json!(["30", "10"]));
    commands::component(&stage.deps(), &select).await;
    let redrawn = &stage.seen()[2];
    assert_eq!(redrawn.body["type"], 7);
    let button = &redrawn.body["data"]["components"][1]["components"][0];
    assert_eq!(button["label"], "確定（2件）");
    assert_eq!(button["disabled"], false);
    assert_eq!(
        stage.guild_settings()["trusted_user_ids"],
        json!([20]),
        "確定の前に書いた"
    );

    // 確定: 設定を書き、本文を結果に置き換えて部品を外す。
    let confirm = component("7003", OWNER, &confirm_id, 2, Value::Null);
    commands::component(&stage.deps(), &confirm).await;
    let done = &stage.seen()[3];
    assert_eq!(done.body["type"], 7);
    assert_eq!(
        done.body["data"]["content"],
        "余の信頼を与えた: <@30>, <@10>\n（信頼済みユーザー数: 3）"
    );
    assert_eq!(done.body["data"]["components"], json!([]));
    assert_eq!(
        stage.guild_settings()["trusted_user_ids"],
        json!([10, 20, 30])
    );

    // 確定のあとは、同じ画面のボタンを押しても何も起きない。
    commands::component(
        &stage.deps(),
        &component("7004", OWNER, &confirm_id, 2, Value::Null),
    )
    .await;
    assert_eq!(stage.seen().len(), 4);
    // この Bot の画面でない部品には応えない。
    commands::component(
        &stage.deps(),
        &component("7005", OWNER, "other:thing", 2, Value::Null),
    )
    .await;
    assert_eq!(stage.seen().len(), 4);
}

/// ロールを選ぶ画面（/bypass remove）: ロールの選択の部品（種類 6）で選んだものを、確定で外すこと。
/// 登録されていないロールを選んでいても、失敗にしないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_bypass_picker_reads_role_selections() {
    let stage = Stage::new(&json!({"bypass_role_ids": [20, 30, 40]})).await;
    let open = json!({
        "id": "8003", "name": "bypass", "type": 1,
        "options": [{"name": "remove", "type": 1, "options": []}],
    });
    commands::dispatch(&stage.deps(), &interaction(OWNER, json!([]), open)).await;
    let opened = stage.seen();
    let rows = &opened[0].body["data"]["components"];
    assert_eq!(rows[0]["components"][0]["type"], 6, "ロールの選択の部品");
    let select_id = rows[0]["components"][0]["custom_id"]
        .as_str()
        .unwrap()
        .to_string();
    let confirm_id = rows[1]["components"][0]["custom_id"]
        .as_str()
        .unwrap()
        .to_string();

    let select = component("7010", OWNER, &select_id, 6, json!(["30", "99"]));
    commands::component(&stage.deps(), &select).await;
    let redrawn = &stage.seen()[1];
    assert_eq!(redrawn.body["type"], 7);
    assert_eq!(
        redrawn.body["data"]["components"][1]["components"][0]["label"],
        "確定（2件）"
    );

    let confirm = component("7011", OWNER, &confirm_id, 2, Value::Null);
    commands::component(&stage.deps(), &confirm).await;
    let done = &stage.seen()[2];
    assert_eq!(
        done.body["data"]["content"],
        "バイパスロールから除いた: <@&30>, <@&99>\n（バイパスロール数: 2）"
    );
    assert_eq!(stage.guild_settings()["bypass_role_ids"], json!([20, 40]));
}

/// /bot settings は Embed と管理画面へのリンクのボタンを、/bot help は誰にでもコマンドの一覧を返すこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn bot_settings_and_help_reply_with_embeds_and_a_link() {
    let data = |sub: &str| {
        json!({"id": "8003", "name": "bot", "type": 1,
               "options": [{"name": sub, "type": 1, "options": []}]})
    };
    let before = json!({"log_level": "ERROR", "trusted_user_ids": [5]});
    let (seen, after) = dispatch(
        interaction(OWNER, json!([]), data("settings")),
        before.clone(),
    )
    .await;
    let body = &seen[0].body["data"];
    assert_eq!(body["flags"], 64);
    assert_eq!(body["embeds"][0]["title"], "余の現在の設定だ");
    assert_eq!(body["embeds"][0]["fields"][1]["value"], "ERROR");
    assert_eq!(body["embeds"][0]["fields"][3]["value"], "<@5>");
    let link = &body["components"][0]["components"][0];
    assert_eq!(link["style"], 5);
    assert_eq!(link["url"], "https://admin.example/login");
    assert_eq!(after, before, "読むだけのコマンドが設定を書いた");

    let (seen, _) = dispatch(interaction(SOMEONE, json!(["21"]), data("help")), json!({})).await;
    let body = &seen[0].body["data"];
    assert_eq!(body["embeds"].as_array().unwrap().len(), 3);
    assert_eq!(body["embeds"][0]["title"], "余が授けたコマンドの一覧");
    assert_eq!(
        body["components"][0]["components"][0]["label"],
        "⚙️ Web管理画面を開く"
    );
}
