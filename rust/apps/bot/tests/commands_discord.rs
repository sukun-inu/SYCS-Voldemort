//! スラッシュコマンドが Discord へ実際に返すもの（HTTP の形）と、設定の表への書き込みを確かめる。
//!
//! 本物の Discord では試せない: 本番の Bot（Python）も同じコマンドに応えるので、打つと本番の設定が
//! 書き換わる。serenity の送り先をテストの中の偽物の Discord に向けて確かめる（`support`）。
//!
//! 設定のキャッシュに Postgres が要る（`SYCS_TEST_DATABASE_URL`）。手元の `cargo test` では飛ばし、CI は
//! `--include-ignored` で必ず回す。

mod support;

use std::time::Duration;

use serde_json::{Value, json};
use serenity::all::{ApplicationId, CommandInteraction};
use sycs_bot::commands;
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

/// コマンドを 1 つ打って、偽物の Discord が受けた要求と、そのあとのサーバーの設定を返す。
async fn dispatch(command: CommandInteraction, before: Value) -> (Vec<Seen>, Value) {
    let (base, seen) = support::start_fake_discord(respond).await;
    let http = support::http_to(&base);
    let cache = support::cache_with(guild());
    let pool = support::settings_pool(GUILD, &before).await;
    let settings = SettingsCache::start(pool, Duration::from_secs(60))
        .await
        .unwrap();
    commands::dispatch(&settings, &cache, &http, &command).await;
    let after = settings
        .snapshot()
        .guild(GUILD.parse().unwrap())
        .cloned()
        .unwrap_or(Value::Null);
    let seen = seen.lock().unwrap().clone();
    (seen, after)
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
