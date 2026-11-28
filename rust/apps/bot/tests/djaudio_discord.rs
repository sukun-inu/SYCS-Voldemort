//! DJAudio の Discord への働きかけ（[`DiscordOutlet`]）が、discord.py と同じ形の要求を送ること。
//!
//! 送り先をテストの中の偽物の Discord に向けて確かめる: リアクションを付ける・自分のものを外す（`@me`）、返信の
//! 形（discord.py の `message.reply(..., mention_author=False)` と同じく、返信の印にメッセージ・チャンネル・サーバー、
//! 許可に @everyone・利用者・ロールと「返信先には通知しない」）、出力チャンネルへの送信（返信の印も許可も付けない）、
//! Discord に断られたとき（`HTTPException`）とそれ以外の分け方、出力チャンネルの見え方（無い・送れる・カテゴリ）。

use serde_json::json;
use serenity::all::CreateEmbed;
use sycs_bot::djaudio::DiscordOutlet;
use sycs_bot::djaudio::flow::{DiscordError, Outlet, OutputChannel};

mod support;

const GUILD: &str = "1399617700363370556";
const CHANNEL: &str = "1505310388051251000";
const OUTPUT: &str = "1505310388051251261";
const CATEGORY: &str = "1505310388051251300";
const MESSAGE: u64 = 5001;

fn respond(method: &str, path: &str) -> (u16, String) {
    match method {
        // 2 つ目のリアクション（✅）は断られる。
        "PUT" if path.contains("%E2%9C%85") => (
            403,
            json!({"message": "Missing Permissions", "code": 50013}).to_string(),
        ),
        "PUT" | "DELETE" => (204, String::new()),
        "POST" => {
            let channel = path
                .trim_start_matches("/api/v10/channels/")
                .split('/')
                .next()
                .unwrap_or("");
            (200, support::sent_message(channel))
        }
        _ => (404, json!({"message": "unknown", "code": 0}).to_string()),
    }
}

fn cache() -> serenity::cache::Cache {
    let mut category = support::text_channel(GUILD, CATEGORY, "cat");
    category["type"] = json!(4);
    support::cache_with(support::guild(
        GUILD,
        "1",
        json!([support::role(GUILD, 0, 0)]),
        json!([]),
        json!([
            support::text_channel(GUILD, CHANNEL, "watch"),
            support::text_channel(GUILD, OUTPUT, "out"),
            category
        ]),
        json!([]),
    ))
}

/// リアクション・返信・送信の要求が、discord.py と同じ形であること。
#[tokio::test]
async fn requests_have_the_discord_py_shape() {
    let (base, seen) = support::start_fake_discord(respond).await;
    let http = support::http_to(&base);
    let cache = cache();
    let outlet = DiscordOutlet {
        http: &http,
        cache: &cache,
        guild_id: GUILD.parse().unwrap(),
        channel_id: CHANNEL.parse().unwrap(),
        message_id: MESSAGE,
    };
    outlet.add_reaction("⏳").await.unwrap();
    outlet.remove_own_reaction("⏳").await.unwrap();
    assert!(matches!(
        outlet.add_reaction("✅").await,
        Err(DiscordError::Refused(_))
    ));
    let sent = outlet.reply(Some("❌ だめ".into()), None).await.unwrap();
    assert_eq!(sent, (CHANNEL.parse().unwrap(), 900));
    outlet
        .send(
            OUTPUT.parse().unwrap(),
            CreateEmbed::new().title("🎵 MP3 の準備が整った"),
        )
        .await
        .unwrap();

    let seen = seen.lock().unwrap().clone();
    let at = |i: usize| (seen[i].method.as_str(), seen[i].path.as_str());
    let reaction =
        format!("/api/v10/channels/{CHANNEL}/messages/{MESSAGE}/reactions/%E2%8F%B3/@me");
    assert_eq!(at(0), ("PUT", reaction.as_str()));
    assert_eq!(at(1), ("DELETE", reaction.as_str()));
    let post = format!("/api/v10/channels/{CHANNEL}/messages");
    assert_eq!(at(3), ("POST", post.as_str()));
    let body = &seen[3].body;
    assert_eq!(body["content"], "❌ だめ");
    assert_eq!(body["message_reference"]["message_id"], MESSAGE.to_string());
    assert_eq!(body["message_reference"]["channel_id"], CHANNEL);
    assert_eq!(body["message_reference"]["guild_id"], GUILD);
    assert_eq!(body["allowed_mentions"]["replied_user"], false);
    let mut parse: Vec<String> = body["allowed_mentions"]["parse"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    parse.sort();
    assert_eq!(parse, ["everyone", "roles", "users"]);
    let out = format!("/api/v10/channels/{OUTPUT}/messages");
    assert_eq!(at(4), ("POST", out.as_str()));
    assert_eq!(seen[4].body["embeds"][0]["title"], "🎵 MP3 の準備が整った");
    assert_eq!(seen[4].body.get("message_reference"), None);
    assert_eq!(seen[4].body.get("allowed_mentions"), None);
}

/// 出力チャンネルは、キャッシュに無ければ「無い」、カテゴリは「送れない」、テキストは「送れる」であること。
#[tokio::test]
async fn output_channels_are_looked_up_in_the_cache() {
    let http = support::http_to("http://127.0.0.1:9");
    let cache = cache();
    let outlet = DiscordOutlet {
        http: &http,
        cache: &cache,
        guild_id: 1,
        channel_id: 2,
        message_id: 3,
    };
    let id = |s: &str| s.parse::<u64>().unwrap();
    assert_eq!(
        outlet.output_channel(id(OUTPUT)),
        OutputChannel::Messageable(id(OUTPUT))
    );
    assert_eq!(
        outlet.output_channel(id(CATEGORY)),
        OutputChannel::NotMessageable(id(CATEGORY))
    );
    assert_eq!(outlet.output_channel(42), OutputChannel::Missing);
}

/// 通信が切れたとき（Discord に断られたのではないとき）は、断られたのとは別の失敗にすること。
#[tokio::test]
async fn transport_errors_are_not_refusals() {
    let http = support::http_to("http://127.0.0.1:9");
    let cache = cache();
    let outlet = DiscordOutlet {
        http: &http,
        cache: &cache,
        guild_id: 1,
        channel_id: 2,
        message_id: 3,
    };
    assert!(
        matches!(outlet.add_reaction("⏳").await, Err(DiscordError::Other(_))),
        "通信の失敗"
    );
}
