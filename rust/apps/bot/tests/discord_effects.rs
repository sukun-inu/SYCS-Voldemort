//! メッセージの検査が Discord へ実際に送るもの（HTTP の形と順番）を、テストの中に立てた偽物の Discord で確かめる。
//!
//! 「メッセージを消す・ロールを剥がす」は元に戻せず、本物の Discord では人を巻き込むので試せない。
//! serenity の送り先を偽物に向けて（`HttpBuilder::proxy`）、ここで確かめる:
//!
//! - serenity のメッセージとキャッシュから、検査の中身（[`Post`]）を discord.py と同じに組み立てること
//!   （メッセージに付いてくるロールを使う・低い順に並べる・サーバーに無いロールは捨てる）
//! - 危険な投稿で、進み具合の Embed → メッセージの削除 → ロールを低い順に 1 つずつ剥がす（権限が足りない
//!   ところで止まる）→ 結果の Embed → ログ、の順に送ること。剥がす理由が監査ログに付くこと
//!
//! 設定のキャッシュに Postgres が要る（`SYCS_TEST_DATABASE_URL`）。手元の `cargo test` では飛ばし、CI は
//! `--include-ignored` で必ず回す（`crates/sycs-core/tests/postgres.rs` と同じ）。

mod support;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use serenity::all::{Cache, Message, RoleId};
use sycs_bot::log_channel::{AvatarColours, LogSink};
use sycs_bot::message_security::{
    self, Assess, Context, DiscordEffects, Judges, Scan, post_from_message,
};
use sycs_bot::moderation::Verdict;
use sycs_bot::security::{RaidDetector, SpamDetector};
use sycs_bot::virustotal::VtResult;
use sycs_core::settings::SettingsCache;

use support::{Seen, user};

const GUILD: &str = "1399617700363370556";
const USER: &str = "80351110224678912";
const CHANNEL: &str = "1505310388051251000";
const LOG_CHANNEL: &str = "1505310388051251261";
const VOICE: &str = "777";
const GUILD_AVATAR: &str = "aaaabbbbccccddddeeeeffff00001111";

fn role(id: &str, position: i64) -> Value {
    support::role(id, position, 0)
}

fn voice_state(user_id: &str, channel_id: &str) -> Value {
    json!({
        "channel_id": channel_id, "user_id": user_id, "session_id": "s", "deaf": false,
        "mute": false, "self_deaf": false, "self_mute": false, "self_video": false,
        "suppress": false, "request_to_speak_timestamp": null,
    })
}

/// サーバー（ロールは位置がばらばら）。4242 の人は、キャッシュに無い VC（888）に入っていることになっている。
/// 読み込み済みのメンバーは、メッセージに付いてくるものと違うロールを持つ。
fn guild() -> Value {
    support::guild(
        GUILD,
        "1",
        // 低い順は 12（位置 1）→ 11（位置 3）→ 13（位置 5）→ 14（位置 7）。
        json!([
            role(GUILD, 0),
            role("11", 3),
            role("12", 1),
            role("13", 5),
            role("14", 7)
        ]),
        json!([{
            "user": user(USER, false), "nick": "古いニック", "avatar": GUILD_AVATAR, "roles": ["11"],
            "joined_at": "2026-01-01T00:00:00+00:00", "deaf": false, "mute": false, "flags": 0,
        }]),
        json!([
            support::text_channel(GUILD, CHANNEL, "general"),
            support::text_channel(GUILD, LOG_CHANNEL, "log"),
            {"id": VOICE, "type": 2, "guild_id": GUILD, "name": "vc", "position": 0,
             "permission_overwrites": [], "nsfw": false, "bitrate": 64000, "user_limit": 0,
             "rate_limit_per_user": 0},
        ]),
        json!([voice_state(USER, VOICE), voice_state("4242", "888")]),
    )
}

fn cache() -> Cache {
    support::cache_with(guild())
}

/// ゲートウェイから届く形のメッセージ。
fn message(author: Value, member: Value, content: &str) -> Message {
    let mut m = json!({
        "id": "5000", "channel_id": CHANNEL, "guild_id": GUILD, "author": author,
        "content": content, "timestamp": "2026-11-27T00:00:00+00:00", "edited_timestamp": null,
        "tts": false, "mention_everyone": false, "mentions": [], "mention_roles": [],
        "attachments": [], "embeds": [], "pinned": false, "type": 0,
    });
    if !member.is_null() {
        m["member"] = member;
    }
    serde_json::from_value(m).expect("メッセージの JSON")
}

fn member_payload() -> Value {
    json!({
        // 999 はサーバーに無いロール（捨てる）。並びはばらばら。
        "roles": ["13", "11", "999", "14", "12"], "joined_at": "2026-11-20T00:00:00.500000+00:00",
        "nick": "ニック", "deaf": false, "mute": false, "flags": 0,
    })
}

/// 偽物の Discord の答え方。メッセージの送信・書き換えにはメッセージを返し、削除は 204、ロール 13 だけ 403。
fn respond(method: &str, path: &str) -> (u16, String) {
    match method {
        "POST" | "PATCH" => (200, support::sent_message(LOG_CHANNEL)),
        "DELETE" if path.ends_with("/roles/13") => (
            403,
            r#"{"message": "Missing Permissions", "code": 50013}"#.into(),
        ),
        "DELETE" => (204, String::new()),
        _ => (404, r#"{"message": "unknown", "code": 0}"#.into()),
    }
}

/// メッセージに付いてくるメンバーの情報で組み立てること（ロールは低い順、無いロールは捨てる、アバターは
/// 読み込み済みのメンバーのもの）。Bot の発言と、メンバーでない作者は検査しない。
#[test]
fn the_post_is_built_like_discord_py() {
    let cache = cache();
    let msg = message(
        user(USER, false),
        member_payload(),
        "こんにちは https://a.example",
    );
    let post = post_from_message(&cache, &msg).expect("検査の対象");
    let ids: Vec<u64> = post.roles.iter().map(|r| r.get()).collect();
    assert_eq!(
        ids,
        [12, 11, 13, 14],
        "低い順・@everyone なし・無いロールなし"
    );
    let joined = post.joined_at.expect("参加日時");
    assert_eq!(joined.to_rfc3339(), "2026-11-20T00:00:00.500+00:00");
    assert_eq!(post.display_name, "ニック");
    assert_eq!(post.voice_channel, Some(777));
    assert_eq!(post.author.name, "nelly");
    assert_eq!(
        post.author.avatar_url,
        format!(
            "https://cdn.discordapp.com/guilds/{GUILD}/users/{USER}/avatars/{GUILD_AVATAR}.png?size=1024"
        )
    );
    assert_eq!(post.content, "こんにちは https://a.example");
    assert_eq!(
        (post.message_id.get(), post.channel_id.to_string()),
        (5000, CHANNEL.to_string())
    );

    // メンバーの情報が付いていなければ、読み込み済みのメンバーから。
    let cached_only =
        post_from_message(&cache, &message(user(USER, false), Value::Null, "x")).unwrap();
    assert_eq!(cached_only.roles, [RoleId::new(11)]);
    assert_eq!(cached_only.display_name, "古いニック");

    // Bot の発言・メンバーでない作者（付いてもいないし読み込んでもいない）・DM は検査しない。
    assert!(post_from_message(&cache, &message(user(USER, true), member_payload(), "x")).is_none());
    assert!(post_from_message(&cache, &message(user("4242", false), Value::Null, "x")).is_none());
    let mut dm = message(user(USER, false), Value::Null, "x");
    dm.guild_id = None;
    assert!(post_from_message(&cache, &dm).is_none());
    // 読み込んでいないが、メッセージにメンバーの情報が付いている人は検査する（discord.py と同じ）。
    let fresh =
        post_from_message(&cache, &message(user("4242", false), member_payload(), "x")).unwrap();
    // キャッシュに無い VC は「入っていない」（discord.py の member.voice.channel が None になる）。
    assert_eq!(fresh.voice_channel, None);
    assert!(
        fresh.author.avatar_url.contains("/embed/avatars/"),
        "{}",
        fresh.author.avatar_url
    );
}

/// VirusTotal が危険（12）と答える投稿を、この設定のサーバーで検査して、偽物の Discord が受けた要求を返す。
async fn check_a_dangerous_post(guild_settings: Value) -> Vec<Seen> {
    let (base, seen) = support::start_fake_discord(respond).await;
    let http = support::http_to(&base);
    let cache = cache();
    let pool = support::settings_pool(GUILD, &guild_settings).await;
    let settings = SettingsCache::start(pool, Duration::from_secs(60))
        .await
        .unwrap();
    let colours = AvatarColours::new();

    let msg = message(
        user(USER, false),
        member_payload(),
        "見て https://bad.example/x",
    );
    let post = post_from_message(&cache, &msg).unwrap();
    let scan: Scan = Arc::new(|_| {
        Box::pin(async {
            VtResult {
                status: "ok".into(),
                kind: "url".into(),
                malicious: 12,
                suspicious: 0,
                reason: None,
            }
        })
    });
    let assess: Assess = Arc::new(|_| Box::pin(async { Verdict::Safe }));
    let judges = Judges {
        scan,
        assess,
        scan_concurrency: 4,
    };
    let (spam, raid) = (SpamDetector::default(), RaidDetector::default());
    let snapshot = settings.snapshot();
    let cx = Context {
        settings: snapshot.guild(GUILD.parse().unwrap()),
        spam: &spam,
        raid: &raid,
        judges: &judges,
        clock: message_security::system_clock,
    };
    let fx = DiscordEffects {
        sink: LogSink {
            cache: &cache,
            http: &http,
            settings: &settings,
            colours: &colours,
        },
        post: &post,
    };
    message_security::check_message(&fx, &cx, &post).await;
    seen.lock().unwrap().clone()
}

fn methods_and_paths(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .map(|s| format!("{} {}", s.method, s.path))
        .collect()
}

fn strip(id: &str) -> String {
    format!("DELETE /api/v10/guilds/{GUILD}/members/{USER}/roles/{id}")
}

/// 危険な投稿で Discord へ送るものと、その順番。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_dangerous_post_is_deleted_and_roles_are_stripped_lowest_first() {
    let log_channel: u64 = LOG_CHANNEL.parse().unwrap();
    let seen =
        check_a_dangerous_post(json!({"log_channel_id": log_channel, "log_level": "INFO"})).await;
    let calls = methods_and_paths(&seen);
    let log = format!("/api/v10/channels/{LOG_CHANNEL}/messages");
    assert_eq!(
        calls,
        [
            format!("POST {log}"),
            format!("PATCH {log}/900"),
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000"),
            // 低い順に 1 つずつ。13 で権限が足りずに止まり、その上の 14 には手を出さない。
            strip("12"),
            strip("11"),
            strip("13"),
            format!("PATCH {log}/900"),
            format!("POST {log}"),
        ],
        "{calls:#?}"
    );
    let title = |i: usize| {
        seen[i].body["embeds"][0]["title"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    let description = |i: usize| {
        seen[i].body["embeds"][0]["description"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    assert_eq!(title(0), "セキュリティ検査中");
    assert_eq!(description(0), "VirusTotal解析中…");
    assert_eq!(description(1), "VirusTotal解析中… [##########] 1/1");
    // 剥がす理由が監査ログに付く（URL の形に直した「セキュリティ違反」）。
    let reason = "%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E9%81%95%E5%8F%8D";
    for s in &seen[3..6] {
        assert_eq!(
            s.reason.as_deref().map(str::to_uppercase).as_deref(),
            Some(reason),
            "{s:?}"
        );
    }
    assert_eq!(
        seen[2].reason, None,
        "メッセージの削除には理由を付けない（Python と同じ）"
    );
    assert_eq!(title(6), "危険な投稿を検出");
    assert_eq!(seen[6].body["embeds"][0]["color"], 0xE7_4C_3C);
    assert!(
        description(6).contains(
            "[ALERT] https://bad.example/x をスキャン: status=ok Malicious=12 Suspicious=0"
        ),
        "{}",
        description(6)
    );
    let last = &seen[7].body["embeds"][0];
    assert_eq!(last["title"], "[ERROR] ボットログ");
    assert_eq!(last["description"], "メッセージセキュリティ検査");
    assert_eq!(last["color"], 0xE7_4C_3C);
    assert_eq!(last["author"]["name"], "nelly");
    assert_eq!(last["fields"][0]["value"], "VT_DANGEROUS, GPT:SAFE");
    assert_eq!(last["fields"][2]["value"], "1");
}

/// ログチャンネルが無くても・ログを止めていても、消す・剥がすは行うこと（報告できないことを理由に見逃さない）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn enforcement_does_not_depend_on_the_log_channel() {
    let log_channel: u64 = LOG_CHANNEL.parse().unwrap();
    for guild_settings in [
        json!({}),
        json!({"log_channel_id": log_channel, "log_level": "NONE"}),
        // ログチャンネルが別のサーバーのもの（このサーバーに無い）。
        json!({"log_channel_id": 42, "log_level": "INFO"}),
    ] {
        let seen = check_a_dangerous_post(guild_settings.clone()).await;
        assert_eq!(
            methods_and_paths(&seen),
            [
                format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000"),
                strip("12"),
                strip("11"),
                strip("13"),
            ],
            "{guild_settings}"
        );
    }
}
