//! メッセージの検査が Discord へ実際に送るもの（HTTP の形と順番）を、テストの中に立てた偽物の Discord で確かめる。
//!
//! 「メッセージを消す・ロールを剥がす」は元に戻せず、本物の Discord では人を巻き込むので試せない。
//! serenity の送り先を偽物に向けて（`HttpBuilder::proxy`）、ここで確かめる:
//!
//! - serenity のメッセージとキャッシュから、検査の中身（[`Post`]）を discord.py と同じに組み立てること
//!   （メッセージに付いてくるロールを使う・低い順に並べる・サーバーに無いロールは捨てる）
//! - 危険な投稿で、進み具合の Embed → メッセージの削除 → ロールを低い順に 1 つずつ剥がす（権限が足りない
//!   ところで止まる）→ 結果の Embed → ログ（剥がせたロールと残ったロールも）、の順に送ること。剥がす理由が
//!   監査ログに付くこと（Bot にタイムアウトの権限が無いサーバー）
//! - Bot にタイムアウトの権限があれば、ロールの代わりに `PATCH /guilds/{g}/members/{u}` の
//!   `communication_disabled_until`（24 時間あと）でタイムアウトすること。断られたらロールは剥がさないこと（S1）
//! - スパムだけなら、スパムと数えた投稿を 1 件ずつ消し（既に消えていても止めない）、10 分のタイムアウト（S2）
//! - VC の荒らしの数に入った全員に、最初に入った順で措置して 1 人ずつ報告すること（S4）
//!
//! 設定のキャッシュに Postgres が要る（`SYCS_TEST_DATABASE_URL`）。手元の `cargo test` では飛ばし、CI は
//! `--include-ignored` で必ず回す（`crates/sycs-core/tests/postgres.rs` と同じ）。

mod support;

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use serenity::all::{Cache, GuildId, Message, RoleId, UserId};
use sycs_bot::log_channel::{Author, AvatarColours, LogSink};
use sycs_bot::message_security::{
    self, Assess, Context, DiscordEffects, Judges, Post, Scan, post_from_message,
};
use sycs_bot::moderation::Verdict;
use sycs_bot::security::{self, RaidDetector, RaidTarget, SecurityConfig, SpamDetector, SpamInput};
use sycs_bot::virustotal::VtResult;
use sycs_core::settings::SettingsCache;

use support::{Seen, user};

const GUILD: &str = "1399617700363370556";
const USER: &str = "80351110224678912";
const CHANNEL: &str = "1505310388051251000";
/// スパムの確かめで、前の投稿があった別のチャンネル（キャッシュには無くてよい。ID で消すだけ）。
const OTHER_CHANNEL: &str = "1505310388051251999";
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

/// 偽物の Discord が、メンバーの書き換え（タイムアウト）に返すメンバー。
fn member_json(path: &str) -> String {
    let id = path.rsplit('/').next().unwrap_or("1");
    json!({
        "user": user(id, false), "roles": [], "joined_at": "2026-01-01T00:00:00+00:00",
        "deaf": false, "mute": false, "flags": 0,
    })
    .to_string()
}

/// [`respond`] に、タイムアウト（`PATCH /guilds/{g}/members/{u}`）を受け付けることを足したもの。
fn respond_with_member(method: &str, path: &str) -> (u16, String) {
    if method == "PATCH" && path.contains("/members/") {
        return (200, member_json(path));
    }
    respond(method, path)
}

/// タイムアウトを権限不足（403）で断る偽物。
fn refuse_timeouts(method: &str, path: &str) -> (u16, String) {
    if method == "PATCH" && path.contains("/members/") {
        let body = r#"{"message": "Missing Permissions", "code": 50013}"#;
        return (403, body.into());
    }
    respond(method, path)
}

/// スパムの確かめ用。前の投稿 100 は既に消えている（404）。タイムアウトは受け付ける。
fn respond_for_spam(method: &str, path: &str) -> (u16, String) {
    if method == "DELETE" && path.ends_with("/messages/100") {
        let body = r#"{"message": "Unknown Message", "code": 10008}"#;
        return (404, body.into());
    }
    respond_with_member(method, path)
}

/// この設定のサーバーで `post` を検査して、偽物の Discord が受けた要求を返す。VirusTotal はどの URL も
/// `malicious` と答え、Groq はいつも SAFE。`spam` は前の投稿を入れたスパムの記録。
async fn check_on_fake(
    guild_settings: Value,
    responder: support::Responder,
    post: &Post,
    malicious: i64,
    spam: &SpamDetector,
) -> Vec<Seen> {
    let (base, seen) = support::start_fake_discord(responder).await;
    let http = support::http_to(&base);
    let cache = cache();
    let pool = support::settings_pool(GUILD, &guild_settings).await;
    let settings = SettingsCache::start(pool, Duration::from_secs(60))
        .await
        .unwrap();
    let colours = AvatarColours::new();
    let scan: Scan = Arc::new(move |_| {
        Box::pin(async move {
            VtResult {
                status: "ok".into(),
                kind: "url".into(),
                malicious,
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
    let raid = RaidDetector::default();
    let config = SecurityConfig::default();
    let snapshot = settings.snapshot();
    let cx = Context {
        settings: snapshot.guild(GUILD.parse().unwrap()),
        config: &config,
        spam,
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
        post,
    };
    message_security::check_message(&fx, &cx, post).await;
    seen.lock().unwrap().clone()
}

/// VirusTotal が危険（12）と答える投稿を、この設定のサーバーで検査して、偽物の Discord が受けた要求を返す。
/// Bot のメンバーはキャッシュに無いので、タイムアウトの権限は無い扱い（ロールを剥がす）。
async fn check_a_dangerous_post(guild_settings: Value) -> Vec<Seen> {
    let cache = cache();
    let msg = message(
        user(USER, false),
        member_payload(),
        "見て https://bad.example/x",
    );
    let post = post_from_message(&cache, &msg).unwrap();
    assert!(!post.bot_can_timeout, "権限があることにした");
    let spam = SpamDetector::default();
    check_on_fake(guild_settings, respond, &post, 12, &spam).await
}

fn methods_and_paths(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .map(|s| format!("{} {}", s.method, s.path))
        .collect()
}

fn strip(id: &str) -> String {
    format!("DELETE /api/v10/guilds/{GUILD}/members/{USER}/roles/{id}")
}

fn log_settings() -> Value {
    let log_channel: u64 = LOG_CHANNEL.parse().unwrap();
    json!({"log_channel_id": log_channel, "log_level": "INFO"})
}

/// [`log_settings`] に、タイムアウトの切り替えを有効にしたもの（設定の既定は無効）。
fn timeout_settings() -> Value {
    let mut settings = log_settings();
    settings["security_timeout_enabled"] = json!(true);
    settings
}

/// 前の投稿を 2 件（100 は 30 秒前にこのチャンネル、101 は 10 秒前に別のチャンネル）入れたスパムの記録。
/// どちらも「限定セール」なので、同じ本文の投稿で 3 回目（スパム）になる。
fn spam_with_two_prior_posts() -> SpamDetector {
    let spam = SpamDetector::default();
    let now = message_security::system_clock();
    for (channel, message_id, ago) in [(CHANNEL, 100, 30.0), (OTHER_CHANNEL, 101, 10.0)] {
        let input = SpamInput {
            guild_id: GUILD.parse().unwrap(),
            user_id: USER.parse().unwrap(),
            channel_id: channel.parse().unwrap(),
            message_id,
            content: "限定セール",
            attachments: &[],
        };
        spam.check(&input, now - ago);
    }
    spam
}

/// 監査ログの理由（URL の形に直した「セキュリティ違反」）。
const REASON: &str = "%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E9%81%95%E5%8F%8D";

fn reason_of(s: &Seen) -> Option<String> {
    s.reason.as_deref().map(str::to_uppercase)
}

/// タイムアウトの期限が、送った前後の時刻から `seconds` 秒あとの間にあること（遅い環境でも落ちない）。
fn assert_until(s: &Seen, seconds: i64, before: DateTime<Utc>, after: DateTime<Utc>) {
    let until = s.body["communication_disabled_until"].as_str().unwrap();
    let until = DateTime::parse_from_rfc3339(until).unwrap();
    let span = TimeDelta::seconds(seconds);
    let slack = TimeDelta::seconds(1);
    assert!(
        until >= before + span - slack,
        "{until} < {before} + {seconds}"
    );
    assert!(
        until <= after + span + slack,
        "{until} > {after} + {seconds}"
    );
}

/// 危険な投稿で Discord へ送るものと、その順番（Bot にタイムアウトの権限が無いサーバー）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_dangerous_post_is_deleted_and_roles_are_stripped_lowest_first() {
    let seen = check_a_dangerous_post(log_settings()).await;
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
    // 剥がす理由が監査ログに付く。
    for s in &seen[3..6] {
        assert_eq!(reason_of(s).as_deref(), Some(REASON), "{s:?}");
    }
    assert_eq!(
        seen[2].reason, None,
        "メッセージの削除には理由を付けない（Python と同じ）"
    );
    // 見出しは取った措置から（S8）。権限が無いのでロールを外した。外せないロールが残ったので一部失敗。
    assert_eq!(title(6), "消してロールを外した（一部失敗）");
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
    assert_eq!(last["fields"][4]["name"], "措置");
    assert_eq!(last["fields"][5]["name"], "消した投稿");
    assert_eq!(last["fields"][5]["value"], "1件");
    // 剥がした結果（剥がせた 12・11 と、権限が足りずに残った 13・14）も出す（rust-09 の (i)）。
    assert_eq!(last["fields"][6]["name"], "剥がしたロール");
    assert_eq!(last["fields"][6]["value"], "<@&12> <@&11>");
    assert_eq!(
        last["fields"][7]["name"],
        "剥がせなかったロール（権限不足）"
    );
    assert_eq!(last["fields"][7]["value"], "<@&13> <@&14>");
}

/// タイムアウトの切り替えが有効で、Bot に権限があれば、危険な投稿を消して 24 時間のタイムアウト（ロールは
/// 剥がさない。S1）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_dangerous_post_times_the_author_out_for_a_day() {
    let cache = cache();
    let msg = message(user(USER, false), member_payload(), "https://bad.example");
    let mut post = post_from_message(&cache, &msg).unwrap();
    post.bot_can_timeout = true;
    let before = Utc::now();
    let spam = SpamDetector::default();
    let seen = check_on_fake(timeout_settings(), respond_with_member, &post, 12, &spam).await;
    let after = Utc::now();
    let log = format!("/api/v10/channels/{LOG_CHANNEL}/messages");
    assert_eq!(
        methods_and_paths(&seen),
        [
            format!("POST {log}"),
            format!("PATCH {log}/900"),
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000"),
            format!("PATCH /api/v10/guilds/{GUILD}/members/{USER}"),
            format!("PATCH {log}/900"),
            format!("POST {log}"),
        ]
    );
    assert_until(&seen[3], 86_400, before, after);
    assert_eq!(reason_of(&seen[3]).as_deref(), Some(REASON));
    assert_eq!(
        seen[4].body["embeds"][0]["title"],
        "消して 24 時間のタイムアウト"
    );
    let fields = &seen[5].body["embeds"][0]["fields"];
    assert_eq!(fields[4]["value"], "消して 24 時間のタイムアウト");
    assert_eq!(fields[6]["name"], "タイムアウト");
    assert_eq!(fields[6]["value"], "24 時間");
}

/// タイムアウトが断られても、ロールを剥がすことは試さない（同じ理由で失敗する）。失敗として報告する。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_refused_timeout_is_not_followed_by_stripping() {
    let cache = cache();
    let msg = message(user(USER, false), member_payload(), "https://bad.example");
    let mut post = post_from_message(&cache, &msg).unwrap();
    post.bot_can_timeout = true;
    let spam = SpamDetector::default();
    let seen = check_on_fake(timeout_settings(), refuse_timeouts, &post, 12, &spam).await;
    let calls = methods_and_paths(&seen);
    assert!(!calls.iter().any(|c| c.contains("/roles/")), "{calls:#?}");
    assert_eq!(
        calls[3],
        format!("PATCH /api/v10/guilds/{GUILD}/members/{USER}")
    );
    let fields = &seen.last().unwrap().body["embeds"][0]["fields"];
    assert_eq!(
        fields[4]["value"],
        "消して 24 時間のタイムアウト（一部失敗）"
    );
    assert_eq!(fields[6]["name"], "タイムアウトできなかった（権限不足）");
}

/// スパムだけなら、スパムと数えた投稿を 1 件ずつ消し（既に消えていても止めない）、10 分のタイムアウト（S2。
/// タイムアウトの切り替えが有効なサーバー）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn spam_posts_are_deleted_one_by_one_and_the_author_timed_out_for_ten_minutes() {
    let cache = cache();
    let msg = message(user(USER, false), member_payload(), "限定セール");
    let mut post = post_from_message(&cache, &msg).unwrap();
    post.bot_can_timeout = true;
    let spam = spam_with_two_prior_posts();
    let before = Utc::now();
    let seen = check_on_fake(timeout_settings(), respond_for_spam, &post, 0, &spam).await;
    let after = Utc::now();
    let log = format!("/api/v10/channels/{LOG_CHANNEL}/messages");
    assert_eq!(
        methods_and_paths(&seen),
        [
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/100"),
            format!("DELETE /api/v10/channels/{OTHER_CHANNEL}/messages/101"),
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000"),
            format!("PATCH /api/v10/guilds/{GUILD}/members/{USER}"),
            format!("POST {log}"),
            format!("POST {log}"),
        ]
    );
    assert_until(&seen[3], 600, before, after);
    let result = &seen[4].body["embeds"][0];
    assert_eq!(result["title"], "消して 10 分のタイムアウト");
    assert_eq!(result["color"], 0xE6_7E_22);
    let fields = &seen[5].body["embeds"][0]["fields"];
    assert_eq!(fields[3]["value"], "3", "スパム回数");
    // 既に消えていた 1 件（100）も、消した数に入る。
    assert_eq!(fields[5]["value"], "3件");
    assert_eq!(fields[6]["value"], "10 分");
}

/// タイムアウトの切り替えが無効（既定）なら、Bot に権限があってもタイムアウトせず、いまどおりロールを低い順に
/// 剥がす。報告にタイムアウトの項目は出さない（2026-11-28 の追加の決定）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn without_the_switch_roles_are_stripped_even_with_the_permission() {
    let cache = cache();
    let msg = message(user(USER, false), member_payload(), "https://bad.example");
    let mut post = post_from_message(&cache, &msg).unwrap();
    post.bot_can_timeout = true;
    let spam = SpamDetector::default();
    let seen = check_on_fake(log_settings(), respond_with_member, &post, 12, &spam).await;
    let calls = methods_and_paths(&seen);
    let timeout = format!("PATCH /api/v10/guilds/{GUILD}/members/{USER}");
    assert!(!calls.contains(&timeout), "{calls:#?}");
    let delete = format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000");
    assert_eq!(calls[2], delete);
    assert_eq!(
        calls[3..6],
        [strip("12"), strip("11"), strip("13")],
        "{calls:#?}"
    );
    let fields = &seen.last().unwrap().body["embeds"][0]["fields"];
    assert_eq!(fields[4]["value"], "消してロールを外した（一部失敗）");
    assert_eq!(fields[6]["name"], "剥がしたロール");
    let names: Vec<&str> = fields
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    let timed = names.iter().any(|n| n.contains("タイムアウト"));
    assert!(!timed, "{names:?}");
}

/// タイムアウトの切り替えが無効（既定）なら、スパムだけのときは、Bot に権限があっても消すだけ。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn without_the_switch_spam_is_only_deleted_even_with_the_permission() {
    let cache = cache();
    let msg = message(user(USER, false), member_payload(), "限定セール");
    let mut post = post_from_message(&cache, &msg).unwrap();
    post.bot_can_timeout = true;
    let spam = spam_with_two_prior_posts();
    let seen = check_on_fake(log_settings(), respond_for_spam, &post, 0, &spam).await;
    let log = format!("/api/v10/channels/{LOG_CHANNEL}/messages");
    assert_eq!(
        methods_and_paths(&seen),
        [
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/100"),
            format!("DELETE /api/v10/channels/{OTHER_CHANNEL}/messages/101"),
            format!("DELETE /api/v10/channels/{CHANNEL}/messages/5000"),
            format!("POST {log}"),
            format!("POST {log}"),
        ]
    );
    let result = &seen[3].body["embeds"][0];
    assert_eq!(result["title"], "消した");
    assert_eq!(result["color"], 0xE6_7E_22);
}

/// VC の荒らしの数に入った全員に、最初に入った順で 24 時間のタイムアウトをし、1 人ずつ報告する（S1・S4）。
/// 権限が無ければ、1 人ずつロールを剥がす。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn everyone_counted_in_a_vc_raid_is_acted_on_in_join_order() {
    let (base, seen) = support::start_fake_discord(respond_with_member).await;
    let http = support::http_to(&base);
    let cache = cache();
    let pool = support::settings_pool(GUILD, &log_settings()).await;
    let settings = SettingsCache::start(pool, Duration::from_secs(60))
        .await
        .unwrap();
    let colours = AvatarColours::new();
    let sink = LogSink {
        cache: &cache,
        http: &http,
        settings: &settings,
        colours: &colours,
    };
    let raid = RaidDetector::default();
    for (i, user_id) in (4000..4004).enumerate() {
        assert!(raid.check(777, user_id, i as f64).is_empty());
    }
    let counted = raid.check(777, 4004, 4.0);
    assert_eq!(counted, [4000, 4001, 4002, 4003, 4004]);
    let targets: Vec<RaidTarget> = counted
        .iter()
        .map(|&id| RaidTarget {
            user_id: UserId::new(id),
            roles: vec![RoleId::new(11)],
            author: Author {
                id,
                name: format!("raider{id}"),
                avatar_url: String::new(),
            },
        })
        .collect();
    let guild = GuildId::new(GUILD.parse().unwrap());
    let before = Utc::now();
    security::act_on_vc_raid(&sink, guild, 777, &targets, true, 86_400).await;
    let after = Utc::now();
    let log = format!("POST /api/v10/channels/{LOG_CHANNEL}/messages");
    let mut want = Vec::new();
    for id in &counted {
        want.push(format!("PATCH /api/v10/guilds/{GUILD}/members/{id}"));
        want.push(log.clone());
    }
    let calls = methods_and_paths(&seen.lock().unwrap());
    assert_eq!(calls, want);
    let seen_now = seen.lock().unwrap().clone();
    assert_until(&seen_now[0], 86_400, before, after);
    let report = &seen_now[1].body["embeds"][0];
    assert_eq!(report["description"], "VCレイド検出");
    assert_eq!(report["fields"][0]["value"], "<#777>");
    assert_eq!(report["fields"][1]["name"], "タイムアウト");
    assert_eq!(report["fields"][1]["value"], "24 時間");

    // 権限が無ければ、1 人ずつロールを剥がす。
    seen.lock().unwrap().clear();
    security::act_on_vc_raid(&sink, guild, 777, &targets[..2], false, 86_400).await;
    let calls = methods_and_paths(&seen.lock().unwrap());
    assert_eq!(
        calls,
        [
            format!("DELETE /api/v10/guilds/{GUILD}/members/4000/roles/11"),
            log.clone(),
            format!("DELETE /api/v10/guilds/{GUILD}/members/4001/roles/11"),
            log,
        ]
    );
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
