//! サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）が Discord へ実際に返すもの
//! （HTTP の形と順番）と、設定の表への書き込みを確かめる。
//!
//! 本物の Discord では試せない（本番の Bot も同じコマンドに応えるので、打つと本番の設定が書き換わる）。
//! serenity の送り先をテストの中の偽物の Discord に向けて確かめる（`support`）。
//!
//! - /sticky set・clear: **返事を送ってから**、固定メッセージを消す・送り直す・設定を書く。したことと終わった
//!   あとの設定を、本物の Python から作った基準（`server_expected.jsonl`）と比べる
//! - 補完: 候補を種類 8 の応答で返す。ロールとチャンネルの名前はキャッシュから引く
//! - 打たれたチャンネルの種類は、キャッシュ → コマンドに付いてきたもの、の順に見る
//!
//! 設定のキャッシュに Postgres が要る（`SYCS_TEST_DATABASE_URL`）。手元の `cargo test` では飛ばし、CI は
//! `--include-ignored` で必ず回す。

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use serenity::all::{Cache, CommandInteraction, Http};
use sqlx::PgPool;
use sycs_bot::commands;
use sycs_bot::commands::picker::Pickers;
use sycs_bot::commands::quake::Screens;
use sycs_bot::log_channel::AvatarColours;
use sycs_bot::metal::{MetalConfig, MetalPrices};
use sycs_bot::sticky::StickyLocks;
use sycs_bot::tts::TtsApi;
use sycs_bot::tts_voice::{NoVoice, Speaker};
use sycs_core::env::Env;
use sycs_core::settings::SettingsCache;

use support::{Seen, user};

const GUILD: &str = "1399617700363370556";
const OWNER: &str = "80351110224678912";
const SOMEONE: &str = "4242";
/// コマンドが打たれたチャンネル（基準の `CHANNEL`）。キャッシュのサーバーには、わざと入れていない。
const CHANNEL: &str = "1505310388051251000";
const NEWS_CHANNEL: &str = "500";
const APP: &str = "1350672236612288633";
const CALLBACK: &str = "/api/v10/interactions/7000/tok/callback";

fn respond(method: &str, path: &str) -> (u16, String) {
    let gone = r#"{"message": "Unknown Message", "code": 10008}"#;
    match method {
        // 7999 は、Discord が応答を受け付けない interaction。
        "POST" if path.contains("/interactions/7999/") => {
            (500, r#"{"message": "boom", "code": 0}"#.into())
        }
        "POST" if path.contains("/interactions/") => (204, String::new()),
        // 556 と 560 は、もう無い固定メッセージ（基準の `old_message: missing` の例の ID）。
        "DELETE" if path.ends_with("/messages/556") || path.ends_with("/messages/560") => {
            (404, gone.into())
        }
        "DELETE" if path.contains("/messages/") => (204, String::new()),
        // Bot が送った固定メッセージ（ID は 900。基準の `NEW_MESSAGE`）。
        "POST" if path.ends_with("/messages") => (200, support::sent_message(CHANNEL)),
        _ => (404, r#"{"message": "unknown", "code": 0}"#.into()),
    }
}

/// サーバー。20 は管理者のロール、21 は何の権限も無いロール。チャンネルは、ニュースの送り先と `extra`。
fn guild(extra: Value, threads: Value) -> Value {
    let mut channels = vec![support::text_channel(GUILD, NEWS_CHANNEL, "ニュース")];
    channels.extend(extra.as_array().into_iter().flatten().cloned());
    let mut guild = support::guild(
        GUILD,
        OWNER,
        json!([
            support::role(GUILD, 0, 0),
            support::role("20", 2, 1 << 3),
            support::role("21", 1, 0)
        ]),
        json!([]),
        json!(channels),
        json!([]),
    );
    guild["threads"] = threads;
    guild
}

/// サーバーのチャンネル（種類つき）。
fn channel_of(id: &str, kind: u64) -> Value {
    let mut channel = support::text_channel(GUILD, id, "打たれた場所");
    channel["type"] = json!(kind);
    channel
}

/// 偽物の Discord・キャッシュ・設定の表をそろえた場。設定を入れ替えながら、続けてコマンドを流せる。
struct Stage {
    http: Http,
    cache: Cache,
    pool: PgPool,
    settings: Arc<SettingsCache>,
    pickers: Pickers,
    sticky_locks: StickyLocks,
    quake_screens: Screens,
    metal: MetalPrices,
    colours: AvatarColours,
    tts: TtsApi,
    speaker: Speaker,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Stage {
    async fn new(before: &Value) -> Self {
        Self::with_guild(before, guild(json!([]), json!([]))).await
    }

    async fn with_guild(before: &Value, guild: Value) -> Self {
        let (base, seen) = support::start_fake_discord(respond).await;
        let pool = support::settings_pool(GUILD, before).await;
        Self {
            http: support::http_to(&base),
            cache: support::cache_with(guild),
            settings: SettingsCache::start(pool.clone(), Duration::from_secs(60))
                .await
                .unwrap(),
            pool,
            pickers: Pickers::default(),
            sticky_locks: StickyLocks::default(),
            quake_screens: Screens::default(),
            metal: MetalPrices::new(MetalConfig::from_env(&Env::from_fn(|_| None))),
            colours: AvatarColours::new(),
            tts: TtsApi::new("http://127.0.0.1:9"),
            speaker: Speaker::new(Arc::new(NoVoice)),
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
            sticky_locks: &self.sticky_locks,
            quake_screens: &self.quake_screens,
            metal: &self.metal,
            colours: &self.colours,
            metals_site_url: "https://metals.example/",
            tts: &self.tts,
            speaker: &self.speaker,
        }
    }

    /// 表の設定を、そのまま（null も残して）入れ替える。別のプロセスが書いたのと同じ形にして、読み直させる。
    async fn store(&self, guild_settings: &Value) {
        sqlx::query("UPDATE bot_settings_guild SET data = $1::jsonb WHERE guild_key = $2")
            .bind(guild_settings.to_string())
            .bind(GUILD)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE bot_settings_state SET version = version + 1 WHERE id = 1")
            .execute(&self.pool)
            .await
            .unwrap();
        self.settings.refresh_if_newer(None).await;
        assert_eq!(
            &self.cached(),
            guild_settings,
            "入れ替えた設定を読めていない"
        );
    }

    /// 手元の設定（Bot が読むもの）。
    fn cached(&self) -> Value {
        let snapshot = self.settings.snapshot();
        let guild = snapshot.guild(GUILD.parse().unwrap());
        guild.cloned().unwrap_or(Value::Null)
    }

    /// 表に書かれている設定（書き換えの時刻は外す）。手元の設定と同じであることも確かめる。
    async fn saved(&self) -> Value {
        let table = sycs_core::settings::load(&self.pool).await.unwrap();
        let mut saved = table.guilds[GUILD].clone();
        assert_eq!(saved, self.cached(), "表と手元の設定が違う");
        if let Some(map) = saved.as_object_mut() {
            map.remove("_updated_at");
        }
        saved
    }

    /// これまでに偽物の Discord が受けた要求の数。
    fn mark(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// `mark` よりあとに偽物の Discord が受けた要求。
    fn since(&self, mark: usize) -> Vec<Seen> {
        self.seen.lock().unwrap()[mark..].to_vec()
    }

    /// コマンドを 1 つ打って、偽物の Discord が受けた要求を返す。
    async fn dispatch(&self, command: &CommandInteraction) -> Vec<Seen> {
        let mark = self.mark();
        commands::dispatch(&self.deps(), command).await;
        self.since(mark)
    }

    /// 補完の問い合わせを 1 つ送って、偽物の Discord が受けた要求を返す。
    async fn autocomplete(&self, interaction: &CommandInteraction) -> Vec<Seen> {
        let mark = self.mark();
        commands::autocomplete(&self.deps(), interaction).await;
        self.since(mark)
    }
}

/// 打った人（admin は持ち主、member は権限の無い人、dm はサーバーの外）と、打たれたチャンネルの種類。
struct Sender<'a> {
    who: &'a str,
    /// コマンドに付いてくるチャンネルの種類。`None` なら付けない（キャッシュにあるものだけが頼り）。
    channel_type: Option<u64>,
    /// interaction の ID（応答の道すじに入る）。
    id: &'a str,
}

impl Sender<'static> {
    fn admin() -> Self {
        Self {
            who: "admin",
            channel_type: Some(0),
            id: "7000",
        }
    }

    fn member() -> Self {
        Self {
            who: "member",
            ..Self::admin()
        }
    }
}

/// 道すじ（`greeting welcome channel`）と末端の引数から、ゲートウェイから届く形のコマンドの中身を作る。
fn data(path: &str, leaf: Value) -> Value {
    let mut names: Vec<&str> = path.split(' ').collect();
    let mut options = leaf;
    while names.len() > 1 {
        let name = names.pop().unwrap();
        // 末端はサブコマンド（1）、その外側はグループ（2）。
        let kind = if options.as_array().is_some_and(|o| {
            o.first()
                .is_some_and(|first| matches!(first["type"].as_u64(), Some(1 | 2)))
        }) {
            2
        } else {
            1
        };
        options = json!([{"name": name, "type": kind, "options": options}]);
    }
    json!({"id": "8000", "name": names[0], "type": 1, "options": options})
}

/// ゲートウェイから届く形の、打たれたコマンド（`kind` 2）か、補完の問い合わせ（`kind` 4）。
fn interaction(kind: u8, from: &Sender<'_>, data: Value) -> CommandInteraction {
    let mut v = json!({
        "id": from.id, "application_id": APP, "type": kind, "data": data,
        "channel_id": CHANNEL,
        "token": "tok", "version": 1, "app_permissions": "0", "locale": "ja",
        "entitlements": [], "authorizing_integration_owners": {},
        "attachment_size_limit": 10485760,
    });
    if let Some(channel_type) = from.channel_type {
        v["channel"] = json!({"id": CHANNEL, "type": channel_type, "name": "打たれた場所", "permissions": "0"});
    }
    if from.who == "dm" {
        v["user"] = user(OWNER, false);
    } else {
        let (user_id, roles) = match from.who {
            "admin" => (OWNER, json!([])),
            _ => (SOMEONE, json!(["21"])),
        };
        v["guild_id"] = json!(GUILD);
        v["guild_locale"] = json!("ja");
        v["member"] = json!({
            "user": user(user_id, false), "roles": roles, "nick": null,
            "joined_at": "2026-01-01T00:00:00+00:00", "deaf": false, "mute": false,
            "flags": 0, "permissions": "0",
        });
    }
    serde_json::from_value(v).expect("interaction の JSON")
}

fn command(from: &Sender<'_>, path: &str, leaf: Value) -> CommandInteraction {
    interaction(2, from, data(path, leaf))
}

fn text(name: &str, value: &str) -> Value {
    json!({"name": name, "type": 3, "value": value})
}

/// 最初の応答: 1 回目の要求が、種類 4・本人にだけ見える形（flags 64）であること。本文を返す。
fn reply_of(seen: &[Seen]) -> &Value {
    assert!(!seen.is_empty(), "返事を送っていない");
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", CALLBACK)
    );
    assert_eq!(seen[0].body["type"], 4, "{:#?}", seen[0]);
    assert_eq!(seen[0].body["data"]["flags"], 64);
    &seen[0].body["data"]["content"]
}

/// 返事だけを送ったこと（ほかに何も送っていない）。本文を返す。
fn only_reply(seen: &[Seen]) -> &Value {
    assert_eq!(seen.len(), 1, "{seen:#?}");
    reply_of(seen)
}

/// 返事のあとにチャンネルへしたことを、基準と同じ形（消す・送る）にする。
fn effects_of(seen: &[Seen]) -> Value {
    let messages = format!("/api/v10/channels/{CHANNEL}/messages");
    let list: Vec<Value> = seen
        .iter()
        .map(
            |s| match (s.method.as_str(), s.path.strip_prefix(&messages)) {
                ("DELETE", Some(id)) => json!(["delete_old", id.trim_start_matches('/')]),
                ("POST", Some("")) => json!(["send", s.body["content"]]),
                _ => panic!("思っていない要求: {s:#?}"),
            },
        )
        .collect();
    json!(list)
}

fn fixture(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/commands");
    std::fs::read_to_string(format!("{dir}/{name}")).unwrap()
}

/// /sticky set・clear: 返事を送ってから貼る・剥がすこと。返事・チャンネルへしたこと・終わったあとの設定が、
/// 本物の Python（基準）と同じであること。打たれたチャンネルの種類は、コマンドに付いてきたもので見分ける。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn sticky_set_and_clear_work_after_the_reply_like_python() {
    let cases: Vec<Value> = serde_json::from_str(&fixture("server_cases.json")).unwrap();
    let expected = fixture("server_expected.jsonl");
    let stage = Stage::new(&json!({})).await;
    let mut checked = 0;
    for (case, want) in cases.iter().zip(expected.lines()) {
        let path = case["path"].as_str().unwrap();
        if !matches!(path, "sticky set" | "sticky clear") {
            continue;
        }
        let want: Value = serde_json::from_str(want).unwrap();
        let id = case["id"].as_str().unwrap();
        assert_eq!(want[0], case["id"]);
        stage.store(&case["before"]).await;
        let from = Sender {
            who: case["who"].as_str().unwrap(),
            channel_type: Some(case["channel_type"].as_u64().unwrap_or(0)),
            id: "7000",
        };
        let leaf: Vec<Value> = case["options"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| text(name, value.as_str().unwrap()))
            .collect();
        let seen = stage.dispatch(&command(&from, path, json!(leaf))).await;
        // 返事が先。そのあとに、古い固定メッセージを消す・新しく送る。
        assert_eq!(reply_of(&seen), &want[1]["content"], "{id}");
        assert_eq!(effects_of(&seen[1..]), want[4], "{id}");
        // 設定は、鍵の並びを問わずに比べる（表の JSONB は並びを保たない）。
        assert_eq!(stage.saved().await, want[5], "{id}");
        checked += 1;
    }
    assert!(checked >= 30, "/sticky の例が減っている: {checked}");
}

/// /sticky set のあと、貼ったメッセージの ID が表に書き戻り、時刻が押されること。次の set は、それを消してから
/// 貼ること（発言のたびの貼り直しと同じ流れに乗っている）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_second_sticky_set_replaces_the_first_post() {
    let stage = Stage::new(&json!({"log_level": "INFO"})).await;
    let set = |content: &str| {
        command(
            &Sender::admin(),
            "sticky set",
            json!([text("content", content)]),
        )
    };
    let seen = stage.dispatch(&set("一回目")).await;
    assert_eq!(reply_of(&seen), "スティッキーメッセージを刻んだ。");
    assert_eq!(effects_of(&seen[1..]), json!([["send", "📌 一回目"]]));
    let after = stage.cached();
    assert_eq!(
        after["sticky_messages"][CHANNEL],
        json!({"content": "一回目", "message_id": 900})
    );
    assert!(after["_updated_at"].is_string(), "{after}");
    assert_eq!(after["log_level"], "INFO");

    let seen = stage.dispatch(&set("二回目")).await;
    assert_eq!(
        effects_of(&seen[1..]),
        json!([["delete_old", "900"], ["send", "📌 二回目"]])
    );
    // 管理者でない人の clear は断り、何もしない。
    let clear = command(&Sender::member(), "sticky clear", json!([]));
    let seen = stage.dispatch(&clear).await;
    assert_eq!(
        only_reply(&seen),
        "管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。"
    );
    assert_eq!(
        stage.cached()["sticky_messages"][CHANNEL]["content"],
        "二回目"
    );
}

/// 打たれたチャンネルの種類は、まずキャッシュのサーバーから引くこと（discord.py と同じ順）。キャッシュに
/// 無ければコマンドに付いてきたもの、どちらにも無ければテキストチャンネルではないとみなす。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_channel_kind_comes_from_the_cache_first() {
    const REFUSED: &str = "テキストチャンネルでのみ使えるぞ。";
    const DONE: &str = "スティッキーメッセージを取り除いた。";
    let attached = |channel_type| Sender {
        channel_type,
        ..Sender::admin()
    };
    let clear = |from: &Sender<'_>| command(from, "sticky clear", json!([]));
    // キャッシュでは VC。コマンドにはテキストと付いてきても、キャッシュを信じる。
    let voice = Stage::with_guild(
        &json!({}),
        guild(json!([channel_of(CHANNEL, 2)]), json!([])),
    )
    .await;
    assert_eq!(
        only_reply(&voice.dispatch(&clear(&attached(Some(0)))).await),
        REFUSED
    );
    // キャッシュではテキスト。コマンドに何も付いてこなくても通る。
    let known = Stage::with_guild(
        &json!({}),
        guild(json!([channel_of(CHANNEL, 0)]), json!([])),
    )
    .await;
    assert_eq!(
        reply_of(&known.dispatch(&clear(&attached(None))).await),
        DONE
    );
    assert_eq!(
        reply_of(&known.dispatch(&clear(&attached(Some(2)))).await),
        DONE
    );
    // キャッシュではスレッド。
    let thread = Stage::with_guild(
        &json!({}),
        guild(json!([]), json!([channel_of(CHANNEL, 11)])),
    )
    .await;
    assert_eq!(
        only_reply(&thread.dispatch(&clear(&attached(Some(0)))).await),
        REFUSED
    );
    // どちらにも無い。
    let unknown = Stage::new(&json!({})).await;
    assert_eq!(
        only_reply(&unknown.dispatch(&clear(&attached(None))).await),
        REFUSED
    );
    assert_eq!(
        reply_of(&unknown.dispatch(&clear(&attached(Some(5)))).await),
        DONE
    );
}

/// 返事を送れなかったら、返事のあとの仕事をしないこと（Python も、そこで止まる）。設定は書かれているので、
/// 貼る指示は残り、定期の巡回が拾う。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn no_work_after_a_reply_that_could_not_be_sent() {
    let stage = Stage::new(&json!({})).await;
    let refused = Sender {
        id: "7999",
        ..Sender::admin()
    };
    let set = command(&refused, "sticky set", json!([text("content", "貼れない")]));
    let seen = stage.dispatch(&set).await;
    // 返事 → 失敗の知らせ、の 2 回だけ（どちらも受け付けられない）。チャンネルには送らない。
    assert_eq!(seen.len(), 2, "{seen:#?}");
    for s in &seen {
        assert_eq!(s.path, "/api/v10/interactions/7999/tok/callback");
    }
    assert_eq!(
        seen[0].body["data"]["content"],
        "スティッキーメッセージを刻んだ。"
    );
    assert_eq!(
        seen[1].body["data"]["content"],
        "❌ 余の力をもってしても処理できなかった。しばし待って試せ。"
    );
    assert_eq!(
        stage.saved().await,
        json!({"sticky_messages": {CHANNEL: {"content": "貼れない", "pending": "post"}}})
    );
}

/// 返事が長すぎて送れないとき（本文は 2000 文字まで）は、「処理できなかった」と返すこと。設定は書かれている
/// （Python も、書いてから返事を送る）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_reply_too_long_to_send_becomes_the_failure_notice() {
    let stage = Stage::new(&json!({})).await;
    let long = "あ".repeat(2000);
    let set = command(
        &Sender::admin(),
        "greeting welcome message",
        json!([text("message", &long)]),
    );
    let seen = stage.dispatch(&set).await;
    assert_eq!(
        only_reply(&seen),
        "❌ 余の力をもってしても処理できなかった。しばし待って試せ。"
    );
    assert_eq!(stage.saved().await, json!({"welcome": {"message": long}}));
    // 上限ちょうどに収まる返事は、そのまま送る。
    let prefix = "ウェルカムメッセージを定めた。\n> ";
    let fits = "い".repeat(2000 - prefix.chars().count());
    let set = command(
        &Sender::admin(),
        "greeting welcome message",
        json!([text("message", &fits)]),
    );
    let seen = stage.dispatch(&set).await;
    let content = only_reply(&seen).as_str().unwrap();
    assert_eq!(content.chars().count(), 2000);
    assert!(content.starts_with(&format!("{prefix}いい")));
}

/// どのコマンドも、表から読み直した設定に重ねて書くこと（1 つの場で続けて打つ）。見るだけのコマンドは
/// 管理者でなくても打て、書き換えるコマンドは断ること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn each_command_writes_through_the_table() {
    let stage = Stage::new(&json!({"log_level": "INFO"})).await;
    let admin = Sender::admin();
    let channel = json!([{"name": "channel", "type": 7, "value": NEWS_CHANNEL}]);
    let run = async |from: &Sender<'_>, path: &str, leaf: Value| {
        let seen = stage.dispatch(&command(from, path, leaf)).await;
        only_reply(&seen).as_str().map(str::to_string)
    };
    let said = run(&admin, "greeting welcome channel", channel.clone()).await;
    assert_eq!(said.unwrap(), "<#500> をウェルカムチャンネルと定めた。");
    let said = run(
        &admin,
        "greeting goodbye message",
        json!([text("message", "さらば {username}")]),
    )
    .await;
    assert_eq!(
        said.unwrap(),
        "グッバイメッセージを定めた。\n> さらば {username}"
    );
    let said = run(&admin, "vcnotify set", channel.clone()).await;
    assert_eq!(said.unwrap(), "<#500> をVC通知チャンネルと定めた。");
    let add = json!([
        text("message_id", " ０１１１ "),
        text("emoji", " 👍 "),
        {"name": "role", "type": 8, "value": "20"},
    ]);
    let said = run(&admin, "reactionrole add", add).await;
    assert_eq!(
        said.unwrap(),
        "メッセージ `111` に  👍  → <@&20> のリアクションロールを追加した。"
    );
    let feed = json!([
        {"name": "channel", "type": 7, "value": NEWS_CHANNEL},
        text("query", "AI技術"),
        {"name": "interval", "type": 4, "value": 30},
    ]);
    let said = run(&admin, "news add", feed).await.unwrap();
    let saved = stage.saved().await;
    let (feed_id, stored) = saved["news_feeds"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    assert_eq!(
        said,
        format!(
            "ニュースフィードを加えた。\nID: `{feed_id}` | クエリ: `AI技術` | チャンネル: <#500> | 間隔: 30分"
        )
    );
    // 表を通っても、数の形（last_run は小数の 0.0）が変わらないこと。
    assert_eq!(stored["last_run"].to_string(), "0.0");
    assert_eq!(
        stored,
        &json!({"channel_id": 500, "query": "AI技術", "interval": 30, "last_run": 0.0, "seen_hashes": []})
    );
    let mut rest = saved.clone();
    rest.as_object_mut().unwrap().remove("news_feeds");
    assert_eq!(
        rest,
        json!({
            "log_level": "INFO",
            "welcome": {"channel_id": 500},
            "goodbye": {"message": "さらば {username}"},
            "vc_notify_channel_id": 500,
            "reaction_roles": {"111": {"👍": 20}},
        })
    );

    // 見るだけのコマンドは、管理者でなくても打てる。設定には触らない。
    let member = Sender::member();
    let said = run(&member, "reactionrole list", json!([])).await.unwrap();
    assert_eq!(
        said,
        "**リアクションロール一覧**\nメッセージ `111` | 👍 → <@&20>"
    );
    let said = run(&member, "news list", json!([])).await.unwrap();
    assert_eq!(
        said,
        format!("**ニュースフィード一覧**\n`{feed_id}` | AI技術 | <#500> | 30分")
    );
    let said = run(&member, "sticky list", json!([])).await.unwrap();
    assert_eq!(said, "スティッキーメッセージは設定されておらぬ。");
    let seen = stage
        .dispatch(&command(&member, "greeting status", json!([])))
        .await;
    let body = &seen[0].body["data"];
    assert_eq!((seen.len(), &body["flags"]), (1, &json!(64)));
    assert_eq!(body["embeds"][0]["title"], "ウェルカム/グッバイ設定");
    assert_eq!(body["embeds"][0]["color"], 0x2E_CC_71);
    assert_eq!(
        body["embeds"][0]["fields"],
        json!([
            {"name": "ウェルカムチャンネル", "value": "<#500>", "inline": true},
            {"name": "ウェルカムメッセージ", "value": "(デフォルト)", "inline": false},
            {"name": "グッバイチャンネル", "value": "未設定", "inline": true},
            {"name": "グッバイメッセージ", "value": "さらば {username}", "inline": false},
        ])
    );
    let link = &body["components"][0]["components"][0];
    assert_eq!(
        (&link["style"], &link["url"]),
        (&json!(5), &json!("https://admin.example/login"))
    );
    assert_eq!(
        stage.saved().await,
        saved,
        "見るだけのコマンドが設定を書いた"
    );

    // 書き換えるコマンドは、管理者でなければ断る。設定には触らない。
    const NOT_ADMIN: &str = "管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。";
    for (path, leaf) in [
        ("greeting welcome channel", channel.clone()),
        ("vcnotify clear", json!([])),
        (
            "reactionrole remove",
            json!([text("message_id", "111"), text("emoji", "👍")]),
        ),
        ("news remove", json!([text("feed_id", feed_id)])),
    ] {
        assert_eq!(run(&member, path, leaf).await.unwrap(), NOT_ADMIN, "{path}");
    }
    assert_eq!(stage.saved().await, saved, "断ったのに設定を書いた");

    // 管理者が外す・消す。
    let said = run(&admin, "vcnotify clear", json!([])).await;
    assert_eq!(said.unwrap(), "VC通知チャンネルを解除した。");
    let remove = json!([text("message_id", "111"), text("emoji", "👍")]);
    let said = run(&admin, "reactionrole remove", remove.clone()).await;
    assert_eq!(said.unwrap(), "リアクションロール (👍) を取り除いた。");
    let said = run(&admin, "reactionrole remove", remove).await;
    assert_eq!(
        said.unwrap(),
        "そのようなリアクションロールは見つからなかった。"
    );
    let said = run(
        &admin,
        "news remove",
        json!([text("feed_id", &format!(" {feed_id} "))]),
    )
    .await;
    assert_eq!(
        said.unwrap(),
        format!("フィード ` {feed_id} ` を抹消した。")
    );
    assert_eq!(
        stage.saved().await,
        json!({
            "log_level": "INFO",
            "welcome": {"channel_id": 500},
            "goodbye": {"message": "さらば {username}"},
            "reaction_roles": {},
            "news_feeds": {},
        })
    );
}

/// 設定が読めない形のとき、見るだけのコマンドは「処理できなかった」と返すこと（Python は例外になり、受け皿が
/// 同じ文を返す）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_broken_setting_becomes_the_failure_notice() {
    let before = json!({"news_feeds": "壊れた値"});
    let stage = Stage::new(&before).await;
    let seen = stage
        .dispatch(&command(&Sender::member(), "news list", json!([])))
        .await;
    assert_eq!(
        only_reply(&seen),
        "❌ 余の力をもってしても処理できなかった。しばし待って試せ。"
    );
    assert_eq!(stage.saved().await, before);
}

/// 補完の問い合わせ（`focused` が入力中の引数）。
fn completion(
    from: &Sender<'_>,
    path: &str,
    filled: &[(&str, &str)],
    focused: (&str, &str),
) -> CommandInteraction {
    let mut leaf: Vec<Value> = filled
        .iter()
        .map(|(name, value)| text(name, value))
        .collect();
    leaf.push(json!({"name": focused.0, "type": 3, "value": focused.1, "focused": true}));
    interaction(4, from, data(path, json!(leaf)))
}

/// 候補を返した応答（種類 8）から、名前と値を取り出す。
fn choices_of(seen: &[Seen]) -> Vec<(String, String)> {
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", CALLBACK)
    );
    assert_eq!(seen[0].body["type"], 8, "{:#?}", seen[0]);
    let list = seen[0].body["data"]["choices"].as_array().unwrap();
    let text = |v: &Value| v.as_str().unwrap().to_string();
    list.iter()
        .map(|c| (text(&c["name"]), text(&c["value"])))
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// 補完: 候補を種類 8 の応答で返すこと。ロールとチャンネルの名前はキャッシュから引き、無ければ保存された値・
/// 「不明なチャンネル」。権限は見ない。設定には触らない。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn autocomplete_replies_with_choices() {
    let before = json!({
        "reaction_roles": {"111": {"👍": 20, "<:Blob:5>": 99}, "222": {"✅": 21.0}},
        "news_feeds": {
            "aaaa1111": {"channel_id": 500, "query": "AI技術"},
            "bbbb2222": {"channel_id": 501, "query": "Rust"},
        },
    });
    let stage = Stage::new(&before).await;
    let member = Sender::member();
    let rr = "reactionrole remove";

    let seen = stage
        .autocomplete(&completion(&member, rr, &[], ("message_id", "")))
        .await;
    assert_eq!(
        choices_of(&seen),
        pairs(&[("111（2件のロール）", "111"), ("222（1件のロール）", "222")])
    );
    let seen = stage
        .autocomplete(&completion(&member, rr, &[], ("message_id", "22")))
        .await;
    assert_eq!(choices_of(&seen), pairs(&[("222（1件のロール）", "222")]));

    // 先に入れた message_id の絵文字だけ。ロールの名前はキャッシュから（99 はサーバーに無いロール）。
    let chosen = [("message_id", "111")];
    let seen = stage
        .autocomplete(&completion(&member, rr, &chosen, ("emoji", "")))
        .await;
    assert_eq!(
        choices_of(&seen),
        pairs(&[("👍 → r20", "👍"), ("<:Blob:5> → 99", "<:Blob:5>")])
    );
    let seen = stage
        .autocomplete(&completion(&member, rr, &chosen, ("emoji", "blob")))
        .await;
    assert_eq!(choices_of(&seen), pairs(&[("<:Blob:5> → 99", "<:Blob:5>")]));
    // 入れていなければ、全部のメッセージから。
    let seen = stage
        .autocomplete(&completion(&member, rr, &[], ("emoji", "✅")))
        .await;
    assert_eq!(choices_of(&seen), pairs(&[("✅ → r21", "✅")]));

    // チャンネルの名前もキャッシュから（501 はサーバーに無いチャンネル）。
    let seen = stage
        .autocomplete(&completion(&member, "news remove", &[], ("feed_id", "")))
        .await;
    assert_eq!(
        choices_of(&seen),
        pairs(&[
            ("AI技術 (#ニュース) [aaaa1111]", "aaaa1111"),
            ("Rust (不明なチャンネル) [bbbb2222]", "bbbb2222")
        ])
    );
    let seen = stage
        .autocomplete(&completion(
            &member,
            "news remove",
            &[],
            ("feed_id", "RUST"),
        ))
        .await;
    assert_eq!(
        choices_of(&seen),
        pairs(&[("Rust (不明なチャンネル) [bbbb2222]", "bbbb2222")])
    );

    // サーバーの外では、候補は空。
    let dm = Sender {
        who: "dm",
        ..Sender::admin()
    };
    let seen = stage
        .autocomplete(&completion(&dm, rr, &[], ("message_id", "")))
        .await;
    assert_eq!(choices_of(&seen), Vec::new());
    // 補完を出さない引数・移していないコマンドには応えない。
    let add = completion(&member, "reactionrole add", &[], ("message_id", ""));
    assert_eq!(stage.autocomplete(&add).await.len(), 0);
    let other = completion(&member, "dict remove", &[], ("word", ""));
    assert_eq!(stage.autocomplete(&other).await.len(), 0);
    assert_eq!(stage.saved().await, before, "補完が設定を書いた");

    // 設定が読めない形なら、何も返さない（Python も例外で、何も返さない）。
    stage
        .store(&json!({"reaction_roles": {"111": 5}, "news_feeds": "壊れた値"}))
        .await;
    for (path, focused) in [
        (rr, "message_id"),
        (rr, "emoji"),
        ("news remove", "feed_id"),
    ] {
        let seen = stage
            .autocomplete(&completion(&member, path, &[], (focused, "")))
            .await;
        assert_eq!(seen.len(), 0, "{path} {focused}: {seen:#?}");
    }
}
