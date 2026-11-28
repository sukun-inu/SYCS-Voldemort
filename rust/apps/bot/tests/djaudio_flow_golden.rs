//! DJAudio の流れ（見張るチャンネルの投稿 → リアクション → 落とす → 返信）が、本物の Python と同じ順に同じことを
//! すること。
//!
//! 基準（`fixtures/djaudio/flow_expected.jsonl`）は、本物の `handle_djaudio_message` を、記録するだけの偽物の Bot・
//! メッセージと、台本どおりに答える落とし口で動かしたもの（`generate_flow.py`）。ここでは同じ台本の偽物を
//! [`Outlet`]・[`Downloader`] に入れて、したこと（リアクション・返信と Embed・出力チャンネルへの送信・落とす URL と
//! 有効期間・登録への書き足し・外へ抜けた失敗）の並びを比べる。見分け方（落とせないサービス・ドメイン・安全でない
//! 行き先）、続けて頼んだ人の待ち時間、同時の重複配信、URL が 2 つのときの順、時間切れ、出力チャンネル（見つからない・
//! 同じ・送れない種類）、Discord に断られたとき（気にせず続ける）と通信の失敗（外へ抜ける）の分かれ方まで。

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use serenity::all::CreateEmbed;
use sycs_bot::djaudio::flow::{
    self, DiscordError, Downloader, Outlet, OutputChannel, Post, Results, Sent, State,
};
use sycs_bot::djaudio::settings::{self, Defaults};

const GUILD: u64 = 1_399_617_700_363_370_556;
const CHANNEL: u64 = 1_505_310_388_051_251_000;
const REPLY_ID: u64 = 7001;
const SENT_ID: u64 = 7002;
const BASE: &str = "https://dl.example";
const EXPECTED: &str = include_str!("fixtures/djaudio/flow_expected.jsonl");

fn embed_json(embed: &CreateEmbed) -> Value {
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
        "title": v["title"], "description": v["description"], "color": v["color"],
        "fields": fields, "footer": v["footer"]["text"],
    })
}

/// 台本どおりに答える偽物の Discord（したことを記録する）。
struct Fake<'a> {
    case: &'a Value,
    effects: &'a Mutex<Vec<Value>>,
    replies: Mutex<u32>,
}

impl Fake<'_> {
    fn push(&self, effect: Value) {
        self.effects.lock().unwrap().push(effect);
    }

    /// 台本の「断られる働きかけ」に当たれば、その失敗。
    fn check(&self, what: &str) -> Result<(), DiscordError> {
        for item in self.case["fail"].as_array().into_iter().flatten() {
            let item = item.as_str().unwrap();
            let other = item.ends_with('!');
            if item.trim_end_matches('!') == what {
                return Err(if other {
                    DiscordError::Other(format!("connection reset ({what})"))
                } else {
                    DiscordError::Refused(format!("refused ({what})"))
                });
            }
        }
        Ok(())
    }
}

impl Outlet for Fake<'_> {
    async fn add_reaction(&self, emoji: &str) -> Result<(), DiscordError> {
        self.check(&format!("react:{emoji}"))?;
        self.push(json!(["react", emoji]));
        Ok(())
    }

    async fn remove_own_reaction(&self, emoji: &str) -> Result<(), DiscordError> {
        self.check(&format!("unreact:{emoji}"))?;
        self.push(json!(["unreact", emoji]));
        Ok(())
    }

    async fn reply(
        &self,
        content: Option<String>,
        embed: Option<CreateEmbed>,
    ) -> Result<Sent, DiscordError> {
        let n = {
            let mut replies = self.replies.lock().unwrap();
            *replies += 1;
            *replies
        };
        self.check(&format!("reply:{n}"))?;
        self.push(json!(["reply", content, embed.as_ref().map(embed_json)]));
        Ok((CHANNEL, REPLY_ID))
    }

    async fn send(&self, channel_id: u64, embed: CreateEmbed) -> Result<Sent, DiscordError> {
        self.check("send")?;
        self.push(json!(["send", channel_id, embed_json(&embed)]));
        Ok((channel_id, SENT_ID))
    }

    fn output_channel(&self, channel_id: u64) -> OutputChannel {
        match self.case["channels"][channel_id.to_string()].as_str() {
            Some("text") => OutputChannel::Messageable(channel_id),
            Some(_) => OutputChannel::NotMessageable(channel_id),
            None => OutputChannel::Missing,
        }
    }

    async fn is_safe(&self, url: &str) -> bool {
        !url.contains("UNSAFE")
    }
}

/// 台本どおりに落とす偽物（1 回は待つ。同時の重複配信のときに、もう片方が先へ進めるように）。
struct FakeDownloads<'a> {
    case: &'a Value,
    effects: &'a Mutex<Vec<Value>>,
}

impl Downloader for FakeDownloads<'_> {
    async fn download(&self, url: &str, guild_id: u64, cache_ttl: i128) -> Result<Results, String> {
        assert_eq!(guild_id, GUILD);
        self.effects
            .lock()
            .unwrap()
            .push(json!(["download", url, cache_ttl as i64]));
        tokio::task::yield_now().await;
        let plan = &self.case["downloads"][url];
        if plan["timeout"].as_bool() == Some(true) {
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
        if let Some(error) = plan["error"].as_str() {
            return Err(error.to_string());
        }
        let results = match plan["results"].as_array() {
            Some(list) => list
                .iter()
                .map(|r| {
                    (
                        r[0].as_str().unwrap().to_string(),
                        r[1].as_str().unwrap().to_string(),
                    )
                })
                .collect(),
            None => vec![("T".to_string(), "tok".to_string())],
        };
        Ok(results)
    }

    fn record_message(&self, token: &str, sent: Sent) {
        self.effects
            .lock()
            .unwrap()
            .push(json!(["record", token, sent.0, sent.1]));
    }
}

fn post(spec: &Value) -> Post {
    let author = spec["author"].as_u64().unwrap_or(42);
    Post {
        guild_id: GUILD,
        channel_id: spec["channel"].as_u64().unwrap_or(CHANNEL),
        message_id: spec["message"].as_u64().unwrap_or(5001),
        author_id: author,
        author_name: spec["name"]
            .as_str()
            .map_or_else(|| format!("user{author}"), str::to_string),
        author_tag: format!("user{author}"),
        content: spec["content"].as_str().unwrap().to_string(),
    }
}

/// 例を 1 つ回して、したことの並びを返す。
async fn run(case: &Value) -> Vec<Value> {
    let effects = Mutex::new(Vec::new());
    let fake = Fake {
        case,
        effects: &effects,
        replies: Mutex::new(0),
    };
    let downloads = FakeDownloads {
        case,
        effects: &effects,
    };
    let default = json!({"djaudio": {"watch_channel_id": CHANNEL, "cooldown": 30}});
    let guild = case.get("settings").unwrap_or(&default);
    let runtime = settings::runtime(Some(guild), Defaults::default());
    let state = State::new(3, Duration::from_millis(200), BASE);
    for spec in case["messages"].as_array().unwrap() {
        let at = spec["at"].as_f64().unwrap_or(1000.0);
        let post = post(spec);
        let handle = || async {
            if flow::handle_message(&state, &fake, &downloads, &post, &runtime, || at)
                .await
                .is_err()
            {
                effects.lock().unwrap().push(json!(["raised"]));
            }
        };
        if case["duplicate"].as_bool() == Some(true) {
            tokio::join!(handle(), handle());
        } else {
            handle().await;
        }
    }
    effects.into_inner().unwrap()
}

/// 全部の例で、したことの並びが Python と同じであること。
#[tokio::test]
async fn djaudio_flow_matches_python() {
    let mut count = 0;
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let got = Value::Array(run(&row[0]).await);
        if got != row[1] {
            wrong.push(format!(
                "{}\n  Python: {}\n  Rust:   {got}",
                row[0]["id"], row[1]
            ));
        }
        count += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 50, "例が少ない: {count}");
}
