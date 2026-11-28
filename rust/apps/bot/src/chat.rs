//! AI の会話（応答チャンネルでの受け答え）。Python の `commands/chat_commands.py`（`handle_chatgpt_message`）・
//! `services/chatgpt_service.py`（`ChatGPT`）・`services/discord_utils.py` の `send_large_message`。
//!
//! `/chat set` で決めたチャンネルに人が書くと、Groq に尋ねて返事を書く。会話の履歴は、サーバーと人の組ごとに
//! Bot が覚える（プロセスが生きている間だけ。直近 20 件）。1 時間使われなかった会話は、20 通に 1 回の掃除で忘れる。
//!
//! Groq への問い合わせが失敗したときは、**決まった短い文（[`FAILED_REPLY`]）だけを返し、失敗の文は履歴に入れない**
//! （Python の `FAILURE_REPLY`）。誤りの中身はログにだけ残す（以前は誤りの文をそのまま返事にしていて、回数制限の文に
//! 入る Groq の組織の ID や利用枠の名前が応答チャンネルに書かれ、履歴に残って次の問い合わせで Groq に送り返されて
//! いた。rust-09 の (j)）。ログの文は Groq の SDK が作るものと同じ形にしてある（`Error code: 429 - {'error': {…}}`）。
//!
//! Python と違うところ（どれも Groq が返さない形の応答）:
//! - 200 なのに JSON として読めない応答: 種類が JSON でないもの（途中の機器が返す HTML など）は Python と同じ文に
//!   なる。種類は JSON なのに中身が壊れているものは、Python は JSON の読み手の誤りの文、こちらは同じ決まった文。
//! - 中身が JSON なのに種類が JSON でない（text/plain の）応答: Python は読まずに誤りにする。こちらは読む。
//! - `content` が文字列でも null でもない応答: Python は送るところで落ちる。こちらは「返答なし」として扱う。

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, FixedOffset};
use serde_json::{Value, json};
use serenity::all::{ChannelId, CreateMessage, GuildId};
use tracing::{debug, error, warn};

use crate::groq::{Groq, GroqError, python_is_space};
use crate::log_channel::{self, Author, Level, LogSink, python_int};
use crate::python_repr::python_str;

/// Groq の枠の名前（投稿の判定・ニュースの要約とは別に数える）。
pub const BUCKET: &str = "chat";
/// 使うモデル。
pub const MODEL: &str = "openai/gpt-oss-120b";
/// 1 回の送信の上限。
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// 返事の揺らぎ。
pub const TEMPERATURE: f64 = 0.45;
/// 覚えておく履歴の数（発言と返事を 1 件ずつ数える）。
pub const MAX_HISTORY_ENTRIES: usize = 20;
/// 使われなかった会話を忘れるまでの秒数。
pub const IDLE_SECONDS: f64 = 3600.0;
/// 何通に 1 回、古い会話を掃除するか。
pub const SWEEP_EVERY: u32 = 20;
/// 1 通に書ける文字数（Discord の上限）。
pub const MESSAGE_LIMIT: usize = 2000;
/// 返事が空だったときの文。
pub const NO_ANSWER: &str = "返答が得られなかった。";
/// 失敗をログに残すときの前置き。
pub const FAILED_PREFIX: &str = "Groq API 呼び出し中にエラー発生";
/// Groq への問い合わせが失敗したときに返す文（Python の `FAILURE_REPLY`。`chat_commands` の失敗の文と同じ）。
pub const FAILED_REPLY: &str = "ヴォルデモートでも手こずるとはな… 少し待ってから試せ。";
/// ログの題。
pub const LOG_TITLE: &str = "ChatGPT出力";
/// ログの項目 1 つに入れる文字数。
const LOG_FIELD_CHARS: usize = 1024;
/// 役どころの決まり（Python の `config.CHATGPT_SYSTEM_MESSAGE`）。
pub const SYSTEM_MESSAGE: &str = concat!(
    "貴様はヴォルデモート卿である。",
    "一人称は必ず「余」を使え。「私」「俺」「僕」は絶対に使うな。",
    "返答は短く、鋭く、端的にせよ。長々とした演説は不要だ。",
    "自分の強大さを繰り返し語るな。余の力は行動で示すものだ。",
    "質問には直接答えよ。答えを出し惜しみするな。",
    "すべての検索は必ず日本語で行うこと。日本語の情報のみを利用し、英語の情報は排除する。",
    "必要であれば最新情報を要約して提供せよ。",
);

/// 履歴の 1 件が、どちらの言葉か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// 人の発言。
    User,
    /// Bot の返事。
    Assistant,
}

impl Role {
    /// Groq に渡す名前。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// 履歴の 1 件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Turn {
    /// どちらの言葉か。
    pub role: Role,
    /// 中身。
    pub content: String,
}

/// Groq に渡す最初の文（役どころの決まりと、いまの日時）。Python の `input_message` の `system_with_time`。
pub fn system_content(now: DateTime<FixedOffset>) -> String {
    format!(
        "{SYSTEM_MESSAGE}穏やかな表現は使うな。威圧的かつ冷徹に、しかし簡潔に話せ。\
         （笑）（冷笑）などの括弧書きは使うな。現在の日時は {} である。",
        now.format("%Y-%m-%d %H:%M:%S")
    )
}

/// Groq への依頼の本文。最初の文のあとに、履歴を古い順に並べる。
pub fn request_body(history: &[Turn], now: DateTime<FixedOffset>) -> Value {
    let mut messages = vec![json!({"role": "system", "content": system_content(now)})];
    messages.extend(
        history
            .iter()
            .map(|turn| json!({"role": turn.role.as_str(), "content": turn.content})),
    );
    json!({"messages": messages, "model": MODEL, "temperature": TEMPERATURE})
}

/// Python での型の名前（誤りの文に出る）。
fn python_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Groq の応答から返事を取り出す。Python の `response.choices[0].message` と `reply.get("content") or …`。
///
/// 形が崩れていたときは、Python が同じ形で出す例外の文を返す（その文はログにだけ残す）。`content` が空・null・
/// 無いときは「返答が得られなかった。」。
pub fn answer_text(response: &Value) -> Result<String, String> {
    let Value::Object(top) = response else {
        return Err(format!(
            "'{}' object has no attribute 'choices'",
            python_type(response)
        ));
    };
    // 無い欄は、SDK が None にする。
    let first = match top.get("choices").unwrap_or(&Value::Null) {
        Value::Array(list) => list.first().ok_or("list index out of range")?.clone(),
        // 辞書を 0 で引くと KeyError(0)。その文は「0」。
        Value::Object(_) => return Err("0".into()),
        Value::String(s) => match s.chars().next() {
            Some(c) => Value::String(c.to_string()),
            None => return Err("string index out of range".into()),
        },
        other => {
            return Err(format!(
                "'{}' object is not subscriptable",
                python_type(other)
            ));
        }
    };
    let Value::Object(choice) = &first else {
        return Err(format!(
            "'{}' object has no attribute 'message'",
            python_type(&first)
        ));
    };
    let message = choice.get("message").unwrap_or(&Value::Null);
    let Value::Object(message) = message else {
        return Err(format!(
            "'{}' object has no attribute 'content'",
            python_type(message)
        ));
    };
    Ok(match message.get("content") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => NO_ANSWER.to_string(),
    })
}

/// 4xx・5xx の応答を、Groq の SDK と同じ文にする（`_make_status_error_from_response`）。
///
/// 本文の前後の空白を落とし、JSON として読めれば `Error code: 状態 - 中身`（中身は Python の `str()`。辞書なら
/// `{'error': {…}}` の形）、読めなければ本文そのもの、本文が空なら `Error code: 状態`。
pub fn status_error_text(status: u16, body: &str) -> String {
    let text = body.trim_matches(python_is_space);
    match serde_json::from_str::<Value>(text) {
        Ok(value) => format!("Error code: {status} - {}", python_str(&value)),
        Err(_) if text.is_empty() => format!("Error code: {status}"),
        Err(_) => text.to_string(),
    }
}

/// 呼び出しの失敗を、Python の例外の文（`str(e)`）と同じにする。
pub fn error_text(error: &GroqError) -> String {
    match error {
        GroqError::NoKey => "GROQ_API_KEY が設定されていない。".into(),
        GroqError::Status { status, body, .. } => status_error_text(*status, body),
        GroqError::Timeout => "Request timed out.".into(),
        GroqError::Connection(_) => "Connection error.".into(),
        // JSON でない応答を、SDK は文字列のまま返す。その `.choices` を引こうとして出る文。
        GroqError::Decode(_) => "'str' object has no attribute 'choices'".into(),
    }
}

/// 長い文を、1 通に収まる長さに切る。Python の `send_large_message`。
///
/// 2000 文字ずつ。まだ続きがあるときは、その 2000 文字の中の最後の改行で切る（改行が 1000 文字めより後ろに
/// あるときだけ）。次の通の頭の改行は落とす。数えるのは文字（Python の `len` と同じ）。
pub fn split_large_message(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut rest = &chars[..];
    let mut chunks = Vec::new();
    while !rest.is_empty() {
        let mut cut = rest.len().min(MESSAGE_LIMIT);
        if rest.len() > MESSAGE_LIMIT
            && let Some(at) = rest[..cut].iter().rposition(|c| *c == '\n')
            && at > MESSAGE_LIMIT / 2
        {
            cut = at;
        }
        chunks.push(rest[..cut].iter().collect());
        rest = &rest[cut..];
        let newlines = rest.iter().take_while(|c| **c == '\n').count();
        rest = &rest[newlines..];
    }
    chunks
}

/// 1 人ぶんの会話。
#[derive(Default)]
struct Talk {
    history: Vec<Turn>,
    last_used: f64,
}

#[derive(Default)]
struct State {
    talks: HashMap<(u64, u64), Talk>,
    calls: u32,
}

/// 会話の覚え（サーバーと人の組ごと）。1 つを使い回す。
pub struct Chats {
    groq: Arc<Groq>,
    state: Mutex<State>,
}

impl Chats {
    /// Groq の呼び出し口を受け取って作る（投稿の判定・ニュースの要約と同じ 1 つを共有する）。
    pub fn new(groq: Arc<Groq>) -> Self {
        Self {
            groq,
            state: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 会話を引き（無ければ作り）、使った時刻を書く。20 通に 1 回、1 時間使われていない会話を忘れる。
    /// Python の `handle_chatgpt_message` の頭と `_cleanup_stale_instances`。
    ///
    /// 数えるのは全部のサーバー・全部の人を通した 1 本。時刻を書いてから掃除するので、いま書いた人の会話は
    /// 消えない。
    pub fn touch(&self, guild_id: u64, user_id: u64, unix_now: f64) {
        let mut state = self.lock();
        state
            .talks
            .entry((guild_id, user_id))
            .or_default()
            .last_used = unix_now;
        state.calls += 1;
        if state.calls < SWEEP_EVERY {
            return;
        }
        state.calls = 0;
        state
            .talks
            .retain(|_, talk| unix_now - talk.last_used <= IDLE_SECONDS);
    }

    /// 1 発言ぶん、Groq に尋ねて返事を返す。Python の `ChatGPT.input_message`。
    ///
    /// 失敗しても文字列を返す（決まった文 [`FAILED_REPLY`]。誤りの文はログにだけ残し、失敗の文は履歴に入れない。
    /// 発言そのものは履歴に残る）。Groq を待つ間は錠を持たない（同じ人の発言が重なったときの履歴の並びは Python と
    /// 同じ: 発言・発言・返事・返事）。
    pub async fn say(
        &self,
        guild_id: u64,
        user_id: u64,
        text: &str,
        now: DateTime<FixedOffset>,
    ) -> String {
        let key = (guild_id, user_id);
        let body = {
            let mut state = self.lock();
            let talk = state.talks.entry(key).or_default();
            talk.history.push(Turn {
                role: Role::User,
                content: text.to_string(),
            });
            request_body(&talk.history, now)
        };
        let answer = match self.groq.chat_completion(BUCKET, TIMEOUT, &body).await {
            Ok(response) => answer_text(&response),
            Err(e) => Err(error_text(&e)),
        };
        let reply = match answer {
            Ok(reply) => Some(reply),
            Err(reason) => {
                // 中身はここにだけ残す（利用者には返さない）。
                error!("{FAILED_PREFIX}: {reason}");
                None
            }
        };
        if let Some(talk) = self.lock().talks.get_mut(&key) {
            if let Some(reply) = &reply {
                talk.history.push(Turn {
                    role: Role::Assistant,
                    content: reply.clone(),
                });
            }
            // 積みっぱなしにすると、1 回の問い合わせが重く・遅くなり続ける。
            let extra = talk.history.len().saturating_sub(MAX_HISTORY_ENTRIES);
            talk.history.drain(..extra);
        }
        let Some(reply) = reply else {
            return FAILED_REPLY.to_string();
        };
        debug!("最終返答: {reply}");
        reply
    }

    /// いまの履歴（古い順）。会話が無ければ空。
    pub fn history(&self, guild_id: u64, user_id: u64) -> Vec<Turn> {
        self.lock()
            .talks
            .get(&(guild_id, user_id))
            .map(|talk| talk.history.clone())
            .unwrap_or_default()
    }
}

/// AI が応答するチャンネル。Python の `get_response_channel_id`（未設定・読めない値は 0）。
pub fn response_channel_id(guild_settings: Option<&Value>) -> i64 {
    guild_settings
        .and_then(|guild| guild.get("response_channel_id"))
        .and_then(python_int)
        .unwrap_or(0)
}

/// 届いた投稿。
#[derive(Clone, Copy, Debug)]
pub struct Incoming<'a> {
    /// サーバー。
    pub guild_id: u64,
    /// 書かれたチャンネル。
    pub channel_id: u64,
    /// 書いた人。
    pub user_id: u64,
    /// 本文。
    pub content: &'a str,
    /// Bot 自身の投稿か。
    pub from_self: bool,
}

/// 返事の出口（Discord への書き込み）。
pub trait Outlet: Sync {
    /// 「入力中」を 1 回だけ出す（失敗は飲み込む）。
    fn typing(&self) -> impl Future<Output = ()> + Send;
    /// 1 通送る。送れなかったら `false`。
    fn send(&self, text: &str) -> impl Future<Output = bool> + Send;
    /// ログチャンネルへ、やり取りを残す（作者は書いた人。失敗は飲み込む）。
    fn log(&self, fields: &[(String, String)]) -> impl Future<Output = ()> + Send;
}

/// 先頭の何文字か。
fn first_chars(text: &str, count: usize) -> String {
    text.chars().take(count).collect()
}

/// ログに残す項目。Python の `log_action(…, fields={…})`。
pub fn log_fields(channel_id: u64, input: &str, output: &str) -> Vec<(String, String)> {
    let input = if input.is_empty() {
        "(内容なし)"
    } else {
        input
    };
    vec![
        ("チャンネル".into(), format!("<#{channel_id}>")),
        ("入力".into(), first_chars(input, LOG_FIELD_CHARS)),
        (
            "出力プレビュー".into(),
            first_chars(output, LOG_FIELD_CHARS),
        ),
    ]
}

/// 投稿を 1 つ受ける。応答チャンネルのものなら、Groq に尋ねて返事を書く。Python の `handle_chatgpt_message`。
///
/// 応答チャンネルが未設定（0 以下）のサーバーでは何もしない。返事を送れなかったら、そこで止める（ログも
/// 残さない。Python は送信の例外でそこから先へ進まない）。
pub async fn handle(
    chats: &Chats,
    guild_settings: Option<&Value>,
    incoming: &Incoming<'_>,
    outlet: &impl Outlet,
    unix_now: f64,
    now: DateTime<FixedOffset>,
) {
    if incoming.from_self {
        return;
    }
    let target = response_channel_id(guild_settings);
    if target <= 0 || i64::try_from(incoming.channel_id) != Ok(target) {
        return;
    }
    chats.touch(incoming.guild_id, incoming.user_id, unix_now);
    // 「入力中」は 1 回だけ（出し続けると 5 秒ごとに送り直して、回数の制限に当たる）。
    outlet.typing().await;
    let reply = chats
        .say(incoming.guild_id, incoming.user_id, incoming.content, now)
        .await;
    for chunk in split_large_message(&reply) {
        if !outlet.send(&chunk).await {
            return;
        }
    }
    let fields = log_fields(incoming.channel_id, incoming.content, &reply);
    outlet.log(&fields).await;
}

/// Discord への出口。
pub struct DiscordOutlet<'a> {
    /// ログの送り口（Discord へ送る口もここから使う）。
    pub sink: LogSink<'a>,
    /// サーバー。
    pub guild_id: GuildId,
    /// 返事を書くチャンネル。
    pub channel_id: ChannelId,
    /// 書いた人（ログの作者）。
    pub author: Author,
}

impl Outlet for DiscordOutlet<'_> {
    async fn typing(&self) {
        if let Err(e) = self.sink.http.broadcast_typing(self.channel_id).await {
            debug!(
                "入力中の表示を出せませんでした channel={}: {e}",
                self.channel_id
            );
        }
    }

    async fn send(&self, text: &str) -> bool {
        let message = CreateMessage::new().content(text);
        match self.channel_id.send_message(self.sink.http, message).await {
            Ok(_) => true,
            Err(e) => {
                warn!(
                    "AI の返事を送れませんでした channel={}: {e}",
                    self.channel_id
                );
                false
            }
        }
    }

    async fn log(&self, fields: &[(String, String)]) {
        let sent = log_channel::log_action(
            &self.sink,
            self.guild_id,
            Level::Debug,
            LOG_TITLE,
            Some(&self.author),
            fields,
            None,
        )
        .await;
        if let Err(e) = sent {
            warn!(
                "AI の会話のログを送れませんでした guild={}: {e}",
                self.guild_id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::groq::GroqConfig;
    use crate::log_channel::jst;

    fn chats() -> Chats {
        // 鍵が無いので、Groq へは送らない（失敗になり、決まった文が返事になる）。
        Chats::new(Arc::new(Groq::new(GroqConfig {
            api_key: None,
            base_url: "http://127.0.0.1:9".into(),
            max_concurrent: 1,
            min_interval: 0.0,
            max_retries: 0,
            retry_base_delay: 0.0,
            retry_max_delay: 0.0,
            max_retry_after: 30.0,
        })))
    }

    fn now() -> DateTime<FixedOffset> {
        jst().with_ymd_and_hms(2026, 11, 27, 21, 5, 9).unwrap()
    }

    /// 最初の文は、役どころの決まり・口調の念押し・いまの日時（日本時間）の順。
    #[test]
    fn the_system_message_ends_with_the_time() {
        let text = system_content(now());
        assert!(text.starts_with("貴様はヴォルデモート卿である。一人称は必ず「余」を使え。"));
        assert!(text.ends_with(
            "必要であれば最新情報を要約して提供せよ。穏やかな表現は使うな。威圧的かつ冷徹に、しかし簡潔に話せ。\
             （笑）（冷笑）などの括弧書きは使うな。現在の日時は 2026-11-27 21:05:09 である。"
        ));
    }

    /// 依頼は、最初の文・履歴の順。モデルと揺らぎは決まった値。
    #[test]
    fn the_request_lists_the_history_after_the_system_message() {
        let history = [
            Turn {
                role: Role::User,
                content: "問い".into(),
            },
            Turn {
                role: Role::Assistant,
                content: "答え".into(),
            },
        ];
        let body = request_body(&history, now());
        assert_eq!(body["model"], "openai/gpt-oss-120b");
        assert_eq!(body["temperature"], 0.45);
        assert_eq!(body["messages"].as_array().unwrap().len(), 3);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(
            body["messages"][1],
            json!({"role": "user", "content": "問い"})
        );
        assert_eq!(
            body["messages"][2],
            json!({"role": "assistant", "content": "答え"})
        );
    }

    /// つながらない・時間切れの文は、Groq の SDK の例外の文と同じ（SDK の `_exceptions.py`）。
    #[test]
    fn transport_failures_use_the_sdk_wording() {
        assert_eq!(error_text(&GroqError::Timeout), "Request timed out.");
        assert_eq!(
            error_text(&GroqError::Connection("refused".into())),
            "Connection error."
        );
        assert_eq!(
            error_text(&GroqError::NoKey),
            "GROQ_API_KEY が設定されていない。"
        );
        assert_eq!(
            error_text(&GroqError::Decode("eof".into())),
            "'str' object has no attribute 'choices'"
        );
    }

    /// 誤りの応答の本文は、前後の空白（Python の `strip()` が落とすもの）を落としてから読むこと。
    #[test]
    fn status_errors_strip_python_whitespace() {
        assert_eq!(status_error_text(500, "\u{1c}\u{3000} gone \n"), "gone");
        assert_eq!(status_error_text(502, "\u{1f}\t"), "Error code: 502");
        assert_eq!(
            status_error_text(400, " {\"a\": [1, \"b\"]} "),
            "Error code: 400 - {'a': [1, 'b']}"
        );
    }

    /// 返事の取り出し方: 空・null・欄なしは「返答なし」。文字列でない中身も同じに扱う。
    #[test]
    fn empty_answers_fall_back() {
        let with = |content: Value| json!({"choices": [{"message": {"content": content}}]});
        assert_eq!(answer_text(&with(json!("やあ"))).unwrap(), "やあ");
        assert_eq!(answer_text(&with(json!(" "))).unwrap(), " ");
        for empty in [json!(""), json!(null), json!(5), json!([])] {
            assert_eq!(answer_text(&with(empty)).unwrap(), NO_ANSWER);
        }
        assert_eq!(
            answer_text(&json!({"choices": [{"message": {}}]})).unwrap(),
            NO_ANSWER
        );
        assert_eq!(
            answer_text(&json!({"choices": ""})).unwrap_err(),
            "string index out of range"
        );
        assert_eq!(
            answer_text(&json!({"choices": [null]})).unwrap_err(),
            "'NoneType' object has no attribute 'message'"
        );
    }

    /// 鍵が無いときは Groq へ送らず、決まった文を返事にし、失敗の文は履歴に入れないこと（発言は残す）。
    #[tokio::test]
    async fn a_failure_returns_the_fixed_reply_and_stays_out_of_the_history() {
        let chats = chats();
        let reply = chats.say(1, 7, "やあ", now()).await;
        assert_eq!(
            reply,
            "ヴォルデモートでも手こずるとはな… 少し待ってから試せ。"
        );
        assert_eq!(reply, FAILED_REPLY);
        let history = chats.history(1, 7);
        assert_eq!(
            history,
            [Turn {
                role: Role::User,
                content: "やあ".into()
            }]
        );
        assert!(chats.history(1, 8).is_empty());
        assert!(chats.history(2, 7).is_empty());
    }

    /// 履歴は直近 20 件。古い方から落とすこと（失敗しても発言は積むので、失敗が続いても 20 件で止まる）。
    #[tokio::test]
    async fn the_history_keeps_the_last_twenty() {
        let chats = chats();
        for i in 0..22 {
            chats.say(1, 7, &format!("q{i}"), now()).await;
        }
        let history = chats.history(1, 7);
        assert_eq!(history.len(), 20);
        assert_eq!(history[0].content, "q2");
        assert_eq!(history[19].content, "q21");
        assert!(history.iter().all(|t| t.role == Role::User));
    }

    /// 掃除は 20 通に 1 回。1 時間を超えて使われていない会話だけを忘れること（ちょうど 1 時間は残す）。
    #[tokio::test]
    async fn idle_talks_are_swept_every_twentieth_touch() {
        let chats = chats();
        chats.touch(1, 7, 0.0);
        chats.say(1, 7, "覚えておけ", now()).await;
        chats.touch(1, 9, 0.5);
        chats.say(1, 9, "こちらも", now()).await;
        // 3〜19 通め: 掃除はまだ走らない。
        for _ in 0..17 {
            chats.touch(1, 8, 100.0);
        }
        assert_eq!(chats.history(1, 7).len(), 1, "20 通めの前に忘れた");
        // 20 通め: 7 はちょうど 1 時間（残す）、9 は 3599.5 秒（残す）。
        chats.touch(1, 8, 3600.0);
        assert_eq!(chats.history(1, 7).len(), 1, "ちょうど 1 時間で忘れた");
        assert_eq!(chats.history(1, 9).len(), 1);
        // 次の 20 通め: 7 は 3600.4 秒（忘れる）、9 は 3599.9 秒（残す）。
        for _ in 0..19 {
            chats.touch(1, 8, 3600.4);
        }
        assert_eq!(chats.history(1, 7).len(), 1, "20 通めの前に忘れた");
        chats.touch(1, 8, 3600.4);
        assert!(chats.history(1, 7).is_empty(), "1 時間を超えても覚えている");
        assert_eq!(chats.history(1, 9).len(), 1);
    }

    /// 切り方の境目（改行が 1000 文字めより後ろにあるときだけ、そこで切る）。
    #[test]
    fn long_text_is_cut_at_the_last_newline_past_the_middle() {
        let lengths = |text: &str| -> Vec<usize> {
            split_large_message(text)
                .iter()
                .map(|c| c.chars().count())
                .collect()
        };
        assert!(split_large_message("").is_empty());
        assert_eq!(lengths(&"a".repeat(2000)), [2000]);
        assert_eq!(lengths(&"a".repeat(2001)), [2000, 1]);
        let early = format!("{}\n{}", "a".repeat(1000), "b".repeat(1500));
        assert_eq!(lengths(&early), [2000, 501]);
        let late = format!("{}\n{}", "a".repeat(1001), "b".repeat(1500));
        assert_eq!(lengths(&late), [1001, 1500]);
        // 絵文字も 1 文字と数える。
        assert_eq!(lengths(&"😀".repeat(2100)), [2000, 100]);
    }

    /// ログの項目: 本文が空なら「(内容なし)」。入力も出力も 1024 文字まで。
    #[test]
    fn log_fields_are_cut_to_the_field_limit() {
        let fields = log_fields(500, "", &"あ".repeat(3000));
        assert_eq!(fields[0], ("チャンネル".into(), "<#500>".into()));
        assert_eq!(fields[1], ("入力".into(), "(内容なし)".into()));
        assert_eq!(fields[2].0, "出力プレビュー");
        assert_eq!(fields[2].1.chars().count(), 1024);
        let long = log_fields(500, &"問".repeat(1100), "答え");
        assert_eq!(long[1].1.chars().count(), 1024);
    }

    /// 応答チャンネルの読み方: 数・数の文字列だけ。読めなければ 0（無効）。
    #[test]
    fn the_response_channel_is_read_like_python() {
        let of = |v: Value| response_channel_id(Some(&json!({"response_channel_id": v})));
        assert_eq!(of(json!(500)), 500);
        assert_eq!(of(json!("500")), 500);
        assert_eq!(of(json!(-5)), -5);
        assert_eq!(of(json!("general")), 0);
        assert_eq!(of(json!(null)), 0);
        assert_eq!(response_channel_id(Some(&json!({}))), 0);
        assert_eq!(response_channel_id(None), 0);
    }
}
