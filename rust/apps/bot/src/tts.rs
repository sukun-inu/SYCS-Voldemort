//! 読み上げ（TTS）の設定の読み方と、読み上げる文の作り方。Python の `services/tts_store.py` と
//! `services/tts_service.py` の `_clean_text`・`_apply_dictionary`・`enqueue_message`・`enqueue_vc_event` の文の部分。
//!
//! 音声の接続と再生（B9b）はここに無い。ここは「何を・どの声で・どの速さで読むか」までを決める（Discord にも
//! 合成の API にも触らない）。
//!
//! 文の整え方は Python の `re.sub` と同じ結果にする。Rust の正規表現の `\w`・`\d`・`\s` は、Python と含む文字が
//! 少し違うので、正規表現は使わず、Python の判定の表（[`crate::python_chars`]）で文字を見ながら左から読む。

use serde_json::{Map, Value};

use crate::commands::CommandError;
use crate::commands::server::python::{dict_setting, int_text, strip};
use crate::commands::settings::python_truthy;
use crate::python_chars::{Class, is};
use crate::python_repr::python_str;

/// 声の既定（Python の `_DEFAULT_VOICE`）。
pub const DEFAULT_VOICE: &str = "Kyoko";
/// 速度の既定（Python の `_DEFAULT_RATE`）。
pub const DEFAULT_RATE: i64 = 200;
/// 整える前の本文を何文字で切るかの既定（Python の `_MAX_TEXT_LEN`）。
pub const DEFAULT_MAX_LENGTH: i64 = 100;
/// 名前を付けた文を何文字で切るかの既定（Python の `speak_max_length` の既定）。
pub const DEFAULT_SPEAK_MAX_LENGTH: i64 = 200;
/// 設定の鍵（サーバーの設定の中のまとまり）。
pub const TTS_KEY: &str = "tts";
/// 長すぎた本文の末尾に付ける文。
pub const OMITTED: &str = "、以下省略";

/// 文字の並びの `at` から `prefix` が始まるか。
fn starts_with(chars: &[char], at: usize, prefix: &str) -> bool {
    prefix
        .chars()
        .enumerate()
        .all(|(n, p)| chars.get(at + n) == Some(&p))
}

/// `at` から、その種類の文字が 1 つ以上続くところの終わり（続かなければ `None`）。
fn run_of(chars: &[char], at: usize, keep: impl Fn(char) -> bool) -> Option<usize> {
    let end = chars[at..]
        .iter()
        .position(|c| !keep(*c))
        .map_or(chars.len(), |n| at + n);
    (end > at).then_some(end)
}

/// `at` から `\d+>` が続けば、`>` の次の位置。
fn digits_then_close(chars: &[char], at: usize) -> Option<usize> {
    let end = run_of(chars, at, |c| is(Class::Digit, c))?;
    (chars.get(end) == Some(&'>')).then_some(end + 1)
}

/// Python の `re.sub(パターン, 置き換え, 文)`。`matcher` は、その位置で当たれば（終わり, 置き換える文）を返す。
/// 左から、重ならないように置き換える（当たらなければ 1 文字進む）。
fn substitute(text: &str, matcher: impl Fn(&[char], usize) -> Option<(usize, String)>) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        match matcher(&chars, i) {
            Some((end, replacement)) => {
                out.push_str(&replacement);
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// `https?://\S+` → `URL`。
fn url_at(chars: &[char], at: usize) -> Option<(usize, String)> {
    let scheme = if starts_with(chars, at, "https://") {
        8
    } else if starts_with(chars, at, "http://") {
        7
    } else {
        return None;
    };
    let end = run_of(chars, at + scheme, |c| !is(Class::Space, c))?;
    Some((end, "URL".into()))
}

/// `<@!?\d+>` → `メンション`。
fn mention_at(chars: &[char], at: usize) -> Option<(usize, String)> {
    if !starts_with(chars, at, "<@") {
        return None;
    }
    let after = at + 2;
    let end = match chars.get(after) {
        Some('!') => {
            digits_then_close(chars, after + 1).or_else(|| digits_then_close(chars, after))
        }
        _ => digits_then_close(chars, after),
    }?;
    Some((end, "メンション".into()))
}

/// `<#\d+>` → `チャンネル`、`<@&\d+>` → `ロール`。
fn tagged_at(
    prefix: &'static str,
    name: &'static str,
) -> impl Fn(&[char], usize) -> Option<(usize, String)> {
    move |chars, at| {
        if !starts_with(chars, at, prefix) {
            return None;
        }
        let end = digits_then_close(chars, at + prefix.chars().count())?;
        Some((end, name.into()))
    }
}

/// `<a?:(\w+):\d+>` → 名前の部分。
fn emoji_at(chars: &[char], at: usize) -> Option<(usize, String)> {
    if chars.get(at) != Some(&'<') {
        return None;
    }
    // `a?` は、まず `a` を取ってみて、だめなら取らずに試す。
    let starts = [at + 2, at + 1]
        .into_iter()
        .filter(|&colon| colon == at + 1 || chars.get(at + 1) == Some(&'a'));
    for colon in starts {
        if chars.get(colon) != Some(&':') {
            continue;
        }
        let Some(name_end) = run_of(chars, colon + 1, |c| is(Class::Word, c)) else {
            continue;
        };
        if chars.get(name_end) != Some(&':') {
            continue;
        }
        if let Some(end) = digits_then_close(chars, name_end + 1) {
            return Some((end, chars[colon + 1..name_end].iter().collect()));
        }
    }
    None
}

/// 読み上げに向かない要素を置き換え、長すぎれば切る。Python の `_clean_text`。
///
/// URL・メンション・チャンネル・ロールは種類の名前に、カスタム絵文字は名前だけにする。前後の空白を落とし、
/// `max_len` 文字を超えたら、そこで切って「、以下省略」を付ける（数えるのは文字。負の数は Python の `[:n]` と
/// 同じく末尾から数える）。
pub fn clean_text(text: &str, max_len: i64) -> String {
    let text = substitute(text, url_at);
    let text = substitute(&text, mention_at);
    let text = substitute(&text, tagged_at("<#", "チャンネル"));
    let text = substitute(&text, tagged_at("<@&", "ロール"));
    let text = substitute(&text, emoji_at);
    let text = strip(&text);
    if text.chars().count() as i64 > max_len {
        return format!("{}{OMITTED}", python_head(text, max_len));
    }
    text.to_string()
}

/// 辞書の読みを当てる。Python の `_apply_dictionary`。
///
/// 1 回の走査で置き換えて、置き換えた結果にはもう当てない（「鈴木→すずき」「すずき→スズキ」で「鈴木」が
/// 「スズキ」にならない）。同じ位置に複数の語が当たるときは長い方（同じ長さなら辞書の登録順で先の方）。
/// 空の見出し語は使わない。
pub fn apply_dictionary(text: &str, dictionary: &[(String, String)]) -> String {
    let mut words: Vec<(Vec<char>, &str)> = dictionary
        .iter()
        .filter(|(word, _)| !word.is_empty())
        .map(|(word, reading)| (word.chars().collect(), reading.as_str()))
        .collect();
    if words.is_empty() {
        return text.to_string();
    }
    // 長い順（同じ長さは登録順のまま）。
    words.sort_by_key(|(word, _)| std::cmp::Reverse(word.len()));
    substitute(text, |chars, at| {
        words.iter().find_map(|(word, reading)| {
            let fits = chars.len() - at >= word.len() && chars[at..at + word.len()] == word[..];
            fits.then(|| (at + word.len(), (*reading).to_string()))
        })
    })
}

/// サーバーの読み上げの設定（`tts` のまとまり）。Python の `get_tts_settings`。
pub fn settings(guild: Option<&Value>) -> Result<&Map<String, Value>, CommandError> {
    dict_setting(guild, TTS_KEY)
}

/// Python の `int(値)`（設定に入りうる値）。読めなければ `Err`（Python では例外）。
pub(crate) fn python_int(value: &Value, what: &'static str) -> Result<i64, CommandError> {
    let broken = || CommandError::BrokenSetting(what);
    match value {
        Value::Bool(flag) => Ok(i64::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|f| f.is_finite())
                    .map(|f| f.trunc() as i64)
            })
            .ok_or_else(broken),
        Value::String(text) => int_text(text)
            .and_then(|t| t.parse().ok())
            .ok_or_else(broken),
        _ => Err(broken()),
    }
}

/// 辞書（見出し語と読み。登録順）。Python の `get_tts_dictionary`（辞書でなければ空。鍵も値も `str()`）。
pub fn dictionary(tts: &Map<String, Value>) -> Vec<(String, String)> {
    match tts.get("dictionary") {
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(word, reading)| (word.clone(), python_str(reading)))
            .collect(),
        _ => Vec::new(),
    }
}

/// その人の声・速度の上書き。Python の `get_user_tts_settings`（`user_settings` が辞書でなければ空）。
pub fn user_settings(
    tts: &Map<String, Value>,
    user_id: u64,
) -> Result<Option<&Map<String, Value>>, CommandError> {
    let Some(Value::Object(users)) = tts.get("user_settings") else {
        return Ok(None);
    };
    match users.get(&user_id.to_string()) {
        None => Ok(None),
        Some(Value::Object(entry)) => Ok(Some(entry)),
        // `dict(...)` にできる空の並び・空の文字は、空の上書き。
        Some(Value::Array(items)) if items.is_empty() => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(_) => Err(CommandError::BrokenSetting("user_settings")),
    }
}

/// 読み上げるテキストチャンネル。Python の `get_effective_vc_watch` の 2 つ目（`[int(cid) for cid in …]`）。
///
/// Python は並びでなくても回す（文字列なら 1 文字ずつ、辞書なら鍵）。読めない要素があれば `Err`（例外）。
pub fn watch_channel_ids(tts: &Map<String, Value>) -> Result<Vec<i64>, CommandError> {
    let what = "watch_channel_ids";
    match tts.get(what) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|v| python_int(v, what)).collect(),
        Some(Value::String(text)) => text
            .chars()
            .map(|c| python_int(&Value::String(c.to_string()), what))
            .collect(),
        Some(Value::Object(map)) => map
            .keys()
            .map(|k| python_int(&Value::String(k.clone()), what))
            .collect(),
        Some(_) => Err(CommandError::BrokenSetting(what)),
    }
}

/// 読み上げる VC と、読み上げるテキストチャンネル。Python の `get_effective_vc_watch`。
///
/// 一時参加（/tts join）中なら、その VC だけ（テキストチャンネルの並びは読まない）。そうでなければ設定の VC と並び
/// （読めなければ `Err`）。
pub fn effective_vc_watch(
    tts: &Map<String, Value>,
    temp_override: Option<u64>,
) -> Result<(Option<i64>, Vec<i64>), CommandError> {
    if let Some(vc) = temp_override {
        return Ok((i64::try_from(vc).ok(), Vec::new()));
    }
    let vc = vc_channel_id(tts)?;
    Ok((vc, watch_channel_ids(tts)?))
}

/// 設定の VC。Python の `get_effective_vc_watch` の 1 つ目（一時参加の上書きの無いとき）。
pub fn vc_channel_id(tts: &Map<String, Value>) -> Result<Option<i64>, CommandError> {
    match tts.get("vc_channel_id") {
        Some(value) if python_truthy(Some(value)) => Ok(Some(python_int(value, "vc_channel_id")?)),
        _ => Ok(None),
    }
}

/// 値があって真ならそれ（Python の `a or b`）。
fn first_truthy<'a>(values: &[Option<&'a Value>]) -> Option<&'a Value> {
    values
        .iter()
        .flatten()
        .copied()
        .find(|value| python_truthy(Some(value)))
}

/// 何を・どの声で・どの速さで読むか。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utterance {
    /// 読む文。
    pub text: String,
    /// 声の名前。
    pub voice: String,
    /// 速度。
    pub rate: i64,
    /// 読み上げる VC。
    pub vc_channel_id: i64,
}

/// メッセージを読み上げるときの文。Python の `enqueue_message` の、合成を頼む前まで。
///
/// 読み上げが無効・VC が未設定・整えた本文が空なら `Ok(None)`（読まない）。設定が読めない形なら `Err`
/// （Python では例外で、そのメッセージは読まれない）。
pub fn message_utterance(
    guild: Option<&Value>,
    temp_override: Option<u64>,
    user_id: u64,
    display_name: &str,
    text: &str,
) -> Result<Option<Utterance>, CommandError> {
    let tts = settings(guild)?;
    if !python_truthy(tts.get("enabled")) {
        return Ok(None);
    }
    // Python は VC と一緒に読み上げるチャンネルの並びも読む（読めなければ、ここで例外）。
    let (vc, _) = effective_vc_watch(tts, temp_override)?;
    let Some(vc) = vc else {
        return Ok(None);
    };
    let max_len = match tts.get("max_length") {
        Some(value) => python_int(value, "max_length")?,
        None => DEFAULT_MAX_LENGTH,
    };
    let cleaned = clean_text(text, max_len);
    if cleaned.is_empty() {
        return Ok(None);
    }
    let dictionary = dictionary(tts);
    let cleaned = apply_dictionary(&cleaned, &dictionary);
    let user = user_settings(tts, user_id)?;
    let voice = first_truthy(&[user.and_then(|u| u.get("voice")), tts.get("default_voice")])
        .map_or_else(|| DEFAULT_VOICE.to_string(), python_str);
    let rate = match first_truthy(&[user.and_then(|u| u.get("rate")), tts.get("default_rate")]) {
        Some(value) => python_int(value, "rate")?,
        None => DEFAULT_RATE,
    };
    let speak_max = match tts.get("speak_max_length") {
        Some(value) => python_int(value, "speak_max_length")?,
        None => DEFAULT_SPEAK_MAX_LENGTH,
    };
    let read_name = tts.get("read_name").is_none_or(|v| python_truthy(Some(v)));
    // 名前にも辞書を当てる（名前の読みを登録する人が多い）。
    let speak = if read_name {
        format!("{}。{cleaned}", apply_dictionary(display_name, &dictionary))
    } else {
        cleaned
    };
    let speak = if speak.chars().count() as i64 > speak_max {
        python_head(&speak, speak_max)
    } else {
        speak
    };
    Ok(Some(Utterance {
        text: speak,
        voice,
        rate,
        vc_channel_id: vc,
    }))
}

/// Python の `text[:n]`（負の数は、末尾から数えて落とす）。
fn python_head(text: &str, n: i64) -> String {
    let count = text.chars().count() as i64;
    let keep = if n < 0 {
        (count + n).max(0)
    } else {
        n.min(count)
    };
    text.chars()
        .take(usize::try_from(keep).unwrap_or(0))
        .collect()
}

/// VC の入退室を読み上げるときの文。Python の `enqueue_vc_event` の、合成を頼む前まで。
///
/// `display_name` が空なら `name`（Python の `str(member)`）を使う。読み上げが無効・入退室の読み上げが無効・
/// VC が未設定なら `Ok(None)`。
pub fn vc_event_utterance(
    guild: Option<&Value>,
    temp_override: Option<u64>,
    display_name: &str,
    name: &str,
    joined: bool,
) -> Result<Option<Utterance>, CommandError> {
    let tts = settings(guild)?;
    if !python_truthy(tts.get("enabled")) || !python_truthy(tts.get("vc_notify")) {
        return Ok(None);
    }
    let (vc, _) = effective_vc_watch(tts, temp_override)?;
    let Some(vc) = vc else {
        return Ok(None);
    };
    let who = if display_name.is_empty() {
        name
    } else {
        display_name
    };
    let text = if joined {
        format!("{who}が参加しました")
    } else {
        format!("{who}が退出しました")
    };
    let text = apply_dictionary(&text, &dictionary(tts));
    let voice = first_truthy(&[tts.get("default_voice")])
        .map_or_else(|| DEFAULT_VOICE.to_string(), python_str);
    let rate = match first_truthy(&[tts.get("default_rate")]) {
        Some(value) => python_int(value, "default_rate")?,
        None => DEFAULT_RATE,
    };
    Ok(Some(Utterance {
        text,
        voice,
        rate,
        vc_channel_id: vc,
    }))
}

/// 合成の API の場所の既定（Python の `TTS_BASE_URL` の既定）。
pub const DEFAULT_BASE_URL: &str = "http://localhost:8080";
/// 声の一覧を取るときの待ち時間（Python の `fetch_voices` の 10 秒）。
pub const VOICES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 合成の API（声の一覧。合成そのものは B9b で足す）。プロセスに 1 つだけ作って使い回す。
pub struct TtsApi {
    base_url: String,
    http: reqwest::Client,
}

impl TtsApi {
    /// 場所を受け取って作る。末尾の `/` は落とす（Python の `rstrip("/")`）。
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// 使える声の名前。Python の `fetch_voices`（取れなければ空。失敗はログに残す）。
    pub async fn fetch_voices(&self) -> Vec<String> {
        let url = format!("{}/api/v1/voices", self.base_url);
        let sent = self
            .http
            .get(&url)
            .query(&[("locale", "ja")])
            .timeout(VOICES_TIMEOUT)
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(e) => {
                tracing::error!("[TTS] fetch_voices error: {}", e.without_url());
                return Vec::new();
            }
        };
        if response.status() != reqwest::StatusCode::OK {
            return Vec::new();
        }
        // aiohttp の `resp.json()` が読む種類（`application/json` か `application/…+json`）。
        let is_json = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| crate::metal::is_json_content_type(&v.to_ascii_lowercase()));
        let body = response.bytes().await.unwrap_or_default();
        if !is_json {
            tracing::error!("[TTS] fetch_voices error: JSON でない応答");
            return Vec::new();
        }
        let data: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        voice_names(&data)
    }
}

/// 合成を待つ時間（Python の `_synthesize` の 30 秒）。
pub const SYNTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl TtsApi {
    /// 文を合成して、音声の場所と、かかったミリ秒を返す。Python の `_synthesize`。
    ///
    /// `POST {TTS_BASE_URL}/api/v1/synthesize`（`{"text","voice","rate","format":"wav"}`）。200 以外・応答が読めない・
    /// つながらないときは場所なし（理由はログに残す。失敗までにかかった時間も返す）。成功したら
    /// `{TTS_BASE_URL}{応答の url}`。
    pub async fn synthesize(&self, text: &str, voice: &str, rate: i64) -> (Option<String>, u64) {
        let started = std::time::Instant::now();
        let ms = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let body = serde_json::json!({"text": text, "voice": voice, "rate": rate, "format": "wav"});
        let sent = self
            .http
            .post(format!("{}/api/v1/synthesize", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .timeout(SYNTH_TIMEOUT)
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(e) => {
                tracing::error!("[TTS] synthesize error（{}ms）: {}", ms(), e.without_url());
                return (None, ms());
            }
        };
        let status = response.status();
        // aiohttp の `resp.json()` が読む種類でなければ、Python は例外になる（場所なし）。
        let is_json = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| crate::metal::is_json_content_type(&v.to_ascii_lowercase()));
        let bytes = response.bytes().await.unwrap_or_default();
        if status != reqwest::StatusCode::OK {
            let text = String::from_utf8_lossy(&bytes);
            let head: String = text.chars().take(200).collect();
            tracing::error!("[TTS] API {}（{}ms）: {head}", status.as_u16(), ms());
            return (None, ms());
        }
        let url = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .filter(|_| is_json)
            .and_then(|data| data.get("url").map(python_str));
        let Some(url) = url else {
            tracing::error!("[TTS] synthesize error（{}ms）: 応答に url が無い", ms());
            return (None, ms());
        };
        tracing::info!(
            "[TTS] 合成 {}ms（{}文字 / voice={voice}）",
            ms(),
            text.chars().count()
        );
        (Some(format!("{}{url}", self.base_url)), ms())
    }
}

/// 声の一覧の応答から、名前を取り出す。Python の `fetch_voices` の後ろ半分。
///
/// 並びならそのまま、辞書なら `voices` の並び。要素は辞書で、`name` が真のものだけ（`str()` にする）。
pub fn voice_names(data: &Value) -> Vec<String> {
    let voices = match data {
        Value::Array(items) => items.as_slice(),
        Value::Object(map) => match map.get("voices") {
            Some(Value::Array(items)) => items.as_slice(),
            _ => &[],
        },
        _ => &[],
    };
    voices
        .iter()
        .filter_map(|v| v.as_object()?.get("name"))
        .filter(|name| python_truthy(Some(name)))
        .map(python_str)
        .collect()
}

/// 声の補完の候補。Python の `_voice_autocomplete`（入っている文字を含むもの。大文字小文字は見ない。25 件まで）。
pub fn voice_choices(voices: &[String], current: &str) -> Vec<String> {
    let needle = current.to_lowercase();
    voices
        .iter()
        .filter(|v| v.to_lowercase().contains(&needle))
        .take(25)
        .cloned()
        .collect()
}
