//! 選択肢（チャンネル・ロール・声）の解決。Python の `webapp_admin/schema/choices.py`（`resolve`・`_channels`・
//! `_voice_channels`・`_roles`・`_tts_voices`）と、`webapp_admin/auth.py` の `_fetch_guild_channels`・`_retry_after`・
//! `_of_type`・`get_guild_channels`・`get_guild_voice_channels`・`get_guild_roles` の写し。
//!
//! - 1 回の要求につき、要る供給元だけを 1 回ずつ、並べて取る（`asyncio.gather`）。取れなかった供給元は空の並び
//!   （理由はログに残す）
//! - チャンネルの一覧（テキストとボイスは同じ `/guilds/{id}/channels`）はサーバーごとに 60 秒使い回す。取りに行くのは
//!   サーバーごとに 1 つずつ（待っているあいだに別の要求が取ってきていれば、それを使う）。429 なら `Retry-After`
//!   （読めなければ 30 秒、長くても 300 秒）のあいだ取りに行かない。失敗したときは古い一覧があればそれを返す
//! - ロールは毎回取る（使い回しは無い）。`@everyone` を除き、位置の大きい順
//! - 声は TTS の API（[`crate::apps::voices`]）を 3 秒で見切る
//!
//! 時刻はアプリの時計（[`crate::app::AdminApp::now`]。Python の `time.time()`）。
//!
//! Python と違うところ: チャンネルの `position` が数でも文字でもない並び（並び・辞書・null が 2 つ以上）は、Python は
//! 並びどうしなら並べ、ほかは TypeError。Rust はどれも TypeError（その供給元は空）。Discord は数しか返さない。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Map, Value};
use tracing::warn;

use crate::apps::schema::ChoiceSource;
use crate::apps::voices::Voices;
use crate::auth::{BotGet, Discord};
use crate::python;

/// チャンネルの一覧を使い回す長さ（秒。`_GUILD_CHANNELS_TTL`）。
pub const CHANNELS_TTL: f64 = 60.0;
/// `Retry-After` が読めないときに待つ長さ（秒。`_GUILD_CHANNELS_COOLDOWN_DEFAULT`）。
pub const COOLDOWN_DEFAULT: f64 = 30.0;
/// 待つ長さの上限（秒。`_GUILD_CHANNELS_COOLDOWN_MAX`）。
pub const COOLDOWN_MAX: f64 = 300.0;
/// テキストチャンネルの種類（`type=0`）。
pub const TEXT_CHANNEL: i64 = 0;
/// ボイスチャンネルの種類（`type=2`）。
pub const VOICE_CHANNEL: i64 = 2;

/// いまの時刻（UNIX 時間の秒）を返すもの。
pub type Now<'a> = &'a (dyn Fn() -> f64 + Send + Sync);

#[derive(Default)]
struct ChannelState {
    /// サーバー → （一覧, 取った時刻）。
    cache: HashMap<String, (Vec<Value>, f64)>,
    /// サーバー → この時刻まで取りに行かない。
    cooldown: HashMap<String, f64>,
}

/// チャンネルの一覧の使い回し（`_guild_channels_cache`・`_guild_channels_locks`・`_guild_channels_cooldown`）。
#[derive(Default)]
pub struct ChannelCache {
    state: Mutex<ChannelState>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for ChannelCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("ChannelCache")
            .field("guilds", &state.cache.len())
            .field("cooling", &state.cooldown.len())
            .finish()
    }
}

/// `float(text)`（前後の空白を落とす。数の間の `_` は 1 つずつ読む。`inf`・`nan` も読む）。読めなければ `None`。
pub fn python_float(text: &str) -> Option<f64> {
    let text = python::strip(text);
    if text.contains('_') {
        let chars: Vec<char> = text.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c != '_' {
                continue;
            }
            let before = i.checked_sub(1).and_then(|j| chars.get(j));
            let after = chars.get(i + 1);
            if !before.is_some_and(char::is_ascii_digit) || !after.is_some_and(char::is_ascii_digit)
            {
                return None;
            }
        }
    }
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    cleaned.parse::<f64>().ok()
}

/// `_retry_after`（`max(0.0, float(Retry-After))`。無い・読めないときは 30 秒）。
pub fn retry_after(header: Option<&str>) -> f64 {
    match python_float(header.unwrap_or_default()) {
        Some(seconds) => seconds.max(0.0),
        None => COOLDOWN_DEFAULT,
    }
}

impl ChannelCache {
    /// 空で作る。
    pub fn new() -> Self {
        Self::default()
    }

    fn fresh(&self, guild_id: &str, now: f64) -> (Option<Vec<Value>>, Option<Vec<Value>>) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let cached = state.cache.get(guild_id);
        let fresh = cached
            .filter(|(_, at)| now - at < CHANNELS_TTL)
            .map(|(channels, _)| channels.clone());
        (fresh, cached.map(|(channels, _)| channels.clone()))
    }

    fn cooling_until(&self, guild_id: &str) -> f64 {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.cooldown.get(guild_id).copied().unwrap_or(0.0)
    }

    fn gate(&self, guild_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(locks.entry(guild_id.to_string()).or_default())
    }

    /// `_fetch_guild_channels`。そのサーバーの全チャンネル（失敗しても例外にせず、古い一覧か空）。
    pub async fn fetch(&self, discord: &Discord, guild_id: &str, now: Now<'_>) -> Vec<Value> {
        if let (Some(channels), _) = self.fresh(guild_id, now()) {
            return channels;
        }
        let gate = self.gate(guild_id);
        let _turn = gate.lock().await;
        // 待っているあいだに他の呼び出しが取ってきているかもしれない。
        let at = now();
        let (fresh, cached) = self.fresh(guild_id, at);
        if let Some(channels) = fresh {
            return channels;
        }
        let stale = || cached.clone().unwrap_or_default();
        // 429 の直後は叩かない（叩くほど解除が遠のく）。
        if at < self.cooling_until(guild_id) {
            return stale();
        }
        let answer = match discord
            .bot_get(&format!("/guilds/{guild_id}/channels"))
            .await
        {
            Ok(answer) => answer,
            Err(e) => {
                warn!("チャンネル一覧の取得に失敗 guild_id={guild_id}: {e}");
                return stale();
            }
        };
        if answer.status == 429 {
            let wait = retry_after(answer.retry_after.as_deref()).min(COOLDOWN_MAX);
            let until = now() + wait;
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .cooldown
                .insert(guild_id.to_string(), until);
            warn!("チャンネル一覧がレート制限されました guild_id={guild_id}: {wait:.0}秒待ちます");
            return stale();
        }
        let data = match answer.json {
            Ok(data) => data,
            Err(e) => {
                warn!("チャンネル一覧の取得に失敗 guild_id={guild_id}: {e}");
                return stale();
            }
        };
        let channels = match data {
            Value::Array(items) => items,
            _ => Vec::new(),
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .cache
            .insert(guild_id.to_string(), (channels.clone(), now()));
        state.cooldown.remove(guild_id);
        channels
    }
}

/// Python の `c.get("type") == channel_type`（`False == 0`・`2.0 == 2` も当たる。文字は当たらない）。
fn type_matches(value: Option<&Value>, channel_type: i64) -> bool {
    match value {
        Some(Value::Number(number)) => number.as_f64() == Some(channel_type as f64),
        Some(Value::Bool(b)) => i64::from(*b) == channel_type,
        _ => false,
    }
}

/// 並べるときの鍵（数・真偽は数として、文字は文字として）。
enum SortKey {
    Number(f64),
    Text(String),
    Other(&'static str),
}

fn sort_key(value: &Value) -> SortKey {
    match value {
        Value::Number(number) => SortKey::Number(number.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => SortKey::Number(f64::from(u8::from(*b))),
        Value::String(text) => SortKey::Text(text.clone()),
        other => SortKey::Other(python::type_name(other)),
    }
}

/// `sorted(items, key=…)`（安定）。2 つ以上あって、数どうし・文字どうしで比べられない鍵があれば TypeError の文。
fn sorted_by_keys(items: Vec<Value>, keys: Vec<SortKey>) -> Result<Vec<Value>, String> {
    if items.len() < 2 {
        return Ok(items);
    }
    let mut pairs: Vec<(SortKey, Value)> = keys.into_iter().zip(items).collect();
    if pairs
        .iter()
        .all(|(key, _)| matches!(key, SortKey::Number(_)))
    {
        pairs.sort_by(|(a, _), (b, _)| match (a, b) {
            (SortKey::Number(a), SortKey::Number(b)) => {
                a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
            }
            _ => std::cmp::Ordering::Equal,
        });
    } else if pairs.iter().all(|(key, _)| matches!(key, SortKey::Text(_))) {
        pairs.sort_by(|(a, _), (b, _)| match (a, b) {
            (SortKey::Text(a), SortKey::Text(b)) => a.cmp(b),
            _ => std::cmp::Ordering::Equal,
        });
    } else {
        let kinds: Vec<&str> = pairs
            .iter()
            .map(|(key, _)| match key {
                SortKey::Number(_) => "number",
                SortKey::Text(_) => "str",
                SortKey::Other(name) => *name,
            })
            .collect();
        return Err(format!(
            "TypeError: '<' not supported between the sort keys {kinds:?}"
        ));
    }
    Ok(pairs.into_iter().map(|(_, item)| item).collect())
}

/// `_of_type`（種類で絞って `position` の順。要素が辞書でなければ AttributeError の文）。
pub fn of_type(channels: &[Value], channel_type: i64) -> Result<Vec<Value>, String> {
    let mut picked = Vec::new();
    for channel in channels {
        let Value::Object(fields) = channel else {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                python::type_name(channel)
            ));
        };
        if type_matches(fields.get("type"), channel_type) {
            picked.push(channel.clone());
        }
    }
    let zero = Value::from(0);
    let keys = picked
        .iter()
        .map(|channel| sort_key(channel.get("position").unwrap_or(&zero)))
        .collect();
    sorted_by_keys(picked, keys)
}

/// `c[key]`（無ければ KeyError の文）。
fn field<'a>(item: &'a Value, key: &str) -> Result<&'a Value, String> {
    item.get(key).ok_or_else(|| format!("KeyError: '{key}'"))
}

/// `_channels`（`{"value": str(c["id"]), "label": f"# {c['name']}"}`）。
pub fn text_choices(channels: &[Value]) -> Result<Vec<Value>, String> {
    of_type(channels, TEXT_CHANNEL)?
        .iter()
        .map(|channel| {
            let id = python::str_of(field(channel, "id")?);
            let label = format!("# {}", python::str_of(field(channel, "name")?));
            Ok(python::object(vec![
                ("value", Value::String(id)),
                ("label", Value::String(label)),
            ]))
        })
        .collect()
}

/// `_voice_channels`（`{"value": str(c["id"]), "label": c["name"]}`。名前はそのまま）。
pub fn voice_choices(channels: &[Value]) -> Result<Vec<Value>, String> {
    of_type(channels, VOICE_CHANNEL)?
        .iter()
        .map(|channel| {
            let id = python::str_of(field(channel, "id")?);
            let label = field(channel, "name")?.clone();
            Ok(python::object(vec![
                ("value", Value::String(id)),
                ("label", label),
            ]))
        })
        .collect()
}

/// `get_guild_roles` の後半（`@everyone` を除いて `-position` の順）。崩れた形は理由の文（Python は拾って空にする）。
pub fn sorted_roles(data: &Value) -> Result<Vec<Value>, String> {
    let items: Vec<Value> = match data {
        Value::Array(items) => items.clone(),
        Value::Object(map) => map.keys().map(|key| Value::String(key.clone())).collect(),
        Value::String(text) => text.chars().map(|c| Value::String(c.to_string())).collect(),
        other => {
            return Err(format!(
                "TypeError: '{}' object is not iterable",
                python::type_name(other)
            ));
        }
    };
    let mut kept = Vec::new();
    for role in items {
        let Value::Object(fields) = &role else {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                python::type_name(&role)
            ));
        };
        if fields.get("name") != Some(&Value::String("@everyone".to_string())) {
            kept.push(role);
        }
    }
    // `key=lambda r: -r.get("position", 0)`（単項の - は数と真偽だけ。1 つでも数でなければ TypeError）。
    let mut keys = Vec::new();
    for role in &kept {
        match role.get("position") {
            None => keys.push(SortKey::Number(-0.0)),
            Some(Value::Number(number)) => {
                keys.push(SortKey::Number(-number.as_f64().unwrap_or(0.0)));
            }
            Some(Value::Bool(b)) => keys.push(SortKey::Number(-f64::from(u8::from(*b)))),
            Some(other) => {
                return Err(format!(
                    "TypeError: bad operand type for unary -: '{}'",
                    python::type_name(other)
                ));
            }
        }
    }
    sorted_by_keys(kept, keys)
}

/// `_roles`（`{"value": str(r["id"]), "label": r["name"]}`。名前はそのまま）。
pub fn role_choices(roles: &[Value]) -> Result<Vec<Value>, String> {
    roles
        .iter()
        .map(|role| {
            let id = python::str_of(field(role, "id")?);
            let label = field(role, "name")?.clone();
            Ok(python::object(vec![
                ("value", Value::String(id)),
                ("label", label),
            ]))
        })
        .collect()
}

/// `get_guild_roles`（取れない・読めない・崩れた形は空。理由はログに残す）。
pub async fn guild_roles(discord: &Discord, guild_id: &str) -> Vec<Value> {
    let answer: Result<BotGet, String> =
        discord.bot_get(&format!("/guilds/{guild_id}/roles")).await;
    let sorted = answer
        .and_then(|answer| answer.json)
        .and_then(|data| sorted_roles(&data));
    match sorted {
        Ok(roles) => roles,
        Err(e) => {
            warn!("ロール一覧の取得に失敗 guild_id={guild_id}: {e}");
            Vec::new()
        }
    }
}

/// 選択肢を解決するもの（チャンネルの使い回しと、声の API）。
#[derive(Debug)]
pub struct Choices {
    channels: ChannelCache,
    voices: Voices,
}

/// 要るときだけ待つ。
async fn when<F>(wanted: bool, future: F) -> Option<Result<Vec<Value>, String>>
where
    F: std::future::Future<Output = Result<Vec<Value>, String>>,
{
    if wanted { Some(future.await) } else { None }
}

impl Choices {
    /// 作る（チャンネルの使い回しは空）。
    pub fn new(voices: Voices) -> Self {
        Self {
            channels: ChannelCache::new(),
            voices,
        }
    }

    /// `choices.resolve`。要る供給元だけを並べて取り、語の順の辞書にする（取れなかったものは空の並び）。
    pub async fn resolve(
        &self,
        discord: &Discord,
        sources: &[ChoiceSource],
        guild_id: &str,
        now: Now<'_>,
    ) -> Map<String, Value> {
        let wanted = |source: ChoiceSource| sources.contains(&source);
        let text = async {
            let channels = self.channels.fetch(discord, guild_id, now).await;
            text_choices(&channels)
        };
        let voice = async {
            let channels = self.channels.fetch(discord, guild_id, now).await;
            voice_choices(&channels)
        };
        let roles = async {
            let roles = guild_roles(discord, guild_id).await;
            role_choices(&roles)
        };
        let (channels, roles, voices, voice_channels) = tokio::join!(
            when(wanted(ChoiceSource::Channels), text),
            when(wanted(ChoiceSource::Roles), roles),
            when(wanted(ChoiceSource::TtsVoices), self.voices.choices()),
            when(wanted(ChoiceSource::VoiceChannels), voice),
        );
        // 語の順（channels → roles → tts_voices → voice_channels）。
        let mut resolved = Map::new();
        for (source, result) in [
            (ChoiceSource::Channels, channels),
            (ChoiceSource::Roles, roles),
            (ChoiceSource::TtsVoices, voices),
            (ChoiceSource::VoiceChannels, voice_channels),
        ] {
            let Some(result) = result else {
                continue;
            };
            let items = result.unwrap_or_else(|e| {
                warn!(
                    "選択肢の取得に失敗しました source={} guild={guild_id}: {e}",
                    source.as_str()
                );
                Vec::new()
            });
            resolved.insert(source.as_str().to_string(), Value::Array(items));
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 解決したものを並べる順が、Python の `sorted(..., key=lambda s: s.value)` と同じであること。
    #[test]
    fn sources_are_resolved_in_name_order() {
        let mut names: Vec<&str> = ChoiceSource::ALL.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["channels", "roles", "tts_voices", "voice_channels"]);
    }

    /// `Retry-After` の読み方（空白・小数・指数・`_`・負・読めない・無い）。
    #[test]
    fn retry_after_is_read_like_python_float() {
        assert_eq!(retry_after(Some(" 2.5 ")), 2.5);
        assert_eq!(retry_after(Some("1e3")), 1000.0);
        assert_eq!(retry_after(Some("1_0")), 10.0);
        assert_eq!(retry_after(Some("-3")), 0.0);
        assert_eq!(retry_after(Some("nan")), 0.0);
        assert_eq!(retry_after(Some("inf")).min(COOLDOWN_MAX), COOLDOWN_MAX);
        assert_eq!(retry_after(Some("abc")), COOLDOWN_DEFAULT);
        assert_eq!(retry_after(Some("1__0")), COOLDOWN_DEFAULT);
        assert_eq!(retry_after(Some("_1")), COOLDOWN_DEFAULT);
        assert_eq!(retry_after(None), COOLDOWN_DEFAULT);
    }

    /// 種類の比べ方（`False == 0`・`0.0 == 0`、文字の "0" は違う）と、位置の順（同じ位置は元の順）。
    #[test]
    fn channels_are_picked_and_sorted_like_python() {
        let channels = json!([
            {"id": "1", "type": 0, "name": "b", "position": 2},
            {"id": "2", "type": false, "name": "a", "position": 1},
            {"id": "3", "type": "0", "name": "x", "position": 0},
            {"id": "4", "type": 0.0, "name": "c", "position": 2},
            {"id": "5", "type": 2, "name": "v"},
            {"id": 6, "type": 0, "name": 7, "position": true}
        ]);
        let picked = text_choices(channels.as_array().unwrap()).unwrap();
        assert_eq!(
            json!(picked),
            json!([
                {"value": "2", "label": "# a"},
                {"value": "6", "label": "# 7"},
                {"value": "1", "label": "# b"},
                {"value": "4", "label": "# c"}
            ])
        );
        let voices = voice_choices(channels.as_array().unwrap()).unwrap();
        assert_eq!(json!(voices), json!([{"value": "5", "label": "v"}]));
        assert!(
            of_type(&[json!("x")], 0)
                .unwrap_err()
                .starts_with("AttributeError")
        );
        let mixed = [
            json!({"type": 0, "position": "1"}),
            json!({"type": 0, "position": 1}),
        ];
        assert!(of_type(&mixed, 0).is_err());
        let one = [json!({"type": 0, "position": null, "id": 1, "name": "n"})];
        assert_eq!(of_type(&one, 0).unwrap().len(), 1);
        let names = [
            json!({"type": 0, "position": "b"}),
            json!({"type": 0, "position": "a"}),
        ];
        assert_eq!(of_type(&names, 0).unwrap()[0]["position"], "a");
        assert_eq!(
            text_choices(&[json!({"type": 0, "id": 1})]).unwrap_err(),
            "KeyError: 'name'"
        );
    }

    /// ロールの絞り方と順（`@everyone` を除く、位置の大きい順、同じ位置は元の順、名前はそのまま）と崩れた形。
    #[test]
    fn roles_are_sorted_like_get_guild_roles() {
        let roles = json!([
            {"id": "1", "name": "@everyone", "position": 0},
            {"id": "2", "name": "a", "position": 1},
            {"id": "3", "name": "b", "position": 3},
            {"id": "4", "name": "c", "position": 1},
            {"id": 5, "name": 12}
        ]);
        let sorted = sorted_roles(&roles).unwrap();
        assert_eq!(
            json!(role_choices(&sorted).unwrap()),
            json!([
                {"value": "3", "label": "b"},
                {"value": "2", "label": "a"},
                {"value": "4", "label": "c"},
                {"value": "5", "label": 12}
            ])
        );
        assert!(sorted_roles(&json!([{"position": "1"}])).is_err());
        assert!(sorted_roles(&json!({"a": 1})).is_err());
        assert!(sorted_roles(&json!({})).unwrap().is_empty());
        assert!(sorted_roles(&Value::Null).is_err());
        assert_eq!(
            role_choices(&[json!({"name": "x"})]).unwrap_err(),
            "KeyError: 'id'"
        );
    }
}
