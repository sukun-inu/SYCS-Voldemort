//! DJAudio のサーバーごとの設定の読み書き。Python の `services/settings_store.py` の `get_djaudio_*`・
//! `set_djaudio_watch_channel`・`set_djaudio_output_channel`・`get_djaudio_runtime_settings`。
//!
//! 設定は新しい置き場（`djaudio` の辞書の中）と古い置き場（サーバーの直下の `djaudio_watch_channel_id` など）の
//! 両方にありうる。読む順と、書くときに両方へ同じ値を書くところまで Python と同じにする（管理画面と Python の
//! Bot がまだ同じ設定を読むので、片方にしか書かないと古い値を返す経路が残る）。

use serde_json::{Map, Value, json};
use sycs_core::settings::Settings;

use crate::commands::server::python::int_text;

/// 監視チャンネル・出力チャンネルの ID（Python の `int`。64 ビットに収まらない数も文字のまま持つ）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSetting(String);

impl ChannelSetting {
    /// 10 進で書いた ID（Python の `str(int)`）。
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Discord のチャンネルの ID として使えるなら、その数（64 ビットに収まらない数はどのチャンネルとも合わない）。
    pub fn id(&self) -> Option<u64> {
        self.0.parse().ok()
    }
}

/// 実行のときに使う設定のまとまり。Python の `DJAudioRuntimeSettings`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runtime {
    /// URL を見張るチャンネル（未設定なら `None`。Python では 0）。
    pub watch_channel: Option<ChannelSetting>,
    /// 配信のリンクの有効期間（秒）。
    pub cache_ttl: i128,
    /// 同じ人が続けて頼めるまでの秒数。
    pub cooldown: i128,
    /// 1 通のメッセージから拾う URL の数の上限。
    pub max_urls: i128,
    /// 結果を送るチャンネル（未設定なら `None`。監視チャンネルへの返信になる）。
    pub output_channel: Option<ChannelSetting>,
}

/// 設定が無いときの値（環境変数 `DJAUDIO_CACHE_TTL_SECONDS`・`DJAUDIO_COOLDOWN_SECONDS`・
/// `DJAUDIO_MAX_URLS_PER_MSG`。Python の config）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Defaults {
    /// 有効期間の既定（秒）。
    pub cache_ttl: i64,
    /// 続けて頼めるまでの既定（秒）。
    pub cooldown: i64,
    /// URL の数の上限の既定。
    pub max_urls: i64,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            cache_ttl: 600,
            cooldown: 30,
            max_urls: 3,
        }
    }
}

/// Python の `int(値)` のうち、設定に入りうる値（JSON の値）の分。読めなければ `None`（`TypeError`・`ValueError`）。
///
/// 真偽は 0・1、小数は 0 の側へ切り捨て、文字は `int(text)`（前後の空白・全角の数字・`1_000` も読む）。
/// 128 ビットに収まらない数は読めない扱いにする（Python は桁のまま使う。設定の画面は上限で丸めて書くので、
/// 手で壊さない限り届かない）。
pub fn python_int(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(flag) => Some(i128::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .or_else(|| {
                let f = number.as_f64()?;
                // 2^127 未満なら i128 に収まる（f64 の整数部はそのまま正確に移る）。
                (f.is_finite() && f.trunc().abs() < 1.7e38).then(|| f.trunc() as i128)
            }),
        Value::String(text) => int_text(text)?.parse().ok(),
        _ => None,
    }
}

/// Python の `_read_int` の結果が正の数なら、その ID。
fn positive_channel(value: Option<&Value>) -> Option<ChannelSetting> {
    let value = value?;
    let text = match value {
        Value::Bool(true) => "1".to_string(),
        Value::String(text) => int_text(text)?,
        Value::Number(number) => match number.as_i64().map(i128::from) {
            Some(n) => n.to_string(),
            None => match number.as_u64() {
                Some(n) => n.to_string(),
                None => {
                    let f = number.as_f64()?;
                    if !f.is_finite() {
                        return None;
                    }
                    // Python の int(小数) は、その値の整数部をそのまま正確に書く。
                    format!("{:.0}", f.trunc())
                }
            },
        },
        _ => return None,
    };
    let positive = !text.starts_with('-') && !text.trim_start_matches('0').is_empty();
    positive.then_some(ChannelSetting(text))
}

/// `djaudio` の辞書（辞書でなければ空）。Python の `nested = guild_settings.get("djaudio", {})` → 辞書でなければ `{}`。
fn nested(guild: &Map<String, Value>) -> Option<&Map<String, Value>> {
    guild.get("djaudio").and_then(Value::as_object)
}

/// Python の `_get_djaudio_top_level`（直下の `key`、無ければ `djaudio_<key>`）。
fn top_level<'a>(guild: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if guild.contains_key(key) {
        return guild.get(key);
    }
    guild.get(&format!("djaudio_{key}"))
}

/// Python の `get_djaudio_settings(guild_id).get(key)`（`djaudio` の中、無ければ古い置き場。null の古い値は拾わない）。
fn detail<'a>(guild: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(n) = nested(guild)
        && n.contains_key(key)
    {
        return n.get(key);
    }
    top_level(guild, key).filter(|v| !v.is_null())
}

/// 監視チャンネル。Python の `get_djaudio_watch_channel`（4 つの置き場を順に見て、最初の正の数）。
pub fn watch_channel(guild: &Map<String, Value>) -> Option<ChannelSetting> {
    let inner = nested(guild);
    [
        guild.get("djaudio_watch_channel_id"),
        guild.get("djaudio_watch_channel"),
        inner.and_then(|n| n.get("watch_channel_id")),
        inner.and_then(|n| n.get("channel_id")),
    ]
    .into_iter()
    .find_map(positive_channel)
}

/// 出力チャンネル。Python の `get_djaudio_output_channel`（`djaudio` の中だけを見る）。
pub fn output_channel(guild: &Map<String, Value>) -> Option<ChannelSetting> {
    positive_channel(nested(guild).and_then(|n| n.get("output_channel_id")))
}

/// 実行のときに使う設定。Python の `get_djaudio_runtime_settings`。設定が無いサーバーは全部が既定。
pub fn runtime(guild: Option<&Value>, defaults: Defaults) -> Runtime {
    let empty = Map::new();
    let guild = guild.and_then(Value::as_object).unwrap_or(&empty);
    let number = |key: &str| detail(guild, key).and_then(python_int);
    Runtime {
        watch_channel: watch_channel(guild),
        cache_ttl: number("cache_ttl").map_or(i128::from(defaults.cache_ttl), |n| n.max(60)),
        cooldown: number("cooldown").map_or(i128::from(defaults.cooldown), |n| n.max(0)),
        max_urls: number("max_urls").map_or(i128::from(defaults.max_urls), |n| n.clamp(1, 10)),
        output_channel: output_channel(guild),
    }
}

/// サーバーの設定の辞書（無ければ末尾に空で作る。辞書でなければ空に置き換える）。Python の `_get_or_create_guild`。
fn guild_entry(settings: &mut Settings, guild_id: u64) -> &mut Map<String, Value> {
    crate::commands::server::guild_entry(settings, guild_id)
}

/// Python の `current.get("djaudio", {})`（辞書でなければ `{}`）の写し。書き換えたあとで `current["djaudio"]` に戻す。
fn take_nested(current: &Map<String, Value>) -> Map<String, Value> {
    current
        .get("djaudio")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// 監視チャンネルを書く（`None` で外す）。Python の `set_djaudio_watch_channel`。
///
/// 新しい置き場（`djaudio.watch_channel_id`）と古い置き場（`djaudio_watch_channel_id`・`djaudio_watch_channel`）の
/// 3 か所に同じ値を書く。鍵の並びも Python と同じ（古い置き場の 2 つを書いてから、`djaudio` を戻す。`djaudio` が
/// 無かったサーバーでは、`djaudio` が最後に付く）。
pub fn set_watch_channel(settings: &mut Settings, guild_id: u64, channel: Option<u64>) {
    let value = channel.map_or(Value::Null, |id| json!(id));
    let current = guild_entry(settings, guild_id);
    let mut inner = take_nested(current);
    inner.insert("watch_channel_id".into(), value.clone());
    current.insert("djaudio_watch_channel_id".into(), value.clone());
    current.insert("djaudio_watch_channel".into(), value);
    current.insert("djaudio".into(), Value::Object(inner));
}

/// 出力チャンネルを書く（`None` で外す）。Python の `set_djaudio_output_channel`（`djaudio` の中だけ）。
pub fn set_output_channel(settings: &mut Settings, guild_id: u64, channel: Option<u64>) {
    let value = channel.map_or(Value::Null, |id| json!(id));
    let current = guild_entry(settings, guild_id);
    let mut inner = take_nested(current);
    inner.insert("output_channel_id".into(), value);
    current.insert("djaudio".into(), Value::Object(inner));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guild(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    /// 監視チャンネルは 4 つの置き場を順に見て、最初の正の数を使うこと（0・負・読めない値は飛ばす）。
    #[test]
    fn watch_channel_takes_the_first_positive_place() {
        let g = guild(
            json!({"djaudio_watch_channel_id": 0, "djaudio_watch_channel": "x",
            "djaudio": {"watch_channel_id": -5, "channel_id": " ７ "}}),
        );
        assert_eq!(watch_channel(&g).unwrap().text(), "7");
        let g = guild(json!({"djaudio_watch_channel": 12, "djaudio": {"watch_channel_id": 99}}));
        assert_eq!(watch_channel(&g).unwrap().id(), Some(12));
        assert_eq!(watch_channel(&guild(json!({"djaudio": "broken"}))), None);
        let huge = guild(json!({"djaudio_watch_channel_id": "123456789012345678901234567890"}));
        assert_eq!(watch_channel(&huge).unwrap().id(), None);
    }

    /// 数の設定は、新しい置き場・古い置き場の順に読み、範囲に丸め、読めなければ既定にすること。
    #[test]
    fn runtime_numbers_follow_python() {
        let d = Defaults {
            cache_ttl: 900,
            cooldown: 7,
            max_urls: 2,
        };
        let r = runtime(
            Some(&json!({"djaudio": {"cache_ttl": 5, "cooldown": -3}, "max_urls": 50})),
            d,
        );
        assert_eq!((r.cache_ttl, r.cooldown, r.max_urls), (60, 0, 10));
        // 新しい置き場に null があると、古い置き場は見ずに既定になる（Python の int(None) は TypeError）。
        let r = runtime(
            Some(&json!({"djaudio": {"cache_ttl": null}, "djaudio_cache_ttl": 1200})),
            d,
        );
        assert_eq!(r.cache_ttl, 900);
        let r = runtime(
            Some(&json!({"djaudio_cache_ttl": "1_200", "cooldown": 30.9})),
            d,
        );
        assert_eq!((r.cache_ttl, r.cooldown, r.max_urls), (1200, 30, 2));
        assert_eq!(runtime(None, d).cache_ttl, 900);
    }

    /// 書くときは 3 か所に同じ値を書き、鍵の並びが Python と同じであること。
    #[test]
    fn writes_go_to_every_place_in_python_order() {
        let mut s = Settings::default();
        s.guilds.insert("1".into(), json!({"a": 1}));
        set_watch_channel(&mut s, 1, Some(5));
        let keys: Vec<&String> = s.guilds["1"].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "a",
                "djaudio_watch_channel_id",
                "djaudio_watch_channel",
                "djaudio"
            ]
        );
        set_output_channel(&mut s, 1, Some(6));
        assert_eq!(
            s.guilds["1"]["djaudio"],
            json!({"watch_channel_id": 5, "output_channel_id": 6})
        );
    }
}
