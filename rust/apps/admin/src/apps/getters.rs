//! 設定の値を読む関数（`Field.get`・`Collection.list`・`Panel.badge`）。Python の関数の名前（`schema.json` の
//! `fields[].get`・`collections[].list`・`badge`）で引く表 [`GETTERS`] と、その中身。
//!
//! 中身は Python の `webapp_admin/schema/panels/*.py` の関数と、そこから呼ぶ `services/settings_store.py`・
//! `services/tts_store.py`・`services/logging_service.py` の読み出しの写し。どれも Python の値の扱いのまま書く:
//!
//! - `get_guild_settings` は `dict(guilds.get(str(guild_id), {}))`、`_get_dict_setting` は
//!   `dict(settings.get(name, {}))`。辞書でない値は Python の `dict()` と同じに読む（[`py_dict`]。並びは組の並びとして
//!   読み、文字・数・null は例外）
//! - `int()`・`str()`・`bool()`・`.get(key, 既定)`・`or` は Python の型ごとの動き（[`crate::python`]）
//! - 例外は Python の型の名前と文（[`Crash`]）。`except (TypeError, ValueError)` で拾うところは、その 2 つだけを拾う
//!   （設定を読み込めていないときの `SettingsNotLoaded` は拾わない）
//!
//! 値は JSON の値で返す（Python の整数は数。64 ビットに収まらない整数だけ 10 進の文字。[`int_value`]）。
//! 基準は `tests/fixtures/getters/`（設定の JSON を決めて Python の関数を呼んだ答え）。
//!
//! Python と違うところ: 並びを `dict()` で読んだときに鍵が文字でない組（`[[1, 2]]`）は、鍵を `str()` した文字にする
//! （Python は数の鍵の辞書になる）。設定の表は Python も Rust も辞書しか書かないので、手で壊した設定にしか出てこない。

use std::sync::Arc;

use serde_json::{Map, Value};
use sycs_core::env::Env;
use sycs_core::settings::Settings;

use crate::apps::schema::int_value;
use crate::auth;
use crate::errors::Crash;
use crate::python;

/// 設定を読み込めていないときの例外の型の名前（Python の `services.settings_pg.SettingsNotLoaded`）。
pub const NOT_LOADED: &str = "SettingsNotLoaded";

/// 地震の通知の種類（`settings_store._NOTIFY_TYPE_KEYS`。辞書の鍵の並びもこの順）。
pub const NOTIFY_TYPE_KEYS: [&str; 5] = [
    "eew_forecast",
    "eew_warning",
    "tsunami",
    "quake_info",
    "bot_news",
];

/// 読み上げの声の既定（`tts.DEFAULT_VOICE`）。
pub const DEFAULT_VOICE: &str = "Kyoko";

/// DJAudio の数の設定が読めないときの値（`config.DJAUDIO_CACHE_TTL` などの環境変数）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DjaudioDefaults {
    /// `DJAUDIO_CACHE_TTL_SECONDS`（既定 600、下限 0）。
    pub cache_ttl: i64,
    /// `DJAUDIO_COOLDOWN_SECONDS`（既定 30、下限 0）。
    pub cooldown: i64,
    /// `DJAUDIO_MAX_URLS_PER_MSG`（既定 3、下限 1）。
    pub max_urls: i64,
}

impl DjaudioDefaults {
    /// 環境変数が無いときの値（Python の `config.py` の既定）。
    pub const PYTHON: Self = Self {
        cache_ttl: 600,
        cooldown: 30,
        max_urls: 3,
    };

    /// 環境変数から読む（`env_int` と同じ読み方）。
    pub fn from_env(env: &Env) -> Self {
        Self {
            cache_ttl: env.int("DJAUDIO_CACHE_TTL_SECONDS", 600, Some(0), None),
            cooldown: env.int("DJAUDIO_COOLDOWN_SECONDS", 30, Some(0), None),
            max_urls: env.int("DJAUDIO_MAX_URLS_PER_MSG", 3, Some(1), None),
        }
    }
}

/// 読む関数に渡すもの。
#[derive(Clone, Copy, Debug)]
pub struct Ctx<'a> {
    /// 設定の全体（読み込めていなければ `SettingsNotLoaded` の文）。
    pub settings: &'a Result<Arc<Settings>, String>,
    /// サーバーの ID（`str(guild_id)`）。
    pub guild_id: &'a str,
    /// DJAudio の環境変数。
    pub djaudio: &'a DjaudioDefaults,
}

/// 読む関数。
pub type Getter = fn(&Ctx<'_>) -> Result<Value, Crash>;

/// Python の関数の名前 → Rust の関数（名前の順）。名前は `schema.json` と同じ付け方（`tests/fixtures/schema/generate.py`
/// の `ref_name`。工場が作った関数は閉じ込めた値、lambda は使い道を後ろに付ける）。
pub const GETTERS: &[(&str, Getter)] = &[
    (
        "services.settings_store.get_djaudio_cache_ttl",
        djaudio_cache_ttl,
    ),
    (
        "services.settings_store.get_djaudio_cooldown",
        djaudio_cooldown,
    ),
    (
        "services.settings_store.get_djaudio_max_urls",
        djaudio_max_urls,
    ),
    (
        "services.settings_store.get_security_timeout_enabled",
        security_timeout_enabled,
    ),
    (
        "webapp_admin.schema.panels.djaudio._output_channel",
        djaudio_output_channel,
    ),
    (
        "webapp_admin.schema.panels.djaudio._watch_channel",
        djaudio_watch_channel,
    ),
    (
        "webapp_admin.schema.panels.earthquake._channel",
        earthquake_channel,
    ),
    (
        "webapp_admin.schema.panels.earthquake._min_scale",
        earthquake_min_scale,
    ),
    (
        "webapp_admin.schema.panels.earthquake._notify_types",
        earthquake_notify_types,
    ),
    (
        "webapp_admin.schema.panels.logging._chatgpt_channel",
        chatgpt_channel,
    ),
    (
        "webapp_admin.schema.panels.logging._log_channel",
        log_channel,
    ),
    ("webapp_admin.schema.panels.logging._log_level", log_level),
    (
        "webapp_admin.schema.panels.news_feeds.<lambda>[news-feeds.badge]",
        news_feeds_badge,
    ),
    (
        "webapp_admin.schema.panels.news_feeds._list",
        news_feeds_list,
    ),
    (
        "webapp_admin.schema.panels.reaction_roles._count",
        reaction_roles_count,
    ),
    (
        "webapp_admin.schema.panels.reaction_roles._list",
        reaction_roles_list,
    ),
    (
        "webapp_admin.schema.panels.security._bypass_list",
        security_bypass_list,
    ),
    ("webapp_admin.schema.panels.security._count", security_count),
    (
        "webapp_admin.schema.panels.security._trusted_list",
        security_trusted_list,
    ),
    (
        "webapp_admin.schema.panels.sticky.<lambda>[sticky.badge]",
        sticky_badge,
    ),
    ("webapp_admin.schema.panels.sticky._list", sticky_list),
    ("webapp_admin.schema.panels.tts._dict_list", tts_dict_list),
    ("webapp_admin.schema.panels.tts._enabled", tts_enabled),
    (
        "webapp_admin.schema.panels.tts._int_setting.<locals>.getter[fallback=100,key=max_length]",
        tts_max_length,
    ),
    (
        "webapp_admin.schema.panels.tts._int_setting.<locals>.getter[fallback=200,key=default_rate]",
        tts_default_rate,
    ),
    (
        "webapp_admin.schema.panels.tts._int_setting.<locals>.getter[fallback=200,key=speak_max_length]",
        tts_speak_max_length,
    ),
    ("webapp_admin.schema.panels.tts._read_name", tts_read_name),
    ("webapp_admin.schema.panels.tts._user_list", tts_user_list),
    ("webapp_admin.schema.panels.tts._vc_channel", tts_vc_channel),
    ("webapp_admin.schema.panels.tts._vc_notify", tts_vc_notify),
    ("webapp_admin.schema.panels.tts._voice", tts_voice),
    ("webapp_admin.schema.panels.tts._watch_list", tts_watch_list),
    (
        "webapp_admin.schema.panels.vc_notify._channel",
        vc_notify_channel,
    ),
    (
        "webapp_admin.schema.panels.vc_notify._filter_role",
        vc_notify_filter_role,
    ),
    ("webapp_admin.schema.panels.vc_notify._role", vc_notify_role),
    (
        "webapp_admin.schema.panels.welcome._goodbye_channel",
        goodbye_channel,
    ),
    (
        "webapp_admin.schema.panels.welcome._goodbye_message",
        goodbye_message,
    ),
    (
        "webapp_admin.schema.panels.welcome._welcome_channel",
        welcome_channel,
    ),
    (
        "webapp_admin.schema.panels.welcome._welcome_message",
        welcome_message,
    ),
];

/// 名前で引く。
pub fn find(name: &str) -> Option<Getter> {
    GETTERS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, getter)| *getter)
}

/// 名前で引いて呼ぶ。表に無い名前は `NotImplementedError`（宣言に関数が増えたのに Rust に無い。テストが先に落とす）。
pub fn call(name: &str, ctx: &Ctx<'_>) -> Result<Value, Crash> {
    match find(name) {
        Some(getter) => getter(ctx),
        None => Err(Crash::new(
            "NotImplementedError",
            format!("{name} を読む Rust の関数がありません"),
        )),
    }
}

// ── Python の値の扱い ─────────────────────────────────────────────

static NULL: Value = Value::Null;

/// `mapping.get(key)`（無ければ None）。
fn get<'a>(mapping: &'a Map<String, Value>, key: &str) -> &'a Value {
    mapping.get(key).unwrap_or(&NULL)
}

/// `mapping.get(key, default)`。
fn get_or(mapping: &Map<String, Value>, key: &str, default: Value) -> Value {
    mapping.get(key).cloned().unwrap_or(default)
}

/// `bool(mapping.get(key, default))`。
fn truthy_or(mapping: &Map<String, Value>, key: &str, default: bool) -> bool {
    mapping.get(key).map_or(default, python::truthy)
}

/// `'X' object has no attribute 'name'`。
fn no_attribute(value: &Value, name: &str) -> Crash {
    Crash::new(
        "AttributeError",
        format!(
            "'{}' object has no attribute '{name}'",
            python::type_name(value)
        ),
    )
}

/// `except (TypeError, ValueError): return fallback`（ほかの例外はそのまま投げる）。
fn catch<T>(result: Result<T, Crash>, fallback: T) -> Result<T, Crash> {
    match result {
        Err(crash) if crash.kind == "TypeError" || crash.kind == "ValueError" => Ok(fallback),
        other => other,
    }
}

/// 10 進の整数の文字が 0 より大きいか（`parsed and parsed > 0`）。
fn is_positive(text: &str) -> bool {
    !text.starts_with('-') && text != "0"
}

/// 10 進の整数の文字と数を比べる（桁の多い数は符号で決める）。
fn compare_int(text: &str, other: i64) -> std::cmp::Ordering {
    match text.parse::<i128>() {
        Ok(value) => value.cmp(&i128::from(other)),
        Err(_) if text.starts_with('-') => std::cmp::Ordering::Less,
        Err(_) => std::cmp::Ordering::Greater,
    }
}

/// `max(low, min(high, n))`（`high` が無ければ `max(low, n)`）。Python の `max`・`min` は同じなら先の値を返すが、
/// 整数どうしなので値は同じ。
fn clamp_int(text: &str, low: i64, high: Option<i64>) -> Value {
    if let Some(high) = high
        && compare_int(text, high) == std::cmp::Ordering::Greater
    {
        return Value::from(high.max(low));
    }
    if compare_int(text, low) == std::cmp::Ordering::Less {
        return Value::from(low);
    }
    int_value(text)
}

/// `int(value)` が読めなければ 0（`_get_int_setting`）。
fn int_or_zero(value: &Value) -> String {
    python::int_text(value).unwrap_or_else(|| "0".to_string())
}

/// `int(...) or None`（0 は None）。
fn int_or_none(text: &str) -> Value {
    if text == "0" {
        Value::Null
    } else {
        int_value(text)
    }
}

/// `dict(item)` の 1 つの要素を（鍵, 値）にする（CPython の `PyDict_MergeFromSeq2` の順で確かめる）。
fn pair_of(index: usize, item: &Value) -> Result<(String, Value), Crash> {
    let parts: Vec<Value> = match item {
        Value::String(text) => text.chars().map(|c| Value::String(c.to_string())).collect(),
        Value::Array(items) => items.clone(),
        Value::Object(map) => map.keys().map(|key| Value::String(key.clone())).collect(),
        _ => {
            return Err(Crash::new(
                "TypeError",
                format!("cannot convert dictionary update sequence element #{index} to a sequence"),
            ));
        }
    };
    if parts.len() != 2 {
        return Err(Crash::new(
            "ValueError",
            format!(
                "dictionary update sequence element #{index} has length {}; 2 is required",
                parts.len()
            ),
        ));
    }
    let key = match &parts[0] {
        Value::String(text) => text.clone(),
        unhashable @ (Value::Array(_) | Value::Object(_)) => {
            return Err(Crash::new(
                "TypeError",
                format!("unhashable type: '{}'", python::type_name(unhashable)),
            ));
        }
        // Python と違うところ（モジュールの説明）: 文字でない鍵は str() した文字にする。
        other => python::str_of(other),
    };
    Ok((key, parts[1].clone()))
}

/// Python の `dict(value)`。辞書は写し、並びは組の並び、文字は 1 文字ずつの組（空なら空の辞書）、ほかは
/// `'X' object is not iterable`。
pub fn py_dict(value: &Value) -> Result<Map<String, Value>, Crash> {
    match value {
        Value::Object(map) => Ok(map.clone()),
        Value::Array(items) => {
            let mut out = Map::new();
            for (index, item) in items.iter().enumerate() {
                let (key, value) = pair_of(index, item)?;
                out.insert(key, value);
            }
            Ok(out)
        }
        Value::String(text) => match text.chars().next() {
            None => Ok(Map::new()),
            Some(c) => pair_of(0, &Value::String(c.to_string())).map(|_| Map::new()),
        },
        other => Err(Crash::new(
            "TypeError",
            format!("'{}' object is not iterable", python::type_name(other)),
        )),
    }
}

/// `get_guild_settings(guild_id)`（`dict(guilds.get(str(guild_id), {}))`）。
pub fn guild_settings(ctx: &Ctx<'_>) -> Result<Map<String, Value>, Crash> {
    let settings = ctx
        .settings
        .as_ref()
        .map_err(|message| Crash::new(NOT_LOADED, message.clone()))?;
    match settings.guilds.get(ctx.guild_id) {
        None => Ok(Map::new()),
        Some(value) => py_dict(value),
    }
}

/// `_get_dict_setting`（`dict(settings.get(name, {}))`）。
fn dict_setting(guild: &Map<String, Value>, name: &str) -> Result<Map<String, Value>, Crash> {
    match guild.get(name) {
        None => Ok(Map::new()),
        Some(value) => py_dict(value),
    }
}

// ── ログ（logging.py・logging_service.get_log_settings） ─────────────

/// `_log_channel`（`get_log_settings(guild_id).get("channel_id")`）。
fn log_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    Ok(get(&guild, "log_channel_id").clone())
}

/// `_log_level`（`str(raw.get("log_level", "INFO")).upper()` が空なら INFO）。null は `"NONE"` になる（`str(None)`）。
fn log_level(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    let stored = get_or(&guild, "log_level", Value::String("INFO".to_string()));
    let level = python::str_of(&stored).to_uppercase();
    Ok(Value::String(if level.is_empty() {
        "INFO".to_string()
    } else {
        level
    }))
}

/// `_chatgpt_channel`（`get_response_channel_id(guild_id) or None`）。
fn chatgpt_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    Ok(int_or_none(&int_or_zero(get(
        &guild,
        "response_channel_id",
    ))))
}

// ── ウェルカム・グッバイ（welcome.py） ───────────────────────────

fn block_value(ctx: &Ctx<'_>, block: &str, key: &str) -> Result<Value, Crash> {
    let settings = dict_setting(&guild_settings(ctx)?, block)?;
    Ok(get(&settings, key).clone())
}

/// `_welcome_channel`。
fn welcome_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    block_value(ctx, "welcome", "channel_id")
}

/// `_welcome_message`。
fn welcome_message(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    block_value(ctx, "welcome", "message")
}

/// `_goodbye_channel`。
fn goodbye_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    block_value(ctx, "goodbye", "channel_id")
}

/// `_goodbye_message`。
fn goodbye_message(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    block_value(ctx, "goodbye", "message")
}

// ── VC 通知（vc_notify.py） ──────────────────────────────────────

fn int_setting_or_none(ctx: &Ctx<'_>, name: &str) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    Ok(int_or_none(&int_or_zero(get(&guild, name))))
}

/// `vc_notify._channel`。
fn vc_notify_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    int_setting_or_none(ctx, "vc_notify_channel_id")
}

/// `vc_notify._role`。
fn vc_notify_role(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    int_setting_or_none(ctx, "vc_notify_role_id")
}

/// `vc_notify._filter_role`。
fn vc_notify_filter_role(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    int_setting_or_none(ctx, "vc_notify_filter_role_id")
}

// ── 地震（earthquake.py・settings_store.get_earthquake_notify_types） ─

/// `earthquake._channel`。
fn earthquake_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    block_value(ctx, "earthquake", "channel_id")
}

/// `_min_scale`（`int(get_earthquake_settings(guild_id).get("min_scale", 30))`。TypeError・ValueError は 30。
/// 設定の読み出しの `dict()` の失敗も同じ try の中なので 30 になる）。
fn earthquake_min_scale(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let read = || -> Result<String, Crash> {
        let quake = dict_setting(&guild_settings(ctx)?, "earthquake")?;
        auth::py_int(&get_or(&quake, "min_scale", Value::from(30)))
    };
    catch(read(), "30".to_string()).map(|text| int_value(&text))
}

/// `_notify_types`（`get_earthquake_notify_types`。保存されていない種類は真）。
fn earthquake_notify_types(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let quake = dict_setting(&guild_settings(ctx)?, "earthquake")?;
    let stored = get_or(&quake, "notify_types", Value::Object(Map::new()));
    let Value::Object(stored) = &stored else {
        return Err(no_attribute(&stored, "get"));
    };
    let mut types = Map::new();
    for key in NOTIFY_TYPE_KEYS {
        types.insert(key.to_string(), Value::Bool(truthy_or(stored, key, true)));
    }
    Ok(Value::Object(types))
}

// ── DJAudio（djaudio.py・settings_store の get_djaudio_*） ──────────

/// `guild_settings.get("djaudio", {})` が辞書でなければ空。
fn djaudio_nested(guild: &Map<String, Value>) -> Map<String, Value> {
    match guild.get("djaudio") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

/// `_watch_channel`（`get_djaudio_watch_channel(guild_id) or None`。古い鍵から順に、0 より大きい最初の値）。
fn djaudio_watch_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    let nested = djaudio_nested(&guild);
    let candidates = [
        get(&guild, "djaudio_watch_channel_id"),
        get(&guild, "djaudio_watch_channel"),
        get(&nested, "watch_channel_id"),
        get(&nested, "channel_id"),
    ];
    for value in candidates {
        if let Some(text) = python::int_text(value)
            && is_positive(&text)
        {
            return Ok(int_value(&text));
        }
    }
    Ok(Value::Null)
}

/// `_output_channel`（`get_djaudio_output_channel(guild_id) or None`）。
fn djaudio_output_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let nested = djaudio_nested(&guild_settings(ctx)?);
    Ok(match python::int_text(get(&nested, "output_channel_id")) {
        Some(text) if is_positive(&text) => int_value(&text),
        _ => Value::Null,
    })
}

/// `get_djaudio_settings`（入れ子の djaudio に無い数の設定は、古い平らな鍵〔`cache_ttl` か `djaudio_cache_ttl`〕で補う）。
fn djaudio_settings(guild: &Map<String, Value>) -> Map<String, Value> {
    let mut result = djaudio_nested(guild);
    for key in ["cache_ttl", "cooldown", "max_urls"] {
        if result.contains_key(key) {
            continue;
        }
        let legacy = if guild.contains_key(key) {
            get(guild, key)
        } else {
            get(guild, &format!("djaudio_{key}"))
        };
        if !legacy.is_null() {
            result.insert(key.to_string(), legacy.clone());
        }
    }
    result
}

/// 数の設定を `int()` して範囲に入れる。読めなければ環境変数の値。
fn djaudio_limit(
    ctx: &Ctx<'_>,
    key: &str,
    low: i64,
    high: Option<i64>,
    fallback: i64,
) -> Result<Value, Crash> {
    let settings = djaudio_settings(&guild_settings(ctx)?);
    Ok(match python::int_text(get(&settings, key)) {
        Some(text) => clamp_int(&text, low, high),
        None => Value::from(fallback),
    })
}

/// `get_djaudio_cache_ttl`（`max(60, int(stored))`）。
fn djaudio_cache_ttl(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    djaudio_limit(ctx, "cache_ttl", 60, None, ctx.djaudio.cache_ttl)
}

/// `get_djaudio_cooldown`（`max(0, int(stored))`）。
fn djaudio_cooldown(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    djaudio_limit(ctx, "cooldown", 0, None, ctx.djaudio.cooldown)
}

/// `get_djaudio_max_urls`（`max(1, min(10, int(stored)))`）。
fn djaudio_max_urls(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    djaudio_limit(ctx, "max_urls", 1, Some(10), ctx.djaudio.max_urls)
}

// ── 読み上げ（tts.py・tts_store） ───────────────────────────────

/// `get_tts_settings`（`_get_dict_setting(guild_id, "tts")`）。
fn tts_settings(ctx: &Ctx<'_>) -> Result<Map<String, Value>, Crash> {
    dict_setting(&guild_settings(ctx)?, "tts")
}

/// `tts._enabled`（`bool(get("enabled", False))`）。
fn tts_enabled(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::Bool(truthy_or(
        &tts_settings(ctx)?,
        "enabled",
        false,
    )))
}

/// `tts._vc_notify`。
fn tts_vc_notify(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::Bool(truthy_or(
        &tts_settings(ctx)?,
        "vc_notify",
        false,
    )))
}

/// `tts._read_name`（未設定なら真）。
fn tts_read_name(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::Bool(truthy_or(
        &tts_settings(ctx)?,
        "read_name",
        true,
    )))
}

/// `tts._vc_channel`（`get("vc_channel_id") or None`）。
fn tts_vc_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let tts = tts_settings(ctx)?;
    let value = get(&tts, "vc_channel_id");
    Ok(if python::truthy(value) {
        value.clone()
    } else {
        Value::Null
    })
}

/// `tts._voice`（`str(get("default_voice") or DEFAULT_VOICE)`）。
fn tts_voice(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let tts = tts_settings(ctx)?;
    let value = get(&tts, "default_voice");
    Ok(Value::String(if python::truthy(value) {
        python::str_of(value)
    } else {
        DEFAULT_VOICE.to_string()
    }))
}

/// `_int_setting(key, fallback)` の getter（`int(get_tts_settings(guild_id).get(key, fallback))`。TypeError・ValueError
/// は fallback。設定の読み出しの `dict()` の失敗も同じ try の中）。
fn tts_int(ctx: &Ctx<'_>, key: &str, fallback: i64) -> Result<Value, Crash> {
    let read = || -> Result<String, Crash> {
        let tts = tts_settings(ctx)?;
        auth::py_int(&get_or(&tts, key, Value::from(fallback)))
    };
    catch(read(), fallback.to_string()).map(|text| int_value(&text))
}

/// `_int_setting("default_rate", 200)`。
fn tts_default_rate(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    tts_int(ctx, "default_rate", 200)
}

/// `_int_setting("max_length", 100)`（`_max_length`）。
fn tts_max_length(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    tts_int(ctx, "max_length", 100)
}

/// `_int_setting("speak_max_length", 200)`（`_speak_max_length`）。
fn tts_speak_max_length(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    tts_int(ctx, "speak_max_length", 200)
}

/// `_watch_ids`（`for cid in settings.get("watch_channel_ids", []) or []` の `int()` できるもの）。並べられない値は
/// Python と同じ例外（try の外）。
fn watch_ids(tts: &Map<String, Value>) -> Result<Vec<String>, Crash> {
    let Some(raw) = tts
        .get("watch_channel_ids")
        .filter(|raw| python::truthy(raw))
    else {
        return Ok(Vec::new());
    };
    Ok(auth::py_iter(raw)?
        .iter()
        .filter_map(python::int_text)
        .collect())
}

/// `_watch_list`。
fn tts_watch_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let rows = watch_ids(&tts_settings(ctx)?)?
        .into_iter()
        .map(|id| {
            python::object(vec![
                ("id", Value::String(id.clone())),
                ("channel_id", Value::String(id)),
            ])
        })
        .collect();
    Ok(Value::Array(rows))
}

/// `_dict_list`（`get_tts_dictionary`。辞書でなければ空、読みは `str()`）。
fn tts_dict_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let tts = tts_settings(ctx)?;
    let Some(Value::Object(dictionary)) = tts.get("dictionary") else {
        return Ok(Value::Array(Vec::new()));
    };
    let rows = dictionary
        .iter()
        .map(|(word, reading)| {
            python::object(vec![
                ("id", Value::String(word.clone())),
                ("word", Value::String(word.clone())),
                ("reading", Value::String(python::str_of(reading))),
            ])
        })
        .collect();
    Ok(Value::Array(rows))
}

/// `_user_list`（`(get("user_settings") or {}).items()`。中身が辞書で空でないものだけ）。
fn tts_user_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let tts = tts_settings(ctx)?;
    let users = match tts.get("user_settings").filter(|v| python::truthy(v)) {
        None => return Ok(Value::Array(Vec::new())),
        Some(Value::Object(users)) => users,
        Some(other) => return Err(no_attribute(other, "items")),
    };
    let rows = users
        .iter()
        .filter_map(|(user_id, cfg)| {
            let cfg = cfg.as_object().filter(|cfg| !cfg.is_empty())?;
            Some(python::object(vec![
                ("id", Value::String(user_id.clone())),
                ("user_id", Value::String(user_id.clone())),
                ("voice", get(cfg, "voice").clone()),
                ("rate", get(cfg, "rate").clone()),
            ]))
        })
        .collect();
    Ok(Value::Array(rows))
}

// ── セキュリティ（security.py・settings_store） ─────────────────────

/// `get_security_timeout_enabled`（`bool(get("security_timeout_enabled", False))`）。
fn security_timeout_enabled(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::Bool(truthy_or(
        &guild_settings(ctx)?,
        "security_timeout_enabled",
        false,
    )))
}

/// `_parse_id_list`（並びでなければ空、`int()` できない要素は捨てる）。
fn parse_id_list(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().filter_map(python::int_text).collect(),
        _ => Vec::new(),
    }
}

fn id_rows(ids: Vec<String>, column: &str) -> Value {
    Value::Array(
        ids.into_iter()
            .map(|id| {
                python::object(vec![
                    ("id", Value::String(id.clone())),
                    (column, Value::String(id)),
                ])
            })
            .collect(),
    )
}

/// `_trusted_list`（`get_trusted_user_ids`）。
fn security_trusted_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    Ok(id_rows(
        parse_id_list(get(&guild, "trusted_user_ids")),
        "user_id",
    ))
}

/// `_bypass_list`（`get_bypass_role_ids`）。
fn security_bypass_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    Ok(id_rows(
        parse_id_list(get(&guild, "bypass_role_ids")),
        "role_id",
    ))
}

/// `security._count`（信頼済みとバイパスの数の和）。
fn security_count(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let guild = guild_settings(ctx)?;
    let trusted = parse_id_list(get(&guild, "trusted_user_ids")).len();
    let bypass = parse_id_list(get(&guild, "bypass_role_ids")).len();
    Ok(Value::from(trusted + bypass))
}

// ── ニュース・スティッキー・リアクションロール ─────────────────────

/// `news_feeds._list`（辞書でない要素は飛ばす。`int(feed.get("interval") or 60)` の失敗はそのまま投げる）。
fn news_feeds_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let feeds = dict_setting(&guild_settings(ctx)?, "news_feeds")?;
    let sixty = Value::from(60);
    let mut rows = Vec::new();
    for (feed_id, feed) in &feeds {
        let Value::Object(feed) = feed else {
            continue;
        };
        let channel = get(feed, "channel_id");
        let channel = if python::truthy(channel) {
            python::str_of(channel)
        } else {
            String::new()
        };
        let interval = get(feed, "interval");
        let interval = auth::py_int(if python::truthy(interval) {
            interval
        } else {
            &sixty
        })?;
        rows.push(python::object(vec![
            ("id", Value::String(feed_id.clone())),
            ("channel_id", Value::String(channel)),
            ("query", get_or(feed, "query", Value::String(String::new()))),
            ("interval", int_value(&interval)),
            ("last_run", get(feed, "last_run").clone()),
        ]));
    }
    Ok(Value::Array(rows))
}

/// ニュースのバッジ（`len(get_news_feeds(guild_id))`）。
fn news_feeds_badge(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::from(
        dict_setting(&guild_settings(ctx)?, "news_feeds")?.len(),
    ))
}

/// `sticky._list`（項目の ID はチャンネルの ID そのもの）。
fn sticky_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let stickies = dict_setting(&guild_settings(ctx)?, "sticky_messages")?;
    let rows = stickies
        .iter()
        .filter_map(|(channel_id, entry)| {
            let entry = entry.as_object()?;
            Some(python::object(vec![
                ("id", Value::String(channel_id.clone())),
                ("channel_id", Value::String(channel_id.clone())),
                (
                    "content",
                    get_or(entry, "content", Value::String(String::new())),
                ),
                ("message_id", get(entry, "message_id").clone()),
            ]))
        })
        .collect();
    Ok(Value::Array(rows))
}

/// スティッキーのバッジ（`len(get_sticky_messages(guild_id))`）。
fn sticky_badge(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    Ok(Value::from(
        dict_setting(&guild_settings(ctx)?, "sticky_messages")?.len(),
    ))
}

/// `reaction_roles._list`（`"<message_id>:<emoji>"` を項目の ID に平らにする）。
fn reaction_roles_list(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let roles = dict_setting(&guild_settings(ctx)?, "reaction_roles")?;
    let mut rows = Vec::new();
    for (message_id, entries) in &roles {
        let Value::Object(entries) = entries else {
            continue;
        };
        for (emoji, role_id) in entries {
            rows.push(python::object(vec![
                ("id", Value::String(format!("{message_id}:{emoji}"))),
                ("message_id", Value::String(message_id.clone())),
                ("emoji", Value::String(emoji.clone())),
                ("role_id", Value::String(python::str_of(role_id))),
            ]));
        }
    }
    Ok(Value::Array(rows))
}

/// `reaction_roles._count`（絵文字ごとの割り当ての総数。辞書でない要素は数えない）。
fn reaction_roles_count(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let roles = dict_setting(&guild_settings(ctx)?, "reaction_roles")?;
    let count: usize = roles
        .values()
        .filter_map(Value::as_object)
        .map(Map::len)
        .sum();
    Ok(Value::from(count))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::apps::schema::schema;

    const GUILD: &str = "900000000000000001";

    fn settings(guild: Value) -> Result<Arc<Settings>, String> {
        let mut settings = Settings::default();
        settings.guilds.insert(GUILD.to_string(), guild);
        Ok(Arc::new(settings))
    }

    fn read(name: &str, guild: Value) -> Result<Value, Crash> {
        let settings = settings(guild);
        let ctx = Ctx {
            settings: &settings,
            guild_id: GUILD,
            djaudio: &DjaudioDefaults::PYTHON,
        };
        call(name, &ctx)
    }

    /// 宣言（`schema.json`）が指す読む関数（入力欄の get・一覧の list・バッジ）の名前と、Rust の表の名前が
    /// ちょうど同じであること。宣言に入力欄が増えたのに Rust が知らない・Rust に余りがある、を CI で気づく。
    #[test]
    fn every_schema_function_has_a_rust_getter() {
        let mut wanted = BTreeSet::new();
        for panel in &schema().panels {
            wanted.extend(panel.fields.iter().filter_map(|f| f.get.clone()));
            wanted.extend(panel.collections.iter().filter_map(|c| c.list.clone()));
            wanted.extend(panel.badge.clone());
        }
        let known: BTreeSet<String> = GETTERS
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();
        assert_eq!(known.len(), GETTERS.len(), "表に同じ名前が 2 つある");
        assert_eq!(wanted, known);
        let names: Vec<&str> = GETTERS.iter().map(|(name, _)| *name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "表は名前の順に並べる");
    }

    /// 地震の通知の種類の鍵が、Python の `_NOTIFY_TYPE_KEYS` と同じ並びであること（画面が固定の順で読む）。
    #[test]
    fn notify_type_keys_match_python() {
        let source = include_str!("../../../../../services/settings_store.py");
        let start = source
            .find("_NOTIFY_TYPE_KEYS: tuple[str, ...] = (")
            .unwrap();
        let end = start + source[start..].find(')').unwrap();
        let keys: Vec<&str> = source[start..end]
            .lines()
            .skip(1)
            .map(|line| line.trim().trim_end_matches(',').trim_matches('"'))
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(keys, NOTIFY_TYPE_KEYS);
    }

    /// `dict()` の読み方（辞書・組の並び・空の文字・例外の型と文）。
    #[test]
    fn dict_follows_python() {
        assert_eq!(
            Value::Object(py_dict(&json!({"a": 1})).unwrap()),
            json!({"a": 1})
        );
        assert_eq!(
            Value::Object(py_dict(&json!([["a", 1], "bc", {"d": 0, "e": 0}, ["a", 2]])).unwrap()),
            json!({"a": 2, "b": "c", "d": "e"})
        );
        assert!(py_dict(&json!("")).unwrap().is_empty());
        let message = |value: Value| py_dict(&value).unwrap_err();
        assert_eq!(
            message(json!("abc")),
            Crash::new(
                "ValueError",
                "dictionary update sequence element #0 has length 1; 2 is required"
            )
        );
        assert_eq!(
            message(json!([["a", 1], 5])),
            Crash::new(
                "TypeError",
                "cannot convert dictionary update sequence element #1 to a sequence"
            )
        );
        assert_eq!(
            message(json!([["a"]])).message,
            "dictionary update sequence element #0 has length 1; 2 is required"
        );
        assert_eq!(
            message(json!([[[1], 2]])),
            Crash::new("TypeError", "unhashable type: 'list'")
        );
        assert_eq!(
            message(Value::Null),
            Crash::new("TypeError", "'NoneType' object is not iterable")
        );
        assert_eq!(
            message(json!(1.5)).message,
            "'float' object is not iterable"
        );
    }

    /// 数の設定の範囲（`max(60, n)`・`max(1, min(10, n))`）と、読めないときの環境変数の値。
    #[test]
    fn djaudio_limits_are_clamped_like_python() {
        let ttl = "services.settings_store.get_djaudio_cache_ttl";
        let cooldown = "services.settings_store.get_djaudio_cooldown";
        let urls = "services.settings_store.get_djaudio_max_urls";
        let guild = json!({"djaudio": {"cache_ttl": "59", "cooldown": -3, "max_urls": 99}});
        assert_eq!(read(ttl, guild.clone()), Ok(json!(60)));
        assert_eq!(read(cooldown, guild.clone()), Ok(json!(0)));
        assert_eq!(read(urls, guild), Ok(json!(10)));
        let legacy = json!({
            "djaudio": {"cache_ttl": null},
            "cache_ttl": 5000,
            "cooldown": "x",
            "djaudio_max_urls": 0
        });
        assert_eq!(read(ttl, legacy.clone()), Ok(json!(600)));
        assert_eq!(read(cooldown, legacy.clone()), Ok(json!(30)));
        assert_eq!(read(urls, legacy), Ok(json!(1)));
        let huge = "1000000000000000000000000000000000000000";
        assert_eq!(clamp_int(huge, 60, None), json!(huge));
        assert_eq!(clamp_int(&format!("-{huge}"), 1, Some(10)), json!(1));
    }

    /// 読み込めていない設定の例外は、TypeError・ValueError を拾う関数でも拾わないこと（Python の
    /// `SettingsNotLoaded` は RuntimeError）。
    #[test]
    fn settings_not_loaded_is_not_swallowed() {
        let settings: Result<Arc<Settings>, String> = Err("読めない".to_string());
        let ctx = Ctx {
            settings: &settings,
            guild_id: GUILD,
            djaudio: &DjaudioDefaults::PYTHON,
        };
        for (name, _) in GETTERS {
            assert_eq!(
                call(name, &ctx),
                Err(Crash::new(NOT_LOADED, "読めない")),
                "{name}"
            );
        }
        assert_eq!(
            call("webapp_admin.schema.panels.nothing._x", &ctx)
                .unwrap_err()
                .kind,
            "NotImplementedError"
        );
    }

    /// 地震の最小震度は、壊れたブロック（`dict()` の失敗）も 30 に倒すこと。通知の種類は辞書でなければ AttributeError。
    #[test]
    fn earthquake_getters_catch_like_python() {
        let name = "webapp_admin.schema.panels.earthquake._min_scale";
        assert_eq!(read(name, json!({"earthquake": 5})), Ok(json!(30)));
        assert_eq!(
            read(name, json!({"earthquake": {"min_scale": 45.7}})),
            Ok(json!(45))
        );
        let types = "webapp_admin.schema.panels.earthquake._notify_types";
        assert_eq!(
            read(types, json!({"earthquake": {"notify_types": []}})),
            Err(Crash::new(
                "AttributeError",
                "'list' object has no attribute 'get'"
            ))
        );
        assert_eq!(
            read(
                types,
                json!({"earthquake": {"notify_types": {"tsunami": 0, "x": true}}})
            ),
            Ok(json!({
                "eew_forecast": true,
                "eew_warning": true,
                "tsunami": false,
                "quake_info": true,
                "bot_news": true
            }))
        );
    }
}
