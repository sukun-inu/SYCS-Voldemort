//! 設定の値を書く関数（`Field.set`・`Collection.add`・`update`・`remove`）。Python の関数の名前（`schema.json` の
//! `fields[].set`・`collections[].add`・`update`・`remove`）で引く表 [`SETTERS`]・[`ADDERS`]・[`UPDATERS`]・
//! [`REMOVERS`] と、その中身（A5 の [`crate::apps::getters::GETTERS`] と同じ作法）。
//!
//! 中身は Python の `webapp_admin/schema/panels/*.py` の関数と、そこから呼ぶ `services/settings_store.py`・
//! `services/tts_store.py`・`services/logging_service.py` の書き換えの関数（`_mutate_settings` に渡す mutator）の写し。
//! 1 つの関数は 2 つに分かれる:
//!
//! 1. 書く前に読むところ（[`Plan`] を作るところ）。引数の `int()`・`str()`、いまの設定の読み出し（`_watch_ids` など。
//!    呼んだ時点の手元の設定を読む。Python と同じく、排他の外）。失敗は Python と同じ型と文の例外（[`Crash`]）
//! 2. 書き換え（[`Mutation`]。排他を取って読み直した全体に当てる。`_get_or_create_guild` でギルドを辞書にし、
//!    ブロックは「辞書でなければ空から」作り直す）。**鍵の並びは Python の dict と同じになるように、Python の文の順に
//!    入れる**（既にある鍵は同じ位置のまま、新しい鍵は末尾。消すときは並びを崩さない `shift_remove`）
//!
//! 書き換えを 1 回も呼ばない関数もある（`_set_voice` に空を渡したとき、`set_djaudio_settings` に読める数が無いとき）。
//! Python は書き換えを 1 回呼ぶごとに 1 回保存し、変わっていれば版番号を 1 上げて Bot に知らせる。Rust も 1 つの関数に
//! つき書き換えは多くて 1 回（[`crate::apps::store::SettingsStore::transact`]）。
//!
//! 値は JSON の値で受け取る（検証の通った値。整数は 64 ビットに収まれば数、収まらなければ 10 進の文字）。保存する整数は
//! Python の `int` と同じく数で書く（[`int_value`]）。基準は `tests/fixtures/apps_write/`（本物の Python の管理画面に
//! 要求を送り、書いたあとの設定を鍵の並びまで書いたもの）。

use std::cmp::Ordering;

use serde_json::{Map, Value};
use sycs_core::settings::Settings;

use crate::apps::getters::{self, Ctx, NOTIFY_TYPE_KEYS};
use crate::apps::schema::{self, int_value};
use crate::apps::store::Mutation;
use crate::apps::validation;
use crate::auth;
use crate::errors::Crash;
use crate::python;

/// ログの重さ（`logging_service._LEVEL_PRIORITY` の鍵。`set_log_level` はこれ以外を断る）。
pub const LOG_LEVELS: [&str; 4] = ["NONE", "ERROR", "INFO", "DEBUG"];
/// 読み上げの本文の上限を読む関数（`tts._max_length`）。
pub const TTS_MAX_LENGTH: &str =
    "webapp_admin.schema.panels.tts._int_setting.<locals>.getter[fallback=100,key=max_length]";
/// 読み上げの全体の上限を読む関数（`tts._speak_max_length`）。
pub const TTS_SPEAK_MAX_LENGTH: &str =
    "webapp_admin.schema.panels.tts._int_setting.<locals>.getter[fallback=200,key=speak_max_length]";
/// リアクションロールの項目の ID の区切り（`reaction_roles._ID_SEPARATOR`）。
pub const ID_SEPARATOR: char = ':';

/// 書く関数が決めたこと（書き換えと、Python の関数の戻り値）。
pub struct Plan {
    /// 書き換え（`None` なら `_mutate_settings` を呼ばない）。
    pub mutation: Option<Mutation>,
    /// Python の関数の戻り値（一覧に足したときの項目の ID など。使わない関数は null）。
    pub returns: Value,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("writes", &self.mutation.is_some())
            .field("returns", &self.returns)
            .finish()
    }
}

impl Plan {
    /// 書き換えを 1 回する。
    fn write(mutation: impl FnOnce(&mut Settings) -> Value + Send + 'static) -> Self {
        Self {
            mutation: Some(Box::new(mutation)),
            returns: Value::Null,
        }
    }

    /// 何も書かない。
    fn nothing() -> Self {
        Self {
            mutation: None,
            returns: Value::Null,
        }
    }

    /// 戻り値を決める。
    fn returning(mut self, value: Value) -> Self {
        self.returns = value;
        self
    }
}

/// `Field.set(guild_id, value)`。
pub type Setter = fn(&Ctx<'_>, &Value) -> Result<Plan, Crash>;
/// `Collection.add(guild_id, data)`（最後の引数は `uuid.uuid4().hex` を作るもの。使う関数だけが呼ぶ）。
pub type Adder = fn(&Ctx<'_>, &Map<String, Value>, &dyn Fn() -> String) -> Result<Plan, Crash>;
/// `Collection.update(guild_id, item_id, data)`。
pub type Updater = fn(&Ctx<'_>, &str, &Map<String, Value>) -> Result<Plan, Crash>;
/// `Collection.remove(guild_id, item_id)`。
pub type Remover = fn(&Ctx<'_>, &str) -> Result<Plan, Crash>;

/// 入力欄の書く関数（名前の順）。
pub const SETTERS: &[(&str, Setter)] = &[
    ("services.logging_service.set_log_channel", set_log_channel),
    ("services.logging_service.set_log_level", set_log_level),
    (
        "services.settings_store.set_djaudio_output_channel",
        set_djaudio_output_channel,
    ),
    (
        "services.settings_store.set_djaudio_watch_channel",
        set_djaudio_watch_channel,
    ),
    (
        "services.settings_store.set_earthquake_channel",
        set_earthquake_channel,
    ),
    ("services.settings_store.set_goodbye_channel", set_goodbye_channel),
    ("services.settings_store.set_goodbye_message", set_goodbye_message),
    (
        "services.settings_store.set_response_channel_id",
        set_response_channel_id,
    ),
    (
        "services.settings_store.set_security_timeout_enabled",
        set_security_timeout_enabled,
    ),
    (
        "services.settings_store.set_vc_notify_channel_id",
        set_vc_notify_channel_id,
    ),
    (
        "services.settings_store.set_vc_notify_filter_role_id",
        set_vc_notify_filter_role_id,
    ),
    (
        "services.settings_store.set_vc_notify_role_id",
        set_vc_notify_role_id,
    ),
    ("services.settings_store.set_welcome_channel", set_welcome_channel),
    ("services.settings_store.set_welcome_message", set_welcome_message),
    ("services.tts_store.set_tts_enabled", set_tts_enabled),
    ("services.tts_store.set_tts_read_name", set_tts_read_name),
    ("services.tts_store.set_tts_vc_notify", set_tts_vc_notify),
    (
        "webapp_admin.schema.panels.djaudio._set_limit.<locals>.setter[key=cache_ttl]",
        djaudio_cache_ttl,
    ),
    (
        "webapp_admin.schema.panels.djaudio._set_limit.<locals>.setter[key=cooldown]",
        djaudio_cooldown,
    ),
    (
        "webapp_admin.schema.panels.djaudio._set_limit.<locals>.setter[key=max_urls]",
        djaudio_max_urls,
    ),
    (
        "webapp_admin.schema.panels.earthquake._set_min_scale",
        earthquake_min_scale,
    ),
    (
        "webapp_admin.schema.panels.earthquake._set_notify_types",
        earthquake_notify_types,
    ),
    ("webapp_admin.schema.panels.tts._set_max_length", tts_max_length),
    ("webapp_admin.schema.panels.tts._set_rate", tts_rate),
    (
        "webapp_admin.schema.panels.tts._set_speak_max_length",
        tts_speak_max_length,
    ),
    ("webapp_admin.schema.panels.tts._set_vc_channel", tts_vc_channel),
    ("webapp_admin.schema.panels.tts._set_voice", tts_voice),
];

/// 一覧に足す関数（名前の順）。
pub const ADDERS: &[(&str, Adder)] = &[
    ("webapp_admin.schema.panels.news_feeds._add", news_add),
    ("webapp_admin.schema.panels.reaction_roles._add", reaction_add),
    ("webapp_admin.schema.panels.security._bypass_add", bypass_add),
    ("webapp_admin.schema.panels.security._trusted_add", trusted_add),
    ("webapp_admin.schema.panels.sticky._add", sticky_add),
    ("webapp_admin.schema.panels.tts._dict_add", tts_dict_add),
    ("webapp_admin.schema.panels.tts._watch_add", tts_watch_add),
];

/// 一覧の 1 件を変える関数（名前の順）。
pub const UPDATERS: &[(&str, Updater)] = &[
    ("webapp_admin.schema.panels.news_feeds._update", news_update),
    ("webapp_admin.schema.panels.sticky._update", sticky_update),
];

/// 一覧の 1 件を消す関数（名前の順）。
pub const REMOVERS: &[(&str, Remover)] = &[
    ("services.settings_store.remove_news_feed", news_remove),
    (
        "webapp_admin.schema.panels.reaction_roles._remove",
        reaction_remove,
    ),
    (
        "webapp_admin.schema.panels.security._bypass_remove",
        bypass_remove,
    ),
    (
        "webapp_admin.schema.panels.security._trusted_remove",
        trusted_remove,
    ),
    ("webapp_admin.schema.panels.sticky._remove", sticky_remove),
    ("webapp_admin.schema.panels.tts._dict_remove", tts_dict_remove),
    ("webapp_admin.schema.panels.tts._user_reset", tts_user_reset),
    ("webapp_admin.schema.panels.tts._watch_remove", tts_watch_remove),
];

fn find<T: Copy>(table: &[(&str, T)], name: &str) -> Option<T> {
    table
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, function)| *function)
}

/// 名前で入力欄の書く関数を引く。
pub fn setter(name: &str) -> Option<Setter> {
    find(SETTERS, name)
}

/// 名前で一覧に足す関数を引く。
pub fn adder(name: &str) -> Option<Adder> {
    find(ADDERS, name)
}

/// 名前で一覧の 1 件を変える関数を引く。
pub fn updater(name: &str) -> Option<Updater> {
    find(UPDATERS, name)
}

/// 名前で一覧の 1 件を消す関数を引く。
pub fn remover(name: &str) -> Option<Remover> {
    find(REMOVERS, name)
}

/// 表に無い名前（宣言に関数が増えたのに Rust に無い。テストが先に落とす）。
pub fn missing(name: &str) -> Crash {
    Crash::new(
        "NotImplementedError",
        format!("{name} を書く Rust の関数がありません"),
    )
}

/// `services.settings_store.delete_guild_settings`（1 ギルドぶんを丸ごと消す。消したものが無い・null なら偽）。
pub fn delete_guild_settings(guild_id: &str) -> Mutation {
    let key = guild_id.to_string();
    Box::new(move |data: &mut Settings| {
        // `guilds.pop(str(guild_id), None) is not None`。
        Value::Bool(matches!(data.guilds.remove(&key), Some(value) if !value.is_null()))
    })
}

// ── Python の値の扱い ─────────────────────────────────────────────

/// `int(value)`（10 進の文字）。
fn int_of(value: &Value) -> Result<String, Crash> {
    auth::py_int(value)
}

/// `int(item_id)`（経路の文字）。
fn int_of_text(text: &str) -> Result<String, Crash> {
    auth::py_int(&Value::String(text.to_string()))
}

/// `data[key]`（無ければ `KeyError`）。
fn item(data: &Map<String, Value>, key: &str) -> Result<Value, Crash> {
    data.get(key)
        .cloned()
        .ok_or_else(|| Crash::new("KeyError", python::repr(&Value::String(key.to_string()))))
}

/// `str(value).strip()`。
fn stripped(value: &Value) -> String {
    python::strip(&python::str_of(value)).to_string()
}

/// 10 進の整数の文字どうしを数として比べる（Python の `sorted` の並び）。
fn compare_ints(a: &str, b: &str) -> Ordering {
    match (a.strip_prefix('-'), b.strip_prefix('-')) {
        (None, None) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => y.len().cmp(&x.len()).then_with(|| y.cmp(x)),
    }
}

/// `_get_or_create_guild(data, guild_id)`（辞書でなければ空の辞書に作り直す。無ければ作る）。
fn guild_mut<'a>(data: &'a mut Settings, guild_id: &str) -> &'a mut Map<String, Value> {
    let slot = data
        .guilds
        .entry(guild_id.to_string())
        .or_insert(Value::Null);
    object_mut(slot)
}

/// 辞書でなければ空の辞書にして、その中身を返す。
fn object_mut(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    match value {
        Value::Object(map) => map,
        _ => unreachable!("直前で辞書にした"),
    }
}

/// `nested = current.get(name, {})` が辞書でなければ `{}`（写しを返す。書き戻すのは呼ぶ側。Python の文の順に
/// `current[name] = nested` するため）。
fn block_of(current: &Map<String, Value>, name: &str) -> Map<String, Value> {
    match current.get(name) {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

/// `update_guild_settings(guild_id, {key: value, …})`（ギルドの直下に入れる）。
fn update_guild(guild_id: &str, pairs: Vec<(&'static str, Value)>) -> Plan {
    let guild_id = guild_id.to_string();
    Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        for (key, value) in pairs {
            current.insert(key.to_string(), value);
        }
        Value::Null
    })
}

/// `_update_nested(guild_id, name, {key: value, …})`（ブロックの中に入れる。ブロックが辞書でなければ空から）。
fn update_block(guild_id: &str, name: &'static str, pairs: Vec<(&'static str, Value)>) -> Plan {
    let guild_id = guild_id.to_string();
    Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut nested = block_of(current, name);
        for (key, value) in pairs {
            nested.insert(key.to_string(), value);
        }
        current.insert(name.to_string(), Value::Object(nested));
        Value::Null
    })
}

// ── ログ（logging.py・logging_service） ─────────────────────────────

/// `set_log_channel`。
fn set_log_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_guild(ctx.guild_id, vec![("log_channel_id", value.clone())]))
}

/// `set_log_level`（`level.upper()` が `_LEVEL_PRIORITY` に無ければ ValueError）。
fn set_log_level(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let Value::String(level) = value else {
        let message = format!(
            "'{}' object has no attribute 'upper'",
            python::type_name(value)
        );
        return Err(Crash::new("AttributeError", message));
    };
    let upper = level.to_uppercase();
    if !LOG_LEVELS.contains(&upper.as_str()) {
        let message = format!("不正なログレベル: {level}. 使用可能: NONE, ERROR, INFO, DEBUG");
        return Err(Crash::new("ValueError", message));
    }
    Ok(update_guild(ctx.guild_id, vec![("log_level", Value::String(upper))]))
}

/// `set_response_channel_id`（ChatGPT の応答チャンネル）。
fn set_response_channel_id(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_guild(ctx.guild_id, vec![("response_channel_id", value.clone())]))
}

// ── ウェルカム・グッバイ・VC 通知 ─────────────────────────────────

/// `set_welcome_channel`。
fn set_welcome_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "welcome", vec![("channel_id", value.clone())]))
}

/// `set_welcome_message`。
fn set_welcome_message(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "welcome", vec![("message", value.clone())]))
}

/// `set_goodbye_channel`。
fn set_goodbye_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "goodbye", vec![("channel_id", value.clone())]))
}

/// `set_goodbye_message`。
fn set_goodbye_message(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "goodbye", vec![("message", value.clone())]))
}

/// `set_vc_notify_channel_id`。
fn set_vc_notify_channel_id(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_guild(ctx.guild_id, vec![("vc_notify_channel_id", value.clone())]))
}

/// `set_vc_notify_role_id`。
fn set_vc_notify_role_id(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_guild(ctx.guild_id, vec![("vc_notify_role_id", value.clone())]))
}

/// `set_vc_notify_filter_role_id`。
fn set_vc_notify_filter_role_id(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let pairs = vec![("vc_notify_filter_role_id", value.clone())];
    Ok(update_guild(ctx.guild_id, pairs))
}

// ── 地震（earthquake.py・settings_store） ─────────────────────────

/// `set_earthquake_channel`。
fn set_earthquake_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "earthquake", vec![("channel_id", value.clone())]))
}

/// `earthquake._set_min_scale`（`set_earthquake_min_scale(guild_id, int(value))`）。
fn earthquake_min_scale(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let scale = int_value(&int_of(value)?);
    Ok(update_block(ctx.guild_id, "earthquake", vec![("min_scale", scale)]))
}

/// 地震の通知の種類（パネルの `NOTIFY_TYPES` の鍵の並び。宣言の通知の種類の入力欄の固定の選択肢）。
fn panel_notify_types() -> Result<&'static [String], Crash> {
    validation::panel_rules("earthquake")
        .and_then(|rules| rules.field("notify_types"))
        .and_then(|rule| rule.statics.as_deref())
        .ok_or_else(|| Crash::new("KeyError", "'notify_types'"))
}

/// `earthquake._set_notify_types`（届いた鍵だけを真に、ほかの種類は全部偽にして、`notify_types` を丸ごと置き換える。
/// `set_earthquake_notify_types` が `_NOTIFY_TYPE_KEYS` に無い鍵を落とす）。
fn earthquake_notify_types(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    // `{str(k) for k in (enabled_keys or [])}`。
    let selected: Vec<String> = if python::truthy(value) {
        auth::py_iter(value)?.iter().map(python::str_of).collect()
    } else {
        Vec::new()
    };
    let mut patch = Map::new();
    for key in panel_notify_types()? {
        if NOTIFY_TYPE_KEYS.contains(&key.as_str()) {
            patch.insert(key.clone(), Value::Bool(selected.contains(key)));
        }
    }
    let pairs = vec![("notify_types", Value::Object(patch))];
    Ok(update_block(ctx.guild_id, "earthquake", pairs))
}

// ── DJAudio（djaudio.py・settings_store） ─────────────────────────

/// `set_djaudio_watch_channel`（入れ子の djaudio と、古い平らな鍵 2 つに同じ値を書く）。
fn set_djaudio_watch_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let guild_id = ctx.guild_id.to_string();
    let value = value.clone();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut nested = block_of(current, "djaudio");
        nested.insert("watch_channel_id".to_string(), value.clone());
        current.insert("djaudio_watch_channel_id".to_string(), value.clone());
        current.insert("djaudio_watch_channel".to_string(), value);
        current.insert("djaudio".to_string(), Value::Object(nested));
        Value::Null
    }))
}

/// `set_djaudio_output_channel`（入れ子の djaudio にだけ書く）。
fn set_djaudio_output_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let pairs = vec![("output_channel_id", value.clone())];
    Ok(update_block(ctx.guild_id, "djaudio", pairs))
}

/// `DJAUDIO_LIMITS[key]`（パネルはこの表から入力欄の `min`・`max` を作っているので、宣言から読む）。
fn djaudio_limits(key: &str) -> Result<(i64, i64), Crash> {
    validation::panel_rules("djaudio")
        .and_then(|rules| rules.field(key))
        .and_then(|rule| rule.min.zip(rule.max))
        .ok_or_else(|| Crash::new("KeyError", python::repr(&Value::String(key.to_string()))))
}

/// `_set_limit(key)` の setter（`set_djaudio_settings(guild_id, {key: int(value)})`。範囲に丸め、入れ子の djaudio と
/// 古い平らな鍵 3 つ〔`djaudio_cache_ttl` など。無い値は null を入れて落とす〕に書く）。
fn djaudio_limit(ctx: &Ctx<'_>, value: &Value, key: &'static str) -> Result<Plan, Crash> {
    let number = int_of(value)?;
    let (low, high) = djaudio_limits(key)?;
    // `max(low, min(high, value))`。
    let clamped = if validation::compare_int(&number, high) == Ordering::Greater {
        Value::from(high.max(low))
    } else if validation::compare_int(&number, low) == Ordering::Less {
        Value::from(low)
    } else {
        int_value(&number)
    };
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut nested = block_of(current, "djaudio");
        nested.insert(key.to_string(), clamped);
        let legacy = |name: &str| nested.get(name).cloned().unwrap_or(Value::Null);
        let (ttl, cooldown, urls) = (legacy("cache_ttl"), legacy("cooldown"), legacy("max_urls"));
        current.insert("djaudio".to_string(), Value::Object(nested));
        current.insert("djaudio_cache_ttl".to_string(), ttl);
        current.insert("djaudio_cooldown".to_string(), cooldown);
        current.insert("djaudio_max_urls".to_string(), urls);
        Value::Null
    }))
}

/// `_set_limit("cache_ttl")`。
fn djaudio_cache_ttl(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    djaudio_limit(ctx, value, "cache_ttl")
}

/// `_set_limit("cooldown")`。
fn djaudio_cooldown(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    djaudio_limit(ctx, value, "cooldown")
}

/// `_set_limit("max_urls")`。
fn djaudio_max_urls(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    djaudio_limit(ctx, value, "max_urls")
}

// ── 読み上げ（tts.py・tts_store） ─────────────────────────────────

/// `set_tts_enabled`。
fn set_tts_enabled(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "tts", vec![("enabled", value.clone())]))
}

/// `set_tts_vc_notify`。
fn set_tts_vc_notify(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "tts", vec![("vc_notify", value.clone())]))
}

/// `set_tts_read_name`。
fn set_tts_read_name(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    Ok(update_block(ctx.guild_id, "tts", vec![("read_name", value.clone())]))
}

/// `set_tts_channels(guild_id, watch_channel_ids, vc_channel_id)`（2 つを丸ごと置き換える）。
fn set_tts_channels(guild_id: &str, ids: Vec<String>, vc_channel_id: Value) -> Plan {
    let guild_id = guild_id.to_string();
    Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut tts = block_of(current, "tts");
        let ids: Vec<Value> = ids.iter().map(|id| int_value(id)).collect();
        tts.insert("watch_channel_ids".to_string(), Value::Array(ids));
        tts.insert("vc_channel_id".to_string(), vc_channel_id);
        current.insert("tts".to_string(), Value::Object(tts));
        Value::Null
    })
}

/// `get_tts_settings(guild_id).get("vc_channel_id")`。
fn current_vc_channel(ctx: &Ctx<'_>) -> Result<Value, Crash> {
    let tts = getters::tts_settings(ctx)?;
    Ok(tts.get("vc_channel_id").cloned().unwrap_or(Value::Null))
}

/// `tts._set_vc_channel`（読み上げの対象のチャンネルは、いまの設定から読んで渡し直す）。
fn tts_vc_channel(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    // `int(value) if value not in (None, "", "0", 0) else None`。
    let vc = if schema::is_unset_id(value) {
        Value::Null
    } else {
        int_value(&int_of(value)?)
    };
    let ids = getters::watch_ids(&getters::tts_settings(ctx)?)?;
    Ok(set_tts_channels(ctx.guild_id, ids, vc))
}

/// `tts._set_voice`（`str(value or "").strip()` が空なら書かない）。
fn tts_voice(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let voice = if python::truthy(value) {
        stripped(value)
    } else {
        String::new()
    };
    if voice.is_empty() {
        return Ok(Plan::nothing());
    }
    Ok(update_block(ctx.guild_id, "tts", vec![("default_voice", Value::String(voice))]))
}

/// `tts._set_rate`（`set_tts_default_rate(guild_id, int(value))`）。
fn tts_rate(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let rate = int_value(&int_of(value)?);
    Ok(update_block(ctx.guild_id, "tts", vec![("default_rate", rate)]))
}

/// `tts._set_max_length`（`set_tts_max_lengths(guild_id, int(value), _speak_max_length(guild_id))`）。
fn tts_max_length(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let max_length = int_value(&int_of(value)?);
    let speak = getters::call(TTS_SPEAK_MAX_LENGTH, ctx)?;
    let pairs = vec![("max_length", max_length), ("speak_max_length", speak)];
    Ok(update_block(ctx.guild_id, "tts", pairs))
}

/// `tts._set_speak_max_length`（`set_tts_max_lengths(guild_id, _max_length(guild_id), int(value))`。引数の順に読む）。
fn tts_speak_max_length(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let max_length = getters::call(TTS_MAX_LENGTH, ctx)?;
    let speak = int_value(&int_of(value)?);
    let pairs = vec![("max_length", max_length), ("speak_max_length", speak)];
    Ok(update_block(ctx.guild_id, "tts", pairs))
}

/// `tts._watch_add`（同じチャンネルは足さない。接続先の VC は、いまの設定のまま渡し直す）。
fn tts_watch_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let channel = int_of(&item(data, "channel_id")?)?;
    let mut ids = getters::watch_ids(&getters::tts_settings(ctx)?)?;
    if !ids.contains(&channel) {
        ids.push(channel.clone());
    }
    let vc = current_vc_channel(ctx)?;
    Ok(set_tts_channels(ctx.guild_id, ids, vc).returning(Value::String(channel)))
}

/// `tts._watch_remove`。
fn tts_watch_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let channel = int_of_text(item_id)?;
    let ids: Vec<String> = getters::watch_ids(&getters::tts_settings(ctx)?)?
        .into_iter()
        .filter(|id| *id != channel)
        .collect();
    let vc = current_vc_channel(ctx)?;
    Ok(set_tts_channels(ctx.guild_id, ids, vc))
}

/// `tts._dict_add`（`add_tts_dictionary_entry`。同じ単語は読みを上書きする）。
fn tts_dict_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let word = stripped(&item(data, "word")?);
    let reading = stripped(&item(data, "reading")?);
    let guild_id = ctx.guild_id.to_string();
    let entry = word.clone();
    let plan = Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut tts = block_of(current, "tts");
        let mut dictionary = block_of(&tts, "dictionary");
        dictionary.insert(entry, Value::String(reading));
        tts.insert("dictionary".to_string(), Value::Object(dictionary));
        current.insert("tts".to_string(), Value::Object(tts));
        Value::Null
    });
    Ok(plan.returning(Value::String(word)))
}

/// `tts._dict_remove`（`remove_tts_dictionary_entry`。無ければ何もせず偽）。
fn tts_dict_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let word = item_id.to_string();
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let removed = match current.get_mut("tts") {
            Some(Value::Object(tts)) => match tts.get_mut("dictionary") {
                Some(Value::Object(dictionary)) => dictionary.shift_remove(word.as_str()).is_some(),
                _ => false,
            },
            _ => false,
        };
        Value::Bool(removed)
    }))
}

/// `tts._user_reset`（`reset_user_tts_settings(guild_id, int(item_id))`。tts が無ければ
/// `{"user_settings": {}}` を作る〔Python と同じ〕）。
fn tts_user_reset(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let user = int_of_text(item_id)?;
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        // `tts = current.get("tts", {})`（辞書でなければ何もしない）。
        let mut tts = match current.get("tts") {
            None => Map::new(),
            Some(Value::Object(tts)) => tts.clone(),
            Some(_) => return Value::Null,
        };
        let mut users = tts
            .get("user_settings")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        if let Value::Object(users) = &mut users {
            users.shift_remove(user.as_str());
        }
        tts.insert("user_settings".to_string(), users);
        current.insert("tts".to_string(), Value::Object(tts));
        Value::Null
    }))
}

// ── セキュリティ（security.py・settings_store） ─────────────────────

/// `set_security_timeout_enabled`（`bool(enabled)`）。
fn set_security_timeout_enabled(ctx: &Ctx<'_>, value: &Value) -> Result<Plan, Crash> {
    let enabled = Value::Bool(python::truthy(value));
    Ok(update_guild(ctx.guild_id, vec![("security_timeout_enabled", enabled)]))
}

/// `add_trusted_users`・`remove_trusted_users`・`add_bypass_roles`・`remove_bypass_roles`（`_parse_id_list` で読み、
/// 重なりを落として足すか外し、数の小さい順に並べ直して丸ごと書く）。
fn change_id_list(guild_id: &str, key: &'static str, id: String, add: bool) -> Plan {
    let guild_id = guild_id.to_string();
    Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut ids = getters::parse_id_list(current.get(key).unwrap_or(&Value::Null));
        if add {
            ids.push(id);
        } else {
            ids.retain(|known| *known != id);
        }
        ids.sort_by(|a, b| compare_ints(a, b));
        ids.dedup();
        let ids: Vec<Value> = ids.iter().map(|id| int_value(id)).collect();
        current.insert(key.to_string(), Value::Array(ids));
        Value::Null
    })
}

/// `security._trusted_add`。
fn trusted_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let user = int_of(&item(data, "user_id")?)?;
    let plan = change_id_list(ctx.guild_id, "trusted_user_ids", user.clone(), true);
    Ok(plan.returning(Value::String(user)))
}

/// `security._trusted_remove`。
fn trusted_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let user = int_of_text(item_id)?;
    Ok(change_id_list(ctx.guild_id, "trusted_user_ids", user, false))
}

/// `security._bypass_add`。
fn bypass_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let role = int_of(&item(data, "role_id")?)?;
    let plan = change_id_list(ctx.guild_id, "bypass_role_ids", role.clone(), true);
    Ok(plan.returning(Value::String(role)))
}

/// `security._bypass_remove`。
fn bypass_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let role = int_of_text(item_id)?;
    Ok(change_id_list(ctx.guild_id, "bypass_role_ids", role, false))
}

// ── ニュース・スティッキー・リアクションロール ─────────────────────

/// `int(data.get("interval") or 60)`。
fn interval_of(data: &Map<String, Value>) -> Result<String, Crash> {
    match data.get("interval") {
        Some(value) if python::truthy(value) => int_of(value),
        _ => int_of(&Value::from(60)),
    }
}

/// `news_feeds._add`（ID は `uuid.uuid4().hex[:8]`。送った記事の印と最後に回した時刻は空から）。
fn news_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let feed_id: String = uuid().chars().take(8).collect();
    let channel = int_value(&int_of(&item(data, "channel_id")?)?);
    let query = python::str_of(&item(data, "query")?);
    let interval = int_value(&interval_of(data)?);
    let guild_id = ctx.guild_id.to_string();
    let key = feed_id.clone();
    let plan = Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut feeds = block_of(current, "news_feeds");
        let feed = python::object(vec![
            ("channel_id", channel),
            ("query", Value::String(query)),
            ("interval", interval),
            ("last_run", Value::from(0.0_f64)),
            ("seen_hashes", Value::Array(Vec::new())),
        ]);
        feeds.insert(key, feed);
        current.insert("news_feeds".to_string(), Value::Object(feeds));
        Value::Null
    });
    Ok(plan.returning(Value::String(feed_id)))
}

/// `news_feeds._update`（`update_news_feed`。チャンネル・検索語・間隔だけを変え、送った記事の印は残す。無ければ偽）。
fn news_update(ctx: &Ctx<'_>, feed_id: &str, data: &Map<String, Value>) -> Result<Plan, Crash> {
    let channel = int_value(&int_of(&item(data, "channel_id")?)?);
    let query = python::str_of(&item(data, "query")?);
    let interval = int_value(&interval_of(data)?);
    let guild_id = ctx.guild_id.to_string();
    let feed_id = feed_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let Some(Value::Object(feeds)) = current.get_mut("news_feeds") else {
            return Value::Bool(false);
        };
        let Some(row) = feeds.get_mut(&feed_id) else {
            return Value::Bool(false);
        };
        let row = object_mut(row);
        row.insert("channel_id".to_string(), channel);
        row.insert("query".to_string(), Value::String(query));
        row.insert("interval".to_string(), interval);
        Value::Bool(true)
    }))
}

/// `remove_news_feed`（無ければ偽）。
fn news_remove(ctx: &Ctx<'_>, feed_id: &str) -> Result<Plan, Crash> {
    let feed_id = feed_id.to_string();
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let removed = match current.get_mut("news_feeds") {
            Some(Value::Object(feeds)) => feeds.shift_remove(feed_id.as_str()).is_some(),
            _ => false,
        };
        Value::Bool(removed)
    }))
}

/// `set_sticky_message`（本文を差し替え、投稿済みのメッセージの ID は残して `pending` を `post` にする）。
fn set_sticky(guild_id: &str, channel: String, content: String) -> Plan {
    let guild_id = guild_id.to_string();
    Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut stickies = block_of(current, "sticky_messages");
        let message_id = match stickies.get(&channel) {
            Some(Value::Object(existing)) => existing.get("message_id").cloned(),
            _ => None,
        };
        let entry = python::object(vec![
            ("content", Value::String(content)),
            ("message_id", message_id.unwrap_or(Value::Null)),
            ("pending", Value::String("post".to_string())),
        ]);
        stickies.insert(channel, entry);
        current.insert("sticky_messages".to_string(), Value::Object(stickies));
        Value::Null
    })
}

/// `sticky._add`（1 チャンネル 1 件。あれば上書き）。
fn sticky_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let channel = int_of(&item(data, "channel_id")?)?;
    let content = python::str_of(&item(data, "content")?);
    let plan = set_sticky(ctx.guild_id, channel.clone(), content);
    Ok(plan.returning(Value::String(channel)))
}

/// `sticky._update`（`_add(guild_id, {"channel_id": item_id, "content": data["content"]})`）。
fn sticky_update(ctx: &Ctx<'_>, item_id: &str, data: &Map<String, Value>) -> Result<Plan, Crash> {
    let content = item(data, "content")?;
    let channel = int_of_text(item_id)?;
    let plan = set_sticky(ctx.guild_id, channel.clone(), python::str_of(&content));
    Ok(plan.returning(Value::String(channel)))
}

/// `sticky._remove`（`mark_sticky_pending_delete`。すぐには消さず `pending` を `delete` にする。Bot が投稿を消してから
/// 設定を消す）。
fn sticky_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let channel = int_of_text(item_id)?;
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        if let Some(Value::Object(stickies)) = current.get_mut("sticky_messages")
            && let Some(Value::Object(entry)) = stickies.get_mut(&channel)
        {
            entry.insert("pending".to_string(), Value::String("delete".to_string()));
        }
        Value::Null
    }))
}

/// `reaction_roles._add`（`add_reaction_role`。項目の ID は `"<message_id>:<emoji>"`）。
fn reaction_add(
    ctx: &Ctx<'_>,
    data: &Map<String, Value>,
    _uuid: &dyn Fn() -> String,
) -> Result<Plan, Crash> {
    let message = int_of(&item(data, "message_id")?)?;
    let emoji = stripped(&item(data, "emoji")?);
    let role = int_value(&int_of(&item(data, "role_id")?)?);
    let returns = Value::String(format!("{message}{ID_SEPARATOR}{emoji}"));
    let guild_id = ctx.guild_id.to_string();
    let plan = Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let mut roles = block_of(current, "reaction_roles");
        let mut mapping = block_of(&roles, &message);
        mapping.insert(emoji, role);
        roles.insert(message, Value::Object(mapping));
        current.insert("reaction_roles".to_string(), Value::Object(roles));
        Value::Null
    });
    Ok(plan.returning(returns))
}

/// `reaction_roles._remove`（最初の `:` で割る。カスタム絵文字 `<:name:id>` も壊さない。空になった組はメッセージごと
/// 消す。無ければ偽）。
fn reaction_remove(ctx: &Ctx<'_>, item_id: &str) -> Result<Plan, Crash> {
    let (message, emoji) = item_id.split_once(ID_SEPARATOR).unwrap_or((item_id, ""));
    let message = int_of_text(message)?;
    let emoji = emoji.to_string();
    let guild_id = ctx.guild_id.to_string();
    Ok(Plan::write(move |data: &mut Settings| {
        let current = guild_mut(data, &guild_id);
        let Some(Value::Object(roles)) = current.get_mut("reaction_roles") else {
            return Value::Bool(false);
        };
        let Some(Value::Object(mapping)) = roles.get_mut(&message) else {
            return Value::Bool(false);
        };
        if mapping.shift_remove(emoji.as_str()).is_none() {
            return Value::Bool(false);
        }
        if mapping.is_empty() {
            roles.shift_remove(message.as_str());
        }
        Value::Bool(true)
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::apps::getters::DjaudioDefaults;
    use crate::apps::schema::schema;

    const GUILD: &str = "900000000000000001";

    fn names<T>(table: &[(&str, T)]) -> Vec<String> {
        table.iter().map(|(name, _)| (*name).to_string()).collect()
    }

    /// 宣言（`schema.json`）が指す書く関数（入力欄の set・一覧の add・update・remove）の名前と、Rust の表の名前が
    /// ちょうど同じで、表は名前の順に並び、同じ名前が無いこと。宣言に関数が増えたのに Rust が知らない、を CI で気づく。
    #[test]
    fn every_schema_function_has_a_rust_setter() {
        let mut sets = BTreeSet::new();
        let mut adds = BTreeSet::new();
        let mut updates = BTreeSet::new();
        let mut removes = BTreeSet::new();
        for panel in &schema().panels {
            sets.extend(panel.fields.iter().filter_map(|f| f.set.clone()));
            for collection in &panel.collections {
                adds.extend(collection.add.clone());
                updates.extend(collection.update.clone());
                removes.extend(collection.remove.clone());
            }
        }
        for (wanted, known) in [
            (sets, names(SETTERS)),
            (adds, names(ADDERS)),
            (updates, names(UPDATERS)),
            (removes, names(REMOVERS)),
        ] {
            let set: BTreeSet<String> = known.iter().cloned().collect();
            assert_eq!(set.len(), known.len(), "表に同じ名前が 2 つある");
            assert_eq!(wanted, set);
            let mut sorted = known.clone();
            sorted.sort_unstable();
            assert_eq!(known, sorted, "表は名前の順に並べる");
        }
        assert!(setter("nothing").is_none());
        assert_eq!(missing("x").kind, "NotImplementedError");
    }

    /// ログの重さ・リアクションロールの区切り・読み上げの上限を読む関数の名前が、Python のソースと宣言に合うこと。
    #[test]
    fn constants_match_python() {
        let logging = include_str!("../../../../../services/logging_service.py");
        for (i, level) in LOG_LEVELS.iter().enumerate() {
            assert!(logging.contains(&format!("    \"{level}\": {i},\n")), "{level}");
        }
        let reaction = include_str!("../../../../../webapp_admin/schema/panels/reaction_roles.py");
        assert!(reaction.contains(&format!("_ID_SEPARATOR = \"{ID_SEPARATOR}\"")));
        assert!(getters::find(TTS_MAX_LENGTH).is_some());
        assert!(getters::find(TTS_SPEAK_MAX_LENGTH).is_some());
        let types = panel_notify_types().unwrap();
        assert_eq!(types, NOTIFY_TYPE_KEYS);
        assert_eq!(djaudio_limits("max_urls").unwrap(), (1, 10));
    }

    fn apply(plan: Plan, guild: Value) -> (Value, Value) {
        let mut settings = Settings::default();
        settings.guilds.insert(GUILD.to_string(), guild);
        let returned = plan.mutation.map_or(Value::Null, |mutation| mutation(&mut settings));
        let after = settings.guilds.get(GUILD).cloned().unwrap_or(Value::Null);
        (after, returned)
    }

    fn ctx_for<'a>(settings: &'a Result<Arc<Settings>, String>) -> Ctx<'a> {
        Ctx {
            settings,
            guild_id: GUILD,
            djaudio: &DjaudioDefaults::PYTHON,
        }
    }

    fn keys(value: &Value) -> Vec<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }

    /// DJAudio の古い平らな鍵は、入れ子の djaudio の後ろに Python の文の順で入り、無い値は落ちること。
    #[test]
    fn djaudio_limits_keep_the_python_key_order() {
        let settings: Result<Arc<Settings>, String> = Ok(Arc::new(Settings::default()));
        let ctx = ctx_for(&settings);
        let plan = djaudio_cooldown(&ctx, &json!(45)).unwrap();
        let (after, _) = apply(plan, json!({"x": 1}));
        assert_eq!(
            keys(&after),
            ["x", "djaudio", "djaudio_cache_ttl", "djaudio_cooldown", "djaudio_max_urls"]
        );
        assert_eq!(after["djaudio_cache_ttl"], Value::Null);
        assert_eq!(after["djaudio_cooldown"], json!(45));
        let plan = djaudio_max_urls(&ctx, &json!(99)).unwrap();
        let (after, _) = apply(plan, json!({}));
        assert_eq!(after["djaudio"], json!({"max_urls": 10}));
        let watch = set_djaudio_watch_channel(&ctx, &json!(5)).unwrap();
        let (after, _) = apply(watch, json!({"djaudio": "x"}));
        assert_eq!(keys(&after), ["djaudio", "djaudio_watch_channel_id", "djaudio_watch_channel"]);
    }

    /// 一覧の ID は数の小さい順に並べ直し、重なりと読めない要素を落とすこと（文字の ID も数になる）。
    #[test]
    fn id_lists_are_sorted_like_python() {
        assert_eq!(compare_ints("9", "10"), Ordering::Less);
        assert_eq!(compare_ints("-10", "-9"), Ordering::Less);
        assert_eq!(compare_ints("-1", "0"), Ordering::Less);
        let plan = change_id_list(GUILD, "trusted_user_ids", "5".to_string(), true);
        let (after, _) = apply(plan, json!({"trusted_user_ids": ["10", 5, "x", 3, 10]}));
        assert_eq!(after["trusted_user_ids"], json!([3, 5, 10]));
        let plan = change_id_list(GUILD, "trusted_user_ids", "5".to_string(), false);
        let (after, _) = apply(plan, json!({"trusted_user_ids": "bad"}));
        assert_eq!(after["trusted_user_ids"], json!([]));
    }

    /// 消す関数は、無ければ偽を返し、並びを崩さずに消すこと。リアクションロールは空になった組ごと消す。
    #[test]
    fn removals_keep_the_order_and_report_what_they_did() {
        let settings: Result<Arc<Settings>, String> = Ok(Arc::new(Settings::default()));
        let ctx = ctx_for(&settings);
        let guild = json!({"news_feeds": {"a": {}, "b": {}, "c": {}}});
        let (after, removed) = apply(news_remove(&ctx, "a").unwrap(), guild.clone());
        assert_eq!(removed, json!(true));
        assert_eq!(keys(&after["news_feeds"]), ["b", "c"]);
        let (_, removed) = apply(news_remove(&ctx, "z").unwrap(), guild);
        assert_eq!(removed, json!(false));
        let roles = json!({"reaction_roles": {"1": {"<:a:2>": 3}, "4": {"x": 5}}});
        let (after, removed) = apply(reaction_remove(&ctx, "1:<:a:2>").unwrap(), roles);
        assert_eq!(removed, json!(true));
        assert_eq!(after["reaction_roles"], json!({"4": {"x": 5}}));
        let error = reaction_remove(&ctx, "x:y").unwrap_err();
        assert_eq!(error.message, "invalid literal for int() with base 10: 'x'");
    }

    /// 消す関数（`_get_or_create_guild` を通る）は、設定の無いサーバーにも空の辞書を作ること。
    #[test]
    fn removals_create_the_guild_like_python() {
        let settings: Result<Arc<Settings>, String> = Ok(Arc::new(Settings::default()));
        let ctx = ctx_for(&settings);
        let plan = tts_user_reset(&ctx, "007").unwrap();
        let mut data = Settings::default();
        let _ = plan.mutation.unwrap()(&mut data);
        assert_eq!(data.guilds[GUILD], json!({"tts": {"user_settings": {}}}));
        let plan = sticky_remove(&ctx, "1").unwrap();
        let mut data = Settings::default();
        let _ = plan.mutation.unwrap()(&mut data);
        assert_eq!(data.guilds[GUILD], json!({}));
    }

    /// 声に空を渡したときは書かないこと。読み上げの上限は、もう片方をいまの設定から読んで渡し直すこと。
    #[test]
    fn tts_setters_read_the_other_half() {
        let mut stored = Settings::default();
        stored.guilds.insert(GUILD.to_string(), json!({"tts": {"max_length": 50}}));
        let settings: Result<Arc<Settings>, String> = Ok(Arc::new(stored));
        let ctx = ctx_for(&settings);
        assert!(tts_voice(&ctx, &json!(null)).unwrap().mutation.is_none());
        let (after, _) = apply(tts_speak_max_length(&ctx, &json!(60)).unwrap(), json!({}));
        assert_eq!(after, json!({"tts": {"max_length": 50, "speak_max_length": 60}}));
        let (after, _) = apply(tts_max_length(&ctx, &json!(70)).unwrap(), json!({}));
        assert_eq!(after, json!({"tts": {"max_length": 70, "speak_max_length": 200}}));
    }
}
