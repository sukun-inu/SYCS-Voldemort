//! 設定のコマンド（/log・/chat）。Python の `commands/settings/log.py`・`chat.py`。
//!
//! どれも「設定を書き換えて、返事の文を作る」だけなので、設定の全体を受け取る関数にしてある
//! （[`sycs_core::settings::SettingsCache::transact`] の中で呼ぶ。表から読み直した設定に当たるので、
//! 他のプロセスの直前の変更を踏みつぶさない）。Discord には触らない。

use serde_json::{Map, Value, json};
use sycs_core::settings::Settings;

use super::reply::Reply;
use crate::log_channel::{Level, python_str};

/// 1 つのギルドの設定に重ねて書く（置き換えではない）。Python の `update_guild_settings`。
///
/// 既にある鍵は場所を変えずに値だけ変え、新しい鍵は末尾に足す。今の値が辞書でなければ空から始める。
/// null を書くと「未設定」になる（保存のときに落ちる）。書いたあとのそのギルドの設定を返す。
pub fn update_guild(
    settings: &mut Settings,
    guild_id: u64,
    updates: impl IntoIterator<Item = (&'static str, Value)>,
) -> Map<String, Value> {
    let key = guild_id.to_string();
    let mut current = settings
        .guilds
        .get(&key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, value) in updates {
        current.insert(name.to_string(), value);
    }
    settings.guilds.insert(key, Value::Object(current.clone()));
    current
}

/// Python の真偽（`if value:`）。設定に入りうる値について。
pub(crate) fn python_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// いまのログレベルの表示。Python の `get_log_settings` の `level`（未設定なら INFO、大文字にそろえる）。
fn level_text(guild: &Map<String, Value>) -> String {
    guild
        .get("log_level")
        .map_or_else(|| "INFO".to_string(), |v| python_str(v).to_uppercase())
}

/// `/log channel`: ログの送り先を決める。
pub fn log_channel(settings: &mut Settings, guild_id: u64, channel_id: u64) -> Reply {
    let current = update_guild(settings, guild_id, [("log_channel_id", json!(channel_id))]);
    Reply::ephemeral(format!(
        "<#{channel_id}> を余のログチャンネルと定めた。ログレベル: {}",
        level_text(&current)
    ))
}

/// `/log level`: ログレベルを決める。知らない名前は書かずに断る（Python の `set_log_level` の `ValueError`）。
pub fn log_level(settings: &mut Settings, guild_id: u64, level: &str) -> Reply {
    let upper = level.to_uppercase();
    if Level::parse(&upper).is_none() {
        return Reply::ephemeral(format!(
            "不正なログレベル: {level}. 使用可能: NONE, ERROR, INFO, DEBUG"
        ));
    }
    let current = update_guild(settings, guild_id, [("log_level", json!(upper))]);
    let channel = current.get("log_channel_id");
    let channel_text = match channel {
        Some(v) if python_truthy(channel) => format!("<#{}>", python_str(v)),
        _ => "未設定".to_string(),
    };
    Reply::ephemeral(format!(
        "ログレベルを {} に定めた。ログチャンネル: {channel_text}",
        level_text(&current)
    ))
}

/// `/chat set`: AI が応答するチャンネルを決める。
pub fn chat_set(settings: &mut Settings, guild_id: u64, channel_id: u64) -> Reply {
    update_guild(
        settings,
        guild_id,
        [("response_channel_id", json!(channel_id))],
    );
    Reply::ephemeral(format!(
        "<#{channel_id}> を余への語りかけチャンネルと定めた。"
    ))
}

/// `/chat clear`: AI が応答するチャンネルを外す（null を書く。保存のときに鍵ごと落ちる）。
pub fn chat_clear(settings: &mut Settings, guild_id: u64) -> Reply {
    update_guild(settings, guild_id, [("response_channel_id", Value::Null)]);
    Reply::ephemeral("余への語りかけチャンネルを解除した。再設定されるまで余は応答しない。")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(guild: Value) -> Settings {
        let mut s = Settings::default();
        s.guilds.insert("7".into(), guild);
        s
    }

    /// 重ねて書く: 既にある鍵は場所を変えず、新しい鍵は末尾。辞書でない値は空から。ほかのギルドは触らない。
    #[test]
    fn updates_merge_and_keep_key_order() {
        let mut s = settings(json!({"a": 1, "b": 2}));
        s.guilds.insert("8".into(), json!({"x": 1}));
        let after = update_guild(&mut s, 7, [("b", json!(9)), ("c", json!(3))]);
        assert_eq!(
            serde_json::to_string(&after).unwrap(),
            r#"{"a":1,"b":9,"c":3}"#
        );
        assert_eq!(s.guilds["7"], json!({"a": 1, "b": 9, "c": 3}));
        assert_eq!(s.guilds["8"], json!({"x": 1}));
        let mut broken = settings(json!("壊れた値"));
        assert_eq!(update_guild(&mut broken, 7, [("a", json!(1))]).len(), 1);
        let mut empty = Settings::default();
        update_guild(&mut empty, 7, [("a", json!(1))]);
        assert_eq!(empty.guilds["7"], json!({"a": 1}));
    }

    /// Python の真偽と同じに読むこと。
    #[test]
    fn truthiness_follows_python() {
        for v in [
            json!(1),
            json!("0"),
            json!([0]),
            json!({"a": 1}),
            json!(true),
            json!(0.5),
        ] {
            assert!(python_truthy(Some(&v)), "{v}");
        }
        for v in [
            json!(0),
            json!(""),
            json!([]),
            json!({}),
            json!(false),
            json!(null),
            json!(0.0),
        ] {
            assert!(!python_truthy(Some(&v)), "{v}");
        }
        assert!(!python_truthy(None));
    }
}
