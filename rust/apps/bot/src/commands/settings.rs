//! 設定のコマンド（/log・/chat・/trusted・/bypass・/bot settings）。Python の `commands/settings/` の
//! `log.py`・`chat.py`・`trusted.py`・`bypass.py`・`overview.py`。
//!
//! どれも「設定を書き換えて、返事の文を作る」だけなので、設定の全体を受け取る関数にしてある
//! （[`sycs_core::settings::SettingsCache::transact`] の中で呼ぶ。表から読み直した設定に当たるので、
//! 他のプロセスの直前の変更を踏みつぶさない）。Discord には触らない。

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use serenity::all::CreateEmbed;
use sycs_core::settings::Settings;

use super::reply::{EMBED_FIELD_BUDGET, MESSAGE_BUDGET, Reply, cap_list_for_message};
use crate::log_channel::{Level, python_int, python_str};
use crate::security::id_list;

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
pub fn python_truthy(value: Option<&Value>) -> bool {
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

/// 信頼済みユーザー・バイパスロールの ID の並びを足す／外す。Python の `add_trusted_users`・
/// `remove_trusted_users`・`add_bypass_roles`・`remove_bypass_roles`。
///
/// いまの並びを読み（読めない要素は捨てる）、足す／外すをして、重複なしの昇順で書く。外すときに登録されて
/// いない ID があっても失敗にしない。書いたあとの並びを返す。
pub fn change_ids(
    settings: &mut Settings,
    guild_id: u64,
    key: &'static str,
    ids: &[u64],
    add: bool,
) -> Vec<i64> {
    let current = settings
        .guilds
        .get(&guild_id.to_string())
        .and_then(|g| g.get(key));
    let mut set: BTreeSet<i64> = id_list(current).into_iter().collect();
    for id in ids {
        let Ok(id) = i64::try_from(*id) else {
            continue;
        };
        if add {
            set.insert(id);
        } else {
            set.remove(&id);
        }
    }
    let sorted: Vec<i64> = set.into_iter().collect();
    update_guild(settings, guild_id, [(key, json!(sorted))]);
    sorted
}

/// 設定の鍵: 信頼済みユーザー。
pub const TRUSTED_KEY: &str = "trusted_user_ids";
/// 設定の鍵: バイパスロール。
pub const BYPASS_KEY: &str = "bypass_role_ids";
/// 一覧のコマンドで並べる件数の上限（文字数の上限とは別に）。
const LIST_LIMIT: usize = 60;
/// `/bot settings` の一覧に並べる件数。Embed の 1 項目は 1024 文字までで、多いサーバーだと収まらない。
const OVERVIEW_LIST_LIMIT: usize = 15;
/// `/bot settings` の Embed の色（discord.py の `Color.blurple()`）。
pub const BLURPLE: u32 = 0x58_65_F2;

/// ロールのメンション。discord.py の `Role.mention`（@everyone のロールも `<@&ID>` と書く）。
pub fn role_mention(role_id: i64) -> String {
    format!("<@&{role_id}>")
}

/// `/trusted list`: 信頼済みユーザーの一覧。
pub fn trusted_list(guild: Option<&Value>) -> Reply {
    let ids = id_list(guild.and_then(|g| g.get(TRUSTED_KEY)));
    if ids.is_empty() {
        return Reply::ephemeral("まだ誰も余の信頼を勝ち取っていない。");
    }
    let members: Vec<String> = ids.iter().map(|id| format!("<@{id}>")).collect();
    // 件数が多いと本文の上限（2000 文字）を超えて、送信そのものが失敗する。
    let header = "余が認めた者の一覧だ:\n";
    let body = cap_list_for_message(
        &members,
        MESSAGE_BUDGET,
        "名",
        "\n",
        Some(LIST_LIMIT),
        header,
    );
    Reply::ephemeral(format!("{header}{body}"))
}

/// `/bypass list`: バイパスロールの一覧。
pub fn bypass_list(guild: Option<&Value>) -> Reply {
    let ids = id_list(guild.and_then(|g| g.get(BYPASS_KEY)));
    if ids.is_empty() {
        return Reply::ephemeral("バイパスロールはまだ設定されていない。");
    }
    let roles: Vec<String> = ids.iter().map(|id| role_mention(*id)).collect();
    let header = "バイパスロール一覧:\n";
    let body = cap_list_for_message(&roles, MESSAGE_BUDGET, "個", "\n", Some(LIST_LIMIT), header);
    Reply::ephemeral(format!("{header}{body}"))
}

/// ID の並びを、Embed の 1 項目に収まる長さの列挙にする。Python の `_mention_list`。
fn mention_list(ids: &[i64], prefix: &str, unit: &str) -> String {
    if ids.is_empty() {
        return "なし".to_string();
    }
    let items: Vec<String> = ids.iter().map(|id| format!("<{prefix}{id}>")).collect();
    cap_list_for_message(
        &items,
        EMBED_FIELD_BUDGET,
        unit,
        ", ",
        Some(OVERVIEW_LIST_LIMIT),
        "",
    )
}

/// `/bot settings` の Embed（いまの設定の一覧）。Python の `_settings_embed`。
pub fn settings_embed(guild: Option<&Value>, guild_id: u64) -> CreateEmbed {
    let get = |key: &str| guild.and_then(|g| g.get(key));
    let log_channel = get("log_channel_id");
    let log_channel_text = match log_channel {
        Some(v) if python_truthy(log_channel) => format!("<#{}>", python_str(v)),
        _ => "未設定".to_string(),
    };
    let level =
        get("log_level").map_or_else(|| "INFO".to_string(), |v| python_str(v).to_uppercase());
    // Python の get_response_channel_id（数として読めなければ 0）。
    let response = get("response_channel_id").and_then(python_int).unwrap_or(0);
    let response_text = if response != 0 {
        format!("<#{response}>")
    } else {
        "未設定（無効）".to_string()
    };
    let trusted = id_list(get(TRUSTED_KEY));
    let bypass = id_list(get(BYPASS_KEY));
    CreateEmbed::new()
        .title("余の現在の設定だ")
        .description(format!("サーバーID: `{guild_id}`"))
        .colour(BLURPLE)
        .field("ログチャンネル", log_channel_text, true)
        .field("ログレベル", level, true)
        .field("AI応答チャンネル", response_text, true)
        .field(
            format!("信頼済みユーザー（{}名）", trusted.len()),
            mention_list(&trusted, "@", "名"),
            false,
        )
        .field(
            format!("バイパスロール（{}個）", bypass.len()),
            mention_list(&bypass, "@&", "個"),
            false,
        )
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
