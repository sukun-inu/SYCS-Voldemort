//! `/reactionrole`（リアクションでロールを付ける設定）と、remove の補完。Python の
//! `commands/server/reactionrole.py` と、`services/settings_store.py` の `add_reaction_role`・
//! `remove_reaction_role`。
//!
//! 書く先はサーバーの設定の `reaction_roles`（メッセージ ID の文字列 → {絵文字 → ロール ID}）。読むのは
//! [`crate::reaction_roles`]（リアクションが付いた・外れたとき）。
//!
//! メッセージ ID は文字列で受ける（64 ビットの数は、スラッシュコマンドの整数の引数では桁が落ちる）。読み方は
//! Python の `int()`（[`super::python::int_text`]）。絵文字は前後の空白だけ落として、入れた書き方のまま鍵にする。

use serde_json::{Value, json};
use sycs_core::settings::Settings;

use super::python::{dict_setting, first_chars, len, lookup_id, strip};
use super::{CHOICE_LIMIT, CHOICE_NAME_CHARS, Choice, child, guild_entry};
use crate::commands::CommandError;
use crate::commands::reply::{MESSAGE_BUDGET, Reply, cap_list_for_message};
use crate::commands::settings::python_truthy;
use crate::log_channel::python_str;

/// メッセージ ID が数として読めないときの文。
pub const BAD_MESSAGE_ID: &str = "メッセージIDは数値で指定するがよい。";
/// 設定の鍵。[`crate::reaction_roles`] が読む鍵と同じ。
const TABLE: &str = "reaction_roles";
/// 一覧に並べる件数の上限（文字数の上限とは別に）。
const LIST_LIMIT: usize = 20;

/// `/reactionrole add`: メッセージと絵文字の組にロールを割り当てる。Python の `_apply_add`・`add_reaction_role`。
///
/// `message_id` は読んだ数を書き直したもの（[`super::python::int_text`]）、`emoji` は入れたまま。同じ組が
/// あれば、ロールだけ入れ替える。返事には、絵文字を入れたまま（空白を落とす前）で出す。
pub fn add(
    settings: &mut Settings,
    guild_id: u64,
    message_id: &str,
    emoji: &str,
    role_id: u64,
) -> Reply {
    let table = child(guild_entry(settings, guild_id), TABLE);
    child(table, message_id).insert(strip(emoji).to_string(), json!(role_id));
    Reply::ephemeral(format!(
        "メッセージ `{message_id}` に {emoji} → <@&{role_id}> のリアクションロールを追加した。"
    ))
}

/// 割り当てを 1 つ外す。Python の `remove_reaction_role`。外したら真。
///
/// 絵文字は、保存された書き方と同じでなければ当たらない。外して対応表が空になったら、メッセージごと消す
/// （表そのものは、空になっても残る）。
fn remove_entry(settings: &mut Settings, guild_id: u64, message_id: &str, emoji: &str) -> bool {
    let Some(table) = guild_entry(settings, guild_id)
        .get_mut(TABLE)
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    let Some(mapping) = table.get_mut(message_id).and_then(Value::as_object_mut) else {
        return false;
    };
    if mapping.shift_remove(emoji).is_none() {
        return false;
    }
    if mapping.is_empty() {
        table.shift_remove(message_id);
    }
    true
}

/// `/reactionrole remove`: 割り当てを外す。Python の `_apply_remove`。
pub fn remove(settings: &mut Settings, guild_id: u64, message_id: &str, emoji: &str) -> Reply {
    if remove_entry(settings, guild_id, message_id, strip(emoji)) {
        Reply::ephemeral(format!("リアクションロール ({emoji}) を取り除いた。"))
    } else {
        Reply::ephemeral("そのようなリアクションロールは見つからなかった。")
    }
}

/// `/reactionrole list`: 割り当ての一覧。管理者でなくても見られる。Python の `_apply_list`。
pub fn list(guild: Option<&Value>) -> Result<Reply, CommandError> {
    let table = dict_setting(guild, TABLE)?;
    if table.is_empty() {
        return Ok(Reply::ephemeral("リアクションロールは設定されておらぬ。"));
    }
    let mut lines = Vec::new();
    for (message_id, mapping) in table {
        let mapping = mapping
            .as_object()
            .ok_or(CommandError::BrokenSetting(TABLE))?;
        for (emoji, role) in mapping {
            lines.push(format!(
                "メッセージ `{message_id}` | {emoji} → <@&{}>",
                python_str(role)
            ));
        }
    }
    // 件数が多いと本文の上限（2000 文字）を超えるので打ち切る（何件省いたかは出す）。
    let header = "**リアクションロール一覧**\n";
    let body = cap_list_for_message(&lines, MESSAGE_BUDGET, "件", "\n", Some(LIST_LIMIT), header);
    Ok(Reply::ephemeral(format!("{header}{body}")))
}

/// remove の `message_id` の候補。Python の `_message_id_choices`。
///
/// 入力中の文字を含む ID だけを、設定の順に 25 件まで。名前には、割り当ての数を添える。
pub fn message_id_choices(
    guild: Option<&Value>,
    current: &str,
) -> Result<Vec<Choice>, CommandError> {
    let table = dict_setting(guild, TABLE)?;
    let mut choices = Vec::new();
    for (message_id, mapping) in table {
        if !current.is_empty() && !message_id.contains(current) {
            continue;
        }
        let count = len(mapping).ok_or(CommandError::BrokenSetting(TABLE))?;
        let name = format!("{message_id}（{count}件のロール）");
        choices.push(Choice {
            name: first_chars(&name, CHOICE_NAME_CHARS),
            value: message_id.clone(),
        });
    }
    choices.truncate(CHOICE_LIMIT);
    Ok(choices)
}

/// remove の `emoji` の候補。Python の `_emoji_choices`。
///
/// 先に入れた `message_id`（入れた文字のまま引く）の絵文字に絞る。入れていない・その ID の割り当てが無い
/// ときは、全部のメッセージの絵文字から出す。入力中の文字を含む絵文字だけを（大文字と小文字は区別しない）、
/// 25 件たまったところで打ち切る。名前には、ロールの名前（サーバーに無ければ保存された値）を添える。
pub fn emoji_choices(
    guild: Option<&Value>,
    selected_message_id: &str,
    current: &str,
    role_name: &dyn Fn(u64) -> Option<String>,
) -> Result<Vec<Choice>, CommandError> {
    let table = dict_setting(guild, TABLE)?;
    let selected = Some(selected_message_id)
        .filter(|id| !id.is_empty())
        .and_then(|id| table.get(id))
        .filter(|mapping| python_truthy(Some(*mapping)));
    let mappings: Vec<&Value> = match selected {
        Some(mapping) => vec![mapping],
        None => table.values().collect(),
    };
    let needle = current.to_lowercase();
    let mut choices = Vec::new();
    for mapping in mappings {
        // 壊れた対応表は、そこまで読み進めたときにだけ誤りになる（先に 25 件たまれば、読まない）。
        let mapping = mapping
            .as_object()
            .ok_or(CommandError::BrokenSetting(TABLE))?;
        for (emoji, role) in mapping {
            if !needle.is_empty() && !emoji.to_lowercase().contains(&needle) {
                continue;
            }
            let label = lookup_id(Some(role), TABLE)?
                .and_then(role_name)
                .unwrap_or_else(|| python_str(role));
            choices.push(Choice {
                name: first_chars(&format!("{emoji} → {label}"), CHOICE_NAME_CHARS),
                value: emoji.clone(),
            });
            if choices.len() >= CHOICE_LIMIT {
                return Ok(choices);
            }
        }
    }
    Ok(choices)
}

#[cfg(test)]
mod tests {
    use serenity::all::ReactionType;

    use super::*;
    use crate::reaction_roles::{self, Decision};

    /// コマンドが書いたものを、ロールを付ける側（[`crate::reaction_roles`]）がそのまま読めること。
    #[test]
    fn what_the_command_writes_is_what_the_role_giver_reads() {
        let mut settings = Settings::default();
        add(&mut settings, 7, "111", " 👍 ", 20);
        add(&mut settings, 7, "111", "<:blob:5>", 21);
        let guild = settings.guild(7);
        let mapping = reaction_roles::mapping_for(guild, 111).unwrap();
        assert_eq!(reaction_roles::role_for(mapping, "👍"), Some(&json!(20)));
        // カスタム絵文字は、付いたリアクションの ID で引ける（保存された書き方を寄せて比べる）。
        assert_eq!(reaction_roles::role_for(mapping, "5"), Some(&json!(21)));
        let none = std::collections::HashMap::new();
        assert_eq!(
            reaction_roles::decide(guild, &none, 111, &ReactionType::Unicode("👍".into())),
            Decision::MissingRole("20".into())
        );
    }

    /// 外したら真、無ければ偽。サーバーの設定が無くても落ちないこと（空の入れ物ができるのは Python と同じ）。
    #[test]
    fn removing_reports_whether_anything_was_removed() {
        let mut settings = Settings::default();
        assert!(!remove_entry(&mut settings, 7, "111", "👍"));
        assert_eq!(settings.guilds["7"], json!({}));
        add(&mut settings, 7, "111", "👍", 20);
        assert!(!remove_entry(&mut settings, 7, "111", "✅"));
        assert!(!remove_entry(&mut settings, 7, "112", "👍"));
        assert!(remove_entry(&mut settings, 7, "111", "👍"));
        assert_eq!(settings.guilds["7"], json!({"reaction_roles": {}}));
    }
}
