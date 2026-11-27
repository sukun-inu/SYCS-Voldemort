//! `/bot help`（コマンドの一覧）と、管理画面へのリンクのボタン。Python の `commands/settings/overview.py` の
//! `_command_lines`・`_help_embeds` と、`commands/interaction_utils.py` の `admin_site_view`。

use serde_json::Value;
use serenity::all::{CreateActionRow, CreateButton, CreateEmbed};

use super::settings::BLURPLE;

/// 1 枚の Embed に詰めるコマンドの数。Embed の説明は 4096 文字までなので、件数で先に切る。
pub const HELP_CHUNK_SIZE: usize = 20;
/// 管理画面へのボタンの文。
pub const ADMIN_SITE_LABEL: &str = "⚙️ Web管理画面を開く";
/// 管理画面の場所の既定（`ADMIN_SITE_URL` が無いとき。Python の config と同じ）。
pub const DEFAULT_ADMIN_SITE_URL: &str = "https://vol.kawasaki-n3t.f5.si/admin/login";

/// 定義にある末端のコマンドと、その説明（`log channel` と説明の組）。
pub fn leaf_commands(definitions: &Value) -> Vec<(String, String)> {
    fn walk(node: &Value, path: String, out: &mut Vec<(String, String)>) {
        // 種類 1 はサブコマンド、2 はサブコマンドのグループ。
        let subs: Vec<&Value> = node["options"]
            .as_array()
            .map(|options| {
                options
                    .iter()
                    .filter(|o| matches!(o["type"].as_u64(), Some(1 | 2)))
                    .collect()
            })
            .unwrap_or_default();
        if subs.is_empty() {
            let description = node["description"].as_str().unwrap_or("").to_string();
            out.push((path, description));
            return;
        }
        for sub in subs {
            let name = sub["name"].as_str().unwrap_or("");
            walk(sub, format!("{path} {name}"), out);
        }
    }
    let mut out = Vec::new();
    for command in definitions.as_array().into_iter().flatten() {
        walk(
            command,
            command["name"].as_str().unwrap_or("").to_string(),
            &mut out,
        );
    }
    out
}

/// 打てるコマンドを 1 行ずつ、名前の順に並べる。Python の `_command_lines`。
pub fn command_lines(definitions: &Value) -> Vec<String> {
    let mut commands = leaf_commands(definitions);
    commands.sort_by(|a, b| a.0.cmp(&b.0));
    commands
        .into_iter()
        .map(|(name, description)| {
            let description = if description.is_empty() {
                "(説明なし)".to_string()
            } else {
                description
            };
            format!("`/{name}` — {description}")
        })
        .collect()
}

/// コマンドの一覧を、見出しつきの 1 枚目とそれ以降に分ける。Python の `_help_embeds`。
pub fn help_embeds(lines: &[String]) -> Vec<CreateEmbed> {
    lines
        .chunks(HELP_CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| {
            let body = chunk.join("\n");
            if i == 0 {
                CreateEmbed::new()
                    .title("余が授けたコマンドの一覧")
                    .description(format!(
                        "余の力を借りられるコマンドだ。使いこなすがよい。\n\n{body}"
                    ))
                    .colour(BLURPLE)
            } else {
                CreateEmbed::new().description(body).colour(BLURPLE)
            }
        })
        .collect()
}

/// 管理画面へのリンクのボタン（1 行）。Python の `admin_site_view`。
pub fn admin_site_row(url: &str) -> Vec<CreateActionRow> {
    vec![CreateActionRow::Buttons(vec![
        CreateButton::new_link(url).label(ADMIN_SITE_LABEL),
    ])]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::definitions;

    /// 一覧は打てる形（グループから葉まで）で、名前の順に並ぶこと。
    #[test]
    fn lines_are_sorted_by_the_full_name() {
        let lines = command_lines(&definitions());
        assert_eq!(lines.len(), 58);
        assert_eq!(
            lines[0],
            "`/bot help` — 利用可能なスラッシュコマンド一覧を表示します"
        );
        assert!(
            lines.windows(2).all(|w| w[0] < w[1]),
            "並びが名前の順でない"
        );
        // /log channel と /quake channel は別の行になる（葉の名前だけで集めると片方が消える）。
        assert!(lines.iter().any(|l| l.starts_with("`/log channel`")));
        assert!(lines.iter().any(|l| l.starts_with("`/quake channel`")));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("`/greeting welcome message`"))
        );
    }

    /// 20 件ずつに分け、見出しは 1 枚目だけに付けること。
    #[test]
    fn help_is_split_into_pages_of_twenty() {
        let lines = command_lines(&definitions());
        let embeds: Vec<Value> = help_embeds(&lines)
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect();
        assert_eq!(embeds.len(), 3);
        assert_eq!(embeds[0]["title"], "余が授けたコマンドの一覧");
        assert!(embeds[1].get("title").is_none());
        let first = embeds[0]["description"].as_str().unwrap();
        assert!(
            first.starts_with("余の力を借りられるコマンドだ。使いこなすがよい。\n\n`/bot help`")
        );
        assert_eq!(first.lines().count(), 2 + 20);
        assert_eq!(
            embeds[2]["description"].as_str().unwrap().lines().count(),
            18
        );
        assert!(help_embeds(&[]).is_empty());
    }
}
