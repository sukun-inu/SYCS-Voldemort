//! 打たれたスラッシュコマンドを、プロセスのログに 1 行ずつ残す。Python の `commands/activity_log.py`。
//!
//! 書くのは「誰が・どのコマンドを・どのサーバーで・何ミリ秒で・成功したか」。**引数の中身は書かない**
//! （読み上げの辞書やチャットの本文が、ログの保管期間のあいだディスクに残ることになるため）。

use serenity::all::{ChannelId, GuildId, UserId};

/// 誰が・どこで打ったか。Python の `describe`（サーバーの外は `guild=DM`）。
pub fn describe(
    guild_id: Option<GuildId>,
    display_name: &str,
    user_id: UserId,
    channel_id: ChannelId,
) -> String {
    let guild = guild_id.map_or_else(|| "DM".to_string(), |g| g.to_string());
    format!("guild={guild} user={display_name}({user_id}) ch={channel_id}")
}

/// 成功して返ったコマンドの 1 行。Python の `_on_completion`。
pub fn completed_line(path: &str, who: &str, elapsed_ms: u128) -> String {
    format!("[CMD] /{path} {who} ok {elapsed_ms}ms")
}

/// 中で失敗したコマンドの 1 行。Python の `_on_tree_error` の `CommandInvokeError`。
pub fn failed_line(path: &str, who: &str, elapsed_ms: u128, error: &str) -> String {
    format!("[CMD] /{path} {who} 実行エラー {elapsed_ms}ms: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 行の形が Python と同じであること（管理画面のログの検索で、同じ書き方で引けるように）。
    #[test]
    fn lines_match_python() {
        let who = describe(
            Some(GuildId::new(1)),
            "ニック",
            UserId::new(2),
            ChannelId::new(3),
        );
        assert_eq!(who, "guild=1 user=ニック(2) ch=3");
        assert_eq!(
            describe(None, "nelly", UserId::new(2), ChannelId::new(3)),
            "guild=DM user=nelly(2) ch=3"
        );
        assert_eq!(
            completed_line("log channel", &who, 12),
            "[CMD] /log channel guild=1 user=ニック(2) ch=3 ok 12ms"
        );
        assert_eq!(
            failed_line("chat set", &who, 5, "時間切れ"),
            "[CMD] /chat set guild=1 user=ニック(2) ch=3 実行エラー 5ms: 時間切れ"
        );
    }
}
