//! 参加したメンバーへの歓迎・退出したメンバーへのお別れ。Python の `services/welcome_service.py`。
//!
//! 設定はギルドの `welcome`・`goodbye`（`channel_id` と `message`）。チャンネルが未設定・
//! 見つからない・テキストチャンネルでないときは何も送らない（未設定は正常）。文面の差し込み
//! （`{user}`・`{username}`・`{server}`・`{count}`）と既定の文面は Python と同じ。

use serde_json::Value;
use serenity::all::{Cache, CreateMessage, GuildId, Http};

use crate::log_channel;

/// 既定の歓迎の文面。Python の `DEFAULT_WELCOME`（テストで Python のソースと突き合わせる）。
pub const DEFAULT_WELCOME: &str = "新たなる者よ、{user} がこの地に降り立った。**{server}** へようこそ… 余の治める場所へ。（現在 {count} 名）";
/// 既定のお別れの文面。Python の `DEFAULT_GOODBYE`。
pub const DEFAULT_GOODBYE: &str =
    "{username} が去っていった。余の名を知りながら逃げるとは… 嘆かわしい。";

/// 歓迎かお別れか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// 参加したとき（設定は `welcome`）。
    Welcome,
    /// 退出したとき（設定は `goodbye`）。
    Goodbye,
}

impl Kind {
    fn key(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::Goodbye => "goodbye",
        }
    }

    fn default_template(self) -> &'static str {
        match self {
            Self::Welcome => DEFAULT_WELCOME,
            Self::Goodbye => DEFAULT_GOODBYE,
        }
    }
}

/// 差し込む値。
pub struct Values<'a> {
    /// `{user}`: mention（`<@ID>`）。
    pub user: &'a str,
    /// `{username}`: `str(member)` と同じ形の名前。
    pub username: &'a str,
    /// `{server}`: サーバーの名前。
    pub server: &'a str,
    /// `{count}`: メンバー数（分からなければ 0）。
    pub count: Option<u64>,
}

/// 文面に値を差し込む。Python の `render_template`。
///
/// **Python と同じ順に 1 つずつ置き換える。** 名前に `{server}` などが入っていると、後の置き換えが
/// それも置き換える（Python と同じ結果にするため、まとめて置き換えない）。
pub fn render_template(template: &str, v: &Values<'_>) -> String {
    template
        .replace("{user}", v.user)
        .replace("{username}", v.username)
        .replace("{server}", v.server)
        .replace("{count}", &v.count.unwrap_or(0).to_string())
}

/// ギルドの設定から、送り先のチャンネルと文面（未設定なら既定）を読む。
///
/// 文面は空でない文字列だけを使う（Python の `s.get("message") or DEFAULT`。文字列でない値は
/// Python では差し込みで落ちて送られないが、こちらは既定の文面で送る）。
pub fn settings_for(guild: Option<&Value>, kind: Kind) -> (Option<u64>, String) {
    let block = guild.and_then(|g| g.get(kind.key()));
    let channel = block
        .and_then(|b| b.get("channel_id"))
        .and_then(log_channel::as_channel_id);
    let template = block
        .and_then(|b| b.get("message"))
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .unwrap_or(kind.default_template());
    (channel, template.to_string())
}

/// 送る。送らなかった（未設定など）ときは `Ok(false)`。送信の失敗は `Err`。
pub async fn send(
    cache: &Cache,
    http: &Http,
    guild_id: GuildId,
    guild_settings: Option<&Value>,
    kind: Kind,
    values: &Values<'_>,
) -> Result<bool, Box<serenity::Error>> {
    let (channel_id, template) = settings_for(guild_settings, kind);
    let Some(channel) = log_channel::text_channel(cache, guild_id, channel_id) else {
        return Ok(false);
    };
    let text = render_template(&template, values);
    channel
        .send_message(http, CreateMessage::new().content(text))
        .await
        .map_err(Box::new)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn values() -> Values<'static> {
        Values {
            user: "<@1>",
            username: "nelly",
            server: "Media Server",
            count: Some(7),
        }
    }

    /// 既定の文面が Python のソースと同じであること。
    #[test]
    fn the_default_texts_match_python() {
        let python = include_str!("../../../../services/welcome_service.py");
        assert!(
            python.contains(&format!("\"{DEFAULT_GOODBYE}\"")),
            "お別れの既定が違う"
        );
        assert!(
            python.contains(&format!("\"{DEFAULT_WELCOME}\"")),
            "歓迎の既定が違う"
        );
    }

    /// 4 つの差し込みが入り、メンバー数が分からなければ 0。
    #[test]
    fn placeholders_are_filled_in() {
        assert_eq!(
            render_template(DEFAULT_WELCOME, &values()),
            "新たなる者よ、<@1> がこの地に降り立った。**Media Server** へようこそ… 余の治める場所へ。（現在 7 名）"
        );
        let unknown = Values {
            count: None,
            ..values()
        };
        assert_eq!(render_template("{count}", &unknown), "0");
    }

    /// Python と同じ順に置き換えること（名前に入った `{server}` も、後で置き換わる）。
    #[test]
    fn placeholders_are_replaced_in_python_order() {
        let tricky = Values {
            username: "名前{server}",
            ..values()
        };
        assert_eq!(render_template("{username}", &tricky), "名前Media Server");
        // 逆に、先に置き換えた {user} は、後から名前に入って現れても置き換わらない。
        let earlier = Values {
            username: "名前{user}",
            ..values()
        };
        assert_eq!(
            render_template("{user} {username}", &earlier),
            "<@1> 名前{user}"
        );
    }

    /// チャンネルと文面を設定から読み、文面が無い・空なら既定にすること。
    #[test]
    fn settings_fall_back_to_the_default_text() {
        let g = json!({"welcome": {"channel_id": "123", "message": "ようこそ {user}"},
                       "goodbye": {"channel_id": 456, "message": ""}});
        assert_eq!(
            settings_for(Some(&g), Kind::Welcome),
            (Some(123), "ようこそ {user}".to_string())
        );
        assert_eq!(
            settings_for(Some(&g), Kind::Goodbye),
            (Some(456), DEFAULT_GOODBYE.to_string())
        );
        assert_eq!(
            settings_for(None, Kind::Welcome),
            (None, DEFAULT_WELCOME.to_string())
        );
    }
}
