//! スラッシュコマンド。Python の `commands/`。
//!
//! - **定義**（[`definitions`]）: Discord に登録するコマンドの一覧。Python の Bot が起動のたびに同期している
//!   ものを、そのまま持つ（`definitions.json`。作り方は `tests/fixtures/commands/generate_definitions.py`）。
//!   Rust の Bot が登録するときも同じものを送る。**一部だけ送ると、残りのコマンドが Discord から消える**ので、
//!   定義は最初から全部持ち、中身は 1 つずつ移す。
//! - **振り分け**（[`dispatch`]）: 打たれたコマンドを、移した中身へ回す。まだ移していないコマンド
//!   （[`NOT_PORTED_YET`]）には、その旨を返す（切り替えの前に利用者が打つことはない）。
//! - 打たれたことは、成功も失敗もプロセスのログに 1 行残す（[`activity`]）。
//!
//! 移した中身（今は /log・/chat）は、設定を書き換えて返事の文を作るだけの関数にしてある（[`settings`]）。

pub mod activity;
pub mod guards;
pub mod reply;
pub mod settings;

use std::time::Instant;

use serde_json::Value;
use serenity::all::{
    Cache, ChannelId, CommandDataOption, CommandDataOptionValue, CommandInteraction,
    CreateInteractionResponse, CreateInteractionResponseMessage, GuildId, Http,
};
use sycs_core::settings::{Settings, SettingsCache, WriteError};
use tracing::{error, info, warn};

use self::guards::Standing;
use self::reply::Reply;
use crate::vc_notify;

/// Discord に登録する定義（JSON の配列）。Python の Bot が `bot.tree.sync()` で送っているものそのまま。
pub const DEFINITIONS_JSON: &str = include_str!("definitions.json");

/// 定義を JSON として読む。
pub fn definitions() -> Value {
    serde_json::from_str(DEFINITIONS_JSON).expect("definitions.json は正しい JSON")
}

/// 定義にある末端のコマンドの道すじ（`log channel`・`greeting welcome message` など）。
pub fn leaf_paths(definitions: &Value) -> Vec<String> {
    fn walk(node: &Value, path: String, out: &mut Vec<String>) {
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
            out.push(path);
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

/// 移したコマンド。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// `/log channel`
    LogChannel,
    /// `/log level`
    LogLevel,
    /// `/chat set`
    ChatSet,
    /// `/chat clear`
    ChatClear,
}

/// 移したコマンドの道すじ。
pub const PORTED: &[(&str, Route)] = &[
    ("log channel", Route::LogChannel),
    ("log level", Route::LogLevel),
    ("chat set", Route::ChatSet),
    ("chat clear", Route::ChatClear),
];

/// 定義にはあるが、中身をまだ移していないコマンド。移したら [`PORTED`] へ動かす
/// （テストが、定義・[`PORTED`]・ここの 3 つが食い違っていないことを確かめる）。
pub const NOT_PORTED_YET: &[&str] = &[
    "metal gold",
    "metal silver",
    "metal platinum",
    "metal all",
    "trusted add",
    "trusted remove",
    "trusted list",
    "bypass add",
    "bypass remove",
    "bypass list",
    "bot settings",
    "bot help",
    "greeting welcome channel",
    "greeting welcome message",
    "greeting goodbye channel",
    "greeting goodbye message",
    "greeting status",
    "vcnotify set",
    "vcnotify clear",
    "sticky set",
    "sticky clear",
    "sticky list",
    "reactionrole add",
    "reactionrole remove",
    "reactionrole list",
    "news add",
    "news remove",
    "news list",
    "quake channel",
    "quake min_scale",
    "quake status",
    "quake type",
    "info server",
    "info user",
    "djaudio channel",
    "djaudio output",
    "djaudio status",
    "tts enable",
    "tts disable",
    "tts add_watch",
    "tts remove_watch",
    "tts vc",
    "tts status",
    "tts join",
    "tts leave",
    "tts default_voice",
    "tts read_name",
    "tts default_rate",
    "voice set",
    "voice reset",
    "voice info",
    "dict add",
    "dict remove",
    "dict list",
];

/// 道すじから、移した中身を引く。
pub fn route(path: &str) -> Option<Route> {
    PORTED.iter().find(|(p, _)| *p == path).map(|(_, r)| *r)
}

/// 打たれたコマンドの道すじと、末端の引数。
pub fn command_path<'a>(
    name: &str,
    options: &'a [CommandDataOption],
) -> (String, &'a [CommandDataOption]) {
    let mut path = name.to_string();
    let mut current = options;
    while let [only] = current {
        match &only.value {
            CommandDataOptionValue::SubCommand(inner)
            | CommandDataOptionValue::SubCommandGroup(inner) => {
                path.push(' ');
                path.push_str(&only.name);
                current = inner;
            }
            _ => break,
        }
    }
    (path, current)
}

fn option<'a>(options: &'a [CommandDataOption], name: &str) -> Option<&'a CommandDataOptionValue> {
    options.iter().find(|o| o.name == name).map(|o| &o.value)
}

fn channel_option(options: &[CommandDataOption], name: &str) -> Option<ChannelId> {
    match option(options, name)? {
        CommandDataOptionValue::Channel(id) => Some(*id),
        _ => None,
    }
}

fn string_option<'a>(options: &'a [CommandDataOption], name: &str) -> Option<&'a str> {
    match option(options, name)? {
        CommandDataOptionValue::String(text) => Some(text),
        _ => None,
    }
}

/// コマンドの中の失敗。
#[derive(Debug)]
pub enum CommandError {
    /// 設定を書けなかった。
    Write(WriteError),
    /// 必須の引数が届いていない（定義と食い違う。ふつうは起きない）。
    MissingOption(&'static str),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write(e) => write!(f, "設定を書けませんでした: {e}"),
            Self::MissingOption(name) => write!(f, "引数 {name} がありません"),
        }
    }
}

impl From<WriteError> for CommandError {
    fn from(e: WriteError) -> Self {
        Self::Write(e)
    }
}

/// 打った人の立場（サーバーの外・ふつうの人・管理者）。discord.py と同じく、キャッシュのロールから決める。
pub fn standing_of(cache: &Cache, command: &CommandInteraction) -> Standing {
    let Some(guild_id) = command.guild_id else {
        return Standing::OutsideGuild;
    };
    let Some(guild) = cache.guild(guild_id) else {
        return Standing::OutsideGuild;
    };
    let roles = command
        .member
        .as_ref()
        .map(|m| m.roles.as_slice())
        .unwrap_or_default();
    if guards::is_administrator(
        guild.owner_id,
        command.user.id,
        roles,
        &guild.roles,
        guild_id,
    ) {
        Standing::Admin
    } else {
        Standing::Member
    }
}

/// 実行の段取り。すぐ返事するか、設定を書き換えてから返事するか。
pub enum Planned {
    /// 設定に触らずに返す（断るときなど）。
    Reply(Box<Reply>),
    /// 設定を書き換えて、その結果から返事を作る（[`SettingsCache::transact`] の中で呼ぶ）。
    Write(Box<dyn FnOnce(&mut Settings) -> Reply + Send>),
}

/// 打たれたコマンドをどう片付けるかを決める（権限・引数を見る。Discord にも DB にも触らない）。
pub fn plan(
    route: Route,
    standing: Standing,
    guild_id: Option<GuildId>,
    options: &[CommandDataOption],
) -> Result<Planned, CommandError> {
    // 今ある 4 つはどれも管理者だけ（Python の ensure_admin）。
    if let Some(text) = guards::refusal_for_admin_only(standing) {
        return Ok(Planned::Reply(Box::new(Reply::ephemeral(text))));
    }
    let Some(guild_id) = guild_id else {
        return Ok(Planned::Reply(Box::new(Reply::ephemeral(
            reply::NOT_IN_GUILD,
        ))));
    };
    let guild = guild_id.get();
    let channel = || {
        channel_option(options, "channel")
            .map(ChannelId::get)
            .ok_or(CommandError::MissingOption("channel"))
    };
    Ok(match route {
        Route::LogChannel => {
            let id = channel()?;
            Planned::Write(Box::new(move |s| settings::log_channel(s, guild, id)))
        }
        Route::LogLevel => {
            let level = string_option(options, "level")
                .ok_or(CommandError::MissingOption("level"))?
                .to_string();
            Planned::Write(Box::new(move |s| settings::log_level(s, guild, &level)))
        }
        Route::ChatSet => {
            let id = channel()?;
            Planned::Write(Box::new(move |s| settings::chat_set(s, guild, id)))
        }
        Route::ChatClear => Planned::Write(Box::new(move |s| settings::chat_clear(s, guild))),
    })
}

/// 移した中身を実行して、返事を作る。
pub async fn run(
    settings: &SettingsCache,
    route: Route,
    standing: Standing,
    command: &CommandInteraction,
    options: &[CommandDataOption],
) -> Result<Reply, CommandError> {
    match plan(route, standing, command.guild_id, options)? {
        Planned::Reply(reply) => Ok(*reply),
        Planned::Write(write) => Ok(settings.transact(write).await?),
    }
}

/// 返事を Discord へ送る（最初の応答）。Python の `interaction.response.send_message`。
/// serenity の誤りは大きいので、箱に入れて返す。
pub async fn respond(
    http: &Http,
    command: &CommandInteraction,
    reply: Reply,
) -> Result<(), Box<serenity::Error>> {
    let mut message = CreateInteractionResponseMessage::new().ephemeral(reply.ephemeral);
    if let Some(content) = reply.content {
        message = message.content(content);
    }
    if let Some(embed) = reply.embed {
        message = message.embed(embed);
    }
    command
        .create_response(http, CreateInteractionResponse::Message(message))
        .await
        .map_err(Box::new)
}

/// 打たれたコマンドを 1 つ片付ける（実行 → 返事 → ログに 1 行）。
pub async fn dispatch(
    settings: &SettingsCache,
    cache: &Cache,
    http: &Http,
    command: &CommandInteraction,
) {
    let started = Instant::now();
    let (path, options) = command_path(&command.data.name, &command.data.options);
    let display_name = vc_notify::display_name(
        command.member.as_ref().and_then(|m| m.nick.as_deref()),
        command.user.global_name.as_deref(),
        &command.user.name,
    );
    let who = activity::describe(
        command.guild_id,
        display_name,
        command.user.id,
        command.channel_id,
    );
    let outcome = match route(&path) {
        Some(route) => {
            let standing = standing_of(cache, command);
            run(settings, route, standing, command, options).await
        }
        None => {
            warn!("[CMD] /{path} {who} まだ移していないコマンドです");
            Ok(Reply::ephemeral(reply::NOT_PORTED))
        }
    };
    let (reply, failure) = match outcome {
        Ok(reply) => (reply, None),
        Err(e) => (Reply::ephemeral(reply::FAILED), Some(e.to_string())),
    };
    if let Some(e) = &failure {
        let ms = started.elapsed().as_millis();
        error!("{}", activity::failed_line(&path, &who, ms, e));
    }
    if let Err(e) = respond(http, command, reply).await {
        warn!("[CMD] /{path} {who} 返事を送れませんでした: {e}");
    }
    if failure.is_none() {
        let ms = started.elapsed().as_millis();
        info!("{}", activity::completed_line(&path, &who, ms));
    }
}

/// 定義を Discord に登録する（全体を置き換える）。Python の `bot.tree.sync()`。登録できた数を返す。
pub async fn sync(http: &Http) -> Result<usize, Box<serenity::Error>> {
    http.create_global_commands(&definitions())
        .await
        .map(|commands| commands.len())
        .map_err(Box::new)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// 定義が Python の Bot と同じ数であること（17 グループ・58 コマンド）。
    #[test]
    fn the_definitions_cover_every_python_command() {
        let defs = definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        // 並びも Python の登録の順（metal → 設定 → サーバー → djaudio → 読み上げ）。
        assert_eq!(
            names,
            [
                "metal",
                "log",
                "chat",
                "trusted",
                "bypass",
                "bot",
                "greeting",
                "vcnotify",
                "sticky",
                "reactionrole",
                "news",
                "quake",
                "info",
                "djaudio",
                "tts",
                "voice",
                "dict"
            ]
        );
        assert_eq!(leaf_paths(&defs).len(), 58);
    }

    /// 定義にあるコマンドは、移したか・まだかのどちらかに 1 回だけ載っていること。
    ///
    /// 定義にコマンドを足したのに振り分けを決めていない、移したのに「まだ」に残っている、を防ぐ。
    #[test]
    fn every_command_is_either_ported_or_listed_as_not_yet() {
        let defined: BTreeSet<String> = leaf_paths(&definitions()).into_iter().collect();
        let ported: BTreeSet<String> = PORTED.iter().map(|(p, _)| p.to_string()).collect();
        let pending: BTreeSet<String> = NOT_PORTED_YET.iter().map(|p| p.to_string()).collect();
        assert_eq!(ported.len(), PORTED.len(), "PORTED に重複がある");
        assert_eq!(
            pending.len(),
            NOT_PORTED_YET.len(),
            "NOT_PORTED_YET に重複がある"
        );
        let both: Vec<&String> = ported.intersection(&pending).collect();
        assert!(both.is_empty(), "両方に載っている: {both:?}");
        let listed: BTreeSet<String> = ported.union(&pending).cloned().collect();
        assert_eq!(listed, defined);
        for (path, r) in PORTED {
            assert_eq!(route(path), Some(*r));
        }
        assert_eq!(route("sticky set"), None);
    }

    fn options(value: Value) -> Vec<CommandDataOption> {
        serde_json::from_value(value).unwrap()
    }

    /// サブコマンドとグループをたどって、道すじと末端の引数を取り出すこと。
    #[test]
    fn the_path_follows_subcommands() {
        let opts = options(serde_json::json!([
            {"name": "welcome", "type": 2, "options": [
                {"name": "message", "type": 1, "options": [
                    {"name": "message", "type": 3, "value": "ようこそ"}
                ]}
            ]}
        ]));
        let (path, leaf) = command_path("greeting", &opts);
        assert_eq!(path, "greeting welcome message");
        assert_eq!(string_option(leaf, "message"), Some("ようこそ"));
        let opts = options(serde_json::json!([
            {"name": "channel", "type": 1, "options": [
                {"name": "channel", "type": 7, "value": "123"}
            ]}
        ]));
        let (path, leaf) = command_path("log", &opts);
        assert_eq!(path, "log channel");
        assert_eq!(channel_option(leaf, "channel"), Some(ChannelId::new(123)));
        assert_eq!(string_option(leaf, "channel"), None);
        // 引数の無いサブコマンド。
        let opts = options(serde_json::json!([{"name": "clear", "type": 1, "options": []}]));
        let (path, leaf) = command_path("chat", &opts);
        assert_eq!((path.as_str(), leaf.len()), ("chat clear", 0));
    }
}
