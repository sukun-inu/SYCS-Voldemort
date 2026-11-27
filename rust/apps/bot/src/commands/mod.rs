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
//! 移した中身（今は /log・/chat・/trusted・/bypass・/bot）は、設定を読み書きして返事を作るだけの関数に
//! してある（[`settings`]・[`overview`]）。人数の決まっていない選択（/trusted・/bypass の追加と削除）は、
//! 選ぶ部品と「確定」のボタンの画面で受ける（[`picker`]）。
//!
//! サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）は [`server`] に置く。
//! 返事を送ったあとの仕事（/sticky の貼る・剥がす。[`After`]）と、引数の補完（[`autocomplete`]）もそこにある。

pub mod activity;
pub mod guards;
pub mod overview;
pub mod picker;
pub mod reply;
pub mod server;
pub mod settings;

use std::time::Instant;

use serde_json::Value;
use serenity::all::{
    Cache, ChannelId, CommandDataOption, CommandDataOptionValue, CommandInteraction,
    ComponentInteraction, ComponentInteractionDataKind, CreateInteractionResponse,
    CreateInteractionResponseMessage, GuildId, Http,
};
use sycs_core::settings::{Settings, SettingsCache, WriteError};
use tracing::{error, info, warn};

use self::guards::Standing;
use self::picker::{Part, PickerKind, Pickers, Step};
use self::reply::Reply;
pub use self::server::autocomplete;
use self::server::{After, Place, ServerRoute};
use crate::sticky::StickyLocks;
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
    /// `/trusted add`
    TrustedAdd,
    /// `/trusted remove`
    TrustedRemove,
    /// `/trusted list`
    TrustedList,
    /// `/bypass add`
    BypassAdd,
    /// `/bypass remove`
    BypassRemove,
    /// `/bypass list`
    BypassList,
    /// `/bot settings`
    BotSettings,
    /// `/bot help`
    BotHelp,
    /// サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）。
    Server(ServerRoute),
}

/// 移したコマンドの道すじ。
pub const PORTED: &[(&str, Route)] = &[
    ("log channel", Route::LogChannel),
    ("log level", Route::LogLevel),
    ("chat set", Route::ChatSet),
    ("chat clear", Route::ChatClear),
    ("trusted add", Route::TrustedAdd),
    ("trusted remove", Route::TrustedRemove),
    ("trusted list", Route::TrustedList),
    ("bypass add", Route::BypassAdd),
    ("bypass remove", Route::BypassRemove),
    ("bypass list", Route::BypassList),
    ("bot settings", Route::BotSettings),
    ("bot help", Route::BotHelp),
    (
        "greeting welcome channel",
        Route::Server(ServerRoute::WelcomeChannel),
    ),
    (
        "greeting welcome message",
        Route::Server(ServerRoute::WelcomeMessage),
    ),
    (
        "greeting goodbye channel",
        Route::Server(ServerRoute::GoodbyeChannel),
    ),
    (
        "greeting goodbye message",
        Route::Server(ServerRoute::GoodbyeMessage),
    ),
    (
        "greeting status",
        Route::Server(ServerRoute::GreetingStatus),
    ),
    ("vcnotify set", Route::Server(ServerRoute::VcNotifySet)),
    ("vcnotify clear", Route::Server(ServerRoute::VcNotifyClear)),
    ("sticky set", Route::Server(ServerRoute::StickySet)),
    ("sticky clear", Route::Server(ServerRoute::StickyClear)),
    ("sticky list", Route::Server(ServerRoute::StickyList)),
    (
        "reactionrole add",
        Route::Server(ServerRoute::ReactionRoleAdd),
    ),
    (
        "reactionrole remove",
        Route::Server(ServerRoute::ReactionRoleRemove),
    ),
    (
        "reactionrole list",
        Route::Server(ServerRoute::ReactionRoleList),
    ),
    ("news add", Route::Server(ServerRoute::NewsAdd)),
    ("news remove", Route::Server(ServerRoute::NewsRemove)),
    ("news list", Route::Server(ServerRoute::NewsList)),
];

/// 定義にはあるが、中身をまだ移していないコマンド。移したら [`PORTED`] へ動かす
/// （テストが、定義・[`PORTED`]・ここの 3 つが食い違っていないことを確かめる）。
pub const NOT_PORTED_YET: &[&str] = &[
    "metal gold",
    "metal silver",
    "metal platinum",
    "metal all",
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
    /// 設定が読めない形をしている（辞書のはずのところが文字列、など。Python では例外になるところ）。
    BrokenSetting(&'static str),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write(e) => write!(f, "設定を書けませんでした: {e}"),
            Self::MissingOption(name) => write!(f, "引数 {name} がありません"),
            Self::BrokenSetting(name) => write!(f, "設定 {name} の形が読めません"),
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
    /// 設定に触らずに返す（断るとき・一覧・選択の画面を開くときなど）。
    Reply(Box<Reply>),
    /// 設定を書き換えて、その結果から返事を作る（[`SettingsCache::transact`] の中で呼ぶ）。
    Write(Box<dyn FnOnce(&mut Settings) -> Reply + Send>),
    /// 設定に触らずに返し、返事を送ったあとで仕事をする（/sticky clear の剥がす）。
    ReplyThen(Box<Reply>, After),
    /// 設定を書き換えて返し、返事を送ったあとで仕事をする（/sticky set の貼る）。
    WriteThen(Box<dyn FnOnce(&mut Settings) -> Reply + Send>, After),
}

/// コマンドの片付け方を決めるのに要るもの。
pub struct PlanInput<'a> {
    /// 打った人の立場。
    pub standing: Standing,
    /// 打たれたサーバー。
    pub guild_id: Option<GuildId>,
    /// 打った人。
    pub user_id: u64,
    /// 末端の引数。
    pub options: &'a [CommandDataOption],
    /// そのサーバーのいまの設定（一覧を出すコマンドが読む）。
    pub guild_settings: Option<&'a Value>,
    /// 開いている選択の画面の覚え。
    pub pickers: &'a Pickers,
    /// 管理画面の場所（リンクのボタン）。
    pub admin_site_url: &'a str,
    /// 打たれた場所（/sticky が、打たれたチャンネルとその種類を見る）。
    pub place: Place,
}

/// 打たれたコマンドをどう片付けるかを決める（権限・引数を見る。Discord にも DB にも触らない）。
pub fn plan(route: Route, input: &PlanInput<'_>) -> Result<Planned, CommandError> {
    let reply = |reply: Reply| Ok(Planned::Reply(Box::new(reply)));
    // /bot help は誰でも打てる。ほかは管理者だけ（Python の ensure_admin）。
    if route == Route::BotHelp {
        return reply(Reply {
            content: None,
            embeds: overview::help_embeds(&overview::command_lines(&definitions())),
            components: overview::admin_site_row(input.admin_site_url),
            ephemeral: true,
        });
    }
    // サーバーの設定のコマンドは、権限を中で見る（一覧と状況の表示は、管理者でなくても打てる）。
    if let Route::Server(route) = route {
        return server::plan(route, input);
    }
    if let Some(text) = guards::refusal_for_admin_only(input.standing) {
        return reply(Reply::ephemeral(text));
    }
    let Some(guild_id) = input.guild_id else {
        return reply(Reply::ephemeral(reply::NOT_IN_GUILD));
    };
    let guild = guild_id.get();
    let options = input.options;
    let channel = || {
        channel_option(options, "channel")
            .map(ChannelId::get)
            .ok_or(CommandError::MissingOption("channel"))
    };
    // 選択の画面を開く（選ぶ部品と「確定」のボタンを出す。書くのは確定を押したとき）。
    let open_picker = |kind: PickerKind| {
        let token = input.pickers.open(input.user_id, kind);
        reply(Reply {
            content: Some(kind.prompt().to_string()),
            embeds: Vec::new(),
            components: picker::components(&token, kind, 0),
            ephemeral: true,
        })
    };
    match route {
        Route::LogChannel => {
            let id = channel()?;
            Ok(Planned::Write(Box::new(move |s| {
                settings::log_channel(s, guild, id)
            })))
        }
        Route::LogLevel => {
            let level = string_option(options, "level")
                .ok_or(CommandError::MissingOption("level"))?
                .to_string();
            Ok(Planned::Write(Box::new(move |s| {
                settings::log_level(s, guild, &level)
            })))
        }
        Route::ChatSet => {
            let id = channel()?;
            Ok(Planned::Write(Box::new(move |s| {
                settings::chat_set(s, guild, id)
            })))
        }
        Route::ChatClear => Ok(Planned::Write(Box::new(move |s| {
            settings::chat_clear(s, guild)
        }))),
        Route::TrustedAdd => open_picker(PickerKind::TrustedAdd),
        Route::TrustedRemove => open_picker(PickerKind::TrustedRemove),
        Route::BypassAdd => open_picker(PickerKind::BypassAdd),
        Route::BypassRemove => open_picker(PickerKind::BypassRemove),
        Route::TrustedList => reply(settings::trusted_list(input.guild_settings)),
        Route::BypassList => reply(settings::bypass_list(input.guild_settings)),
        Route::BotSettings => reply(Reply {
            content: None,
            embeds: vec![settings::settings_embed(input.guild_settings, guild)],
            components: overview::admin_site_row(input.admin_site_url),
            ephemeral: true,
        }),
        // 上で返している。
        Route::BotHelp => reply(Reply::default()),
        Route::Server(route) => server::plan(route, input),
    }
}

/// コマンドと部品の応答に要るもの。
pub struct Deps<'a> {
    /// ギルドごとの設定。
    pub settings: &'a SettingsCache,
    /// serenity のキャッシュ（権限を決める）。
    pub cache: &'a Cache,
    /// Discord へ送る口。
    pub http: &'a Http,
    /// 開いている選択の画面の覚え。
    pub pickers: &'a Pickers,
    /// 管理画面の場所。
    pub admin_site_url: &'a str,
    /// スティッキーのチャンネルごとの排他（/sticky set が、返事のあとで貼るときに通る）。
    pub sticky_locks: &'a StickyLocks,
}

/// 移した中身を実行して、返事を作る。
/// 返事を送ったあとにする仕事（/sticky の貼る・剥がす）があれば、それも返す。
pub async fn run(
    deps: &Deps<'_>,
    route: Route,
    command: &CommandInteraction,
    options: &[CommandDataOption],
) -> Result<(Reply, Option<After>), CommandError> {
    let snapshot = deps.settings.snapshot();
    let input = PlanInput {
        standing: standing_of(deps.cache, command),
        guild_id: command.guild_id,
        user_id: command.user.id.get(),
        options,
        guild_settings: command.guild_id.and_then(|g| snapshot.guild(g.get())),
        pickers: deps.pickers,
        admin_site_url: deps.admin_site_url,
        place: server::place_of(deps.cache, command),
    };
    match plan(route, &input)? {
        Planned::Reply(reply) => Ok((*reply, None)),
        Planned::Write(write) => Ok((deps.settings.transact(write).await?, None)),
        Planned::ReplyThen(reply, after) => Ok((*reply, Some(after))),
        Planned::WriteThen(write, after) => Ok((deps.settings.transact(write).await?, Some(after))),
    }
}

fn response_message(reply: Reply) -> CreateInteractionResponseMessage {
    let mut message = CreateInteractionResponseMessage::new().ephemeral(reply.ephemeral);
    if let Some(content) = reply.content {
        message = message.content(content);
    }
    if !reply.embeds.is_empty() {
        message = message.embeds(reply.embeds);
    }
    if !reply.components.is_empty() {
        message = message.components(reply.components);
    }
    message
}

/// 返事を Discord へ送る（最初の応答）。Python の `interaction.response.send_message`。
/// serenity の誤りは大きいので、箱に入れて返す。
pub async fn respond(
    http: &Http,
    command: &CommandInteraction,
    reply: Reply,
) -> Result<(), Box<serenity::Error>> {
    command
        .create_response(
            http,
            CreateInteractionResponse::Message(response_message(reply)),
        )
        .await
        .map_err(Box::new)
}

/// 打たれたコマンドを 1 つ片付ける（実行 → 返事 → ログに 1 行）。
pub async fn dispatch(deps: &Deps<'_>, command: &CommandInteraction) {
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
        Some(route) => run(deps, route, command, options).await,
        None => {
            warn!("[CMD] /{path} {who} まだ移していないコマンドです");
            Ok((Reply::ephemeral(reply::NOT_PORTED), None))
        }
    };
    let (reply, after, failure) = match outcome {
        Ok((reply, after)) => (reply, after, None),
        Err(e) => (Reply::ephemeral(reply::FAILED), None, Some(e.to_string())),
    };
    if let Some(e) = &failure {
        let ms = started.elapsed().as_millis();
        error!("{}", activity::failed_line(&path, &who, ms, e));
    }
    let mut unsent = None;
    if let Err(e) = respond(deps.http, command, reply).await {
        warn!("[CMD] /{path} {who} 返事を送れませんでした: {e}");
        unsent = Some(format!("返事を送れませんでした: {e}"));
    }
    // 中身は済んだのに返事を送れなかったとき（本文が 2000 文字を超えた、など）は、Python と同じく
    // 「処理できなかった」と返す（設定は書かれている）。返事のあとの仕事はしない（Python も、そこで止まる）。
    let failure = match (failure, unsent) {
        (None, Some(e)) => {
            let ms = started.elapsed().as_millis();
            error!("{}", activity::failed_line(&path, &who, ms, &e));
            let fallback = Reply::ephemeral(reply::FAILED);
            if let Err(e) = respond(deps.http, command, fallback).await {
                warn!("[CMD] /{path} {who} 失敗の知らせも送れませんでした: {e}");
            }
            Some(e)
        }
        (failure, _) => failure,
    };
    // 返事を送ったあとの仕事（/sticky set・clear の貼る・剥がす）。
    if let (None, Some(after)) = (&failure, after) {
        after.run(deps).await;
    }
    if failure.is_none() {
        let ms = started.elapsed().as_millis();
        info!("{}", activity::completed_line(&path, &who, ms));
    }
}

/// 触られた部品（選択・ボタン）を 1 つ片付ける。いまは、信頼済みユーザー・バイパスロールの選択の画面だけ。
///
/// この Bot が開いた画面でない・時間切れのものには応えない（Python の View も、時間切れのあとは応えない）。
pub async fn component(deps: &Deps<'_>, interaction: &ComponentInteraction) {
    let Some((token, part)) = picker::parse_custom_id(&interaction.data.custom_id) else {
        return;
    };
    let user = interaction.user.id.get();
    let step = match (part, &interaction.data.kind) {
        (Part::Select, ComponentInteractionDataKind::UserSelect { values }) => {
            deps.pickers
                .select(token, user, values.iter().map(|id| id.get()).collect())
        }
        (Part::Select, ComponentInteractionDataKind::RoleSelect { values }) => {
            deps.pickers
                .select(token, user, values.iter().map(|id| id.get()).collect())
        }
        (Part::Confirm, ComponentInteractionDataKind::Button) => deps.pickers.confirm(token, user),
        _ => Step::Ignore,
    };
    let say =
        |text: &str| CreateInteractionResponse::Message(response_message(Reply::ephemeral(text)));
    let response = match step {
        Step::Ignore => return,
        Step::NotYours => say(picker::NOT_YOURS),
        Step::NothingPicked => say(picker::NOTHING_PICKED),
        // 選んだだけではまだ書かない。確定のボタンに件数を出す（Python の `edit_message(view=self)`）。
        Step::Redraw { kind, picked } => CreateInteractionResponse::UpdateMessage(
            CreateInteractionResponseMessage::new()
                .components(picker::components(token, kind, picked)),
        ),
        Step::Confirm { kind, picked } => {
            let Some(guild_id) = interaction.guild_id else {
                return;
            };
            let guild = guild_id.get();
            let ids = picked.clone();
            let written = deps
                .settings
                .transact(move |s| {
                    settings::change_ids(s, guild, kind.settings_key(), &ids, kind.adds())
                })
                .await;
            match written {
                Ok(updated) => {
                    // 書けたら画面は終わり（Python の `self.stop()`）。本文を結果に置き換え、部品を外す。
                    deps.pickers.close(token);
                    let text = picker::confirmed_text(kind, &picked, updated.len());
                    CreateInteractionResponse::UpdateMessage(
                        CreateInteractionResponseMessage::new()
                            .content(text)
                            .components(Vec::new()),
                    )
                }
                Err(e) => {
                    // 画面は残す（もう一度「確定」を押せる。Python も、書けなかったときは View を止めない）。
                    error!("[CMD] 選択の確定で設定を書けませんでした guild={guild}: {e}");
                    say(reply::FAILED)
                }
            }
        }
    };
    if let Err(e) = interaction.create_response(deps.http, response).await {
        warn!("[CMD] 選択の画面への応答を送れませんでした: {e}");
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
        assert_eq!(route("tts join"), None);
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
