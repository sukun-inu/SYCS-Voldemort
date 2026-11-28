//! /djaudio channel・output・status。Python の `commands/djaudio_commands.py`。
//!
//! channel・output は、Discord の「チャンネルの管理」の権限（discord.py の `has_permissions(manage_channels=True)`）を
//! 先に見て、そのあと管理者かを見る（`ensure_admin`。権限だけ持つ管理者でない人も断る）。
//!
//! 断り方と失敗の知らせ方は Python と同じく **2 通**になる。このコマンドには専用の受け皿
//! （`bind_permission_error_handler`）があり、discord.py はそのあとで全体の受け皿（`tree.on_error`）も呼ぶ:
//!
//! - 権限が無い: 「チャンネル管理の権限がなければ使えぬ」→（応答のあとから）「使う権限が貴様にはない」
//! - 中で失敗した（設定を書けない・返事を送れない）: 「何かが邪魔をした」→（あとから）「処理できなかった」
//!
//! status には専用の受け皿が無い（Python で `bind_permission_error_handler` を付けていない）ので、失敗は
//! 全体の受け皿の「処理できなかった」の 1 通だけ。

use serde_json::Value;
use serenity::all::{
    ChannelId, Colour, CommandDataOption, CommandDataOptionValue, CommandInteraction, CreateEmbed,
    GuildId,
};
use sycs_core::settings::Settings;
use tracing::warn;

use super::guards::Standing;
use super::reply::{self, Reply};
use super::{Deps, Route, metal, overview, respond, standing_of};
use crate::djaudio::Config;
use crate::djaudio::settings::{self, ChannelSetting, Runtime};

/// 「チャンネルの管理」の権限が無いとき（このコマンドの受け皿の文）。
pub const MISSING_MANAGE_CHANNELS: &str = "❌ チャンネル管理の権限がなければ使えぬ。";
/// 権限が無いとき（全体の受け皿の文。応答のあとから送る）。
pub const MISSING_PERMISSIONS: &str = "❌ 余のコマンドを使う権限が貴様にはない。";
/// 中で失敗したとき（このコマンドの受け皿の文）。
pub const COMMAND_FAILED: &str = "❌ 何かが邪魔をしたようだ。しばし待って試せ。";

/// discord.py の `discord.Color.red()`・`green()`・`blurple()`。
const RED: u32 = 0xe74c3c;
const GREEN: u32 = 0x2ecc71;
const BLURPLE: u32 = 0x5865f2;

/// どの /djaudio か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `/djaudio channel`
    Channel,
    /// `/djaudio output`
    Output,
    /// `/djaudio status`
    Status,
}

/// 道すじから /djaudio を引く。
pub fn command_of(route: Route) -> Option<Command> {
    match route {
        Route::DjaudioChannel => Some(Command::Channel),
        Route::DjaudioOutput => Some(Command::Output),
        Route::DjaudioStatus => Some(Command::Status),
        _ => None,
    }
}

/// 片付け方を決めるのに要るもの。
pub struct Input<'a> {
    /// 打った人の立場（管理者か）。
    pub standing: Standing,
    /// 打った人が、そのチャンネルで「チャンネルの管理」の権限を持つか（Discord が interaction に付けてくる権限）。
    pub manage_channels: bool,
    /// 打たれたサーバー（DM なら `None`）。
    pub guild_id: Option<u64>,
    /// 引数のチャンネル（無ければ外す）。
    pub channel: Option<u64>,
    /// そのサーバーのいまの設定。
    pub guild_settings: Option<&'a Value>,
    /// DJAudio の設定（配信のリンクの頭・既定の値）。
    pub config: &'a Config,
    /// 管理画面の場所（リンクのボタン）。
    pub admin_site_url: &'a str,
    /// そのサーバーにそのチャンネルがあるか（Python の `guild.get_channel`）。
    pub channel_exists: &'a dyn Fn(u64) -> bool,
}

/// 片付け方。
pub enum Plan {
    /// 本文だけを並べた順に送る（最初が応答、残りは応答のあとから）。
    Messages(Vec<&'static str>),
    /// 設定に触らずに返す。
    Reply(Reply),
    /// 設定を書いてから返す（返事は書く前に作る。Python も書く前に読んだ設定で返事を作る）。
    Write(Box<dyn FnOnce(&mut Settings) + Send>, Reply),
}

fn embed(title: &str, colour: u32) -> CreateEmbed {
    CreateEmbed::new().title(title).colour(Colour::new(colour))
}

/// `<#id>`（Python の `channel.mention`）。
fn mention(id: u64) -> String {
    format!("<#{id}>")
}

/// 設定のチャンネルの書き方。Python の `_channel_text`（消えたチャンネルは ID だけ）。
fn channel_text(channel: Option<&ChannelSetting>, exists: &dyn Fn(u64) -> bool) -> String {
    match channel {
        None => "未設定".to_string(),
        Some(c) => match c.id().filter(|id| exists(*id)) {
            Some(id) => mention(id),
            None => format!("ID: {}（チャンネル未検出）", c.text()),
        },
    }
}

/// 状況の Embed。Python の `_status_embed`。
pub fn status_embed(
    runtime: &Runtime,
    config: &Config,
    exists: &dyn Fn(u64) -> bool,
) -> CreateEmbed {
    let output = channel_text(runtime.output_channel.as_ref(), exists)
        + if runtime.output_channel.is_some() {
            ""
        } else {
            "（監視チャンネルに返信）"
        };
    let mut e = embed("🎵 DJAudio 設定", BLURPLE)
        .field(
            "監視チャンネル",
            channel_text(runtime.watch_channel.as_ref(), exists),
            true,
        )
        .field("出力チャンネル", output, true)
        .field("配信 URL ベース", format!("`{}`", config.base_url), false)
        .field(
            "キャッシュ有効期間",
            format!("{}分", runtime.cache_ttl.div_euclid(60)),
            true,
        )
        .field("クールダウン", format!("{}秒", runtime.cooldown), true)
        .field("最大URL / メッセージ", runtime.max_urls.to_string(), true);
    if config.base_url_is_local() {
        e = e.field(
            "⚠️ 配信 URL が localhost のまま",
            "サーバー外からリンクを開けない状態だ。`DJAUDIO_BASE_URL` を外部到達可能な URL に設定せよ。",
            false,
        );
    }
    e
}

fn with_admin_site(embed: CreateEmbed, admin_site_url: &str) -> Reply {
    Reply {
        content: None,
        embeds: vec![embed],
        components: overview::admin_site_row(admin_site_url),
        ephemeral: true,
    }
}

/// 打たれた /djaudio をどう片付けるかを決める（Discord にも DB にも触らない）。
pub fn plan(command: Command, input: &Input<'_>) -> Plan {
    let runtime = || settings::runtime(input.guild_settings, input.config.defaults);
    if command == Command::Status {
        // 見るだけなので、権限も管理者も見ない。
        return match input.guild_id {
            None => Plan::Messages(vec![reply::NOT_IN_GUILD]),
            Some(_) => Plan::Reply(with_admin_site(
                status_embed(&runtime(), input.config, input.channel_exists),
                input.admin_site_url,
            )),
        };
    }
    if !input.manage_channels {
        return Plan::Messages(vec![MISSING_MANAGE_CHANNELS, MISSING_PERMISSIONS]);
    }
    let Some(guild) = input.guild_id else {
        return Plan::Messages(vec![reply::NOT_IN_GUILD]);
    };
    if input.standing != Standing::Admin {
        return Plan::Messages(vec![reply::NOT_ADMIN]);
    }
    let channel = input.channel;
    match (command, channel) {
        (Command::Channel, None) => Plan::Write(
            Box::new(move |s| settings::set_watch_channel(s, guild, None)),
            Reply {
                embeds: vec![
                    embed("✅ DJAudio 監視チャンネル解除", RED)
                        .description("URL の自動 MP3 変換を無効にした。"),
                ],
                ephemeral: true,
                ..Reply::default()
            },
        ),
        (Command::Channel, Some(id)) => {
            let runtime = runtime();
            let mut e = embed("✅ DJAudio チャンネル設定完了", GREEN).description(format!(
                "{} を監視チャンネルと定めた。\nこのチャンネルに URL を投稿すれば、自動で MP3 リンクを返してやろう。\n\n\
                 🔗 配信 URL ベース: `{}`\n⏱️ キャッシュ有効期間: `{}分`\n⏳ クールダウン: `{}秒` / 最大URL: `{}`",
                mention(id),
                input.config.base_url,
                runtime.cache_ttl.div_euclid(60),
                runtime.cooldown,
                runtime.max_urls,
            ));
            if input.config.base_url_is_local() {
                e = e.field(
                    "⚠️ 注意",
                    "配信 URL ベースが `localhost` のままだ。このままではサーバー外の者はリンクを開けぬ。\
                     管理者は `DJAUDIO_BASE_URL` 環境変数を外部から到達可能な URL に設定せよ。",
                    false,
                );
            }
            Plan::Write(
                Box::new(move |s| settings::set_watch_channel(s, guild, Some(id))),
                with_admin_site(e, input.admin_site_url),
            )
        }
        (Command::Output, None) => Plan::Write(
            Box::new(move |s| settings::set_output_channel(s, guild, None)),
            with_admin_site(
                embed("✅ DJAudio 出力チャンネル解除", RED)
                    .description("結果は監視チャンネルへの返信で送られるようになった。"),
                input.admin_site_url,
            ),
        ),
        (Command::Output, Some(id)) => Plan::Write(
            Box::new(move |s| settings::set_output_channel(s, guild, Some(id))),
            with_admin_site(
                embed("✅ DJAudio 出力チャンネル設定完了", GREEN).description(format!(
                    "{} に MP3 リンクを送信するよう定めた。",
                    mention(id)
                )),
                input.admin_site_url,
            ),
        ),
        (Command::Status, _) => unreachable!("上で返している"),
    }
}

/// 中で失敗したときに送る文（channel・output はこのコマンドの受け皿と全体の受け皿の 2 通、status は全体の 1 通）。
pub fn failure_messages(command: Command) -> &'static [&'static str] {
    match command {
        Command::Status => &[reply::FAILED],
        Command::Channel | Command::Output => &[COMMAND_FAILED, reply::FAILED],
    }
}

fn channel_option(options: &[CommandDataOption], name: &str) -> Option<u64> {
    options
        .iter()
        .find(|o| o.name == name)
        .and_then(|o| match &o.value {
            CommandDataOptionValue::Channel(id) => Some(id.get()),
            _ => None,
        })
}

/// 本文だけを並べた順に送る（最初が応答、残りは応答のあとから）。どれかを送れなければ、そこで止める
/// （Python も、受け皿の中で送れなければ次の受け皿を呼ばない）。
async fn send_messages(
    deps: &Deps<'_>,
    command: &CommandInteraction,
    texts: &[&'static str],
    answered: bool,
) -> Result<(), String> {
    let mut answered = answered;
    for text in texts {
        let reply = Reply::ephemeral(*text);
        let outcome = if answered {
            command
                .create_followup(deps.http, metal::followup_message(reply))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        } else {
            respond(deps.http, command, reply)
                .await
                .map_err(|e| e.to_string())
        };
        outcome.map_err(|e| format!("「{text}」を送れませんでした: {e}"))?;
        answered = true;
    }
    Ok(())
}

/// /djaudio を 1 つ片付ける（返事まで送る）。`Err` はログに残す失敗の理由。
pub async fn run(
    deps: &Deps<'_>,
    command: &CommandInteraction,
    options: &[CommandDataOption],
    which: Command,
) -> Result<(), String> {
    // 段取りは待つ前に決めて、キャッシュと設定の控えを手放す（待つ間に持っていると、送れない値になる）。
    let planned = {
        let snapshot = deps.settings.snapshot();
        let guild_id = command.guild_id.map(GuildId::get);
        let exists = |id: u64| {
            command
                .guild_id
                .and_then(|g| deps.cache.guild(g))
                .is_some_and(|g| g.channels.contains_key(&ChannelId::new(id)))
        };
        let input = Input {
            standing: standing_of(deps.cache, command),
            manage_channels: command
                .member
                .as_ref()
                .and_then(|m| m.permissions)
                .is_some_and(|p| p.manage_channels()),
            guild_id,
            channel: channel_option(options, "channel"),
            guild_settings: guild_id.and_then(|g| snapshot.guild(g)),
            config: deps.djaudio,
            admin_site_url: deps.admin_site_url,
            channel_exists: &exists,
        };
        plan(which, &input)
    };
    let failure = match planned {
        Plan::Messages(texts) => return send_messages(deps, command, &texts, false).await,
        Plan::Reply(reply) => respond(deps.http, command, reply)
            .await
            .err()
            .map(|e| format!("返事を送れませんでした: {e}")),
        Plan::Write(write, reply) => match deps.settings.transact(move |s| write(s)).await {
            Err(e) => Some(format!("設定を書けませんでした: {e}")),
            Ok(()) => respond(deps.http, command, reply)
                .await
                .err()
                .map(|e| format!("返事を送れませんでした: {e}")),
        },
    };
    let Some(failure) = failure else {
        return Ok(());
    };
    // Python と同じく、このコマンドの受け皿 → 全体の受け皿の順に知らせる（まだ応答していないので、1 通目が応答）。
    if let Err(e) = send_messages(deps, command, failure_messages(which), false).await {
        warn!("[DJAudio] 失敗の知らせを送れませんでした: {e}");
    }
    Err(failure)
}
