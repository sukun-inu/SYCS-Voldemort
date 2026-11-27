//! サーバーの設定のコマンド（/greeting・/vcnotify・/sticky・/reactionrole・/news）。Python の
//! `commands/server/` の `welcome_goodbye.py`・`vcnotify.py`・`sticky.py`・`reactionrole.py`・`news.py`。
//!
//! - 書き換えるコマンド（Python が `ensure_admin` を呼ぶもの）は管理者だけ。見るだけのコマンド（status・list）は、
//!   サーバーの中なら誰でも打てる
//! - `/sticky set`・`/sticky clear` は、**返事を返してから**貼る・剥がす（[`After`]）
//! - `/reactionrole remove`・`/news remove` の引数には補完がある（[`choices`]・[`autocomplete`]）。補完は権限を
//!   見ない（Python も見ていない）
//!
//! 返事の文・設定の書き方は Python と同じ。一致は、本物の Python のコマンドと補完の関数を呼んで作った基準
//! （`tests/fixtures/commands/server_expected.jsonl`）と突き合わせて確かめている
//! （`tests/commands_server_golden.rs`）。

pub mod greeting;
pub mod news;
pub mod python;
pub mod reactionrole;
pub mod sticky;

use serde_json::{Map, Value};
use serenity::all::{
    AutocompleteChoice, Cache, ChannelId, ChannelType, CommandDataOption, CommandDataOptionValue,
    CommandInteraction, CreateAutocompleteResponse, CreateInteractionResponse, RoleId,
};
use sycs_core::settings::Settings;
use tracing::warn;

use super::guards::{self, Standing};
use super::reply::{self, Reply};
use super::{
    CommandError, Deps, PlanInput, Planned, Route, channel_option, command_path, option, route,
    string_option,
};
use crate::sticky::StickyCtx;
use crate::welcome::Kind;

/// サーバーの設定のコマンド。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRoute {
    /// `/greeting welcome channel`
    WelcomeChannel,
    /// `/greeting welcome message`
    WelcomeMessage,
    /// `/greeting goodbye channel`
    GoodbyeChannel,
    /// `/greeting goodbye message`
    GoodbyeMessage,
    /// `/greeting status`
    GreetingStatus,
    /// `/vcnotify set`
    VcNotifySet,
    /// `/vcnotify clear`
    VcNotifyClear,
    /// `/sticky set`
    StickySet,
    /// `/sticky clear`
    StickyClear,
    /// `/sticky list`
    StickyList,
    /// `/reactionrole add`
    ReactionRoleAdd,
    /// `/reactionrole remove`
    ReactionRoleRemove,
    /// `/reactionrole list`
    ReactionRoleList,
    /// `/news add`
    NewsAdd,
    /// `/news remove`
    NewsRemove,
    /// `/news list`
    NewsList,
}

impl ServerRoute {
    /// 見るだけのコマンドか（Python が `ensure_admin` を呼ばないもの。サーバーの中なら誰でも打てる）。
    pub fn open_to_everyone(self) -> bool {
        matches!(
            self,
            Self::GreetingStatus | Self::StickyList | Self::ReactionRoleList | Self::NewsList
        )
    }
}

/// コマンドが打たれた場所。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Place {
    /// 打たれたチャンネル。
    pub channel_id: u64,
    /// テキストチャンネルか。Python の `isinstance(interaction.channel, discord.TextChannel)`。
    pub is_text: bool,
}

/// テキストチャンネルの種類か（お知らせチャンネルを含む。discord.py の `TextChannel` に入るもの）。
///
/// スレッド・VC のチャット・ステージ・フォーラムは入らない。
pub fn is_text_kind(kind: ChannelType) -> bool {
    matches!(kind, ChannelType::Text | ChannelType::News)
}

/// コマンドが打たれた場所を調べる。
///
/// チャンネルの種類は、discord.py と同じく、まずキャッシュのサーバーから引き（チャンネル → スレッド）、無ければ
/// Discord がコマンドに付けてきたものを使う。どちらにも無ければ、テキストチャンネルではないとみなす。
pub fn place_of(cache: &Cache, command: &CommandInteraction) -> Place {
    let channel_id = command.channel_id;
    let cached = command
        .guild_id
        .and_then(|guild_id| cache.guild(guild_id))
        .and_then(|guild| {
            let channel = guild.channels.get(&channel_id).map(|c| c.kind);
            channel.or_else(|| {
                let thread = guild.threads.iter().find(|t| t.id == channel_id);
                thread.map(|t| t.kind)
            })
        });
    let kind = cached.or_else(|| command.channel.as_ref().map(|c| c.kind));
    Place {
        channel_id: channel_id.get(),
        is_text: kind.is_some_and(is_text_kind),
    }
}

/// 返事を送ったあとにする仕事。Python が「応答してから」行っているもの。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum After {
    /// いまの設定で、スティッキーを貼り直す（`/sticky set`）。Python の `post_sticky`。
    PostSticky {
        /// サーバー。
        guild_id: u64,
        /// 貼るチャンネル。
        channel_id: u64,
    },
    /// スティッキーを剥がし、設定からも外す（`/sticky clear`）。Python の `delete_sticky`。
    DeleteSticky {
        /// サーバー。
        guild_id: u64,
        /// 剥がすチャンネル。
        channel_id: u64,
    },
}

impl After {
    /// 仕事をする（返事を送り終えてから呼ぶ）。失敗は中でログに残す。
    pub async fn run(self, deps: &Deps<'_>) {
        match self {
            Self::PostSticky {
                guild_id,
                channel_id,
            } => {
                let ctx = StickyCtx {
                    http: deps.http,
                    cache: deps.cache,
                    settings: deps.settings,
                    locks: deps.sticky_locks,
                };
                crate::sticky::post_now(&ctx, guild_id, channel_id).await;
            }
            Self::DeleteSticky {
                guild_id,
                channel_id,
            } => sticky::delete(deps.http, deps.settings, guild_id, channel_id).await,
        }
    }
}

/// そのサーバーの設定の入れ物（無ければ空で作る。辞書でなければ空に置き換える）。Python の
/// `_get_or_create_guild`。
fn guild_entry(settings: &mut Settings, guild_id: u64) -> &mut Map<String, Value> {
    child_of(settings.guilds.entry(guild_id.to_string()).or_default())
}

/// 辞書の中の辞書（無ければ末尾に空で作る。辞書でなければ、その場所で空に置き換える）。Python の
/// `x = parent.get(key, {})` → 辞書でなければ `{}` → 書き換え → `parent[key] = x`。
fn child<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    child_of(parent.entry(key).or_insert(Value::Null))
}

fn child_of(slot: &mut Value) -> &mut Map<String, Value> {
    if !slot.is_object() {
        *slot = Value::Object(Map::new());
    }
    slot.as_object_mut().expect("直前に辞書にした")
}

fn role_option(options: &[CommandDataOption], name: &str) -> Option<RoleId> {
    match option(options, name)? {
        CommandDataOptionValue::Role(id) => Some(*id),
        _ => None,
    }
}

fn integer_option(options: &[CommandDataOption], name: &str) -> Option<i64> {
    match option(options, name)? {
        CommandDataOptionValue::Integer(number) => Some(*number),
        _ => None,
    }
}

/// サーバーの設定のコマンドを、どう片付けるかを決める（権限・引数・打たれた場所を見る。Discord にも DB にも
/// 触らない）。
pub fn plan(route: ServerRoute, input: &PlanInput<'_>) -> Result<Planned, CommandError> {
    use ServerRoute as R;
    let reply = |reply: Reply| Ok(Planned::Reply(Box::new(reply)));
    let say = |text: &str| reply(Reply::ephemeral(text));
    // 見るだけのコマンドは、サーバーの中なら誰でも。書き換えるコマンドは管理者だけ（Python の ensure_admin）。
    let refusal = if route.open_to_everyone() {
        (input.standing == Standing::OutsideGuild).then_some(reply::NOT_IN_GUILD)
    } else {
        guards::refusal_for_admin_only(input.standing)
    };
    if let Some(text) = refusal {
        return say(text);
    }
    let Some(guild_id) = input.guild_id else {
        return say(reply::NOT_IN_GUILD);
    };
    let guild = guild_id.get();
    let stored = input.guild_settings;
    let options = input.options;
    let channel = || {
        channel_option(options, "channel")
            .map(ChannelId::get)
            .ok_or(CommandError::MissingOption("channel"))
    };
    let text = |name: &'static str| {
        string_option(options, name)
            .map(str::to_string)
            .ok_or(CommandError::MissingOption(name))
    };
    // /reactionrole の message_id。数として読めなければ断る（権限を見たあと。Python の `_parse_message_id`）。
    let message_id = || text("message_id").map(|raw| python::int_text(&raw));
    match route {
        R::GreetingStatus => reply(greeting::status(stored, input.admin_site_url)?),
        R::StickyList => reply(sticky::list(stored)?),
        R::ReactionRoleList => reply(reactionrole::list(stored)?),
        R::NewsList => reply(news::list(stored)?),
        R::WelcomeChannel | R::GoodbyeChannel => {
            let (kind, id) = (greeting_kind(route), channel()?);
            Ok(Planned::Write(Box::new(move |s| {
                greeting::set_channel(s, guild, kind, id)
            })))
        }
        R::WelcomeMessage | R::GoodbyeMessage => {
            let (kind, message) = (greeting_kind(route), text("message")?);
            Ok(Planned::Write(Box::new(move |s| {
                greeting::set_message(s, guild, kind, &message)
            })))
        }
        R::VcNotifySet => {
            let id = channel()?;
            Ok(Planned::Write(Box::new(move |s| {
                greeting::vc_notify_set(s, guild, id)
            })))
        }
        R::VcNotifyClear => Ok(Planned::Write(Box::new(move |s| {
            greeting::vc_notify_clear(s, guild)
        }))),
        R::StickySet => {
            let content = text("content")?;
            if !input.place.is_text {
                return say(sticky::TEXT_CHANNEL_ONLY);
            }
            let channel_id = input.place.channel_id;
            // 書いて返事をしてから、貼る（貼るのが遅くても、3 秒の応答期限に響かないように）。
            Ok(Planned::WriteThen(
                Box::new(move |s| sticky::set(s, guild, channel_id, &content)),
                After::PostSticky {
                    guild_id: guild,
                    channel_id,
                },
            ))
        }
        R::StickyClear => {
            if !input.place.is_text {
                return say(sticky::TEXT_CHANNEL_ONLY);
            }
            // 返事をしてから、剥がして設定から外す。
            Ok(Planned::ReplyThen(
                Box::new(Reply::ephemeral(sticky::CLEARED)),
                After::DeleteSticky {
                    guild_id: guild,
                    channel_id: input.place.channel_id,
                },
            ))
        }
        R::ReactionRoleAdd => {
            let (id, emoji) = (message_id()?, text("emoji")?);
            let role = role_option(options, "role")
                .ok_or(CommandError::MissingOption("role"))?
                .get();
            let Some(id) = id else {
                return say(reactionrole::BAD_MESSAGE_ID);
            };
            Ok(Planned::Write(Box::new(move |s| {
                reactionrole::add(s, guild, &id, &emoji, role)
            })))
        }
        R::ReactionRoleRemove => {
            let (id, emoji) = (message_id()?, text("emoji")?);
            let Some(id) = id else {
                return say(reactionrole::BAD_MESSAGE_ID);
            };
            Ok(Planned::Write(Box::new(move |s| {
                reactionrole::remove(s, guild, &id, &emoji)
            })))
        }
        R::NewsAdd => {
            let (id, query) = (channel()?, text("query")?);
            let interval =
                integer_option(options, "interval").unwrap_or(news::DEFAULT_INTERVAL_MINUTES);
            if let Some(refusal) = news::refusal_for_add(stored, interval)? {
                return say(&refusal);
            }
            let feed_id = news::new_feed_id();
            Ok(Planned::Write(Box::new(move |s| {
                news::add(s, guild, &feed_id, id, &query, interval)
            })))
        }
        R::NewsRemove => {
            let feed_id = text("feed_id")?;
            Ok(Planned::Write(Box::new(move |s| {
                news::remove(s, guild, &feed_id)
            })))
        }
    }
}

/// 歓迎の設定か、お別れの設定か。
fn greeting_kind(route: ServerRoute) -> Kind {
    match route {
        ServerRoute::GoodbyeChannel | ServerRoute::GoodbyeMessage => Kind::Goodbye,
        _ => Kind::Welcome,
    }
}

/// 補完の候補 1 つ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    /// 候補として見せる文（100 文字まで）。
    pub name: String,
    /// 選んだときに引数に入る値。
    pub value: String,
}

/// 候補の数の上限（Discord の決まり）。
pub const CHOICE_LIMIT: usize = 25;
/// 候補の名前の長さの上限（Discord の決まり）。
pub const CHOICE_NAME_CHARS: usize = 100;

/// 補完の候補を決めるのに要るもの。
pub struct ChoiceInput<'a> {
    /// サーバーの中で打たれているか（外なら候補は空）。
    pub in_guild: bool,
    /// そのサーバーのいまの設定。
    pub guild_settings: Option<&'a Value>,
    /// 末端の引数（入力中のものと、先に入れたもの）。
    pub options: &'a [CommandDataOption],
    /// ロールの名前（サーバーに無ければ `None`）。
    pub role_name: &'a dyn Fn(u64) -> Option<String>,
    /// チャンネルの名前（サーバーに無ければ `None`。スレッドは引かない）。
    pub channel_name: &'a dyn Fn(u64) -> Option<String>,
}

/// 補完の候補を決める（Discord にも DB にも触らない）。Python の `_message_id_choices`・`_emoji_choices`・
/// `_feed_id_choices`。
///
/// `path` はコマンドの道すじ、`focused` は入力中の引数、`current` はそこに入っている文字。この Bot が補完を
/// 出さない引数なら `Ok(None)`（応えない）。設定が読めない形なら `Err`（Python は例外で、何も返さない）。
pub fn choices(
    path: &str,
    focused: &str,
    current: &str,
    input: &ChoiceInput<'_>,
) -> Result<Option<Vec<Choice>>, CommandError> {
    let Some(Route::Server(route)) = route(path) else {
        return Ok(None);
    };
    let stored = input.guild_settings;
    let found = match (route, focused) {
        (ServerRoute::ReactionRoleRemove, "message_id") if input.in_guild => {
            reactionrole::message_id_choices(stored, current)?
        }
        (ServerRoute::ReactionRoleRemove, "emoji") if input.in_guild => {
            // 先に入れた message_id（入れた文字のまま。数として読み直さない）。
            let selected = string_option(input.options, "message_id").unwrap_or("");
            reactionrole::emoji_choices(stored, selected, current, input.role_name)?
        }
        (ServerRoute::NewsRemove, "feed_id") if input.in_guild => {
            news::feed_id_choices(stored, current, input.channel_name)?
        }
        // サーバーの外では、候補は空（Python の `if interaction.guild is None: return []`）。
        (ServerRoute::ReactionRoleRemove, "message_id" | "emoji")
        | (ServerRoute::NewsRemove, "feed_id") => Vec::new(),
        _ => return Ok(None),
    };
    Ok(Some(found))
}

/// 補完の問い合わせを 1 つ片付ける（候補を返す）。
///
/// 権限は見ない（Python も見ていない）。打たれた記録も残さない（1 文字ごとに届く）。
pub async fn autocomplete(deps: &Deps<'_>, interaction: &CommandInteraction) {
    let (path, options) = command_path(&interaction.data.name, &interaction.data.options);
    let Some(focused) = interaction.data.autocomplete() else {
        return;
    };
    // サーバーの中か。コマンドと同じく、キャッシュにあるサーバーだけを「中」とみなす。
    let guild_id = interaction
        .guild_id
        .filter(|guild_id| deps.cache.guild(*guild_id).is_some());
    // 候補を決めるところは、送る前に終える（名前を引く関数を、送信の待ちをまたいで持たない）。
    let decided = {
        let snapshot = deps.settings.snapshot();
        let role_name = |id: u64| {
            let guild = deps.cache.guild(guild_id?)?;
            guild.roles.get(&RoleId::new(id)).map(|r| r.name.clone())
        };
        let channel_name = |id: u64| {
            let guild = deps.cache.guild(guild_id?)?;
            let channel = guild.channels.get(&ChannelId::new(id));
            channel.map(|c| c.name.clone())
        };
        let input = ChoiceInput {
            in_guild: guild_id.is_some(),
            guild_settings: guild_id.and_then(|g| snapshot.guild(g.get())),
            options,
            role_name: &role_name,
            channel_name: &channel_name,
        };
        choices(&path, focused.name, focused.value, &input)
    };
    let found = match decided {
        Ok(Some(found)) => found,
        Ok(None) => return,
        Err(e) => {
            // Python も、候補の関数が例外を出したら何も返さない（利用者には「読み込めませんでした」と出る）。
            warn!(
                "[CMD] /{path} の補完（{}）を作れませんでした: {e}",
                focused.name
            );
            return;
        }
    };
    let list = found
        .into_iter()
        .map(|choice| AutocompleteChoice::new(choice.name, choice.value))
        .collect();
    let response = CreateInteractionResponse::Autocomplete(
        CreateAutocompleteResponse::new().set_choices(list),
    );
    if let Err(e) = interaction.create_response(deps.http, response).await {
        warn!("[CMD] /{path} の補完の候補を送れませんでした: {e}");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 入れ物の作り方: 無ければ末尾に作り、辞書でなければその場所で空に置き換え、あればそのまま使う。
    #[test]
    fn nested_tables_are_created_in_place() {
        let mut settings = Settings::default();
        settings
            .guilds
            .insert("7".into(), json!({"a": 1, "t": "壊れた値", "z": {"k": 1}}));
        let guild = guild_entry(&mut settings, 7);
        child(guild, "t").insert("x".into(), json!(1));
        child(guild, "z").insert("x".into(), json!(2));
        child(guild, "new").insert("x".into(), json!(3));
        assert_eq!(
            serde_json::to_string(&settings.guilds["7"]).unwrap(),
            r#"{"a":1,"t":{"x":1},"z":{"k":1,"x":2},"new":{"x":3}}"#
        );
        // サーバーの設定そのものが無い・辞書でないときも、空から始める。
        let mut broken = Settings::default();
        broken.guilds.insert("7".into(), json!("壊れた値"));
        assert!(guild_entry(&mut broken, 7).is_empty());
        assert!(guild_entry(&mut broken, 8).is_empty());
        assert_eq!(broken.guilds["8"], json!({}));
    }

    /// テキストチャンネルに数えるのは、テキストとお知らせだけ。
    #[test]
    fn only_text_and_news_channels_count_as_text() {
        assert!(is_text_kind(ChannelType::Text));
        assert!(is_text_kind(ChannelType::News));
        for kind in [
            ChannelType::Voice,
            ChannelType::Stage,
            ChannelType::Forum,
            ChannelType::Category,
            ChannelType::PublicThread,
            ChannelType::PrivateThread,
            ChannelType::NewsThread,
        ] {
            assert!(!is_text_kind(kind), "{kind:?}");
        }
    }

    /// 見るだけのコマンドは 4 つ（status と 3 つの list）。
    #[test]
    fn the_four_viewing_commands_are_open_to_everyone() {
        let open: Vec<&str> = crate::commands::PORTED
            .iter()
            .filter_map(|(path, route)| match route {
                Route::Server(route) if route.open_to_everyone() => Some(*path),
                _ => None,
            })
            .collect();
        assert_eq!(
            open,
            [
                "greeting status",
                "sticky list",
                "reactionrole list",
                "news list"
            ]
        );
    }
}
