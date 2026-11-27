//! サーバーとユーザーの情報を表示するコマンド（/info server・/info user）。Python の `commands/server/info.py`。
//!
//! どちらも読むだけで、誰でも打てる（サーバーの中なら）。返事は全員に見える。
//!
//! 情報の出どころは discord.py と同じにしてある:
//!
//! - サーバー（名前・アイコン・持ち主・人数・チャンネルとロールの数・ブースト）は、Bot が覚えているもの
//!   （serenity のキャッシュ。discord.py の `interaction.guild`）
//! - メンバー（ニックネーム・ロール・参加日・サーバーごとのアバター）は、**コマンドと一緒に届いたもの**
//!   （打った本人は `member`、引数で選んだ人は `resolved`）。discord.py も、届いたものから `Member` を作る。
//!   ロールの名前や色・位置は、サーバーの側（キャッシュ）から引く
//!
//! 権限の見方がほかのコマンドと違う（管理者でなくても打てる）ので、[`super::plan`] は通さず、
//! [`super::run`] が先にここ（[`run`]）へ回す。

use serenity::all::{
    Cache, ChannelType, CommandDataOption, CommandDataOptionValue, CommandInteraction, CreateEmbed,
    Guild, GuildId, ImageHash, RoleId, Timestamp, User,
};

use super::guards::Standing;
use super::overview::admin_site_row;
use super::reply::{self, Reply};
use super::settings::BLURPLE;
use super::{CommandError, Deps, Route};
use crate::compat;
use crate::members::{jst_minutes, snowflake_jst, sorted_roles};

/// 引数で選んだ人がこのサーバーのメンバーでないときの文。
///
/// discord.py は、メンバーを取る引数にメンバーでない人が来ると、コマンドの中身を呼ぶ前に失敗にする
/// （`TransformerError`）。その受け皿（`_on_tree_error` の最後の枝）がこの文を返す。
pub const NOT_A_MEMBER: &str = "❌ 予期せぬ障害が生じた。しばし待て。";
/// 打った人のメンバーとしての情報が届いていないときの文（Python の `isinstance(target, discord.Member)` の枝）。
pub const NO_MEMBER: &str = "そのメンバーの情報を取得できなかった。";
/// 一覧に並べるロールの数（Python の `roles[:15]`。超えたぶんは黙って省く）。
pub const ROLE_LIMIT: usize = 15;

/// どの /info か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `/info server`
    Server,
    /// `/info user`
    User,
}

/// 振り分けの先から、どの /info かを引く。/info でなければ `None`。
pub fn command_of(route: Route) -> Option<Command> {
    match route {
        Route::InfoServer => Some(Command::Server),
        Route::InfoUser => Some(Command::User),
        _ => None,
    }
}

/// サーバーのアイコンの URL。discord.py の `guild.icon.url`（動くものは gif、それ以外は png。大きさは 1024）。
pub fn guild_icon_url(guild_id: GuildId, hash: &ImageHash) -> String {
    let format = if hash.is_animated() { "gif" } else { "png" };
    format!("{}/icons/{guild_id}/{hash}.{format}?size=1024", compat::CDN)
}

/// `/info server` の返事（Embed と、管理画面へのリンクのボタン）。Python の `serverinfo_cmd`。
pub fn server_reply(guild: &Guild, admin_site_url: &str) -> Reply {
    // 持ち主は、Bot がメンバーとして覚えているときだけ出せる（discord.py の `guild.owner`）。
    let owner = guild
        .members
        .get(&guild.owner_id)
        .map_or_else(|| "不明".to_string(), |m| compat::mention(m.user.id));
    // @everyone は数えない。
    let roles_count = guild.roles.len() as i64 - 1;
    let count = |wanted: fn(ChannelType) -> bool| {
        guild
            .channels
            .values()
            .filter(|channel| wanted(channel.kind))
            .count()
    };
    // discord.py の TextChannel はテキストとお知らせ、VoiceChannel は VC だけ（ステージは別）。
    let text_channels = count(|kind| matches!(kind, ChannelType::Text | ChannelType::News));
    let voice_channels = count(|kind| matches!(kind, ChannelType::Voice));
    let mut embed = CreateEmbed::new().title(&guild.name).colour(BLURPLE);
    if let Some(icon) = &guild.icon {
        embed = embed.thumbnail(guild_icon_url(guild.id, icon));
    }
    let embed = embed
        .field("サーバーID", guild.id.to_string(), true)
        .field("オーナー", owner, true)
        .field("メンバー数", guild.member_count.to_string(), true)
        .field("テキストチャンネル", text_channels.to_string(), true)
        .field("ボイスチャンネル", voice_channels.to_string(), true)
        .field("ロール数", roles_count.to_string(), true)
        .field("作成日", snowflake_jst(guild.id.get()), true)
        .field(
            "ブーストレベル",
            u8::from(guild.premium_tier).to_string(),
            true,
        )
        .field(
            "ブースト数",
            guild.premium_subscription_count.unwrap_or(0).to_string(),
            true,
        );
    Reply {
        content: None,
        embeds: vec![embed],
        components: admin_site_row(admin_site_url),
        ephemeral: false,
    }
}

/// 情報を出す相手（コマンドと一緒に届いたメンバーの情報）。
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// その人。
    pub user: &'a User,
    /// ニックネーム。
    pub nick: Option<&'a str>,
    /// 持っているロール。
    pub roles: &'a [RoleId],
    /// サーバーに参加した時刻。
    pub joined_at: Option<Timestamp>,
    /// サーバーごとのアバター。
    pub guild_avatar: Option<&'a ImageHash>,
}

/// だれの情報を出すか。Python の `target = member or interaction.user`。
pub fn target_of<'a>(
    command: &'a CommandInteraction,
    options: &[CommandDataOption],
) -> Result<Target<'a>, &'static str> {
    let picked = options
        .iter()
        .find(|o| o.name == "member")
        .and_then(|o| match &o.value {
            CommandDataOptionValue::User(id) => Some(*id),
            _ => None,
        });
    let Some(picked) = picked else {
        // 省略したら自分。
        let member = command.member.as_deref().ok_or(NO_MEMBER)?;
        return Ok(Target {
            user: &member.user,
            nick: member.nick.as_deref(),
            roles: &member.roles,
            joined_at: member.joined_at,
            guild_avatar: member.avatar.as_ref(),
        });
    };
    // 選んだ人がこのサーバーにいれば、Discord がメンバーの情報を付けてくる。いなければ付かない。
    let resolved = &command.data.resolved;
    let (Some(member), Some(user)) = (resolved.members.get(&picked), resolved.users.get(&picked))
    else {
        return Err(NOT_A_MEMBER);
    };
    Ok(Target {
        user,
        nick: member.nick.as_deref(),
        roles: &member.roles,
        joined_at: member.joined_at,
        guild_avatar: member.avatar.as_ref(),
    })
}

/// `/info user` の返事（Embed）。Python の `userinfo_cmd`。
pub fn user_reply(guild: &Guild, target: &Target<'_>) -> Reply {
    let user = target.user;
    // 位置の低い順（discord.py の `member.roles`。@everyone と、サーバーにもう無いロールは入らない）。
    let roles = sorted_roles(target.roles, &guild.roles, guild.id);
    // 表示の色は、いちばん上のロールから順に見て、色の付いている最初のもの（discord.py の `member.colour`）。
    let colour = roles
        .iter()
        .rev()
        .filter_map(|id| guild.roles.get(id))
        .map(|role| role.colours.primary_colour.0)
        .find(|colour| *colour != 0)
        .unwrap_or(0);
    let avatar = match target.guild_avatar {
        Some(hash) => compat::guild_avatar_url(guild.id, user.id, hash),
        None => compat::user_avatar_url(user),
    };
    let joined = target
        .joined_at
        .map_or_else(|| "不明".to_string(), jst_minutes);
    let nick = match target.nick {
        Some(nick) if !nick.is_empty() => nick,
        _ => "(なし)",
    };
    let mentions: Vec<String> = roles
        .iter()
        .take(ROLE_LIMIT)
        .map(|id| format!("<@&{id}>"))
        .collect();
    let role_list = if mentions.is_empty() {
        "なし".to_string()
    } else {
        mentions.join(" ")
    };
    let embed = CreateEmbed::new()
        .title(compat::user_tag(user))
        .colour(colour)
        .thumbnail(avatar)
        .field("ユーザーID", user.id.to_string(), true)
        .field("ニックネーム", nick, true)
        .field("アカウント作成日", snowflake_jst(user.id.get()), true)
        .field("サーバー参加日", joined, true)
        .field("BOT", if user.bot { "はい" } else { "いいえ" }, true)
        .field(format!("ロール（{}個）", roles.len()), role_list, false);
    Reply {
        content: None,
        embeds: vec![embed],
        components: Vec::new(),
        ephemeral: false,
    }
}

/// 打たれた /info の返事を作る（キャッシュと、届いたコマンドを読むだけ）。
pub fn answer(
    which: Command,
    standing: Standing,
    cache: &Cache,
    command: &CommandInteraction,
    options: &[CommandDataOption],
    admin_site_url: &str,
) -> Reply {
    // サーバーの外（Bot がそのサーバーを覚えていないときも）では使えない。
    let guild = match (standing, command.guild_id.and_then(|id| cache.guild(id))) {
        (Standing::OutsideGuild, _) | (_, None) => return Reply::ephemeral(reply::NOT_IN_GUILD),
        (_, Some(guild)) => guild,
    };
    match which {
        Command::Server => server_reply(&guild, admin_site_url),
        Command::User => match target_of(command, options) {
            Ok(target) => user_reply(&guild, &target),
            Err(text) => Reply::ephemeral(text),
        },
    }
}

/// 打たれた /info を実行して、返事を作る。/info でなければ `None`（[`super::run`] が続きをする）。
pub fn run(
    deps: &Deps<'_>,
    route: Route,
    command: &CommandInteraction,
    options: &[CommandDataOption],
) -> Option<Result<Reply, CommandError>> {
    let which = command_of(route)?;
    let standing = super::standing_of(deps.cache, command);
    Some(Ok(answer(
        which,
        standing,
        deps.cache,
        command,
        options,
        deps.admin_site_url,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// アイコンの URL は discord.py と同じ形（静止画は png、動くものは gif、大きさ 1024）。
    #[test]
    fn icon_urls_match_discord_py() {
        let guild = GuildId::new(1_399_617_700_363_370_556);
        let still: ImageHash = "8342729096ea3675442027381ff50dfe".parse().unwrap();
        assert_eq!(
            guild_icon_url(guild, &still),
            "https://cdn.discordapp.com/icons/1399617700363370556/8342729096ea3675442027381ff50dfe.png?size=1024"
        );
        let moving: ImageHash = "a_8342729096ea3675442027381ff50dfe".parse().unwrap();
        assert!(
            guild_icon_url(guild, &moving)
                .ends_with("/a_8342729096ea3675442027381ff50dfe.gif?size=1024")
        );
    }

    /// 振り分けの先との組み合わせ。/info でないものは引かない。
    #[test]
    fn routes_map_to_commands() {
        assert_eq!(command_of(Route::InfoServer), Some(Command::Server));
        assert_eq!(command_of(Route::InfoUser), Some(Command::User));
        assert_eq!(command_of(Route::QuakeStatus), None);
        assert_eq!(command_of(Route::BotHelp), None);
    }
}
