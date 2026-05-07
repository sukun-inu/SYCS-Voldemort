import uuid
from datetime import timezone, timedelta
from typing import Optional

import discord
from discord import app_commands
from discord.ext.commands import Bot

from services.sticky_service import post_sticky
from services.settings_store import (
    add_news_feed,
    add_reaction_role,
    get_earthquake_settings,
    get_goodbye_settings,
    get_news_feeds,
    get_reaction_roles,
    get_sticky_messages,
    get_vc_notify_channel_id,
    get_welcome_settings,
    remove_news_feed,
    remove_reaction_role,
    remove_sticky_message,
    set_earthquake_channel,
    set_earthquake_min_scale,
    set_goodbye_channel,
    set_goodbye_message,
    set_sticky_message,
    set_vc_notify_channel_id,
    set_welcome_channel,
    set_welcome_message,
)

_JST = timezone(timedelta(hours=9))


async def _ensure_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await interaction.response.send_message("ギルド内でのみ使用可能だ。", ephemeral=True)
        return False
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("このコマンドは管理者のみが実行できる。", ephemeral=True)
        return False
    return True


def register_server_commands(bot: Bot) -> None:

    # ──────────────────────────────────────────────
    # ウェルカム / グッバイ
    # ──────────────────────────────────────────────

    @bot.tree.command(name="set_welcome_channel", description="参加メッセージを送信するチャンネルを設定（管理者専用）")
    @app_commands.describe(channel="ウェルカムメッセージを送るチャンネル")
    async def set_welcome_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin(interaction):
            return
        set_welcome_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(f"ウェルカムチャンネルを {channel.mention} に設定した。", ephemeral=True)

    @bot.tree.command(name="set_welcome_message", description="参加メッセージのテンプレートを設定（管理者専用）")
    @app_commands.describe(message="テンプレート: {user} {username} {server} {count} が使用可能")
    async def set_welcome_msg(interaction: discord.Interaction, message: str):
        if not await _ensure_admin(interaction):
            return
        set_welcome_message(interaction.guild.id, message)
        await interaction.response.send_message(f"ウェルカムメッセージを設定した。\n> {message}", ephemeral=True)

    @bot.tree.command(name="set_goodbye_channel", description="退出メッセージを送信するチャンネルを設定（管理者専用）")
    @app_commands.describe(channel="グッバイメッセージを送るチャンネル")
    async def set_goodbye_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin(interaction):
            return
        set_goodbye_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(f"グッバイチャンネルを {channel.mention} に設定した。", ephemeral=True)

    @bot.tree.command(name="set_goodbye_message", description="退出メッセージのテンプレートを設定（管理者専用）")
    @app_commands.describe(message="テンプレート: {user} {username} {server} {count} が使用可能")
    async def set_goodbye_msg(interaction: discord.Interaction, message: str):
        if not await _ensure_admin(interaction):
            return
        set_goodbye_message(interaction.guild.id, message)
        await interaction.response.send_message(f"グッバイメッセージを設定した。\n> {message}", ephemeral=True)

    @bot.tree.command(name="welcome_settings", description="現在のウェルカム/グッバイ設定を表示（管理者専用）")
    async def welcome_settings_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        ws = get_welcome_settings(interaction.guild.id)
        gs = get_goodbye_settings(interaction.guild.id)
        w_ch = f"<#{ws.get('channel_id')}>" if ws.get("channel_id") else "未設定"
        g_ch = f"<#{gs.get('channel_id')}>" if gs.get("channel_id") else "未設定"
        embed = discord.Embed(title="ウェルカム/グッバイ設定", color=discord.Color.green())
        embed.add_field(name="ウェルカムチャンネル", value=w_ch, inline=True)
        embed.add_field(name="ウェルカムメッセージ", value=ws.get("message") or "(デフォルト)", inline=False)
        embed.add_field(name="グッバイチャンネル", value=g_ch, inline=True)
        embed.add_field(name="グッバイメッセージ", value=gs.get("message") or "(デフォルト)", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ──────────────────────────────────────────────
    # VC 通知
    # ──────────────────────────────────────────────

    @bot.tree.command(name="set_vc_notify_channel", description="VC参加/退出通知を送るチャンネルを設定（管理者専用）")
    @app_commands.describe(channel="VC通知を送るテキストチャンネル")
    async def set_vc_notify_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin(interaction):
            return
        set_vc_notify_channel_id(interaction.guild.id, channel.id)
        await interaction.response.send_message(f"VC通知チャンネルを {channel.mention} に設定した。", ephemeral=True)

    @bot.tree.command(name="clear_vc_notify_channel", description="VC通知チャンネル設定を解除（管理者専用）")
    async def clear_vc_notify_ch(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        set_vc_notify_channel_id(interaction.guild.id, None)
        await interaction.response.send_message("VC通知チャンネル設定を解除した。", ephemeral=True)

    # ──────────────────────────────────────────────
    # スティッキーメッセージ
    # ──────────────────────────────────────────────

    @bot.tree.command(name="sticky", description="このチャンネルにスティッキーメッセージを設定（管理者専用）")
    @app_commands.describe(content="スティッキーとして固定するメッセージ内容")
    async def sticky_cmd(interaction: discord.Interaction, content: str):
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルで使用してください。", ephemeral=True)
            return
        set_sticky_message(interaction.guild.id, interaction.channel.id, content)
        await interaction.response.send_message("スティッキーメッセージを設定した。", ephemeral=True)
        await post_sticky(interaction.channel, interaction.guild.id)

    @bot.tree.command(name="unsticky", description="このチャンネルのスティッキーメッセージを解除（管理者専用）")
    async def unsticky_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message("テキストチャンネルで使用してください。", ephemeral=True)
            return
        stickies = get_sticky_messages(interaction.guild.id)
        entry = stickies.get(str(interaction.channel.id))
        if entry and entry.get("message_id"):
            try:
                old_msg = await interaction.channel.fetch_message(entry["message_id"])
                await old_msg.delete()
            except (discord.NotFound, discord.HTTPException):
                pass
        remove_sticky_message(interaction.guild.id, interaction.channel.id)
        await interaction.response.send_message("スティッキーメッセージを解除した。", ephemeral=True)

    @bot.tree.command(name="list_stickies", description="スティッキーメッセージ一覧を表示（管理者専用）")
    async def list_stickies_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        stickies = get_sticky_messages(interaction.guild.id)
        if not stickies:
            await interaction.response.send_message("スティッキーメッセージは設定されていない。", ephemeral=True)
            return
        lines = [f"<#{ch_id}>: {v.get('content', '')[:50]}" for ch_id, v in stickies.items()]
        await interaction.response.send_message("**スティッキー一覧**\n" + "\n".join(lines), ephemeral=True)

    # ──────────────────────────────────────────────
    # リアクションロール
    # ──────────────────────────────────────────────

    @bot.tree.command(name="add_reaction_role", description="リアクションロールを追加（管理者専用）")
    @app_commands.describe(
        message_id="対象メッセージのID",
        emoji="リアクションで使う絵文字",
        role="付与するロール",
    )
    async def add_rr_cmd(
        interaction: discord.Interaction,
        message_id: str,
        emoji: str,
        role: discord.Role,
    ):
        if not await _ensure_admin(interaction):
            return
        try:
            mid = int(message_id)
        except ValueError:
            await interaction.response.send_message("メッセージIDは数値で指定してください。", ephemeral=True)
            return
        add_reaction_role(interaction.guild.id, mid, emoji.strip(), role.id)
        await interaction.response.send_message(
            f"メッセージ `{mid}` に {emoji} → {role.mention} のリアクションロールを追加した。",
            ephemeral=True,
        )

    @bot.tree.command(name="remove_reaction_role", description="リアクションロールを削除（管理者専用）")
    @app_commands.describe(
        message_id="対象メッセージのID",
        emoji="削除するリアクション絵文字",
    )
    async def remove_rr_cmd(
        interaction: discord.Interaction,
        message_id: str,
        emoji: str,
    ):
        if not await _ensure_admin(interaction):
            return
        try:
            mid = int(message_id)
        except ValueError:
            await interaction.response.send_message("メッセージIDは数値で指定してください。", ephemeral=True)
            return
        removed = remove_reaction_role(interaction.guild.id, mid, emoji.strip())
        if removed:
            await interaction.response.send_message(f"リアクションロール ({emoji}) を削除した。", ephemeral=True)
        else:
            await interaction.response.send_message("該当するリアクションロールが見つからなかった。", ephemeral=True)

    @bot.tree.command(name="list_reaction_roles", description="リアクションロール一覧を表示（管理者専用）")
    async def list_rr_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        rr = get_reaction_roles(interaction.guild.id)
        if not rr:
            await interaction.response.send_message("リアクションロールは設定されていない。", ephemeral=True)
            return
        lines = []
        for msg_id, mapping in rr.items():
            for emoji, role_id in mapping.items():
                lines.append(f"メッセージ `{msg_id}` | {emoji} → <@&{role_id}>")
        await interaction.response.send_message("**リアクションロール一覧**\n" + "\n".join(lines[:20]), ephemeral=True)

    # ──────────────────────────────────────────────
    # ニュースフィード
    # ──────────────────────────────────────────────

    @bot.tree.command(name="add_news_feed", description="Google Newsフィードを追加（管理者専用）")
    @app_commands.describe(
        channel="ニュースを投稿するチャンネル",
        query="検索キーワード（例: AI技術）",
        interval="チェック間隔（分、最小5）",
    )
    async def add_news_cmd(
        interaction: discord.Interaction,
        channel: discord.TextChannel,
        query: str,
        interval: int = 60,
    ):
        if not await _ensure_admin(interaction):
            return
        if interval < 5:
            await interaction.response.send_message("間隔は5分以上で指定してください。", ephemeral=True)
            return
        feeds = get_news_feeds(interaction.guild.id)
        if len(feeds) >= 10:
            await interaction.response.send_message("フィードは最大10件まで登録できる。", ephemeral=True)
            return
        feed_id = uuid.uuid4().hex[:8]
        add_news_feed(interaction.guild.id, feed_id, channel.id, query, interval)
        await interaction.response.send_message(
            f"ニュースフィードを追加した。\nID: `{feed_id}` | クエリ: `{query}` | チャンネル: {channel.mention} | 間隔: {interval}分",
            ephemeral=True,
        )

    @bot.tree.command(name="remove_news_feed", description="ニュースフィードを削除（管理者専用）")
    @app_commands.describe(feed_id="削除するフィードID（/list_news_feeds で確認）")
    async def remove_news_cmd(interaction: discord.Interaction, feed_id: str):
        if not await _ensure_admin(interaction):
            return
        removed = remove_news_feed(interaction.guild.id, feed_id.strip())
        if removed:
            await interaction.response.send_message(f"フィード `{feed_id}` を削除した。", ephemeral=True)
        else:
            await interaction.response.send_message("該当するフィードが見つからなかった。", ephemeral=True)

    @bot.tree.command(name="list_news_feeds", description="ニュースフィード一覧を表示（管理者専用）")
    async def list_news_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        feeds = get_news_feeds(interaction.guild.id)
        if not feeds:
            await interaction.response.send_message("ニュースフィードは登録されていない。", ephemeral=True)
            return
        lines = [
            f"`{fid}` | {f.get('query')} | <#{f.get('channel_id')}> | {f.get('interval')}分"
            for fid, f in feeds.items()
        ]
        await interaction.response.send_message("**ニュースフィード一覧**\n" + "\n".join(lines), ephemeral=True)

    # ──────────────────────────────────────────────
    # 地震アラート
    # ──────────────────────────────────────────────

    @bot.tree.command(name="set_earthquake_channel", description="地震アラートを送信するチャンネルを設定（管理者専用）")
    @app_commands.describe(channel="地震情報を送るテキストチャンネル")
    async def set_eq_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin(interaction):
            return
        set_earthquake_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(f"地震アラートチャンネルを {channel.mention} に設定した。", ephemeral=True)

    @bot.tree.command(name="set_earthquake_min_scale", description="地震アラートの最小震度を設定（管理者専用）")
    @app_commands.describe(scale="最小震度（10=1, 20=2, 30=3, 40=4, 45=4強, 50=5弱, 55=5強, 60=6弱, 65=6強, 70=7）")
    async def set_eq_scale(interaction: discord.Interaction, scale: int):
        if not await _ensure_admin(interaction):
            return
        valid = {10, 20, 30, 40, 45, 50, 55, 60, 65, 70}
        if scale not in valid:
            await interaction.response.send_message(
                f"有効な震度値: {', '.join(str(v) for v in sorted(valid))}",
                ephemeral=True,
            )
            return
        set_earthquake_min_scale(interaction.guild.id, scale)
        await interaction.response.send_message(f"地震アラートの最小震度を {scale} に設定した。", ephemeral=True)

    @bot.tree.command(name="earthquake_settings", description="地震アラート設定を表示（管理者専用）")
    async def eq_settings_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        s = get_earthquake_settings(interaction.guild.id)
        ch_id = s.get("channel_id")
        ch_text = f"<#{ch_id}>" if ch_id else "未設定"
        min_scale = s.get("min_scale", 30)
        embed = discord.Embed(title="地震アラート設定", color=discord.Color.orange())
        embed.add_field(name="チャンネル", value=ch_text, inline=True)
        embed.add_field(name="最小震度", value=str(min_scale), inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ──────────────────────────────────────────────
    # サーバー情報 / ユーザー情報
    # ──────────────────────────────────────────────

    @bot.tree.command(name="serverinfo", description="サーバーの情報を表示")
    async def serverinfo_cmd(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使用可能だ。", ephemeral=True)
            return
        g = interaction.guild
        created = g.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M")
        owner = g.owner.mention if g.owner else "不明"

        roles_count = len(g.roles) - 1  # @everyone 除く
        text_ch = sum(1 for c in g.channels if isinstance(c, discord.TextChannel))
        voice_ch = sum(1 for c in g.channels if isinstance(c, discord.VoiceChannel))

        embed = discord.Embed(title=g.name, color=discord.Color.blurple())
        if g.icon:
            embed.set_thumbnail(url=g.icon.url)
        embed.add_field(name="サーバーID", value=str(g.id), inline=True)
        embed.add_field(name="オーナー", value=owner, inline=True)
        embed.add_field(name="メンバー数", value=str(g.member_count), inline=True)
        embed.add_field(name="テキストチャンネル", value=str(text_ch), inline=True)
        embed.add_field(name="ボイスチャンネル", value=str(voice_ch), inline=True)
        embed.add_field(name="ロール数", value=str(roles_count), inline=True)
        embed.add_field(name="作成日", value=created, inline=True)
        embed.add_field(name="ブーストレベル", value=str(g.premium_tier), inline=True)
        embed.add_field(name="ブースト数", value=str(g.premium_subscription_count or 0), inline=True)
        await interaction.response.send_message(embed=embed)

    @bot.tree.command(name="userinfo", description="ユーザーの情報を表示")
    @app_commands.describe(member="情報を表示するメンバー（省略時は自分）")
    async def userinfo_cmd(
        interaction: discord.Interaction,
        member: Optional[discord.Member] = None,
    ):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使用可能だ。", ephemeral=True)
            return
        target = member or interaction.user
        if not isinstance(target, discord.Member):
            await interaction.response.send_message("メンバー情報を取得できなかった。", ephemeral=True)
            return

        joined = target.joined_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if target.joined_at else "不明"
        created = target.created_at.astimezone(_JST).strftime("%Y/%m/%d %H:%M") if target.created_at else "不明"
        roles = [r.mention for r in target.roles if not r.is_default()]

        embed = discord.Embed(title=str(target), color=target.color)
        embed.set_thumbnail(url=target.display_avatar.url)
        embed.add_field(name="ユーザーID", value=str(target.id), inline=True)
        embed.add_field(name="ニックネーム", value=target.nick or "(なし)", inline=True)
        embed.add_field(name="アカウント作成日", value=created, inline=True)
        embed.add_field(name="サーバー参加日", value=joined, inline=True)
        embed.add_field(name="BOT", value="はい" if target.bot else "いいえ", inline=True)
        embed.add_field(
            name=f"ロール（{len(roles)}個）",
            value=" ".join(roles[:15]) or "なし",
            inline=False,
        )
        await interaction.response.send_message(embed=embed)
