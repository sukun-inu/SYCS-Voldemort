"""ニュースフィード（Google News）の登録・削除・一覧コマンド。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

import uuid
from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message
from services.settings_store import add_news_feed, awrite, get_news_feeds, remove_news_feed


MAX_FEEDS = 10
MIN_INTERVAL_MINUTES = 5


async def _apply_add(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    query: str,
    interval: int,
) -> None:
    """/news add の中身。

    フィード数の上限10件は、/news list をメッセージ本文の上限(2000文字)
    に収めるための設計上の制約であって、任意の運用ルールではない。ここを
    緩めると一覧側の表示が壊れうる（query の100文字制限も同じ理由）。
    """
    if not await _ensure_admin(interaction):
        return
    if interval < MIN_INTERVAL_MINUTES:
        await interaction.response.send_message(f"間隔は{MIN_INTERVAL_MINUTES}分以上で指定せよ。", ephemeral=True)
        return
    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild = cast(discord.Guild, interaction.guild)
    if len(get_news_feeds(guild.id)) >= MAX_FEEDS:
        await interaction.response.send_message(
            f"フィードは最大{MAX_FEEDS}件までだ。余の力にも限りがある。", ephemeral=True
        )
        return

    feed_id = uuid.uuid4().hex[:8]
    await awrite(add_news_feed, guild.id, feed_id, channel.id, query, interval)
    await interaction.response.send_message(
        f"ニュースフィードを加えた。\nID: `{feed_id}` | クエリ: `{query}` | "
        f"チャンネル: {channel.mention} | 間隔: {interval}分",
        ephemeral=True,
    )


async def _apply_remove(interaction: discord.Interaction, feed_id: str) -> None:
    """/news remove の中身。

    feed_id は自由入力可能（autocomplete の選択を強制できない）なので、
    コピペ由来の前後空白を strip() してから照合する。
    """
    if not await _ensure_admin(interaction):
        return
    # ensure_admin は guild が None なら False を返して打ち切るので、ここは必ず非 None。
    guild = cast(discord.Guild, interaction.guild)
    removed = await awrite(remove_news_feed, guild.id, feed_id.strip())
    if removed:
        await interaction.response.send_message(f"フィード `{feed_id}` を抹消した。", ephemeral=True)
    else:
        await interaction.response.send_message("そのようなフィードは見つからなかった。", ephemeral=True)


async def _feed_id_choices(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
    """feed_id の候補。

    label[:100] と choices[:25] はどちらもアプリの都合ではなく、Discord の
    Autocomplete Choice 側の固定上限（名前100文字・候補25件）に合わせている。
    """
    if interaction.guild is None:
        return []
    feeds = get_news_feeds(interaction.guild.id)
    current_lower = current.lower()
    choices = []
    for fid, f in feeds.items():
        query = str(f.get("query", ""))
        if current_lower and current_lower not in fid.lower() and current_lower not in query.lower():
            continue
        ch = interaction.guild.get_channel(f.get("channel_id"))
        ch_text = f"#{ch.name}" if ch else "不明なチャンネル"
        label = f"{query} ({ch_text}) [{fid}]"
        choices.append(app_commands.Choice(name=label[:100], value=fid))
    return choices[:25]


async def _apply_list(interaction: discord.Interaction) -> None:
    """/news list の中身。add/remove と違い ensure_admin を呼んでいない。

    閲覧は誰でもでき、変更だけ管理者に絞る設計。
    """
    if interaction.guild is None:
        await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
        return
    feeds = get_news_feeds(interaction.guild.id)
    if not feeds:
        await interaction.response.send_message("ニュースフィードは登録されておらぬ。", ephemeral=True)
        return
    # フィード数自体は10件までに制限されているため cap_list_for_message の
    # 件数上限（既定の並びなら常に10件以内）はここでは働かない。クエリ長は
    # /news add 側で100文字に制限したが、それより前に登録された既存データは
    # 制限を経ていないため、表示側でも1件あたりの長さを切り詰めておく
    # （スティッキー一覧の content[:50] と同じ考え方）。
    lines = [
        f"`{fid}` | {(f.get('query') or '')[:60]} | <#{f.get('channel_id')}> | {f.get('interval')}分"
        for fid, f in feeds.items()
    ]
    header = "**ニュースフィード一覧**\n"
    body = cap_list_for_message(lines, budget=MESSAGE_BUDGET, header=header, limit=MAX_FEEDS, omitted_unit="件")
    await interaction.response.send_message(header + body, ephemeral=True)


def register(bot: Bot) -> None:
    """/news add・remove・list（Google Newsフィード配信の設定）を登録する。"""
    news_group = app_commands.Group(name="news", description="ニュースフィードの配信設定", guild_only=True)

    @news_group.command(name="add", description="【管理者】Google Newsフィードを追加します")
    @app_commands.describe(
        channel="ニュースを投稿するチャンネル",
        query="検索キーワード（例: AI技術、最大100文字）",
        interval="チェック間隔（分、最小5）",
    )
    async def add_news_cmd(
        interaction: discord.Interaction,
        channel: discord.TextChannel,
        # query に長さ上限が無いと、/news list の一覧表示だけで
        # メッセージ上限(2000文字)を超えうる（フィード数は10件までに絞っても、
        # 1件のクエリが数千文字ならそれだけで超える）。
        query: app_commands.Range[str, 1, 100],
        interval: int = 60,
    ):
        """フィードを足す（本体は _apply_add）。"""
        await _apply_add(interaction, channel, query, interval)

    @news_group.command(name="remove", description="【管理者】ニュースフィードを削除します")
    @app_commands.describe(feed_id="削除するフィード（候補から選択できる）")
    async def remove_news_cmd(interaction: discord.Interaction, feed_id: str):
        """フィードを消す（本体は _apply_remove）。"""
        await _apply_remove(interaction, feed_id)

    @remove_news_cmd.autocomplete("feed_id")
    async def _remove_news_feed_id_autocomplete(
        interaction: discord.Interaction, current: str
    ) -> list[app_commands.Choice[str]]:
        """feed_id の候補（本体は _feed_id_choices）。"""
        return await _feed_id_choices(interaction, current)

    @news_group.command(name="list", description="ニュースフィード一覧を表示します")
    async def list_news_cmd(interaction: discord.Interaction):
        """フィードの一覧を出す（本体は _apply_list）。"""
        await _apply_list(interaction)

    bot.tree.add_command(news_group)
