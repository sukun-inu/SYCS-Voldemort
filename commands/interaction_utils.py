import logging

import discord
from discord import app_commands
from discord.ext.commands import Bot

from config import ADMIN_SITE_URL, METALS_SITE_URL

logger = logging.getLogger(__name__)


def metals_site_view() -> discord.ui.View:
    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.link,
        label="📊 貴金属トラッカーを開く",
        url=METALS_SITE_URL,
    ))
    return view


def admin_site_view() -> discord.ui.View:
    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.link,
        label="⚙️ Web管理画面を開く",
        url=ADMIN_SITE_URL,
    ))
    return view


async def send_interaction(
    interaction: discord.Interaction,
    *,
    content: str | None = None,
    embed: discord.Embed | None = None,
    ephemeral: bool = True,
) -> None:
    kwargs: dict[str, object] = {"ephemeral": ephemeral}
    if content is not None:
        kwargs["content"] = content
    if embed is not None:
        kwargs["embed"] = embed

    if interaction.response.is_done():
        await interaction.followup.send(**kwargs)
    else:
        await interaction.response.send_message(**kwargs)


async def send_ephemeral(interaction: discord.Interaction, message: str) -> None:
    await send_interaction(interaction, content=message, ephemeral=True)


def bind_permission_error_handler(
    command: app_commands.Command,
    *,
    missing_permissions_message: str = "❌ 余のコマンドを使う権限が貴様にはない。",
) -> None:
    @command.error
    async def _on_error(
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        if isinstance(error, app_commands.MissingPermissions):
            await send_ephemeral(interaction, missing_permissions_message)
            return

        if isinstance(error, app_commands.CheckFailure):
            await send_ephemeral(interaction, "❌ 条件を満たしておらぬ。出直してこい。")
            return

        logger.exception("コマンドエラー: %s", error)
        await send_ephemeral(interaction, "❌ 何かが邪魔をしたようだ。しばし待って試せ。")


def install_global_app_command_error_handler(bot: Bot) -> None:
    @bot.tree.error
    async def _on_tree_error(
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        if isinstance(error, app_commands.CommandNotFound):
            return

        if isinstance(error, app_commands.MissingPermissions):
            await send_ephemeral(interaction, "❌ 余のコマンドを使う権限が貴様にはない。")
            return

        if isinstance(error, app_commands.CheckFailure):
            await send_ephemeral(interaction, "❌ 条件を満たしておらぬ。出直してこい。")
            return

        if isinstance(error, app_commands.CommandInvokeError):
            logger.exception("スラッシュコマンド実行エラー: %s", error.original)
            await send_ephemeral(interaction, "❌ 余の力をもってしても処理できなかった。しばし待って試せ。")
            return

        logger.exception("スラッシュコマンドエラー: %s", error)
        await send_ephemeral(interaction, "❌ 予期せぬ障害が生じた。しばし待て。")
