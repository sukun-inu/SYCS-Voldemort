import logging

import discord
from discord import app_commands
from discord.ext.commands import Bot

logger = logging.getLogger(__name__)


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
    missing_permissions_message: str = "❌ このコマンドを実行する権限がありません。",
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
            await send_ephemeral(interaction, "❌ 実行条件を満たしていません。")
            return

        await send_ephemeral(interaction, f"❌ エラー: {error}")


def install_global_app_command_error_handler(bot: Bot) -> None:
    @bot.tree.error
    async def _on_tree_error(
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        if isinstance(error, app_commands.CommandNotFound):
            return

        if isinstance(error, app_commands.MissingPermissions):
            await send_ephemeral(interaction, "❌ このコマンドを実行する権限がありません。")
            return

        if isinstance(error, app_commands.CheckFailure):
            await send_ephemeral(interaction, "❌ 実行条件を満たしていません。")
            return

        if isinstance(error, app_commands.CommandInvokeError):
            logger.exception("スラッシュコマンド実行エラー: %s", error.original)
            await send_ephemeral(interaction, "❌ コマンド実行中にエラーが発生しました。")
            return

        logger.exception("スラッシュコマンドエラー: %s", error)
        await send_ephemeral(interaction, f"❌ エラー: {error}")
