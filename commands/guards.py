import discord
from commands.interaction_utils import send_ephemeral


async def ensure_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return False
    if not interaction.user.guild_permissions.administrator:
        await send_ephemeral(interaction, "管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。")
        return False
    return True
