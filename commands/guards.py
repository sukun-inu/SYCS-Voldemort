import discord
from commands.interaction_utils import send_ephemeral


async def ensure_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使用可能だ。")
        return False
    if not interaction.user.guild_permissions.administrator:
        await send_ephemeral(interaction, "このコマンドは管理者のみが実行できる。")
        return False
    return True
