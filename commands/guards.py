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


def is_admin(interaction: discord.Interaction) -> bool:
    """管理者かどうかを、返信せずに判定する。

    ensure_admin() は拒否メッセージを送ってしまうため、「権限があれば追加の
    処理もする」といった分岐の判定には使えない。そちら向け。
    """
    if interaction.guild is None:
        return False
    permissions = getattr(interaction.user, "guild_permissions", None)
    return bool(permissions and permissions.administrator)
