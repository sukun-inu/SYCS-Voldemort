from typing import cast

import discord
from commands.interaction_utils import send_ephemeral


async def ensure_admin(interaction: discord.Interaction) -> bool:
    """管理者でなければ理由付きで断り、コマンド本体はここで打ち切る。

    defer() より前に呼ぶ前提。defer 済みだと ephemeral な初回応答が使えず、
    断り方が変わってしまう（ephemeral な followup にする等の分岐が要る）。
    """
    if interaction.guild is None:
        await send_ephemeral(interaction, "ギルド内でのみ使えるぞ。")
        return False
    # guild が非 None ということはギルド内での実行なので、interaction.user は
    # 実行時には必ず Member（guild_permissions を持つ）になる。
    member = cast(discord.Member, interaction.user)
    if not member.guild_permissions.administrator:
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
