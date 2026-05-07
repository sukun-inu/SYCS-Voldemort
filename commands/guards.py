import discord


async def ensure_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await interaction.response.send_message("ギルド内でのみ使用可能だ。", ephemeral=True)
        return False
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("このコマンドは管理者のみが実行できる。", ephemeral=True)
        return False
    return True
