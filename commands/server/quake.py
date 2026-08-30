"""地震アラートの設定コマンドと、通知タイプ切り替え用の View。

register_server_commands() 分割前の commands/server_commands.py から
そのまま切り出した（経緯は commands/server/__init__.py を参照）。
"""

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin
from commands.interaction_utils import admin_site_view
from config import SCALE_LABELS
from services.settings_store import (
    awrite,
    get_earthquake_notify_types,
    get_earthquake_settings,
    set_earthquake_channel,
    set_earthquake_min_scale,
    set_earthquake_notify_types,
)

_NOTIFY_TYPE_LABELS: dict[str, str] = {
    "eew_forecast": "緊急地震速報（予報）",
    "eew_warning": "緊急地震速報（警報）",
    "tsunami": "津波情報",
    "quake_info": "地震情報",
    "bot_news": "ボットに関するお知らせ",
}


def _build_notify_type_embed(types: dict[str, bool]) -> discord.Embed:
    embed = discord.Embed(
        title="地震通知タイプ設定",
        description="ボタンをクリックしてオン/オフを切り替え、「保存」で確定します。",
        color=discord.Color.orange(),
    )
    for key, label in _NOTIFY_TYPE_LABELS.items():
        enabled = types.get(key, True)
        embed.add_field(name=label, value="✅ 有効" if enabled else "❌ 無効", inline=True)
    return embed


class _ToggleButton(discord.ui.Button):
    def __init__(self, key: str, label: str, enabled: bool, row: int):
        super().__init__(
            label=f"{'✅' if enabled else '❌'} {label}",
            style=discord.ButtonStyle.success if enabled else discord.ButtonStyle.secondary,
            custom_id=f"eq_toggle_{key}",
            row=row,
        )
        self.key = key

    async def callback(self, interaction: discord.Interaction) -> None:
        await self.view.handle_toggle(interaction, self.key)  # type: ignore[attr-defined]


class _SaveButton(discord.ui.Button):
    def __init__(self, row: int):
        super().__init__(
            label="保存して閉じる",
            style=discord.ButtonStyle.primary,
            custom_id="eq_notify_save_btn",
            row=row,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        await self.view.handle_save(interaction)  # type: ignore[attr-defined]


class _NotifyTypeView(discord.ui.View):
    def __init__(self, guild_id: int, author_id: int, types: dict[str, bool]):
        super().__init__(timeout=180)
        self.guild_id = guild_id
        self.author_id = author_id
        self.types = dict(types)
        self._rebuild()

    def _rebuild(self) -> None:
        self.clear_items()
        keys = list(_NOTIFY_TYPE_LABELS.keys())
        for i, key in enumerate(keys):
            label = _NOTIFY_TYPE_LABELS[key]
            enabled = self.types.get(key, True)
            self.add_item(_ToggleButton(key, label, enabled, row=i // 2))
        self.add_item(_SaveButton(row=len(keys) // 2 + 1))

    async def _check_author(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("貴様にその操作の権限はない。", ephemeral=True)
            return False
        return True

    async def handle_toggle(self, interaction: discord.Interaction, key: str) -> None:
        if not await self._check_author(interaction):
            return
        self.types[key] = not self.types.get(key, True)
        self._rebuild()
        await interaction.response.edit_message(embed=_build_notify_type_embed(self.types), view=self)

    async def handle_save(self, interaction: discord.Interaction) -> None:
        if not await self._check_author(interaction):
            return
        await awrite(set_earthquake_notify_types, self.guild_id, self.types)
        self.clear_items()
        self.stop()
        await interaction.response.edit_message(
            content="✅ 余の意志を刻んだ。",
            embed=_build_notify_type_embed(self.types),
            view=self,
        )


def register(bot: Bot) -> None:
    quake_group = app_commands.Group(name="quake", description="地震アラートの設定", guild_only=True)

    @quake_group.command(name="channel", description="【管理者】地震アラートチャンネルを設定します")
    @app_commands.describe(channel="地震情報を送るテキストチャンネル")
    async def set_eq_ch(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin(interaction):
            return
        await awrite(set_earthquake_channel, interaction.guild.id, channel.id)
        await interaction.response.send_message(f"{channel.mention} を地震アラートチャンネルと定めた。", ephemeral=True)

    @quake_group.command(name="min_scale", description="【管理者】地震通知の最小震度を設定します")
    @app_commands.describe(scale="通知する最小震度")
    @app_commands.choices(
        scale=[app_commands.Choice(name=f"震度 {label} 以上", value=code) for code, label in SCALE_LABELS.items()]
    )
    async def set_eq_scale(interaction: discord.Interaction, scale: int):
        if not await _ensure_admin(interaction):
            return
        await awrite(set_earthquake_min_scale, interaction.guild.id, scale)
        await interaction.response.send_message(
            f"地震アラートの最小震度を 震度{SCALE_LABELS.get(scale, scale)} と定めた。",
            ephemeral=True,
        )

    @quake_group.command(name="status", description="地震アラート設定を表示します")
    async def eq_settings_cmd(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("ギルド内でのみ使えるぞ。", ephemeral=True)
            return
        s = get_earthquake_settings(interaction.guild.id)
        types = get_earthquake_notify_types(interaction.guild.id)
        ch_id = s.get("channel_id")
        ch_text = f"<#{ch_id}>" if ch_id else "未設定"
        min_scale = s.get("min_scale", 30)
        embed = discord.Embed(title="地震アラート設定", color=discord.Color.orange())
        embed.add_field(name="チャンネル", value=ch_text, inline=True)
        embed.add_field(name="最小震度", value=str(min_scale), inline=True)
        embed.add_field(name="​", value="​", inline=False)
        for key, label in _NOTIFY_TYPE_LABELS.items():
            embed.add_field(name=label, value="✅ 有効" if types.get(key, True) else "❌ 無効", inline=True)
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    @quake_group.command(name="type", description="【管理者】地震通知タイプのオン/オフを設定します")
    async def eq_notify_type_cmd(interaction: discord.Interaction):
        if not await _ensure_admin(interaction):
            return
        types = get_earthquake_notify_types(interaction.guild.id)
        view = _NotifyTypeView(interaction.guild.id, interaction.user.id, types)
        await interaction.response.send_message(embed=_build_notify_type_embed(types), view=view, ephemeral=True)

    bot.tree.add_command(quake_group)
