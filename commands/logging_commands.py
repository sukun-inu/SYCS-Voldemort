from typing import Callable, List

import discord
from discord import app_commands
from discord.ext.commands import Bot

from commands.guards import ensure_admin as _ensure_admin_in_guild
from commands.interaction_utils import admin_site_view
from services.logging_service import get_log_settings, set_log_channel, set_log_level
from services.settings_store import (
    add_bypass_roles,
    add_trusted_users,
    get_bypass_role_ids,
    get_response_channel_id,
    get_trusted_user_ids,
    remove_bypass_roles,
    remove_trusted_users,
    set_response_channel_id,
)


async def _update_entity_list(
    interaction: discord.Interaction,
    entities: list,
    update_fn: Callable,
    action_text: str,
    count_label: str,
    *,
    edit: bool = False,
) -> None:
    ids = [e.id for e in entities]
    updated = update_fn(interaction.guild.id, ids)
    mentions = ", ".join(e.mention for e in entities)
    content = f"{action_text}: {mentions}\n（{count_label}: {len(updated)}）"
    if edit:
        await interaction.response.edit_message(content=content, view=None)
    else:
        await interaction.response.send_message(content, ephemeral=True)


class _EntityPickerView(discord.ui.View):
    """UserSelect/RoleSelectで複数選択させてから確定するビュー。

    Discordのスラッシュコマンドは可変長引数（member1, member2, ...のような固定枠なしで
    好きな人数を選ぶ）を取れないため、コマンド実行後にこのビューを表示して選ばせる。
    """

    def __init__(
        self,
        author_id: int,
        select_item: discord.ui.Select,
        update_fn: Callable,
        action_text: str,
        count_label: str,
    ):
        super().__init__(timeout=120)
        self.author_id = author_id
        self.update_fn = update_fn
        self.action_text = action_text
        self.count_label = count_label
        self.picked: list = []

        self.select_item = select_item
        self.select_item.callback = self._on_select
        self.add_item(self.select_item)

        self.confirm_button = discord.ui.Button(
            label="確定", style=discord.ButtonStyle.primary, disabled=True
        )
        self.confirm_button.callback = self._on_confirm
        self.add_item(self.confirm_button)

    async def _check_author(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("貴様にその操作の権限はない。", ephemeral=True)
            return False
        return True

    async def _on_select(self, interaction: discord.Interaction) -> None:
        if not await self._check_author(interaction):
            return
        self.picked = list(self.select_item.values)
        self.confirm_button.disabled = not self.picked
        self.confirm_button.label = f"確定（{len(self.picked)}件）" if self.picked else "確定"
        await interaction.response.edit_message(view=self)

    async def _on_confirm(self, interaction: discord.Interaction) -> None:
        if not await self._check_author(interaction):
            return
        if not self.picked:
            await interaction.response.send_message("何も選ばれておらぬ。", ephemeral=True)
            return
        await _update_entity_list(
            interaction, self.picked, self.update_fn, self.action_text, self.count_label, edit=True
        )
        self.stop()


def register_logging_commands(bot: Bot) -> None:
    # 平坦な名前を並べると /（スラッシュ）の一覧が長くなり、関連するものが
    # 隣り合う保証も無い。同じ話題はグループにまとめる。
    log_group = app_commands.Group(
        name="log", description="ログの送信先とレベル", guild_only=True)
    chat_group = app_commands.Group(
        name="chat", description="AI応答チャンネルの設定", guild_only=True)
    trusted_group = app_commands.Group(
        name="trusted", description="信頼済みユーザー（検出の対象外）", guild_only=True)
    bypass_group = app_commands.Group(
        name="bypass", description="バイパスロール（検出の対象外）", guild_only=True)
    bot_group = app_commands.Group(
        name="bot", description="Bot の設定とヘルプ", guild_only=True)

    @log_group.command(name="channel", description="【管理者】ログ送信チャンネルを設定します")
    @app_commands.describe(channel="ログを投稿するテキストチャンネル")
    async def set_log_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_log_channel(interaction.guild.id, channel.id)
        settings = get_log_settings(interaction.guild.id)
        await interaction.response.send_message(
            f"{channel.mention} を余のログチャンネルと定めた。ログレベル: {settings.get('level', 'INFO')}",
            ephemeral=True,
        )

    @log_group.command(name="level", description="【管理者】ログレベルを設定します")
    @app_commands.describe(level="記録するログの詳細さ")
    @app_commands.choices(level=[
        app_commands.Choice(name="NONE（ログを記録しない）", value="NONE"),
        app_commands.Choice(name="ERROR（エラーのみ）", value="ERROR"),
        app_commands.Choice(name="INFO（通常運用向け・推奨）", value="INFO"),
        app_commands.Choice(name="DEBUG（詳細・調査向け）", value="DEBUG"),
    ])
    async def set_log_level_cmd(interaction: discord.Interaction, level: str):
        if not await _ensure_admin_in_guild(interaction):
            return

        try:
            set_log_level(interaction.guild.id, level)
        except ValueError as e:
            await interaction.response.send_message(str(e), ephemeral=True)
            return

        settings = get_log_settings(interaction.guild.id)
        channel_id = settings.get("channel_id")
        ch_text = f"<#{channel_id}>" if channel_id else "未設定"
        await interaction.response.send_message(
            f"ログレベルを {settings.get('level')} に定めた。ログチャンネル: {ch_text}",
            ephemeral=True,
        )

    @chat_group.command(name="set", description="【管理者】AI応答チャンネルを設定します")
    @app_commands.describe(channel="ChatGPTが応答するテキストチャンネル")
    async def set_response_channel_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"{channel.mention} を余への語りかけチャンネルと定めた。",
            ephemeral=True,
        )

    @chat_group.command(name="clear", description="【管理者】AI応答チャンネル設定を解除します")
    async def clear_response_channel_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        set_response_channel_id(interaction.guild.id, None)
        await interaction.response.send_message(
            "余への語りかけチャンネルを解除した。再設定されるまで余は応答しない。",
            ephemeral=True,
        )

    @trusted_group.command(name="add", description="【管理者】信頼済みユーザーを追加します（複数選択可）")
    async def add_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.UserSelect(
            placeholder="追加するユーザーを選択（複数選択可・最大25人）", min_values=1, max_values=25
        )
        view = _EntityPickerView(
            interaction.user.id, select, add_trusted_users, "余の信頼を与えた", "信頼済みユーザー数"
        )
        await interaction.response.send_message(
            "信頼済みに追加するユーザーを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @trusted_group.command(name="remove", description="【管理者】信頼済みユーザーを削除します（複数選択可）")
    async def remove_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.UserSelect(
            placeholder="削除するユーザーを選択（複数選択可・最大25人）", min_values=1, max_values=25
        )
        view = _EntityPickerView(
            interaction.user.id, select, remove_trusted_users, "余の信頼を取り消した", "信頼済みユーザー数"
        )
        await interaction.response.send_message(
            "信頼済みから削除するユーザーを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @trusted_group.command(name="list", description="【管理者】信頼済みユーザー一覧を表示します")
    async def list_trusted_members_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_trusted_user_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("まだ誰も余の信頼を勝ち取っていない。", ephemeral=True)
            return

        members: List[str] = []
        for uid in ids:
            m = interaction.guild.get_member(uid)
            members.append(m.mention if m else f"<@{uid}>")

        await interaction.response.send_message(
            "余が認めた者の一覧だ:\n" + "\n".join(members),
            ephemeral=True,
        )

    @bypass_group.command(name="add", description="【管理者】バイパスロールを追加します（複数選択可）")
    async def add_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.RoleSelect(
            placeholder="追加するロールを選択（複数選択可・最大25個）", min_values=1, max_values=25
        )
        view = _EntityPickerView(
            interaction.user.id, select, add_bypass_roles, "バイパスロールに加えた", "バイパスロール数"
        )
        await interaction.response.send_message(
            "バイパスロールに追加するロールを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @bypass_group.command(name="remove", description="【管理者】バイパスロールを削除します（複数選択可）")
    async def remove_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return
        select = discord.ui.RoleSelect(
            placeholder="削除するロールを選択（複数選択可・最大25個）", min_values=1, max_values=25
        )
        view = _EntityPickerView(
            interaction.user.id, select, remove_bypass_roles, "バイパスロールから除いた", "バイパスロール数"
        )
        await interaction.response.send_message(
            "バイパスロールから削除するロールを選んでから「確定」を押すがよい。", view=view, ephemeral=True
        )

    @bypass_group.command(name="list", description="【管理者】バイパスロール一覧を表示します")
    async def list_bypass_roles_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        ids = get_bypass_role_ids(interaction.guild.id)
        if not ids:
            await interaction.response.send_message("バイパスロールはまだ設定されていない。", ephemeral=True)
            return

        role_mentions: List[str] = []
        for rid in ids:
            r = interaction.guild.get_role(rid)
            role_mentions.append(r.mention if r else f"<@&{rid}>")

        await interaction.response.send_message(
            "バイパスロール一覧:\n" + "\n".join(role_mentions),
            ephemeral=True,
        )

    @bot_group.command(name="settings", description="【管理者】Bot設定を一覧表示します")
    async def settings_cmd(interaction: discord.Interaction):
        if not await _ensure_admin_in_guild(interaction):
            return

        guild_id = interaction.guild.id

        log_settings = get_log_settings(guild_id)
        log_ch_id = log_settings.get("channel_id")
        log_level = log_settings.get("level", "INFO")
        log_ch_text = f"<#{log_ch_id}>" if log_ch_id else "未設定"

        resp_ch_id = get_response_channel_id(guild_id)
        resp_ch_text = f"<#{resp_ch_id}>" if resp_ch_id else "未設定（無効）"

        trusted_ids = get_trusted_user_ids(guild_id)
        if not trusted_ids:
            trusted_text = "なし"
        else:
            mentions = [f"<@{uid}>" for uid in trusted_ids[:15]]
            trusted_text = ", ".join(mentions)
            if len(trusted_ids) > 15:
                trusted_text += f" …他{len(trusted_ids) - 15}名"

        bypass_ids = get_bypass_role_ids(guild_id)
        if not bypass_ids:
            bypass_text = "なし"
        else:
            mentions = [f"<@&{rid}>" for rid in bypass_ids[:15]]
            bypass_text = ", ".join(mentions)
            if len(bypass_ids) > 15:
                bypass_text += f" …他{len(bypass_ids) - 15}個"

        embed = discord.Embed(
            title="余の現在の設定だ",
            description=f"サーバーID: `{guild_id}`",
            color=discord.Color.blurple(),
        )
        embed.add_field(name="ログチャンネル", value=log_ch_text, inline=True)
        embed.add_field(name="ログレベル", value=log_level, inline=True)
        embed.add_field(name="AI応答チャンネル", value=resp_ch_text, inline=True)
        embed.add_field(
            name=f"信頼済みユーザー（{len(trusted_ids)}名）",
            value=trusted_text,
            inline=False,
        )
        embed.add_field(
            name=f"バイパスロール（{len(bypass_ids)}個）",
            value=bypass_text,
            inline=False,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True, view=admin_site_view())

    @bot_group.command(name="help", description="利用可能なスラッシュコマンド一覧を表示します")
    async def help_cmd(interaction: discord.Interaction):
        # walk_commands() はグループ自身も返し、cmd.name は葉の名前しか持たない。
        # 素直に name で集めると /log channel と /quake channel が衝突して
        # 片方が消える。実際に打てる形（qualified_name）で並べる。
        all_commands: dict[str, str] = {}
        for cmd in bot.tree.walk_commands():
            if isinstance(cmd, app_commands.Group):
                continue
            all_commands[cmd.qualified_name] = cmd.description or "(説明なし)"

        items = sorted(all_commands.items(), key=lambda x: x[0])
        lines = [f"`/{name}` — {desc}" for name, desc in items]

        chunk_size = 20
        embeds: list[discord.Embed] = []
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i : i + chunk_size]
            is_first = i == 0
            embed = discord.Embed(
                title="余が授けたコマンドの一覧" if is_first else None,
                description=(
                    "余の力を借りられるコマンドだ。使いこなすがよい。\n\n" + "\n".join(chunk)
                    if is_first
                    else "\n".join(chunk)
                ),
                color=discord.Color.blurple(),
            )
            embeds.append(embed)

        await interaction.response.send_message(
            embeds=embeds, ephemeral=True, view=admin_site_view()
        )

    for group in (log_group, chat_group, trusted_group, bypass_group, bot_group):
        bot.tree.add_command(group)
