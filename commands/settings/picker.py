"""信頼済みユーザー / バイパスロールの複数選択ビュー。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
trusted.py と bypass.py の両方から使うため、ここに置いてある。
"""

from typing import Callable

import discord


async def update_entity_list(
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


class EntityPickerView(discord.ui.View):
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

        self.confirm_button = discord.ui.Button(label="確定", style=discord.ButtonStyle.primary, disabled=True)
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
        await update_entity_list(
            interaction, self.picked, self.update_fn, self.action_text, self.count_label, edit=True
        )
        self.stop()
