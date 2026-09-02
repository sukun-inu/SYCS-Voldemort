"""信頼済みユーザー / バイパスロールの複数選択ビュー。

register_logging_commands() 分割前の commands/logging_commands.py から
そのまま切り出した（経緯は commands/settings/__init__.py を参照）。
trusted.py と bypass.py の両方から使うため、ここに置いてある。
"""

from typing import Any, Callable, cast

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
    """edit=True で edit_message、False で send_message と応答方法を切り替える。

    現状の呼び出し元は EntityPickerView._on_confirm の edit=True 経路だけで、
    edit=False（新規メッセージ送信）は今のコードベースでは実際には通らない
    （呼び出し元が1箇所しかない）。消してよいかは呼び出し側を増やす予定の
    有無を確認してから判断すること。
    """
    ids = [e.id for e in entities]
    # EntityPickerView はコマンド側の ensure_admin 通過後にしか生成されないので、
    # ここに来る interaction.guild は必ず非 None。
    guild = cast(discord.Guild, interaction.guild)
    updated = update_fn(guild.id, ids)
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
        select_item: discord.ui.Select[Any] | discord.ui.UserSelect[Any] | discord.ui.RoleSelect[Any],
        update_fn: Callable,
        action_text: str,
        count_label: str,
    ):
        """update_fn/action_text/count_label を保持しておくのは、実際の更新
        (update_entity_list呼び出し)を選択完了(_on_confirm)まで遅らせるため。
        select_item は trusted.py/bypass.py がそれぞれ UserSelect/RoleSelect を
        渡す（このクラス自体はどちらの型か知らない）。
        """
        super().__init__(timeout=120)
        self.author_id = author_id
        self.update_fn = update_fn
        self.action_text = action_text
        self.count_label = count_label
        self.picked: list = []

        self.select_item = select_item
        # Item.callback はメソッドだが、View の定石どおりインスタンスへ差し替える。
        self.select_item.callback = self._on_select  # type: ignore[method-assign]
        self.add_item(self.select_item)

        self.confirm_button: discord.ui.Button = discord.ui.Button(
            label="確定", style=discord.ButtonStyle.primary, disabled=True
        )
        self.confirm_button.callback = self._on_confirm  # type: ignore[method-assign]  # 同上
        self.add_item(self.confirm_button)

    async def _check_author(self, interaction: discord.Interaction) -> bool:
        """ephemeral な応答で通常は本人にしか見えないはずだが、念のための防御
        （quake._NotifyTypeView._check_author と同じ考え方）。
        """
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("貴様にその操作の権限はない。", ephemeral=True)
            return False
        return True

    async def _on_select(self, interaction: discord.Interaction) -> None:
        """選択しただけではまだ更新しない。self.picked に貯め、確定は _on_confirm 側。"""
        if not await self._check_author(interaction):
            return
        self.picked = list(self.select_item.values)
        self.confirm_button.disabled = not self.picked
        self.confirm_button.label = f"確定（{len(self.picked)}件）" if self.picked else "確定"
        await interaction.response.edit_message(view=self)

    async def _on_confirm(self, interaction: discord.Interaction) -> None:
        """confirm_button は未選択時 disabled のはずだが、念のため self.picked
        の空チェックを二重に持つ（disabled は表示上のヒントでしかなく、
        古いクライアント状態から押せてしまう可能性を排除できないため）。
        """
        if not await self._check_author(interaction):
            return
        if not self.picked:
            await interaction.response.send_message("何も選ばれておらぬ。", ephemeral=True)
            return
        await update_entity_list(
            interaction, self.picked, self.update_fn, self.action_text, self.count_label, edit=True
        )
        self.stop()
