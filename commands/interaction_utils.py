import logging
from collections.abc import Sequence

import discord
from discord import app_commands
from discord.ext.commands import Bot

from config import ADMIN_SITE_URL, METALS_SITE_URL

logger = logging.getLogger(__name__)


# Discord側の各種文字数上限。呼び出し側が「ここは field だから1024」のように
# その場の数字を書くと、書き間違いや context 違い（メッセージ用の値を embed
# field に流用する等）に気づけない。名前を付けてここに集約する。
MESSAGE_BUDGET = 2000  # メッセージ本文
EMBED_DESCRIPTION_BUDGET = 4096  # embed の description
EMBED_FIELD_BUDGET = 1024  # embed の 1 field の value


def cap_list_for_message(
    items: Sequence[str],
    *,
    budget: int,
    omitted_unit: str,
    joiner: str = "\n",
    limit: int | None = None,
    header: str = "",
) -> str:
    """一覧を文字数予算(budget)に収まるよう打ち切る。件数(limit)ではなく
    文字数を最終的な保証にする。

    件数だけで打ち切ると、1件あたりの長さが可変な入力（検索クエリや辞書の
    読みなど）では上限超過を防げない（実際に /news list で発生した）。
    budget には MESSAGE_BUDGET / EMBED_DESCRIPTION_BUDGET / EMBED_FIELD_BUDGET
    のうち、呼び出し側の文脈に合ったものを渡すこと。

    - header はメッセージの前置き（"**一覧**\n" 等）。込みで budget を守れる
      よう、header の長さを先に差し引く。
    - 省略行（"…他N件"）自身の長さも budget に含めて計算する。省略件数が
      2桁→3桁になると省略行自体が伸びるため、末尾に足してからはみ出す事故を
      防ぐには、これを見込んでおく必要がある。
    - limit を指定すると、文字数に余裕があっても件数でも打ち切る（両方を
      満たす）。省略表記のUXとして、極端に短い項目が大量にあっても表示件数を
      抑えたい場合に使う。
    """
    remaining = budget - len(header)
    total = len(items)
    candidates = list(items) if limit is None else list(items[:limit])

    # 1) budget を見ながら候補を1件ずつ足す。
    fitted: list[str] = []
    for item in candidates:
        text = joiner.join(fitted + [item])
        if len(text) > remaining:
            break
        fitted.append(item)

    # 2) 省略行が必要なら、その分も budget に収まるまで後ろから削る
    #    （省略件数が増えるほど省略行はわずかに伸びうるため）。
    omitted_count = total - len(fitted)
    while True:
        if omitted_count <= 0:
            return joiner.join(fitted)
        omission = f"…他{omitted_count}{omitted_unit}"
        text = joiner.join(fitted)
        candidate = f"{text}{joiner}{omission}" if text else omission
        if len(candidate) <= remaining or not fitted:
            # fitted が空でもなお収まらないのは budget 自体が極端に小さい
            # 呼び出し側の誤り。無限ループにせず、best-effort で返す。
            return candidate
        fitted.pop()
        omitted_count += 1


def metals_site_view() -> discord.ui.View:
    view = discord.ui.View()
    view.add_item(
        discord.ui.Button(
            style=discord.ButtonStyle.link,
            label="📊 貴金属トラッカーを開く",
            url=METALS_SITE_URL,
        )
    )
    return view


def admin_site_view() -> discord.ui.View:
    view = discord.ui.View()
    view.add_item(
        discord.ui.Button(
            style=discord.ButtonStyle.link,
            label="⚙️ Web管理画面を開く",
            url=ADMIN_SITE_URL,
        )
    )
    return view


async def send_interaction(
    interaction: discord.Interaction,
    *,
    content: str | None = None,
    embed: discord.Embed | None = None,
    view: discord.ui.View | None = None,
    ephemeral: bool = True,
) -> None:
    """初回応答でも defer 済みでも、同じ呼び方で送れるようにする。

    defer() を挟んだあとに response.send_message() を呼ぶと失敗する。
    どちらの経路も通るように、ここで吸収する。
    """
    kwargs: dict[str, object] = {"ephemeral": ephemeral}
    if content is not None:
        kwargs["content"] = content
    if embed is not None:
        kwargs["embed"] = embed
    if view is not None:
        kwargs["view"] = view

    if interaction.response.is_done():
        # kwargs は dict[str, object] で動的に組み立てるため、mypy がどのオーバーロードか解決できない。
        await interaction.followup.send(**kwargs)  # type: ignore[call-overload]
    else:
        # 同上。
        await interaction.response.send_message(**kwargs)  # type: ignore[call-overload]


async def send_ephemeral(interaction: discord.Interaction, message: str) -> None:
    await send_interaction(interaction, content=message, ephemeral=True)


def bind_permission_error_handler(
    command: app_commands.Command,
    *,
    missing_permissions_message: str = "❌ 余のコマンドを使う権限が貴様にはない。",
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
            await send_ephemeral(interaction, "❌ 条件を満たしておらぬ。出直してこい。")
            return

        logger.exception("コマンドエラー: %s", error)
        await send_ephemeral(interaction, "❌ 何かが邪魔をしたようだ。しばし待って試せ。")


def install_global_app_command_error_handler(bot: Bot) -> None:
    @bot.tree.error
    async def _on_tree_error(
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        if isinstance(error, app_commands.CommandNotFound):
            return

        if isinstance(error, app_commands.MissingPermissions):
            await send_ephemeral(interaction, "❌ 余のコマンドを使う権限が貴様にはない。")
            return

        if isinstance(error, app_commands.CheckFailure):
            await send_ephemeral(interaction, "❌ 条件を満たしておらぬ。出直してこい。")
            return

        if isinstance(error, app_commands.CommandInvokeError):
            logger.exception("スラッシュコマンド実行エラー: %s", error.original)
            await send_ephemeral(interaction, "❌ 余の力をもってしても処理できなかった。しばし待って試せ。")
            return

        logger.exception("スラッシュコマンドエラー: %s", error)
        await send_ephemeral(interaction, "❌ 予期せぬ障害が生じた。しばし待て。")
