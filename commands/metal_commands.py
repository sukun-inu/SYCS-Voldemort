import asyncio
import logging
from typing import cast

import discord
from discord import app_commands
from discord.ext.commands import Bot

from config import METAL_COMMANDS, MetalSpec
from commands.interaction_utils import metals_site_view, send_interaction
from services.discord_utils import create_embed
from services.logging_service import log_action
from services.metal_service import MetalPriceError, calculate_metal_value

logger = logging.getLogger(__name__)


def _format_prices(prices: dict[str, int]) -> str:
    """単体表示(_handle_single_metal)とまとめ表示(all_metals)で表記を揃えるための共通整形。"""
    return "\n".join([f"{k}: {format(v, ',')}円" for k, v in prices.items()])


async def _defer(interaction: discord.Interaction) -> None:
    """まだ何も返していなければ「考え中」にしておく。"""
    if not interaction.response.is_done():
        try:
            await interaction.response.defer()
        except discord.HTTPException as e:
            logger.warning("defer に失敗: %s", e)


async def _respond_error(interaction: discord.Interaction, message: str) -> None:
    """初回レスポンス済みかを考慮したエラー返信"""
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except Exception:
        # どうしても失敗した場合は握りつぶす（ログは別で送信済み）
        pass


async def _handle_single_metal(interaction: discord.Interaction, grams: float, spec: MetalSpec) -> None:
    """except は ValueError/MetalPriceError だけを狙って拾う。

    それ以外の想定外の例外はここでは拾わず、呼び出し元（コマンド本体）から
    抜けて discord.py 側の CommandInvokeError 経路に流す。監査ログ
    (log_action) に載せるのは「価格取得の失敗」という想定内の事象だけにし、
    プログラムの不具合まで通常運用のエラーとしてギルドの監査ログに残さない
    ための切り分け。
    """
    if grams <= 0:
        await _respond_error(interaction, "グラム数は正の値で指定せよ。")
        return

    # 価格は外部APIから取る。Discord は最初の応答まで3秒しか待たないので、
    # 取りに行く前に defer しておく（これで15分まで伸びる）。
    await _defer(interaction)
    try:
        price_map = await calculate_metal_value(grams, spec.code, spec.purity)
        text = _format_prices(price_map)
        embed = create_embed(
            f"{grams}グラムの{spec.display_name}価格",
            spec.description,
            {"現在の価格": text},
            spec.color,
            footer_text="Powered by MetalpriceAPI Free",
        )
        await send_interaction(interaction, embed=embed, view=metals_site_view(), ephemeral=False)
    except (ValueError, MetalPriceError) as e:
        if interaction.guild is not None:
            await log_action(
                interaction.client,
                interaction.guild.id,
                "ERROR",
                f"/metal {spec.key} エラー",
                user=interaction.user,
                fields={"エラー内容": str(e)},
            )
        # 一人称は「余」で統一している（「俺」「俺様」はこのbotの口調ルール違反）。
        await _respond_error(interaction, "エラーだ。余の力をもってしても処理できなかった。しばらく待ってから試せ。")


async def _log_command_use(interaction: discord.Interaction, title: str, fields: dict[str, str]) -> None:
    """コマンドを打った事実を監査ログへ残す。ギルド外では何もしない。

    **呼ぶ前に defer しておくこと。** 監査ログも Discord への往復で、混んで
    いれば待たされる。3秒の持ち時間をここで使い切ると、コマンドそのものが
    「応答なし」で失敗する。ログが速い平常時には起きない。
    """
    if interaction.guild is None:
        return
    await log_action(
        interaction.client,
        interaction.guild.id,
        "INFO",
        title,
        user=interaction.user,
        fields=fields,
    )


def _channel_label(interaction: discord.Interaction) -> str:
    """監査ログに載せるチャンネルの呼び名。"""
    if hasattr(interaction.channel, "mention"):
        # hasattr で絞っているが mypy は追えない（None も含め対象外なら else 分岐へ）
        return str(interaction.channel.mention)  # type: ignore[union-attr]
    return str(interaction.channel)


async def _all_metals_embed(g: float) -> discord.Embed:
    """3種の価格をまとめた Embed を作る。1つでも失敗したらその例外を上げる。

    3種の外部API呼び出しを gather(return_exceptions=True) でまとめて待つ。
    1つでも失敗した時点で例外を投げて終わらせるのではなく、必ず全部の
    リクエストを最後まで並行して走らせてから raise する（1件だけ早く
    中断しても、他の待機中リクエストの遅延はどのみち解消しないため）。
    """
    specs = list(METAL_COMMANDS.values())
    results = await asyncio.gather(
        *[calculate_metal_value(g, spec.code, spec.purity) for spec in specs],
        return_exceptions=True,
    )
    data = {}
    for spec, prices in zip(specs, results):
        if isinstance(prices, Exception):
            raise prices
        # gather の型は dict[str, int] | BaseException だが、上の isinstance
        # で Exception は排除済み（BaseException 直系の非 Exception 型は
        # calculate_metal_value が投げないので実行時には来ない）。
        data[f"{spec.display_name} ({spec.key.title()})"] = _format_prices(cast(dict[str, int], prices))

    return create_embed(
        f"{g}グラムの金属価格",
        "金、銀、プラチナの力を見せてやろう。",
        data,
        discord.Color.gold(),
        footer_text="Powered by MetalpriceAPI Free",
    )


async def _handle_all_metals(interaction: discord.Interaction, g: float) -> None:
    """/metal all の中身。

    0 以下のグラム数は **defer より前に**断る。defer したあとでは ephemeral な
    初回応答を使えず、断り文句が全員に見える形で出てしまう。
    """
    if g <= 0:
        await _respond_error(interaction, "グラム数は正の値で指定せよ。")
        return

    # 3種類ぶん外部APIを叩く。単体より遅くなるので必ず defer してから。
    await _defer(interaction)
    try:
        embed = await _all_metals_embed(g)
        await send_interaction(interaction, embed=embed, view=metals_site_view(), ephemeral=False)
        await _log_command_use(interaction, "/metal all 実行", {"グラム数": str(g)})
    except Exception as e:
        if interaction.guild is not None:
            await log_action(
                interaction.client,
                interaction.guild.id,
                "ERROR",
                "/metal all エラー",
                user=interaction.user,
                fields={"エラー内容": str(e)},
            )
        # 一人称は「余」で統一している（「俺」「俺様」はこのbotの口調ルール違反）。
        await _respond_error(interaction, "エラーだ。余の力をもってしても処理できなかった。しばらく待ってから試せ。")


async def _handle_metal_command(interaction: discord.Interaction, g: float, spec: MetalSpec) -> None:
    """金属1種のコマンドの中身。

    価格計算そのものは _handle_single_metal に委譲し、ここでは実行の監査ログ
    送信だけを担う（成功/失敗を問わず実行された事実を残したいので、価格取得の
    成否を待たず先に打つ）。
    """
    # 監査ログの送信も Discord への往復で、失敗すれば待たされる。
    # 3秒の持ち時間を使い切らないよう、先に defer しておく。
    await _defer(interaction)
    await _log_command_use(
        interaction,
        f"/metal {spec.key} 実行",
        {"チャンネル": _channel_label(interaction), "グラム数": str(g)},
    )
    await _handle_single_metal(interaction, g, spec)


def register_metal_commands(bot: Bot) -> None:
    """金属価格コマンドを登録"""
    group = app_commands.Group(name="metal", description="貴金属の現在価格")

    def _create_single_command(spec: MetalSpec):
        """for ループの中で直接 @group.command を定義すると、Python のクロージャは
        遅延束縛のため全コマンドが最後の spec を共有してしまう（ループ変数の
        典型的な事故）。関数でラップし spec を引数として束縛することで防ぐ。
        """

        @group.command(name=spec.key, description=f"{spec.display_name}の現在価格を表示します")
        @app_commands.describe(g="計算するグラム数を入力してください")
        async def _cmd(interaction: discord.Interaction, g: float):
            """金属1種の現在価格（本体は _handle_metal_command）。"""
            await _handle_metal_command(interaction, g, spec)

        return _cmd

    for spec in METAL_COMMANDS.values():
        _create_single_command(spec)

    @group.command(name="all", description="金・銀・プラチナの現在価格をまとめて表示します")
    @app_commands.describe(g="計算するグラム数を入力してください")
    async def all_metals(interaction: discord.Interaction, g: float):
        """3種まとめての現在価格（本体は _handle_all_metals）。"""
        await _handle_all_metals(interaction, g)

    bot.tree.add_command(group)
