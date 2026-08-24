import asyncio
import logging

import discord
from discord import app_commands

from config import METAL_COMMANDS, MetalSpec
from commands.interaction_utils import metals_site_view, send_interaction
from services.discord_utils import create_embed
from services.logging_service import log_action
from services.metal_service import MetalPriceError, calculate_metal_value

logger = logging.getLogger(__name__)


def _format_prices(prices: dict[str, int]) -> str:
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
        await send_interaction(interaction, embed=embed, view=metals_site_view(),
                               ephemeral=False)
    except (ValueError, MetalPriceError) as e:
        if interaction.guild is not None:
            await log_action(
                interaction.client,
                interaction.guild.id,
                "ERROR",
                f"/metal_{spec.key} エラー",
                user=interaction.user,
                fields={"エラー内容": str(e)},
            )
        await _respond_error(interaction, "エラーだ。俺様の力をもってしても処理できなかった。しばらく待ってから試せ。")


def register_metal_commands(bot: discord.Client) -> None:
    """金属価格コマンドを登録"""

    def _create_single_command(spec: MetalSpec):
        @bot.tree.command(name=f"metal_{spec.key}", description=f"{spec.display_name}の現在価格を表示します")
        @app_commands.describe(g="計算するグラム数を入力してください")
        async def _cmd(interaction: discord.Interaction, g: float):
            # 監査ログの送信も Discord への往復で、失敗すれば待たされる。
            # 3秒の持ち時間を使い切らないよう、先に defer しておく。
            await _defer(interaction)
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "INFO",
                    f"/metal_{spec.key} 実行",
                    user=interaction.user,
                    fields={
                        "チャンネル": interaction.channel.mention if hasattr(interaction.channel, "mention") else str(interaction.channel),
                        "グラム数": str(g),
                    },
                )
            await _handle_single_metal(interaction, g, spec)

        return _cmd

    for spec in METAL_COMMANDS.values():
        _create_single_command(spec)

    @bot.tree.command(name="metal_all", description="金・銀・プラチナの現在価格をまとめて表示します")
    @app_commands.describe(g="計算するグラム数を入力してください")
    async def all_metals(interaction: discord.Interaction, g: float):
        if g <= 0:
            await _respond_error(interaction, "グラム数は正の値で指定せよ。")
            return

        # 3種類ぶん外部APIを叩く。単体より遅くなるので必ず defer してから。
        await _defer(interaction)
        try:
            specs = list(METAL_COMMANDS.values())
            results = await asyncio.gather(
                *[calculate_metal_value(g, spec.code, spec.purity) for spec in specs],
                return_exceptions=True,
            )
            data = {}
            for spec, prices in zip(specs, results):
                if isinstance(prices, Exception):
                    raise prices
                data[f"{spec.display_name} ({spec.key.title()})"] = _format_prices(prices)

            embed = create_embed(
                f"{g}グラムの金属価格",
                "金、銀、プラチナの力を見せてやろう。",
                data,
                discord.Color.gold(),
                footer_text="Powered by MetalpriceAPI Free",
            )
            await send_interaction(interaction, embed=embed, view=metals_site_view(),
                                   ephemeral=False)

            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "INFO",
                    "/metal_all 実行",
                    user=interaction.user,
                    fields={"グラム数": str(g)},
                )
        except Exception as e:
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "ERROR",
                    "/metal_all エラー",
                    user=interaction.user,
                    fields={"エラー内容": str(e)},
                )
            await _respond_error(interaction, "エラーだ。俺様の力をもってしても処理できなかった。しばらく待ってから試せ。")
