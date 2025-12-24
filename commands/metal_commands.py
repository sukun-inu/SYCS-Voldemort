import discord
from discord import app_commands

from config import METAL_COMMANDS, MetalSpec
from services.discord_utils import create_embed
from services.logging_service import log_action
from services.metal_service import MetalPriceError, calculate_metal_value


def _format_prices(prices: dict[str, int]) -> str:
    return "\n".join([f"{k}: {format(v, ',')}円" for k, v in prices.items()])


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

    try:
        price_map = await calculate_metal_value(grams, spec.code, spec.purity)
        text = _format_prices(price_map if isinstance(price_map, dict) else {spec.display_name: price_map})
        embed = create_embed(
            f"{grams}グラムの{spec.display_name}価格",
            spec.description,
            {"現在の価格": text},
            spec.color,
        )
        await interaction.response.send_message(embed=embed)
    except (ValueError, MetalPriceError) as e:
        if interaction.guild is not None:
            await log_action(
                interaction.client,
                interaction.guild.id,
                "ERROR",
                f"/{spec.display_name} エラー",
                user=interaction.user,
                fields={"エラー内容": str(e)},
            )
        await _respond_error(interaction, f"エラーだ。俺様の力をもってしても: {e}")


def register_metal_commands(bot: discord.Client) -> None:
    """金属価格コマンドを登録"""

    for spec in METAL_COMMANDS.values():

        @bot.tree.command(name=spec.key, description=f"{spec.display_name}のリアルタイムレート価格を取得")
        @app_commands.describe(g="計算するグラム数を入力してください")
        async def _cmd(interaction: discord.Interaction, g: float, _spec: MetalSpec = spec):
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "INFO",
                    f"/{_spec.display_name} 実行",
                    user=interaction.user,
                    fields={
                        "チャンネル": interaction.channel.mention if hasattr(interaction.channel, "mention") else str(interaction.channel),
                        "グラム数": str(g),
                    },
                )
            await _handle_single_metal(interaction, g, _spec)

    @bot.tree.command(name="all", description="金、銀、プラチナのリアルタイムレート価格を取得")
    @app_commands.describe(g="計算するグラム数を入力してください")
    async def all_metals(interaction: discord.Interaction, g: float):
        try:
            if g <= 0:
                raise ValueError("グラム数は正の値で指定せよ。")

            data = {}
            for spec in METAL_COMMANDS.values():
                prices = await calculate_metal_value(g, spec.code, spec.purity)
                data[f"{spec.display_name} ({spec.key.title()})"] = _format_prices(prices if isinstance(prices, dict) else {spec.display_name: prices})

            embed = create_embed(
                f"{g}グラムの金属価格",
                "金、銀、プラチナの力を見せてやろう。",
                data,
                discord.Color.gold(),
            )
            await interaction.response.send_message(embed=embed)

            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "INFO",
                    "/all 実行",
                    user=interaction.user,
                    fields={"グラム数": str(g)},
                )
        except Exception as e:
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "ERROR",
                    "/all エラー",
                    user=interaction.user,
                    fields={"エラー内容": str(e)},
                )
            await _respond_error(interaction, f"エラーだ。俺様の力をもってしても: {e}")
