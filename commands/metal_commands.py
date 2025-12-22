import discord
from discord import app_commands
from config import METAL_COMMANDS
from services.metal_service import calculate_metal_value
from services.discord_utils import create_embed
from services.logging_service import log_action


def create_metal_command(metal_code: str, purity: dict, metal_name: str, description: str, color: str):
    """金属価格コマンドを作成する高階関数"""
    async def cmd(interaction: discord.Interaction, g: str):
        try:
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "INFO",
                    f"/{metal_name} 実行",
                    user=interaction.user,
                    fields={
                        "チャンネル": interaction.channel.mention if hasattr(interaction.channel, "mention") else str(interaction.channel),
                        "グラム数": str(g),
                    },
                )

            grams = float(g)
            prices = calculate_metal_value(grams, metal_code, purity)
            text = "\n".join([f"{k}: ¥{format(v, ',')}円" for k, v in prices.items()])
            embed = create_embed(
                f"{grams}グラムの{metal_name}価格",
                description,
                {"現在の価格 (¥)": text},
                color
            )
            await interaction.response.send_message(embed=embed)
        except Exception as e:
            if interaction.guild is not None:
                await log_action(
                    interaction.client,
                    interaction.guild.id,
                    "ERROR",
                    f"/{metal_name} エラー",
                    user=interaction.user,
                    fields={"エラー内容": str(e)},
                )
            await interaction.response.send_message(f"エラーだ。俺様の力をもってしても: {e}")
    
    return cmd


def register_metal_commands(bot):
    """金属価格コマンドを登録"""
    
    # /gold コマンド
    gold_cmd = create_metal_command(
        METAL_COMMANDS['gold']['code'],
        METAL_COMMANDS['gold']['purity'],
        METAL_COMMANDS['gold']['name'],
        METAL_COMMANDS['gold']['description'],
        METAL_COMMANDS['gold']['color']
    )
    bot.tree.command(name="gold", description="金のリアルタイムレート価格を取得")(
        app_commands.describe(g="計算するグラム数を入力してください")(gold_cmd)
    )
    
    # /silver コマンド
    silver_cmd = create_metal_command(
        METAL_COMMANDS['silver']['code'],
        METAL_COMMANDS['silver']['purity'],
        METAL_COMMANDS['silver']['name'],
        METAL_COMMANDS['silver']['description'],
        METAL_COMMANDS['silver']['color']
    )
    bot.tree.command(name="silver", description="銀のリアルタイムレート価格を取得")(
        app_commands.describe(g="計算するグラム数を入力してください")(silver_cmd)
    )
    
    # /platinum コマンド
    platinum_cmd = create_metal_command(
        METAL_COMMANDS['platinum']['code'],
        METAL_COMMANDS['platinum']['purity'],
        METAL_COMMANDS['platinum']['name'],
        METAL_COMMANDS['platinum']['description'],
        METAL_COMMANDS['platinum']['color']
    )
    bot.tree.command(name="platinum", description="プラチナのリアルタイムレート価格を取得")(
        app_commands.describe(g="計算するグラム数を入力してください")(platinum_cmd)
    )
    
    # /all コマンド
    @bot.tree.command(name="all", description="金、銀、プラチナのリアルタイムレート価格を取得")
    @app_commands.describe(g="計算するグラム数を入力してください")
    async def all_metals(interaction: discord.Interaction, g: str):
        try:
            grams = float(g)
            gold = calculate_metal_value(grams, METAL_COMMANDS['gold']['code'], METAL_COMMANDS['gold']['purity'])
            silver = calculate_metal_value(grams, METAL_COMMANDS['silver']['code'], METAL_COMMANDS['silver']['purity'])
            platinum = calculate_metal_value(grams, METAL_COMMANDS['platinum']['code'], METAL_COMMANDS['platinum']['purity'])
            data = {
                "金 (Gold)": "\n".join([f"{k}: ¥{format(v, ',')}円" for k, v in gold.items()]),
                "銀 (Silver)": "\n".join([f"{k}: ¥{format(v, ',')}円" for k, v in silver.items()]),
                "プラチナ (Platinum)": "\n".join([f"{k}: ¥{format(v, ',')}円" for k, v in platinum.items()])
            }
            embed = create_embed(
                f"{grams}グラムの金属価格",
                "金、銀、プラチナの力を見せてやろう。",
                data,
                discord.Color.gold()
            )
            await interaction.response.send_message(embed=embed)
        except Exception as e:
            try:
                await interaction.response.send_message(f"エラーだ。俺様の力をもってしても: {e}")
            except discord.InteractionResponded:
                await interaction.followup.send(f"エラーだ。俺様の力をもってしても: {e}")
