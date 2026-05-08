import asyncio
import logging
from bot_setup import create_bot, setup_events
from commands.djaudio_commands import register_djaudio_commands
from commands.logging_commands import register_logging_commands
from commands.metal_commands import register_metal_commands
from commands.server_commands import register_server_commands
from config import DISCORD_BOT_TOKEN

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


async def main():
    bot = create_bot()
    setup_events(bot)
    register_metal_commands(bot)
    register_logging_commands(bot)
    register_server_commands(bot)
    register_djaudio_commands(bot)

    async with bot:
        if not DISCORD_BOT_TOKEN:
            raise RuntimeError("DISCORD_BOT_TOKEN が設定されていません。環境変数または .env を確認してください。")
        await bot.start(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
