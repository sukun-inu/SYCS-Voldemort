import asyncio
import logging

from bot_setup import create_bot, setup_events
from commands import register_all_commands
from commands.interaction_utils import install_global_app_command_error_handler
from config import DISCORD_BOT_TOKEN

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


async def main():
    bot = create_bot()
    setup_events(bot)
    loaded_modules = register_all_commands(bot)
    install_global_app_command_error_handler(bot)

    logging.getLogger(__name__).info(
        "Slash command modules loaded: %s",
        ", ".join(loaded_modules),
    )

    async with bot:
        if not DISCORD_BOT_TOKEN:
            raise RuntimeError("DISCORD_BOT_TOKEN が設定されていません。環境変数または .env を確認してください。")
        await bot.start(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
