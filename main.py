import asyncio
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from bot_setup import create_bot, setup_events
from commands import register_all_commands
from commands.interaction_utils import install_global_app_command_error_handler
from config import DISCORD_BOT_TOKEN

_LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FMT)

_log_dir = Path(os.getenv("SETTINGS_DIR", str(Path(__file__).parent / "data"))) / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_fh = RotatingFileHandler(_log_dir / "bot.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
_fh.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_fh)


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
