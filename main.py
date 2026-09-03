import asyncio
import logging
from pathlib import Path

from bot_setup import create_bot, setup_events
from commands import register_all_commands
from commands.interaction_utils import install_global_app_command_error_handler
from config import DISCORD_BOT_TOKEN
from envutil import env_path
from services.log_setup import LOG_FORMAT, install_file_logging

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# 素の os.getenv("SETTINGS_DIR", 既定値) は SETTINGS_DIR="" のとき Path("") =
# カレントディレクトリになり、ログだけ data/ の外へ出ていた。envutil に揃える。
_log_dir = env_path("SETTINGS_DIR", Path(__file__).resolve().parent / "data") / "logs"
install_file_logging(_log_dir, "bot.log")


async def main():
    """Bot を組み立てて起動する。

    登録の順に意味がある。setup_events → register_all_commands →
    エラーハンドラの順で、最後のものはコマンドツリー全体に掛けるため、
    コマンドが出揃ってから入れる必要がある。
    """
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
        try:
            await bot.start(DISCORD_BOT_TOKEN)
        finally:
            # 録音中に落ちると、そこまで録った分がまるごと消える。
            # 終了時は必ず書き出してからにする。
            from services.http_client import close_session
            from services.recording_service import stop_all

            await stop_all(bot, reason="bot 停止")
            # 使い回している HTTP セッションを閉じる。録音の書き出しより後に
            # 置くのは、書き出し側がまだ通信する可能性があるため。
            await close_session()


if __name__ == "__main__":
    asyncio.run(main())
