import asyncio
import logging
from pathlib import Path

from bot_setup import create_bot, setup_events
from commands import register_all_commands
from commands.activity_log import install_command_activity_logging
from commands.interaction_utils import install_global_app_command_error_handler
from config import DISCORD_BOT_TOKEN
from envutil import env_path
from services.log_setup import install_console_logging, install_file_logging, install_structured_logging

# basicConfig ではなくこちらを使う。LOG_FORMAT は `%(category)s` を含み、
# basicConfig が作る素の Formatter では KeyError になる。
install_console_logging()

# 素の os.getenv("SETTINGS_DIR", 既定値) は SETTINGS_DIR="" のとき Path("") =
# カレントディレクトリになり、ログだけ data/ の外へ出ていた。envutil に揃える。
_log_dir = env_path("SETTINGS_DIR", Path(__file__).resolve().parent / "data") / "logs"
install_file_logging(_log_dir, "bot.log")
# 端末から読むテキストと、管理画面が絞り込む JSONL の両方を書く。
install_structured_logging(_log_dir, "bot.jsonl")


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
    # 打たれたコマンドを1行ずつ残す。172個へ個別に書き足す方式は次に足す
    # コマンドで必ず忘れるので、入口で1箇所にしてある。
    install_command_activity_logging(bot)

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
            from services.http_client import close_session

            # 使い回している HTTP セッションを閉じる。
            await close_session()


if __name__ == "__main__":
    asyncio.run(main())
