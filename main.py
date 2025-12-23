import asyncio
import threading

from config import DISCORD_BOT_TOKEN
from bot_setup import create_bot, setup_events
from commands.metal_commands import register_metal_commands
from commands.logging_commands import register_logging_commands
from bot_status_server import start_status_server


async def main():
    """メイン処理"""
    # ボット作成
    bot = create_bot()

    # イベント設定（on_message 含む）
    setup_events(bot)

    # コマンド登録（スラッシュ / prefix）
    register_metal_commands(bot)
    register_logging_commands(bot)

    # ボット起動
    async with bot:
        if not DISCORD_BOT_TOKEN:
            raise RuntimeError("DISCORD_BOT_TOKEN が設定されていません。環境変数または .env を確認してください。")
        await bot.start(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    # Flask ステータスサーバー起動
    flask_thread = threading.Thread(
        target=start_status_server,
        daemon=True
    )
    flask_thread.start()

    # Discord Bot 起動
    asyncio.run(main())
