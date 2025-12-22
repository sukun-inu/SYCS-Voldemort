import asyncio
from config import DISCORD_BOT_TOKEN
from bot_setup import create_bot, setup_events
from commands.metal_commands import register_metal_commands
from commands.chat_commands import register_message_handler
from commands.logging_commands import register_logging_commands


async def main():
    """メイン処理"""
    # ボット作成
    bot = create_bot()
    
    # イベント設定
    setup_events(bot)
    
    # コマンド登録
    register_metal_commands(bot)
    register_message_handler(bot)
    register_logging_commands(bot)
    
    # ボット起動
    async with bot:
        await bot.start(DISCORD_BOT_TOKEN)



import threading
from bot_status_server import start_status_server

if __name__ == "__main__":
    # Flaskサーバーをサブスレッドで起動
    flask_thread = threading.Thread(target=start_status_server, daemon=True)
    flask_thread.start()
    # Discord Bot起動
    asyncio.run(main())
