"""Bot 設定系スラッシュコマンドの登録入口。

以前は register_logging_commands(bot) 自体が271行・循環的複雑度35の単一
クロージャで、ログ設定から /bot help まで5トピック分のコマンドを1関数に
抱えていた。commands/server/ の分割に倣い、実体は commands/settings/ 以下へ
トピックごとに切り出した（分け方の理由は commands/settings/__init__.py を
参照）。

グループの生成と bot.tree.add_command() はここに残してある。元のコードが
5つのグループをまとめて作り、最後に1つのループで登録していたので、登録順
（log → chat → trusted → bypass → bot）が1箇所で読める形を保った。

commands/__init__.py の register_all_commands() がこの関数を直接呼んでいる
ため、呼び出し口の型（register_logging_commands(bot) -> None）は変えていない。
"""

from discord import app_commands
from discord.ext.commands import Bot

from commands.settings import bypass, chat, log, overview, trusted


def register_logging_commands(bot: Bot) -> None:
    """log/chat/trusted/bypass/bot の5グループを作り、各サブモジュールに
    登録させたうえで bot.tree に足す。分割の経緯はモジュール docstring参照。
    """
    # 平坦な名前を並べると /（スラッシュ）の一覧が長くなり、関連するものが
    # 隣り合う保証も無い。同じ話題はグループにまとめる。
    log_group = app_commands.Group(name="log", description="ログの送信先とレベル", guild_only=True)
    chat_group = app_commands.Group(name="chat", description="AI応答チャンネルの設定", guild_only=True)
    trusted_group = app_commands.Group(name="trusted", description="信頼済みユーザー（検出の対象外）", guild_only=True)
    bypass_group = app_commands.Group(name="bypass", description="バイパスロール（検出の対象外）", guild_only=True)
    bot_group = app_commands.Group(name="bot", description="Bot の設定とヘルプ", guild_only=True)

    log.register(log_group)
    chat.register(chat_group)
    trusted.register(trusted_group)
    bypass.register(bypass_group)
    overview.register(bot, bot_group)

    for group in (log_group, chat_group, trusted_group, bypass_group, bot_group):
        bot.tree.add_command(group)
