"""サーバー設定系スラッシュコマンドの登録入口。

以前は register_server_commands(bot) 自体が584行・循環的複雑度75の単一
クロージャで、ウェルカム/グッバイからサーバー情報表示まで7トピック分の
コマンドを1関数に抱えていた（71件のテストで99.73%カバーされてはいたが、
どれか1つを直すにも全体を読む必要があった）。events/ パッケージの分割に
倣い、実体は commands/server/ 以下へトピックごとに切り出した（分け方の
理由は commands/server/__init__.py を参照）。ここでは各モジュールの
register(bot) を元の記述順（ウェルカム/グッバイ → VC通知 → スティッキー →
リアクションロール → ニュース → 地震アラート → サーバー/ユーザー情報）で
呼ぶだけにしてある。

commands/__init__.py の register_all_commands() がこの関数を直接呼んでいる
ため、呼び出し口の型（register_server_commands(bot) -> None）は変えていない。
"""

from discord.ext.commands import Bot

from commands.server import info, news, quake, reactionrole, sticky, vcnotify, welcome_goodbye


def register_server_commands(bot: Bot) -> None:
    welcome_goodbye.register(bot)
    vcnotify.register(bot)
    sticky.register(bot)
    reactionrole.register(bot)
    news.register(bot)
    quake.register(bot)
    info.register(bot)
