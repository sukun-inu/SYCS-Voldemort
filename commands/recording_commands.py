"""VC録音のスラッシュコマンドの登録入口（管理者専用）。

/record start  … 今いる VC（または指定した VC）の録音を開始
/record stop   … 停止して ZIP のリンクを返す
/record status … 録音中かどうか、経過時間、参加者
/record auto   … 自動録音のオン／オフ
/record config … 録音の設定を表示・変更
/record exclude … 自分を録音対象から外す／戻す（本人が使う）

以前は register_recording_commands(bot) 自体が268行・循環的複雑度35の単一
クロージャで、上の6コマンドすべてを1関数に抱えていた。実体は
commands/record/ 以下へ切り出してある（分け方の理由は
commands/record/__init__.py を参照）。6つとも1つの /record グループに属する
ので、グループの生成と bot.tree.add_command() はここに残し、各モジュールの
register() へグループを渡している。呼ぶ順は分割前の記述順と同じ。

commands/__init__.py の register_all_commands() がこの関数を直接呼んでいる
ため、呼び出し口の型（register_recording_commands(bot) -> None）は変えていない。
"""

from discord import app_commands
from discord.ext.commands import Bot

from commands.record import config, exclude, session


def register_recording_commands(bot: Bot) -> None:
    group = app_commands.Group(
        name="record",
        description="【管理者】ボイスチャンネルを録音します",
        guild_only=True,
    )

    session.register(bot, group)
    config.register(group)
    exclude.register(group)

    bot.tree.add_command(group)
