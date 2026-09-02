import logging

import discord

from services.settings_store import get_goodbye_settings, get_welcome_settings

logger = logging.getLogger(__name__)

DEFAULT_WELCOME = (
    "新たなる者よ、{user} がこの地に降り立った。**{server}** へようこそ… 余の治める場所へ。（現在 {count} 名）"
)
DEFAULT_GOODBYE = "{username} が去っていった。余の名を知りながら逃げるとは… 嘆かわしい。"

# 後方互換（旧名を参照している箇所があっても壊れないように）
_DEFAULT_WELCOME = DEFAULT_WELCOME
_DEFAULT_GOODBYE = DEFAULT_GOODBYE


def render_template(
    template: str,
    *,
    user: str,
    username: str,
    server: str,
    count: int | None,
) -> str:
    """プレースホルダを差し替える。

    開発者パネルのテスト送信もこれを使う。以前はテスト側が自前の
    replace 連鎖と別の既定文面を持っていたため、「本番で何が届くかを
    確かめる」ためのテストが本番と違う文面を出していた。
    """
    return (
        template.replace("{user}", user)
        .replace("{username}", username)
        .replace("{server}", server)
        .replace("{count}", str(count if count is not None else 0))
    )


def _render(template: str, member: discord.Member) -> str:
    """discord.Member から render_template に渡す値を組み立てる薄いラッパー。
    実際の入退室（send_welcome/send_goodbye）専用で、テスト送信側は
    render_template を直接呼んでダミー値を渡す。
    """
    return render_template(
        template,
        user=member.mention,
        username=str(member),
        server=member.guild.name,
        count=member.guild.member_count,
    )


async def send_welcome(member: discord.Member) -> None:
    """メンバー参加時のウェルカムメッセージを送る。チャンネル未設定・
    チャンネルが見つからない・テキストチャンネルでない場合は何も送らず
    静かに終わる（機能未設定は正常系として扱う）。送信自体の失敗は
    例外にせずログへ残し、on_member_join のイベント処理を止めない。
    """
    s = get_welcome_settings(member.guild.id)
    channel_id = s.get("channel_id")
    if not channel_id:
        return
    channel = member.guild.get_channel(int(channel_id))
    if channel is None or not isinstance(channel, discord.TextChannel):
        return
    message = s.get("message") or DEFAULT_WELCOME
    try:
        await channel.send(_render(message, member))
    except Exception as e:
        logger.exception("[welcome_service] send_welcome error: %s", e)


async def send_goodbye(member: discord.Member) -> None:
    """メンバー退出時のお別れメッセージを送る。send_welcome と同じ方針
    （未設定は正常系、送信失敗は例外にせずログへ）。
    """
    s = get_goodbye_settings(member.guild.id)
    channel_id = s.get("channel_id")
    if not channel_id:
        return
    channel = member.guild.get_channel(int(channel_id))
    if channel is None or not isinstance(channel, discord.TextChannel):
        return
    message = s.get("message") or DEFAULT_GOODBYE
    try:
        await channel.send(_render(message, member))
    except Exception as e:
        logger.exception("[welcome_service] send_goodbye error: %s", e)
