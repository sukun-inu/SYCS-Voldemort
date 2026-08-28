"""開発者パネルの「通知テスト」で実際に送る中身。

原則は2つ。

1. 本番と同じ関数・同じ既定値を使う。テストが本番と違うものを出すと確認の
   意味が無い（実際、ウェルカムのテストだけ独自の既定文面を持っていて、
   本番と違う文面を出していた）。
2. channel_id を指定したら、その機能の本番用チャンネル設定を一切見ずに
   そこへ直接送る。本番設定を作らないとテストできない、という状態にしない。

送信先が決まらなかった場合は「なぜ送れなかったか」を1文で返す。呼び出し側
(bot_setup) はそれをそのまま warning ログに出す。
"""

from __future__ import annotations

import logging

import discord
from discord.ext.commands import Bot

logger = logging.getLogger(__name__)

# kind → (人が読む名前, その機能の本番用チャンネルIDを引く関数)
# 「本番ではどこへ送るのか」をここに一覧化しておく。
_TEST_KINDS: dict[str, str] = {
    "welcome":        "ウェルカム",
    "goodbye":        "お別れ",
    "vc":             "VC通知",
    "logging":        "ログ出力",
    "sticky":         "スティッキー",
    "reaction_roles": "リアクションロール",
    "tts":            "読み上げ",
}

KINDS = tuple(_TEST_KINDS)


def kind_label(kind: str) -> str:
    return _TEST_KINDS.get(kind, kind)


def _configured_channel_id(kind: str, guild_id: int) -> int | None:
    """その機能の本番用チャンネルID。未設定なら None。"""
    from services.settings_store import (
        get_goodbye_settings,
        get_reaction_roles,
        get_sticky_messages,
        get_vc_notify_channel_id,
        get_welcome_settings,
    )

    if kind == "welcome":
        return _as_id(get_welcome_settings(guild_id).get("channel_id"))
    if kind == "goodbye":
        return _as_id(get_goodbye_settings(guild_id).get("channel_id"))
    if kind == "vc":
        return _as_id(get_vc_notify_channel_id(guild_id))
    if kind == "logging":
        from services.logging_service import get_log_settings
        return _as_id(get_log_settings(guild_id).get("log_channel_id"))
    if kind == "sticky":
        # スティッキーはチャンネルごとの設定。最初の1つを既定の送信先にする。
        for channel_id in get_sticky_messages(guild_id):
            return _as_id(channel_id)
        return None
    if kind == "reaction_roles":
        for entry in get_reaction_roles(guild_id).values():
            if isinstance(entry, dict):
                return _as_id(entry.get("channel_id"))
        return None
    return None


def _as_id(value) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def resolve_channel(
    bot: Bot, kind: str, guild_id: int, override_channel_id: int | None,
) -> tuple[discord.TextChannel | None, str]:
    """送信先を決める。決まらなければ理由を1文で返す。

    地震アラート側の _evaluate_guild と同じ考え方で、複数の候補を並べず
    最初に引っかかった理由だけを返す。
    """
    guild = bot.get_guild(guild_id)
    if guild is None:
        return None, "bot がこのギルドをまだキャッシュしていません（未参加、または再起動直後）"

    if override_channel_id is not None:
        channel = guild.get_channel(int(override_channel_id))
        if not isinstance(channel, discord.TextChannel):
            return None, f"指定チャンネル（{override_channel_id}）が見つからないか、テキストチャンネルではありません"
        return channel, ""

    channel_id = _configured_channel_id(kind, guild_id)
    if channel_id is None:
        return None, (
            f"「{kind_label(kind)}」のチャンネルが未設定です"
            "（送信先チャンネルIDの指定もありません）"
        )

    channel = guild.get_channel(channel_id)
    if not isinstance(channel, discord.TextChannel):
        return None, f"設定されているチャンネル（{channel_id}）が見つからないか、テキストチャンネルではありません"
    return channel, ""


# ── 各テストの中身 ───────────────────────────────────────────

async def _send_welcome_like(channel, guild, *, goodbye: bool) -> str:
    from services.settings_store import get_goodbye_settings, get_welcome_settings
    from services.welcome_service import (
        DEFAULT_GOODBYE, DEFAULT_WELCOME, render_template,
    )

    settings = get_goodbye_settings(guild.id) if goodbye else get_welcome_settings(guild.id)
    default = DEFAULT_GOODBYE if goodbye else DEFAULT_WELCOME
    label = "お別れ" if goodbye else "ウェルカム"
    text = render_template(
        settings.get("message") or default,
        user="**@テストユーザー**",
        username="テストユーザー",
        server=guild.name,
        count=guild.member_count,
    )
    await channel.send(f"🧪 **[テスト送信 — {label}]**\n{text}")
    return f"{label}メッセージを送りました"


async def _send_vc(channel, guild) -> str:
    embed = discord.Embed(
        title="🎙️ テストユーザー が参加しました",
        description="VC: テストチャンネル",
        color=discord.Color.blue(),
    )
    embed.set_footer(text="🧪 テスト送信 — VC通知")
    await channel.send(embed=embed)
    return "VC通知を送りました"


async def _send_logging(channel, guild) -> str:
    """本番の log_action と同じ Embed を組んで送る。"""
    from services.logging_service import build_log_embed, get_log_settings

    level = str(get_log_settings(guild.id).get("log_level") or "INFO").upper()
    embed = await build_log_embed(
        level,
        "開発者パネルからのテスト送信です。",
        fields={
            "きっかけ": "開発者パネル → 通知テスト",
            "ログレベル設定": level,
        },
    )
    await channel.send(content="🧪 **[テスト送信 — ログ出力]**", embed=embed)
    return f"ログ出力テスト（{level}）を送りました"


async def _send_sticky(channel, guild) -> str:
    """本番と同じ post_sticky を呼ぶ。未設定のチャンネルでは何も起きないので、
    そのときは「設定が無い」と分かるメッセージを送る。"""
    from services.settings_store import get_sticky_messages
    from services.sticky_service import post_sticky

    entry = get_sticky_messages(guild.id).get(str(channel.id))
    if not entry or not entry.get("content"):
        await channel.send(
            "🧪 **[テスト送信 — スティッキー]**\n"
            "このチャンネルにはスティッキーが設定されていないため、"
            "本番でも何も投稿されません。"
        )
        return "スティッキー未設定であることを通知しました"

    await post_sticky(channel, guild.id)
    return "スティッキーを投稿しました"


async def _send_reaction_roles(channel, guild) -> str:
    """設定されている絵文字を実際にリアクションとして付けてみる。

    「絵文字がもう存在しない／bot が使えない」が主な故障なので、一覧を出す
    だけでなく実際に付けて確かめる。
    """
    from services.settings_store import get_reaction_roles

    mappings = get_reaction_roles(guild.id)
    if not mappings:
        await channel.send(
            "🧪 **[テスト送信 — リアクションロール]**\n"
            "このサーバーにはリアクションロールが設定されていません。"
        )
        return "リアクションロール未設定であることを通知しました"

    lines, emojis = [], []
    for entry in mappings.values():
        if not isinstance(entry, dict):
            continue
        emoji = str(entry.get("emoji") or "").strip()
        role = guild.get_role(_as_id(entry.get("role_id")) or 0)
        lines.append(f"{emoji or '(絵文字なし)'} → {role.mention if role else '(ロールが見つかりません)'}")
        if emoji:
            emojis.append(emoji)

    message = await channel.send(
        "🧪 **[テスト送信 — リアクションロール]**\n"
        "設定されている組み合わせです（このメッセージのリアクションではロールは付きません）。\n"
        + "\n".join(lines[:20])
    )

    added, failed = 0, []
    for emoji in emojis[:20]:
        try:
            await message.add_reaction(emoji)
            added += 1
        except Exception:
            failed.append(emoji)
    if failed:
        await channel.send(f"⚠️ 付けられなかった絵文字: {' '.join(failed)}")
    return f"{len(lines)} 件を表示し、{added} 個の絵文字を実際に付けました"


async def _send_tts(channel, guild, bot: Bot) -> str:
    """本番と同じ enqueue_message を通す。TTS が無効／VC 未設定なら何も鳴らない
    ので、その旨をチャンネルへ返す。"""
    from services.tts_service import enqueue_message, get_effective_vc_watch
    from services.tts_store import get_tts_settings

    settings = get_tts_settings(guild.id)
    if not settings.get("enabled"):
        await channel.send("🧪 **[テスト送信 — 読み上げ]**\nTTS が無効なので読み上げません。")
        return "TTS が無効であることを通知しました"

    vc_id, _ = get_effective_vc_watch(guild.id, settings)
    if not vc_id:
        await channel.send("🧪 **[テスト送信 — 読み上げ]**\n読み上げ対象の VC が未設定です。")
        return "VC 未設定であることを通知しました"

    speaker = guild.me or next(iter(guild.members), None)
    if speaker is None:
        return "読み上げを実行するメンバーを取得できませんでした"

    # bot を渡さないと、新しく立つ _player_loop が bot.get_guild() で
    # AttributeError を起こして黙って死ぬ（キューに入れた音声が二度と
    # 再生されない）。ここは「キューに入れました」と成功を返した直後に
    # 本番と違う理由で無音になる、という一番気づきにくい壊れ方だった。
    await enqueue_message(bot, guild, speaker, "これは読み上げのテストです。")
    await channel.send(
        f"🧪 **[テスト送信 — 読み上げ]**\n<#{vc_id}> で読み上げをキューに入れました。"
    )
    return f"VC {vc_id} への読み上げをキューに入れました"


_SENDERS = {
    "welcome":        lambda ch, g, bot: _send_welcome_like(ch, g, goodbye=False),
    "goodbye":        lambda ch, g, bot: _send_welcome_like(ch, g, goodbye=True),
    "vc":             lambda ch, g, bot: _send_vc(ch, g),
    "logging":        lambda ch, g, bot: _send_logging(ch, g),
    "sticky":         lambda ch, g, bot: _send_sticky(ch, g),
    "reaction_roles": lambda ch, g, bot: _send_reaction_roles(ch, g),
    "tts":            _send_tts,
}


async def run_test(
    bot: Bot, kind: str, guild_id: int, override_channel_id: int | None = None,
) -> None:
    """1件のテスト送信を実行し、結果をログに残す。"""
    if kind not in _SENDERS:
        logger.warning("[DEV] test_notify: 未知の種類です: %s", kind)
        return

    channel, reason = resolve_channel(bot, kind, guild_id, override_channel_id)
    if channel is None:
        logger.warning(
            "[DEV] test_notify(%s): guild=%s へ送れませんでした（理由: %s）",
            kind, guild_id, reason,
        )
        return

    guild = bot.get_guild(guild_id)
    result = await _SENDERS[kind](channel, guild, bot)
    logger.info(
        "[DEV] test_notify(%s): guild=%s ch=%s %s", kind, guild_id, channel.id, result,
    )
