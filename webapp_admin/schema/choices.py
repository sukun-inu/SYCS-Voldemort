"""選択肢（チャンネル・ロール・声）の実行時解決。

1リクエストにつき、必要な供給元だけを1回ずつ取得してまとめて返す。
従来は画面ごとに get_guild_channels() を個別に呼んでいた。

取得に失敗した供給元は空リストになる。呼び出し側は「選択肢が空」を
異常ではなく通常の状態として扱うこと（例: TTS API 停止時の声一覧）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Iterable

from webapp_admin.auth import get_guild_channels, get_guild_roles, get_guild_voice_channels
from webapp_admin.schema.types_def import ChoiceSource

logger = logging.getLogger(__name__)


async def _channels(guild_id: int) -> list[dict[str, str]]:
    """ChoiceSource.CHANNELS の実体。_RESOLVERS から (guild_id) だけで一律に呼ばれるため、
    引数を増やすなど呼び出し規約からはみ出す変更はできない。"""
    return [{"value": str(c["id"]), "label": f"# {c['name']}"} for c in await get_guild_channels(guild_id)]


async def _voice_channels(guild_id: int) -> list[dict[str, str]]:
    """ChoiceSource.VOICE_CHANNELS の実体。_channels と同じ理由でシグネチャは固定。"""
    return [{"value": str(c["id"]), "label": c["name"]} for c in await get_guild_voice_channels(guild_id)]


async def _roles(guild_id: int) -> list[dict[str, str]]:
    """ChoiceSource.ROLES の実体。_channels と同じ理由でシグネチャは固定。"""
    return [{"value": str(r["id"]), "label": r["name"]} for r in await get_guild_roles(guild_id)]


# 声一覧は画面を開くたびに取りに行く。応答が返らない相手だと、その間ずっと
# パネルが「読み込み中」で止まるため、短めに見切る（取れなければ手入力になる）。
_VOICES_TIMEOUT = 3.0


async def _tts_voices(guild_id: int) -> list[dict[str, str]]:
    """ChoiceSource.TTS_VOICES の実体。応答が来ない相手を _VOICES_TIMEOUT で見切る。

    ここで timeout せず待ち続けると、resolve() の asyncio.gather 全体がその分
    止まり、TTS 以外の選択肢も含めて画面が「読み込み中」のまま固まる。
    TimeoutError は resolve() 側が拾って空リスト扱いにする前提。
    """
    # tts_service は discord.py を読み込むため、必要になった時だけ import する。
    from services.tts_service import fetch_voices

    voices = await asyncio.wait_for(fetch_voices(), timeout=_VOICES_TIMEOUT)
    return [{"value": v, "label": v} for v in voices]


_RESOLVERS: dict[ChoiceSource, Callable[[int], Awaitable[list[dict[str, str]]]]] = {
    ChoiceSource.CHANNELS: _channels,
    ChoiceSource.VOICE_CHANNELS: _voice_channels,
    ChoiceSource.ROLES: _roles,
    ChoiceSource.TTS_VOICES: _tts_voices,
}


async def resolve(sources: Iterable[ChoiceSource], guild_id: int) -> dict[str, list[dict[str, str]]]:
    """必要な供給元をまとめて解決する。同じ供給元は1回しか取得しない。"""
    wanted = sorted({ChoiceSource(s) for s in sources}, key=lambda s: s.value)
    if not wanted:
        return {}

    results: list[Any] = await asyncio.gather(
        *(_RESOLVERS[source](guild_id) for source in wanted),
        return_exceptions=True,
    )

    resolved: dict[str, list[dict[str, str]]] = {}
    for source, result in zip(wanted, results):
        if isinstance(result, BaseException):
            from webapp_admin.api.dev import describe_exception

            logger.warning(
                "選択肢の取得に失敗しました source=%s guild=%s: %s",
                source.value,
                guild_id,
                describe_exception(result),
            )
            resolved[source.value] = []
        else:
            resolved[source.value] = result
    return resolved
