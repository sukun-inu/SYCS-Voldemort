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
from webapp_admin.schema.types import ChoiceSource

logger = logging.getLogger(__name__)


async def _channels(guild_id: int) -> list[dict[str, str]]:
    return [
        {"value": str(c["id"]), "label": f"# {c['name']}"}
        for c in await get_guild_channels(guild_id)
    ]


async def _voice_channels(guild_id: int) -> list[dict[str, str]]:
    return [
        {"value": str(c["id"]), "label": c["name"]}
        for c in await get_guild_voice_channels(guild_id)
    ]


async def _roles(guild_id: int) -> list[dict[str, str]]:
    return [
        {"value": str(r["id"]), "label": r["name"]}
        for r in await get_guild_roles(guild_id)
    ]


async def _tts_voices(guild_id: int) -> list[dict[str, str]]:
    # tts_service は discord.py を読み込むため、必要になった時だけ import する。
    from services.tts_service import fetch_voices

    return [{"value": v, "label": v} for v in await fetch_voices()]


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
            logger.warning("選択肢の取得に失敗しました source=%s: %s", source.value, result)
            resolved[source.value] = []
        else:
            resolved[source.value] = result
    return resolved
