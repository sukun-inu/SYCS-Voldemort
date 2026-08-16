import asyncio
import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode

import aiohttp

logger = logging.getLogger(__name__)

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://localhost:5001/admin/callback")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_OAUTH_PROMPT = os.environ.get("DISCORD_OAUTH_PROMPT", "").strip().lower()
if DISCORD_OAUTH_PROMPT and DISCORD_OAUTH_PROMPT not in {"none", "consent"}:
    logger.warning("DISCORD_OAUTH_PROMPT=%s は無効なため無視します。", DISCORD_OAUTH_PROMPT)
    DISCORD_OAUTH_PROMPT = ""

_API = "https://discord.com/api/v10"
_SCOPES = "identify guilds"
_ADMINISTRATOR_BIT = 0x8

_TIMEOUT = aiohttp.ClientTimeout(total=10)


def get_oauth_url(state: str) -> str:
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
    }
    if DISCORD_OAUTH_PROMPT in {"none", "consent"}:
        params["prompt"] = DISCORD_OAUTH_PROMPT
    return f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"


async def exchange_code(code: str) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.post(
                f"{_API}/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_REDIRECT_URI,
                },
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
    except Exception:
        return None


async def get_user_info(access_token: str) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
    except Exception:
        return None


async def get_user_guilds(access_token: str) -> list[dict]:
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me/guilds",
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
    except Exception:
        return []


async def _get_bot_guild_ids() -> set[int]:
    if not DISCORD_BOT_TOKEN:
        logger.warning("DISCORD_BOT_TOKEN が未設定のため Bot ギルド一覧を取得できません。")
        return set()
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/users/@me/guilds",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                ids = {int(g["id"]) for g in await resp.json()}
                if not ids:
                    logger.warning("Bot がどのサーバーにも参加していません。")
                return ids
    except Exception as e:
        logger.warning("Bot ギルド一覧取得失敗: %s", e)
        return set()


_guild_count_cache: tuple[int, float] | None = None
_guild_count_lock = asyncio.Lock()
_GUILD_COUNT_TTL = 300


async def get_bot_guild_count() -> int:
    """Bot が参加しているサーバー数を返す（5分キャッシュ）。"""
    global _guild_count_cache
    now = time.time()
    if _guild_count_cache and now - _guild_count_cache[1] < _GUILD_COUNT_TTL:
        return _guild_count_cache[0]

    async with _guild_count_lock:
        now = time.time()
        if _guild_count_cache and now - _guild_count_cache[1] < _GUILD_COUNT_TTL:
            return _guild_count_cache[0]

        count = 0
        if DISCORD_BOT_TOKEN:
            try:
                async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                    async with session.get(
                        f"{_API}/users/@me/guilds?limit=200",
                        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                    ) as resp:
                        resp.raise_for_status()
                        count = len(await resp.json())
            except Exception as e:
                logger.warning("get_bot_guild_count: Discord API 失敗、フォールバックを使用: %s", e)

        if count == 0:
            try:
                from services.settings_store import get_all_guild_ids
                count = len(get_all_guild_ids())
            except Exception as e:
                logger.warning("get_bot_guild_count: settings_store フォールバックも失敗: %s", e)

        _guild_count_cache = (count, now)
        return count


async def get_admin_guilds(access_token: str) -> list[dict]:
    """ユーザーが administrator 権限を持ち、Botが参加しているギルド一覧。"""
    user_guilds, bot_ids = await asyncio.gather(
        get_user_guilds(access_token),
        _get_bot_guild_ids(),
    )
    result: list[dict[str, str | None]] = []
    for g in user_guilds:
        try:
            guild_id = int(g["id"])
            if (int(g.get("permissions", 0)) & _ADMINISTRATOR_BIT) and guild_id in bot_ids:
                icon = g.get("icon")
                result.append({
                    "id": str(guild_id),
                    "name": str(g.get("name") or "Unknown"),
                    "icon": icon if isinstance(icon, str) else None,
                })
        except (TypeError, ValueError):
            continue
    return result


async def get_guild_channels(guild_id: int) -> list[dict]:
    """テキストチャンネル (type=0) のみ返す。"""
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/guilds/{guild_id}/channels",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                return sorted(
                    [c for c in await resp.json() if c.get("type") == 0],
                    key=lambda c: c.get("position", 0),
                )
    except Exception:
        return []


async def get_guild_voice_channels(guild_id: int) -> list[dict]:
    """ボイスチャンネル (type=2) のみ返す。"""
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/guilds/{guild_id}/channels",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                return sorted(
                    [c for c in await resp.json() if c.get("type") == 2],
                    key=lambda c: c.get("position", 0),
                )
    except Exception:
        return []


_user_info_cache: dict[int, tuple[Optional[dict], float]] = {}
_user_info_cache_lock = asyncio.Lock()
_USER_INFO_CACHE_TTL = 600


async def get_discord_user(user_id: int) -> Optional[dict]:
    """DiscordユーザーIDから基本情報（表示名・アバター等）を取得する（10分キャッシュ）。

    見つからない/取得失敗時は None。設定ページで「生のユーザーID」を表示せず
    名前解決して見せるために使う（チャンネル/ロールと同様の扱いに揃える）。
    """
    now = time.time()
    cached = _user_info_cache.get(user_id)
    if cached and now - cached[1] < _USER_INFO_CACHE_TTL:
        return cached[0]

    if not DISCORD_BOT_TOKEN:
        return None

    async with _user_info_cache_lock:
        now = time.time()
        cached = _user_info_cache.get(user_id)
        if cached and now - cached[1] < _USER_INFO_CACHE_TTL:
            return cached[0]

        data: Optional[dict] = None
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.get(
                    f"{_API}/users/{user_id}",
                    headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
        except Exception as e:
            logger.warning("get_discord_user(%s) 失敗: %s", user_id, e)

        _user_info_cache[user_id] = (data, now)
        return data


async def get_discord_users(user_ids: list[int]) -> dict[int, Optional[dict]]:
    """複数ユーザーIDをまとめて解決する（並列取得、内部はキャッシュ経由）。"""
    unique_ids = list(dict.fromkeys(user_ids))
    if not unique_ids:
        return {}
    results = await asyncio.gather(*[get_discord_user(uid) for uid in unique_ids])
    return dict(zip(unique_ids, results))


async def get_guild_roles(guild_id: int) -> list[dict]:
    """管理されていないロール（@everyone 除く）を返す。"""
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(
                f"{_API}/guilds/{guild_id}/roles",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            ) as resp:
                resp.raise_for_status()
                return sorted(
                    [r for r in await resp.json() if r.get("name") != "@everyone"],
                    key=lambda r: -r.get("position", 0),
                )
    except Exception:
        return []
