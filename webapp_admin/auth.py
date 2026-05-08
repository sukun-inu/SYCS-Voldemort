import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode

import requests as req

logger = logging.getLogger(__name__)

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://localhost:5001/admin/callback")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

_API = "https://discord.com/api/v10"
_SCOPES = "identify guilds"
_ADMINISTRATOR_BIT = 0x8

_TIMEOUT = 10


def get_oauth_url(state: str) -> str:
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
        "prompt": "none",
    }
    return f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"


def exchange_code(code: str) -> Optional[dict]:
    try:
        resp = req.post(
            f"{_API}/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def get_user_info(access_token: str) -> Optional[dict]:
    try:
        resp = req.get(
            f"{_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def get_user_guilds(access_token: str) -> list[dict]:
    try:
        resp = req.get(
            f"{_API}/users/@me/guilds",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return []


def _get_bot_guild_ids() -> set[int]:
    try:
        resp = req.get(
            f"{_API}/users/@me/guilds",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return {int(g["id"]) for g in resp.json()}
    except Exception:
        return set()


_guild_count_cache: tuple[int, float] | None = None
_GUILD_COUNT_TTL = 300  # 5分キャッシュ


def get_bot_guild_count() -> int:
    """Bot が参加しているサーバー数を返す（5分キャッシュ）。"""
    global _guild_count_cache
    now = time.time()
    if _guild_count_cache and now - _guild_count_cache[1] < _GUILD_COUNT_TTL:
        return _guild_count_cache[0]

    count = 0
    if DISCORD_BOT_TOKEN:
        try:
            resp = req.get(
                f"{_API}/users/@me/guilds?limit=200",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            count = len(resp.json())
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


def get_admin_guilds(access_token: str) -> list[dict]:
    """ユーザーが administrator 権限を持ち、Botが参加しているギルド一覧。"""
    user_guilds = get_user_guilds(access_token)
    bot_ids = _get_bot_guild_ids()
    result = []
    for g in user_guilds:
        try:
            if (int(g.get("permissions", 0)) & _ADMINISTRATOR_BIT) and int(g["id"]) in bot_ids:
                result.append(g)
        except (TypeError, ValueError):
            continue
    return result


def get_guild_channels(guild_id: int) -> list[dict]:
    """テキストチャンネル (type=0) のみ返す。"""
    try:
        resp = req.get(
            f"{_API}/guilds/{guild_id}/channels",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return sorted(
            [c for c in resp.json() if c.get("type") == 0],
            key=lambda c: c.get("position", 0),
        )
    except Exception:
        return []


def get_guild_roles(guild_id: int) -> list[dict]:
    """管理されていないロール（@everyone 除く）を返す。"""
    try:
        resp = req.get(
            f"{_API}/guilds/{guild_id}/roles",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return sorted(
            [r for r in resp.json() if r.get("name") != "@everyone"],
            key=lambda r: -r.get("position", 0),
        )
    except Exception:
        return []
