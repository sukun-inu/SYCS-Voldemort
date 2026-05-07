import os
from pathlib import Path
from typing import Any, Dict

try:
    import orjson as _json
    _ORJSON = True
except ImportError:
    import json as _json  # type: ignore
    _ORJSON = False

# Docker: ./data:/app/data がボリュームマウントされるため /app/data 配下に保存。
# SETTINGS_DIR 環境変数で上書き可能（ローカル開発用）。
_default_dir = Path(__file__).resolve().parent.parent / "data"
_SETTINGS_DIR = Path(os.getenv("SETTINGS_DIR", str(_default_dir)))
_SETTINGS_FILE = _SETTINGS_DIR / "settings.json"

# メモリ内ライトスルーキャッシュ。
# asyncio はシングルスレッドのため Lock 不要。
_cache: Dict[str, Any] | None = None


def _load_all() -> Dict[str, Any]:
    global _cache
    if _cache is not None:
        return _cache

    if not _SETTINGS_FILE.exists():
        _cache = {"guilds": {}}
        return _cache

    try:
        data = _json.loads(_SETTINGS_FILE.read_bytes())
    except Exception:
        _cache = {"guilds": {}}
        return _cache

    if not isinstance(data, dict):
        _cache = {"guilds": {}}
        return _cache

    data.setdefault("guilds", {})
    if not isinstance(data["guilds"], dict):
        data["guilds"] = {}

    _cache = data
    return _cache


def _save_all(data: Dict[str, Any]) -> None:
    global _cache
    _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)

    # アトミック書き込み: 一時ファイルに書いてからリネーム。
    # クラッシュ時に settings.json が壊れるのを防ぐ。
    tmp = _SETTINGS_FILE.with_suffix(".json.tmp")
    if _ORJSON:
        tmp.write_bytes(_json.dumps(data, option=_json.OPT_INDENT_2))  # type: ignore[attr-defined]
    else:
        tmp.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(_SETTINGS_FILE)

    _cache = data


def get_guild_settings(guild_id: int) -> Dict[str, Any]:
    """指定ギルドの設定を取得（存在しない場合は空 dict）。"""
    guilds: Dict[str, Any] = _load_all().get("guilds", {})  # type: ignore[assignment]
    return dict(guilds.get(str(guild_id), {}))


def update_guild_settings(guild_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
    """指定ギルドの設定を更新し、保存してから最新状態を返す。"""
    data = _load_all()
    guilds: Dict[str, Any] = data.setdefault("guilds", {})  # type: ignore[assignment]
    current = guilds.get(str(guild_id), {})
    if not isinstance(current, dict):
        current = {}
    current.update(updates)
    guilds[str(guild_id)] = current
    _save_all(data)
    return dict(current)


def _update_nested(guild_id: int, top_key: str, patch: Dict[str, Any]) -> None:
    s = get_guild_settings(guild_id).get(top_key, {})
    s.update(patch)
    update_guild_settings(guild_id, {top_key: s})


def _parse_id_list(raw: Any) -> list[int]:
    if not isinstance(raw, list):
        return []
    result: list[int] = []
    for v in raw:
        try:
            result.append(int(v))
        except (TypeError, ValueError):
            continue
    return result


def get_response_channel_id(guild_id: int) -> int:
    """ChatGPT応答チャンネルIDを取得（未設定なら0を返す）。"""
    value = get_guild_settings(guild_id).get("response_channel_id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def set_response_channel_id(guild_id: int, channel_id: int | None) -> Dict[str, Any]:
    """ChatGPT応答チャンネルIDを設定/解除。"""
    return update_guild_settings(guild_id, {"response_channel_id": channel_id})


def get_trusted_user_ids(guild_id: int) -> list[int]:
    return _parse_id_list(get_guild_settings(guild_id).get("trusted_user_ids"))


def set_trusted_user_ids(guild_id: int, ids: list[int]) -> Dict[str, Any]:
    """信頼済みユーザーIDのリストを設定。"""
    return update_guild_settings(guild_id, {"trusted_user_ids": list({int(i) for i in ids})})


def add_trusted_users(guild_id: int, user_ids: list[int]) -> list[int]:
    """信頼済みユーザーに追加して、最新のリストを返す。"""
    current = set(get_trusted_user_ids(guild_id))
    current.update(int(i) for i in user_ids)
    set_trusted_user_ids(guild_id, list(current))
    return sorted(current)


def remove_trusted_users(guild_id: int, user_ids: list[int]) -> list[int]:
    """信頼済みユーザーから削除して、最新のリストを返す。"""
    current = set(get_trusted_user_ids(guild_id))
    for i in user_ids:
        try:
            current.discard(int(i))
        except (TypeError, ValueError):
            continue
    set_trusted_user_ids(guild_id, list(current))
    return sorted(current)


def get_bypass_role_ids(guild_id: int) -> list[int]:
    return _parse_id_list(get_guild_settings(guild_id).get("bypass_role_ids"))


def set_bypass_role_ids(guild_id: int, role_ids: list[int]) -> Dict[str, Any]:
    """セキュリティチェックをバイパスするロールIDを設定。"""
    return update_guild_settings(guild_id, {"bypass_role_ids": list({int(i) for i in role_ids})})


def add_bypass_roles(guild_id: int, role_ids: list[int]) -> list[int]:
    """バイパス対象ロールに追加し、最新のリストを返す。"""
    current = set(get_bypass_role_ids(guild_id))
    current.update(int(i) for i in role_ids)
    set_bypass_role_ids(guild_id, list(current))
    return sorted(current)


def remove_bypass_roles(guild_id: int, role_ids: list[int]) -> list[int]:
    """バイパス対象ロールから削除し、最新のリストを返す。"""
    current = set(get_bypass_role_ids(guild_id))
    for i in role_ids:
        try:
            current.discard(int(i))
        except (TypeError, ValueError):
            continue
    set_bypass_role_ids(guild_id, list(current))
    return sorted(current)


# ──────────────────────────────────────────────
# ウェルカム / グッバイ
# ──────────────────────────────────────────────

def get_welcome_settings(guild_id: int) -> Dict[str, Any]:
    return dict(get_guild_settings(guild_id).get("welcome", {}))


def set_welcome_channel(guild_id: int, channel_id: int | None) -> None:
    _update_nested(guild_id, "welcome", {"channel_id": channel_id})


def set_welcome_message(guild_id: int, message: str | None) -> None:
    _update_nested(guild_id, "welcome", {"message": message})


def get_goodbye_settings(guild_id: int) -> Dict[str, Any]:
    return dict(get_guild_settings(guild_id).get("goodbye", {}))


def set_goodbye_channel(guild_id: int, channel_id: int | None) -> None:
    _update_nested(guild_id, "goodbye", {"channel_id": channel_id})


def set_goodbye_message(guild_id: int, message: str | None) -> None:
    _update_nested(guild_id, "goodbye", {"message": message})


# ──────────────────────────────────────────────
# VC 通知チャンネル
# ──────────────────────────────────────────────

def get_vc_notify_channel_id(guild_id: int) -> int:
    value = get_guild_settings(guild_id).get("vc_notify_channel_id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def set_vc_notify_channel_id(guild_id: int, channel_id: int | None) -> None:
    update_guild_settings(guild_id, {"vc_notify_channel_id": channel_id})


# ──────────────────────────────────────────────
# スティッキーメッセージ
# ──────────────────────────────────────────────

def get_sticky_messages(guild_id: int) -> Dict[str, Any]:
    """channel_id(str) → {"content": str, "message_id": int|None}"""
    return dict(get_guild_settings(guild_id).get("sticky_messages", {}))


def set_sticky_message(guild_id: int, channel_id: int, content: str) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    stickies[str(channel_id)] = {"content": content, "message_id": None}
    update_guild_settings(guild_id, {"sticky_messages": stickies})


def update_sticky_message_id(guild_id: int, channel_id: int, message_id: int | None) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    key = str(channel_id)
    if key in stickies:
        stickies[key]["message_id"] = message_id
        update_guild_settings(guild_id, {"sticky_messages": stickies})


def remove_sticky_message(guild_id: int, channel_id: int) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    stickies.pop(str(channel_id), None)
    update_guild_settings(guild_id, {"sticky_messages": stickies})


# ──────────────────────────────────────────────
# リアクションロール
# ──────────────────────────────────────────────

def get_reaction_roles(guild_id: int) -> Dict[str, Any]:
    """message_id(str) → {emoji(str) → role_id(int)}"""
    return dict(get_guild_settings(guild_id).get("reaction_roles", {}))


def add_reaction_role(guild_id: int, message_id: int, emoji: str, role_id: int) -> None:
    rr = get_guild_settings(guild_id).get("reaction_roles", {})
    key = str(message_id)
    rr.setdefault(key, {})[emoji] = role_id
    update_guild_settings(guild_id, {"reaction_roles": rr})


def remove_reaction_role(guild_id: int, message_id: int, emoji: str) -> bool:
    rr = get_guild_settings(guild_id).get("reaction_roles", {})
    key = str(message_id)
    if key not in rr or emoji not in rr[key]:
        return False
    del rr[key][emoji]
    if not rr[key]:
        del rr[key]
    update_guild_settings(guild_id, {"reaction_roles": rr})
    return True


# ──────────────────────────────────────────────
# ニュースフィード
# ──────────────────────────────────────────────

def get_all_guild_ids() -> list[int]:
    guilds: Dict[str, Any] = _load_all().get("guilds", {})
    result: list[int] = []
    for k in guilds:
        try:
            result.append(int(k))
        except (TypeError, ValueError):
            continue
    return result


def get_news_feeds(guild_id: int) -> Dict[str, Any]:
    """feed_id(str) → {"channel_id": int, "query": str, "interval": int, "last_run": float, "seen_hashes": list}"""
    return dict(get_guild_settings(guild_id).get("news_feeds", {}))


def add_news_feed(guild_id: int, feed_id: str, channel_id: int, query: str, interval_minutes: int) -> None:
    feeds = get_guild_settings(guild_id).get("news_feeds", {})
    feeds[feed_id] = {
        "channel_id": channel_id,
        "query": query,
        "interval": interval_minutes,
        "last_run": 0.0,
        "seen_hashes": [],
    }
    update_guild_settings(guild_id, {"news_feeds": feeds})


def remove_news_feed(guild_id: int, feed_id: str) -> bool:
    feeds = get_guild_settings(guild_id).get("news_feeds", {})
    if feed_id not in feeds:
        return False
    del feeds[feed_id]
    update_guild_settings(guild_id, {"news_feeds": feeds})
    return True


def update_news_feed_state(guild_id: int, feed_id: str, last_run: float, seen_hashes: list) -> None:
    feeds = get_guild_settings(guild_id).get("news_feeds", {})
    if feed_id not in feeds:
        return
    feeds[feed_id]["last_run"] = last_run
    feeds[feed_id]["seen_hashes"] = seen_hashes[-100:]
    update_guild_settings(guild_id, {"news_feeds": feeds})


# ──────────────────────────────────────────────
# 地震アラート
# ──────────────────────────────────────────────

def get_earthquake_settings(guild_id: int) -> Dict[str, Any]:
    return dict(get_guild_settings(guild_id).get("earthquake", {}))


def set_earthquake_channel(guild_id: int, channel_id: int | None) -> None:
    _update_nested(guild_id, "earthquake", {"channel_id": channel_id})


def set_earthquake_min_scale(guild_id: int, scale: int) -> None:
    _update_nested(guild_id, "earthquake", {"min_scale": scale})


def set_earthquake_last_event_id(guild_id: int, event_id: str) -> None:
    _update_nested(guild_id, "earthquake", {"last_event_id": event_id})
