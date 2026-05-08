import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

# メモリ内キャッシュ。ファイル署名（mtime_ns + size）が変わったら自動無効化するため、
# Bot と WebUI が別プロセスでもファイル更新を検知できる。
_cache: dict[str, Any] | None = None
_cache_sig: tuple[int, int] | None = None


def _file_signature() -> tuple[int, int] | None:
    try:
        stat = _SETTINGS_FILE.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _load_all() -> dict[str, Any]:
    global _cache, _cache_sig
    sig = _file_signature()
    if _cache is not None and sig == _cache_sig:
        return _cache

    if sig is None:
        _cache = {"guilds": {}}
        _cache_sig = sig
        return _cache

    try:
        data = _json.loads(_SETTINGS_FILE.read_bytes())
    except Exception:
        _cache = {"guilds": {}}
        _cache_sig = sig
        return _cache

    if not isinstance(data, dict):
        _cache = {"guilds": {}}
        _cache_sig = sig
        return _cache

    data.setdefault("guilds", {})
    if not isinstance(data["guilds"], dict):
        data["guilds"] = {}

    _cache = data
    _cache_sig = sig
    return _cache


def _save_all(data: dict[str, Any]) -> None:
    global _cache, _cache_sig
    _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)

    # アトミック書き込み: クラッシュ時に settings.json が壊れるのを防ぐ。
    tmp = _SETTINGS_FILE.with_suffix(".json.tmp")
    if _ORJSON:
        tmp.write_bytes(_json.dumps(data, option=_json.OPT_INDENT_2))  # type: ignore[attr-defined]
    else:
        tmp.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(_SETTINGS_FILE)

    _cache = data
    _cache_sig = _file_signature()


def get_guild_settings(guild_id: int) -> dict[str, Any]:
    """指定ギルドの設定を取得（存在しない場合は空 dict）。"""
    guilds: dict[str, Any] = _load_all().get("guilds", {})  # type: ignore[assignment]
    return dict(guilds.get(str(guild_id), {}))


def update_guild_settings(guild_id: int, updates: dict[str, Any]) -> dict[str, Any]:
    """指定ギルドの設定を更新し、保存してから最新状態を返す。"""
    data = _load_all()
    guilds: dict[str, Any] = data.setdefault("guilds", {})  # type: ignore[assignment]
    current = guilds.get(str(guild_id), {})
    if not isinstance(current, dict):
        current = {}
    current.update(updates)
    guilds[str(guild_id)] = current
    _save_all(data)
    return dict(current)


def _update_nested(guild_id: int, top_key: str, patch: dict[str, Any]) -> None:
    s = get_guild_settings(guild_id).get(top_key, {})
    if not isinstance(s, dict):
        s = {}
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


def set_response_channel_id(guild_id: int, channel_id: int | None) -> dict[str, Any]:
    """ChatGPT応答チャンネルIDを設定/解除。"""
    return update_guild_settings(guild_id, {"response_channel_id": channel_id})


def get_trusted_user_ids(guild_id: int) -> list[int]:
    return _parse_id_list(get_guild_settings(guild_id).get("trusted_user_ids"))


def set_trusted_user_ids(guild_id: int, ids: list[int]) -> dict[str, Any]:
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


def set_bypass_role_ids(guild_id: int, role_ids: list[int]) -> dict[str, Any]:
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

def get_welcome_settings(guild_id: int) -> dict[str, Any]:
    return dict(get_guild_settings(guild_id).get("welcome", {}))


def set_welcome_channel(guild_id: int, channel_id: int | None) -> None:
    _update_nested(guild_id, "welcome", {"channel_id": channel_id})


def set_welcome_message(guild_id: int, message: str | None) -> None:
    _update_nested(guild_id, "welcome", {"message": message})


def get_goodbye_settings(guild_id: int) -> dict[str, Any]:
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


def get_vc_notify_role_id(guild_id: int) -> int:
    """VC通知時にメンションするロールIDを取得（未設定なら0）。"""
    value = get_guild_settings(guild_id).get("vc_notify_role_id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def set_vc_notify_role_id(guild_id: int, role_id: int | None) -> None:
    update_guild_settings(guild_id, {"vc_notify_role_id": role_id})


# ──────────────────────────────────────────────
# スティッキーメッセージ
# ──────────────────────────────────────────────

def get_sticky_messages(guild_id: int) -> dict[str, Any]:
    """channel_id(str) → {"content": str, "message_id": int|None}"""
    return dict(get_guild_settings(guild_id).get("sticky_messages", {}))


def set_sticky_message(guild_id: int, channel_id: int, content: str) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    key = str(channel_id)
    existing = stickies.get(key, {})
    stickies[key] = {
        "content": content,
        "message_id": existing.get("message_id"),
        "pending": "post",
    }
    update_guild_settings(guild_id, {"sticky_messages": stickies})


def update_sticky_message_id(guild_id: int, channel_id: int, message_id: int | None) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    key = str(channel_id)
    if key in stickies:
        stickies[key]["message_id"] = message_id
        stickies[key].pop("pending", None)
        update_guild_settings(guild_id, {"sticky_messages": stickies})


def mark_sticky_pending_delete(guild_id: int, channel_id: int) -> None:
    """削除待ちフラグを立てる。Botの定期タスクがDiscordメッセージを削除した後エントリを消す。"""
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    key = str(channel_id)
    if key in stickies:
        stickies[key]["pending"] = "delete"
        update_guild_settings(guild_id, {"sticky_messages": stickies})


def remove_sticky_message(guild_id: int, channel_id: int) -> None:
    stickies = get_guild_settings(guild_id).get("sticky_messages", {})
    stickies.pop(str(channel_id), None)
    update_guild_settings(guild_id, {"sticky_messages": stickies})


# ──────────────────────────────────────────────
# リアクションロール
# ──────────────────────────────────────────────

def get_reaction_roles(guild_id: int) -> dict[str, Any]:
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
    guilds: dict[str, Any] = _load_all().get("guilds", {})
    result: list[int] = []
    for k in guilds:
        try:
            result.append(int(k))
        except (TypeError, ValueError):
            continue
    return result


def get_news_feeds(guild_id: int) -> dict[str, Any]:
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


def update_news_feed(guild_id: int, feed_id: str, channel_id: int, query: str, interval_minutes: int) -> bool:
    """フィードの設定（チャンネル・クエリ・間隔）を更新する。seen_hashes と last_run は保持する。"""
    feeds = get_guild_settings(guild_id).get("news_feeds", {})
    if feed_id not in feeds:
        return False
    feeds[feed_id].update({"channel_id": channel_id, "query": query, "interval": interval_minutes})
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

def get_earthquake_settings(guild_id: int) -> dict[str, Any]:
    return dict(get_guild_settings(guild_id).get("earthquake", {}))


def set_earthquake_channel(guild_id: int, channel_id: int | None) -> None:
    _update_nested(guild_id, "earthquake", {"channel_id": channel_id})


def set_earthquake_min_scale(guild_id: int, scale: int) -> None:
    _update_nested(guild_id, "earthquake", {"min_scale": scale})


def set_earthquake_last_event_id(guild_id: int, event_id: str) -> None:
    _update_nested(guild_id, "earthquake", {"last_event_id": event_id})


# ──────────────────────────────────────────────
# 地震通知タイプ
# ──────────────────────────────────────────────

_NOTIFY_TYPE_KEYS: frozenset[str] = frozenset(
    {"eew_forecast", "eew_warning", "tsunami", "quake_info", "bot_news"}
)


def get_earthquake_notify_types(guild_id: int) -> dict[str, bool]:
    """通知タイプ設定を取得。未設定キーはデフォルト True（有効）。"""
    stored = get_earthquake_settings(guild_id).get("notify_types", {})
    return {k: bool(stored.get(k, True)) for k in _NOTIFY_TYPE_KEYS}


def set_earthquake_notify_types(guild_id: int, types: dict[str, bool]) -> None:
    """通知タイプ設定を保存。有効なキーのみ受け付ける。"""
    patch = {k: bool(v) for k, v in types.items() if k in _NOTIFY_TYPE_KEYS}
    _update_nested(guild_id, "earthquake", {"notify_types": patch})


# ──────────────────────────────────────────────
# DJAudio-DL 監視チャンネル
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class DJAudioRuntimeSettings:
    watch_channel_id: int
    cache_ttl: int
    cooldown: int
    max_urls: int


def _read_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _get_djaudio_top_level(guild_settings: dict[str, Any], key: str) -> Any:
    if key in guild_settings:
        return guild_settings.get(key)
    return guild_settings.get(f"djaudio_{key}")


def get_djaudio_watch_channel(guild_id: int) -> int:
    """URL監視チャンネルIDを取得（未設定なら0）。"""
    guild_settings = get_guild_settings(guild_id)
    nested = guild_settings.get("djaudio", {})
    if not isinstance(nested, dict):
        nested = {}

    candidates = (
        guild_settings.get("djaudio_watch_channel_id"),
        guild_settings.get("djaudio_watch_channel"),
        nested.get("watch_channel_id"),
        nested.get("channel_id"),
    )
    for value in candidates:
        parsed = _read_int(value)
        if parsed and parsed > 0:
            return parsed
    return 0


def set_djaudio_watch_channel(guild_id: int, channel_id: int | None) -> None:
    """URL監視チャンネルIDを設定/解除。"""
    nested = get_djaudio_settings(guild_id)
    nested["watch_channel_id"] = channel_id
    update_guild_settings(
        guild_id,
        {
            "djaudio_watch_channel_id": channel_id,
            "djaudio_watch_channel": channel_id,  # legacy 互換
            "djaudio": nested,
        },
    )


def get_djaudio_settings(guild_id: int) -> dict[str, Any]:
    """DJAudio の詳細設定を取得。"""
    guild_settings = get_guild_settings(guild_id)
    nested = guild_settings.get("djaudio", {})
    if not isinstance(nested, dict):
        nested = {}

    result = dict(nested)
    if "cache_ttl" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "cache_ttl")
        if legacy is not None:
            result["cache_ttl"] = legacy
    if "cooldown" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "cooldown")
        if legacy is not None:
            result["cooldown"] = legacy
    if "max_urls" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "max_urls")
        if legacy is not None:
            result["max_urls"] = legacy
    return result


def set_djaudio_settings(guild_id: int, patch: dict[str, Any]) -> None:
    """DJAudio の詳細設定を更新。"""
    normalized: dict[str, int] = {}
    if "cache_ttl" in patch:
        value = _read_int(patch.get("cache_ttl"))
        if value is not None:
            normalized["cache_ttl"] = max(60, min(86400, value))
    if "cooldown" in patch:
        value = _read_int(patch.get("cooldown"))
        if value is not None:
            normalized["cooldown"] = max(0, min(3600, value))
    if "max_urls" in patch:
        value = _read_int(patch.get("max_urls"))
        if value is not None:
            normalized["max_urls"] = max(1, min(10, value))

    if not normalized:
        return

    existing = get_djaudio_settings(guild_id)
    existing.update(normalized)
    update_guild_settings(
        guild_id,
        {
            "djaudio": existing,
            "djaudio_cache_ttl": existing.get("cache_ttl"),  # legacy 互換
            "djaudio_cooldown": existing.get("cooldown"),
            "djaudio_max_urls": existing.get("max_urls"),
        },
    )


_DJAUDIO_DEFAULTS: dict[str, int] = {
    "cache_ttl":  600,
    "cooldown":   30,
    "max_urls":   3,
}


def get_djaudio_cache_ttl(guild_id: int) -> int:
    """キャッシュ有効期間（秒）を取得。未設定なら環境変数 or デフォルト 600。"""
    stored = get_djaudio_settings(guild_id).get("cache_ttl")
    try:
        return max(60, int(stored))
    except (TypeError, ValueError):
        from config import DJAUDIO_CACHE_TTL
        return DJAUDIO_CACHE_TTL


def get_djaudio_cooldown(guild_id: int) -> int:
    """ユーザークールダウン（秒）を取得。未設定なら環境変数 or デフォルト 30。"""
    stored = get_djaudio_settings(guild_id).get("cooldown")
    try:
        return max(0, int(stored))
    except (TypeError, ValueError):
        from config import DJAUDIO_COOLDOWN
        return DJAUDIO_COOLDOWN


def get_djaudio_max_urls(guild_id: int) -> int:
    """1メッセージあたりのURL上限を取得。未設定なら環境変数 or デフォルト 3。"""
    stored = get_djaudio_settings(guild_id).get("max_urls")
    try:
        return max(1, min(10, int(stored)))
    except (TypeError, ValueError):
        from config import DJAUDIO_MAX_URLS
        return DJAUDIO_MAX_URLS


def get_djaudio_runtime_settings(guild_id: int) -> DJAudioRuntimeSettings:
    """DJAudio 実行時に使う設定をまとめて返す。"""
    return DJAudioRuntimeSettings(
        watch_channel_id=get_djaudio_watch_channel(guild_id),
        cache_ttl=get_djaudio_cache_ttl(guild_id),
        cooldown=get_djaudio_cooldown(guild_id),
        max_urls=get_djaudio_max_urls(guild_id),
    )
