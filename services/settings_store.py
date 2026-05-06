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
    """信頼済みユーザーIDのリストを取得。"""
    ids = get_guild_settings(guild_id).get("trusted_user_ids") or []
    if not isinstance(ids, list):
        return []
    result: list[int] = []
    for v in ids:
        try:
            result.append(int(v))
        except (TypeError, ValueError):
            continue
    return result


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
    """セキュリティチェックをバイパスするロールIDのリストを取得。"""
    ids = get_guild_settings(guild_id).get("bypass_role_ids") or []
    if not isinstance(ids, list):
        return []
    result: list[int] = []
    for v in ids:
        try:
            result.append(int(v))
        except (TypeError, ValueError):
            continue
    return result


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
