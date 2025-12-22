from pathlib import Path
from typing import Any, Dict

try:
    import orjson as _json
except ImportError:  # フォールバック（orjson が入っていない場合）
    import json as _json  # type: ignore


# プロジェクトルート直下に settings.json を作成
_SETTINGS_FILE = Path(__file__).resolve().parent.parent / "settings.json"


def _load_all() -> Dict[str, Any]:
    """settings.json 全体を読み込む。壊れている場合はデフォルト構造を返す。"""
    if not _SETTINGS_FILE.exists():
        return {"guilds": {}}

    try:
        raw = _SETTINGS_FILE.read_bytes()
        data = _json.loads(raw)
    except Exception:
        # 壊れていた場合は初期化
        return {"guilds": {}}

    if not isinstance(data, dict):
        return {"guilds": {}}

    data.setdefault("guilds", {})
    if not isinstance(data["guilds"], dict):
        data["guilds"] = {}

    return data


def _save_all(data: Dict[str, Any]) -> None:
    """settings.json 全体を書き出す。"""
    if hasattr(_json, "dumps") and _json.__name__ == "orjson":  # type: ignore[attr-defined]
        _SETTINGS_FILE.write_bytes(_json.dumps(data, option=_json.OPT_INDENT_2))  # type: ignore[attr-defined]
    else:
        text = _json.dumps(data, indent=2, ensure_ascii=False)
        _SETTINGS_FILE.write_text(text, encoding="utf-8")


def get_guild_settings(guild_id: int) -> Dict[str, Any]:
    """指定ギルドの設定を取得（存在しない場合は空 dict）。"""
    data = _load_all()
    guilds: Dict[str, Any] = data.get("guilds", {})  # type: ignore[assignment]
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
    settings = get_guild_settings(guild_id)
    value = settings.get("response_channel_id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def set_response_channel_id(guild_id: int, channel_id: int | None) -> Dict[str, Any]:
    """ChatGPT応答チャンネルIDを設定/解除。"""
    return update_guild_settings(guild_id, {"response_channel_id": channel_id})


def get_trusted_user_ids(guild_id: int) -> list[int]:
    """信頼済みユーザーIDのリストを取得。"""
    settings = get_guild_settings(guild_id)
    ids = settings.get("trusted_user_ids") or []
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
    # JSONに素直に書けるようにintのリストとして保存
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
    settings = get_guild_settings(guild_id)
    ids = settings.get("bypass_role_ids") or []
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
