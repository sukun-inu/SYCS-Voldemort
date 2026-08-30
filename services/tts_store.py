from typing import Any

from services.settings_store import (
    _get_dict_setting,
    _get_or_create_guild,
    _mutate_settings,
    _update_nested,
)


def get_tts_settings(guild_id: int) -> dict[str, Any]:
    return _get_dict_setting(guild_id, "tts")


def set_tts_enabled(guild_id: int, enabled: bool) -> None:
    _update_nested(guild_id, "tts", {"enabled": enabled})


def set_tts_channels(
    guild_id: int,
    watch_channel_ids: list[int],
    vc_channel_id: int | None,
) -> None:
    def _mutator(data: dict[str, Any]) -> None:
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            tts = {}
        tts["watch_channel_ids"] = list(watch_channel_ids)
        tts["vc_channel_id"] = vc_channel_id
        current["tts"] = tts

    _mutate_settings(_mutator)


def get_user_tts_settings(guild_id: int, user_id: int) -> dict[str, Any]:
    user_settings = get_tts_settings(guild_id).get("user_settings", {})
    if not isinstance(user_settings, dict):
        return {}
    return dict(user_settings.get(str(user_id), {}))


def set_user_tts_settings(
    guild_id: int,
    user_id: int,
    *,
    voice: str | None = None,
    rate: int | None = None,
) -> None:
    def _mutator(data: dict[str, Any]) -> None:
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            tts = {}
        user_settings = tts.get("user_settings", {})
        if not isinstance(user_settings, dict):
            user_settings = {}
        entry = dict(user_settings.get(str(user_id), {}))
        if voice is not None:
            entry["voice"] = voice
        if rate is not None:
            entry["rate"] = rate
        user_settings[str(user_id)] = entry
        tts["user_settings"] = user_settings
        current["tts"] = tts

    _mutate_settings(_mutator)


def reset_user_tts_settings(guild_id: int, user_id: int) -> None:
    def _mutator(data: dict[str, Any]) -> None:
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            return
        user_settings = tts.get("user_settings", {})
        if isinstance(user_settings, dict):
            user_settings.pop(str(user_id), None)
        tts["user_settings"] = user_settings
        current["tts"] = tts

    _mutate_settings(_mutator)


def get_tts_dictionary(guild_id: int) -> dict[str, str]:
    d = get_tts_settings(guild_id).get("dictionary", {})
    if not isinstance(d, dict):
        return {}
    return {str(k): str(v) for k, v in d.items()}


def add_tts_dictionary_entry(guild_id: int, word: str, reading: str) -> None:
    def _mutator(data: dict[str, Any]) -> None:
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            tts = {}
        d = tts.get("dictionary", {})
        if not isinstance(d, dict):
            d = {}
        d[word] = reading
        tts["dictionary"] = d
        current["tts"] = tts

    _mutate_settings(_mutator)


def remove_tts_dictionary_entry(guild_id: int, word: str) -> bool:
    def _mutator(data: dict[str, Any]) -> bool:
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            return False
        d = tts.get("dictionary", {})
        if not isinstance(d, dict) or word not in d:
            return False
        del d[word]
        tts["dictionary"] = d
        current["tts"] = tts
        return True

    return _mutate_settings(_mutator)


def set_tts_default_voice(guild_id: int, voice: str) -> None:
    _update_nested(guild_id, "tts", {"default_voice": voice})


def set_tts_default_rate(guild_id: int, rate: int) -> None:
    _update_nested(guild_id, "tts", {"default_rate": rate})


def set_tts_max_lengths(guild_id: int, max_length: int, speak_max_length: int) -> None:
    _update_nested(guild_id, "tts", {"max_length": max_length, "speak_max_length": speak_max_length})


def set_tts_read_name(guild_id: int, read_name: bool) -> None:
    _update_nested(guild_id, "tts", {"read_name": read_name})


def set_tts_vc_notify(guild_id: int, enabled: bool) -> None:
    _update_nested(guild_id, "tts", {"vc_notify": enabled})
