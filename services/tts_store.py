from typing import Any

from services.settings_store import (
    _get_dict_setting,
    _get_or_create_guild,
    _mutate_settings,
    _update_nested,
)


def get_tts_settings(guild_id: int) -> dict[str, Any]:
    """tts ブロック（enabled, watch_channel_ids, vc_channel_id, user_settings,
    dictionary 等）を返す。未設定なら空 dict。
    """
    return _get_dict_setting(guild_id, "tts")


def set_tts_enabled(guild_id: int, enabled: bool) -> None:
    """読み上げ機能そのものを有効/無効にする。監視チャンネルやVCの設定は
    そのまま保持されるので、無効化しても再設定なしで戻せる。
    """
    _update_nested(guild_id, "tts", {"enabled": enabled})


def set_tts_channels(
    guild_id: int,
    watch_channel_ids: list[int],
    vc_channel_id: int | None,
) -> None:
    """監視チャンネル一覧と接続先VCをまとめて設定する。

    個別のsetterに分けていないのは、2つを常にセットで扱うため。片方だけ
    変えられると「監視はしているのに読み上げ先VCが無い」ような不整合が
    作れてしまう。
    """

    def _mutator(data: dict[str, Any]) -> None:
        """watch_channel_ids・vc_channel_id を丸ごと置き換える。既存の値との
        マージはしない。
        """
        current = _get_or_create_guild(data, guild_id)
        tts = current.get("tts", {})
        if not isinstance(tts, dict):
            tts = {}
        tts["watch_channel_ids"] = list(watch_channel_ids)
        tts["vc_channel_id"] = vc_channel_id
        current["tts"] = tts

    _mutate_settings(_mutator)


def get_user_tts_settings(guild_id: int, user_id: int) -> dict[str, Any]:
    """そのユーザー個別の声・速度の上書き設定を返す。未設定なら空 dict
    （呼び出し側はギルド既定値へフォールバックする前提で読む）。
    """
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
    """ユーザー個別の声・速度を設定する。voice/rate は None を渡すと
    その項目だけ変更しない（両方そろえなくても片方だけ更新できる）。
    """

    def _mutator(data: dict[str, Any]) -> None:
        """指定ユーザーの既存エントリを土台に、voice/rate のうち渡された
        ものだけを上書きする。
        """
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
    """ユーザー個別設定を削除し、ギルド既定値に戻す。"""

    def _mutator(data: dict[str, Any]) -> None:
        """user_settings から該当ユーザーのエントリを削除する。tts ブロックが
        まだ無い場合は何もしない。
        """
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
    """読み方辞書（単語→読み）を返す。キー・値とも文字列であることを
    保証して返す（保存形式が壊れていても呼び出し側の型を守る）。
    """
    d = get_tts_settings(guild_id).get("dictionary", {})
    if not isinstance(d, dict):
        return {}
    return {str(k): str(v) for k, v in d.items()}


def add_tts_dictionary_entry(guild_id: int, word: str, reading: str) -> None:
    """辞書に単語を1件登録する。同じ単語が既にあれば読みを上書きする。"""

    def _mutator(data: dict[str, Any]) -> None:
        """dictionary に word: reading を1件追加/上書きする。"""
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
    """辞書から単語を1件削除する。存在しなければ何もせず False を返す。"""

    def _mutator(data: dict[str, Any]) -> bool:
        """word が登録されているときだけ削除し、真偽値で結果を伝える。"""
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
    """このギルドの既定の読み上げ音声を設定する。ユーザー個別設定が
    無い人はここを使う。
    """
    _update_nested(guild_id, "tts", {"default_voice": voice})


def set_tts_default_rate(guild_id: int, rate: int) -> None:
    """このギルドの既定の読み上げ速度を設定する。"""
    _update_nested(guild_id, "tts", {"default_rate": rate})


def set_tts_max_lengths(guild_id: int, max_length: int, speak_max_length: int) -> None:
    """読み上げるメッセージの最大文字数を、表示用(max_length)と実際に
    読み上げる範囲(speak_max_length)とで別々に設定する。

    長文をそのまま読み上げると1メッセージで数十秒拘束されるため、
    読み上げ側だけ短く切れるようにしてある。
    """
    _update_nested(guild_id, "tts", {"max_length": max_length, "speak_max_length": speak_max_length})


def set_tts_read_name(guild_id: int, read_name: bool) -> None:
    """発言者名を先頭に読み上げるかどうかを設定する。"""
    _update_nested(guild_id, "tts", {"read_name": read_name})


def set_tts_vc_notify(guild_id: int, enabled: bool) -> None:
    """VCへの入退室を読み上げで通知するかどうかを設定する。"""
    _update_nested(guild_id, "tts", {"vc_notify": enabled})
