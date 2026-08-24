"""DJAudio-DL パネル。"""

from __future__ import annotations

from services.settings_store import (
    get_djaudio_cache_ttl,
    get_djaudio_cooldown,
    get_djaudio_max_urls,
    get_djaudio_output_channel,
    get_djaudio_watch_channel,
    set_djaudio_output_channel,
    set_djaudio_settings,
    set_djaudio_watch_channel,
)
from webapp_admin.schema.duration import DAY, MINUTE
from webapp_admin.schema.types import Field, Panel, Section, Widget


def _watch_channel(guild_id: int):
    return get_djaudio_watch_channel(guild_id) or None


def _output_channel(guild_id: int):
    return get_djaudio_output_channel(guild_id) or None


# 数値3項目は set_djaudio_settings() が一括で受け取る形なので、
# 1項目ずつのパッチに直して渡す（正規化・上下限は store 側にもある）。
def _set_limit(key: str):
    def setter(guild_id: int, value) -> None:
        set_djaudio_settings(guild_id, {key: int(value)})

    return setter


PANEL = Panel(
    id="djaudio",
    title="DJAudio-DL",
    icon="bi-music-note-beamed",
    group="メディア",
    path="/admin/settings/djaudio",
    sections=(
        Section(
            "チャンネル",
            fields=(
                Field(
                    "channel_id", "URL を監視するチャンネル", Widget.CHANNEL,
                    get=_watch_channel, set=set_djaudio_watch_channel,
                    help="未設定にすると DJAudio-DL は反応しません。",
                ),
                Field(
                    "output_channel_id", "結果を送るチャンネル", Widget.CHANNEL,
                    get=_output_channel, set=set_djaudio_output_channel,
                    help="未設定なら監視チャンネルに返信します。",
                ),
            ),
        ),
        Section(
            "制限",
            fields=(
                Field(
                    "cache_ttl", "キャッシュ保持時間", Widget.DURATION,
                    get=get_djaudio_cache_ttl, set=_set_limit("cache_ttl"),
                    default=10 * MINUTE, min=MINUTE, max=30 * DAY, nullable=False,
                    help="ダウンロードリンクが切れるまでの時間です。"
                         "長くするほどサーバーのディスクを使います。",
                ),
                Field(
                    "cooldown", "クールダウン（秒）", Widget.INT,
                    get=get_djaudio_cooldown, set=_set_limit("cooldown"),
                    default=30, min=0, max=3600, nullable=False,
                    help="同じ利用者が連続で実行できるまでの間隔です。",
                ),
                Field(
                    "max_urls", "1メッセージあたりの URL 上限", Widget.INT,
                    get=get_djaudio_max_urls, set=_set_limit("max_urls"),
                    default=3, min=1, max=10, nullable=False,
                ),
            ),
        ),
    ),
)
