"""地震アラートパネル。"""

from __future__ import annotations

from config import SCALE_LABELS
from services.settings_store import (
    get_earthquake_notify_types,
    get_earthquake_settings,
    set_earthquake_channel,
    set_earthquake_min_scale,
    set_earthquake_notify_types,
)
from webapp_admin.schema.types import Choice, Field, Panel, Section, Widget

# 通知タイプは Bot 側 (services/earthquake_service.py) が参照するキーと一致させること。
NOTIFY_TYPES: tuple[tuple[str, str], ...] = (
    ("eew_forecast", "緊急地震速報（予報）"),
    ("eew_warning", "緊急地震速報（警報）"),
    ("tsunami", "津波情報"),
    ("quake_info", "地震情報"),
    ("bot_news", "ボットに関するお知らせ"),
)

# P2PQuake の仕様にある値だけ。65 は存在しない階級で、選べても一致しない。
VALID_SCALES: tuple[int, ...] = (10, 20, 30, 40, 45, 50, 55, 60, 70)


def _channel(guild_id: int):
    return get_earthquake_settings(guild_id).get("channel_id")


def _min_scale(guild_id: int) -> int:
    try:
        return int(get_earthquake_settings(guild_id).get("min_scale", 30))
    except (TypeError, ValueError):
        return 30


def _set_min_scale(guild_id: int, value) -> None:
    set_earthquake_min_scale(guild_id, int(value))


def _notify_types(guild_id: int) -> dict[str, bool]:
    return get_earthquake_notify_types(guild_id)


def _set_notify_types(guild_id: int, enabled_keys) -> None:
    selected = {str(k) for k in (enabled_keys or [])}
    set_earthquake_notify_types(guild_id, {key: key in selected for key, _ in NOTIFY_TYPES})


PANEL = Panel(
    id="earthquake",
    title="地震アラート",
    icon="bi-exclamation-triangle-fill",
    group="自動通知",
    path="/admin/settings/earthquake",
    sections=(
        Section(
            "通知先と条件",
            fields=(
                Field(
                    "channel_id", "アラートを送るチャンネル", Widget.CHANNEL,
                    get=_channel, set=set_earthquake_channel,
                    help="未設定にすると地震アラートを送りません。",
                ),
                Field(
                    "min_scale", "通知する最小震度", Widget.SELECT,
                    get=_min_scale, set=_set_min_scale,
                    default=30, nullable=False,
                    choices=tuple(
                        Choice(str(scale), SCALE_LABELS.get(scale, str(scale)))
                        for scale in VALID_SCALES
                    ),
                    help="この震度以上の地震だけを通知します。",
                ),
            ),
        ),
        Section(
            "通知タイプ",
            fields=(
                Field(
                    "notify_types", "通知する情報の種類", Widget.CHECKLIST,
                    get=_notify_types, set=_set_notify_types, nullable=False,
                    choices=tuple(Choice(key, label) for key, label in NOTIFY_TYPES),
                ),
            ),
        ),
    ),
)
