"""VC 通知パネル。"""

from __future__ import annotations

from services.settings_store import (
    get_vc_notify_channel_id,
    get_vc_notify_filter_role_id,
    get_vc_notify_role_id,
    set_vc_notify_channel_id,
    set_vc_notify_filter_role_id,
    set_vc_notify_role_id,
)
from webapp_admin.schema.types import Field, Panel, Section, Widget


# getter は未設定を 0 で返すため、スキーマ側で None に寄せる。
def _channel(guild_id: int):
    return get_vc_notify_channel_id(guild_id) or None


def _role(guild_id: int):
    return get_vc_notify_role_id(guild_id) or None


def _filter_role(guild_id: int):
    return get_vc_notify_filter_role_id(guild_id) or None


PANEL = Panel(
    id="vc-notify",
    title="VC 通知",
    icon="bi-mic-fill",
    group="基本設定",
    path="/admin/settings/vc-notify",
    window=(720, 560),
    sections=(
        Section(
            "通知先",
            fields=(
                Field(
                    "vc_notify_channel_id",
                    "通知を送るチャンネル",
                    Widget.CHANNEL,
                    get=_channel,
                    set=set_vc_notify_channel_id,
                    help="未設定にすると VC の参加・退出を通知しません。",
                ),
                Field(
                    "vc_notify_role_id",
                    "メンションするロール",
                    Widget.ROLE,
                    get=_role,
                    set=set_vc_notify_role_id,
                    help="未設定ならメンションなしで通知します。",
                ),
            ),
        ),
        Section(
            "通知の絞り込み",
            fields=(
                Field(
                    "vc_notify_filter_role_id",
                    "通知対象のロール",
                    Widget.ROLE,
                    get=_filter_role,
                    set=set_vc_notify_filter_role_id,
                    help="指定するとそのロールを持つ人の入退室だけを通知します。未設定なら全員が対象です。",
                ),
            ),
        ),
    ),
)
