"""ウェルカム / グッバイ パネル。"""

from __future__ import annotations

from services.settings_store import (
    get_goodbye_settings,
    get_welcome_settings,
    set_goodbye_channel,
    set_goodbye_message,
    set_welcome_channel,
    set_welcome_message,
)
from webapp_admin.schema.types_def import Field, Panel, Section, Widget

_MESSAGE_HELP = (
    "使えるテンプレート変数: {user}=メンション / {username}=ユーザー名 / " "{server}=サーバー名 / {count}=メンバー数"
)


def _welcome_channel(guild_id: int):
    """welcome_channel_id フィールドの Field.get。"""
    return get_welcome_settings(guild_id).get("channel_id")


def _welcome_message(guild_id: int):
    """welcome_message フィールドの Field.get。テンプレート変数の説明は _MESSAGE_HELP 側にまとめてある。"""
    return get_welcome_settings(guild_id).get("message")


def _goodbye_channel(guild_id: int):
    """goodbye_channel_id フィールドの Field.get。ウェルカムと保存先（get_goodbye_settings）が別なので取り違え注意。"""
    return get_goodbye_settings(guild_id).get("channel_id")


def _goodbye_message(guild_id: int):
    """goodbye_message フィールドの Field.get。_welcome_message と同じくテンプレート変数を使える。"""
    return get_goodbye_settings(guild_id).get("message")


PANEL = Panel(
    id="welcome",
    title="ウェルカム/グッバイ",
    icon="bi-person-plus-fill",
    group="基本設定",
    path="/admin/settings/welcome",
    sections=(
        Section(
            "ウェルカムメッセージ",
            fields=(
                Field(
                    "welcome_channel_id",
                    "送信先チャンネル",
                    Widget.CHANNEL,
                    get=_welcome_channel,
                    set=set_welcome_channel,
                    help="未設定にすると参加時のメッセージを送りません。",
                ),
                Field(
                    "welcome_message",
                    "本文",
                    Widget.TEXTAREA,
                    get=_welcome_message,
                    set=set_welcome_message,
                    max_len=1000,
                    help=_MESSAGE_HELP,
                ),
            ),
        ),
        Section(
            "グッバイメッセージ",
            fields=(
                Field(
                    "goodbye_channel_id",
                    "送信先チャンネル",
                    Widget.CHANNEL,
                    get=_goodbye_channel,
                    set=set_goodbye_channel,
                    help="未設定にすると退出時のメッセージを送りません。",
                ),
                Field(
                    "goodbye_message",
                    "本文",
                    Widget.TEXTAREA,
                    get=_goodbye_message,
                    set=set_goodbye_message,
                    max_len=1000,
                    help=_MESSAGE_HELP,
                ),
            ),
        ),
    ),
)
