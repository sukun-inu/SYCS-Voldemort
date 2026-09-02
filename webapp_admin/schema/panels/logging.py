"""ログ設定パネル。"""

from __future__ import annotations

from services.logging_service import get_log_settings, set_log_channel, set_log_level
from services.settings_store import get_response_channel_id, set_response_channel_id
from webapp_admin.schema.types_def import Choice, Field, Panel, Section, Widget

LOG_LEVELS = ("NONE", "ERROR", "INFO", "DEBUG")


def _log_channel(guild_id: int):
    """log_channel_id フィールドの Field.get。"""
    return get_log_settings(guild_id).get("channel_id")


def _log_level(guild_id: int) -> str:
    """log_level フィールドの Field.get。空値は「レベル未設定」ではなく INFO に倒す。

    Widget.SELECT は nullable=False で default="INFO" だが、default は保存側が
    値を返さなかったとき（未初期化のギルド）まではカバーしない。ここで
    フォールバックしておかないと空文字が選択肢一覧に無い値として
    _validate_select を素通りし、画面のプルダウンが「選べない値」を表示する。
    """
    return str(get_log_settings(guild_id).get("level") or "INFO")


def _chatgpt_channel(guild_id: int):
    """chatgpt_channel_id フィールドの Field.get。0 は「未設定」を表す規約（下記コメント）に合わせて None にする。"""
    # 0 は「未設定=無効」を意味する（Bot / WebUI で統一済みの仕様）。
    return get_response_channel_id(guild_id) or None


PANEL = Panel(
    id="logging",
    title="ログ設定",
    icon="bi-journal-text",
    group="基本設定",
    path="/admin/settings/logging",
    window=(720, 560),
    sections=(
        Section(
            "ログチャンネル / レベル",
            fields=(
                Field(
                    "log_channel_id",
                    "ログを送信するチャンネル",
                    Widget.CHANNEL,
                    get=_log_channel,
                    set=set_log_channel,
                    help="未設定にするとログ出力を止めます。",
                ),
                Field(
                    "log_level",
                    "ログレベル",
                    Widget.SELECT,
                    get=_log_level,
                    set=set_log_level,
                    default="INFO",
                    nullable=False,
                    choices=tuple(Choice(level, level) for level in LOG_LEVELS),
                    help="通常運用は INFO、調査時だけ DEBUG にすると読みやすく保てます。",
                ),
            ),
        ),
        Section(
            "ChatGPT 応答チャンネル",
            fields=(
                Field(
                    "chatgpt_channel_id",
                    "ChatGPT が応答するチャンネル",
                    Widget.CHANNEL,
                    get=_chatgpt_channel,
                    set=set_response_channel_id,
                    help="未設定の場合は ChatGPT は応答しません。",
                ),
            ),
        ),
    ),
)
