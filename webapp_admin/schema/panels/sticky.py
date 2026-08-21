"""スティッキーメッセージパネル。

1チャンネルにつき1件。チャンネルIDがそのまま項目IDになる。
"""

from __future__ import annotations

from typing import Any

from services.settings_store import (
    get_sticky_messages,
    mark_sticky_pending_delete,
    set_sticky_message,
)
from webapp_admin.schema.types import Collection, Field, Panel, Section, Widget


def _list(guild_id: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for channel_id, entry in get_sticky_messages(guild_id).items():
        if not isinstance(entry, dict):
            continue
        rows.append({
            "id": str(channel_id),
            "channel_id": str(channel_id),
            "content": entry.get("content", ""),
            "message_id": entry.get("message_id"),
        })
    return rows


def _add(guild_id: int, data: dict[str, Any]) -> str:
    channel_id = int(data["channel_id"])
    set_sticky_message(guild_id, channel_id, str(data["content"]))
    return str(channel_id)


def _update(guild_id: int, item_id: str, data: dict[str, Any]) -> str:
    # チャンネル単位の上書きなので、追加と同じ操作になる。
    return _add(guild_id, {"channel_id": item_id, "content": data["content"]})


def _remove(guild_id: int, item_id: str) -> None:
    # 実際の削除は Bot 側が投稿済みメッセージを消してから行うため、
    # ここでは「削除保留」を立てるだけにする（既存の解除動作と同じ）。
    mark_sticky_pending_delete(guild_id, int(item_id))


PANEL = Panel(
    id="sticky",
    title="スティッキー",
    icon="bi-pin-angle-fill",
    group="チャンネル機能",
    path="/admin/settings/sticky",
    window=(820, 640),
    badge=lambda guild_id: len(get_sticky_messages(guild_id)),
    sections=(
        Section(
            "スティッキーメッセージ",
            collections=(
                Collection(
                    key="stickies",
                    label="設定済みチャンネル",
                    item_label="スティッキー",
                    id_key="channel_id",
                    list=_list,
                    add=_add,
                    update=_update,
                    remove=_remove,
                    help="チャンネルに新しい投稿があるたび、最後に貼り直されます。",
                    item_fields=(
                        Field("channel_id", "チャンネル", Widget.CHANNEL,
                              required=True, nullable=False),
                        Field("content", "本文", Widget.TEXTAREA,
                              required=True, nullable=False, max_len=1000),
                    ),
                ),
            ),
        ),
    ),
)
