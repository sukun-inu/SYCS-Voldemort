"""リアクションロールパネル。

保存構造は message_id → {emoji: role_id} の入れ子。一覧では
"<message_id>:<emoji>" を項目IDとして平坦化して扱う。
"""

from __future__ import annotations

from typing import Any

from services.settings_store import (
    add_reaction_role,
    get_reaction_roles,
    remove_reaction_role,
)
from webapp_admin.schema.types import Collection, Field, Panel, Section, Widget

_ID_SEPARATOR = ":"


def _count(guild_id: int) -> int:
    return sum(len(entries) for entries in get_reaction_roles(guild_id).values() if isinstance(entries, dict))


def _list(guild_id: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for message_id, entries in get_reaction_roles(guild_id).items():
        if not isinstance(entries, dict):
            continue
        for emoji, role_id in entries.items():
            rows.append(
                {
                    "id": f"{message_id}{_ID_SEPARATOR}{emoji}",
                    "message_id": str(message_id),
                    "emoji": emoji,
                    "role_id": str(role_id),
                }
            )
    return rows


def _add(guild_id: int, data: dict[str, Any]) -> str:
    message_id = int(data["message_id"])
    emoji = str(data["emoji"]).strip()
    add_reaction_role(guild_id, message_id, emoji, int(data["role_id"]))
    return f"{message_id}{_ID_SEPARATOR}{emoji}"


def _remove(guild_id: int, item_id: str) -> bool:
    message_id, _, emoji = str(item_id).partition(_ID_SEPARATOR)
    return remove_reaction_role(guild_id, int(message_id), emoji)


PANEL = Panel(
    id="reaction-roles",
    title="リアクションロール",
    icon="bi-emoji-smile-fill",
    group="チャンネル機能",
    path="/admin/settings/reaction-roles",
    window=(820, 640),
    badge=_count,
    sections=(
        Section(
            "リアクションロール",
            collections=(
                Collection(
                    key="reaction_roles",
                    label="登録済みの割り当て",
                    item_label="割り当て",
                    list=_list,
                    add=_add,
                    remove=_remove,
                    help="対象メッセージに指定の絵文字が付くと、ロールを付与・剥奪します。",
                    item_fields=(
                        Field(
                            "message_id",
                            "メッセージID",
                            Widget.SNOWFLAKE,
                            required=True,
                            nullable=False,
                            max_len=20,
                            help="Discord で対象メッセージを右クリック →「IDをコピー」で取得できます。",
                        ),
                        Field("emoji", "絵文字", Widget.TEXT, required=True, nullable=False, max_len=50),
                        Field("role_id", "付与するロール", Widget.ROLE, required=True, nullable=False),
                    ),
                ),
            ),
        ),
    ),
)
