"""セキュリティ設定パネル（スパム・レイド検出の対象外リスト）。"""

from __future__ import annotations

from typing import Any

from services.settings_store import (
    add_bypass_roles,
    add_trusted_users,
    get_bypass_role_ids,
    get_trusted_user_ids,
    remove_bypass_roles,
    remove_trusted_users,
)
from webapp_admin.schema.types_def import Collection, Field, Panel, Section, Widget


def _trusted_list(guild_id: int) -> list[dict[str, Any]]:
    return [{"id": str(uid), "user_id": str(uid)} for uid in get_trusted_user_ids(guild_id)]


def _trusted_add(guild_id: int, data: dict[str, Any]) -> str:
    user_id = int(data["user_id"])
    add_trusted_users(guild_id, [user_id])
    return str(user_id)


def _trusted_remove(guild_id: int, item_id: str) -> None:
    remove_trusted_users(guild_id, [int(item_id)])


def _bypass_list(guild_id: int) -> list[dict[str, Any]]:
    return [{"id": str(rid), "role_id": str(rid)} for rid in get_bypass_role_ids(guild_id)]


def _bypass_add(guild_id: int, data: dict[str, Any]) -> str:
    role_id = int(data["role_id"])
    add_bypass_roles(guild_id, [role_id])
    return str(role_id)


def _bypass_remove(guild_id: int, item_id: str) -> None:
    remove_bypass_roles(guild_id, [int(item_id)])


def _count(guild_id: int) -> int:
    return len(get_trusted_user_ids(guild_id)) + len(get_bypass_role_ids(guild_id))


PANEL = Panel(
    id="security",
    title="セキュリティ設定",
    icon="bi-shield-fill-check",
    group="セキュリティ",
    path="/admin/settings/security",
    window=(820, 620),
    badge=_count,
    sections=(
        Section(
            "信頼済みユーザー",
            collections=(
                Collection(
                    key="trusted_users",
                    label="信頼済みユーザー",
                    item_label="ユーザー",
                    id_key="user_id",
                    list=_trusted_list,
                    add=_trusted_add,
                    remove=_trusted_remove,
                    help="スパム・レイド検出の対象から外します。",
                    item_fields=(
                        Field("user_id", "ユーザーID", Widget.SNOWFLAKE, required=True, nullable=False, max_len=20),
                    ),
                ),
            ),
        ),
        Section(
            "セキュリティバイパスロール",
            collections=(
                Collection(
                    key="bypass_roles",
                    label="バイパスロール",
                    item_label="ロール",
                    id_key="role_id",
                    list=_bypass_list,
                    add=_bypass_add,
                    remove=_bypass_remove,
                    help="このロールを持つ人は検出の対象外になります。",
                    item_fields=(Field("role_id", "ロール", Widget.ROLE, required=True, nullable=False),),
                ),
            ),
        ),
    ),
)
