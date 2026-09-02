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
    """trusted_users コレクションの Collection.list。

    信頼済み＝スパム/レイド検出の対象外（モジュール docstring 参照）。
    """
    return [{"id": str(uid), "user_id": str(uid)} for uid in get_trusted_user_ids(guild_id)]


def _trusted_add(guild_id: int, data: dict[str, Any]) -> str:
    """trusted_users コレクションの Collection.add。

    ここに追加したユーザーはスパム・レイド検出を素通りするようになる
    （services 側の検出ロジックがこのリストを見て判定自体をスキップする）。
    誤って追加すると、そのユーザーが起こす荒らし行為を自動検出が拾わなく
    なるので、UI 側では慎重な操作として扱うこと。
    """
    user_id = int(data["user_id"])
    add_trusted_users(guild_id, [user_id])
    return str(user_id)


def _trusted_remove(guild_id: int, item_id: str) -> None:
    """trusted_users コレクションの Collection.remove。外すと以後そのユーザーも通常どおり検出対象になる。"""
    remove_trusted_users(guild_id, [int(item_id)])


def _bypass_list(guild_id: int) -> list[dict[str, Any]]:
    """bypass_roles コレクションの Collection.list。"""
    return [{"id": str(rid), "role_id": str(rid)} for rid in get_bypass_role_ids(guild_id)]


def _bypass_add(guild_id: int, data: dict[str, Any]) -> str:
    """bypass_roles コレクションの Collection.add。

    _trusted_add と違い、こちらはロール単位で検出を素通りさせる。ロール付与を
    自由に行えるサーバーで @everyone に近いロールを誤って登録すると、
    実質的にスパム/レイド検出そのものを無効化してしまう。
    """
    role_id = int(data["role_id"])
    add_bypass_roles(guild_id, [role_id])
    return str(role_id)


def _bypass_remove(guild_id: int, item_id: str) -> None:
    """bypass_roles コレクションの Collection.remove。"""
    remove_bypass_roles(guild_id, [int(item_id)])


def _count(guild_id: int) -> int:
    """タイルのバッジ用件数。信頼済みユーザーとバイパスロールを合算した「例外の総数」を出す。"""
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
