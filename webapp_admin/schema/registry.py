"""全パネルの登録。

デスクトップUIのタイル一覧と、直接URLアクセスをデスクトップへ集約するための
パス逆引き表の単一の情報源。以前の webapp_admin/apps_registry.py を吸収した。
並び順がそのままスタートメニューの並びになる。
"""

from __future__ import annotations

from typing import Any

from webapp_admin.schema.panels.custom import DEV, MONITORING, RECORDING, SQL, USER_STATE
from webapp_admin.schema.panels.djaudio import PANEL as DJAUDIO
from webapp_admin.schema.panels.earthquake import PANEL as EARTHQUAKE
from webapp_admin.schema.panels.guild_data import PANEL as GUILD_DATA
from webapp_admin.schema.panels.logging import PANEL as LOGGING
from webapp_admin.schema.panels.news_feeds import PANEL as NEWS_FEEDS
from webapp_admin.schema.panels.reaction_roles import PANEL as REACTION_ROLES
from webapp_admin.schema.panels.security import PANEL as SECURITY
from webapp_admin.schema.panels.sticky import PANEL as STICKY
from webapp_admin.schema.panels.tts import PANEL as TTS
from webapp_admin.schema.panels.vc_notify import PANEL as VC_NOTIFY
from webapp_admin.schema.panels.welcome import PANEL as WELCOME
from webapp_admin.schema.types_def import Panel, Widget

PANELS: tuple[Panel, ...] = (
    MONITORING,
    USER_STATE,
    LOGGING,
    WELCOME,
    VC_NOTIFY,
    GUILD_DATA,
    EARTHQUAKE,
    NEWS_FEEDS,
    STICKY,
    REACTION_ROLES,
    DJAUDIO,
    TTS,
    RECORDING,
    SECURITY,
    DEV,
    SQL,
)

PANEL_BY_ID: dict[str, Panel] = {panel.id: panel for panel in PANELS}

# 直接URLアクセス（非埋め込み）をデスクトップへリダイレクトするための逆引き表。
PATH_TO_ID: dict[str, str] = {panel.path: panel.id for panel in PANELS if panel.path}


def visible_panels(is_dev: bool) -> list[Panel]:
    """スタートメニューに出してよいパネルだけを返す。

    dev_only なパネル（SQL コンソールなど）は、is_dev_user() が False の相手には
    存在ごと隠す。403 ではなく一覧から消すのは、URL を知っていても手がかりを
    与えないため。個別ルート側の認可判定はこれとは別に必要（一覧を隠しても
    直接URLアクセスは防げない）。
    """
    return [panel for panel in PANELS if is_dev or not panel.dev_only]


def app_groups(guild_id: int, is_dev: bool) -> list[dict[str, Any]]:
    """スタートメニュー用にグループ分けしたタイル一覧を返す。"""
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for panel in visible_panels(is_dev):
        if panel.group not in groups:
            groups[panel.group] = []
            order.append(panel.group)
        groups[panel.group].append(panel.tile(guild_id))
    return [{"label": label, "apps": groups[label]} for label in order]


def validate() -> list[str]:
    """宣言の不整合を洗い出す。tools/check_admin_schema.py から呼ぶ。"""
    problems: list[str] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()

    for panel in PANELS:
        if panel.id in seen_ids:
            problems.append(f"{panel.id}: パネルIDが重複している")
        seen_ids.add(panel.id)
        if panel.path:
            if panel.path in seen_paths:
                problems.append(f"{panel.id}: パス {panel.path} が重複している")
            seen_paths.add(panel.path)
        elif not panel.custom or panel.client == "iframe":
            problems.append(f"{panel.id}: path が無いのに埋め込み表示になっている")

        if panel.custom:
            if panel.sections:
                problems.append(f"{panel.id}: custom パネルに sections がある")
            continue

        if not panel.sections:
            problems.append(f"{panel.id}: sections が空（custom にすべきか要確認）")

        field_keys: set[str] = set()
        for field in panel.fields:
            where = f"{panel.id}.{field.key}"
            if field.key in field_keys:
                problems.append(f"{where}: フィールドキーが重複している")
            field_keys.add(field.key)
            if field.get is None:
                problems.append(f"{where}: get が未定義")
            if field.set is None:
                problems.append(f"{where}: set が未定義")
            if field.widget in (Widget.SELECT, Widget.CHECKLIST) and field.choices is None:
                problems.append(f"{where}: {field.widget.value} に choices がない")
            if field.enabled_when and field.enabled_when not in field_keys | {f.key for f in panel.fields}:
                problems.append(f"{where}: enabled_when が存在しないキー {field.enabled_when} を指している")

        for collection in panel.collections:
            where = f"{panel.id}.{collection.key}"
            if not collection.item_fields:
                problems.append(f"{where}: item_fields が空")
            if collection.list is None:
                problems.append(f"{where}: list が未定義")
            if collection.add is None and collection.update is None and collection.remove is None:
                problems.append(f"{where}: 追加・更新・削除のいずれも定義されていない")
            for field in collection.item_fields:
                if field.get is not None or field.set is not None:
                    problems.append(f"{where}.{field.key}: コレクションの入力欄に get/set は不要")
            id_field = collection.id_key
            if id_field != "id" and id_field not in {f.key for f in collection.item_fields}:
                problems.append(f"{where}: id_key {id_field} に対応する入力欄がない")

    return problems
