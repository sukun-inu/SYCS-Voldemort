"""スキーマ駆動の設定 API。

- 読み取り: パネルの定義・現在値・選択肢をまとめて返す
- 書き込み: パネル単位の明示保存（変更された項目のみ）とコレクション操作

画面ごとの action 分岐は持たない。何を受け付けるかは webapp_admin/schema/ の
宣言だけが決める。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from webapp_admin.api.jsonsafe import SafeJSONResponse as JSONResponse

from webapp_admin.schema import choices as choice_resolver
from webapp_admin.schema.registry import PANEL_BY_ID, app_groups
from webapp_admin.schema.types import Collection, Panel
from webapp_admin.schema.validation import validate_item, validate_values
from webapp_admin.security import check_csrf, check_guild, is_dev_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _guild_id(request: Request) -> int:
    return int(request.session["guild_id"])


def _panel_or_404(request: Request, app_id: str) -> Panel:
    panel = PANEL_BY_ID.get(app_id)
    if panel is None or (panel.dev_only and not is_dev_user(request)):
        raise HTTPException(status_code=404)
    return panel


def _editable_panel(request: Request, app_id: str) -> Panel:
    panel = _panel_or_404(request, app_id)
    if panel.custom:
        raise HTTPException(status_code=404)
    return panel


def _collection_or_404(panel: Panel, key: str) -> Collection:
    collection = panel.collection(key)
    if collection is None:
        raise HTTPException(status_code=404)
    return collection


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON を解釈できませんでした。")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON オブジェクトを送ってください。")
    return body


def _read_values(panel: Panel, guild_id: int) -> tuple[dict[str, Any], dict[str, str]]:
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for field in panel.fields:
        try:
            values[field.key] = field.to_json_value(field.get(guild_id))
        except Exception as exc:  # 1項目の失敗でパネル全体を落とさない
            logger.exception("設定値の読み取りに失敗 panel=%s field=%s", panel.id, field.key)
            values[field.key] = field.default
            errors[field.key] = str(exc)
    return values, errors


def _read_collections(panel: Panel, guild_id: int) -> tuple[dict[str, list], dict[str, str]]:
    rows: dict[str, list] = {}
    errors: dict[str, str] = {}
    for collection in panel.collections:
        try:
            rows[collection.key] = collection.list(guild_id)
        except Exception as exc:
            logger.exception("一覧の読み取りに失敗 panel=%s collection=%s", panel.id, collection.key)
            rows[collection.key] = []
            errors[collection.key] = str(exc)
    return rows, errors


async def _choices_for_keys(panel: Panel, keys, guild_id: int) -> dict[str, list[dict[str, str]]]:
    """変更された項目に関係する選択肢だけを解決する（無駄な Discord API 呼び出しを避ける）。"""
    sources = set()
    for key in keys:
        field = panel.field(key)
        if field is not None and field.choice_source:
            sources.add(field.choice_source)
    return await choice_resolver.resolve(sources, guild_id)


# ── 読み取り ──────────────────────────────────────────────────


@router.get("/apps")
async def list_apps(request: Request, _=Depends(check_guild)):
    """スタートメニュー用のタイル一覧。"""
    return JSONResponse({"groups": app_groups(_guild_id(request), is_dev_user(request))})


@router.get("/apps/{app_id}")
async def get_app(app_id: str, request: Request, _=Depends(check_guild)):
    """1パネルのスキーマ・現在値・選択肢。"""
    panel = _panel_or_404(request, app_id)
    payload: dict[str, Any] = panel.to_json()

    if panel.custom:
        return JSONResponse(payload)

    guild_id = _guild_id(request)
    # 選択肢は供給元ごとに1回だけ取得する（同じチャンネル一覧を複数フィールドで共有）。
    payload["choices"] = await choice_resolver.resolve(panel.choice_sources(), guild_id)

    values, value_errors = _read_values(panel, guild_id)
    collections, collection_errors = _read_collections(panel, guild_id)
    payload["values"] = values
    payload["collections"] = collections

    errors = {**value_errors, **collection_errors}
    if errors:
        payload["errors"] = errors
    return JSONResponse(payload)


# ── 明示保存 ──────────────────────────────────────────────────


@router.put("/apps/{app_id}")
async def save_app(
    app_id: str,
    request: Request,
    _=Depends(check_guild),
    _csrf=Depends(check_csrf),
):
    """変更された項目だけを保存する。"""
    panel = _editable_panel(request, app_id)
    guild_id = _guild_id(request)

    body = await _json_body(request)
    incoming = body.get("values")
    if not isinstance(incoming, dict):
        raise HTTPException(status_code=400, detail="values オブジェクトが必要です。")
    if not incoming:
        values, _ = _read_values(panel, guild_id)
        return JSONResponse({"saved": [], "values": values})

    choices = await _choices_for_keys(panel, incoming.keys(), guild_id)
    clean, errors = validate_values(panel, incoming, choices)

    # 保存は settings.json のファイルロックを取る。ロックが空くのを待つ間は
    # 同期のポーリング（最大10秒）なので、直に呼ぶとこのワーカーのイベント
    # ループごと止まり、他の全リクエスト（ヘルスチェック含む）が固まる。
    # Bot と管理画面は同じファイルを共有していて、競合は実際に起きる。
    # 項目ごとにスレッドを跨ぐ必要は無いので、ループごと逃がす。
    def _apply() -> tuple[list[str], dict[str, str]]:
        applied: list[str] = []
        failures: dict[str, str] = {}
        for key, value in clean.items():
            field = panel.field(key)
            try:
                field.set(guild_id, value)
                applied.append(key)
            except Exception as exc:
                logger.exception("設定の保存に失敗 panel=%s field=%s", panel.id, key)
                failures[key] = f"保存できませんでした（{exc}）"
        return applied, failures

    saved, failures = await asyncio.to_thread(_apply)
    errors.update(failures)

    values, _ = _read_values(panel, guild_id)
    payload = {"saved": saved, "values": values}
    if errors:
        payload["errors"] = errors
        return JSONResponse(payload, status_code=422)
    return JSONResponse(payload)


# ── コレクション操作（追加・更新・削除は即時反映） ─────────────


@router.post("/apps/{app_id}/collections/{key}")
async def add_item(
    app_id: str,
    key: str,
    request: Request,
    _=Depends(check_guild),
    _csrf=Depends(check_csrf),
):
    panel = _editable_panel(request, app_id)
    collection = _collection_or_404(panel, key)
    if collection.add is None:
        raise HTTPException(status_code=405, detail="この一覧には追加できません。")

    guild_id = _guild_id(request)
    body = await _json_body(request)
    incoming = body.get("values")
    if not isinstance(incoming, dict):
        raise HTTPException(status_code=400, detail="values オブジェクトが必要です。")

    if collection.max_items is not None and len(collection.list(guild_id)) >= collection.max_items:
        return JSONResponse(
            {
                "errors": {"__all__": f"登録できるのは {collection.max_items} 件までです。"},
                "items": collection.list(guild_id),
            },
            status_code=422,
        )

    choices = await choice_resolver.resolve(
        {f.choice_source for f in collection.item_fields if f.choice_source}, guild_id
    )
    clean, errors = validate_item(collection, incoming, choices)
    if errors:
        return JSONResponse({"errors": errors, "items": collection.list(guild_id)}, status_code=422)

    try:
        item_id = await asyncio.to_thread(collection.add, guild_id, clean)
    except Exception as exc:
        logger.exception("一覧への追加に失敗 panel=%s collection=%s", panel.id, key)
        return JSONResponse(
            {"errors": {"__all__": f"追加できませんでした（{exc}）"}, "items": collection.list(guild_id)},
            status_code=422,
        )

    return JSONResponse({"id": None if item_id is None else str(item_id), "items": collection.list(guild_id)})


@router.put("/apps/{app_id}/collections/{key}/{item_id}")
async def update_item(
    app_id: str,
    key: str,
    item_id: str,
    request: Request,
    _=Depends(check_guild),
    _csrf=Depends(check_csrf),
):
    panel = _editable_panel(request, app_id)
    collection = _collection_or_404(panel, key)
    if collection.update is None:
        raise HTTPException(status_code=405, detail="この一覧は編集できません。")

    guild_id = _guild_id(request)
    body = await _json_body(request)
    incoming = body.get("values")
    if not isinstance(incoming, dict):
        raise HTTPException(status_code=400, detail="values オブジェクトが必要です。")

    choices = await choice_resolver.resolve(
        {f.choice_source for f in collection.item_fields if f.choice_source}, guild_id
    )
    clean, errors = validate_item(collection, incoming, choices)
    if errors:
        return JSONResponse({"errors": errors, "items": collection.list(guild_id)}, status_code=422)

    try:
        await asyncio.to_thread(collection.update, guild_id, item_id, clean)
    except Exception as exc:
        logger.exception("一覧の更新に失敗 panel=%s collection=%s", panel.id, key)
        return JSONResponse(
            {"errors": {"__all__": f"更新できませんでした（{exc}）"}, "items": collection.list(guild_id)},
            status_code=422,
        )

    return JSONResponse({"id": item_id, "items": collection.list(guild_id)})


@router.delete("/apps/{app_id}/collections/{key}/{item_id}")
async def remove_item(
    app_id: str,
    key: str,
    item_id: str,
    request: Request,
    _=Depends(check_guild),
    _csrf=Depends(check_csrf),
):
    panel = _editable_panel(request, app_id)
    collection = _collection_or_404(panel, key)
    if collection.remove is None:
        raise HTTPException(status_code=405, detail="この一覧からは削除できません。")

    guild_id = _guild_id(request)
    try:
        await asyncio.to_thread(collection.remove, guild_id, item_id)
    except Exception as exc:
        logger.exception("一覧からの削除に失敗 panel=%s collection=%s", panel.id, key)
        return JSONResponse(
            {"errors": {"__all__": f"削除できませんでした（{exc}）"}, "items": collection.list(guild_id)},
            status_code=422,
        )

    return JSONResponse({"items": collection.list(guild_id)})
