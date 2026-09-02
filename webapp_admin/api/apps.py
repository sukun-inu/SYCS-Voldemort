"""スキーマ駆動の設定 API。

- 読み取り: パネルの定義・現在値・選択肢をまとめて返す
- 書き込み: パネル単位の明示保存（変更された項目のみ）とコレクション操作

画面ごとの action 分岐は持たない。何を受け付けるかは webapp_admin/schema/ の
宣言だけが決める。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from webapp_admin.api.jsonsafe import SafeJSONResponse as JSONResponse

from webapp_admin.schema import choices as choice_resolver
from webapp_admin.schema.registry import PANEL_BY_ID, app_groups
from webapp_admin.schema.types_def import Collection, Field, Panel
from webapp_admin.schema.validation import validate_item, validate_values
from webapp_admin.security import check_csrf, check_guild, is_dev_user

logger = logging.getLogger(__name__)

router = APIRouter()


def _guild_id(request: Request) -> int:
    """check_guild 依存を通過済みという前提で session から取り出す。呼ぶ側で存在保証すること。"""
    return int(request.session["guild_id"])


def _panel_or_404(request: Request, app_id: str) -> Panel:
    """未知のパネルIDと、開発者専用パネルへの非開発者アクセスを同じ404にする。

    dev_only パネル（SQLコンソール等）を403にすると「存在するが権限が無い」
    ことが伝わってしまう。404で一様に扱い、パネルの存在自体を開発者以外へ
    漏らさない。registry.visible_panels() の一覧非表示と揃えた振る舞い。
    """
    panel = PANEL_BY_ID.get(app_id)
    if panel is None or (panel.dev_only and not is_dev_user(request)):
        raise HTTPException(status_code=404)
    return panel


def _editable_panel(request: Request, app_id: str) -> Panel:
    """書き込み系エンドポイント共通のガード。custom パネルには明示保存の概念が無い。

    custom パネル（DEV/SQL/RECORDING/USER_STATE 等）は自前のAPIで状態を持ち、
    このスキーマ駆動の values/collections 経由の保存対象ではない。ここを
    通さずに save_app 等を直接叩かれても 404 で弾く。
    """
    panel = _panel_or_404(request, app_id)
    if panel.custom:
        raise HTTPException(status_code=404)
    return panel


def _collection_or_404(panel: Panel, key: str) -> Collection:
    """パネルにそのコレクションキーが定義されていなければ404。"""
    collection = panel.collection(key)
    if collection is None:
        raise HTTPException(status_code=404)
    return collection


async def _json_body(request: Request) -> dict[str, Any]:
    """書き込み系エンドポイント共通の本文パース。JSON でない/オブジェクトでなければ400で止める。

    ここで型を保証しておかないと、下流の validate_values/validate_item が
    list や文字列を渡されて予期しない例外を出し、422 ではなく素の 500 になる。
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON を解釈できませんでした。")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON オブジェクトを送ってください。")
    return body


def _read_values(panel: Panel, guild_id: int) -> tuple[dict[str, Any], dict[str, str]]:
    """パネルの全フィールドを読む。1項目の読み取り失敗でパネル全体を落とさない。

    失敗した項目は field.default で埋めて errors に理由を積む。ここで例外を
    伝播させると、1つの壊れた設定値のせいでパネル全体が開けなくなり、
    直そうにも画面へ辿り着けなくなる。
    """
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for field in panel.fields:
        try:
            # Field.get はコレクションの入力欄では省略できるため型は Optional
            # だが、registry の検査（app_groups 経由で読み込み時に走る）が
            # トップレベルのフィールドには必ず get/set がある前提を保証している。
            # None ならここで TypeError になり、下の except でそのまま拾われる
            # （挙動は変えていない）。
            getter = cast(Callable[[int], Any], field.get)
            values[field.key] = field.to_json_value(getter(guild_id))
        except Exception as exc:  # 1項目の失敗でパネル全体を落とさない
            logger.exception("設定値の読み取りに失敗 panel=%s field=%s", panel.id, field.key)
            values[field.key] = field.default
            errors[field.key] = str(exc)
    return values, errors


def _read_collections(panel: Panel, guild_id: int) -> tuple[dict[str, list], dict[str, str]]:
    """パネルの全コレクションを読む。_read_values と同じく1件の失敗で全体を落とさない。"""
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
        """実際の書き込みを担う。asyncio.to_thread で呼ぶ前提（直呼びしない）。

        setter は settings.json のファイルロックを取るため、ここを await せず
        イベントループ上で直接呼ぶと、ロック待ちの間ワーカー全体が固まり、
        Bot 側の書き込みと鉢合わせたときは特に長く止まる（上のコメント参照）。
        1項目の失敗は failures に積んで続行し、他の項目の保存は妨げない。
        """
        applied: list[str] = []
        failures: dict[str, str] = {}
        for key, value in clean.items():
            # clean の key は validate_values() が
            # 「panel.field(key) が存在し、かつ field.set が非 None」の場合に
            # しか入れていない（webapp_admin/schema/validation.py 参照）ので、
            # ここで None になることは無い。None なら下の except がそのまま拾う
            # （挙動は変えていない）。
            field = cast(Field, panel.field(key))
            try:
                setter = cast(Callable[[int, Any], Any], field.set)
                setter(guild_id, value)
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
    """コレクションへ1件追加する。保存ボタンを介さず即時反映（明示保存とは別系統）。

    max_items の上限チェックは検証（validate_item）より前に行う。件数超過を
    先に弾かないと、入力自体は正しいのに上限で失敗したケースでも個別項目の
    エラー扱いになり、原因が「多すぎる」ではなく「値がおかしい」ように見える。
    """
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
    """コレクションの1件を更新する。add_item と同じく即時反映で、明示保存は経由しない。"""
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
    """コレクションの1件を削除する。取り消し確認は画面側の責務で、ここでは即座に消す。"""
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
