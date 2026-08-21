"""スキーマに基づく入力検証。

検証の規則はスキーマ（Field の widget / min / max / max_len / choices / nullable）
だけから導く。画面ごとに if を書き分けない。エラーはフィールド単位で返し、
クライアントは該当入力欄の直下に出す。
"""

from __future__ import annotations

from typing import Any

from webapp_admin.schema.types import Collection, Field, Panel, Widget
from webapp_admin.security import MAX_STR_LEN, sanitize

_ID_WIDGETS = (Widget.CHANNEL, Widget.VOICE_CHANNEL, Widget.ROLE, Widget.SNOWFLAKE)


class InvalidValue(ValueError):
    """1項目の入力が受け付けられないことを表す。message はそのまま利用者に見せる。"""


def _options(field: Field, choices: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    source = field.choice_source
    if source is None:
        return []
    return choices.get(source.value, [])


def _validate_id(field: Field, raw: Any, choices) -> int | None:
    if raw in (None, "", "0", 0):
        if not field.nullable:
            raise InvalidValue("選択してください。")
        return None

    text = str(raw).strip()
    if not text.isdigit() or int(text) <= 0:
        raise InvalidValue("Discord の ID（数字）を指定してください。")

    # 一覧を取得できているときは、その中の項目かどうかまで見る。
    # 別サーバーのIDや古いIDをそのまま保存してしまうのを防ぐ。
    options = _options(field, choices)
    if options and not field.free_text and text not in {o["value"] for o in options}:
        raise InvalidValue("一覧にない項目です。選び直してください。")
    return int(text)


def _validate_int(field: Field, raw: Any) -> int:
    if raw in (None, "") and field.default is not None:
        return int(field.default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise InvalidValue("数値を入力してください。")
    if field.min is not None and value < field.min:
        raise InvalidValue(f"{field.min} 以上で入力してください。")
    if field.max is not None and value > field.max:
        raise InvalidValue(f"{field.max} 以下で入力してください。")
    return value


def _validate_select(field: Field, raw: Any, choices) -> str | None:
    text = "" if raw is None else str(raw).strip()
    if not text:
        if not field.nullable:
            raise InvalidValue("選択してください。")
        return None

    statics = field.static_choices
    if statics is not None:
        if text not in {c.value for c in statics}:
            raise InvalidValue("選べない値です。")
        return text

    options = _options(field, choices)
    if options:
        if text not in {o["value"] for o in options}:
            raise InvalidValue("利用できない選択肢です。")
        return text
    # 一覧を取得できなかった場合（例: TTS API 停止中）。
    # free_text を許した項目だけ、手入力の値をそのまま受け付ける。
    if not field.free_text:
        raise InvalidValue("選択肢を取得できませんでした。時間をおいて再試行してください。")
    return text


def _validate_checklist(field: Field, raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple, set)):
        raise InvalidValue("選択内容を解釈できませんでした。")
    values = [str(v) for v in raw]
    allowed = {c.value for c in (field.static_choices or ())}
    if any(value not in allowed for value in values):
        raise InvalidValue("不明な項目が含まれています。")
    return values


def _validate_text(field: Field, raw: Any) -> str | None:
    text = "" if raw is None else str(raw)
    if field.max_len is not None and len(text) > field.max_len:
        raise InvalidValue(f"{field.max_len} 文字以内で入力してください。")
    text = sanitize(text, field.max_len or MAX_STR_LEN)
    if field.widget is not Widget.TEXTAREA:
        text = text.strip()
    if not text:
        if field.required or not field.nullable:
            raise InvalidValue("入力してください。")
        return None
    return text


def validate_field(field: Field, raw: Any, choices: dict[str, list[dict[str, str]]]) -> Any:
    """1項目を検証し、set() へ渡せる値にして返す。不正なら InvalidValue。"""
    if field.widget in _ID_WIDGETS:
        return _validate_id(field, raw, choices)
    if field.widget is Widget.BOOL:
        return field.coerce(raw)
    if field.widget is Widget.INT:
        return _validate_int(field, raw)
    if field.widget is Widget.SELECT:
        return _validate_select(field, raw, choices)
    if field.widget is Widget.CHECKLIST:
        return _validate_checklist(field, raw)
    return _validate_text(field, raw)


def validate_values(
    panel: Panel,
    incoming: dict[str, Any],
    choices: dict[str, list[dict[str, str]]],
) -> tuple[dict[str, Any], dict[str, str]]:
    """パネルへの変更（変更されたフィールドのみ）を検証する。"""
    clean: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for key, raw in incoming.items():
        field = panel.field(key)
        if field is None:
            errors[key] = "不明な設定項目です。"
            continue
        if field.set is None:
            errors[key] = "この項目は変更できません。"
            continue
        try:
            clean[key] = validate_field(field, raw, choices)
        except InvalidValue as exc:
            errors[key] = str(exc)

    return clean, errors


def validate_item(
    collection: Collection,
    incoming: dict[str, Any],
    choices: dict[str, list[dict[str, str]]],
    *,
    partial: bool = False,
) -> tuple[dict[str, Any], dict[str, str]]:
    """コレクションへ追加・更新する1項目を検証する。"""
    clean: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for field in collection.item_fields:
        if field.key not in incoming:
            if partial:
                continue
            if field.required:
                errors[field.key] = "入力してください。"
                continue
        try:
            clean[field.key] = validate_field(field, incoming.get(field.key), choices)
        except InvalidValue as exc:
            errors[field.key] = str(exc)

    unknown = set(incoming) - {f.key for f in collection.item_fields}
    for key in unknown:
        errors[key] = "不明な項目です。"

    return clean, errors
