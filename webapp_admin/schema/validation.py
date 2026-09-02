"""スキーマに基づく入力検証。

検証の規則はスキーマ（Field の widget / min / max / max_len / choices / nullable）
だけから導く。画面ごとに if を書き分けない。エラーはフィールド単位で返し、
クライアントは該当入力欄の直下に出す。
"""

from __future__ import annotations

from typing import Any

from webapp_admin.schema.duration import humanize
from webapp_admin.schema.types_def import Collection, Field, Panel, Widget
from webapp_admin.security import MAX_STR_LEN, sanitize

_ID_WIDGETS = (Widget.CHANNEL, Widget.VOICE_CHANNEL, Widget.ROLE, Widget.SNOWFLAKE)


class InvalidValue(ValueError):
    """1項目の入力が受け付けられないことを表す。message はそのまま利用者に見せる。"""


def _options(field: Field, choices: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    """field の choice_source に対応する解決済み一覧だけを取り出す。

    _validate_id と _validate_select の両方が「一覧にある値か」を判定するのに使う。
    判定基準をここ1箇所にまとめておかないと、ID系とSELECT系で「一覧にない値」の
    扱いがいずれズレる。
    """
    source = field.choice_source
    if source is None:
        return []
    return choices.get(source.value, [])


def _validate_id(field: Field, raw: Any, choices) -> int | None:
    """チャンネル・ロールなど Discord ID系のウィジェットを検証する。

    数字であることまでは形式チェックで弾けるが、それだけでは「今のギルドに
    実在する項目か」までは保証できない。一覧が取れているときに限って
    _options() で突き合わせるのは、退出済みチャンネルや別サーバーの ID を
    貼り付けても数字である限り通ってしまう抜け道を塞ぐため。
    """
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
    """整数項目の検証。

    validate_values に渡ってくるのは「変更された項目のみ」（呼び出し元
    api/apps.py の書き込みエンドポイントが差分だけを送る想定）なので、ここに
    来る空文字は未入力ではなく利用者が明示的に消した値。そのまま int() に
    渡すと ValueError で弾かれてしまうため、default があればそれで埋めて
    「空に戻す」操作を成立させる。
    """
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


def _validate_duration(field: Field, raw: Any) -> int:
    """期間（秒）。範囲は秒で持つが、伝える文言は単位付きにする。

    「2592000 以下で入力してください」では何日なのか分からないため。
    """
    if raw in (None, "") and field.default is not None:
        return int(field.default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise InvalidValue("期間を入力してください。")
    if field.min is not None and value < field.min:
        raise InvalidValue(f"{humanize(field.min)} 以上で入力してください。")
    if field.max is not None and value > field.max:
        raise InvalidValue(f"{humanize(field.max)} 以下で入力してください。")
    return value


def _validate_select(field: Field, raw: Any, choices) -> str | None:
    """SELECT ウィジェットの検証。静的選択肢・動的選択肢・free_text の3経路を持つ。

    動的選択肢（choices）が空で返ってくるのは webapp_admin/schema/choices.py の
    設計どおり「取得失敗＝通常状態」（例: TTS API 停止中）。ここで free_text の
    項目まで拒否すると、外部APIが落ちているだけで既存の声設定を1文字も
    変更できなくなる。free_text を許した項目だけ手入力をそのまま通す。
    """
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
    """CHECKLIST ウィジェットの検証。static_choices だけを正とする。

    CHECKLIST は choice_source（Discord API 等からの動的解決）を今のところ
    使わない設計（地震アラートの通知タイプのように選択肢が固定の項目専用）。
    そのため _validate_select と違って _options() を呼ばず、field.static_choices
    に無い値は無条件で不正とする。
    """
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
    """TEXT/TEXTAREA の検証。長さ超過は sanitize() に切らせず、先にここで拒否する。

    sanitize() 自体にも max_len 相当の切り詰め（s[:max_len]）があるので、この
    事前チェックを外しても例外にはならない。ただしその場合、上限を超えた
    入力が「エラーで差し戻される」のではなく「黙って末尾が消えて保存される」
    動作に変わる。利用者が気づかないまま設定が欠けるのを避けるため、先に
    弾いてから sanitize() へ渡す。
    """
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
    if field.widget is Widget.DURATION:
        return _validate_duration(field, raw)
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
