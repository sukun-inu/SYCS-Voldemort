#!/usr/bin/env python3
"""管理UIの設定スキーマを検証する。

webapp_admin/schema/panels/ の宣言が実際の services/* の関数と噛み合っているかを、
使い捨ての設定ディレクトリに対して実際に読み書きして確かめる。

  python tools/check_admin_schema.py

検証内容:
  1. 宣言の構造チェック（registry.validate）
  2. パネルの path が実在するルートを指しているか
  3. 各フィールドの get / set 往復（未設定に戻す操作も含む）
  4. 各コレクションの list / add / remove 往復

本物の settings.json には触らない。常に一時ディレクトリを SETTINGS_DIR にして
ダミーのギルドIDで実行する。
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# services/* はモジュール読み込み時に SETTINGS_DIR を解決するため、
# プロジェクトの import より前に一時ディレクトリへ差し替える。
_TMP_DIR = tempfile.mkdtemp(prefix="admin-schema-check-")
os.environ["SETTINGS_DIR"] = _TMP_DIR
os.environ.setdefault("ADMIN_FLASK_SECRET_KEY", "x" * 64)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webapp_admin.schema.registry import PANELS, validate  # noqa: E402
from webapp_admin.schema.types_def import Field, Panel, Widget  # noqa: E402

GUILD_ID = 999_999_999_999_999_999
SAMPLE_ID = "123456789012345678"
SAMPLE_ID_2 = "876543210987654321"

_OK = "  [OK]"
_NG = "  [NG]"

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)
    print(f"{_NG} {message}")


def collect_route_paths(routes, prefix: str = "") -> set[str]:
    """アプリに登録されている全ルートのパスを集める。

    FastAPI 0.141 以降は include_router したルーターが _IncludedRouter として
    保持され、app.routes には展開されない。include_context を辿って再帰する。
    """
    found: set[str] = set()
    for route in routes:
        context = getattr(route, "include_context", None)
        if context is not None:
            found |= collect_route_paths(context.included_router.routes, prefix + (context.prefix or ""))
            continue
        path = getattr(route, "path", None)
        if path is not None:
            # 空文字のパス（@router.get("") = プレフィックスそのもの）も拾う。
            found.add(prefix + path)
    return found


def sample_value(field: Field, current):
    """そのフィールドに入れて意味のあるダミー値を作る。"""
    if field.widget in (Widget.CHANNEL, Widget.VOICE_CHANNEL, Widget.ROLE, Widget.SNOWFLAKE):
        return SAMPLE_ID if str(current or "") != SAMPLE_ID else SAMPLE_ID_2
    if field.widget is Widget.BOOL:
        return not bool(current)
    if field.widget in (Widget.INT, Widget.DURATION):
        # DURATION も値そのものは秒（整数）なので、範囲の中から選べばよい
        low = field.min if field.min is not None else 1
        high = field.max if field.max is not None else low + 10
        candidate = low + 1 if low + 1 <= high else low
        if candidate == current:
            candidate = high
        return candidate
    if field.widget is Widget.CHECKLIST:
        choices = field.static_choices or ()
        return [choices[0].value] if choices else []
    if field.widget is Widget.SELECT:
        choices = field.static_choices
        if choices:
            for choice in choices:
                if choice.value != str(current):
                    return choice.value
            return choices[0].value
        # 動的な選択肢（TTSの声など）は API 不通でも入力できる必要がある。
        return "SchemaCheckValue"
    return "スキーマ検証"


def check_field(panel: Panel, field: Field) -> None:
    where = f"{panel.id}.{field.key}"
    try:
        original = field.get(GUILD_ID)
    except Exception as exc:
        fail(f"{where}: get が例外 ({exc})")
        return

    expected = sample_value(field, field.to_json_value(original))
    try:
        field.set(GUILD_ID, field.coerce(expected))
    except Exception as exc:
        fail(f"{where}: set が例外 ({exc})")
        return

    try:
        actual = field.to_json_value(field.get(GUILD_ID))
    except Exception as exc:
        fail(f"{where}: 保存後の get が例外 ({exc})")
        return

    want = field.to_json_value(field.coerce(expected))
    if actual != want:
        fail(f"{where}: 保存した値が読み戻せない (書いた値={want!r} 読めた値={actual!r})")
        return

    # 「未設定に戻す」も設定操作のひとつ。0 / None / キー欠落の揺れをここで検出する。
    if field.nullable:
        try:
            field.set(GUILD_ID, field.coerce(None))
            cleared = field.to_json_value(field.get(GUILD_ID))
        except Exception as exc:
            fail(f"{where}: 未設定に戻せない ({exc})")
            return
        if cleared not in (None, "", [], 0):
            fail(f"{where}: 未設定に戻したのに値が残る ({cleared!r})")
            return

    print(f"{_OK} {where}")


def check_collection(panel: Panel, collection) -> None:
    where = f"{panel.id}.{collection.key}"
    try:
        before = collection.list(GUILD_ID)
    except Exception as exc:
        fail(f"{where}: list が例外 ({exc})")
        return

    if collection.add is None:
        print(f"{_OK} {where} (list のみ: {len(before)} 件)")
        return

    payload = {}
    for field in collection.item_fields:
        if field.required or field.default is not None:
            payload[field.key] = field.coerce(sample_value(field, None))
    for field in collection.item_fields:
        payload.setdefault(field.key, field.coerce(sample_value(field, None)))

    try:
        item_id = collection.add(GUILD_ID, payload)
    except Exception as exc:
        fail(f"{where}: add が例外 ({exc})")
        return

    rows = collection.list(GUILD_ID)
    if len(rows) != len(before) + 1:
        fail(f"{where}: add したのに件数が増えない ({len(before)} -> {len(rows)})")
        return

    if collection.remove is not None:
        target = str(item_id) if item_id is not None else str(rows[-1].get(collection.id_key))
        try:
            collection.remove(GUILD_ID, target)
        except Exception as exc:
            fail(f"{where}: remove が例外 ({exc})")
            return
        after = collection.list(GUILD_ID)
        # sticky は「削除保留」を立てる方式なので、件数が減らなくても保留印が付いていればよい。
        removed = len(after) < len(rows) or any(
            row.get(collection.id_key) == target and row.get("pending_delete") for row in after
        )
        if not removed and len(after) == len(rows):
            still_there = any(str(row.get(collection.id_key)) == target for row in after)
            if still_there and panel.id != "sticky":
                fail(f"{where}: remove しても消えない (id={target})")
                return

    print(f"{_OK} {where}")


def main() -> int:
    print("== 1. 宣言の構造チェック ==")
    problems = validate()
    for problem in problems:
        fail(problem)
    if not problems:
        print(f"{_OK} 構造に問題なし（パネル {len(PANELS)} 枚）")

    print()
    print("== 2. パネルの path が実在するルートか ==")
    from webapp_admin.app import app  # SETTINGS_DIR 差し替え後に読み込む

    routes = collect_route_paths(app.routes)
    for panel in PANELS:
        if not panel.path:
            print(f"{_OK} {panel.id} (ネイティブ実装のため対象外)")
        elif panel.path in routes:
            print(f"{_OK} {panel.id} -> {panel.path}")
        else:
            fail(f"{panel.id}: path {panel.path} に対応するルートが無い")

    print()
    print("== 3. フィールドの get / set 往復 ==")
    for panel in PANELS:
        if panel.custom:
            continue
        for field in panel.fields:
            check_field(panel, field)

    print()
    print("== 4. コレクションの list / add / remove 往復 ==")
    for panel in PANELS:
        if panel.custom:
            continue
        for collection in panel.collections:
            check_collection(panel, collection)

    print()
    if failures:
        print(f"RESULT: {len(failures)} 件の不整合")
        return 1
    print("RESULT: 全て通過")
    return 0


if __name__ == "__main__":
    sys.exit(main())
