"""設定パネルの入力の検証（webapp_admin/schema/validation.py）の基準を、本物の Python で作る（純粋な表）。

Rust の管理画面（rust/apps/admin）の tests/validation_golden.rs が読む。宣言（webapp_admin/schema/registry.py の
PANELS）の入力欄を全部（パネルの直下と、一覧の入力欄）、例の入力の並び（raws）と選択肢の組（choices）の組み合わせで
validate_field に通し、答え（値か、利用者に見せる誤りの文か、拾われない例外の型と文）を書く。ID と選択の入力欄だけ
選択肢の組を全部試し、ほかの入力欄は none だけ（選択肢を見ないため）。

例（cases.json）:

    raws          入力の並び。{"$repeat": 文字, "times": 回数} は文字をくり返したもの（長さの上限の例）。基準には
                  開いたものを書く。64 ビットを超える整数は書かない（Rust の serde_json は本文の段階で小数にする）
    choices       選択肢の組の名前 → choices.resolve の答えの形（供給元 → [{"value", "label"}…]）
    values_cases  validate_values（パネル・届いた辞書・選択肢の組）
    item_cases    validate_item（パネル・一覧・届いた辞書・選択肢の組）
    humanize      duration.humanize に通す秒の並び

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/validation/generate.py

**`from __future__ import annotations` を書かないこと**（ほかの道具と同じ決まり。errors/generate.py の説明）。
"""

import json
import sys
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/validation/generate.py"
SECRET = "a6-validation-fixture-secret-not-for-production"
# 選択肢を見る入力欄（ID と選択）。ほかの入力欄は選択肢の組を none だけ試す。
CHOICE_WIDGETS = ("channel", "voice_channel", "role", "snowflake", "select")


def expand(value: Any) -> Any:
    """例の入力の印を開く（{"$repeat": 文字, "times": 回数}）。ほかは harness.decode と同じ。"""
    if isinstance(value, dict) and set(value) == {"$repeat", "times"}:
        return str(value["$repeat"]) * int(value["times"])
    return harness.decode(value, {})


def outcome(call: Callable[[], Any]) -> dict[str, Any]:
    """呼んだ答え（値・利用者に見せる誤りの文・拾われない例外の型と文のどれか）。"""
    from webapp_admin.schema.validation import InvalidValue

    try:
        value = call()
    except InvalidValue as exc:
        return {"invalid": str(exc)}
    except Exception as exc:
        return {"raises": {"type": type(exc).__name__, "message": str(exc)}}
    return {"value": harness.encode(value)}


def fields() -> list[tuple[str, Any, Any]]:
    """宣言の入力欄（パネルの ID・一覧の鍵〔直下なら None〕・Field）。PANELS の並びのまま。"""
    from webapp_admin.schema.registry import PANELS

    found: list[tuple[str, Any, Any]] = []
    for panel in PANELS:
        for field in panel.fields:
            found.append((panel.id, None, field))
        for collection in panel.collections:
            for field in collection.item_fields:
                found.append((panel.id, collection.key, field))
    return found


def field_rows(raws: list[Any], choices: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """入力欄の一覧と、入力欄 × 選択肢の組 × 入力 → 答えの表。"""
    from webapp_admin.schema.validation import validate_field

    listed: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, (panel_id, collection_key, field) in enumerate(fields()):
        widget = field.widget.value
        listed.append({"panel": panel_id, "collection": collection_key, "key": field.key, "widget": widget})
        names = list(choices) if widget in CHOICE_WIDGETS else ["none"]
        for name in names:
            for position, raw in enumerate(raws):

                def call(field: Any = field, raw: Any = raw, name: str = name) -> Any:
                    """1 項目を検証する（ループの値を閉じ込める）。"""
                    return validate_field(field, raw, choices[name])

                rows.append({"f": index, "c": name, "r": position, "result": outcome(call)})
    return listed, rows


def values_rows(cases: list[dict[str, Any]], choices: dict[str, Any]) -> list[dict[str, Any]]:
    """validate_values の例（答えは [clean, errors]）。"""
    from webapp_admin.schema.registry import PANEL_BY_ID
    from webapp_admin.schema.validation import validate_values

    rows = []
    for case in cases:
        panel = PANEL_BY_ID[case["panel"]]
        incoming = {key: expand(value) for key, value in case["incoming"].items()}
        result = outcome(lambda: validate_values(panel, incoming, choices[case["choices"]]))
        rows.append({**case, "incoming": harness.encode(incoming), "result": result})
    return rows


def item_rows(cases: list[dict[str, Any]], choices: dict[str, Any]) -> list[dict[str, Any]]:
    """validate_item の例（答えは [clean, errors]）。"""
    from webapp_admin.schema.registry import PANEL_BY_ID
    from webapp_admin.schema.validation import validate_item

    rows = []
    for case in cases:
        collection = PANEL_BY_ID[case["panel"]].collection(case["collection"])
        incoming = {key: expand(value) for key, value in case["incoming"].items()}
        result = outcome(lambda: validate_item(collection, incoming, choices[case["choices"]]))
        rows.append({**case, "incoming": harness.encode(incoming), "result": result})
    return rows


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(SECRET)
    from webapp_admin.schema.duration import humanize

    names = [case["name"] for case in document["values_cases"] + document["item_cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    raws = [expand(raw) for raw in document["raws"]]
    choices = document["choices"]
    listed, rows = field_rows(raws, choices)
    return {
        "generated_by": GENERATED_BY,
        "raws": harness.encode(raws),
        "choices": choices,
        "fields": listed,
        "rows": rows,
        "values_cases": values_rows(document["values_cases"], choices),
        "item_cases": item_rows(document["item_cases"], choices),
        "humanize": [[seconds, humanize(seconds)] for seconds in document["humanize"]],
    }


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
