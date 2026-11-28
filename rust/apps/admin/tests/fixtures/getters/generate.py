"""設定パネルの値を読む関数（Field.get・Collection.list・Panel.badge）と Field.to_json_value の基準を、
本物の Python で作る。

Rust の管理画面（rust/apps/admin）の tests/getters_golden.rs が読む。宣言（webapp_admin/schema/registry.py の PANELS）が
指す読む関数を全部、例の設定の JSON ごとに呼び、答え（値か、例外の型の名前と文）を書く。関数の名前は schema.json と
同じ付け方（../schema/generate.py の ref_name をそのまま使う）。入力欄の関数は、to_json_value に通した値も書く。

例（cases.json）:

    guild_id                     読むサーバーの ID（例ごとに書かなければ文書の guild_id）
    cases[].settings             設定の全体（{"guilds": {鍵: 設定}}）。{"$raise": …, "message": …} なら読み込めない
                                 （services.settings_pg.SettingsNotLoaded を投げる）
    to_json.widgets・values      入力欄の種類 × 値の表（to_json.defaults は種類ごとの既定値）

設定は services.settings_store._load_all を差し替えて渡す（本物の Postgres にも settings.json にも触らない）。
DJAudio の数の既定は環境変数（DJAUDIO_*）を Python の既定と違う値にして import し、Rust のテストも同じ値を使う。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/getters/generate.py

**`from __future__ import annotations` を書かないこと**（ほかの道具と同じ決まり。errors/generate.py の説明）。
"""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/getters/generate.py"
SCHEMA_TOOL = HERE.parent / "schema" / "generate.py"
SECRET = "a5-getters-fixture-secret-not-for-production"
# Python の既定（600・30・3）と違う値にして、Rust が環境変数を読んでいることも確かめる。
DJAUDIO_ENV = {
    "DJAUDIO_CACHE_TTL_SECONDS": "720",
    "DJAUDIO_COOLDOWN_SECONDS": "45",
    "DJAUDIO_MAX_URLS_PER_MSG": "4",
}


def schema_tool() -> Any:
    """../schema/generate.py を読み込む（関数の名前の付け方を schema.json と同じにするため）。"""
    spec = importlib.util.spec_from_file_location("admin_schema_export", SCHEMA_TOOL)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{SCHEMA_TOOL} を読み込めない")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def functions(tool: Any) -> dict[str, tuple[str, Any, Any]]:
    """宣言が指す読む関数（名前 → (種類, 関数, 入力欄)。名前の順）。種類は get・list・badge。"""
    from webapp_admin.schema.registry import PANELS

    found: dict[str, tuple[str, Any, Any]] = {}

    def remember(name: str, entry: tuple[str, Any, Any]) -> None:
        """同じ名前に別の関数が来たら止める（Rust は名前で引く）。"""
        if name in found and found[name][1] is not entry[1]:
            raise SystemExit(f"関数の名前がぶつかった: {name}")
        found[name] = entry

    for panel in PANELS:
        for field in panel.fields:
            if field.get is not None:
                remember(tool.ref_name(field.get, f"{panel.id}.{field.key}.get"), ("get", field.get, field))
        for collection in panel.collections:
            name = tool.ref_name(collection.list, f"{panel.id}.{collection.key}.list")
            remember(name, ("list", collection.list, None))
        if panel.badge is not None:
            remember(tool.ref_name(panel.badge, f"{panel.id}.badge"), ("badge", panel.badge, None))
    return dict(sorted(found.items()))


def settings_loader(spec: Any) -> Any:
    """settings_store._load_all の偽物（例の settings。{"$raise": …} なら SettingsNotLoaded を投げる）。"""
    from services.settings_pg import SettingsNotLoaded

    def load_all() -> Any:
        """呼ばれるたびに例の中身を作り直して返す（読む関数が書き換えても次に響かない）。"""
        if isinstance(spec, dict) and "$raise" in spec:
            raise SettingsNotLoaded(str(spec.get("message", "")))
        return json.loads(json.dumps(spec))

    return load_all


def call(fn: Any, field: Any, guild_id: int) -> dict[str, Any]:
    """関数を呼んで、値（入力欄なら to_json_value に通したものも）か、例外の型の名前と文を返す。"""
    try:
        value = fn(guild_id)
    except Exception as exc:
        return {"raises": {"type": type(exc).__name__, "message": str(exc)}}
    result: dict[str, Any] = {"value": harness.encode(value)}
    if field is not None:
        result["json"] = harness.encode(field.to_json_value(value))
    return result


def run_case(case: dict[str, Any], table: dict[str, tuple[str, Any, Any]], guild_id: int) -> dict[str, Any]:
    """1 つの設定で、全部の関数を呼ぶ。"""
    import services.settings_store as settings_store

    results: dict[str, Any] = {}
    with patch.object(settings_store, "_load_all", settings_loader(case["settings"])):
        for name, (_, fn, field) in table.items():
            results[name] = call(fn, field, guild_id)
    return {"name": case["name"], "guild_id": str(guild_id), "settings": case["settings"], "results": results}


def to_json_rows(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """入力欄の種類 × 値 → to_json_value の答え（既定値は種類ごとに決めたもの。無ければ None）。"""
    from webapp_admin.schema.types_def import Field, Widget

    rows = []
    for widget in spec["widgets"]:
        default = spec.get("defaults", {}).get(widget)
        field = Field("key", "label", Widget(widget), default=default)
        for value in spec["values"]:
            result = harness.encode(field.to_json_value(value))
            rows.append({"widget": widget, "default": default, "value": value, "result": result})
    return rows


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(SECRET, DJAUDIO_ENV)
    tool = schema_tool()
    import config

    table = functions(tool)
    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    cases = [run_case(case, table, int(case.get("guild_id", document["guild_id"]))) for case in document["cases"]]
    return {
        "generated_by": GENERATED_BY,
        "djaudio": {
            "cache_ttl": config.DJAUDIO_CACHE_TTL,
            "cooldown": config.DJAUDIO_COOLDOWN,
            "max_urls": config.DJAUDIO_MAX_URLS,
        },
        "functions": {name: kind for name, (kind, _, _) in table.items()},
        "cases": cases,
        "to_json": to_json_rows(document["to_json"]),
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
