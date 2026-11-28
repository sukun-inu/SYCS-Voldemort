"""設定パネルの定義（webapp_admin/schema/）を、Rust の管理画面（rust/apps/admin）が読める JSON に書き出す。

管理画面の設定の画面は、webapp_admin/schema/panels/ の宣言（Panel・Section・Field・Collection・Widget）だけから
描かれ、検証され、保存される（webapp_admin/schema/types_def.py の冒頭）。Rust の管理画面も同じ宣言から動くように、
宣言を JSON に写す（スラッシュコマンドの definitions.json と同じやり方）。書き出すもの（schema.json）:

- vocabulary: 入力欄の種類・選択肢の供給元・種類から決まる供給元・文字の上限・期間の単位（Rust の列挙と突き合わせる）
- panels: PANELS の並びのまま。パネルごとに
  - wire: Panel.to_json() そのもの。GET /admin/api/apps/{id} の本文のうち、choices・values などを足す前の形で、
    キーの並びも Python のまま。入力欄の種類・上下限・既定値・選択肢・必須かどうかは全部ここにある
  - tile: スタートメニューのタイル（Panel.tile()）。バッジは数えずに null（数は Rust が実行時に数える）
  - dev_only・custom・badge（バッジを数える関数の名前）
  - fields・collections: 入力欄と一覧ごとに、値を出し入れする関数の名前（get・set、list・add・update・remove）
- functions: 上の名前ごとの手がかり。呼ぶ services の関数（calls）、関数の中に書いてある設定の鍵らしい文字列
  （identifiers）、工場が閉じ込めた値（bound。djaudio の _set_limit("cache_ttl") の "cache_ttl" など）、使っている
  モジュールの定数（constants。地震の NOTIFY_TYPES など）、たどったパネル側の関数（helpers）。呼ばれる services の
  関数自身も載せる（その中の鍵らしい文字列と、さらに呼ぶ services の関数の名前まで。その先はたどらない）
- problems: webapp_admin/schema/registry.py の validate() の結果（空のはず）

関数の名前は「モジュール.関数」（services.settings_store.set_welcome_channel など）。工場が作った関数は閉じ込めた値を
後ろに付けて区別する（webapp_admin.schema.panels.djaudio._set_limit.<locals>.setter[key=cache_ttl]）。lambda は
どのパネルの何に使うかを付ける（webapp_admin.schema.panels.sticky.<lambda>[sticky.badge]）。

identifiers は手がかりで、設定の鍵そのものの一覧ではない（呼び出しのキーワード引数の名前や、状態の値も混ざる）。
getter・setter が何をするかの本当の確かめは、Rust 側で動かして Python と突き合わせる基準でする（W2 の計画）。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/schema/generate.py

tests/test_admin_schema_export.py が、書き出しが PANELS を漏れなく写していることを確かめる。
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
OUTPUT = HERE / "schema.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/schema/generate.py"

# 設定の鍵らしい文字列（英字か _ で始まり、英数字と _ だけ）。docstring や画面の文言はここで落ちる。
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# パネル側の関数のモジュール。ここの関数はたどって、その先の services の関数まで集める。
_SCHEMA_PREFIX = "webapp_admin.schema."
_SERVICES_PREFIX = "services."
# JSON にできない定数の印。
_NOT_DATA = object()


def prepare() -> None:
    """宣言を import する前に、本物の設定に触らない置き場を渡し、リポジトリを import できるようにする。

    services の一部は import した時点で SETTINGS_DIR を読む（tools/generate_admin_docs.py と同じ理由）。
    既に決まっていれば（テストから呼ぶとき）そのまま使う。
    """
    os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="admin-schema-export-"))
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def _qualified(fn: Any) -> tuple[str, str]:
    """関数のモジュール名と、モジュールの中での名前。"""
    return str(getattr(fn, "__module__", "?")), str(getattr(fn, "__qualname__", getattr(fn, "__name__", "?")))


def _is_lambda(fn: Any) -> bool:
    """lambda で書いた関数か（名前では区別できないので、使い道を名前に付ける）。"""
    return _qualified(fn)[1].endswith("<lambda>")


def _is_scalar(value: Any) -> bool:
    """JSON にそのまま書ける 1 つの値か。"""
    return value is None or isinstance(value, (str, int, float, bool))


def bound_values(fn: Any) -> dict[str, Any]:
    """工場が作った関数に閉じ込めた値（JSON にそのまま書けるものだけ。名前の順）。"""
    code = getattr(fn, "__code__", None)
    if code is None:
        return {}
    values: dict[str, Any] = {}
    for name, cell in zip(code.co_freevars, getattr(fn, "__closure__", None) or ()):
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if _is_scalar(value):
            values[name] = value
    return dict(sorted(values.items()))


def ref_name(fn: Any, role: str) -> str:
    """関数の名前（モジュール.関数。工場が作ったものは閉じ込めた値を、lambda は使い道 role を後ろに付ける）。"""
    module, qualname = _qualified(fn)
    if _is_lambda(fn):
        return f"{module}.{qualname}[{role}]"
    bound = bound_values(fn)
    if bound:
        inner = ",".join(f"{key}={value}" for key, value in bound.items())
        return f"{module}.{qualname}[{inner}]"
    return f"{module}.{qualname}"


def _code_objects(code: types.CodeType) -> list[types.CodeType]:
    """関数の本体と、その中に書いた関数（入れ子の def・lambda・生成式）の本体。"""
    found = [code]
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            found.extend(_code_objects(const))
    return found


def _strings(value: Any) -> list[str]:
    """定数（入れ子のタプルの中も）に入っている文字列。"""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (tuple, frozenset)):
        return [text for item in value for text in _strings(item)]
    return []


def _identifiers(fn: Any) -> set[str]:
    """関数の中に書いてある文字列のうち、設定の鍵らしいもの（docstring は除く）。"""
    code = getattr(fn, "__code__", None)
    if code is None:
        return set()
    found: set[str] = set()
    for inner in _code_objects(code):
        for const in inner.co_consts:
            for text in _strings(const):
                if text != fn.__doc__ and _IDENTIFIER.match(text):
                    found.add(text)
    return found


def _referenced(fn: Any) -> list[tuple[str, Any, bool]]:
    """関数の中で引いている名前と値。（名前, 値, モジュールの大域の値か）の並び（名前の順）。

    大域の値は、本体と入れ子の本体が名前で引くもの（co_names。属性の名前も混ざるが、大域に同じ名前が無ければ
    引けないので落ちる）。閉じ込めた値は関数だけを拾う（定数は bound に出す）。
    """
    code = getattr(fn, "__code__", None)
    if code is None:
        return []
    namespace = getattr(fn, "__globals__", {})
    found: dict[str, tuple[Any, bool]] = {}
    for inner in _code_objects(code):
        for name in inner.co_names:
            if name in namespace:
                found[name] = (namespace[name], True)
    for name, cell in zip(code.co_freevars, getattr(fn, "__closure__", None) or ()):
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if inspect.isfunction(value):
            found.setdefault(name, (value, False))
    return [(name, value, is_global) for name, (value, is_global) in sorted(found.items())]


def _to_data(value: Any) -> Any:
    """モジュールの定数を JSON の値にする（タプルは配列）。JSON にできなければ _NOT_DATA。"""
    if _is_scalar(value):
        return value
    if isinstance(value, (tuple, list)):
        items = [_to_data(item) for item in value]
        return _NOT_DATA if any(item is _NOT_DATA for item in items) else items
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        entries = {key: _to_data(item) for key, item in value.items()}
        return _NOT_DATA if any(item is _NOT_DATA for item in entries.values()) else entries
    return _NOT_DATA


def _remember(found: dict[str, Any], name: str, fn: Any) -> None:
    """たどった関数を名前で控える。同じ名前に別の関数が来たら止める（名前で区別できなくなる）。"""
    if found.setdefault(name, fn) is not fn:
        raise SystemExit(f"関数の名前がぶつかった: {name}")


def _walk(fn: Any, summary: dict[str, Any], found: dict[str, Any], seen: set[int]) -> None:
    """fn の中を見て summary に集める。パネル側の関数はその中までたどる（services の関数の中まではたどらない）。"""
    target = inspect.unwrap(fn)
    if id(target) in seen:
        return
    seen.add(id(target))
    schema_side = _qualified(target)[0].startswith(_SCHEMA_PREFIX)
    summary["identifiers"] |= _identifiers(target)
    for name, value, is_global in _referenced(target):
        if inspect.isfunction(value):
            module = _qualified(value)[0]
            if module.startswith(_SERVICES_PREFIX):
                key = ref_name(value, name)
                summary["calls"].add(key)
                _remember(found, key, value)
            elif schema_side and module.startswith(_SCHEMA_PREFIX):
                key = ref_name(value, name)
                summary["helpers"].add(key)
                _remember(found, key, value)
                _walk(value, summary, found, seen)
            continue
        if schema_side and is_global and not inspect.ismodule(value):
            data = _to_data(value)
            if data is not _NOT_DATA:
                summary["constants"][name] = data


def describe(fn: Any, found: dict[str, Any]) -> dict[str, Any]:
    """1 つの関数の手がかり（モジュールの説明の functions）。たどった関数は found に控える。"""
    summary: dict[str, Any] = {"calls": set(), "helpers": set(), "identifiers": set(), "constants": {}}
    _walk(fn, summary, found, set())
    module, qualname = _qualified(fn)
    bound = bound_values(fn)
    if _is_lambda(fn):
        kind = "lambda"
    elif getattr(fn, "__closure__", None):
        kind = "closure"
    else:
        kind = "function"
    return {
        "module": module,
        "qualname": qualname,
        "kind": kind,
        "bound": bound,
        "calls": sorted(summary["calls"]),
        "helpers": sorted(summary["helpers"]),
        "identifiers": sorted(summary["identifiers"]),
        "constants": dict(sorted(summary["constants"].items())),
    }


def _function_table(refs: dict[str, Any]) -> dict[str, Any]:
    """宣言が指す関数と、そこからたどった関数（パネル側の関数と、呼ばれる services の関数）の手がかり。名前の順。"""
    found: dict[str, Any] = {}
    table = {name: describe(fn, found) for name, fn in refs.items()}
    for name, fn in list(found.items()):
        if name in refs:
            _remember(refs, name, fn)
            continue
        # services の関数の中の、さらに先の関数は表に足さない（その名前は calls に残る）。
        table[name] = describe(fn, {})
    return dict(sorted(table.items()))


def _export_panel(panel: Any, refs: dict[str, Any]) -> dict[str, Any]:
    """1 枚のパネルを書き出す形にする。値を出し入れする関数は名前にして refs（名前 → 関数）に控える。"""

    def name(fn: Any, role: str) -> str | None:
        """関数があれば名前にして控える（無ければ None）。"""
        if fn is None:
            return None
        key = ref_name(fn, role)
        _remember(refs, key, fn)
        return key

    fields = []
    collections = []
    for index, section in enumerate(panel.sections):
        for field in section.fields:
            fields.append(
                {
                    "section": index,
                    "key": field.key,
                    "get": name(field.get, f"{panel.id}.{field.key}.get"),
                    "set": name(field.set, f"{panel.id}.{field.key}.set"),
                }
            )
        for collection in section.collections:
            role = f"{panel.id}.{collection.key}"
            collections.append(
                {
                    "section": index,
                    "key": collection.key,
                    "item_fields": [item.key for item in collection.item_fields],
                    "list": name(collection.list, f"{role}.list"),
                    "add": name(collection.add, f"{role}.add"),
                    "update": name(collection.update, f"{role}.update"),
                    "remove": name(collection.remove, f"{role}.remove"),
                }
            )
    return {
        "id": panel.id,
        "dev_only": panel.dev_only,
        "custom": panel.custom,
        "badge": name(panel.badge, f"{panel.id}.badge"),
        "wire": panel.to_json(),
        "tile": dataclasses.replace(panel, badge=None).tile(0),
        "fields": fields,
        "collections": collections,
    }


def _vocabulary() -> dict[str, Any]:
    """宣言が使う語の一覧（入力欄の種類・選択肢の供給元・種類から決まる供給元・文字の上限・期間の単位）。"""
    from webapp_admin.schema.duration import UNITS
    from webapp_admin.schema.types_def import IMPLIED_SOURCE, ChoiceSource, Widget
    from webapp_admin.security import MAX_STR_LEN

    return {
        "widgets": [widget.value for widget in Widget],
        "choice_sources": [source.value for source in ChoiceSource],
        "implied_sources": {widget.value: source.value for widget, source in IMPLIED_SOURCE.items()},
        "max_str_len": MAX_STR_LEN,
        "duration_units": [[label, factor] for label, factor in UNITS],
    }


def build() -> dict[str, Any]:
    """PANELS を書き出す形にする（ファイルには書かない。テストもこれを呼ぶ）。"""
    prepare()
    from webapp_admin.schema.registry import PANELS, validate

    refs: dict[str, Any] = {}
    panels = [_export_panel(panel, refs) for panel in PANELS]
    return {
        "generated_by": GENERATED_BY,
        "vocabulary": _vocabulary(),
        "panels": panels,
        "functions": _function_table(refs),
        "problems": validate(),
    }


def render(document: dict[str, Any]) -> str:
    """書き出す文字列（UTF-8 のまま・字下げ 1・末尾に改行。キーの並びは作った順のまま）。"""
    return json.dumps(document, ensure_ascii=False, indent=1) + "\n"


def main(argv: list[str]) -> int:
    """schema.json（引数があればそのパス）に書き出す。"""
    path = Path(argv[0]) if argv else OUTPUT
    path.write_text(render(build()), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
