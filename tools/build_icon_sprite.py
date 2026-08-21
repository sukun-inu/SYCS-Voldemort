#!/usr/bin/env python3
"""管理UIで使うアイコンだけの SVG スプライトを作り直す。

    python tools/build_icon_sprite.py

テンプレートと JS から `bi-*` の参照を集め、bootstrap-icons の公式スプライト
（2,000 個以上）から該当する分だけを抜き出して
webapp_admin/static/icons/sprite.svg に書き出す。

アイコンを増やしたあとに実行すること。実行にはネットワークが必要。
"""

from __future__ import annotations

import re
import sys
import urllib.request
from pathlib import Path

VERSION = "1.13.1"
SOURCE = f"https://cdn.jsdelivr.net/npm/bootstrap-icons@{VERSION}/bootstrap-icons.svg"

ROOT = Path(__file__).resolve().parent.parent
SEARCH_DIRS = [
    ROOT / "webapp_admin" / "templates",
    ROOT / "webapp_admin" / "static" / "js",
    ROOT / "webapp_admin" / "static" / "css",
]
OUTPUT = ROOT / "webapp_admin" / "static" / "icons" / "sprite.svg"

_ICON_REF = re.compile(r"\bbi-([a-z0-9-]+)")
_SYMBOL = re.compile(r'<symbol[^>]*id="([^"]+)"[^>]*>.*?</symbol>', re.S)


def used_icon_names() -> list[str]:
    names: set[str] = set()
    for directory in SEARCH_DIRS:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in {".html", ".js", ".css"}:
                names.update(_ICON_REF.findall(path.read_text(encoding="utf-8")))
    # icon('house-fill') のように接頭辞なしで書かれている呼び出しも拾う
    for directory in SEARCH_DIRS:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in {".html", ".js"}:
                text = path.read_text(encoding="utf-8")
                names.update(re.findall(r"icon\(\s*['\"]([a-z0-9-]+)['\"]", text))
    return sorted(names)


def main() -> int:
    names = used_icon_names()
    print(f"参照されているアイコン: {len(names)} 個")

    with urllib.request.urlopen(SOURCE, timeout=120) as response:
        sprite = response.read().decode("utf-8")
    symbols = {match.group(1): match.group(0) for match in _SYMBOL.finditer(sprite)}
    print(f"取得元: {SOURCE} ({len(symbols):,} アイコン)")

    kept = [name for name in names if name in symbols]
    missing = [name for name in names if name not in symbols]

    body = "\n".join(symbols[name] for name in kept)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" style="display:none">\n'
        f"<!-- bootstrap-icons {VERSION} (MIT License) から、管理UIで使うアイコンだけを抜き出したもの。\n"
        "     アイコンを増やしたら tools/build_icon_sprite.py を実行して作り直す。 -->\n"
        f"{body}\n</svg>\n",
        encoding="utf-8",
    )
    print(f"書き出し: {OUTPUT.relative_to(ROOT)} ({OUTPUT.stat().st_size:,} bytes / {len(kept)} アイコン)")

    if missing:
        print("見つからなかった名前:", ", ".join(missing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
