#!/usr/bin/env python3
"""本体の関数に docstring が付いているかを数え、下限を割ったら落とす。

  python tools/check_docstrings.py            現在の充足率を出して下限と比べる
  python tools/check_docstrings.py --list     不足している関数を全部並べる
  python tools/check_docstrings.py --floor N  下限を上書きして試す（CI では使わない）

対象は本体のみ。tests/ tools/ scripts/ は数えない（テストの docstring は
CONTRIBUTING 5. で別に「なぜこのテストがあるか」を求めているし、この
スクリプト自身を対象にしても意味が無い）。

■ 下限を持つ理由

.coveragerc の fail_under と同じ考え方で、「今より悪くしない」ための歯止め。
100% に達したあとも下限として残しておけば、docstring の無い関数を足した
時点で CI が落ちる。達成したことより、達成を保つことのほうが難しい。

■ 何をもって「付いている」とするか

ast.get_docstring() が空でない文字列を返すこと。中身の良し悪しはここでは
見ない。**見られないことを承知で数えている。** 何を書くべきかは
CONTRIBUTING 4.（コメントは「なぜ」を書く）に書いてあり、それは人が読んで
判断するしかない。この検査が守れるのは「書く場所が空でない」ことだけで、
「読めば分かることを書き写しただけの docstring」は素通りする。

数だけ追って中身が伴わないなら、この検査は無いほうがましになる。増やす
ときは、その関数が「無いと何が困るか」を書くこと。
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

# 現在の下限。改善したら締めること（CONTRIBUTING 7.）。
# 100 に到達したので 100 で固定した。ここを下げるのは「docstring の無い関数を
# 足したい」ということなので、下げる前に 4. を読み直すこと。
FLOOR_PERCENT = 100.0

SKIP_PREFIXES = ("tests/", "tools/", "scripts/")


def _app_files() -> list[str]:
    """検査対象のファイル一覧。

    git の管理下にあるものだけを見る。未追跡のファイルを数え落とすと、
    新設したモジュールが丸ごと検査を素通りする（実際、別の集計でこれを
    踏んで数を誤った）。
    """
    out = subprocess.run(
        ["git", "ls-files", "*.py"],
        capture_output=True,
        text=True,
        check=True,
        cwd=Path(__file__).resolve().parent.parent,
    ).stdout.split()
    return [f for f in out if not f.startswith(SKIP_PREFIXES)]


def _scan(root: Path, files: list[str]) -> tuple[int, list[tuple[str, str, int]]]:
    """関数の総数と、docstring が無いものの一覧を返す。"""
    total = 0
    missing: list[tuple[str, str, int]] = []
    for name in files:
        path = root / name
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as e:
            print(f"読めませんでした: {name} ({e})", file=sys.stderr)
            return -1, []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            total += 1
            if not ast.get_docstring(node):
                missing.append((name, node.name, node.lineno))
    return total, missing


def main() -> int:
    """充足率を出し、下限を割っていれば 1 を返す。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="不足している関数を並べる")
    parser.add_argument("--floor", type=float, default=FLOOR_PERCENT, help="下限を上書きする")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    total, missing = _scan(root, _app_files())
    if total < 0:
        return 1
    if total == 0:
        print("対象の関数がありません。")
        return 1

    have = total - len(missing)
    percent = have * 100.0 / total
    print(f"本体の関数 {total} 本 / docstring あり {have} 本 = {percent:.2f}%（下限 {args.floor:.2f}%）")

    if args.list:
        for name, func, line in sorted(missing):
            print(f"  {name}:{line}: {func}")

    if percent + 1e-9 < args.floor:
        print(
            f"\nRESULT: 下限を割りました（{percent:.2f}% < {args.floor:.2f}%）。\n"
            "docstring の無い関数を足したか、既存の docstring を消しています。\n"
            "--list で場所が出ます。何を書くかは CONTRIBUTING 4. を参照。",
            file=sys.stderr,
        )
        return 1

    print("RESULT: 全て通過")
    return 0


if __name__ == "__main__":
    sys.exit(main())
