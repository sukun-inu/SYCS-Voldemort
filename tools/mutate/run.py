"""変異テスト: コードを 1 か所ずつわざと壊して、テストが落ちることを確かめる。

CI の「変異テスト」（.github/workflows/mutate.yml。手で回す）が回す。**手元の PC では回さない**
（Rust のビルドとテストを変異の数だけ繰り返すので重い。本人の指示 2026-11-28）。

一覧は tools/mutate/lists/ の下の .py に書く:

    KIND = "rust"   # か "python"
    MUTS = [
        ("変異なし（通るはず）", "services/x.py", "a = 1", "a = 1"),   # 最初は必ず変えないもの
        ("境を含める", "services/x.py", "if n < 3:", "if n <= 3:"),
    ]

パスはリポジトリの直下から。置き換える前の文は、そのファイルにちょうど 1 か所だけあること。
**最初の 1 つは何も変えないもの**で、これが通らないと（テストが元から落ちる・道具が足りない）
ほかの結果は全部「落ちた」に見えて何も確かめていないことになるので、そこで止める。

変異はチェックアウトしたファイルを書き換えて当て、テストのあとで元に戻す（CI の使い捨ての木なので）。
1 つでも「通ってしまった」があれば、終了コード 1 で終わる（一覧は CI の Summary にも出す）。
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TIMEOUT_SECONDS = 1800


def load(list_path: str):
    """一覧のファイルを読み、(KIND, MUTS) を返す。"""
    path = (ROOT / list_path).resolve()
    spec = importlib.util.spec_from_file_location("mutation_list", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"一覧を読めない: {list_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    kind = getattr(module, "KIND", None)
    if kind not in ("rust", "python"):
        raise SystemExit(f"KIND は rust か python（いまは {kind!r}）")
    return kind, list(module.MUTS)


def test_command(kind: str, path: str) -> tuple[list[str], Path]:
    """変異を当てたファイルに合わせて、回すテストと作業ディレクトリを決める。"""
    if kind == "python":
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-q"], ROOT
    packages = ["-p", "sycs-bot"]
    if path.startswith("rust/crates/sycs-core/"):
        packages = ["-p", "sycs-core", "-p", "sycs-bot"]
    elif path.startswith("rust/crates/sycs-text/"):
        packages = ["-p", "sycs-text", "-p", "sycs-bot"]
    elif path.startswith("rust/crates/sycs-web/"):
        # web の土台は、使う側（配信）のテストでも確かめる。
        packages = ["-p", "sycs-web", "-p", "sycs-cdn"]
    elif path.startswith("rust/apps/cdn/"):
        packages = ["-p", "sycs-cdn"]
    return ["cargo", "test", "--locked", "-q", *packages, "--", "--include-ignored"], ROOT / "rust"


def run_one(kind: str, label: str, path: str, before: str, after: str) -> str:
    """1 つの変異を当ててテストを回し、結果の言葉を返す（ファイルは元に戻す）。"""
    target = ROOT / path
    original = target.read_bytes()
    text = original.decode("utf-8")
    count = text.count(before)
    if count != 1:
        return f"当てる場所が 1 か所に定まらない（{count} か所）"
    target.write_bytes(text.replace(before, after).encode("utf-8"))
    try:
        command, cwd = test_command(kind, path)
        try:
            done = subprocess.run(
                command, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired:
            return "テストが落ちた（時間切れ）"
        return "通ってしまった" if done.returncode == 0 else "テストが落ちた"
    finally:
        target.write_bytes(original)


def summary(rows: list[tuple[str, str]]) -> None:
    """結果の表を CI の Summary に書く（CI の外なら何もしない）。"""
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        f.write("| 変異 | 結果 |\n|---|---|\n")
        for label, result in rows:
            f.write(f"| {label} | {result} |\n")


def main(list_path: str) -> int:
    """一覧の変異を順に当てる。最初の「変えないもの」が通らなければ、そこで止める。"""
    kind, muts = load(list_path)
    if not muts or muts[0][2] != muts[0][3]:
        print("一覧の最初は、何も変えないもの（置き換える前と後が同じ）にすること")
        return 2
    rows: list[tuple[str, str]] = []
    survived = 0
    for index, (label, path, before, after) in enumerate(muts):
        result = run_one(kind, label, path, before, after)
        print(f"{result}: {label}", flush=True)
        rows.append((label, result))
        if index == 0 and result != "通ってしまった":
            print("変異なしの基準が通らない。テストか道具が足りないので、ほかの結果は当てにならない。ここで止める")
            summary(rows)
            return 1
        if index > 0 and not result.startswith("テストが落ちた"):
            survived += 1
    summary(rows)
    print(f"変異 {len(muts) - 1} 通りのうち、捕まらなかったもの {survived} 通り")
    return 1 if survived else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("使い方: python tools/mutate/run.py tools/mutate/lists/<名前>.py")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
