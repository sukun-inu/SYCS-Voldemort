"""純度ごとの値段の API（GET /api/prices/calculate）の基準（expected.json）を、本物の Python の Web から作る。

対象は webapp/app.py の calculate_by_purity と、その前後で効くもの（入力の検証と 422 の言葉・最新の値段の
キャッシュ〔_get_latest_prices〕・計算のキャッシュ・レート制限〔calculate の枠と既定の枠〕・許すホスト・見出し・
405・404・500）。Rust の Web（rust/apps/web）の値段の計算のテストが読む。

本物の Web（webapp/app.py の app）に、ミドルウェアごと通す。差し替えるのは DB を読む 1 つだけ（webapp/app.py が
import した名前のところで）:

    load_latest_rows(session) → {金属の鍵: 行}（行は snapshot_date・price_per_gram・delta_from_previous を持つ）

例（cases.json）の service に、偽物が返すものを書く（書かなかった関数が呼ばれたら作り直しを止める）。
それ以外の書き方（値の印・要求の並び・接続元・時計・環境変数）は ../web_harness.py の説明のとおり。基準には、
例ごとに開いた service と、要求ごとに送った要求・偽物に届いた呼び出し（引数まで）・応答（状態・見出し・本文）を書く。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/web/tests/fixtures/prices_calculate/generate.py

ほかの API の基準は、このファイルを写して、cases.json と（DB や外へ行く関数が増えるなら）web_harness.py の
WEB_SERVICES を変えれば作れる（W3 の計画の「基準の作り方の型」）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import web_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/web/tests/fixtures/prices_calculate/generate.py"


def _patches(service: dict[str, Any], calls: list[dict[str, Any]], library: dict[str, Any]) -> list[Any]:
    """例の service から、webapp/app.py の DB や外へ行く名前を差し替える patch を作る（この API は 1 つだけ使う）。"""
    return harness.service_patches(harness.WEB_SERVICES, service, calls, library)


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    web, env = harness.load_web()
    return {**harness.header(document, env, GENERATED_BY), "cases": harness.run_cases(web, document, _patches)}


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
