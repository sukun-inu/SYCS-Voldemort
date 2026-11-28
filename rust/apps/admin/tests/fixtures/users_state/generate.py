"""利用者の状態の一覧と詳細の API の基準（expected.json）を、本物の Python の管理画面から作る。

対象は webapp_admin/api/users.py の list_states（GET /admin/api/users/state）と user_detail
（GET /admin/api/users/state/{user_id}）。Rust の管理画面（rust/apps/admin）の利用者の状態のテストが読む。

本物の管理画面（webapp_admin/app.py の app）に、セッション・ログインの確かめ・パラメータの検証・エラーの応答・
見出しのミドルウェアごと通す。差し替えるのは services/user_state_service.py の 3 つだけ（API のモジュールが
import した名前のところで）:

    list    → list_recent_user_states(guild_id, query=…, limit=…, offset=…)
    count   → count_user_states(guild_id, query=…)
    detail  → get_user_state_detail(guild_id, user_id, event_limit=…)

例（cases.json）の service に、偽物が返すものを書く（書かなかった関数が呼ばれたら作り直しを止める）。
それ以外の書き方（Cookie の作り方・値の印・時計）は ../admin_harness.py の説明のとおり。基準には、例ごとに
送った要求・偽物に届いた呼び出し（引数まで）・応答（状態・見出し・本文）を書く。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/users_state/generate.py

ほかの API の基準は、このファイルを写して SERVICES と patch の先を変えれば作れる（W2 の計画の「基準の作り方の型」）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/users_state/generate.py"
# API のモジュール（差し替える名前の置き場）。
API_MODULE = "webapp_admin.api.users"
# 例の service の鍵 → 差し替える関数の名前。
SERVICES = {
    "list": "list_recent_user_states",
    "count": "count_user_states",
    "detail": "get_user_state_detail",
}


def _patches(service: dict[str, Any], calls: list[dict[str, Any]], library: dict[str, Any]) -> list[Any]:
    """例の service から、API のモジュールの 3 つの名前を差し替える patch を作る。"""
    from unittest.mock import patch

    patchers = []
    for key, name in SERVICES.items():
        if key in service:
            fake = harness.fake_function(name, service[key], calls, library)
        else:
            fake = harness.unexpected_function(name, calls)
        patchers.append(patch(f"{API_MODULE}.{name}", fake))
    return patchers


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment(document["secret"])
    from webapp_admin.app import app

    return {**harness.header(document, GENERATED_BY), "cases": harness.run_cases(app, document, _patches)}


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
