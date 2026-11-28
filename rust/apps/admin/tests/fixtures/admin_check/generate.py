"""「いまもそのサーバーの管理者か」（webapp_admin/auth.py の user_still_admin）の基準（expected.json）を作る。

Rust の管理画面（rust/apps/admin）の tests/auth_golden.rs が読む。本物の user_still_admin を、偽物の Discord
（../fake_discord.py。auth._API をそこへ向ける）に当てて回し、例ごとに「Discord の答え方 → 答え（真・偽・null）
か投げた例外（型の名前と文）、Discord に届いた要求」を書く。権限の組み立て（持ち主・@everyone・持っている
ロールの permissions の OR と 0x8・int() で読めない permissions を飛ばす）と、答えの形が崩れたときの例外を表にする。

例（cases.json）は guild_id・user_id（無ければ文書のもの）・bot_token（無ければ文書のもの。空なら聞かない）・
discord（答え方）・expect（道具の確かめ。true・false・null か "raise"）を書く。

作り直すとき（本番と同じ依存 requirements.txt で。CI の「基準」が tools/fixtures/regen.py から回す）:

    python rust/apps/admin/tests/fixtures/admin_check/generate.py
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import admin_harness as harness  # noqa: E402
import fake_discord  # noqa: E402

CASES = HERE / "cases.json"
OUTPUT = HERE / "expected.json"
GENERATED_BY = "rust/apps/admin/tests/fixtures/admin_check/generate.py"


def run_case(case: dict[str, Any], document: dict[str, Any], fake: Any) -> dict[str, Any]:
    """1 つの例を回す（本物の user_still_admin を偽物の Discord に当てる）。"""
    from webapp_admin import auth

    guild_id = int(case.get("guild_id", document["guild_id"]))
    user_id = int(case.get("user_id", document["user_id"]))
    bot_token = str(case.get("bot_token", document["bot_token"]))
    answers = harness.decode(case.get("discord") or {}, document.get("library") or {})
    fake.script(answers)
    result: dict[str, Any]
    with patch.object(auth, "_API", fake.api_base), patch.object(auth, "DISCORD_BOT_TOKEN", bot_token):
        try:
            result = {"value": asyncio.run(auth.user_still_admin(guild_id, user_id))}
        except Exception as exc:
            result = {"raises": {"type": type(exc).__name__, "message": str(exc)}}
    seen = fake.take()
    unexpected = fake_discord.unexpected(seen)
    if unexpected:
        raise SystemExit(f"{case['name']}: 例に書いていない Discord の要求: {', '.join(unexpected)}")
    got = "raise" if "raises" in result else result["value"]
    if "expect" in case and got != case["expect"]:
        raise SystemExit(f"{case['name']}: 答えが {got!r}（道具の確かめでは {case['expect']!r}）")
    return {
        "name": case["name"],
        "guild_id": guild_id,
        "user_id": user_id,
        "bot_token": bot_token,
        "discord_responses": answers,
        "discord": seen,
        "result": result,
    }


def build(document: dict[str, Any]) -> dict[str, Any]:
    """例の文書を回して、基準の中身を作る。"""
    harness.prepare_environment("a3-admin-check-fixture-secret")
    names = [case["name"] for case in document["cases"]]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise SystemExit(f"例の名前が重なっている: {', '.join(duplicated)}")
    fake = fake_discord.FakeDiscord()
    try:
        cases = [run_case(case, document, fake) for case in document["cases"]]
    finally:
        fake.close()
    return {"generated_by": GENERATED_BY, "cases": cases}


def main(argv: list[str]) -> int:
    """cases.json（引数があればそのパス）を読み、expected.json（2 つ目の引数があればそのパス）に書く。"""
    source = Path(argv[0]) if argv else CASES
    target = Path(argv[1]) if len(argv) > 1 else OUTPUT
    document = json.loads(source.read_text(encoding="utf-8"))
    harness.write_json(target, build(document))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
