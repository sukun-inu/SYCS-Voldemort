"""Rust の Bot が持っているスラッシュコマンドの定義が、Python の Bot のものと同じであること。

    python -m unittest discover -s tests -t .

Rust の Bot は、Python の Bot が `bot.tree.sync()` で Discord に送っている定義をそのまま持っている
（rust/apps/bot/src/commands/definitions.json）。切り替えのとき、Rust の Bot はそれを登録し直す。
登録は全体の置き換えなので、**食い違ったまま切り替えると、利用者から見えるコマンドが黙って変わる。**

移行が終わるまで Python の機能は凍結しているが、依存の更新（discord.py が定義の書き出し方を変える）や
障害対応でコマンドに手が入ることはある。そのときにここが落ちて、定義を作り直すことに気づけるようにする。
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="rust-defs-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="rust-defs-cache-"))

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import discord  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402

DEFINITIONS = ROOT / "rust" / "apps" / "bot" / "src" / "commands" / "definitions.json"
GENERATOR = "rust/apps/bot/tests/fixtures/commands/generate_definitions.py"


class RustCommandDefinitionsTests(unittest.TestCase):
    """Rust 側に置いた定義が、いまの Python の Bot の定義と一致すること。"""

    def test_rust_definitions_match_what_python_syncs(self):
        """食い違っていたら、作り直す道具の名前を出して落とす。"""
        bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
        register_all_commands(bot)
        current = [command.to_dict(bot.tree) for command in bot.tree.get_commands()]

        stored = json.loads(DEFINITIONS.read_text(encoding="utf-8"))

        self.assertEqual(
            stored,
            current,
            f"Rust 側の定義（{DEFINITIONS.relative_to(ROOT)}）が Python の Bot と食い違っています。"
            f"{GENERATOR} で作り直してください。",
        )


if __name__ == "__main__":
    unittest.main()
