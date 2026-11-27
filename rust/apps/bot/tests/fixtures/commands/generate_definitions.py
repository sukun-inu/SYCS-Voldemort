"""スラッシュコマンドの定義（src/commands/definitions.json）を、本物の Python の Bot から作る。

Python の Bot は起動のたびに `bot.tree.sync()` で、ここに出るものをそのまま Discord に送っている。
Rust の Bot も同じものを送る（一部だけ送ると、残りのコマンドが Discord から消える）。

    python generate_definitions.py > ../../../src/commands/definitions.json
    # 本番と同じ依存（requirements.txt）で、リポジトリの直下を /app に置いて
"""

import json
import os
import sys
import tempfile

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
import discord  # noqa: E402
from discord.ext import commands as dcommands  # noqa: E402

from commands import register_all_commands  # noqa: E402

bot = dcommands.Bot(command_prefix="!", intents=discord.Intents.default())
register_all_commands(bot)
definitions = [c.to_dict(bot.tree) for c in bot.tree.get_commands()]
print(json.dumps(definitions, ensure_ascii=False, indent=1, sort_keys=True))
