#!/usr/bin/env python3
"""Postgres にある設定を settings.json へ書き出す。**settings.json を書き換える。**

本番を 6c61884（設定をファイルに置いていた版）へ戻すときに、戻す前に1回だけ使う。
SETTINGS_BACKEND=postgres に切り替えてからの変更は Postgres にしか無いので、書き出さずに
戻すと、その間の設定の変更が全部消える。

    docker compose exec sycs-voldemort python scripts/export_settings_to_file.py

- 今ある settings.json は settings.json.before-export-<時刻> に退避してから書く
- SETTINGS_BACKEND が postgres でなければ何もせず、終了コード 1 で止まる
  （ファイルが正の環境で動かすと、意味の無い退避だけが残る）

手順の全体は docs/UPGRADE.ja.md の「戻し方」。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    """書き出して、書いた先とギルドの数を出す。"""
    from services import settings_store

    try:
        path = settings_store.export_to_file()
    except RuntimeError as e:
        print(f"書き出しませんでした: {e}", file=sys.stderr)
        return 1
    guilds = len(settings_store._load_all().get("guilds", {}))
    print(f"{path} へ {guilds} ギルドぶんの設定を書き出しました（元のファイルは before-export-* に退避）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
