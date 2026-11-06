"""services/dev_signals.py のテスト。

    python -m unittest tests.test_dev_signals -v

管理画面が置いた依頼を Bot が取り出す、その置き場の振る舞いを見る。
本番は Postgres（user_state_audit）だが、ここでは同じ SQL を SQLite で実行する
（tests/sqlite_session.py）。行ロック（FOR UPDATE SKIP LOCKED）だけは SQLite で
確かめられないので、Postgres 向けに組み立てた SQL を直接見るテストを別に置いた。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="dev-signals-test-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import inspect  # noqa: E402
from sqlalchemy.dialects import postgresql  # noqa: E402

from services import dev_signals  # noqa: E402
from tests.sqlite_session import use_sqlite_for_dev_signals  # noqa: E402


def _run(coro):
    """テストから1回だけ await する。"""
    return asyncio.run(coro)


class DevSignalStoreTests(unittest.TestCase):
    """置く・畳む・取り出す、の3つ。"""

    def setUp(self):
        self.engine = use_sqlite_for_dev_signals(self)

    def test_the_table_is_created_on_first_use(self):
        """最初に使ったときに表が作られること。

        Bot と管理画面はマイグレーションを待たずに立ち上がる。表を作る前に
        書きに行くと、デプロイ直後の最初の1回が「表が無い」で 503 になる。
        """
        self.assertFalse(inspect(self.engine).has_table("dev_signal"))
        _run(dev_signals.write("news_feeds", {"task": "news_feeds"}))
        self.assertTrue(inspect(self.engine).has_table("dev_signal"))

    def test_signals_for_different_guilds_are_kept_apart(self):
        """per_guild=True の依頼は、同じ用途でも1回ずつ別に残ること。

        ここが畳まれると、2つのサーバーの管理者が30秒以内に地震リプレイを
        押したとき、先の1件が黙って消える（ファイルの頃に実際に起きた）。
        """
        _run(dev_signals.write("eq_replay", {"guild_id": 1}, per_guild=True))
        _run(dev_signals.write("eq_replay", {"guild_id": 2}, per_guild=True))

        claimed = _run(dev_signals.claim())
        self.assertEqual([signal.task for signal in claimed], ["eq_replay", "eq_replay"])
        self.assertEqual([json.loads(signal.payload)["guild_id"] for signal in claimed], [1, 2])

    def test_repeatable_signals_collapse_into_one_with_the_latest_payload(self):
        """per_guild=False の依頼は、何回置いても1件に畳まれること。

        畳まないと、ボタンを3回押しただけでニュース取得が3回走る。中身は
        最後に置いたものになる。
        """
        _run(dev_signals.write("news_feeds", {"n": 1}))
        _run(dev_signals.write("news_feeds", {"n": 2}))
        _run(dev_signals.write("news_feeds", {"n": 3}))

        self.assertEqual(_run(dev_signals.pending()), ["news_feeds"])
        claimed = _run(dev_signals.claim())
        self.assertEqual(len(claimed), 1)
        self.assertEqual(json.loads(claimed[0].payload), {"n": 3})

    def test_claim_returns_signals_in_the_order_they_were_placed(self):
        """置いた順に返ること。

        用途を3つとも別にしてあるのは、並びを逆にする変異で落ちるように
        するため（同じ用途だけだと、逆順でも見分けがつかない）。
        """
        _run(dev_signals.write("sticky", "a"))
        _run(dev_signals.write("eq_replay", "b", per_guild=True))
        _run(dev_signals.write("news_feeds", "c"))

        claimed = _run(dev_signals.claim())
        self.assertEqual([signal.task for signal in claimed], ["sticky", "eq_replay", "news_feeds"])

    def test_a_claimed_signal_is_not_handed_out_again(self):
        """取り出した依頼は表から消え、次の巡回では返らないこと。

        消えないと、Bot は30秒ごとに同じ依頼を実行し続ける（テスト通知が
        止まらなくなる）。
        """
        _run(dev_signals.write("news_feeds", "x"))
        self.assertEqual(len(_run(dev_signals.claim())), 1)
        self.assertEqual(_run(dev_signals.claim()), [])
        self.assertEqual(_run(dev_signals.pending()), [])

    def test_claim_takes_at_most_the_limit_and_leaves_the_rest_in_order(self):
        """上限を超えた分は残り、次の巡回で古い順に取れること。"""
        for guild_id in range(5):
            _run(dev_signals.write("eq_replay", {"guild_id": guild_id}, per_guild=True))

        first = _run(dev_signals.claim(limit=2))
        rest = _run(dev_signals.claim(limit=10))
        self.assertEqual([json.loads(s.payload)["guild_id"] for s in first], [0, 1])
        self.assertEqual([json.loads(s.payload)["guild_id"] for s in rest], [2, 3, 4])

    def test_latest_returns_the_newest_payload_without_taking_it(self):
        """latest は中身を見るだけで、取り出さないこと。

        開発者パネルや検証から覗いただけで依頼が消えると、Bot に届かない。
        """
        _run(dev_signals.write("test_vc", {"guild_id": 1}, per_guild=True))
        _run(dev_signals.write("test_vc", {"guild_id": 2}, per_guild=True))

        self.assertEqual(json.loads(_run(dev_signals.latest("test_vc"))), {"guild_id": 2})
        self.assertIsNone(_run(dev_signals.latest("eq_replay")))
        self.assertEqual(len(_run(dev_signals.claim())), 2)

    def test_a_string_payload_is_stored_as_is(self):
        """文字列はそのまま、それ以外は JSON にして置くこと。

        Bot 側は文字列として受け取って json.loads する。文字列まで JSON に
        すると引用符で包まれ、Bot 側で辞書ではなく文字列が出てくる。
        """
        _run(dev_signals.write("eq_replay", '{"raw": true}', per_guild=True))
        self.assertEqual(_run(dev_signals.claim())[0].payload, '{"raw": true}')


class RepeatableSignalRaceTests(unittest.TestCase):
    """同じ用途の依頼が、ほぼ同時に2つ置かれたとき。"""

    def test_losing_the_race_to_insert_is_not_an_error(self):
        """「無いので入れる」の間に相手が先に入れても、失敗にしないこと。

        管理画面は1プロセスでも、要求は await のたびに入れ替わる。UPDATE が
        0件だったあとに相手が同じ用途を INSERT すると、こちらの INSERT は
        一意制約で落ちる。結果が同じ依頼なので、相手の1行が残っていれば
        目的は果たせている。ここで例外を上げると、押した人には 503 が返り、
        実際には依頼が届いているのに「保存できませんでした」と出る。
        """
        from sqlalchemy.exc import IntegrityError

        session = AsyncMock()
        session.__aenter__.return_value = session
        session.__aexit__.return_value = False
        nothing_updated = SimpleNamespace(rowcount=0)
        duplicate = IntegrityError("INSERT INTO dev_signal", {}, Exception("duplicate key"))
        session.execute.side_effect = [nothing_updated, duplicate]

        with (
            patch.object(dev_signals, "_session", lambda: session),
            patch.object(dev_signals, "_initialized", True),
        ):
            _run(dev_signals.write("news_feeds", {"task": "news_feeds"}))

        session.rollback.assert_awaited_once()
        session.commit.assert_not_awaited()


class ClaimStatementTests(unittest.TestCase):
    """Postgres で走る取り出しの SQL そのもの。"""

    def _sql(self) -> str:
        return str(dev_signals._claim_statement(7).compile(dialect=postgresql.dialect())).upper()

    def test_rows_are_locked_and_skipped_while_another_bot_holds_them(self):
        """FOR UPDATE SKIP LOCKED が付いていること。

        SQLite はこの句を黙って捨てるので、上の DevSignalStoreTests は外しても
        全部通る。外すと、Bot を2つ動かしたときに同じ依頼を両方が拾い、
        テスト通知や地震リプレイが二重に飛ぶ。
        """
        self.assertIn("FOR UPDATE SKIP LOCKED", self._sql())

    def test_the_oldest_rows_are_taken_first(self):
        """古い順（id 昇順）に、上限つきで選んでいること。

        並び順を落とすと、上限で打ち切ったときに古い依頼が残り続けうる。
        """
        sql = self._sql()
        self.assertIn("ORDER BY DEV_SIGNAL.ID", sql)
        self.assertNotIn("ORDER BY DEV_SIGNAL.ID DESC", sql)
        self.assertIn("LIMIT", sql)

    def test_taking_and_deleting_happen_in_one_statement(self):
        """取り出しと削除が1文（DELETE ... RETURNING）であること。

        SELECT してから別の文で DELETE すると、その間に別の Bot が同じ行を
        拾える。
        """
        sql = self._sql()
        self.assertTrue(sql.startswith("DELETE FROM DEV_SIGNAL"))
        self.assertIn("RETURNING", sql)


if __name__ == "__main__":
    unittest.main()
