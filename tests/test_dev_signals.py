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


class LegacyFileImportTests(unittest.TestCase):
    """6c61884 までの置き場（SETTINGS_DIR/_dev_signals/）に残った依頼を表へ移す。

    本番は 6c61884 で動いている。入れ替えた時点で残っている依頼と、入れ替えの
    途中で古い管理画面が書いた依頼を、取りこぼさず、二重にも実行しないこと。
    """

    def setUp(self):
        use_sqlite_for_dev_signals(self)
        self.settings_dir = Path(tempfile.mkdtemp(prefix="dev-signals-legacy-"))
        patcher = patch.dict(os.environ, {"SETTINGS_DIR": str(self.settings_dir)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.legacy = self.settings_dir / "_dev_signals"
        self.legacy.mkdir()

    def _place(self, name: str, payload: object, mtime: float) -> Path:
        """以前の管理画面と同じ形でファイルを置く（中身は JSON、時刻は指定どおり）。"""
        path = self.legacy / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.utime(path, (mtime, mtime))
        return path

    def test_files_are_moved_in_the_order_they_were_placed(self):
        """置かれた順（更新時刻）に表へ入り、その順で Bot に渡ること。

        ファイル名の順（e < n < s）と置かれた順を逆にしてある。名前で並べる
        変異でも落ちるようにするため。
        """
        self._place("sticky.signal", {"n": 1}, mtime=1_000)
        self._place("news_feeds.signal", {"n": 2}, mtime=2_000)
        self._place("eq_replay.19f3a2c1de.signal", {"guild_id": 3}, mtime=3_000)

        self.assertEqual(_run(dev_signals.import_legacy_files()), 3)

        claimed = _run(dev_signals.claim())
        self.assertEqual([s.task for s in claimed], ["sticky", "news_feeds", "eq_replay"])
        self.assertEqual([json.loads(s.payload) for s in claimed], [{"n": 1}, {"n": 2}, {"guild_id": 3}])

    def test_per_guild_files_stay_apart_and_repeatable_ones_collapse(self):
        """ファイル名に一意な部分があるものは別の行、無いものは表の既存の行に畳まれること。

        畳み方を間違えると、2つのサーバー宛の地震リプレイが1件に潰れる。
        """
        _run(dev_signals.write("news_feeds", {"from": "table"}))
        self._place("news_feeds.signal", {"from": "file"}, mtime=1_000)
        self._place("eq_replay.aaa.signal", {"guild_id": 1}, mtime=2_000)
        self._place("eq_replay.bbb.signal", {"guild_id": 2}, mtime=3_000)

        _run(dev_signals.import_legacy_files())

        self.assertEqual(_run(dev_signals.pending()), ["eq_replay", "eq_replay", "news_feeds"])

    def test_moved_files_are_gone_and_are_not_moved_twice(self):
        """移したファイルは消え、次の巡回で二重に移さないこと。

        二重に移すと、テスト通知や地震リプレイが二度飛ぶ。
        """
        self._place("eq_replay.aaa.signal", {"guild_id": 1}, mtime=1_000)

        self.assertEqual(_run(dev_signals.import_legacy_files()), 1)
        self.assertEqual(list(self.legacy.iterdir()), [])
        self.assertEqual(_run(dev_signals.import_legacy_files()), 0)
        self.assertEqual(len(_run(dev_signals.claim())), 1)

    def test_a_file_that_could_not_be_saved_is_left_for_the_next_round(self):
        """表へ書けなかったら、ファイルを元の名前に戻して例外を上げること。

        戻さないと .importing のまま残り、二度と拾われない（依頼が黙って消える）。
        """
        from sqlalchemy.exc import OperationalError

        path = self._place("eq_replay.aaa.signal", {"guild_id": 1}, mtime=1_000)
        failure = OperationalError("INSERT INTO dev_signal", {}, Exception("connection refused"))
        with patch.object(dev_signals, "write", AsyncMock(side_effect=failure)):
            with self.assertRaises(OperationalError):
                _run(dev_signals.import_legacy_files())

        self.assertTrue(path.exists(), "書けなかったファイルが元の名前で残っていない")
        self.assertEqual(_run(dev_signals.import_legacy_files()), 1)

    def test_a_file_already_being_imported_is_not_picked_up_again(self):
        """.importing のファイルは拾わないこと。

        表へ書けたあとで消せなかったファイルがこの名前で残る。拾い直すと二重に
        実行される。
        """
        (self.legacy / "eq_replay.aaa.signal.importing").write_text("{}", encoding="utf-8")

        self.assertEqual(_run(dev_signals.import_legacy_files()), 0)
        self.assertEqual(_run(dev_signals.pending()), [])

    def test_nothing_happens_when_the_old_directory_does_not_exist(self):
        """以前の置き場が無い（新しく立てた環境）なら、何もせず 0 を返すこと。"""
        self.legacy.rmdir()
        self.assertEqual(_run(dev_signals.import_legacy_files()), 0)


if __name__ == "__main__":
    unittest.main()
