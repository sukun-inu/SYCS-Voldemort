"""services/settings_pg.py（設定の Postgres 版の置き場）のテスト。

    python -m unittest tests.test_settings_pg -v

本番は Postgres（user_state_audit）だが、ここでは同じ SQL を SQLite で実行する
（tests/sqlite_session.py）。advisory lock・NOTIFY・LISTEN は SQLite に無いので、
「どの順に発行するか」は Postgres のふりをする記録係で確かめ、実際に効くかは手元の
WSL で本物の Postgres 16 に当てて確かめる（変更のコミットに記録）。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="settings-pg-test-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import event, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from services import settings_pg  # noqa: E402
from tests.sqlite_session import FakeAsyncSession, sqlite_engine  # noqa: E402


def _make(engine, legacy: Any, *, load_timeout: float = 10.0) -> settings_pg.PostgresSettings:
    """SQLite に向けた置き場を作る。legacy は取り込み元の中身か、投げる例外。"""
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    async def create_tables() -> None:
        """本番と同じく checkfirst で表を作る。"""
        settings_pg.metadata.create_all(engine, checkfirst=True)

    def load_legacy() -> tuple[dict[str, Any], str]:
        """取り込み元。例外を渡されたら投げる（壊れた settings.json の代わり）。"""
        if isinstance(legacy, BaseException):
            raise legacy
        return json.loads(json.dumps(legacy)), "test:settings.json"

    return settings_pg.PostgresSettings(
        session_factory=lambda: FakeAsyncSession(maker()),
        create_tables=create_tables,
        load_legacy=load_legacy,
        dialect="sqlite",
        listen_dsn=None,
        poll_seconds=3600.0,
        write_timeout=10.0,
        load_timeout=load_timeout,
    )


LEGACY = {
    "guilds": {
        "111": {"welcome": {"channel_id": 1}},
        "222": {"tts": {"enabled": True}},
    },
    "schema": "v1",
}


class ImportTests(unittest.TestCase):
    """最初の起動で settings.json を取り込む。"""

    def setUp(self):
        self.engine = sqlite_engine()
        self.addCleanup(self.engine.dispose)

    def test_the_old_file_is_imported_once_with_every_guild(self):
        """全ギルドと、guilds 以外のトップレベルのキーが入ること。

        トップレベルのキーを落とすと、今のコードが使っていなくても、手で足された
        ものが黙って消える。
        """
        store = _make(self.engine, LEGACY)
        self.addCleanup(store.close)

        self.assertEqual(store.snapshot(), LEGACY)
        self.assertEqual(store.version(), 1)
        with self.engine.connect() as conn:
            keys = sorted(row.guild_key for row in conn.execute(select(settings_pg.guild_table.c.guild_key)))
            state = conn.execute(select(settings_pg.state_table)).one()
        self.assertEqual(keys, ["111", "222"])
        self.assertEqual(state.imported_from, "test:settings.json")

    def test_a_second_start_does_not_import_again(self):
        """2つ目のプロセス（管理画面）が起動しても、取り込み直さないこと。

        取り込み直すと、Bot がすでに変えた設定が settings.json の古い中身で上書きされる。
        """
        first = _make(self.engine, LEGACY)
        self.addCleanup(first.close)
        first.transact(lambda data: data["guilds"]["111"].update({"changed": True}))

        second = _make(self.engine, {"guilds": {"999": {}}})
        self.addCleanup(second.close)
        self.assertTrue(second.snapshot()["guilds"]["111"]["changed"])
        self.assertNotIn("999", second.snapshot()["guilds"])

    def test_a_broken_file_is_not_imported_and_nothing_is_served(self):
        """壊れた settings.json は取り込まず、設定も返さないこと。

        空として取り込むと、空の設定が正になり、元のファイルは二度と読まれない
        （全ギルドの設定が黙って消える）。空の設定で動くと、セキュリティ機能が
        全部切れたように振る舞う。
        """
        store = _make(self.engine, ValueError("壊れている"), load_timeout=0.5)
        self.addCleanup(store.close)

        with self.assertLogs(settings_pg.logger, level="WARNING") as logs:
            with self.assertRaises(settings_pg.SettingsNotLoaded):
                store.snapshot()
        # 読めない理由がログに残ること（残らないと、なぜ起動しないのかが分からない）。
        self.assertTrue(any("壊れている" in line for line in logs.output))
        with self.engine.connect() as conn:
            self.assertIsNone(conn.execute(select(settings_pg.state_table.c.id)).first())


class TransactTests(unittest.TestCase):
    """排他を取って読み直し、変わったところだけを書く。"""

    def setUp(self):
        self.engine = sqlite_engine()
        self.addCleanup(self.engine.dispose)
        self.store = _make(self.engine, LEGACY)
        self.addCleanup(self.store.close)
        self.store.snapshot()
        self.statements: list[tuple[str, Any]] = []

        def record(conn, cursor, statement, parameters, context, executemany):
            """発行された SQL を控える。"""
            self.statements.append((statement, parameters))

        event.listen(self.engine, "before_cursor_execute", record)
        self.addCleanup(event.remove, self.engine, "before_cursor_execute", record)

    def _guild_writes(self) -> list[str]:
        """bot_settings_guild への INSERT・UPDATE・DELETE だけを拾う。"""
        return [
            sql
            for sql, _ in self.statements
            if "bot_settings_guild" in sql and sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
        ]

    def test_only_the_changed_guild_is_written(self):
        """書き換えたギルドの行だけを書くこと。

        全ギルドを毎回書き直すと、ニュースの既読の更新（数分おき）のたびに全サーバー
        ぶんの行が書き換わる。
        """
        self.store.transact(lambda data: data["guilds"]["222"]["tts"].update({"enabled": False}))

        self.assertEqual(len(self._guild_writes()), 1)
        self.assertEqual(self.store.snapshot()["guilds"]["222"]["tts"], {"enabled": False})
        self.assertEqual(self.store.snapshot()["guilds"]["111"], {"welcome": {"channel_id": 1}})
        self.assertEqual(self.store.version(), 2)

    def test_nothing_is_written_when_nothing_changes(self):
        """何も変わらなければ書かず、版番号も上げないこと。

        版番号を上げると、他のプロセスが中身の同じ設定を全部読み直す。起動のたびに
        走る null の掃除（drop_stored_nulls）が、ここに当たる。
        """
        result = self.store.transact(lambda data: "読んだだけ")

        self.assertEqual(result, "読んだだけ")
        self.assertEqual(self._guild_writes(), [])
        self.assertEqual(self.store.version(), 1)

    def test_a_removed_guild_is_deleted(self):
        """辞書から消したギルドは、行も消すこと（サーバーのデータの削除で使う）。"""
        self.store.transact(lambda data: data["guilds"].pop("111"))

        with self.engine.connect() as conn:
            keys = [row.guild_key for row in conn.execute(select(settings_pg.guild_table.c.guild_key))]
        self.assertEqual(keys, ["222"])
        self.assertNotIn("111", self.store.snapshot()["guilds"])

    def test_a_new_guild_is_inserted(self):
        """まだ行の無いギルドは、新しく入ること。"""
        self.store.transact(lambda data: data["guilds"].update({"333": {"sticky": {}}}))

        other = _make(self.engine, {"guilds": {}})
        self.addCleanup(other.close)
        self.assertEqual(other.snapshot()["guilds"]["333"], {"sticky": {}})

    def test_a_failed_change_writes_nothing(self):
        """書き換えの途中で例外が出たら、何も書かず、例外をそのまま上げること。"""

        def broken(data):
            """1つ書き換えてから落ちる。"""
            data["guilds"]["111"]["welcome"]["channel_id"] = 999
            raise RuntimeError("途中で落ちた")

        with self.assertRaises(RuntimeError):
            self.store.transact(broken)

        fresh = _make(self.engine, {"guilds": {}})
        self.addCleanup(fresh.close)
        self.assertEqual(fresh.snapshot()["guilds"]["111"]["welcome"]["channel_id"], 1)
        self.assertEqual(fresh.version(), 1)

    def test_another_process_sees_the_change_after_refresh(self):
        """別のプロセスが書いたら、版番号を見て読み直すこと。

        本番では通知（NOTIFY）が数ミリ秒で届き、取りこぼしても 30 秒ごとの版番号の
        確認で拾う。ここでは「新しい版を見つけたら読み直す」ところを確かめる。
        """
        other = _make(self.engine, {"guilds": {}})
        self.addCleanup(other.close)
        self.assertEqual(other.snapshot()["guilds"]["111"]["welcome"]["channel_id"], 1)

        self.store.transact(lambda data: data["guilds"]["111"]["welcome"].update({"channel_id": 42}))
        other.refresh()

        self.assertEqual(other.snapshot()["guilds"]["111"]["welcome"]["channel_id"], 42)
        self.assertEqual(other.version(), 2)

    def test_top_level_keys_other_than_guilds_survive_a_write(self):
        """guilds 以外のトップレベルのキーが、書き込みのあとも残ること。"""
        self.store.transact(lambda data: data["guilds"]["111"].update({"x": 1}))
        other = _make(self.engine, {"guilds": {}})
        self.addCleanup(other.close)
        self.assertEqual(other.snapshot()["schema"], "v1")


class _RecordingSession:
    """Postgres のふりをして、発行した SQL を控えるだけのセッション。

    advisory lock と NOTIFY は SQLite に無い。ここでは「排他を最初に取り、通知は
    コミットの前に出す」という順番だけを確かめる。
    """

    def __init__(self, log: list[str], inner: FakeAsyncSession):
        self._log = log
        self._inner = inner

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)

    async def execute(self, stmt):
        sql = str(stmt)
        if "pg_advisory_xact_lock" in sql or "pg_notify" in sql:
            self._log.append(sql.split("(")[0].replace("SELECT ", ""))
            return None
        return await self._inner.execute(stmt)

    async def commit(self):
        self._log.append("commit")
        await self._inner.commit()

    async def rollback(self):
        self._log.append("rollback")
        await self._inner.rollback()


class PostgresStatementOrderTests(unittest.TestCase):
    """Postgres でだけ発行する文の順番。"""

    def test_the_lock_comes_first_and_the_notice_goes_out_before_commit(self):
        """排他を読む前に取り、通知はコミットの前に出すこと。

        読んでから排他を取ると、その間に別のプロセスが書いた変更を上書きする。
        通知をコミットの後に別の文で出すと、落ちたときに通知だけが失われる
        （NOTIFY はトランザクションに乗り、コミットと同時に届く）。
        """
        engine = sqlite_engine()
        self.addCleanup(engine.dispose)
        maker = sessionmaker(bind=engine, expire_on_commit=False)
        log: list[str] = []
        store = _make(engine, LEGACY)
        self.addCleanup(store.close)
        store.snapshot()

        store._dialect = "postgresql"
        store._session = lambda: _RecordingSession(log, FakeAsyncSession(maker()))
        store.transact(lambda data: data["guilds"]["111"].update({"x": 1}))

        self.assertEqual(log[0], "pg_advisory_xact_lock")
        self.assertEqual(log[-2:], ["pg_notify", "commit"])


class SettingsStoreOnPostgresTests(unittest.TestCase):
    """settings_store の公開関数が、保存先を Postgres にしても同じに振る舞うこと。"""

    def setUp(self):
        from services import settings_store as store

        self.store_module = store
        self.engine = sqlite_engine()
        self.addCleanup(self.engine.dispose)
        self.pg = _make(self.engine, {"guilds": {"555": {"welcome": {"channel_id": None, "message": "hi"}}}})
        self.addCleanup(self.pg.close)
        for patcher in (patch.object(store, "_BACKEND", "postgres"), patch.object(store, "_pg", self.pg)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_setter_writes_to_postgres_and_stamps_the_guild(self):
        """セッターの書き込みが Postgres に入り、「最後に触られた時刻」が押されること。

        時刻が押されないと、放棄された設定の掃除（guild_retention）が、使われている
        サーバーの設定を消しにいく。
        """
        self.store_module.set_welcome_channel(555, 777)

        fresh = _make(self.engine, {"guilds": {}})
        self.addCleanup(fresh.close)
        guild = fresh.snapshot()["guilds"]["555"]
        self.assertEqual(guild["welcome"]["channel_id"], 777)
        self.assertIn(self.store_module.TOUCHED_AT_KEY, guild)

    def test_stored_nulls_are_dropped_and_counted(self):
        """取り込んだ null を起動時の掃除で落とし、落とした数を返すこと。"""
        self.assertEqual(self.store_module.drop_stored_nulls(), 1)
        self.assertNotIn("channel_id", self.pg.snapshot()["guilds"]["555"]["welcome"])
        version = self.pg.version()
        self.assertEqual(self.store_module.drop_stored_nulls(), 0)
        self.assertEqual(self.pg.version(), version, "取り除くものが無いのに書いた")

    def test_export_writes_the_database_to_settings_json_and_keeps_the_old_file(self):
        """書き出しが Postgres の中身を settings.json に書き、元のファイルを退避すること。

        6c61884（ファイルの版）へ戻す前に使う。退避しないと、書き出しを間違えたときに
        戻す先が無くなる。
        """
        settings_dir = Path(tempfile.mkdtemp(prefix="settings-export-"))
        target = settings_dir / "settings.json"
        target.write_text('{"guilds": {"old": {}}}', encoding="utf-8")
        with (
            patch.object(self.store_module, "_SETTINGS_DIR", settings_dir),
            patch.object(self.store_module, "_SETTINGS_FILE", target),
            patch.object(self.store_module, "_SETTINGS_LOCK_FILE", settings_dir / "settings.json.lock"),
        ):
            self.store_module.set_welcome_message(555, "exported")
            path = self.store_module.export_to_file()

        written = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(written["guilds"]["555"]["welcome"]["message"], "exported")
        backups = list(settings_dir.glob("settings.json.before-export-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(json.loads(backups[0].read_text(encoding="utf-8")), {"guilds": {"old": {}}})


class LegacyFileReaderTests(unittest.TestCase):
    """settings_store._load_legacy_strict（取り込み元の settings.json を読む口）。"""

    def setUp(self):
        from services import settings_store as store

        self.store = store
        self.dir = Path(tempfile.mkdtemp(prefix="settings-legacy-"))
        self.file = self.dir / "settings.json"
        patcher = patch.object(store, "_SETTINGS_FILE", self.file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_broken_file_raises_instead_of_reading_as_empty(self):
        """壊れた settings.json は例外を上げ、空として返さないこと。

        ファイル版の読み込み（_load_all_from_disk）は壊れたファイルを空として返す。
        取り込みで同じことをすると、空の設定が正になり、全ギルドの設定が黙って消える。
        """
        self.file.write_text("{ 壊れている", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store._load_legacy_strict()

    def test_a_file_with_the_wrong_shape_raises(self):
        """JSON としては読めても、guilds が辞書でなければ例外を上げること。"""
        self.file.write_text('{"guilds": []}', encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store._load_legacy_strict()

    def test_a_missing_file_starts_empty_and_says_so(self):
        """ファイルが無い（新しく立てた環境）なら、空から始め、そう記録すること。"""
        data, label = self.store._load_legacy_strict()
        self.assertEqual(data, {"guilds": {}})
        self.assertIn("無かった", label)

    def test_a_good_file_is_read_as_is(self):
        """読めるファイルは、トップレベルのキーも含めてそのまま返すこと。"""
        self.file.write_text('{"guilds": {"1": {"a": 1}}, "extra": true}', encoding="utf-8")
        data, label = self.store._load_legacy_strict()
        self.assertEqual(data, {"guilds": {"1": {"a": 1}}, "extra": True})
        self.assertEqual(label, str(self.file))


if __name__ == "__main__":
    unittest.main()
