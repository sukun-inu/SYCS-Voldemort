"""ギルドごとの設定（settings）を Postgres に置く。

services/settings_store.py の保存先の1つで、`SETTINGS_BACKEND=postgres` のときに使う。
公開関数（get_xxx / set_xxx）は settings_store 側にあり、ここは「全体を読む」と
「排他を取って読み直し、書き換えて保存する」の2つだけを受け持つ。

■ なぜファイルから移すのか

settings.json は Bot と管理画面が同じボリュームを見ている間しか共有できない。
コンテナを別のホストへ分けると、片方の変更がもう片方に届かず、設定が黙って
食い違う。Rust へ移す間は Python と Rust のプロセスが同じ設定を読むので、どちらの
言語からも触れる置き場が要る。置き場は user_state_audit データベース（Bot と管理画面の
両方が接続できる唯一のデータベース。services/dev_signals.py と同じ理由）。

■ 表の形

    bot_settings_guild  ギルドごとに1行（guild_key, data）。書いたときは変わった
                        ギルドの行だけを更新する。SQL エディタからも1ギルドずつ読める
    bot_settings_state  1行だけ。版番号（書くたびに 1 増える）と、guilds 以外の
                        トップレベルのキー、取り込み元の記録

guild_key を数値ではなく文字列にしているのは、取り込み元の settings.json の鍵を
そのまま残すため（手で編集されて数値でない鍵が混ざっていても、黙って落とさない）。

■ 読み込み（キャッシュ）

読むたびに Postgres へ行くと、往復のぶんだけ呼び出し側のイベントループが止まる
（設定はメッセージのたびに読まれる）。全体をメモリに持ち、他のプロセスが書いたら
捨てて読み直す。合図は2つ。

    LISTEN/NOTIFY  書いたトランザクションが bot_settings_changed に版番号を流す。
                   受けたら、手元より新しければ読み直す（数ミリ秒で届く）
    版番号の確認   SETTINGS_PG_POLL_SECONDS（既定 30 秒）ごとに版番号だけを見る。
                   LISTEN の接続が切れていた間の書き込みを、これで拾う

■ なぜ専用のスレッドとイベントループを持つのか

settings_store の公開関数は同期で、非同期の文脈からはスレッドへ逃がして呼ぶ決まり
（settings_store.awrite）。一方 asyncpg は非同期でしか使えない。同期の呼び出し元から
asyncpg を使うために、設定専用のイベントループを1本のスレッドで回し、そこへ処理を
頼んで結果を待つ。

Bot や管理画面のイベントループのエンジンを使い回さないこと。asyncpg の接続は作った
ループに縛られるので、別のループから使うと壊れる。ここは自分のループで、自分の
エンジンと自分の LISTEN 用の接続を持つ。

■ 読めないとき

最初の読み込みが済むまで、読む側は SETTINGS_LOAD_TIMEOUT_SECONDS（既定 30 秒）待ち、
それでも読めなければ例外を上げる。**空の設定で動き出すことはしない。** 空で動くと、
セキュリティ機能が全部切れたサーバーのように振る舞い、しかも誰も気づかない。
一度読めたあとは、Postgres が落ちても手元のキャッシュで読み続ける（書き込みは失敗する）。

■ 取り込み（settings.json から）

表がまだ空なら、最初の起動で settings.json を取り込む。**壊れた settings.json は
取り込まない**（例外を上げて、読めるまで起動を待たせる）。ファイル版の読み込みは
壊れたファイルを空として扱うが、それをここで取り込むと、空の設定が正になって元の
ファイルは二度と読まれない。settings.json 自体には触らない（6c61884 へ戻せるように）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Awaitable, Callable, Optional, TypeVar

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    DateTime,
    MetaData,
    SmallInteger,
    Table,
    Text,
    delete,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

CHANNEL = "bot_settings_changed"

# 書き込みを1人に絞る advisory lock の鍵。値そのものに意味は無いが、同じデータベースで
# 他の用途の鍵と重ならないこと（webapp のスケジューラは別のデータベースを使う）。
LOCK_KEY = 0x5E771165

_JSON = JSON().with_variant(JSONB(), "postgresql")

metadata = MetaData()

guild_table = Table(
    "bot_settings_guild",
    metadata,
    Column("guild_key", Text(), primary_key=True),
    Column("data", _JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

state_table = Table(
    "bot_settings_state",
    metadata,
    # 1行しか置かない（id = 1）。
    Column("id", SmallInteger(), primary_key=True),
    Column("version", BigInteger(), nullable=False),
    # guilds 以外のトップレベルのキー。今のコードは guilds しか使わないが、取り込み元に
    # あったものを黙って落とさないために持つ。
    Column("root", _JSON, nullable=False),
    Column("imported_from", Text(), nullable=True),
    Column("imported_at", DateTime(timezone=True), nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


class SettingsNotLoaded(RuntimeError):
    """最初の読み込みが済んでいないので、設定を返せない。"""


def _canon(value: Any) -> str:
    """変わったかどうかを比べるための正規形（鍵の順を揃えた JSON）。"""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _root_of(data: dict[str, Any]) -> dict[str, Any]:
    """guilds 以外のトップレベル。"""
    return {key: value for key, value in data.items() if key != "guilds"}


class PostgresSettings:
    """settings の Postgres 版の置き場。1プロセスに1つ。

    session_factory   async with で使えるセッションを返す。専用のループの中でしか呼ばない
    create_tables     表を（無ければ）作る非同期関数
    load_legacy       取り込み元を読む。(中身, 取り込み元の説明) を返す。壊れていたら例外
    dialect           "postgresql" のときだけ advisory lock・NOTIFY・LISTEN を使う
                      （テストは SQLite で同じ SQL を回すため）
    listen_dsn        LISTEN に使う asyncpg の接続先。None なら LISTEN しない
    """

    def __init__(
        self,
        *,
        session_factory: Callable[[], Any],
        create_tables: Callable[[], Awaitable[None]],
        load_legacy: Callable[[], tuple[dict[str, Any], str]],
        dialect: str,
        listen_dsn: Optional[str],
        poll_seconds: float,
        write_timeout: float,
        load_timeout: float,
    ) -> None:
        """組み立てるだけで、つなぎには行かない（start か最初の snapshot / transact で動き出す）。

        poll_seconds は版番号を確かめる間隔、write_timeout は transact の待ち時間、
        load_timeout は最初の読み込みを snapshot が待つ時間（どれも秒）。
        """
        self._session = session_factory
        self._create_tables = create_tables
        self._load_legacy = load_legacy
        self._dialect = dialect
        self._listen_dsn = listen_dsn
        self._poll_seconds = poll_seconds
        self._write_timeout = write_timeout
        self._load_timeout = load_timeout
        # (中身, 版番号)。差し替えは参照の代入1回なので、読む側はロック無しで読める。
        self._cache: Optional[tuple[dict[str, Any], int]] = None
        self._loaded = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._start_lock = threading.Lock()
        self._tasks: list[asyncio.Task[Any]] = []

    # ── 外から呼ぶもの（同期。どのスレッドからでもよい） ─────────────────

    def start(self) -> None:
        """専用のスレッドとループを立て、最初の読み込みを始める。2回目以降は何もしない。"""
        with self._start_lock:
            if self._thread is not None:
                return
            ready = threading.Event()

            def run() -> None:
                """専用のループを回す（daemon スレッド。プロセスと一緒に終わる）。"""
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                ready.set()
                self._tasks.append(loop.create_task(self._bootstrap_forever()))
                loop.run_forever()
                loop.close()

            self._thread = threading.Thread(target=run, name="settings-pg", daemon=True)
            self._thread.start()
            ready.wait()

    def snapshot(self) -> dict[str, Any]:
        """いまの設定の全体。最初の読み込みが済むまでは待つ。

        返す辞書はキャッシュそのもの（ファイル版の _load_all と同じ）。書き換えは
        必ず transact を通すこと。
        """
        self.start()
        if not self._loaded.wait(self._load_timeout):
            raise SettingsNotLoaded(
                f"設定を Postgres から {self._load_timeout:.0f} 秒以内に読み込めませんでした。"
                "接続先と、ログの [settings] の警告を確かめてください。"
            )
        assert self._cache is not None
        return self._cache[0]

    def version(self) -> int:
        """手元のキャッシュの版番号。まだ読めていなければ 0。"""
        return self._cache[1] if self._cache is not None else 0

    def transact(self, fn: Callable[[dict[str, Any]], _T]) -> _T:
        """排他を取って最新を読み直し、fn で書き換えて保存する。fn の戻り値を返す。

        **専用のループのスレッドからは呼ばないこと**（自分の終わりを待って止まる）。
        settings_store の中からしか呼ばれないので、起きるとしたら作りの誤り。
        """
        self.start()
        assert self._loop is not None
        if threading.current_thread() is self._thread:
            raise RuntimeError("settings の専用ループの中から transact を呼んだ（待ち合わせで止まる）")
        future = asyncio.run_coroutine_threadsafe(self._transact(fn), self._loop)
        try:
            return future.result(self._write_timeout)
        except TimeoutError:
            future.cancel()
            raise TimeoutError(f"設定の保存が {self._write_timeout:.0f} 秒以内に終わりませんでした。") from None

    def refresh(self) -> None:
        """いますぐ版番号を確かめ、新しければ読み直す（検証と、テスト用）。"""
        self.start()
        assert self._loop is not None
        asyncio.run_coroutine_threadsafe(self._refresh_if_newer(None), self._loop).result(self._write_timeout)

    def close(self) -> None:
        """専用のループを止める。本番では呼ばない（プロセスと一緒に終わる）。テストの後片付け用。

        見張り（読み込み・版番号の確認・LISTEN）を取り消し、終わるのを待ってから
        ループを止める。待たずに止めると "Task was destroyed but it is pending" が出る。
        """
        loop = self._loop
        if loop is None:
            return

        async def shutdown() -> None:
            """見張りを取り消して、終わるのを待つ。"""
            for task in self._tasks:
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)

        try:
            asyncio.run_coroutine_threadsafe(shutdown(), loop).result(5)
        finally:
            loop.call_soon_threadsafe(loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5)

    # ── 専用のループの中で動くもの ────────────────────────────────

    async def _bootstrap_forever(self) -> None:
        """表を作り、空なら取り込み、全体を読む。読めるまで間を空けて繰り返す。

        読めたら、LISTEN と版番号の確認を動かし始める。
        """
        delay = 1.0
        while True:
            try:
                await self._create_tables()
                await self._import_if_empty()
                data, version = await self._read_all_fresh()
                self._cache = (data, version)
                self._loaded.set()
                logger.info("[settings] Postgres から読み込みました（%d ギルド、版 %d）", len(data["guilds"]), version)
                break
            except Exception as e:
                logger.warning("[settings] Postgres から読み込めませんでした（%.0f 秒後にやり直します）: %s", delay, e)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)
        loop = asyncio.get_running_loop()
        self._tasks.append(loop.create_task(self._poll_forever()))
        if self._listen_dsn and self._dialect == "postgresql":
            self._tasks.append(loop.create_task(self._listen_forever()))

    async def _lock(self, session: Any) -> None:
        """書き込みを1人に絞る。トランザクションが終わると自動で外れる。"""
        if self._dialect == "postgresql":
            await session.execute(text("SELECT pg_advisory_xact_lock(:key)").bindparams(key=LOCK_KEY))

    async def _read_all(self, session: Any) -> tuple[dict[str, Any], int]:
        """全体を読む。表が空なら版 0 の空の構造。"""
        state = (
            await session.execute(select(state_table.c.version, state_table.c.root).where(state_table.c.id == 1))
        ).first()
        rows = (await session.execute(select(guild_table.c.guild_key, guild_table.c.data))).all()
        data: dict[str, Any] = dict(state.root) if state is not None and isinstance(state.root, dict) else {}
        data["guilds"] = {str(row.guild_key): row.data for row in rows}
        return data, int(state.version) if state is not None else 0

    async def _read_all_fresh(self) -> tuple[dict[str, Any], int]:
        """自分のセッションで全体を読む（排他は取らない）。"""
        async with self._session() as session:
            result = await self._read_all(session)
            await session.rollback()
            return result

    async def _import_if_empty(self) -> None:
        """表が空なら、取り込み元（settings.json）から入れる。

        Bot と管理画面が同時に起動しても1回だけになるよう、排他を取ってから
        「まだ空か」を確かめる。
        """
        async with self._session() as session:
            try:
                await self._lock(session)
                exists = (await session.execute(select(state_table.c.id).where(state_table.c.id == 1))).first()
                if exists is not None:
                    await session.rollback()
                    return
                legacy, label = self._load_legacy()
                raw_guilds = legacy.get("guilds")
                guilds: dict[str, Any] = raw_guilds if isinstance(raw_guilds, dict) else {}
                for key, value in guilds.items():
                    await session.execute(insert(guild_table).values(guild_key=str(key), data=value))
                await session.execute(
                    insert(state_table).values(
                        id=1, version=1, root=_root_of(legacy), imported_from=label, imported_at=func.now()
                    )
                )
                await session.commit()
                logger.info("[settings] %s から %d ギルドを取り込みました", label, len(guilds))
            except BaseException:
                await session.rollback()
                raise

    async def _transact(self, fn: Callable[[dict[str, Any]], _T]) -> _T:
        """排他を取り、読み直し、fn を当て、変わったところだけを保存する。

        何も変わらなければ書かない（版番号も上げず、通知も出さない）。ファイル版で
        「取り除くものが無ければ書かない」としていたのと同じ（drop_stored_nulls）。
        """
        async with self._session() as session:
            try:
                await self._lock(session)
                data, version = await self._read_all(session)
                before_guilds = {key: _canon(value) for key, value in data["guilds"].items()}
                before_root = _canon(_root_of(data))

                result = fn(data)

                guilds = data.get("guilds")
                if not isinstance(guilds, dict):
                    raise TypeError("設定の guilds が辞書でなくなった（書き換えの誤り）")
                changed = {key: value for key, value in guilds.items() if before_guilds.get(str(key)) != _canon(value)}
                kept = {str(k) for k in guilds}
                removed = [key for key in before_guilds if key not in kept]
                root_changed = _canon(_root_of(data)) != before_root
                if not changed and not removed and not root_changed:
                    await session.rollback()
                    self._cache = (data, version)
                    return result

                for key, value in changed.items():
                    replaced = await session.execute(
                        update(guild_table)
                        .where(guild_table.c.guild_key == str(key))
                        .values(data=value, updated_at=func.now())
                    )
                    if not int(getattr(replaced, "rowcount", 0) or 0):
                        await session.execute(insert(guild_table).values(guild_key=str(key), data=value))
                for key in removed:
                    await session.execute(delete(guild_table).where(guild_table.c.guild_key == key))

                new_version = version + 1
                bumped = await session.execute(
                    update(state_table)
                    .where(state_table.c.id == 1)
                    .values(version=new_version, root=_root_of(data), updated_at=func.now())
                )
                if not int(getattr(bumped, "rowcount", 0) or 0):
                    await session.execute(insert(state_table).values(id=1, version=new_version, root=_root_of(data)))
                if self._dialect == "postgresql":
                    await session.execute(
                        text("SELECT pg_notify(:channel, :payload)").bindparams(
                            channel=CHANNEL, payload=str(new_version)
                        )
                    )
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        # 自分の書き込みは通知を待たずに手元へ入れる（通知が来ても版が同じなので読み直さない）。
        self._cache = (data, new_version)
        return result

    async def _refresh_if_newer(self, version_hint: Optional[int]) -> None:
        """手元より新しい版があれば、全体を読み直して差し替える。"""
        current = self.version()
        if version_hint is not None and version_hint <= current:
            return
        data, version = await self._read_all_fresh()
        if version > self.version():
            self._cache = (data, version)
            logger.debug("[settings] 他のプロセスの変更を読み直しました（版 %d → %d）", current, version)

    async def _poll_forever(self) -> None:
        """版番号だけを定期的に見る（LISTEN を取りこぼしたときの保険）。"""
        while True:
            await asyncio.sleep(self._poll_seconds)
            try:
                async with self._session() as session:
                    row = (await session.execute(select(state_table.c.version).where(state_table.c.id == 1))).first()
                    await session.rollback()
                if row is not None and int(row.version) > self.version():
                    await self._refresh_if_newer(int(row.version))
            except Exception as e:
                logger.warning("[settings] 版番号を確かめられませんでした（手元の設定で続けます）: %s", e)

    async def _listen_forever(self) -> None:
        """bot_settings_changed を聞き続ける。切れたらつなぎ直し、その間の分を読み直す。"""
        import asyncpg

        delay = 1.0
        while True:
            conn = None
            try:
                conn = await asyncpg.connect(self._listen_dsn)
                loop = asyncio.get_running_loop()

                def on_notify(_conn: Any, _pid: int, _channel: str, payload: str) -> None:
                    """通知の版番号が手元より新しければ読み直す。"""
                    try:
                        hint: Optional[int] = int(payload)
                    except ValueError:
                        hint = None
                    loop.create_task(self._refresh_if_newer(hint))

                # 接続が閉じたら即座に起こす。ときどきの問い合わせだけで気づく形にして
                # いたころは、サーバー側から切られると最大 30 秒、通知を受けられない
                # まま気づかなかった（本物の Postgres で pg_terminate_backend を当てて
                # 見つけた）。
                closed = asyncio.Event()
                conn.add_termination_listener(lambda _conn: closed.set())
                await conn.add_listener(CHANNEL, on_notify)
                # つないでいなかった間の書き込みを拾う。
                await self._refresh_if_newer(None)
                delay = 1.0
                while True:
                    try:
                        await asyncio.wait_for(closed.wait(), timeout=30)
                    except asyncio.TimeoutError:
                        # 閉じたことすら届かない切れ方（経路の途中で落ちた）に気づくため、
                        # ときどき問い合わせる。
                        await conn.execute("SELECT 1")
                        continue
                    raise ConnectionError("LISTEN の接続が切れた")
            except Exception as e:
                logger.warning("[settings] 変更の通知を受けられません（%.0f 秒後につなぎ直します）: %s", delay, e)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)
            finally:
                if conn is not None and not conn.is_closed():
                    try:
                        await conn.close()
                    except Exception:
                        pass


def asyncpg_dsn(sqlalchemy_url: str) -> str:
    """SQLAlchemy の URL（postgresql+asyncpg://…）を asyncpg が読める形にする。"""
    from sqlalchemy.engine import make_url

    return make_url(sqlalchemy_url).set(drivername="postgresql").render_as_string(hide_password=False)
