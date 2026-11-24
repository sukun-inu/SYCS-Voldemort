"""Bot と管理画面のあいだで受け渡す「シグナル」。

管理画面は Bot とは別プロセスなので、Bot にしかできない操作（VC への接続、
Discord への送信など）を直接は呼べない。管理画面が依頼を1行書き、Bot が
30秒ごとに取り出して実行する。

■ 置き場が Postgres である理由

以前は SETTINGS_DIR/_dev_signals/ にファイルを置いていた。これは Bot と管理画面が
同じボリュームを見ている間しか成り立たない。コンテナを別のホストへ分けた瞬間に、
管理画面には「キューに追加しました」と出るのに Bot には何も届かず、ログにも何も
残らない形で壊れる。

置き場は user_state_audit データベース。Bot と管理画面の両方が接続できる唯一の
データベースで、Web（metal_prices）はこの表を知らなくてよい。Valkey にしなかった
のは、Valkey には「消えても作り直せるもの」だけを置く約束だから
（docker-compose.yml の valkey の説明）。消えた依頼は作り直せない。

■ 2種類の依頼

    per_guild=False   何度実行しても結果が同じもの（ニュース取得など）。
                      溜めておく意味が無いので、同じ用途は1行にまとめる
                      （dedupe_key に用途名を入れ、一意制約で畳む）。

    per_guild=True    対象が payload の中にしかないもの（guild_id 付き）。
                      まとめると別のサーバー宛の指示が消えるので、dedupe_key を
                      NULL にして1回ごとに別の行にする。

後者をまとめていたころ（ファイル名が用途名だけだったころ）は、2つのサーバーの
管理者が30秒以内に操作すると先の1件が黙って消えていた。押した側には
「キューに追加しました」と出たままで、ログにも何も残らなかった。

■ 取り出し

claim() は取り出すと同時に消す。処理の途中で Bot が落ちれば、その依頼は失われる
（ファイルの頃と同じ）。2回実行されるより1回も実行されないほうを選んでいる。
地震リプレイやテスト通知が二重に飛ぶほうが、押し直すより困る。

取り出しは FOR UPDATE SKIP LOCKED で行う。今の Bot は1つだが、複数動かしたときに
同じ依頼を2つが拾わないようにするため。**SQLite（テスト）はこの句を黙って捨てる
ので、テストが通ってもここが効いている証拠にはならない。** Postgres 向けに
組み立てた SQL を直接確かめるテストを別に置いてある。
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Integer,
    MetaData,
    Table,
    Text,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.dml import ReturningDelete

from envutil import env_path

logger = logging.getLogger(__name__)

# 1回の巡回で取り出す上限。管理画面の各操作には 5〜10回/分 のレート制限が
# あるので、30秒の間にこれを超えて溜まることは通常ない。上限を置くのは、
# 何かの間違いで大量に積まれたときに1回の巡回が終わらなくなるのを避けるため
# （残りは次の巡回で取る）。
CLAIM_BATCH = 50

metadata = MetaData()

dev_signal = Table(
    "dev_signal",
    metadata,
    # SQLite（テスト）では BIGINT の主キーが自動採番にならないので INTEGER に読み替える。
    Column("id", BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True),
    Column("task", Text(), nullable=False),
    # per_guild=False の依頼だけ用途名を入れる。Postgres の一意制約は NULL 同士を
    # 別物として扱うので、per_guild=True の行（NULL）は何行でも並べられる。
    Column("dedupe_key", Text(), nullable=True, unique=True),
    Column("payload", Text(), nullable=False),
    # 並び順には使っていない（id で並べる）。溜まったまま残っている依頼を
    # SQL エディタで見たときに、いつ置かれたものかを分かるようにするため。
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


@dataclass(frozen=True)
class Signal:
    """取り出した依頼1件。payload は書いたときの文字列（JSON）のまま。"""

    id: int
    task: str
    payload: str


_init_lock: asyncio.Lock | None = None
_initialized = False


def _session() -> AsyncSession:
    """user_state_audit へのセッション。

    import をここまで遅らせているのは、このモジュールを読み込んだだけで接続先の
    解決（パスワードファイルの読み込み）が走らないようにするため。テストはこの
    関数を差し替えて SQLite へ向ける。
    """
    from services.user_state_db import SessionLocal

    return SessionLocal()


async def _create_table() -> None:
    """表が無ければ作る。checkfirst なので既にあっても何もしない。

    Alembic ではなく起動時に作るのは user_state_audit の他の表と同じ理由
    （services/user_state_db.py の ensure_user_state_db）。マイグレーションを回す
    のは Web のコンテナだけで、Bot と管理画面はそれを待たずに立ち上がる。
    """
    from services.user_state_db import engine

    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all, checkfirst=True)


async def _ensure_table() -> None:
    """初回だけ _create_table を呼ぶ。

    ロックの前後で2回見るのは、複数のコルーチンがほぼ同時に初回を迎えたときに
    CREATE TABLE を1回に留めるため（ensure_user_state_db と同じ形）。
    """
    global _init_lock, _initialized
    if _initialized:
        return
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    async with _init_lock:
        if _initialized:
            return
        await _create_table()
        _initialized = True


def _encode(payload: Any) -> str:
    """payload を保存する文字列にする。文字列はそのまま、それ以外は JSON にする。"""
    return payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)


async def write(name: str, payload: Any, *, per_guild: bool = False) -> None:
    """依頼を1つ置く。

    per_guild=True は「対象が payload の中にしかない」依頼に付ける。付け忘れると
    同じ用途の依頼が1行に畳まれ、Bot が拾う前に別の対象宛で上書きされて消える。

    保存できなかったときは例外をそのまま上げる。呼び出し側（管理画面）は
    それを押した人へ伝えること。握りつぶすと「キューに追加しました」と表示した
    まま何も起きない、という以前の壊れ方に戻る。
    """
    text = _encode(payload)
    await _ensure_table()

    if per_guild:
        async with _session() as session:
            await session.execute(insert(dev_signal).values(task=name, dedupe_key=None, payload=text))
            await session.commit()
        return

    async with _session() as session:
        # 同じ用途が既に待っていれば中身だけ差し替える。並び（id）は最初に置いた
        # 位置のまま。何度実行しても結果が同じ依頼なので、順序を動かす意味が無い。
        replaced = await session.execute(update(dev_signal).where(dev_signal.c.dedupe_key == name).values(payload=text))
        # rowcount は UPDATE が返す CursorResult にしか無い（Result の型には無い）。
        if int(getattr(replaced, "rowcount", 0) or 0) > 0:
            await session.commit()
            return
        try:
            await session.execute(insert(dev_signal).values(task=name, dedupe_key=name, payload=text))
            await session.commit()
        except IntegrityError:
            # 確かめてから入れるまでの間に、別の要求が同じ用途を入れた。結果が同じ
            # 依頼なので、相手の1行が残っていれば目的は果たせている。
            await session.rollback()


def _claim_statement(limit: int) -> ReturningDelete[Any]:
    """古いほうから limit 件を取り出して消す文。

    関数に分けてあるのは、Postgres 向けに組み立てた SQL をテストから直接確かめる
    ため（モジュール冒頭の「取り出し」）。
    """
    oldest = select(dev_signal.c.id).order_by(dev_signal.c.id).limit(limit).with_for_update(skip_locked=True)
    return (
        delete(dev_signal)
        .where(dev_signal.c.id.in_(oldest))
        .returning(dev_signal.c.id, dev_signal.c.task, dev_signal.c.payload)
    )


async def claim(limit: int = CLAIM_BATCH) -> list[Signal]:
    """待っている依頼を置かれた順に取り出し、表から消す。

    同じ用途が複数溜まっていることがあり、順序が入れ替わると噛み合わないので、
    必ず置いた順で返す。DELETE ... RETURNING が返す行の順は保証されないので、
    id で並べ直す。
    """
    await _ensure_table()
    async with _session() as session:
        rows = (await session.execute(_claim_statement(limit))).all()
        await session.commit()
    signals = [Signal(id=int(row.id), task=str(row.task), payload=str(row.payload)) for row in rows]
    return sorted(signals, key=lambda signal: signal.id)


async def pending() -> list[str]:
    """待っている依頼の用途名。開発者パネルの表示用。"""
    await _ensure_table()
    async with _session() as session:
        rows = await session.execute(select(dev_signal.c.task).order_by(dev_signal.c.id))
        return sorted(str(row[0]) for row in rows)


async def latest(name: str) -> str | None:
    """その用途で最後に置かれた依頼の中身。無ければ None。

    検証と、開発者パネルから中身を確認するためのもの。取り出さない（消さない）。
    """
    await _ensure_table()
    async with _session() as session:
        stmt = select(dev_signal.c.payload).where(dev_signal.c.task == name).order_by(dev_signal.c.id.desc()).limit(1)
        value = await session.scalar(stmt)
    return None if value is None else str(value)


# ── 以前の置き場（ファイル）からの移行 ─────────────────────────────
#
# 6c61884 までは SETTINGS_DIR/_dev_signals/ にファイルを置いていた。本番は
# 2026-11-25 時点でまだその版で動いている。入れ替えた時点で残っている依頼と、
# 入れ替えの途中で古い管理画面が書いた依頼を、取りこぼさずに表へ移す。
#
# **外せる条件:** 本番から 6c61884 以前の版が無くなり、data/_dev_signals/ が空に
# なったことを確かめたら、この節と events/background_tasks.py の呼び出しを消してよい。

LEGACY_SUFFIX = ".signal"
_IMPORTING_SUFFIX = ".importing"
_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def legacy_dir() -> Path:
    """以前の置き場。書いていた側と同じく SETTINGS_DIR から解決する。"""
    return env_path("SETTINGS_DIR", _DEFAULT_DATA_DIR) / "_dev_signals"


def _legacy_files(directory: Path) -> list[Path]:
    """残っている依頼ファイルを、置かれた順（更新時刻、同じならファイル名）に並べる。

    取り込む順が表の id の順になり、それが Bot の実行順になる。ファイルの頃も
    置かれた順に実行していたので、並びを崩さない。
    """

    def order(path: Path) -> tuple[float, str]:
        """並べ替えの鍵。読んでいる間に消えたものは最後へ回す。"""
        try:
            return (path.stat().st_mtime, path.name)
        except OSError:
            return (float("inf"), path.name)

    return sorted(directory.glob(f"*{LEGACY_SUFFIX}"), key=order)


def _parse_legacy_name(path: Path) -> tuple[str, bool]:
    """ファイル名から (用途名, per_guild か) を取り出す。

    "news_feeds.signal"          -> ("news_feeds", False)
    "eq_replay.19f3a2c1de.signal" -> ("eq_replay", True)

    以前の書き方では、per_guild の依頼だけ用途名の後ろに一意な部分を足していた。
    """
    stem = path.name[: -len(LEGACY_SUFFIX)]
    task, _, unique = stem.partition(".")
    return task, bool(unique)


async def import_legacy_files() -> int:
    """以前の置き場に残っている依頼を表へ移し、移した件数を返す。

    1件ずつ、名前を .importing に変えてから表へ書き、書けたら消す。

      - 書けなかったら名前を戻す。次の巡回で取り直す（取りこぼさない）
      - 書けたあとで消せなくても、名前がもう .signal ではないので、次の巡回で
        二重に取り込まない（二重に実行しない）

    表へ書く途中の失敗（データベースに届かない）は、そのまま上げる。呼ぶ側
    （Bot の巡回）が warning を出し、次の巡回で続きから移す。
    """
    directory = legacy_dir()
    if not directory.is_dir():
        return 0
    moved = 0
    for path in _legacy_files(directory):
        importing = path.with_name(path.name + _IMPORTING_SUFFIX)
        try:
            path.rename(importing)
            text = importing.read_text(encoding="utf-8")
        except FileNotFoundError:
            # 別の巡回か別のプロセスが先に取った。
            continue
        except OSError as e:
            logger.warning("[signal] 以前の置き場のファイルを読めませんでした（%s）: %s", path.name, e)
            continue
        task, per_guild = _parse_legacy_name(path)
        try:
            await write(task, text, per_guild=per_guild)
        except BaseException:
            # 名前を戻してから上げる。戻さないと .importing のまま残り、二度と
            # 拾われない（依頼が黙って消える）。
            try:
                importing.rename(path)
            except OSError as e:
                logger.error("[signal] 取り込みに失敗したファイルの名前を戻せませんでした（%s）: %s", importing.name, e)
            raise
        try:
            importing.unlink()
        except OSError as e:
            logger.warning("[signal] 取り込んだファイルを消せませんでした（%s）: %s", importing.name, e)
        moved += 1
    if moved:
        logger.info("[signal] 以前の置き場（%s）から %d 件を表へ移しました", directory, moved)
    return moved
