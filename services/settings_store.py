import logging
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar, cast

from envutil import env_float, env_path

try:
    import orjson as _json

    _ORJSON = True
except ImportError:
    # orjson が無いときは標準の json を同じ名前で使う（片方しか入らない）。
    import json as _json  # type: ignore[no-redef]

    _ORJSON = False

logger = logging.getLogger(__name__)

# Docker: ./data:/app/data がボリュームマウントされるため /app/data 配下に保存。
# SETTINGS_DIR 環境変数で上書き可能（ローカル開発用）。
# 素の os.getenv(..., "既定値") は、変数が空文字で「宣言だけされている」場合に
# 既定値へ倒れない（int/float なら例外、Path なら Path("") = カレントディレクトリに
# なって事故る）。envutil はそれを空文字ごと「未設定」として扱う。
_default_dir = Path(__file__).resolve().parent.parent / "data"
_SETTINGS_DIR = env_path("SETTINGS_DIR", _default_dir)
_SETTINGS_FILE = _SETTINGS_DIR / "settings.json"
_SETTINGS_LOCK_FILE = _SETTINGS_DIR / "settings.json.lock"
_SETTINGS_LOCK_TIMEOUT_SEC = env_float("SETTINGS_LOCK_TIMEOUT_SECONDS", 10.0, minimum=0.2)
_SETTINGS_LOCK_STALE_SEC = env_float(
    "SETTINGS_LOCK_STALE_SECONDS",
    30.0,
    minimum=_SETTINGS_LOCK_TIMEOUT_SEC,
)
_SETTINGS_LOCK_POLL_SEC = 0.05

# メモリ内キャッシュ。ファイル署名（mtime_ns + size）が変わったら自動無効化するため、
# Bot と WebUI が別プロセスでもファイル更新を検知できる。
_cache: dict[str, Any] | None = None
_cache_sig: tuple[int, int] | None = None
_T = TypeVar("_T")


def _file_signature() -> tuple[int, int] | None:
    """ファイルが無ければ None を返す。

    _cache_sig との比較にしか使わないので、None は「絶対に一致しない」ための
    センチネル。数値のタプルにしてしまうと、ファイル未作成時のキャッシュ判定が
    誤って「有効」になりかねない。
    """
    try:
        stat = _SETTINGS_FILE.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _normalize_root(data: Any) -> dict[str, Any]:
    """settings.json の中身が壊れていても構造だけは保証する。

    トップレベルが dict でない、または "guilds" が dict でない場合はここで
    空の構造に矯正する。以降の全コードは data["guilds"] が dict である前提で
    書かれているため、ここを通さないと手動編集や書き込み中断で壊れた JSON を
    読んだときに AttributeError で落ちる。
    """
    if not isinstance(data, dict):
        return {"guilds": {}}

    data.setdefault("guilds", {})
    if not isinstance(data["guilds"], dict):
        data["guilds"] = {}
    return data


def _load_all_from_disk() -> dict[str, Any]:
    """破損した settings.json を握りつぶし、空の構造にフォールバックする。

    読み込み専用に見えるが、_mutate_settings はこの戻り値をそのまま
    _save_all() で書き戻す。つまりここで壊れたファイルを「空」に丸めると、
    次に誰かが1ギルドの設定を変えただけで、他の全ギルド分の設定ごと
    消えて保存されてしまう。例外を潰しているのは「起動を止めない」ためで
    あって、「データを守る」保証ではない。
    """
    sig = _file_signature()
    if sig is None:
        return {"guilds": {}}

    try:
        data = _json.loads(_SETTINGS_FILE.read_bytes())
    except Exception:
        return {"guilds": {}}
    return _normalize_root(data)


@contextmanager
def _settings_file_lock(timeout_sec: float = _SETTINGS_LOCK_TIMEOUT_SEC):
    """settings.json 用のプロセス間排他ロック（O_CREAT|O_EXCL によるファイルロック）。

    Bot 本体と管理画面（webapp_admin）は別プロセスで同じ settings.json を
    共有しているため、スレッドロックではなくファイルロックで取る。
    timeout_sec 以内に取得できなければ TimeoutError を送出する。
    SETTINGS_LOCK_STALE_SECONDS を超えて残っているロックは、所有プロセスが
    クラッシュして消し忘れたものとみなして奪い取る（そうしないと恒久的な
    デッドロックになる）。
    """
    _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    owner_id = uuid.uuid4().hex
    deadline = time.monotonic() + timeout_sec

    while True:
        try:
            fd = os.open(
                str(_SETTINGS_LOCK_FILE),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as lock_fp:
                lock_fp.write(owner_id)
            break
        except FileExistsError:
            try:
                lock_age = time.time() - _SETTINGS_LOCK_FILE.stat().st_mtime
                if lock_age > _SETTINGS_LOCK_STALE_SEC:
                    _SETTINGS_LOCK_FILE.unlink(missing_ok=True)
                    continue
            except OSError as e:
                # ポーリング中（最短0.05秒間隔）に起きうるので debug に留める。
                # stat() が失敗するのはファイルが競合相手に削除された直後などで
                # 一過性のことが多いが、恒久的な原因（権限不足等）なら最終的に
                # 下の TimeoutError で気づける。理由だけは残しておく。
                logger.warning("[settings] ロックの経過時間を確認できませんでした: %s", e)
            if time.monotonic() >= deadline:
                raise TimeoutError("settings.json のロック取得がタイムアウトしました。")
            time.sleep(_SETTINGS_LOCK_POLL_SEC)

    try:
        yield
    finally:
        try:
            current_owner = _SETTINGS_LOCK_FILE.read_text(encoding="utf-8")
        except OSError as e:
            # 所有者を確認できない以上、他人のロックを消さないため空扱いにして
            # unlink はしない（安全側）。ただし本来なら自分が持っているはずの
            # ロックを読めなかった、という異常は残しておく。
            logger.warning("[settings] ロックファイルの所有者を確認できませんでした: %s", e)
            current_owner = ""
        if current_owner == owner_id:
            try:
                _SETTINGS_LOCK_FILE.unlink(missing_ok=True)
            except OSError as e:
                # 自分のロックを消せなかった。他プロセスは _SETTINGS_LOCK_STALE_SEC
                # 経過するまで「使用中」と誤認して待たされ続けるので、原因を残す。
                logger.warning("[settings] ロックファイルを削除できませんでした: %s", e)


def _load_all() -> dict[str, Any]:
    """ファイル署名が前回と同じならディスクを読まずキャッシュを返す。

    mtime_ns + size だけを見る軽量な検証で、Bot と管理画面が別プロセスでも
    互いの書き込みをポーリングなしで検知できる。中身までは比較しないため、
    別プロセスが同一 mtime・同一サイズになる書き込みをした場合は理論上
    すり抜ける。
    """
    global _cache, _cache_sig
    sig = _file_signature()
    if _cache is not None and sig == _cache_sig:
        return _cache

    _cache = _load_all_from_disk()
    _cache_sig = _file_signature()
    return _cache


def _save_all(data: dict[str, Any]) -> None:
    """一時ファイル経由でアトミックに書き込み、メモリキャッシュも更新する。

    直接 _SETTINGS_FILE に書くと、書き込み中のクラッシュや別プロセスとの
    競合で JSON が壊れた状態のまま残り得る。tmp.replace() は同一
    ファイルシステム上ならアトミックなので、既存ファイルが半端な状態で
    上書きされることはない。
    """
    global _cache, _cache_sig
    _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)

    # アトミック書き込み: クラッシュ時に settings.json が壊れるのを防ぐ。
    tmp = _SETTINGS_FILE.with_suffix(".json.tmp")
    if _ORJSON:
        tmp.write_bytes(_json.dumps(data, option=_json.OPT_INDENT_2))
    else:
        # _json は try/except で orjson か json のどちらかが入る変数だが、mypy は
        # 代入時の型（orjson側）で固定して見てしまうため、_ORJSON が False の
        # ときに実際に使われる標準ライブラリ json.dumps の signature
        # （indent/ensure_ascii を受け取り str を返す）と食い違って誤検知する。
        tmp.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")  # type: ignore[call-arg,arg-type]
    tmp.replace(_SETTINGS_FILE)

    _cache = data
    _cache_sig = _file_signature()


def _mutate_settings(mutator: Callable[[dict[str, Any]], _T]) -> _T:
    """ロックを取り、ディスクから読み直してから mutator を適用して保存する。

    _load_all() のキャッシュではなく _load_all_from_disk() を使うのは、
    ロックを取るまでの間に他プロセスが書き込んでいる可能性があるため。
    キャッシュ経由で読むと、他プロセスの直前の変更を mutator が知らずに
    上書きしてしまう。
    """
    with _settings_file_lock():
        data = _load_all_from_disk()
        result = mutator(data)
        _save_all(data)
        return result


async def awrite(func: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """設定を書き換える同期関数を、別スレッドで実行する。

    settings.json の書き込みはファイルロックを取る。ロックが空くのを待つ間は
    time.sleep(0.05) のポーリングで、既定のタイムアウトは10秒
    （SETTINGS_LOCK_TIMEOUT_SECONDS）。Bot と管理画面は別プロセスで同じ
    ファイルを共有しているので、競合は実際に起きる。

    async の中から同期のセッターを直に呼ぶと、待つ側のイベントループ全体が
    その間止まる。Bot なら Discord のハートビートと全ギルドのイベント処理が、
    管理画面（既定 workers=1）ならヘルスチェックを含む全 HTTP 応答が固まる。

    そのため、非同期の文脈から設定を書き換えるときは必ずこれを通す。

        await awrite(set_welcome_channel, guild_id, channel.id)

    直呼びが混ざっていないことは tests 側で機械的に確かめている
    （tests/test_services.py の SettingsWriteOffloadTests）。
    """
    import asyncio

    return await asyncio.to_thread(lambda: func(*args, **kwargs))


async def amutate_settings(mutator: Callable[[dict[str, Any]], _T]) -> _T:
    """_mutate_settings を別スレッドで実行する。

    ロック取得は time.sleep(0.05) のポーリングで、タイムアウトは既定10秒。
    Bot と管理画面は別プロセスなので実際に競合する。async から直接呼ぶと
    そのあいだ呼び出し側プロセスのイベントループ全体が止まるため、
    非同期の文脈からはこちらを使う。
    """
    import asyncio

    return await asyncio.to_thread(_mutate_settings, mutator)


async def aupdate_news_feed_state(
    guild_id: int,
    feed_id: str,
    last_run: float,
    seen_hashes: list,
) -> None:
    """update_news_feed_state の非同期版（ニュースループから使う）。"""
    await amutate_settings(_news_feed_state_mutator(guild_id, feed_id, last_run, seen_hashes))


def get_guild_settings(guild_id: int) -> dict[str, Any]:
    """指定ギルドの設定を取得（存在しない場合は空 dict）。"""
    guilds: dict[str, Any] = _load_all().get("guilds", {})
    return dict(guilds.get(str(guild_id), {}))


def update_guild_settings(guild_id: int, updates: dict[str, Any]) -> dict[str, Any]:
    """指定ギルドの設定を更新し、保存してから最新状態を返す。"""

    def _mutator(data: dict[str, Any]) -> dict[str, Any]:
        """updates を既存の設定にマージする（丸ごと置換ではない）。

        updates に含まれないキーはそのまま残る。current が dict でない場合
        （データ破損時）は空の dict から始めて実質的に復旧する。
        """
        guilds: dict[str, Any] = data.setdefault("guilds", {})
        current = guilds.get(str(guild_id), {})
        if not isinstance(current, dict):
            current = {}
        current.update(updates)
        guilds[str(guild_id)] = current
        return dict(current)

    return _mutate_settings(_mutator)


def replace_guild_settings(guild_id: int, new_settings: dict[str, Any]) -> None:
    """指定ギルドの設定を丸ごと置換して保存する（インポート用）。"""

    def _mutator(data: dict[str, Any]) -> None:
        """指定ギルドの設定をまるごと差し替える（マージしない）。

        インポート機能から呼ばれる想定で、既存キーが新しい設定に無ければ
        消えてよいという前提で書かれている。
        """
        data.setdefault("guilds", {})[str(guild_id)] = dict(new_settings)

    _mutate_settings(_mutator)


def _get_or_create_guild(data: dict[str, Any], guild_id: int) -> dict[str, Any]:
    """guilds[str(guild_id)] を dict として保証し、その実体への参照を返す。

    コピーではなく data 内の実体を返す点が重要。呼び出し側はこの戻り値を
    直接書き換えることで data 全体に反映させる設計になっており、
    _update_nested などがこの挙動に依存している。
    """
    guilds: dict[str, Any] = data.setdefault("guilds", {})
    current: dict[str, Any] = guilds.get(str(guild_id), {})
    if not isinstance(current, dict):
        current = {}
    guilds[str(guild_id)] = current
    return current


def _update_nested(guild_id: int, top_key: str, patch: dict[str, Any]) -> None:
    """top_key 配下の辞書に patch をマージして保存する共通ヘルパー。

    welcome / goodbye / earthquake など「ネストした設定ブロックの一部だけ
    更新したい」呼び出しはすべてこれを経由する。ネストが dict でなければ
    （型不整合や初回書き込み）空から作り直すので、壊れた値が入っていても
    例外にならない。
    """

    def _mutator(data: dict[str, Any]) -> None:
        """current[top_key] の dict を取り出し、patch で上書きマージしてから
        書き戻す。戻り値は使わない（呼び出し側は _update_nested 経由で
        結果を必要としない）。
        """
        current = _get_or_create_guild(data, guild_id)
        nested = current.get(top_key, {})
        if not isinstance(nested, dict):
            nested = {}
        nested.update(patch)
        current[top_key] = nested

    _mutate_settings(_mutator)


def _parse_id_list(raw: Any) -> list[int]:
    """リスト以外や int に変換できない要素は黙って捨てる。

    設定ファイルはユーザー入力やインポートを経由するため、文字列化された
    ID や壊れた値が混ざり得る。ここで例外を出すと呼び出し元の設定読み込みが
    軒並み落ちるので、無効な要素だけ落として処理を続ける。
    """
    if not isinstance(raw, list):
        return []
    result: list[int] = []
    for v in raw:
        try:
            result.append(int(v))
        except (TypeError, ValueError):
            continue
    return result


def _get_int_setting(guild_id: int, setting_name: str) -> int:
    """整数型の設定値を取得する。未設定または無効な値の場合は0を返す。"""
    value = get_guild_settings(guild_id).get(setting_name)
    try:
        return int(cast(Any, value))
    except (TypeError, ValueError):
        return 0


def _get_dict_setting(guild_id: int, setting_name: str) -> dict[str, Any]:
    """辞書型の設定値を取得する。未設定の場合は空の辞書を返す。"""
    return dict(get_guild_settings(guild_id).get(setting_name, {}))


def get_response_channel_id(guild_id: int) -> int:
    """ChatGPT応答チャンネルIDを取得（未設定なら0を返す）。"""
    return _get_int_setting(guild_id, "response_channel_id")


def set_response_channel_id(guild_id: int, channel_id: int | None) -> dict[str, Any]:
    """ChatGPT応答チャンネルIDを設定/解除。"""
    return update_guild_settings(guild_id, {"response_channel_id": channel_id})


def get_trusted_user_ids(guild_id: int) -> list[int]:
    """信頼済みユーザーの許可リストを返す。

    保存値が壊れていても _parse_id_list が不正な要素を弾くので、
    呼び出し側は常に int のリストを受け取れる。
    """
    return _parse_id_list(get_guild_settings(guild_id).get("trusted_user_ids"))


def add_trusted_users(guild_id: int, user_ids: list[int]) -> list[int]:
    """信頼済みユーザーに追加して、最新のリストを返す。"""

    def _mutator(data: dict[str, Any]) -> list[int]:
        """現在の信頼済みIDへ user_ids を足し込み、重複除去のうえ昇順ソートして
        保存する。set 経由なので同じIDを何度追加しても増えない。
        """
        current = _get_or_create_guild(data, guild_id)
        trusted = set(_parse_id_list(current.get("trusted_user_ids")))
        for i in user_ids:
            try:
                trusted.add(int(i))
            except (TypeError, ValueError):
                continue
        current["trusted_user_ids"] = sorted(trusted)
        return sorted(trusted)

    return _mutate_settings(_mutator)


def remove_trusted_users(guild_id: int, user_ids: list[int]) -> list[int]:
    """信頼済みユーザーから削除して、最新のリストを返す。"""

    def _mutator(data: dict[str, Any]) -> list[int]:
        """discard で該当IDを取り除く。remove() ではないので、そもそも登録されて
        いないIDを渡しても例外にならず、UIの一括解除操作が安全に動く。
        """
        current = _get_or_create_guild(data, guild_id)
        trusted = set(_parse_id_list(current.get("trusted_user_ids")))
        for i in user_ids:
            try:
                trusted.discard(int(i))
            except (TypeError, ValueError):
                continue
        current["trusted_user_ids"] = sorted(trusted)
        return sorted(trusted)

    return _mutate_settings(_mutator)


def get_bypass_role_ids(guild_id: int) -> list[int]:
    """モデレーション等をバイパスするロールIDの一覧を返す。

    保存値の型が壊れていても _parse_id_list 経由で int のリストとして返る。
    """
    return _parse_id_list(get_guild_settings(guild_id).get("bypass_role_ids"))


def add_bypass_roles(guild_id: int, role_ids: list[int]) -> list[int]:
    """バイパス対象ロールに追加し、最新のリストを返す。"""

    def _mutator(data: dict[str, Any]) -> list[int]:
        """現在のバイパスロールへ role_ids を足し込み、重複除去のうえ昇順ソートして
        保存する。
        """
        current = _get_or_create_guild(data, guild_id)
        bypass = set(_parse_id_list(current.get("bypass_role_ids")))
        for i in role_ids:
            try:
                bypass.add(int(i))
            except (TypeError, ValueError):
                continue
        current["bypass_role_ids"] = sorted(bypass)
        return sorted(bypass)

    return _mutate_settings(_mutator)


def remove_bypass_roles(guild_id: int, role_ids: list[int]) -> list[int]:
    """バイパス対象ロールから削除し、最新のリストを返す。"""

    def _mutator(data: dict[str, Any]) -> list[int]:
        """discard でロールIDを取り除く。指定IDが未登録でも例外にならない。"""
        current = _get_or_create_guild(data, guild_id)
        bypass = set(_parse_id_list(current.get("bypass_role_ids")))
        for i in role_ids:
            try:
                bypass.discard(int(i))
            except (TypeError, ValueError):
                continue
        current["bypass_role_ids"] = sorted(bypass)
        return sorted(bypass)

    return _mutate_settings(_mutator)


# ──────────────────────────────────────────────
# ウェルカム / グッバイ
# ──────────────────────────────────────────────


def get_welcome_settings(guild_id: int) -> dict[str, Any]:
    """welcome ブロック（channel_id, message）を返す。未設定なら空 dict。"""
    return _get_dict_setting(guild_id, "welcome")


def set_welcome_channel(guild_id: int, channel_id: int | None) -> None:
    """ウェルカムメッセージの送信先チャンネルを設定/解除する。

    channel_id に None を渡すと送信自体が無効になるが、message は消えない
    （再度チャンネルを設定すれば以前の本文がそのまま使われる）。
    """
    _update_nested(guild_id, "welcome", {"channel_id": channel_id})


def set_welcome_message(guild_id: int, message: str | None) -> None:
    """ウェルカムメッセージ本文を設定する。channel_id が未設定のままだと
    本文があっても送信されない（events 側の実送信は channel_id 有無で
    判断している）。
    """
    _update_nested(guild_id, "welcome", {"message": message})


def get_goodbye_settings(guild_id: int) -> dict[str, Any]:
    """goodbye ブロック（channel_id, message）を返す。未設定なら空 dict。"""
    return _get_dict_setting(guild_id, "goodbye")


def set_goodbye_channel(guild_id: int, channel_id: int | None) -> None:
    """退出時メッセージの送信先チャンネルを設定/解除する。welcome とは
    独立したチャンネルとして保存される。
    """
    _update_nested(guild_id, "goodbye", {"channel_id": channel_id})


def set_goodbye_message(guild_id: int, message: str | None) -> None:
    """退出時メッセージ本文を設定する。channel_id が未設定なら送信されない
    のは welcome 側と同じ。
    """
    _update_nested(guild_id, "goodbye", {"message": message})


# ──────────────────────────────────────────────
# VC 通知チャンネル
# ──────────────────────────────────────────────


def get_vc_notify_channel_id(guild_id: int) -> int:
    """VC通知チャンネルIDを取得（未設定なら0を返す）。"""
    return _get_int_setting(guild_id, "vc_notify_channel_id")


def set_vc_notify_channel_id(guild_id: int, channel_id: int | None) -> None:
    """VC入退室通知の送信先チャンネルを設定/解除する。0 ではなく None を
    渡すと未設定として扱われる（get 側は _get_int_setting で 0 に
    フォールバックする）。
    """
    update_guild_settings(guild_id, {"vc_notify_channel_id": channel_id})


def get_vc_notify_role_id(guild_id: int) -> int:
    """VC通知時にメンションするロールIDを取得（未設定なら0）。"""
    return _get_int_setting(guild_id, "vc_notify_role_id")


def set_vc_notify_role_id(guild_id: int, role_id: int | None) -> None:
    """VC通知でメンションするロールを設定/解除する。ここでは値の保存のみで、
    実際にメンションを付けるかどうかは通知を組み立てる側の責務。
    """
    update_guild_settings(guild_id, {"vc_notify_role_id": role_id})


def get_vc_notify_filter_role_id(guild_id: int) -> int:
    """通知フィルター用ロールIDを取得（未設定なら0＝全VC通知）。"""
    return _get_int_setting(guild_id, "vc_notify_filter_role_id")


def set_vc_notify_filter_role_id(guild_id: int, role_id: int | None) -> None:
    """指定ロールを持つメンバーの入退室だけ通知するよう絞り込む設定。
    未設定または 0 なら全員が通知対象になる。
    """
    update_guild_settings(guild_id, {"vc_notify_filter_role_id": role_id})


# ──────────────────────────────────────────────
# スティッキーメッセージ
# ──────────────────────────────────────────────


def get_sticky_messages(guild_id: int) -> dict[str, Any]:
    """channel_id(str) → {"content": str, "message_id": int|None}"""
    return _get_dict_setting(guild_id, "sticky_messages")


def set_sticky_message(guild_id: int, channel_id: int, content: str) -> None:
    """スティッキーメッセージの内容を差し替える。

    既存の message_id は温存したまま pending を "post" にする。実際の
    Discord メッセージの再投稿はここでは行わず、Bot 側の定期タスクに
    指示を出すだけ。
    """
    key = str(channel_id)

    def _mutator(data: dict[str, Any]) -> None:
        """content を書き換え、既存の message_id はそのまま残しつつ
        pending="post" を立てる。
        """
        current = _get_or_create_guild(data, guild_id)
        stickies = current.get("sticky_messages", {})
        if not isinstance(stickies, dict):
            stickies = {}
        existing = stickies.get(key, {})
        if not isinstance(existing, dict):
            existing = {}
        stickies[key] = {
            "content": content,
            "message_id": existing.get("message_id"),
            "pending": "post",
        }
        current["sticky_messages"] = stickies

    _mutate_settings(_mutator)


def update_sticky_message_id(guild_id: int, channel_id: int, message_id: int | None) -> None:
    """Discord へ実際に投稿・編集した後の message_id を書き戻す。

    pending フラグはここで消える。定期タスクはこれを見て「対応済み」と
    判断する。
    """
    key = str(channel_id)

    def _mutator(data: dict[str, Any]) -> None:
        """message_id を更新して pending を消す。エントリが存在しない、または
        壊れている場合は何もしない（削除タイミングとの競合に対して
        安全側に倒す）。
        """
        current = _get_or_create_guild(data, guild_id)
        stickies = current.get("sticky_messages", {})
        if not isinstance(stickies, dict):
            return
        if key not in stickies or not isinstance(stickies[key], dict):
            return
        stickies[key]["message_id"] = message_id
        stickies[key].pop("pending", None)
        current["sticky_messages"] = stickies

    _mutate_settings(_mutator)


def mark_sticky_pending_delete(guild_id: int, channel_id: int) -> None:
    """削除待ちフラグを立てる。Botの定期タスクがDiscordメッセージを削除した後エントリを消す。"""
    key = str(channel_id)

    def _mutator(data: dict[str, Any]) -> None:
        """pending="delete" を立てるだけでエントリ自体は消さない。実際の削除は
        Discord 側のメッセージ削除が完了してから定期タスクが行う。
        """
        current = _get_or_create_guild(data, guild_id)
        stickies = current.get("sticky_messages", {})
        if not isinstance(stickies, dict):
            return
        if key in stickies and isinstance(stickies[key], dict):
            stickies[key]["pending"] = "delete"
            current["sticky_messages"] = stickies

    _mutate_settings(_mutator)


def remove_sticky_message(guild_id: int, channel_id: int) -> None:
    """スティッキー設定を完全に削除する。Discord 側の実メッセージ削除は
    呼び出し側の責務で、ここでは設定データを消すだけ。
    """
    key = str(channel_id)

    def _mutator(data: dict[str, Any]) -> None:
        """stickies から該当キーを pop するだけ。存在しなくてもエラーにならない。"""
        current = _get_or_create_guild(data, guild_id)
        stickies = current.get("sticky_messages", {})
        if not isinstance(stickies, dict):
            return
        stickies.pop(key, None)
        current["sticky_messages"] = stickies

    _mutate_settings(_mutator)


# ──────────────────────────────────────────────
# リアクションロール
# ──────────────────────────────────────────────


def get_reaction_roles(guild_id: int) -> dict[str, Any]:
    """message_id(str) → {emoji(str) → role_id(int)}"""
    return _get_dict_setting(guild_id, "reaction_roles")


def add_reaction_role(guild_id: int, message_id: int, emoji: str, role_id: int) -> None:
    """message_id + emoji の組にロールを登録する。既に同じ組み合わせが
    あれば role_id を上書きする（重複登録は起きない）。
    """
    key = str(message_id)

    def _mutator(data: dict[str, Any]) -> None:
        """message_id をキーに emoji→role_id の対応表へ1件追加/上書きする。"""
        current = _get_or_create_guild(data, guild_id)
        rr = current.get("reaction_roles", {})
        if not isinstance(rr, dict):
            rr = {}
        mapping = rr.get(key, {})
        if not isinstance(mapping, dict):
            mapping = {}
        mapping[emoji] = role_id
        rr[key] = mapping
        current["reaction_roles"] = rr

    _mutate_settings(_mutator)


def remove_reaction_role(guild_id: int, message_id: int, emoji: str) -> bool:
    """指定の絵文字だけを削除する。対応表が空になったら message_id の
    エントリごと消し、空の dict がゴミとして残らないようにする。
    戻り値は実際に何か削除したかどうか。
    """
    key = str(message_id)

    def _mutator(data: dict[str, Any]) -> bool:
        """emoji が登録されていなければ何もせず False を返す。マッピングが空に
        なったら message_id のエントリごと削除する。
        """
        current = _get_or_create_guild(data, guild_id)
        rr = current.get("reaction_roles", {})
        if not isinstance(rr, dict):
            return False
        mapping = rr.get(key)
        if not isinstance(mapping, dict) or emoji not in mapping:
            return False
        del mapping[emoji]
        if not mapping:
            del rr[key]
        else:
            rr[key] = mapping
        current["reaction_roles"] = rr
        return True

    return _mutate_settings(_mutator)


# ──────────────────────────────────────────────
# ニュースフィード
# ──────────────────────────────────────────────


def get_all_guild_ids() -> list[int]:
    """保存済みの全ギルドIDを返す。キーが int に変換できないもの（データ破損）
    は黙って除外される。
    """
    guilds: dict[str, Any] = _load_all().get("guilds", {})
    result: list[int] = []
    for k in guilds:
        try:
            result.append(int(k))
        except (TypeError, ValueError):
            continue
    return result


def get_news_feeds(guild_id: int) -> dict[str, Any]:
    """feed_id(str) → {"channel_id": int, "query": str, "interval": int, "last_run": float, "seen_hashes": list}"""
    return _get_dict_setting(guild_id, "news_feeds")


def add_news_feed(guild_id: int, feed_id: str, channel_id: int, query: str, interval_minutes: int) -> None:
    """新しいニュースフィードを登録する。

    同じ feed_id が既にあれば内容ごと上書きする。last_run と seen_hashes は
    必ず初期化されるため、既存フィードの feed_id を使い回すと既読済み記事が
    「未読」扱いに戻り、大量の再通知を招く（呼び出し側が feed_id の一意性を
    保証する前提）。
    """

    def _mutator(data: dict[str, Any]) -> None:
        """feed_id で新規エントリを作る。last_run と seen_hashes は必ず初期値へ
        リセットされる。
        """
        current = _get_or_create_guild(data, guild_id)
        feeds = current.get("news_feeds", {})
        if not isinstance(feeds, dict):
            feeds = {}
        feeds[feed_id] = {
            "channel_id": channel_id,
            "query": query,
            "interval": interval_minutes,
            "last_run": 0.0,
            "seen_hashes": [],
        }
        current["news_feeds"] = feeds

    _mutate_settings(_mutator)


def remove_news_feed(guild_id: int, feed_id: str) -> bool:
    """フィードを削除する。存在しなければ何もせず False を返す。"""

    def _mutator(data: dict[str, Any]) -> bool:
        """feed_id が存在するときだけ削除し、真偽値で結果を呼び出し側へ伝える。"""
        current = _get_or_create_guild(data, guild_id)
        feeds = current.get("news_feeds", {})
        if not isinstance(feeds, dict) or feed_id not in feeds:
            return False
        del feeds[feed_id]
        current["news_feeds"] = feeds
        return True

    return _mutate_settings(_mutator)


def update_news_feed(guild_id: int, feed_id: str, channel_id: int, query: str, interval_minutes: int) -> bool:
    """フィードの設定（チャンネル・クエリ・間隔）を更新する。seen_hashes と last_run は保持する。"""

    def _mutator(data: dict[str, Any]) -> bool:
        """channel_id・query・interval だけを更新し、last_run と seen_hashes は
        意図的に触らない。ここを丸ごと置換にすると、設定を少し直しただけで
        既読済み記事が全部「未読」に戻り、大量の再通知が飛ぶ。
        """
        current = _get_or_create_guild(data, guild_id)
        feeds = current.get("news_feeds", {})
        if not isinstance(feeds, dict) or feed_id not in feeds:
            return False
        row = feeds.get(feed_id, {})
        if not isinstance(row, dict):
            row = {}
        row.update({"channel_id": channel_id, "query": query, "interval": interval_minutes})
        feeds[feed_id] = row
        current["news_feeds"] = feeds
        return True

    return _mutate_settings(_mutator)


def _news_feed_state_mutator(
    guild_id: int,
    feed_id: str,
    last_run: float,
    seen_hashes: list,
) -> Callable[[dict[str, Any]], None]:
    """同期版・非同期版の両方から使う mutator。"""

    def _mutator(data: dict[str, Any]) -> None:
        """seen_hashes は直近100件だけ保持する。無制限に増やすと settings.json が
        肥大化し続けるため、重複判定に足りる範囲で打ち切っている。
        """
        current = _get_or_create_guild(data, guild_id)
        feeds = current.get("news_feeds", {})
        if not isinstance(feeds, dict) or feed_id not in feeds:
            return
        row = feeds.get(feed_id, {})
        if not isinstance(row, dict):
            row = {}
        row["last_run"] = last_run
        row["seen_hashes"] = seen_hashes[-100:]
        feeds[feed_id] = row
        current["news_feeds"] = feeds

    return _mutator


def update_news_feed_state(guild_id: int, feed_id: str, last_run: float, seen_hashes: list) -> None:
    """同期版。ニュースループ以外（コマンド等）からの直接呼び出しを想定。
    async の文脈からは awrite 経由でこれを呼ぶか、非同期版の
    aupdate_news_feed_state を使うこと。
    """
    _mutate_settings(_news_feed_state_mutator(guild_id, feed_id, last_run, seen_hashes))


# ──────────────────────────────────────────────
# 地震アラート
# ──────────────────────────────────────────────


def get_earthquake_settings(guild_id: int) -> dict[str, Any]:
    """earthquake ブロック（channel_id, min_scale, notify_types）を返す。
    未設定なら空 dict。
    """
    return _get_dict_setting(guild_id, "earthquake")


def set_earthquake_channel(guild_id: int, channel_id: int | None) -> None:
    """地震速報の送信先チャンネルを設定/解除する。"""
    _update_nested(guild_id, "earthquake", {"channel_id": channel_id})


def set_earthquake_min_scale(guild_id: int, scale: int) -> None:
    """この震度未満の地震情報は通知しない、というしきい値を保存する。
    値の妥当性チェックはここでは行わない（呼び出し元のコマンドが
    受け付ける範囲を制限している）。
    """
    _update_nested(guild_id, "earthquake", {"min_scale": scale})


# ──────────────────────────────────────────────
# 地震通知タイプ
# ──────────────────────────────────────────────


# frozenset ではなく tuple にする。frozenset は文字列ハッシュのランダム化
# （PYTHONHASHSEED、既定で毎プロセス起動ごとに変わる）のせいで反復順序が
# 実行のたびに変わり、下の get_earthquake_notify_types() が返す dict の
# キー順序（＝ JSON 配列にしたときの並び）もそのたびに変わってしまう。
# 管理画面側はチェックボックスを常に固定順で読むため、中身が同じでも
# 並びが違うだけで「変更あり」と誤検知し続け、保存しても保存しても
# 未保存のまま、という不具合になっていた。
_NOTIFY_TYPE_KEYS: tuple[str, ...] = (
    "eew_forecast",
    "eew_warning",
    "tsunami",
    "quake_info",
    "bot_news",
)


def get_earthquake_notify_types(guild_id: int) -> dict[str, bool]:
    """通知タイプ設定を取得。未設定キーはデフォルト True（有効）。"""
    stored = _get_dict_setting(guild_id, "earthquake").get("notify_types", {})
    return {k: bool(stored.get(k, True)) for k in _NOTIFY_TYPE_KEYS}


def set_earthquake_notify_types(guild_id: int, types: dict[str, bool]) -> None:
    """通知タイプ設定を保存。有効なキーのみ受け付ける。"""
    patch = {k: bool(v) for k, v in types.items() if k in _NOTIFY_TYPE_KEYS}
    _update_nested(guild_id, "earthquake", {"notify_types": patch})


# ──────────────────────────────────────────────
# DJAudio-DL 監視チャンネル
# ──────────────────────────────────────────────


@dataclass(frozen=True)
class DJAudioRuntimeSettings:
    watch_channel_id: int
    cache_ttl: int
    cooldown: int
    max_urls: int
    output_channel_id: int | None = None


def _read_int(value: Any) -> int | None:
    """int変換に失敗したら None を返す。

    0 のような有効な値と、未設定・壊れた値を区別するために使う。
    単純に int(value) or None とすると 0 まで None 扱いになってしまう。
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _get_djaudio_top_level(guild_settings: dict[str, Any], key: str) -> Any:
    """旧形式のフラットなキーを、プレフィックスの有無が分からないまま拾う
    ためのフォールバック。

    "cache_ttl" 単体でも "djaudio_cache_ttl" でも過去に保存され得たため、
    両方を順に見て最初に見つかった方を返す。
    """
    if key in guild_settings:
        return guild_settings.get(key)
    return guild_settings.get(f"djaudio_{key}")


def get_djaudio_watch_channel(guild_id: int) -> int:
    """URL監視チャンネルIDを取得（未設定なら0）。"""
    guild_settings = get_guild_settings(guild_id)
    nested = guild_settings.get("djaudio", {})
    if not isinstance(nested, dict):
        nested = {}

    candidates = (
        guild_settings.get("djaudio_watch_channel_id"),
        guild_settings.get("djaudio_watch_channel"),
        nested.get("watch_channel_id"),
        nested.get("channel_id"),
    )
    for value in candidates:
        parsed = _read_int(value)
        if parsed and parsed > 0:
            return parsed
    return 0


def set_djaudio_watch_channel(guild_id: int, channel_id: int | None) -> None:
    """URL監視チャンネルIDを設定/解除。"""

    def _mutator(data: dict[str, Any]) -> None:
        """新旧両方の保存場所（nested の djaudio.watch_channel_id と、フラットな
        djaudio_watch_channel_id / djaudio_watch_channel）に同じ値を書く。
        読み出し側がどちらの形式を見ても最新値を拾えるようにするための
        二重書き。
        """
        current = _get_or_create_guild(data, guild_id)
        nested = current.get("djaudio", {})
        if not isinstance(nested, dict):
            nested = {}
        nested["watch_channel_id"] = channel_id
        current["djaudio_watch_channel_id"] = channel_id
        current["djaudio_watch_channel"] = channel_id  # legacy 互換
        current["djaudio"] = nested

    _mutate_settings(_mutator)


def get_djaudio_settings(guild_id: int) -> dict[str, Any]:
    """DJAudio の詳細設定を取得。"""
    guild_settings = get_guild_settings(guild_id)
    nested = guild_settings.get("djaudio", {})
    if not isinstance(nested, dict):
        nested = {}

    result = dict(nested)
    if "cache_ttl" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "cache_ttl")
        if legacy is not None:
            result["cache_ttl"] = legacy
    if "cooldown" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "cooldown")
        if legacy is not None:
            result["cooldown"] = legacy
    if "max_urls" not in result:
        legacy = _get_djaudio_top_level(guild_settings, "max_urls")
        if legacy is not None:
            result["max_urls"] = legacy
    return result


# DJAudio の数値設定の許容範囲。(最小, 最大) を項目名で引く。
#
# 画面側（webapp_admin/schema/panels/djaudio.py）は、この表を読んで
# Field の min / max を作る。以前は同じ数値を両方に手で書いていて、
# 「画面側のスキーマと必ず揃えること」という注意書きだけが頼りだった。
# 片方だけ変えると、画面の検証は通るのに保存される値は黙って丸められる。
# 表を1つにして、ずれようがない形にする。
DJAUDIO_LIMITS: dict[str, tuple[int, int]] = {
    "cache_ttl": (60, 30 * 24 * 3600),  # 1分 〜 30日
    "cooldown": (0, 3600),
    "max_urls": (1, 10),
}


def set_djaudio_settings(guild_id: int, patch: dict[str, Any]) -> None:
    """DJAudio の詳細設定を更新。"""
    normalized: dict[str, int] = {}
    for key, (low, high) in DJAUDIO_LIMITS.items():
        if key not in patch:
            continue
        value = _read_int(patch.get(key))
        if value is not None:
            normalized[key] = max(low, min(high, value))

    if not normalized:
        return

    def _mutator(data: dict[str, Any]) -> None:
        """nested の djaudio dict を更新しつつ、フラットな legacy キー
        （djaudio_cache_ttl 等）にも同じ値を複製する。新形式にしか書かないと、
        まだ移行していない読み出し経路が古い値を返し続ける。
        """
        current = _get_or_create_guild(data, guild_id)
        nested = current.get("djaudio", {})
        if not isinstance(nested, dict):
            nested = {}
        nested.update(normalized)
        current["djaudio"] = nested
        current["djaudio_cache_ttl"] = nested.get("cache_ttl")  # legacy 互換
        current["djaudio_cooldown"] = nested.get("cooldown")
        current["djaudio_max_urls"] = nested.get("max_urls")

    _mutate_settings(_mutator)


_DJAUDIO_DEFAULTS: dict[str, int] = {
    "cache_ttl": 600,
    "cooldown": 30,
    "max_urls": 3,
}


def get_djaudio_cache_ttl(guild_id: int) -> int:
    """キャッシュ有効期間（秒）を取得。未設定なら環境変数 or デフォルト 600。"""
    stored = get_djaudio_settings(guild_id).get("cache_ttl")
    try:
        return max(60, int(cast(Any, stored)))
    except (TypeError, ValueError):
        from config import DJAUDIO_CACHE_TTL

        return DJAUDIO_CACHE_TTL


def get_djaudio_cooldown(guild_id: int) -> int:
    """ユーザークールダウン（秒）を取得。未設定なら環境変数 or デフォルト 30。"""
    stored = get_djaudio_settings(guild_id).get("cooldown")
    try:
        return max(0, int(cast(Any, stored)))
    except (TypeError, ValueError):
        from config import DJAUDIO_COOLDOWN

        return DJAUDIO_COOLDOWN


def get_djaudio_max_urls(guild_id: int) -> int:
    """1メッセージあたりのURL上限を取得。未設定なら環境変数 or デフォルト 3。"""
    stored = get_djaudio_settings(guild_id).get("max_urls")
    try:
        return max(1, min(10, int(cast(Any, stored))))
    except (TypeError, ValueError):
        from config import DJAUDIO_MAX_URLS

        return DJAUDIO_MAX_URLS


def get_djaudio_output_channel(guild_id: int) -> int | None:
    """結果送信チャンネルIDを取得（未設定なら None）。"""
    guild_settings = get_guild_settings(guild_id)
    nested = guild_settings.get("djaudio", {})
    if not isinstance(nested, dict):
        nested = {}
    value = nested.get("output_channel_id")
    parsed = _read_int(value)
    return parsed if parsed and parsed > 0 else None


def set_djaudio_output_channel(guild_id: int, channel_id: int | None) -> None:
    """結果送信チャンネルIDを設定/解除。"""

    def _mutator(data: dict[str, Any]) -> None:
        """output_channel_id は nested の djaudio dict にだけ保存する。他の
        djaudio 系設定と違って legacy のフラットキーが存在しない項目なので、
        二重書きは不要。
        """
        current = _get_or_create_guild(data, guild_id)
        nested = current.get("djaudio", {})
        if not isinstance(nested, dict):
            nested = {}
        nested["output_channel_id"] = channel_id
        current["djaudio"] = nested

    _mutate_settings(_mutator)


def get_djaudio_runtime_settings(guild_id: int) -> DJAudioRuntimeSettings:
    """DJAudio 実行時に使う設定をまとめて返す。"""
    return DJAudioRuntimeSettings(
        watch_channel_id=get_djaudio_watch_channel(guild_id),
        cache_ttl=get_djaudio_cache_ttl(guild_id),
        cooldown=get_djaudio_cooldown(guild_id),
        max_urls=get_djaudio_max_urls(guild_id),
        output_channel_id=get_djaudio_output_channel(guild_id),
    )


# ──────────────────────────────────────────────
# VC録音
# ──────────────────────────────────────────────

_RECORDING_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    # 誰かが VC に入ったら自動で録り始めるか。既定は False。
    # 勝手に録られていた、という状態を既定にしない（開始時の告知は別途必ず出る）。
    "auto_start": False,
    # 自動録音の対象VC。未設定なら TTS の対象VCに従う（同じ接続を共有するため）。
    "vc_channel_id": None,
    "max_minutes": 360,  # 6時間で自動停止。0 なら時間では止めない
    "retention_days": 7,  # ダウンロードリンクの有効期間
    "announce_channel_id": None,  # 開始・完了の通知先（未設定ならVCのチャット欄）
    "excluded_user_ids": [],  # 録音しないユーザー（本人希望の除外）
}


def get_recording_settings(guild_id: int) -> dict[str, Any]:
    """録音設定を既定値とマージして返す。

    保存されているのは既定値からの差分だけのことが多いため、
    _RECORDING_DEFAULTS で埋めてから上書きする。excluded_user_ids は
    保存形式が壊れていても _parse_id_list で必ず int のリストに矯正する。
    """
    stored = _get_dict_setting(guild_id, "recording")
    if not isinstance(stored, dict):
        stored = {}
    settings = dict(_RECORDING_DEFAULTS)
    settings.update(stored)
    settings["excluded_user_ids"] = _parse_id_list(settings.get("excluded_user_ids"))
    return settings


def set_recording_settings(guild_id: int, patch: dict[str, Any]) -> None:
    """_RECORDING_DEFAULTS に存在しないキーは黙って無視する。フロントエンドが
    知らない追加キーを送ってきても、設定ファイルに余計なフィールドが
    紛れ込まないようにする許可リスト方式。
    """
    allowed = {k: v for k, v in patch.items() if k in _RECORDING_DEFAULTS}
    _update_nested(guild_id, "recording", allowed)


def set_recording_excluded_users(guild_id: int, user_ids: list[int]) -> None:
    """録音対象から除外するユーザーの一覧を丸ごと置き換える（追加ではない）。"""
    _update_nested(guild_id, "recording", {"excluded_user_ids": [int(u) for u in user_ids]})
