"""プロセスをまたいで共有するキャッシュ（Valkey / Redis 互換）。

■ なぜ要るか

キャッシュがプロセス内にしかなかった。web トラッカーは WEB_WORKERS=2 が既定で、
ワーカーごとに別の TTLCache を持つため、同じ問い合わせに対して**同じ DB クエリと
同じ予測計算が2回走る。** 期限が切れるたびに2回、切れる時刻もずれる。管理画面の
レート制限も同じ理由でワーカーごとに独立していて、2ワーカーなら実質2倍通っていた
（docker-compose.yml の ADMIN_WORKERS のコメントに、その旨だけは書かれていた）。

■ なぜ「落ちても動く」ことを最優先にしたか

キャッシュは無くても正しく動くための部品で、あるのは速いからにすぎない。ところが
素直に書くと、Valkey が落ちた瞬間に価格 API が 500 を返すようになる。**キャッシュの
故障が、キャッシュが無ければ起きなかった障害を作る**形は避けなければならない。

そのため、この層は次の3つを守る。

  1. 例外を外へ出さない。get は None を、set は黙って何もしないで返る。
     呼び出し側から見ると「キャッシュミスが増えた」ようにしか見えない。
  2. 待たない。socket_timeout を短く切る。Valkey が固まったときに、
     繋がらないより悪いのは「繋がったまま応答しない」ことで、素の設定だと
     リクエストがそこで止まる。
  3. 死んでいる相手に毎回試さない。一度失敗したら決めた時間だけ諦める
     （下の遮断器）。試し続けると、1リクエストごとに接続のタイムアウトぶん
     待たされて、キャッシュが無い場合よりむしろ遅くなる。

■ 呼び出し側の作り

呼び出し側（webapp/cache.py）はプロセス内のキャッシュを一次として残したまま、
こちらを二次として使う。一次を捨てないのは、上の 1. で「無いのと同じ」に落ちた
ときに、少なくとも今までと同じ速さで動き続けるため。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Awaitable, Callable, Optional

from envutil import env_float, env_str

logger = logging.getLogger(__name__)

# 鍵の頭に必ず付ける。同じ Valkey を別の用途と相乗りさせたときに、
# clear_namespace の走査が他人の鍵を巻き込まないようにするため。
KEY_PREFIX = "sycs"

# 既定のタイムアウト。ローカルネットワーク上の Valkey を前提にしている。
# 長くする意味は無い。「応答しない Valkey を待つ」のは、キャッシュが無いより
# 常に悪い（詳細はモジュール冒頭の 2.）。
_DEFAULT_TIMEOUT_SECONDS = 0.5

# 遮断器を開いたままにする時間。短すぎると死んでいる相手に何度も当たり、
# 長すぎると復旧に気づくのが遅れる。
_DEFAULT_BREAKER_COOLDOWN_SECONDS = 30.0


class SharedCache:
    """Valkey を使う共有キャッシュ。繋がらないときは「何も無い」ように振る舞う。

    このクラス自身は接続を張らない。最初に使われたときに初めて張る
    （import しただけでネットワークへ出ないこと。テストが実 Valkey を
    要求するようになると、CONTRIBUTING 5. の「出てはいけない先」に触れる）。
    """

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        breaker_cooldown_seconds: float = _DEFAULT_BREAKER_COOLDOWN_SECONDS,
        client_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        """url が空文字なら、この入れ物は最初から無効（何もしない）になる。

        client_factory はテストのための差し替え口。省略すると redis.asyncio を
        使う。ここを引数にしておかないと、テストが実際の Valkey か、
        redis モジュールへの patch を必要とする。
        """
        self._url = url.strip()
        self._timeout = max(0.05, float(timeout_seconds))
        self._cooldown = max(1.0, float(breaker_cooldown_seconds))
        self._client_factory = client_factory
        self._client: Any = None
        # 遮断器がこの時刻まで開いている（monotonic 秒）。0 は閉じている。
        self._blocked_until = 0.0

    @property
    def configured(self) -> bool:
        """接続先が設定されているか。無効なら呼び出し側は一次キャッシュだけで動く。"""
        return bool(self._url)

    @property
    def available(self) -> bool:
        """今この瞬間に使ってよいか（設定済みで、かつ遮断器が閉じている）。"""
        return self.configured and time.monotonic() >= self._blocked_until

    async def get_json(self, namespace: str, key: str) -> Any | None:
        """値を取り出す。無い・壊れている・繋がらないのいずれも None を返す。

        3つを呼び出し側から区別できるようにしていない。区別できたとしても
        できることは同じ（作り直す）で、分岐を増やすと「繋がらないときだけ
        通る道」が生まれてテストされないまま残る。
        """
        if not self.available:
            return None
        raw = await self._run(lambda c: c.get(self._compose_key(namespace, key)))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # 別の版の自分が書いた、あるいは他人が同じ鍵を使った。作り直せるので
            # 捨ててよい。ここで例外を出すと、キャッシュの中身1つで API が落ちる。
            logger.warning("共有キャッシュの値を復号できませんでした（捨てます）: %s/%s", namespace, key)
            return None

    async def set_json(self, namespace: str, key: str, value: Any, ttl_seconds: int) -> None:
        """値を書き込む。JSON にできない値と、繋がらない場合は黙って諦める。

        戻り値で成否を返していない。呼び出し側は一次キャッシュへ既に書いた
        あとでここへ来るので、失敗しても続ける以外の選択肢が無い。
        """
        if not self.available:
            return
        try:
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            # 呼び出し側の値が JSON にできない。これは設定ミスに近いので警告を
            # 出すが、リクエストは通す（一次キャッシュには入っている）。
            logger.warning("共有キャッシュに入れられない値でした（一次のみ）: %s/%s", namespace, key)
            return
        ttl = max(1, int(ttl_seconds))
        await self._run(lambda c: c.set(self._compose_key(namespace, key), raw, ex=ttl))

    async def get_value(self, namespace: str, key: str) -> str | None:
        """文字列を1つ取り出す。JSON を通さない値（メトリクスの数値など）用。"""
        if not self.available:
            return None
        raw = await self._run(lambda c: c.get(self._compose_key(namespace, key)))
        return None if raw is None else str(raw)

    async def set_value(self, namespace: str, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """文字列を1つ書き込む。ttl_seconds が None なら期限を付けない。

        期限を付けない選択肢を残しているのは、メトリクスの計数（カウンタ）が
        単調増加でなければならないため。途中で消えると、読む側は「減った」と
        解釈して差分がおかしくなる。
        """
        if not self.available:
            return
        composed = self._compose_key(namespace, key)
        if ttl_seconds is None:
            await self._run(lambda c: c.set(composed, value))
            return
        ttl = max(1, int(ttl_seconds))
        await self._run(lambda c: c.set(composed, value, ex=ttl))

    async def incr(self, namespace: str, key: str, amount: int = 1, ttl_seconds: int | None = None) -> int | None:
        """1つの値を原子的に増やして、増やした後の値を返す（失敗なら None）。

        **読んで足して書き戻す形にしてはいけない。** 複数のプロセスとワーカーが
        同時に呼ぶので、その形だと数え落ちる。ここが数え落ちると、レート制限では
        「上限より多く通る」、メトリクスでは「実際より少なく見える」ことになる。

        ttl_seconds を渡すと、鍵が新しく作られたときだけ期限を付ける
        （既にある鍵の期限を延ばさない。延ばすと、窓が永久にずれ続ける）。
        """
        if not self.available:
            return None
        composed = self._compose_key(namespace, key)

        async def _incr(client: Any) -> int:
            """INCRBY で増やし、この呼び出しで鍵が作られたときだけ期限を付ける。"""
            value = int(await client.incrby(composed, amount))
            # 戻り値が amount と等しい＝この呼び出しで作られた鍵。ここでだけ
            # 期限を付ける。毎回付けると窓の終わりが後ろへずれ続ける。
            if ttl_seconds is not None and value == amount:
                await client.expire(composed, max(1, int(ttl_seconds)))
            return value

        result = await self._run(_incr)
        return None if result is None else int(result)

    async def scan_values(self, namespace: str) -> dict[str, str]:
        """名前空間の中身を「鍵（接頭辞を外したもの）→ 値」で全部返す。

        メトリクスを組み立てるときに使う。繋がらなければ空の辞書を返すので、
        呼び出し側は「何も報告されていない」ものとして扱えばよい。

        KEYS ではなく SCAN で回す（clear_namespace と同じ理由）。
        """
        if not self.available:
            return {}
        prefix = self._compose_key(namespace, "")
        pattern = f"{prefix}*"
        found: dict[str, str] = {}

        async def _scan_get(client: Any) -> None:
            """cursor が 0 に戻るまで回し、1ページぶんを MGET でまとめて取る。

            1件ずつ GET しない。鍵の数だけ往復すると、メトリクスが増えるほど
            スクレイプ1回の時間が伸びる。
            """
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor=cursor, match=pattern, count=256)
                if keys:
                    values = await client.mget(keys)
                    for key, value in zip(keys, values):
                        if value is not None:
                            found[str(key)[len(prefix) :]] = str(value)
                if cursor == 0:
                    return

        await self._run(_scan_get)
        return found

    async def clear_namespace(self, namespace: str) -> None:
        """その名前空間の鍵を全部消す。

        KEYS ではなく SCAN を使う。KEYS は一致するまで Valkey を止めるので、
        鍵が増えたときに全プロセスがそのぶん待たされる。
        """
        if not self.available:
            return
        pattern = self._compose_key(namespace, "*")

        async def _scan_delete(client: Any) -> None:
            """cursor が 0 に戻るまで回して、見つかった鍵をまとめて消す。

            1ページ目で止めてはいけない。SCAN は「1回で全部返す」ことを保証
            しないので、途中で抜けると消し残りが出る。消し残った古い価格は、
            次に期限が切れるまで他のワーカーから見え続ける。
            """
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor=cursor, match=pattern, count=256)
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    return

        await self._run(_scan_delete)

    async def close(self) -> None:
        """接続を閉じる。閉じ損なっても次の起動で困らないが、テストが
        「開いたまま終わった」警告で汚れるので明示的に閉じられるようにしておく。
        """
        client, self._client = self._client, None
        if client is None:
            return
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 - 閉じる失敗で呼び出し側を落としたくない
            logger.debug("共有キャッシュの接続を閉じるときに失敗しました", exc_info=True)

    def _compose_key(self, namespace: str, key: str) -> str:
        """実際に Valkey へ渡す鍵。KEY_PREFIX を必ず挟む（相乗り対策）。"""
        return f"{KEY_PREFIX}:{namespace}:{key}"

    async def _client_or_none(self) -> Any | None:
        """接続を作る（作れなければ None）。作った接続は使い回す。"""
        if self._client is not None:
            return self._client
        try:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                # import をここまで遅らせている。モジュールの import 時点で
                # redis を要求すると、redis が入っていない環境（テストだけを
                # 回したいとき）で services 全体が import できなくなる。
                import redis.asyncio as redis_asyncio

                self._client = redis_asyncio.from_url(
                    self._url,
                    socket_timeout=self._timeout,
                    socket_connect_timeout=self._timeout,
                    decode_responses=True,
                )
            return self._client
        except Exception as exc:  # noqa: BLE001 - 接続の作成失敗も遮断器に載せる
            self._trip(exc, "接続を作れませんでした")
            return None

    async def _run(self, operation: Callable[[Any], Awaitable[Any]]) -> Any | None:
        """Valkey への1操作を、例外を外へ出さずに実行する。

        **Valkey へ触る処理は必ずここを通すこと。** 直に await すると、その1箇所
        だけが例外を外へ出す道になる。キャッシュの故障が API を落とす形は、
        まさにそうやって生まれる（モジュール冒頭の 1.）。
        """
        client = await self._client_or_none()
        if client is None:
            return None
        try:
            return await operation(client)
        except Exception as exc:  # noqa: BLE001 - モジュール冒頭の 1.
            # 接続そのものを捨てる。壊れた接続を使い回すと、復旧後も失敗し続ける。
            self._client = None
            self._trip(exc, "操作に失敗しました")
            return None

    def _trip(self, exc: BaseException, what: str) -> None:
        """遮断器を開く。開くときだけログを出す。

        毎回出すと、Valkey が落ちている間ログが同じ行で埋まり、本当の原因が
        埋もれる。ここを「1リクエスト1行」にした結果ログが読めなくなった例が
        別の箇所であったので、最初からこうしておく。
        """
        already_open = time.monotonic() < self._blocked_until
        self._blocked_until = time.monotonic() + self._cooldown
        if already_open:
            return
        logger.warning(
            "共有キャッシュを %.0f 秒間使いません（%s: %s）。一次キャッシュだけで動作を続けます。",
            self._cooldown,
            what,
            exc,
        )


_INSTANCE: SharedCache | None = None


def shared_cache() -> SharedCache:
    """環境変数から作った共有キャッシュを返す（1プロセスに1つ）。

    VALKEY_URL が未設定なら、何もしない入れ物が返る。呼び出し側に
    「設定されているか」の分岐を書かせないため、None は返さない。
    """
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = SharedCache(
            # env_str は未設定のとき None を返しうる。空文字へ倒しておかないと
            # SharedCache の url が Optional になり、configured の判定が濁る。
            env_str("VALKEY_URL", "") or "",
            timeout_seconds=env_float("VALKEY_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS, minimum=0.05),
            breaker_cooldown_seconds=env_float(
                "VALKEY_BREAKER_COOLDOWN_SECONDS",
                _DEFAULT_BREAKER_COOLDOWN_SECONDS,
                minimum=1.0,
            ),
        )
    return _INSTANCE


def set_shared_cache(instance: SharedCache | None) -> None:
    """共有キャッシュを差し替える（テスト用）。

    None を渡すと、次の shared_cache() が環境変数から作り直す。テストが
    互いの状態を引き継がないよう、tearDown でこれを呼んで戻すこと。
    """
    global _INSTANCE
    _INSTANCE = instance
