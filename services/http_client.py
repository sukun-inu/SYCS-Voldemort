"""使い回す aiohttp のセッション。

■ なぜ要るか

呼び出しのたびに `aiohttp.ClientSession()` を作ると、毎回 DNS 解決・TCP 接続・
TLS ハンドシェイクからやり直す。手元で測ると、同じ相手への1リクエストが
こうなった（2026-09-03）。

    相手              毎回作り直す   使い回す
    127.0.0.1（平文）      3.5ms       1.8ms
    HTTPS の外部           49.3ms      13.5ms

**1回あたり 36ms。** 読み上げ1発話ごと、ログ埋め込み1件ごと、リンク1本ごとに
これが乗っていた。

■ 使い方

    session = get_session()
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
        ...

**`async with get_session()` としないこと。** 抜けるときに閉じてしまい、
次の呼び出しが「Session is closed」で落ちる。制限時間とヘッダは
リクエストごとに渡す（セッションに焼き付けると使い回せない）。

■ 何を使い回さないか

長生きする接続（地震の WebSocket）は、こちらを使わずに専用のセッションを
持つ。1本のコネクションを何時間も掴む用途で、接続の作り直しが問題に
ならないうえ、閉じる契機も違う。

数分〜数時間に1回しか呼ばないもの（ニュース、貴金属、予測、地図タイル）も
そのままにしてある。36ms を惜しむ理由が無く、置き換えるぶんだけ壊す余地が
増えるため。**「よく呼ぶものだけを置き換える」**という線引きにしている。
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)

_session: aiohttp.ClientSession | None = None
_loop: asyncio.AbstractEventLoop | None = None


def get_session() -> aiohttp.ClientSession:
    """使い回すセッションを返す。無ければ、いま動いているループの上で作る。

    ループが変わったとき（テストごとに asyncio.run する場合や、再起動）に
    作り直すのは、**セッションが作られたときのループに縛られている**ため。
    別のループから使うと "attached to a different loop" で落ちる。

    古いセッションはここでは閉じない。閉じるには元のループが要るが、
    そのループは既に終わっている。参照を捨てて GC に任せる。
    """
    global _session, _loop
    loop = asyncio.get_running_loop()
    if _session is None or _session.closed or _loop is not loop:
        _session = aiohttp.ClientSession()
        _loop = loop
    return _session


async def close_session() -> None:
    """終了時に閉じる。閉じ忘れると "Unclosed client session" が出る。

    閉じられなくても停止処理そのものは続ける（後始末の失敗で、録音の
    書き出しなど本筋の後始末を止めない）。
    """
    global _session, _loop
    session, _session, _loop = _session, None, None
    if session is None or session.closed:
        return
    try:
        await session.close()
    except Exception as e:
        logger.warning("[http] セッションを閉じられませんでした: %s", e)
