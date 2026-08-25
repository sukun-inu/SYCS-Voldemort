"""Discord の音声E2EE（DAVE）の受信側。

Discord は 2024年9月から音声・映像を端から端まで暗号化している（DAVE）。
2026年3月2日からはボットにも必須になり、未対応だと音声接続そのものが
クローズコード 4017 で拒否される。

鍵交換（MLS）は discord.py 2.7.1 が実装済みで、`davey` が入っていれば
自動で成立する。ただし discord.py が使うのは送信側（encrypt_opus）だけで、
受信側の復号はどこにも無い。discord-ext-voice-recv にも無い。

その状態で暗号文を Opus に渡すと、多くは例外にならずに雑音が返る。
「録れているのに聞けない」という一番たちの悪い壊れ方になるので、
ここで復号してから渡す。

フレームの見分け方（https://github.com/discord/dave-protocol）:

    [暗号文][認証タグ 8][nonce ULEB128][平文範囲 ULEB128][補助データ長 1][0xFAFA 2]

実際に本番で観測したフレーム:

    ... c8db 04 0c fafa      長さ 0x0c=12 = タグ8 + nonce1 + 長さ1 + マーカー2
    ... 01 0d fafa 02 02     末尾は RTP パディング（voice_recv は剥がさない）
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:  # 入っていない環境でも、録音以外は動かせるようにする
    import davey  # type: ignore

    AVAILABLE = True
    MAX_PROTOCOL_VERSION: int = davey.DAVE_PROTOCOL_VERSION
except ImportError:  # pragma: no cover - 導入済みの環境では通らない
    davey = None  # type: ignore
    AVAILABLE = False
    MAX_PROTOCOL_VERSION = 0

DAVE_MAGIC = b"\xfa\xfa"
# 認証タグ8 + nonce1 + 補助データ長1 + マーカー2。これを下回る長さはあり得ない。
MIN_SUPPLEMENTAL = 12
# RTP パディングが剥がされずに残っていることがあるので、少しだけ後ろも見る。
_MAX_PADDING = 8


def _supplemental_ok(payload: bytes, end: int) -> bool:
    """end の直前2バイトがマーカーだとして、補助データ長が筋の通る値か。

    偶然 0xFAFA が並んだ平文フレームを暗号化扱いしないための確認。
    """
    if end < 3:
        return False
    size = payload[end - 3]
    return MIN_SUPPLEMENTAL <= size < end


def is_dave_frame(payload: bytes | None) -> bool:
    """端から端まで暗号化されたフレームか。"""
    if not payload or len(payload) < MIN_SUPPLEMENTAL + 1:
        return False
    for back in range(_MAX_PADDING + 1):
        end = len(payload) - back
        if end < 2:
            break
        if payload[end - 2:end] == DAVE_MAGIC and _supplemental_ok(payload, end):
            return True
    return False


def session_of(voice_client: Any) -> Any | None:
    """使える DAVE セッションを取り出す。無ければ None。

    鍵交換が済んでいない（ready でない）あいだに復号を試すと例外になるので、
    そこも含めてここで判定する。
    """
    state = getattr(voice_client, "_connection", None)
    session = getattr(state, "dave_session", None)
    if session is None or not getattr(session, "ready", False):
        return None
    return session


def decrypt_opus(voice_client: Any, user_id: int, payload: bytes) -> bytes | None:
    """暗号化された Opus フレームを平文に戻す。

    戻り値が None なら復号できなかった、という意味。呼び出し側は、それを
    音として書かずに数えること（暗号文をデコードすると雑音になる）。
    """
    if not AVAILABLE:
        return None
    session = session_of(voice_client)
    if session is None:
        return None
    try:
        return bytes(session.decrypt(user_id, davey.MediaType.audio, payload))
    except Exception as e:
        logger.debug("[dave] 復号に失敗 user=%s: %s", user_id, e)
        return None


def unavailable_reason() -> str:
    """復号できない理由を、そのまま利用者に見せられる形で返す。"""
    if not AVAILABLE:
        return (
            "この通話は端から端まで暗号化（E2EE / DAVE）されていますが、"
            "復号に必要な davey が入っていないため録音できません"
        )
    return (
        "この通話は端から端まで暗号化（E2EE / DAVE）されており、"
        "鍵の共有ができていないため録音できません"
    )
