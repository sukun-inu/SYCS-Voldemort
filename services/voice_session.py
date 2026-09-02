"""VC接続を TTS と録音で共有するための層。

Discord の bot は1ギルドにつき音声接続を1本しか持てない。読み上げ（送信）と
録音（受信）を同時に使うには、同じ VoiceClient を共有するしかない。そのため
接続の所有をこのモジュールに集約し、TTS も録音もここ経由で取りにくる。

もう一つの役割が「占有（hold）」。TTS には「VCが空になったら切る」「アイドルで
切る」という動きがあり、そのまま働くと録音中に接続ごと落ちる。録音は開始時に
hold を立て、誰かが掴んでいるあいだ release() は実際の切断をしない。

音声の受信は discord.py 本体には無い（play はあるが受信APIが存在しない）。
discord-ext-voice-recv が VoiceClient のサブクラスとして両方を持つので、
入っていればそれを使い、入っていなければ通常の VoiceClient にフォールバック
する（その場合 TTS は従来どおり動き、録音だけが使えない）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import cast

import discord

logger = logging.getLogger(__name__)

try:
    from discord.ext import voice_recv as _voice_recv

    RECEIVE_AVAILABLE = True
    _RECEIVE_UNAVAILABLE_REASON = ""
except Exception as exc:  # pragma: no cover - 環境依存
    # 読み込めなかった目印。使う側は RECEIVE_AVAILABLE を見るので、
    # ここが None であること自体は参照されない。
    _voice_recv = None  # type: ignore[assignment]
    RECEIVE_AVAILABLE = False
    _RECEIVE_UNAVAILABLE_REASON = f"{type(exc).__name__}: {exc}"
    logger.info(
        "[voice] 音声受信の拡張が使えません（録音機能は無効・読み上げは通常どおり）: %s",
        _RECEIVE_UNAVAILABLE_REASON,
    )

# guild_id -> VoiceClient
_clients: dict[int, discord.VoiceClient] = {}
# guild_id -> 占有している名前の集合（"recording" など）
_holds: dict[int, set[str]] = {}
_locks: dict[int, asyncio.Lock] = {}


def receive_unavailable_reason() -> str:
    """discord-ext-voice-recv が読み込めなかった理由。RECEIVE_AVAILABLE が
    True の間は空文字（読み込みに成功しているため）。録音機能が無効な
    ときに、なぜ無効かをログや管理画面で示すためのもの。
    """
    return _RECEIVE_UNAVAILABLE_REASON


def voice_client_cls() -> type[discord.VoiceClient]:
    """接続に使うクラス。受信拡張があればそちらを使う。"""
    if RECEIVE_AVAILABLE and _voice_recv is not None:
        return _voice_recv.VoiceRecvClient
    return discord.VoiceClient


def can_receive(client: discord.VoiceClient | None) -> bool:
    """その接続が音声を受信できるか（listen を持っているか）。"""
    return client is not None and hasattr(client, "listen")


def get(guild_id: int) -> discord.VoiceClient | None:
    """現在の共有接続を返す。切断済みなら None（_clients に残っていても
    実際には繋がっていないハンドシェイク切れの接続を、生きているものと
    偽って返さないようにする）。
    """
    client = _clients.get(guild_id)
    if client is not None and not client.is_connected():
        return None
    return client


def channel_id(guild_id: int) -> int | None:
    """現在接続中のVCチャンネルID。未接続なら None。"""
    client = get(guild_id)
    return client.channel.id if client and client.channel else None


# ── 占有 ─────────────────────────────────────────────────────


def hold(guild_id: int, holder: str) -> None:
    """接続を掴む。掴んでいるあいだ release() は切断しない。"""
    _holds.setdefault(guild_id, set()).add(holder)


def unhold(guild_id: int, holder: str) -> None:
    """占有を解除する。占有者が他にもいれば release() はまだ切断しない
    （空集合になったときだけ guild_id のエントリごと片付ける）。
    """
    holders = _holds.get(guild_id)
    if not holders:
        return
    holders.discard(holder)
    if not holders:
        _holds.pop(guild_id, None)


def holders(guild_id: int) -> set[str]:
    """現在の占有者名の集合を返す（コピー）。ログ表示用。呼び出し側が
    内部の _holds セットを直接書き換えられないようにコピーを渡す。
    """
    return set(_holds.get(guild_id, ()))


def is_held(guild_id: int) -> bool:
    """誰か一人でも占有していれば True。"""
    return bool(_holds.get(guild_id))


# ── 接続 ─────────────────────────────────────────────────────


async def acquire(
    guild: discord.Guild,
    vc_channel_id: int,
    *,
    purpose: str = "tts",
) -> discord.VoiceClient | None:
    """VCに接続する。既に別チャンネルに繋がっていれば移動する。

    占有中に別チャンネルへ移そうとした場合は移動せず、今の接続をそのまま返す
    （録音中に読み上げの都合で別VCへ連れ出されると、録音が途切れるため）。
    """
    lock = _locks.setdefault(guild.id, asyncio.Lock())
    async with lock:
        existing = _clients.get(guild.id)

        if existing is not None and existing.is_connected():
            if existing.channel and existing.channel.id == vc_channel_id:
                return existing
            if is_held(guild.id):
                logger.info(
                    "[voice] guild=%s は %s が使用中のため移動しません（要求元: %s）",
                    guild.id,
                    "・".join(sorted(holders(guild.id))),
                    purpose,
                )
                return existing
            channel = guild.get_channel(vc_channel_id)
            if isinstance(channel, discord.VoiceChannel):
                try:
                    await existing.move_to(channel)
                    return existing
                except Exception as e:
                    logger.warning("[voice] move_to 失敗 guild=%s: %s", guild.id, e)
            await _force_disconnect(guild.id, existing)

        elif existing is not None:
            # ハンドシェイク切断などで失われた古い接続を捨ててから繋ぎ直す
            logger.info("[voice] 切れている接続を破棄して再接続します guild=%s", guild.id)
            await _force_disconnect(guild.id, existing)

        channel = guild.get_channel(vc_channel_id)
        if not isinstance(channel, discord.VoiceChannel):
            logger.warning("[voice] vc_channel_id=%s が見つからないか VC ではありません", vc_channel_id)
            return None

        # discord.py 側に既に接続済みの client があれば拾い直す
        # 型の上では VoiceProtocol だが、接続は voice_client_cls()
        # （VoiceClient の派生）でしか行わないので実体は必ず VoiceClient。
        current = cast("discord.VoiceClient | None", guild.voice_client)
        if current is not None and current.is_connected():
            if current.channel and current.channel.id == vc_channel_id:
                _clients[guild.id] = current
                return current
            if is_held(guild.id):
                _clients[guild.id] = current
                return current
            await _force_disconnect(guild.id, current)

        try:
            client = await channel.connect(cls=voice_client_cls())
        except discord.ClientException as e:
            if "Already connected" in str(e):
                current = cast("discord.VoiceClient | None", guild.voice_client)
                if current is not None and current.is_connected():
                    _clients[guild.id] = current
                    return current
            logger.exception("[voice] 接続エラー guild=%s: %s", guild.id, e)
            return None
        except Exception as e:
            logger.exception("[voice] 接続エラー guild=%s: %s", guild.id, e)
            return None

        _clients[guild.id] = client
        return client


async def _force_disconnect(guild_id: int, client: discord.VoiceClient) -> None:
    """古い/移動できない接続を切ってから _clients から取り除く。切断が
    discord.py 側で失敗しても _clients からは必ず外す（呼び出し元は
    このあと新しい接続を張りに行くため、管理表だけは新しい接続に
    差し替えられるようにしておく必要がある）。
    """
    try:
        await client.disconnect(force=True)
    except Exception as e:
        # 失敗しても呼び出し元は新しい接続を張りに行くので処理は止めないが、
        # 古い接続が discord.py 側には生きたまま残っている可能性があるので
        # 理由は残す（黙って握りつぶすと、居座りに気づく手がかりが無くなる）。
        logger.warning("[voice] guild=%s 古い接続の強制切断に失敗しました: %s", guild_id, e)
    if _clients.get(guild_id) is client:
        _clients.pop(guild_id, None)


async def release(guild_id: int, *, force: bool = False) -> bool:
    """接続を切る。占有されていれば切らない。

    戻り値は実際に切断したかどうか。force=True は占有を無視する
    （録音を止めてから明示的に切る場合など）。
    """
    if not force and is_held(guild_id):
        logger.debug(
            "[voice] guild=%s は %s が使用中のため切断を見送りました",
            guild_id,
            "・".join(sorted(holders(guild_id))),
        )
        return False

    # _locks はここでは消さない。acquire() は "async with lock" の間だけ
    # _locks[guild_id] を見ており、ここで pop すると、その最中に別の
    # acquire() 呼び出しが setdefault() で新しい（ロックされていない）Lock を
    # 作ってしまい、進行中の acquire() と排他が効かないまま両方が同時に
    # channel.connect() へ進んでしまう。ギルド数は有限なので Lock を
    # 残しておいても増え続ける心配はない。
    client = _clients.pop(guild_id, None)
    if force:
        _holds.pop(guild_id, None)
    if client is None:
        return False
    try:
        await client.disconnect(force=True)
    except Exception as e:
        # _clients からは既に pop 済みなので、ここで諦めると実際の接続が
        # 生きたまま管理外になる（bot が VC に居座り続ける、次の acquire() が
        # 拾い直すまで誰も気づけない）。黙って握りつぶさず理由を残す。
        logger.warning(
            "[voice] guild=%s 切断に失敗しました（管理外の接続が残っている可能性）: %s",
            guild_id,
            e,
        )
    return True
