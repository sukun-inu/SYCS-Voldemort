import asyncio
import logging
import re
from typing import Optional

import aiohttp
import discord
from discord.ext.commands import Bot

from config import TTS_BASE_URL

logger = logging.getLogger(__name__)

_DEFAULT_VOICE = "Kyoko"
_DEFAULT_RATE = 200
_MAX_TEXT_LEN = 100
_IDLE_TIMEOUT_SEC = 1800  # 30分無音でVC自動退出
_RECONNECT_RETRIES = 3    # ハンドシェイク切断後の再接続試行回数
_RECONNECT_DELAY_SEC = 2.0  # 再接続間隔（秒）

# ギルドごとの状態
_queues: dict[int, asyncio.Queue] = {}
_tasks: dict[int, asyncio.Task] = {}
_voice_clients: dict[int, discord.VoiceClient] = {}
_temp_overrides: dict[int, dict] = {}  # guild_id -> {"vc_channel_id": int}
_connect_locks: dict[int, asyncio.Lock] = {}  # 接続操作の guild ごとロック


def get_effective_vc_watch(guild_id: int, settings: dict) -> tuple[int | None, list[int]]:
    """temp override があれば (temp_vc_id, []) を、なければ設定値を返す。"""
    ov = _temp_overrides.get(guild_id)
    if ov:
        return int(ov["vc_channel_id"]), []
    vc_id = settings.get("vc_channel_id")
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    return (int(vc_id) if vc_id else None), watch_ids


def has_temp_override(guild_id: int) -> bool:
    return guild_id in _temp_overrides


def _clean_text(text: str, max_len: int) -> str:
    text = re.sub(r"https?://\S+", "URL", text)
    text = re.sub(r"<@!?\d+>", "メンション", text)
    text = re.sub(r"<#\d+>", "チャンネル", text)
    text = re.sub(r"<@&\d+>", "ロール", text)
    text = re.sub(r"<a?:(\w+):\d+>", r"\1", text)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len] + "、以下省略"
    return text


def _apply_dictionary(text: str, dictionary: dict[str, str]) -> str:
    for word, reading in dictionary.items():
        text = text.replace(word, reading)
    return text


async def _synthesize(text: str, voice: str, rate: int) -> Optional[str]:
    """TTS APIを叩いて音声URLを返す。失敗時はNone。"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{TTS_BASE_URL}/api/v1/synthesize",
                json={"text": text, "voice": voice, "rate": rate, "format": "wav"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("[TTS] API %s: %s", resp.status, body[:200])
                    return None
                data = await resp.json()
                return f"{TTS_BASE_URL}{data['url']}"
    except Exception as e:
        logger.exception("[TTS] synthesize error: %s", e)
        return None


async def _connect_or_move(
    guild: discord.Guild, vc_channel_id: int
) -> discord.VoiceClient | None:
    """VCに接続。既に別チャンネルに接続中なら移動。per-guild ロックで並行接続競合を防ぐ。"""
    lock = _connect_locks.setdefault(guild.id, asyncio.Lock())
    async with lock:
        existing = _voice_clients.get(guild.id)
        if existing and existing.is_connected():
            if existing.channel.id == vc_channel_id:
                return existing
            try:
                ch = guild.get_channel(vc_channel_id)
                await existing.move_to(ch)
                return existing
            except Exception as e:
                logger.warning("[TTS] move_to failed: %s", e)
                try:
                    await existing.disconnect(force=True)
                except Exception:
                    pass
                _voice_clients.pop(guild.id, None)
        elif existing and not existing.is_connected():
            # ハンドシェイク切断などで接続が失われた古いVCを破棄してから再接続
            logger.info("[TTS] stale voice client, cleaning up before reconnect guild=%s", guild.id)
            try:
                await existing.disconnect(force=True)
            except Exception:
                pass
            _voice_clients.pop(guild.id, None)

        ch = guild.get_channel(vc_channel_id)
        if not isinstance(ch, discord.VoiceChannel):
            logger.warning("[TTS] vc_channel_id=%s not found or not VC", vc_channel_id)
            return None

        # discord.py 内部にすでに接続済みの VoiceClient があれば再利用
        guild_vc = guild.voice_client
        if guild_vc is not None and guild_vc.is_connected():
            if guild_vc.channel.id == vc_channel_id:
                _voice_clients[guild.id] = guild_vc
                return guild_vc
            try:
                await guild_vc.disconnect(force=True)
            except Exception:
                pass

        try:
            vc = await ch.connect()
            _voice_clients[guild.id] = vc
            return vc
        except discord.ClientException as e:
            if "Already connected" in str(e):
                # ロック外から割り込んだ別接続を拾い直す
                guild_vc = guild.voice_client
                if guild_vc and guild_vc.is_connected():
                    _voice_clients[guild.id] = guild_vc
                    return guild_vc
            logger.exception("[TTS] connect error: %s", e)
            return None
        except Exception as e:
            logger.exception("[TTS] connect error: %s", e)
            return None


async def _player_loop(bot: Bot, guild_id: int) -> None:
    queue = _queues.setdefault(guild_id, asyncio.Queue())
    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=float(_IDLE_TIMEOUT_SEC))
        except asyncio.TimeoutError:
            _temp_overrides.pop(guild_id, None)
            vc = _voice_clients.pop(guild_id, None)
            if vc and vc.is_connected():
                await vc.disconnect()
            _tasks.pop(guild_id, None)
            return
        except asyncio.CancelledError:
            break

        audio_url, vc_channel_id = item
        guild = bot.get_guild(guild_id)
        if guild is None:
            queue.task_done()
            continue

        vc = None
        for _attempt in range(_RECONNECT_RETRIES + 1):
            vc = await _connect_or_move(guild, vc_channel_id)
            if vc is not None:
                break
            if _attempt < _RECONNECT_RETRIES:
                logger.info("[TTS] reconnect attempt %d/%d guild=%s", _attempt + 1, _RECONNECT_RETRIES, guild_id)
                await asyncio.sleep(_RECONNECT_DELAY_SEC)
        if vc is None:
            logger.error("[TTS] failed to connect after %d attempts, dropping item guild=%s", _RECONNECT_RETRIES + 1, guild_id)
            queue.task_done()
            continue

        try:
            if vc.is_playing():
                # 通常はここに来ないが、複数タスク競合の残留を防ぐ
                logger.warning("[TTS] vc already playing, stopping first guild=%s", guild_id)
                vc.stop()
                await asyncio.sleep(0.2)

            done_event = asyncio.Event()

            def _after(error: Exception | None) -> None:
                if error:
                    logger.error("[TTS] playback error: %s", error)
                done_event.set()

            source = discord.FFmpegPCMAudio(audio_url)
            vc.play(source, after=_after)
            await done_event.wait()
        except Exception as e:
            logger.exception("[TTS] play error: %s", e)

        queue.task_done()


async def enqueue_message(
    bot: Bot,
    guild: discord.Guild,
    member: discord.Member,
    text: str,
) -> None:
    """メッセージをTTSキューに追加する。"""
    from services.tts_store import get_tts_dictionary, get_tts_settings, get_user_tts_settings

    settings = get_tts_settings(guild.id)
    if not settings.get("enabled"):
        return

    vc_channel_id, _ = get_effective_vc_watch(guild.id, settings)
    if not vc_channel_id:
        return

    max_len = int(settings.get("max_length", _MAX_TEXT_LEN))
    cleaned = _clean_text(text, max_len)
    if not cleaned:
        return

    dictionary = get_tts_dictionary(guild.id)
    cleaned = _apply_dictionary(cleaned, dictionary)

    user_cfg = get_user_tts_settings(guild.id, member.id)
    voice = str(user_cfg.get("voice") or settings.get("default_voice") or _DEFAULT_VOICE)
    rate = int(user_cfg.get("rate") or settings.get("default_rate") or _DEFAULT_RATE)

    speak_max = int(settings.get("speak_max_length", 200))
    read_name = settings.get("read_name", True)
    speak_text = f"{member.display_name}。{cleaned}" if read_name else cleaned
    if len(speak_text) > speak_max:
        speak_text = speak_text[:speak_max]

    audio_url = await _synthesize(speak_text, voice, rate)
    if not audio_url:
        return

    queue = _queues.setdefault(guild.id, asyncio.Queue())
    await queue.put((audio_url, int(vc_channel_id)))

    task = _tasks.get(guild.id)
    if task is None or task.done():
        _tasks[guild.id] = asyncio.create_task(_player_loop(bot, guild.id))


async def enqueue_vc_event(
    bot: Bot,
    guild: discord.Guild,
    member: discord.Member,
    event: str,
) -> None:
    """VC参加・退出をTTSで読み上げる。event は 'join' または 'leave'。"""
    from services.tts_store import get_tts_settings

    settings = get_tts_settings(guild.id)
    if not settings.get("enabled") or not settings.get("vc_notify"):
        return
    vc_channel_id, _ = get_effective_vc_watch(guild.id, settings)
    if not vc_channel_id:
        return

    name = getattr(member, "display_name", None) or str(member)
    text = f"{name}が参加しました" if event == "join" else f"{name}が退出しました"

    voice = str(settings.get("default_voice") or _DEFAULT_VOICE)
    rate = int(settings.get("default_rate") or _DEFAULT_RATE)

    audio_url = await _synthesize(text, voice, rate)
    if not audio_url:
        return

    queue = _queues.setdefault(guild.id, asyncio.Queue())
    await queue.put((audio_url, int(vc_channel_id)))

    task = _tasks.get(guild.id)
    if task is None or task.done():
        _tasks[guild.id] = asyncio.create_task(_player_loop(bot, guild.id))


async def temp_join(bot: Bot, guild: discord.Guild, vc_channel_id: int) -> None:
    """指定VCに一時参加し、そのVCのサブコメ欄を優先読み上げ対象とする。
    退出時（disconnect / アイドルタイムアウト / 全員退出）に自動で元の設定に戻る。"""
    _temp_overrides[guild.id] = {"vc_channel_id": vc_channel_id}
    vc = await _connect_or_move(guild, vc_channel_id)
    if vc is None:
        _temp_overrides.pop(guild.id, None)
        return
    task = _tasks.get(guild.id)
    if task is None or task.done():
        _tasks[guild.id] = asyncio.create_task(_player_loop(bot, guild.id))


async def auto_join(guild: discord.Guild, vc_channel_id: int) -> None:
    """TTSのVCに接続する（メッセージなしで先行参加用）。"""
    await _connect_or_move(guild, vc_channel_id)


async def disconnect(guild_id: int) -> None:
    """指定ギルドのVCから退出し、キューをクリアする。temp override も解除する。"""
    _temp_overrides.pop(guild_id, None)
    _connect_locks.pop(guild_id, None)
    task = _tasks.pop(guild_id, None)
    if task and not task.done():
        task.cancel()

    vc = _voice_clients.pop(guild_id, None)
    if vc:
        try:
            await vc.disconnect(force=True)
        except Exception:
            pass

    queue = _queues.pop(guild_id, None)
    if queue:
        while not queue.empty():
            try:
                queue.get_nowait()
                queue.task_done()
            except Exception:
                break


async def fetch_voices(locale: str = "ja") -> list[str]:
    """利用可能な声の一覧をAPIから取得する。"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{TTS_BASE_URL}/api/v1/voices",
                params={"locale": locale},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                voices = data if isinstance(data, list) else data.get("voices", [])
                return [v["name"] for v in voices if isinstance(v, dict) and v.get("name")]
    except Exception as e:
        logger.exception("[TTS] fetch_voices error: %s", e)
        return []
