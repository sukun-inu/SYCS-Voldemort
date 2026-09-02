import asyncio
import time
import logging
import re
from functools import lru_cache
from typing import NamedTuple, Optional

import aiohttp
import discord
from discord.ext.commands import Bot

from config import TTS_BASE_URL
from services import voice_session

logger = logging.getLogger(__name__)

if "localhost" in TTS_BASE_URL:
    logger.warning(
        "[TTS] TTS_BASE_URL=%s (デフォルト値。本番では TTS_BASE_URL 環境変数を設定してください)", TTS_BASE_URL
    )

_DEFAULT_VOICE = "Kyoko"
_DEFAULT_RATE = 200
_MAX_TEXT_LEN = 100
_IDLE_TIMEOUT_SEC = None  # アイドルタイムアウト無効（手動退出のみ）
_RECONNECT_RETRIES = 3  # ハンドシェイク切断後の再接続試行回数
_RECONNECT_DELAY_SEC = 2.0  # 再接続間隔（秒）

# ギルドごとの状態
_queues: dict[int, asyncio.Queue] = {}


class _Utterance(NamedTuple):
    """読み上げ1件ぶん。所要時間を測るための時刻も一緒に運ぶ。

    合成にかかった時間は合成した側にしか分からず、待ち時間は再生する側に
    しか分からない。**両方そろって初めて「喋り出すまで何ミリ秒か」になる**
    ので、1件に括って持ち回す。
    """

    audio_url: str
    vc_channel_id: int
    synth_ms: int
    queued_at: float


_tasks: dict[int, asyncio.Task] = {}
_temp_overrides: dict[int, dict] = {}  # guild_id -> {"vc_channel_id": int}


def get_effective_vc_watch(guild_id: int, settings: dict) -> tuple[int | None, list[int]]:
    """temp override があれば (temp_vc_id, []) を、なければ設定値を返す。"""
    ov = _temp_overrides.get(guild_id)
    if ov:
        return int(ov["vc_channel_id"]), []
    vc_id = settings.get("vc_channel_id")
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    return (int(vc_id) if vc_id else None), watch_ids


def has_temp_override(guild_id: int) -> bool:
    """一時参加（temp_join）中で、通常の監視チャンネル設定より優先すべき
    VCがあるかどうか。
    """
    return guild_id in _temp_overrides


def _clean_text(text: str, max_len: int) -> str:
    """読み上げに向かない要素をテキストへ置き換える。

    URL・メンション・チャンネル/ロールリンクをそのまま読み上げると
    意味不明な羅列になるため種別名に差し替え、カスタム絵文字は
    <a?:name:id> の name 部分だけを読ませる。max_len を超える分は
    「、以下省略」で打ち切り、長文で読み上げが延々続くのを防ぐ。
    """
    text = re.sub(r"https?://\S+", "URL", text)
    text = re.sub(r"<@!?\d+>", "メンション", text)
    text = re.sub(r"<#\d+>", "チャンネル", text)
    text = re.sub(r"<@&\d+>", "ロール", text)
    text = re.sub(r"<a?:(\w+):\d+>", r"\1", text)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len] + "、以下省略"
    return text


@lru_cache(maxsize=64)
def _dictionary_pattern(words: tuple[str, ...]) -> re.Pattern[str]:
    """辞書の見出し語をまとめた1つのパターン。長い語を先に当てる。

    ギルドごとに辞書は数十語で、読み上げのたびに組み直すのは無駄なので
    見出し語の組み合わせで覚えておく。
    """
    return re.compile("|".join(re.escape(word) for word in words))


def _apply_dictionary(text: str, dictionary: dict[str, str]) -> str:
    """辞書の読みを当てる。置き換えた結果は、もう一度は置き換えない。

    1語ずつ str.replace() を重ねていたため、前の規則の「出力」に次の規則が
    当たっていた。「鈴木→すずき」と「すずき→スズキ」を別々に登録している
    だけで「鈴木さん」が「スズキさん」になり、しかも結果が JSON の登録順に
    依存していた。1回の走査で置き換えて、その連鎖を断つ。

    同じ位置に複数の語が当たるときは長いほうを採る（「エーアイ研」と「エーアイ」
    なら前者）。短いほうが先に当たると、長い語の登録が意味を持たなくなる。
    """
    words = tuple(sorted((w for w in dictionary if w), key=len, reverse=True))
    if not words:
        return text
    return _dictionary_pattern(words).sub(lambda m: dictionary[m.group(0)], text)


async def _synthesize(text: str, voice: str, rate: int) -> tuple[Optional[str], int]:
    """TTS APIを叩いて (音声URL, 所要ミリ秒) を返す。失敗時は (None, 所要ミリ秒)。

    所要時間を返すのは、**遅いときにどこが遅いのかを後から言えるようにする**
    ため。ここは1発話ごとに `aiohttp.ClientSession()` を作り直しており、毎回
    DNS 解決・TCP・TLS からやり直している。その固定費が効いているのか、
    サーバ側の生成が遅いのかは、測らないと区別できない。

    失敗したときも測って返す。**いちばん知りたいのは、失敗するまでに何秒
    待たされたか**（30秒の制限まで待って落ちているのか、すぐ断られたのか）。
    """
    started = time.monotonic()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{TTS_BASE_URL}/api/v1/synthesize",
                json={"text": text, "voice": voice, "rate": rate, "format": "wav"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    logger.error("[TTS] API %s（%dms）: %s", resp.status, elapsed_ms, body[:200])
                    return None, elapsed_ms
                data = await resp.json()
                elapsed_ms = int((time.monotonic() - started) * 1000)
                logger.info("[TTS] 合成 %dms（%d文字 / voice=%s）", elapsed_ms, len(text), voice)
                return f"{TTS_BASE_URL}{data['url']}", elapsed_ms
    except Exception as e:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        logger.exception("[TTS] synthesize error（%dms）: %s", elapsed_ms, e)
        return None, elapsed_ms


async def _connect_or_move(guild: discord.Guild, vc_channel_id: int) -> discord.VoiceClient | None:
    """VCに接続。既に別チャンネルに接続中なら移動。

    接続そのものの管理は services/voice_session.py に持たせている。読み上げと
    録音は bot の仕様上ひとつの接続を共有するしかなく、片方が勝手に繋ぎ直したり
    切ったりすると、もう片方が巻き添えで落ちるため。
    """
    return await voice_session.acquire(guild, vc_channel_id, purpose="tts")


async def _player_loop(bot: Bot, guild_id: int) -> None:
    """1ギルドにつき1つだけ動く、キューから取り出して順に読み上げる
    常駐タスク。キューが _IDLE_TIMEOUT_SEC の間空ならVCから退出して
    自分自身を終了する（現状は None で無効化されており、手動退出
    以外では止まらない）。接続が切れていれば _RECONNECT_RETRIES 回
    まで再接続を試み、それでも繋がらなければそのアイテムは諦めて
    次へ進む（1件の失敗でキュー全体を詰まらせない）。
    """
    queue = _queues.setdefault(guild_id, asyncio.Queue())
    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=_IDLE_TIMEOUT_SEC)
        except asyncio.TimeoutError:
            _temp_overrides.pop(guild_id, None)
            # 録音中などで占有されていれば切断は見送られる
            await voice_session.release(guild_id)
            _tasks.pop(guild_id, None)
            return
        except asyncio.CancelledError:
            break

        audio_url, vc_channel_id, synth_ms, queued_at = item
        guild = bot.get_guild(guild_id)
        if guild is None:
            queue.task_done()
            continue

        # 再接続前にVCに人間がいるか確認（disconnect後に合成が完了した場合の幽霊接続を防ぐ）
        ch = guild.get_channel(vc_channel_id)
        if isinstance(ch, discord.VoiceChannel) and not any(m for m in ch.members if not m.bot):
            logger.info("[TTS] VC空のためスキップ guild=%s", guild_id)
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
            logger.error(
                "[TTS] failed to connect after %d attempts, dropping item guild=%s", _RECONNECT_RETRIES + 1, guild_id
            )
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
                """discord.py の再生完了コールバック（別スレッドから呼ばれる）。
                done_event を立てるだけで、実際の待機はループ側の
                await done_event.wait() が行う。
                """
                if error:
                    logger.error("[TTS] playback error: %s", error)
                done_event.set()

            source = discord.FFmpegPCMAudio(audio_url)
            vc.play(source, after=_after)
            # 合成が終わってから実際に音が出るまで。キューの待ちと VC 接続、
            # ffmpeg の起動がここに入る。合成と足すと「投稿から喋り出すまで」。
            wait_ms = int((time.monotonic() - queued_at) * 1000)
            logger.info(
                "[TTS] 再生開始 guild=%s 合成=%dms 待ち=%dms 計=%dms",
                guild_id,
                synth_ms,
                wait_ms,
                synth_ms + wait_ms,
            )
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

    audio_url, synth_ms = await _synthesize(speak_text, voice, rate)
    if not audio_url:
        return

    queue = _queues.setdefault(guild.id, asyncio.Queue())
    await queue.put(_Utterance(audio_url, int(vc_channel_id), synth_ms, time.monotonic()))

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

    audio_url, synth_ms = await _synthesize(text, voice, rate)
    if not audio_url:
        return

    queue = _queues.setdefault(guild.id, asyncio.Queue())
    await queue.put(_Utterance(audio_url, int(vc_channel_id), synth_ms, time.monotonic()))

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
    task = _tasks.pop(guild_id, None)
    if task and not task.done():
        task.cancel()

    # 録音中は接続を切らない（録音側が止めるまで掴んだままにする）。
    await voice_session.release(guild_id)

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
