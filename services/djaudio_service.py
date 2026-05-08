"""
DJAudio-DL コアサービス。
- 設定チャンネルに投稿された URL を自動検知
- yt-dlp + ffmpeg で MP3 変換・キャッシュ保存
- Flask Blueprint が配信 URL を生成（/dlaudio/files/<guild_id>/<token>）
"""

import asyncio
import json
import logging
import re
import tempfile
import time
from pathlib import Path

import discord
from discord.ext.commands import Bot

from config import (
    DJAUDIO_BASE_URL,
    DJAUDIO_DL_CONCURRENCY,
    DJAUDIO_DL_TIMEOUT,
    DJAUDIO_FFMPEG_PATH,
)
from services.djaudio_cache import register_file, update_discord_message
from services.djaudio_isrc_meta import enrich_metadata
from services.djaudio_site_detection import detect_site, is_unsupported_url
from services.settings_store import (
    get_djaudio_cache_ttl,
    get_djaudio_cooldown,
    get_djaudio_max_urls,
    get_djaudio_watch_channel,
)

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s]+")

_dl_semaphore: asyncio.Semaphore | None = None
_user_cooldown: dict[int, float] = {}
_processing: set[tuple] = set()


def _get_semaphore() -> asyncio.Semaphore:
    global _dl_semaphore
    if _dl_semaphore is None:
        _dl_semaphore = asyncio.Semaphore(DJAUDIO_DL_CONCURRENCY)
    return _dl_semaphore


# ──────────────────────────────────────────────
# yt-dlp ユーティリティ
# ──────────────────────────────────────────────

async def _can_download(url: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "yt-dlp", "--simulate", "--quiet", "--no-warnings",
        "--ffmpeg-location", DJAUDIO_FFMPEG_PATH,
        url,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    return proc.returncode == 0


def _normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _format_title_from_metadata(meta: dict) -> str:
    title  = _normalize_text(meta.get("title"))
    artist = _normalize_text(
        meta.get("artist") or meta.get("album_artist")
        or meta.get("creator") or meta.get("uploader")
    )
    track = _normalize_text(
        meta.get("track") or meta.get("alt_title") or meta.get("release_title")
    )
    site = detect_site(meta)

    def _with_artist(first: str, second: str) -> str:
        if not first:
            return second
        if not second:
            return first
        if second.lower().startswith(first.lower()):
            return second
        return f"{first} - {second}"

    if not title:
        return artist or track or "unknown"

    if site == "youtube":
        if artist and track:
            return _with_artist(artist, track)
        if artist:
            return _with_artist(artist, title)
        if meta.get("uploader"):
            return _with_artist(_normalize_text(meta["uploader"]), title)
        return title

    if site == "soundcloud":
        return _with_artist(artist, title) if artist else title

    if site == "bandcamp":
        if artist:
            return _with_artist(artist, title)
        return _with_artist(track, title) if track else title

    if site == "nicovideo":
        return title

    if site == "tiktok":
        uploader = _normalize_text(meta.get("uploader"))
        return _with_artist(uploader, title) if uploader else title

    if artist:
        return _with_artist(artist, title)
    return _with_artist(track, title) if track else title


def _load_info_json(mp3_path: Path) -> dict | None:
    info_path = mp3_path.with_suffix(".info.json")
    if not info_path.exists():
        return None
    try:
        return json.loads(info_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("info.json の読み込みに失敗しました: %s", e)
        return None


async def _download_as_mp3(url: str, output_dir: str) -> list[Path]:
    template = str(Path(output_dir) / "%(title).80s.%(ext)s")
    cmd = [
        "yt-dlp",
        "-x",
        "--audio-format", "mp3",
        "--audio-quality", "0",
        "-f", "bestaudio/best",
        "--format-sort", "asr,abr,acodec:opus",
        "--postprocessor-args", "ffmpeg:-q:a 0",
        "--write-info-json",
        "--embed-thumbnail",
        "--convert-thumbnails", "jpg",
        "--embed-metadata",
        "--concurrent-fragments", "4",
        "--buffer-size", "1M",
        "--http-chunk-size", "10M",
        "--retries", "5",
        "--socket-timeout", "30",
        "--no-playlist",
        "-o", template,
        "--ffmpeg-location", DJAUDIO_FFMPEG_PATH,
        "--no-warnings",
        url,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        err = stderr.decode("utf-8", errors="replace")
        logger.error("yt-dlp エラー [%s]: %s", url, err[-400:])
        raise RuntimeError(err[-400:])

    return sorted(Path(output_dir).glob("*.mp3"))


async def _download_and_register(url: str, guild_id: int, tmpdir: str) -> list[tuple[str, str]]:
    """MP3 をダウンロードしてメタデータを補完・キャッシュ登録し、(title, token) のリストを返す。"""
    mp3_files = await _download_as_mp3(url, tmpdir)
    if not mp3_files:
        raise RuntimeError("MP3 ファイルが生成されませんでした")

    results: list[tuple[str, str]] = []
    for mp3 in mp3_files:
        info_meta = _load_info_json(mp3)
        if info_meta:
            await enrich_metadata(mp3, info_meta)
        title_text = _format_title_from_metadata(info_meta) if info_meta else mp3.stem
        token = register_file(mp3, source_url=url, title=title_text, guild_id=guild_id, ttl=get_djaudio_cache_ttl(guild_id))
        results.append((title_text, token))
    return results


def _build_result_embed(results: list[tuple[str, str]], guild_id: int) -> discord.Embed:
    ttl_min = get_djaudio_cache_ttl(guild_id) // 60
    embed = discord.Embed(
        title="🎵 MP3 準備完了",
        color=discord.Color.blurple(),
        description=f"⏱️ リンクは **{ttl_min}分後** に失効します",
    )
    for title, token in results:
        link = f"{DJAUDIO_BASE_URL}/dlaudio/files/{guild_id}/{token}"
        embed.add_field(
            name=f"📥 {title[:50]}",
            value=f"[ダウンロード]({link})\n`{link}`",
            inline=False,
        )
    return embed


# ──────────────────────────────────────────────
# メッセージハンドラ（bot_setup から呼び出す）
# ──────────────────────────────────────────────

async def handle_djaudio_message(bot: Bot, message: discord.Message) -> None:
    """on_message から呼ばれる DJAudio URL 監視ハンドラ。"""
    if not message.guild:
        return

    watch_ch_id = get_djaudio_watch_channel(message.guild.id)
    if not watch_ch_id or message.channel.id != watch_ch_id:
        return

    guild_id = message.guild.id
    max_urls = get_djaudio_max_urls(guild_id)
    cooldown = get_djaudio_cooldown(guild_id)

    urls = URL_PATTERN.findall(message.content)[:max_urls]
    if not urls:
        return

    now = time.monotonic()
    last = _user_cooldown.get(message.author.id, 0)
    if cooldown > 0 and now - last < cooldown:
        remaining = int(cooldown - (now - last))
        await message.reply(f"⏱️ {remaining}秒後に再試行してください。", mention_author=False)
        return
    _user_cooldown[message.author.id] = now

    await asyncio.gather(*[_process_url(bot, message, url) for url in urls])


async def _process_url(bot: Bot, message: discord.Message, url: str) -> None:
    key = (message.guild.id, message.id, url)
    if key in _processing:
        return
    _processing.add(key)

    try:
        await message.add_reaction("⏳")
        logger.info("URL検知 guild=%s [%s]: %s", message.guild.id, message.author, url)

        unsupported_reason = is_unsupported_url(url)
        if unsupported_reason:
            await message.remove_reaction("⏳", bot.user)
            await message.add_reaction("❌")
            await message.reply(f"❌ {unsupported_reason}", mention_author=False)
            return

        if not await _can_download(url):
            await message.remove_reaction("⏳", bot.user)
            await message.add_reaction("❓")
            return

        async with _get_semaphore():
            with tempfile.TemporaryDirectory() as tmpdir:
                results = await asyncio.wait_for(
                    _download_and_register(url, message.guild.id, tmpdir),
                    timeout=DJAUDIO_DL_TIMEOUT,
                )

        await message.remove_reaction("⏳", bot.user)
        await message.add_reaction("✅")

        embed = _build_result_embed(results, message.guild.id)
        embed.set_footer(text=f"リクエスト: {message.author.display_name}")
        reply_msg = await message.reply(embed=embed, mention_author=False)
        for _, token in results:
            update_discord_message(token, reply_msg.channel.id, reply_msg.id)
        logger.info("完了 guild=%s [%s]: %s ファイル", message.guild.id, message.author, len(results))

    except asyncio.TimeoutError:
        logger.error("タイムアウト [%s]", url)
        try:
            await message.remove_reaction("⏳", bot.user)
            await message.add_reaction("❌")
            await message.reply("⚠️ タイムアウトしました。時間をおいて再試行してください。", mention_author=False)
        except discord.HTTPException:
            pass
    except Exception as e:
        logger.exception("処理失敗 [%s]: %s", url, e)
        try:
            await message.remove_reaction("⏳", bot.user)
            await message.add_reaction("❌")
            await message.reply(
                f"⚠️ ダウンロードに失敗しました\n```\n{str(e)[:300]}\n```",
                mention_author=False,
            )
        except discord.HTTPException:
            pass
    finally:
        _processing.discard(key)
