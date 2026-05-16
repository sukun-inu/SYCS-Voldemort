"""
DJAudio-DL コアサービス。
- 設定チャンネルに投稿された URL を自動検知
- yt-dlp + ffmpeg で MP3 変換・キャッシュ保存
- FastAPI ルーターが配信 URL を生成（/dlaudio/files/<guild_id>/<token>）
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
from services.djaudio_site_detection import detect_site, is_djaudio_allowed_url, is_unsupported_url
from services.url_safety import URLSafetyError, validate_public_http_url
from services.settings_store import (
    DJAudioRuntimeSettings,
    get_djaudio_runtime_settings,
)

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s]+")

_dl_semaphore: asyncio.Semaphore | None = None
_user_cooldown: dict[tuple[int, int], float] = {}
_processing: set[tuple[int, int, str]] = set()

_ytdlp_update_lock = asyncio.Lock()
_ytdlp_last_update: float = -9999.0  # 起動直後は即更新を許可
_SOUNDCLOUD_CLIENT_ID_ERR = "Unable to extract client id"


def _get_semaphore() -> asyncio.Semaphore:
    global _dl_semaphore
    if _dl_semaphore is None:
        _dl_semaphore = asyncio.Semaphore(DJAUDIO_DL_CONCURRENCY)
    return _dl_semaphore


async def _try_update_ytdlp() -> bool:
    """yt-dlp を自動更新する。直近1時間以内に更新済みなら skip して False を返す。"""
    global _ytdlp_last_update
    async with _ytdlp_update_lock:
        if time.monotonic() - _ytdlp_last_update < 3600:
            return False
        logger.info("yt-dlp 自動更新を試みる...")
        proc = await asyncio.create_subprocess_exec(
            "yt-dlp", "-U",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        _ytdlp_last_update = time.monotonic()
        if proc.returncode == 0:
            logger.info("yt-dlp の自動更新が完了した")
            return True
        logger.warning("yt-dlp の自動更新に失敗した: %s", stderr.decode("utf-8", errors="replace")[-200:])
        return False


# ──────────────────────────────────────────────
# yt-dlp / URL ユーティリティ
# ──────────────────────────────────────────────

def _extract_urls(content: str, max_urls: int) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for raw in URL_PATTERN.findall(content):
        cleaned = raw.strip().strip("<>").rstrip(")]}>.,!?;:")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        urls.append(cleaned)
        if len(urls) >= max_urls:
            break
    return urls


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


async def _run_ytdlp(url: str, output_dir: str) -> tuple[int, str]:
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
    _, stderr = await proc.communicate()
    return proc.returncode, stderr.decode("utf-8", errors="replace")


async def _download_as_mp3(url: str, output_dir: str) -> list[Path]:
    returncode, err = await _run_ytdlp(url, output_dir)

    if returncode != 0:
        if _SOUNDCLOUD_CLIENT_ID_ERR in err:
            updated = await _try_update_ytdlp()
            if updated:
                logger.info("yt-dlp 更新後にリトライ [%s]", url)
                returncode, err = await _run_ytdlp(url, output_dir)

    if returncode != 0:
        logger.error("yt-dlp エラー [%s]: %s", url, err[-400:])
        raise RuntimeError(err[-400:])

    return sorted(Path(output_dir).glob("*.mp3"))


async def _download_and_register(
    url: str,
    guild_id: int,
    tmpdir: str,
    cache_ttl: int,
) -> list[tuple[str, str]]:
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
        token = register_file(
            mp3,
            source_url=url,
            title=title_text,
            guild_id=guild_id,
            ttl=cache_ttl,
        )
        results.append((title_text, token))
    return results


def _build_result_embed(results: list[tuple[str, str]], guild_id: int, cache_ttl: int) -> discord.Embed:
    ttl_min = cache_ttl // 60
    embed = discord.Embed(
        title="🎵 MP3 の準備が整った",
        color=discord.Color.blurple(),
        description=f"⏱️ リンクは **{ttl_min}分後** に失効するぞ",
    )
    for title, token in results:
        link = f"{DJAUDIO_BASE_URL}/dlaudio/files/{guild_id}/{token}"
        embed.add_field(
            name=f"📥 {title[:50]}",
            value=f"[ダウンロード]({link})\n`{link}`",
            inline=False,
        )
    return embed


async def _add_reaction_safe(message: discord.Message, emoji: str) -> None:
    try:
        await message.add_reaction(emoji)
    except discord.HTTPException:
        pass


async def _remove_reaction_safe(message: discord.Message, emoji: str, bot: Bot) -> None:
    if bot.user is None:
        return
    try:
        await message.remove_reaction(emoji, bot.user)
    except discord.HTTPException:
        pass


# ──────────────────────────────────────────────
# メッセージハンドラ（bot_setup から呼び出す）
# ──────────────────────────────────────────────

async def handle_djaudio_message(bot: Bot, message: discord.Message) -> None:
    """on_message から呼ばれる DJAudio URL 監視ハンドラ。"""
    if not message.guild:
        return

    guild_id = message.guild.id
    settings = get_djaudio_runtime_settings(guild_id)
    if not settings.watch_channel_id or message.channel.id != settings.watch_channel_id:
        return

    urls = _extract_urls(message.content, settings.max_urls)
    if not urls:
        return

    supported_urls: list[str] = []
    djaudio_rejected: list[str] = []   # DJ-Audio 非対応プラットフォーム・ドメイン
    security_rejected: list[str] = []  # セキュリティ上の理由でブロック

    for url in urls:
        # ① DJ-Audio 判定：明示的非対応プラットフォーム（Spotify 等）
        platform_reason = is_unsupported_url(url)
        if platform_reason:
            djaudio_rejected.append(platform_reason)
            continue
        # ② DJ-Audio 判定：許可ドメインリストに含まれるか
        if not is_djaudio_allowed_url(url):
            djaudio_rejected.append("このURLのサービスはDJAudioでサポートされていないぞ。")
            continue
        # ③ セキュリティ判定：SSRF・プライベートIPなどのチェック
        try:
            validate_public_http_url(url)
        except URLSafetyError:
            security_rejected.append("この URL はセキュリティ上の理由で処理できぬ。")
            continue
        supported_urls.append(url)

    if not supported_urls:
        if security_rejected:
            notice = security_rejected[0]
        elif djaudio_rejected:
            notice = djaudio_rejected[0]
        else:
            notice = "この URL は現在サポート対象外だ。"
        await message.reply(f"❌ {notice}", mention_author=False)
        return

    now = time.monotonic()
    cooldown_key = (guild_id, message.author.id)
    last = _user_cooldown.get(cooldown_key, 0)
    if settings.cooldown > 0 and now - last < settings.cooldown:
        remaining = int(settings.cooldown - (now - last))
        await message.reply(f"⏱️ {remaining}秒後に再試行するがよい。", mention_author=False)
        return
    _user_cooldown[cooldown_key] = now

    await asyncio.gather(*[_process_url(bot, message, url, settings) for url in supported_urls])


async def _process_url(
    bot: Bot,
    message: discord.Message,
    url: str,
    settings: DJAudioRuntimeSettings,
) -> None:
    key = (message.guild.id, message.id, url)
    if key in _processing:
        return
    _processing.add(key)

    try:
        await _add_reaction_safe(message, "⏳")
        logger.info("URL検知 guild=%s [%s]: %s", message.guild.id, message.author, url)

        async with _get_semaphore():
            with tempfile.TemporaryDirectory() as tmpdir:
                results = await asyncio.wait_for(
                    _download_and_register(url, message.guild.id, tmpdir, settings.cache_ttl),
                    timeout=DJAUDIO_DL_TIMEOUT,
                )

        await _remove_reaction_safe(message, "⏳", bot)
        await _add_reaction_safe(message, "✅")

        embed = _build_result_embed(results, message.guild.id, settings.cache_ttl)
        embed.set_footer(text=f"リクエスト: {message.author.display_name}")

        output_ch = None
        if settings.output_channel_id:
            output_ch = bot.get_channel(settings.output_channel_id)
        if output_ch and output_ch.id != message.channel.id:
            embed.add_field(name="元メッセージ", value=f"[ジャンプ]({message.jump_url})", inline=True)
            reply_msg = await output_ch.send(embed=embed)
        else:
            reply_msg = await message.reply(embed=embed, mention_author=False)
        for _, token in results:
            update_discord_message(token, reply_msg.channel.id, reply_msg.id)
        logger.info("完了 guild=%s [%s]: %s ファイル", message.guild.id, message.author, len(results))

    except asyncio.TimeoutError:
        logger.error("タイムアウト [%s]", url)
        try:
            await _remove_reaction_safe(message, "⏳", bot)
            await _add_reaction_safe(message, "❌")
            await message.reply("⚠️ タイムアウトしたぞ。時間をおいてから再試行せよ。", mention_author=False)
        except discord.HTTPException:
            pass
    except Exception as e:
        logger.exception("処理失敗 [%s]: %s", url, e)
        try:
            await _remove_reaction_safe(message, "⏳", bot)
            await _add_reaction_safe(message, "❌")
            await message.reply(
                "⚠️ ダウンロードに失敗した。URL を確認して再試行せよ。",
                mention_author=False,
            )
        except discord.HTTPException:
            pass
    finally:
        _processing.discard(key)
