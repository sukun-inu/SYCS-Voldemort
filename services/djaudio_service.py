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
from urllib.parse import urlparse

import aiohttp

import discord
from discord.ext.commands import Bot

from config import (
    DJAUDIO_BASE_URL,
    DJAUDIO_DL_CONCURRENCY,
    DJAUDIO_DL_TIMEOUT,
    DJAUDIO_FFMPEG_PATH,
    SOUNDCLOUD_CLIENT_ID as _SC_ENV_CLIENT_ID,
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

if "localhost" in DJAUDIO_BASE_URL or "127.0.0.1" in DJAUDIO_BASE_URL:
    logger.warning(
        "[DJAudio] DJAUDIO_BASE_URL=%s (デフォルト値。本番では DJAUDIO_BASE_URL 環境変数を設定してください。"
        "未設定のままだと配信リンクがサーバー外から開けません)",
        DJAUDIO_BASE_URL,
    )

URL_PATTERN = re.compile(r"https?://[^\s]+")

_dl_semaphore: asyncio.Semaphore | None = None
_user_cooldown: dict[tuple[int, int], float] = {}
_processing: set[tuple[int, int, str]] = set()

_SOUNDCLOUD_CLIENT_ID_ERR = "Unable to extract client id"

# SoundCloud client_id 動的取得キャッシュ
_sc_client_id: str | None = None
_sc_client_id_fetched_at: float = -9999.0
_sc_client_id_lock = asyncio.Lock()

# SoundCloud JS バンドルから client_id を探す正規表現（複数パターン）
_SC_CLIENT_ID_PATTERNS = [
    re.compile(r'client_id\s*:\s*"([A-Za-z0-9]{20,64})"'),
    re.compile(r'"client_id"\s*:\s*"([A-Za-z0-9]{20,64})"'),
    re.compile(r'client_id\s*=\s*"([A-Za-z0-9]{20,64})"'),
    re.compile(r"client_id\s*:\s*'([A-Za-z0-9]{20,64})'"),
]


def _get_semaphore() -> asyncio.Semaphore:
    global _dl_semaphore
    if _dl_semaphore is None:
        _dl_semaphore = asyncio.Semaphore(DJAUDIO_DL_CONCURRENCY)
    return _dl_semaphore


def _sync_fetch_sc_client_id_via_ytdlp() -> str | None:
    """yt-dlp Python ライブラリ（pip版）を使って同期的に SoundCloud client_id を取得する。
    subprocess バイナリとは別コードパスのため、バイナリが失敗しても成功する可能性がある。
    """
    try:
        from yt_dlp.extractor.soundcloud import SoundcloudIE  # type: ignore[import]
        import yt_dlp  # type: ignore[import]

        SoundcloudIE._CLIENT_ID = None  # クラスキャッシュをリセット
        with yt_dlp.YoutubeDL({"quiet": True, "no_warnings": True}) as ydl:
            ie = SoundcloudIE(ydl)
            ie._real_initialize()

        cid = SoundcloudIE._CLIENT_ID
        if cid:
            logger.info("yt-dlp Python API で client_id 取得成功: %s…", str(cid)[:8])
            return cid
        logger.error("yt-dlp Python API: client_id が空だった")
    except Exception as e:
        logger.error("yt-dlp Python API からの client_id 取得に失敗: %s", e, exc_info=True)
    return None


async def _scrape_sc_client_id_via_aiohttp() -> str | None:
    """SoundCloud の HTML を直接 fetch して JS バンドルから client_id を正規表現で探す。"""
    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(
            headers={"User-Agent": _UA}, timeout=timeout
        ) as session:
            try:
                async with session.get("https://soundcloud.com") as resp:
                    html = await resp.text()
                logger.info("SoundCloud HTML 取得: status=%s len=%d", resp.status, len(html))
            except Exception as e:
                logger.error("SoundCloud HTML fetch に失敗: %s", e)
                return None

            script_urls: list[str] = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
            logger.info("スクリプト URL %d 件発見", len(script_urls))
            if not script_urls:
                logger.error("SoundCloud HTML にスクリプト URL がない (先頭500文字: %s)", html[:500])
                return None

            for script_url in list(reversed(script_urls))[:12]:
                try:
                    async with session.get(script_url) as resp:
                        js = await resp.text()
                    for pat in _SC_CLIENT_ID_PATTERNS:
                        m = pat.search(js)
                        if m:
                            cid = m.group(1)
                            logger.info("aiohttp scraper で client_id 取得成功: %s…", cid[:8])
                            return cid
                except Exception as e:
                    logger.warning("スクリプト fetch 失敗 [%s]: %s", script_url, e)
                    continue

            logger.error(
                "全スクリプトに client_id パターンが見つからなかった (試行 %d 件)",
                min(len(script_urls), 12),
            )
    except Exception as e:
        logger.error("aiohttp scraper が例外で終了: %s", e, exc_info=True)
    return None


async def _fetch_soundcloud_client_id(*, force: bool = False) -> str | None:
    """SoundCloud client_id を取得してキャッシュする。TTL=12時間。
    優先順: 環境変数 SOUNDCLOUD_CLIENT_ID → yt-dlp Python API → aiohttp scraper
    """
    global _sc_client_id, _sc_client_id_fetched_at
    async with _sc_client_id_lock:
        # 環境変数が設定されていれば常にそちらを優先（動的取得は行わない）
        if _SC_ENV_CLIENT_ID:
            if not force and _sc_client_id == _SC_ENV_CLIENT_ID:
                return _sc_client_id
            logger.info("SOUNDCLOUD_CLIENT_ID 環境変数を使用: %s…", _SC_ENV_CLIENT_ID[:8])
            _sc_client_id = _SC_ENV_CLIENT_ID
            _sc_client_id_fetched_at = time.monotonic()
            return _sc_client_id

        if not force and _sc_client_id and time.monotonic() - _sc_client_id_fetched_at < 43200:
            return _sc_client_id

        logger.info("SoundCloud client_id を動的取得中 (force=%s)...", force)

        # Method 1: yt-dlp Python ライブラリ（subprocess バイナリとは別コード）
        cid = await asyncio.get_event_loop().run_in_executor(
            None, _sync_fetch_sc_client_id_via_ytdlp
        )

        # Method 2: aiohttp スクレイパー
        if not cid:
            cid = await _scrape_sc_client_id_via_aiohttp()

        if cid:
            _sc_client_id = cid
            _sc_client_id_fetched_at = time.monotonic()
        else:
            logger.error(
                "すべての方法で SoundCloud client_id の取得に失敗した。"
                "ブラウザの DevTools (Network タブ) で api-v2.soundcloud.com へのリクエストURLから "
                "client_id=XXXX を見つけて環境変数 SOUNDCLOUD_CLIENT_ID に設定してください。"
            )

        return cid


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


def _is_soundcloud_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    return host in ("soundcloud.com", "on.soundcloud.com")


async def _run_ytdlp(url: str, output_dir: str, sc_client_id: str | None = None) -> tuple[int, str]:
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
    ]
    if sc_client_id:
        cmd += ["--extractor-args", f"soundcloud:client_id={sc_client_id}"]
    cmd.append(url)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    return proc.returncode, stderr.decode("utf-8", errors="replace")


async def _download_as_mp3(url: str, output_dir: str) -> list[Path]:
    returncode, err = await _run_ytdlp(url, output_dir)

    if returncode != 0 and _SOUNDCLOUD_CLIENT_ID_ERR in err and _is_soundcloud_url(url):
        logger.error("SoundCloud client_id エラーを検知。動的取得を試みる [%s]", url)
        cid = await _fetch_soundcloud_client_id()
        if cid:
            logger.error("client_id 取得成功 (%s…)。リトライ開始 [%s]", cid[:8], url)
            returncode, err = await _run_ytdlp(url, output_dir, sc_client_id=cid)
        else:
            logger.error("client_id 取得失敗。リトライ不可 [%s]", url)

        # それでも失敗した場合はキャッシュ強制更新してもう一度だけ試す
        if returncode != 0 and _SOUNDCLOUD_CLIENT_ID_ERR in err:
            logger.error("client_id 指定でもエラー継続。強制再取得を試みる [%s]", url)
            new_cid = await _fetch_soundcloud_client_id(force=True)
            if new_cid and new_cid != cid:
                logger.error("新 client_id (%s…) で最終リトライ [%s]", new_cid[:8], url)
                returncode, err = await _run_ytdlp(url, output_dir, sc_client_id=new_cid)

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
