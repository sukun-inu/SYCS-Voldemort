"""
DJAudio-DL キャッシュ管理モジュール。
- トークンに guild_id を紐づけて保存
- FastAPI ルーター側で guild_id を照合してアクセス制御
- TTL 経過後に自動削除
"""

import json
import re
import uuid
import shutil
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone

from config import DJAUDIO_CACHE_DIR, DJAUDIO_CACHE_TTL

logger = logging.getLogger(__name__)

DJAUDIO_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize_filename(value: str, fallback: str = "file") -> str:
    value = str(value or "").strip()
    value = value.replace("/", " ").replace("\\", " ")
    value = re.sub(r'[<>:"|?*\\]', "", value)
    value = re.sub(r"\s+", " ", value).strip()
    safe = "".join(c for c in value if c.isalnum() or c in " ._-()[]{}")
    safe = safe.strip()[:120]
    if not safe:
        safe = fallback
    return safe


# 配信できる拡張子。録音は ZIP でまとめて渡すため mp3 以外も置けるようにしている。
_CONTENT_TYPES = {
    ".mp3": "audio/mpeg",
    ".zip": "application/zip",
    ".ogg": "audio/ogg",
    ".wav": "audio/wav",
}


def content_type_for(extension: str) -> str:
    return _CONTENT_TYPES.get(extension.lower(), "application/octet-stream")


def payload_path(token: str, meta: dict | None = None) -> Path | None:
    """トークンの実ファイル。メタに拡張子が無い旧エントリは .mp3 として扱う。"""
    extension = str((meta or {}).get("extension") or ".mp3")
    if extension not in _CONTENT_TYPES:
        return None
    path = DJAUDIO_CACHE_DIR / f"{token}{extension}"
    return path if path.exists() else None


def register_file(
    mp3_path: Path,
    source_url: str,
    title: str,
    guild_id: int,
    ttl: int | None = None,
    *,
    kind: str = "djaudio",
) -> str:
    """ファイルをキャッシュに登録してトークンを返す。ttl 省略時はグローバル設定値を使用。

    拡張子は元のファイルのものを引き継ぐ（録音の ZIP など mp3 以外も扱う）。
    引数名が mp3_path なのは既存の呼び出しとの互換のため。
    """
    token = uuid.uuid4().hex
    extension = mp3_path.suffix.lower() or ".mp3"
    if extension not in _CONTENT_TYPES:
        raise ValueError(f"配信できない拡張子です: {extension}")
    dest = DJAUDIO_CACHE_DIR / f"{token}{extension}"
    meta_path = DJAUDIO_CACHE_DIR / f"{token}.json"

    shutil.move(str(mp3_path), dest)

    effective_ttl = ttl if ttl is not None else DJAUDIO_CACHE_TTL
    safe_title = _sanitize_filename(title, fallback=token)
    expires_at = datetime.now(timezone.utc).timestamp() + effective_ttl
    meta = {
        "token": token,
        "guild_id": str(guild_id),
        "title": title,
        "source_url": source_url,
        "filename": f"{safe_title}{extension}",
        "extension": extension,
        "kind": kind,
        "size_bytes": dest.stat().st_size,
        "expires_at": expires_at,
    }
    _write_meta_atomic(meta_path, meta)

    logger.info("キャッシュ登録: %s guild=%s (%s) TTL=%ss", token, guild_id, safe_title, effective_ttl)
    return token


def _write_meta_atomic(meta_path: Path, meta: dict) -> None:
    """メタJSONを一時ファイル経由で書く。

    直接 open("w") で上書きすると、CDN（別プロセス）側の get_meta() や
    定期掃除の glob() が書き込み途中のファイルを読んで JSONDecodeError に
    なりうる（本番の CDN と Bot は別プロセスで、同じディレクトリを見ている）。
    settings_store / recording_service と同じ tmp→replace の作法に揃える。
    """
    tmp = meta_path.with_suffix(meta_path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False)
    tmp.replace(meta_path)


def update_discord_message(token: str, channel_id: int, message_id: int) -> None:
    """キャッシュエントリに Discord 返信メッセージ情報を記録する。"""
    meta_path = DJAUDIO_CACHE_DIR / f"{token}.json"
    try:
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["discord_channel_id"] = str(channel_id)
        meta["discord_message_id"] = str(message_id)
        _write_meta_atomic(meta_path, meta)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Discord メッセージ情報の更新失敗 %s: %s", token, e)


def get_meta(token: str) -> dict | None:
    """メタデータを返す。存在しない or 期限切れなら None。"""
    meta_path = DJAUDIO_CACHE_DIR / f"{token}.json"

    if not meta_path.exists():
        return None

    try:
        with meta_path.open("r", encoding="utf-8") as f:
            meta: dict = json.load(f)
    except json.JSONDecodeError as e:
        # 書き込み途中を読んだ、または壊れて残った場合にここへ来る。
        # 呼び出し元にはこれまでどおり「期限切れ」として返すが（利用者に
        # 見せる文面は変えたくない）、本当に期限切れたのか壊れていたのかが
        # 追えなくなるので理由は残す。
        logger.warning("キャッシュメタデータが壊れています %s: %s", meta_path.name, e)
        return None

    if payload_path(token, meta) is None:
        return None

    if datetime.now(timezone.utc).timestamp() > meta.get("expires_at", 0):
        _delete_entry(token)
        return None

    return meta


def _delete_entry(token: str) -> None:
    for suffix in (*_CONTENT_TYPES, ".json"):
        p = DJAUDIO_CACHE_DIR / f"{token}{suffix}"
        try:
            p.unlink(missing_ok=True)
        except OSError as e:
            logger.warning("削除失敗 %s: %s", p, e)
    logger.info("キャッシュ削除: %s", token)


async def cache_cleanup_loop(bot=None, interval: int = 60) -> None:
    """interval 秒ごとに期限切れキャッシュを掃除するループ。"""
    logger.info("DJAudio キャッシュ掃除ループ開始（%s秒間隔）", interval)
    while True:
        await asyncio.sleep(interval)
        await _cleanup_expired(bot)


async def _cleanup_expired(bot=None) -> None:
    now = datetime.now(timezone.utc).timestamp()
    deleted = 0
    for meta_path in DJAUDIO_CACHE_DIR.glob("*.json"):
        try:
            with meta_path.open("r", encoding="utf-8") as f:
                meta = json.load(f)
            if now > meta.get("expires_at", 0):
                if bot is not None:
                    channel_id = meta.get("discord_channel_id")
                    message_id = meta.get("discord_message_id")
                    if channel_id and message_id:
                        try:
                            channel = bot.get_channel(int(channel_id))
                            if channel:
                                msg = await channel.fetch_message(int(message_id))
                                await msg.delete()
                                logger.info("Discord メッセージ削除: %s", message_id)
                        except Exception as e:
                            logger.warning("メッセージ削除失敗 %s: %s", message_id, e)
                _delete_entry(meta["token"])
                deleted += 1
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("掃除中にエラー %s: %s", meta_path, e)
    if deleted:
        logger.info("DJAudio 期限切れキャッシュ %s 件を削除", deleted)
    _cleanup_orphaned_tmp_files(now)


# _write_meta_atomic() が tmp.replace() の前に落ちると *.tmp が残る。
# *.json の glob には引っかからないので、ここで掃除しないと永久に残る。
# 書き込み自体は json.dump 一回ぶんで一瞬なので、進行中の書き込みを誤って
# 消さないよう、十分に古いものだけを「落ちて残った」とみなす。
_TMP_ORPHAN_MAX_AGE_SEC = 300


def _cleanup_orphaned_tmp_files(now: float) -> None:
    removed = 0
    for tmp_path in DJAUDIO_CACHE_DIR.glob("*.json.tmp"):
        try:
            age = now - tmp_path.stat().st_mtime
        except OSError:
            continue
        if age <= _TMP_ORPHAN_MAX_AGE_SEC:
            continue
        try:
            tmp_path.unlink(missing_ok=True)
            removed += 1
        except OSError as e:
            logger.warning("一時ファイルの削除に失敗 %s: %s", tmp_path, e)
    if removed:
        logger.info("DJAudio 書き込み中に残った一時ファイル %s 件を削除", removed)
