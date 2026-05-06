import asyncio
import hashlib
import logging
import os
import tempfile
import time
from typing import Any, Dict, Optional

import aiohttp
import vt

from config import VIRUSTOTAL_API_KEY

MALICIOUS_THRESHOLD = 10
VT_CACHE_TTL = 60 * 60 * 6

_vt_cache: Dict[str, Dict[str, Any]] = {}
logger = logging.getLogger(__name__)


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _vt_cache_get(key: str) -> Optional[Dict[str, Any]]:
    entry = _vt_cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["time"] > VT_CACHE_TTL:
        _vt_cache.pop(key, None)
        return None
    return entry["data"]


def _vt_cache_set(key: str, data: Dict[str, Any]) -> None:
    _vt_cache[key] = {"time": time.time(), "data": data}
    now = time.time()
    expired = [k for k, v in list(_vt_cache.items()) if now - v["time"] > VT_CACHE_TTL]
    for k in expired:
        _vt_cache.pop(k, None)


async def fetch_content_type(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.head(url, allow_redirects=True) as r:
            if r.status < 400:
                return r.headers.get("Content-Type", "")
    except Exception:
        pass
    try:
        async with session.get(url, allow_redirects=True) as r:
            return r.headers.get("Content-Type", "")
    except Exception:
        return ""


def is_file_content_type(content_type: str) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    if ct.startswith("application/"):
        return True
    if ct in ("binary/octet-stream", "application/octet-stream"):
        return True
    return False


async def vt_check_url(url: str) -> Dict[str, Any]:
    key = hash_text(url)
    cached = _vt_cache_get(key)
    if cached is not None:
        return cached

    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "url", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    try:
        def sync():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                analysis = client.scan_url(url, wait_for_completion=True)
                stats = analysis.stats
                return {
                    "status": "ok",
                    "type": "url",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        result = await asyncio.to_thread(sync)
        _vt_cache_set(key, result)
        return result

    except Exception as e:
        logger.error("[VT] URL scan exception: %s", e)
        return {"status": "error", "type": "url", "reason": str(e), "malicious": 0, "suspicious": 0}


async def vt_check_file(content: bytes) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "file", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    sha256 = hashlib.sha256(content).hexdigest()
    tmp_path = None

    try:
        def sync_lookup():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                try:
                    obj = client.get_object(f"/files/{sha256}")
                    stats = obj.last_analysis_stats
                    return {
                        "status": "cached",
                        "type": "file",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                    }
                except vt.error.APIError:
                    return None

        cached = await asyncio.to_thread(sync_lookup)
        if cached:
            return cached

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        def sync_scan():
            with vt.Client(VIRUSTOTAL_API_KEY) as client:
                with open(tmp_path, "rb") as f:
                    analysis = client.scan_file(f, wait_for_completion=True)
                stats = analysis.stats
                return {
                    "status": "ok",
                    "type": "file",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }

        return await asyncio.to_thread(sync_scan)

    except vt.error.ConflictError:
        try:
            def sync_fallback():
                with vt.Client(VIRUSTOTAL_API_KEY) as client:
                    obj = client.get_object(f"/files/{sha256}")
                    stats = obj.last_analysis_stats
                    return {
                        "status": "conflict_fallback",
                        "type": "file",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                    }

            return await asyncio.to_thread(sync_fallback)
        except Exception:
            raise

    except Exception as e:
        logger.error("[VT] File scan exception: %s", e)
        return {"status": "error", "type": "file", "reason": str(e), "malicious": 0, "suspicious": 0}

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError as e:
                logger.warning("[VT] 一時ファイルの削除に失敗: %s", e)


async def vt_scan_target(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    content_type = await fetch_content_type(session, url)
    logger.info("[VT] Content-Type %s -> %s", url, content_type)

    if content_type.startswith("image/"):
        return {"status": "skip", "type": "image", "reason": "image", "malicious": 0, "suspicious": 0}

    if is_file_content_type(content_type):
        try:
            async with session.get(url) as r:
                data = await r.read()
        except Exception as e:
            logger.error("[VT] file download failed: %s", e)
            return {"status": "error", "type": "file", "reason": str(e), "malicious": -1, "suspicious": -1}
        return await vt_check_file(data)

    return await vt_check_url(url)
