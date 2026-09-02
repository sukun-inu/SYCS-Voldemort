import asyncio
import hashlib
import logging
import os
import tempfile
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import aiohttp
import vt

from config import VIRUSTOTAL_API_KEY
from envutil import env_int
from services.ttl_cache import TTLCache
from services.url_safety import URLSafetyError, validate_public_http_url

MALICIOUS_THRESHOLD = 10
VT_CACHE_TTL = 60 * 60 * 6
VT_MAX_REDIRECTS = env_int("VT_MAX_REDIRECTS", 5, minimum=0)
VT_MAX_DOWNLOAD_BYTES = env_int("VT_MAX_DOWNLOAD_BYTES", 20 * 1024 * 1024, minimum=1)

# URL 1件ごとに鍵が増える。追い出しの無い素の dict だったため、大量の
# 異なる URL がスキャンされ続けると TTL の6時間が経つまで際限なく膨らんでいた。
_vt_cache: TTLCache[str, Dict[str, Any]] = TTLCache(ttl=VT_CACHE_TTL, max_entries=5000)
logger = logging.getLogger(__name__)


def hash_text(text: str) -> str:
    """URLをキャッシュキーにするための sha256 ハッシュ。URLをそのままキーに
    すると長さや記号がまちまちで扱いづらいため、固定長へ丸める。
    """
    return hashlib.sha256(text.encode()).hexdigest()


def _vt_cache_get(key: str) -> Optional[Dict[str, Any]]:
    """スキャン結果のキャッシュを読む薄いラッパー。呼び出し側に TTLCache の
    実装を直接触らせないための間接層。
    """
    return _vt_cache.get(key)


def _vt_cache_set(key: str, data: Dict[str, Any]) -> None:
    """スキャン結果をキャッシュへ書く薄いラッパー。"""
    _vt_cache.set(key, data)


async def fetch_content_type(session: aiohttp.ClientSession, url: str) -> str:
    """URL の Content-Type を確認する。

    まず HEAD で試し、失敗したり Content-Type が空だったりした場合だけ
    GET にフォールバックする。HEAD の方がファイル本体を落とさず安く済み、
    対応していないサーバー向けの保険として GET を残している。
    """

    async def _probe(method: str, target_url: str) -> tuple[int, str]:
        """1つのHTTPメソッドでリダイレクトを辿りながら、最終的な status と
        Content-Type を得る。

        VT_MAX_REDIRECTS を超えたら追跡を諦める（無限リダイレクトに
        引きずられないため）。リダイレクト先ごとに validate_public_http_url
        を通すので、外部URLがリダイレクトで内部アドレスへ誘導する経路も
        弾く。
        """
        current = target_url
        for _ in range(VT_MAX_REDIRECTS + 1):
            validate_public_http_url(current)
            async with session.request(method, current, allow_redirects=False) as r:
                if 300 <= r.status < 400:
                    location = r.headers.get("Location")
                    if not location:
                        return r.status, ""
                    current = urljoin(current, location)
                    continue
                return r.status, r.headers.get("Content-Type", "")
        return 310, ""

    try:
        status, content_type = await _probe("HEAD", url)
        if status < 400 and content_type:
            return content_type
    except URLSafetyError as e:
        logger.warning("[VT] unsafe URL blocked in content-type probe: %s (%s)", url, e)
        return ""
    except Exception:
        pass

    try:
        _, content_type = await _probe("GET", url)
        return content_type
    except URLSafetyError as e:
        logger.warning("[VT] unsafe URL blocked in content-type fallback: %s (%s)", url, e)
        return ""
    except Exception:
        return ""


def is_file_content_type(content_type: str) -> bool:
    """VirusTotalへファイルとして送るべき Content-Type かどうか。
    application/* と application/octet-stream 系だけを対象にする
    （画像・テキスト・動画等はここでは扱わない）。
    """
    if not content_type:
        return False
    ct = content_type.lower()
    if ct.startswith("application/"):
        return True
    if ct in ("binary/octet-stream", "application/octet-stream"):
        return True
    return False


async def vt_check_url(url: str) -> Dict[str, Any]:
    """URLをVirusTotalへ送って結果を得る（結果はキャッシュする）。

    APIキー未設定なら実際には呼ばずスキップとして返す。例外はここで
    握りつぶし、呼び出し元には status="error" として伝える（検査全体を
    1URLの失敗で止めないため）。
    """
    key = hash_text(url)
    cached = _vt_cache_get(key)
    if cached is not None:
        return cached

    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "url", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    try:

        def sync() -> Dict[str, Any]:
            """vt-py の同期クライアントで実際にスキャンする本体。vt-py が同期APIしか
            持たないため、asyncio.to_thread に包んで呼ぶ。
            """
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
    """ファイルの内容をVirusTotalへ送って結果を得る。

    先にハッシュでの既知ファイル照会（sync_lookup）を試し、無ければ
    実際にアップロードしてスキャンする。同時に同じファイルがスキャン
    され始めていた場合（ConflictError）は、新規スキャンを諦めて既存の
    解析結果を取りに行く（sync_fallback）。
    """
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skip", "type": "file", "reason": "no_api_key", "malicious": 0, "suspicious": 0}

    sha256 = hashlib.sha256(content).hexdigest()
    tmp_path = None

    try:

        def sync_lookup() -> Optional[Dict[str, Any]]:
            """ハッシュだけでVirusTotal側に既存の解析結果が無いか確認する。
            見つからない（APIError）場合は None を返し、アップロードによる
            新規スキャンへ進ませる。
            """
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
            """一時ファイルとして書き出した内容を実際にアップロードしてスキャン
            する。成功・失敗のどちらでも一時ファイルは必ず削除する。
            """
            try:
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
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return await asyncio.to_thread(sync_scan)

    except vt.error.ConflictError:
        try:

            def sync_fallback():
                """新規スキャンが ConflictError（他所で同時にスキャン中）になったとき、
                既存の解析結果をハッシュから取得し直す。
                """
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
    """URLをVirusTotalへ回す前段の窓口。

    まず公開URLとして安全か検証し、Content-Typeを見て画像なら丸ごと
    スキップ、ファイルらしい種別ならダウンロードしてファイルスキャン
    （vt_check_file）、それ以外はURLスキャン（vt_check_url）へ振り分ける。
    ダウンロード中もリダイレクトごとに安全性を検証し、
    VT_MAX_DOWNLOAD_BYTES を超えたら読み切る前に打ち切る。
    """
    try:
        validate_public_http_url(url)
    except URLSafetyError as e:
        logger.warning("[VT] unsafe URL blocked: %s (%s)", url, e)
        return {"status": "skip", "type": "url", "reason": f"unsafe_url:{e}", "malicious": 0, "suspicious": 0}

    content_type = await fetch_content_type(session, url)
    logger.info("[VT] Content-Type %s -> %s", url, content_type)

    if content_type.startswith("image/"):
        return {"status": "skip", "type": "image", "reason": "image", "malicious": 0, "suspicious": 0}

    if is_file_content_type(content_type):
        try:
            current = url
            data: bytes | None = None
            for _ in range(VT_MAX_REDIRECTS + 1):
                validate_public_http_url(current)
                async with session.get(current, allow_redirects=False) as r:
                    if 300 <= r.status < 400:
                        location = r.headers.get("Location")
                        if not location:
                            return {
                                "status": "error",
                                "type": "file",
                                "reason": "redirect_without_location",
                                "malicious": -1,
                                "suspicious": -1,
                            }
                        current = urljoin(current, location)
                        continue

                    if r.status >= 400:
                        return {
                            "status": "error",
                            "type": "file",
                            "reason": f"http_status_{r.status}",
                            "malicious": -1,
                            "suspicious": -1,
                        }

                    content_length = r.headers.get("Content-Length")
                    if content_length:
                        try:
                            if int(content_length) > VT_MAX_DOWNLOAD_BYTES:
                                return {
                                    "status": "skip",
                                    "type": "file",
                                    "reason": f"file_too_large>{VT_MAX_DOWNLOAD_BYTES}",
                                    "malicious": 0,
                                    "suspicious": 0,
                                }
                        except ValueError:
                            pass

                    chunks: bytearray = bytearray()
                    async for chunk in r.content.iter_chunked(64 * 1024):
                        chunks.extend(chunk)
                        if len(chunks) > VT_MAX_DOWNLOAD_BYTES:
                            return {
                                "status": "skip",
                                "type": "file",
                                "reason": f"file_too_large>{VT_MAX_DOWNLOAD_BYTES}",
                                "malicious": 0,
                                "suspicious": 0,
                            }
                    data = bytes(chunks)
                    break

            if data is None:
                return {
                    "status": "error",
                    "type": "file",
                    "reason": "too_many_redirects",
                    "malicious": -1,
                    "suspicious": -1,
                }
        except Exception as e:
            logger.error("[VT] file download failed: %s", e)
            return {"status": "error", "type": "file", "reason": str(e), "malicious": -1, "suspicious": -1}
        return await vt_check_file(data)

    return await vt_check_url(url)
