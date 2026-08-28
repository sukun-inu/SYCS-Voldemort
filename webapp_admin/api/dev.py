"""開発者パネルの API。

DEV_USER_ID と一致するユーザーだけが使える。本番データに直接影響する操作を
含むため、各エンドポイントに個別のレート制限を掛けている。

Bot 本体へ渡す操作（タスク実行・通知テスト・地震リプレイ）は、
SETTINGS_DIR/_dev_signals にシグナルファイルを置いて Bot 側に拾わせる。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from webapp_admin.api.jsonsafe import SafeJSONResponse as JSONResponse

from config import DISCORD_BOT_TOKEN, DJAUDIO_CACHE_DIR
from webapp_admin.core.config import settings_dir
from webapp_admin.extensions import limiter
from webapp_admin.security import _NeedsLogin, check_csrf, is_dev_user, sanitize

logger = logging.getLogger(__name__)

router = APIRouter()

_DISCORD_API = "https://discord.com/api/v10"
_P2PQUAKE_API = "https://api.p2pquake.net/v2/history"
_TIMEOUT = aiohttp.ClientTimeout(total=10)
_MAX_IMPORT_BYTES = 512 * 1024  # 512 KB
_SIGNAL_DIR = settings_dir() / "_dev_signals"
_LOG_DIR = settings_dir() / "logs"
_ID_PATTERN = re.compile(r"\d+")
_MESSAGE_URL_PATTERN = re.compile(r"https?://discord(?:app)?\.com/channels/\d+/(\d+)/(\d+)")

SCALE_LABELS: dict[int, str] = {
    10: "震度1", 20: "震度2", 30: "震度3", 40: "震度4", 45: "震度4強",
    50: "震度5弱", 55: "震度5強", 60: "震度6弱", 65: "震度6強", 70: "震度7",
}

VALID_TASKS: dict[str, str] = {
    "news_feeds": "ニュースフィードを今すぐ実行",
    "sticky": "スティッキーペンディング処理を実行",
    "djaudio_cache": "DJAudioキャッシュの期限切れを今すぐ掃除",
    "earthquake_reconnect": "地震WSを再接続",
    "user_state_repair": "ユーザー状態DBの自動修復を今すぐ実行",
}

_ENV_DISPLAY: list[tuple[str, bool]] = [
    ("DISCORD_BOT_TOKEN", True),
    ("DISCORD_CLIENT_ID", False),
    ("DISCORD_CLIENT_SECRET", True),
    ("ADMIN_FLASK_SECRET_KEY", True),
    ("OPENAI_API_KEY", True),
    ("GROQ_API_KEY", True),
    ("VIRUSTOTAL_API_KEY", True),
    ("METALPRICE_API_KEY", True),
    ("USER_STATE_POSTGRES_DSN", True),
    ("USER_STATE_POSTGRES_HOST", False),
    ("USER_STATE_POSTGRES_PORT", False),
    ("USER_STATE_POSTGRES_DB", False),
    ("USER_STATE_POSTGRES_USER", False),
    ("USER_STATE_POSTGRES_PASSWORD", True),
    ("USER_STATE_POSTGRES_PASSWORD_FILE", False),
    ("USER_STATE_SYNC_ON_READY", False),
    ("USER_STATE_SYNC_DELAY_SECONDS", False),
    ("USER_STATE_SYNC_GUILD_PAUSE_SECONDS", False),
    ("USER_STATE_SYNC_MAX_MEMBERS_PER_GUILD", False),
    ("USER_STATE_AUTO_REPAIR_ENABLED", False),
    ("USER_STATE_AUTO_REPAIR_INTERVAL_SECONDS", False),
    ("USER_STATE_AUTO_REPAIR_START_DELAY_SECONDS", False),
    ("USER_STATE_AUTO_REPAIR_MAX_ROWS_PER_GUILD", False),
    ("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", False),
    ("USER_STATE_RETENTION_DAYS", False),
    ("USER_STATE_CLEANUP_INTERVAL_SECONDS", False),
    ("METAL_AUTO_REPAIR_ENABLED", False),
    ("METAL_AUTO_REPAIR_INTERVAL_MINUTES", False),
    ("METAL_AUTO_REPAIR_FORCE_FORECAST_REFRESH", False),
    ("SETTINGS_DIR", False),
    ("DJAUDIO_BASE_URL", False),
    ("DJAUDIO_CACHE_DIR", False),
    ("DJAUDIO_CACHE_TTL_SECONDS", False),
    ("FLASK_SECURE_COOKIES", False),
    ("ADMIN_SITE_URL", False),
    ("METALS_SITE_URL", False),
]

# 旧名や運用時の別名を吸収する
_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "ADMIN_FLASK_SECRET_KEY": ("FLASK_SECRET_KEY",),
}

# config.py 側で解決済みの実効値も参照する
_CONFIG_ENV_ATTRS: dict[str, str] = {
    "DISCORD_BOT_TOKEN": "DISCORD_BOT_TOKEN",
    "OPENAI_API_KEY": "OPENAI_API_KEY",
    "GROQ_API_KEY": "GROQ_API_KEY",
    "VIRUSTOTAL_API_KEY": "VIRUSTOTAL_API_KEY",
    "METALPRICE_API_KEY": "METALPRICE_API_KEY",
    "DJAUDIO_BASE_URL": "DJAUDIO_BASE_URL",
    "DJAUDIO_CACHE_DIR": "DJAUDIO_CACHE_DIR",
    "METALS_SITE_URL": "METALS_SITE_URL",
    "ADMIN_SITE_URL": "ADMIN_SITE_URL",
}


# ── 認可 ─────────────────────────────────────────────────────

def check_dev(request: Request) -> dict:
    """DEV_USER_ID と一致する開発者だけを通す。未設定なら存在しない扱い。"""
    if not os.getenv("DEV_USER_ID"):
        raise HTTPException(status_code=404)
    if not request.session.get("user"):
        raise _NeedsLogin()
    if not is_dev_user(request):
        raise HTTPException(status_code=403, detail="開発者専用です。")
    return request.session["user"]


# ── 内部ヘルパー ─────────────────────────────────────────────

def describe_exception(exc: BaseException, *, timeout: float | None = None) -> str:
    """外部呼び出しの失敗理由を、ログにも画面にも出せる一文にする。

    TimeoutError のように str() が空になる例外が多く、そのまま "%s" で出すと
    「失敗しました: 」という何も分からないログになるため、必ず型名を含める。
    """
    if isinstance(exc, asyncio.TimeoutError):
        return f"タイムアウト（{timeout:g}秒以内に応答なし）" if timeout else "タイムアウト"
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return f"TLS証明書エラー（{exc}）"
    if isinstance(exc, aiohttp.ClientConnectorError):
        return f"接続できません（DNSまたはネットワーク到達性: {exc.os_error if exc.os_error else exc}）"
    if isinstance(exc, aiohttp.ClientResponseError):
        return f"HTTP {exc.status} {exc.message}"
    if isinstance(exc, aiohttp.ClientError):
        return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


async def _discord(method: str, path: str, **kwargs) -> Any:
    if not DISCORD_BOT_TOKEN:
        return None
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.request(
                method,
                f"{_DISCORD_API}{path}",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                **kwargs,
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    logger.warning(
                        "Discord API が %s を返しました %s %s: %s", resp.status, method, path, body
                    )
                    return None
                return await resp.json()
    except Exception as exc:
        logger.warning(
            "Discord API 呼び出しに失敗 %s %s: %s", method, path,
            describe_exception(exc, timeout=_TIMEOUT.total),
        )
        return None


def _all_settings() -> dict:
    try:
        from services.settings_store import _load_all_from_disk
        return _load_all_from_disk()
    except Exception:
        return {"guilds": {}}


def _cache_entries() -> list[dict]:
    entries: list[dict] = []
    try:
        paths = sorted(DJAUDIO_CACHE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return []

    now = datetime.now(timezone.utc).timestamp()
    for meta_path in paths:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            mp3_path = DJAUDIO_CACHE_DIR / f"{meta_path.stem}.mp3"
            entries.append({
                "token": meta_path.stem,
                "title": meta.get("title") or meta.get("url") or meta_path.stem,
                "guild_id": str(meta.get("guild_id") or ""),
                "size_mb": round(mp3_path.stat().st_size / 1024 / 1024, 2) if mp3_path.exists() else 0,
                "expires_at": meta.get("expires_at"),
                "expired": now > float(meta.get("expires_at") or 0),
            })
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return entries


def _pending_signals() -> list[str]:
    try:
        return sorted(p.stem for p in _SIGNAL_DIR.glob("*.signal"))
    except OSError:
        return []


def _write_signal(name: str, payload: Any) -> None:
    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    (_SIGNAL_DIR / f"{name}.signal").write_text(text, encoding="utf-8")


def _normalize_env_value(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _resolve_env_value(key: str, cfg: object | None) -> str | None:
    for candidate in (key, *_ENV_ALIASES.get(key, ())):
        normalized = _normalize_env_value(os.environ.get(candidate))
        if normalized is not None:
            return normalized
    if cfg is not None:
        attr = _CONFIG_ENV_ATTRS.get(key)
        if attr:
            return _normalize_env_value(getattr(cfg, attr, None))
    return None


def _env_rows() -> list[dict]:
    try:
        import config as cfg
        defaults = {
            "DJAUDIO_BASE_URL": str(cfg.DJAUDIO_BASE_URL),
            "DJAUDIO_CACHE_DIR": str(cfg.DJAUDIO_CACHE_DIR),
            "DJAUDIO_CACHE_TTL_SECONDS": str(cfg.DJAUDIO_CACHE_TTL),
            "METALS_SITE_URL": cfg.METALS_SITE_URL,
            "ADMIN_SITE_URL": cfg.ADMIN_SITE_URL,
        }
    except Exception:
        cfg = None
        defaults = {}

    rows: list[dict] = []
    for key, secret in _ENV_DISPLAY:
        value = _resolve_env_value(key, cfg)
        if value is not None:
            display = (
                f"{value[:4]}{'*' * min(len(value) - 4, 20)}" if secret and len(value) > 4
                else ("****" if secret else value)
            )
            status = "set"
        elif key in defaults:
            display = defaults[key]
            status = "default"
        else:
            display = None
            status = "missing"
        rows.append({"key": key, "value": display, "status": status, "secret": secret})
    return rows


def _all_stickies() -> list[dict]:
    rows: list[dict] = []
    for guild_id, guild_data in _all_settings().get("guilds", {}).items():
        if not isinstance(guild_data, dict):
            continue
        for channel_id, sticky in (guild_data.get("sticky_messages") or {}).items():
            if not isinstance(sticky, dict):
                continue
            rows.append({
                "guild_id": str(guild_id),
                "channel_id": str(channel_id),
                "content": sticky.get("content", ""),
                "message_id": sticky.get("message_id"),
                "pending_delete": bool(sticky.get("pending_delete")),
            })
    return sorted(rows, key=lambda row: row["guild_id"])


def _tail_file(path: Path, lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f.readlines()[-lines:]]
    except OSError:
        return []


def _require_id(value: str, label: str) -> str:
    text = sanitize(value or "", 20).strip()
    if not _ID_PATTERN.fullmatch(text):
        raise HTTPException(status_code=400, detail=f"{label}は数字のIDで指定してください。")
    return text


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON を解釈できませんでした。")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON オブジェクトを送ってください。")
    return body


def _ok(message: str, **extra) -> JSONResponse:
    return JSONResponse({"ok": True, "message": message, **extra})


# ── 概要 ─────────────────────────────────────────────────────

@router.get("/overview")
async def overview(request: Request, _=Depends(check_dev)):
    guilds, bot_user = await asyncio.gather(
        _discord("GET", "/users/@me/guilds?limit=200"),
        _discord("GET", "/users/@me"),
    )
    guild_list = guilds if isinstance(guilds, list) else []
    guild_list.sort(key=lambda g: (g.get("name") or "").lower())

    # guilds が空になる理由は「Bot がどこにも参加していない」と
    # 「Discord API から取得できなかった」のどちらもありうるが、見た目は
    # 同じ「0 ギルド」になってしまう。失敗は _discord() 内でログには残るが、
    # ログを見ない限り気づけないので、画面にも理由を伝える。
    discord_error = None
    if not DISCORD_BOT_TOKEN:
        discord_error = "DISCORD_BOT_TOKEN が未設定です。"
    elif guilds is None:
        discord_error = "Discord API からギルド一覧を取得できませんでした（ログを確認してください）。"

    settings = _all_settings()
    entries = _cache_entries()

    payload: dict[str, Any] = {
        "bot_user": bot_user or {},
        "guilds": [
            {"id": str(g.get("id")), "name": g.get("name") or "Unknown", "icon": g.get("icon")}
            for g in guild_list
        ],
        "settings_guild_ids": sorted(str(gid) for gid in settings.get("guilds", {})),
        "cache": {
            "entries": entries,
            "expired": sum(1 for entry in entries if entry["expired"]),
        },
        "pending_signals": _pending_signals(),
        "tasks": VALID_TASKS,
        "env_rows": _env_rows(),
        "stickies": _all_stickies(),
    }
    if discord_error:
        payload["discord_error"] = discord_error
    return JSONResponse(payload)


@router.get("/earthquakes")
@limiter.limit("10/minute")
async def earthquakes(request: Request, _=Depends(check_dev), limit: int = Query(5, ge=1, le=20)):
    """リプレイ用の直近の地震情報。外部APIを叩くので概要とは分けている。"""
    history: Any = []
    error: str | None = None
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(_P2PQUAKE_API, params={"codes": "551", "limit": str(limit)}) as resp:
                if resp.status == 200:
                    history = await resp.json()
                else:
                    error = f"HTTP {resp.status}"
                    logger.warning("地震履歴の取得に失敗 %s: %s", _P2PQUAKE_API, error)
    except Exception as exc:
        error = describe_exception(exc, timeout=_TIMEOUT.total)
        # 相手先が落ちている / 経路が塞がっている、のどちらかを判別できるように
        # URL と理由を必ず残す（この呼び出しはコンテナからの外向き通信）。
        logger.warning("地震履歴の取得に失敗 %s: %s", _P2PQUAKE_API, error)

    events = []
    for item in history if isinstance(history, list) else []:
        quake = item.get("earthquake") or {}
        hypocenter = quake.get("hypocenter") or {}
        scale = quake.get("maxScale")
        events.append({
            "time": quake.get("time") or item.get("time"),
            "place": hypocenter.get("name") or "不明",
            "magnitude": hypocenter.get("magnitude"),
            "scale": scale,
            "scale_label": SCALE_LABELS.get(scale, "不明"),
            "json": json.dumps(item, ensure_ascii=False),
        })
    return JSONResponse({"events": events, "error": error})


# ── 送信系 ───────────────────────────────────────────────────

@router.post("/send-message")
@limiter.limit("10/minute")
async def send_message(request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    body = await _json_body(request)
    channel_id = _require_id(body.get("channel_id", ""), "チャンネルID")
    content = sanitize(body.get("content", ""), 2000).strip()
    if not content:
        raise HTTPException(status_code=400, detail="メッセージ内容を入力してください。")

    result = await _discord("POST", f"/channels/{channel_id}/messages", json={"content": content})
    if not result:
        raise HTTPException(status_code=502, detail="送信に失敗しました。チャンネルIDを確認してください。")
    return _ok(f"ch:{channel_id} へ送信しました。")


@router.post("/forward-message")
@limiter.limit("10/minute")
async def forward_message(request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    body = await _json_body(request)
    match = _MESSAGE_URL_PATTERN.match(sanitize(body.get("message_url", ""), 200).strip())
    if not match:
        raise HTTPException(status_code=400, detail="有効な Discord メッセージURLを入力してください。")
    target_channel = _require_id(body.get("target_channel_id", ""), "転送先チャンネルID")

    source_channel, message_id = match.group(1), match.group(2)
    message = await _discord("GET", f"/channels/{source_channel}/messages/{message_id}")
    if not isinstance(message, dict):
        raise HTTPException(status_code=502, detail="元メッセージを取得できませんでした。")

    author = message.get("author") or {}
    username = author.get("global_name") or author.get("username") or "Unknown"
    text = f"**[転送: {username}]**\n{message.get('content') or '(内容なし)'}"[:2000]

    result = await _discord("POST", f"/channels/{target_channel}/messages", json={"content": text})
    if not result:
        raise HTTPException(status_code=502, detail="転送先への送信に失敗しました。")
    return _ok("メッセージを転送しました。")


@router.post("/news-send")
@limiter.limit("5/minute")
async def news_send(request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    body = await _json_body(request)
    channel_id = _require_id(body.get("channel_id", ""), "チャンネルID")
    query = sanitize(body.get("query", ""), 200).strip()
    if not query:
        raise HTTPException(status_code=400, detail="検索クエリを入力してください。")

    from services.news_service import _fetch_articles, _format_pub_date, _summarize_article

    async with aiohttp.ClientSession() as session:
        articles = await _fetch_articles(session, query)
    if not articles:
        raise HTTPException(status_code=404, detail="記事が見つかりませんでした。クエリを変えてお試しください。")

    article = articles[0]
    embed: dict = {"title": article["title"][:256], "url": article["link"], "color": 0x3498DB}
    if article.get("desc"):
        embed["description"] = article["desc"][:4096]
    if article.get("source"):
        embed["author"] = {"name": article["source"][:256]}
    if article.get("pubDate"):
        embed["footer"] = {"text": _format_pub_date(article["pubDate"])}
    try:
        summary = await _summarize_article(article)
        if summary:
            embed["fields"] = [{"name": "要約 (Groq)", "value": summary[:1024], "inline": False}]
    except Exception:
        logger.warning("ニュース要約の生成に失敗しました。要約なしで送信します。")

    result = await _discord("POST", f"/channels/{channel_id}/messages", json={"embeds": [embed]})
    if not result:
        raise HTTPException(status_code=502, detail="送信に失敗しました。チャンネルIDを確認してください。")
    return _ok(f"「{article['title'][:50]}…」を ch:{channel_id} へ送信しました。")


# ── Bot へのシグナル ─────────────────────────────────────────

@router.post("/signal/{task_name}")
@limiter.limit("10/minute")
async def trigger_signal(task_name: str, request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    if task_name not in VALID_TASKS:
        raise HTTPException(status_code=404, detail="不明なタスクです。")
    _write_signal(task_name, {"task": task_name, "created_at": datetime.now(timezone.utc).isoformat()})
    return _ok(f"「{VALID_TASKS[task_name]}」をキューに追加しました。数十秒以内に実行されます。",
               pending_signals=_pending_signals())


@router.post("/test-notify/{kind}")
@limiter.limit("10/minute")
async def test_notify(kind: str, request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    from services.dev_test_notify import KINDS, kind_label

    if kind not in KINDS:
        raise HTTPException(status_code=404, detail="不明な通知テストです。")

    body = await _json_body(request)
    guild_id = int(_require_id(body.get("guild_id", ""), "ギルドID"))

    # チャンネルを指定すると、その機能の本番用チャンネル設定を一切見ずに
    # 直接そこへ送る。設定していないギルドでもテストできるようにする
    # DEV 専用の逃げ道（地震リプレイと同じ考え方）。
    raw_channel_id = str(body.get("channel_id") or "").strip()
    channel_id = int(_require_id(raw_channel_id, "チャンネルID")) if raw_channel_id else None

    _write_signal(f"test_{kind}", {
        "guild_id": guild_id, "channel_id": channel_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    target = f"ギルド {guild_id} のチャンネル {channel_id}（設定は無視）" if channel_id else f"ギルド {guild_id}"
    return _ok(
        f"「{kind_label(kind)}」のテストをキューに追加しました。（送信先: {target}）",
        pending_signals=_pending_signals(),
    )


@router.post("/earthquake-replay")
@limiter.limit("5/minute")
async def earthquake_replay(request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    body = await _json_body(request)
    event_json = sanitize(body.get("event_json", ""), 100000).strip()
    if not event_json:
        raise HTTPException(status_code=400, detail="イベントJSONが必要です。")

    try:
        data = json.loads(event_json)
        quake = data.get("earthquake")
        if not isinstance(quake, dict) or not isinstance(quake.get("hypocenter"), dict):
            raise ValueError("earthquake / hypocenter キーが必要です")
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"無効な地震イベントJSONです: {exc}")

    # ギルド未指定＝全サーバーへ送信。テスト用のリプレイが本番の全サーバーへ
    # 誤爆すると混乱を招くため、画面側は既定でギルドを選ばせ、全サーバー送信は
    # 明示的に選んだときだけ通す（guild_id を送らない）。
    raw_guild_id = str(body.get("guild_id") or "").strip()
    guild_id = int(_require_id(raw_guild_id, "ギルドID")) if raw_guild_id else None

    # チャンネルIDを指定すると、そのギルドの本番用「地震アラート」設定
    # （チャンネル・最小震度・通知タイプ）を一切見ずに直接そこへ送る。
    # 本番設定が無いギルドでも中身を確認したい、という DEV 専用の逃げ道。
    raw_channel_id = str(body.get("channel_id") or "").strip()
    if raw_channel_id and guild_id is None:
        raise HTTPException(status_code=400, detail="送信先チャンネルを指定する場合は、ギルドも指定してください。")
    channel_id = int(_require_id(raw_channel_id, "チャンネルID")) if raw_channel_id else None

    _write_signal("eq_replay", {"event": data, "guild_id": guild_id, "channel_id": channel_id})
    if channel_id:
        target = f"ギルド {guild_id} のチャンネル {channel_id}（地震アラート設定は無視）"
    elif guild_id:
        target = f"ギルド {guild_id}"
    else:
        target = "全サーバー"
    return _ok(f"地震速報をリプレイキューに追加しました（送信先: {target}）。数十秒以内に通知が送信されます。",
               pending_signals=_pending_signals())


# ── 参照系 ───────────────────────────────────────────────────

@router.get("/channels")
@limiter.limit("30/minute")
async def channels(request: Request, guild_id: str = Query(...), _=Depends(check_dev)):
    gid = _require_id(guild_id, "ギルドID")
    # 取得は webapp_admin.auth のキャッシュ層に任せる。送信タブは1回の
    # ギルド変更で3つの選択欄が同時にここを叩くため、素通しすると同じ
    # 問い合わせが重なって Discord のレート制限に当たる。
    from webapp_admin.auth import _fetch_guild_channels

    data = await _fetch_guild_channels(int(gid))
    if not isinstance(data, list):
        return JSONResponse({"channels": [], "voice_channels": []})

    text_types = {0, 5, 10, 11, 12, 15}  # GUILD_TEXT / ANNOUNCEMENT / THREAD / FORUM 等
    voice_types = {2, 13}                # GUILD_VOICE / STAGE_VOICE

    def pick(types: set[int]) -> list[dict]:
        return sorted(
            (
                {"id": str(c["id"]), "name": c.get("name", ""), "type": c.get("type", 0)}
                for c in data
                if c.get("type") in types
            ),
            key=lambda c: c["name"].lower(),
        )

    # 録音の対象は VC なので、テキストと一緒に返して画面側で選ばせる。
    return JSONResponse({"channels": pick(text_types), "voice_channels": pick(voice_types)})


@router.get("/user")
@limiter.limit("20/minute")
async def user_lookup(request: Request, user_id: str = Query(...), _=Depends(check_dev)):
    uid = _require_id(user_id, "ユーザーID")
    data = await _discord("GET", f"/users/{uid}")
    if not isinstance(data, dict):
        raise HTTPException(status_code=404, detail="ユーザーが見つかりませんでした。")

    # Discord のIDは生成時刻を含む（Discord epoch: 2015-01-01）
    created_ms = (int(uid) >> 22) + 1420070400000
    avatar = data.get("avatar")
    return JSONResponse({
        "id": str(data.get("id")),
        "username": data.get("username"),
        "global_name": data.get("global_name"),
        "bot": bool(data.get("bot")),
        "avatar_url": (
            f"https://cdn.discordapp.com/avatars/{uid}/{avatar}.webp?size=128" if avatar else None
        ),
        "created_at": datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
        .astimezone()
        .strftime("%Y/%m/%d %H:%M:%S"),
    })


@router.get("/logs")
@limiter.limit("20/minute")
async def logs(
    request: Request,
    _=Depends(check_dev),
    source: str = Query("bot", pattern="^(bot|admin)$"),
    lines: int = Query(200, ge=10, le=1000),
):
    path = _LOG_DIR / f"{source}.log"
    return JSONResponse({"source": source, "path": str(path), "lines": _tail_file(path, lines)})


# ── ギルド設定の書き出し / 取り込み ─────────────────────────

@router.get("/settings/{guild_id}")
@limiter.limit("20/minute")
async def guild_settings(guild_id: str, request: Request, _=Depends(check_dev)):
    gid = _require_id(guild_id, "ギルドID")
    data = _all_settings().get("guilds", {}).get(gid)
    if data is None:
        raise HTTPException(status_code=404, detail="そのギルドの設定が見つかりません。")
    return JSONResponse({"guild_id": gid, "settings": data})


@router.post("/settings/{guild_id}/import")
@limiter.limit("5/minute")
async def import_guild_settings(
    guild_id: str, request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)
):
    gid = _require_id(guild_id, "ギルドID")
    body = await _json_body(request)
    settings = body.get("settings")
    if not isinstance(settings, dict):
        raise HTTPException(status_code=400, detail="settings オブジェクトが必要です。")

    encoded = json.dumps(settings, ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"設定が上限（{_MAX_IMPORT_BYTES // 1024} KB）を超えています。",
        )

    from services.settings_store import replace_guild_settings

    try:
        replace_guild_settings(int(gid), settings)
    except Exception as exc:
        logger.exception("ギルド設定のインポートに失敗 guild_id=%s", gid)
        raise HTTPException(status_code=500, detail=f"設定の保存に失敗しました（{exc}）")
    return _ok(f"ギルド {gid} の設定をインポートしました。")


# ── DJAudio キャッシュ ───────────────────────────────────────

@router.delete("/cache/{token}")
@limiter.limit("20/minute")
async def delete_cache_entry(token: str, request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", token or ""):
        raise HTTPException(status_code=400, detail="無効なトークンです。")
    from services.djaudio_cache import _delete_entry

    _delete_entry(token)
    return _ok("キャッシュを削除しました。", entries=_cache_entries())


@router.post("/cache/purge")
@limiter.limit("5/minute")
async def purge_cache(request: Request, _=Depends(check_dev), _csrf=Depends(check_csrf)):
    from services.djaudio_cache import _cleanup_expired

    await _cleanup_expired()
    return _ok("期限切れキャッシュをすべて削除しました。", entries=_cache_entries())
