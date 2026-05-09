import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from starlette.responses import RedirectResponse

from config import DJAUDIO_CACHE_DIR, DISCORD_BOT_TOKEN
from webapp_admin.security import _NeedsLogin, check_csrf, sanitize
from webapp_admin.templating import flash, render

_DEV_USER_ID = "987278623641829436"
_DISCORD_API = "https://discord.com/api/v10"
_P2PQUAKE_API = "https://api.p2pquake.net/v2/history"
_TIMEOUT = aiohttp.ClientTimeout(total=10)
_SIGNAL_DIR = Path(os.getenv("SETTINGS_DIR", "/app/data")) / "_dev_signals"

_SCALE_LABELS: dict[int, str] = {
    10: "震度1", 20: "震度2", 30: "震度3", 40: "震度4", 45: "震度4強",
    50: "震度5弱", 55: "震度5強", 60: "震度6弱", 65: "震度6強", 70: "震度7",
}

_SCALE_BADGE: dict[int, str] = {
    10: "bg-secondary",       20: "bg-secondary",       30: "bg-info text-dark",
    40: "bg-warning text-dark", 45: "bg-warning text-dark",
    50: "bg-orange",          55: "bg-orange",
    60: "bg-danger",          65: "bg-danger",          70: "bg-danger",
}

_VALID_TASKS = {
    "news_feeds":            "ニュースフィードを今すぐ実行",
    "sticky":                "スティッキーペンディング処理を実行",
    "djaudio_cache":         "DJAudioキャッシュの期限切れを今すぐ掃除",
    "earthquake_reconnect":  "地震WSを再接続",
}

router = APIRouter()


def _check_dev(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise _NeedsLogin()
    if str(user.get("id", "")) != _DEV_USER_ID:
        raise HTTPException(status_code=403, detail="開発者専用ページです。")
    return user


async def _api(method: str, path: str, **kwargs):
    if not DISCORD_BOT_TOKEN:
        return None
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as s:
            async with s.request(
                method,
                f"{_DISCORD_API}{path}",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                **kwargs,
            ) as resp:
                return await resp.json() if resp.status < 400 else None
    except Exception:
        return None


def _all_settings() -> dict:
    try:
        from services.settings_store import _load_all_from_disk
        return _load_all_from_disk()
    except Exception:
        return {"guilds": {}}


def _list_cache_entries() -> list[dict]:
    entries = []
    try:
        for meta_path in sorted(
            DJAUDIO_CACHE_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                with meta_path.open("r", encoding="utf-8") as f:
                    meta = json.load(f)
                mp3_path = DJAUDIO_CACHE_DIR / f"{meta_path.stem}.mp3"
                meta["_token"] = meta_path.stem
                meta["_size_mb"] = (
                    round(mp3_path.stat().st_size / 1024 / 1024, 2)
                    if mp3_path.exists() else 0
                )
                meta["_expired"] = (
                    datetime.now(timezone.utc).timestamp() > meta.get("expires_at", 0)
                )
                entries.append(meta)
            except Exception:
                continue
    except Exception:
        pass
    return entries


def _pending_signals() -> list[str]:
    try:
        return [p.stem for p in _SIGNAL_DIR.glob("*.signal")]
    except Exception:
        return []


async def _fetch_eq_history(limit: int = 5) -> list[dict]:
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as s:
            async with s.get(
                _P2PQUAKE_API,
                params={"codes": "551", "limit": str(limit)},
            ) as resp:
                if resp.status != 200:
                    return []
                return await resp.json()
    except Exception:
        return []


_LOG_DIR = Path(os.getenv("SETTINGS_DIR", "/app/data")) / "logs"

_ENV_DISPLAY: list[tuple[str, bool]] = [
    ("DISCORD_BOT_TOKEN",         True),
    ("DISCORD_CLIENT_ID",         False),
    ("DISCORD_CLIENT_SECRET",     True),
    ("ADMIN_FLASK_SECRET_KEY",    True),
    ("OPENAI_API_KEY",            True),
    ("GROQ_API_KEY",              True),
    ("VIRUSTOTAL_API_KEY",        True),
    ("METALPRICE_API_KEY",        True),
    ("SETTINGS_DIR",              False),
    ("DJAUDIO_BASE_URL",          False),
    ("DJAUDIO_CACHE_DIR",         False),
    ("DJAUDIO_CACHE_TTL_SECONDS", False),
    ("FLASK_SECURE_COOKIES",      False),
    ("ADMIN_SITE_URL",            False),
    ("METALS_SITE_URL",           False),
]


def _tail_file(path: Path, lines: int = 200) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        return [ln.rstrip("\n") for ln in all_lines[-lines:]]
    except (OSError, FileNotFoundError):
        return []


def _env_rows() -> list[dict]:
    rows = []
    for key, secret in _ENV_DISPLAY:
        val = os.environ.get(key)
        if val is None:
            display = None
            status = "missing"
        elif secret:
            display = f"{val[:4]}{'*' * min(len(val) - 4, 20)}" if len(val) > 4 else "****"
            status = "set"
        else:
            display = val
            status = "set"
        rows.append({"key": key, "value": display, "status": status, "secret": secret})
    return rows


def _list_all_stickies() -> list[dict]:
    try:
        from services.settings_store import _load_all_from_disk
        data = _load_all_from_disk()
        result = []
        for guild_id, guild_data in data.get("guilds", {}).items():
            for ch_id, sticky in guild_data.get("sticky_messages", {}).items():
                result.append({
                    "guild_id": guild_id,
                    "channel_id": ch_id,
                    "content": sticky.get("content", ""),
                    "message_id": sticky.get("message_id"),
                    "pending_delete": sticky.get("pending_delete", False),
                })
        return sorted(result, key=lambda x: x["guild_id"])
    except Exception:
        return []


@router.get("")
@router.get("/")
async def dev_index(request: Request, _=Depends(_check_dev)):
    guilds, bot_user, eq_history = await asyncio.gather(
        _api("GET", "/users/@me/guilds?limit=200"),
        _api("GET", "/users/@me"),
        _fetch_eq_history(),
    )
    guilds = guilds or []
    if isinstance(guilds, list):
        guilds.sort(key=lambda g: (g.get("name") or "").lower())
    settings = _all_settings()
    return render(
        request, "dev/index.html",
        guilds=guilds,
        bot_user=bot_user or {},
        settings_guild_ids=set(settings.get("guilds", {}).keys()),
        cache_entries=_list_cache_entries(),
        pending_signals=_pending_signals(),
        valid_tasks=_VALID_TASKS,
        eq_history=eq_history,
        scale_labels=_SCALE_LABELS,
        scale_badge=_SCALE_BADGE,
        stickies=_list_all_stickies(),
        env_rows=_env_rows(),
    )


@router.post("/send-message")
async def send_message(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    channel_id = sanitize(form.get("channel_id", ""), 20).strip()
    content = sanitize(form.get("content", ""), 2000).strip()
    if not channel_id or not content:
        flash(request, "チャンネルIDとメッセージ内容は必須です。", "warning")
        return RedirectResponse("/admin/dev#message", status_code=303)
    result = await _api("POST", f"/channels/{channel_id}/messages", json={"content": content})
    if result:
        flash(request, f"ch:{channel_id} へ送信しました。", "success")
    else:
        flash(request, "送信に失敗しました。チャンネルIDを確認してください。", "danger")
    return RedirectResponse("/admin/dev#message", status_code=303)


@router.post("/forward-message")
async def forward_message(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    msg_url = sanitize(form.get("message_url", ""), 200).strip()
    target_ch = sanitize(form.get("target_channel_id", ""), 20).strip()

    m = re.match(r"https?://discord(?:app)?\.com/channels/\d+/(\d+)/(\d+)", msg_url)
    if not m:
        flash(request, "有効なDiscordメッセージURLを入力してください。", "warning")
        return RedirectResponse("/admin/dev#message", status_code=303)

    src_ch, msg_id = m.group(1), m.group(2)
    msg = await _api("GET", f"/channels/{src_ch}/messages/{msg_id}")
    if not msg or not isinstance(msg, dict):
        flash(request, "元メッセージの取得に失敗しました。", "danger")
        return RedirectResponse("/admin/dev#message", status_code=303)

    author = msg.get("author") or {}
    username = author.get("global_name") or author.get("username", "Unknown")
    body = msg.get("content") or "(内容なし)"
    forward_text = f"**[転送: {username}]**\n{body}"[:2000]

    result = await _api("POST", f"/channels/{target_ch}/messages", json={"content": forward_text})
    if result:
        flash(request, "メッセージを転送しました。", "success")
    else:
        flash(request, "転送先への送信に失敗しました。", "danger")
    return RedirectResponse("/admin/dev#message", status_code=303)


@router.get("/settings/{guild_id}")
async def settings_guild(
    request: Request, guild_id: str, _=Depends(_check_dev)
):
    if not re.fullmatch(r"\d+", guild_id):
        raise HTTPException(status_code=400)
    data = _all_settings()
    guild_data = data.get("guilds", {}).get(guild_id)
    if guild_data is None:
        flash(request, "そのギルドの設定が見つかりません。", "warning")
        return RedirectResponse("/admin/dev#settings", status_code=303)
    return render(
        request, "dev/settings_guild.html",
        guild_id=guild_id,
        settings_json=json.dumps(guild_data, ensure_ascii=False, indent=2),
    )


@router.post("/cache/delete")
async def delete_cache_entry(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    token = sanitize(form.get("token", ""), 64).strip()
    if not token or not re.fullmatch(r"[A-Za-z0-9_\-]+", token):
        flash(request, "無効なトークンです。", "warning")
        return RedirectResponse("/admin/dev#cache", status_code=303)
    from services.djaudio_cache import _delete_entry
    _delete_entry(token)
    flash(request, f"キャッシュ {token[:20]}… を削除しました。", "success")
    return RedirectResponse("/admin/dev#cache", status_code=303)


@router.post("/cache/purge")
async def purge_cache(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    from services.djaudio_cache import _cleanup_expired
    await _cleanup_expired()
    flash(request, "期限切れキャッシュをすべて削除しました。", "success")
    return RedirectResponse("/admin/dev#cache", status_code=303)


@router.post("/signal/{task_name}")
async def trigger_signal(
    request: Request, task_name: str, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    if task_name not in _VALID_TASKS:
        raise HTTPException(status_code=400)
    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    sig_file = _SIGNAL_DIR / f"{task_name}.signal"
    sig_file.write_text(
        json.dumps({
            "task": task_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }),
        encoding="utf-8",
    )
    flash(request, f"タスク '{task_name}' をキューに追加しました。数十秒以内に実行されます。", "info")
    return RedirectResponse("/admin/dev#tasks", status_code=303)


@router.post("/news-send")
async def news_send(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    query = sanitize(form.get("query", ""), 200).strip()
    channel_id = sanitize(form.get("channel_id", ""), 20).strip()
    if not query or not channel_id:
        flash(request, "クエリとチャンネルIDは必須です。", "warning")
        return RedirectResponse("/admin/dev#news", status_code=303)

    from services.news_service import _fetch_articles, _format_pub_date, _summarize_article

    async with aiohttp.ClientSession() as session:
        articles = await _fetch_articles(session, query)

    if not articles:
        flash(request, "記事が見つかりませんでした。クエリを変えてお試しください。", "warning")
        return RedirectResponse("/admin/dev#news", status_code=303)

    article = articles[0]
    embed: dict = {
        "title": article["title"][:256],
        "url": article["link"],
        "color": 0x3498DB,
    }
    if article.get("desc"):
        embed["description"] = article["desc"][:4096]
    if article.get("source"):
        embed["author"] = {"name": article["source"][:256]}
    if article.get("pubDate"):
        embed["footer"] = {"text": _format_pub_date(article["pubDate"])}

    try:
        summary = await _summarize_article(article)
        if summary:
            embed.setdefault("fields", []).append({
                "name": "要約 (Groq)",
                "value": summary[:1024],
                "inline": False,
            })
    except Exception:
        pass

    result = await _api("POST", f"/channels/{channel_id}/messages", json={"embeds": [embed]})
    if result:
        title_short = article["title"][:50]
        flash(request, f"ニュース「{title_short}…」を ch:{channel_id} へ送信しました。", "success")
    else:
        flash(request, "送信に失敗しました。チャンネルIDを確認してください。", "danger")
    return RedirectResponse("/admin/dev#news", status_code=303)


@router.post("/earthquake-replay")
async def earthquake_replay(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    event_json = sanitize(form.get("event_json", ""), 100000).strip()
    if not event_json:
        flash(request, "イベントJSONが必要です。", "warning")
        return RedirectResponse("/admin/dev#earthquake", status_code=303)

    try:
        json.loads(event_json)
    except (ValueError, json.JSONDecodeError):
        flash(request, "無効なJSONです。", "danger")
        return RedirectResponse("/admin/dev#earthquake", status_code=303)

    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    (_SIGNAL_DIR / "eq_replay.signal").write_text(event_json, encoding="utf-8")
    flash(request, "地震速報をリプレイキューに追加しました。数十秒以内に通知が送信されます。", "info")
    return RedirectResponse("/admin/dev#earthquake", status_code=303)


@router.get("/api/channels")
async def api_channels(
    request: Request,
    guild_id: str = Query(...),
    _=Depends(_check_dev),
):
    if not re.fullmatch(r"\d+", guild_id):
        raise HTTPException(status_code=400)
    data = await _api("GET", f"/guilds/{guild_id}/channels")
    if not isinstance(data, list):
        return JSONResponse({"channels": []})
    text_types = {0, 5, 10, 11, 12, 15}  # GUILD_TEXT, ANNOUNCEMENT, THREAD, FORUM 等
    channels = sorted(
        [
            {"id": c["id"], "name": c.get("name", ""), "type": c.get("type", 0)}
            for c in data
            if c.get("type") in text_types
        ],
        key=lambda c: c["name"].lower(),
    )
    return JSONResponse({"channels": channels})


@router.get("/api/logs")
async def api_logs(
    request: Request,
    source: str = Query("bot", pattern="^(bot|admin)$"),
    lines: int = Query(200, ge=10, le=1000),
    _=Depends(_check_dev),
):
    log_path = _LOG_DIR / f"{source}.log"
    tail = _tail_file(log_path, lines)
    return JSONResponse({"source": source, "lines": tail, "path": str(log_path)})


@router.get("/api/user")
async def api_user(
    request: Request,
    user_id: str = Query(...),
    _=Depends(_check_dev),
):
    if not re.fullmatch(r"\d+", user_id):
        raise HTTPException(status_code=400, detail="user_id は数値のみ")
    data = await _api("GET", f"/users/{user_id}")
    if not data or not isinstance(data, dict):
        return JSONResponse({"error": "ユーザーが見つかりませんでした"}, status_code=404)
    snowflake = int(user_id)
    created_ms = (snowflake >> 22) + 1420070400000  # Discord epoch
    data["_created_at"] = datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc).isoformat()
    return JSONResponse(data)


@router.get("/settings/{guild_id}/export")
async def export_guild_settings(
    request: Request, guild_id: str, _=Depends(_check_dev)
):
    if not re.fullmatch(r"\d+", guild_id):
        raise HTTPException(status_code=400)
    data = _all_settings()
    guild_data = data.get("guilds", {}).get(guild_id)
    if guild_data is None:
        raise HTTPException(status_code=404, detail="ギルド設定が見つかりません")
    content = json.dumps(guild_data, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="guild_{guild_id}.json"'},
    )


@router.post("/settings/{guild_id}/import")
async def import_guild_settings(
    request: Request,
    guild_id: str,
    _csrf=Depends(check_csrf),
    _dev=Depends(_check_dev),
    file: UploadFile = File(...),
):
    if not re.fullmatch(r"\d+", guild_id):
        raise HTTPException(status_code=400)
    content = await file.read()
    try:
        new_settings = json.loads(content.decode("utf-8"))
        if not isinstance(new_settings, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        flash(request, "無効なJSONファイルです。", "danger")
        return RedirectResponse("/admin/dev#settings", status_code=303)
    from services.settings_store import replace_guild_settings
    replace_guild_settings(int(guild_id), new_settings)
    flash(request, f"ギルド {guild_id} の設定をインポートしました。", "success")
    return RedirectResponse("/admin/dev#settings", status_code=303)


@router.post("/test-notify/welcome")
async def test_notify_welcome(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    guild_id = sanitize(form.get("guild_id", ""), 20).strip()
    if not guild_id or not re.fullmatch(r"\d+", guild_id):
        flash(request, "ギルドIDが無効です。", "warning")
        return RedirectResponse("/admin/dev#notify", status_code=303)
    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    (_SIGNAL_DIR / "test_welcome.signal").write_text(
        json.dumps({"guild_id": guild_id, "created_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )
    flash(request, f"ウェルカム通知テストをキューに追加しました。（ギルド: {guild_id}）", "info")
    return RedirectResponse("/admin/dev#notify", status_code=303)


@router.post("/test-notify/vc")
async def test_notify_vc(
    request: Request, _=Depends(_check_dev), _csrf=Depends(check_csrf)
):
    form = await request.form()
    guild_id = sanitize(form.get("guild_id", ""), 20).strip()
    if not guild_id or not re.fullmatch(r"\d+", guild_id):
        flash(request, "ギルドIDが無効です。", "warning")
        return RedirectResponse("/admin/dev#notify", status_code=303)
    _SIGNAL_DIR.mkdir(parents=True, exist_ok=True)
    (_SIGNAL_DIR / "test_vc_notify.signal").write_text(
        json.dumps({"guild_id": guild_id, "created_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )
    flash(request, f"VC通知テストをキューに追加しました。（ギルド: {guild_id}）", "info")
    return RedirectResponse("/admin/dev#notify", status_code=303)
