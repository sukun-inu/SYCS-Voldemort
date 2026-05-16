import asyncio
import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

from services.tts_store import (
    add_tts_dictionary_entry,
    get_tts_dictionary,
    get_tts_settings,
    get_user_tts_settings,
    remove_tts_dictionary_entry,
    reset_user_tts_settings,
    set_tts_channels,
    set_tts_default_rate,
    set_tts_default_voice,
    set_tts_enabled,
    set_tts_max_lengths,
    set_tts_read_name,
    set_tts_vc_notify,
)
from services.tts_service import fetch_voices
from webapp_admin.auth import get_guild_channels, get_guild_voice_channels
from webapp_admin.security import check_csrf, check_guild, sanitize, validate_int
from webapp_admin.templating import flash, render

logger = logging.getLogger(__name__)

router = APIRouter()

_REDIRECT = "/admin/settings/tts"
_DEFAULT_VOICE = "Kyoko"
_DEFAULT_RATE = 200
_DEFAULT_MAX_LENGTH = 100
_DEFAULT_SPEAK_MAX_LENGTH = 200


def _tts_context(gid: int, text_channels: list, voice_channels: list, available_voices: list[str]) -> dict:
    settings = get_tts_settings(gid)
    watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
    vc_id = settings.get("vc_channel_id")

    watch_channels = [c for c in text_channels if int(c["id"]) in watch_ids]
    available_channels = [c for c in text_channels if int(c["id"]) not in watch_ids]

    user_settings_raw = settings.get("user_settings", {})
    user_rows = []
    if isinstance(user_settings_raw, dict):
        for uid, cfg in user_settings_raw.items():
            if isinstance(cfg, dict) and cfg:
                user_rows.append({
                    "user_id": uid,
                    "voice": cfg.get("voice", "（デフォルト）"),
                    "rate": cfg.get("rate", "（デフォルト）"),
                })

    return dict(
        settings=settings,
        enabled=settings.get("enabled", False),
        watch_ids=watch_ids,
        vc_id=vc_id,
        watch_channels=watch_channels,
        available_channels=available_channels,
        voice_channels=voice_channels,
        default_voice=settings.get("default_voice", _DEFAULT_VOICE),
        default_rate=settings.get("default_rate", _DEFAULT_RATE),
        max_length=int(settings.get("max_length", _DEFAULT_MAX_LENGTH)),
        speak_max_length=int(settings.get("speak_max_length", _DEFAULT_SPEAK_MAX_LENGTH)),
        read_name=bool(settings.get("read_name", True)),
        vc_notify=bool(settings.get("vc_notify", False)),
        available_voices=available_voices,
        dictionary=get_tts_dictionary(gid),
        user_rows=user_rows,
    )


@router.api_route("/tts", methods=["GET", "POST"])
async def tts_settings(request: Request, _=Depends(check_guild), _csrf=Depends(check_csrf)):
    gid = request.session["guild_id"]

    if request.method == "POST":
        form = await request.form()
        action = form.get("action", "")

        if action == "toggle":
            enabled = form.get("enabled") == "1"
            set_tts_enabled(gid, enabled)
            flash(request, f"TTS読み上げを{'有効' if enabled else '無効'}にしました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "toggle_vc_notify":
            vc_notify = form.get("vc_notify") == "1"
            set_tts_vc_notify(gid, vc_notify)
            flash(request, f"VC参加・退出アナウンスを{'有効' if vc_notify else '無効'}にしました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "set_vc":
            raw = form.get("vc_channel_id", "")
            settings = get_tts_settings(gid)
            watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
            if raw == "0" or not raw:
                set_tts_channels(gid, watch_ids, None)
                flash(request, "VCチャンネルを解除しました。", "success")
            else:
                try:
                    vc_id = int(raw)
                    if vc_id <= 0:
                        raise ValueError
                except (TypeError, ValueError):
                    flash(request, "無効なチャンネルIDです。", "danger")
                    return RedirectResponse(_REDIRECT, status_code=303)
                set_tts_channels(gid, watch_ids, vc_id)
                flash(request, "VCチャンネルを保存しました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "add_watch":
            raw = form.get("channel_id", "")
            try:
                ch_id = int(raw)
                if ch_id <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                flash(request, "無効なチャンネルIDです。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            settings = get_tts_settings(gid)
            watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", [])]
            if ch_id not in watch_ids:
                watch_ids.append(ch_id)
            set_tts_channels(gid, watch_ids, settings.get("vc_channel_id"))
            flash(request, "読み上げチャンネルを追加しました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "remove_watch":
            raw = form.get("channel_id", "")
            try:
                ch_id = int(raw)
            except (TypeError, ValueError):
                flash(request, "無効なチャンネルIDです。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            settings = get_tts_settings(gid)
            watch_ids = [int(cid) for cid in settings.get("watch_channel_ids", []) if int(cid) != ch_id]
            set_tts_channels(gid, watch_ids, settings.get("vc_channel_id"))
            flash(request, "チャンネルを読み上げ対象から削除しました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "set_defaults":
            voice = sanitize(form.get("default_voice", ""), 100).strip()
            if voice:
                available = await fetch_voices()
                if available and voice not in available:
                    flash(request, f"「{voice}」は利用可能な声に含まれていません。", "danger")
                    return RedirectResponse(_REDIRECT, status_code=303)
            try:
                rate = validate_int(form.get("default_rate", "200"), min_val=100, max_val=400)
            except Exception:
                flash(request, "速度は 100〜400 の範囲で指定してください。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            try:
                max_length = validate_int(form.get("max_length", "100"), min_val=10, max_val=500)
            except Exception:
                flash(request, "メッセージ字数制限は 10〜500 の範囲で指定してください。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            try:
                speak_max_length = validate_int(form.get("speak_max_length", "200"), min_val=10, max_val=500)
            except Exception:
                flash(request, "読み上げ最大文字数は 10〜500 の範囲で指定してください。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            read_name = form.get("read_name") == "1"
            if voice:
                set_tts_default_voice(gid, voice)
            set_tts_default_rate(gid, rate)
            set_tts_max_lengths(gid, max_length, speak_max_length)
            set_tts_read_name(gid, read_name)
            flash(request, "デフォルト設定を保存しました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "add_dict":
            word = sanitize(form.get("word", ""), 50).strip()
            reading = sanitize(form.get("reading", ""), 100).strip()
            if not word or not reading:
                flash(request, "単語と読みは両方必須です。", "warning")
                return RedirectResponse(_REDIRECT, status_code=303)
            add_tts_dictionary_entry(gid, word, reading)
            flash(request, f"辞書に「{word} → {reading}」を追加しました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "remove_dict":
            word = sanitize(form.get("word", ""), 50).strip()
            if remove_tts_dictionary_entry(gid, word):
                flash(request, f"「{word}」を辞書から削除しました。", "success")
            else:
                flash(request, f"「{word}」は辞書に見つかりませんでした。", "warning")
            return RedirectResponse(_REDIRECT, status_code=303)

        elif action == "reset_user":
            uid_raw = form.get("user_id", "")
            try:
                uid = int(uid_raw)
            except (TypeError, ValueError):
                flash(request, "無効なユーザーIDです。", "danger")
                return RedirectResponse(_REDIRECT, status_code=303)
            reset_user_tts_settings(gid, uid)
            flash(request, f"ユーザー {uid} の声設定をリセットしました。", "success")
            return RedirectResponse(_REDIRECT, status_code=303)

        flash(request, "不明なアクションです。", "warning")
        return RedirectResponse(_REDIRECT, status_code=303)

    text_channels, voice_channels, available_voices = await asyncio.gather(
        get_guild_channels(gid),
        get_guild_voice_channels(gid),
        fetch_voices(),
    )
    ctx = _tts_context(gid, text_channels, voice_channels, available_voices)
    return render(request, "settings/tts.html", **ctx)
