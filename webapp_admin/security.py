import secrets

from fastapi import HTTPException, Request

MAX_STR_LEN = 2000


class _NeedsLogin(Exception):
    pass


class _NeedsGuild(Exception):
    pass


async def check_login(request: Request) -> None:
    if "user" not in request.session:
        raise _NeedsLogin()


async def check_guild(request: Request) -> None:
    if "user" not in request.session:
        raise _NeedsLogin()
    if "guild_id" not in request.session:
        raise _NeedsGuild()


async def check_csrf(request: Request) -> None:
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    form = await request.form()
    token = str(form.get("csrf_token", "") or request.headers.get("X-CSRFToken", ""))
    expected = request.session.get("_csrf_token", "")
    if not expected:
        # セッションにトークンがない = 未ログインまたはセッション切れ。
        # check_login が同じ依存関係として 303 リダイレクトを処理するため、
        # ここでは 403 を返さない（エラー画面でなくログイン画面に戻す）。
        return
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403)


def sanitize(s: str, max_len: int = MAX_STR_LEN) -> str:
    if not isinstance(s, str):
        return ""
    s = s.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    return s[:max_len]


def validate_channel_id(value) -> int:
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v
    except (TypeError, ValueError):
        raise HTTPException(status_code=400)


def validate_int(value, min_val: int = 0, max_val: int = 2 ** 63) -> int:
    try:
        v = int(value)
        if not (min_val <= v <= max_val):
            raise ValueError
        return v
    except (TypeError, ValueError):
        raise HTTPException(status_code=400)


def validate_choice(value: str, choices: set) -> str:
    if value not in choices:
        raise HTTPException(status_code=400)
    return value
