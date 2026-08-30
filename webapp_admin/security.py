import secrets

from fastapi import HTTPException, Request

from envutil import env_str

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


def is_dev_user(request: Request) -> bool:
    """ログイン中のユーザーが DEV_USER_ID と一致する「開発者」かどうか。

    開発者パネル (dev_views._check_dev) 本体の認可判定と、
    デスクトップUI（スタートメニューへの表示・直接URLアクセス時のリダイレクト可否）
    の両方から参照する単一の情報源。DEV_USER_ID 未設定時は常に False。
    """
    configured = dev_user_id()
    if not configured:
        return False
    user = request.session.get("user") or {}
    return str(user.get("id", "")) == configured


def dev_user_id() -> str:
    """設定されている DEV_USER_ID。未設定・空白のみなら空文字。

    「開発者パネルが存在するか(404)」と「この人が開発者か(403)」の両方が
    この値を見る。読み方が分かれると、空白だけ設定したときに片方だけが
    「設定済み」と判断する食い違いになる。
    """
    return env_str("DEV_USER_ID", "") or ""


def issue_csrf_token(request: Request) -> str:
    """セッションに CSRF トークンが無ければ発行して返す。

    ログイン確定時（OAuth コールバック）と、HTML を返すときの両方から呼ぶ。
    以前は HTML 描画時にしか作られておらず、トークンが無いセッションでは
    check_csrf が素通りしていた。
    """
    token = request.session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        request.session["_csrf_token"] = token
    return token


async def check_csrf(request: Request) -> None:
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if "user" not in request.session:
        # 未ログイン。check_login / check_guild / check_dev が同じ依存関係として
        # 303 リダイレクトや 403 を返すので、ここでは判定しない
        # （エラー画面ではなくログイン画面へ戻したい）。
        return

    form = await request.form()
    token = str(form.get("csrf_token", "") or request.headers.get("X-CSRFToken", ""))
    expected = request.session.get("_csrf_token", "")
    # ログイン済みなのにトークンが無いセッションは、素通しせず必ず弾く。
    # 以前はここで return しており、CSRF 防御の全体が「その時点でトークンが
    # 存在すること」に依存していた（フェイルオープン）。
    if not expected or not token or not secrets.compare_digest(token, expected):
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


def validate_int(value, min_val: int = 0, max_val: int = 2**63) -> int:
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
