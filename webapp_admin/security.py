import secrets

from fastapi import HTTPException, Request

from envutil import env_str

MAX_STR_LEN = 2000


class _NeedsLogin(Exception):
    pass


class _NeedsGuild(Exception):
    pass


async def check_login(request: Request) -> None:
    """FastAPI の Depends 用。ログイン必須なルートに付ける。

    未ログインは 401/403 ではなく `_NeedsLogin` を投げる。app.py の
    exception_handler がこれを拾って /admin/login へ 303 リダイレクトする
    ので、エラー画面ではなくログイン画面に落ちる。
    """
    if "user" not in request.session:
        raise _NeedsLogin()


async def check_guild(request: Request) -> None:
    """FastAPI の Depends 用。ログイン済み・ギルド選択済みの両方を要求する。

    check_login と同じくエラーではなく専用の例外（`_NeedsGuild`）で分岐し、
    app.py の exception_handler が /admin/guilds へ 303 で戻す。ここでは
    「セッションに guild_id が入っているか」しか見ておらず、その利用者が
    今もそのギルドの管理者かどうかまでは確認しない（それは呼び出し側が
    auth.user_still_admin() で個別に行う）。
    """
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
    """状態を変える HTTP メソッドに CSRF トークンを要求する。判定できないときは通さない。

    フォームの `csrf_token` とヘッダ `X-CSRFToken` の両方を見る（fetch する
    JSON API と、素の <form> POST の両方から呼ばれるため）。
    """
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
    """自由記述の設定値（メッセージ本文など）をDB・テンプレートへ渡せる形に削る。

    文字列でない入力は例外を出さず空文字にする（呼び出し側の request.form()
    は型を保証しないため）。NUL は SQLite/Postgres の text カラムに書けずに
    落ちることがあるので除去し、改行は \n へ統一する。長さを切るのは、
    上限の無い自由入力を無制限にDBへ書かせないため（他の設定値と揃え、
    保存先の想定サイズを超えさせない）。
    """
    if not isinstance(s, str):
        return ""
    s = s.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    return s[:max_len]


def validate_channel_id(value) -> int:
    """チャンネルIDとして受け取れる形（正の整数）かを確かめる。ダメなら 400。

    フォーム経由の値は常に文字列で来るため int() 変換自体が失敗しうるうえ、
    0 や負値は Discord の ID として存在しない。ここで弾かず後段まで通すと、
    存在しないチャンネルIDが設定として保存されてしまう。
    """
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v
    except (TypeError, ValueError):
        raise HTTPException(status_code=400)


def validate_int(value, min_val: int = 0, max_val: int = 2**63) -> int:
    """指定した範囲に収まる整数だけを受け付ける。範囲外・変換不能なら 400。

    max_val の既定値 2**63 は用途を選ばない緩い上限であり、意味のある上限
    （例: 秒数・件数の実用範囲）がある呼び出し側は自分で min_val/max_val を
    渡すこと。範囲チェックを省略すると、極端に大きい値がそのまま設定へ
    書き込まれ、他の場所（表示・計算）で桁あふれや異常な待ち時間を起こす。
    """
    try:
        v = int(value)
        if not (min_val <= v <= max_val):
            raise ValueError
        return v
    except (TypeError, ValueError):
        raise HTTPException(status_code=400)


def validate_choice(value: str, choices: set) -> str:
    """事前に決めた選択肢（enum・select の choices）以外を弾く。範囲外なら 400。

    フォームは任意の文字列を送れるため、テンプレート側の <select> に無い
    値が届いてもここを通らなければ弾かれない。呼び出し側で choices を
    渡し忘れると素通りしてしまうので、選択式のフィールドは必ずここを通すこと。
    """
    if value not in choices:
        raise HTTPException(status_code=400)
    return value
