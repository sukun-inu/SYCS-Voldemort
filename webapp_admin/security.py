from functools import wraps

from flask import abort, redirect, session, url_for

MAX_STR_LEN = 2000


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def guild_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login"))
        if "guild_id" not in session:
            return redirect(url_for("dashboard.guild_select"))
        return f(*args, **kwargs)
    return decorated


def sanitize(s: str, max_len: int = MAX_STR_LEN) -> str:
    if not isinstance(s, str):
        return ""
    return s.replace("\x00", "")[:max_len]


def validate_channel_id(value) -> int:
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v
    except (TypeError, ValueError):
        abort(400)


def validate_int(value, min_val: int = 0, max_val: int = 2 ** 63) -> int:
    try:
        v = int(value)
        if not (min_val <= v <= max_val):
            raise ValueError
        return v
    except (TypeError, ValueError):
        abort(400)


def validate_choice(value: str, choices: set) -> str:
    if value not in choices:
        abort(400)
    return value
