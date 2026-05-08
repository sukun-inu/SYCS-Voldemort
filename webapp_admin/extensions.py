import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
_LIMITER_STORAGE_URI = os.getenv("ADMIN_LIMITER_STORAGE_URI", "memory://")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute"],
    storage_uri=_LIMITER_STORAGE_URI,
)
