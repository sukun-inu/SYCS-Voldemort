import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_LIMITER_STORAGE_URI = os.getenv("ADMIN_LIMITER_STORAGE_URI", "memory://")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300/minute"],
    storage_uri=_LIMITER_STORAGE_URI,
)
