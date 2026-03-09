import asyncio
import json
import logging

from pywebpush import WebPushException, webpush

from .vapid_service import VapidConfig, load_vapid_config

logger = logging.getLogger(__name__)
_cached_config: VapidConfig | None = None


def refresh_vapid_config() -> VapidConfig:
    global _cached_config
    _cached_config = load_vapid_config()
    return _cached_config


def _get_vapid_config() -> VapidConfig:
    global _cached_config
    if _cached_config is None:
        _cached_config = load_vapid_config()
    return _cached_config


def get_vapid_public_key() -> str | None:
    return _get_vapid_config().public_key


def is_push_enabled() -> bool:
    config = _get_vapid_config()
    return bool(config.public_key and config.private_key and config.subject)


def build_push_payload(*, title: str, body: str, url: str = "./") -> str:
    payload = {
        "title": title,
        "body": body,
        "url": url,
        "tag": "metal-daily-delta",
    }
    return json.dumps(payload, ensure_ascii=False)


async def send_push(subscription: dict, payload: str) -> tuple[bool, bool]:
    """
    Returns:
      - success: 送信成功
      - remove_subscription: 404/410 等で購読削除すべき
    """
    config = _get_vapid_config()
    if not config.private_key or not config.subject:
        return False, False

    try:
        await asyncio.to_thread(
            webpush,
            subscription_info=subscription,
            data=payload,
            vapid_private_key=config.private_key,
            vapid_claims={"sub": config.subject},
        )
        return True, False
    except WebPushException as exc:
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code in {404, 410}:
            return False, True
        logger.warning("WebPush送信エラー: status=%s message=%s", status_code, str(exc))
        return False, False
    except Exception:
        logger.exception("WebPush送信中に想定外エラー")
        return False, False
