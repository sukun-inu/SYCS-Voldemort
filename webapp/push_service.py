import asyncio
import json
import logging
import os

from pywebpush import WebPushException, webpush

logger = logging.getLogger(__name__)


def get_vapid_public_key() -> str | None:
    value = os.getenv("VAPID_PUBLIC_KEY")
    return value.strip() if value else None


def _get_vapid_private_key() -> str | None:
    value = os.getenv("VAPID_PRIVATE_KEY")
    return value.strip() if value else None


def _get_vapid_subject() -> str | None:
    value = os.getenv("VAPID_SUBJECT")
    return value.strip() if value else None


def is_push_enabled() -> bool:
    return bool(get_vapid_public_key() and _get_vapid_private_key() and _get_vapid_subject())


def build_push_payload(*, title: str, body: str, url: str = "/") -> str:
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
    vapid_private_key = _get_vapid_private_key()
    vapid_subject = _get_vapid_subject()
    if not vapid_private_key or not vapid_subject:
        return False, False

    try:
        await asyncio.to_thread(
            webpush,
            subscription_info=subscription,
            data=payload,
            vapid_private_key=vapid_private_key,
            vapid_claims={"sub": vapid_subject},
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

