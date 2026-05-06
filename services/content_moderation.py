import logging
from typing import Any, Dict, List

from groq import AsyncGroq

from config import GROQ_API_KEY
from services.virustotal_service import MALICIOUS_THRESHOLD

logger = logging.getLogger(__name__)

_groq_client: AsyncGroq | None = None


def _get_groq_client() -> AsyncGroq:
    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncGroq(api_key=GROQ_API_KEY, timeout=20.0)
    return _groq_client


async def gpt_assess(text: str, vt_results: List[Dict[str, Any]]) -> str:
    for r in vt_results:
        mal = int(r.get("malicious", 0) or 0)
        sus = int(r.get("suspicious", 0) or 0)
        if mal >= MALICIOUS_THRESHOLD:
            return "DANGEROUS"
        if mal > 0 or sus > 0:
            return "SUSPICIOUS"

    if not GROQ_API_KEY:
        return "SAFE"

    try:
        response = await _get_groq_client().chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a security moderation AI."},
                {"role": "user", "content": f"以下の投稿を判定してください:\n{text}"},
            ],
        )
        reply = response.choices[0].message.content.upper()
    except Exception as e:
        logger.warning("[SECURITY] Groq判定失敗: %s", e)
        return "UNKNOWN"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply or "WARNING" in reply:
        return "SUSPICIOUS"
    return "SAFE"
