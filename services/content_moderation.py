import logging
from typing import Any, Dict, List

import aiohttp

from config import OPENAI_API_KEY
from services.virustotal_service import MALICIOUS_THRESHOLD

logger = logging.getLogger(__name__)


async def gpt_assess(text: str, vt_results: List[Dict[str, Any]]) -> str:
    for r in vt_results:
        mal = int(r.get("malicious", 0) or 0)
        sus = int(r.get("suspicious", 0) or 0)
        if mal >= MALICIOUS_THRESHOLD:
            return "DANGEROUS"
        if mal > 0 or sus > 0:
            return "SUSPICIOUS"

    if not OPENAI_API_KEY:
        return "SAFE"

    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "gpt-5-mini",
        "messages": [
            {"role": "system", "content": "You are a security moderation AI."},
            {"role": "user", "content": f"以下の投稿を判定してください:\n{text}"},
        ],
    }

    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload) as r:
                data = await r.json()
                reply = data["choices"][0]["message"]["content"].upper()
    except Exception as e:
        logger.warning("[SECURITY] GPT判定失敗: %s", e)
        return "UNKNOWN"

    if "DANGEROUS" in reply:
        return "DANGEROUS"
    if "SUSPICIOUS" in reply or "WARNING" in reply:
        return "SUSPICIOUS"
    return "SAFE"
