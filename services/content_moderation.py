import logging
from typing import Any, Dict, List

from groq import AsyncGroq

from config import GROQ_API_KEY
from services.groq_client import create_chat_completion, get_groq_client
from services.virustotal_service import MALICIOUS_THRESHOLD

logger = logging.getLogger(__name__)

_GROQ_BUCKET = "moderation"


def _get_groq_client() -> AsyncGroq:
    return get_groq_client(timeout=20.0, bucket=_GROQ_BUCKET)


async def gpt_assess(
    text: str,
    vt_results: List[Dict[str, Any]],
    spam_count: int = 0,
    min_interval: float = float("inf"),
    is_new_member: bool = False,
) -> str:
    for r in vt_results:
        mal = int(r.get("malicious", 0) or 0)
        sus = int(r.get("suspicious", 0) or 0)
        if mal >= MALICIOUS_THRESHOLD:
            return "DANGEROUS"
        if mal > 0 or sus > 0:
            return "SUSPICIOUS"

    if not GROQ_API_KEY:
        return "SAFE"

    context_lines: list[str] = []
    if spam_count >= 4:
        context_lines.append(
            f"【スパム警告】このユーザーは直近15秒間に{spam_count}回メッセージを送信しています。"
        )
    if min_interval != float("inf") and min_interval < 2.0:
        context_lines.append(
            f"【高頻度】メッセージ送信間隔が最短{min_interval:.1f}秒と非常に短いです。"
        )
    if is_new_member:
        context_lines.append("【新規】このユーザーはサーバー参加から7日未満の新規メンバーです。")

    context_block = ("\n".join(context_lines) + "\n\n") if context_lines else ""

    prompt = (
        "あなたはDiscordサーバーのセキュリティモデレーションAIです。\n"
        "以下の情報をもとに投稿を判定し、DANGEROUS / SUSPICIOUS / SAFE のいずれか1語のみで回答してください。\n\n"
        "判定基準:\n"
        "- DANGEROUS: フィッシング詐欺、マルウェア拡散、レイド攻撃、明確な規約違反\n"
        "- SUSPICIOUS: スパム行動、不審なリンク、新規メンバーによる一方的な宣伝、疑わしい内容\n"
        "- SAFE: 通常のコミュニケーション\n\n"
        f"{context_block}"
        f"投稿内容:\n{text}"
    )

    try:
        response = await create_chat_completion(
            _get_groq_client(),
            bucket=_GROQ_BUCKET,
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "system", "content": "You are a security moderation AI. Reply with only one word: DANGEROUS, SUSPICIOUS, or SAFE."},
                {"role": "user", "content": prompt},
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
