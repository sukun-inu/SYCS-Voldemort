import hashlib
import logging
from typing import Any, Dict, List

from groq import AsyncGroq

from config import GROQ_API_KEY
from envutil import env_int
from services.groq_client import create_chat_completion, get_groq_client
from services.ttl_cache import TTLCache
from services.virustotal_service import MALICIOUS_THRESHOLD

logger = logging.getLogger(__name__)

_GROQ_BUCKET = "moderation"

# 同じ入力に対する判定を短く覚えておく時間（秒）。
#
# gpt_assess は**メッセージ1件ごとに**呼ばれる。Groq 側は「同時3件・最小
# 間隔0.25秒」で絞ってあるので、混んだチャンネルでは順番待ちが積み上がり、
# そのあいだ security ハンドラが返らない。連投・コピペ荒らしはまったく同じ
# 入力で来るので、そこだけでも呼ばずに済ませる。
#
# **判定は弱めない。** 同じ入力に同じモデルが違う答えを返す前提は置いて
# いないので、使い回しても結論は変わらない。逆に「短いから安全だろう」と
# いった推測では減らさない（どこで線を引いても根拠が無く、それは判定を
# 弱める設定になる）。
MODERATION_CACHE_TTL = env_int("MODERATION_CACHE_TTL_SECONDS", 300, minimum=10)
_verdict_cache: TTLCache[str, str] = TTLCache(ttl=MODERATION_CACHE_TTL, max_entries=2000)


def _verdict_key(text: str, vt_results: List[Dict[str, Any]], context_block: str) -> str:
    """判定を使い回してよい範囲を表す鍵。

    本文だけでは足りない。スパム回数・新規メンバーかどうかはプロンプトへ
    入るので、同じ文でも状況が違えば別の答えが出うる（context_block が
    そこを表している）。VirusTotal の結果も判断材料なので混ぜる。
    """
    vt_digest = "|".join(f"{r.get('malicious', 0)}/{r.get('suspicious', 0)}" for r in vt_results)
    material = chr(0).join((context_block, vt_digest, text))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _get_groq_client() -> AsyncGroq:
    """モデレーション専用のbucket("moderation")でGroqクライアントを取得する。"""
    return get_groq_client(timeout=20.0, bucket=_GROQ_BUCKET)


async def gpt_assess(
    text: str,
    vt_results: List[Dict[str, Any]],
    spam_count: int = 0,
    min_interval: float = float("inf"),
    is_new_member: bool = False,
) -> str:
    """投稿を DANGEROUS / SUSPICIOUS / SAFE / UNKNOWN のいずれかに判定する。

    VirusTotalで既に危険と分かっているならLLMには回さず即断する（判定の
    信頼性が高い上、無駄なAPI呼び出しを避けられる）。GROQ_API_KEY が無い
    環境では SAFE を返す（UNKNOWNではない）——LLM判定が使えないことを
    「疑わしい」ではなく「判定機能自体が無効」として扱う設計。逆に、
    キーはあるのに呼び出し自体が失敗した場合は UNKNOWN を返し、
    呼び出し元（security_service.gpt_icon）でSUSPICIOUSと同じ警戒表示に
    倒す。「判定できなかった」を「安全」と混同しないため。
    """
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
        context_lines.append(f"【スパム警告】このユーザーは直近15秒間に{spam_count}回メッセージを送信しています。")
    if min_interval != float("inf") and min_interval < 2.0:
        context_lines.append(f"【高頻度】メッセージ送信間隔が最短{min_interval:.1f}秒と非常に短いです。")
    if is_new_member:
        context_lines.append("【新規】このユーザーはサーバー参加から7日未満の新規メンバーです。")

    context_block = ("\n".join(context_lines) + "\n\n") if context_lines else ""

    # 判じるものが何も無いなら呼ばない。画像だけの投稿などで実際に起きる。
    # 空の本文を「危険か」と尋ねても材料が無く、返るのは常に SAFE である。
    if not text.strip() and not vt_results:
        return "SAFE"

    cache_key = _verdict_key(text, vt_results, context_block)
    cached = _verdict_cache.get(cache_key)
    if cached is not None:
        return cached

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
                {
                    "role": "system",
                    "content": (
                        "You are a security moderation AI. " "Reply with only one word: DANGEROUS, SUSPICIOUS, or SAFE."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        )
        reply = response.choices[0].message.content.upper()
    except Exception as e:
        logger.warning("[SECURITY] Groq判定失敗: %s", e)
        # 失敗は覚えない。覚えると、次の同じ投稿も判定されないまま通る。
        return "UNKNOWN"

    if "DANGEROUS" in reply:
        verdict = "DANGEROUS"
    elif "SUSPICIOUS" in reply or "WARNING" in reply:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    _verdict_cache.set(cache_key, verdict)
    return verdict
