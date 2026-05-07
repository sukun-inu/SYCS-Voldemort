import logging
from datetime import datetime
from typing import Dict, List

from groq import AsyncGroq

from config import CHATGPT_SYSTEM_MESSAGE, GROQ_API_KEY, JST as _JST

logger = logging.getLogger(__name__)

MAX_HISTORY_ENTRIES = 20

_groq_client: AsyncGroq | None = None


def _get_groq_client() -> AsyncGroq:
    global _groq_client
    if _groq_client is None:
        if not GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY が設定されていない。")
        _groq_client = AsyncGroq(api_key=GROQ_API_KEY, timeout=30.0)
    return _groq_client


class ChatGPT:
    """Groq LLM統合クラス（ユーザーごとに会話履歴を保持）"""

    def __init__(self, system_setting: str = CHATGPT_SYSTEM_MESSAGE) -> None:
        self.system_content = system_setting
        self.history: List[Dict[str, str]] = []

    def _trim_history(self) -> None:
        if len(self.history) > MAX_HISTORY_ENTRIES:
            self.history = self.history[-MAX_HISTORY_ENTRIES:]

    async def input_message(self, input_text: str) -> str:
        current_time = datetime.now(_JST).strftime("%Y-%m-%d %H:%M:%S")
        system_with_time = {
            "role": "system",
            "content": (
                f"{self.system_content} 貴様は決して穏やかな表現を使ってはならない。"
                f"常に威圧的であり、力を誇示するのだ。現在の日時は {current_time} である。"
            ),
        }

        self.history.append({"role": "user", "content": input_text})
        messages = [system_with_time] + self.history

        try:
            reply = await self._call_chat_api(messages)
            final = reply.get("content") or "返答が得られなかった。"
        except Exception as e:
            logger.exception("Groq API 呼び出し中にエラー発生")
            final = f"Groq API 呼び出し中にエラー発生: {e}"

        self.history.append({"role": "assistant", "content": final})
        self._trim_history()

        logger.debug("最終返答: %s", final)
        return final

    async def _call_chat_api(self, messages: List[Dict[str, str]]) -> Dict:
        client = _get_groq_client()
        response = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.45,
        )
        msg = response.choices[0].message
        logger.debug("Groq APIレスポンス: %s", msg.content)
        return {"role": msg.role, "content": msg.content}
