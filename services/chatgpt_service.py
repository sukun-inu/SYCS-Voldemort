import logging
from datetime import datetime
from typing import Dict, List

from groq import AsyncGroq

from config import CHATGPT_SYSTEM_MESSAGE, GROQ_API_KEY, JST as _JST
from services.groq_client import create_chat_completion, get_groq_client

logger = logging.getLogger(__name__)

MAX_HISTORY_ENTRIES = 20
_GROQ_BUCKET = "chat"


def _get_groq_client() -> AsyncGroq:
    """会話AI専用のbucket("chat")でGroqクライアントを取得する。

    bucketを固定してここに集約しておくことで、他機能（コンテンツモデレーション・
    ニュース要約等）の呼び出しバーストとレート制限の枠を分離できる。
    """
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY が設定されていない。")
    return get_groq_client(timeout=30.0, bucket=_GROQ_BUCKET)


class ChatGPT:
    """Groq LLM統合クラス（ユーザーごとに会話履歴を保持）"""

    def __init__(self, system_setting: str = CHATGPT_SYSTEM_MESSAGE) -> None:
        """会話履歴をインスタンスの中に持つ。呼び出し側（chat_commands）は
        (guild_id, user_id) ごとに1つのインスタンスを使い回すことで、
        ユーザーごとの会話の文脈をプロセスが生きている間だけ保持する。
        """
        self.system_content = system_setting
        self.history: List[Dict[str, str]] = []

    def _trim_history(self) -> None:
        """履歴を直近 MAX_HISTORY_ENTRIES 件に切り詰める。無制限に積むと
        1リクエストごとのトークン数（＝レイテンシとコスト）が増え続けるため。
        """
        if len(self.history) > MAX_HISTORY_ENTRIES:
            self.history = self.history[-MAX_HISTORY_ENTRIES:]

    async def input_message(self, input_text: str) -> str:
        """1発言を履歴に積んで応答を得る。API呼び出しが失敗しても例外を
        外へ投げず、エラー内容を文字列にしてそのまま返答扱いで返す
        （呼び出し元のDiscordコマンドが例外処理を持たないため、ここで
        必ず文字列を返し切る）。失敗時のエラー文言も履歴に残る。
        """
        current_time = datetime.now(_JST).strftime("%Y-%m-%d %H:%M:%S")
        system_with_time = {
            "role": "system",
            "content": (
                f"{self.system_content}"
                f"穏やかな表現は使うな。威圧的かつ冷徹に、しかし簡潔に話せ。"
                f"（笑）（冷笑）などの括弧書きは使うな。現在の日時は {current_time} である。"
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
        """Groqへ1回問い合わせ、role/contentだけの辞書に絞って返す。
        レスポンスオブジェクトをそのまま履歴やログに持ち回さないための境界。
        """
        client = _get_groq_client()
        response = await create_chat_completion(
            client,
            bucket=_GROQ_BUCKET,
            model="openai/gpt-oss-120b",
            messages=messages,
            temperature=0.45,
        )
        msg = response.choices[0].message
        logger.debug("Groq APIレスポンス: %s", msg.content)
        return {"role": msg.role, "content": msg.content}
