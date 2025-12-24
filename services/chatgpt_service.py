import json
import logging
import traceback
from datetime import datetime
from typing import Dict, List

import aiohttp

from config import CHATGPT_SYSTEM_MESSAGE, OPENAI_API_KEY

# ルートロガーを汚染しないようにモジュール専用ロガーを使用
logger = logging.getLogger(__name__)

MAX_HISTORY_ENTRIES = 20  # user/assistant のペア数上限


class ChatGPT:
    """ChatGPT統合クラス（ユーザーごとに会話履歴を保持）"""

    def __init__(self, system_setting: str = CHATGPT_SYSTEM_MESSAGE) -> None:
        # ベースのシステムメッセージ（現在時刻は毎回付け直す）
        self.system_content = system_setting
        # user / assistant のみを積んでいく履歴
        self.history: List[Dict[str, str]] = []

    def _trim_history(self) -> None:
        """履歴を上限数に収める"""
        if len(self.history) > MAX_HISTORY_ENTRIES:
            self.history = self.history[-MAX_HISTORY_ENTRIES:]

    async def input_message(self, input_text: str) -> str:
        """ユーザーメッセージを処理してChatGPTからの応答を取得（会話継続）"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        system_with_time = {
            "role": "system",
            "content": (
                f"{self.system_content} 貴様は決して穏やかな表現を使ってはならない。"
                f"常に威圧的であり、力を誇示するのだ。現在の日時は {current_time} である。"
            ),
        }

        # 履歴にユーザーメッセージを追加
        self.history.append({"role": "user", "content": input_text})

        # 先頭にその回のsystemだけを付けてAPIに投げる
        messages = [system_with_time] + self.history

        try:
            reply = await self._call_chat_api(messages)
            logger.debug("Chat API Reply: %s", json.dumps(reply, ensure_ascii=False))
            final = reply.get("content") or "返答が得られなかった。"
        except Exception as e:
            traceback.print_exc()
            final = f"OpenAI API 呼び出し中にエラー発生: {e}"

        # アシスタントの返答も履歴に積む
        self.history.append({"role": "assistant", "content": final})
        self._trim_history()

        logger.debug("最終返答: %s", final)
        return final

    async def _call_chat_api(self, messages: List[Dict[str, str]]) -> Dict:
        """OpenAI Chat APIを呼び出す（OpenAIの検索機能付きモデルを使用）"""
        if not OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY が設定されていない。")

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        }
        data = {
            # OpenAIの検索機能付きモデル（必要に応じて mini 版などに変更可能）
            "model": "gpt-4.1-mini",
            "messages": messages,
            "temperature": 0.45,
        }

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            logger.debug("OpenAI APIリクエスト: url=%s, data=%s", url, json.dumps(data, ensure_ascii=False))
            async with session.post(url, headers=headers, json=data) as resp:
                try:
                    result = await resp.json()
                except aiohttp.ContentTypeError:
                    text = await resp.text()
                    raise RuntimeError(
                        f"OpenAI API error ({resp.status}): unexpected content-type, body={text[:300]}"
                    )

                logger.debug("OpenAI APIレスポンス: status=%s, body=%s", resp.status, json.dumps(result, ensure_ascii=False))
                # エラー時は例外を投げる
                if resp.status != 200:
                    message = result.get("error", {}).get("message", str(result))
                    raise RuntimeError(f"OpenAI API error ({resp.status}): {message}")
                return result["choices"][0]["message"]
