import json
import aiohttp
import traceback
import logging
from datetime import datetime
from config import OPENAI_API_KEY, CHATGPT_SYSTEM_MESSAGE

# デバッグログ設定（必要に応じてmain等で再設定可）
logging.basicConfig(level=logging.DEBUG)


class ChatGPT:
    """ChatGPT統合クラス（ユーザーごとに会話履歴を保持）"""
    
    def __init__(self, system_setting: str = CHATGPT_SYSTEM_MESSAGE):
        # ベースのシステムメッセージ（現在時刻は毎回付け直す）
        self.system_content = system_setting
        # user / assistant のみを積んでいく履歴
        self.history: list[dict] = []

    async def input_message(self, input_text: str) -> str:
        """ユーザーメッセージを処理してChatGPTからの応答を取得（会話継続）"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        system_with_time = {
            "role": "system",
            "content": f"{self.system_content} 貴様は決して穏やかな表現を使ってはならない。常に威圧的であり、力を誇示するのだ。現在の日時は {current_time} である。"
        }

        # 履歴にユーザーメッセージを追加
        self.history.append({"role": "user", "content": input_text})

        # 先頭にその回のsystemだけを付けてAPIに投げる
        messages = [system_with_time] + self.history

        try:
            reply = await self._call_chat_api(messages)
            logging.debug("Chat API Reply: %s", json.dumps(reply, ensure_ascii=False))
            final = reply.get("content") or "返答が得られなかった。"
        except Exception as e:
            traceback.print_exc()
            final = f"OpenAI API 呼び出し中にエラー発生: {e}"

        # アシスタントの返答も履歴に積む
        self.history.append({"role": "assistant", "content": final})

        logging.debug("最終返答: %s", final)
        return final

    async def _call_chat_api(self, messages: list) -> dict:
        """OpenAI Chat APIを呼び出す（OpenAIの検索機能付きモデルを使用）"""
        async with aiohttp.ClientSession() as session:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {OPENAI_API_KEY}"
            }
            data = {
                # OpenAIの検索機能付きモデル（必要に応じて mini 版などに変更可能）
                "model": "gpt-4o-search-preview",
                "messages": messages,
                "temperature": 0.45,
                # モデル側で必要に応じてWeb検索を行わせる
                "web_search_options": {}
            }

            logging.debug("OpenAI APIリクエスト: url=%s, headers=%s, data=%s", url, headers, json.dumps(data, ensure_ascii=False))
            async with session.post(url, headers=headers, json=data) as resp:
                result = await resp.json()
                logging.debug("OpenAI APIレスポンス: status=%s, body=%s", resp.status, json.dumps(result, ensure_ascii=False))
                # エラー時は例外を投げる
                if resp.status != 200:
                    message = result.get("error", {}).get("message", str(result))
                    raise RuntimeError(f"OpenAI API error ({resp.status}): {message}")
                return result["choices"][0]["message"]
