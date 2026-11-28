"""偽物の Deezer（基準づくりで本物の Python を当てる相手。Rust のテストも同じ台本で同じ偽物を立てる）。

台本は規則の並び。要求のパス（`?` より前）が `path` と同じ（`path_prefix` ならそれで始まる）で、`q` があれば
検索語（クエリの q を `urllib.parse.parse_qs` で読んだもの）も同じ規則のうち、最初のものの応答を返す。
どれにも当たらなければ 404。

応答: status（既定 200）・headers（既定は Content-Type: application/json）・body（文。`{BASE}` は偽物の
場所に置き換える）か body_b64（バイト列）・delay（頭を返す前に待つ秒）・body_delay（頭のあと本文の前に
待つ秒）・close（何も返さずに切る）。
"""

import asyncio
import base64
from urllib.parse import parse_qs


def match_rule(rules, target):
    """要求の行のパスとクエリ（target）に当たる最初の規則を返す。"""
    path, _, query = target.partition("?")
    q = parse_qs(query, keep_blank_values=True).get("q", [None])[0]
    for rule in rules:
        if rule.get("path") is not None and rule["path"] != path:
            continue
        if rule.get("path_prefix") is not None and not path.startswith(rule["path_prefix"]):
            continue
        if "q" in rule and rule["q"] != q:
            continue
        return rule
    return None


def build_response(response, base):
    """応答の頭と本文のバイト列を作る。"""
    if "body_b64" in response:
        body = base64.b64decode(response["body_b64"])
    else:
        body = response.get("body", "").replace("{BASE}", base).encode("utf-8")
    headers = response.get("headers", {"Content-Type": "application/json"})
    lines = [f"HTTP/1.1 {response.get('status', 200)} X", f"Content-Length: {len(body)}", "Connection: close"]
    for key, value in headers.items():
        lines.append(f"{key}: {value.replace('{BASE}', base)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head, body


class FakeDeezer:
    """127.0.0.1 の空いているポートに立つ偽物。届いた要求の行（パスとクエリ）を順に覚える。"""

    def __init__(self, rules):
        """台本を受け取る。"""
        self.rules = rules
        self.requests = []
        self.base = ""
        self._server = None

    async def start(self):
        """待ち受けを始める。"""
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"

    async def stop(self):
        """待ち受けを止める。"""
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader, writer):
        """1 つの接続に答える。"""
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            writer.close()
            return
        target = head.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin-1")
        self.requests.append(target)
        rule = match_rule(self.rules, target)
        response = rule["response"] if rule else {"status": 404, "body": ""}
        try:
            if response.get("close"):
                return
            await asyncio.sleep(response.get("delay", 0))
            head_bytes, body = build_response(response, self.base)
            writer.write(head_bytes)
            await writer.drain()
            await asyncio.sleep(response.get("body_delay", 0))
            writer.write(body)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
