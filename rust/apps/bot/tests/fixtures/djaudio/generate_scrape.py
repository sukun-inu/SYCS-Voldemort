"""SoundCloud の client_id をページから探す段（`_scrape_sc_client_id_via_aiohttp`）の基準（scrape_expected.jsonl）を、
本物の Python から作る。

本物の関数の `aiohttp.ClientSession` を、例の台本どおりに答える偽物に差し替える（本物の SoundCloud には行かない）。
ページの HTML と、スクリプトの URL ごとの中身を台本で決め、取りに行った URL の順と、見つけた client_id を書き出す。

- URL の ``http://fake.invalid`` は、Rust のテストでは偽物のサーバーの場所に置き換える（ここではそのまま使う）
- 台本で中身が ``null`` の URL と、``http`` で始まらない URL（相対の URL）は、取りに行くと失敗する（aiohttp は
  基準の URL の無いセッションに相対の URL を渡すと `InvalidUrlClientError`）
- ページの台本が ``null`` なら、ページを取りに行くところで失敗する

1 行に 1 例。``[例, 取りに行った URL の並び, 見つけた client_id]``:

    python generate_scrape.py > scrape_expected.jsonl
"""

import asyncio
import json
import os
import sys
import tempfile

import aiohttp

os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp()
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp()
os.environ["SETTINGS_BACKEND"] = "file"
sys.path.insert(0, "/app")
from services import djaudio_service  # noqa: E402

PAGE = "https://soundcloud.com"
ID = ["a" * 32, "b" * 32, "c" * 32]


class FakeResponse:
    """台本の中身を返す応答。"""

    def __init__(self, text):
        """中身を覚える。"""
        self._text = text
        self.status = 200

    async def __aenter__(self):
        """`async with` で使う。"""
        return self

    async def __aexit__(self, *exc):
        """何もしない。"""
        return False

    async def text(self):
        """中身。"""
        return self._text


def make_session_class(case, fetched):
    """例の台本で答える偽物の ClientSession を作る。"""

    class FakeSession:
        """取りに行った URL を記録し、台本の中身を返す。"""

        def __init__(self, *args, **kwargs):
            """名乗りと時間切れは受け取るだけ。"""

        async def __aenter__(self):
            """`async with` で使う。"""
            return self

        async def __aexit__(self, *exc):
            """何もしない。"""
            return False

        def get(self, url):
            """URL を記録し、台本の中身（無ければ失敗）を返す。"""
            fetched.append(url)
            if url == PAGE:
                body = case["page"]
            elif not url.startswith("http"):
                raise aiohttp.InvalidUrlClientError(url)
            else:
                body = case["scripts"].get(url)
            if body is None:
                raise aiohttp.ClientConnectionError(f"failed: {url}")
            return FakeResponse(body)

    return FakeSession


def page_with(urls):
    """スクリプトの URL を並べたページ。"""
    return "<html>" + "".join(f'<script src="{u}"></script>' for u in urls) + "</html>"


def cases():
    """例の一覧。"""
    many = [f"http://fake.invalid/s{i}.js" for i in range(1, 15)]
    js = lambda cid: f'var x={{client_id:"{cid}"}};'  # noqa: E731
    return [
        {
            "id": "one",
            "page": page_with(["http://fake.invalid/a.js"]),
            "scripts": {"http://fake.invalid/a.js": js(ID[0])},
        },
        {
            "id": "last-first",
            "page": page_with(["http://fake.invalid/a.js", "http://fake.invalid/b.js", "http://fake.invalid/c.js"]),
            "scripts": {
                "http://fake.invalid/a.js": js(ID[0]),
                "http://fake.invalid/b.js": "nothing",
                "http://fake.invalid/c.js": js(ID[2]),
            },
        },
        {
            "id": "only-last-12",
            "page": page_with(many),
            "scripts": {**{u: "nothing" for u in many}, many[0]: js(ID[0]), many[1]: js(ID[1])},
        },
        {
            "id": "twelfth-from-the-end",
            "page": page_with(many),
            "scripts": {**{u: "nothing" for u in many}, many[2]: js(ID[2])},
        },
        {
            "id": "failing-scripts-are-skipped",
            "page": page_with(["http://fake.invalid/a.js", "http://fake.invalid/b.js", "http://fake.invalid/c.js"]),
            "scripts": {
                "http://fake.invalid/a.js": js(ID[0]),
                "http://fake.invalid/b.js": None,
                "http://fake.invalid/c.js": None,
            },
        },
        {
            "id": "relative-urls-fail",
            "page": page_with(["http://fake.invalid/a.js", "/rel.js"]),
            "scripts": {"http://fake.invalid/a.js": js(ID[1])},
        },
        {"id": "no-scripts", "page": "<html>no scripts</html>", "scripts": {}},
        {"id": "page-fails", "page": None, "scripts": {}},
        {
            "id": "pattern-order",
            "page": page_with(["http://fake.invalid/a.js"]),
            "scripts": {"http://fake.invalid/a.js": f'client_id = "{ID[0]}" ; client_id: "{ID[1]}"'},
        },
        {
            "id": "duplicates",
            "page": page_with(["http://fake.invalid/a.js", "http://fake.invalid/a.js"]),
            "scripts": {"http://fake.invalid/a.js": "nothing"},
        },
    ]


async def main():
    """全部の例を回して、1 行に 1 例ずつ書き出す。"""
    djaudio_service._SC_ENV_CLIENT_ID = ""
    for case in cases():
        fetched = []
        djaudio_service.aiohttp.ClientSession = make_session_class(case, fetched)
        found = await djaudio_service._scrape_sc_client_id_via_aiohttp()
        print(json.dumps([case, fetched, found], ensure_ascii=False, separators=(",", ":")))


asyncio.run(main())
