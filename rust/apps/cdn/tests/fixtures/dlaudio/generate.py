"""配信（/dlaudio/）の基準（rust/apps/cdn/tests/dlaudio_golden.rs が読む expected.json）を、本物の Python から作る。

本番で /dlaudio/ を返しているのは管理画面のアプリ（webapp_admin.app。services/djaudio_cdn.py の dlaudio_router が
入っていて、レート制限・セキュリティの見出し・数・エラーの振り分けの層を通る）。それを starlette の TestClient で
回す。置き場（DJAUDIO_CACHE_DIR）は一時ディレクトリにし、例ごとに空にしてから cases.json のファイルを置き、決めた
順にリクエストを送って、応答の状態・見出し・本文と、例が終わったときに置き場に残ったファイルを書き出す。

- 時刻は止める（services/djaudio_cache.py と services/djaudio_cdn.py の datetime を差し替える。期限と残り時間）
- レート制限（slowapi。1 分 300 回）の数は、例ごとに空にする（limiter.reset()）
- 置いたファイルは、置いたバイトのまま（16 進）書き出す。Rust のテストは同じバイトを置く
- リクエストは、httpx が整えたあとのパスと、TestClient が付けた見出しのまま書き出す（Rust のテストは同じものを渡す）
- 本文は、ファイルの答え（Content-Disposition が付いたもの）なら 16 進、ほかは文字。HEAD は本文を見ない
- 例外で 500 になるもの（壊れた情報など）も、本番と同じく応答として受け取る（raise_server_exceptions=False）

あわせて、印と guild_id の確かめに使う str.isalnum() と str.isdigit() が真になる文字の範囲も書き出す（Rust の表が
Python と同じかを、全部の文字で確かめるため）。

作り直すとき（例を足したとき、Python の配信や管理画面の層を直したとき）は、リポジトリの直下で、本番と同じ依存
（requirements.txt）の Python 3.13 で:

    python rust/apps/cdn/tests/fixtures/dlaudio/generate.py
"""

import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
CACHE = tempfile.mkdtemp(prefix="cdn-golden-cache-")

# services/* は読み込んだときに環境変数を読むので、import より前に決める（tests/test_admin_api.py と同じ）。
os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="cdn-golden-settings-")
os.environ["DJAUDIO_CACHE_DIR"] = CACHE
os.environ["ADMIN_FLASK_SECRET_KEY"] = "x" * 64
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"
for _name in ("FLASK_SECURE_COOKIES", "ADMIN_LIMITER_STORAGE_URI", "VALKEY_URL", "SETTINGS_BACKEND"):
    os.environ.pop(_name, None)
sys.path.insert(0, ROOT)

from starlette.testclient import TestClient  # noqa: E402

from services import djaudio_cache, djaudio_cdn  # noqa: E402
from webapp_admin.app import app  # noqa: E402
from webapp_admin.extensions import limiter  # noqa: E402


class FrozenClock:
    """services の `datetime.now(timezone.utc)` を、決めた時刻に止める（差し替える datetime の代わり）。"""

    def __init__(self, now):
        """止める時刻（UNIX 時間の秒）を受け取る。"""
        self.fixed = datetime.fromtimestamp(now, timezone.utc)

    def now(self, tz=None):
        """止めた時刻を返す（services は UTC でしか呼ばない）。"""
        return self.fixed


def file_bytes(spec):
    """cases.json の 1 ファイルぶんの中身をバイトにする（json・text・hex のどれか）。"""
    if "json" in spec:
        return json.dumps(spec["json"], ensure_ascii=False).encode("utf-8")
    if "text" in spec:
        return spec["text"].encode("utf-8")
    return bytes.fromhex(spec["hex"])


def place(files):
    """置き場を空にして例のファイルを置き、置いたものを Rust が同じに置ける形（16 進・ディレクトリ）で返す。"""
    shutil.rmtree(CACHE)
    os.makedirs(CACHE)
    placed = []
    for spec in files:
        path = os.path.join(CACHE, spec["name"])
        if spec.get("dir"):
            os.makedirs(path)
            placed.append({"name": spec["name"], "dir": True})
            continue
        content = file_bytes(spec)
        with open(path, "wb") as f:
            f.write(content)
        placed.append({"name": spec["name"], "hex": content.hex()})
    return placed


def send(client, step):
    """1 つのリクエストを（repeat 回）送り、最後の応答を返す。付け替え（307）は追わない。"""
    response = None
    for _ in range(step.get("repeat", 1)):
        response = client.request(step["method"], step["path"], headers=step.get("headers", {}), follow_redirects=False)
    return response


def record_request(response):
    """実際に送ったリクエスト（パスと問い合わせは httpx が整えたあとの形。見出しは TestClient が付けたものも含む）。"""
    request = response.request
    return {
        "method": request.method,
        "target": request.url.raw_path.decode("ascii"),
        "headers": [[name.lower(), value] for name, value in request.headers.multi_items()],
    }


def record_response(response, method):
    """応答の状態・見出し・本文（ファイルなら 16 進、ほかは文字、HEAD は見ない）。"""
    out = {
        "status": response.status_code,
        "headers": [[name.lower(), value] for name, value in response.headers.multi_items()],
    }
    if method == "HEAD":
        out["body"] = None
    elif "content-disposition" in response.headers:
        out["body_hex"] = response.content.hex()
    else:
        out["body"] = response.content.decode("utf-8")
    return out


def run_case(client, case):
    """1 つの例を回し、置いたもの・リクエストと応答・残ったファイルを返す。"""
    limiter.reset()
    placed = place(case.get("files", []))
    secure = case.get("secure_cookies", False)
    if secure:
        # 管理画面はリクエストのたびにこの変数を読んで HSTS を付ける。
        os.environ["FLASK_SECURE_COOKIES"] = "true"
    steps = []
    try:
        for step in case["requests"]:
            response = send(client, step)
            entry = {"request": record_request(response), "response": record_response(response, step["method"])}
            if step.get("repeat", 1) != 1:
                entry["repeat"] = step["repeat"]
            steps.append(entry)
    finally:
        os.environ.pop("FLASK_SECURE_COOKIES", None)
    return {
        "name": case["name"],
        "secure_cookies": secure,
        "placed": placed,
        "steps": steps,
        "remaining": sorted(os.listdir(CACHE)),
    }


def char_ranges(test):
    """test が真になる文字（サロゲートを除く）の範囲を、[始め, 終わり] の並びで返す。"""
    ranges = []
    start = None
    for code in range(0x110000):
        hit = not (0xD800 <= code <= 0xDFFF) and test(chr(code))
        if hit and start is None:
            start = code
        if not hit and start is not None:
            ranges.append([start, code - 1])
            start = None
    if start is not None:
        ranges.append([start, 0x10FFFF])
    return ranges


def main():
    """cases.json の例を全部回し、文字の範囲と一緒に expected.json に書く。"""
    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as f:
        data = json.load(f)
    now = data["now"]
    clock = FrozenClock(now)
    client = TestClient(app, raise_server_exceptions=False)
    with patch.object(djaudio_cache, "datetime", clock), patch.object(djaudio_cdn, "datetime", clock):
        cases = [run_case(client, case) for case in data["cases"]]
    result = {
        "now": now,
        "cases": cases,
        "chars": {"isalnum": char_ranges(str.isalnum), "isdigit": char_ranges(str.isdigit)},
    }
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(len(cases), "例,", sum(len(case["steps"]) for case in cases), "リクエスト")


if __name__ == "__main__":
    main()
