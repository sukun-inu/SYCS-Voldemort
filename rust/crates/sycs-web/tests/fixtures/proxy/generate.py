"""信頼するプロキシの読み方の基準（rust/crates/sycs-web/tests/proxy_golden.rs が読む expected.json）を作る。

Python の 3 つのアプリ（admin_main.py・web_main.py・cdn_main.py）は、uvicorn を proxy_headers=True・
forwarded_allow_ips=trusted_proxies() で起動している。その組を、本物の services/log_setup.trusted_proxies() と
本物の uvicorn（本番と同じ版）の ProxyHeadersMiddleware に通し、アプリに渡る接続元（request.client.host）と
scheme を書き出す。

例は、TRUSTED_PROXY_CIDRS の値（未設定・空・帯域・ネットマスク・ホストマスク・読めない値・*）と、直接つないで
きた相手と、X-Forwarded-For・X-Forwarded-Proto の組（複数・空・空白・ポート付き・大文字など）。

作り直すとき（例を足したとき、uvicorn を上げたとき）は、リポジトリの直下で本番と同じ依存の Python で:

    python rust/crates/sycs-web/tests/fixtures/proxy/generate.py
"""

import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
sys.path.insert(0, ROOT)

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware  # noqa: E402

from services.log_setup import trusted_proxies  # noqa: E402

# TRUSTED_PROXY_CIDRS を設定しない（既定になる）。
UNSET = None
XFF = "x-forwarded-for"
XFP = "x-forwarded-proto"

# (TRUSTED_PROXY_CIDRS, 直接つないできた相手〔None は分からない相手〕, [(見出し, 値), ...])
CASES = [
    (UNSET, "172.18.0.2", [(XFF, "203.0.113.5")]),
    (UNSET, "172.18.0.2", []),
    (UNSET, "203.0.113.9", [(XFF, "198.51.100.1")]),
    (UNSET, "127.0.0.1", [(XFF, "198.51.100.1, 172.18.0.1")]),
    (UNSET, "127.0.0.1", [(XFF, "198.51.100.40, 198.51.100.41")]),
    (UNSET, "127.0.0.1", [(XFF, "198.51.100.42, 172.18.0.5, 172.18.0.1")]),
    (UNSET, "127.0.0.1", [(XFF, "172.18.0.9, 172.18.0.1")]),
    (UNSET, "127.0.0.1", [(XFF, "10.0.0.1")]),
    (UNSET, "::1", [(XFF, "2001:db8::5")]),
    (UNSET, "172.18.0.2", [(XFF, "")]),
    (UNSET, "172.18.0.2", [(XFF, " , 198.51.100.2")]),
    (UNSET, "172.18.0.2", [(XFF, "198.51.100.2,")]),
    (UNSET, "172.18.0.2", [(XFF, "198.51.100.3:5678")]),
    # ポートの落とし方（数でないポート・括弧つきの IPv6・ポートつきの信頼する相手）。
    (UNSET, "172.18.0.2", [(XFF, "198.51.100.52:abc")]),
    (UNSET, "172.18.0.2", [(XFF, "[2001:db8::7]:8443")]),
    (UNSET, "172.18.0.2", [(XFF, "[2001:db8::8]")]),
    (UNSET, "127.0.0.1", [(XFF, "198.51.100.51, 172.18.0.1:9999")]),
    (UNSET, "172.18.0.2", [(XFF, "unknown")]),
    (UNSET, "172.18.0.2", [(XFF, "2001:DB8::A")]),
    (UNSET, "172.18.0.2", [(XFF, "::ffff:172.18.0.1")]),
    (UNSET, "172.18.0.2", [(XFF, "198.51.100.4"), (XFF, "198.51.100.5")]),
    (UNSET, "172.18.0.2", [(XFF, "\t198.51.100.6\xa0")]),
    (UNSET, "172.18.0.2", [(XFP, "https")]),
    (UNSET, "203.0.113.9", [(XFP, "https")]),
    (UNSET, "172.18.0.2", [(XFP, "HTTPS")]),
    (UNSET, "172.18.0.2", [(XFP, " https ")]),
    (UNSET, "172.18.0.2", [(XFP, "\xa0https\x85")]),
    (UNSET, "172.18.0.2", [(XFP, "wss")]),
    (UNSET, "172.18.0.2", [(XFP, "ftp")]),
    (UNSET, "172.18.0.2", [(XFP, "http"), (XFP, "https")]),
    (UNSET, "172.18.0.2", [(XFF, "198.51.100.7"), (XFP, "https")]),
    (UNSET, "172.31.255.255", [(XFF, "198.51.100.7")]),
    (UNSET, "172.32.0.1", [(XFF, "198.51.100.7")]),
    (UNSET, None, [(XFF, "198.51.100.8")]),
    ("", "172.18.0.2", [(XFF, "198.51.100.9")]),
    ("   ", "127.0.0.1", [(XFF, "198.51.100.9")]),
    ("*", "203.0.113.9", [(XFF, "198.51.100.10, 198.51.100.11"), (XFP, "https")]),
    ("*", None, [(XFF, "198.51.100.12")]),
    ("*,127.0.0.1", "203.0.113.9", [(XFF, "198.51.100.13")]),
    ("10.0.0.1/8", "10.0.0.1", [(XFF, "198.51.100.14")]),
    ("10.0.0.0/255.0.0.0", "10.1.2.3", [(XFF, "198.51.100.15")]),
    ("10.0.0.0/0.255.255.255", "10.1.2.3", [(XFF, "198.51.100.16")]),
    ("10.0.0.0/255.0.255.0", "10.1.2.3", [(XFF, "198.51.100.17")]),
    ("192.168.1.10", "192.168.1.10", [(XFF, "198.51.100.18")]),
    ("192.168.1.10", "192.168.1.11", [(XFF, "198.51.100.18")]),
    ("testclient", "testclient", [(XFF, "198.51.100.19")]),
    (" 172.16.0.0/12 , ::1/128 ", "::1", [(XFF, "198.51.100.20")]),
    ("fe80::/10", "fe80::1", [(XFF, "198.51.100.21")]),
    ("0.0.0.0/0", "8.8.8.8", [(XFF, "198.51.100.22")]),
    ("0.0.0.0/0", "::1", [(XFF, "198.51.100.22")]),
    ("1.2.3.4/33", "1.2.3.4", [(XFF, "198.51.100.23")]),
    ("1.2.3.0/024", "1.2.3.7", [(XFF, "198.51.100.24")]),
    ("1.2.3.0/ 24", "1.2.3.7", [(XFF, "198.51.100.25")]),
    ("01.2.3.4", "1.2.3.4", [(XFF, "198.51.100.26")]),
    ("[::1]", "::1", [(XFF, "198.51.100.27")]),
    ("1.2.3.0/24/8", "1.2.3.7", [(XFF, "198.51.100.28")]),
    ("2001:db8::/32", "2001:db8::1", [(XFF, "198.51.100.29, 2001:db8::2")]),
    ("172.18.0.2", "172.18.0.2", [(XFF, "198.51.100.30, 172.18.0.2")]),
]


def setting_for(env):
    """TRUSTED_PROXY_CIDRS を env にした（None なら消した）ときの、本物の trusted_proxies() の答え。"""
    if env is None:
        os.environ.pop("TRUSTED_PROXY_CIDRS", None)
    else:
        os.environ["TRUSTED_PROXY_CIDRS"] = env
    return trusted_proxies()


def through(setting, peer, headers):
    """本物の ProxyHeadersMiddleware に 1 回通し、アプリに渡った接続元（の host）と scheme を返す。"""
    seen = {}

    async def app(scope, receive, send):
        """アプリの代わり。渡された scope の接続元と scheme を控える。"""
        seen["client"] = scope.get("client")
        seen["scheme"] = scope.get("scheme")

    scope = {
        "type": "http",
        "scheme": "http",
        "client": None if peer is None else (peer, 40000),
        "headers": [(name.encode("latin-1"), value.encode("latin-1")) for name, value in headers],
    }
    asyncio.run(ProxyHeadersMiddleware(app, trusted_hosts=setting)(scope, None, None))
    client = seen["client"]
    return (None if client is None else client[0]), seen["scheme"]


def main():
    """全部の例を通して expected.json に書く。"""
    out = []
    for env, peer, headers in CASES:
        setting = setting_for(env)
        client, scheme = through(setting, peer, headers)
        out.append(
            {
                "env": env,
                "setting": setting,
                "peer": peer,
                "headers": [list(pair) for pair in headers],
                "client": client,
                "scheme": scheme,
            }
        )
    os.environ.pop("TRUSTED_PROXY_CIDRS", None)
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"cases": out}, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(len(out), "例")


if __name__ == "__main__":
    main()
