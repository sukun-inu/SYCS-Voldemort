"""URL の安全確認の基準（rust/crates/sycs-core/tests/url_safety_golden.rs が読む）。

答え（expected.json）は、本番と同じ Python 3.13 で services/url_safety.py が出したもの。
Rust の移植（crates/sycs-core/src/url_safety.rs）が同じ答えを出すことを CI で確かめる。

- ips: 公開アドレスの表（Python 3.13 の ipaddress）の各範囲の端（最初・最後・その外側）と、
  乱数で作った IPv4・IPv6・IPv4-mapped の IPv6
- urls: URL の分解と拒否の理由（名前は引かない。アドレスが書いてあればその判定まで）

作り直すとき（表が変わったとき、例を足すとき）は、リポジトリの直下で本番と同じ Python で:

    python rust/crates/sycs-core/tests/fixtures/url_safety/generate.py
"""

import ipaddress
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", "..")))
from services import url_safety as us  # noqa: E402

NETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.0.170/31",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "192.0.0.9/32",
    "192.0.0.10/32",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "::1/128",
    "::/128",
    "::ffff:0.0.0.0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "fc00::/7",
    "fe80::/10",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:20::/28",
    "2001:30::/28",
    "ff00::/8",
    "64:ff9b::/96",
]

URLS = [
    "example.com",
    "ftp://x/",
    "file:///etc/passwd",
    "https://user:pass@example.com/",
    "https://:pass@example.com/",
    "https://@example.com/",
    "https:///path",
    "http://localhost/",
    "http://LOCALHOST.localdomain:8080/",
    "https://[abc",
    "https://abc]",
    "https://[1.2.3.4]/",
    "https://x[::1]/",
    "https://[::1]x/",
    "https://[vz.1]/",
    "https://[v1.x]/",
    "https://[V1F.abc]/",
    "http://127.0.0.1/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://169.254.169.254/",
    "http://[::1]/",
    "http://100.64.0.1/",
    "http://[fe80::1%25eth0]/",
    "http://[::ffff:10.0.0.1]/",
    "https://[::ffff:142.251.150.119]/path",
    "https://8.8.8.8/",
    "HTTPS://Example.COM:443/x",
    "https://u@a.Example@b.Example/",
    " \t https://ex\tample.com/",
    "https://a\u2100b.example/",
    "https://\u65e5\u672c\u8a9e.example/",
    "http://01.2.3.4/",
    "http://1.2.3/",
    "http://[::1.2.3.4]/",
    "http://[2001:db8::1]/",
    "http://[ff02::1]/",
    "http://224.0.0.1/",
    "http://255.255.255.255/",
    "http://0.0.0.0/",
    "http://192.0.0.9/",
    "https://example.com:99999/",
    "https://example.com#frag",
    "https://example.com?q=1",
    "https:example.com",
    "https:/example.com",
    "//example.com/",
    "javascript:alert(1)",
    "https://[::1]:80/",
    "https://[::1]:x/",
    "https://u[x]@example.com/",
    "https://exa mple.com/",
    "https://\u0000example.com/",
    "\u0001https://example.com/",
    "https://ex\u3000ample.com/",
    "HTTP://[FE80::1%25EtH0]/",
    "https://xn--wgv71a119e.jp/",
    "h://x",
    "1http://x",
    "ht+t.p-s://x/",
    "https://[::]/",
    "http://[64:ff9b:1::1]/",
    "http://[2002::1]/",
    "http://[3fff::1]/",
    "http://[2001:3::1]/",
    "http://[2001:1::1]/",
    "http://[2001:1::3]/",
]


def ips() -> list[str]:
    """表の各範囲の端と、乱数のアドレス（種は固定）。"""
    out: set[str] = set()
    for n in NETS:
        net = ipaddress.ip_network(n)
        top = 2**32 if net.version == 4 else 2**128
        first, last = int(net.network_address), int(net.broadcast_address)
        for x in (first - 1, first, last, last + 1):
            if 0 <= x < top:
                out.add(str(ipaddress.IPv4Address(x) if net.version == 4 else ipaddress.IPv6Address(x)))
    r = random.Random(7)
    for _ in range(60):
        out.add(str(ipaddress.IPv4Address(r.getrandbits(32))))
        out.add(str(ipaddress.IPv6Address(r.getrandbits(128))))
        out.add(str(ipaddress.IPv6Address((0xFFFF << 32) | r.getrandbits(32))))
    return sorted(out)


def url_code(url: str) -> str:
    """URL の分解と拒否の理由。名前は引かない。"""
    try:
        found, host = us._parse_target(url, True)
        if found is None:
            return "host:" + host
        us._reject_non_public(found)
        return "ok"
    except us.URLSafetyError as e:
        return str(e).split(":")[0]


def main() -> None:
    """答えを expected.json に書く。"""
    data = {
        "ips": [[ip, us._is_public_ip(ipaddress.ip_address(ip))] for ip in ips()],
        "urls": [[u, url_code(u)] for u in URLS],
    }
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=0)
        f.write("\n")
    print(len(data["ips"]), "アドレス,", len(data["urls"]), "URL")


if __name__ == "__main__":
    main()
