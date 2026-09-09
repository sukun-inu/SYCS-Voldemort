"""外部URLの安全性検査（SSRF対策）。

■ 同期版と非同期版がある理由

検査の本体は名前解決で、`socket.getaddrinfo` は **返るまでスレッドを止める**。
イベントループの上でそのまま呼ぶと、DNS が返るまでループごと止まる。実際に
本番で 509ms／720ms の停止として観測された（DJ-Audio の URL 検査）:

    File "/app/services/djaudio_service.py", line 524, in handle_djaudio_message
      validate_public_http_url(url)
    File "/app/services/url_safety.py", line 61, in _resolve_hostname
      infos = socket.getaddrinfo(ascii_host, None, proto=socket.IPPROTO_TCP)

DNS の応答が遅いこと自体は避けようがない（権威サーバーが遠い、UDP が落ちて
再送待ちになる、等）。**避けられるのは「待っているあいだ他を止めること」の方**
なので、ループの上から呼ぶ経路は `validate_public_http_url_async` を使う。
中身は `loop.getaddrinfo`、つまり解決だけをスレッドへ逃がしたもので、検査の
判断は同期版と1つの実装を共有する（片方だけ緩むことがないように）。

同期版を残してあるのは、ループの無いところ（スクリプト、テスト）から呼べる
ようにするため。ループの上から同期版を呼んだ場合は、名前解決に入る手前で
警告を残す——停止として現れるより先に、どこから呼んだかが名指しで分かる。
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import traceback
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class URLSafetyError(ValueError):
    """外部URL利用時の安全性チェック失敗。"""


_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


def _unwrap_ipv4_mapped(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """IPv4-mapped IPv6（::ffff:a.b.c.d）は、実体である IPv4 として判定する。

    ここを噛ませないと Python のバージョンで結果が変わる。3.12.4 未満の
    ipaddress は ::ffff:0:0/96 を丸ごと「private」に数えるので、公開 IPv4 を
    指す ::ffff:142.251.150.119 が is_global=False になる。3.13 以降は
    「IPv4-mapped の is_private は、埋め込まれた IPv4 の意味で決まる」と
    明記された（IPv6Address.is_private の docstring）。

    手元（3.13）で通るのに本番・CI（3.11）だけ弾かれる、という形だった。
    実際に VirusTotal のスキャンが non_public_ip で落ちる事例が出ている。

    **本番を 3.13 へ揃えたあとも、この関数を消さないこと。** 3.13 の挙動が
    望むものだから要らない、という判断は2つの点で誤る。対象の Python を
    下げ戻したとき（あるいは古い版で動かしたとき）に同じ事故へ戻るうえ、
    「埋め込まれた IPv4 で判定する」という意図がコードから消える。
    判定の前に IPv4 へ開くのは、版に関わらず正しい。
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """SSRF対策の核。private/loopback/link-local/multicast/reservedの
    どれかに該当すれば拒否する。IPv4-mapped IPv6を先に開くのは
    _unwrap_ipv4_mapped のdocstring参照。
    """
    # is_global=False のアドレス（private / loopback / link-local / multicast / reserved など）を拒否
    return _unwrap_ipv4_mapped(ip).is_global


def _ascii_hostname(hostname: str) -> str:
    """IDN（国際化ドメイン名）を ASCII（punycode）へ直す。名前解決の前段。"""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise URLSafetyError(f"invalid_hostname:{e}") from e


def _addrinfo_to_ips(infos: Iterable[tuple[Any, ...]]) -> set[IPAddress]:
    """getaddrinfo の戻りから A/AAAA 両方のアドレスを集める。

    1つも取れなかった場合に「解決できないので安全」とはみなさず例外にする
    （呼び出し元は URL の取得自体を諦める）。
    """
    ips: set[IPAddress] = set()
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ips.add(ipaddress.ip_address(sockaddr[0]))
        elif family == socket.AF_INET6:
            ips.add(ipaddress.ip_address(sockaddr[0]))

    if not ips:
        raise URLSafetyError("dns_resolution_empty")
    return ips


def _warn_if_on_event_loop(hostname: str) -> None:
    """イベントループの上で同期の名前解決に入ろうとしていたら、警告を残す。

    ここを通る＝これから DNS が返るまでループが止まる、ということ。停止として
    現れるより先に、**どこから呼ばれたかを名指しで**残しておく。ループの無い
    ところ（スクリプト・テスト）から呼ばれた場合は何もしない。
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return  # ループの外。同期で解決してよい

    # 直近の呼び出し元＝このモジュールの外にある、いちばん深いフレーム。
    caller = "（呼び出し元を特定できません）"
    for frame in reversed(traceback.extract_stack()[:-1]):
        if frame.filename != __file__:
            caller = f"{frame.filename}:{frame.lineno} ({frame.name})"
            break
    logger.warning(
        "[stall] イベントループの上で同期の名前解決に入ります（%s）。"
        "validate_public_http_url_async を使ってください: %s",
        hostname,
        caller,
    )


def _resolve_hostname(hostname: str) -> set[IPAddress]:
    """ホスト名を同期で名前解決し、A/AAAA 両方の結果を集める。

    **返るまでスレッドが止まる。** イベントループの上からは
    `_resolve_hostname_async` を使うこと。
    """
    ascii_host = _ascii_hostname(hostname)
    _warn_if_on_event_loop(hostname)

    try:
        infos = socket.getaddrinfo(ascii_host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise URLSafetyError(f"dns_resolution_failed:{e}") from e

    return _addrinfo_to_ips(infos)


async def _resolve_hostname_async(hostname: str) -> set[IPAddress]:
    """ホスト名を名前解決する。解決そのものはスレッドへ逃がす。

    `loop.getaddrinfo` は `socket.getaddrinfo` を既定のエグゼキュータで
    走らせる。**待っているあいだ、ループは他の仕事を進められる。**
    結果の扱いと判定は同期版と同じ実装を共有する。
    """
    ascii_host = _ascii_hostname(hostname)

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(ascii_host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise URLSafetyError(f"dns_resolution_failed:{e}") from e

    return _addrinfo_to_ips(infos)


def _parse_target(url: str, allow_http: bool) -> tuple[set[IPAddress] | None, str]:
    """URL の形を検査し、「何を確かめればよいか」まで進める。名前解決はしない。

    戻り値は (確定した宛先IP, ホスト名)。URL が IP リテラルなら第1要素が
    埋まっていて名前解決は要らない。ホスト名なら None を返すので、呼び出し側が
    同期・非同期のどちらで解決するかを選ぶ。
    """
    parsed = urlparse((url or "").strip())
    if not parsed.scheme:
        raise URLSafetyError("missing_scheme")

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLSafetyError("unsupported_scheme")
    if scheme == "http" and not allow_http:
        raise URLSafetyError("http_not_allowed")

    if parsed.username or parsed.password:
        raise URLSafetyError("userinfo_not_allowed")

    host = parsed.hostname
    if not host:
        raise URLSafetyError("missing_hostname")

    host_l = host.lower()
    if host_l in _BLOCKED_HOSTNAMES:
        raise URLSafetyError("localhost_not_allowed")

    try:
        return {ipaddress.ip_address(host_l)}, host_l
    except ValueError:
        return None, host_l


def _reject_non_public(ips: set[IPAddress]) -> None:
    """1つでも非公開なら拒否する（fail-close）。

    DNS を握られていれば「公開IPも返しつつ、実際の接続先は内部IP」に
    できるため、多数決や「1つでも公開なら可」にはしない。
    """
    for ip in ips:
        resolved = _unwrap_ipv4_mapped(ip)
        if not _is_public_ip(ip):
            detail = f"{ip}" if resolved == ip else f"{ip}(={resolved})"
            raise URLSafetyError(f"non_public_ip:{detail}")


def validate_public_http_url(
    url: str,
    *,
    allow_http: bool = True,
) -> None:
    """URL が外部向け HTTP(S) 宛であることを検証する（同期）。

    **イベントループの上から呼ばないこと。** 名前解決が返るまでループごと
    止まる。ループの上では `validate_public_http_url_async` を使う。

    既知の限界（DNS リバインディング）:
      ここで名前解決して公開IPであることを確かめても、実際に取得するのは
      別プロセス（yt-dlp）や別のクライアントで、そちらは名前解決をやり直す。
      DNS を握られていれば、検証時は公開IP・取得時は内部IPを返すことができる。
      事前検証方式に共通の構造的な限界で、この関数だけでは塞げない。
      実運用では呼び出し側のドメイン許可リスト（is_djaudio_allowed_url など）が
      効いている。厳密にやるなら、解決済みのIPへ固定して接続する必要がある。
    """
    ips, host = _parse_target(url, allow_http)
    if ips is None:
        ips = _resolve_hostname(host)
    _reject_non_public(ips)


async def validate_public_http_url_async(
    url: str,
    *,
    allow_http: bool = True,
) -> None:
    """`validate_public_http_url` と同じ検査を、ループを止めずに行う。

    違いは名前解決をスレッドへ逃がす点だけで、受理・拒否の判断は同じ実装を
    共有する。限界（DNS リバインディング）も同期版の docstring のとおり。
    """
    ips, host = _parse_target(url, allow_http)
    if ips is None:
        ips = await _resolve_hostname_async(host)
    _reject_non_public(ips)
