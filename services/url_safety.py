import ipaddress
import socket
from urllib.parse import urlparse


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

    手元（3.13）で通るのに本番・CI（3.11）だけ弾かれる、という形になる。
    実際に VirusTotal のスキャンが non_public_ip で落ちる事例が出ている。
    バージョンに依存させないため、判定の前に IPv4 へ開いておく。
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


def _resolve_hostname(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """ホスト名を名前解決し、A/AAAA両方の結果を集める。IDN（国際化ドメイン名）
    はASCII（punycode）に変換してから解決する。解決に失敗した場合も
    「解決できないので安全」とはみなさず例外にする（呼び出し元は
    URLの取得自体を諦める）。
    """
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise URLSafetyError(f"invalid_hostname:{e}") from e

    try:
        infos = socket.getaddrinfo(ascii_host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise URLSafetyError(f"dns_resolution_failed:{e}") from e

    ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ips.add(ipaddress.ip_address(sockaddr[0]))
        elif family == socket.AF_INET6:
            ips.add(ipaddress.ip_address(sockaddr[0]))

    if not ips:
        raise URLSafetyError("dns_resolution_empty")
    return ips


def validate_public_http_url(
    url: str,
    *,
    allow_http: bool = True,
) -> None:
    """URL が外部向け HTTP(S) 宛であることを検証する。

    既知の限界（DNS リバインディング）:
      ここで名前解決して公開IPであることを確かめても、実際に取得するのは
      別プロセス（yt-dlp）や別のクライアントで、そちらは名前解決をやり直す。
      DNS を握られていれば、検証時は公開IP・取得時は内部IPを返すことができる。
      事前検証方式に共通の構造的な限界で、この関数だけでは塞げない。
      実運用では呼び出し側のドメイン許可リスト（is_djaudio_allowed_url など）が
      効いている。厳密にやるなら、解決済みのIPへ固定して接続する必要がある。
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
        ip = ipaddress.ip_address(host_l)
        ips = {ip}
    except ValueError:
        ips = _resolve_hostname(host_l)

    # 1つでも非公開なら拒否する（fail-close）。DNS を握られていれば
    # 「公開IPも返しつつ、実際の接続先は内部IP」にできるため、多数決や
    # 「1つでも公開なら可」にはしない。
    for ip in ips:
        resolved = _unwrap_ipv4_mapped(ip)
        if not _is_public_ip(ip):
            detail = f"{ip}" if resolved == ip else f"{ip}(={resolved})"
            raise URLSafetyError(f"non_public_ip:{detail}")
