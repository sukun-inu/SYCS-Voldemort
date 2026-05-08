import ipaddress
import socket
from urllib.parse import urlparse


class URLSafetyError(ValueError):
    """外部URL利用時の安全性チェック失敗。"""


_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # is_global=False のアドレス（private / loopback / link-local / multicast / reserved など）を拒否
    return ip.is_global


def _resolve_hostname(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
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
    """URL が外部向け HTTP(S) 宛であることを検証する。"""
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

    for ip in ips:
        if not _is_public_ip(ip):
            raise URLSafetyError(f"non_public_ip:{ip}")
