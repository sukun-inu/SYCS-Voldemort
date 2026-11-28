//! 外部の URL へ取りに行く前の安全確認（SSRF 対策）。Python の `services/url_safety.py`。
//!
//! 外向けの http(s) で、ホストの名前を引いたアドレスが**1 つ残らず**公開アドレスであるときだけ通す
//! （1 つでも内部のアドレスが混じれば拒否する。DNS を握られていれば公開と内部を混ぜて返せるので、
//! 多数決にしない）。
//!
//! # Python と揃えてあるもの
//!
//! - URL の分解: Python 3.13 の `urlsplit` と同じ決まり（先頭の制御文字と空白を落とす・タブと改行を
//!   取り除く・括弧の検査・`@` の右の最後の部分をホストにする・`%` の手前だけを小文字にする）。分解
//!   できない URL は `invalid_url`（Python では ValueError が漏れて、メッセージの検査を止めていた。5b9cb87）
//! - 公開アドレスか: Python 3.13 の `ipaddress` の `is_global` と同じ表（IPv4-mapped の IPv6 は中の IPv4 で判定）に、
//!   マルチキャスト（224.0.0.0/4・ff00::/8）の拒否を足したもの（Python の `_is_public_ip` と同じ。`is_global` だけでは
//!   マルチキャストが公開扱いで通っていた。rust-09 の (a)）
//! - 拒否の理由の名前（`missing_scheme`・`non_public_ip:…` など）
//!
//! # 違うもの
//!
//! - ASCII 以外のホスト名の変換: Python は IDNA2003、こちらは UTS46（`idna` crate）。まれな文字（ß など）で
//!   結果が違う。こちらは reqwest が実際に接続に使う変換と同じなので、確かめた相手と接続する相手が揃う
//!
//! 限界（DNS リバインディング）は Python と同じ: 確かめたあとに取りに行く側が名前を引き直すので、
//! DNS を握られていれば、確かめたときと取りに行くときで別のアドレスを返せる。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use unicode_normalization::UnicodeNormalization;

/// 安全確認に通らなかった理由。中身は Python の `URLSafetyError` の文字列と同じ形。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlSafetyError(pub String);

impl fmt::Display for UrlSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UrlSafetyError {}

impl UrlSafetyError {
    /// 理由の名前（`:` より前）。
    pub fn code(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }
}

fn err(text: impl Into<String>) -> UrlSafetyError {
    UrlSafetyError(text.into())
}

const BLOCKED_HOSTNAMES: [&str; 2] = ["localhost", "localhost.localdomain"];

/// 取りに行く前に確かめる相手。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// URL にアドレスがそのまま書いてある（名前を引かない）。
    Address(IpAddr),
    /// ホストの名前（小文字。これから引く）。
    Host(String),
}

/// URL の形を確かめ、確かめる相手まで進める。名前は引かない。Python の `_parse_target`。
pub fn parse_target(url: &str, allow_http: bool) -> Result<Target, UrlSafetyError> {
    let parts = urlsplit(url.trim()).map_err(|e| err(format!("invalid_url:{e}")))?;
    if parts.scheme.is_empty() {
        return Err(err("missing_scheme"));
    }
    if parts.scheme != "http" && parts.scheme != "https" {
        return Err(err("unsupported_scheme"));
    }
    if parts.scheme == "http" && !allow_http {
        return Err(err("http_not_allowed"));
    }
    let (user, password) = userinfo(&parts.netloc);
    if user.is_some_and(|u| !u.is_empty()) || password.is_some_and(|p| !p.is_empty()) {
        return Err(err("userinfo_not_allowed"));
    }
    let Some(host) = hostname(&parts.netloc) else {
        return Err(err("missing_hostname"));
    };
    if BLOCKED_HOSTNAMES.contains(&host.as_str()) {
        return Err(err("localhost_not_allowed"));
    }
    Ok(match python_ip_address(&host) {
        Some(ip) => Target::Address(ip),
        None => Target::Host(host),
    })
}

/// 外向けの http(s) で、行き先が全部公開アドレスであることを確かめる。Python の
/// `validate_public_http_url_async`（名前を引く間もほかの処理を止めない）。
pub async fn validate_public_http_url(url: &str, allow_http: bool) -> Result<(), UrlSafetyError> {
    let ips = match parse_target(url, allow_http)? {
        Target::Address(ip) => vec![ip],
        Target::Host(host) => resolve(&host).await?,
    };
    reject_non_public(&ips)
}

/// 1 つでも公開でなければ拒否する。Python の `_reject_non_public`。
pub fn reject_non_public(ips: &[IpAddr]) -> Result<(), UrlSafetyError> {
    for ip in ips {
        if !is_public_ip(*ip) {
            let detail = match ipv4_mapped(*ip) {
                Some(v4) => format!("{ip}(={v4})"),
                None => ip.to_string(),
            };
            return Err(err(format!("non_public_ip:{detail}")));
        }
    }
    Ok(())
}

async fn resolve(host: &str) -> Result<Vec<IpAddr>, UrlSafetyError> {
    let ascii = ascii_hostname(host)?;
    let addrs = tokio::net::lookup_host((ascii.as_str(), 0))
        .await
        .map_err(|e| err(format!("dns_resolution_failed:{e}")))?;
    let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(err("dns_resolution_empty"));
    }
    Ok(ips)
}

/// ホスト名を ASCII に。ASCII の名前は Python の idna コーデックと同じく、最後以外のラベルが
/// 1〜63 文字・最後は 63 文字以下であることを確かめる。ASCII 以外は UTS46（モジュールの説明）。
fn ascii_hostname(host: &str) -> Result<String, UrlSafetyError> {
    if host.is_ascii() {
        let labels: Vec<&str> = host.split('.').collect();
        let (last, rest) = labels.split_last().expect("split は 1 つ以上返す");
        if rest.iter().any(|l| l.is_empty() || l.len() >= 64) {
            return Err(err("invalid_hostname:label empty or too long"));
        }
        if last.len() >= 64 {
            return Err(err("invalid_hostname:label too long"));
        }
        return Ok(host.to_string());
    }
    idna::domain_to_ascii(host).map_err(|e| err(format!("invalid_hostname:{e}")))
}

/// IPv4-mapped の IPv6（`::ffff:a.b.c.d`）なら中の IPv4。
fn ipv4_mapped(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        IpAddr::V4(_) => None,
    }
}

/// 公開アドレスか。Python の `_is_public_ip`: 3.13 の `ip.is_global` で、マルチキャストでないもの（IPv4-mapped は
/// 中の IPv4 で）。
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ipv4_mapped(ip) {
        Some(v4) => v4_is_global(v4) && !v4.is_multicast(),
        None => match ip {
            IpAddr::V4(v4) => v4_is_global(v4) && !v4.is_multicast(),
            IpAddr::V6(v6) => !v6_is_private(v6) && !v6.is_multicast(),
        },
    }
}

fn v4_in(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

/// Python 3.13 の `IPv4Address._constants._private_networks`。
const V4_PRIVATE: [([u8; 4], u32); 14] = [
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 0, 170], 31),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];
/// `_private_networks_exceptions`（private の中でも公開とみなすもの）。
const V4_PRIVATE_EXCEPTIONS: [([u8; 4], u32); 2] = [([192, 0, 0, 9], 32), ([192, 0, 0, 10], 32)];

fn v4_is_global(ip: Ipv4Addr) -> bool {
    // 100.64.0.0/10（共有アドレス）は private でも global でもない。
    let shared = v4_in(ip, [100, 64, 0, 0], 10);
    let private = V4_PRIVATE.iter().any(|(n, p)| v4_in(ip, *n, *p))
        && !V4_PRIVATE_EXCEPTIONS.iter().any(|(n, p)| v4_in(ip, *n, *p));
    !shared && !private
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

/// Python 3.13 の `IPv6Address._constants._private_networks`（文字で持ち、使うときに読む）。
const V6_PRIVATE: [(&str, u32); 11] = [
    ("::1", 128),
    ("::", 128),
    ("::ffff:0.0.0.0", 96),
    ("64:ff9b:1::", 48),
    ("100::", 64),
    ("2001::", 23),
    ("2001:db8::", 32),
    ("2002::", 16),
    ("3fff::", 20),
    ("fc00::", 7),
    ("fe80::", 10),
];
/// `_private_networks_exceptions`。
const V6_PRIVATE_EXCEPTIONS: [(&str, u32); 6] = [
    ("2001:1::1", 128),
    ("2001:1::2", 128),
    ("2001:3::", 32),
    ("2001:4:112::", 48),
    ("2001:20::", 28),
    ("2001:30::", 28),
];

fn v6_is_private(ip: Ipv6Addr) -> bool {
    let inside = |table: &[(&str, u32)]| {
        table
            .iter()
            .any(|(n, p)| v6_in(ip, n.parse().expect("表のアドレスは正しい"), *p))
    };
    inside(&V6_PRIVATE) && !inside(&V6_PRIVATE_EXCEPTIONS)
}

/// Python の `ipaddress.ip_address(text)`（文字列のとき）。IPv6 の `%ゾーン` も読む（判定はアドレスだけで行う）。
fn python_ip_address(text: &str) -> Option<IpAddr> {
    if let Some((addr, zone)) = text.split_once('%') {
        if zone.is_empty() || zone.contains('%') {
            return None;
        }
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    text.parse::<IpAddr>().ok()
}

/// Python の `urlsplit(url).netloc`（`//` の後ろから `/`・`?`・`#` の手前まで。ユーザー名やポートも含む）。
/// `//` で始まるホストの部分が無ければ空。分解できない URL（括弧の合わない `https://[abc` など）は `Err`
/// （Python は ValueError）。
pub fn netloc(url: &str) -> Result<String, UrlSafetyError> {
    urlsplit(url)
        .map(|parts| parts.netloc)
        .map_err(|e| err(format!("invalid_url:{e}")))
}

/// Python の `urlparse(url).hostname`（小文字にしたホストの名前。無ければ `None`）。分解できない URL
/// （括弧の合わない `https://[abc` など）は `Err`（Python は ValueError）。
pub fn hostname_of(url: &str) -> Result<Option<String>, UrlSafetyError> {
    urlsplit(url)
        .map(|parts| hostname(&parts.netloc))
        .map_err(|e| err(format!("invalid_url:{e}")))
}

/// 分解した URL のうち、安全確認に要るところ。
struct Parts {
    scheme: String,
    netloc: String,
}

/// Python 3.13 の `urllib.parse.urlsplit` のうち、スキームとホストの部分（と、そこで投げる ValueError）。
fn urlsplit(url: &str) -> Result<Parts, String> {
    let url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(i) = rest.find(':')
        && i > 0
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest[..i]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        scheme = rest[..i].to_ascii_lowercase();
        rest = &rest[i + 1..];
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_string();
        let (open, close) = (netloc.contains('['), netloc.contains(']'));
        if open != close {
            return Err("Invalid IPv6 URL".into());
        }
        if open && close {
            check_bracketed_netloc(&netloc)?;
        }
    }
    check_netloc(&netloc)?;
    Ok(Parts { scheme, netloc })
}

/// Python の `str.rpartition(sep)[2]` と `str.partition(sep)`。
fn after_last(s: &str, sep: char) -> &str {
    s.rsplit_once(sep).map_or(s, |(_, r)| r)
}

fn partition(s: &str, sep: char) -> (&str, bool, &str) {
    match s.split_once(sep) {
        Some((a, b)) => (a, true, b),
        None => (s, false, ""),
    }
}

fn check_bracketed_netloc(netloc: &str) -> Result<(), String> {
    let host_and_port = after_last(netloc, '@');
    let (before, open, bracketed) = partition(host_and_port, '[');
    let host = if open {
        if !before.is_empty() {
            return Err("Invalid IPv6 URL".into());
        }
        let (host, _, port) = partition(bracketed, ']');
        if !port.is_empty() && !port.starts_with(':') {
            return Err("Invalid IPv6 URL".into());
        }
        host
    } else {
        partition(host_and_port, ':').0
    };
    check_bracketed_host(host)
}

fn check_bracketed_host(host: &str) -> Result<(), String> {
    if let Some(rest) = host.strip_prefix(['v', 'V']) {
        // \A[vV][a-fA-F0-9]+\..+\Z
        let hex_len = rest.chars().take_while(char::is_ascii_hexdigit).count();
        let tail = &rest[hex_len..];
        let ok =
            hex_len > 0 && tail.starts_with('.') && tail.len() > 1 && !tail[1..].contains('\n');
        return if ok {
            Ok(())
        } else {
            Err("IPvFuture address is invalid".into())
        };
    }
    match python_ip_address(host) {
        Some(IpAddr::V4(_)) => Err("An IPv4 address cannot be in brackets".into()),
        Some(IpAddr::V6(_)) => Ok(()),
        None => Err(format!(
            "'{host}' does not appear to be an IPv4 or IPv6 address"
        )),
    }
}

/// NFKC で `/?#@:` に化ける文字を拒否する。Python の `_checknetloc`。
fn check_netloc(netloc: &str) -> Result<(), String> {
    if netloc.is_empty() || netloc.is_ascii() {
        return Ok(());
    }
    let n: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = n.nfkc().collect();
    if n == normalized {
        return Ok(());
    }
    if normalized.contains(['/', '?', '#', '@', ':']) {
        return Err(format!(
            "netloc '{netloc}' contains invalid characters under NFKC normalization"
        ));
    }
    Ok(())
}

/// Python の `_userinfo`: (ユーザー名, パスワード)。`@` が無ければどちらも `None`。
fn userinfo(netloc: &str) -> (Option<&str>, Option<&str>) {
    match netloc.rsplit_once('@') {
        Some((info, _)) => match info.split_once(':') {
            Some((u, p)) => (Some(u), Some(p)),
            None => (Some(info), None),
        },
        None => (None, None),
    }
}

/// Python の `hostname`: 括弧の中か `:` の手前。空なら `None`。`%` の手前だけを小文字にする。
fn hostname(netloc: &str) -> Option<String> {
    let info = after_last(netloc, '@');
    let (_, open, bracketed) = partition(info, '[');
    let host = if open {
        partition(bracketed, ']').0
    } else {
        partition(info, ':').0
    };
    if host.is_empty() {
        return None;
    }
    let (name, percent, zone) = partition(host, '%');
    Some(format!(
        "{}{}{zone}",
        name.to_lowercase(),
        if percent { "%" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// netloc は Python の urlsplit と同じところを切り出し、分解できない URL は失敗にすること。
    #[test]
    fn netloc_is_cut_like_urlsplit() {
        let ok = |url: &str| netloc(url).unwrap();
        assert_eq!(ok("https://space.example.jp"), "space.example.jp");
        assert_eq!(ok("  https://a.example/path?x=1  "), "a.example");
        assert_eq!(
            ok("http://user:pw@a.example:8080/x#f"),
            "user:pw@a.example:8080"
        );
        assert_eq!(
            ok("//schemeless.example.com/path"),
            "schemeless.example.com"
        );
        assert_eq!(ok("HTTPS://UPPER.Example.COM:443"), "UPPER.Example.COM:443");
        assert_eq!(ok("https://exa\tmple.com/"), "example.com");
        for none in [
            "",
            "no-scheme.example.com/path",
            "mailto:a@b.example",
            "https:///x",
        ] {
            assert_eq!(ok(none), "", "{none}");
        }
        for bad in ["https://[broken", "https://bro]ken/"] {
            assert!(
                netloc(bad).unwrap_err().0.starts_with("invalid_url:"),
                "{bad}"
            );
        }
    }

    fn code(url: &str) -> String {
        match parse_target(url, true) {
            Ok(Target::Address(ip)) => match reject_non_public(&[ip]) {
                Ok(()) => "ok".into(),
                Err(e) => e.code().to_string(),
            },
            Ok(Target::Host(h)) => format!("host:{h}"),
            Err(e) => e.code().to_string(),
        }
    }

    /// 形の誤り（スキーム・ユーザー情報・ホスト・localhost・壊れた URL）を、Python と同じ名前で拒否する。
    #[test]
    fn malformed_urls_are_rejected_with_python_codes() {
        assert_eq!(code("example.com"), "missing_scheme");
        assert_eq!(code("ftp://x/"), "unsupported_scheme");
        assert_eq!(code("file:///etc/passwd"), "unsupported_scheme");
        assert_eq!(
            code("https://user:pass@example.com/"),
            "userinfo_not_allowed"
        );
        assert_eq!(code("https://:pass@example.com/"), "userinfo_not_allowed");
        // 空のユーザー名だけなら Python も通す。
        assert_eq!(code("https://@example.com/"), "host:example.com");
        assert_eq!(code("https:///path"), "missing_hostname");
        assert_eq!(code("http://localhost/"), "localhost_not_allowed");
        assert_eq!(
            code("http://LOCALHOST.localdomain:8080/"),
            "localhost_not_allowed"
        );
        for bad in [
            "https://[abc",
            "https://abc]",
            "https://[1.2.3.4]/",
            "https://x[::1]/",
            "https://[::1]x/",
            "https://[vz.1]/",
        ] {
            assert_eq!(code(bad), "invalid_url", "{bad}");
        }
        assert_eq!(
            parse_target("http://x/", false).unwrap_err().code(),
            "http_not_allowed"
        );
    }

    /// 内部のアドレスは拒否し、IPv4-mapped は中の IPv4 で判定する。
    #[test]
    fn private_addresses_are_rejected() {
        for url in [
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/",
            "http://[::1]/",
            "http://100.64.0.1/",
            "http://[fe80::1%25eth0]/",
            "http://[::ffff:10.0.0.1]/",
        ] {
            assert_eq!(code(url), "non_public_ip", "{url}");
        }
        assert_eq!(code("https://[::ffff:142.251.150.119]/path"), "ok");
        assert_eq!(code("https://8.8.8.8/"), "ok");
        assert_eq!(
            reject_non_public(&["::ffff:10.0.0.1".parse().unwrap()])
                .unwrap_err()
                .0,
            "non_public_ip:::ffff:10.0.0.1(=10.0.0.1)"
        );
    }

    /// Python の表の境目（private の例外・共有アドレス・マルチキャスト）。
    #[test]
    fn the_public_table_matches_python() {
        let public = |s: &str| is_public_ip(s.parse().unwrap());
        assert!(public("192.0.0.9"), "private の例外は公開");
        assert!(!public("192.0.0.8"));
        assert!(!public("100.127.255.255"));
        assert!(public("100.128.0.0"));
        // マルチキャストは公開扱いにしない（is_global は真だが、Python の _is_public_ip が別に拒否する）。
        assert!(!public("224.0.0.1"));
        assert!(!public("239.255.255.255"));
        assert!(public("223.255.255.255"));
        assert!(!public("::ffff:224.0.0.251"));
        assert!(!public("240.0.0.1"));
        assert!(!public("2001:db8::1"));
        assert!(public("2001:3::1"), "private の例外は公開");
        assert!(!public("fd00::1"));
        assert!(public("2606:4700::1111"));
        assert!(!public("ff02::1"));
        assert!(!public("ff00::"));
        assert!(public("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    /// ホスト名は小文字にし（% の後ろはそのまま）、括弧とポートを外す。
    #[test]
    fn hostnames_are_taken_like_python() {
        assert_eq!(code("HTTPS://Example.COM:443/x"), "host:example.com");
        // 最後の @ の右がホスト。左はユーザー名として読まれるので、Python と同じく拒否される。
        assert_eq!(
            code("https://u@a.Example@b.Example/"),
            "userinfo_not_allowed"
        );
        assert_eq!(
            hostname("u@a.Example@b.Example").as_deref(),
            Some("b.example")
        );
        assert_eq!(code(" \t https://ex\tample.com/"), "host:example.com");
        assert_eq!(
            hostname("[FE80::1%eTh0]:80").as_deref(),
            Some("fe80::1%eTh0")
        );
    }

    /// ASCII のホスト名のラベルの長さを Python の idna コーデックと同じく確かめる。
    #[test]
    fn ascii_labels_are_checked_like_python_idna() {
        assert!(ascii_hostname("example.com.").is_ok());
        assert_eq!(
            ascii_hostname("a..b").unwrap_err().code(),
            "invalid_hostname"
        );
        let long = "a".repeat(64);
        assert!(ascii_hostname(&format!("{long}.com")).is_err());
        assert!(ascii_hostname(&format!("x.{long}")).is_err());
        assert!(ascii_hostname(&"a".repeat(63)).is_ok());
    }

    /// NFKC で区切りの文字に化けるホストを拒否する（℀ は a/c になる）。
    #[test]
    fn nfkc_tricks_in_the_host_are_rejected() {
        assert_eq!(code("https://a\u{2100}b.example/"), "invalid_url");
        assert_eq!(code("https://日本語.example/"), "host:日本語.example");
    }
}
