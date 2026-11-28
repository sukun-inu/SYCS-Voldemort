//! 信頼するプロキシ（`TRUSTED_PROXY_CIDRS`）。Python と同じ読み方にしてある。
//!
//! Python の 3 つのアプリは、uvicorn を `proxy_headers=True, forwarded_allow_ips=trusted_proxies()` で起動している
//! （`services/log_setup.py` の `trusted_proxies`）。直接つないできた相手が信頼する一覧に入っているときだけ、
//! `X-Forwarded-For` から本当の接続元を、`X-Forwarded-Proto` から scheme を読む。ここは uvicorn 0.54 の
//! `ProxyHeadersMiddleware`（と `_TrustedHosts`）の写し。nginx の後ろでは、nginx が足した `X-Forwarded-For` を、
//! nginx のコンテナ（既定の 172.16.0.0/12 に入る）から来たときだけ読む。
//!
//! **`X-Forwarded-For` は誰でも付けられる。** 信頼する相手から来たときだけ読むのはそのため（一覧を `*` に広げると、
//! 外から直接ヘッダを付けるだけで別人になりすませる）。
//!
//! Python と違うところ: IPv6 の `%` 付きのスコープ（`fe80::1%eth0`）は、アドレスとして読まずに文字列として比べる
//! （Python はアドレスとして読む）。compose の設定にも、プロキシが付ける値にも出てこない。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::http::HeaderMap;

/// 既定で信頼する帯域。Python の `DEFAULT_TRUSTED_PROXIES` と同じ（ループバックと Docker のブリッジ）。
///
/// 家庭・社内の LAN でよく使う 192.168.0.0/16 と 10.0.0.0/8 は入れていない（Python のコメントと同じ理由。
/// 同じ LAN から直接叩いてヘッダを偽装できてしまう）。
pub const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.1/32,::1/128,172.16.0.0/12";

/// `TRUSTED_PROXY_CIDRS` の値から、uvicorn に渡す一覧の文字列を決める。Python の `trusted_proxies()`。
///
/// 未設定なら既定。設定してあれば前後の空白を落とし、空なら `127.0.0.1`（Python の
/// `os.getenv(…, 既定).strip() or "127.0.0.1"`。**未設定と空を区別する**ので、`sycs_core::env` の読み方とは違う）。
pub fn trusted_proxies_setting(raw: Option<&str>) -> String {
    match raw {
        None => DEFAULT_TRUSTED_PROXIES.to_string(),
        Some(value) => {
            let stripped = python_strip(value);
            if stripped.is_empty() {
                "127.0.0.1".to_string()
            } else {
                stripped.to_string()
            }
        }
    }
}

/// このプロセスの `TRUSTED_PROXY_CIDRS` から作る（UTF-8 でない値は未設定として扱う）。
pub fn trusted_from_process() -> TrustedHosts {
    let raw = std::env::var("TRUSTED_PROXY_CIDRS").ok();
    TrustedHosts::parse(&trusted_proxies_setting(raw.as_deref()))
}

/// 信頼する相手の一覧。uvicorn の `_TrustedHosts`。
#[derive(Clone, Debug, Default)]
pub struct TrustedHosts {
    setting: String,
    always: bool,
    literals: Vec<String>,
    hosts: Vec<IpAddr>,
    networks: Vec<Network>,
}

/// 帯域（ネットワークの頭のアドレスと、長さ）。
#[derive(Clone, Copy, Debug)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// Python の `ip in network`（版の違うものは入らない）。
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(u32::from(ip), self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(u128::from(ip), self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl TrustedHosts {
    /// 一覧の文字列（[`trusted_proxies_setting`] の答え）を読む。uvicorn と同じく、`,` で区切って前後の空白を落とし、
    /// `/` を含むものは帯域、ほかはアドレスとして読む。**読めないものは捨てずに文字列のまま比べる**（uvicorn と同じ）。
    ///
    /// 全体がちょうど `*` なら、誰でも信頼する（`*` を一覧の 1 つとして書いたものは、ただの文字列になる）。
    pub fn parse(setting: &str) -> Self {
        let mut trusted = Self {
            setting: setting.to_string(),
            always: setting == "*",
            ..Self::default()
        };
        if trusted.always {
            return trusted;
        }
        for host in raw_hosts(setting) {
            let parsed = if host.contains('/') {
                parse_network(&host).map(Entry::Network)
            } else {
                parse_ip(&host).map(Entry::Host)
            };
            match parsed {
                Some(Entry::Network(network)) => trusted.networks.push(network),
                Some(Entry::Host(ip)) => trusted.hosts.push(ip),
                None => trusted.literals.push(host),
            }
        }
        trusted
    }

    /// 読んだ元の文字列（ログに出す用）。
    pub fn setting(&self) -> &str {
        &self.setting
    }

    /// その相手を信頼するか。uvicorn の `_TrustedHosts.__contains__`（空や分からない相手は信頼しない）。
    pub fn contains(&self, host: Option<&str>) -> bool {
        if self.always {
            return true;
        }
        let Some(host) = host.filter(|h| !h.is_empty()) else {
            return false;
        };
        match parse_ip(host) {
            Some(ip) => self.hosts.contains(&ip) || self.networks.iter().any(|n| n.contains(ip)),
            None => self.literals.iter().any(|literal| literal == host),
        }
    }

    /// `X-Forwarded-For` から接続元を選ぶ。uvicorn の `get_trusted_client_address`。
    ///
    /// プロキシは右へ足していくので、右から見て最初の「信頼しない相手」が接続元。全部が信頼する相手なら、いちばん左。
    /// どの項目も、ポートを落としてから（`without_port`）信頼する相手かを見る。
    pub fn client_host(&self, x_forwarded_for: &str) -> String {
        let hosts: Vec<String> = raw_hosts(x_forwarded_for)
            .iter()
            .map(|host| without_port(host.as_str()))
            .collect();
        if self.always {
            return hosts[0].clone();
        }
        for host in hosts.iter().rev() {
            if !self.contains(Some(host.as_str())) {
                return host.clone();
            }
        }
        hosts[0].clone()
    }
}

/// 一覧の 1 項目を読んだもの。
enum Entry {
    Network(Network),
    Host(IpAddr),
}

/// `,` で区切って前後の空白を落とす。uvicorn の `_parse_raw_hosts`（空の項目も残す）。
fn raw_hosts(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| python_strip(item).to_string())
        .collect()
}

/// `X-Forwarded-For` の 1 項目から、ポートを落とした接続元。uvicorn 0.54 の `_parse_host_port` の写し
/// （uvicorn 0.54.0 の `uvicorn/middleware/proxy_headers.py` を読んで写した）。
///
/// - `[` で始まるもの: `]` が無ければそのまま。`]` のあとが空か `:` で始まれば括弧の中（`:` のあとが数でなくても
///   括弧の中）。ほかの何かが続けばそのまま
/// - `:` がちょうど 1 つ: `:` のあとが Python の `int()` で読めるときだけ `:` の前。読めなければ（`abc`・空など）そのまま
/// - ほか（`:` が無い・括弧の無い IPv6）: そのまま
fn without_port(host: &str) -> String {
    if let Some(after_bracket) = host.strip_prefix('[') {
        let Some(end) = after_bracket.find(']') else {
            return host.to_string();
        };
        let remainder = &after_bracket[end + 1..];
        if remainder.is_empty() || remainder.starts_with(':') {
            return after_bracket[..end].to_string();
        }
        return host.to_string();
    }
    if host.matches(':').count() == 1
        && let Some((before, port)) = host.rsplit_once(':')
        && python_int(port)
    {
        return before.to_string();
    }
    host.to_string()
}

/// Python の `int(文字)`（10 進）が読めるか。前後の空白・`+`・`-`・数の間の `_`（1 つずつ）を許す。
///
/// 見出しの値は latin-1 として読んでいるので、数字は ASCII の 0〜9 だけを見ればよい（latin-1 の範囲の
/// ほかの数字〔`²` など〕は、Python の `int()` も読まない）。
fn python_int(text: &str) -> bool {
    let text = python_strip(text);
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_')
}

/// アプリに渡す接続元と scheme。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forwarded {
    /// 接続元（Python の `request.client.host`）。分からなければ `None`。
    pub client: Option<String>,
    /// `http`。信頼する相手が `X-Forwarded-Proto` で `https`・`ws`・`wss` を伝えたらそれ。
    pub scheme: String,
}

/// 直接つないできた相手（`peer`）と見出しから、アプリに渡す接続元と scheme を決める。uvicorn の
/// `ProxyHeadersMiddleware.__call__`。
///
/// 値は latin-1 として読み、Python の `strip()` と同じ空白を落とす。`X-Forwarded-Proto` は 2 つ以上あれば最後のもので、
/// 小文字の 4 つだけを受け付ける。`X-Forwarded-For` は 2 つ以上あれば `, ` でつないで 1 つとして読む（uvicorn 0.54 と同じ）。
pub fn resolve(trusted: &TrustedHosts, peer: Option<&str>, headers: &HeaderMap) -> Forwarded {
    let mut forwarded = Forwarded {
        client: peer.map(str::to_string),
        scheme: "http".to_string(),
    };
    if !trusted.contains(peer) {
        return forwarded;
    }
    if let Some(proto) = last_header(headers, "x-forwarded-proto") {
        let proto = python_strip(&proto);
        if matches!(proto, "http" | "https" | "ws" | "wss") {
            forwarded.scheme = proto.to_string();
        }
    }
    let x_forwarded_for: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|value| latin1(value.as_bytes()))
        .collect();
    if !x_forwarded_for.is_empty() {
        let host = trusted.client_host(&x_forwarded_for.join(", "));
        // 空（`X-Forwarded-For:` だけ、など）なら、直接の相手のまま（uvicorn と同じ）。
        if !host.is_empty() {
            forwarded.client = Some(host);
        }
    }
    forwarded
}

/// その名前の見出しの最後の値（latin-1 として読む）。
fn last_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .next_back()
        .map(|value| latin1(value.as_bytes()))
}

/// バイトを latin-1 として読む（Python の `bytes.decode("latin-1")`。見出しの値の読み方）。
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// 前後の空白を落とす。空白は Python の `str.isspace()`（Rust の空白に、区切りの制御文字 U+001C〜U+001F を足したもの）。
pub fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python の `ipaddress.ip_address(文字列)`。IPv4 は 10 進 4 つ（先頭の 0 は許さない）、ほかは IPv6。
fn parse_ip(text: &str) -> Option<IpAddr> {
    if let Some(v4) = parse_ipv4(text) {
        return Some(IpAddr::V4(v4));
    }
    text.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// Python の `IPv4Address(文字列)`。4 つの 10 進（ASCII の数字だけ・3 桁まで・255 まで・先頭の 0 は `0` だけ）。
fn parse_ipv4(text: &str) -> Option<Ipv4Addr> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (slot, octet) in bytes.iter_mut().zip(&octets) {
        if octet.is_empty() || octet.len() > 3 || !octet.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if *octet != "0" && octet.starts_with('0') {
            return None;
        }
        *slot = octet.parse().ok()?;
    }
    Some(Ipv4Addr::from(bytes))
}

/// Python の `ipaddress.ip_network(文字列)`（strict。頭のアドレスに余りのビットがあれば読めない）。
///
/// IPv4 は長さ（`/24`）のほか、点で区切ったネットマスク（`/255.255.255.0`）とホストマスク（`/0.0.0.255`）も読む。
/// IPv6 は長さだけ。
fn parse_network(text: &str) -> Option<Network> {
    let (address, mask) = text.split_once('/')?;
    if mask.contains('/') {
        return None;
    }
    if let Some(v4) = parse_ipv4(address) {
        let prefix = v4_prefix(mask)?;
        let value = u32::from(v4);
        if mask_v4(value, prefix) != value {
            return None;
        }
        return Some(Network {
            address: IpAddr::V4(v4),
            prefix,
        });
    }
    let v6 = address.parse::<Ipv6Addr>().ok()?;
    let prefix = prefix_number(mask, 128)?;
    let value = u128::from(v6);
    if mask_v6(value, prefix) != value {
        return None;
    }
    Some(Network {
        address: IpAddr::V6(v6),
        prefix,
    })
}

/// IPv4 の長さ。Python の `_make_netmask`（数字の長さ → だめならネットマスク → だめならホストマスク）。
fn v4_prefix(mask: &str) -> Option<u8> {
    if let Some(prefix) = prefix_number(mask, 32) {
        return Some(prefix);
    }
    let value = u32::from(parse_ipv4(mask)?);
    contiguous_prefix(value).or_else(|| contiguous_prefix(!value))
}

/// 数字だけの長さ（ASCII の数字・`max` まで）。Python の `_prefix_from_prefix_string`（`024` も 24 と読む）。
fn prefix_number(text: &str, max: u8) -> Option<u8> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u32 = text.parse().ok()?;
    u8::try_from(value).ok().filter(|prefix| *prefix <= max)
}

/// 左から 1 が続き、そのあと 0 が続く形なら、その 1 の数。Python の `_prefix_from_ip_int`。
fn contiguous_prefix(value: u32) -> Option<u8> {
    let zeros = if value == 0 {
        32
    } else {
        value.trailing_zeros()
    };
    let prefix = 32 - zeros;
    let ones = if zeros == 32 { 0 } else { value >> zeros };
    let all_ones = if prefix == 0 {
        0
    } else {
        u32::MAX >> (32 - prefix)
    };
    if ones == all_ones {
        u8::try_from(prefix).ok()
    } else {
        None
    }
}

fn mask_v4(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        value & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        value & (u128::MAX << (128 - u32::from(prefix)))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    /// 既定の一覧では、Docker のブリッジから来た nginx の `X-Forwarded-For` を読み、外から直接来たものは読まないこと。
    #[test]
    fn only_a_trusted_peer_may_name_the_client() {
        let trusted = TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES);
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.5, 172.18.0.1")]);
        let from_nginx = resolve(&trusted, Some("172.18.0.3"), &forwarded);
        assert_eq!(from_nginx.client.as_deref(), Some("203.0.113.5"));
        let from_outside = resolve(&trusted, Some("198.51.100.9"), &forwarded);
        assert_eq!(from_outside.client.as_deref(), Some("198.51.100.9"));
    }

    /// 未設定は既定、空は 127.0.0.1 になること（Python の `trusted_proxies()` と同じく、未設定と空を区別する）。
    #[test]
    fn unset_and_empty_settings_differ_like_python() {
        assert_eq!(trusted_proxies_setting(None), DEFAULT_TRUSTED_PROXIES);
        assert_eq!(trusted_proxies_setting(Some("  ")), "127.0.0.1");
        assert_eq!(trusted_proxies_setting(Some(" 10.0.0.0/8 ")), "10.0.0.0/8");
    }

    /// 帯域の書き方（長さ・ネットマスク・ホストマスク）と、読めないもの（余りのビット・長すぎる）を Python と同じに読むこと。
    #[test]
    fn networks_are_read_like_ipaddress() {
        assert!(TrustedHosts::parse("10.0.0.0/255.0.0.0").contains(Some("10.9.9.9")));
        assert!(TrustedHosts::parse("10.0.0.0/0.255.255.255").contains(Some("10.9.9.9")));
        assert!(!TrustedHosts::parse("10.0.0.1/8").contains(Some("10.0.0.1")));
        assert!(!TrustedHosts::parse("1.2.3.4/33").contains(Some("1.2.3.4")));
        assert!(TrustedHosts::parse("1.2.3.0/024").contains(Some("1.2.3.7")));
        assert!(TrustedHosts::parse("0.0.0.0/0").contains(Some("8.8.8.8")));
        assert!(!TrustedHosts::parse("0.0.0.0/0").contains(Some("::1")));
        assert!(TrustedHosts::parse("testclient").contains(Some("testclient")));
    }

    /// `X-Forwarded-For` の項目のポートを uvicorn と同じに落とし、落とした形で信頼する相手かを見ること。
    ///
    /// `:` のあとが数でなければ落とさない（括弧つきの IPv6 は、数でなくても括弧の中）。括弧の無い IPv6 は触らない。
    #[test]
    fn ports_in_forwarded_for_are_dropped_like_uvicorn() {
        for (raw, host) in [
            ("198.51.100.3:5678", "198.51.100.3"),
            ("198.51.100.52:abc", "198.51.100.52:abc"),
            ("198.51.100.53:", "198.51.100.53:"),
            ("198.51.100.55:8_080", "198.51.100.55"),
            ("198.51.100.56:+80", "198.51.100.56"),
            ("198.51.100.59:1_", "198.51.100.59:1_"),
            ("[2001:db8::7]:8443", "2001:db8::7"),
            ("[2001:db8::8]", "2001:db8::8"),
            ("[2001:db8::9]:abc", "2001:db8::9"),
            ("[2001:db8::a]x", "[2001:db8::a]x"),
            ("[2001:db8::b", "[2001:db8::b"),
            ("2001:db8::7", "2001:db8::7"),
            ("unknown", "unknown"),
        ] {
            assert_eq!(without_port(raw), host, "{raw}");
        }
        let trusted = TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES);
        assert_eq!(
            trusted.client_host("198.51.100.51, 172.18.0.1:9999"),
            "198.51.100.51"
        );
    }

    /// `X-Forwarded-For` が 2 つ以上あれば、つないで 1 つとして読むこと（最後の 1 つだけを読むと、信頼する nginx が
    /// 足した項目しか見えない）。
    #[test]
    fn several_forwarded_for_headers_are_joined() {
        let trusted = TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES);
        let forwarded = headers(&[
            ("x-forwarded-for", "198.51.100.60"),
            ("x-forwarded-for", "172.18.0.1"),
        ]);
        let got = resolve(&trusted, Some("172.18.0.2"), &forwarded);
        assert_eq!(got.client.as_deref(), Some("198.51.100.60"));
    }
}
