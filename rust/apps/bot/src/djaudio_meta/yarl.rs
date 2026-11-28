//! aiohttp 3.14.5 が送る要求の行（パスとクエリ）を作るところ（yarl 1.25.1 の `URL(文字列)`・`extend_query`・
//! `raw_path_qs` と `_Quoter`）の写し。
//!
//! Deezer の ISRC の URL（`https://api.deezer.com/track/isrc:{isrc}`）・検索の `params={"q": q, "limit": 5}`・
//! カバー画像の URL を、Python と同じバイト列にする。
//!
//! reqwest（url crate）に渡すと、クエリの中の `'` だけは `%27` に直される（WHATWG の特別なスキームのクエリの
//! 符号化）。それ以外はここで作ったままの形で送られる（テストで確かめている）。

use crate::djaudio_meta::pyint::py_int;

const ALLOWED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$'()*,";
const QS: &str = "+&=;";

/// yarl の `_Quoter`。
#[derive(Clone, Copy)]
struct Quoter {
    safe: &'static str,
    protected: &'static str,
    qs: bool,
    requote: bool,
}

/// パスの直し（`PATH_REQUOTER`）。
const PATH_REQUOTER: Quoter = Quoter {
    safe: "@:",
    protected: "/+",
    qs: false,
    requote: true,
};
/// URL の中にあったクエリの直し（`QUERY_REQUOTER`）。
const QUERY_REQUOTER: Quoter = Quoter {
    safe: "?/:@",
    protected: "=+&;",
    qs: true,
    requote: true,
};
/// `params` の鍵と値の符号化（`QUERY_PART_QUOTER`）。
const QUERY_PART_QUOTER: Quoter = Quoter {
    safe: "?/:@",
    protected: "",
    qs: true,
    requote: false,
};
/// 利用者名・合言葉の直し（`REQUOTER`）。
const REQUOTER: Quoter = Quoter {
    safe: "",
    protected: "",
    qs: false,
    requote: true,
};

impl Quoter {
    fn quote(&self, val: &str) -> String {
        if val.is_empty() {
            return String::new();
        }
        let mut safe: Vec<u8> = self.safe.bytes().chain(ALLOWED.bytes()).collect();
        if !self.qs {
            safe.extend(QS.bytes());
        }
        safe.extend(self.protected.bytes());
        let bval = val.as_bytes();
        let mut ret: Vec<u8> = Vec::with_capacity(bval.len());
        let mut pct: Vec<u8> = Vec::new();
        let mut idx = 0;
        while idx < bval.len() {
            let mut ch = bval[idx];
            idx += 1;
            if !pct.is_empty() {
                if ch.is_ascii_lowercase() {
                    ch -= 32;
                }
                pct.push(ch);
                if pct.len() == 3 {
                    let buf = &pct[1..];
                    let shaped = buf
                        .iter()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
                    let value = std::str::from_utf8(buf)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok());
                    match value.filter(|_| shaped) {
                        None => {
                            ret.extend_from_slice(b"%25");
                            pct.clear();
                            idx -= 2;
                            continue;
                        }
                        Some(v) => {
                            if v < 0x80 && self.protected.as_bytes().contains(&v) {
                                ret.extend_from_slice(&pct);
                            } else if v < 0x80 && safe.contains(&v) {
                                ret.push(v);
                            } else {
                                ret.extend_from_slice(&pct);
                            }
                            pct.clear();
                        }
                    }
                } else if pct.len() == 2 && idx == bval.len() {
                    ret.extend_from_slice(b"%25");
                    pct.clear();
                    idx -= 1;
                }
                continue;
            } else if ch == b'%' && self.requote {
                pct.clear();
                pct.push(ch);
                if idx == bval.len() {
                    ret.extend_from_slice(b"%25");
                }
                continue;
            }
            if self.qs && ch == b' ' {
                ret.push(b'+');
                continue;
            }
            if safe.contains(&ch) {
                ret.push(ch);
                continue;
            }
            ret.extend_from_slice(format!("%{ch:02X}").as_bytes());
        }
        String::from_utf8(ret).unwrap_or_default()
    }
}

/// URL を読めなかった（yarl の ValueError。aiohttp は `InvalidUrlClientError`＝ClientError にする）。
#[derive(Debug)]
pub struct InvalidUrl(pub String);

/// yarl で読んだ URL（符号化したあとの部品）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// スキーム（小文字）。
    pub scheme: String,
    /// 利用者名・合言葉・ホスト・ポート（`user:pass@host:port`）。
    pub netloc: String,
    /// パス。
    pub path: String,
    /// クエリ（`?` を除く）。
    pub query: String,
}

/// `urllib.parse.scheme_chars`。
fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// yarl の `normalize_path`（`.` と `..` を除く）。
fn normalize_path(path: &str) -> String {
    let (prefix, rest) = match path.strip_prefix('/') {
        Some(r) => ("/", r),
        None => ("", path),
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let mut resolved: Vec<&str> = Vec::new();
    for seg in &segments {
        if *seg == ".." {
            resolved.pop();
        } else if *seg != "." {
            resolved.push(seg);
        }
    }
    if segments.last().is_some_and(|s| *s == "." || *s == "..") {
        resolved.push("");
    }
    format!("{prefix}{}", resolved.join("/"))
}

/// yarl の `_encode_host`（ASCII のホスト名は小文字、IPv4 はそのまま。ASCII でないものは url crate に任せる）。
fn encode_host(host: &str) -> String {
    if host.is_ascii() {
        host.to_ascii_lowercase()
    } else {
        host.to_string()
    }
}

/// `URL(text)`（`encode_url`）。
pub fn parse(text: &str) -> Result<Url, InvalidUrl> {
    let bad = |why: &str| InvalidUrl(why.to_string());
    // split_url
    let mut url: String = text
        .trim_start_matches(|c: char| u32::from(c) <= 0x20)
        .to_string();
    url.retain(|c| !matches!(c, '\t' | '\r' | '\n'));
    let mut scheme = String::new();
    if let Some(i) = url.find(':') {
        let head = &url[..i];
        if i > 0 && head.chars().all(is_scheme_char) {
            scheme = head.to_ascii_lowercase();
            url = url[i + 1..].to_string();
        }
    }
    let has_hash = url.contains('#');
    let has_question = url.contains('?');
    let mut netloc = String::new();
    if url.starts_with("//") {
        let delims: &[char] = match (has_hash, has_question) {
            (true, true) => &['/', '?', '#'],
            (false, true) => &['/', '?'],
            (true, false) => &['/', '#'],
            (false, false) => &['/'],
        };
        let delim = url[2..].find(delims).map_or(url.len(), |p| p + 2);
        netloc = url[2..delim].to_string();
        url = url[delim..].to_string();
        if netloc.contains('\\') {
            return Err(bad("backslash in authority"));
        }
        if netloc.contains('[') || netloc.contains(']') {
            // IPv6 の書き方は写していない（Deezer の URL には出ない）。
            return Err(bad("IPv6 URL is not supported"));
        }
    }
    let mut fragment_cut = url.as_str();
    if has_hash {
        fragment_cut = url.split_once('#').map_or(fragment_cut, |(a, _)| a);
    }
    let (path, query) = match fragment_cut.split_once('?') {
        Some((p, q)) if has_question => (p.to_string(), q.to_string()),
        _ => (fragment_cut.to_string(), String::new()),
    };
    // netloc
    let mut new_netloc = String::new();
    if !netloc.is_empty() {
        let (userinfo, hostinfo) = match netloc.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, netloc.as_str()),
        };
        let (hostname, port) = match hostinfo.split_once(':') {
            Some((h, p)) if !p.is_empty() => {
                let port = py_int(p)
                    .filter(|v| !v.negative && v.lt(65536))
                    .ok_or_else(|| bad("bad port"))?;
                (h, Some(port.to_decimal()))
            }
            Some((h, _)) => (h, None),
            None => (hostinfo, None),
        };
        if hostname.is_empty() && matches!(scheme.as_str(), "http" | "https" | "ws" | "wss" | "ftp")
        {
            return Err(bad("host is required"));
        }
        let host = encode_host(hostname);
        let host_port = match port {
            Some(p) => format!("{host}:{p}"),
            None => host,
        };
        new_netloc = match userinfo {
            Some(u) => {
                let (user, password) = match u.split_once(':') {
                    Some((a, b)) => (a, Some(b)),
                    None => (u, None),
                };
                let user = if user.is_empty() {
                    String::new()
                } else {
                    REQUOTER.quote(user)
                };
                match password {
                    Some(p) => {
                        let p = if p.is_empty() {
                            String::new()
                        } else {
                            REQUOTER.quote(p)
                        };
                        format!("{user}:{p}@{host_port}")
                    }
                    None if !user.is_empty() => format!("{user}@{host_port}"),
                    None => host_port,
                }
            }
            None => host_port,
        };
    }
    let mut path = if path.is_empty() {
        path
    } else {
        PATH_REQUOTER.quote(&path)
    };
    if !new_netloc.is_empty() && path.contains('.') {
        path = normalize_path(&path);
    }
    let query = if query.is_empty() {
        query
    } else {
        QUERY_REQUOTER.quote(&query)
    };
    Ok(Url {
        scheme,
        netloc: new_netloc,
        path,
        query,
    })
}

impl Url {
    /// `extend_query({"q": q, "limit": 5})` のように、鍵と値の組を足す（値は文字列）。
    pub fn extend_query(&mut self, pairs: &[(&str, &str)]) {
        let new: Vec<String> = pairs
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    QUERY_PART_QUOTER.quote(k),
                    QUERY_PART_QUOTER.quote(v)
                )
            })
            .collect();
        let new = new.join("&");
        if new.is_empty() {
            return;
        }
        if self.query.is_empty() {
            self.query = new;
        } else if self.query.ends_with('&') {
            self.query.push_str(&new);
        } else {
            self.query = format!("{}&{new}", self.query);
        }
    }

    /// 要求の行に載るパスとクエリ（`raw_path_qs`）。
    pub fn raw_path_qs(&self) -> String {
        let path = if self.path.is_empty() && !self.netloc.is_empty() {
            "/"
        } else {
            self.path.as_str()
        };
        if self.query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", self.query)
        }
    }

    /// reqwest に渡す URL の文字列。
    pub fn to_request_url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.netloc, self.raw_path_qs())
    }
}
