//! 自分に 1 回だけ HTTP/1.1 で尋ねる小さな道具。
//!
//! 本番の CPU（Sandy Bridge）で起動できるかの確かめ（イメージの `cpu-check` の段。待ち受けて、自分に尋ねて、答えを
//! 読むところまでを QEMU の上で通す）と、テストで本当に TCP を通すために使う。HTTP のクライアントの crate を
//! 足すほどのことではないので、`Connection: close` で 1 往復するだけのものを手で書いてある。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 1 往復を待つ長さ（QEMU の上でも足りるように長めにしてある）。
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// 返ってきた答え。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// 状態（200 など）。
    pub status: u16,
    /// 見出し（名前は小文字にしてある。来た順）。
    pub headers: Vec<(String, String)>,
    /// 本文（HEAD なら空。chunked なら解いたもの）。
    pub body: Vec<u8>,
}

impl Answer {
    /// その名前の最初の見出し。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// `addr` に 1 回だけ尋ねる。`host` を渡さなければ `addr` を `Host` にする。
pub async fn request(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
) -> io::Result<Answer> {
    tokio::time::timeout(TIMEOUT, exchange(addr, method, target, headers))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "応答が返ってこない"))?
}

async fn exchange(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
) -> io::Result<Answer> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
        head.push_str(&format!("host: {addr}\r\n"));
    }
    head.push_str("connection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse(&raw, method.eq_ignore_ascii_case("HEAD"))
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// 返ってきたバイトを、状態・見出し・本文に分ける。
fn parse(raw: &[u8], head_only: bool) -> io::Result<Answer> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| invalid("見出しの終わりが無い"))?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| invalid("状態の行が読めない"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let rest = &raw[end + 4..];
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let body = if head_only {
        Vec::new()
    } else if chunked {
        dechunk(rest)?
    } else {
        match length {
            Some(length) => rest[..length.min(rest.len())].to_vec(),
            None => rest.to_vec(),
        }
    };
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// chunked の本文を解く。
fn dechunk(mut rest: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| invalid("chunk の大きさの行が無い"))?;
        let line = String::from_utf8_lossy(&rest[..line_end]);
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| invalid("chunk の大きさが読めない"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            return Err(invalid("chunk が途中で切れている"));
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 状態・見出し・本文を分け、Content-Length で切り、chunked を解き、HEAD は本文を読まないこと。
    #[test]
    fn answers_are_split_into_status_headers_and_body() {
        let plain = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b\r\n\r\nokEXTRA",
            false,
        )
        .unwrap();
        assert_eq!(plain.status, 200);
        assert_eq!(plain.header("x-a"), Some("b"));
        assert_eq!(plain.body, b"ok");
        let chunked = parse(
            b"HTTP/1.1 404 Not Found\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            false,
        )
        .unwrap();
        assert_eq!(chunked.status, 404);
        assert_eq!(chunked.body, b"abcde");
        let head = parse(
            b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 9\r\n\r\n",
            true,
        )
        .unwrap();
        assert!(head.body.is_empty());
    }
}
