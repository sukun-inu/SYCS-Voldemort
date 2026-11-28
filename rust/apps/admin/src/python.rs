//! Python の値と文字の扱いのうち、管理画面の骨組みが使うものの写し。どれも基準（`tests/fixtures/session/`）で
//! Python の答えと突き合わせる。
//!
//! - `json.dumps`（既定の書き方〔セッションの Cookie〕と、詰めた書き方〔`JSONResponse`・インシデント〕）と小数の `repr`
//! - `base64.b64decode`（`validate` しない読み方。`binascii.a2b_base64` の strict でない動き）と書き方
//! - starlette の Cookie の読み方（`cookie_parser` と `http.cookies._unquote`）
//! - `str(int(x))`（`_compact_admin_guilds` の ID）と `str(x)`
//! - フォームの値の戻し方（latin-1 で読んだ文字に `urllib.parse.unquote_plus`）
//! - `str.splitlines()`（インシデントの切り詰め）と、`request.url.path`（`urlsplit` の path）
//! - `urllib.parse.quote`（付け替え先の `Location`）
//!
//! Python と違うところ: Rust の文字列はサロゲートを持てないので、`json.loads` がそのまま通す単独のサロゲート
//! （`"\ud800"`）や `NaN`・`Infinity`、64 ビットを超える整数は扱えない（セッションの Cookie では、秘密鍵を知って
//! いる人が作ったものにしか出てこない。`session` の説明）。

use std::fmt::Write as _;
use std::sync::OnceLock;

use axum::http::HeaderMap;
use serde_json::{Map, Number, Value};

pub use sycs_web::proxy::{latin1, python_strip as strip};

/// 文字の種類ごとの範囲（Bot と配信が使っている Python 3.13 の表。`d` が `str.isdecimal()`）。
const CLASSES_TSV: &str = include_str!("../../bot/src/python_char_classes.tsv");

/// `json.dumps` の書き方。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    /// ASCII 以外を `\uXXXX` にするか（Python の `ensure_ascii`）。
    pub ensure_ascii: bool,
    /// 要素の区切り。
    pub item_separator: &'static str,
    /// 鍵と値の区切り。
    pub key_separator: &'static str,
}

/// `json.dumps(value)`（既定）。starlette がセッションを Cookie に書くときの形。
pub const DEFAULT: Style = Style {
    ensure_ascii: true,
    item_separator: ", ",
    key_separator: ": ",
};

/// `json.dumps(value, ensure_ascii=False, separators=(",", ":"))`。starlette の `JSONResponse` とインシデントの形。
pub const COMPACT: Style = Style {
    ensure_ascii: false,
    item_separator: ",",
    key_separator: ":",
};

/// `json.dumps(value)` を、その書き方で。
pub fn dumps(value: &Value, style: Style) -> String {
    let mut out = String::new();
    write_value(&mut out, value, style);
    out
}

fn write_value(out: &mut String, value: &Value, style: Style) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number_text(number)),
        Value::String(text) => write_string(out, text, style.ensure_ascii),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_separator);
                }
                write_value(out, item, style);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_separator);
                }
                write_string(out, key, style.ensure_ascii);
                out.push_str(style.key_separator);
                write_value(out, item, style);
            }
            out.push('}');
        }
    }
}

/// 数の書き方（整数はそのまま、小数は Python の `repr`）。
pub fn number_text(number: &Number) -> String {
    if let Some(u) = number.as_u64() {
        return u.to_string();
    }
    if let Some(i) = number.as_i64() {
        return i.to_string();
    }
    let x = number.as_f64().unwrap_or(f64::NAN);
    if x.is_nan() {
        "NaN".to_string()
    } else if x.is_infinite() {
        if x > 0.0 { "Infinity" } else { "-Infinity" }.to_string()
    } else {
        float_repr(x)
    }
}

/// 文字列を JSON の文字にする。Python の `encode_basestring_ascii`（`ensure_ascii`）と `encode_basestring`。
///
/// どちらも `"`・`\`・制御文字（0x20 未満。5 つは短い形）を逃がす。`ensure_ascii` なら、空白〜`~` の外を全部
/// `\uXXXX`（小文字の 16 進。BMP の外はサロゲートの組）にする（0x7F も逃がす）。
fn write_string(out: &mut String, text: &str, ensure_ascii: bool) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c if ensure_ascii && !(' '..='~').contains(&c) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// 小数の Python の `repr`（いちばん短く元へ戻る桁。小数点の位置が -4 以下か 16 を超えれば指数の形）。
///
/// 桁は Rust の `{:e}`（いちばん短い桁）から取る。Python の `float_repr_style == "short"` と同じ規則で並べる:
/// `1e+16`・`1000000000000000.0`・`0.0001`・`1e-05`・`123.0`・`-0.0`。
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    let scientific = format!("{:e}", x.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let count = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    // 小数点が digits のどこに来るか（0.d1d2… × 10^point）。
    let point = exponent + 1;
    let sign = if x < 0.0 { "-" } else { "" };
    let body = if point <= -4 || point > 16 {
        let mut head = digits[..1].to_string();
        if digits.len() > 1 {
            head.push('.');
            head.push_str(&digits[1..]);
        }
        let e = point - 1;
        format!("{head}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
    } else if point <= 0 {
        format!(
            "0.{}{digits}",
            "0".repeat(usize::try_from(-point).unwrap_or(0))
        )
    } else if point >= count {
        format!(
            "{digits}{}.0",
            "0".repeat(usize::try_from(point - count).unwrap_or(0))
        )
    } else {
        let (whole, fraction) = digits.split_at(usize::try_from(point).unwrap_or(0));
        format!("{whole}.{fraction}")
    };
    format!("{sign}{body}")
}

/// base64 の 1 文字の値（標準の字）。
fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `base64.b64decode(data)`（`validate=False`。`binascii.a2b_base64(data, strict_mode=False)`）。
///
/// 字でないものは黙って飛ばし、`=` の詰め物で終わる。数が合わなければ（字が 4 の倍数＋1、詰め物が足りない）`None`。
/// `urlsafe` なら先に `-` を `+`、`_` を `/` に直す（`base64.urlsafe_b64decode`。`+` と `/` もそのまま読む）。
pub fn b64decode(data: &[u8], urlsafe: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad = 0u8;
    let mut left = 0u8;
    let mut pads = 0u8;
    for &raw in data {
        let byte = match (urlsafe, raw) {
            (true, b'-') => b'+',
            (true, b'_') => b'/',
            _ => raw,
        };
        if byte == b'=' {
            // C の `quad_pos >= 2 && quad_pos + ++pads >= 4`（詰め物は 2 文字目より後でだけ数える）。
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let Some(value) = b64_value(byte) else {
            continue;
        };
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = value;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    (quad == 0).then_some(out)
}

/// itsdangerous の `base64_decode`（足りない `=` を足してから `urlsafe_b64decode`）。
pub fn itsdangerous_b64decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut padded = data.to_vec();
    padded.resize(data.len() + (4 - data.len() % 4) % 4, b'=');
    b64decode(&padded, true)
}

/// base64 で書く。`urlsafe` なら `-_`（itsdangerous の `base64_encode`）、`pad` が偽なら `=` を落とす。
pub fn b64encode(data: &[u8], urlsafe: bool, pad: bool) -> String {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if urlsafe { URLSAFE } else { STANDARD };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let indexes = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0f) << 2) | (b[2] >> 6),
            b[2] & 0x3f,
        ];
        let used = chunk.len() + 1;
        for (i, index) in indexes.iter().enumerate() {
            if i < used {
                out.push(char::from(alphabet[usize::from(*index)]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// `http.cookies._unquote`（starlette の `cookie_parser` が値に当てる）。
///
/// `"` で始まり `"` で終わる 2 文字以上のものだけ、両端を落として `\ooo`（8 進、先頭は 0〜3）と `\x`（改行以外の
/// 1 文字）を戻す。どちらにも当たらない `\` はそのまま残す。
pub fn cookie_unquote(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 2 || chars[0] != '"' || chars[chars.len() - 1] != '"' {
        return text.to_string();
    }
    let inner = &chars[1..chars.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let c = inner[i];
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let octal = inner.get(i + 1..i + 4).filter(|digits| {
            ('0'..='3').contains(&digits[0])
                && ('0'..='7').contains(&digits[1])
                && ('0'..='7').contains(&digits[2])
        });
        if let Some(digits) = octal {
            let value = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + d.to_digit(8).unwrap_or(0));
            out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
            i += 4;
        } else if let Some(next) = inner.get(i + 1).filter(|next| **next != '\n') {
            out.push(*next);
            i += 2;
        } else {
            out.push('\\');
            i += 1;
        }
    }
    out
}

/// starlette の `HTTPConnection.cookies`（`Cookie` の見出しを全部、来た順に `cookie_parser` で読んで上書きする）。
///
/// `;` で区切り、`=` があれば最初の `=` で名前と値に分け（無ければ名前は空）、前後の空白を落とす。両方とも空なら
/// 捨てる。値には [`cookie_unquote`] を当てる。並びは Python の dict と同じ（最初に出た位置、最後の値）。
pub fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut cookies: Vec<(String, String)> = Vec::new();
    for header in headers.get_all("cookie") {
        let text = latin1(header.as_bytes());
        for chunk in text.split(';') {
            let (key, value) = chunk.split_once('=').unwrap_or(("", chunk));
            let (key, value) = (strip(key), strip(value));
            if key.is_empty() && value.is_empty() {
                continue;
            }
            let value = cookie_unquote(value);
            match cookies.iter_mut().find(|(name, _)| name.as_str() == key) {
                Some(slot) => slot.1 = value,
                None => cookies.push((key.to_string(), value)),
            }
        }
    }
    cookies
}

/// その名前の Cookie の値（[`parse_cookies`] の答えから）。
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    parse_cookies(headers)
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

/// `str.isdecimal()` が真の文字の範囲（始めの順）。
fn decimal_ranges() -> &'static [(u32, u32)] {
    static RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    RANGES.get_or_init(|| {
        let mut ranges = Vec::new();
        for line in CLASSES_TSV.lines() {
            let mut parts = line.trim_end().split('\t');
            let (Some("d"), Some(start), Some(end)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if let (Ok(start), Ok(end)) =
                (u32::from_str_radix(start, 16), u32::from_str_radix(end, 16))
            {
                ranges.push((start, end));
            }
        }
        ranges.sort_unstable();
        ranges
    })
}

/// 10 進の数字（Unicode の Nd）の値。Nd は 0〜9 が 10 文字ずつ続けて並ぶので、範囲の始めからの差を 10 で割った余り。
pub fn decimal_value(c: char) -> Option<u32> {
    let code = u32::from(c);
    let ranges = decimal_ranges();
    let after = ranges.partition_point(|(start, _)| *start <= code);
    let (start, end) = *ranges.get(after.checked_sub(1)?)?;
    (code <= end).then_some((code - start) % 10)
}

/// `str(int(text))`（10 進）。前後の空白・`+`・`-`・数の間の `_`（1 つずつ）・Unicode の 10 進の数字を読む。
/// 読めなければ `None`（Python の `ValueError`）。
fn int_text_of_str(text: &str) -> Option<String> {
    let text = strip(text);
    let (negative, digits) = match text.chars().next() {
        Some('-') => (true, &text[1..]),
        Some('+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut value = String::with_capacity(digits.len());
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        value.push(char::from_digit(decimal_value(c)?, 10)?);
    }
    let trimmed = value.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_string()
    } else if negative {
        format!("-{trimmed}")
    } else {
        trimmed.to_string()
    })
}

/// `str(int(value))`。読めなければ `None`（Python の `TypeError`・`ValueError`）。
///
/// 真偽は 1 と 0、小数は 0 の方へ切り捨てた整数（桁は全部）、文字は 10 進として読む。null・並び・辞書は読めない。
pub fn int_text(value: &Value) -> Option<String> {
    match value {
        Value::Bool(b) => Some(if *b { "1" } else { "0" }.to_string()),
        Value::Number(number) => {
            if let Some(u) = number.as_u64() {
                return Some(u.to_string());
            }
            if let Some(i) = number.as_i64() {
                return Some(i.to_string());
            }
            let x = number.as_f64().filter(|x| x.is_finite())?;
            let text = format!("{:.0}", x.trunc());
            Some(if text == "-0" { "0".to_string() } else { text })
        }
        Value::String(text) => int_text_of_str(text),
        _ => None,
    }
}

/// `str(value)`。文字はそのまま、null は `None`、真偽は `True`・`False`、数は Python の書き方、並びと辞書は [`repr`]。
pub fn str_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => repr(other),
    }
}

/// `repr(value)`。並びと辞書の中の文字は Python の `repr` の引用（`'` か、`'` を含み `"` を含まなければ `"`）。
///
/// 文字の逃がし方は、制御文字と 0x7F〜0xA0 を `\xNN` にするところまで（Python は Unicode の「表示できない文字」を
/// 全部逃がす。ここが要るのは、セッションの ID や名前に並びや辞書が入ったときだけ）。
pub fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => {
            let text = number_text(number);
            match text.as_str() {
                "NaN" => "nan".to_string(),
                "Infinity" => "inf".to_string(),
                "-Infinity" => "-inf".to_string(),
                _ => text,
            }
        }
        Value::String(text) => repr_str(text),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}: {}", repr_str(key), repr(item)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 || (0x7f..=0xa0).contains(&u32::from(c)) => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// JSON の値の Python での真偽（`if value:`。null・偽・0・空の文字と並びと辞書が偽）。
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// JSON の値を Python で読んだときの型の名前（例外の文面に使う）。
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// starlette のフォームの値の戻し方。バイトを latin-1 で文字にし、`unquote_plus`（`+` を空白にし、ASCII の続きごとに
/// `%XX` を戻して UTF-8 として読む。読めない並びは U+FFFD。ASCII でない文字はそのまま）。
pub fn form_unquote(raw: &[u8]) -> String {
    let text = latin1(raw).replace('+', " ");
    let mut out = String::with_capacity(text.len());
    let mut run: Vec<u8> = Vec::new();
    for c in text.chars() {
        if c.is_ascii() {
            run.push(u8::try_from(u32::from(c)).unwrap_or(b'?'));
        } else {
            flush_ascii(&mut out, &mut run);
            out.push(c);
        }
    }
    flush_ascii(&mut out, &mut run);
    out
}

fn flush_ascii(out: &mut String, run: &mut Vec<u8>) {
    if run.is_empty() {
        return;
    }
    let decoded: Vec<u8> = percent_encoding::percent_decode(run.as_slice()).collect();
    out.push_str(&String::from_utf8_lossy(&decoded));
    run.clear();
}

/// `str.splitlines()`（区切りは捨てる。最後の区切りのあとに空の行は作らない）。区切りは Python と同じ
/// `\n`・`\r`・`\r\n`・`\v`・`\f`・`\x1c`・`\x1d`・`\x1e`・`\x85`・`\u2028`・`\u2029`。
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let separator = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !separator {
            continue;
        }
        lines.push(&text[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|(_, n)| *n == '\n') {
            chars.next();
            next += 1;
        }
        start = next;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `request.url.path`。starlette は戻したパスから URL を組み直して `urlsplit` するので、タブと改行（`\t`・`\r`・`\n`）は
/// 消え、`?` か `#` から後ろは問い合わせ・断片として落ちる（Host は starlette が確かめるので、パスには響かない）。
pub fn url_path(decoded: &str) -> String {
    let cleaned: String = decoded
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let end = cleaned.find(['?', '#']).unwrap_or(cleaned.len());
    cleaned[..end].to_string()
}

/// `urllib.parse.quote(text, safe=safe)`。UTF-8 のバイトごとに、英数字・`_.-~`・`safe` の文字はそのまま、ほかは
/// `%XX`（大文字の 16 進）にする。`safe` は ASCII だけ。
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        let c = char::from(byte);
        if byte.is_ascii_alphanumeric()
            || b"_.-~".contains(&byte)
            || (byte.is_ascii() && safe.contains(c))
        {
            out.push(c);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `html.escape(text)`（`quote=True`）。A1 の仮のエラーのページだけが使う。
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// 辞書を作る（鍵の順は渡した順）。
pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    /// 小数の repr が Python と同じ規則で並ぶこと（指数の形に変わる境・-0.0・末尾の .0）。
    #[test]
    fn floats_are_written_like_python_repr() {
        for (x, want) in [
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (123.0, "123.0"),
            (1_798_761_600.25, "1798761600.25"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1.5e-7, "1.5e-07"),
            (5e-324, "5e-324"),
            (-2.5e300, "-2.5e+300"),
        ] {
            assert_eq!(float_repr(x), want, "{x}");
        }
    }

    /// 既定の書き方は ASCII 以外を小文字の \u に、詰めた書き方はそのまま残すこと（0x7F は既定だけ逃がす）。
    #[test]
    fn json_is_dumped_like_python() {
        let value = json!({"a": [1, -2, 1.0, true, null], "テ😀": "x\"\\\n\u{7f}\u{1}"});
        assert_eq!(
            dumps(&value, DEFAULT),
            r#"{"a": [1, -2, 1.0, true, null], "\u30c6\ud83d\ude00": "x\"\\\n\u007f\u0001"}"#
        );
        assert_eq!(
            dumps(&value, COMPACT),
            "{\"a\":[1,-2,1.0,true,null],\"テ😀\":\"x\\\"\\\\\\n\u{7f}\\u0001\"}"
        );
        assert_eq!(dumps(&json!({}), DEFAULT), "{}");
        assert_eq!(dumps(&json!([]), DEFAULT), "[]");
    }

    /// base64 を Python と同じに緩く読むこと（字でないものは飛ばす・詰め物で止まる・数が合わなければ読めない）。
    #[test]
    fn base64_is_read_leniently_like_binascii() {
        assert_eq!(b64decode(b"e30=", false).unwrap(), b"{}");
        assert_eq!(b64decode(b"e3!0=", false).unwrap(), b"{}");
        assert_eq!(b64decode(b"e30=junk", false).unwrap(), b"{}");
        assert!(b64decode(b"e30", false).is_none());
        assert!(b64decode(b"e", false).is_none());
        assert_eq!(b64decode(b"!!!", false).unwrap(), b"");
        assert_eq!(b64decode(b"-_8", true), b64decode(b"+/8", false));
        assert_eq!(
            itsdangerous_b64decode(b"azbsgA").unwrap(),
            vec![0x6b, 0x36, 0xec, 0x80]
        );
        assert_eq!(b64encode(&[0x6b, 0x36, 0xec, 0x80], true, false), "azbsgA");
        assert_eq!(b64encode(b"{}", false, true), "e30=");
        assert_eq!(b64encode(b"", false, true), "");
    }

    /// Cookie を starlette と同じに読むこと（後の値が勝つ・名前の無いもの・引用の戻し方）。
    #[test]
    fn cookies_are_parsed_like_starlette() {
        let mut headers = HeaderMap::new();
        headers.append(
            "cookie",
            HeaderValue::from_static(" a = 1 ; justvalue; b=\"x\\073y\\\"\"; ;"),
        );
        headers.append("cookie", HeaderValue::from_static("a=2"));
        assert_eq!(
            parse_cookies(&headers),
            vec![
                ("a".to_string(), "2".to_string()),
                (String::new(), "justvalue".to_string()),
                ("b".to_string(), "x;y\"".to_string()),
            ]
        );
        assert_eq!(cookie_unquote("\""), "\"");
        assert_eq!(cookie_unquote("\"a\\\nb\""), "a\\\nb");
        assert_eq!(cookie_unquote("\"\\400\""), "400");
    }

    /// str(int(x)) を Python と同じに読むこと（空白・符号・_・全角の数字・小数の切り捨て・読めないもの）。
    #[test]
    fn ints_are_read_like_python() {
        for (value, want) in [
            (json!(" 0012 "), Some("12")),
            (json!("-0"), Some("0")),
            (json!("+1_000"), Some("1000")),
            (json!("１２"), Some("12")),
            (json!("٣"), Some("3")),
            (json!(1.9), Some("1")),
            (json!(-0.5), Some("0")),
            (json!(1e20), Some("100000000000000000000")),
            (json!(true), Some("1")),
            (json!("1__0"), None),
            (json!("_1"), None),
            (json!("0x10"), None),
            (json!(""), None),
            (json!(null), None),
            (json!([1]), None),
        ] {
            assert_eq!(int_text(&value).as_deref(), want, "{value}");
        }
    }

    /// splitlines が Python と同じ区切りで割ること（\r\n は 1 つ、最後の区切りのあとに空の行を作らない）。
    #[test]
    fn lines_are_split_like_python() {
        assert_eq!(
            splitlines("a\r\nb\rc\u{2028}d\u{85}e\n\nf\n"),
            vec!["a", "b", "c", "d", "e", "", "f"]
        );
        assert!(splitlines("").is_empty());
    }

    /// request.url.path がタブと改行を消し、? と # で切ること。フォームの値が latin-1 と %XX の両方で戻ること。
    #[test]
    fn url_paths_and_form_values_match_starlette() {
        assert_eq!(url_path("/admin/api\n/x"), "/admin/api/x");
        assert_eq!(url_path("/admin/api?x/y#z"), "/admin/api");
        assert_eq!(form_unquote(b"a+b%20c%E3%81%82"), "a b cあ");
        assert_eq!(form_unquote(b"%E3%81\xe9%82"), "\u{fffd}\u{e9}\u{fffd}");
        assert_eq!(
            quote("/a b/あ#x", ":/%#?=@[]!$&'()*+,;"),
            "/a%20b/%E3%81%82#x"
        );
    }

    /// str() と真偽が Python と同じであること。
    #[test]
    fn str_and_truthiness_match_python() {
        assert_eq!(str_of(&json!(1.0)), "1.0");
        assert_eq!(str_of(&json!(true)), "True");
        assert_eq!(str_of(&json!(null)), "None");
        assert_eq!(str_of(&json!(["a", 1])), "['a', 1]");
        assert_eq!(str_of(&json!({"k": "it's"})), "{'k': \"it's\"}");
        assert!(!truthy(&json!(0.0)));
        assert!(truthy(&json!("0")));
    }
}
