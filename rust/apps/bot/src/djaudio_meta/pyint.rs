//! Python 3.13 の `int(文字列)` の写し（mutagen の日付・トラック番号・ジャンル番号の読み方が使う）。
//!
//! Python の `int()` は、前後の空白・`+`/`-`・数字の間の `_`・ASCII 以外の 10 進の数字（全角・アラビアの数字など）を
//! 受け付ける。4300 桁を超えると ValueError（`sys.get_int_max_str_digits()` の既定）。

use super::text::{is_digit, is_space};

/// Python の `int()` の結果。桁は先頭の 0 を除いた 10 進（0 は "0"）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyInt {
    /// 負か（0 は負にしない）。
    pub negative: bool,
    /// 10 進の桁。
    pub digits: String,
}

/// Python が `int()` で受け付ける桁数の上限（`sys.int_info.default_max_str_digits`）。
const MAX_STR_DIGITS: usize = 4300;

/// 10 進の数字の値（Python の `unicodedata.decimal`）。数字は 0〜9 の続きで並ぶので、続きの始めからの位置で決まる。
pub fn decimal_value(c: char) -> Option<u32> {
    if !is_digit(c) {
        return None;
    }
    let mut start = u32::from(c);
    while start > 0 && char::from_u32(start - 1).is_some_and(is_digit) {
        start -= 1;
    }
    Some((u32::from(c) - start) % 10)
}

impl PyInt {
    /// 値が 0 か。
    pub fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    /// u64 に収まるなら、その値（負なら None）。
    pub fn to_u64(&self) -> Option<u64> {
        if self.negative {
            return None;
        }
        self.digits.parse().ok()
    }

    /// 値が n より小さいか。
    pub fn lt(&self, n: u64) -> bool {
        self.negative || self.to_u64().is_some_and(|v| v < n)
    }

    /// Python の `"%0{width}d" % 値`。
    pub fn zero_pad(&self, width: usize) -> String {
        let body_width = if self.negative {
            width.saturating_sub(1)
        } else {
            width
        };
        let mut out = String::new();
        if self.negative {
            out.push('-');
        }
        for _ in self.digits.len()..body_width {
            out.push('0');
        }
        out.push_str(&self.digits);
        out
    }

    /// Python の `str(値)`。
    pub fn to_decimal(&self) -> String {
        self.zero_pad(0)
    }
}

/// Python の `int(text)`。ValueError なら None。
pub fn py_int(text: &str) -> Option<PyInt> {
    // _PyUnicode_TransformDecimalAndSpaceToASCII: ASCII（0x7F 未満）はそのまま、ほかの空白は ' '、
    // 10 進の数字は ASCII の数字、それ以外は受け付けない文字。
    let mut ascii = Vec::with_capacity(text.len());
    for c in text.chars() {
        if u32::from(c) < 127 {
            ascii.push(c as u8);
        } else if is_space(c) {
            ascii.push(b' ');
        } else {
            let d = decimal_value(c)?;
            ascii.push(b'0' + d as u8);
        }
    }
    // PyLong_FromString(base=10): 前の空白、符号、`_` を挟んだ数字、後ろの空白。
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    let mut i = 0;
    while i < ascii.len() && is_ws(ascii[i]) {
        i += 1;
    }
    let mut negative = false;
    if i < ascii.len() && (ascii[i] == b'+' || ascii[i] == b'-') {
        negative = ascii[i] == b'-';
        i += 1;
    }
    if i < ascii.len() && ascii[i] == b'_' {
        return None;
    }
    let mut digits = String::new();
    let mut prev = 0u8;
    while i < ascii.len() && (ascii[i].is_ascii_digit() || ascii[i] == b'_') {
        if ascii[i] == b'_' {
            if prev == b'_' {
                return None;
            }
        } else {
            digits.push(ascii[i] as char);
        }
        prev = ascii[i];
        i += 1;
    }
    if prev == b'_' || digits.is_empty() || digits.len() > MAX_STR_DIGITS {
        return None;
    }
    while i < ascii.len() && is_ws(ascii[i]) {
        i += 1;
    }
    if i != ascii.len() {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    let digits = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };
    let negative = negative && digits != "0";
    Some(PyInt { negative, digits })
}
