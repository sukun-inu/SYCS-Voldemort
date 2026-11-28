//! Python の文字と値の扱いのうち、配信が使うもの。
//!
//! - `str.isalnum()`・`str.isdigit()`（印と `guild_id` の確かめ。Python は Unicode の英数字も通す）
//! - `str.strip()`（空白は Python の `str.isspace()`）
//! - `urllib.parse.quote()`（`Content-Disposition` と、付け替え先の `Location`）
//! - `html.escape()`（エラーのページ）
//! - JSON の値の真偽（`if value:`）と型の名前（例外の文面）
//!
//! 英数字・10 進の数字・空白の表は、Bot が読み上げで使っている Python 3.13（Unicode 15.1）の表をそのまま読む
//! （`apps/bot/src/python_char_classes.tsv`。`w` は `str.isalnum()` か `_`、`d` は `str.isdecimal()`、`s` は
//! `str.isspace()`。作り方は Bot の `tests/fixtures/tts/generate_classes.py`）。`str.isdigit()` は `d` に
//! [`DIGIT_NOT_DECIMAL`] を足したもの。どちらも、Python の答えと同じかを基準（`tests/fixtures/dlaudio/expected.json`
//! の `chars`）で全部の文字について確かめる。

use std::fmt::Write as _;
use std::sync::OnceLock;

use serde_json::Value;

/// 文字の種類ごとの範囲（種類・始め・終わり。16 進）。Bot と同じ表。
const CLASSES_TSV: &str = include_str!("../../bot/src/python_char_classes.tsv");

/// `str.isdigit()` は真で `str.isdecimal()` は偽の文字（Unicode の Numeric_Type=Digit。上付き・下付き・丸数字など）。
pub const DIGIT_NOT_DECIMAL: &[(u32, u32)] = &[
    (0x00B2, 0x00B3),
    (0x00B9, 0x00B9),
    (0x1369, 0x1371),
    (0x19DA, 0x19DA),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247C),
    (0x2488, 0x2490),
    (0x24EA, 0x24EA),
    (0x24F5, 0x24FD),
    (0x24FF, 0x24FF),
    (0x2776, 0x277E),
    (0x2780, 0x2788),
    (0x278A, 0x2792),
    (0x10A40, 0x10A43),
    (0x10E60, 0x10E68),
    (0x11052, 0x1105A),
    (0x1E8C7, 0x1E8CF),
    (0x1F100, 0x1F10A),
];

/// 表を読んだもの（始めの順に並んでいる）。
struct Tables {
    word: Vec<(u32, u32)>,
    decimal: Vec<(u32, u32)>,
    space: Vec<(u32, u32)>,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut tables = Tables {
            word: Vec::new(),
            decimal: Vec::new(),
            space: Vec::new(),
        };
        for line in CLASSES_TSV.lines() {
            let mut parts = line.trim_end().split('\t');
            let (Some(tag), Some(start), Some(end)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(start), Ok(end)) =
                (u32::from_str_radix(start, 16), u32::from_str_radix(end, 16))
            else {
                continue;
            };
            match tag {
                "w" => tables.word.push((start, end)),
                "d" => tables.decimal.push((start, end)),
                "s" => tables.space.push((start, end)),
                _ => {}
            }
        }
        tables
    })
}

fn in_ranges(ranges: &[(u32, u32)], c: char) -> bool {
    let code = u32::from(c);
    let after = ranges.partition_point(|(start, _)| *start <= code);
    after > 0 && code <= ranges[after - 1].1
}

/// 1 文字の `str.isalnum()`（Python の `re` の `\w` から `_` を除いたもの）。
pub fn is_alnum_char(c: char) -> bool {
    c != '_' && in_ranges(&tables().word, c)
}

/// 1 文字の `str.isdigit()`。
pub fn is_digit_char(c: char) -> bool {
    in_ranges(&tables().decimal, c) || in_ranges(DIGIT_NOT_DECIMAL, c)
}

/// 1 文字の `str.isspace()`。
pub fn is_space_char(c: char) -> bool {
    in_ranges(&tables().space, c)
}

/// `str.isalnum()`（空なら偽）。
pub fn isalnum(text: &str) -> bool {
    !text.is_empty() && text.chars().all(is_alnum_char)
}

/// `str.isdigit()`（空なら偽）。
pub fn isdigit(text: &str) -> bool {
    !text.is_empty() && text.chars().all(is_digit_char)
}

/// `str.strip()`（引数なし。前後の空白を落とす）。
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space_char)
}

/// `urllib.parse.quote(text, safe=safe)`。UTF-8 のバイトごとに、英数字・`_.-~`・`safe` の文字はそのまま、
/// ほかは `%XX`（大文字の 16 進）にする。`safe` は ASCII だけ。
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

/// `html.escape(text)`（`quote=True`。`&` `<` `>` `"` `'` を逃がす）。
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

/// ログに出すための、Python の `str()` に近い書き方（無いものは `None`）。
pub fn str_of(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Unicode の英数字と数字を Python と同じに見ること（`²` は数字、`Ⅰ` は英数字だが数字ではない、`_` は英数字でない）。
    #[test]
    fn characters_are_classified_like_python() {
        assert!(isalnum("abc123"));
        assert!(isalnum("あ漢字"));
        assert!(isalnum("Ⅰ²"));
        assert!(!isalnum("a_b"));
        assert!(!isalnum(""));
        assert!(isdigit("0123"));
        assert!(isdigit("²①٣"));
        assert!(!isdigit("Ⅰ"));
        assert!(!isdigit("12a"));
        assert!(!isdigit(""));
        assert_eq!(strip("\u{3000} a b \u{1c}"), "a b");
    }

    /// `quote` が Python の `urllib.parse.quote` と同じに逃がすこと（空白・日本語・既定の `/`・付け替え先の記号）。
    #[test]
    fn quote_matches_urllib() {
        assert_eq!(quote("Song Title.mp3", "/"), "Song%20Title.mp3");
        assert_eq!(quote("曲.mp3", "/"), "%E6%9B%B2.mp3");
        assert_eq!(quote("a/b~c_d-e", "/"), "a/b~c_d-e");
        assert_eq!(
            quote("a:b?c=d&e%20\n", ":/%#?=@[]!$&'()*+,;"),
            "a:b?c=d&e%20%0A"
        );
    }

    /// `html.escape` が 5 つの文字を逃がすこと。
    #[test]
    fn html_is_escaped_like_python() {
        assert_eq!(
            html_escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }

    /// JSON の値の真偽が Python と同じであること（0.0 と空の辞書は偽、"0" は真）。
    #[test]
    fn truthiness_matches_python() {
        let falsy = [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ];
        for value in falsy {
            assert!(!truthy(&value), "{value}");
        }
        let truthy_values = [
            json!(true),
            json!(1),
            json!(-0.5),
            json!("0"),
            json!([0]),
            json!({"a": 1}),
        ];
        for value in truthy_values {
            assert!(truthy(&value), "{value}");
        }
    }
}
