//! Python の `str()` と `repr()` を、JSON から読んだ値について写す。
//!
//! Python は、例外の文に値の `repr()` をそのまま入れることがある（Groq の SDK は、誤りの応答の本文を
//! `json.loads` で読み、`f"Error code: {状態} - {本文}"` と書く。本文が辞書なら `{'error': {'message': '…'}}` の
//! 形になる）。その文が利用者に見えるところ（AI の会話の返事）を Python と同じにするために使う。
//!
//! Python と違いうるのは、Rust の JSON の読み方が Python と違うところだけ: 64 ビットに収まらない整数
//! （Python は桁を全部持つ。こちらは小数として読む）と、`NaN`・`Infinity`（Python は読む。こちらは読めない）。

use std::sync::OnceLock;

use serde_json::Value;

/// Python が「印字できない」とみなす文字の範囲（`str.isprintable()` が偽になるもの。サロゲートを除く）。
/// Python 3.13（Unicode 15.1）から作った（`tests/fixtures/chat/generate.py nonprintable`）。
const NONPRINTABLE_TSV: &str = include_str!("python_nonprintable.tsv");

/// 印字できない文字の範囲を、始めの順に並べたもの。
fn nonprintable() -> &'static [(u32, u32)] {
    static TABLE: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        NONPRINTABLE_TSV
            .lines()
            .filter_map(|line| {
                let (start, end) = line.trim_end().split_once('\t')?;
                Some((
                    u32::from_str_radix(start, 16).ok()?,
                    u32::from_str_radix(end, 16).ok()?,
                ))
            })
            .collect()
    })
}

/// Python の `str.isprintable()`（1 文字について）。
pub fn is_printable(c: char) -> bool {
    let code = u32::from(c);
    let table = nonprintable();
    // code を含みうるのは、始めが code 以下の最後の範囲だけ。
    let after = table.partition_point(|(start, _)| *start <= code);
    after == 0 || table[after - 1].1 < code
}

/// Python の `str(値)`。文字列はそのまま、ほかは `repr()` と同じ。
pub fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => python_repr(other),
    }
}

/// Python の `repr(値)`。値は `json.loads` が返すもの（辞書・リスト・文字列・数・真偽・None）。
pub fn python_repr(value: &Value) -> String {
    let mut out = String::new();
    write_repr(value, &mut out);
    out
}

fn write_repr(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(true) => out.push_str("True"),
        Value::Bool(false) => out.push_str("False"),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => out.push_str(&i.to_string()),
            (None, Some(u), _) => out.push_str(&u.to_string()),
            (None, None, Some(f)) => out.push_str(&repr_float(f)),
            (None, None, None) => out.push_str(&n.to_string()),
        },
        Value::String(s) => out.push_str(&repr_str(s)),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_repr(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&repr_str(key));
                out.push_str(": ");
                write_repr(item, out);
            }
            out.push('}');
        }
    }
}

/// Python の `repr(文字列)`。
///
/// 引用符は `'`。ただし中に `'` があって `"` が無ければ `"` で囲む。`\`・囲みの引用符・タブ・改行・復帰は
/// `\` を付け、印字できない文字は `\xNN`・`\uNNNN`・`\UNNNNNNNN` と書く。
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        let code = u32::from(c);
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if c == quote => {
                out.push('\\');
                out.push(c);
            }
            _ if is_printable(c) => out.push(c),
            _ if code < 0x100 => out.push_str(&format!("\\x{code:02x}")),
            _ if code < 0x1_0000 => out.push_str(&format!("\\u{code:04x}")),
            _ => out.push_str(&format!("\\U{code:08x}")),
        }
    }
    out.push(quote);
    out
}

/// Python の `repr(小数)`。
///
/// 元の値に戻せるいちばん短い桁で書く。小数点の位置が -4 以下か 16 を超えたら指数の形（`1e+16`・`1e-05`。
/// 指数は 2 桁以上・符号つき）、そうでなければ普通の形（整数でも `.0` を付ける）。
pub fn repr_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.into();
    }
    // Rust の指数の書式も「戻せるいちばん短い桁」を出す（例: 1.2345e20、5e-324、-0e0）。
    let shown = format!("{value:e}");
    let (mantissa, exponent) = shown.split_once('e').unwrap_or((&shown, "0"));
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    // 値 = 0.桁 × 10^point。
    let point = exponent + 1;
    let count = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if point <= -4 || point > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let sign = if exponent < 0 { '-' } else { '+' };
        out.push_str(&format!("e{sign}{:02}", exponent.abs()));
    } else if point <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(usize::try_from(-point).unwrap_or(0)));
        out.push_str(&digits);
    } else if point >= count {
        out.push_str(&digits);
        out.push_str(&"0".repeat(usize::try_from(point - count).unwrap_or(0)));
        out.push_str(".0");
    } else {
        let split = usize::try_from(point).unwrap_or(0);
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 小数の書き方。値は Python 3.13 の `repr()` で確かめたもの。
    #[test]
    fn floats_are_written_like_python() {
        for (value, want) in [
            (1.5, "1.5"),
            (3.0, "3.0"),
            (0.1, "0.1"),
            (100.0, "100.0"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (-2.5, "-2.5"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (9_999_999_999_999_998.0, "9999999999999998.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e22, "1e+22"),
            (123_456_789_012_345_680_000.0, "1.2345678901234568e+20"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (1e100, "1e+100"),
            (123.456, "123.456"),
            (0.001_234, "0.001234"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
        ] {
            assert_eq!(repr_float(value), want);
        }
        assert_eq!(repr_float(f64::NAN), "nan");
    }

    /// 文字列の囲み方と、`\` の付け方。
    #[test]
    fn strings_pick_their_quotes_like_python() {
        assert_eq!(repr_str("plain"), "'plain'");
        assert_eq!(repr_str(""), "''");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("say \"hi\""), "'say \"hi\"'");
        assert_eq!(repr_str("it's \"quoted\""), "'it\\'s \"quoted\"'");
        assert_eq!(repr_str("a\\b\nc\td\re"), "'a\\\\b\\nc\\td\\re'");
        assert_eq!(
            repr_str("\u{1}\u{1f}\u{7f}\u{80}\u{9f}"),
            "'\\x01\\x1f\\x7f\\x80\\x9f'"
        );
        assert_eq!(
            repr_str("a\u{a0}b\u{3000}c\u{2028}d\u{200b}e\u{ad}f\u{feff}g"),
            "'a\\xa0b\\u3000c\\u2028d\\u200be\\xadf\\ufeffg'"
        );
        assert_eq!(repr_str("日本語と絵文字😀 ok"), "'日本語と絵文字😀 ok'");
        assert_eq!(repr_str("\u{e000}\u{378}"), "'\\ue000\\u0378'");
        assert_eq!(repr_str("\u{e0001}"), "'\\U000e0001'");
    }

    /// 印字できない文字の表が読めていて、境目が合っていること。
    #[test]
    fn the_nonprintable_table_is_loaded() {
        let table = nonprintable();
        assert!(table.len() > 600, "{}", table.len());
        assert!(
            table.windows(2).all(|w| w[0].1 < w[1].0),
            "並びが崩れている"
        );
        assert_eq!(table[0], (0, 0x1f));
        for c in [' ', 'a', '~', 'é', 'あ', '😀', '\u{10fffd}'] {
            assert_eq!(is_printable(c), c != '\u{10fffd}', "{c:?}");
        }
        for c in ['\0', '\u{1f}', '\u{7f}', '\u{a0}', '\u{3000}', '\u{10ffff}'] {
            assert!(!is_printable(c), "{c:?}");
        }
    }

    /// 入れ子の値の書き方。文字列だけは、いちばん外では囲まない（`str()`）。
    #[test]
    fn values_are_written_like_python() {
        let value = json!({"error": {"message": "it's", "n": [1, -2, 1.5, null, true, false], "e": {}, "l": []}});
        assert_eq!(
            python_repr(&value),
            "{'error': {'message': \"it's\", 'n': [1, -2, 1.5, None, True, False], 'e': {}, 'l': []}}"
        );
        assert_eq!(python_str(&json!("it's")), "it's");
        assert_eq!(python_repr(&json!("it's")), "\"it's\"");
        assert_eq!(python_str(&json!(null)), "None");
        assert_eq!(
            python_str(&json!(18_446_744_073_709_551_615_u64)),
            "18446744073709551615"
        );
    }
}
