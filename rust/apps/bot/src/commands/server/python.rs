//! Python の組み込みの振る舞いのうち、サーバーの設定のコマンドが頼っているもの（`int()`・`str.strip()`・
//! `dict()`・`len()`・辞書の引き方）。
//!
//! 返事の文と設定の鍵を Python と同じにするには、ここを同じにする必要がある。たとえば /reactionrole の
//! メッセージ ID は `int(message_id)` で読まれるので、全角の数字・前後の空白・`1_000` のような区切りも
//! 数として通り、設定の鍵は読んだ数を書き直したもの（`"１２３"` → `"123"`）になる。
//!
//! どの文字を空白・数字と見るかは、本物の Python（3.13。Unicode 15.1）に全部の文字を答えさせた表
//! （`tests/fixtures/commands/server_tables.json`）と、テストで突き合わせている。

use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::commands::CommandError;

/// Python の `int()` が読む桁数の上限（`sys.int_info.default_max_str_digits`）。超えると `ValueError`。
pub const MAX_INT_DIGITS: usize = 4300;

/// 10 進の数字の「0」にあたる文字。どの文字体系でも、ここから 9 までが続き番号で並ぶ（Unicode の決まり）。
///
/// Python 3.13 の `unicodedata`（Unicode 15.1）と同じ。昇順。
const DECIMAL_ZEROS: [u32; 68] = [
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60,
    0x16AC0, 0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0,
    0x1E950, 0x1FBF0,
];

/// Python の `str.isspace()` が真になる 1 文字か（`str.strip()` が落とす文字）。
///
/// Rust の `char::is_whitespace` との違いは、区切りの制御文字（U+001C〜U+001F）も空白に数えること。
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python の `text.strip()`（前後の空白を落とす）。
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// 10 進の数字の値（0〜9）。数字でなければ `None`。Python の `unicodedata.decimal`。
pub fn decimal_value(c: char) -> Option<u32> {
    let code = u32::from(c);
    // code 以下で最も大きい「0」を探し、そこから 9 つ先までなら、その体系の数字。
    let index = DECIMAL_ZEROS.partition_point(|zero| *zero <= code);
    let zero = *DECIMAL_ZEROS.get(index.checked_sub(1)?)?;
    (code - zero < 10).then_some(code - zero)
}

/// Python の `str(int(text))`。数として読めなければ `None`（Python の `ValueError`）。
///
/// 64 ビットに収まらない数も読む（Python の整数に上限は無い）ので、数ではなく 10 進の文字列で返す。
///
/// - 前後の空白は落とす。符号（`+`・`-`）は 1 つだけ、数字の直前に付けられる
/// - 数字は Unicode の 10 進の数字ならどの文字体系でもよい（全角の `１２３` も読む）
/// - 数字の間に 1 つずつなら `_` を挟める（`1_000`）。先頭・末尾・連続は読まない
/// - 先頭の 0 は落とす（`007` → `7`、`-0` → `0`）
/// - 数字が 4300 桁を超えたら読まない（[`MAX_INT_DIGITS`]。先頭の 0 も桁に数える）
pub fn int_text(text: &str) -> Option<String> {
    // 空白と数字を ASCII に寄せる（CPython の `_PyUnicode_TransformDecimalAndSpaceToASCII`）。ASCII の文字は
    // そのまま通すので、区切りの制御文字（U+001C〜U+001F）は、ここでは空白にならない。
    let mut ascii = String::with_capacity(text.len());
    for c in text.chars() {
        ascii.push(if c.is_ascii() {
            c
        } else if c.is_whitespace() {
            ' '
        } else {
            char::from_digit(decimal_value(c)?, 10)?
        });
    }
    // C の isspace（垂直タブを含む）。Rust の `is_ascii_whitespace` は垂直タブを含まない。
    let is_gap = |c: char| matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ');
    let body = ascii.trim_start_matches(is_gap);
    let (negative, body) = match body.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, body.strip_prefix('+').unwrap_or(body)),
    };
    let body = body.trim_end_matches(is_gap);
    if body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    if digits.is_empty()
        || digits.len() > MAX_INT_DIGITS
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let significant = digits.trim_start_matches('0');
    Some(match (significant.is_empty(), negative) {
        (true, _) => "0".to_string(),
        (false, true) => format!("-{significant}"),
        (false, false) => significant.to_string(),
    })
}

/// 先頭から `count` 文字。Python の `text[:count]`（文字はコードポイントで数える）。
pub fn first_chars(text: &str, count: usize) -> String {
    text.chars().take(count).collect()
}

/// Python の `len(value)`。数えられない値（数・真偽・null）は `None`（Python の `TypeError`）。
pub fn len(value: &Value) -> Option<usize> {
    match value {
        Value::Object(map) => Some(map.len()),
        Value::Array(items) => Some(items.len()),
        Value::String(text) => Some(text.chars().count()),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

/// Python の `dict(value)`（`value` が無ければ空の辞書）。`what` は、読めなかったときに残す設定の名前。
///
/// 辞書はそのまま。空の並びと空の文字列は、`dict()` が空の辞書にする。それ以外（数・真偽・null・中身のある
/// 文字列や並び）は、Python では例外になる（コマンドは「処理できなかった」と返す）ので `Err`。
fn as_dict<'a>(
    value: Option<&'a Value>,
    what: &'static str,
) -> Result<&'a Map<String, Value>, CommandError> {
    match value {
        None => Ok(&EMPTY),
        Some(Value::Object(map)) => Ok(map),
        Some(Value::Array(items)) if items.is_empty() => Ok(&EMPTY),
        Some(Value::String(text)) if text.is_empty() => Ok(&EMPTY),
        Some(_) => Err(CommandError::BrokenSetting(what)),
    }
}

/// サーバーの設定の中の辞書を読む。Python の `_get_dict_setting`
/// （`dict(get_guild_settings(guild_id).get(key, {}))`）。
pub fn dict_setting<'a>(
    guild: Option<&'a Value>,
    key: &'static str,
) -> Result<&'a Map<String, Value>, CommandError> {
    as_dict(as_dict(guild, "（サーバーの設定）")?.get(key), key)
}

/// 設定に入っている ID を、Python の辞書（`guild._roles`・`guild._channels`。鍵は整数）から引くときの鍵にする。
///
/// 整数と、値が整数の小数（`20.0`）と真（1 と等しい）は引ける。文字列（`"20"`）・null・無い鍵は、どの鍵とも
/// 等しくならないので `Ok(None)`（負の数と 0 も、ID には無いので同じ）。並びと辞書は Python では鍵にできない
/// （`TypeError`）ので `Err`。
pub fn lookup_id(value: Option<&Value>, what: &'static str) -> Result<Option<u64>, CommandError> {
    let id = match value {
        None | Some(Value::Null | Value::String(_)) => None,
        Some(Value::Bool(flag)) => Some(u64::from(*flag)),
        Some(Value::Number(number)) => number.as_u64().or_else(|| {
            number
                .as_f64()
                .filter(|f| f.fract() == 0.0 && (1.0..18_446_744_073_709_551_616.0).contains(f))
                .map(|f| f as u64)
        }),
        Some(Value::Array(_) | Value::Object(_)) => return Err(CommandError::BrokenSetting(what)),
    };
    Ok(id.filter(|id| *id > 0))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 表が昇順で、どの「0」も 10 文字ぶん離れていること（重なると、値の引き方が狂う）。
    #[test]
    fn the_decimal_table_is_sorted_and_does_not_overlap() {
        assert!(DECIMAL_ZEROS.windows(2).all(|w| w[0] + 10 <= w[1]));
        assert_eq!(DECIMAL_ZEROS.len(), 68);
    }

    /// 数字の値。ASCII・全角・アラビア・数学用の太字。数字に見えても 10 進の数字でないものは読まない。
    #[test]
    fn decimal_digits_have_values() {
        for (c, value) in [('0', 0), ('9', 9), ('５', 5), ('٣', 3), ('𝟗', 9), ('🯹', 9)] {
            assert_eq!(decimal_value(c), Some(value), "{c}");
        }
        for c in ['/', ':', 'a', '²', '①', 'Ⅷ', '五', '\u{ff1a}', '\u{65f}'] {
            assert_eq!(decimal_value(c), None, "{c}");
        }
    }

    /// `int()` と同じに読み、同じに書き直すこと。
    #[test]
    fn integers_are_read_like_python() {
        for (text, want) in [
            ("111", "111"),
            (" 111\t\n", "111"),
            ("\x0b\x0c7\r", "7"),
            ("+111", "111"),
            ("-5", "-5"),
            ("-0", "0"),
            ("000111", "111"),
            ("1_000_000", "1000000"),
            ("１２３", "123"),
            ("\u{3000}１_２\u{a0}", "12"),
            (
                "123456789012345678901234567890",
                "123456789012345678901234567890",
            ),
        ] {
            assert_eq!(int_text(text).as_deref(), Some(want), "{text:?}");
        }
        for text in [
            "",
            " ",
            "abc",
            "1 2",
            "1__0",
            "_1",
            "1_",
            "-_1",
            "+",
            "+-1",
            "- 1",
            "1.0",
            "0x10",
            "1e3",
            "12a",
            "\x1c5",
            "\x1c５",
            "\u{200b}5",
            "²",
            "－5",
            "1＿0",
            "1\x000",
        ] {
            assert_eq!(int_text(text), None, "{text:?}");
        }
    }

    /// 4300 桁までは読み、4301 桁は読まないこと。先頭の 0 も桁に数え、`_`・符号・空白は数えない。
    #[test]
    fn integers_longer_than_4300_digits_are_refused() {
        assert_eq!(int_text(&"1".repeat(4300)), Some("1".repeat(4300)));
        assert_eq!(int_text(&"1".repeat(4301)), None);
        assert_eq!(int_text(&"0".repeat(4300)).as_deref(), Some("0"));
        assert_eq!(int_text(&"0".repeat(4301)), None);
        let spaced = format!(" -{}1 ", "1_".repeat(4299));
        assert_eq!(int_text(&spaced), Some(format!("-{}", "1".repeat(4300))));
        assert_eq!(int_text(&format!("{}1", "1_".repeat(4300))), None);
    }

    /// `strip()` は Python の空白（区切りの制御文字も）を落とし、幅のない空白は落とさないこと。
    #[test]
    fn strip_removes_what_python_calls_whitespace() {
        assert_eq!(strip(" \t👍\u{3000}\n"), "👍");
        assert_eq!(strip("\x1c\x1f👍\x1d\x1e\u{85}\u{a0}"), "👍");
        assert_eq!(strip("\u{200b}a b\u{200b}"), "\u{200b}a b\u{200b}");
        assert_eq!(strip("  "), "");
    }

    /// 辞書の読み方: 無ければ空、空の並びと空の文字列も空、ほかは読めない。
    #[test]
    fn dict_settings_follow_python_dict() {
        let guild =
            json!({"a": {"x": 1}, "b": [], "c": "", "d": "壊れた値", "e": null, "f": [1], "g": 0});
        assert_eq!(dict_setting(Some(&guild), "a").unwrap().len(), 1);
        for key in ["b", "c", "missing"] {
            assert!(dict_setting(Some(&guild), key).unwrap().is_empty(), "{key}");
        }
        for key in ["d", "e", "f", "g"] {
            assert!(dict_setting(Some(&guild), key).is_err(), "{key}");
        }
        assert!(dict_setting(None, "a").unwrap().is_empty());
        assert!(dict_setting(Some(&json!([])), "a").unwrap().is_empty());
        assert!(dict_setting(Some(&json!("壊れた値")), "a").is_err());
    }

    /// ID の引き方: 整数・整数の値の小数・真は引け、文字列・null・負・0 は当たらず、並びと辞書は誤り。
    #[test]
    fn ids_are_looked_up_like_python_dict_keys() {
        for (value, want) in [
            (json!(20), Some(20)),
            (json!(20.0), Some(20)),
            (json!(true), Some(1)),
            (json!(18_446_744_073_709_551_615_u64), Some(u64::MAX)),
            (json!("20"), None),
            (json!(null), None),
            (json!(20.5), None),
            (json!(-20), None),
            (json!(-20.0), None),
            (json!(0), None),
            (json!(false), None),
            (json!(1e30), None),
        ] {
            assert_eq!(lookup_id(Some(&value), "x").unwrap(), want, "{value}");
        }
        assert_eq!(lookup_id(None, "x").unwrap(), None);
        assert!(lookup_id(Some(&json!([20])), "x").is_err());
        assert!(lookup_id(Some(&json!({"id": 20})), "x").is_err());
    }

    /// `len()`: 辞書・並び・文字列（コードポイント）は数え、ほかは数えられない。
    #[test]
    fn len_counts_like_python() {
        assert_eq!(len(&json!({"a": 1, "b": 2})), Some(2));
        assert_eq!(len(&json!([1, 2, 3])), Some(3));
        assert_eq!(len(&json!("あいう😀")), Some(4));
        for value in [json!(5), json!(null), json!(true)] {
            assert_eq!(len(&value), None, "{value}");
        }
        assert_eq!(first_chars("あいう😀x", 4), "あいう😀");
    }
}
