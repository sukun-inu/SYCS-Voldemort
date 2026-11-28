//! テンプレートの `{{ … }}` の書き出しを、Jinja2（markupsafe）と同じにする。
//!
//! minijinja の既定の書き出しは Python と 2 つの点で違う（計画 4.2）。
//!
//! - エスケープの書き方: minijinja は `"` を `&quot;`、`'` を `&#x27;`、`/` を `&#x2f;` にする。markupsafe の
//!   `escape` は `&` `<` `>` `'` `"` の 5 つだけを、`&amp;` `&lt;` `&gt;` `&#39;` `&#34;` にする（`/` はそのまま）。
//!   招待リンク（`&` と `/` を含む）や `admin_asset_url` の URL が、バイト単位で変わってしまう
//! - 値の文字の形: minijinja は `none`・`true`・`false` と書く。Jinja2 は Python の `str()` なので `None`・`True`・
//!   `False`。小数も Python の `repr`（`1e+16`・`1.5e-05`）
//!
//! ここの [`write_value`] を minijinja の書き出しの係（`Environment::set_formatter`）に据えて、Python と同じにする。
//! 未定義（Jinja2 の `Undefined`）は空、印の付いた値（Python の `Markup`。`icon()` が返すもの）は逃がさない。
//!
//! 一覧と辞書をそのまま書く場所はテンプレートに無いので、Python の `repr` には合わせていない（minijinja の書き方の
//! まま。Python は `['a', 'b']`、minijinja は `["a", "b"]`）。

use minijinja::value::{Value, ValueKind};
use minijinja::{AutoEscape, Error, ErrorKind, Output};

/// markupsafe の `escape(text)` と同じに逃がす（`&` `<` `>` `'` `"` の 5 つだけ）。
pub fn markupsafe_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            '"' => out.push_str("&#34;"),
            _ => out.push(ch),
        }
    }
    out
}

/// 値を Python の `str()` と同じ形の文字にする（Jinja2 が `{{ … }}` で書く形）。
///
/// 未定義は空、`None`・`True`・`False`、整数は 10 進、小数は Python の `repr`、文字はそのまま。一覧と辞書は
/// minijinja の書き方のまま（モジュールの説明）。
pub fn python_str(value: &Value) -> String {
    match value.kind() {
        ValueKind::Undefined => String::new(),
        ValueKind::None => "None".to_string(),
        ValueKind::Bool => String::from(if value.is_true() { "True" } else { "False" }),
        ValueKind::String => value.as_str().unwrap_or_default().to_string(),
        ValueKind::Number => number_str(value),
        _ => value.to_string(),
    }
}

/// 数を Python の `str()` の形にする。整数は 10 進のまま、小数は [`python_float_repr`]。
///
/// 整数と小数の見分けは、値を JSON の数にして見る（minijinja の `as_i64` は `2.0` のような小数も整数として返すので、
/// 見分けには使えない）。
fn number_str(value: &Value) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::Number(number)) if number.is_f64() => number
            .as_f64()
            .map_or_else(|| value.to_string(), python_float_repr),
        _ => value.to_string(),
    }
}

/// Python の `repr(float)` と同じ形（最短で往復する桁。10 の指数が -4 より小さいか 16 以上なら指数の形）。
///
/// 桁は Rust の書き方（`{}` と `{:e}`。どちらも最短で往復する桁）から取り、形だけを Python に合わせる:
/// 指数は `e+16`・`e-05` のように符号と 2 桁以上、整数の値には `.0` を付ける。
pub fn python_float_repr(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_string();
    }
    if number.is_infinite() {
        return String::from(if number < 0.0 { "-inf" } else { "inf" });
    }
    if number == 0.0 {
        return String::from(if number.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        });
    }
    let scientific = format!("{number:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if (-4..16).contains(&exponent) {
        let plain = format!("{number}");
        if plain.contains('.') {
            plain
        } else {
            format!("{plain}.0")
        }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.unsigned_abs())
    }
}

/// Python の真偽（`if value:`）と同じに、JSON の値が真かを返す。
///
/// `None`・`False`・0・空の文字・空の一覧・空の辞書は偽。`render()` の `issue_csrf_token` の `if not token:` に使う。
pub fn json_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
    }
}

/// minijinja の書き出しの係（`Environment::set_formatter` に渡す）。Jinja2 が `{{ value }}` で書くものと同じものを書く。
///
/// - 未定義は何も書かない（Jinja2 の `Undefined` の `str()` は空）
/// - 印の付いた値（`Value::from_safe_string`。Python の `Markup`）はそのまま
/// - ほかは [`python_str`] にして、逃がす設定なら [`markupsafe_escape`] で逃がす
pub fn write_value(out: &mut Output<'_>, escape: AutoEscape, value: &Value) -> Result<(), Error> {
    if value.is_undefined() {
        return Ok(());
    }
    let written = if value.is_safe() {
        out.write_str(value.as_str().unwrap_or_default())
    } else {
        let text = python_str(value);
        if matches!(escape, AutoEscape::None) {
            out.write_str(&text)
        } else {
            out.write_str(&markupsafe_escape(&text))
        }
    };
    written.map_err(|_| {
        Error::new(
            ErrorKind::InvalidOperation,
            "テンプレートの書き出しに失敗しました",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 逃がすのは 5 つだけで、書き方は markupsafe と同じであること（`/` と `=` はそのまま）。
    #[test]
    fn escape_is_markupsafe() {
        assert_eq!(
            markupsafe_escape(r#"<a href="/x?a=1&b=2">'q'</a>"#),
            "&lt;a href=&#34;/x?a=1&amp;b=2&#34;&gt;&#39;q&#39;&lt;/a&gt;"
        );
        assert_eq!(markupsafe_escape("&amp;"), "&amp;amp;");
        assert_eq!(markupsafe_escape("日本語/😀"), "日本語/😀");
    }

    /// 値の形が Python の `str()` と同じであること。
    #[test]
    fn values_print_like_python() {
        assert_eq!(python_str(&Value::from(())), "None");
        assert_eq!(python_str(&Value::from(true)), "True");
        assert_eq!(python_str(&Value::from(false)), "False");
        assert_eq!(python_str(&Value::UNDEFINED), "");
        assert_eq!(python_str(&Value::from(-12_i64)), "-12");
        assert_eq!(python_str(&Value::from(u64::MAX)), "18446744073709551615");
        assert_eq!(python_str(&Value::from(2.0_f64)), "2.0");
        assert_eq!(python_str(&Value::from("a<b")), "a<b");
    }

    /// 小数の形が Python の `repr` と同じであること（指数の境は -4 と 16）。
    #[test]
    fn floats_print_like_python_repr() {
        for (number, want) in [
            (0.1, "0.1"),
            (1.0, "1.0"),
            (-2.5, "-2.5"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (123_456_789.125, "123456789.125"),
            (f64::MAX, "1.7976931348623157e+308"),
            (-0.0, "-0.0"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(python_float_repr(number), want, "{number:?}");
        }
    }

    /// JSON の真偽が Python の `if value:` と同じであること。
    #[test]
    fn truthiness_is_python() {
        for (value, want) in [
            (serde_json::json!(null), false),
            (serde_json::json!(""), false),
            (serde_json::json!("x"), true),
            (serde_json::json!(0), false),
            (serde_json::json!(0.0), false),
            (serde_json::json!(3), true),
            (serde_json::json!([]), false),
            (serde_json::json!({}), false),
            (serde_json::json!({"a": 1}), true),
            (serde_json::json!(false), false),
        ] {
            assert_eq!(json_truthy(&value), want, "{value}");
        }
    }
}
