//! FastAPI の引数（`Query`・`Path`）の読み方と、pydantic の検証の誤り（422 の `detail` の 1 件ずつ）。
//!
//! - 問い合わせ: starlette の `request.query_params`。`?` より後を latin-1 の文字として `&` で割り、`=` の前後に
//!   `unquote_plus`（`+` は空白、`%XX` は UTF-8 として戻し、読めない並びは U+FFFD）。`=` の無い欄は値が空
//!   （`parse_qsl(…, keep_blank_values=True)`）。同じ名前は最後の値（[`QueryParams::get`]）
//! - FastAPI は、欄が無ければ既定の値を（検証せずに）使い、あれば空の文字でも pydantic に渡す
//! - int（pydantic の lax の「文字 → int」。pydantic-core の `str_as_int`。[`parse_int`]）: 前後の空白を落とし、
//!   4300 バイトを超えれば `int_parsing_size`。19 バイト未満は Rust の `i64` の読み方（`+`・`-` の 1 文字と ASCII の
//!   数字）、19 バイト以上は num-bigint の読み方（`_` を飛ばす）。読めなければ、小数点のあとが 0 だけなら小数点の前を、
//!   それも無ければ `_` を 1 つずつ挟んだもの（先頭・末尾・続けての `_` は駄目）を読み直す。全角の数字などは読まない
//!   （Python の `int()` とは違う。pydantic の答え）
//! - `ge`・`le`（`greater_than_equal`・`less_than_equal`）、str の `max_length`（文字の数。`string_too_long`）
//! - 誤りは `{"type", "loc", "msg", "input"(, "ctx")}`。`input` は送られた文字のまま（空白を落とす前）。FastAPI は
//!   引数を書いた順（パス → 問い合わせ）に全部の誤りを集めてから 422 にする（[`crate::errors::Failure::Validation`]）
//!
//! 文の言い回しと型の名前は、基準（A0 の `users_state`）の pydantic の答えで確かめる。読み方の細部（空白・`+`・
//! 小数点・`_`・長さ）は記憶からの写しで、同じ基準の例（`list_limit_with_*` など）で確かめる。

use serde_json::{Map, Value, json};

use crate::python;

/// pydantic-core が「文字 → int」で読む長さの上限（バイト。超えたら `int_parsing_size`）。
pub const MAX_INT_TEXT: usize = 4300;
/// `int_parsing` の文。
pub const INT_PARSING: &str =
    "Input should be a valid integer, unable to parse string as an integer";
/// `int_parsing_size` の文。
pub const INT_PARSING_SIZE: &str =
    "Unable to parse input string as an integer, exceeded maximum size";

/// starlette の `request.query_params`（来た順の名前と値）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    /// `?` より後（無ければ `None`）を読む（`parse_qsl(query, keep_blank_values=True)`）。
    pub fn parse(query: Option<&str>) -> Self {
        let mut pairs = Vec::new();
        for field in query.unwrap_or_default().split('&') {
            if field.is_empty() {
                continue;
            }
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            let name = python::form_unquote(name.as_bytes());
            let value = python::form_unquote(value.as_bytes());
            pairs.push((name, value));
        }
        Self { pairs }
    }

    /// その名前の値（`query_params.get(name)`。同じ名前が何度もあれば最後のもの）。
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// pydantic が読んだ整数（Python の `int`。大きさに限りが無い）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Int {
    /// `i128` に収まるもの。
    Small(i128),
    /// 収まらないもの（Python の `str(value)`。符号つきの 10 進、前の 0 は無い）。
    Huge(String),
}

impl Int {
    /// 符号と 10 進の数字（ASCII。前の 0 はあってよい）から作る。
    pub fn from_digits(negative: bool, digits: &str) -> Self {
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            return Self::Small(0);
        }
        let text = if negative {
            format!("-{trimmed}")
        } else {
            trimmed.to_string()
        };
        match text.parse::<i128>() {
            Ok(value) => Self::Small(value),
            Err(_) => Self::Huge(text),
        }
    }

    /// `str(int(x))` の形（`-` と ASCII の数字）から作る。形が違えば `None`。
    pub fn from_decimal(text: &str) -> Option<Self> {
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self::from_digits(negative, digits))
    }

    /// `i128` に収まれば、その値。
    pub fn get(&self) -> Option<i128> {
        match self {
            Self::Small(value) => Some(*value),
            Self::Huge(_) => None,
        }
    }

    /// 負か。
    pub fn is_negative(&self) -> bool {
        match self {
            Self::Small(value) => *value < 0,
            Self::Huge(text) => text.starts_with('-'),
        }
    }

    /// `bound` 以上か（`ge`）。
    pub fn at_least(&self, bound: i128) -> bool {
        match self {
            Self::Small(value) => *value >= bound,
            Self::Huge(_) => !self.is_negative(),
        }
    }

    /// `bound` 以下か（`le`）。
    pub fn at_most(&self, bound: i128) -> bool {
        match self {
            Self::Small(value) => *value <= bound,
            Self::Huge(_) => self.is_negative(),
        }
    }

    /// Python の `str(value)`。
    pub fn decimal(&self) -> String {
        match self {
            Self::Small(value) => value.to_string(),
            Self::Huge(text) => text.clone(),
        }
    }

    /// JSON に書く値。`i64` に収まれば数（安全な範囲を超えるものは [`crate::jsonsafe`] が文字にする）、
    /// 収まらなければ 10 進の文字（`SafeJSONResponse` が書くのと同じ）。
    pub fn to_json(&self) -> Value {
        match self.get().and_then(|value| i64::try_from(value).ok()) {
            Some(value) => Value::from(value),
            None => Value::String(self.decimal()),
        }
    }
}

/// pydantic が「文字 → int」で読めなかった理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntError {
    /// `int_parsing`（数として読めない）。
    Parsing,
    /// `int_parsing_size`（長すぎる）。
    Size,
}

/// pydantic-core の `str_as_int`（モジュールの説明）。
pub fn parse_int(text: &str) -> Result<Int, IntError> {
    let text = text.trim();
    let len = text.len();
    if len > MAX_INT_TEXT {
        return Err(IntError::Size);
    }
    if let Some(value) = parse_plain(text, len) {
        return Ok(value);
    }
    if let Some(stripped) = strip_decimal_zeros(text) {
        return parse_plain(stripped, len).ok_or(IntError::Parsing);
    }
    if let Some(stripped) = strip_underscores(text) {
        return parse_plain(&stripped, len).ok_or(IntError::Parsing);
    }
    Err(IntError::Parsing)
}

/// pydantic-core の `_parse_str`（長さは、空白を落としたあとの元の文字のもの）。
fn parse_plain(text: &str, len: usize) -> Option<Int> {
    if len < 19 {
        let value = text.parse::<i64>().ok()?;
        return Some(Int::Small(i128::from(value)));
    }
    parse_big(text)
}

/// num-bigint の `BigInt::from_str`（先頭の `-` か `+` を 1 つ、そのあとは数字と `_`。最初は数字）。
fn parse_big(text: &str) -> Option<Int> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(tail) if !tail.starts_with('+') => (true, tail),
        _ => (false, text),
    };
    let rest = match rest.strip_prefix('+') {
        Some(tail) if !tail.starts_with('+') => tail,
        _ => rest,
    };
    if rest.is_empty() || rest.starts_with('_') {
        return None;
    }
    let mut digits = String::with_capacity(rest.len());
    for c in rest.chars() {
        match c {
            '0'..='9' => digits.push(c),
            '_' => {}
            _ => return None,
        }
    }
    Some(Int::from_digits(negative, &digits))
}

/// 小数点のあとが 0 だけ（空も含む）なら、小数点の前（pydantic-core の `strip_decimal_zeros`）。
fn strip_decimal_zeros(text: &str) -> Option<&str> {
    let dot = text.find('.')?;
    if text[dot + 1..].chars().all(|c| c == '0') {
        Some(&text[..dot])
    } else {
        None
    }
}

/// `_` を 1 つずつ挟んだ数なら、`_` を落としたもの（pydantic-core の `strip_underscores`）。
fn strip_underscores(text: &str) -> Option<String> {
    if text.starts_with('_') || text.ends_with('_') || text.contains("__") || !text.contains('_') {
        return None;
    }
    Some(text.replace('_', ""))
}

/// 引数の置き場所と名前（誤りの `loc`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    /// `query` か `path`。
    pub loc: &'static str,
    /// 引数の名前。
    pub name: &'a str,
}

impl<'a> Field<'a> {
    /// 問い合わせの欄（`Query`）。
    pub fn query(name: &'a str) -> Self {
        let loc = "query";
        Self { loc, name }
    }

    /// パスの欄（`Path`）。
    pub fn path(name: &'a str) -> Self {
        let loc = "path";
        Self { loc, name }
    }
}

/// int の範囲（`ge`・`le`）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bounds {
    /// これ以上（`ge`）。
    pub ge: Option<i128>,
    /// これ以下（`le`）。
    pub le: Option<i128>,
}

impl Bounds {
    /// 範囲なし。
    pub fn none() -> Self {
        Self::default()
    }

    /// `ge=low`。
    pub fn at_least(low: i128) -> Self {
        Self {
            ge: Some(low),
            le: None,
        }
    }

    /// `ge=low, le=high`。
    pub fn between(low: i128, high: i128) -> Self {
        Self {
            ge: Some(low),
            le: Some(high),
        }
    }
}

/// pydantic の誤りの 1 件（`{"type", "loc", "msg", "input"(, "ctx")}`）。
pub fn error(
    kind: &str,
    field: Field<'_>,
    msg: String,
    input: Value,
    ctx: Option<(&str, Value)>,
) -> Value {
    let mut map = Map::new();
    map.insert("type".to_string(), Value::String(kind.to_string()));
    map.insert("loc".to_string(), json!([field.loc, field.name]));
    map.insert("msg".to_string(), Value::String(msg));
    map.insert("input".to_string(), input);
    if let Some((key, value)) = ctx {
        let mut inner = Map::new();
        inner.insert(key.to_string(), value);
        map.insert("ctx".to_string(), Value::Object(inner));
    }
    Value::Object(map)
}

/// 範囲の数を JSON に（`ctx` の値。範囲は小さい数だけ）。
fn bound_json(bound: i128) -> Value {
    match i64::try_from(bound) {
        Ok(value) => Value::from(value),
        Err(_) => Value::String(bound.to_string()),
    }
}

/// int の引数（`Query(default=…, ge=…, le=…)`・パスの `int`）。欄が無ければ既定（無ければ `missing`）。
/// 読めない・範囲の外なら `errors` に足して `None`。
pub fn int_value(
    errors: &mut Vec<Value>,
    field: Field<'_>,
    raw: Option<&str>,
    default: Option<i128>,
    bounds: Bounds,
) -> Option<Int> {
    let Some(raw) = raw else {
        if let Some(default) = default {
            return Some(Int::Small(default));
        }
        let msg = "Field required".to_string();
        errors.push(error("missing", field, msg, Value::Null, None));
        return None;
    };
    let input = || Value::String(raw.to_string());
    let value = match parse_int(raw) {
        Ok(value) => value,
        Err(reason) => {
            let (kind, msg) = match reason {
                IntError::Parsing => ("int_parsing", INT_PARSING),
                IntError::Size => ("int_parsing_size", INT_PARSING_SIZE),
            };
            errors.push(error(kind, field, msg.to_string(), input(), None));
            return None;
        }
    };
    if let Some(ge) = bounds.ge.filter(|ge| !value.at_least(*ge)) {
        let msg = format!("Input should be greater than or equal to {ge}");
        let ctx = Some(("ge", bound_json(ge)));
        errors.push(error("greater_than_equal", field, msg, input(), ctx));
        return None;
    }
    if let Some(le) = bounds.le.filter(|le| !value.at_most(*le)) {
        let msg = format!("Input should be less than or equal to {le}");
        let ctx = Some(("le", bound_json(le)));
        errors.push(error("less_than_equal", field, msg, input(), ctx));
        return None;
    }
    Some(value)
}

/// str の引数（`Query(default=…, max_length=…)`）。欄が無ければ既定。長すぎれば `errors` に足して `None`。
pub fn str_value(
    errors: &mut Vec<Value>,
    field: Field<'_>,
    raw: Option<&str>,
    default: &str,
    max_length: Option<usize>,
) -> Option<String> {
    let Some(raw) = raw else {
        return Some(default.to_string());
    };
    if let Some(max) = max_length.filter(|max| raw.chars().count() > *max) {
        let plural = if max == 1 { "" } else { "s" };
        let msg = format!("String should have at most {max} character{plural}");
        let ctx = Some(("max_length", Value::from(max)));
        let input = Value::String(raw.to_string());
        errors.push(error("string_too_long", field, msg, input, ctx));
        return None;
    }
    Some(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good(text: &str, want: &str) {
        let got = parse_int(text).map(|value| value.decimal());
        assert_eq!(got, Ok(want.to_string()), "{text:?}");
    }

    fn bad(text: &str) {
        let got = parse_int(text).map(|value| value.decimal());
        assert_eq!(got, Err(IntError::Parsing), "{text:?}");
    }

    /// pydantic-core の読み方: 空白・符号・前の 0・小数点のあとの 0・`_`・長い数。
    #[test]
    fn integers_are_read_like_pydantic() {
        good("5", "5");
        good(" 5 ", "5");
        good("\u{3000}5\n", "5");
        good("+5", "5");
        good("-5", "-5");
        good("0012", "12");
        good("-0", "0");
        good("5.00", "5");
        good("5.", "5");
        good("1_0", "10");
        good("1_000_000", "1000000");
        good("99999999999999999999", "99999999999999999999");
        good("-99999999999999999999", "-99999999999999999999");
        good("0000000000000000000012", "12");
        good("+1000000000000000000000", "1000000000000000000000");
        // 19 バイト以上は num-bigint の読み方なので、末尾の `_` も読む。`-` のすぐあとの `_` は、`_` を落として読み直す。
        good("1000000000000000000_0", "10000000000000000000");
        good("-_1000000000000000000", "-1000000000000000000");
        let long = "1".repeat(4300);
        good(&long, &long);
        good(&format!(" {long} "), &long);
    }

    /// 読まないもの: 空・字・小数・指数・16 進・`_` の置き方・符号の重ね・全角・間の空白。長すぎるものは別の誤り。
    #[test]
    fn non_integers_are_refused_like_pydantic() {
        bad("");
        bad(" ");
        bad("abc");
        bad("5.5");
        bad(".0");
        bad("1e2");
        bad("0x10");
        bad("_1");
        bad("1_");
        bad("1__0");
        bad("--5");
        bad("+-5");
        bad("-+5");
        bad("５");
        bad("1 0");
        bad("++1000000000000000000");
        let long = "1".repeat(4301);
        assert_eq!(parse_int(&long), Err(IntError::Size));
    }

    /// 大きい数の大小（`Huge` は符号だけで決まる）と、JSON に書く形。
    #[test]
    fn huge_integers_compare_by_sign() {
        let nines = "9".repeat(50);
        let big = parse_int(&nines).unwrap();
        let negative = parse_int(&format!("-{nines}")).unwrap();
        assert!(big.get().is_none());
        assert!(big.at_least(0) && !big.at_most(200));
        assert!(!negative.at_least(1) && negative.at_most(200));
        // 範囲の端は含む（ge・le）。
        assert!(Int::Small(1).at_least(1));
        assert!(!Int::Small(0).at_least(1));
        assert!(Int::Small(200).at_most(200));
        assert!(!Int::Small(201).at_most(200));
        assert_eq!(big.to_json(), json!(nines));
        assert_eq!(Int::Small(25).to_json(), json!(25));
        let beyond_i64 = Int::Small(100_000_000_000_000_000_000);
        assert_eq!(beyond_i64.to_json(), json!("100000000000000000000"));
        assert_eq!(Int::from_decimal("-0012"), Some(Int::Small(-12)));
        assert_eq!(Int::from_decimal("12a"), None);
        assert_eq!(Int::from_decimal("-"), None);
    }

    /// 問い合わせは最後の値が勝ち、`+` は空白、`=` の無い欄は空、名前も戻すこと。
    #[test]
    fn queries_are_read_like_starlette() {
        let raw = "limit=5&limit=10&q=a+b%20c&flag&%71x=1&&e=%FF&x=%E3%81%82";
        let query = QueryParams::parse(Some(raw));
        assert_eq!(query.get("limit"), Some("10"));
        assert_eq!(query.get("q"), Some("a b c"));
        assert_eq!(query.get("flag"), Some(""));
        assert_eq!(query.get("qx"), Some("1"));
        assert_eq!(query.get("e"), Some("\u{fffd}"));
        assert_eq!(query.get("x"), Some("あ"));
        assert_eq!(query.get("nope"), None);
        assert_eq!(QueryParams::parse(None).get("q"), None);
    }

    /// 誤りの形（並び・文・ctx）が pydantic と同じこと。
    #[test]
    fn errors_have_the_pydantic_shape() {
        let mut errors = Vec::new();
        let limit = Field::query("limit");
        let id = Field::path("id");
        let range = Bounds::between(1, 200);
        let got = [
            int_value(&mut errors, limit, Some("0"), None, range),
            int_value(&mut errors, limit, Some("201"), None, range),
            int_value(&mut errors, id, Some("x"), None, Bounds::none()),
        ];
        assert_eq!(got, [None, None, None]);
        let text = str_value(&mut errors, Field::query("q"), Some("ab"), "", Some(1));
        assert_eq!(text, None);
        assert_eq!(
            Value::Array(errors),
            json!([
                {"type": "greater_than_equal", "loc": ["query", "limit"],
                 "msg": "Input should be greater than or equal to 1", "input": "0", "ctx": {"ge": 1}},
                {"type": "less_than_equal", "loc": ["query", "limit"],
                 "msg": "Input should be less than or equal to 200", "input": "201", "ctx": {"le": 200}},
                {"type": "int_parsing", "loc": ["path", "id"],
                 "msg": "Input should be a valid integer, unable to parse string as an integer", "input": "x"},
                {"type": "string_too_long", "loc": ["query", "q"],
                 "msg": "String should have at most 1 character", "input": "ab", "ctx": {"max_length": 1}},
            ])
        );
        let mut errors = Vec::new();
        let missing = int_value(&mut errors, limit, None, Some(25), range);
        assert_eq!(missing, Some(Int::Small(25)));
        let q = Field::query("q");
        let long = "あ".repeat(128);
        let text = str_value(&mut errors, q, Some(long.as_str()), "", Some(128));
        assert_eq!(text, Some(long));
        assert!(errors.is_empty());
    }
}
