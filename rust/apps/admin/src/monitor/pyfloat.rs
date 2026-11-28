//! Python の小数の扱いのうち、監視（`webapp_admin/metrics.py`）と `/metrics`（`services/metrics_registry.py`）が
//! 使うものの写し。どれも基準（`tests/fixtures/monitor/` の functions と `tests/fixtures/prometheus/` の functions）で
//! Python の答えと突き合わせる。
//!
//! - `format(x, ".Nf")`（[`fixed`]）と `round(x, N)`（[`round`]）: Python は 2 進の値を**正確に** 10 進へ直してから、
//!   ちょうど半分なら偶数の側へ丸める（`0.125` は `0.12`、`2.675` は 2 進では少し小さいので `2.67`）。Rust の
//!   `{:.N}` の丸め方には頼らず、正確な 10 進の桁（[`Exact`]）を作って自分で丸める
//! - `format(x, "g")`（[`general`]。有効数字 6 桁・後ろの 0 を落とす・桁が大きい／小さいときは `1e+06` の形）
//! - `float(文字)`（[`py_float`]。前後の空白・数の間の `_`・Unicode の 10 進の数字・`inf`・`nan`）
//! - `sum(小数の並び)`（[`pysum`]。Python 3.12 からの Neumaier の足し方。psutil の CPU の割合が使う）
//! - `max(a, b)`・`min(a, b)`（[`py_max`]・[`py_min`]。NaN と -0.0 の扱いが Rust の `f64::max` と違う）
//! - Prometheus の値の書き方（[`format_value`]。`metrics_registry._format_value`。NaN・無限大は Python と同じく例外）

use crate::errors::Crash;
use crate::python;

/// 10 進の 1 桁の基数（多倍長の 1 つの桁に 9 桁ずつ入れる）。
const LIMB: u64 = 1_000_000_000;

/// 小さい多倍長の正の整数（10^9 ごとの桁を下から並べたもの）。小数を正確な 10 進に直すためだけに使う。
struct Big(Vec<u32>);

impl Big {
    fn from_u64(mut value: u64) -> Self {
        let mut limbs = Vec::new();
        while value > 0 {
            limbs.push((value % LIMB) as u32);
            value /= LIMB;
        }
        Self(limbs)
    }

    fn mul_small(&mut self, factor: u32) {
        let mut carry: u64 = 0;
        for limb in &mut self.0 {
            let product = u64::from(*limb) * u64::from(factor) + carry;
            *limb = (product % LIMB) as u32;
            carry = product / LIMB;
        }
        while carry > 0 {
            self.0.push((carry % LIMB) as u32);
            carry /= LIMB;
        }
    }

    fn mul_pow2(&mut self, mut n: u32) {
        while n >= 29 {
            self.mul_small(1 << 29);
            n -= 29;
        }
        if n > 0 {
            self.mul_small(1 << n);
        }
    }

    fn mul_pow5(&mut self, mut n: u32) {
        // 5^13 = 1220703125 は u32 に入る。
        while n >= 13 {
            self.mul_small(1_220_703_125);
            n -= 13;
        }
        if n > 0 {
            self.mul_small(5u32.pow(n));
        }
    }

    /// 10 進の桁（ASCII。先頭は 0 でない。0 なら空）。
    fn digits(&self) -> Vec<u8> {
        let Some((top, rest)) = self.0.split_last() else {
            return Vec::new();
        };
        let mut text = top.to_string();
        for limb in rest.iter().rev() {
            text.push_str(&format!("{limb:09}"));
        }
        text.into_bytes()
    }
}

/// 有限で 0 でない小数の絶対値の、正確な 10 進の表し方（値 = `digits` の整数 × 10^`exp10`）。
struct Exact {
    digits: Vec<u8>,
    exp10: i64,
}

/// `x`（有限・0 でない）を正確な 10 進にする。2 進の値は m × 2^e なので、e が負なら m × 5^(-e) × 10^e と書ける。
fn exact(x: f64) -> Exact {
    let bits = x.abs().to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, exp2) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1u64 << 52), biased - 1075)
    };
    let mut big = Big::from_u64(mantissa);
    let exp10 = if exp2 >= 0 {
        big.mul_pow2(exp2 as u32);
        0
    } else {
        big.mul_pow5((-exp2) as u32);
        exp2
    };
    Exact {
        digits: big.digits(),
        exp10,
    }
}

/// 10 進の桁の並びに 1 を足す（繰り上がりで桁が増えれば頭に 1）。
fn increment(digits: &mut Vec<u8>) {
    for digit in digits.iter_mut().rev() {
        if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            return;
        }
    }
    digits.insert(0, b'1');
}

/// `digits`（先頭は 0 でない）の頭から `keep` 桁を残して丸めた整数の桁（ちょうど半分なら偶数の側）。
///
/// `keep` が桁の数以上なら、足りない分は 0 で埋める（値 × 10^(keep - 桁の数)）。0 以下なら 0 か 1。
fn round_half_even(digits: &[u8], keep: i64) -> Vec<u8> {
    let len = digits.len() as i64;
    if keep >= len {
        let mut out = digits.to_vec();
        out.extend(std::iter::repeat_n(b'0', (keep - len) as usize));
        return out;
    }
    if keep < 0 {
        return vec![b'0'];
    }
    let (head, tail) = digits.split_at(keep as usize);
    let up = match tail[0].cmp(&b'5') {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            tail[1..].iter().any(|d| *d != b'0') || head.last().is_some_and(|d| (d - b'0') % 2 == 1)
        }
    };
    let mut out = if head.is_empty() {
        vec![b'0']
    } else {
        head.to_vec()
    };
    if up {
        increment(&mut out);
    }
    out
}

fn ascii(digits: &[u8]) -> String {
    digits.iter().map(|d| char::from(*d)).collect()
}

/// `format(x, f".{places}f")`（`f"{x:.1f}"` など）。負の数（-0.0 も）は `-` を付ける（Python と同じく、丸めて 0 に
/// なっても `-0.0`）。NaN と無限大は `nan`・`inf`・`-inf`。
pub fn fixed(x: f64, places: usize) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sign = if x.is_sign_negative() { "-" } else { "" };
    let rounded = if x == 0.0 {
        vec![b'0']
    } else {
        let exact = exact(x);
        let keep = exact.digits.len() as i64 + exact.exp10 + places as i64;
        round_half_even(&exact.digits, keep)
    };
    let mut text = ascii(&rounded);
    if places > 0 {
        if text.len() <= places {
            text = format!("{}{text}", "0".repeat(places + 1 - text.len()));
        }
        text.insert(text.len() - places, '.');
    }
    format!("{sign}{text}")
}

/// `round(x, places)`（Python は正確に丸めた 10 進の文字を小数に読み直す。[`fixed`] と同じ丸め方）。
pub fn round(x: f64, places: usize) -> f64 {
    fixed(x, places).parse::<f64>().unwrap_or(x)
}

/// `format(x, "g")`（有効数字 6 桁）。指数が -4 以上 6 未満なら小数の形、ほかは `1.5e+06` の形（指数は 2 桁以上）。
/// どちらも後ろの 0 と、残る桁の無い小数点を落とす。
pub fn general(x: f64) -> String {
    const PRECISION: i64 = 6;
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sign = if x.is_sign_negative() { "-" } else { "" };
    if x == 0.0 {
        return format!("{sign}0");
    }
    let exact = exact(x);
    let mut exponent = exact.digits.len() as i64 - 1 + exact.exp10;
    let mut significant = round_half_even(&exact.digits, PRECISION);
    if significant.len() as i64 > PRECISION {
        exponent += 1;
        significant.truncate(PRECISION as usize);
    }
    while significant.len() > 1 && significant.last() == Some(&b'0') {
        significant.pop();
    }
    let digits = ascii(&significant);
    let body = if (-4..PRECISION).contains(&exponent) {
        if exponent >= 0 {
            let whole = exponent as usize + 1;
            if digits.len() <= whole {
                format!("{digits}{}", "0".repeat(whole - digits.len()))
            } else {
                format!("{}.{}", &digits[..whole], &digits[whole..])
            }
        } else {
            format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize))
        }
    } else {
        let mantissa = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.clone()
        };
        let mark = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{mark}{:02}", exponent.abs())
    };
    format!("{sign}{body}")
}

/// `float(text)`（読めなければ `None`。Python の `ValueError`）。
///
/// Python と同じ順に読む: 前後の空白（`str.isspace()`）を落とし、Unicode の 10 進の数字を ASCII の数字にし（ほかの
/// ASCII でない文字があれば読めない）、`_` は数の間に 1 つずつだけ許して消し、残りを小数の書き方
/// （符号・数字・`.`・指数、`inf`・`infinity`・`nan`〔大文字小文字は問わない〕）として読む。
pub fn py_float(text: &str) -> Option<f64> {
    let text = python::strip(text);
    let mut plain = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            plain.push(c);
        } else {
            let digit = python::decimal_value(c)?;
            plain.push(char::from_digit(digit, 10)?);
        }
    }
    if plain.contains('_') {
        plain = without_underscores(&plain)?;
    }
    if plain.is_empty() || plain.contains(char::is_whitespace) {
        return None;
    }
    plain.parse::<f64>().ok()
}

/// `_Py_string_to_number_with_underscores`（`_` は数字のあとにだけ、そのあとも数字だけ。最後に来てはいけない）。
fn without_underscores(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut previous = '\0';
    for c in text.chars() {
        if c == '_' {
            if !previous.is_ascii_digit() {
                return None;
            }
        } else {
            if previous == '_' && !c.is_ascii_digit() {
                return None;
            }
            out.push(c);
        }
        previous = c;
    }
    (previous != '_').then_some(out)
}

/// 小数の並びの `sum()`（Python 3.12 からの Neumaier の足し方。最後に補正を足す。補正が 0 か有限でなければ足さない）。
pub fn pysum(values: &[f64]) -> f64 {
    let mut total = 0.0_f64;
    let mut compensation = 0.0_f64;
    for &x in values {
        let t = total + x;
        if total.abs() >= x.abs() {
            compensation += (total - t) + x;
        } else {
            compensation += (x - t) + total;
        }
        total = t;
    }
    if compensation != 0.0 && compensation.is_finite() {
        total += compensation;
    }
    total
}

/// Python の `max(a, b)`（`b > a` のときだけ `b`。NaN と -0.0 は `a` のまま）。
pub fn py_max(a: f64, b: f64) -> f64 {
    if b > a { b } else { a }
}

/// Python の `min(a, b)`（`b < a` のときだけ `b`）。
pub fn py_min(a: f64, b: f64) -> f64 {
    if b < a { b } else { a }
}

/// Prometheus の値の書き方。`metrics_registry._format_value`（整数で 1e15 より小さければ小数点なし、ほかは `repr`）。
///
/// Python は `value == int(value)` で比べるので、NaN は `ValueError`、無限大は `OverflowError` になり、`/metrics`
/// 全体が 500 になる。同じにする（Valkey の値は Python と Rust の報告口が書くので、ふつうは出ない）。
pub fn format_value(value: f64) -> Result<String, Crash> {
    if value.is_nan() {
        return Err(Crash::new("ValueError", "cannot convert float NaN to integer"));
    }
    if value.is_infinite() {
        return Err(Crash::new(
            "OverflowError",
            "cannot convert float infinity to integer",
        ));
    }
    if value == value.trunc() && value.abs() < 1e15 {
        return Ok(format!("{}", value as i64));
    }
    Ok(python::float_repr(value))
}

/// Python の `int(x)`（0 の方へ切り捨て。i64 に収まらなければ端に寄せる）。`_format_duration` が使う。
pub fn trunc(x: f64) -> i64 {
    x.trunc() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ちょうど半分は偶数の側、2 進で少しずれている値はそのずれのとおりに丸めること。
    #[test]
    fn fixed_rounds_the_exact_binary_value() {
        assert_eq!(fixed(0.125, 2), "0.12");
        assert_eq!(fixed(0.375, 2), "0.38");
        assert_eq!(fixed(2.5, 0), "2");
        assert_eq!(fixed(3.5, 0), "4");
        assert_eq!(fixed(2.675, 2), "2.67");
        assert_eq!(fixed(-0.04, 1), "-0.0");
        assert_eq!(fixed(0.0, 2), "0.00");
        assert_eq!(fixed(123.0, 1), "123.0");
        assert_eq!(fixed(1e22, 0), "10000000000000000000000");
        assert_eq!(round(0.125, 2), 0.12);
    }

    /// 有効数字 6 桁と、指数の形の切り替わり。
    #[test]
    fn general_matches_the_g_format() {
        assert_eq!(general(50.0), "50");
        assert_eq!(general(0.01), "0.01");
        assert_eq!(general(1e6), "1e+06");
        assert_eq!(general(123456.5), "123456");
        assert_eq!(general(1234567.0), "1.23457e+06");
        assert_eq!(general(0.0001), "0.0001");
        assert_eq!(general(0.00001), "1e-05");
        assert_eq!(general(999999.5), "1e+06");
    }

    /// `float()` の読み方（空白・`_`・指数・読めないもの）。
    #[test]
    fn py_float_reads_like_python() {
        assert_eq!(py_float(" 7 "), Some(7.0));
        assert_eq!(py_float("1_000"), Some(1000.0));
        assert_eq!(py_float("1e3"), Some(1000.0));
        assert_eq!(py_float("1__0"), None);
        assert_eq!(py_float("_1"), None);
        assert_eq!(py_float("1_"), None);
        assert_eq!(py_float("abc"), None);
        assert_eq!(py_float(""), None);
        assert_eq!(py_float("1 2"), None);
        assert!(py_float("nan").is_some_and(f64::is_nan));
    }

    /// 整数は小数点なし、大きいものと小数は repr、NaN と無限大は Python と同じ例外。
    #[test]
    fn values_are_formatted_like_the_registry() {
        assert_eq!(format_value(3.0).unwrap(), "3");
        assert_eq!(format_value(-0.0).unwrap(), "0");
        assert_eq!(format_value(1e15).unwrap(), "1000000000000000.0");
        assert_eq!(format_value(0.25).unwrap(), "0.25");
        assert_eq!(format_value(f64::NAN).unwrap_err().kind, "ValueError");
        assert_eq!(format_value(f64::INFINITY).unwrap_err().kind, "OverflowError");
    }
}
