//! メールの形の日付（`Fri, 27 Nov 2026 01:23:45 GMT`）を読む。Python の `email.utils.parsedate_to_datetime`
//! （中身は `email._parseaddr._parsedate_tz`）。
//!
//! Python の読み方はかなり寛容で、RSS の配信元ごとの崩れた書き方も読む。同じものを同じに読めるよう、
//! 手順をそのまま写してある（曜日は読み飛ばす・`27-Nov-26` の形・月と日の入れ替わり・2 桁の年は
//! 69〜99 が 1900 年代・時刻の区切りに `.`・時刻帯は名前か `+0900` の形）。
//!
//! 時刻帯が読めないもの（`JST`・`+09:00`・`-0000`・無し）は「時刻帯なし」として返す。Python はそれを
//! 「その場の時刻帯の時刻」として扱う（呼ぶ側が決める）。
//!
//! # Python と違うところ
//!
//! ASCII 以外の数字（全角の `２７` など）は読まない（Python の `int()` は読む）。その日付は「読めない」になる。

use chrono::{NaiveDate, NaiveDateTime};

use crate::groq::python_is_space;

const MONTHS: [&str; 24] = [
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
/// 名前で書ける時刻帯（`-500` は -05:00）。Python の `_timezones`。
const ZONES: [(&str, i128); 14] = [
    ("UT", 0),
    ("UTC", 0),
    ("GMT", 0),
    ("Z", 0),
    ("AST", -400),
    ("ADT", -300),
    ("EST", -500),
    ("EDT", -400),
    ("CST", -600),
    ("CDT", -500),
    ("MST", -700),
    ("MDT", -600),
    ("PST", -800),
    ("PDT", -700),
];

/// 読んだ日付。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// 書いてあった日時（時刻帯を引く前）。
    pub local: NaiveDateTime,
    /// UTC からのずれ（秒）。時刻帯が読めなければ `None`。
    pub offset_seconds: Option<i32>,
}

/// 数として読めなかった理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotInt {
    /// 数の形をしていない。
    Invalid,
    /// 数の形だが大きすぎる（Python は読めるが、そのあと日付にできずに失敗する）。
    TooBig,
}

/// Python の `int(text)`（ASCII の範囲）。符号と、数字の間の `_` を許す。
fn python_int(text: &str) -> Result<i128, NotInt> {
    let t = text.trim_matches(python_is_space);
    let (negative, digits) = match t.strip_prefix(['+', '-']) {
        Some(rest) => (t.starts_with('-'), rest),
        None => (false, t),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return Err(NotInt::Invalid);
    }
    // `_` は数字の間に 1 つずつ。
    let shaped = bytes.iter().enumerate().all(|(i, b)| match b {
        b'0'..=b'9' => true,
        b'_' => bytes[i - 1].is_ascii_digit(),
        _ => false,
    });
    if !shaped {
        return Err(NotInt::Invalid);
    }
    let mut value: i128 = 0;
    for b in bytes.iter().filter(|b| b.is_ascii_digit()) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i128::from(b - b'0')))
            .ok_or(NotInt::TooBig)?;
    }
    Ok(if negative { -value } else { value })
}

/// ASCII 以外の数字が入っているか（Python は読むが、こちらは読まない）。
fn has_foreign_digit(text: &str) -> bool {
    text.chars().any(|c| !c.is_ascii() && c.is_numeric())
}

/// 日付を読む。読めなければ `None`（Python は ValueError などを投げる）。
pub fn parse(data: &str) -> Option<Parsed> {
    let mut parts: Vec<String> = data
        .split(python_is_space)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        return None;
    }
    // 曜日は読み飛ばす（後ろの空白は無くてもよい）。
    if parts[0].ends_with(',') || DAYS.contains(&parts[0].to_lowercase().as_str()) {
        parts.remove(0);
    } else if let Some(i) = parts[0].rfind(',') {
        parts[0] = parts[0][i + 1..].to_string();
    }
    // `27-Nov-26 01:23:45 GMT`（RFC 850 の形）。
    if parts.len() == 3 {
        let stuff: Vec<String> = parts[0].split('-').map(str::to_string).collect();
        if stuff.len() == 3 {
            parts.splice(0..1, stuff);
        }
    }
    // 時刻に時刻帯がくっついている（`01:23:45+0900`）。
    if parts.len() == 4 {
        let s = parts[3].clone();
        let i = s.find('+').or_else(|| s.find('-'));
        match i {
            Some(i) if i > 0 => {
                parts[3] = s[..i].to_string();
                parts.push(s[i..].to_string());
            }
            _ => parts.push(String::new()),
        }
    }
    if parts.len() < 5 {
        return None;
    }
    let mut it = parts.into_iter();
    let (mut dd, mut mm, mut yy, mut tm, mut tz) =
        (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
    if dd.is_empty() || mm.is_empty() || yy.is_empty() {
        return None;
    }
    if [&dd, &mm, &yy, &tm, &tz]
        .iter()
        .any(|p| has_foreign_digit(p))
    {
        return None;
    }
    mm = mm.to_lowercase();
    if !MONTHS.contains(&mm.as_str()) {
        // 月と日が入れ替わっている（`Nov 27`）。
        (dd, mm) = (mm, dd.to_lowercase());
        if !MONTHS.contains(&mm.as_str()) {
            return None;
        }
    }
    let mut month = MONTHS.iter().position(|m| *m == mm)? + 1;
    if month > 12 {
        month -= 12;
    }
    if dd.ends_with(',') {
        dd.pop();
    }
    // 年と時刻が入れ替わっている（`27 Nov 01:23:45 2026`）。
    if yy.find(':').is_some_and(|i| i > 0) {
        std::mem::swap(&mut yy, &mut tm);
    }
    if yy.ends_with(',') {
        yy.pop();
        if yy.is_empty() {
            return None;
        }
    }
    if !yy.as_bytes().first()?.is_ascii_digit() {
        std::mem::swap(&mut yy, &mut tz);
    }
    if tm.ends_with(',') {
        tm.pop();
    }
    let fields: Vec<&str> = tm.split(':').collect();
    let (hh, mi, ss) = match fields.as_slice() {
        [h, m] => (*h, *m, "0"),
        [h, m, s] => (*h, *m, *s),
        // 区切りに `.` を使うものもある。
        [only] if only.contains('.') => match only.split('.').collect::<Vec<_>>().as_slice() {
            [h, m] => (*h, *m, "0"),
            [h, m, s] => (*h, *m, *s),
            _ => return None,
        },
        _ => return None,
    };
    let mut year = python_int(&yy).ok()?;
    let day = python_int(&dd).ok()?;
    let (hour, minute, second) = (
        python_int(hh).ok()?,
        python_int(mi).ok()?,
        python_int(ss).ok()?,
    );
    // 2 桁の年: 69〜99 は 1900 年代、それより小さければ 2000 年代。
    if year < 100 {
        year += if year > 68 { 1900 } else { 2000 };
    }
    let tz = tz.to_uppercase();
    let mut offset = match ZONES.iter().find(|(name, _)| *name == tz) {
        Some((_, hhmm)) => Some(*hhmm),
        None => match python_int(&tz) {
            Ok(n) => Some(n),
            Err(NotInt::TooBig) => return None,
            Err(NotInt::Invalid) => None,
        },
    };
    // `-0000` は「時刻帯は分からない」。
    if offset == Some(0) && tz.starts_with('-') {
        offset = None;
    }
    let offset_seconds = match offset {
        Some(hhmm) if hhmm != 0 => {
            let (sign, abs) = if hhmm < 0 { (-1, -hhmm) } else { (1, hhmm) };
            let seconds = sign * ((abs / 100) * 3600 + (abs % 100) * 60);
            // Python の timezone は 24 時間未満だけ。
            Some(i32::try_from(seconds).ok().filter(|s| s.abs() < 86_400)?)
        }
        Some(_) => Some(0),
        None => None,
    };
    // Python の datetime は 1〜9999 年。
    let year = i32::try_from(year)
        .ok()
        .filter(|y| (1..=9999).contains(y))?;
    let date = NaiveDate::from_ymd_opt(year, u32::try_from(month).ok()?, u32::try_from(day).ok()?)?;
    let local = date.and_hms_opt(
        u32::try_from(hour).ok().filter(|h| *h < 24)?,
        u32::try_from(minute).ok().filter(|m| *m < 60)?,
        u32::try_from(second).ok().filter(|s| *s < 60)?,
    )?;
    Some(Parsed {
        local,
        offset_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, s)
            .unwrap()
    }

    /// ふつうの形と、時刻帯の読み方（名前・数・分からない）。
    #[test]
    fn the_usual_shapes_are_read() {
        let p = parse("Fri, 27 Nov 2026 01:23:45 GMT").unwrap();
        assert_eq!(p.local, at(2026, 11, 27, 1, 23, 45));
        assert_eq!(p.offset_seconds, Some(0));
        assert_eq!(
            parse("Fri, 27 Nov 2026 01:23:45 +0930")
                .unwrap()
                .offset_seconds,
            Some(34_200)
        );
        assert_eq!(
            parse("27 Nov 2026 01:23 est").unwrap().offset_seconds,
            Some(-18_000)
        );
        for unknown in ["-0000", "JST", "+09:00", ""] {
            let text = format!("Fri, 27 Nov 2026 01:23:45 {unknown}");
            assert_eq!(parse(&text).unwrap().offset_seconds, None, "{unknown}");
        }
    }

    /// 崩れた形: 曜日なし・RFC 850・月と日の入れ替わり・年と時刻の入れ替わり・`.` の区切り・2 桁の年。
    #[test]
    fn sloppy_shapes_are_read_like_python() {
        let want = at(2026, 11, 27, 1, 23, 45);
        for text in [
            "27 Nov 2026 01:23:45 GMT",
            "Fri,27 Nov 2026 01:23:45 GMT",
            "Friday, 27-Nov-26 01:23:45 GMT",
            "Fri, Nov 27 2026 01:23:45 GMT",
            "Fri, 27 Nov 01:23:45 2026 GMT",
            "Fri, 27 Nov 2026 01.23.45 GMT",
            "Fri, 27 November 2026 01:23:45+0900",
            "x, 27 Nov 2026 01:23:45 GMT extra words",
        ] {
            assert_eq!(parse(text).map(|p| p.local), Some(want), "{text}");
        }
        assert_eq!(
            parse("27 Nov 69 01:23 GMT").unwrap().local.to_string(),
            "1969-11-27 01:23:00"
        );
        assert_eq!(
            parse("27 Nov 68 01:23 GMT").unwrap().local.to_string(),
            "2068-11-27 01:23:00"
        );
        assert_eq!(
            parse("27 Nov 100 01:23 GMT").unwrap().local.to_string(),
            "0100-11-27 01:23:00"
        );
    }

    /// 読めないもの（Python が失敗するもの）。
    #[test]
    fn unreadable_dates_are_none() {
        for text in [
            "",
            " ",
            "not a date",
            "2026-11-27T01:23:45Z",
            "Fri, 27 Nov 2026",
            "Fri, 31 Nov 2026 01:23:45 GMT",
            "Fri, 29 Feb 2026 01:23:45 GMT",
            "Fri, 27 Nov 2026 24:00:00 GMT",
            "Fri, 27 Nov 2026 23:59:60 GMT",
            "Fri, 27 Nov 2026 01:23:45:67 GMT",
            "Fri, 27 Nov 10000 01:23:45 GMT",
            "Fri, 27 Nov 2026 15:00:00 +2400",
            "Fri, 27 Nov 2026 15:00:00 +99999999999999999999999999999999999999999999",
            "Fri, 27 Xyz 2026 01:23:45 GMT",
            // ASCII 以外の数字は読まない（Python は読む）。
            "Fri, ２７ Nov 2026 01:23:45 GMT",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    /// Python の int() と同じものを読むこと。
    #[test]
    fn integers_are_read_like_python() {
        assert_eq!(python_int("0001"), Ok(1));
        assert_eq!(python_int("+12"), Ok(12));
        assert_eq!(python_int("-5"), Ok(-5));
        assert_eq!(python_int("1_0"), Ok(10));
        for bad in ["", "+", "1__0", "_1", "1_", "1.0", "a", "0x10"] {
            assert_eq!(python_int(bad), Err(NotInt::Invalid), "{bad}");
        }
        assert_eq!(python_int(&"9".repeat(60)), Err(NotInt::TooBig));
        // 時刻帯が数の形でないもの（`1__0`）は「時刻帯なし」、大きすぎる数は「読めない」。
        assert_eq!(
            parse("Fri, 27 Nov 2026 01:23:45 1__0")
                .unwrap()
                .offset_seconds,
            None
        );
    }
}
