//! Python の `re` が文字の種類をどう見るか（`\w`・`\d`・`\s`）。
//!
//! Rust の正規表現の `\w`・`\d`・`\s` とは、含む文字が少し違う（Python の `\w` は結合文字やつなぎの記号を含まない、
//! Python の `\s` は区切りの制御文字 U+001C〜U+001F を含む、など）。Python 3.13（Unicode 15.1）の判定そのものを
//! 表にして持つ（`tests/fixtures/tts/generate_classes.py` で作る）。

use std::sync::OnceLock;

/// 種類ごとの範囲（種類・始め・終わり。16 進）。
const CLASSES_TSV: &str = include_str!("python_char_classes.tsv");

/// 文字の種類。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// `\w`（`str.isalnum()` か `_`）。
    Word,
    /// `\d`（`str.isdecimal()`）。
    Digit,
    /// `\s`（`str.isspace()`）。
    Space,
}

impl Class {
    fn tag(self) -> &'static str {
        match self {
            Self::Word => "w",
            Self::Digit => "d",
            Self::Space => "s",
        }
    }
}

/// 種類ごとの範囲を、始めの順に並べたもの（w・d・s の順）。
fn tables() -> &'static [Vec<(u32, u32)>; 3] {
    static TABLES: OnceLock<[Vec<(u32, u32)>; 3]> = OnceLock::new();
    TABLES.get_or_init(|| {
        let read = |class: Class| -> Vec<(u32, u32)> {
            CLASSES_TSV
                .lines()
                .filter_map(|line| {
                    let mut parts = line.trim_end().split('\t');
                    if parts.next()? != class.tag() {
                        return None;
                    }
                    let start = u32::from_str_radix(parts.next()?, 16).ok()?;
                    let end = u32::from_str_radix(parts.next()?, 16).ok()?;
                    Some((start, end))
                })
                .collect()
        };
        [read(Class::Word), read(Class::Digit), read(Class::Space)]
    })
}

/// その文字が、Python の `re` でその種類に入るか。
pub fn is(class: Class, c: char) -> bool {
    let table = &tables()[class as usize];
    let code = u32::from(c);
    let after = table.partition_point(|(start, _)| *start <= code);
    after > 0 && code <= table[after - 1].1
}

/// Python の小文字の表（`l`）と、`Σ` の判定に使う 2 つの範囲（`c` = Cased、`i` = Case_Ignorable）。
/// `tests/fixtures/djaudio/generate_case.py` で Python 3.13 から作る。
const CASE_TSV: &str = include_str!("python_case.tsv");

/// 小文字の表と範囲を読んだもの。
struct CaseTables {
    lower: std::collections::HashMap<char, String>,
    cased: Vec<(u32, u32)>,
    ignorable: Vec<(u32, u32)>,
}

fn case_tables() -> &'static CaseTables {
    static TABLES: OnceLock<CaseTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut tables = CaseTables {
            lower: std::collections::HashMap::new(),
            cased: Vec::new(),
            ignorable: Vec::new(),
        };
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        for line in CASE_TSV.lines() {
            let mut parts = line.trim_end().split('\t');
            match (parts.next(), parts.next(), parts.next()) {
                (Some("l"), Some(from), Some(to)) => {
                    if let Some(from) = hex(from).and_then(char::from_u32) {
                        let to: String = to
                            .split(' ')
                            .filter_map(|x| hex(x).and_then(char::from_u32))
                            .collect();
                        tables.lower.insert(from, to);
                    }
                }
                (Some(kind @ ("c" | "i")), Some(start), Some(end)) => {
                    if let (Some(start), Some(end)) = (hex(start), hex(end)) {
                        let list = if kind == "c" {
                            &mut tables.cased
                        } else {
                            &mut tables.ignorable
                        };
                        list.push((start, end));
                    }
                }
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

/// Python の `str.lower()`（Python 3.13 の表どおり。`Σ` は、前に大文字小文字のある文字があり、後ろに無ければ `ς`）。
pub fn lower(text: &str) -> String {
    let tables = case_tables();
    let chars: Vec<char> = text.chars().collect();
    let cased = |c: char| in_ranges(&tables.cased, c);
    let ignorable = |c: char| in_ranges(&tables.ignorable, c);
    let mut out = String::with_capacity(text.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '\u{3a3}' {
            // CPython の handle_capital_sigma。
            let before = chars[..i].iter().rev().find(|c| !ignorable(**c));
            let mut last = before.is_some_and(|c| cased(*c));
            if last && i + 1 < chars.len() {
                last = chars[i + 1..]
                    .iter()
                    .find(|c| !ignorable(**c))
                    .is_none_or(|c| !cased(*c));
            }
            out.push(if last { '\u{3c2}' } else { '\u{3c3}' });
            continue;
        }
        match tables.lower.get(&c) {
            Some(lowered) => out.push_str(lowered),
            None => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 小文字は Python と同じ（`İ` は 2 文字になる、`Σ` は語の終わりで `ς`、ケルビンの記号は `k`）。
    #[test]
    fn lower_follows_python() {
        assert!(case_tables().lower.len() > 1400);
        assert_eq!(lower("ABC Ä"), "abc ä");
        assert_eq!(lower("\u{130}"), "i\u{307}");
        assert_eq!(lower("\u{212a}"), "k");
        assert_eq!(lower("ΣΑΣ ΟΔΟΣ."), "σας οδος.");
        assert_eq!(lower("Σ"), "σ");
        assert_eq!(lower("AΣ'b"), "aσ'b");
        assert_eq!(lower("AΣ'"), "aς'");
    }

    /// 表が読めていて、Python と Rust で見方が違う文字を、Python と同じに見ること。
    #[test]
    fn classes_follow_python() {
        for (class, count) in [(Class::Word, 700), (Class::Digit, 60), (Class::Space, 10)] {
            assert!(tables()[class as usize].len() >= count, "{class:?}");
        }
        // 語の文字: 英数字・下線・ひらがな・漢字・全角の数字。結合文字（U+0301）とつなぎの記号（U+203F）は入らない。
        for c in ['a', 'Z', '0', '_', 'あ', '漢', '１', 'é'] {
            assert!(is(Class::Word, c), "{c:?}");
        }
        for c in ['-', ' ', '\u{301}', '\u{203f}', '😀', ':'] {
            assert!(!is(Class::Word, c), "{c:?}");
        }
        // 数字: アラビア・インドの数字と全角の数字も入る。丸数字（No）は入らない。
        for c in ['0', '٣', '１'] {
            assert!(is(Class::Digit, c), "{c:?}");
        }
        for c in ['①', 'a', '五'] {
            assert!(!is(Class::Digit, c), "{c:?}");
        }
        // 空白: 区切りの制御文字（U+001C〜U+001F）も入る。ゼロ幅の空白（U+200B）は入らない。
        for c in [
            ' ', '\t', '\n', '\u{1c}', '\u{1f}', '\u{85}', '\u{a0}', '\u{3000}',
        ] {
            assert!(is(Class::Space, c), "{c:?}");
        }
        for c in ['\u{200b}', '\u{feff}', '\u{180e}', 'a'] {
            assert!(!is(Class::Space, c), "{c:?}");
        }
        // 空白の判定は、設定の読み方で使っている Python の `str.isspace` の写しと同じであること。
        for code in 0..0x3100 {
            let c = char::from_u32(code).unwrap();
            assert_eq!(
                is(Class::Space, c),
                crate::commands::server::python::is_space(c),
                "{c:?}"
            );
        }
    }
}
