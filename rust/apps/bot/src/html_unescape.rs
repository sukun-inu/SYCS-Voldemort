//! HTML の実体参照（`&amp;`・`&#12354;`・`&#x3042;` など）を文字に戻す。Python の `html.unescape`。
//!
//! 決まりは Python と同じ（HTML5 の決まり）:
//!
//! - 名前つき: HTML5 の表（2231 個）にあるものを戻す。`;` の無い古い形（`&copy`・`&amp` など）も表にある。
//!   表に無ければ、前から一致するいちばん長い名前を戻して残りをそのまま付ける（`&notit;` → `¬it;`）。
//!   どれにも当たらなければそのまま
//! - 番号: 10 進（`&#65;`）と 16 進（`&#x41;`）。`;` は無くてもよい。0 や代用符号・範囲外は U+FFFD、
//!   Windows-1252 の番号（128〜159）はその文字に置き換え、制御文字などは消す
//!
//! 表（`html5_entities.tsv`）は Python 3.13 の `html.entities.html5` と `html._invalid_charrefs`・
//! `html._invalid_codepoints` を書き出したもの（`tests/fixtures/news/generate.py entities`）。

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};

struct Tables {
    /// 名前（`amp;`・`amp` など）→ 文字。
    named: HashMap<&'static str, String>,
    /// 別の文字に置き換える番号。
    replaced: HashMap<u32, String>,
    /// 消す番号。
    dropped: HashSet<u32>,
}

fn chars_of(hex: &str) -> String {
    hex.split(' ')
        .filter_map(|h| u32::from_str_radix(h, 16).ok().and_then(char::from_u32))
        .collect()
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let mut tables = Tables {
        named: HashMap::new(),
        replaced: HashMap::new(),
        dropped: HashSet::new(),
    };
    for line in include_str!("html5_entities.tsv").lines() {
        let mut cols = line.split('\t');
        match (cols.next(), cols.next(), cols.next()) {
            (Some("E"), Some(name), Some(value)) => {
                tables.named.insert(name, chars_of(value));
            }
            (Some("R"), Some(num), Some(value)) => {
                if let Ok(n) = u32::from_str_radix(num, 16) {
                    tables.replaced.insert(n, chars_of(value));
                }
            }
            (Some("X"), Some(num), None) => {
                if let Ok(n) = u32::from_str_radix(num, 16) {
                    tables.dropped.insert(n);
                }
            }
            _ => {}
        }
    }
    tables
});

/// Python の `html._charref`。
static CHARREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\x0C <&#;]{1,32};?)")
        .expect("正しい正規表現")
});

/// 番号の実体参照を戻す。桁が多すぎて数にできないものは範囲外（U+FFFD）。
fn numeric(digits: &str, radix: u32) -> String {
    let num = u32::from_str_radix(digits, radix).unwrap_or(u32::MAX);
    if let Some(replaced) = TABLES.replaced.get(&num) {
        return replaced.clone();
    }
    if (0xD800..=0xDFFF).contains(&num) || num > 0x10_FFFF {
        return "\u{FFFD}".into();
    }
    if TABLES.dropped.contains(&num) {
        return String::new();
    }
    char::from_u32(num).map(String::from).unwrap_or_default()
}

/// 名前つきの実体参照を戻す。`s` は `&` の後ろ（`;` があればそれも含む）。
fn named(s: &str) -> String {
    if let Some(value) = TABLES.named.get(s) {
        return value.clone();
    }
    // 前から一致するいちばん長い名前（2 文字以上）を探す。
    let ends: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    for x in (2..ends.len()).rev() {
        let (head, tail) = s.split_at(ends[x]);
        if let Some(value) = TABLES.named.get(head) {
            return format!("{value}{tail}");
        }
    }
    format!("&{s}")
}

fn replace(caps: &Captures<'_>) -> String {
    let s = &caps[1];
    match s.strip_prefix('#') {
        Some(rest) => {
            let rest = rest.trim_end_matches(';');
            match rest.strip_prefix(['x', 'X']) {
                Some(hex) => numeric(hex, 16),
                None => numeric(rest, 10),
            }
        }
        None => named(s),
    }
}

/// 実体参照を文字に戻す。
pub fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    CHARREF.replace_all(text, replace).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表を読み切れていること（Python 3.13 の表の大きさ）。
    #[test]
    fn the_tables_are_complete() {
        assert_eq!(TABLES.named.len(), 2231);
        assert_eq!(TABLES.replaced.len(), 34);
        assert_eq!(TABLES.dropped.len(), 126);
        assert_eq!(TABLES.named["amp;"], "&");
        assert_eq!(TABLES.named["NotEqualTilde;"], "\u{2242}\u{338}");
    }

    /// 名前つき: 表にあるもの・`;` の無い古い形・前から一致するいちばん長い名前・当たらないもの。
    #[test]
    fn named_references_follow_html5() {
        assert_eq!(unescape("&lt;b&gt; &amp; &quot;x&quot;"), "<b> & \"x\"");
        assert_eq!(unescape("&nbsp;"), "\u{A0}");
        assert_eq!(unescape("&copy &copy; &copyright;"), "© © ©right;");
        assert_eq!(unescape("&notin; &notit; &not"), "∉ ¬it; ¬");
        assert_eq!(unescape("&ampfoo; &AMP; &Amp;"), "&foo; & &Amp;");
        assert_eq!(unescape("&unknown; &a; &; &&"), "&unknown; &a; &; &&");
        // 二重の実体は一段だけ戻す。
        assert_eq!(unescape("&amp;lt;"), "&lt;");
        assert_eq!(unescape("実体なし"), "実体なし");
    }

    /// 番号: 10 進・16 進・`;` なし、置き換え・範囲外・消す番号。
    #[test]
    fn numeric_references_follow_html5() {
        assert_eq!(unescape("&#65;&#x41;&#X41;&#0065&#x41"), "AAAAA");
        assert_eq!(unescape("&#12354;&#x3042;&#x1F600;"), "ああ😀");
        assert_eq!(
            unescape("&#0;&#xD800;&#x110000;"),
            "\u{FFFD}\u{FFFD}\u{FFFD}"
        );
        assert_eq!(unescape("&#99999999999999999999;"), "\u{FFFD}");
        assert_eq!(unescape("&#128;&#130;&#159;"), "\u{20AC}\u{201A}\u{178}");
        assert_eq!(unescape("[&#1;&#8;&#11;&#127;&#xFDD0;&#xFFFE;]"), "[]");
        assert_eq!(unescape("&#13;&#9;"), "\r\t");
        assert_eq!(unescape("&#; &#x; &# &#a;"), "&#; &#x; &# &#a;");
    }
}
