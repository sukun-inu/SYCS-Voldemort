//! 曲名の整え方と比べ方の下ごしらえ（`services/djaudio_isrc_meta.py` の `_clean_title`・`_normalize_for_compare`・
//! `_TOPIC_SUFFIX`・`_DASH_SPLIT`）を、Python 3.13 の `re`・`unicodedata`・`str` と同じ結果になるように写したもの。
//!
//! - 正規表現は Python の `re` と同じ「左から、書いた順の候補を先に、欲張りに」試す後戻りの照合で写す（Rust の
//!   `regex` は最長一致の規則も `\w`・`\d`・`\s` の中身も `IGNORECASE` の比べ方も違う）。`\w`・`\d`・`\s` は
//!   [`crate::python_chars`] の表、`IGNORECASE` の英字は Python が当てる文字の表（`ſ`・`K`・`İ`・`ı` を含む）を使う。
//! - `unicodedata.normalize("NFKD")` のあとに結合文字を除いたもの・`str.lower()`（語末の `Σ` を含む）は、
//!   Python 3.13（Unicode 15.1）から作った表（`python_text.tsv`。作り方は
//!   `tests/fixtures/djaudio_meta/generate_tables.py`）で引く。

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::python_chars::{self, Class};

/// Python から作った文字の表（L・N・C・I・E の行。説明は生成スクリプトの冒頭）。
const TEXT_TSV: &str = include_str!("python_text.tsv");

/// 表を読んだもの。
struct Tables {
    /// `str.lower()` が変える文字 → 変えた後。
    lower: HashMap<u32, Vec<char>>,
    /// NFKD に分けて結合文字を除くと変わる文字 → 残り（ハングルの音節は計算で出す）。
    strip: HashMap<u32, Vec<char>>,
    /// 語末の Σ の判定で「大文字小文字がある」とみなす文字（case-ignorable でないもの）の範囲。
    cased: Vec<(u32, u32)>,
    /// 語末の Σ の判定で飛ばす文字（case-ignorable）の範囲。
    ignorable: Vec<(u32, u32)>,
    /// `IGNORECASE` で英字（小文字）に当たる文字。
    equivalents: HashMap<char, Vec<char>>,
}

fn hex_chars(field: &str) -> Vec<char> {
    field
        .split_whitespace()
        .filter_map(|h| u32::from_str_radix(h, 16).ok().and_then(char::from_u32))
        .collect()
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Tables {
            lower: HashMap::new(),
            strip: HashMap::new(),
            cased: Vec::new(),
            ignorable: Vec::new(),
            equivalents: HashMap::new(),
        };
        for line in TEXT_TSV.lines() {
            let mut parts = line.split('\t');
            let (Some(kind), Some(first), rest) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            let Ok(code) = u32::from_str_radix(first, 16) else {
                continue;
            };
            let rest = rest.unwrap_or("");
            match kind {
                "L" => {
                    t.lower.insert(code, hex_chars(rest));
                }
                "N" => {
                    t.strip.insert(code, hex_chars(rest));
                }
                "C" | "I" => {
                    let Ok(end) = u32::from_str_radix(rest, 16) else {
                        continue;
                    };
                    if kind == "C" {
                        t.cased.push((code, end));
                    } else {
                        t.ignorable.push((code, end));
                    }
                }
                "E" => {
                    if let Some(c) = char::from_u32(code) {
                        t.equivalents.insert(c, hex_chars(rest));
                    }
                }
                _ => {}
            }
        }
        t
    })
}

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let code = u32::from(c);
    let after = table.partition_point(|(start, _)| *start <= code);
    after > 0 && code <= table[after - 1].1
}

/// Python の `str.isspace()`（`re` の `\s`・`str.strip()` が使う空白）。
pub fn is_space(c: char) -> bool {
    python_chars::is(Class::Space, c)
}

/// Python の `re` の `\w`。
pub fn is_word(c: char) -> bool {
    python_chars::is(Class::Word, c)
}

/// Python の `re` の `\d`（`str.isdecimal()`）。
pub fn is_digit(c: char) -> bool {
    python_chars::is(Class::Digit, c)
}

/// Python の `str.strip()`（引数なし）。
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// 1 文字の NFKD から結合文字を除いたもの（`_normalize_for_compare` の前半）を `out` に足す。
fn push_stripped(c: char, out: &mut Vec<char>) {
    let code = u32::from(c);
    // ハングルの音節は、規則どおり子音・母音（・終声）に分かれる（どれも結合文字ではない）。
    if (0xAC00..=0xD7A3).contains(&code) {
        let s = code - 0xAC00;
        let parts = [0x1100 + s / 588, 0x1161 + (s % 588) / 28, 0x11A7 + s % 28];
        let count = if parts[2] == 0x11A7 { 2 } else { 3 };
        out.extend(parts[..count].iter().filter_map(|p| char::from_u32(*p)));
        return;
    }
    match tables().strip.get(&code) {
        Some(mapped) => out.extend_from_slice(mapped),
        None => out.push(c),
    }
}

/// `"".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))`。
///
/// NFKD は 1 文字ずつ分けてから結合文字の順を並べ替えるだけで、並べ替えは結合文字どうしの間でしか起きない。
/// 結合文字を全部除くので、1 文字ずつの結果をつなげたものと同じになる。
pub fn strip_marks(text: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(text.len());
    for &c in text {
        push_stripped(c, &mut out);
    }
    out
}

/// CPython の `handle_capital_sigma`。i 番目の Σ が語末（前に大文字小文字のある文字があり、後ろに無い）か。
fn final_sigma(text: &[char], i: usize) -> bool {
    let t = tables();
    let mut j = i;
    let mut found = None;
    while j > 0 {
        j -= 1;
        if !in_ranges(&t.ignorable, text[j]) {
            found = Some(text[j]);
            break;
        }
    }
    let mut is_final = found.is_some_and(|c| in_ranges(&t.cased, c));
    if is_final && i + 1 < text.len() {
        let mut j = i + 1;
        while j < text.len() && in_ranges(&t.ignorable, text[j]) {
            j += 1;
        }
        is_final = j == text.len() || !in_ranges(&t.cased, text[j]);
    }
    is_final
}

/// Python の `str.lower()`。
pub fn py_lower(text: &[char]) -> Vec<char> {
    let t = tables();
    let mut out = Vec::with_capacity(text.len());
    for (i, &c) in text.iter().enumerate() {
        if c == '\u{3a3}' {
            out.push(if final_sigma(text, i) {
                '\u{3c2}'
            } else {
                '\u{3c3}'
            });
            continue;
        }
        match t.lower.get(&u32::from(c)) {
            Some(mapped) => out.extend_from_slice(mapped),
            None => out.push(c),
        }
    }
    out
}

/// Python の `_normalize_for_compare`: NFKD に分けて結合文字を除き、小文字にし、`[^\w\s]` を空白にし、
/// 空白の続きを 1 つにして両端を落とす。
pub fn normalize_for_compare(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let lowered = py_lower(&strip_marks(&chars));
    let mut out = String::with_capacity(lowered.len());
    let mut in_space = false;
    for c in lowered {
        // [^\w\s] → " " のあとの \s+ → " "。空白になった記号も、元の空白と同じ続きに入る。
        let space = is_space(c) || !is_word(c);
        if space {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    py_strip(&out).to_string()
}

// ---- Python の re と同じ順で試す、小さな後戻りの照合 ----

/// 1 文字の条件。
#[derive(Clone, Copy, Debug)]
enum Pred {
    /// その文字そのもの。
    Lit(char),
    /// `IGNORECASE` の英字（小文字で書く）。Python が当てる文字の表で比べる。
    Ci(char),
    /// `\s`。
    Space,
    /// `\d`。
    Digit,
    /// `\w`。
    Word,
    /// `.`（改行以外）。
    AnyButNewline,
    /// `[...]`（そのどれか）。
    Set(&'static [char]),
    /// `[^...]`（そのどれでもない）。
    NotSet(&'static [char]),
    /// `[\s\-_|/\\]`。
    TrailClass,
}

impl Pred {
    fn test(self, c: char) -> bool {
        match self {
            Self::Lit(l) => c == l,
            Self::Ci(l) => tables()
                .equivalents
                .get(&l)
                .map_or(c == l, |set| set.contains(&c)),
            Self::Space => is_space(c),
            Self::Digit => is_digit(c),
            Self::Word => is_word(c),
            Self::AnyButNewline => c != '\n',
            Self::Set(set) => set.contains(&c),
            Self::NotSet(set) => !set.contains(&c),
            Self::TrailClass => is_space(c) || matches!(c, '-' | '_' | '|' | '/' | '\\'),
        }
    }
}

/// 正規表現の木。
#[derive(Debug)]
enum Node {
    One(Pred),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    /// 欲張りな繰り返し（min 回以上 max 回以下）。
    Rep(Box<Node>, usize, usize),
    /// `$`（終わりか、終わりの改行の直前）。
    End,
}

const MANY: usize = usize::MAX;

fn m(node: &Node, s: &[char], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    match node {
        Node::One(p) => i < s.len() && p.test(s[i]) && k(i + 1),
        Node::Seq(nodes) => seq(nodes, s, i, k),
        Node::Alt(alts) => alts.iter().any(|a| m(a, s, i, &mut *k)),
        Node::Rep(inner, min, max) => match **inner {
            // 1 文字の繰り返しは、取れるだけ取ってから 1 つずつ戻す（Python の REPEAT_ONE と同じ順）。
            Node::One(p) => {
                let mut n = 0;
                while n < *max && i + n < s.len() && p.test(s[i + n]) {
                    n += 1;
                }
                if n < *min {
                    return false;
                }
                (*min..=n).rev().any(|j| (*k)(i + j))
            }
            _ => rep(inner, *min, *max, 0, s, i, k),
        },
        Node::End => (i == s.len() || (i + 1 == s.len() && s[i] == '\n')) && k(i),
    }
}

fn seq(nodes: &[Node], s: &[char], i: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    match nodes.split_first() {
        None => k(i),
        Some((first, rest)) => m(first, s, i, &mut |p| seq(rest, s, p, k)),
    }
}

fn rep(
    inner: &Node,
    min: usize,
    max: usize,
    count: usize,
    s: &[char],
    i: usize,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    // もう 1 回を先に試す（欲張り）。空の繰り返しは止める（ここで使う組は空にならない）。
    if count < max
        && m(inner, s, i, &mut |p| {
            p != i && rep(inner, min, max, count + 1, s, p, k)
        })
    {
        return true;
    }
    count >= min && k(i)
}

/// `pattern.search(s, start)` の当たった範囲。
fn search(node: &Node, s: &[char], start: usize) -> Option<(usize, usize)> {
    for i in start..=s.len() {
        let mut end = None;
        let found = m(node, s, i, &mut |e| {
            end = Some(e);
            true
        });
        if found {
            return Some((i, end.unwrap_or(i)));
        }
    }
    None
}

/// `pattern.sub(repl, s)`（ここのパターンは空には当たらない）。
fn sub(node: &Node, s: &[char], repl: &str) -> Vec<char> {
    let mut out = Vec::with_capacity(s.len());
    let mut last = 0;
    let mut pos = 0;
    while pos <= s.len() {
        let Some((start, end)) = search(node, s, pos) else {
            break;
        };
        out.extend_from_slice(&s[last..start]);
        out.extend(repl.chars());
        last = end;
        pos = if end == start { end + 1 } else { end };
    }
    out.extend_from_slice(&s[last.min(s.len())..]);
    out
}

// ---- パターンの組み立て ----

fn one(p: Pred) -> Node {
    Node::One(p)
}

/// IGNORECASE の文字列（英字は表で比べ、ほかはそのまま）。
fn ci(text: &str) -> Node {
    Node::Seq(
        text.chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    one(Pred::Ci(c))
                } else {
                    one(Pred::Lit(c))
                }
            })
            .collect(),
    )
}

fn alt(items: &[&str]) -> Node {
    Node::Alt(items.iter().map(|t| ci(t)).collect())
}

fn opt(node: Node) -> Node {
    Node::Rep(Box::new(node), 0, 1)
}

fn star(p: Pred) -> Node {
    Node::Rep(Box::new(one(p)), 0, MANY)
}

fn plus(p: Pred) -> Node {
    Node::Rep(Box::new(one(p)), 1, MANY)
}

fn seq_of(nodes: Vec<Node>) -> Node {
    Node::Seq(nodes)
}

const OPEN: &[char] = &['(', '[', '【'];
const CLOSE: &[char] = &[')', ']', '】'];
const DASHES: &[char] = &['-', '－', '—', '–'];
const SLASH_DASH: &[char] = &['-', '/'];

/// `_NOISE_BRACKET`（`re.IGNORECASE | re.VERBOSE`）。候補の順は Python のとおり。
fn noise_bracket() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| {
        let s = Pred::Space;
        let not_close = || plus(Pred::NotSet(CLOSE));
        let ver_sion = || seq_of(vec![ci("ver"), opt(ci("sion"))]);
        let lyric_s = || seq_of(vec![ci("lyric"), opt(ci("s"))]);
        let alternatives = vec![
            // official\s+(?:music\s+)?(?:video|audio|mv|visualizer|lyric[s]?|clip)
            seq_of(vec![
                ci("official"),
                plus(s),
                opt(seq_of(vec![ci("music"), plus(s)])),
                Node::Alt(vec![
                    ci("video"),
                    ci("audio"),
                    ci("mv"),
                    ci("visualizer"),
                    lyric_s(),
                    ci("clip"),
                ]),
            ]),
            // (?:hd|4k|8k|hq)\s*(?:video)?
            seq_of(vec![
                alt(&["hd", "4k", "8k", "hq"]),
                star(s),
                opt(ci("video")),
            ]),
            // full\s+(?:song|album|version)
            seq_of(vec![
                ci("full"),
                plus(s),
                alt(&["song", "album", "version"]),
            ]),
            // (?:audio|video)\s*(?:only)?
            seq_of(vec![alt(&["audio", "video"]), star(s), opt(ci("only"))]),
            // remaster(?:ed)?(?:\s+\d{4})?
            seq_of(vec![
                ci("remaster"),
                opt(ci("ed")),
                opt(seq_of(vec![
                    plus(s),
                    Node::Rep(Box::new(one(Pred::Digit)), 4, 4),
                ])),
            ]),
            // (?:extended|original|radio|album|single)\s+(?:mix|edit|version)
            seq_of(vec![
                alt(&["extended", "original", "radio", "album", "single"]),
                plus(s),
                alt(&["mix", "edit", "version"]),
            ]),
            // from\s+[^\)\]\】]+
            seq_of(vec![ci("from"), plus(s), not_close()]),
            // (?:feat|ft)\.?\s+[^\)\]\】]+
            seq_of(vec![
                alt(&["feat", "ft"]),
                opt(one(Pred::Lit('.'))),
                plus(s),
                not_close(),
            ]),
            // lyric[s]?
            lyric_s(),
            // (?:m/?v|p/?v)
            Node::Alt(vec![
                seq_of(vec![ci("m"), opt(one(Pred::Lit('/'))), ci("v")]),
                seq_of(vec![ci("p"), opt(one(Pred::Lit('/'))), ci("v")]),
            ]),
            // \d{4}(?:\s+version)?
            seq_of(vec![
                Node::Rep(Box::new(one(Pred::Digit)), 4, 4),
                opt(seq_of(vec![plus(s), ci("version")])),
            ]),
            // live(?:\s+ver(?:sion)?)?
            seq_of(vec![ci("live"), opt(seq_of(vec![plus(s), ver_sion()]))]),
            // ver(?:sion)?\.?\s*\w*
            seq_of(vec![
                ver_sion(),
                opt(one(Pred::Lit('.'))),
                star(s),
                star(Pred::Word),
            ]),
            // short\s+ver(?:sion)?
            seq_of(vec![ci("short"), plus(s), ver_sion()]),
            // music\s+video
            seq_of(vec![ci("music"), plus(s), ci("video")]),
            // visuali[sz]er
            seq_of(vec![
                ci("visuali"),
                Node::Alt(vec![ci("s"), ci("z")]),
                ci("er"),
            ]),
            // sub(?:title)?[s]?\s+(?:indo|english|日本語)
            seq_of(vec![
                ci("sub"),
                opt(ci("title")),
                opt(ci("s")),
                plus(s),
                alt(&["indo", "english", "日本語"]),
            ]),
            // (?:日本語|英語|한국어|中文)\s*(?:字幕|ver)?
            seq_of(vec![
                alt(&["日本語", "英語", "한국어", "中文"]),
                star(s),
                opt(alt(&["字幕", "ver"])),
            ]),
        ];
        seq_of(vec![
            one(Pred::Set(OPEN)),
            star(s),
            Node::Alt(alternatives),
            star(s),
            one(Pred::Set(CLOSE)),
        ])
    })
}

/// `_FEAT_BARE`（`\s+(?:feat|ft)\.?\s+.+$`、IGNORECASE）。
fn feat_bare() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| {
        seq_of(vec![
            plus(Pred::Space),
            alt(&["feat", "ft"]),
            opt(one(Pred::Lit('.'))),
            plus(Pred::Space),
            plus(Pred::AnyButNewline),
            Node::End,
        ])
    })
}

/// `_TOPIC_SUFFIX`（`\s*[-/]\s*Topic\s*$`、IGNORECASE）。
fn topic_suffix() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| {
        seq_of(vec![
            star(Pred::Space),
            one(Pred::Set(SLASH_DASH)),
            star(Pred::Space),
            ci("topic"),
            star(Pred::Space),
            Node::End,
        ])
    })
}

/// `_DASH_SPLIT`（`\s+[-－—–]\s+`）。
fn dash_split_node() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| {
        seq_of(vec![
            plus(Pred::Space),
            one(Pred::Set(DASHES)),
            plus(Pred::Space),
        ])
    })
}

/// `\s{2,}`。
fn two_spaces() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| Node::Rep(Box::new(one(Pred::Space)), 2, MANY))
}

/// `[\s\-_|/\\]+$`。
fn trailing_junk() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| seq_of(vec![plus(Pred::TrailClass), Node::End]))
}

fn to_string(chars: &[char]) -> String {
    chars.iter().collect()
}

/// Python の `_clean_title`: 動画の題から検索の邪魔になる飾り（「(Official Music Video)」「feat. ○○」「[4K]」など）を
/// 除く。全部除いて空になったら元の題を返す。
pub fn clean_title(title: &str) -> String {
    let chars: Vec<char> = title.chars().collect();
    let t = sub(feat_bare(), &chars, "");
    let t = sub(noise_bracket(), &t, "");
    let t = sub(two_spaces(), &t, " ");
    let t: Vec<char> = py_strip(&to_string(&t)).chars().collect();
    let t = sub(trailing_junk(), &t, "");
    let t = py_strip(&to_string(&t)).to_string();
    if t.is_empty() { title.to_string() } else { t }
}

/// `_TOPIC_SUFFIX.sub("", text)`（YouTube の「○○ - Topic」の末尾を除く）。
pub fn remove_topic_suffix(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    to_string(&sub(topic_suffix(), &chars, ""))
}

/// `_DASH_SPLIT.search(text)` が当たるか。
pub fn has_dash(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    search(dash_split_node(), &chars, 0).is_some()
}

/// `_DASH_SPLIT.split(text, maxsplit=1)`（当たらなければ元の 1 つだけ）。
pub fn dash_split_once(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    match search(dash_split_node(), &chars, 0) {
        Some((start, end)) => vec![to_string(&chars[..start]), to_string(&chars[end..])],
        None => vec![text.to_string()],
    }
}

/// 表の全部の文字について Python と同じかを、生成スクリプトと同じ形のハッシュの材料で返す（テスト用）。
///
/// 返すのは (小文字・結合文字を除いたもの・語末の Σ の 2 つの性質・数字の値) の 4 つのバイト列の作り方。
pub mod digest_parts {
    use super::*;

    /// 1 文字の `str.lower()`（語末の Σ の判定を含まない、1 文字だけの文字列として）。
    pub fn lower(c: char) -> String {
        py_lower(&[c]).into_iter().collect()
    }

    /// 1 文字の NFKD から結合文字を除いたもの。
    pub fn strip(c: char) -> String {
        strip_marks(&[c]).into_iter().collect()
    }

    /// 語末の Σ の判定の 2 つの性質（飛ばすか、大文字小文字があるか）。
    pub fn sigma(c: char) -> [u8; 2] {
        let t = tables();
        [
            u8::from(in_ranges(&t.ignorable, c)),
            u8::from(in_ranges(&t.cased, c)),
        ]
    }
}
