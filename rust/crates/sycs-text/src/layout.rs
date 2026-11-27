//! 文字を並べる。Pillow が使う raqm 0.11（`src/thirdparty/raqm/raqm.c`）と HarfBuzz（hb-ft）にあたるところ。
//!
//! Pillow（`_imagingft.c` の `text_layout_raqm`）は、文字列を raqm に渡してグリフの番号と位置をもらう。raqm は
//!
//! 1. 文字ごとに用字（スクリプト）を決める（`_raqm_resolve_scripts`。数字や記号は前の字に合わせる。括弧は
//!    開きと閉じを同じ用字にする）
//! 2. 用字の変わり目で区切る（`_raqm_itemize`）
//! 3. 区切りごとに HarfBuzz で形を決める（`_raqm_shape`。前後の文字は文脈として渡す）
//!
//! の順に進める。HarfBuzz の部分は `harfrust`（HarfBuzz の Rust への写し）に任せ、送り幅は FreeType と同じ値を
//! 渡す（[`FtFuncs`]。hb-ft の `hb_ft_get_glyph_h_advances`）。カーニングなどの移動量は、HarfBuzz と同じ丸めで
//! 26.6 に直される（`ShaperFont` に倍率を渡す）。
//!
//! # Pillow と違うところ
//!
//! - 右から左へ書く文字（アラビア文字・ヘブライ文字など）は、左から右として並べる。raqm は FriBidi で
//!   並べ替えるが、ここでは写していない（使うフォントにその字は無く、どちらでも「字が無い」印になる）。
//! - 言語の指定はしない。Pillow（HarfBuzz）は環境の言語（本番は `C.UTF-8` → `c`）を渡すが、これは
//!   OpenType の言語に当たらないので、既定の言語として扱われる。指定しないのと同じ。

use harfrust::{
    Buffer, BufferFlags, Direction, FontFuncs, GlyphId, Script, ShapeOptions, ShaperFont,
};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

use super::glyph::SizedFace;

/// 並べた 1 つのグリフ（raqm の `raqm_glyph_t`。位置は 26.6）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacedGlyph {
    /// グリフの番号。
    pub index: u32,
    /// 横のずらし。
    pub x_offset: i32,
    /// 縦のずらし（上が正）。
    pub y_offset: i32,
    /// 横の送り。
    pub x_advance: i32,
    /// 縦の送り。
    pub y_advance: i32,
    /// 元の文の何文字目か。
    pub cluster: u32,
}

/// 並べられなかった理由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// 段落の区切り（改行・復帰など）が入っている。raqm は「1 段落だけ」を扱う（`raqm_layout() failed.`）。
    ParagraphSeparator,
    /// 形を決められなかった。
    Shape,
}

/// 括弧の組（raqm の `paired_chars`。偶数番が開き、次の奇数番が閉じ）。
const PAIRED_CHARS: [u32; 34] = [
    0x0028, 0x0029, 0x003c, 0x003e, 0x005b, 0x005d, 0x007b, 0x007d, 0x00ab, 0x00bb, 0x2018, 0x2019,
    0x201c, 0x201d, 0x2039, 0x203a, 0x3008, 0x3009, 0x300a, 0x300b, 0x300c, 0x300d, 0x300e, 0x300f,
    0x3010, 0x3011, 0x3014, 0x3015, 0x3016, 0x3017, 0x3018, 0x3019, 0x301a, 0x301b,
];

/// 段落の区切りか（raqm の `_raqm_is_paragraph_separator`）。
fn is_paragraph_separator(ch: u32) -> bool {
    matches!(
        ch,
        0x000A | 0x000D | 0x001C | 0x001D | 0x001E | 0x0085 | 0x2029
    )
}

/// 1 文字の用字（raqm の `_raqm_unicode_script`）。重ねる記号（Mn）は、前の字に従う扱いにする。
fn unicode_script(ch: u32) -> Script {
    let is_mark =
        char::from_u32(ch).is_some_and(|c| c.general_category() == GeneralCategory::NonspacingMark);
    if is_mark {
        Script::INHERITED
    } else {
        harfrust::unicode::script(ch)
    }
}

/// 文字ごとの用字を決める（raqm の `_raqm_resolve_scripts`）。
///
/// 共通の字（数字・記号・空白）と「前の字に従う」字は、前の字の用字にする。括弧は、開きと閉じを同じ用字に
/// する。先頭に残った共通の字は、後ろの字に合わせる。
pub fn resolve_scripts(text: &[u32]) -> Vec<Script> {
    let mut scripts: Vec<Script> = text.iter().map(|ch| unicode_script(*ch)).collect();
    let mut last_script_index: Option<usize> = None;
    let mut last_set_index: Option<usize> = None;
    let mut last_script = Script::UNKNOWN;
    // 開いている括弧（用字・括弧の表の番号）。
    let mut stack: Vec<(Script, usize)> = Vec::new();
    for i in 0..text.len() {
        if scripts[i] == Script::COMMON && last_script_index.is_some() {
            match PAIRED_CHARS.binary_search(&text[i]) {
                Ok(pair_index) if pair_index & 1 == 0 => {
                    // 開く括弧
                    scripts[i] = last_script;
                    last_set_index = Some(i);
                    stack.push((scripts[i], pair_index));
                }
                Ok(pair_index) => {
                    // 閉じる括弧。対になる開きを探す（間の開きは捨てる）。
                    while stack.last().is_some_and(|top| top.1 != pair_index & !1) {
                        stack.pop();
                    }
                    if let Some(top) = stack.last() {
                        scripts[i] = top.0;
                        last_script = scripts[i];
                    } else {
                        scripts[i] = last_script;
                    }
                    last_set_index = Some(i);
                }
                Err(_) => {
                    scripts[i] = last_script;
                    last_set_index = Some(i);
                }
            }
        } else if scripts[i] == Script::INHERITED && last_script_index.is_some() {
            scripts[i] = last_script;
            last_set_index = Some(i);
        } else {
            let from = last_set_index.map_or(0, |index| index + 1);
            for j in from..i {
                scripts[j] = scripts[i];
            }
            last_script = scripts[i];
            last_script_index = Some(i);
            last_set_index = Some(i);
        }
    }
    // 先頭に残った共通の字は、次の字に合わせる。
    for i in (0..text.len().saturating_sub(1)).rev() {
        if scripts[i] == Script::INHERITED || scripts[i] == Script::COMMON {
            scripts[i] = scripts[i + 1];
        }
    }
    scripts
}

/// HarfBuzz に渡す送り幅（hb-ft の `hb_ft_get_glyph_h_advances`）。
///
/// FreeType のヒンティングなしの送り幅（16.16）を、512 を足して 10 ビット落とす（26.6）。
struct FtFuncs<'a>(&'a SizedFace);

impl FontFuncs for FtFuncs<'_> {
    fn glyph_h_advance(&self, _font: &ShaperFont, glyph: GlyphId) -> i32 {
        ((self.0.linear_advance(glyph.to_u32()) + (1 << 9)) >> 10) as i32
    }
}

/// 文を並べる（Pillow の `text_layout_raqm`）。空の文は空の並び。
pub fn layout(face: &SizedFace, text: &str) -> Result<Vec<PlacedGlyph>, LayoutError> {
    let chars: Vec<u32> = text.chars().map(u32::from).collect();
    if chars.is_empty() {
        return Ok(Vec::new());
    }
    if chars.iter().any(|ch| is_paragraph_separator(*ch)) {
        return Err(LayoutError::ParagraphSeparator);
    }
    let scripts = resolve_scripts(&chars);
    let funcs = FtFuncs(face);
    let font = ShaperFont::new(face.font())
        .with_scale(face.shaping_scale())
        .with_font_funcs(Some(&funcs));
    let mut placed = Vec::with_capacity(chars.len());
    let mut start = 0usize;
    while start < chars.len() {
        // 用字が同じ間を 1 区切りにする。
        let mut end = start + 1;
        while end < chars.len() && scripts[end] == scripts[start] {
            end += 1;
        }
        let mut buffer = Buffer::new();
        for (offset, ch) in chars[start..end].iter().enumerate() {
            buffer.push(*ch, (start + offset) as u32);
        }
        // 前後の文字は文脈として渡す（`hb_buffer_add_utf32` と同じ。前は近い順）。
        let before: Vec<u32> = chars[..start].iter().rev().copied().collect();
        buffer.set_pre_context_codepoints(&before);
        buffer.set_post_context_codepoints(&chars[end..]);
        buffer.set_script(Some(scripts[start]));
        buffer.set_direction(Direction::LeftToRight);
        buffer.set_flags(BufferFlags::BEGINNING_OF_TEXT | BufferFlags::END_OF_TEXT);
        harfrust::shape(&font, &mut buffer, ShapeOptions::new()).map_err(|_| LayoutError::Shape)?;
        for (info, position) in buffer.glyph_infos().iter().zip(buffer.glyph_positions()) {
            placed.push(PlacedGlyph {
                index: info.glyph_id,
                x_offset: position.x_offset,
                y_offset: position.y_offset,
                x_advance: position.x_advance,
                y_advance: position.y_advance,
                cluster: info.cluster,
            });
        }
        start = end;
    }
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用字の並びを、読みやすい 4 文字の名前で返す。
    fn scripts_of(text: &str) -> Vec<String> {
        let chars: Vec<u32> = text.chars().map(u32::from).collect();
        resolve_scripts(&chars)
            .iter()
            .map(|script| script.tag().to_string())
            .collect()
    }

    /// 数字・空白・記号は前の字の用字になること（「深さ 40 km」は 漢字／ひらがな／ラテン の 3 区切り）。
    #[test]
    fn common_characters_follow_the_previous_script() {
        assert_eq!(
            scripts_of("深さ 40 km"),
            [
                "Hani", "Hira", "Hira", "Hira", "Hira", "Hira", "Latn", "Latn"
            ]
        );
        assert_eq!(scripts_of("M5.2"), ["Latn"; 4]);
        assert_eq!(scripts_of("最大震度 5弱"), ["Hani"; 7]);
    }

    /// 先頭の共通の字は、後ろの字に合わせること。共通の字だけなら共通のまま。
    #[test]
    fn leading_common_characters_take_the_next_script() {
        assert_eq!(scripts_of(" 茨城"), ["Hani"; 3]);
        assert_eq!(scripts_of("12 km"), ["Latn"; 5]);
        assert_eq!(scripts_of("5+"), ["Zyyy"; 2]);
        assert_eq!(scripts_of(""), Vec::<String>::new());
    }

    /// 括弧は、開きと閉じが同じ用字になること（中で用字が変わっても、閉じは開きに合わせる）。
    #[test]
    fn brackets_share_the_script_of_their_opening() {
        // 開きの「 は前の「本」に合わせて漢字。閉じの 」 は、中がカタカナでも開きと同じ漢字。
        assert_eq!(
            scripts_of("日本「カナ」を"),
            ["Hani", "Hani", "Hani", "Kana", "Kana", "Hani", "Hira"]
        );
        // 対の無い閉じ括弧は、前の字に合わせる。
        assert_eq!(scripts_of("カ」"), ["Kana", "Kana"]);
        // 違う種類の開きは、閉じを探すときに捨てる。
        assert_eq!(scripts_of("a(「b)"), ["Latn"; 5]);
    }

    /// 重ねる記号（濁点 U+3099）は前の字に従うこと。
    #[test]
    fn combining_marks_inherit() {
        assert_eq!(
            scripts_of("か\u{3099}ウ\u{3099}"),
            ["Hira", "Hira", "Kana", "Kana"]
        );
        assert_eq!(scripts_of("e\u{301}"), ["Latn", "Latn"]);
    }

    /// 段落の区切りを見分けること。
    #[test]
    fn paragraph_separators_are_recognised() {
        for ch in [0x0A, 0x0D, 0x1C, 0x1D, 0x1E, 0x85, 0x2029] {
            assert!(is_paragraph_separator(ch), "{ch:#x}");
        }
        for ch in [0x09, 0x0B, 0x0C, 0x20, 0x2028, 0x3000] {
            assert!(!is_paragraph_separator(ch), "{ch:#x}");
        }
    }

    /// 括弧の表が、探せる並び（小さい順）で、開きと閉じが隣り合っていること。
    #[test]
    fn the_bracket_table_is_sorted_pairs() {
        assert!(PAIRED_CHARS.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(PAIRED_CHARS.binary_search(&0x300c), Ok(20));
        assert_eq!(PAIRED_CHARS.binary_search(&0x300d), Ok(21));
        assert_eq!(
            PAIRED_CHARS.binary_search(&0xff08),
            Err(34),
            "全角の括弧は表に無い"
        );
    }
}
