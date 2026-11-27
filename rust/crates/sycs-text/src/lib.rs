//! 文字を描く。Python（Pillow 13.0.0）の `ImageDraw.text`・`textbbox`・`textlength` と、画素まで同じ結果を出す。
//!
//! 地震の画像（震度の札・震度の地図）は、Python の Bot が Pillow で描いていた。Rust の Bot も同じ絵を出すので、
//! 文字も Pillow と同じ手順で描く。Pillow の文字は 4 つの段でできている。段ごとに同じ計算を写してある。
//!
//! | 段 | Pillow が使うもの | ここでは |
//! |---|---|---|
//! | 並べる | raqm 0.11＋HarfBuzz 14.5 | [`layout`]（`harfrust`） |
//! | 輪郭とヒンティング | FreeType 2.14.3 の CFF エンジン | [`glyph`]（`skrifa`） |
//! | 塗る | FreeType の smooth ラスタライザ | [`ftgrays`] |
//! | 置く | `_imagingft.c`・`ImageDraw.py`・`Paste.c` | このファイル |
//!
//! フォントは Python と同じファイル（Debian の `fonts-noto-cjk` の `NotoSansCJK-Regular.ttc`・`-Bold.ttc`、
//! 面の番号は 0）。段ごとに本物の Pillow・FreeType と突き合わせてあり、基準は `tests/fixtures/expected.json`
//! （`tests/fixtures/generate.py` が本物の Python から作る）、確かめるテストは `tests/golden.rs`（フォントが要る）。
//!
//! この文字を使う小さな絵（震度の札）も、ここに置く（[`badge`]）。
//!
//! # Bot と別の crate にしてある理由
//!
//! 画素を 1 つずつ回す処理なので、最適化なし（`cargo test` の既定）だと桁違いに遅い。CI はテストを QEMU の
//! Sandy Bridge のふりで動かすので、さらに遅くなる。この crate と、字の形を出す依存（skrifa・harfrust・
//! read-fonts）だけ、`rust/Cargo.toml` の `[profile.dev.package.*]` で最適化を効かせてある（Bot 本体のビルドは
//! 変わらない）。Bot からは `sycs_bot::earthquake_text` が同じ名前で出し直している。
//!
//! # 置き方（Pillow の決まり）
//!
//! - `font_getsize`・`font_render`（`_imagingft.c`）: グリフの位置は 26.6 で足していき、1 字ごとに画素へ
//!   丸める（`PIXEL`）。字の絵そのものは整数の位置にしか置かない。座標の小数は、置く位置の丸めにだけ効く。
//! - anchor: 1 文字目は横（`l` 左・`m` 中・`r` 右）、2 文字目は縦（`a` 上端・`t` 絵の上・`m` 上端と下端の真ん中・
//!   `s` ベースライン・`b` 絵の下・`d` 下端）。
//! - `ImageDraw.text` は、字の濃さを型にして色を塗る（`ImagingFill2` → `fill_mask_L`）。下の画素が透明
//!   （アルファ 0）なら色は fill そのものに、そうでなければ濃さで混ぜる。アルファは濃さで混ぜる。
//!
//! # Pillow と違うところ
//!
//! - 形の指定（features）・言語・縦書き・縁取り・色つきの字は無い（Python の地震の画像は使っていない）。
//! - 右から左へ書く文字は並べ替えない（[`layout`] の説明）。
//! - 描けない文（復帰 U+000D などの段落の区切りが入っている・anchor の字が違う）は、Python では例外になる。
//!   ここでは何も描かず、長さは 0・箱は全部 0 を返す。

pub mod badge;
pub mod ftgrays;
pub mod glyph;
pub mod layout;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use image::RgbaImage;

pub use glyph::GlyphBitmap;
use glyph::{Face, SizedFace};
pub use layout::PlacedGlyph;

/// 文字を描くのに使うフォント（Python の `_get_font(size, bold)`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FontSpec {
    /// 大きさ（ピクセル。Python の `ImageFont.truetype(path, size)` の size）。
    pub size: u32,
    /// 太字（NotoSansCJK-Bold）か。
    pub bold: bool,
}

/// Pillow の anchor（`"la"`・`"ls"`・`"lm"`・`"mm"` など、2 文字）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor(pub [u8; 2]);

/// Pillow の `ImageDraw` の文字の口。
pub trait TextPainter: Sync {
    /// `draw.textlength(text, font=…)`。
    fn text_length(&self, text: &str, font: FontSpec) -> f64;
    /// `draw.textbbox(xy, text, font=…, anchor=…)`（左・上・右・下）。
    fn text_bbox(
        &self,
        xy: (f64, f64),
        text: &str,
        font: FontSpec,
        anchor: Anchor,
    ) -> (i32, i32, i32, i32);
    /// `draw.text(xy, text, font=…, fill=…, anchor=…)`。RGBA の画像に、Pillow と同じ画素で描く。
    fn draw_text(
        &self,
        canvas: &mut RgbaImage,
        xy: (f64, f64),
        text: &str,
        font: FontSpec,
        fill: [u8; 4],
        anchor: Anchor,
    );
}

/// 通常の字面を探す場所。Python の `_FONT_SEARCH_PATHS` のうち Linux の分（順番も同じ）。
///
/// 基準を作ったのは 1 つ目（Debian の `fonts-noto-cjk`）。ほかの場所のファイルは、中身が同じとは限らない。
pub const REGULAR_FONT_PATHS: [&str; 4] = [
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
];

/// 太字を探す場所。Python の `_BOLD_FONT_SEARCH_PATHS` のうち Linux の分。
pub const BOLD_FONT_PATHS: [&str; 4] = [
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Bold.otf",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Bold.ttc",
];

/// フォントを用意できなかった理由。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FontError {
    /// どの場所にも無い（探した場所）。
    NotFound(Vec<String>),
    /// 読めない（場所・理由）。
    Unreadable(String, String),
    /// フォントとして読めない（場所）。
    Malformed(String),
}

impl fmt::Display for FontError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(tried) => write!(
                f,
                "フォントがありません（fonts-noto-cjk を入れてください。探した場所: {}）",
                tried.join("、")
            ),
            Self::Unreadable(path, error) => write!(f, "フォント {path} を読めません: {error}"),
            Self::Malformed(path) => write!(f, "フォント {path} の中身を読めません"),
        }
    }
}

impl std::error::Error for FontError {}

/// 描いた文字の濃さ（Pillow の `font.getmask2` の結果）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextMask {
    /// 幅。
    pub width: u32,
    /// 高さ。
    pub height: u32,
    /// 濃さ（0〜255）。上の行が先。
    pub pixels: Vec<u8>,
    /// 描く座標から、この絵の左上までのずれ（`getmask2` が返す offset）。
    pub offset: (i32, i32),
}

/// Pillow と同じ描き方をする [`TextPainter`]。
///
/// 読んだ文字の形は、この値が生きている間は覚えている（同じ大きさの同じ字を塗り直さない）。フォントの
/// ファイル（1 本 約 20MB）もメモリに持つので、**画像を 1 枚作る間だけ作って、終わったら捨てる**使い方を
/// 想定している。
pub struct PillowText {
    regular: Option<Face>,
    bold: Option<Face>,
}

impl PillowText {
    /// 決まった場所（[`REGULAR_FONT_PATHS`]・[`BOLD_FONT_PATHS`]）からフォントを読む。
    ///
    /// 要る方だけ読む（札は太字だけ、地図は通常だけ）。Python の `_font_path` と同じく、太字が無ければ
    /// 通常の字面で代える。通常の字面も無ければ誤り（Python は Pillow の内蔵の欧文フォントへ落とすが、
    /// それは写していない）。
    pub fn load(regular: bool, bold: bool) -> Result<Self, FontError> {
        let regular_path = first_existing(&REGULAR_FONT_PATHS);
        let bold_path = first_existing(&BOLD_FONT_PATHS).or_else(|| regular_path.clone());
        let not_found = |paths: &[&str]| {
            FontError::NotFound(paths.iter().map(|path| (*path).to_owned()).collect())
        };
        let regular = match (regular, regular_path) {
            (false, _) => None,
            (true, Some(path)) => Some(path),
            (true, None) => return Err(not_found(&REGULAR_FONT_PATHS)),
        };
        let bold = match (bold, bold_path) {
            (false, _) => None,
            (true, Some(path)) => Some(path),
            (true, None) => return Err(not_found(&BOLD_FONT_PATHS)),
        };
        Self::from_files(regular.as_deref(), bold.as_deref())
    }

    /// 指定したファイルから読む（`None` の方は読まない）。
    pub fn from_files(regular: Option<&Path>, bold: Option<&Path>) -> Result<Self, FontError> {
        let read = |path: &Path| -> Result<Face, FontError> {
            let shown = path.display().to_string();
            let data = std::fs::read(path)
                .map_err(|error| FontError::Unreadable(shown.clone(), error.to_string()))?;
            Face::new(data).ok_or(FontError::Malformed(shown))
        };
        Ok(Self {
            regular: regular.map(read).transpose()?,
            bold: bold.map(read).transpose()?,
        })
    }

    /// 大きさを決めた面。読んでいない太さなら `None`。
    fn sized(&self, font: FontSpec) -> Option<Arc<SizedFace>> {
        let face = if font.bold {
            self.bold.as_ref()
        } else {
            self.regular.as_ref()
        }?;
        // 大きさ 0 は、Pillow では「font size must be greater than 0」の例外。
        (font.size > 0).then(|| face.sized(font.size))
    }

    /// 文字からグリフの番号を引く（FreeType の `FT_Get_Char_Index`。無い字は 0）。
    pub fn glyph_index(&self, font: FontSpec, ch: char) -> Option<u32> {
        let sized = self.sized(font)?;
        Some(
            sized
                .font()
                .charmap()
                .map_unicode(ch)
                .map_or(0, |glyph| glyph.to_u32()),
        )
    }

    /// 1 文字の輪郭（ヒンティング済み、26.6）。FreeType の `FT_Load_Glyph(face, glyph, FT_LOAD_DEFAULT)` の結果。
    pub fn glyph_outline(&self, font: FontSpec, glyph: u32) -> Option<ftgrays::Outline> {
        Some(self.sized(font)?.glyph(glyph).outline.clone())
    }

    /// 1 文字のビットマップ。FreeType の `FT_Render_Glyph(slot, FT_RENDER_MODE_NORMAL)` の結果。
    pub fn glyph_bitmap(&self, font: FontSpec, glyph: u32) -> Option<GlyphBitmap> {
        Some(self.sized(font)?.glyph(glyph).bitmap())
    }

    /// ヒンティングなしの送り幅（16.16）。FreeType の `FT_Get_Advance(face, glyph, FT_LOAD_NO_HINTING)`。
    pub fn linear_advance(&self, font: FontSpec, glyph: u32) -> Option<i64> {
        Some(self.sized(font)?.linear_advance(glyph))
    }

    /// 上端と下端（画素。Pillow の `font.getmetrics()`。下端は正の数）。
    pub fn metrics(&self, font: FontSpec) -> Option<(i32, i32)> {
        let sized = self.sized(font)?;
        Some((
            pixel(i64::from(sized.ascender)),
            -pixel(i64::from(sized.descender)),
        ))
    }

    /// 文を並べた結果（グリフの番号と、26.6 の位置）。Pillow の `text_layout`。
    pub fn layout(&self, text: &str, font: FontSpec) -> Option<Vec<PlacedGlyph>> {
        let sized = self.sized(font)?;
        layout::layout(&sized, text).ok()
    }

    /// `font.getlength(text)` の 64 倍（26.6 の整数）。
    pub fn length_26_6(&self, text: &str, font: FontSpec) -> Option<i64> {
        let glyphs = self.layout(text, font)?;
        Some(glyphs.iter().map(|glyph| i64::from(glyph.x_advance)).sum())
    }

    /// `font.getbbox(text, anchor=…)`（左・上・右・下。1 行ぶん）。
    pub fn bbox(&self, text: &str, font: FontSpec, anchor: Anchor) -> Option<(i32, i32, i32, i32)> {
        let sized = self.sized(font)?;
        let glyphs = layout::layout(&sized, text).ok()?;
        let extent = bounding_box_and_anchors(&sized, anchor, &glyphs)?;
        let (left, top) = (i64::from(extent.x_offset), extent.y_offset);
        Some((
            left as i32,
            top as i32,
            (left + extent.width) as i32,
            (top + extent.height) as i32,
        ))
    }

    /// `font.getmask2(text, "L", anchor=…, start=…)`。1 行ぶんの字の濃さと、描く座標からのずれ。
    ///
    /// `start` は座標の小数の部分（`ImageDraw.text` が `math.modf` で分けて渡すもの）。
    pub fn mask(
        &self,
        text: &str,
        font: FontSpec,
        anchor: Anchor,
        start: (f32, f32),
    ) -> Option<TextMask> {
        let sized = self.sized(font)?;
        let glyphs = layout::layout(&sized, text).ok()?;
        font_render(&sized, anchor, &glyphs, start)
    }

    /// 改行で分けて、行ごとの座標を決める（`ImageText.Text._split`。行揃えは左）。
    ///
    /// 1 行なら座標はそのまま。複数行のときの行送りは「`A` の箱の下端＋4」（Pillow の既定の spacing）。
    fn split<'t>(
        &self,
        xy: (f64, f64),
        text: &'t str,
        font: FontSpec,
        anchor: Anchor,
    ) -> Option<Vec<(f64, f64, &'t str)>> {
        let lines: Vec<&str> = text.split('\n').collect();
        if lines.len() == 1 {
            return Some(vec![(xy.0, xy.1, text)]);
        }
        // 複数行では、絵の上・下に合わせる anchor は使えない（Pillow は ValueError）。
        if matches!(anchor.0[1], b't' | b'b') {
            return None;
        }
        let line_spacing = f64::from(self.bbox("A", font, Anchor(*b"la"))?.3) + 4.0;
        let widths = lines
            .iter()
            .map(|line| {
                self.length_26_6(line, font)
                    .map(|length| length as f64 / 64.0)
            })
            .collect::<Option<Vec<f64>>>()?;
        let max_width = widths.iter().copied().fold(0.0f64, f64::max);
        let mut top = xy.1;
        match anchor.0[1] {
            b'm' => top -= (lines.len() - 1) as f64 * line_spacing / 2.0,
            b'd' => top -= (lines.len() - 1) as f64 * line_spacing,
            _ => {}
        }
        let mut parts = Vec::with_capacity(lines.len());
        for (line, width) in lines.into_iter().zip(widths) {
            let mut left = xy.0;
            let width_difference = max_width - width;
            match anchor.0[0] {
                b'm' => left -= width_difference / 2.0,
                b'r' => left -= width_difference,
                _ => {}
            }
            parts.push((left, top, line));
            top += line_spacing;
        }
        Some(parts)
    }

    /// `draw.textbbox` の値そのもの。座標に小数があれば、Python と同じく小数のまま返す。
    pub fn text_bbox_exact(
        &self,
        xy: (f64, f64),
        text: &str,
        font: FontSpec,
        anchor: Anchor,
    ) -> Option<(f64, f64, f64, f64)> {
        let mut bbox: Option<(f64, f64, f64, f64)> = None;
        for (x, y, line) in self.split(xy, text, font, anchor)? {
            let (left, top, right, bottom) = self.bbox(line, font, anchor)?;
            let line_box = (
                f64::from(left) + x,
                f64::from(top) + y,
                f64::from(right) + x,
                f64::from(bottom) + y,
            );
            bbox = Some(match bbox {
                None => line_box,
                Some(so_far) => (
                    so_far.0.min(line_box.0),
                    so_far.1.min(line_box.1),
                    so_far.2.max(line_box.2),
                    so_far.3.max(line_box.3),
                ),
            });
        }
        bbox
    }
}

impl TextPainter for PillowText {
    /// 改行を含む文は Python では例外（`can't measure length of multiline text`）。ここでは 0。
    fn text_length(&self, text: &str, font: FontSpec) -> f64 {
        self.length_26_6(text, font)
            .map_or(0.0, |length| length as f64 / 64.0)
    }

    /// 座標が整数のときの値（Python の呼び出しは `(0, 0)` だけ）。座標に小数があると Python は小数を返す。
    /// そのときは切り捨てた値になるので、小数まで要るなら [`PillowText::text_bbox_exact`] を使う。
    fn text_bbox(
        &self,
        xy: (f64, f64),
        text: &str,
        font: FontSpec,
        anchor: Anchor,
    ) -> (i32, i32, i32, i32) {
        self.text_bbox_exact(xy, text, font, anchor).map_or(
            (0, 0, 0, 0),
            |(left, top, right, bottom)| {
                (
                    left.floor() as i32,
                    top.floor() as i32,
                    right.floor() as i32,
                    bottom.floor() as i32,
                )
            },
        )
    }

    fn draw_text(
        &self,
        canvas: &mut RgbaImage,
        xy: (f64, f64),
        text: &str,
        font: FontSpec,
        fill: [u8; 4],
        anchor: Anchor,
    ) {
        let Some(lines) = self.split(xy, text, font, anchor) else {
            return;
        };
        for (x, y, line) in lines {
            // `x = int(line.x)`・`start = (math.modf(line.x)[0], …)`。小数は C の float で渡る。
            let start = (x.fract() as f32, y.fract() as f32);
            let Some(mask) = self.mask(line, font, anchor, start) else {
                continue;
            };
            let left = x.trunc() as i64 + i64::from(mask.offset.0);
            let top = y.trunc() as i64 + i64::from(mask.offset.1);
            fill_with_mask(canvas, &mask, left, top, fill);
        }
    }
}

/// 最初に見つかったファイル。
fn first_existing(paths: &[&str]) -> Option<PathBuf> {
    paths
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(Path::to_path_buf)
}

/// 26.6 を、いちばん近い画素へ丸める（`_imagingft.c` の `PIXEL`。半分は切り上げ）。
fn pixel(value: i64) -> i32 {
    (((value + 32) & -64) >> 6) as i32
}

/// 文の大きさと、anchor までのずれ（`bounding_box_and_anchors` の結果）。
struct Extent {
    width: i64,
    height: i64,
    x_offset: i32,
    y_offset: i64,
}

/// `_imagingft.c` の `bounding_box_and_anchors`（横書き）。anchor の字が違えば `None`。
///
/// 文の箱は「1 字ごとの箱」と「ペンが動いた線（0 から送りの合計まで）」を合わせたもの。原点 (0, 0) は
/// 必ず箱に入る。
fn bounding_box_and_anchors(
    face: &SizedFace,
    anchor: Anchor,
    glyphs: &[PlacedGlyph],
) -> Option<Extent> {
    let mut position = 0i64;
    let (mut x_min, mut x_max, mut y_min, mut y_max) = (0i32, 0i32, 0i32, 0i32);
    for placed in glyphs {
        let px = pixel(position + i64::from(placed.x_offset));
        let py = pixel(i64::from(placed.y_offset));
        position += i64::from(placed.x_advance);
        x_max = x_max.max(pixel(position));
        // `FT_Glyph_Get_CBox(glyph, FT_GLYPH_BBOX_PIXELS, &bbox)`
        let (left, bottom, right, top) = face.glyph(placed.index).pixel_box;
        x_max = x_max.max(right + px);
        x_min = x_min.min(left + px);
        y_max = y_max.max(top + py);
        y_min = y_min.min(bottom + py);
    }
    let (mut x_anchor, mut y_anchor) = (0i32, 0i32);
    if !glyphs.is_empty() {
        x_anchor = match anchor.0[0] {
            b'l' => 0,
            b'm' => pixel(position / 2),
            b'r' => pixel(position),
            _ => return None,
        };
        let (ascender, descender) = (i64::from(face.ascender), i64::from(face.descender));
        y_anchor = match anchor.0[1] {
            b'a' => pixel(ascender),
            b't' => y_max,
            b'm' => pixel((ascender + descender) / 2),
            b's' => 0,
            b'b' => y_min,
            b'd' => pixel(descender),
            _ => return None,
        };
    }
    Some(Extent {
        width: i64::from(x_max) - i64::from(x_min),
        height: i64::from(y_max) - i64::from(y_min),
        x_offset: -x_anchor + x_min,
        y_offset: i64::from(y_anchor) - i64::from(y_max),
    })
}

/// `_imagingft.c` の `font_render`（濃さの絵。縁取りなし・色なし）。
fn font_render(
    face: &SizedFace,
    anchor: Anchor,
    glyphs: &[PlacedGlyph],
    start: (f32, f32),
) -> Option<TextMask> {
    let extent = bounding_box_and_anchors(face, anchor, glyphs)?;
    // `width += ceil(stroke_width * 2 + x_start)`（float で足してから切り上げ）。
    let width = (extent.width as f64 + f64::from(0.0f32 * 2.0 + start.0).ceil()) as i64;
    let height = (extent.height as f64 + f64::from(0.0f32 * 2.0 + start.1).ceil()) as i64;
    let offset = (extent.x_offset, extent.y_offset as i32);
    let (width, height) = (width.max(0) as usize, height.max(0) as usize);
    let mut pixels = vec![0u8; width * height];
    if !(glyphs.is_empty() || width == 0 || height == 0) {
        // 1 回目: いちばん左（x_min）といちばん上（y_max）を、絵そのものの位置から求める。
        let (mut x, mut y) = (0i32, 0i32);
        let (mut x_min, mut y_max) = (0i32, 0i32);
        for placed in glyphs {
            let px = pixel(i64::from(x) + i64::from(placed.x_offset));
            let py = pixel(i64::from(y) + i64::from(placed.y_offset));
            let glyph = face.glyph(placed.index);
            y_max = y_max.max(glyph.top() + py);
            x_min = x_min.min(glyph.left() + px);
            x += placed.x_advance;
            y += placed.y_advance;
        }
        // ペンを文の原点へ。座標の小数（start）はここで足す。C の float（32 ビット）の計算のまま。
        let mut x = f64::from((-x_min as f32 + 0.0f32 + start.0) * 64.0f32).round() as i32;
        let mut y = f64::from((-y_max as f32 + -0.0f32 - start.1) * 64.0f32).round() as i32;
        // 2 回目: 1 字ずつ置く。
        for placed in glyphs {
            let px = pixel(i64::from(x) + i64::from(placed.x_offset));
            let py = pixel(i64::from(y) + i64::from(placed.y_offset));
            let glyph = face.glyph(placed.index);
            let source = glyph.pixels();
            let (glyph_width, glyph_rows) = (glyph.width() as i64, glyph.rows() as i64);
            if !source.is_empty() {
                let xx = i64::from(px) + i64::from(glyph.left());
                let first_row = -(i64::from(py) + i64::from(glyph.top()));
                // 絵の幅に切り取る。
                let x0 = if xx < 0 { -xx } else { 0 };
                let x1 = if xx + glyph_width > width as i64 {
                    width as i64 - xx
                } else {
                    glyph_width
                };
                for (row, yy) in (0..glyph_rows).zip(first_row..) {
                    if yy >= 0 && yy < height as i64 {
                        for k in x0..x1 {
                            let src_alpha = u32::from(source[(row * glyph_width + k) as usize]);
                            if src_alpha > 0 {
                                let target = &mut pixels[yy as usize * width + (xx + k) as usize];
                                // 字が重なるところは、濃さを重ねる。
                                *target = if *target > 0 {
                                    (src_alpha + muldiv255(u32::from(*target), 255 - src_alpha))
                                        .min(255) as u8
                                } else {
                                    src_alpha as u8
                                };
                            }
                        }
                    }
                }
            }
            x += placed.x_advance;
            y += placed.y_advance;
        }
    }
    Some(TextMask {
        width: width as u32,
        height: height as u32,
        pixels,
        offset,
    })
}

/// Pillow の `MULDIV255`（a × b ÷ 255 を、割り算なしで四捨五入）。
fn muldiv255(a: u32, b: u32) -> u32 {
    let tmp = a * b + 128;
    ((tmp >> 8) + tmp) >> 8
}

/// Pillow の `BLEND`（mask の割合で in1 から in2 へ混ぜる）。
fn blend(mask: u32, in1: u32, in2: u32) -> u8 {
    let tmp = in1 * (255 - mask) + in2 * mask + 128;
    (((tmp >> 8) + tmp) >> 8) as u8
}

/// 濃さの絵を型にして、色を塗る。`ImagingDrawBitmap` → `ImagingFill2` → `fill_mask_L`（RGBA の画像）。
///
/// 色（RGB）は、下の画素が透明（アルファ 0）なら fill そのものにする。そうでなければ濃さで混ぜる。
/// アルファは濃さで混ぜる。絵が画像からはみ出す分は切り取る。
fn fill_with_mask(canvas: &mut RgbaImage, mask: &TextMask, left: i64, top: i64, ink: [u8; 4]) {
    let (canvas_width, canvas_height) = (i64::from(canvas.width()), i64::from(canvas.height()));
    let (mut dx0, mut dy0) = (left, top);
    let (mut xsize, mut ysize) = (i64::from(mask.width), i64::from(mask.height));
    let (mut sx0, mut sy0) = (0i64, 0i64);
    if dx0 < 0 {
        xsize += dx0;
        sx0 = -dx0;
        dx0 = 0;
    }
    if dx0 + xsize > canvas_width {
        xsize = canvas_width - dx0;
    }
    if dy0 < 0 {
        ysize += dy0;
        sy0 = -dy0;
        dy0 = 0;
    }
    if dy0 + ysize > canvas_height {
        ysize = canvas_height - dy0;
    }
    if xsize <= 0 || ysize <= 0 {
        return;
    }
    let mask_width = mask.width as usize;
    let stride = canvas_width as usize * 4;
    let out: &mut [u8] = canvas;
    for y in 0..ysize as usize {
        let mask_row = &mask.pixels[(y + sy0 as usize) * mask_width + sx0 as usize..];
        let out_row = &mut out[(y + dy0 as usize) * stride + dx0 as usize * 4..];
        for x in 0..xsize as usize {
            let coverage = u32::from(mask_row[x]);
            let pixel = &mut out_row[x * 4..x * 4 + 4];
            // `255 - (255 - mask) * (1 - (255 - out[3]) / 255)`（整数の割り算。下が透明のときだけ 255）。
            let colour_mask = if coverage != 0 && pixel[3] == 0 {
                255
            } else {
                coverage
            };
            for channel in 0..3 {
                pixel[channel] = blend(
                    colour_mask,
                    u32::from(pixel[channel]),
                    u32::from(ink[channel]),
                );
            }
            pixel[3] = blend(coverage, u32::from(pixel[3]), u32::from(ink[3]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PIXEL` は、半分を切り上げ、負の数でも下へ丸めること。
    #[test]
    fn pixel_rounds_half_up() {
        assert_eq!(pixel(0), 0);
        assert_eq!(pixel(31), 0);
        assert_eq!(pixel(32), 1);
        assert_eq!(pixel(95), 1);
        assert_eq!(pixel(96), 2);
        assert_eq!(pixel(-32), 0);
        assert_eq!(pixel(-33), -1);
        assert_eq!(pixel(-96), -1);
        assert_eq!(pixel(-97), -2);
        assert_eq!(pixel(15217), 238);
    }

    /// Pillow の混ぜ方（255 で割る四捨五入）と同じ値になること。
    #[test]
    fn blending_matches_pillow_rounding() {
        assert_eq!(muldiv255(255, 255), 255);
        assert_eq!(muldiv255(128, 128), 64);
        assert_eq!(muldiv255(1, 127), 0);
        assert_eq!(muldiv255(1, 128), 1);
        assert_eq!(blend(0, 10, 200), 10);
        assert_eq!(blend(255, 10, 200), 200);
        assert_eq!(blend(128, 0, 255), 128);
        assert_eq!(blend(127, 255, 0), 128);
        for mask in 0..=255u32 {
            for (a, b) in [(0u32, 255u32), (255, 0), (17, 203), (170, 170)] {
                let exact = ((a * (255 - mask) + b * mask) as f64 / 255.0).round() as u8;
                assert_eq!(blend(mask, a, b), exact, "{mask} {a} {b}");
            }
        }
    }

    /// 濃さ 1 枚ぶんの型（2×2）。
    fn mask_2x2(pixels: [u8; 4]) -> TextMask {
        TextMask {
            width: 2,
            height: 2,
            pixels: pixels.to_vec(),
            offset: (0, 0),
        }
    }

    /// 透明な画像に塗ると、色は fill そのもの・アルファは濃さに応じた値になること（濃さ 0 は触らない）。
    #[test]
    fn filling_a_transparent_canvas_keeps_the_ink_colour() {
        let mut canvas = RgbaImage::new(2, 2);
        fill_with_mask(
            &mut canvas,
            &mask_2x2([0, 128, 255, 1]),
            0,
            0,
            [16, 20, 26, 170],
        );
        assert_eq!(canvas.get_pixel(0, 0).0, [0, 0, 0, 0]);
        assert_eq!(canvas.get_pixel(1, 0).0, [16, 20, 26, 85]);
        assert_eq!(canvas.get_pixel(0, 1).0, [16, 20, 26, 170]);
        assert_eq!(canvas.get_pixel(1, 1).0, [16, 20, 26, 1]);
    }

    /// 色のある画像に塗ると、色もアルファも濃さで混ざること。
    #[test]
    fn filling_an_opaque_canvas_blends_by_coverage() {
        let mut canvas = RgbaImage::from_pixel(2, 2, image::Rgba([200, 100, 0, 255]));
        fill_with_mask(
            &mut canvas,
            &mask_2x2([0, 128, 255, 64]),
            0,
            0,
            [0, 0, 255, 255],
        );
        assert_eq!(canvas.get_pixel(0, 0).0, [200, 100, 0, 255]);
        assert_eq!(canvas.get_pixel(1, 0).0, [100, 50, 128, 255]);
        assert_eq!(canvas.get_pixel(0, 1).0, [0, 0, 255, 255]);
        assert_eq!(canvas.get_pixel(1, 1).0, [150, 75, 64, 255]);
        // 半透明の下地（アルファ 1 以上）は、透明の扱いにならない。
        let mut canvas = RgbaImage::from_pixel(1, 1, image::Rgba([200, 100, 0, 1]));
        let dot = TextMask {
            width: 1,
            height: 1,
            pixels: vec![128],
            offset: (0, 0),
        };
        fill_with_mask(&mut canvas, &dot, 0, 0, [0, 0, 255, 255]);
        assert_eq!(canvas.get_pixel(0, 0).0, [100, 50, 128, 128]);
    }

    /// 画像からはみ出す分は切り取ること（左上・右下・完全に外）。
    #[test]
    fn filling_clips_to_the_canvas() {
        let ink = [9, 9, 9, 255];
        let mut canvas = RgbaImage::new(2, 2);
        fill_with_mask(&mut canvas, &mask_2x2([10, 20, 30, 40]), -1, -1, ink);
        assert_eq!(canvas.get_pixel(0, 0).0, [9, 9, 9, 40]);
        assert_eq!(canvas.get_pixel(1, 0).0, [0, 0, 0, 0]);
        let mut canvas = RgbaImage::new(2, 2);
        fill_with_mask(&mut canvas, &mask_2x2([10, 20, 30, 40]), 1, 1, ink);
        assert_eq!(canvas.get_pixel(1, 1).0, [9, 9, 9, 10]);
        assert_eq!(canvas.get_pixel(0, 1).0, [0, 0, 0, 0]);
        for (left, top) in [(-2, 0), (0, -2), (2, 0), (0, 2), (-9, -9), (9, 9)] {
            let mut canvas = RgbaImage::new(2, 2);
            fill_with_mask(&mut canvas, &mask_2x2([255; 4]), left, top, ink);
            assert!(canvas.pixels().all(|p| p.0 == [0, 0, 0, 0]), "{left} {top}");
        }
    }

    /// フォントが無いときは、探した場所を添えて誤りにすること。
    #[test]
    fn missing_fonts_are_reported_with_the_paths_tried() {
        let missing = Path::new("/nonexistent/b7t/NotoSansCJK-Bold.ttc");
        let error = PillowText::from_files(None, Some(missing)).err().unwrap();
        assert!(matches!(error, FontError::Unreadable(..)), "{error}");
        assert!(
            error
                .to_string()
                .contains("/nonexistent/b7t/NotoSansCJK-Bold.ttc")
        );
        let error = FontError::NotFound(vec!["/a".into(), "/b".into()]);
        assert!(error.to_string().contains("fonts-noto-cjk"));
        assert!(error.to_string().contains("/a、/b"));
        assert_eq!(
            first_existing(&["/nonexistent/b7t/x", "/nonexistent/b7t/y"]),
            None
        );
    }

    /// 描き手は、別のスレッド（`spawn_blocking`）へ渡せて、`&dyn TextPainter` としても使えること
    /// （地図の側は `T: TextPainter + Send + 'static` と `&dyn TextPainter` で受け取る）。
    #[test]
    fn the_painter_can_move_between_threads() {
        fn sendable<T: TextPainter + Send + Sync + 'static>() {}
        sendable::<PillowText>();
        let painter = PillowText::from_files(None, None).unwrap();
        let as_dyn: &dyn TextPainter = &painter;
        let font = FontSpec {
            size: 26,
            bold: false,
        };
        assert_eq!(as_dyn.text_length("地図", font), 0.0);
    }

    /// 読んでいない太さ・大きさ 0 では、何も描かず、長さ 0・箱 0 を返すこと（落ちない）。
    #[test]
    fn an_unloaded_weight_draws_nothing() {
        let painter = PillowText::from_files(None, None).unwrap();
        let font = FontSpec {
            size: 20,
            bold: true,
        };
        assert_eq!(painter.text_length("震度", font), 0.0);
        assert_eq!(
            painter.text_bbox((3.0, 4.0), "震度", font, Anchor(*b"ls")),
            (0, 0, 0, 0)
        );
        let mut canvas = RgbaImage::new(4, 4);
        painter.draw_text(
            &mut canvas,
            (0.0, 0.0),
            "震度",
            font,
            [255; 4],
            Anchor(*b"la"),
        );
        assert!(canvas.pixels().all(|p| p.0 == [0, 0, 0, 0]));
        assert!(painter.glyph_index(font, 'A').is_none());
        assert!(painter.metrics(font).is_none());
    }
}
