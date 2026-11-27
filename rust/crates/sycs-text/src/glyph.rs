//! 1 文字の形と濃さ。FreeType の `FT_New_Face`・`FT_Request_Size`・`FT_Load_Glyph`・`FT_Render_Glyph` にあたるところ。
//!
//! - 輪郭とヒンティングは `skrifa`（Google の Fontations）。Noto Sans CJK は CFF の輪郭で、FreeType は Adobe の
//!   CFF エンジン（`src/psaux/`）でヒンティングする。skrifa にはその写しがあり、26.6 の固定小数まで同じ点を返す
//!   （Pillow が同梱する FreeType 2.14.3 を直に呼んだ結果と、2 つの太さ・150 通りの大きさ・のべ 23 万字あまりで
//!   突き合わせた）。違うのは 1 つだけ: ヒンティングで長さ 0 になった線（同じ点が続くところ）を、FreeType は残し、
//!   skrifa は捨てる。長さ 0 の線は塗りにも外接箱にも効かないので、絵は同じになる。
//! - 受け取った点は、FreeType の `FT_Outline` と同じ形に積み直す（[`OutlineBuilder`]。`ps_builder_close_contour` の
//!   決まり）。外接箱（`FT_Outline_Get_CBox`）が同じになるように。
//! - 絵の位置と大きさは `ft_glyphslot_preset_bitmap`（`src/base/ftobjs.c`）、塗りは [`ftgrays`](super::ftgrays)。
//! - 大きさごとの目盛り（`x_scale`・上端・下端）は `FT_Request_Metrics`、送り幅は `FT_Get_Advance`。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use skrifa::{DrawMemory, Font, GlyphId, HintOptions, PathSink, ScalerFont};

use super::ftgrays::{self, Outline, TAG_CONIC, TAG_CUBIC, TAG_ON};

/// 1 文字のビットマップ（FreeType の `bitmap`・`bitmap_left`・`bitmap_top`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlyphBitmap {
    /// 字の原点から、絵の左端までの画素数（右が正）。
    pub left: i32,
    /// 字の原点（ベースライン）から、絵の上端までの画素数（上が正）。
    pub top: i32,
    /// 幅。
    pub width: u32,
    /// 高さ。
    pub rows: u32,
    /// 濃さ（0〜255）。上の行が先。
    pub pixels: Vec<u8>,
}

/// 読み込んだ 1 文字（`FT_Load_Glyph` の結果）。
pub struct Glyph {
    /// ヒンティング済みの輪郭（26.6）。
    pub outline: Outline,
    /// 画素にそろえた外接箱（左・下・右・上。`FT_Glyph_Get_CBox(…, FT_GLYPH_BBOX_PIXELS)`）。
    pub pixel_box: (i32, i32, i32, i32),
    /// 塗った結果（使うときに 1 度だけ塗る）。
    bitmap: OnceLock<Vec<u8>>,
}

impl Glyph {
    /// 輪郭から作る。
    fn new(outline: Outline) -> Self {
        let pixel_box = pixel_box(&outline);
        Self {
            outline,
            pixel_box,
            bitmap: OnceLock::new(),
        }
    }

    /// 絵の左端（`bitmap_left`）。
    pub fn left(&self) -> i32 {
        self.pixel_box.0
    }

    /// 絵の上端（`bitmap_top`）。
    pub fn top(&self) -> i32 {
        self.pixel_box.3
    }

    /// 絵の幅。
    pub fn width(&self) -> usize {
        (self.pixel_box.2 - self.pixel_box.0) as usize
    }

    /// 絵の高さ。
    pub fn rows(&self) -> usize {
        (self.pixel_box.3 - self.pixel_box.1) as usize
    }

    /// 濃さ（上の行が先）。`ft_smooth_render` と同じく、絵の左下が原点になるよう輪郭をずらしてから塗る。
    pub fn pixels(&self) -> &[u8] {
        self.bitmap.get_or_init(|| {
            let (width, rows) = (self.width(), self.rows());
            if width == 0 || rows == 0 {
                return Vec::new();
            }
            let x_shift = -64 * self.left();
            let y_shift = -64 * self.top() + 64 * rows as i32;
            let mut shifted = self.outline.clone();
            for point in &mut shifted.points {
                point.0 += x_shift;
                point.1 += y_shift;
            }
            ftgrays::render(&shifted, width, rows)
        })
    }

    /// 位置・大きさ・濃さをまとめて返す。
    pub fn bitmap(&self) -> GlyphBitmap {
        GlyphBitmap {
            left: self.left(),
            top: self.top(),
            width: self.width() as u32,
            rows: self.rows() as u32,
            pixels: self.pixels().to_vec(),
        }
    }
}

/// 外接箱（`FT_Outline_Get_CBox`。制御点も含めた箱）。点が無ければ全部 0。
pub fn control_box(outline: &Outline) -> (i32, i32, i32, i32) {
    let Some(&(x, y)) = outline.points.first() else {
        return (0, 0, 0, 0);
    };
    let mut cbox = (x, y, x, y);
    for &(x, y) in &outline.points[1..] {
        cbox.0 = cbox.0.min(x);
        cbox.1 = cbox.1.min(y);
        cbox.2 = cbox.2.max(x);
        cbox.3 = cbox.3.max(y);
    }
    cbox
}

/// 外接箱を画素にそろえる（左と下は切り捨て、右と上は切り上げ）。`ft_glyphslot_preset_bitmap` の
/// `FT_RENDER_MODE_NORMAL` の枝と、`FT_Glyph_Get_CBox` の `FT_GLYPH_BBOX_PIXELS` は同じ値になる。
fn pixel_box(outline: &Outline) -> (i32, i32, i32, i32) {
    let (x_min, y_min, x_max, y_max) = control_box(outline);
    (x_min >> 6, y_min >> 6, (x_max + 63) >> 6, (y_max + 63) >> 6)
}

/// skrifa が出す「移動・線・曲線」を、FreeType の `FT_Outline` と同じ形に積む。
///
/// FreeType の CFF の読み込み（`cf2_builder_moveTo`・`ps_builder_close_contour`）と同じ決まり:
/// 輪郭の最後の点が最初の点と同じ場所で「輪郭の上の点」なら捨てる。1 点しか残らない輪郭は捨てる。
#[derive(Default)]
struct OutlineBuilder {
    outline: Outline,
    /// いま積んでいる輪郭の、最初の点の番号。
    first: usize,
    /// 輪郭を積んでいる途中か。
    open: bool,
}

impl OutlineBuilder {
    /// 点を 1 つ積む。skrifa の座標は 1/64 の倍数ちょうど（26.6 を float にしたもの）。
    fn push(&mut self, x: f32, y: f32, tag: u8) {
        let fixed = |v: f32| (f64::from(v) * 64.0).round() as i32;
        self.outline.points.push((fixed(x), fixed(y)));
        self.outline.tags.push(tag);
    }

    /// `ps_builder_close_contour`。
    fn close_contour(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        let outline = &mut self.outline;
        let first = self.first;
        if first == outline.points.len() {
            return;
        }
        // 最後の点が最初の点に重なっていたら、最後の点は入れない。
        if outline.points.len() > 1 {
            let last = outline.points.len() - 1;
            if outline.points[first] == outline.points[last] && outline.tags[last] == TAG_ON {
                outline.points.pop();
                outline.tags.pop();
            }
        }
        if first + 1 == outline.points.len() {
            // 1 点だけの輪郭は入れない。
            outline.points.pop();
            outline.tags.pop();
        } else if first < outline.points.len() {
            outline.contours.push(outline.points.len() - 1);
        }
    }
}

impl PathSink for OutlineBuilder {
    fn move_to(&mut self, x: f32, y: f32) {
        self.close_contour();
        self.first = self.outline.points.len();
        self.open = true;
        self.push(x, y, TAG_ON);
    }

    fn line_to(&mut self, x: f32, y: f32) {
        self.push(x, y, TAG_ON);
    }

    fn quad_to(&mut self, cx0: f32, cy0: f32, x: f32, y: f32) {
        self.push(cx0, cy0, TAG_CONIC);
        self.push(x, y, TAG_ON);
    }

    fn curve_to(&mut self, cx0: f32, cy0: f32, cx1: f32, cy1: f32, x: f32, y: f32) {
        self.push(cx0, cy0, TAG_CUBIC);
        self.push(cx1, cy1, TAG_CUBIC);
        self.push(x, y, TAG_ON);
    }

    fn close(&mut self) {
        self.close_contour();
    }
}

/// `FT_DivFix`（16.16 の割り算。四捨五入）。
fn div_fix(a: i64, b: i64) -> i64 {
    if b == 0 {
        return 0x7FFF_FFFF;
    }
    let sign = if (a < 0) != (b < 0) { -1 } else { 1 };
    let (a, b) = (a.abs(), b.abs());
    sign * (((a << 16) + (b >> 1)) / b)
}

/// `FT_MulFix`（16.16 の掛け算。四捨五入）。
fn mul_fix(a: i64, b: i64) -> i64 {
    let ab = a * b;
    (ab + 0x8000 - i64::from(ab < 0)) >> 16
}

/// `FT_MulDiv`（a × b ÷ c。四捨五入）。
fn mul_div(a: i64, b: i64, c: i64) -> i64 {
    if c == 0 {
        return 0x7FFF_FFFF;
    }
    let sign = if ((a < 0) != (b < 0)) != (c < 0) {
        -1
    } else {
        1
    };
    let (a, b, c) = (a.abs(), b.abs(), c.abs());
    sign * ((a * b + (c >> 1)) / c)
}

/// 1 つのフォント（`FT_Face`）。面の番号は 0（Pillow の `ImageFont.truetype(path, size)` の既定）。
pub struct Face {
    /// 読み込んだフォント。
    font: Font,
    /// 1 em の目盛り（`units_per_EM`）。
    units_per_em: i64,
    /// 上端・下端（フォントの目盛り。`face->ascender`・`face->descender`）。
    ascender: i64,
    descender: i64,
    /// 大きさごとの覚え。
    sizes: Mutex<HashMap<u32, Arc<SizedFace>>>,
}

impl Face {
    /// フォントのバイト列から作る。読めなければ `None`。
    pub fn new(data: Vec<u8>) -> Option<Self> {
        let font = Font::new(data, 0)?;
        let units_per_em = i64::from(font.units_per_em());
        if units_per_em == 0 {
            return None;
        }
        // FreeType の `sfnt_load_face` と同じ選び方（OS/2 が USE_TYPO_METRICS なら sTypo、でなければ hhea、
        // hhea が 0 なら sTypo、それも 0 なら usWin）。`Metrics::h_line` が同じ順で選ぶ。
        let line = font.metrics().h_line();
        let whole = |v: skrifa::raw::types::F48Dot16| v.to_bits() >> 16;
        let (ascender, descender) =
            line.map_or((0, 0), |line| (whole(line.ascender), whole(line.descender)));
        Some(Self {
            font,
            units_per_em,
            ascender,
            descender,
            sizes: Mutex::new(HashMap::new()),
        })
    }

    /// 読み込んだフォント（並べるときに使う）。
    pub fn font(&self) -> &Font {
        &self.font
    }

    /// 1 em の目盛り。
    pub fn units_per_em(&self) -> i64 {
        self.units_per_em
    }

    /// 大きさを決めた面（`FT_Request_Size`）。同じ大きさは使い回す。
    pub fn sized(&self, size: u32) -> Arc<SizedFace> {
        let mut sizes = self.sizes.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            sizes
                .entry(size)
                .or_insert_with(|| Arc::new(SizedFace::new(self, size))),
        )
    }
}

/// 大きさを決めた面（`FT_Size`）。
pub struct SizedFace {
    /// ヒンティングつきで輪郭を出す口。
    scaler: ScalerFont,
    /// フォントの目盛り → 26.6 の倍率（16.16。`metrics.x_scale`。縦も同じ値）。
    pub x_scale: i64,
    /// 上端（26.6。画素に切り上げ済み。`metrics.ascender`）。
    pub ascender: i32,
    /// 下端（26.6。画素に切り下げ済み。負の値。`metrics.descender`）。
    pub descender: i32,
    /// 1 em の目盛り。
    units_per_em: i64,
    /// 読んだ文字の覚え（グリフ番号 → 形）。
    glyphs: Mutex<HashMap<u32, Arc<Glyph>>>,
}

impl SizedFace {
    /// `FT_Request_Size`（`FT_SIZE_REQUEST_TYPE_NOMINAL`、幅も高さも `size * 64`）と `ft_recompute_scaled_metrics`。
    fn new(face: &Face, size: u32) -> Self {
        let x_scale = div_fix(i64::from(size) * 64, face.units_per_em);
        let ascender = (mul_fix(face.ascender, x_scale) + 63) & !63;
        let descender = mul_fix(face.descender, x_scale) & !63;
        // FreeType は、CFF のフォントを自前のエンジンでヒンティングする（`FT_LOAD_DEFAULT`＝
        // `FT_LOAD_TARGET_NORMAL`）。skrifa の `interpreter` がそれにあたる。
        let scaler = ScalerFont::hinted(face.font.clone(), size as f32, HintOptions::interpreter());
        Self {
            scaler,
            x_scale,
            ascender: ascender as i32,
            descender: descender as i32,
            units_per_em: face.units_per_em,
            glyphs: Mutex::new(HashMap::new()),
        }
    }

    /// 1 文字を読む（`FT_Load_Glyph(face, glyph, FT_LOAD_DEFAULT)`）。同じ文字は使い回す。
    ///
    /// 輪郭が取れない番号（フォントに無い番号）は、空の字として返す。
    pub fn glyph(&self, glyph: u32) -> Arc<Glyph> {
        if let Some(found) = self
            .glyphs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&glyph)
        {
            return Arc::clone(found);
        }
        let mut builder = OutlineBuilder::default();
        let drawn = self
            .scaler
            .outline(GlyphId::new(glyph))
            .is_some_and(|outline| outline.draw(DrawMemory::Scratch, &mut builder).is_ok());
        builder.close_contour();
        let outline = if drawn {
            builder.outline
        } else {
            Outline::default()
        };
        let loaded = Arc::new(Glyph::new(outline));
        self.glyphs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(glyph, Arc::clone(&loaded));
        loaded
    }

    /// ヒンティングなしの送り幅（16.16）。`FT_Get_Advance(face, glyph, FT_LOAD_NO_HINTING)`:
    /// `hmtx` の値に `x_scale` を掛けて 64 で割る（`ft_face_scale_advances_`）。
    pub fn linear_advance(&self, glyph: u32) -> i64 {
        let font = self.scaler.font();
        let units = font
            .glyph_metrics()
            .h_advance_exact(GlyphId::new(glyph))
            .to_bits()
            >> 16;
        mul_div(units, self.x_scale, 64)
    }

    /// HarfBuzz（hb-ft）が使う倍率: 1 em が何目盛りか（26.6）。`hb_ft_font_changed`。
    pub fn shaping_scale(&self) -> i32 {
        (((self.x_scale as u64) * (self.units_per_em as u64) + (1 << 15)) >> 16) as i32
    }

    /// 読み込んだフォント。
    pub fn font(&self) -> &Font {
        self.scaler.font()
    }

    /// ヒンティングが効いているか（CFF なら PostScript のエンジン）。確認用。
    pub fn is_hinted(&self) -> bool {
        self.scaler.is_hinted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定小数の計算が FreeType と同じ丸めになること（403 px・1000 目盛りの実際の値で）。
    #[test]
    fn fixed_point_helpers_round_like_freetype() {
        // x_scale = FT_DivFix(403 * 64, 1000)。Python（FreeType）が返した値。
        assert_eq!(div_fix(403 * 64, 1000), 1_690_305);
        assert_eq!(div_fix(128 * 64, 1000), 536_871);
        // 上端 1160・下端 -288（Noto Sans CJK の hhea）→ 128 px で 149 px・-37 px。
        assert_eq!((mul_fix(1160, 536_871) + 63) & !63, 9536);
        assert_eq!(mul_fix(-288, 536_871) & !63, -2368);
        // 半分ちょうどは 0 から遠い方へ。
        assert_eq!(mul_fix(1, 0x8000), 1);
        assert_eq!(mul_fix(-1, 0x8000), -1);
        assert_eq!(mul_div(590, 1_690_305, 64), 15_582_499);
        assert_eq!(mul_div(-590, 1_690_305, 64), -15_582_499);
        assert_eq!(div_fix(-64, 1000), -4194);
        assert_eq!(div_fix(1, 0), 0x7FFF_FFFF);
        assert_eq!(mul_div(1, 1, 0), 0x7FFF_FFFF);
    }

    /// 輪郭を積む決まり: 最初の点に戻った最後の点は捨てる。1 点だけの輪郭は捨てる。
    #[test]
    fn the_builder_follows_freetype_contour_rules() {
        let mut builder = OutlineBuilder::default();
        builder.move_to(0.0, 0.0);
        builder.line_to(1.0, 0.0);
        builder.line_to(1.0, 1.5);
        builder.line_to(0.0, 0.0);
        builder.close();
        // 1 点だけ（移動して、同じ場所への線）。
        builder.move_to(5.0, 5.0);
        builder.line_to(5.0, 5.0);
        builder.close();
        // 曲線で終わる輪郭（最後の点は最初と同じ → 捨てる）。
        builder.move_to(2.0, 2.0);
        builder.curve_to(3.0, 2.0, 3.0, 3.0, 2.5, 3.0);
        builder.quad_to(2.0, 3.0, 2.0, 2.0);
        builder.close_contour();
        let outline = builder.outline;
        assert_eq!(
            outline.points,
            vec![
                (0, 0),
                (64, 0),
                (64, 96),
                (128, 128),
                (192, 128),
                (192, 192),
                (160, 192),
                (128, 192)
            ]
        );
        assert_eq!(
            outline.tags,
            vec![
                TAG_ON, TAG_ON, TAG_ON, TAG_ON, TAG_CUBIC, TAG_CUBIC, TAG_ON, TAG_CONIC
            ]
        );
        assert_eq!(outline.contours, vec![2, 7]);
        assert_eq!(control_box(&outline), (0, 0, 192, 192));
    }

    /// 外接箱を画素にそろえる向き（左下は切り捨て、右上は切り上げ。負の座標でも）。
    #[test]
    fn the_pixel_box_rounds_outward() {
        let outline = Outline {
            points: vec![(-65, -1), (130, 64), (0, 200)],
            tags: vec![TAG_ON; 3],
            contours: vec![2],
        };
        let glyph = Glyph::new(outline);
        assert_eq!(glyph.pixel_box, (-2, -1, 3, 4));
        assert_eq!((glyph.left(), glyph.top()), (-2, 4));
        assert_eq!((glyph.width(), glyph.rows()), (5, 5));
        assert_eq!(glyph.pixels().len(), 25);
        // 点の無い字（空白）は大きさ 0。
        let empty = Glyph::new(Outline::default());
        assert_eq!(empty.pixel_box, (0, 0, 0, 0));
        assert!(empty.pixels().is_empty());
        assert_eq!(empty.bitmap().width, 0);
    }
}
