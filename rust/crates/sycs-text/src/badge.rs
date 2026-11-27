//! 最大震度の札（Embed のサムネイル）。Python の `_generate_badge` を、Rust だけで同じ画素に描く。
//!
//! 札は「超楕円の輪郭・上を明るくした地の色・上の縁の光と下の縁の影」の上に、小さな見出し（最大震度）と
//! 大きな数字（と「弱」「強」）を置いたもの。3 倍の大きさ（720×720）で描いてから 240×240 に縮める。
//!
//! Python は numpy（float32）と Pillow で描いている。同じ画素にするために、計算の型と順をそのまま写してある:
//!
//! - 輪郭・地・縁（`_squircle`・`_badge_ground`・`_badge_rim`）: float32 の計算（Python の数〔float64〕は、
//!   float32 の配列と計算するときに float32 になる）。uint8 への変換は切り捨て。
//! - 重ね合わせ（`Image.alpha_composite`）と縮小（`Image.resize(…, LANCZOS)`）: Pillow の整数の式。
//! - 文字（`_draw_tracked`・`_draw_intensity`）: [`TextPainter`]（Pillow と同じ描き方）。置く座標は float64 の
//!   計算で、Python と同じ式・同じ順。
//!
//! 9 枚（震度 1〜7）とも、本物の Python の出力と全画素が同じことを `tests/golden.rs` が確かめる。
//!
//! # Python と違うところ
//!
//! - フォント（`fonts-noto-cjk`）が無いとき、Python は Pillow の内蔵フォントで欧文の札（MAX INTENSITY）を作る。
//!   ここでは札を作らない（Bot は警告を出して、札なしで通知する）。本番のイメージにはフォントを入れてある。
//! - PNG の詰め方は Pillow と違う（画素は同じ。ファイルのバイト列は同じにならない）。

use image::{ImageEncoder, RgbaImage};

use super::{Anchor, FontSpec, PillowText, TextPainter};

/// 描くときの倍率（Python の `ss`）。3 倍で描いてから縮めると、字間も中央合わせも 1/3 画素まで詰められる。
const SS: u32 = 3;
/// できあがりの一辺（Python の `size`）。
pub const BADGE_SIZE: u32 = 240;

/// 角の大きさ。辺の半分に対する割合（Python の `_SQUIRCLE_R`）。
const SQUIRCLE_R: f64 = 0.45;
/// 角の曲がり方。2 でただの円弧、上げるほど直線からなだらかに入る（Python の `_SQUIRCLE_P`）。
const SQUIRCLE_P: f64 = 4.2;

/// 札に置く「数字」と「添え字」。知らない震度は `None`（Python の `_badge_glyphs`。和字が出せる場合）。
pub fn badge_glyphs(scale: i64) -> Option<(&'static str, &'static str)> {
    Some(match scale {
        10 => ("1", ""),
        20 => ("2", ""),
        30 => ("3", ""),
        40 => ("4", ""),
        45 => ("5", "弱"),
        50 => ("5", "強"),
        55 => ("6", "弱"),
        60 => ("6", "強"),
        70 => ("7", ""),
        _ => return None,
    })
}

/// 震度ごとの地の色（Python の `_MAP_FILL_RGB`）。
pub fn fill_rgb(scale: i64) -> [u8; 3] {
    match scale {
        10 => [58, 122, 216],
        20 => [46, 158, 214],
        30 => [44, 176, 154],
        40 => [226, 192, 62],
        45 => [232, 152, 48],
        50 => [233, 119, 43],
        55 => [226, 78, 44],
        60 => [206, 47, 62],
        70 => [132, 44, 128],
        _ => [120, 130, 150],
    }
}

/// その色の上に置く文字の色。明るい震度では白が沈む（Python の `_ink_for`）。
pub fn ink_for(rgb: [u8; 3]) -> [u8; 3] {
    let luma = 0.2126 * f64::from(rgb[0]) + 0.7152 * f64::from(rgb[1]) + 0.0722 * f64::from(rgb[2]);
    if luma > 150.0 {
        [16, 20, 26]
    } else {
        [255, 255, 255]
    }
}

/// `numpy.linspace(start, stop, n, dtype=float32)`。float64 で計算してから float32 に落とす。
fn linspace(start: f64, stop: f64, n: usize) -> Vec<f32> {
    let step = (stop - start) / (n - 1) as f64;
    (0..n)
        .map(|i| {
            if i == n - 1 {
                stop
            } else {
                i as f64 * step + start
            }
        })
        .map(|v| v as f32)
        .collect()
}

/// 札の抜き型（0.0〜1.0 の濃さ、行ごとの並び）。Python の `_squircle`。
///
/// 辺はまっすぐ保ったまま、角だけを超楕円でつなぐ。`inset` は内側へ縮める画素数。
fn squircle(w: usize, h: usize, inset: f32) -> Vec<f32> {
    let xs: Vec<f32> = linspace(-1.0, 1.0, w).into_iter().map(f32::abs).collect();
    let ys: Vec<f32> = linspace(-1.0, 1.0, h).into_iter().map(f32::abs).collect();
    let corner = (1.0 - SQUIRCLE_R) as f32;
    let p = SQUIRCLE_P as f32;
    let inv_p = (1.0 / SQUIRCLE_P) as f32;
    let r = SQUIRCLE_R as f32;
    let px = (2.0 / w as f64) as f32;
    let mut out = Vec::with_capacity(w * h);
    for y in &ys {
        let qy = (y - corner).max(0.0);
        for x in &xs {
            let qx = (x - corner).max(0.0);
            let dist = (qx.powf(p) + qy.powf(p)).powf(inv_p) - r;
            out.push((-dist / px - inset + 0.5).clamp(0.0, 1.0));
        }
    }
    out
}

/// 文字を置く前の札（地・抜き型・縁を重ねたところ）。Python の `_generate_badge` の前半。
pub fn badge_base(w: u32, h: u32, rgb: [u8; 3]) -> RgbaImage {
    let (width, height) = (w as usize, h as usize);
    let mask = squircle(width, height, 0.0);
    // 地（`_badge_ground`）: 上から下へ、ごくわずかに沈ませる。抜き型をアルファにする（`putalpha`）。
    let ramp: Vec<f32> = linspace(0.0, 1.0, height)
        .into_iter()
        .map(|t| 1.09f32 - 0.23f32 * t)
        .collect();
    let mut img = RgbaImage::new(w, h);
    for (y, row) in img.rows_mut().enumerate() {
        for (x, pixel) in row.enumerate() {
            for (channel, value) in pixel.0.iter_mut().zip(rgb) {
                *channel = (f32::from(value) * ramp[y]).clamp(0.0, 255.0) as u8;
            }
            pixel.0[3] = (mask[y * width + x] * 255.0) as u8;
        }
    }
    // 縁（`_badge_rim`）: 4 画素内側へ縮めた型との差が縁。上の縁を明るく、下の縁を暗く。
    let inner = squircle(width, height, 4.0);
    let ys = linspace(0.0, 1.0, height);
    let mut rim = RgbaImage::new(w, h);
    for (y, row) in rim.rows_mut().enumerate() {
        let up = (1.0f32 - ys[y] / 0.55f32).clamp(0.0, 1.0).powf(1.6f32);
        let down = ((ys[y] - 0.45f32) / 0.55f32).clamp(0.0, 1.0).powf(1.6f32);
        for (x, pixel) in row.enumerate() {
            let edge = (mask[y * width + x] - inner[y * width + x]).clamp(0.0, 1.0);
            let light = edge * up * 112.0f32;
            let shade = edge * down * 80.0f32;
            // 上半分は白、下半分は黒。境目のあたりはどちらも 0 なので色は効かない。
            let colour = if light >= shade { 255 } else { 0 };
            pixel.0 = [colour, colour, colour, (light + shade) as u8];
        }
    }
    alpha_composite(&mut img, &rim);
    img
}

/// Pillow の `Image.alpha_composite`（`dst` の上に `src` を重ねる。整数の式）。同じ大きさであること。
pub fn alpha_composite(dst: &mut RgbaImage, src: &RgbaImage) {
    const BITS: u32 = 7;
    let div255 = |a: u32| ((a >> 8) + a) >> 8;
    for (d, s) in dst.pixels_mut().zip(src.pixels()) {
        let (sa, da) = (u32::from(s.0[3]), u32::from(d.0[3]));
        if sa == 0 {
            continue;
        }
        let blend = da * (255 - sa);
        let outa255 = sa * 255 + blend;
        let coef1 = sa * 255 * 255 * (1 << BITS) / outa255;
        let coef2 = 255 * (1 << BITS) - coef1;
        for (out, under) in d.0.iter_mut().zip(s.0).take(3) {
            let tmp = u32::from(under) * coef1 + u32::from(*out) * coef2;
            *out = (div255(tmp + (0x80 << BITS)) >> BITS) as u8;
        }
        d.0[3] = div255(outa255 + 0x80) as u8;
    }
}

/// Pillow の縮小の係数（`precompute_coeffs` と `normalize_coeffs_8bpc`、LANCZOS）。
///
/// 返すのは、1 画素あたりの係数の数・画素ごとの（読み始め、読む数）・係数（22 ビットの固定小数）。
fn lanczos_coefficients(in_size: usize, out_size: usize) -> (usize, Vec<(usize, usize)>, Vec<i32>) {
    const PRECISION_BITS: u32 = 32 - 8 - 2;
    let sinc = |x: f64| {
        if x == 0.0 {
            1.0
        } else {
            let x = x * std::f64::consts::PI;
            x.sin() / x
        }
    };
    let lanczos = |x: f64| {
        if (-3.0..3.0).contains(&x) {
            sinc(x) * sinc(x / 3.0)
        } else {
            0.0
        }
    };
    let scale = in_size as f64 / out_size as f64;
    let filterscale = scale.max(1.0);
    let support = 3.0 * filterscale;
    let ksize = support.ceil() as usize * 2 + 1;
    let mut bounds = Vec::with_capacity(out_size);
    let mut kk = vec![0i32; out_size * ksize];
    for xx in 0..out_size {
        let center = (xx as f64 + 0.5) * scale;
        let ss = 1.0 / filterscale;
        let xmin = ((center - support + 0.5) as i64).max(0) as usize;
        let xmax = ((center + support + 0.5) as i64).min(in_size as i64) as usize - xmin;
        let mut k: Vec<f64> = (0..xmax)
            .map(|x| lanczos((x as f64 + xmin as f64 - center + 0.5) * ss))
            .collect();
        let ww: f64 = k.iter().sum();
        if ww != 0.0 {
            for v in &mut k {
                *v /= ww;
            }
        }
        for (slot, v) in kk[xx * ksize..].iter_mut().zip(&k) {
            let scaled = v * f64::from(1u32 << PRECISION_BITS);
            *slot = if *v < 0.0 {
                (-0.5 + scaled) as i32
            } else {
                (0.5 + scaled) as i32
            };
        }
        bounds.push((xmin, xmax));
    }
    (ksize, bounds, kk)
}

/// 22 ビットの固定小数を 8 ビットへ（Pillow の `clip8`）。
fn clip8(v: i32) -> u8 {
    (v >> 22).clamp(0, 255) as u8
}

/// Pillow の `Image.resize((ow, oh), Image.LANCZOS)`（RGBA。先にアルファを掛け、縮めてから戻す）。
pub fn resize_lanczos(src: &RgbaImage, ow: u32, oh: u32) -> RgbaImage {
    let (w, h) = (src.width() as usize, src.height() as usize);
    let (ow, oh) = (ow as usize, oh as usize);
    // RGBA → RGBa（色にアルファを掛ける）
    let muldiv = |a: u8, b: u8| {
        let tmp = u32::from(a) * u32::from(b) + 128;
        (((tmp >> 8) + tmp) >> 8) as u8
    };
    let mut pre = src.as_raw().clone();
    for p in pre.as_chunks_mut::<4>().0 {
        let alpha = p[3];
        for channel in &mut p[..3] {
            *channel = muldiv(*channel, alpha);
        }
    }
    let (kh, bh, kkh) = lanczos_coefficients(w, ow);
    let (kv, bv, kkv) = lanczos_coefficients(h, oh);
    // 横
    let mut tmp = vec![0u8; ow * h * 4];
    for y in 0..h {
        for (xx, &(xmin, xmax)) in bh.iter().enumerate() {
            let mut sums = [1i32 << 21; 4];
            for (x, k) in kkh[xx * kh..xx * kh + xmax].iter().enumerate() {
                let i = (y * w + x + xmin) * 4;
                for (sum, value) in sums.iter_mut().zip(&pre[i..i + 4]) {
                    *sum += i32::from(*value) * k;
                }
            }
            let o = (y * ow + xx) * 4;
            for (out, sum) in tmp[o..o + 4].iter_mut().zip(sums) {
                *out = clip8(sum);
            }
        }
    }
    // 縦
    let mut out = vec![0u8; ow * oh * 4];
    for (yy, &(ymin, ymax)) in bv.iter().enumerate() {
        for x in 0..ow {
            let mut sums = [1i32 << 21; 4];
            for (y, k) in kkv[yy * kv..yy * kv + ymax].iter().enumerate() {
                let i = ((y + ymin) * ow + x) * 4;
                for (sum, value) in sums.iter_mut().zip(&tmp[i..i + 4]) {
                    *sum += i32::from(*value) * k;
                }
            }
            let o = (yy * ow + x) * 4;
            for (pixel, sum) in out[o..o + 4].iter_mut().zip(sums) {
                *pixel = clip8(sum);
            }
        }
    }
    // RGBa → RGBA（色をアルファで割り戻す）
    for p in out.as_chunks_mut::<4>().0 {
        let a = u32::from(p[3]);
        if a != 255 && a != 0 {
            for channel in &mut p[..3] {
                *channel = ((255 * u32::from(*channel)) / a).min(255) as u8;
            }
        }
    }
    RgbaImage::from_raw(ow as u32, oh as u32, out).unwrap_or_default()
}

/// 字間を空けて、中央揃えで 1 行置く（Python の `_draw_tracked`）。
///
/// Pillow に字送りの指定は無いので 1 文字ずつ置く。
fn draw_tracked(
    painter: &impl TextPainter,
    canvas: &mut RgbaImage,
    centre: (f64, f64),
    text: &str,
    font: FontSpec,
    fill: [u8; 4],
    tracking: f64,
) {
    let chars: Vec<String> = text.chars().map(String::from).collect();
    let widths: Vec<f64> = chars
        .iter()
        .map(|ch| painter.text_length(ch, font))
        .collect();
    // Python の sum() と同じく、0 から順に足す。
    let total = widths.iter().fold(0.0f64, |sum, width| sum + width);
    let mut x = centre.0 - (total + tracking * (chars.len() as f64 - 1.0)) / 2.0;
    for (ch, width) in chars.iter().zip(&widths) {
        painter.draw_text(canvas, (x, centre.1), ch, font, fill, Anchor(*b"lm"));
        x += width + tracking;
    }
}

/// 数字と添え字を、ひとかたまりとして中央へ置く（Python の `_draw_intensity`。添え字はベースラインに載せる）。
///
/// 数字はどの震度でも同じ大きさにする。中央合わせは字の実体（インクの箱）で取る。
#[allow(clippy::too_many_arguments)]
fn draw_intensity(
    painter: &impl TextPainter,
    canvas: &mut RgbaImage,
    centre: (f64, f64),
    numeral: &str,
    suffix: &str,
    numeral_font: FontSpec,
    suffix_font: FontSpec,
    gap: f64,
    fill: [u8; 4],
) {
    let baseline = Anchor(*b"ls");
    let (left, top, right, bottom) = painter.text_bbox((0.0, 0.0), numeral, numeral_font, baseline);
    let (left, mut top, mut right, mut bottom) = (
        f64::from(left),
        f64::from(top),
        f64::from(right),
        f64::from(bottom),
    );
    // （文・フォント・横のずらし）。縦のずらし（rise）は、ベースラインに載せるので 0。
    let mut placed = vec![(numeral, numeral_font, 0.0f64)];
    if !suffix.is_empty() {
        let (s_left, s_top, s_right, s_bottom) =
            painter.text_bbox((0.0, 0.0), suffix, suffix_font, baseline);
        let offset = right + gap - f64::from(s_left);
        placed.push((suffix, suffix_font, offset));
        right = offset + f64::from(s_right);
        top = top.min(f64::from(s_top));
        bottom = bottom.max(f64::from(s_bottom));
    }
    let ox = centre.0 - (left + right) / 2.0;
    let oy = centre.1 - (top + bottom) / 2.0;
    for (text, font, offset) in placed {
        painter.draw_text(canvas, (ox + offset, oy), text, font, fill, baseline);
    }
}

/// 文字だけの層（720×720、透明の上に見出しと数字）。Python の `_generate_badge` の `over`。
pub fn badge_text_layer(painter: &impl TextPainter, scale: i64) -> Option<RgbaImage> {
    let (numeral, suffix) = badge_glyphs(scale)?;
    let ink = ink_for(fill_rgb(scale));
    let (w, h) = (BADGE_SIZE * SS, BADGE_SIZE * SS);
    let (size, ss) = (f64::from(BADGE_SIZE), f64::from(SS));
    let mut over = RgbaImage::new(w, h);
    // 見出し。字間を空けて小さく載せる。
    let caption_px = (size * 0.098 * ss) as u32;
    draw_tracked(
        painter,
        &mut over,
        (f64::from(w) / 2.0, f64::from(h) * 0.225),
        "最大震度",
        FontSpec {
            size: caption_px,
            bold: true,
        },
        [ink[0], ink[1], ink[2], 170],
        f64::from(caption_px) * 0.16,
    );
    // 数字（と添え字）。
    let numeral_px = (size * 0.56 * ss) as u32;
    draw_intensity(
        painter,
        &mut over,
        (f64::from(w) / 2.0, f64::from(h) * 0.600),
        numeral,
        suffix,
        FontSpec {
            size: numeral_px,
            bold: true,
        },
        FontSpec {
            size: (f64::from(numeral_px) * 0.42) as u32,
            bold: true,
        },
        f64::from(numeral_px) * 0.10,
        [ink[0], ink[1], ink[2], 255],
    );
    Some(over)
}

/// 札を描く（240×240 の RGBA）。知らない震度は `None`。Python の `_generate_badge`（PNG にする前まで）。
pub fn render_badge(painter: &impl TextPainter, scale: i64) -> Option<RgbaImage> {
    // 字は別の層に描いてから重ねる（半透明の字が「半透明の穴」にならないように）。
    let over = badge_text_layer(painter, scale)?;
    let mut img = badge_base(over.width(), over.height(), fill_rgb(scale));
    alpha_composite(&mut img, &over);
    Some(resize_lanczos(&img, BADGE_SIZE, BADGE_SIZE))
}

/// RGBA の画像を PNG にする。
pub fn encode_png(image: &RgbaImage) -> Option<Vec<u8>> {
    use image::codecs::png::{CompressionType, FilterType, PngEncoder};
    let mut png = Vec::new();
    PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::Adaptive)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgba8,
        )
        .ok()?;
    Some(png)
}

/// 札の PNG を作る（フォントを読むところから）。作れなければ理由を返す。
///
/// 太字のフォント（約 20MB）は、作る間だけ読んで、終わったら手放す。
pub fn generate_badge(scale: i64) -> Result<Vec<u8>, String> {
    if badge_glyphs(scale).is_none() {
        return Err(format!("震度 {scale} は札にできません"));
    }
    let painter = PillowText::load(false, true).map_err(|error| error.to_string())?;
    let image = render_badge(&painter, scale).ok_or("札を描けません")?;
    encode_png(&image).ok_or_else(|| "PNG にできません".to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// 控えた 1 回の `draw_text`（文・大きさ・座標・色・anchor）。
    type Drawn = (String, u32, (f64, f64), [u8; 4], [u8; 2]);

    /// 呼ばれ方を控えるだけの偽物。長さと箱は決まった値を返す。
    #[derive(Default)]
    struct Recorder {
        drawn: Mutex<Vec<Drawn>>,
    }

    impl TextPainter for Recorder {
        fn text_length(&self, text: &str, font: FontSpec) -> f64 {
            // 1 字あたり、大きさと同じ幅。
            text.chars().count() as f64 * f64::from(font.size)
        }

        fn text_bbox(
            &self,
            _xy: (f64, f64),
            text: &str,
            font: FontSpec,
            _anchor: Anchor,
        ) -> (i32, i32, i32, i32) {
            // 数字は左に 10 の余白。和字は左に 7 の余白で、ベースラインの下へ 20 はみ出す。
            if text.is_ascii() {
                (10, -300, 10 + 200, 0)
            } else {
                (7, -(font.size as i32), font.size as i32, 20)
            }
        }

        fn draw_text(
            &self,
            _canvas: &mut RgbaImage,
            xy: (f64, f64),
            text: &str,
            font: FontSpec,
            fill: [u8; 4],
            anchor: Anchor,
        ) {
            assert!(font.bold, "札の字は全部太字");
            self.drawn
                .lock()
                .unwrap()
                .push((text.to_owned(), font.size, xy, fill, anchor.0));
        }
    }

    /// 震度の値と、札に置く字の対応（Python の `_SCALE_BADGE_LABEL` と `_badge_glyphs`）。
    #[test]
    fn glyphs_follow_the_python_table() {
        let want = [
            (10, ("1", "")),
            (20, ("2", "")),
            (30, ("3", "")),
            (40, ("4", "")),
            (45, ("5", "弱")),
            (50, ("5", "強")),
            (55, ("6", "弱")),
            (60, ("6", "強")),
            (70, ("7", "")),
        ];
        for (scale, glyphs) in want {
            assert_eq!(badge_glyphs(scale), Some(glyphs), "{scale}");
        }
        // 知らない震度は札にしない（「最大震度 -1」の札を貼らない）。
        for scale in [-1, 0, 15, 46, 65, 99] {
            assert!(badge_glyphs(scale).is_none(), "{scale}");
        }
    }

    /// 地の色と、その上の字の色（明るい色の上は黒っぽく、暗い色の上は白）。
    #[test]
    fn ink_is_dark_on_bright_fills() {
        assert_eq!(fill_rgb(40), [226, 192, 62]);
        assert_eq!(fill_rgb(70), [132, 44, 128]);
        assert_eq!(fill_rgb(99), [120, 130, 150]);
        let dark: Vec<i64> = [10, 20, 30, 40, 45, 50, 55, 60, 70]
            .into_iter()
            .filter(|scale| ink_for(fill_rgb(*scale)) == [16, 20, 26])
            .collect();
        assert_eq!(
            dark,
            [40, 45],
            "黒っぽい字になるのは 4 と 5弱（Python の輝度の式で 150 を超える色）"
        );
        assert_eq!(ink_for([255, 255, 255]), [16, 20, 26]);
        assert_eq!(ink_for([0, 0, 0]), [255, 255, 255]);
    }

    /// `numpy.linspace` と同じ値になること（最後はちょうど stop）。
    #[test]
    fn linspace_matches_numpy() {
        assert_eq!(linspace(-1.0, 1.0, 5), [-1.0, -0.5, 0.0, 0.5, 1.0]);
        let ys = linspace(0.0, 1.0, 720);
        assert_eq!(ys[0], 0.0);
        assert_eq!(ys[719], 1.0);
        assert_eq!(ys[1], (1.0f64 / 719.0) as f32);
    }

    /// 札の形: 四隅は透明、真ん中は地の色で不透明、上の縁は明るく・下の縁は暗い。
    #[test]
    fn the_base_is_a_lit_squircle() {
        let rgb = fill_rgb(40);
        let base = badge_base(720, 720, rgb);
        for (x, y) in [(0, 0), (719, 0), (0, 719), (719, 719), (20, 20)] {
            assert_eq!(base.get_pixel(x, y).0[3], 0, "({x}, {y})");
        }
        let centre = base.get_pixel(360, 360).0;
        assert_eq!(centre[3], 255);
        assert!(centre[0].abs_diff(rgb[0]) < 12, "{centre:?}");
        // 上の縁（光）は地より明るく、下の縁（影）は地より暗い。
        let (top_edge, below_top) = (base.get_pixel(360, 1).0, base.get_pixel(360, 12).0);
        assert!(top_edge[2] > below_top[2], "{top_edge:?} {below_top:?}");
        let (bottom_edge, above_bottom) = (base.get_pixel(360, 718).0, base.get_pixel(360, 707).0);
        assert!(
            bottom_edge[0] < above_bottom[0],
            "{bottom_edge:?} {above_bottom:?}"
        );
        // 地は上が明るく下が暗い。
        assert!(base.get_pixel(360, 100).0[0] > base.get_pixel(360, 600).0[0]);
    }

    /// 重ね合わせ: 透明は何もしない・不透明は置き換える・半透明は混ぜる（Pillow の整数の式）。
    #[test]
    fn alpha_composite_matches_pillow() {
        let pixel = |r, g, b, a| RgbaImage::from_pixel(1, 1, image::Rgba([r, g, b, a]));
        let over = |dst: RgbaImage, src: RgbaImage| {
            let mut out = dst;
            alpha_composite(&mut out, &src);
            out.get_pixel(0, 0).0
        };
        assert_eq!(
            over(pixel(10, 20, 30, 200), pixel(9, 9, 9, 0)),
            [10, 20, 30, 200]
        );
        assert_eq!(
            over(pixel(10, 20, 30, 200), pixel(1, 2, 3, 255)),
            [1, 2, 3, 255]
        );
        assert_eq!(
            over(pixel(0, 0, 0, 0), pixel(100, 150, 200, 128)),
            [100, 150, 200, 128]
        );
        // Pillow の Image.alpha_composite で確かめた値。
        assert_eq!(
            over(pixel(255, 0, 0, 255), pixel(0, 0, 255, 128)),
            [127, 0, 128, 255]
        );
        assert_eq!(
            over(pixel(226, 192, 62, 100), pixel(16, 20, 26, 170)),
            [50, 48, 32, 203]
        );
    }

    /// 縮小: 一色の画像は同じ色のまま、大きさだけ変わること。
    #[test]
    fn resizing_a_flat_image_keeps_its_colour() {
        let flat = RgbaImage::from_pixel(30, 30, image::Rgba([200, 100, 50, 255]));
        let small = resize_lanczos(&flat, 10, 10);
        assert_eq!((small.width(), small.height()), (10, 10));
        assert!(small.pixels().all(|p| p.0 == [200, 100, 50, 255]));
        let clear = resize_lanczos(&RgbaImage::new(30, 30), 10, 10);
        assert!(clear.pixels().all(|p| p.0 == [0, 0, 0, 0]));
    }

    /// 見出しは 1 字ずつ、字間を空けて中央揃えで置くこと（Python の `_draw_tracked` の式）。
    #[test]
    fn the_caption_is_tracked_and_centred() {
        let recorder = Recorder::default();
        badge_text_layer(&recorder, 40).unwrap();
        let drawn = recorder.drawn.lock().unwrap();
        let caption: Vec<_> = drawn.iter().filter(|d| d.1 == 70).collect();
        assert_eq!(
            caption.iter().map(|d| d.0.as_str()).collect::<String>(),
            "最大震度"
        );
        // 幅 70 × 4 字＋字間 11.2 × 3 = 313.6。左端は 360 - 156.8、送りは 70 + 11.2。
        let tracking = 70.0 * 0.16;
        let mut x = 360.0 - (280.0 + tracking * 3.0) / 2.0;
        for d in &caption {
            assert_eq!(d.2, (x, 720.0 * 0.225), "{}", d.0);
            assert_eq!(d.3, [16, 20, 26, 170], "見出しは半透明");
            assert_eq!(&d.4, b"lm");
            x += 70.0 + tracking;
        }
    }

    /// 数字だけの札は、数字のインクの箱を中央（360, 432）に合わせること。
    #[test]
    fn a_lone_numeral_is_centred_on_its_ink() {
        let recorder = Recorder::default();
        badge_text_layer(&recorder, 70).unwrap();
        let drawn = recorder.drawn.lock().unwrap();
        let numeral: Vec<_> = drawn.iter().filter(|d| d.1 == 403).collect();
        assert_eq!(numeral.len(), 1);
        // 箱は (10, -300, 210, 0)。中心 (110, -150) が (360, 432) に来る。
        assert_eq!(numeral[0].0, "7");
        assert_eq!(numeral[0].2, (360.0 - 110.0, 720.0 * 0.600 + 150.0));
        assert_eq!(numeral[0].3, [255, 255, 255, 255]);
        assert_eq!(&numeral[0].4, b"ls");
        assert!(!drawn.iter().any(|d| d.1 == 169), "添え字は無い");
    }

    /// 添え字つきの札は、数字と添え字をひとかたまりとして中央へ置くこと（数字の大きさは変えない）。
    #[test]
    fn a_suffix_sits_on_the_baseline_beside_the_numeral() {
        let recorder = Recorder::default();
        badge_text_layer(&recorder, 45).unwrap();
        let drawn = recorder.drawn.lock().unwrap();
        let numeral = drawn.iter().find(|d| d.1 == 403).unwrap();
        let suffix = drawn.iter().find(|d| d.1 == 169).unwrap();
        assert_eq!((numeral.0.as_str(), suffix.0.as_str()), ("5", "弱"));
        // 数字の箱 (10, -300, 210, 0)、添え字の箱 (7, -169, 169, 20)、間は 403 × 0.10。
        // 添え字は、インクの左端（7）が数字のインクの右端＋間に来るように置く。
        let offset = 210.0 + 403.0 * 0.10 - 7.0;
        let right = offset + 169.0;
        let ox = 360.0 - (10.0 + right) / 2.0;
        let oy = 720.0 * 0.600 - (-300.0 + 20.0) / 2.0;
        assert_eq!(numeral.2, (ox, oy));
        assert_eq!(suffix.2, (ox + offset, oy), "同じベースライン");
        assert_eq!(suffix.3, [16, 20, 26, 255]);
        assert_eq!(&suffix.4, b"ls");
    }

    /// 知らない震度は描かないこと。
    #[test]
    fn unknown_scales_are_not_rendered() {
        let recorder = Recorder::default();
        for scale in [-1, 0, 15, 99] {
            assert!(badge_text_layer(&recorder, scale).is_none());
            assert!(render_badge(&recorder, scale).is_none());
            assert!(
                generate_badge(scale)
                    .unwrap_err()
                    .contains("札にできません")
            );
        }
        assert!(recorder.drawn.lock().unwrap().is_empty());
    }

    /// PNG にして読み戻すと、同じ画素であること。
    #[test]
    fn png_round_trips() {
        let image = badge_base(48, 48, [58, 122, 216]);
        let png = encode_png(&image).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let back = image::load_from_memory(&png).unwrap().to_rgba8();
        assert_eq!(back, image);
    }
}
