//! Pillow 13.0.0 の画像の処理の写し（重ね合わせ・貼り付け・LANCZOS の拡大縮小・ぼかし・色の形の変換）。
//!
//! 原典: `src/libImaging/AlphaComposite.c`・`Paste.c`・`Crop.c`・`Resample.c`・`BoxBlur.c`・`Convert.c` と、
//! `PIL/Image.py` の `alpha_composite`・`paste`・`resize`・`filter`、`PIL/ImageFilter.py` の `GaussianBlur`。
//!
//! どれも整数の計算（縮小の係数と、ぼかしの半径だけ浮動小数）で、**原典の型と順をそのまま写している。**
//! 式の形を変えないこと（`tests/earthquake_map_golden.rs` が、Python の出力と画素まで同じことを見張っている）。

use image::{RgbImage, RgbaImage};

/// `SHIFTFORDIV255(a)`（255 で割る近似）。
fn shift_for_div255(a: u32) -> u32 {
    ((a >> 8) + a) >> 8
}

/// `MULDIV255(a, b)`（a × b ÷ 255 を四捨五入）。
fn muldiv255(a: u8, b: u8) -> u8 {
    shift_for_div255(u32::from(a) * u32::from(b) + 128) as u8
}

// ── 重ね合わせと貼り付け ─────────────────────────────────

/// 1 画素を重ねる（`ImagingAlphaComposite` の中身。`dst` の上に `src`）。
fn composite_pixel(dst: &mut [u8; 4], src: &[u8; 4]) {
    const PRECISION_BITS: u32 = 7;
    let (sa, da) = (u32::from(src[3]), u32::from(dst[3]));
    if sa == 0 {
        return;
    }
    let blend = da * (255 - sa);
    let outa255 = sa * 255 + blend;
    let coef1 = sa * 255 * 255 * (1 << PRECISION_BITS) / outa255;
    let coef2 = 255 * (1 << PRECISION_BITS) - coef1;
    for (d, s) in dst.iter_mut().zip(src).take(3) {
        let tmp = u32::from(*s) * coef1 + u32::from(*d) * coef2;
        *d = (shift_for_div255(tmp + (0x80 << PRECISION_BITS)) >> PRECISION_BITS) as u8;
    }
    dst[3] = shift_for_div255(outa255 + 0x80) as u8;
}

/// `dst` と `src`（左上を `at` に置く）が重なる範囲。`(dst の x, dst の y, src の x, src の y, 幅, 高さ)`。
fn overlap(
    dst: (u32, u32),
    src: (u32, u32),
    at: (i64, i64),
) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let x0 = at.0.max(0);
    let y0 = at.1.max(0);
    let x1 = (at.0 + i64::from(src.0)).min(i64::from(dst.0));
    let y1 = (at.1 + i64::from(src.1)).min(i64::from(dst.1));
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some((
        x0 as usize,
        y0 as usize,
        (x0 - at.0) as usize,
        (y0 - at.1) as usize,
        (x1 - x0) as usize,
        (y1 - y0) as usize,
    ))
}

/// `dst.alpha_composite(src, dest=at)`。`src` の左上を `at` に置いて、`dst` の上に重ねる。
///
/// Pillow は「`dst` からその範囲を切り出す（外は透明）→ 重ねる → 貼り戻す（外は捨てる）」の順でやる。
/// 結果は、画像の中に入る範囲だけを重ねるのと同じ（`at` が負でも、画像の外でもよい）。
pub fn alpha_composite(dst: &mut RgbaImage, src: &RgbaImage, at: (i64, i64)) {
    let Some((dx, dy, sx, sy, w, h)) = overlap(dst.dimensions(), src.dimensions(), at) else {
        return;
    };
    let (dst_w, src_w) = (dst.width() as usize, src.width() as usize);
    let src_buf: &[u8] = src;
    let dst_buf: &mut [u8] = dst;
    for row in 0..h {
        let d = ((dy + row) * dst_w + dx) * 4;
        let s = ((sy + row) * src_w + sx) * 4;
        let (over, _) = src_buf[s..s + w * 4].as_chunks::<4>();
        let (under, _) = dst_buf[d..d + w * 4].as_chunks_mut::<4>();
        for (dp, sp) in under.iter_mut().zip(over) {
            composite_pixel(dp, sp);
        }
    }
}

/// `dst.paste(src, at)`（RGB どうし。型抜きなしの貼り付け）。はみ出す分は捨てる。
pub fn paste_rgb(dst: &mut RgbImage, src: &RgbImage, at: (i64, i64)) {
    let Some((dx, dy, sx, sy, w, h)) = overlap(dst.dimensions(), src.dimensions(), at) else {
        return;
    };
    let (dst_w, src_w) = (dst.width() as usize, src.width() as usize);
    let src_buf: &[u8] = src;
    let dst_buf: &mut [u8] = dst;
    for row in 0..h {
        let d = ((dy + row) * dst_w + dx) * 3;
        let s = ((sy + row) * src_w + sx) * 3;
        dst_buf[d..d + w * 3].copy_from_slice(&src_buf[s..s + w * 3]);
    }
}

// ── 色の形の変換 ────────────────────────────────────────

/// `convert("RGBA")`（RGB から。アルファは 255）。
pub fn rgb_to_rgba(src: &RgbImage) -> RgbaImage {
    let mut out = Vec::with_capacity(src.len() / 3 * 4);
    for [r, g, b] in src.as_chunks::<3>().0 {
        out.extend_from_slice(&[*r, *g, *b, 255]);
    }
    RgbaImage::from_raw(src.width(), src.height(), out).unwrap_or_default()
}

/// `convert("RGB")`（RGBA から。アルファを捨てるだけで、色は混ぜない）。
pub fn rgba_to_rgb(src: &RgbaImage) -> RgbImage {
    let mut out = Vec::with_capacity(src.len() / 4 * 3);
    for [r, g, b, _] in src.as_chunks::<4>().0 {
        out.extend_from_slice(&[*r, *g, *b]);
    }
    RgbImage::from_raw(src.width(), src.height(), out).unwrap_or_default()
}

/// 色から明るさへ（`L24(rgb) >> 16`。ITU-R 601-2）。
pub fn luma(r: u8, g: u8, b: u8) -> u8 {
    ((u32::from(r) * 19595 + u32::from(g) * 38470 + u32::from(b) * 7471 + 0x8000) >> 16) as u8
}

// ── LANCZOS の拡大縮小（`Resample.c`） ───────────────────────

/// 係数の小数部のビット数（`PRECISION_BITS`）。
const RESAMPLE_BITS: u32 = 32 - 8 - 2;

/// `sinc_filter`。
fn sinc(x: f64) -> f64 {
    if x == 0.0 {
        return 1.0;
    }
    let x = x * std::f64::consts::PI;
    x.sin() / x
}

/// `lanczos_filter`（幅 3）。
fn lanczos(x: f64) -> f64 {
    if (-3.0..3.0).contains(&x) {
        sinc(x) * sinc(x / 3.0)
    } else {
        0.0
    }
}

/// 1 方向の係数（`precompute_coeffs` と `normalize_coeffs_8bpc`）。
struct Coeffs {
    /// 出力の 1 画素あたりの係数の数。
    ksize: usize,
    /// 出力の画素ごとの、入力の始まりと個数。
    bounds: Vec<(usize, usize)>,
    /// 係数（22 ビットの固定小数）。
    kk: Vec<i32>,
}

/// `in_size` を `out_size` にするときの係数（切り出しなし）。
fn coeffs(in_size: usize, out_size: usize) -> Coeffs {
    let scale = f64::from(in_size as f32) / out_size as f64;
    let filterscale = if scale < 1.0 { 1.0 } else { scale };
    let support = 3.0 * filterscale;
    let ksize = support.ceil() as usize * 2 + 1;
    let inv_filterscale = 1.0 / filterscale;
    let mut bounds = Vec::with_capacity(out_size);
    let mut kk = vec![0_i32; out_size * ksize];
    let mut k = vec![0.0_f64; ksize];
    for xx in 0..out_size {
        let center = 0.0 + (xx as f64 + 0.5) * scale;
        let mut ww = 0.0;
        let xmin = ((center - support + 0.5) as i32).max(0);
        let xmax = ((center + support + 0.5) as i32).min(in_size as i32) - xmin;
        let count = xmax.max(0) as usize;
        for (x, slot) in k.iter_mut().enumerate().take(count) {
            let w = lanczos((f64::from(x as i32 + xmin) - center + 0.5) * inv_filterscale);
            *slot = w;
            ww += w;
        }
        for (x, slot) in k.iter().enumerate().take(count) {
            let v = if ww != 0.0 { slot / ww } else { *slot };
            let scaled = v * f64::from(1_u32 << RESAMPLE_BITS);
            kk[xx * ksize + x] = if v < 0.0 {
                (-0.5 + scaled) as i32
            } else {
                (0.5 + scaled) as i32
            };
        }
        bounds.push((xmin as usize, count));
    }
    Coeffs { ksize, bounds, kk }
}

/// 係数を、丸めの境からどれだけ離れているかと一緒に調べる（テスト用）。`sin` の最後の桁が違っても係数が
/// 変わらないことを確かめるために、境までのいちばん短い距離（係数の 1 目盛りを 1 として）を返す。
#[doc(hidden)]
pub fn lanczos_rounding_margin(in_size: usize, out_size: usize) -> f64 {
    let scale = f64::from(in_size as f32) / out_size as f64;
    let filterscale = if scale < 1.0 { 1.0 } else { scale };
    let support = 3.0 * filterscale;
    let inv_filterscale = 1.0 / filterscale;
    let mut margin = f64::INFINITY;
    for xx in 0..out_size {
        let center = (xx as f64 + 0.5) * scale;
        let xmin = ((center - support + 0.5) as i32).max(0);
        let xmax = ((center + support + 0.5) as i32).min(in_size as i32) - xmin;
        let weights: Vec<f64> = (0..xmax.max(0))
            .map(|x| lanczos((f64::from(x + xmin) - center + 0.5) * inv_filterscale))
            .collect();
        let ww: f64 = weights.iter().sum();
        for w in weights {
            let v = if ww != 0.0 { w / ww } else { w };
            let scaled = (v * f64::from(1_u32 << RESAMPLE_BITS)).abs() + 0.5;
            // 0 ちょうど（フィルタの外）は、どちらに転んでも 0 のまま。
            if v != 0.0 {
                margin = margin.min((scaled - scaled.round()).abs());
            }
        }
    }
    margin
}

/// `clip8`（22 ビットの固定小数を 0〜255 に）。
fn clip8(v: i32) -> u8 {
    (v >> RESAMPLE_BITS).clamp(0, 255) as u8
}

/// 横に伸び縮みさせる（`_ImagingResampleHorizontal_8bpc`）。`offset` 行目から `out_h` 行だけを作る。
fn resample_horizontal(
    src: &[u8],
    in_w: usize,
    bands: usize,
    offset: usize,
    out_h: usize,
    c: &Coeffs,
) -> Vec<u8> {
    let out_w = c.bounds.len();
    let mut out = vec![0_u8; out_w * out_h * bands];
    for yy in 0..out_h {
        let line = &src[(yy + offset) * in_w * bands..(yy + offset + 1) * in_w * bands];
        for xx in 0..out_w {
            let (xmin, xmax) = c.bounds[xx];
            let k = &c.kk[xx * c.ksize..xx * c.ksize + xmax];
            let mut ss = [1_i32 << (RESAMPLE_BITS - 1); 4];
            for (x, coefficient) in k.iter().enumerate() {
                let p = (x + xmin) * bands;
                for b in 0..bands {
                    ss[b] += i32::from(line[p + b]) * coefficient;
                }
            }
            let o = (yy * out_w + xx) * bands;
            for b in 0..bands {
                out[o + b] = clip8(ss[b]);
            }
        }
    }
    out
}

/// 縦に伸び縮みさせる（`_ImagingResampleVertical_8bpc`）。
fn resample_vertical(src: &[u8], w: usize, bands: usize, c: &Coeffs) -> Vec<u8> {
    let out_h = c.bounds.len();
    let mut out = vec![0_u8; w * out_h * bands];
    for yy in 0..out_h {
        let (ymin, ymax) = c.bounds[yy];
        let k = &c.kk[yy * c.ksize..yy * c.ksize + ymax];
        for xx in 0..w {
            let mut ss = [1_i32 << (RESAMPLE_BITS - 1); 4];
            for (y, coefficient) in k.iter().enumerate() {
                let p = ((y + ymin) * w + xx) * bands;
                for b in 0..bands {
                    ss[b] += i32::from(src[p + b]) * coefficient;
                }
            }
            let o = (yy * w + xx) * bands;
            for b in 0..bands {
                out[o + b] = clip8(ss[b]);
            }
        }
    }
    out
}

/// LANCZOS で大きさを変える（`ImagingResampleInner`）。`bands` は 1 画素のバイト数（3 か 4）。
///
/// 横 → 縦の順が基本で、縦の縮みが横の縮みの 2 倍を超えるときだけ縦を先にする（原典と同じ。順で丸めが変わる）。
fn resample(
    src: &[u8],
    in_size: (usize, usize),
    out_size: (usize, usize),
    bands: usize,
) -> Vec<u8> {
    let (in_w, in_h) = in_size;
    let (out_w, out_h) = out_size;
    let need_horizontal = out_w != in_w;
    let need_vertical = out_h != in_h;
    let shrink_h = in_h as i64 - out_h as i64;
    let shrink_w = in_w as i64 - out_w as i64;
    let horizontal_first = !(shrink_h > 0 && shrink_h > shrink_w * 2);
    if !need_horizontal && !need_vertical {
        return src.to_vec();
    }
    let mut vertical = coeffs(in_h, out_h);
    if horizontal_first {
        let mut current = src.to_vec();
        if need_horizontal {
            // 縦で使う行だけを横に伸び縮みさせる。
            let first = vertical.bounds[0].0;
            let last_bound = vertical.bounds[out_h - 1];
            let last = last_bound.0 + last_bound.1;
            for bound in &mut vertical.bounds {
                bound.0 -= first;
            }
            let horizontal = coeffs(in_w, out_w);
            current = resample_horizontal(src, in_w, bands, first, last - first, &horizontal);
        }
        if need_vertical {
            current = resample_vertical(&current, out_w, bands, &vertical);
        }
        current
    } else {
        let mut current = src.to_vec();
        if need_vertical {
            current = resample_vertical(src, in_w, bands, &vertical);
        }
        if need_horizontal {
            let horizontal = coeffs(in_w, out_w);
            current = resample_horizontal(&current, in_w, bands, 0, out_h, &horizontal);
        }
        current
    }
}

/// `Image.resize((w, h), Image.LANCZOS)`（RGB）。
pub fn resize_rgb(src: &RgbImage, w: u32, h: u32) -> RgbImage {
    let size = (src.width() as usize, src.height() as usize);
    let out = resample(src, size, (w as usize, h as usize), 3);
    RgbImage::from_raw(w, h, out).unwrap_or_default()
}

/// `Image.resize((w, h), Image.LANCZOS)`（RGBA）。Pillow と同じく、先に色へアルファを掛け（RGBa）、
/// 大きさを変えてから、アルファで割り戻す。
pub fn resize_rgba(src: &RgbaImage, w: u32, h: u32) -> RgbaImage {
    if src.dimensions() == (w, h) {
        return src.clone();
    }
    let mut pre = src.as_raw().clone();
    for p in pre.as_chunks_mut::<4>().0 {
        let alpha = p[3];
        for c in &mut p[..3] {
            *c = muldiv255(*c, alpha);
        }
    }
    let size = (src.width() as usize, src.height() as usize);
    let mut out = resample(&pre, size, (w as usize, h as usize), 4);
    for p in out.as_chunks_mut::<4>().0 {
        let alpha = u32::from(p[3]);
        if alpha != 255 && alpha != 0 {
            for c in &mut p[..3] {
                *c = (255 * u32::from(*c) / alpha).min(255) as u8;
            }
        }
    }
    RgbaImage::from_raw(w, h, out).unwrap_or_default()
}

// ── ぼかし（`BoxBlur.c`） ────────────────────────────────────

/// 1 行を箱ぼかしにする（`ImagingLineBoxBlur32`）。`line_in` と `line_out` は 4 バイトの画素の並び。
fn line_box_blur(
    line_out: &mut [u8],
    line_in: &[u8],
    radius: i32,
    edge_a: i32,
    edge_b: i32,
    ww: u32,
    fw: u32,
) {
    let lastx = (line_in.len() / 4) as i32 - 1;
    let px = |x: i32, c: usize| i32::from(line_in[x as usize * 4 + c]);
    for c in 0..4 {
        // 画像の外（左）は、いちばん左の画素が続いているものとして足し込む。
        let mut acc: u32 = (px(0, c) * (radius + 1)) as u32;
        for x in 0..edge_a - 1 {
            acc = acc.wrapping_add(px(x, c) as u32);
        }
        acc = acc.wrapping_add((px(lastx, c) * (radius - edge_a + 1)) as u32);
        let mut step = |acc: &mut u32, x: i32, subtract: i32, add: i32, left: i32, right: i32| {
            *acc = acc.wrapping_add((px(add, c) - px(subtract, c)) as u32);
            let bulk = acc
                .wrapping_mul(ww)
                .wrapping_add(((px(left, c) + px(right, c)) as u32).wrapping_mul(fw));
            line_out[x as usize * 4 + c] = (bulk.wrapping_add(1 << 23) >> 24) as u8;
        };
        if edge_a <= edge_b {
            for x in 0..edge_a {
                step(&mut acc, x, 0, x + radius, 0, x + radius + 1);
            }
            for x in edge_a..edge_b {
                step(
                    &mut acc,
                    x,
                    x - radius - 1,
                    x + radius,
                    x - radius - 1,
                    x + radius + 1,
                );
            }
            for x in edge_b..=lastx {
                step(&mut acc, x, x - radius - 1, lastx, x - radius - 1, lastx);
            }
        } else {
            for x in 0..edge_b {
                step(&mut acc, x, 0, x + radius, 0, x + radius + 1);
            }
            for x in edge_b..edge_a {
                step(&mut acc, x, 0, lastx, 0, lastx);
            }
            for x in edge_a..=lastx {
                step(&mut acc, x, x - radius - 1, lastx, x - radius - 1, lastx);
            }
        }
    }
}

/// 横の箱ぼかしを 1 回（`ImagingHorizontalBoxBlur`）。
fn horizontal_box_blur(buf: &mut [u8], w: usize, float_radius: f32) {
    let radius = float_radius as i32;
    let ww = ((1_u32 << 24) as f32 / (float_radius * 2.0 + 1.0)) as u32;
    let fw = (1_u32 << 24).wrapping_sub(((radius * 2 + 1) as u32).wrapping_mul(ww)) / 2;
    let edge_a = (radius + 1).min(w as i32);
    let edge_b = (w as i32 - radius - 1).max(0);
    let mut line = vec![0_u8; w * 4];
    for row in buf.chunks_exact_mut(w * 4) {
        line_box_blur(&mut line, row, radius, edge_a, edge_b, ww, fw);
        row.copy_from_slice(&line);
    }
}

/// 縦と横を入れ替える（`ImagingTranspose`）。
fn transpose(buf: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0_u8; buf.len()];
    for y in 0..h {
        for x in 0..w {
            let (s, d) = ((y * w + x) * 4, (x * h + y) * 4);
            out[d..d + 4].copy_from_slice(&buf[s..s + 4]);
        }
    }
    out
}

/// ガウスぼかしの半径から、箱ぼかしの半径を出す（`_gaussian_blur_radius`）。float と double の混ざり方も
/// 原典のまま。
fn gaussian_box_radius(radius: f32, passes: i32) -> f32 {
    let sigma2: f32 = radius * radius / passes as f32;
    let length: f32 = (12.0 * f64::from(sigma2) + 1.0).sqrt() as f32;
    let l: f32 = ((f64::from(length) - 1.0) / 2.0).floor() as f32;
    let mut a: f32 = (2.0 * l + 1.0) * (l * (l + 1.0) - 3.0 * sigma2);
    a /= 6.0 * (sigma2 - (l + 1.0) * (l + 1.0));
    l + a
}

/// `image.filter(ImageFilter.GaussianBlur(radius))`（RGBA。箱ぼかしを縦横 3 回ずつ）。
///
/// 4 つの色の成分を別々にぼかす（アルファを先に掛けない。Pillow と同じ）。
pub fn gaussian_blur(src: &RgbaImage, radius: f64) -> RgbaImage {
    const PASSES: i32 = 3;
    if radius == 0.0 || src.width() == 0 || src.height() == 0 {
        return src.clone();
    }
    let box_radius = gaussian_box_radius(radius as f32, PASSES);
    let (w, h) = (src.width() as usize, src.height() as usize);
    let mut buf = src.as_raw().clone();
    if box_radius != 0.0 {
        for _ in 0..PASSES {
            horizontal_box_blur(&mut buf, w, box_radius);
        }
        let mut turned = transpose(&buf, w, h);
        for _ in 0..PASSES {
            horizontal_box_blur(&mut turned, h, box_radius);
        }
        buf = transpose(&turned, h, w);
    }
    RgbaImage::from_raw(src.width(), src.height(), buf).unwrap_or_default()
}
