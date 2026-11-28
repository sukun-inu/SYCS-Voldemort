//! 地図のタイル（国土地理院の白地図）を読んで、暗い色の地図に塗り替えて 1 枚の面に貼る。
//! Python の `_paste_tiles`・`_recolour_tile`。
//!
//! タイルは PNG のバイト列のまま受け取り、ここで復号する（Python の `Image.open(…).convert("L")`）。
//! 白地図は「白い面に細い黒い線」なので、明るさだけを使う。**復号と明るさへの直し方は Pillow に合わせてある**
//! （PNG の色の形ごとに Pillow の直し方が違う。下の [`decode_gray`] を参照）。
//!
//! Python と違うところ: Pillow は PNG 以外（JPEG・GIF など）も読めるが、こちらは PNG だけを読む。国土地理院の
//! 白地図は PNG なので差は出ない。読めないタイルは、Python と同じく飛ばす（その枡は海の色のまま）。

use std::io::Cursor;

use image::RgbImage;

use sycs_imaging::raster::{luma, paste_rgb};

/// タイルの一辺（画素）。Python の `_TILE_SZ`。
pub const TILE_SIZE: i64 = 256;
/// 出来上がりの地図の幅と高さ（画素）。Python の `_MAP_W`・`_MAP_H`。
pub const MAP_SIZE: (u32, u32) = (1200, 720);
/// 海（タイルの無いところ）の色。Python の `_MAP_SEA`。
pub const MAP_SEA: [u8; 3] = [11, 15, 22];
/// 陸の色。Python の `_MAP_LAND`。
pub const MAP_LAND: [u8; 3] = [38, 47, 62];
/// 線（海岸線・県境）の色。Python の `_MAP_LINE`。
pub const MAP_LINE: [u8; 3] = [96, 114, 142];

/// 明るさだけにした画像。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrayImage {
    /// 幅。
    pub width: u32,
    /// 高さ。
    pub height: u32,
    /// 明るさ（行ごとの並び）。
    pub pixels: Vec<u8>,
}

/// 詰めてある行から、`index` 番目の値（`bits` ビット、上の桁から）を取り出す。
fn packed(row: &[u8], index: usize, bits: usize) -> u8 {
    let bit = index * bits;
    let shift = 8 - bits - (bit % 8);
    (row[bit / 8] >> shift) & ((1 << bits) - 1)
}

/// PNG を読んで明るさにする。Python の `Image.open(io.BytesIO(raw)).convert("L")`。読めなければ `None`。
///
/// Pillow は PNG の色の形ごとに、いったん自分の形（mode）にしてから明るさへ直す。同じ結果になるように:
///
/// - グレー 1・2・4・8 ビット: 0〜255 に引き伸ばした値そのまま
/// - グレー 16 ビット: Pillow の mode は `I;16` で、明るさへは **255 で頭打ち**（上の桁が 0 でなければ 255）
/// - グレー＋アルファ: グレーの値（16 ビットは上の桁）。アルファは見ない
/// - 色（RGB・RGBA）: `(R*19595 + G*38470 + B*7471 + 0x8000) >> 16`（16 ビットは上の桁）。アルファは見ない
/// - パレット: パレットの色を上の式で。透過の指定（tRNS）は見ない。パレットに無い番号は黒
pub fn decode_gray(png_bytes: &[u8]) -> Option<GrayImage> {
    let mut decoder = png::Decoder::new(Cursor::new(png_bytes));
    // 何も変換させず、ファイルに入っている形のまま受け取る（直し方を Pillow に合わせるため）。
    decoder.set_transformations(png::Transformations::IDENTITY);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0_u8; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut buf).ok()?;
    let info = reader.info();
    let (width, height) = (frame.width as usize, frame.height as usize);
    let stride = frame.line_size;
    let palette: &[u8] = info.palette.as_deref().unwrap_or(&[]);
    let bits = info.bit_depth as usize;
    let wide = bits == 16;
    let mut pixels = Vec::with_capacity(width * height);
    for row in buf.chunks_exact(stride).take(height) {
        for x in 0..width {
            // 16 ビットは上の桁が先に入っている。`sample(n)` は n 番目の成分の上の桁。
            let sample = |n: usize| {
                if wide {
                    row[(x * n_of(info.color_type) + n) * 2]
                } else {
                    row[x * n_of(info.color_type) + n]
                }
            };
            let value = match info.color_type {
                png::ColorType::Grayscale => match bits {
                    1 => packed(row, x, 1) * 255,
                    2 => packed(row, x, 2) * 85,
                    4 => packed(row, x, 4) * 17,
                    8 => row[x],
                    _ => {
                        if row[x * 2] != 0 {
                            255
                        } else {
                            row[x * 2 + 1]
                        }
                    }
                },
                png::ColorType::GrayscaleAlpha => sample(0),
                png::ColorType::Rgb | png::ColorType::Rgba => luma(sample(0), sample(1), sample(2)),
                png::ColorType::Indexed => {
                    let index = usize::from(if bits == 8 {
                        row[x]
                    } else {
                        packed(row, x, bits)
                    });
                    match palette.get(index * 3..index * 3 + 3) {
                        Some(rgb) => luma(rgb[0], rgb[1], rgb[2]),
                        None => 0,
                    }
                }
            };
            pixels.push(value);
        }
    }
    Some(GrayImage {
        width: frame.width,
        height: frame.height,
        pixels,
    })
}

/// 色の形ごとの、1 画素の成分の数。
fn n_of(color_type: png::ColorType) -> usize {
    match color_type {
        png::ColorType::Grayscale | png::ColorType::Indexed => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
    }
}

/// 白地図を暗い色の地図に塗り替える。Python の `_recolour_tile`。
///
/// 明るさをそのまま「線の濃さ」として読み、陸の色から線の色へ混ぜる。numpy と同じ float32 の計算を、
/// 同じ順でする（`(land * (1 - ink) + line * ink)` を 0 の方へ切り捨てて整数に）。
pub fn recolour_tile(gray: &GrayImage) -> RgbImage {
    let mut table = [[0_u8; 3]; 256];
    for (value, entry) in table.iter_mut().enumerate() {
        let values = value as f32 / 255.0_f32;
        let ink = (1.0_f32 - values).clamp(0.0, 1.0);
        for (c, slot) in entry.iter_mut().enumerate() {
            let (land, line) = (f32::from(MAP_LAND[c]), f32::from(MAP_LINE[c]));
            *slot = (land * (1.0_f32 - ink) + line * ink) as u8;
        }
    }
    let mut out = Vec::with_capacity(gray.pixels.len() * 3);
    for value in &gray.pixels {
        out.extend_from_slice(&table[usize::from(*value)]);
    }
    RgbImage::from_raw(gray.width, gray.height, out).unwrap_or_default()
}

/// 取ってきたタイルを 1 枚の面に貼る。Python の `_paste_tiles`。
///
/// `tiles` は `coords`（タイルの x・y）と同じ並びの PNG のバイト列（取れなかった枚は `None`）。置き場所は
/// Python の `int(tx * 256 - origin_x)` と同じ（0 の方へ切り捨て）。読めないタイルは飛ばす。
pub fn paste_tiles(
    coords: &[(i64, i64)],
    tiles: &[Option<Vec<u8>>],
    origin_x: f64,
    origin_y: f64,
) -> RgbImage {
    let mut base = RgbImage::from_pixel(MAP_SIZE.0, MAP_SIZE.1, image::Rgb(MAP_SEA));
    for ((tx, ty), raw) in coords.iter().zip(tiles) {
        let Some(raw) = raw else { continue };
        let Some(gray) = decode_gray(raw) else {
            tracing::debug!("[earthquake] tile {tx}/{ty} decode error");
            continue;
        };
        let at = (
            ((tx * TILE_SIZE) as f64 - origin_x) as i64,
            ((ty * TILE_SIZE) as f64 - origin_y) as i64,
        );
        paste_rgb(&mut base, &recolour_tile(&gray), at);
    }
    base
}
