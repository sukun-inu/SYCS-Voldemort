//! 緯度・経度から地図の画素への計算（Web メルカトル）と、県庁所在地・県の形の表。
//! Python の `_latlon_to_tile_float`・`_project`・`_PREF_CENTERS`・`_load_prefecture_shapes`。
//!
//! 画素の位置は、ここで出した小数を 0 の方へ切り捨てて決まる。Python と最後の桁まで同じ数を出さないと、
//! 境のところで 1 画素ずれる。そこで:
//!
//! - `asinh` は、本番（FMA の無い CPU）の Python が呼ぶ glibc 2.41 のもの（fdlibm 由来。FMA を使わない版）を
//!   そのまま写した（[`asinh`]）。Rust の標準の `f64::asinh` も Linux では glibc の `asinh` を呼ぶが、glibc は
//!   CPU に FMA があると別の版を選ぶので、機械によって最後の桁が変わる（下）。写しなら、どの機械でも本番の
//!   Python と同じ値になる。
//! - `tan` は標準の `f64::tan`（Linux では glibc の `tan`。Python も同じものを呼ぶ）。
//! - 掛け算・割り算の順は Python の式のまま。
//!
//! Python 自身も、CPU に FMA があるかどうかで glibc が別の版を選び、最後の桁が変わることがある（160 万件に
//! 対して `tan` が 6 件、`asinh` が 610 件）。本番（Sandy Bridge）は FMA なしなので、基準は FMA なしで
//! 作ってある。

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value;

use super::tiles::TILE_SIZE;

// ── glibc 2.41 の asinh・log1p の写し ─────────────────────────
//
// 元は fdlibm（s_asinh.c・s_log1p.c）。元の注記:
//
//   Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
//
//   Developed at SunPro, a Sun Microsystems, Inc. business.
//   Permission to use, copy, modify, and distribute this
//   software is freely granted, provided that this notice
//   is preserved.
//
// log1p は glibc に入っている形（多項式を 4 つに分けて足す。Naohiko Shimizu/Tokai University による変更）。

/// 上の 32 ビットを符号つきの整数で（`GET_HIGH_WORD`）。
fn high_word(x: f64) -> i32 {
    (x.to_bits() >> 32) as u32 as i32
}

/// 上の 32 ビットを差し替える（`SET_HIGH_WORD`）。
fn with_high_word(x: f64, high: i32) -> f64 {
    f64::from_bits((u64::from(high as u32) << 32) | (x.to_bits() & 0xFFFF_FFFF))
}

/// glibc 2.41 の `__log1p`（FMA を使わない版）。
fn log1p(x: f64) -> f64 {
    // 定数は、原典に書いてある 16 進の形（ビットの並び）で持つ。
    const LN2_HI: f64 = f64::from_bits(0x3fe6_2e42_fee0_0000);
    const LN2_LO: f64 = f64::from_bits(0x3dea_39ef_3579_3c76);
    const TWO_THIRDS: f64 = f64::from_bits(0x3fe5_5555_5555_5555);
    const LP: [f64; 8] = [
        0.0,
        f64::from_bits(0x3fe5_5555_5555_5593),
        f64::from_bits(0x3fd9_9999_9997_fa04),
        f64::from_bits(0x3fd2_4924_9422_9359),
        f64::from_bits(0x3fcc_71c5_1d8e_78af),
        f64::from_bits(0x3fc7_4664_96cb_03de),
        f64::from_bits(0x3fc3_9a09_d078_c69f),
        f64::from_bits(0x3fc2_f112_df3e_5244),
    ];
    let hx = high_word(x);
    let ax = hx & 0x7fff_ffff;
    let mut k: i32 = 1;
    let mut f = 0.0;
    let mut hu: i32 = 0;
    let mut c = 0.0;
    if hx < 0x3FDA_827A {
        // x < 0.41422
        if ax >= 0x3ff0_0000 {
            // x <= -1.0
            // 原典は -two54/zero（-∞）と (x-x)/(x-x)（非数）。
            return if x == -1.0 {
                f64::NEG_INFINITY
            } else {
                f64::NAN
            };
        }
        if ax < 0x3e20_0000 {
            // |x| < 2**-29
            return if ax < 0x3c90_0000 { x } else { x - x * x * 0.5 };
        }
        if hx > 0 || hx <= (0xbfd2_bec3_u32 as i32) {
            // -0.2929 < x < 0.41422
            k = 0;
            f = x;
            hu = 1;
        }
    } else if hx >= 0x7ff0_0000 {
        return x + x;
    }
    if k != 0 {
        let mut u;
        if hx < 0x4340_0000 {
            u = 1.0 + x;
            hu = high_word(u);
            k = (hu >> 20) - 1023;
            // 丸めで落ちた分の補正。
            c = if k > 0 { 1.0 - (u - x) } else { x - (u - 1.0) };
            c /= u;
        } else {
            u = x;
            hu = high_word(u);
            k = (hu >> 20) - 1023;
            c = 0.0;
        }
        hu &= 0x000f_ffff;
        if hu < 0x6a09e {
            u = with_high_word(u, hu | 0x3ff0_0000);
        } else {
            k += 1;
            u = with_high_word(u, hu | 0x3fe0_0000);
            hu = (0x0010_0000 - hu) >> 2;
        }
        f = u - 1.0;
    }
    let hfsq = 0.5 * f * f;
    let kf = f64::from(k);
    if hu == 0 {
        // |f| < 2**-20
        if f == 0.0 {
            if k == 0 {
                return 0.0;
            }
            c += kf * LN2_LO;
            return kf * LN2_HI + c;
        }
        let r = hfsq * (1.0 - TWO_THIRDS * f);
        return if k == 0 {
            f - r
        } else {
            kf * LN2_HI - ((r - (kf * LN2_LO + c)) - f)
        };
    }
    let s = f / (2.0 + f);
    let z = s * s;
    let r1 = z * LP[1];
    let z2 = z * z;
    let r2 = LP[2] + z * LP[3];
    let z4 = z2 * z2;
    let r3 = LP[4] + z * LP[5];
    let z6 = z4 * z2;
    let r4 = LP[6] + z * LP[7];
    let r = r1 + z2 * r2 + z4 * r3 + z6 * r4;
    if k == 0 {
        f - (hfsq - s * (hfsq + r))
    } else {
        kf * LN2_HI - ((hfsq - (s * (hfsq + r) + (kf * LN2_LO + c))) - f)
    }
}

/// Python の `math.asinh`（glibc 2.41 の `__asinh`）。
///
/// `|x| <= 2`（緯度でいうと ±63.4 度まで。日本は全部この中）は、最後の桁まで Python と同じになる。それより
/// 大きい `x` は中で `log` を使い、そこは標準の `f64::ln` に任せている（glibc の `log` の写しではないので、
/// 最後の桁まで同じとは限らない）。
pub fn asinh(x: f64) -> f64 {
    const LN2: f64 = f64::from_bits(0x3fe6_2e42_fefa_39ef);
    const HUGE: f64 = 1.0e300;
    let ix = high_word(x) & 0x7fff_ffff;
    if ix < 0x3e30_0000 && HUGE + x > 1.0 {
        // |x| < 2**-28
        return x;
    }
    let w = if ix > 0x41b0_0000 {
        // |x| > 2**28
        if ix >= 0x7ff0_0000 {
            return x + x;
        }
        x.abs().ln() + LN2
    } else {
        let xa = x.abs();
        if ix > 0x4000_0000 {
            // 2**28 > |x| > 2.0
            (2.0 * xa + 1.0 / ((xa * xa + 1.0).sqrt() + xa)).ln()
        } else {
            let t = xa * xa;
            log1p(xa + t / (1.0 + (1.0 + t).sqrt()))
        }
    };
    w.copysign(x)
}

// ── メルカトル ───────────────────────────────────────────

/// 緯度の `tan` から、タイルの y（小数）。Python の `_latlon_to_tile_float` の y の式のうち `tan` より後
/// （`(1 - asinh(t) / pi) / 2 * n`）。
///
/// `tan` だけは機械の libm に任せるので、そこを切り離して確かめられるように分けてある（ここから先は、どの
/// 機械でも Python と最後のビットまで同じ）。
pub fn tile_y_from_tan(tan: f64, zoom: u32) -> f64 {
    let n = f64::from(1_u32 << zoom);
    (1.0 - asinh(tan) / std::f64::consts::PI) / 2.0 * n
}

/// 緯度・経度を、タイルの座標（小数）にする。Python の `_latlon_to_tile_float`。
pub fn latlon_to_tile(lat: f64, lon: f64, zoom: u32) -> (f64, f64) {
    let n = f64::from(1_u32 << zoom);
    let tx = (lon + 180.0) / 360.0 * n;
    // math.radians は「x * (pi / 180)」。
    let lat_r = lat * (std::f64::consts::PI / 180.0);
    (tx, tile_y_from_tan(lat_r.tan(), zoom))
}

/// 経度・緯度の点を、タイルの座標の画素にする。Python の `_project`（numpy で同じ式を計算している）。
pub fn project(point: (f64, f64), zoom: u32) -> (f64, f64) {
    let (lon, lat) = point;
    let (tx, ty) = latlon_to_tile(lat, lon, zoom);
    (tx * TILE_SIZE as f64, ty * TILE_SIZE as f64)
}

// ── 県庁所在地 ───────────────────────────────────────────

/// 都道府県の中心（県庁所在地）の緯度・経度。Python の `_PREF_CENTERS`。
pub const PREF_CENTERS: [(&str, f64, f64); 47] = [
    ("北海道", 43.064, 141.347),
    ("青森県", 40.824, 140.740),
    ("岩手県", 39.703, 141.153),
    ("宮城県", 38.268, 140.872),
    ("秋田県", 39.718, 140.102),
    ("山形県", 38.240, 140.363),
    ("福島県", 37.750, 140.468),
    ("茨城県", 36.341, 140.447),
    ("栃木県", 36.565, 139.883),
    ("群馬県", 36.391, 139.060),
    ("埼玉県", 35.857, 139.649),
    ("千葉県", 35.605, 140.123),
    ("東京都", 35.689, 139.692),
    ("神奈川県", 35.447, 139.642),
    ("新潟県", 37.902, 139.023),
    ("富山県", 36.695, 137.211),
    ("石川県", 36.594, 136.626),
    ("福井県", 36.065, 136.222),
    ("山梨県", 35.664, 138.568),
    ("長野県", 36.651, 138.181),
    ("岐阜県", 35.391, 136.722),
    ("静岡県", 34.977, 138.383),
    ("愛知県", 35.180, 136.906),
    ("三重県", 34.730, 136.509),
    ("滋賀県", 35.004, 135.869),
    ("京都府", 35.021, 135.756),
    ("大阪府", 34.686, 135.520),
    ("兵庫県", 34.691, 135.183),
    ("奈良県", 34.685, 135.833),
    ("和歌山県", 34.226, 135.167),
    ("鳥取県", 35.503, 134.238),
    ("島根県", 35.472, 133.051),
    ("岡山県", 34.661, 133.934),
    ("広島県", 34.396, 132.460),
    ("山口県", 34.186, 131.471),
    ("徳島県", 34.066, 134.559),
    ("香川県", 34.340, 134.043),
    ("愛媛県", 33.842, 132.766),
    ("高知県", 33.560, 133.531),
    ("福岡県", 33.606, 130.418),
    ("佐賀県", 33.249, 130.299),
    ("長崎県", 32.745, 129.874),
    ("熊本県", 32.789, 130.742),
    ("大分県", 33.238, 131.613),
    ("宮崎県", 31.911, 131.424),
    ("鹿児島県", 31.560, 130.558),
    ("沖縄県", 26.212, 127.681),
];

/// 都道府県の名前から中心の緯度・経度を引く。
pub fn pref_centre(name: &str) -> Option<(f64, f64)> {
    PREF_CENTERS
        .iter()
        .find(|(pref, _, _)| *pref == name)
        .map(|(_, lat, lon)| (*lat, *lon))
}

// ── 県の形 ──────────────────────────────────────────────

/// 県の名前 → 輪の並び。輪は（経度, 緯度）の点の並び。
pub type Shapes = HashMap<String, Vec<Vec<(f64, f64)>>>;

/// 県の形のデータ（`assets/jp_prefectures.json` と同じ中身。`tools/build_pref_polygons.py` が作る）。
///
/// 出典: 地球地図日本 第2.1版 行政界（国土地理院）を加工して作成。Bot のイメージは `rust/` だけでビルドする
/// ので、リポジトリの直下のものと同じファイルを `apps/bot/assets/` にも置いて埋め込んでいる
/// （同じであることは下のテストが見張る）。
const SHAPE_JSON: &str = include_str!("../../assets/jp_prefectures.json");

/// 県の形を JSON から読む。Python の `_load_prefecture_shapes` の中身。
///
/// 各輪は `[x0, y0, dx1, dy1, …]` の差分の並びで、足し戻してから `unit` で割る（numpy の
/// `cumsum(…) / unit` と同じ順）。
pub fn parse_shapes(json: &str) -> Result<Shapes, String> {
    let payload: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let unit = match payload.get("unit").and_then(Value::as_f64) {
        Some(unit) if unit != 0.0 => unit,
        _ => 1000.0,
    };
    let mut shapes = Shapes::new();
    let Some(prefectures) = payload.get("prefectures").and_then(Value::as_object) else {
        return Ok(shapes);
    };
    for (name, rings) in prefectures {
        let mut built = Vec::new();
        for ring in rings.as_array().ok_or("輪の並びではありません")? {
            let flat: Vec<f64> = ring
                .as_array()
                .ok_or("輪が数の並びではありません")?
                .iter()
                .map(|v| v.as_f64().ok_or("輪に数でないものがあります"))
                .collect::<Result<_, _>>()?;
            if !flat.len().is_multiple_of(2) {
                return Err("輪の数の個数が奇数です".into());
            }
            let (mut x, mut y) = (0.0, 0.0);
            let (steps, _) = flat.as_chunks::<2>();
            let points = steps
                .iter()
                .map(|[dx, dy]| {
                    x += dx;
                    y += dy;
                    (x / unit, y / unit)
                })
                .collect();
            built.push(points);
        }
        if !built.is_empty() {
            shapes.insert(name.clone(), built);
        }
    }
    Ok(shapes)
}

/// 県の形（読むのは 1 回だけ）。読めなければ空（県を塗らずに、地図と札は出す。Python と同じ）。
pub fn prefecture_shapes() -> &'static Shapes {
    static SHAPES: LazyLock<Shapes> = LazyLock::new(|| {
        parse_shapes(SHAPE_JSON).unwrap_or_else(|e| {
            tracing::warn!("[earthquake] 県の輪郭を読めませんでした（塗りなしで描きます）: {e}");
            Shapes::new()
        })
    });
    &SHAPES
}
