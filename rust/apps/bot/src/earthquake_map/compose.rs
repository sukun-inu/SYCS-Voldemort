//! 震度の地図の組み立て。Python の `_generate_intensity_map`（タイルを取る前まで）と
//! `_compose_intensity_map` 以下（`_fill_prefectures`・`_place_badges`・`_draw_epicentre`・`_scale_badge`・
//! `_draw_place_labels`・`_draw_map_chrome`）。
//!
//! 描く順に意味がある（Python と同じ）: タイルの面 → 県の塗り → 震源の座と印 → 震度の札（弱い順）→ 地名 →
//! 題の帯・凡例・出典。全部を 2 倍の大きさで描いてから LANCZOS で縮める（Pillow の図形は縁をなめらかに
//! しないので、縮小がその代わりになる）。
//!
//! 数の計算は Python の式の形・順のまま（小数を整数にするところは `int()` と同じ「0 の方へ切り捨て」）。
//! 文字は [`TextPainter`] を通して描く。

use image::{RgbImage, RgbaImage};
use serde_json::Value;

use super::geo::{self, Shapes};
use super::tiles::{self, MAP_SIZE, TILE_SIZE};
use crate::earthquake_text::{Anchor, FontSpec, TextPainter};
use sycs_imaging::draw::{self, ShapeError};
use sycs_imaging::raster;

/// 描くときの倍率（描いてから、この分だけ縮める）。Python の `_MAP_SS`。
pub const MAP_SS: i64 = 2;
/// 出典の文。Python の `_TILE_ATTRIBUTION`。
pub const TILE_ATTRIBUTION: &str = "地理院タイル・地球地図日本（国土地理院）を加工して作成";
/// 表に無い震度の色。Python の `_MAP_FILL_RGB.get(scale, (120, 130, 150))` の既定。
const UNKNOWN_RGB: [u8; 3] = [120, 130, 150];

/// 地図を作れなかった理由（Python では例外になり、地図なしで通知が出る）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// 図形を描けなかった。
    Shape(ShapeError),
    /// 位置が数として読めない（無限大・非数）。
    NotFinite,
    /// 観測点の形が崩れている（辞書でない・震度が数でない など）。
    BadPoint,
}

impl From<ShapeError> for MapError {
    fn from(e: ShapeError) -> Self {
        Self::Shape(e)
    }
}

/// 震度の値（P2P地震情報の 10・20・…・70）。表に無い値も、そのまま持つ。
#[derive(Clone, Debug, PartialEq)]
pub struct Scale {
    /// 値。
    pub value: f64,
    /// Python の `str(scale)`（表に無い震度のときに、札に書く字）。
    pub text: String,
}

impl Scale {
    /// 整数の震度の値から作る。
    pub fn new(value: i64) -> Self {
        Self {
            value: value as f64,
            text: value.to_string(),
        }
    }

    /// 表（10〜70 の 9 通り）の何番目か。
    fn known(&self) -> Option<usize> {
        [10.0, 20.0, 30.0, 40.0, 45.0, 50.0, 55.0, 60.0, 70.0]
            .iter()
            .position(|v| *v == self.value)
    }

    /// 塗りと札の色。Python の `_MAP_FILL_RGB`。
    pub fn fill_rgb(&self) -> [u8; 3] {
        const TABLE: [[u8; 3]; 9] = [
            [58, 122, 216],
            [46, 158, 214],
            [44, 176, 154],
            [226, 192, 62],
            [232, 152, 48],
            [233, 119, 43],
            [226, 78, 44],
            [206, 47, 62],
            [132, 44, 128],
        ];
        self.known().map_or(UNKNOWN_RGB, |i| TABLE[i])
    }

    /// 札に書く字。Python の `_SCALE_BADGE_LABEL`（表に無ければ値そのもの）。
    pub fn badge_label(&self) -> &str {
        const TABLE: [&str; 9] = ["1", "2", "3", "4", "5-", "5+", "6-", "6+", "7"];
        self.known().map_or(self.text.as_str(), |i| TABLE[i])
    }

    /// 札の一辺（倍率を掛ける前）。強いほど大きい。Python の `_badge_size`。
    pub fn badge_size(&self) -> i64 {
        match self.value {
            v if v >= 55.0 => 34,
            v if v >= 45.0 => 30,
            v if v >= 40.0 => 26,
            v if v >= 30.0 => 22,
            _ => 18,
        }
    }

    /// 県を塗る濃さ。強いほど濃い。Python の `_fill_alpha`。
    pub fn fill_alpha(&self) -> u8 {
        (84 + (self.value.min(70.0) / 70.0 * 96.0) as i64).clamp(0, 255) as u8
    }
}

/// その色の上に置く文字の色。明るい色の上では白が沈むので、暗い字にする。Python の `_ink_for`。
pub fn ink_for(rgb: [u8; 3]) -> [u8; 4] {
    let luma = 0.2126 * f64::from(rgb[0]) + 0.7152 * f64::from(rgb[1]) + 0.0722 * f64::from(rgb[2]);
    if luma > 150.0 {
        [16, 20, 26, 255]
    } else {
        [255, 255, 255, 255]
    }
}

/// 色にアルファを足す。
fn rgba(rgb: [u8; 3], alpha: u8) -> [u8; 4] {
    [rgb[0], rgb[1], rgb[2], alpha]
}

/// Python の `int()`（0 の方へ切り捨て）。
fn int(v: f64) -> i64 {
    v as i64
}

/// 地図に打つ 1 点（県ごとに 1 つ）。
#[derive(Clone, Debug, PartialEq)]
pub struct PlotPoint {
    /// 緯度（県庁所在地）。
    pub lat: f64,
    /// 経度。
    pub lon: f64,
    /// 震度。
    pub scale: Scale,
    /// 地名（県の名前。県の塗りと地名の札に使う）。
    pub name: String,
}

/// Python の真偽（`bool(value)`）。
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python の `str(value)`（県の名前に入りうるもの）。
fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

/// 観測点（電文の `points`）から、地図に打つ点を作る。Python の `_generate_intensity_map` の最初の繰り返し。
///
/// 震度 1 未満（10 未満）・県の分からない点は飛ばす。位置は県庁所在地（県の名前 `pref`、無ければ `addr` で
/// 引く）。形の崩れた点（辞書でない・震度が数でない・`addr` が並びや辞書）は、Python では例外になって地図が
/// 出ないので、ここでも `Err` にする。
pub fn plot_points(points: &[Value]) -> Result<Vec<PlotPoint>, MapError> {
    let mut plot = Vec::new();
    for point in points {
        let point = point.as_object().ok_or(MapError::BadPoint)?;
        let scale = match point.get("scale") {
            // 無ければ -1、真偽値は 1 か 0。どちらも 10 未満。
            None | Some(Value::Bool(_)) => continue,
            Some(Value::Number(n)) => n,
            Some(_) => return Err(MapError::BadPoint),
        };
        let value = scale.as_f64().ok_or(MapError::BadPoint)?;
        if value < 10.0 {
            continue;
        }
        let pref = point
            .get("pref")
            .filter(|v| truthy(v))
            .map(python_str)
            .unwrap_or_default();
        let addr = point.get("addr");
        let coord = match geo::pref_centre(&pref) {
            Some(coord) => Some(coord),
            None => match addr {
                Some(Value::String(name)) => geo::pref_centre(name),
                // 並びと辞書は、Python では表を引く鍵にできない（TypeError）。
                Some(Value::Array(_) | Value::Object(_)) => return Err(MapError::BadPoint),
                _ => None,
            },
        };
        let Some((lat, lon)) = coord else { continue };
        let name = if pref.is_empty() {
            addr.filter(|v| truthy(v))
                .map(python_str)
                .unwrap_or_default()
        } else {
            pref
        };
        plot.push(PlotPoint {
            lat,
            lon,
            scale: Scale {
                value,
                text: scale.to_string(),
            },
            name,
        });
    }
    Ok(plot)
}

/// 同じ場所の点を、いちばん強い震度の 1 つにまとめる（先に出た順を保つ）。
///
/// 観測点の位置は県庁所在地に丸めてあるので、同じ県の点は全部ひとつの場所に重なる。Python の
/// `_generate_intensity_map` の `strongest`。
pub fn strongest_per_place(points: Vec<PlotPoint>) -> Vec<PlotPoint> {
    let mut out: Vec<PlotPoint> = Vec::new();
    for point in points {
        match out
            .iter_mut()
            .find(|p| p.lat == point.lat && p.lon == point.lon)
        {
            Some(kept) => {
                if point.scale.value > kept.scale.value {
                    kept.scale = point.scale;
                    kept.name = point.name;
                }
            }
            None => out.push(point),
        }
    }
    out
}

/// どこを・どの大きさで描くか。
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    /// 打つ点（まとめた後）。
    pub plot: Vec<PlotPoint>,
    /// ズーム（5〜11）。
    pub zoom: u32,
    /// 地図の左上の、タイルの座標での画素の位置。
    pub origin_x: f64,
    /// 同じく縦。
    pub origin_y: f64,
    /// 要るタイル（x・y）。上の行から、左から。
    pub coords: Vec<(i64, i64)>,
}

/// 全部の点と震源が入り、余白が残る、いちばん大きなズームと範囲を決める。Python の
/// `_generate_intensity_map` の前半。点が無ければ `None`（地図を作らない）。
pub fn plan(lat: f64, lon: f64, points: Vec<PlotPoint>) -> Option<Plan> {
    if points.is_empty() {
        return None;
    }
    let plot = strongest_per_place(points);
    // 点と震源の全部が入る範囲。
    let max_lat = plot.iter().map(|p| p.lat).fold(lat, f64::max);
    let min_lat = plot.iter().map(|p| p.lat).fold(lat, f64::min);
    let max_lon = plot.iter().map(|p| p.lon).fold(lon, f64::max);
    let min_lon = plot.iter().map(|p| p.lon).fold(lon, f64::min);
    let (map_w, map_h) = (f64::from(MAP_SIZE.0), f64::from(MAP_SIZE.1));
    let tile = TILE_SIZE as f64;

    let mut zoom = 5;
    for candidate in (5..=11).rev() {
        let (x0, y0) = geo::latlon_to_tile(max_lat, min_lon, candidate);
        let (x1, y1) = geo::latlon_to_tile(min_lat, max_lon, candidate);
        // 上の帯と凡例の分だけ、縦を控えめにする。
        if (x1 - x0).abs() * tile < map_w * 0.92 && (y1 - y0).abs() * tile < map_h * 0.84 {
            zoom = candidate;
            break;
        }
    }
    let (centre_x, centre_y) =
        geo::latlon_to_tile((max_lat + min_lat) / 2.0, (max_lon + min_lon) / 2.0, zoom);
    let origin_x = centre_x * tile - map_w / 2.0;
    let origin_y = centre_y * tile - map_h / 2.0;
    if !origin_x.is_finite() || !origin_y.is_finite() {
        // Python は int(nan) で例外になり、地図を作らない。
        return None;
    }
    let (tx0, ty0) = (
        int((origin_x / tile).floor()),
        int((origin_y / tile).floor()),
    );
    let tx1 = int(((origin_x + map_w) / tile).floor());
    let ty1 = int(((origin_y + map_h) / tile).floor());
    let coords = (ty0..=ty1)
        .flat_map(|ty| (tx0..=tx1).map(move |tx| (tx, ty)))
        .collect();
    Some(Plan {
        plot,
        zoom,
        origin_x,
        origin_y,
        coords,
    })
}

/// 緯度・経度を、描く面（2 倍の大きさ）の画素の位置にする。Python の `to_px`。
fn to_px(plan: &Plan, lat: f64, lon: f64) -> (f64, f64) {
    let (px, py) = geo::latlon_to_tile(lat, lon, plan.zoom);
    let (tile, ss) = (TILE_SIZE as f64, MAP_SS as f64);
    (
        (px * tile - plan.origin_x) * ss,
        (py * tile - plan.origin_y) * ss,
    )
}

/// 揺れた県を、その震度の色で塗る。Python の `_fill_prefectures`。
///
/// 弱い順に塗る（県境が接しているところは、あとから塗る強い方が残る）。透明な層に上書きで塗ってから、
/// 層ごと重ねる。
pub fn fill_prefectures(
    canvas: &mut RgbaImage,
    plan: &Plan,
    shapes: &Shapes,
) -> Result<(), MapError> {
    if shapes.is_empty() {
        return Ok(());
    }
    let (width, height) = (f64::from(canvas.width()), f64::from(canvas.height()));
    let ss = MAP_SS as f64;
    let mut layer = RgbaImage::new(canvas.width(), canvas.height());
    let mut order: Vec<&PlotPoint> = plan.plot.iter().collect();
    order.sort_by(|a, b| a.scale.value.total_cmp(&b.scale.value));
    for point in order {
        let Some(rings) = shapes.get(&point.name) else {
            continue;
        };
        let paint = rgba(point.scale.fill_rgb(), point.scale.fill_alpha());
        for ring in rings {
            let px: Vec<(f64, f64)> = ring
                .iter()
                .map(|p| {
                    let (x, y) = geo::project(*p, plan.zoom);
                    ((x - plan.origin_x) * ss, (y - plan.origin_y) * ss)
                })
                .collect();
            let x_max = px.iter().map(|p| p.0).fold(f64::NEG_INFINITY, f64::max);
            let x_min = px.iter().map(|p| p.0).fold(f64::INFINITY, f64::min);
            let y_max = px.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
            let y_min = px.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
            // 画面の外に出ている輪は描かない。
            if x_max < 0.0 || x_min > width || y_max < 0.0 || y_min > height {
                continue;
            }
            draw::polygon(&mut layer, &px, paint)?;
        }
    }
    raster::alpha_composite(canvas, &layer, (0, 0));
    Ok(())
}

/// `area` が `taken` のどれかと重なっているか（四角は左・上・右・下。辺が接するだけなら重ならない）。
/// Python の `_overlaps`。
pub fn overlaps(area: (f64, f64, f64, f64), taken: &[(f64, f64, f64, f64)]) -> bool {
    taken
        .iter()
        .any(|r| !(area.2 <= r.0 || area.0 >= r.2 || area.3 <= r.1 || area.1 >= r.3))
}

/// 強い順に並べた点（同じ震度は元の順）。札を置くときと、地名を置くときの順。
fn strongest_first(plot: &[PlotPoint]) -> Vec<&PlotPoint> {
    let mut order: Vec<&PlotPoint> = plot.iter().collect();
    order.sort_by(|a, b| b.scale.value.total_cmp(&a.scale.value));
    order
}

/// 札の置き場所。
struct Placement {
    /// ふさがっている四角（札・震源・地名）。
    taken: Vec<(f64, f64, f64, f64)>,
    /// 置いた札（x・y・震度）。置いた順（強い順）。
    badges: Vec<(f64, f64, Scale)>,
    /// 強い順に並べた点のうち、札を置けたもの。
    placed: Vec<bool>,
}

/// 札の置き場所を決める。Python の `_place_badges`。
///
/// 強い順に置いて、もう置いた札と重なるものは落とす。先頭（最大震度）は無条件で置く。
fn place_badges(plan: &Plan) -> Placement {
    let ss = MAP_SS as f64;
    let mut placement = Placement {
        taken: Vec::new(),
        badges: Vec::new(),
        placed: Vec::new(),
    };
    for (index, point) in strongest_first(&plan.plot).into_iter().enumerate() {
        let (x, y) = to_px(plan, point.lat, point.lon);
        let half = point.scale.badge_size() as f64 * ss / 2.0;
        let area = (x - half, y - half, x + half, y + half);
        if index != 0 && overlaps(area, &placement.taken) {
            placement.placed.push(false);
            continue;
        }
        placement.taken.push(area);
        placement.badges.push((x, y, point.scale.clone()));
        placement.placed.push(true);
    }
    placement
}

/// 震度の札（角丸の座に数字）。Python の `_scale_badge`。`size` は倍率を掛けた後の一辺。
pub fn scale_badge(
    scale: &Scale,
    size: i64,
    text: &dyn TextPainter,
) -> Result<RgbaImage, MapError> {
    let rgb = scale.fill_rgb();
    let label = scale.badge_label();
    let pad = size / 3;
    let edge = (size + pad * 2) as u32;
    let (p, s) = (pad as f64, size as f64);
    let radius = (size / 4) as f64;
    let mut img = RgbaImage::new(edge, edge);

    // 落ち影。暗い地図の上で札の縁が溶けないように、下に薄く敷く。
    let mut shade = RgbaImage::new(edge, edge);
    let drop = (size / 10) as f64;
    draw::rounded_rectangle(
        &mut shade,
        [p, p + drop, p + s, p + s + drop],
        radius,
        Some([0, 0, 0, 165]),
        None,
        1,
    )?;
    raster::alpha_composite(&mut img, &raster::gaussian_blur(&shade, s / 8.0), (0, 0));

    draw::rounded_rectangle(
        &mut img,
        [p, p, p + s, p + s],
        radius,
        Some(rgba(rgb, 255)),
        Some([255, 255, 255, 210]),
        (size / 14).max(1) as i32,
    )?;
    // 「5-」のような 2 文字は、1 文字より小さく組む。
    let ratio = if label.chars().count() == 1 {
        0.60
    } else {
        0.44
    };
    let font = FontSpec {
        size: int(s * ratio) as u32,
        bold: false,
    };
    let at = (p + s / 2.0, p + s / 2.0 + (size / 28) as f64);
    text.draw_text(&mut img, at, label, font, ink_for(rgb), Anchor(*b"mm"));
    Ok(img)
}

/// 震源の印（二重の輪と十字）。Python の `_epicentre_marker`。
pub fn epicentre_marker(size: i64) -> Result<RgbaImage, MapError> {
    let mut img = RgbaImage::new(size as u32, size as u32);
    let centre = size as f64 / 2.0;
    let radius = size as f64 / 2.0 - (size / 10) as f64;
    for (r, width, alpha) in [
        (radius, (size / 12).max(1), 255),
        (radius * 0.62, (size / 14).max(1), 210),
    ] {
        draw::ellipse(
            &mut img,
            [centre - r, centre - r, centre + r, centre + r],
            None,
            Some([255, 72, 72, alpha]),
            width as i32,
        )?;
    }
    let arm = radius * 1.16;
    for (dx, dy) in [(1.0, 0.0), (0.0, 1.0)] {
        draw::line(
            &mut img,
            &[
                (centre - arm * dx, centre - arm * dy),
                (centre + arm * dx, centre + arm * dy),
            ],
            [255, 72, 72, 255],
            (size / 12).max(1) as i32,
        );
    }
    Ok(img)
}

/// 震源の座の濃さ（中心が濃く、外へなめらかに抜ける円）。一辺 `seat_r * 2` の正方形の並び。
///
/// numpy と同じ式（float64）: `120 * clip(1 - hypot(x - r + 0.5, y - r + 0.5) / r, 0, 1) ** 1.1` を
/// 0 の方へ切り捨てる。
pub fn seat_alpha(seat_r: i64) -> Vec<u8> {
    let side = seat_r * 2;
    let r = seat_r as f64;
    let mut out = Vec::with_capacity((side * side) as usize);
    for y in 0..side {
        for x in 0..side {
            let dist = ((x - seat_r) as f64 + 0.5).hypot((y - seat_r) as f64 + 0.5) / r;
            out.push((120.0 * (1.0 - dist).clamp(0.0, 1.0).powf(1.1)) as u8);
        }
    }
    out
}

/// 震源の座（淡い影）と印を置く。Python の `_draw_epicentre`。札より先に呼ぶ。
pub fn draw_epicentre(canvas: &mut RgbaImage, ex: f64, ey: f64) -> Result<(), MapError> {
    let seat_r = 30 * MAP_SS;
    let side = (seat_r * 2) as u32;
    let mut seat = RgbaImage::from_pixel(side, side, image::Rgba([8, 11, 17, 0]));
    for (pixel, alpha) in seat.pixels_mut().zip(seat_alpha(seat_r)) {
        pixel.0[3] = alpha;
    }
    let r = seat_r as f64;
    raster::alpha_composite(canvas, &seat, (int(ex - r), int(ey - r)));
    let marker = epicentre_marker(40 * MAP_SS)?;
    let half = f64::from(marker.width()) / 2.0;
    raster::alpha_composite(canvas, &marker, (int(ex - half), int(ey - half)));
    Ok(())
}

/// 地名の札に使う字。
const LABEL_FONT: FontSpec = FontSpec {
    size: 13 * MAP_SS as u32,
    bold: false,
};

/// 地名の札の大きさ（幅・高さ）。Python の `_label_box`。
pub fn label_box(text: &dyn TextPainter, name: &str) -> (i64, i64) {
    let width = int(text.text_length(name, LABEL_FONT));
    (width + 12 * MAP_SS, 19 * MAP_SS)
}

/// 地名の札を 1 枚置く。Python の `_draw_place_label`。暗い座を敷いてから字を置く。
pub fn draw_place_label(
    canvas: &mut RgbaImage,
    left: f64,
    top: f64,
    name: &str,
    text: &dyn TextPainter,
) -> Result<(), MapError> {
    let (width, height) = label_box(text, name);
    let mut area = RgbaImage::new(width as u32, height as u32);
    draw::rounded_rectangle(
        &mut area,
        [0.0, 0.0, (width - 1) as f64, (height - 1) as f64],
        (5 * MAP_SS) as f64,
        Some([10, 14, 21, 214]),
        Some([120, 140, 170, 110]),
        (MAP_SS / 2).max(1) as i32,
    )?;
    raster::alpha_composite(canvas, &area, (int(left), int(top)));
    text.draw_text(
        canvas,
        (left + (6 * MAP_SS) as f64, top + height as f64 / 2.0),
        name,
        LABEL_FONT,
        [232, 238, 246, 255],
        Anchor(*b"lm"),
    );
    Ok(())
}

/// 地名を、強い方から 5 点まで置く。Python の `_draw_place_labels`。
///
/// 札を置けた点にだけ付ける。右 → 左 → 上 → 下の順に、空いているところを探す。
fn draw_place_labels(
    canvas: &mut RgbaImage,
    plan: &Plan,
    placement: &mut Placement,
    text: &dyn TextPainter,
) -> Result<(), MapError> {
    let ss = MAP_SS as f64;
    let canvas_width = f64::from(canvas.width());
    for (index, point) in strongest_first(&plan.plot).into_iter().enumerate().take(5) {
        if point.name.is_empty() || !placement.placed[index] {
            continue;
        }
        let (x, y) = to_px(plan, point.lat, point.lon);
        let half = point.scale.badge_size() as f64 * ss / 2.0;
        let (label_w, label_h) = label_box(text, &point.name);
        let (label_w, label_h) = (label_w as f64, label_h as f64);
        for (dx, dy) in [
            (half + 5.0 * ss, 0.0),
            (-half - 5.0 * ss - label_w, 0.0),
            (-label_w / 2.0, -half - label_h / 2.0 - 3.0 * ss),
            (-label_w / 2.0, half + label_h / 2.0 + 3.0 * ss),
        ] {
            let (lx, ly) = (x + dx, y + dy - label_h / 2.0);
            let label = (lx, ly, lx + label_w, ly + label_h);
            if 0.0 <= label.0 && label.2 <= canvas_width && !overlaps(label, &placement.taken) {
                placement.taken.push(label);
                draw_place_label(canvas, label.0, label.1, &point.name, text)?;
                break;
            }
        }
    }
    Ok(())
}

/// 題の帯の、行ごとの濃さ（上が濃く、下へ抜ける）。`215 * (1 - 行 / 高さ) ** 1.3` を 0 の方へ切り捨てる。
pub fn band_alpha(band_h: i64) -> Vec<u8> {
    (0..band_h)
        .map(|row| (215.0 * (1.0 - row as f64 / band_h as f64).powf(1.3)) as u8)
        .collect()
}

/// 凡例に並べる震度（重なりを除いて、弱い順）。Python の `sorted({point[2] for point in plot})`。
pub fn legend_scales(plot: &[PlotPoint]) -> Vec<Scale> {
    let mut scales: Vec<Scale> = Vec::new();
    for point in plot {
        if !scales.iter().any(|s| s.value == point.scale.value) {
            scales.push(point.scale.clone());
        }
    }
    scales.sort_by(|a, b| a.value.total_cmp(&b.value));
    scales
}

/// 題の帯・凡例・出典。Python の `_draw_map_chrome`。
pub fn draw_map_chrome(
    canvas: &mut RgbaImage,
    title: &str,
    subtitle: &str,
    scales: &[Scale],
    text: &dyn TextPainter,
) -> Result<(), MapError> {
    let ss = MAP_SS;
    let (width, height) = (i64::from(canvas.width()), i64::from(canvas.height()));
    let regular = |size: i64| FontSpec {
        size: size as u32,
        bold: false,
    };
    let top_left = Anchor(*b"la");

    // 題の帯（上から下へ薄くなる暗い帯）。
    let band_h = 74 * ss;
    let mut band = RgbaImage::new(width as u32, band_h as u32);
    for (row, alpha) in band_alpha(band_h).into_iter().enumerate() {
        let y = row as f64;
        draw::line(
            &mut band,
            &[(0.0, y), (width as f64, y)],
            [10, 13, 20, alpha],
            1,
        );
    }
    raster::alpha_composite(canvas, &band, (0, 0));
    let at = |x: i64, y: i64| (x as f64, y as f64);
    text.draw_text(
        canvas,
        at(22 * ss, 20 * ss),
        title,
        regular(23 * ss),
        [255; 4],
        top_left,
    );
    if !subtitle.is_empty() {
        let fill = [178, 192, 210, 255];
        text.draw_text(
            canvas,
            at(22 * ss, 47 * ss),
            subtitle,
            regular(14 * ss),
            fill,
            top_left,
        );
    }

    // 凡例（色の札を弱い順に並べる）。
    let (chip, gap, pad) = (22 * ss, 7 * ss, 12 * ss);
    let count = scales.len() as i64;
    let box_w = pad * 2 + count * chip + (count - 1).max(0) * gap;
    let box_h = pad * 2 + chip + 15 * ss;
    let (bx, by) = (width - box_w - 16 * ss, height - box_h - 16 * ss);
    let mut panel = RgbaImage::new(box_w as u32, box_h as u32);
    draw::rounded_rectangle(
        &mut panel,
        [0.0, 0.0, (box_w - 1) as f64, (box_h - 1) as f64],
        (9 * ss) as f64,
        Some([12, 16, 24, 208]),
        Some([120, 140, 170, 120]),
        ss.max(1) as i32,
    )?;
    raster::alpha_composite(canvas, &panel, (bx, by));
    let fill = [170, 186, 206, 255];
    text.draw_text(
        canvas,
        at(bx + pad, by + pad - ss),
        "震度",
        regular(11 * ss),
        fill,
        top_left,
    );
    for (index, scale) in scales.iter().enumerate() {
        let x = bx + pad + index as i64 * (chip + gap);
        let y = by + pad + 14 * ss;
        let rgb = scale.fill_rgb();
        let label = scale.badge_label();
        draw::rounded_rectangle(
            canvas,
            [x as f64, y as f64, (x + chip) as f64, (y + chip) as f64],
            (5 * ss) as f64,
            Some(rgba(rgb, 255)),
            None,
            1,
        )?;
        let ratio = if label.chars().count() == 1 {
            0.62
        } else {
            0.46
        };
        let font = regular(int(chip as f64 * ratio));
        let centre = (x as f64 + chip as f64 / 2.0, y as f64 + chip as f64 / 2.0);
        text.draw_text(canvas, centre, label, font, ink_for(rgb), Anchor(*b"mm"));
    }

    // 出典（左下。字の幅に合わせた暗い座の上に置く）。
    let font = regular(11 * ss);
    let text_w = int(text.text_length(TILE_ATTRIBUTION, font));
    draw::rectangle(
        canvas,
        [
            0.0,
            (height - 19 * ss) as f64,
            (text_w + 16 * ss) as f64,
            height as f64,
        ],
        Some([8, 11, 17, 190]),
        None,
        1,
    )?;
    let fill = [150, 165, 185, 255];
    text.draw_text(
        canvas,
        at(8 * ss, height - 16 * ss),
        TILE_ATTRIBUTION,
        font,
        fill,
        top_left,
    );
    Ok(())
}

/// 1 枚の地図に描くもの。
#[derive(Clone, Copy, Debug)]
pub struct Scene<'a> {
    /// 範囲と点（[`plan`] が決めたもの）。
    pub plan: &'a Plan,
    /// [`Plan::coords`] と同じ並びのタイル（PNG のバイト列。取れなかった枚は `None`）。
    pub tiles: &'a [Option<Vec<u8>>],
    /// 震源の緯度。
    pub lat: f64,
    /// 震源の経度。
    pub lon: f64,
    /// 題（「最大震度 5弱」など）。
    pub title: &'a str,
    /// 副題（震源・規模・深さ・時刻）。空なら描かない。
    pub subtitle: &'a str,
}

/// 取ってきたタイルから地図を組み立てる。Python の `_compose_intensity_map`（PNG にする手前まで）。
/// 出来上がりは 1200×720 の RGB。
pub fn compose(
    scene: &Scene<'_>,
    shapes: &Shapes,
    text: &dyn TextPainter,
) -> Result<RgbImage, MapError> {
    compose_traced(scene, shapes, text, &mut |_, _| {})
}

/// [`compose`] と同じ。描く段ごとに、その時点の画素（段の名前と、生の並び）を `trace` に渡す。
///
/// 段は `base`（タイルを貼った面。RGB）→ `upscaled`（2 倍にした面。以下 RGBA）→ `filled`（県の塗り）→
/// `epicentre`（震源）→ `badges`（札）→ `labels`（地名）→ `chrome`（帯・凡例・出典）→ `final`（縮めた RGB）。
/// テストが、Python の同じ段と比べるために使う。
pub fn compose_traced(
    scene: &Scene<'_>,
    shapes: &Shapes,
    text: &dyn TextPainter,
    trace: &mut dyn FnMut(&'static str, &[u8]),
) -> Result<RgbImage, MapError> {
    let plan = scene.plan;
    let ss = MAP_SS as f64;
    let (ex, ey) = to_px(plan, scene.lat, scene.lon);
    if !ex.is_finite() || !ey.is_finite() {
        return Err(MapError::NotFinite);
    }
    // 2 倍に伸ばしてから描き、最後に縮める。
    let base = tiles::paste_tiles(&plan.coords, scene.tiles, plan.origin_x, plan.origin_y);
    trace("base", &base);
    let (wide, tall) = (MAP_SIZE.0 * MAP_SS as u32, MAP_SIZE.1 * MAP_SS as u32);
    let mut canvas = raster::rgb_to_rgba(&raster::resize_rgb(&base, wide, tall));
    trace("upscaled", &canvas);

    // 先に県の面を塗る。札はその上。
    fill_prefectures(&mut canvas, plan, shapes)?;
    trace("filled", &canvas);
    let mut placement = place_badges(plan);
    draw_epicentre(&mut canvas, ex, ey)?;
    trace("epicentre", &canvas);

    // 札を描くのは弱い順（落ち影が強い札の上に乗らないように）。
    let mut badges: Vec<&(f64, f64, Scale)> = placement.badges.iter().collect();
    badges.sort_by(|a, b| a.2.value.total_cmp(&b.2.value));
    for (x, y, scale) in badges {
        let badge = scale_badge(scale, scale.badge_size() * MAP_SS, text)?;
        let half = f64::from(badge.width()) / 2.0;
        raster::alpha_composite(&mut canvas, &badge, (int(x - half), int(y - half)));
    }
    trace("badges", &canvas);

    // 震源の座は、ここで初めてふさぐ（地名は震源の印に重ねないが、札は重ねてよい）。
    placement.taken.push((
        ex - 20.0 * ss,
        ey - 20.0 * ss,
        ex + 20.0 * ss,
        ey + 20.0 * ss,
    ));
    draw_place_labels(&mut canvas, plan, &mut placement, text)?;
    trace("labels", &canvas);
    let scales = legend_scales(&plan.plot);
    draw_map_chrome(&mut canvas, scene.title, scene.subtitle, &scales, text)?;
    trace("chrome", &canvas);

    let small = raster::resize_rgba(&canvas, MAP_SIZE.0, MAP_SIZE.1);
    let out = raster::rgba_to_rgb(&small);
    trace("final", &out);
    Ok(out)
}

/// RGB の画像を PNG にする（Python の `save(buf, format="PNG", optimize=True)`）。
///
/// 画素は同じだが、PNG のバイト列は Pillow のものと同じにはならない（圧縮の実装が違う）。
pub fn encode_png(img: &RgbImage) -> Option<Vec<u8>> {
    use image::ImageEncoder;
    use image::codecs::png::{CompressionType, FilterType, PngEncoder};
    let mut out = Vec::new();
    PngEncoder::new_with_quality(&mut out, CompressionType::Best, FilterType::Adaptive)
        .write_image(
            img,
            img.width(),
            img.height(),
            image::ExtendedColorType::Rgb8,
        )
        .ok()?;
    Some(out)
}
