//! 震度の地図の画像が、Python（Pillow）の作るものと画素まで同じになること。
//!
//! 基準は `fixtures/earthquake_map/`（`generate.py` が、本番と同じ環境の本物の Python で作る）:
//!
//! - `shapes.json` … 図形（多角形・楕円・線・四角・角丸）・ぼかし・重ね合わせ・拡大縮小・貼り付けの例と、
//!   Pillow が描いた画素のハッシュ
//! - `tiles.json` … タイルの PNG（色の形いろいろ）と、明るさにして塗り替えた結果のハッシュ
//! - `mercator.json` … 緯度 → tan・asinh・タイルの y（最後の桁まで）
//! - `plans.json` … 震源と観測点 → ズーム・範囲・要るタイル（境の値を含む）
//! - `pieces.json` … 札・震源の印・地名の札・帯と凡例・県の塗りを 1 つずつ描いた結果
//! - `maps.json` と `tiles/` … 地図の全体（描く段ごとの画素のハッシュ）と、そこで配るタイルの見本
//!
//! 文字は別の部品（`earthquake_text`）が描くので、ここでは「描かずに記録するだけ」の偽物に差し替え、文字
//! 以外の画素と、文字を描く呼び出し（場所・字・大きさ・色）が Python と同じことを確かめる。
//!
//! 1 画素でも違えば落ちる。落ちたときに、どの例が・何画素違うかを見たいときは、`generate.py --dump <置き場>`
//! で生の画素を書き出し、環境変数 `EARTHQUAKE_MAP_DUMP` にその置き場を渡す。

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use image::{RgbImage, RgbaImage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sycs_bot::earthquake_map::compose::{self, Plan, PlotPoint, Scale, Scene};
use sycs_bot::earthquake_map::{geo, tiles};
use sycs_bot::earthquake_text::{Anchor, FontSpec, TextPainter};
use sycs_imaging::{draw, raster};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/earthquake_map");

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{DIR}/{name}")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// 決まった「でたらめ」のバイト列。`gen_shapes.py` の `noise` と同じ式。
fn noise(seed: u64, count: usize) -> Vec<u8> {
    (0..count as u64)
        .map(|i| {
            let mut v = (i.wrapping_mul(2_654_435_761).wrapping_add(seed * 40_503)) & 0xFFFF_FFFF;
            v ^= v >> 15;
            v = v.wrapping_mul(2_246_822_519) & 0xFFFF_FFFF;
            v ^= v >> 13;
            (v & 0xFF) as u8
        })
        .collect()
}

/// 基準と違ったとき、生の画素があれば違う画素の数を数える。
fn differing_pixels(name: &str, ours: &[u8], bytes_per_pixel: usize) -> String {
    let Ok(dir) = std::env::var("EARTHQUAKE_MAP_DUMP") else {
        return "ハッシュが違う".into();
    };
    let Ok(theirs) = std::fs::read(format!("{dir}/{name}")) else {
        return "ハッシュが違う（生の画素が無い）".into();
    };
    if theirs.len() != ours.len() {
        return format!(
            "大きさが違う（Python {} バイト / Rust {}）",
            theirs.len(),
            ours.len()
        );
    }
    let mut pixels = 0;
    let mut worst = 0;
    for (p, q) in theirs
        .chunks_exact(bytes_per_pixel)
        .zip(ours.chunks_exact(bytes_per_pixel))
    {
        if p != q {
            pixels += 1;
        }
        for (a, b) in p.iter().zip(q) {
            worst = worst.max(a.abs_diff(*b));
        }
    }
    format!(
        "違う画素 {pixels} / {}（最大の差 {worst}）",
        ours.len() / bytes_per_pixel
    )
}

fn ink(value: &Value) -> Option<draw::Ink> {
    let list = value.as_array()?;
    let mut out = [0_u8; 4];
    for (slot, v) in out.iter_mut().zip(list) {
        *slot = v.as_u64().unwrap() as u8;
    }
    Some(out)
}

fn numbers<const N: usize>(value: &Value) -> [f64; N] {
    let mut out = [0.0; N];
    for (slot, v) in out.iter_mut().zip(value.as_array().unwrap()) {
        *slot = v.as_f64().unwrap();
    }
    out
}

fn points(value: &Value) -> Vec<(f64, f64)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let [x, y] = numbers::<2>(p);
            (x, y)
        })
        .collect()
}

fn size(value: &Value) -> (u32, u32) {
    let [w, h] = numbers::<2>(value);
    (w as u32, h as u32)
}

/// 例の 1 つを、Rust の写しで描く。Pillow が例外にするものは `Err`。
fn run_shape(case: &Value) -> Result<Vec<u8>, draw::ShapeError> {
    let (w, h) = size(&case["size"]);
    let pixels = (w * h) as usize;
    if case["mode"] == "RGB" {
        let mut img =
            RgbImage::from_raw(w, h, noise(case["noise"].as_u64().unwrap(), pixels * 3)).unwrap();
        for op in case["ops"].as_array().unwrap() {
            match op["op"].as_str().unwrap() {
                "paste" => {
                    let (tw, th) = size(&op["size"]);
                    let seed = op["noise"].as_u64().unwrap();
                    let tile = RgbImage::from_raw(tw, th, noise(seed, (tw * th * 3) as usize));
                    let [x, y] = numbers::<2>(&op["at"]);
                    raster::paste_rgb(&mut img, &tile.unwrap(), (x as i64, y as i64));
                }
                "resize" => {
                    let (tw, th) = size(&op["size"]);
                    img = raster::resize_rgb(&img, tw, th);
                }
                other => panic!("知らない操作: {other}"),
            }
        }
        return Ok(raster::rgb_to_rgba(&img).into_raw());
    }
    let mut img = match case["noise"].as_u64() {
        Some(seed) => RgbaImage::from_raw(w, h, noise(seed, pixels * 4)).unwrap(),
        None => RgbaImage::from_pixel(w, h, image::Rgba(ink(&case["base"]).unwrap())),
    };
    for op in case["ops"].as_array().unwrap() {
        let (fill, outline) = (ink(&op["fill"]), ink(&op["outline"]));
        let width = op["width"].as_i64().unwrap_or(1) as i32;
        match op["op"].as_str().unwrap() {
            "polygon" => draw::polygon(&mut img, &points(&op["xy"]), fill.unwrap())?,
            "ellipse" => draw::ellipse(&mut img, numbers(&op["xy"]), fill, outline, width)?,
            "line" => draw::line(&mut img, &points(&op["xy"]), fill.unwrap(), width),
            "rectangle" => draw::rectangle(&mut img, numbers(&op["xy"]), fill, outline, width)?,
            "rounded_rectangle" => draw::rounded_rectangle(
                &mut img,
                numbers(&op["xy"]),
                op["radius"].as_f64().unwrap(),
                fill,
                outline,
                width,
            )?,
            "blur" => img = raster::gaussian_blur(&img, op["radius"].as_f64().unwrap()),
            "composite" => {
                let (ow, oh) = size(&op["size"]);
                let seed = op["noise"].as_u64().unwrap();
                let overlay = RgbaImage::from_raw(ow, oh, noise(seed, (ow * oh * 4) as usize));
                let [x, y] = numbers::<2>(&op["at"]);
                raster::alpha_composite(&mut img, &overlay.unwrap(), (x as i64, y as i64));
            }
            "resize" => {
                let (tw, th) = size(&op["size"]);
                img = raster::resize_rgba(&img, tw, th);
            }
            other => panic!("知らない操作: {other}"),
        }
    }
    Ok(img.into_raw())
}

/// 図形・ぼかし・重ね合わせ・拡大縮小が、どの例でも Pillow と同じ画素になること。
#[test]
fn shapes_have_the_pixels_pillow_drew() {
    let cases = fixture("shapes.json");
    let cases = cases.as_array().unwrap();
    let mut wrong = Vec::new();
    // 種類ごとの（例の数・違った数）。
    let mut kinds: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = case["sha256"].as_str().unwrap();
        let kind = name.split('-').next().unwrap().to_string();
        let entry = kinds.entry(kind).or_default();
        entry.0 += 1;
        let problem = match run_shape(case) {
            Err(_) if want == "error" => None,
            Err(e) => Some(format!("Pillow は描くのに、Rust は断った（{e:?}）")),
            Ok(_) if want == "error" => Some("Pillow は断るのに、Rust は描いた".to_string()),
            Ok(pixels) if sha256(&pixels) == want => None,
            Ok(pixels) => Some(differing_pixels(&format!("{name}.rgba"), &pixels, 4)),
        };
        if let Some(problem) = problem {
            entry.1 += 1;
            wrong.push(format!("{name}: {problem}"));
        }
    }
    println!("図形ごとの結果（例の数・違った数）: {kinds:?}");
    assert!(cases.len() >= 450, "例が足りない（{}）", cases.len());
    for kind in [
        "polygon",
        "ellipse",
        "line",
        "rectangle",
        "rounded",
        "blur",
        "composite",
        "resize",
        "paste",
    ] {
        assert!(kinds.contains_key(kind), "{kind} の例が無い");
    }
    assert!(wrong.is_empty(), "Pillow と違う:\n{}", wrong.join("\n"));
}

/// タイルの PNG を、どの色の形でも Pillow と同じ明るさ・同じ色に直すこと。読めないものは読めないとすること。
#[test]
fn tiles_are_decoded_and_recoloured_like_pillow() {
    let cases = fixture("tiles.json");
    let cases = cases.as_array().unwrap();
    let mut wrong = Vec::new();
    let mut unreadable = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let png = hex::decode(case["png"].as_str().unwrap()).unwrap();
        let want = case["sha256"].as_str().unwrap();
        match tiles::decode_gray(&png) {
            None if want == "error" => unreadable += 1,
            None => wrong.push(format!("{name}: Pillow は読めるのに、Rust は読めない")),
            Some(_) if want == "error" => {
                wrong.push(format!("{name}: Pillow は読めないのに、Rust は読めた"));
            }
            Some(gray) => {
                assert_eq!((gray.width, gray.height), size(&case["size"]), "{name}");
                if sha256(&gray.pixels) != case["gray_sha256"].as_str().unwrap() {
                    let detail = differing_pixels(&format!("tile-{name}.gray"), &gray.pixels, 1);
                    wrong.push(format!("{name}（明るさ）: {detail}"));
                }
                let rgb = tiles::recolour_tile(&gray).into_raw();
                if sha256(&rgb) != want {
                    let detail = differing_pixels(&format!("tile-{name}.rgb"), &rgb, 3);
                    wrong.push(format!("{name}（塗り替え）: {detail}"));
                }
            }
        }
    }
    assert!(cases.len() >= 25, "例が足りない（{}）", cases.len());
    assert_eq!(unreadable, 3, "読めないタイルの例の数");
    assert!(wrong.is_empty(), "Pillow と違う:\n{}", wrong.join("\n"));
}

// ── ここから下は、地図そのもの（計算・範囲の決め方・部品・全体） ───────────────

/// 小数を、ビットの並び（16 進 16 桁）にする。`gen_maps.py` の `bits` と同じ。
fn bits(value: f64) -> String {
    format!("{:016x}", value.to_bits())
}

/// ビットの並びを小数に戻す。
fn unbits(value: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(value.as_str().unwrap(), 16).unwrap())
}

/// 文字を描く口の偽物。描かずに、呼び出しを記録する。文字の幅は、Python が返した値（基準に控えてある）を返す。
struct RecordingText {
    lengths: HashMap<String, f64>,
    calls: Mutex<Vec<Value>>,
}

impl RecordingText {
    fn new(lengths: &Value) -> Self {
        let lengths = lengths
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), unbits(value)))
            .collect();
        Self {
            lengths,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// 記録した呼び出しを取り出す（記録は空にする）。
    fn take(&self) -> Vec<Value> {
        std::mem::take(&mut self.calls.lock().unwrap())
    }
}

impl TextPainter for RecordingText {
    fn text_length(&self, text: &str, font: FontSpec) -> f64 {
        let key = format!("{}|{}|{text}", font.size, u8::from(font.bold));
        *self
            .lengths
            .get(&key)
            .unwrap_or_else(|| panic!("Python が測っていない文字の幅を聞かれた: {key}"))
    }

    fn text_bbox(&self, _: (f64, f64), text: &str, _: FontSpec, _: Anchor) -> (i32, i32, i32, i32) {
        panic!("地図は textbbox を使わないはず: {text}");
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
        self.calls.lock().unwrap().push(json!({
            "canvas": [canvas.width(), canvas.height()],
            "xy": [bits(xy.0), bits(xy.1)],
            "text": text,
            "size": font.size,
            "bold": font.bold,
            "fill": fill,
            "anchor": String::from_utf8_lossy(&anchor.0),
        }));
    }
}

fn scale_of(value: &Value) -> Scale {
    Scale {
        value: unbits(&value[0]),
        text: value[1].as_str().unwrap().to_string(),
    }
}

/// 下地（でたらめな不透明の色）。`gen_maps.py` の `blank` と同じ。
fn blank(case: &Value) -> RgbaImage {
    let (w, h) = size(&case["canvas"]);
    let mut pixels = noise(case["seed"].as_u64().unwrap(), (w * h * 4) as usize);
    for alpha in pixels.iter_mut().skip(3).step_by(4) {
        *alpha = 255;
    }
    RgbaImage::from_raw(w, h, pixels).unwrap()
}

/// 緯度 → タイルの位置の計算が、Python と最後の桁まで同じであること。
///
/// `asinh` は Python（glibc）の式の写しなので、どの機械でも同じ値になる。`tan` は機械の libm を使う。Linux
/// では Python と同じ glibc の `tan` で、CPU に FMA が無ければ（本番・CI の QEMU）最後の桁まで同じになる。
/// FMA のある機械では glibc が別の版を選ぶので、ごくまれに最後の桁が違う（そのときは 1 目盛り以内を見る）。
#[test]
fn mercator_matches_python_to_the_last_bit() {
    let samples = fixture("mercator.json");
    let samples = samples.as_array().unwrap();
    #[cfg(target_arch = "x86_64")]
    let exact = cfg!(target_env = "gnu") && !std::arch::is_x86_feature_detected!("fma");
    #[cfg(not(target_arch = "x86_64"))]
    let exact = false;
    let mut wrong = Vec::new();
    for sample in samples {
        let [lat, tan, asinh, ty] = [0, 1, 2, 3].map(|i| unbits(&sample[i]));
        if geo::asinh(tan).to_bits() != asinh.to_bits() {
            wrong.push(format!(
                "asinh({tan:e}) = {:e}（Python {asinh:e}）",
                geo::asinh(tan)
            ));
        }
        // tan より後（asinh と割り算・掛け算）は、どの機械でも最後のビットまで同じ。
        let from_tan = geo::tile_y_from_tan(tan, 8);
        if from_tan.to_bits() != ty.to_bits() {
            wrong.push(format!(
                "tan = {tan:e} からのタイルの y = {from_tan:e}（Python {ty:e}）"
            ));
        }
        let ours = geo::latlon_to_tile(lat, 139.0, 8).1;
        let off = ours.to_bits().abs_diff(ty.to_bits());
        if off > u64::from(!exact) * 4 {
            wrong.push(format!(
                "緯度 {lat} のタイルの y = {ours:e}（Python {ty:e}）"
            ));
        }
        // Python の式を逆からたどって、x の式も確かめる（経度は足し算と掛け算だけ）。
        assert_eq!(
            geo::latlon_to_tile(lat, 139.0, 8).0,
            (139.0 + 180.0) / 360.0 * 256.0
        );
    }
    assert!(samples.len() >= 2000, "見本が足りない（{}）", samples.len());
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong[..wrong.len().min(10)].join("\n")
    );
}

fn plan_json(plan: &Plan) -> Value {
    json!({
        "zoom": plan.zoom,
        "origin": [bits(plan.origin_x), bits(plan.origin_y)],
        "coords": plan.coords.iter().map(|c| json!([c.0, c.1])).collect::<Vec<_>>(),
        "plot": plan.plot.iter().map(|p| json!([
            bits(p.lat), bits(p.lon), [bits(p.scale.value), p.scale.text], p.name
        ])).collect::<Vec<_>>(),
    })
}

/// 震源と観測点から決めた範囲（Python の `_generate_intensity_map` の前半と同じ形で）。
fn plan_of(lat: f64, lon: f64, points: &Value) -> Value {
    match compose::plot_points(points.as_array().unwrap()) {
        Err(_) => json!({"raises": true}),
        Ok(points) => match compose::plan(lat, lon, points) {
            None => json!({"none": true}),
            Some(plan) => plan_json(&plan),
        },
    }
}

/// 震源と観測点から、ズーム・範囲・要るタイル・打つ点を Python と同じに決めること。
///
/// タイルの番号やズームが切り替わる、ちょうど境の値（浮動小数の 1 目盛りずつ前後にずらしたもの）と、
/// 形の崩れた観測点（Python が例外にするもの）を含む。
#[test]
fn the_area_and_tiles_are_chosen_like_python() {
    let cases = fixture("plans.json");
    let cases = cases.as_array().unwrap();
    let mut wrong = Vec::new();
    let (mut raised, mut none, mut zooms) = (0, 0, std::collections::BTreeSet::new());
    // 境の例のうち、隣（1 目盛り違い）と答えが変わるところの数。
    let mut flips = 0;
    let mut previous: Option<(String, Value)> = None;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let want = &case["plan"];
        let got = plan_of(unbits(&case["lat"]), unbits(&case["lon"]), &case["points"]);
        let same = if want.get("raises").is_some() {
            raised += 1;
            got.get("raises").is_some()
        } else {
            none += usize::from(want.get("none").is_some());
            got == *want
        };
        if !same {
            wrong.push(format!("{name}: Python {want} / Rust {got}"));
        }
        if let Some(zoom) = want["zoom"].as_u64() {
            zooms.insert(zoom);
        }
        // 境の例の名前は「組の名前＋何目盛りずらしたか（-4〜-1・+1〜+4）」。同じ組の隣どうしを比べる。
        let boundary = name.starts_with("edge-") || name.starts_with("zoom-");
        let family = if boundary {
            name[..name.len() - 2].to_string()
        } else {
            name.to_string()
        };
        if let Some((last_family, last_plan)) = &previous
            && *last_family == family
            && (last_plan["coords"] != want["coords"] || last_plan["zoom"] != want["zoom"])
        {
            flips += 1;
        }
        previous = Some((family, want.clone()));
    }
    println!(
        "範囲の例 {}（例外 {raised}・地図なし {none}・境で答えが変わるところ {flips}・出たズーム {zooms:?}）",
        cases.len()
    );
    assert!(cases.len() >= 450, "例が足りない（{}）", cases.len());
    assert!(raised >= 5 && none >= 4, "形の崩れた例が足りない");
    assert!(flips >= 32, "境をまたぐ例が足りない（{flips}）");
    assert_eq!(zooms.len(), 7, "5〜11 の全部のズームが出ること");
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong[..wrong.len().min(8)].join("\n")
    );
}

/// 部品を 1 つ描く。返すのは（幅, 高さ, RGBA の並び）。
fn run_piece(case: &Value, text: &RecordingText) -> (u32, u32, Vec<u8>) {
    let img = match case["kind"].as_str().unwrap() {
        "badge" => compose::scale_badge(
            &scale_of(&case["scale"]),
            case["size"].as_i64().unwrap(),
            text,
        )
        .unwrap(),
        "marker" => compose::epicentre_marker(case["size"].as_i64().unwrap()).unwrap(),
        kind => {
            let mut canvas = blank(case);
            match kind {
                "epicentre" => {
                    compose::draw_epicentre(
                        &mut canvas,
                        unbits(&case["at"][0]),
                        unbits(&case["at"][1]),
                    )
                    .unwrap();
                }
                "label" => {
                    let (left, top) = (unbits(&case["at"][0]), unbits(&case["at"][1]));
                    compose::draw_place_label(
                        &mut canvas,
                        left,
                        top,
                        case["text"].as_str().unwrap(),
                        text,
                    )
                    .unwrap();
                }
                "chrome" => {
                    let scales: Vec<Scale> = case["scales"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(scale_of)
                        .collect();
                    let (title, subtitle) = (
                        case["title"].as_str().unwrap(),
                        case["subtitle"].as_str().unwrap(),
                    );
                    compose::draw_map_chrome(&mut canvas, title, subtitle, &scales, text).unwrap();
                }
                "fill" => {
                    let plot = case["plot"].as_array().unwrap().iter().map(|p| PlotPoint {
                        lat: 0.0,
                        lon: 0.0,
                        scale: scale_of(&p[1]),
                        name: p[0].as_str().unwrap().to_string(),
                    });
                    let plan = Plan {
                        plot: plot.collect(),
                        zoom: case["zoom"].as_u64().unwrap() as u32,
                        origin_x: unbits(&case["origin"][0]),
                        origin_y: unbits(&case["origin"][1]),
                        coords: Vec::new(),
                    };
                    compose::fill_prefectures(&mut canvas, &plan, geo::prefecture_shapes())
                        .unwrap();
                }
                other => panic!("知らない部品: {other}"),
            }
            canvas
        }
    };
    (img.width(), img.height(), img.into_raw())
}

/// 札・震源の印・地名の札・帯と凡例・県の塗りが、1 つずつ Python と同じ画素になること（文字は除く）。
/// 文字を描く呼び出し（場所・字・大きさ・色・そろえ方）も Python と同じであること。
#[test]
fn map_pieces_have_the_pixels_python_drew() {
    let pieces = fixture("pieces.json");
    let text = RecordingText::new(&pieces["lengths"]);
    let cases = pieces["cases"].as_array().unwrap();
    let mut wrong = Vec::new();
    let mut kinds: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let entry = kinds
            .entry(case["kind"].as_str().unwrap().to_string())
            .or_default();
        entry.0 += 1;
        let (w, h, pixels) = run_piece(case, &text);
        let mut problems = Vec::new();
        if (w, h) != size(&case["size_out"]) {
            problems.push(format!("大きさ {w}x{h}"));
        } else if sha256(&pixels) != case["sha256"].as_str().unwrap() {
            problems.push(differing_pixels(&format!("piece-{name}.rgba"), &pixels, 4));
        }
        if Value::Array(text.take()) != case["text_calls"] {
            problems.push("文字の呼び出しが違う".into());
        }
        if !problems.is_empty() {
            entry.1 += 1;
            wrong.push(format!("{name}: {}", problems.join("・")));
        }
    }
    println!("部品ごとの結果（例の数・違った数）: {kinds:?}");
    assert!(cases.len() >= 50, "例が足りない（{}）", cases.len());
    assert_eq!(kinds.len(), 6, "部品の種類");
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
}

/// 札・地名の重なりの判定が Python の `_overlaps` と同じであること（辺が接するだけの例を多く含む）。
#[test]
fn overlap_checks_match_python() {
    let pieces = fixture("pieces.json");
    let cases = pieces["overlaps"].as_array().unwrap();
    let rect = |v: &Value| {
        let [l, t, r, b] = numbers::<4>(v);
        (l, t, r, b)
    };
    let mut touching = 0;
    for case in cases {
        let area = rect(&case[0]);
        let taken: Vec<_> = case[1].as_array().unwrap().iter().map(rect).collect();
        let want = case[2].as_bool().unwrap();
        assert_eq!(
            compose::overlaps(area, &taken),
            want,
            "{area:?} と {taken:?}"
        );
        touching += usize::from(
            taken
                .iter()
                .any(|r| area.2 == r.0 || area.0 == r.2 || area.3 == r.1 || area.1 == r.3),
        );
    }
    assert!(cases.len() >= 300, "例が足りない（{}）", cases.len());
    assert!(touching >= 100, "接する例が足りない（{touching}）");
}

/// 浮動小数の `pow`・`hypot`・`sin` を通る 3 か所（題の帯の濃さ・震源の座の濃さ・縮小の係数）が Python と
/// 同じ整数になり、しかも丸めの境から十分に離れていること（libm の最後の桁が違っても結果が変わらない）。
#[test]
fn float_tables_are_far_from_rounding_boundaries() {
    let pieces = fixture("pieces.json");
    let band: Vec<u64> = compose::band_alpha(148)
        .into_iter()
        .map(u64::from)
        .collect();
    let want: Vec<u64> = pieces["band_alpha"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(band, want, "題の帯の濃さ");
    let seat = compose::seat_alpha(60);
    assert_eq!(
        sha256(&seat),
        pieces["seat_alpha_sha256"].as_str().unwrap(),
        "震源の座の濃さ"
    );

    // 切り捨ての境（整数）までの、いちばん近い距離。ちょうど 0 と 1 の累乗（どの libm でも正確）は除く。
    let distance = |v: f64| (v - v.round()).abs();
    let band_margin = (1..148)
        .map(|row| distance(215.0 * (1.0 - f64::from(row) / 148.0).powf(1.3)))
        .fold(f64::INFINITY, f64::min);
    let mut seat_margin = f64::INFINITY;
    for y in 0..120 {
        for x in 0..120 {
            let dist = (f64::from(x - 60) + 0.5).hypot(f64::from(y - 60) + 0.5) / 60.0;
            if dist < 1.0 {
                seat_margin = seat_margin.min(distance(120.0 * (1.0 - dist).powf(1.1)));
            }
        }
    }
    let resize_margin = [(1200, 2400), (720, 1440), (2400, 1200), (1440, 720)]
        .into_iter()
        .map(|(from, to)| raster::lanczos_rounding_margin(from, to))
        .fold(f64::INFINITY, f64::min);
    println!(
        "丸めの境までの距離: 帯 {band_margin:e}・座 {seat_margin:e}・縮小の係数 {resize_margin:e}"
    );
    // 倍精度の 1 目盛りは、この大きさの数で 1e-13 ほど。
    assert!(band_margin > 1e-6, "題の帯: {band_margin:e}");
    assert!(seat_margin > 1e-6, "震源の座: {seat_margin:e}");
    assert!(resize_margin > 1e-6, "縮小の係数: {resize_margin:e}");
}

/// そのタイルに何を返すか。`gen_maps.py` の `tile_rule` と同じ規則。
fn tile_rule(mode: &str, samples: &[Vec<u8>], z: i64, x: i64, y: i64) -> Option<Vec<u8>> {
    if mode == "none" {
        return None;
    }
    if mode == "holes" {
        match (x + 2 * y).rem_euclid(5) {
            0 => return None,
            1 => return Some(b"this is not a png".to_vec()),
            _ => {}
        }
    }
    let index = (x * 3 + y * 5 + z).rem_euclid(samples.len() as i64);
    Some(samples[index as usize].clone())
}

/// 生の画素と比べるときの名前と、1 画素のバイト数（基準の生の画素は、どの段も RGBA で書き出してある）。
fn stage_pixels(name: &str, stage: &str, pixels: &[u8]) -> String {
    let rgba: Vec<u8> = if matches!(stage, "base" | "final") {
        let (rgb, _) = pixels.as_chunks::<3>();
        rgb.iter().flat_map(|[r, g, b]| [*r, *g, *b, 255]).collect()
    } else {
        pixels.to_vec()
    };
    differing_pixels(&format!("map-{name}-{stage}.rgba"), &rgba, 4)
}

/// 地図を 1 枚描いて、基準と違う段の説明を返す。`every_stage` が偽なら、最初と最後の段だけを比べる。
fn check_map(
    case: &Value,
    samples: &[Vec<u8>],
    text: &RecordingText,
    every_stage: bool,
) -> Vec<String> {
    let name = case["name"].as_str().unwrap();
    let (lat, lon) = (case["lat"].as_f64().unwrap(), case["lon"].as_f64().unwrap());
    let points = compose::plot_points(case["points"].as_array().unwrap()).unwrap();
    let plan = compose::plan(lat, lon, points).unwrap();
    if plan_json(&plan) != case["plan"] {
        return vec![format!("{name}: 範囲が違う")];
    }
    let mode = case["tiles"].as_str().unwrap();
    let tiles: Vec<Option<Vec<u8>>> = plan
        .coords
        .iter()
        .map(|(x, y)| tile_rule(mode, samples, i64::from(plan.zoom), *x, *y))
        .collect();
    let scene = Scene {
        plan: &plan,
        tiles: &tiles,
        lat,
        lon,
        title: case["title"].as_str().unwrap(),
        subtitle: case["subtitle"].as_str().unwrap(),
    };
    let want = case["stages"].as_object().unwrap();
    let mut wrong = Vec::new();
    let mut seen = 0;
    let out = compose::compose_traced(
        &scene,
        geo::prefecture_shapes(),
        text,
        &mut |stage, pixels| {
            seen += 1;
            let compared = every_stage || matches!(stage, "base" | "final");
            if compared && sha256(pixels) != want[stage].as_str().unwrap() {
                wrong.push(format!(
                    "{name}（{stage}）: {}",
                    stage_pixels(name, stage, pixels)
                ));
            }
        },
    );
    assert_eq!(out.unwrap().dimensions(), (1200, 720), "{name}");
    assert_eq!(seen, want.len(), "{name}: 段の数");
    if Value::Array(text.take()) != case["text_calls"] {
        wrong.push(format!("{name}: 文字の呼び出しが違う"));
    }
    wrong
}

/// 地図の全体が Python と同じ画素になること（文字は除く。文字を描く呼び出しは同じであること）。
///
/// 震源が陸・海・遠く、観測点が 1 つ／全国、震度いろいろ、表に無い震度、タイルが取れない・壊れている、を含む。
///
/// ふだんは、タイルを貼った面と、出来上がり（縮めた後）の画素を比べる。違ったときは、描く段ごと（県の塗り・
/// 震源・札・地名・帯と凡例）に比べ直して、どの段から違うかを出す。環境変数 `EARTHQUAKE_MAP_EVERY_STAGE` を
/// 付けると、最初から全部の段を比べる（段ごとに 1300 万バイトのハッシュを取るので遅い）。
#[test]
fn whole_maps_have_the_pixels_python_drew() {
    let maps = fixture("maps.json");
    let text = RecordingText::new(&maps["lengths"]);
    let samples: Vec<Vec<u8>> = (0..6)
        .map(|i| std::fs::read(format!("{DIR}/tiles/tile_{i}.png")).unwrap())
        .collect();
    let cases = maps["cases"].as_array().unwrap();
    let every_stage = std::env::var_os("EARTHQUAKE_MAP_EVERY_STAGE").is_some();
    let mut wrong = Vec::new();
    for case in cases {
        let mut problems = check_map(case, &samples, &text, every_stage);
        if !problems.is_empty() && !every_stage {
            problems = check_map(case, &samples, &text, true);
        }
        wrong.extend(problems);
    }
    let stages = if every_stage { 8 } else { 2 };
    println!(
        "地図の全体 {} 例・比べた段 {}",
        cases.len(),
        cases.len() * stages
    );
    assert!(cases.len() >= 12, "例が足りない（{}）", cases.len());
    assert!(
        wrong.is_empty(),
        "Python と違う:
{}",
        wrong.join(
            "
"
        )
    );
}
