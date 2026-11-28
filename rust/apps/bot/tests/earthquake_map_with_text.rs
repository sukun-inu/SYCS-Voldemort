//! 震度の地図を本物の文字（`PillowText`。文字の担当の部品）まで入れて描き、Python（Pillow）の出来上がりと
//! 画素まで同じになること。
//!
//! 基準は `earthquake_map_golden.rs` と同じ `fixtures/earthquake_map/`（`generate.py` が、文字を描かない形と
//! 描く形の両方で作ってある）。こちらは文字ありの方（`stages_with_text`・`sha256_with_text`）と比べる。
//!
//! フォント（apt の `fonts-noto-cjk`。Python の本番と同じファイル）が要るので `#[ignore]`。CI は
//! `--include-ignored` で回す（フォントが無ければ落ちる。素通りはさせない）。

use image::RgbaImage;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sycs_bot::earthquake_map::compose::{self, Plan, PlotPoint, Scale, Scene};
use sycs_bot::earthquake_map::{geo, load_fonts};
use sycs_bot::earthquake_text::PillowText;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/earthquake_map");

/// 基準を作ったときの通常の字面（`NotoSansCJK-Regular.ttc`）のハッシュ。違うフォントでは比べられない。
const REGULAR_FONT_SHA256: &str =
    "b76b0433203017ca80401b2ee0dd69350349871c4b19d504c34dbdd80541690a";
const REGULAR_FONT_PATH: &str = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc";

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{DIR}/{name}")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// フォントを読む。基準と同じファイルであることを先に確かめる。
fn fonts() -> PillowText {
    let bytes = std::fs::read(REGULAR_FONT_PATH)
        .unwrap_or_else(|e| panic!("{REGULAR_FONT_PATH} が無い（fonts-noto-cjk を入れる）: {e}"));
    assert_eq!(sha256(&bytes), REGULAR_FONT_SHA256, "基準と違うフォント");
    load_fonts().expect("フォントを読めること")
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

fn unbits(value: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(value.as_str().unwrap(), 16).unwrap())
}

fn size(value: &Value) -> (u32, u32) {
    let list = value.as_array().unwrap();
    (
        list[0].as_u64().unwrap() as u32,
        list[1].as_u64().unwrap() as u32,
    )
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

/// 部品を 1 つ、本物の文字で描く。
fn run_piece(case: &Value, text: &PillowText) -> RgbaImage {
    match case["kind"].as_str().unwrap() {
        "badge" => compose::scale_badge(
            &scale_of(&case["scale"]),
            case["size"].as_i64().unwrap(),
            text,
        )
        .unwrap(),
        "marker" => compose::epicentre_marker(case["size"].as_i64().unwrap()).unwrap(),
        kind => {
            let mut canvas = blank(case);
            let at = |i: usize| unbits(&case["at"][i]);
            match kind {
                "epicentre" => compose::draw_epicentre(&mut canvas, at(0), at(1)).unwrap(),
                "label" => compose::draw_place_label(
                    &mut canvas,
                    at(0),
                    at(1),
                    case["text"].as_str().unwrap(),
                    text,
                )
                .unwrap(),
                "chrome" => {
                    let scales: Vec<Scale> = case["scales"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(scale_of)
                        .collect();
                    compose::draw_map_chrome(
                        &mut canvas,
                        case["title"].as_str().unwrap(),
                        case["subtitle"].as_str().unwrap(),
                        &scales,
                        text,
                    )
                    .unwrap();
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
    }
}

/// 札・震源の印・地名の札・帯と凡例・県の塗りを、文字まで入れて 1 つずつ描くと Python と同じ画素になること。
#[test]
#[ignore = "フォント（fonts-noto-cjk）が要る"]
fn map_pieces_with_text_have_the_pixels_python_drew() {
    let text = fonts();
    let pieces = fixture("pieces.json");
    let cases = pieces["cases"].as_array().unwrap();
    let mut wrong = Vec::new();
    for case in cases {
        let img = run_piece(case, &text);
        if sha256(img.as_raw()) != case["sha256_with_text"].as_str().unwrap() {
            wrong.push(case["name"].as_str().unwrap().to_string());
        }
    }
    println!(
        "部品（文字あり） {} 例・違った {}",
        cases.len(),
        wrong.len()
    );
    assert!(cases.len() >= 50);
    assert!(wrong.is_empty(), "Python と違う: {wrong:?}");
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

/// 地図の全体を、文字まで入れて描くと Python の出来上がりと同じ画素になること（描く段ごとに比べる）。
#[test]
#[ignore = "フォント（fonts-noto-cjk）が要る"]
fn whole_maps_with_text_have_the_pixels_python_drew() {
    let text = fonts();
    let maps = fixture("maps.json");
    let samples: Vec<Vec<u8>> = (0..6)
        .map(|i| std::fs::read(format!("{DIR}/tiles/tile_{i}.png")).unwrap())
        .collect();
    let cases = maps["cases"].as_array().unwrap();
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (lat, lon) = (case["lat"].as_f64().unwrap(), case["lon"].as_f64().unwrap());
        let points = compose::plot_points(case["points"].as_array().unwrap()).unwrap();
        let plan = compose::plan(lat, lon, points).unwrap();
        let mode = case["tiles"].as_str().unwrap();
        let tiles: Vec<Option<Vec<u8>>> = plan
            .coords
            .iter()
            .map(|(x, y)| tile_rule(mode, &samples, i64::from(plan.zoom), *x, *y))
            .collect();
        let scene = Scene {
            plan: &plan,
            tiles: &tiles,
            lat,
            lon,
            title: case["title"].as_str().unwrap(),
            subtitle: case["subtitle"].as_str().unwrap(),
        };
        let want = case["stages_with_text"].as_object().unwrap();
        let mut stages = 0;
        let out =
            compose::compose_traced(&scene, geo::prefecture_shapes(), &text, &mut |stage, px| {
                stages += 1;
                if sha256(px) != want[stage].as_str().unwrap() {
                    wrong.push(format!("{name}（{stage}）"));
                }
            })
            .unwrap();
        assert_eq!(stages, want.len(), "{name}: 段の数");
        // PNG にしたもの（目で見るとき用。環境変数 EARTHQUAKE_MAP_OUT に置き場を渡すと書き出す）。
        let png = compose::encode_png(&out).unwrap();
        let decoded = image::load_from_memory(&png).unwrap().to_rgb8();
        assert_eq!(
            decoded.as_raw(),
            out.as_raw(),
            "{name}: PNG にしても画素が変わらない"
        );
        println!(
            "{name}: PNG {} バイト（Python {} バイト）",
            png.len(),
            case["png_bytes"]
        );
        if let Some(dir) = std::env::var_os("EARTHQUAKE_MAP_OUT") {
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.png")), &png).unwrap();
        }
    }
    println!(
        "地図の全体（文字あり） {} 例・違った段 {}",
        cases.len(),
        wrong.len()
    );
    assert!(cases.len() >= 12);
    assert!(wrong.is_empty(), "Python と違う: {wrong:?}");
}
