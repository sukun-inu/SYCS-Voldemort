//! 文字の描画と震度の札が、本物の Python（Pillow 13.0.0・numpy）と画素まで同じことを確かめる。
//!
//! 基準は `tests/fixtures/expected.json`。`tests/fixtures/generate.py` が、本番と同じ環境の Python
//! （python:3.13-slim ＋ apt の ffmpeg・fonts-noto-cjk ＋ requirements.txt）で作る。ハッシュにするバイト列の
//! 並びは generate.py の冒頭の説明と同じ。
//!
//! フォント（apt の `fonts-noto-cjk`）が要るので、手元の `cargo test` では飛ばす（`#[ignore]`）。CI
//! （.github/workflows/rust.yml）はフォントを入れて `--include-ignored` で必ず回す。**フォントが無い・中身が
//! 基準と違うときは落とす**（素通りさせると、何も確かめずに緑になる）。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use image::{Rgba, RgbaImage};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sycs_text::badge;
use sycs_text::{Anchor, FontSpec, PillowText, TextMask, TextPainter};

/// 基準。
fn expected() -> &'static Value {
    static EXPECTED: OnceLock<Value> = OnceLock::new();
    EXPECTED.get_or_init(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/expected.json");
        let text = std::fs::read_to_string(&path).expect("基準（expected.json）を読めない");
        serde_json::from_str(&text).expect("基準が JSON でない")
    })
}

/// 基準を作ったときと同じフォントのファイルか（ハッシュ）を確かめてから読む。両方の太さを読む。
fn painter() -> &'static PillowText {
    static PAINTER: OnceLock<PillowText> = OnceLock::new();
    PAINTER.get_or_init(|| {
        let fonts = &expected()["fonts"];
        for (name, path) in [
            ("regular", sycs_text::REGULAR_FONT_PATHS[0]),
            ("bold", sycs_text::BOLD_FONT_PATHS[0]),
        ] {
            let data = std::fs::read(path).unwrap_or_else(|error| {
                panic!("フォント {path} が無い（apt の fonts-noto-cjk を入れる）: {error}")
            });
            assert_eq!(
                hex::encode(Sha256::digest(&data)),
                fonts[name]["sha256"].as_str().unwrap(),
                "{path} が基準を作ったときのフォントと違う（Debian の fonts-noto-cjk の版が違う）"
            );
            assert_eq!(fonts[name]["path"].as_str(), Some(path));
        }
        PillowText::load(true, true).expect("フォントを読めない")
    })
}

/// 文字列の値。
fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// 大きさと太さ。
fn font_of(entry: &Value) -> FontSpec {
    FontSpec {
        size: entry["size"].as_u64().unwrap() as u32,
        bold: entry["bold"].as_bool().unwrap(),
    }
}

/// 2 文字の anchor。
fn anchor_of(value: &Value) -> Anchor {
    let name = text(value).as_bytes();
    Anchor([name[0], name[1]])
}

/// 4 つの数（色）。
fn rgba_of(value: &Value) -> [u8; 4] {
    let parts: Vec<u8> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    parts.try_into().unwrap()
}

/// 濃さの絵を、generate.py の `mask_bytes` と同じ並びでハッシュに足す。
fn update_mask(digest: &mut Sha256, mask: &TextMask) {
    digest.update(mask.width.to_le_bytes());
    digest.update(mask.height.to_le_bytes());
    digest.update(mask.offset.0.to_le_bytes());
    digest.update(mask.offset.1.to_le_bytes());
    digest.update(&mask.pixels);
}

/// `font.getmask2(text, "L", anchor=…, start=…)`。
fn mask(text: &str, font: FontSpec, anchor: Anchor, start: (f32, f32)) -> TextMask {
    painter()
        .mask(text, font, anchor, start)
        .unwrap_or_else(|| panic!("{text:?} を描けない（{font:?}）"))
}

/// 違いを読みやすく並べる（どの例が違ったか）。
fn report(failures: &[String], total: usize, what: &str) {
    assert!(
        failures.is_empty(),
        "{what}: {} / {total} 件が Python と違う\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// フォントのファイルが、基準を作った Python の環境のものと同じこと（ハッシュ）。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn the_fonts_are_the_ones_python_used() {
    let environment = &expected()["environment"];
    assert_eq!(text(&environment["pillow"]), "13.0.0");
    assert_eq!(text(&environment["freetype"]), "2.14.3");
    painter();
}

/// 1 文字ずつ: 長さ（26.6）と、濃さの絵（大きさ・ずれ・各画素）が同じこと。
///
/// 太さ・大きさ・文字の種類（ASCII・かな・使う字・JIS 第 1・第 2 水準の漢字）ごとにハッシュ 1 つ。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn single_characters_match_pillow() {
    let blocks = expected()["char_blocks"].as_object().unwrap();
    let entries = expected()["chars"].as_array().unwrap();
    let mut failures = Vec::new();
    let mut characters = 0usize;
    for entry in entries {
        let font = font_of(entry);
        let block = text(&entry["block"]);
        let mut digest = Sha256::new();
        for ch in text(&blocks[block]).chars() {
            let one = ch.to_string();
            let length = painter().length_26_6(&one, font).unwrap();
            digest.update(u32::from(ch).to_le_bytes());
            digest.update(length.to_le_bytes());
            update_mask(&mut digest, &mask(&one, font, Anchor(*b"la"), (0.0, 0.0)));
            characters += 1;
        }
        if hex::encode(digest.finalize()) != text(&entry["sha256"]) {
            failures.push(format!("  {font:?} {block}"));
        }
    }
    assert!(entries.len() >= 40, "基準が少なすぎる（{}）", entries.len());
    assert!(
        characters > 20_000,
        "確かめた文字が少なすぎる（{characters}）"
    );
    report(&failures, entries.len(), "1 文字ずつ");
}

/// 文ごと: `getlength`・`getbbox`（18 通りの anchor）・`getmask2`（4 通りの anchor × 3 通りの始点）が同じこと。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn strings_match_pillow() {
    let texts: Vec<&str> = expected()["texts"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    let anchors: Vec<Anchor> = expected()["anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(anchor_of)
        .collect();
    let mask_anchors: Vec<Anchor> = expected()["mask_anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(anchor_of)
        .collect();
    let starts: Vec<(f32, f32)> = expected()["starts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|start| {
            let start = start.as_array().unwrap();
            (
                start[0].as_f64().unwrap() as f32,
                start[1].as_f64().unwrap() as f32,
            )
        })
        .collect();
    assert_eq!(anchors.len(), 18);
    let entries = expected()["strings"].as_array().unwrap();
    let mut failures = Vec::new();
    for entry in entries {
        let font = font_of(entry);
        let max_chars = entry["max_chars"].as_u64().unwrap() as usize;
        let (mut lengths, mut boxes, mut masks) = (Sha256::new(), Sha256::new(), Sha256::new());
        for &line in &texts {
            lengths.update(painter().length_26_6(line, font).unwrap().to_le_bytes());
            for &anchor in &anchors {
                let (left, top, right, bottom) = painter().bbox(line, font, anchor).unwrap();
                for v in [left, top, right, bottom] {
                    boxes.update(v.to_le_bytes());
                }
            }
            // Python の len() は文字（コードポイント）の数。
            if line.chars().count() > max_chars {
                continue;
            }
            for &anchor in &mask_anchors {
                for &start in &starts {
                    update_mask(&mut masks, &mask(line, font, anchor, start));
                }
            }
        }
        for (name, digest) in [("lengths", lengths), ("boxes", boxes), ("masks", masks)] {
            if hex::encode(digest.finalize()) != text(&entry[name]) {
                failures.push(format!("  {font:?} {name}"));
            }
        }
    }
    assert!(texts.len() > 100, "文が少なすぎる（{}）", texts.len());
    report(&failures, entries.len() * 3, "文ごと");
}

/// 画像に描く（`ImageDraw.text`）: 下地・座標（小数を含む）・色・anchor・複数行を変えた例が、全画素同じこと。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn drawing_matches_pillow() {
    let entries = expected()["draws"].as_array().unwrap();
    let mut failures = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let font = font_of(entry);
        let canvas = entry["canvas"].as_array().unwrap();
        let (width, height) = (
            canvas[0].as_u64().unwrap() as u32,
            canvas[1].as_u64().unwrap() as u32,
        );
        let xy = entry["xy"].as_array().unwrap();
        let xy = (xy[0].as_f64().unwrap(), xy[1].as_f64().unwrap());
        let line = text(&entry["text"]);
        let anchor = anchor_of(&entry["anchor"]);
        let mut image = RgbaImage::from_pixel(width, height, Rgba(rgba_of(&entry["background"])));
        painter().draw_text(&mut image, xy, line, font, rgba_of(&entry["fill"]), anchor);
        if hex::encode(Sha256::digest(image.as_raw())) != text(&entry["sha256"]) {
            failures.push(format!(
                "  {i}: {font:?} {line:?} {:?} {xy:?}",
                text(&entry["anchor"])
            ));
        }
    }
    assert!(entries.len() >= 300, "例が少なすぎる（{}）", entries.len());
    report(&failures, entries.len(), "画像に描く");
}

/// `textbbox`・`textlength`（口の形のまま）が、`getbbox`・`getlength` と食い違わないこと（複数行も）。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn the_painter_interface_agrees_with_the_font_calls() {
    let font = FontSpec {
        size: 26,
        bold: false,
    };
    for line in ["茨城県沖", "M5.2", " 茨城県沖 ", ""] {
        let length = painter().length_26_6(line, font).unwrap();
        assert_eq!(painter().text_length(line, font), length as f64 / 64.0);
        for anchor in [*b"la", *b"ls", *b"mm", *b"rd"] {
            let (left, top, right, bottom) = painter().bbox(line, font, Anchor(anchor)).unwrap();
            assert_eq!(
                painter().text_bbox((10.0, 20.0), line, font, Anchor(anchor)),
                (left + 10, top + 20, right + 10, bottom + 20)
            );
        }
    }
    // 複数行: 1 行目と 2 行目の箱を合わせたもの。2 行目は「A の箱の下端＋4」だけ下。
    let spacing = painter().bbox("A", font, Anchor(*b"la")).unwrap().3 + 4;
    let first = painter().bbox("震度", font, Anchor(*b"la")).unwrap();
    let second = painter().bbox("分布", font, Anchor(*b"la")).unwrap();
    assert_eq!(
        painter().text_bbox((0.0, 0.0), "震度\n分布", font, Anchor(*b"la")),
        (
            first.0.min(second.0),
            first.1,
            first.2.max(second.2),
            second.3 + spacing
        )
    );
    // 複数行で「絵の上・下」に合わせる anchor は Python では例外。ここでは何も描かない。
    assert_eq!(
        painter().text_bbox((0.0, 0.0), "a\nb", font, Anchor(*b"lt")),
        (0, 0, 0, 0)
    );
}

/// 札 9 枚: 文字を置く前の地（720×720）・それを縮めたもの・文字だけの層・できあがり（PNG を読み戻した画素）が、
/// 全部 Python と同じこと。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn badges_match_python() {
    let entries = expected()["badges"].as_object().unwrap();
    let mut failures = Vec::new();
    let mut seen = BTreeMap::new();
    for (scale, want) in entries {
        let scale: i64 = scale.parse().unwrap();
        let base = badge::badge_base(720, 720, badge::fill_rgb(scale));
        let small = badge::resize_lanczos(&base, 240, 240);
        let over = badge::badge_text_layer(painter(), scale).unwrap();
        let full = badge::render_badge(painter(), scale).unwrap();
        let png = badge::encode_png(&full).unwrap();
        let decoded = image::load_from_memory(&png).unwrap().to_rgba8();
        assert_eq!(decoded, full, "PNG を読み戻すと同じ画素");
        for (name, image) in [
            ("base", &base),
            ("small", &small),
            ("text", &over),
            ("full", &full),
        ] {
            if hex::encode(Sha256::digest(image.as_raw())) != text(&want[name]) {
                failures.push(format!("  震度 {scale} の {name}"));
            }
        }
        seen.insert(scale, full);
    }
    assert_eq!(
        seen.keys().copied().collect::<Vec<_>>(),
        [10, 20, 30, 40, 45, 50, 55, 60, 70]
    );
    report(&failures, entries.len() * 4, "札");
}

/// Bot が呼ぶ口（フォントを読むところから PNG まで）でも、同じ画素の札になること。
#[test]
#[ignore = "fonts-noto-cjk が要る（CI は --include-ignored で回す）"]
fn generate_badge_produces_the_python_pixels() {
    painter();
    let png = badge::generate_badge(55).unwrap();
    let image = image::load_from_memory(&png).unwrap().to_rgba8();
    assert_eq!(
        hex::encode(Sha256::digest(image.as_raw())),
        text(&expected()["badges"]["55"]["full"])
    );
}
