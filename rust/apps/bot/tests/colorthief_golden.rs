//! 代表色が Python の colorthief 0.2.1 と同じになること。
//!
//! 基準の画像と答えは `fixtures/colorthief/`（generate.py が Pillow で作り、本物の colorthief で
//! 答えを出した）。透過・パレット・グレー・GIF・動く GIF・ほぼ白・全部透明など、復号の道筋と
//! 色の数えかたの違いが出やすいものを 1 枚ずつ置いてある。
//!
//! 色がずれると、移行の途中で Python と Rust の Bot が同じ人のログを違う色で出す。

use sycs_bot::log_channel::colour_of_image;

#[test]
fn colours_match_python_colorthief() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/colorthief");
    let expected = std::fs::read_to_string(format!("{dir}/expected.txt")).unwrap();
    let mut checked = 0;
    let mut wrong = Vec::new();
    for line in expected.lines().filter(|l| !l.trim().is_empty()) {
        let (name, want) = line.split_once(' ').expect("「名前 色」の形");
        let bytes = std::fs::read(format!("{dir}/{name}")).unwrap();
        let got =
            colour_of_image(&bytes).map_or_else(|| "none".to_string(), |c| format!("{c:06x}"));
        if got != want {
            wrong.push(format!("{name}: Python {want} / Rust {got}"));
        }
        checked += 1;
    }
    assert!(checked >= 16, "基準の画像が足りない（{checked} 枚）");
    assert!(wrong.is_empty(), "Python と違う:\n{}", wrong.join("\n"));
}
