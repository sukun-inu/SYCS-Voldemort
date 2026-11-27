//! 最大震度の札（Embed のサムネイル）。Python の `_generate_badge` が作る画像を、そのまま持っておく。
//!
//! 札は震度の値だけで決まる（9 通り）。そこで、本物の Python（Pillow・numpy・本番と同じフォント）が作った
//! PNG を `assets/earthquake/` に置き、実行ファイルに埋め込む。Python の出力そのものなので、画素まで同じ
//! （描く処理を Rust に写して合わせ込むより確かで、文字の描画〔FreeType〕の違いも入らない）。
//!
//! 絵柄を変えるときは、`assets/earthquake/generate.py` で作り直す（Python の描き方が要る）。
//!
//! 地図（震度の分布）は震源と観測点で変わるので、持っておけない。まだ付かない。

use crate::earthquake::{Images, MapRequest};

/// 震度の値 → 札の PNG。知らない震度（-1・0・99 など）は `None`（Python も札にしない）。
pub fn badge_png(scale: i64) -> Option<&'static [u8]> {
    Some(match scale {
        10 => include_bytes!("../assets/earthquake/badge_10.png"),
        20 => include_bytes!("../assets/earthquake/badge_20.png"),
        30 => include_bytes!("../assets/earthquake/badge_30.png"),
        40 => include_bytes!("../assets/earthquake/badge_40.png"),
        45 => include_bytes!("../assets/earthquake/badge_45.png"),
        50 => include_bytes!("../assets/earthquake/badge_50.png"),
        55 => include_bytes!("../assets/earthquake/badge_55.png"),
        60 => include_bytes!("../assets/earthquake/badge_60.png"),
        70 => include_bytes!("../assets/earthquake/badge_70.png"),
        _ => return None,
    })
}

/// 札だけを付ける（地図はまだ作らない）。
pub struct PrerenderedBadges;

impl Images for PrerenderedBadges {
    async fn badge(&self, scale: i64) -> Option<Vec<u8>> {
        badge_png(scale).map(<[u8]>::to_vec)
    }

    async fn map(&self, _request: &MapRequest) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    /// 札の画素（240×240 の RGBA）のハッシュ。本物の Python の出力から取った値。
    const PIXELS: &[(i64, &str)] = &[
        (
            10,
            "07988687452025b687f33f91206113a74ba22d14e7f430fe63e594768b9daaba",
        ),
        (
            20,
            "9454ed61c426e9bfc936d8f8c78d8c4b50f585c420aea5f330fb0942714fd445",
        ),
        (
            30,
            "db7210e3f16ad13b6c25bba6b0c04f56533607f2dbf63c403995e79a206127cc",
        ),
        (
            40,
            "d1fb0f27a473e03fa4480322381a611a1b2f0f900af0326b32c319d3b69480cb",
        ),
        (
            45,
            "1693491dd0a703e0fbe92f3befc973cf9f8e58e82626bbae1af8706f4de394b5",
        ),
        (
            50,
            "9581a4e33e1c534d67fee3ba14dd2ed570b0f73acb08d1912ee17cc75bf2cfe8",
        ),
        (
            55,
            "9fa0453854030b73c7a838ad67c0866846ae47da55707d65bb3ab24e88b5ae3c",
        ),
        (
            60,
            "c256bb2e4e9b6fd55049740ceca24575a317cb919ccf134a99deee117fefc81b",
        ),
        (
            70,
            "2fe88d7341601fa19530662543e0c67db3b12c4cd4c4fbf84e3f7820694262fc",
        ),
    ];

    /// 9 枚とも読める PNG で、画素が Python の出力と同じであること（差し替え・壊れに気づけるように）。
    #[test]
    fn every_badge_has_the_pixels_python_made() {
        for (scale, want) in PIXELS {
            let png = badge_png(*scale).unwrap_or_else(|| panic!("震度の値 {scale} の札が無い"));
            let image = image::load_from_memory(png).unwrap().to_rgba8();
            assert_eq!((image.width(), image.height()), (240, 240), "{scale}");
            assert_eq!(
                hex::encode(Sha256::digest(image.as_raw())),
                *want,
                "{scale}"
            );
        }
    }

    /// 震度ごとに別の札であること（取り違えていない）。
    #[test]
    fn each_scale_has_its_own_badge() {
        let mut seen = std::collections::HashSet::new();
        for (scale, _) in PIXELS {
            assert!(
                seen.insert(badge_png(*scale).unwrap()),
                "{scale} が他と同じ"
            );
        }
    }

    /// 知らない震度は札にしないこと（「最大震度 -1」の札を貼らない）。Python の `_badge_glyphs` と同じ。
    #[test]
    fn unknown_scales_have_no_badge() {
        for scale in [-1, 0, 15, 46, 65, 99] {
            assert!(badge_png(scale).is_none(), "{scale}");
        }
    }

    /// 札は付け、地図は付けないこと。
    #[tokio::test]
    async fn only_badges_are_provided() {
        assert_eq!(PrerenderedBadges.badge(40).await.as_deref(), badge_png(40));
        assert!(PrerenderedBadges.badge(-1).await.is_none());
        let request = MapRequest {
            lat: 36.5,
            lon: 141.0,
            points: Vec::new(),
            title: String::new(),
            subtitle: String::new(),
        };
        assert!(PrerenderedBadges.map(&request).await.is_none());
    }
}
