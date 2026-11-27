//! 最大震度の札（Embed のサムネイル）を付ける。Python の `_quake_badge`・`_generate_badge` にあたる。
//!
//! 札は Rust で描く（`sycs_text::badge`。Python の `_generate_badge` と全画素が同じ）。以前は Python が作った
//! PNG を実行ファイルに埋め込んでいたが、絵柄を変えるたびに Python が要るので、やめた。
//!
//! 描くにはフォント（`fonts-noto-cjk` の NotoSansCJK-Bold.ttc）が要る。無ければ札なしで通知する
//! （Python は Pillow の内蔵フォントで欧文の札を作るが、それは写していない。本番のイメージには入れてある）。
//!
//! 地図（震度の分布）は別の部品が作る。ここでは付けない。

use tracing::warn;

use crate::earthquake::{Images, MapRequest};

/// 札を Rust で描いて付ける。
pub struct DrawnBadges;

impl Images for DrawnBadges {
    /// 描く処理（フォントの読み込み・塗り・PNG）は重いので、別のスレッドで回す（Python の
    /// `asyncio.to_thread(_generate_badge, …)`）。作れなくても通知は出す（`_quake_badge` と同じ）。
    async fn badge(&self, scale: i64) -> Option<Vec<u8>> {
        if sycs_text::badge::badge_glyphs(scale).is_none() {
            // 呼ぶ側も震度が分かるときだけ呼ぶが、「最大震度 -1」の札を貼る事故はここでも止める。
            warn!("[earthquake] 震度 {scale} は札にできないので作りません");
            return None;
        }
        match tokio::task::spawn_blocking(move || sycs_text::badge::generate_badge(scale)).await {
            Ok(Ok(png)) => Some(png),
            Ok(Err(error)) => {
                warn!("[earthquake] 震度の札を作れませんでした: {error}");
                None
            }
            Err(error) => {
                warn!("[earthquake] 震度の札を作る処理が落ちました: {error}");
                None
            }
        }
    }

    async fn map(&self, _request: &MapRequest) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 知らない震度では、フォントを読みにも行かずに「付けない」こと（Python の `_badge_glyphs` が None）。
    #[tokio::test]
    async fn unknown_scales_have_no_badge() {
        for scale in [-1, 0, 15, 46, 65, 99] {
            assert!(DrawnBadges.badge(scale).await.is_none(), "{scale}");
        }
    }

    /// 地図は付けないこと。
    #[tokio::test]
    async fn maps_are_not_provided() {
        let request = MapRequest {
            lat: 36.5,
            lon: 141.0,
            points: Vec::new(),
            title: String::new(),
            subtitle: String::new(),
        };
        assert!(DrawnBadges.map(&request).await.is_none());
    }

    /// 知っている震度では、フォントがあれば 240×240 の PNG を、無ければ「付けない」を返すこと
    /// （どちらでも落ちない。画素が Python と同じことは `sycs-text` の `tests/golden.rs` が確かめる）。
    #[tokio::test]
    async fn known_scales_yield_a_badge_when_the_font_is_installed() {
        let font_installed = sycs_text::BOLD_FONT_PATHS
            .iter()
            .chain(&sycs_text::REGULAR_FONT_PATHS)
            .any(|path| std::path::Path::new(path).exists());
        let badge = DrawnBadges.badge(40).await;
        assert_eq!(badge.is_some(), font_installed);
        if let Some(png) = badge {
            let image = image::load_from_memory(&png).unwrap().to_rgba8();
            assert_eq!((image.width(), image.height()), (240, 240));
            assert_eq!(image.get_pixel(0, 0).0[3], 0, "四隅は透明");
            assert_eq!(image.get_pixel(120, 120).0[3], 255, "真ん中は不透明");
        }
    }
}
