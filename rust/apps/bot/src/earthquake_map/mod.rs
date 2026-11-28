//! 震度の地図（地震の通知の Embed に付ける画像）。Python の `services/earthquake_service.py` の
//! `_generate_intensity_map` 以下（約 600 行）。**Python（Pillow）が作る画像と、画素まで同じものを作る。**
//!
//! 流れは Python と同じ:
//!
//! 1. 観測点を県ごとにまとめ、全部と震源が入るズームと範囲を決める（[`compose::plan`]）
//! 2. その範囲の白地図のタイル（国土地理院）を、全部いっぺんに取りに行く（[`MapRenderer`]。1 枚 3 秒まで。
//!    取れない枚があっても待たずに進む。その枡は海の色のまま）。同時に、文字を描く部品（フォント）を読む
//! 3. タイルを暗い色に塗り替えて貼り、県の塗り・震源・震度の札・地名・題と凡例と出典を描く
//!    （[`compose::compose`]。重いので別のスレッドで）
//! 4. PNG にする
//!
//! - [`geo`] … 緯度・経度から画素への計算（Python と最後の桁まで同じにしてある）と、県庁所在地・県の形
//! - [`tiles`] … タイルの復号と塗り替え
//! - [`compose`] … 配置の決め方と、全体の組み立て
//! - 図形・重ね合わせ・拡大縮小・ぼかし（Pillow の写し）は別の crate（`sycs-imaging`）。画素を 1 つずつ回す
//!   ので、テストのビルドでも最適化が効くように分けてある
//! - 文字は [`crate::earthquake_text::TextPainter`] を通して描く
//!
//! Python と同じことは `tests/earthquake_map_golden.rs` が毎回確かめる（図形ごと・部品ごと・地図の全体）。
//! タイルの取り方は `tests/earthquake_map_fake.rs` が、テストの中に立てた偽物の配信元で確かめる。
//!
//! Python と違うところ:
//!
//! - PNG のバイト列は同じにならない（圧縮の実装が違う）。画素は同じ
//! - タイルは PNG だけを読む（Pillow は JPEG なども読める。国土地理院の白地図は PNG）
//! - フォントが無いときは地図を作らない（Python は Pillow の内蔵の欧文フォントへ落として、和字が □ の地図を
//!   出す。本番のイメージには `fonts-noto-cjk` が入っているので、どちらも起きない）

pub mod compose;
pub mod geo;
pub mod tiles;

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error};

use crate::earthquake::{Images, MapRequest};
use crate::earthquake_text::{FontError, PillowText, TextPainter};

/// 地図のタイルの場所（`{z}`・`{x}`・`{y}` を差し替える）。Python の `_TILE_URL`。
///
/// 国土地理院の白地図（blank）。鍵は要らず、出典を書けば使える（政府標準利用規約）。
pub const TILE_URL: &str = "https://cyberjapandata.gsi.go.jp/xyz/blank/{z}/{x}/{y}.png";
/// タイルを取るときに名乗る名前。Python の `_TILE_UA`。
pub const TILE_USER_AGENT: &str = "VoldermortBot/1.0 (earthquake alert; contact: github)";
/// 1 枚のタイルを待つ上限。Python の `aiohttp.ClientTimeout(total=3)`。
pub const TILE_TIMEOUT: Duration = Duration::from_secs(3);

/// 本番の文字の部品を用意する関数の型（[`load_fonts`]）。
pub type Fonts = fn() -> Result<PillowText, FontError>;

/// 本番の文字の部品を用意する。地図は通常の字面だけを使う（太字は読まない）。
pub fn load_fonts() -> Result<PillowText, FontError> {
    PillowText::load(true, false)
}

/// 本番の地図の作り手（国土地理院の配信元・本物の文字）。
pub fn production_renderer() -> MapRenderer<Fonts> {
    MapRenderer::new(load_fonts)
}

/// 震度の地図を作るもの。1 つを使い回す。
///
/// `fonts` は、地図を 1 枚作るたびに文字を描く部品を用意する関数（本番は [`load_fonts`]。フォントを 1 本
/// 約 20MB 読むので、1 枚描き終わったら捨てる）。用意できなければ、その地図は作らない。
pub struct MapRenderer<F> {
    http: reqwest::Client,
    tile_url: String,
    fonts: Arc<F>,
}

impl<F, T, E> MapRenderer<F>
where
    F: Fn() -> Result<T, E> + Send + Sync + 'static,
    T: TextPainter + Send + 'static,
    E: Display + Send + 'static,
{
    /// 作る（本番の配信元と待ち時間で）。
    pub fn new(fonts: F) -> Self {
        Self::with_tiles(TILE_URL, TILE_TIMEOUT, fonts)
    }

    /// タイルの場所と待ち時間も決めて作る（テストで、偽物の配信元に向けるため）。
    pub fn with_tiles(tile_url: &str, timeout: Duration, fonts: F) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(TILE_USER_AGENT)
            .build()
            .unwrap_or_default();
        Self {
            http,
            tile_url: tile_url.into(),
            fonts: Arc::new(fonts),
        }
    }

    /// タイルを 1 枚取る。Python の `_fetch_tile`。PNG のバイト列のまま返す（復号は描くときに）。
    ///
    /// 200 以外・時間切れ・つながらないときは `None`（タイルなしで描き続ける）。
    async fn fetch_tile(&self, zoom: u32, x: i64, y: i64) -> Option<Vec<u8>> {
        let url = self
            .tile_url
            .replace("{z}", &zoom.to_string())
            .replace("{x}", &x.to_string())
            .replace("{y}", &y.to_string());
        let fetched = async {
            let response = self.http.get(&url).send().await?;
            if response.status().as_u16() != 200 {
                return Ok(None);
            }
            Ok::<_, reqwest::Error>(Some(response.bytes().await?.to_vec()))
        };
        fetched.await.unwrap_or_else(|e| {
            debug!("[earthquake] tile {zoom}/{x}/{y} fetch error: {e}");
            None
        })
    }

    /// 震度の地図（PNG）を作る。Python の `_quake_map` の中身（`_generate_intensity_map`）。
    ///
    /// 打てる点が無ければ `None`。途中で失敗しても `None`（地図が 1 枚足りないだけで、通知は出す）。
    pub async fn render(&self, request: &MapRequest) -> Option<Vec<u8>> {
        let points = match compose::plot_points(&request.points) {
            Ok(points) => points,
            Err(e) => {
                error!("[earthquake] map generation error: {e:?}");
                return None;
            }
        };
        let plan = compose::plan(request.lat, request.lon, points)?;
        // 全部のタイルを、いっぺんに取りに行く（Python の asyncio.gather。多くて 24 枚）。待つ間に、別の
        // スレッドでフォントを読む（ファイルを読むので、非同期の処理を止めないように）。
        let fonts = Arc::clone(&self.fonts);
        let (tiles, text) = tokio::join!(
            futures_util::future::join_all(
                plan.coords
                    .iter()
                    .map(|(x, y)| self.fetch_tile(plan.zoom, *x, *y)),
            ),
            tokio::task::spawn_blocking(move || fonts()),
        );
        let text = match text {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                error!("[earthquake] map generation error: {e}");
                return None;
            }
            Err(e) => {
                error!("[earthquake] map generation error: {e}");
                return None;
            }
        };
        // ここから先は重い（塗り替え・合成・描画・PNG）。別のスレッドへ逃がす（Python の asyncio.to_thread）。
        let (lat, lon) = (request.lat, request.lon);
        let (title, subtitle) = (request.title.clone(), request.subtitle.clone());
        let drawn = tokio::task::spawn_blocking(move || {
            let scene = compose::Scene {
                plan: &plan,
                tiles: &tiles,
                lat,
                lon,
                title: &title,
                subtitle: &subtitle,
            };
            let image = compose::compose(&scene, geo::prefecture_shapes(), &text)
                .map_err(|e| format!("{e:?}"))?;
            compose::encode_png(&image).ok_or_else(|| "PNG にできませんでした".to_string())
        })
        .await;
        match drawn {
            Ok(Ok(png)) => Some(png),
            Ok(Err(e)) => {
                error!("[earthquake] map generation error: {e}");
                None
            }
            Err(e) => {
                error!("[earthquake] map generation error: {e}");
                None
            }
        }
    }
}

/// 札は `badges` に任せ、地図を [`MapRenderer`] で作る [`Images`]。
pub struct WithMap<B, F> {
    /// 最大震度の札を作るもの。
    pub badges: B,
    /// 震度の地図を作るもの。
    pub map: MapRenderer<F>,
}

impl<B, F, T, E> Images for WithMap<B, F>
where
    B: Images,
    F: Fn() -> Result<T, E> + Send + Sync + 'static,
    T: TextPainter + Send + 'static,
    E: Display + Send + 'static,
{
    async fn badge(&self, scale: i64) -> Option<Vec<u8>> {
        self.badges.badge(scale).await
    }

    async fn map(&self, request: &MapRequest) -> Option<Vec<u8>> {
        self.map.render(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 配信元・名乗る名前・待ち時間が Python と同じであること。
    #[test]
    fn the_tile_source_matches_python() {
        let python = include_str!("../../../../../services/earthquake_service.py");
        assert!(python.contains(&format!("_TILE_URL = \"{TILE_URL}\"")));
        assert!(python.contains(&format!("_TILE_UA = \"{TILE_USER_AGENT}\"")));
        assert!(python.contains("timeout=aiohttp.ClientTimeout(total=3),"));
        assert_eq!(TILE_TIMEOUT, Duration::from_secs(3));
        assert!(python.contains(&format!(
            "_TILE_ATTRIBUTION = \"{}\"",
            compose::TILE_ATTRIBUTION
        )));
    }

    /// 埋め込んだ県の形が、リポジトリの直下（Python が読むもの）と同じファイルであること。
    #[test]
    fn the_embedded_shapes_are_the_file_python_reads() {
        let python_side = include_str!("../../../../../assets/jp_prefectures.json");
        let embedded = include_str!("../../assets/jp_prefectures.json");
        assert!(python_side == embedded, "assets/jp_prefectures.json と違う");
        let shapes = geo::prefecture_shapes();
        assert_eq!(shapes.len(), 47);
        for (name, _, _) in geo::PREF_CENTERS {
            assert!(shapes.contains_key(name), "{name} の形が無い");
        }
    }

    /// 色・大きさ・県庁所在地の表が Python と同じであること（Python のソースと突き合わせる）。
    #[test]
    fn the_tables_match_python() {
        let python = include_str!("../../../../../services/earthquake_service.py");
        for (name, lat, lon) in geo::PREF_CENTERS {
            let line = format!("    \"{name}\": ({lat:.3}, {lon:.3}),");
            assert!(python.contains(&line), "{line}");
        }
        assert_eq!(python.matches("\": (").count(), 47, "県の数");
        for (value, label) in [
            (10, "1"),
            (20, "2"),
            (30, "3"),
            (40, "4"),
            (45, "5-"),
            (50, "5+"),
            (55, "6-"),
            (60, "6+"),
            (70, "7"),
        ] {
            let scale = compose::Scale::new(value);
            let [r, g, b] = scale.fill_rgb();
            assert!(
                python.contains(&format!("    {value}: ({r}, {g}, {b}),")),
                "{value} の色"
            );
            assert!(
                python.contains(&format!("    {value}: \"{label}\",")),
                "{value} の字"
            );
            assert_eq!(scale.badge_label(), label);
        }
        let [r, g, b] = tiles::MAP_SEA;
        assert!(python.contains(&format!("_MAP_SEA = ({r}, {g}, {b})")));
        let [r, g, b] = tiles::MAP_LAND;
        assert!(python.contains(&format!("_MAP_LAND = ({r}, {g}, {b})")));
        let [r, g, b] = tiles::MAP_LINE;
        assert!(python.contains(&format!("_MAP_LINE = ({r}, {g}, {b})")));
        let (w, h) = tiles::MAP_SIZE;
        assert!(python.contains(&format!("_MAP_W, _MAP_H = {w}, {h}")));
        assert!(python.contains(&format!("_MAP_SS = {}", compose::MAP_SS)));
        assert!(python.contains(&format!("_TILE_SZ = {}", tiles::TILE_SIZE)));
    }
}
