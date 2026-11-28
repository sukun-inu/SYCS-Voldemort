//! 震度の地図を、テストの中に立てた偽物のタイルの配信元から作る。
//!
//! 本物の配信元（国土地理院）には取りに行かない。偽物は、`fixtures/earthquake_map/tiles/` の見本を
//! 決まった規則（`gen_maps.py` の `tile_rule`）で配る。出来上がった PNG を復号した画素が、Python が同じ
//! タイルから作ったもの（`maps.json` の最終の段）と同じことを確かめる。文字は描かない偽物に差し替える
//! （文字以外の画素を比べる。基準も文字なしで作ってある）。
//!
//! 取り方の決まりは Python（`_fetch_tile`・`_generate_intensity_map`）と同じ:
//!
//! - 要るタイルを全部、いっぺんに取りに行く
//! - 200 以外・時間切れ・つながらない・PNG でないものは「取れなかった」として、その枡を海の色のまま描く
//! - 名乗る名前（User-Agent）は Python と同じ
//!
//! 時間に頼るところは下限だけを見る（CI は遅い）。

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use sycs_bot::earthquake::{Images, MapRequest, NoImages};
use sycs_bot::earthquake_map::{MapRenderer, TILE_USER_AGENT, WithMap};
use sycs_bot::earthquake_text::{Anchor, FontSpec, TextPainter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/earthquake_map");

/// 文字を描かない偽物。文字の幅は、Python が返した値（基準に控えてある）を返す。
#[derive(Clone)]
struct SilentText(HashMap<String, f64>);

impl TextPainter for SilentText {
    fn text_length(&self, text: &str, font: FontSpec) -> f64 {
        let key = format!("{}|{}|{text}", font.size, u8::from(font.bold));
        *self
            .0
            .get(&key)
            .unwrap_or_else(|| panic!("Python が測っていない文字の幅を聞かれた: {key}"))
    }

    fn text_bbox(&self, _: (f64, f64), text: &str, _: FontSpec, _: Anchor) -> (i32, i32, i32, i32) {
        panic!("地図は textbbox を使わないはず: {text}");
    }

    fn draw_text(
        &self,
        _: &mut image::RgbaImage,
        _: (f64, f64),
        _: &str,
        _: FontSpec,
        _: [u8; 4],
        _: Anchor,
    ) {
    }
}

/// 基準（`maps.json`）と、そこから取り出すもの。
struct Golden {
    maps: Value,
    samples: Vec<Vec<u8>>,
}

impl Golden {
    fn load() -> Self {
        let text = std::fs::read_to_string(format!("{DIR}/maps.json")).unwrap();
        let samples = (0..6)
            .map(|i| std::fs::read(format!("{DIR}/tiles/tile_{i}.png")).unwrap())
            .collect();
        Self {
            maps: serde_json::from_str(&text).unwrap(),
            samples,
        }
    }

    fn case(&self, name: &str) -> &Value {
        self.maps["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("基準に {name} が無い"))
    }

    fn text(&self) -> SilentText {
        let lengths = self.maps["lengths"].as_object().unwrap();
        SilentText(
            lengths
                .iter()
                .map(|(key, bits)| {
                    let bits = u64::from_str_radix(bits.as_str().unwrap(), 16).unwrap();
                    (key.clone(), f64::from_bits(bits))
                })
                .collect(),
        )
    }

    /// 地図 1 枚ごとに文字の部品を用意する関数（本番の `load_fonts` の代わり）。
    fn fonts(&self) -> impl Fn() -> Result<SilentText, Infallible> + Send + Sync + 'static + use<> {
        let text = self.text();
        move || Ok(text.clone())
    }

    fn request(&self, name: &str) -> MapRequest {
        let case = self.case(name);
        MapRequest {
            lat: case["lat"].as_f64().unwrap(),
            lon: case["lon"].as_f64().unwrap(),
            points: case["points"].as_array().unwrap().clone(),
            title: case["title"].as_str().unwrap().into(),
            subtitle: case["subtitle"].as_str().unwrap().into(),
        }
    }

    /// Python が作った、出来上がりの画素（1200×720 の RGB）のハッシュ。
    fn final_pixels(&self, name: &str) -> &str {
        self.case(name)["stages"]["final"].as_str().unwrap()
    }

    /// その地図が頼むはずのタイル（`/z/x/y` の形）。
    fn wanted_tiles(&self, name: &str) -> BTreeSet<String> {
        let plan = &self.case(name)["plan"];
        let zoom = plan["zoom"].as_i64().unwrap();
        plan["coords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| format!("/{zoom}/{}/{}", c[0], c[1]))
            .collect()
    }
}

/// PNG を復号して、画素（RGB）のハッシュを出す。大きさと色の形も確かめる。
fn pixels_of(png: &[u8]) -> String {
    let image = image::load_from_memory(png).unwrap();
    assert_eq!(
        image.color(),
        image::ColorType::Rgb8,
        "RGB の PNG であること"
    );
    assert_eq!((image.width(), image.height()), (1200, 720));
    hex::encode(Sha256::digest(image.to_rgb8().as_raw()))
}

/// 偽物の返事。
#[derive(Clone)]
enum Reply {
    /// この状態と本文を返す。
    Status(u16, Vec<u8>),
    /// 何も返さない（時間切れになるまで待たせる）。
    Hang,
}

/// 偽物が受けた要求。
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    /// `/z/x/y` の形。
    tile: String,
    user_agent: String,
}

struct Fake {
    /// タイルの場所の型紙（`{z}`・`{x}`・`{y}` 入り）。
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// 偽物の配信元を立てる。`rule(z, x, y)` で返事を決める。`hold_until` 件の要求が届くまでは、どの要求にも
/// 答えない（全部をいっぺんに取りに来ていることを、時間を測らずに確かめるため）。
async fn start_tiles<F>(rule: F, hold_until: usize) -> Fake
where
    F: Fn(i64, i64, i64) -> Reply + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/xyz/blank/{{z}}/{{x}}/{{y}}.png",
        listener.local_addr().unwrap()
    );
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = Arc::clone(&seen);
    let rule = Arc::new(rule);
    let (arrived, _) = watch::channel(0_usize);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (log, rule, arrived) = (Arc::clone(&log), Arc::clone(&rule), arrived.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let mut first = head.lines().next().unwrap_or("").split(' ');
                let method = first.next().unwrap_or("").to_string();
                let path = first.next().unwrap_or("");
                let tile = path
                    .strip_prefix("/xyz/blank")
                    .and_then(|p| p.strip_suffix(".png"))
                    .unwrap_or(path)
                    .to_string();
                let user_agent = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("user-agent")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let numbers: Vec<i64> = tile.split('/').filter_map(|n| n.parse().ok()).collect();
                log.lock().unwrap().push(Seen {
                    method,
                    tile,
                    user_agent,
                });
                arrived.send_modify(|count| *count += 1);
                let mut enough = arrived.subscribe();
                if enough.wait_for(|count| *count >= hold_until).await.is_err() {
                    return;
                }
                let reply = match numbers[..] {
                    [z, x, y] => rule(z, x, y),
                    _ => Reply::Status(400, Vec::new()),
                };
                match reply {
                    Reply::Hang => tokio::time::sleep(Duration::from_secs(120)).await,
                    Reply::Status(status, body) => {
                        let head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(&body).await;
                        let _ = socket.shutdown().await;
                    }
                }
            });
        }
    });
    Fake { url, seen }
}

/// 見本を配る規則。`gen_maps.py` の `tile_rule` と同じ（`None` は「取れない」、`Some(None)` は「PNG でない」）。
fn sample_index(mode: &str, count: usize, z: i64, x: i64, y: i64) -> Option<Option<usize>> {
    if mode == "none" {
        return None;
    }
    if mode == "holes" {
        match (x + 2 * y).rem_euclid(5) {
            0 => return None,
            1 => return Some(None),
            _ => {}
        }
    }
    Some(Some((x * 3 + y * 5 + z).rem_euclid(count as i64) as usize))
}

/// 規則どおりに配る偽物の返事。取れないタイルは `missing` の返事にする。
fn by_rule(
    samples: Vec<Vec<u8>>,
    mode: &'static str,
    missing: Reply,
) -> impl Fn(i64, i64, i64) -> Reply + Send + Sync + 'static {
    move |z, x, y| match sample_index(mode, samples.len(), z, x, y) {
        None => missing.clone(),
        Some(None) => Reply::Status(200, b"this is not a png".to_vec()),
        Some(Some(index)) => Reply::Status(200, samples[index].clone()),
    }
}

/// 偽物から取ったタイルで描いた地図が、Python と同じ画素になること。取れないタイル（404）と壊れたタイル
/// （200 だが PNG でない）は飛ばして描くこと。要るタイルを 1 回ずつ、Python と同じ名乗りで取りに行くこと。
#[tokio::test(flavor = "multi_thread")]
async fn a_map_is_drawn_from_the_tiles_it_fetched() {
    let golden = Golden::load();
    let name = "tiles-with-holes";
    let fake = start_tiles(
        by_rule(
            golden.samples.clone(),
            "holes",
            Reply::Status(404, Vec::new()),
        ),
        0,
    )
    .await;
    let renderer = MapRenderer::with_tiles(&fake.url, Duration::from_secs(30), golden.fonts());
    let png = renderer.render(&golden.request(name)).await.expect("地図");
    assert_eq!(pixels_of(&png), golden.final_pixels(name));

    let seen = fake.seen.lock().unwrap().clone();
    let asked: BTreeSet<String> = seen.iter().map(|s| s.tile.clone()).collect();
    assert_eq!(asked, golden.wanted_tiles(name), "取りに行ったタイル");
    assert_eq!(
        seen.len(),
        asked.len(),
        "同じタイルを 2 回取りに行っていない"
    );
    for request in &seen {
        assert_eq!(request.method, "GET");
        assert_eq!(request.user_agent, TILE_USER_AGENT, "{}", request.tile);
    }
}

/// 要るタイルを全部いっぺんに取りに行くこと（Python の `asyncio.gather`）。
///
/// 偽物は、全部の要求が届くまでどれにも答えない。1 枚ずつ（または何枚かずつ）取りに行く作りだと、全部が
/// 届くことがなく、どのタイルも取れない（地図が Python と違う画素になる）。
#[tokio::test(flavor = "multi_thread")]
async fn every_tile_is_requested_at_once() {
    let golden = Golden::load();
    let name = "offshore-many";
    let count = golden.wanted_tiles(name).len();
    assert!(count >= 15, "タイルの数が少なすぎる（{count}）");
    let fake = start_tiles(
        by_rule(
            golden.samples.clone(),
            "all",
            Reply::Status(404, Vec::new()),
        ),
        count,
    )
    .await;
    let renderer = MapRenderer::with_tiles(&fake.url, Duration::from_secs(30), golden.fonts());
    let png = renderer.render(&golden.request(name)).await.expect("地図");
    assert_eq!(pixels_of(&png), golden.final_pixels(name));
    assert_eq!(fake.seen.lock().unwrap().len(), count);
}

/// 200 以外の返事は、中身が正しいタイルでも使わないこと（Python は `resp.status == 200` だけを使う）。
#[tokio::test(flavor = "multi_thread")]
async fn only_status_200_is_used() {
    let golden = Golden::load();
    let name = "no-tiles";
    let samples = golden.samples.clone();
    let fake = start_tiles(
        move |z, x, y| {
            let status = [404, 500, 403, 201, 206, 503][(x + y).rem_euclid(6) as usize];
            let index = (x * 3 + y * 5 + z).rem_euclid(samples.len() as i64) as usize;
            Reply::Status(status, samples[index].clone())
        },
        0,
    )
    .await;
    let renderer = MapRenderer::with_tiles(&fake.url, Duration::from_secs(30), golden.fonts());
    let png = renderer.render(&golden.request(name)).await.expect("地図");
    assert_eq!(pixels_of(&png), golden.final_pixels(name));
    assert_eq!(
        fake.seen.lock().unwrap().len(),
        golden.wanted_tiles(name).len()
    );
}

/// 返事の来ないタイルは、待ち時間で見切って、そのタイルなしで描くこと（地図そのものは出す）。
#[tokio::test(flavor = "multi_thread")]
async fn slow_tiles_are_given_up() {
    let golden = Golden::load();
    let name = "tiles-with-holes";
    let fake = start_tiles(by_rule(golden.samples.clone(), "holes", Reply::Hang), 0).await;
    let timeout = Duration::from_millis(1500);
    let renderer = MapRenderer::with_tiles(&fake.url, timeout, golden.fonts());
    let started = Instant::now();
    let png = renderer.render(&golden.request(name)).await.expect("地図");
    // 返事の来ないタイルを、待ち時間いっぱいまでは待っている（下限だけを見る）。
    assert!(started.elapsed() >= timeout, "{:?}", started.elapsed());
    assert_eq!(pixels_of(&png), golden.final_pixels(name));
}

/// 配信元につながらなくても、タイルなしの地図を出すこと。
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_source_still_gives_a_map() {
    let golden = Golden::load();
    let name = "no-tiles";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/xyz/blank/{{z}}/{{x}}/{{y}}.png",
        listener.local_addr().unwrap()
    );
    drop(listener);
    let renderer = MapRenderer::with_tiles(&url, Duration::from_secs(5), golden.fonts());
    let png = renderer.render(&golden.request(name)).await.expect("地図");
    assert_eq!(pixels_of(&png), golden.final_pixels(name));
}

/// 打てる点が無い・観測点の形が崩れているときは、地図を作らないこと（タイルも取りに行かない）。札は
/// 札の担当に任せること。
#[tokio::test(flavor = "multi_thread")]
async fn no_map_without_plottable_points() {
    let golden = Golden::load();
    let fake = start_tiles(
        by_rule(
            golden.samples.clone(),
            "all",
            Reply::Status(404, Vec::new()),
        ),
        0,
    )
    .await;
    let images = WithMap {
        badges: NoImages,
        map: MapRenderer::with_tiles(&fake.url, Duration::from_secs(5), golden.fonts()),
    };
    let mut request = golden.request("single-point");
    for points in [
        serde_json::json!([]),
        serde_json::json!([{"pref": "どこか", "addr": "どこか", "scale": 40}]),
        serde_json::json!([{"pref": "東京都", "addr": "東京都", "scale": 9}]),
        serde_json::json!([{"pref": "東京都", "addr": "東京都", "scale": "40"}]),
        serde_json::json!(["東京都"]),
    ] {
        request.points = points.as_array().unwrap().clone();
        assert!(images.map(&request).await.is_none(), "{points}");
    }
    assert!(fake.seen.lock().unwrap().is_empty(), "タイルを取りに行った");
    assert!(images.badge(40).await.is_none(), "札は札の担当のものを返す");

    // 点があれば、同じ口から地図が出る。
    let request = golden.request("single-point");
    let png = images.map(&request).await.expect("地図");
    assert_eq!(pixels_of(&png), golden.final_pixels("single-point"));
}

/// 文字の部品（フォント）を用意できなければ、地図を作らないこと（文字の無い地図は出さない）。部品は、地図
/// 1 枚ごとに 1 回だけ用意すること（フォントを持ち続けない）。
#[tokio::test(flavor = "multi_thread")]
async fn no_map_without_fonts_and_fonts_are_opened_per_map() {
    let golden = Golden::load();
    let name = "single-point";
    let fake = start_tiles(
        by_rule(
            golden.samples.clone(),
            "all",
            Reply::Status(404, Vec::new()),
        ),
        0,
    )
    .await;
    let missing = MapRenderer::with_tiles(&fake.url, Duration::from_secs(5), || {
        Err::<SilentText, _>("フォントがありません")
    });
    assert!(missing.render(&golden.request(name)).await.is_none());

    let opened = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&opened);
    let text = golden.text();
    let renderer = MapRenderer::with_tiles(&fake.url, Duration::from_secs(5), move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok::<_, Infallible>(text.clone())
    });
    for round in 1..=2 {
        let png = renderer.render(&golden.request(name)).await.expect("地図");
        assert_eq!(pixels_of(&png), golden.final_pixels(name));
        assert_eq!(opened.load(Ordering::SeqCst), round, "地図 1 枚に 1 回");
    }
}
