//! 地震の電文の受け取り（P2P地震情報の WebSocket）と、気象庁の一覧の取得、Discord への送り口。
//! Python の `services/earthquake_service.py` の `run_earthquake_ws`・`_get_jma_list`・
//! `_resolve_jma_detail_url`。電文の読み方と送る流れは [`crate::earthquake`]。
//!
//! 受け取りの決まりは Python と同じ:
//!
//! - WebSocket 1 本で 551（地震情報）・552（津波予報）・554（緊急地震速報の検出）・556（緊急地震速報の
//!   予報）を受ける。それ以外の種類・JSON でない文は捨てる
//! - 同じ電文が何度か配信されるので、`id` で重複だけを弾く（新しい順に 500 件覚える。あふれたら古い順に
//!   1 件ずつ忘れる）。覚えは、つなぎ直しても持ち越す
//! - 通知は別のタスクで走らせる（地図の取得や Discord への送信で、受け取りを待たせない）
//! - 20 秒何も届かなければ ping を送り、さらに 10 秒何も届かなければ切れたとみなす（aiohttp の
//!   `heartbeat=20` と同じ）。切れたら 10 秒待ってつなぎ直す
//!
//! Python と違うところ: 辞書でない JSON（配列など）が届いたとき、Python は例外でつなぎ直す。こちらは
//! その文だけ捨てる。

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use serenity::all::{Cache, ChannelId, CreateAttachment, CreateMessage, GuildId, Http};
use sycs_core::ttl_cache::TtlCache;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::earthquake::{self, DetailUrls, Directory, Notice, NotifyType, Outbox};
use crate::log_channel;

/// P2P地震情報の WebSocket。
pub const WS_URL: &str = "wss://api.p2pquake.net/v2/ws";
/// 気象庁の地震の一覧。
pub const JMA_LIST_URL: &str = "https://www.jma.go.jp/bosai/quake/data/list.json";
/// 重複を見るために覚えておく id の数。Python の `_SEEN_ID_LIMIT`。
pub const SEEN_ID_LIMIT: usize = 500;
/// 一覧を取り直すまでの秒数。Python の `_JMA_LIST_TTL_SEC`。
pub const JMA_LIST_TTL: f64 = 30.0;
/// 決めたリンクを覚えておく秒数と件数。Python の `_JMA_DETAIL_CACHE_TTL_SEC`。
const DETAIL_CACHE_TTL: f64 = 3600.0;
const DETAIL_CACHE_MAX: usize = 500;

/// 受け取りの設定。本番は [`FeedConfig::default`]（テストで偽物に向け、待ちを短くする）。
#[derive(Clone, Debug)]
pub struct FeedConfig {
    /// WebSocket の場所。
    pub ws_url: String,
    /// 何も届かないとき ping を送るまでの時間。
    pub heartbeat: Duration,
    /// ping のあと、何も届かなければ切れたとみなすまでの時間（aiohttp は heartbeat の半分）。
    pub pong_wait: Duration,
    /// 切れてからつなぎ直すまでの時間。
    pub reconnect_delay: Duration,
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            ws_url: WS_URL.into(),
            heartbeat: Duration::from_secs(20),
            pong_wait: Duration::from_secs(10),
            reconnect_delay: Duration::from_secs(10),
        }
    }
}

/// 受け取った電文の種類。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// 地震情報（551）。
    Quake,
    /// 津波予報（552）。
    Tsunami,
    /// 緊急地震速報（554 は警報の検出、556 は予報）。
    Eew(NotifyType),
}

/// 見た id の覚え。新しい順に [`SEEN_ID_LIMIT`] 件。
#[derive(Default)]
pub struct SeenIds {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenIds {
    /// 初めて見る id なら覚えて `true`。もう見た id なら `false`。
    pub fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        self.set.insert(id.to_string());
        self.order.push_back(id.to_string());
        // 全部消すと、消した直後の再配信が二重の通知になる。古い順に 1 件ずつ忘れる。
        while self.order.len() > SEEN_ID_LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    /// 覚えている数。
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// 何も覚えていないか。
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// 重複を見る鍵。Python は `id` が真（空でない）ときだけ重複を見る。文字と数は別の鍵にする
/// （Python の集合でも `"1"` と `1` は別）。
fn seen_key(id: &Value) -> Option<String> {
    match id {
        Value::String(s) if !s.is_empty() => Some(format!("s:{s}")),
        Value::Number(n) if n.as_f64().is_some_and(|f| f != 0.0) => Some(format!("n:{n}")),
        _ => None,
    }
}

/// 届いた文を読んで、通知するものだけを返す。Python の `run_earthquake_ws` の中の判定。
///
/// JSON でない文・辞書でない JSON・扱わない種類・もう見た id は `None`。
pub fn accept(text: &str, seen: &mut SeenIds) -> Option<(Kind, Value)> {
    let data: Value = serde_json::from_str(text).ok()?;
    if !data.is_object() {
        return None;
    }
    let code = data["code"].as_f64()?;
    let kind = if code == 551.0 {
        Kind::Quake
    } else if code == 552.0 {
        Kind::Tsunami
    } else if code == 554.0 {
        Kind::Eew(NotifyType::EewWarning)
    } else if code == 556.0 {
        Kind::Eew(NotifyType::EewForecast)
    } else {
        return None;
    };
    if let Some(key) = seen_key(&data["id"])
        && !seen.insert(&key)
    {
        return None;
    }
    Some((kind, data))
}

/// 1 回の接続で読み続ける。切れた・失敗したら戻る。
async fn read_until_closed<F, Fut>(
    config: &FeedConfig,
    seen: &mut SeenIds,
    on_event: &F,
) -> Result<(), String>
where
    F: Fn(Kind, Value) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (stream, _) = tokio_tungstenite::connect_async(config.ws_url.as_str())
        .await
        .map_err(|e| e.to_string())?;
    info!("[earthquake] P2PQuake WS 接続確立");
    let (mut sink, mut source) = stream.split();
    let mut waiting_pong = false;
    loop {
        let wait = if waiting_pong {
            config.pong_wait
        } else {
            config.heartbeat
        };
        let next = match tokio::time::timeout(wait, source.next()).await {
            Ok(next) => next,
            Err(_) if waiting_pong => {
                return Err("ping に応答がありません".into());
            }
            Err(_) => {
                sink.send(Message::Ping(Vec::new().into()))
                    .await
                    .map_err(|e| e.to_string())?;
                waiting_pong = true;
                continue;
            }
        };
        // 何か届いたら、相手は生きている。
        waiting_pong = false;
        match next {
            Some(Ok(Message::Text(text))) => {
                if let Some((kind, data)) = accept(text.as_str(), seen) {
                    // 通知は別のタスクで走らせる（受け取りを待たせない）。
                    tokio::spawn(on_event(kind, data));
                }
            }
            Some(Ok(Message::Close(frame))) => {
                warn!("[earthquake] WS 切断: {frame:?}");
                return Ok(());
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e.to_string()),
            None => {
                warn!("[earthquake] WS 切断");
                return Ok(());
            }
        }
    }
}

/// 止められるまで受け取り続ける。Python の `run_earthquake_ws`。
///
/// `on_event` は、通知するものが届くたびに別のタスクで呼ぶ。
pub async fn run_forever<F, Fut>(config: FeedConfig, on_event: F)
where
    F: Fn(Kind, Value) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut seen = SeenIds::default();
    loop {
        if let Err(e) = read_until_closed(&config, &mut seen, &on_event).await {
            error!("[earthquake] WS エラー: {e}");
        }
        info!(
            "[earthquake] {}秒後に再接続",
            config.reconnect_delay.as_secs()
        );
        tokio::time::sleep(config.reconnect_delay).await;
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// 気象庁の一覧を取り、この地震のリンクを決めて覚えておく口。1 つを使い回す。
pub struct JmaDetailUrls {
    http: reqwest::Client,
    list_url: String,
    /// 一覧を取り直すまでの秒数。
    list_ttl: f64,
    /// 取った一覧と、取った時刻。
    list: Mutex<Option<(Arc<Vec<Value>>, f64)>>,
    /// 同時に取りに行くのを 1 本にする錠。
    fetching: tokio::sync::Mutex<()>,
    /// 決めたリンク。
    resolved: Mutex<TtlCache<String, String>>,
    started: Instant,
}

impl Default for JmaDetailUrls {
    fn default() -> Self {
        Self::new(JMA_LIST_URL)
    }
}

impl JmaDetailUrls {
    /// 作る（一覧の場所を渡す。本番は [`JMA_LIST_URL`]）。
    pub fn new(list_url: &str) -> Self {
        Self::with_list_ttl(list_url, JMA_LIST_TTL)
    }

    /// 一覧を取り直すまでの秒数も決めて作る（テストで、毎回取り直させるため）。
    pub fn with_list_ttl(list_url: &str, list_ttl: f64) -> Self {
        let http = reqwest::Client::builder()
            // Python の aiohttp.ClientTimeout(total=3)。
            .timeout(Duration::from_secs(3))
            .user_agent("sycs-bot (earthquake alert)")
            .build()
            .unwrap_or_default();
        Self {
            http,
            list_url: list_url.into(),
            list_ttl,
            list: Mutex::new(None),
            fetching: tokio::sync::Mutex::new(()),
            resolved: Mutex::new(TtlCache::new(DETAIL_CACHE_TTL, DETAIL_CACHE_MAX)),
            started: Instant::now(),
        }
    }

    fn fresh(&self, now: f64) -> Option<Arc<Vec<Value>>> {
        let list = self.list.lock().unwrap_or_else(|p| p.into_inner());
        list.as_ref()
            .filter(|(_, at)| now - at < self.list_ttl)
            .map(|(items, _)| Arc::clone(items))
    }

    fn stale(&self) -> Arc<Vec<Value>> {
        let list = self.list.lock().unwrap_or_else(|p| p.into_inner());
        list.as_ref()
            .map_or_else(|| Arc::new(Vec::new()), |(items, _)| Arc::clone(items))
    }

    async fn fetch(&self) -> Result<Value, String> {
        let response = self
            .http
            .get(&self.list_url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status().as_u16() != 200 {
            return Err(format!("HTTP {}", response.status().as_u16()));
        }
        let bytes = response.bytes().await.map_err(|e| e.to_string())?;
        // 種類（Content-Type）は見ない（Python の `resp.json(content_type=None)`）。
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }

    /// 気象庁の一覧。30 秒は取り直さない。取れなければ、前に取ったもの（無ければ空）。Python の
    /// `_get_jma_list`。
    pub async fn list(&self) -> Arc<Vec<Value>> {
        if let Some(items) = self.fresh(unix_now()) {
            return items;
        }
        let _one_at_a_time = self.fetching.lock().await;
        // 待っている間に、先の人が取り終えているかもしれない。
        let now = unix_now();
        if let Some(items) = self.fresh(now) {
            return items;
        }
        match self.fetch().await {
            Ok(Value::Array(items)) => {
                let items = Arc::new(items);
                let mut list = self.list.lock().unwrap_or_else(|p| p.into_inner());
                *list = Some((Arc::clone(&items), now));
                return items;
            }
            // 配列でなければ使わない（覚えもしない）。
            Ok(_) => {}
            Err(e) => debug!("[earthquake] JMA list fetch failed: {e}"),
        }
        self.stale()
    }
}

impl DetailUrls for JmaDetailUrls {
    /// この地震にいちばん近い気象庁のページ。結果は 1 時間覚えておく。Python の `_resolve_jma_detail_url`。
    async fn resolve(&self, event: &Value, max_scale: i64) -> String {
        let key = earthquake::cache_key_for_event(event, max_scale);
        let now = || self.started.elapsed().as_secs_f64();
        let cached = self
            .resolved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key, now());
        if let Some(url) = cached {
            return url;
        }
        let items = self.list().await;
        let url = earthquake::best_detail_url(&items, event, max_scale);
        self.resolved
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set(key, url.clone(), now());
        url
    }
}

/// serenity のキャッシュから、サーバーとチャンネルの様子を引く。
pub struct CacheDirectory<'a>(pub &'a Cache);

impl Directory for CacheDirectory<'_> {
    fn has_guild(&self, guild_id: u64) -> bool {
        guild_id != 0 && self.0.guild(GuildId::new(guild_id)).is_some()
    }

    fn is_text_channel(&self, guild_id: u64, channel_id: i64) -> bool {
        let Some(channel_id) = u64::try_from(channel_id).ok().filter(|id| *id != 0) else {
            return false;
        };
        guild_id != 0
            && log_channel::text_channel(self.0, GuildId::new(guild_id), Some(channel_id)).is_some()
    }
}

/// Discord へ送る口（本物）。
pub struct HttpOutbox<'a>(pub &'a Http);

impl Outbox for HttpOutbox<'_> {
    async fn send(&self, _guild_id: u64, channel_id: u64, notice: &Notice) -> Result<(), String> {
        let mut message = CreateMessage::new().embed(notice.embed.clone());
        if let Some(url) = &notice.detail_url {
            message = message.components(vec![earthquake::detail_button(url)]);
        }
        // 添付は送り先ごとに作り直す（1 回送ると使い切る）。
        for (name, data) in &notice.attachments {
            message = message.add_file(CreateAttachment::bytes(data.clone(), *name));
        }
        ChannelId::new(channel_id)
            .send_message(self.0, message)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 扱う種類だけを通し、種類ごとに通知の種類を決めること。
    #[test]
    fn only_four_codes_are_accepted() {
        let mut seen = SeenIds::default();
        let kind = |code: Value, seen: &mut SeenIds| {
            accept(&json!({ "code": code }).to_string(), seen).map(|(k, _)| k)
        };
        assert_eq!(kind(json!(551), &mut seen), Some(Kind::Quake));
        assert_eq!(kind(json!(552), &mut seen), Some(Kind::Tsunami));
        assert_eq!(
            kind(json!(554), &mut seen),
            Some(Kind::Eew(NotifyType::EewWarning))
        );
        assert_eq!(
            kind(json!(556), &mut seen),
            Some(Kind::Eew(NotifyType::EewForecast))
        );
        // Python の `551.0 in (551, …)` は真。
        assert_eq!(kind(json!(551.0), &mut seen), Some(Kind::Quake));
        for other in [json!(555), json!(561), json!("551"), json!(null)] {
            assert_eq!(kind(other.clone(), &mut seen), None, "{other}");
        }
        assert_eq!(accept("not json", &mut seen), None);
        assert_eq!(accept("[551]", &mut seen), None);
        assert_eq!(accept("{}", &mut seen), None);
    }

    /// 同じ id は 1 回だけ通すこと。id が無い・空の電文は毎回通すこと。
    #[test]
    fn duplicates_are_dropped_by_id() {
        let mut seen = SeenIds::default();
        let text = |id: Value| json!({"code": 551, "id": id}).to_string();
        assert!(accept(&text(json!("a")), &mut seen).is_some());
        assert!(accept(&text(json!("a")), &mut seen).is_none());
        assert!(accept(&text(json!("b")), &mut seen).is_some());
        // 種類が違っても、同じ id なら重複。
        assert!(accept(&json!({"code": 552, "id": "b"}).to_string(), &mut seen).is_none());
        // 文字と数は別の id。
        assert!(accept(&text(json!(1)), &mut seen).is_some());
        assert!(accept(&text(json!("1")), &mut seen).is_some());
        assert!(accept(&text(json!(1)), &mut seen).is_none());
        for no_id in [json!(""), json!(null), json!(0)] {
            assert!(accept(&text(no_id.clone()), &mut seen).is_some(), "{no_id}");
            assert!(accept(&text(no_id.clone()), &mut seen).is_some(), "{no_id}");
        }
        assert!(accept(&json!({"code": 551}).to_string(), &mut seen).is_some());
        // 扱わない種類の id は覚えない。
        assert!(accept(&json!({"code": 555, "id": "z"}).to_string(), &mut seen).is_none());
        assert!(accept(&text(json!("z")), &mut seen).is_some());
    }

    /// 500 件を超えたら古い順に 1 件ずつ忘れること（全部は消さない）。
    #[test]
    fn the_oldest_ids_are_forgotten_one_by_one() {
        assert_eq!(SEEN_ID_LIMIT, 500);
        let mut seen = SeenIds::default();
        assert!(seen.is_empty());
        for i in 0..SEEN_ID_LIMIT {
            assert!(seen.insert(&i.to_string()));
        }
        assert_eq!(seen.len(), SEEN_ID_LIMIT);
        // 501 件目で、いちばん古い 0 だけを忘れる。
        assert!(seen.insert("new"));
        assert_eq!(seen.len(), SEEN_ID_LIMIT);
        assert!(!seen.insert("1"), "2 番目に古いものまで忘れた");
        assert!(!seen.insert("499"));
        assert!(seen.insert("0"), "いちばん古いものを覚えたままだった");
    }

    /// 本番の場所と待ちが Python と同じであること。
    #[test]
    fn the_defaults_match_python() {
        let python = include_str!("../../../../services/earthquake_service.py");
        let c = FeedConfig::default();
        assert!(python.contains(&format!("_WS_URL = \"{}\"", c.ws_url)));
        assert!(python.contains(&format!("_JMA_QUAKE_LIST_URL = \"{JMA_LIST_URL}\"")));
        assert!(python.contains("ws_connect(_WS_URL, heartbeat=20)"));
        assert!(python.contains("await asyncio.sleep(10)"));
        assert_eq!(c.heartbeat, Duration::from_secs(20));
        assert_eq!(c.pong_wait, Duration::from_secs(10));
        assert_eq!(c.reconnect_delay, Duration::from_secs(10));
    }
}
