//! 読み上げの音声: サーバーごとの順番待ちと、VC への接続・再生。Python の `services/tts_service.py` の
//! `_player_loop`・`enqueue_message`・`enqueue_vc_event`・`temp_join`・`auto_join`・`disconnect`・
//! `get_effective_vc_watch` の一時の上書きと、`services/voice_session.py`（接続の管理）の使い方。
//!
//! VC への接続・再生そのものは [`VoiceOut`] の口の向こう（本番は songbird。[`crate::voice_session`]）。ここは
//! 「いつ・どの VC に・何を鳴らすか」と、やり直し・飛ばし方だけを持つ（テストでは偽物の口を使う）。
//!
//! - 1 つのサーバーにつき再生の係は 1 つ。積まれた順に 1 件ずつ鳴らし、鳴り終わってから次へ
//! - 鳴らす前に、その VC に人間が居なければ飛ばす（切ったあとに合成が終わったときの幽霊接続を防ぐ）
//! - つながらなければ 2 秒おきに 3 回までやり直し、それでもだめならその 1 件を捨てる（1 件でキュー全体を止めない）
//! - 一時参加（/tts join）中は、その VC を読み上げる VC にする。切ったら（/tts leave・全員退出）元に戻す

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// つながらなかったときに、やり直す回数（Python の `_RECONNECT_RETRIES`）。
pub const RECONNECT_RETRIES: u32 = 3;
/// やり直しの間隔（Python の `_RECONNECT_DELAY_SEC`）。
pub const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// 待ち受けの結果を返す箱。
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 読み上げる VC に聞く人間が 1 人もいないか（空か、Bot だけ）。VC でない・見つからないときは `false`
/// （判断できないので読む）。Python の `_vc_has_no_humans`。
///
/// 合成の前と、鳴らす直前の両方で見る。合成の前に見ないと、誰もいない VC のために合成の API を呼んでから捨てる
/// （本番のログで見つかった）。鳴らす直前にも見るのは、合成している間に全員が抜けることがあるため。
pub fn nobody_to_hear(out: &(impl VoiceOut + ?Sized), guild: u64, vc: u64) -> bool {
    out.humans_in(guild, vc) == Some(0)
}

/// VC への接続と再生の口。
pub trait VoiceOut: Send + Sync + 'static {
    /// その VC につなぐ（既に別の VC なら移る）。つながったら `true`。Python の `voice_session.acquire`。
    fn connect(&self, guild: u64, vc: u64) -> BoxFuture<'_, bool>;
    /// 切る。Python の `voice_session.release`。
    fn disconnect(&self, guild: u64) -> BoxFuture<'_, ()>;
    /// 音声の場所（wav）を鳴らし、鳴り終わるまで待つ。
    fn play(&self, guild: u64, url: String) -> BoxFuture<'_, Result<(), String>>;
    /// その VC に居る人間（Bot でない人）の数。VC でない・見つからなければ `None`（Python は飛ばさずに
    /// 接続を試みる）。
    fn humans_in(&self, guild: u64, vc: u64) -> Option<usize>;
}

/// 何もしない口（VC につながない。テストと、音声を使わない確かめのため）。
pub struct NoVoice;

impl VoiceOut for NoVoice {
    fn connect(&self, _guild: u64, _vc: u64) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }
    fn disconnect(&self, _guild: u64) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
    fn play(&self, _guild: u64, _url: String) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("VC につながない口".into()) })
    }
    fn humans_in(&self, _guild: u64, _vc: u64) -> Option<usize> {
        None
    }
}

/// 鳴らす 1 件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// 合成した音声の場所。
    pub audio_url: String,
    /// 鳴らす VC。
    pub vc_channel_id: u64,
    /// 合成にかかったミリ秒（ログに出す）。
    pub synth_ms: u64,
    /// 積んだ時刻（「待ち」のミリ秒をログに出す）。
    pub queued_at: Instant,
}

struct GuildState {
    queue: mpsc::UnboundedSender<Item>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct State {
    guilds: HashMap<u64, GuildState>,
    overrides: HashMap<u64, u64>,
}

/// 読み上げの係（全サーバーぶん）。プロセスに 1 つだけ作って使い回す。
pub struct Speaker {
    out: Arc<dyn VoiceOut>,
    retry_delay: Duration,
    state: Mutex<State>,
}

impl Speaker {
    /// 接続と再生の口を受け取って作る。
    pub fn new(out: Arc<dyn VoiceOut>) -> Self {
        Self::with_retry_delay(out, RECONNECT_DELAY)
    }

    /// やり直しの間隔を変えて作る（テストで待たないため）。
    pub fn with_retry_delay(out: Arc<dyn VoiceOut>, retry_delay: Duration) -> Self {
        Self {
            out,
            retry_delay,
            state: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 一時参加中の VC。Python の `_temp_overrides`。
    pub fn temp_override(&self, guild: u64) -> Option<u64> {
        self.lock().overrides.get(&guild).copied()
    }

    /// 一時参加中か。Python の `has_temp_override`。
    pub fn has_temp_override(&self, guild: u64) -> bool {
        self.lock().overrides.contains_key(&guild)
    }

    /// 鳴らす 1 件を積む。係が居なければ起こす。Python の `enqueue_message` の後ろ半分。
    pub fn enqueue(&self, guild: u64, item: Item) {
        let mut state = self.lock();
        let alive = state
            .guilds
            .get(&guild)
            .is_some_and(|g| !g.task.is_finished() && !g.queue.is_closed());
        if !alive {
            let (tx, rx) = mpsc::unbounded_channel();
            let task = tokio::spawn(player_loop(
                Arc::clone(&self.out),
                guild,
                rx,
                self.retry_delay,
            ));
            state.guilds.insert(guild, GuildState { queue: tx, task });
        }
        if let Some(g) = state.guilds.get(&guild) {
            let _ = g.queue.send(item);
        }
    }

    /// その VC に一時参加し、その VC を読み上げる VC にする。つながらなければ元に戻す。Python の `temp_join`。
    pub async fn temp_join(&self, guild: u64, vc: u64) {
        self.lock().overrides.insert(guild, vc);
        if !self.out.connect(guild, vc).await {
            self.lock().overrides.remove(&guild);
        }
    }

    /// 設定の VC に先に入っておく（誰かが入ったとき）。Python の `auto_join`。
    pub async fn auto_join(&self, guild: u64, vc: u64) {
        self.out.connect(guild, vc).await;
    }

    /// 切る。一時参加を外し、係を止め、積んであったものを捨てる。Python の `disconnect`。
    pub async fn disconnect(&self, guild: u64) {
        let removed = {
            let mut state = self.lock();
            state.overrides.remove(&guild);
            state.guilds.remove(&guild)
        };
        if let Some(g) = removed {
            g.task.abort();
        }
        self.out.disconnect(guild).await;
    }
}

/// VC の出入り 1 つに応じて、読み上げの係にしてもらうこと。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoiceStep {
    /// 切る（読み上げる VC から人間が居なくなった）。
    Disconnect,
    /// 入退室を読み上げる。
    Announce {
        /// 入った（でなければ抜けた）。
        joined: bool,
    },
    /// 設定の VC に先に入る。
    AutoJoin(u64),
}

/// VC の出入り 1 つ。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceEvent {
    /// 出入りしたのが Bot か。
    pub is_bot: bool,
    /// 前の VC。
    pub before: Option<u64>,
    /// あとの VC。
    pub after: Option<u64>,
    /// 前の VC に、もう人間が居ないか（Bot しか居ない・誰も居ない）。
    pub before_has_no_humans: bool,
}

/// 出入りを見るときの、そのサーバーの読み上げの設定。読めなかったものは `None`（Python ではそこで例外になり、
/// その手順だけ飛ぶ）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceSettings {
    /// 読み上げが有効か。
    pub enabled: bool,
    /// 入退室を読み上げるか。
    pub notify: bool,
    /// 読み上げる VC（一時参加の上書きを含む。Python の `get_effective_vc_watch`）。
    pub watched: Option<Option<i64>>,
    /// 設定の VC（上書きを含まない）。
    pub configured: Option<Option<i64>>,
    /// 一時参加中か。
    pub has_temp: bool,
}

/// 出入り 1 つに応じて、何をするか（頼む順）。Python の `_tts_vc_announce`（Bot を含む全員）と、人間のときだけ
/// 続く `_maybe_tts_auto_join`・`_maybe_tts_auto_leave`（`_dispatch_voice_state` の順）。
pub fn voice_plan(event: &VoiceEvent, settings: &VoiceSettings) -> Vec<VoiceStep> {
    let mut steps = Vec::new();
    let joined = event.before.is_none() && event.after.is_some();
    let left = event.before.is_some() && event.after.is_none();
    let moved = event.before.is_some() && event.after.is_some() && event.before != event.after;
    let same = |watched: Option<i64>, channel: Option<u64>| matches!((watched, channel), (Some(w), Some(c)) if u64::try_from(w) == Ok(c));
    // 前の VC が、読み上げる VC で、人間が居なくなったか。Python の `_tts_vc_became_empty`。
    let before_emptied =
        |watched: Option<i64>| same(watched, event.before) && event.before_has_no_humans;
    if let Some(watched) = settings.watched
        && (joined || left)
    {
        if left && before_emptied(watched) {
            steps.push(VoiceStep::Disconnect);
        } else if !event.is_bot
            && settings.enabled
            && settings.notify
            && watched.is_some_and(|w| w != 0)
        {
            let target = if joined { event.after } else { event.before };
            if same(watched, target) {
                steps.push(VoiceStep::Announce { joined });
            }
        }
    }
    if event.is_bot {
        return steps;
    }
    if joined
        && settings.enabled
        && let Some(Some(vc)) = settings.configured
        && vc != 0
        && same(Some(vc), event.after)
        && !settings.has_temp
        && let Some(after) = event.after
    {
        steps.push(VoiceStep::AutoJoin(after));
    }
    if (left || moved)
        && let Some(watched) = settings.watched
        && before_emptied(watched)
    {
        steps.push(VoiceStep::Disconnect);
    }
    steps
}

/// 1 つのサーバーの再生の係。Python の `_player_loop`。
async fn player_loop(
    out: Arc<dyn VoiceOut>,
    guild: u64,
    mut queue: mpsc::UnboundedReceiver<Item>,
    retry_delay: Duration,
) {
    while let Some(item) = queue.recv().await {
        // 合成している間に全員が抜けたものを、空の VC で鳴らしに行かない。
        if nobody_to_hear(out.as_ref(), guild, item.vc_channel_id) {
            info!("[TTS] VC空のためスキップ guild={guild}");
            continue;
        }
        let mut connected = false;
        for attempt in 0..=RECONNECT_RETRIES {
            if out.connect(guild, item.vc_channel_id).await {
                connected = true;
                break;
            }
            if attempt < RECONNECT_RETRIES {
                info!(
                    "[TTS] reconnect attempt {}/{RECONNECT_RETRIES} guild={guild}",
                    attempt + 1
                );
                tokio::time::sleep(retry_delay).await;
            }
        }
        if !connected {
            error!(
                "[TTS] failed to connect after {} attempts, dropping item guild={guild}",
                RECONNECT_RETRIES + 1
            );
            continue;
        }
        let wait_ms = u64::try_from(item.queued_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        info!(
            "[TTS] 再生開始 guild={guild} 合成={}ms 待ち={wait_ms}ms 計={}ms",
            item.synth_ms,
            item.synth_ms.saturating_add(wait_ms)
        );
        if let Err(e) = out.play(guild, item.audio_url).await {
            warn!("[TTS] play error: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// 頼まれたことを順に覚える偽物の口。`hold` が立っていると、鳴らし始めたところで `release` を待つ。
    #[derive(Default)]
    struct Fake {
        log: Mutex<Vec<String>>,
        fail_connects: AtomicUsize,
        humans: Mutex<Option<usize>>,
        hold: std::sync::atomic::AtomicBool,
        release: tokio::sync::Notify,
    }

    impl Fake {
        fn push(&self, line: String) {
            self.log.lock().unwrap().push(line);
        }
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl VoiceOut for Fake {
        fn connect(&self, guild: u64, vc: u64) -> BoxFuture<'_, bool> {
            let ok = self
                .fail_connects
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_err();
            self.push(format!("connect {guild} {vc} {ok}"));
            Box::pin(async move { ok })
        }
        fn disconnect(&self, guild: u64) -> BoxFuture<'_, ()> {
            self.push(format!("disconnect {guild}"));
            Box::pin(async {})
        }
        fn play(&self, guild: u64, url: String) -> BoxFuture<'_, Result<(), String>> {
            self.push(format!("play {guild} {url}"));
            Box::pin(async move {
                if self.hold.load(Ordering::SeqCst) {
                    self.release.notified().await;
                }
                Ok(())
            })
        }
        fn humans_in(&self, _guild: u64, _vc: u64) -> Option<usize> {
            *self.humans.lock().unwrap()
        }
    }

    fn item(url: &str) -> Item {
        Item {
            audio_url: url.into(),
            vc_channel_id: 50,
            synth_ms: 1,
            queued_at: Instant::now(),
        }
    }

    /// 係が全部を片付けるまで待つ（下限だけを見る。CI は遅い）。
    async fn settle(fake: &Fake, lines: usize) {
        for _ in 0..500 {
            if fake.log().len() >= lines {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 積んだ順に、つないでから鳴らすこと。
    /// 聞く人がいないのは、VC に人間が 0 人と分かったときだけ（分からない・1 人以上なら読む）。
    #[test]
    fn nobody_to_hear_only_when_the_vc_is_known_empty() {
        let fake = Fake::default();
        for (humans, expected) in [
            (Some(0), true),
            (Some(1), false),
            (Some(3), false),
            (None, false),
        ] {
            *fake.humans.lock().unwrap() = humans;
            assert_eq!(nobody_to_hear(&fake, 1, 50), expected, "{humans:?}");
        }
    }

    #[tokio::test]
    async fn items_are_played_in_order() {
        let fake = Arc::new(Fake::default());
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.enqueue(7, item("a"));
        speaker.enqueue(7, item("b"));
        settle(&fake, 4).await;
        assert_eq!(
            fake.log(),
            [
                "connect 7 50 true",
                "play 7 a",
                "connect 7 50 true",
                "play 7 b"
            ]
        );
    }

    /// 人間の居ない VC では鳴らさない（VC か分からないときは、接続を試みる）。
    #[tokio::test]
    async fn an_empty_vc_is_skipped() {
        let fake = Arc::new(Fake::default());
        *fake.humans.lock().unwrap() = Some(0);
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.enqueue(7, item("a"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(fake.log().is_empty(), "{:?}", fake.log());
        *fake.humans.lock().unwrap() = None;
        speaker.enqueue(7, item("b"));
        settle(&fake, 2).await;
        assert_eq!(fake.log(), ["connect 7 50 true", "play 7 b"]);
    }

    /// つながらなければ 3 回までやり直す。4 回だめならその 1 件を捨てて、次へ進む。
    #[tokio::test]
    async fn connections_are_retried_three_times() {
        let fake = Arc::new(Fake::default());
        fake.fail_connects.store(3, Ordering::SeqCst);
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.enqueue(7, item("a"));
        settle(&fake, 5).await;
        assert_eq!(
            fake.log(),
            [
                "connect 7 50 false",
                "connect 7 50 false",
                "connect 7 50 false",
                "connect 7 50 true",
                "play 7 a"
            ]
        );
        let fake = Arc::new(Fake::default());
        fake.fail_connects.store(4, Ordering::SeqCst);
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.enqueue(7, item("a"));
        speaker.enqueue(7, item("b"));
        settle(&fake, 6).await;
        assert_eq!(fake.log().len(), 6, "{:?}", fake.log());
        assert_eq!(fake.log()[4..], ["connect 7 50 true", "play 7 b"]);
    }

    /// 一時参加: つながれば上書きが残り、つながらなければ外れる。切ると上書きも外れる。
    #[tokio::test]
    async fn temp_join_overrides_until_disconnect() {
        let fake = Arc::new(Fake::default());
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.temp_join(7, 60).await;
        assert_eq!(speaker.temp_override(7), Some(60));
        assert!(speaker.has_temp_override(7));
        assert!(!speaker.has_temp_override(8));
        speaker.disconnect(7).await;
        assert_eq!(speaker.temp_override(7), None);
        fake.fail_connects.store(1, Ordering::SeqCst);
        speaker.temp_join(7, 61).await;
        assert_eq!(
            speaker.temp_override(7),
            None,
            "つながらなかったのに上書きが残った"
        );
        assert_eq!(
            fake.log(),
            ["connect 7 60 true", "disconnect 7", "connect 7 61 false"]
        );
    }

    /// 鳴らしている最中に切ると、その係は止まり、積んであった次のものは鳴らさない。
    #[tokio::test]
    async fn disconnect_stops_the_player_mid_play() {
        let fake = Arc::new(Fake::default());
        fake.hold.store(true, Ordering::SeqCst);
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.enqueue(7, item("a"));
        speaker.enqueue(7, item("b"));
        settle(&fake, 2).await;
        assert_eq!(fake.log(), ["connect 7 50 true", "play 7 a"]);
        speaker.disconnect(7).await;
        fake.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            fake.log(),
            ["connect 7 50 true", "play 7 a", "disconnect 7"],
            "切ったのに、積んであったものを鳴らした"
        );
    }

    /// 切ると、積んであったものは鳴らさない。そのあと積んだものは、新しい係が鳴らす。
    #[tokio::test]
    async fn disconnect_drops_the_queue() {
        let fake = Arc::new(Fake::default());
        let speaker = Speaker::with_retry_delay(fake.clone(), Duration::ZERO);
        speaker.disconnect(7).await;
        speaker.enqueue(7, item("c"));
        settle(&fake, 3).await;
        assert_eq!(
            fake.log(),
            ["disconnect 7", "connect 7 50 true", "play 7 c"]
        );
    }
}
