//! VC への接続と再生（songbird）。Python の `services/voice_session.py` と、`_player_loop` の再生の部分
//! （`discord.FFmpegPCMAudio` で鳴らして、終わるまで待つ）。
//!
//! Discord の Bot は 1 つのサーバーにつき音声の接続を 1 本しか持てない。接続はここ（songbird の管理役）に
//! まとめ、読み上げ（[`crate::tts_voice`]）はここを通して接続を取りに来る。DJAudio（B10）も同じ口を使う。
//!
//! 音声は合成の API が返す wav を取ってきて、songbird（symphonia の wav）で鳴らす（Python は ffmpeg に URL を
//! 渡していた。Rust は ffmpeg を使わない）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serenity::all::{Cache, ChannelId, ChannelType, GuildId};
use serenity::async_trait;
use songbird::Songbird;
use songbird::events::{Event, EventContext, EventHandler, TrackEvent};
use songbird::input::Input;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::tts_voice::{BoxFuture, VoiceOut};

/// 音声の wav を取ってくる待ち時間。
pub const AUDIO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// songbird での接続と再生。
pub struct SongbirdOut {
    manager: Arc<Songbird>,
    cache: OnceLock<Arc<Cache>>,
    http: reqwest::Client,
    /// サーバーごとの錠（同じサーバーへの接続を同時に 2 本張らない。Python の `_locks`）。
    locks: Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
}

impl SongbirdOut {
    /// songbird の管理役を受け取って作る（Discord のクライアントにも同じものを登録する）。
    pub fn new(manager: Arc<Songbird>) -> Self {
        Self {
            manager,
            cache: OnceLock::new(),
            http: reqwest::Client::new(),
            locks: Mutex::default(),
        }
    }

    /// serenity のキャッシュを渡す（クライアントを作ったあと）。
    pub fn set_cache(&self, cache: Arc<Cache>) {
        let _ = self.cache.set(cache);
    }

    fn lock_for(&self, guild: u64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(locks.entry(guild).or_default())
    }

    /// その VC がサーバーにある音声チャンネルか（discord.py の `isinstance(channel, discord.VoiceChannel)`。
    /// ステージは入らない）。
    fn is_voice(&self, guild: u64, vc: u64) -> bool {
        let Some(cache) = self.cache.get() else {
            return false;
        };
        let Some(guild) = cache.guild(GuildId::new(guild)) else {
            return false;
        };
        guild
            .channels
            .get(&ChannelId::new(vc))
            .is_some_and(|c| c.kind == ChannelType::Voice)
    }

    async fn connect_locked(&self, guild: u64, vc: u64) -> bool {
        let lock = self.lock_for(guild);
        let _guard = lock.lock().await;
        if let Some(call) = self.manager.get(GuildId::new(guild)) {
            let current = call.lock().await.current_channel();
            if current.is_some_and(|c| c.0.get() == vc) {
                return true;
            }
        }
        if !self.is_voice(guild, vc) {
            warn!("[voice] vc_channel_id={vc} が見つからないか VC ではありません");
            return false;
        }
        // 既に別の VC に居れば、songbird が移る。切れた接続は張り直す。
        match self
            .manager
            .join(GuildId::new(guild), ChannelId::new(vc))
            .await
        {
            Ok(_) => true,
            Err(e) => {
                error!("[voice] 接続エラー guild={guild}: {e}");
                false
            }
        }
    }

    async fn play_url(&self, guild: u64, url: String) -> Result<(), String> {
        let response = self
            .http
            .get(&url)
            .timeout(AUDIO_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("音声を取れません: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("音声を取れません: {}", response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("音声を取れません: {}", e.without_url()))?;
        let Some(call) = self.manager.get(GuildId::new(guild)) else {
            return Err("VC に接続していません".into());
        };
        let (done_tx, done_rx) = oneshot::channel();
        let notifier = Notify(Arc::new(Mutex::new(Some(done_tx))));
        let track = {
            let mut handler = call.lock().await;
            // 通常はここに来ないが、前の再生が残っていれば止める（Python も同じ）。
            handler.stop();
            handler.play_input(Input::from(bytes.to_vec()))
        };
        for event in [TrackEvent::End, TrackEvent::Error] {
            track
                .add_event(Event::Track(event), notifier.clone())
                .map_err(|e| format!("再生の終わりを待てません: {e}"))?;
        }
        let _ = done_rx.await;
        Ok(())
    }
}

/// 再生が終わった（か、失敗した）ことを 1 回だけ知らせる（終わりと失敗の両方に登録するので、写しを共有する）。
#[derive(Clone)]
struct Notify(Arc<Mutex<Option<oneshot::Sender<()>>>>);

#[async_trait]
impl EventHandler for Notify {
    async fn act(&self, _ctx: &EventContext<'_>) -> Option<Event> {
        if let Some(tx) = self.0.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
        None
    }
}

impl VoiceOut for SongbirdOut {
    fn connect(&self, guild: u64, vc: u64) -> BoxFuture<'_, bool> {
        Box::pin(self.connect_locked(guild, vc))
    }

    fn disconnect(&self, guild: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.manager.get(GuildId::new(guild)).is_none() {
                return;
            }
            match self.manager.remove(GuildId::new(guild)).await {
                Ok(()) => info!("[voice] 切断しました guild={guild}"),
                Err(e) => warn!(
                    "[voice] guild={guild} 切断に失敗しました（管理外の接続が残っている可能性）: {e}"
                ),
            }
        })
    }

    fn play(&self, guild: u64, url: String) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(self.play_url(guild, url))
    }

    fn humans_in(&self, guild: u64, vc: u64) -> Option<usize> {
        if !self.is_voice(guild, vc) {
            return None;
        }
        let cache = self.cache.get()?;
        let guild = cache.guild(GuildId::new(guild))?;
        let channel = ChannelId::new(vc);
        let count = guild
            .voice_states
            .values()
            .filter(|state| state.channel_id == Some(channel))
            .filter(|state| {
                let bot = state
                    .member
                    .as_ref()
                    .map(|m| m.user.bot)
                    .or_else(|| guild.members.get(&state.user_id).map(|m| m.user.bot));
                bot != Some(true)
            })
            .count();
        Some(count)
    }
}
