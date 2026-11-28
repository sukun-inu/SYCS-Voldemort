//! 見張るチャンネルに貼られた URL を MP3 にして、リンクを返す流れ。Python の `services/djaudio_service.py` の
//! `handle_djaudio_message`・`_process_url`・`_build_result_embed`・`_add_reaction_safe`・`_remove_reaction_safe`。
//!
//! 1. 見張るチャンネルの投稿から URL を拾う（上限まで）
//! 2. 1 つずつ見分ける（落とせないサービス → 受け付けないドメイン → 安全でない行き先〔SSRF〕）。どれも駄目なら、
//!    いちばん重い理由（安全 → サービス）を 1 つ返して終わる
//! 3. 同じ人が続けて頼んだら待ってもらう（サーバー・人ごとに秒数を数える）
//! 4. URL ごとに並べて: ⏳ を付ける → 落とす（同時に動かす数の上限・時間切れつき）→ ⏳ を外して ✅ → リンクの
//!    Embed を返信（出力チャンネルがあればそちらへ送る）→ 送ったメッセージを登録に書き足す。失敗したら ⏳ を外して
//!    ❌ を付け、時間切れか失敗かを返信する

use std::collections::HashSet;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serenity::all::{Colour, CreateEmbed, CreateEmbedFooter};
use sycs_core::ttl_cache::TtlCache;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use super::download::extract_urls;
use super::settings::Runtime;
use super::site::{is_djaudio_allowed_url, is_unsupported_url};

/// 受け付けないドメインのときの理由。
pub const NOT_SUPPORTED: &str = "このURLのサービスはDJAudioでサポートされていないぞ。";
/// 安全でない行き先のときの理由。
pub const UNSAFE: &str = "この URL はセキュリティ上の理由で処理できぬ。";
/// どの理由も無いのに受け付けなかったとき（起きない。Python と同じ文を持っておく）。
pub const UNSUPPORTED_NOW: &str = "この URL は現在サポート対象外だ。";
/// 時間切れの返信。
pub const TIMED_OUT: &str = "⚠️ タイムアウトしたぞ。時間をおいてから再試行せよ。";
/// 失敗の返信。
pub const FAILED: &str = "⚠️ ダウンロードに失敗した。URL を確認して再試行せよ。";

/// 進み具合のリアクション。
pub const WORKING: &str = "⏳";
/// 済んだ。
pub const DONE: &str = "✅";
/// 失敗した。
pub const FAILED_MARK: &str = "❌";

/// Discord から断られた（discord.py の `HTTPException`。応答の状態が 2xx でない）か、それ以外（通信の失敗など。
/// Python では例外がそのまま外へ抜ける）。
#[derive(Debug)]
pub enum DiscordError {
    /// Discord が断った。
    Refused(String),
    /// それ以外。
    Other(String),
}

impl std::fmt::Display for DiscordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) | Self::Other(e) => f.write_str(e),
        }
    }
}

/// 送ったメッセージ（チャンネルとメッセージの ID）。
pub type Sent = (u64, u64);

/// 出力チャンネルの見え方（キャッシュから引いたもの）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputChannel {
    /// 見つからない（返信にする）。
    Missing,
    /// 送れるチャンネル（テキスト・VC・スレッドなど）。
    Messageable(u64),
    /// 送れないチャンネル（カテゴリ・フォーラム。Python では `send` が無くて例外になる）。
    NotMessageable(u64),
}

/// 投稿への働きかけ（Discord）。テストでは記録するだけの偽物に差し替える。
pub trait Outlet: Sync {
    /// 投稿にリアクションを付ける。
    fn add_reaction(&self, emoji: &str) -> impl Future<Output = Result<(), DiscordError>> + Send;
    /// 自分が付けたリアクションを外す。
    fn remove_own_reaction(
        &self,
        emoji: &str,
    ) -> impl Future<Output = Result<(), DiscordError>> + Send;
    /// 投稿に返信する（作者には通知しない）。文か Embed のどちらか。
    fn reply(
        &self,
        content: Option<String>,
        embed: Option<CreateEmbed>,
    ) -> impl Future<Output = Result<Sent, DiscordError>> + Send;
    /// チャンネルへ Embed を送る。
    fn send(
        &self,
        channel_id: u64,
        embed: CreateEmbed,
    ) -> impl Future<Output = Result<Sent, DiscordError>> + Send;
    /// 出力チャンネルを引く（Python の `bot.get_channel`）。
    fn output_channel(&self, channel_id: u64) -> OutputChannel;
    /// 行き先が安全か（Python の `validate_public_http_url_async`。名前を引く）。
    fn is_safe(&self, url: &str) -> impl Future<Output = bool> + Send;
}

/// できたファイル（題と印）。
pub type Results = Vec<(String, String)>;

/// URL を落として登録する口。Python の `_download_and_register`（テストでは台本どおりに答える偽物）。
pub trait Downloader: Sync {
    /// URL を落として登録し、題と印を返す。
    fn download(
        &self,
        url: &str,
        guild_id: u64,
        cache_ttl: i128,
    ) -> impl Future<Output = Result<Results, String>> + Send;
    /// 登録に、リンクを載せたメッセージを書き足す（Python の `update_discord_message`。失敗は警告だけ）。
    fn record_message(&self, token: &str, sent: Sent);
}

/// 拾った投稿。
#[derive(Clone, Debug)]
pub struct Post {
    /// サーバー。
    pub guild_id: u64,
    /// チャンネル。
    pub channel_id: u64,
    /// メッセージ。
    pub message_id: u64,
    /// 作者。
    pub author_id: u64,
    /// 作者の表示名（Python の `display_name`）。
    pub author_name: String,
    /// 作者のタグ（ログに書く。Python の `str(message.author)`）。
    pub author_tag: String,
    /// 本文。
    pub content: String,
}

/// 流れが覚えているもの（続けて頼んだ人・処理中の URL・同時に落とす数）。
pub struct State {
    cooldowns: Mutex<TtlCache<(u64, u64), f64>>,
    processing: Mutex<HashSet<(u64, u64, String)>>,
    downloads: Semaphore,
    /// 1 つの URL を落とすのに待つ長さ（`DJAUDIO_DL_TIMEOUT_SECONDS`）。
    timeout: Duration,
    /// 配信のリンクの頭（`DJAUDIO_BASE_URL`）。
    base_url: String,
    /// 単調な時計の起点。
    origin: Instant,
}

impl State {
    /// 作る（同時に落とす数は `DJAUDIO_DL_CONCURRENCY`）。続けて頼んだ人は 1 時間・5000 人まで覚える（Python と同じ）。
    pub fn new(concurrency: usize, timeout: Duration, base_url: &str) -> Self {
        Self {
            cooldowns: Mutex::new(TtlCache::new(3600.0, 5000)),
            processing: Mutex::new(HashSet::new()),
            downloads: Semaphore::new(concurrency.max(1)),
            timeout,
            base_url: base_url.to_string(),
            origin: Instant::now(),
        }
    }

    /// 単調な時計の秒（作ったときから）。続けて頼んだかを数える。
    pub fn now(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }

    /// 配信のリンクの頭。
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// リンクの Embed。Python の `_build_result_embed`（題は 50 文字で切る）。
pub fn result_embed(
    results: &Results,
    base_url: &str,
    guild_id: u64,
    cache_ttl: i128,
) -> CreateEmbed {
    let ttl_min = cache_ttl.div_euclid(60);
    let mut embed = CreateEmbed::new()
        .title("🎵 MP3 の準備が整った")
        // discord.py の `Color.blurple()`（serenity の `Colour::BLURPLE` は古い色 0x7289DA）。
        .colour(Colour::new(0x5865f2))
        .description(format!("⏱️ リンクは **{ttl_min}分後** に失効するぞ"));
    for (title, token) in results {
        let link = format!("{base_url}/dlaudio/files/{guild_id}/{token}");
        let short: String = title.chars().take(50).collect();
        embed = embed.field(
            format!("📥 {short}"),
            format!("[ダウンロード]({link})\n`{link}`"),
            false,
        );
    }
    embed
}

/// 進み具合のリアクションを付ける。Discord に断られただけなら、気にせず先へ進む（Python の `_add_reaction_safe`）。
async fn add_reaction_safe<O: Outlet>(outlet: &O, emoji: &str) -> Result<(), DiscordError> {
    match outlet.add_reaction(emoji).await {
        Err(DiscordError::Refused(e)) => {
            debug!("[DJAudio] リアクション追加に失敗 {emoji}: {e}");
            Ok(())
        }
        other => other,
    }
}

/// 自分の進み具合のリアクションを外す（Python の `_remove_reaction_safe`）。
async fn remove_reaction_safe<O: Outlet>(outlet: &O, emoji: &str) -> Result<(), DiscordError> {
    match outlet.remove_own_reaction(emoji).await {
        Err(DiscordError::Refused(e)) => {
            debug!("[DJAudio] リアクション除去に失敗 {emoji}: {e}");
            Ok(())
        }
        other => other,
    }
}

/// 投稿を 1 つ見る。Python の `handle_djaudio_message`（見張るチャンネルでなければ何もしない）。
///
/// `clock` は単調な時計の秒（続けて頼んだかを数える。Python と同じく、行き先を確かめたあとで読む）。`Err` は、
/// Python で例外が外へ抜けるところ（Bot の受け皿がログに残す）。
pub async fn handle_message<O: Outlet, D: Downloader>(
    state: &State,
    outlet: &O,
    downloader: &D,
    post: &Post,
    settings: &Runtime,
    clock: impl Fn() -> f64,
) -> Result<(), DiscordError> {
    let watching = settings.watch_channel.as_ref().and_then(|c| c.id());
    if watching != Some(post.channel_id) {
        return Ok(());
    }
    let max_urls = usize::try_from(settings.max_urls).unwrap_or(1);
    let urls = extract_urls(&post.content, max_urls);
    if urls.is_empty() {
        return Ok(());
    }
    let mut supported = Vec::new();
    let mut service_reasons = Vec::new();
    let mut unsafe_found = false;
    for url in urls {
        if let Some(reason) = is_unsupported_url(&url) {
            service_reasons.push(reason);
            continue;
        }
        if !is_djaudio_allowed_url(&url) {
            service_reasons.push(NOT_SUPPORTED);
            continue;
        }
        if !outlet.is_safe(&url).await {
            unsafe_found = true;
            continue;
        }
        supported.push(url);
    }
    if supported.is_empty() {
        let notice = if unsafe_found {
            UNSAFE
        } else {
            service_reasons.first().copied().unwrap_or(UNSUPPORTED_NOW)
        };
        outlet.reply(Some(format!("❌ {notice}")), None).await?;
        return Ok(());
    }

    let now = clock();
    let key = (post.guild_id, post.author_id);
    // 覚えていなければ待たせない（Python の `get(...) or 0` は、起動からの時間〔単調な時計〕と比べるので、
    // 覚えていない人はまず通る。Rust の時計は Bot の起動からなので、0 と比べずに「覚えていない」で分ける）。
    let last = state
        .cooldowns
        .lock()
        .expect("錠が壊れていない")
        .get(&key, now);
    let cooldown = settings.cooldown as f64;
    if let Some(last) = last.filter(|_| settings.cooldown > 0)
        && now - last < cooldown
    {
        let remaining = (cooldown - (now - last)).trunc() as i64;
        outlet
            .reply(
                Some(format!("⏱️ {remaining}秒後に再試行するがよい。")),
                None,
            )
            .await?;
        return Ok(());
    }
    state
        .cooldowns
        .lock()
        .expect("錠が壊れていない")
        .set(key, now, now);

    let jobs = supported
        .iter()
        .map(|url| process_url(state, outlet, downloader, post, url, settings));
    for outcome in futures_util::future::join_all(jobs).await {
        outcome?;
    }
    Ok(())
}

/// 処理中の印を、どの道を通っても外す。
struct Processing<'a> {
    state: &'a State,
    key: (u64, u64, String),
}

impl Drop for Processing<'_> {
    fn drop(&mut self) {
        self.state
            .processing
            .lock()
            .expect("錠が壊れていない")
            .remove(&self.key);
    }
}

/// URL を 1 つ片付ける。Python の `_process_url`（同じ投稿の同じ URL が処理中なら、すぐ戻る）。
async fn process_url<O: Outlet, D: Downloader>(
    state: &State,
    outlet: &O,
    downloader: &D,
    post: &Post,
    url: &str,
    settings: &Runtime,
) -> Result<(), DiscordError> {
    let key = (post.guild_id, post.message_id, url.to_string());
    if !state
        .processing
        .lock()
        .expect("錠が壊れていない")
        .insert(key.clone())
    {
        return Ok(());
    }
    let _processing = Processing { state, key };

    let outcome = try_process(state, outlet, downloader, post, url, settings).await;
    let notice = match outcome {
        Ok(()) => return Ok(()),
        Err(Failure::TimedOut) => {
            error!("タイムアウト [{url}]");
            TIMED_OUT
        }
        Err(Failure::Other(e)) => {
            error!("処理失敗 [{url}]: {e}");
            FAILED
        }
    };
    let tell = async {
        remove_reaction_safe(outlet, WORKING).await?;
        add_reaction_safe(outlet, FAILED_MARK).await?;
        outlet
            .reply(Some(notice.to_string()), None)
            .await
            .map(|_| ())
    };
    match tell.await {
        Err(DiscordError::Refused(e)) => {
            let what = if notice == TIMED_OUT {
                "タイムアウト通知"
            } else {
                "失敗通知"
            };
            warn!("[DJAudio] {what}を送れませんでした [{url}]: {e}");
            Ok(())
        }
        other => other,
    }
}

/// 片付けの失敗（時間切れか、それ以外か）。
enum Failure {
    TimedOut,
    Other(String),
}

impl From<DiscordError> for Failure {
    fn from(e: DiscordError) -> Self {
        Self::Other(e.to_string())
    }
}

async fn try_process<O: Outlet, D: Downloader>(
    state: &State,
    outlet: &O,
    downloader: &D,
    post: &Post,
    url: &str,
    settings: &Runtime,
) -> Result<(), Failure> {
    add_reaction_safe(outlet, WORKING).await?;
    info!(
        "URL検知 guild={} [{}]: {url}",
        post.guild_id, post.author_tag
    );
    let results = {
        let _permit = state
            .downloads
            .acquire()
            .await
            .map_err(|e| Failure::Other(e.to_string()))?;
        tokio::time::timeout(
            state.timeout,
            downloader.download(url, post.guild_id, settings.cache_ttl),
        )
        .await
        .map_err(|_| Failure::TimedOut)?
        .map_err(Failure::Other)?
    };
    remove_reaction_safe(outlet, WORKING).await?;
    add_reaction_safe(outlet, DONE).await?;

    let mut embed =
        result_embed(&results, &state.base_url, post.guild_id, settings.cache_ttl).footer(
            CreateEmbedFooter::new(format!("リクエスト: {}", post.author_name)),
        );
    let output = settings
        .output_channel
        .as_ref()
        .and_then(|c| c.id())
        .map_or(OutputChannel::Missing, |id| outlet.output_channel(id));
    let sent = match output {
        OutputChannel::Missing => outlet.reply(None, Some(embed)).await?,
        OutputChannel::Messageable(id) | OutputChannel::NotMessageable(id)
            if id == post.channel_id =>
        {
            outlet.reply(None, Some(embed)).await?
        }
        OutputChannel::Messageable(id) => {
            let jump = format!(
                "https://discord.com/channels/{}/{}/{}",
                post.guild_id, post.channel_id, post.message_id
            );
            embed = embed.field("元メッセージ", format!("[ジャンプ]({jump})"), true);
            outlet.send(id, embed).await?
        }
        OutputChannel::NotMessageable(id) => {
            return Err(Failure::Other(format!("チャンネル {id} には送れない")));
        }
    };
    for (_, token) in &results {
        downloader.record_message(token, sent);
    }
    info!(
        "完了 guild={} [{}]: {} ファイル",
        post.guild_id,
        post.author_tag,
        results.len()
    );
    Ok(())
}
