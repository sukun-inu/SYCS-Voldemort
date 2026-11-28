//! DJAudio（見張るチャンネルに貼られた URL を MP3 にして、配信のリンクを返す）。Python の
//! `services/djaudio_service.py`・`djaudio_cache.py`・`djaudio_site_detection.py` と、`settings_store.py` の DJAudio の分。
//!
//! - [`settings`] … サーバーごとの設定（見張るチャンネル・出力チャンネル・有効期間・待ち時間・URL の数）
//! - [`site`] … どのサービスの URL か
//! - [`download`] … yt-dlp で MP3 にする（SoundCloud の client_id の取り直しを含む）
//! - [`cache`] … 配信するファイルの置き場（配信は別のプロセス。同じ置き場を読む）と、期限切れの掃除
//! - [`flow`] … 投稿を見て、⏳ → 落とす → ✅ → リンクの返信、までの流れ
//!
//! 配信（`/dlaudio/files/<guild_id>/<token>`）は、いまは Python の CDN（`cdn_main.py`）が受け持つ。

pub mod cache;
pub mod download;
pub mod flow;
pub mod settings;
pub mod site;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use serenity::all::{
    ChannelId, ChannelType, CreateAllowedMentions, CreateEmbed, CreateMessage, GuildId, Http,
    HttpError, MessageId, MessageReference, MessageReferenceKind, ReactionType,
};
use serenity::cache::Cache as SerenityCache;
use sycs_core::env::Env;
use tracing::{info, warn};

use crate::commands::server::python::int_text;
use crate::commands::settings::python_truthy;

use self::cache::{Cache, Entry};
use self::download::{SoundCloudIds, Tools};
use self::flow::{DiscordError, Downloader, Outlet, OutputChannel, Results, Sent};
use self::settings::Defaults;

/// 配信のリンクの頭の既定（Python の config と同じ。サーバーの外からは開けない）。
pub const DEFAULT_BASE_URL: &str = "http://localhost:5001";

/// DJAudio の設定（環境変数）。名前・既定・下限は Python の config と同じ。
#[derive(Clone, Debug)]
pub struct Config {
    /// 配信のリンクの頭（`DJAUDIO_BASE_URL`。末尾の `/` は落とす）。
    pub base_url: String,
    /// ファイルの置き場（`DJAUDIO_CACHE_DIR`。既定 `/app/data/djaudio_cache`）。
    pub cache_dir: PathBuf,
    /// サーバーの設定が無いときの値（`DJAUDIO_CACHE_TTL_SECONDS`・`DJAUDIO_COOLDOWN_SECONDS`・`DJAUDIO_MAX_URLS_PER_MSG`）。
    pub defaults: Defaults,
    /// 同時に落とす数（`DJAUDIO_DL_CONCURRENCY`、既定 3・下限 1）。
    pub concurrency: usize,
    /// 1 つの URL を落とすのに待つ秒数（`DJAUDIO_DL_TIMEOUT_SECONDS`、既定 120・下限 1）。
    pub timeout: Duration,
    /// yt-dlp・ffmpeg と SoundCloud の client_id（`DJAUDIO_FFMPEG_PATH`・`SOUNDCLOUD_CLIENT_ID`）。
    pub tools: Tools,
}

impl Config {
    /// 環境変数から読む。
    ///
    /// ffmpeg は `DJAUDIO_FFMPEG_PATH`、無ければ PATH の ffmpeg（見つからなければ `ffmpeg`）。Python が最後に試す
    /// imageio-ffmpeg からの自動取得（`DJAUDIO_AUTO_INSTALL_FFMPEG`）は持ち込まない（Rust のイメージは apt の ffmpeg）。
    pub fn from_env(env: &Env) -> Self {
        let base_url = env
            .raw("DJAUDIO_BASE_URL")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        if base_url.contains("localhost") || base_url.contains("127.0.0.1") {
            warn!(
                "[DJAudio] DJAUDIO_BASE_URL={base_url} (デフォルト値。本番では DJAUDIO_BASE_URL 環境変数を設定してください。\
                 未設定のままだと配信リンクがサーバー外から開けません)"
            );
        }
        let cache_dir = match env.raw("DJAUDIO_CACHE_DIR").filter(|v| !v.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from("/app/data/djaudio_cache"),
        };
        let ffmpeg = env
            .raw("DJAUDIO_FFMPEG_PATH")
            .filter(|v| !v.is_empty())
            .or_else(|| which("ffmpeg"))
            .unwrap_or_else(|| "ffmpeg".to_string());
        Self {
            base_url,
            cache_dir,
            defaults: Defaults {
                cache_ttl: env.int("DJAUDIO_CACHE_TTL_SECONDS", 600, Some(0), None),
                cooldown: env.int("DJAUDIO_COOLDOWN_SECONDS", 30, Some(0), None),
                max_urls: env.int("DJAUDIO_MAX_URLS_PER_MSG", 3, Some(1), None),
            },
            concurrency: usize::try_from(env.int("DJAUDIO_DL_CONCURRENCY", 3, Some(1), None))
                .unwrap_or(1),
            timeout: Duration::from_secs(
                u64::try_from(env.int("DJAUDIO_DL_TIMEOUT_SECONDS", 120, Some(1), None))
                    .unwrap_or(1),
            ),
            tools: Tools {
                ytdlp: "yt-dlp".to_string(),
                ffmpeg,
                soundcloud_client_id: env.raw("SOUNDCLOUD_CLIENT_ID").unwrap_or_default(),
                soundcloud_page: "https://soundcloud.com".to_string(),
            },
        }
    }

    /// 配信のリンクの頭が、サーバーの外から開けない既定のままか（Python の `_base_url_is_local`）。
    pub fn base_url_is_local(&self) -> bool {
        self.base_url.contains("localhost") || self.base_url.contains("127.0.0.1")
    }
}

/// PATH から実行ファイルを探す（Python の `shutil.which`）。
fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
        .map(|p| p.to_string_lossy().into_owned())
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// 本物の落とし口（yt-dlp → 題 → 置き場へ登録）。Python の `_download_and_register`。
pub struct Service {
    /// yt-dlp・ffmpeg・client_id の取り方。
    pub tools: Tools,
    /// 覚えている SoundCloud の client_id。
    pub ids: SoundCloudIds,
    /// 置き場。
    pub cache: Cache,
    /// メタデータの補い（Deezer。既定は本物の API。テストでは偽物に向ける）。
    pub deezer: crate::djaudio_meta::Deezer,
}

impl Service {
    /// 設定から作る（置き場が無ければ作る）。
    pub fn new(config: &Config) -> Self {
        Self {
            tools: config.tools.clone(),
            ids: SoundCloudIds::default(),
            cache: Cache::new(&config.cache_dir),
            deezer: crate::djaudio_meta::Deezer::new(crate::djaudio_meta::DEFAULT_BASE),
        }
    }
}

impl Downloader for Service {
    async fn download(&self, url: &str, guild_id: u64, cache_ttl: i128) -> Result<Results, String> {
        let dir =
            tempfile::tempdir().map_err(|e| format!("一時ディレクトリを作れませんでした: {e}"))?;
        let files = download::download_as_mp3(&self.tools, &self.ids, url, dir.path()).await?;
        if files.is_empty() {
            return Err("MP3 ファイルが生成されませんでした".to_string());
        }
        let mut results = Vec::new();
        for mp3 in files {
            let info = download::load_info_json(&mp3)?;
            let title = match info.as_ref().filter(|v| python_truthy(Some(v))) {
                Some(value @ Value::Object(meta)) => {
                    // Python は戻り値を見ない（補えなかっただけなら、そのまま登録する）。例外が外へ抜ける入力
                    // （Err）だけが、その URL の失敗になる。
                    crate::djaudio_meta::enrich_metadata(
                        &self.deezer,
                        &mp3,
                        value,
                        site::detect_site(meta),
                    )
                    .await
                    .map_err(|e| format!("メタデータの補いで例外: {e}"))?;
                    download::format_title(meta)
                }
                // 辞書でない info.json（配列・文字など）は、Python では `.get` が無くて例外になる。
                Some(_) => return Err("info.json が辞書でない".to_string()),
                None => download::stem(&mp3),
            };
            let token = cache::new_token()?;
            let cache = self.cache.clone();
            let (source, title_for_meta) = (url.to_string(), title.clone());
            // ファイルを移す（別のファイルシステムなら写す）のは重いので、非同期の処理を止めない側で。
            tokio::task::spawn_blocking(move || {
                cache.register(
                    &Entry {
                        file: &mp3,
                        source_url: &source,
                        title: &title_for_meta,
                        guild_id,
                        ttl: cache_ttl,
                    },
                    &token,
                )?;
                Ok::<String, String>(token)
            })
            .await
            .map_err(|e| format!("登録が途中で落ちました: {e}"))?
            .map(|token| results.push((title, token)))?;
        }
        Ok(results)
    }

    fn record_message(&self, token: &str, sent: Sent) {
        self.cache.set_discord_message(token, sent.0, sent.1);
    }
}

/// serenity の誤りを、Discord に断られた（discord.py の `HTTPException`）かそれ以外かに分ける。
fn classify(e: serenity::Error) -> DiscordError {
    match e {
        serenity::Error::Http(HttpError::UnsuccessfulRequest(_)) => {
            DiscordError::Refused(e.to_string())
        }
        other => DiscordError::Other(other.to_string()),
    }
}

/// 本物の Discord への働きかけ（拾った投稿 1 つぶん）。
pub struct DiscordOutlet<'a> {
    /// Discord へ送る口。
    pub http: &'a Http,
    /// serenity のキャッシュ（出力チャンネルを引く）。
    pub cache: &'a SerenityCache,
    /// 投稿のサーバー。
    pub guild_id: u64,
    /// 投稿のチャンネル。
    pub channel_id: u64,
    /// 投稿。
    pub message_id: u64,
}

impl DiscordOutlet<'_> {
    fn reaction(emoji: &str) -> ReactionType {
        ReactionType::Unicode(emoji.to_string())
    }
}

/// チャンネルがメッセージを送れる種類か（discord.py で `send` を持つクラスか）。カテゴリとフォーラム（メディアを
/// 含む）は持たない。
fn messageable(kind: ChannelType) -> bool {
    !matches!(
        kind,
        ChannelType::Category | ChannelType::Forum | ChannelType::Unknown(16)
    )
}

/// キャッシュからチャンネルを引く（どのサーバーのものでも。スレッドも）。Python の `bot.get_channel`。
/// 種類と、どのサーバーのものか。
fn lookup_channel(cache: &SerenityCache, channel_id: u64) -> Option<(ChannelType, u64)> {
    let id = ChannelId::new(channel_id);
    cache.guilds().into_iter().find_map(|g| {
        let guild = cache.guild(g)?;
        guild
            .channels
            .get(&id)
            .map(|c| c.kind)
            .or_else(|| guild.threads.iter().find(|t| t.id == id).map(|t| t.kind))
            .map(|kind| (kind, g.get()))
    })
}

impl Outlet for DiscordOutlet<'_> {
    async fn add_reaction(&self, emoji: &str) -> Result<(), DiscordError> {
        self.http
            .create_reaction(
                ChannelId::new(self.channel_id),
                MessageId::new(self.message_id),
                &Self::reaction(emoji),
            )
            .await
            .map_err(classify)
    }

    async fn remove_own_reaction(&self, emoji: &str) -> Result<(), DiscordError> {
        self.http
            .delete_reaction_me(
                ChannelId::new(self.channel_id),
                MessageId::new(self.message_id),
                &Self::reaction(emoji),
            )
            .await
            .map_err(classify)
    }

    async fn reply(
        &self,
        content: Option<String>,
        embed: Option<CreateEmbed>,
    ) -> Result<Sent, DiscordError> {
        // discord.py の `message.reply(..., mention_author=False)`: 返信の印（メッセージ・チャンネル・サーバー）と、
        // 既定の許可（@everyone・利用者・ロール）に「返信先には通知しない」を足したもの。
        let reference = MessageReference::new(
            MessageReferenceKind::Default,
            ChannelId::new(self.channel_id),
        )
        .message_id(MessageId::new(self.message_id))
        .guild_id(GuildId::new(self.guild_id));
        let mentions = CreateAllowedMentions::new()
            .everyone(true)
            .all_users(true)
            .all_roles(true)
            .replied_user(false);
        let mut message = CreateMessage::new()
            .reference_message(reference)
            .allowed_mentions(mentions);
        if let Some(content) = content {
            message = message.content(content);
        }
        if let Some(embed) = embed {
            message = message.embed(embed);
        }
        let sent = ChannelId::new(self.channel_id)
            .send_message(self.http, message)
            .await
            .map_err(classify)?;
        Ok((sent.channel_id.get(), sent.id.get()))
    }

    async fn send(&self, channel_id: u64, embed: CreateEmbed) -> Result<Sent, DiscordError> {
        let sent = ChannelId::new(channel_id)
            .send_message(self.http, CreateMessage::new().embed(embed))
            .await
            .map_err(classify)?;
        Ok((sent.channel_id.get(), sent.id.get()))
    }

    fn output_channel(&self, channel_id: u64) -> OutputChannel {
        match lookup_channel(self.cache, channel_id) {
            None => OutputChannel::Missing,
            Some((kind, _)) if messageable(kind) => OutputChannel::Messageable(channel_id),
            Some(_) => OutputChannel::NotMessageable(channel_id),
        }
    }

    async fn is_safe(&self, url: &str) -> bool {
        sycs_core::url_safety::validate_public_http_url(url, true)
            .await
            .is_ok()
    }
}

/// 期限を過ぎた登録を消す（リンクを載せた Discord のメッセージも消す）。Python の `_cleanup_expired`。
///
/// `discord` があれば、メッセージを取りに行ってから消す（Python と同じく GET → DELETE。失敗は警告だけで、
/// ファイルはどちらにしても消す）。`handles` が偽のサーバーのメッセージには触らない（`BOT_ONLY_GUILD_ID`）。
pub async fn cleanup_expired(
    cache: &Cache,
    discord: Option<(&Http, &SerenityCache)>,
    handles: impl Fn(u64) -> bool,
) {
    let now = cache::now_timestamp();
    let scanner = cache.clone();
    let expired = tokio::task::spawn_blocking(move || scanner.scan_expired(now))
        .await
        .unwrap_or_default();
    if let Some((http, serenity_cache)) = discord {
        for meta in &expired {
            let (_, message) = cache::token_and_message(meta);
            let Some((channel_text, message_text)) = message else {
                continue;
            };
            delete_link_message(http, serenity_cache, &channel_text, &message_text, &handles).await;
        }
    }
    if !expired.is_empty() {
        let tokens: Vec<String> = expired
            .iter()
            .map(|m| cache::token_and_message(m).0)
            .collect();
        let count = tokens.len();
        let deleter = cache.clone();
        let _ = tokio::task::spawn_blocking(move || {
            tokens.iter().for_each(|t| deleter.delete_entry(t))
        })
        .await;
        info!("DJAudio 期限切れキャッシュ {count} 件を削除");
    }
    let sweeper = cache.clone();
    let _ = tokio::task::spawn_blocking(move || sweeper.cleanup_orphaned_tmp(now)).await;
}

/// リンクを載せたメッセージを 1 つ消す。Python の `bot.get_channel(int(channel_id))` → `fetch_message(int(message_id))`
/// → `delete()` と同じ順に見る（ID が読めなければ警告、チャンネルがキャッシュに無ければ何もしない）。
async fn delete_link_message(
    http: &Http,
    serenity_cache: &SerenityCache,
    channel_text: &str,
    message_text: &str,
    handles: &impl Fn(u64) -> bool,
) {
    // 数として読めない ID は Python の ValueError（警告）。読めても 64 ビットに収まらない・0 以下の ID は、
    // どのチャンネルとも合わない（Python の get_channel は None）。
    let Some(channel_id) = int_text(channel_text) else {
        warn!("メッセージ削除失敗 {message_text}: チャンネルの ID が数でない");
        return;
    };
    let Some((kind, guild)) = channel_id
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .and_then(|id| lookup_channel(serenity_cache, id))
    else {
        return;
    };
    if !handles(guild) {
        return;
    }
    let Some(message_id) = int_text(message_text) else {
        warn!("メッセージ削除失敗 {message_text}: メッセージの ID が数でない");
        return;
    };
    if !messageable(kind) {
        warn!("メッセージ削除失敗 {message_text}: メッセージを持てないチャンネル");
        return;
    }
    let ids = (channel_id.parse::<u64>(), message_id.parse::<u64>());
    let (Ok(channel), Ok(message)) = ids else {
        warn!("メッセージ削除失敗 {message_text}: ID が大きすぎる");
        return;
    };
    let (channel, message) = (ChannelId::new(channel), MessageId::new(message.max(1)));
    let outcome = async {
        let found = http.get_message(channel, message).await?;
        found.delete(http).await
    }
    .await;
    match outcome {
        Ok(()) => info!("Discord メッセージ削除: {message_text}"),
        Err(e) => warn!("メッセージ削除失敗 {message_text}: {e}"),
    }
}

/// 60 秒ごとに掃除する。Python の `cache_cleanup_loop`（最初の 1 回も 60 秒待ってから）。
pub async fn cleanup_forever(
    cache: Cache,
    http: std::sync::Arc<Http>,
    serenity_cache: std::sync::Arc<SerenityCache>,
    handles: impl Fn(u64) -> bool,
) {
    info!(
        "DJAudio キャッシュ掃除ループ開始（{}秒間隔）",
        cache::CLEANUP_INTERVAL.as_secs()
    );
    loop {
        tokio::time::sleep(cache::CLEANUP_INTERVAL).await;
        cleanup_expired(&cache, Some((&http, &serenity_cache)), &handles).await;
    }
}
