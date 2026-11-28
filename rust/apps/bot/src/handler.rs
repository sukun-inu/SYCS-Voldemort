//! Discord のイベントを受ける。Python の `events/` にあたる（今は ready・メンバーの出入りと変更・BAN・
//! メッセージの検査・メッセージの削除と編集のログ・スティッキー・リアクションロール・VC の出入り・
//! 利用者の状態の記録・スラッシュコマンド・地震の通知・ニュースの配信）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::Utc;
use serenity::all::{
    Cache, ChannelId, ChunkGuildFilter, Context, CreateMessage, EventHandler, Guild, GuildId,
    GuildMemberUpdateEvent, Interaction, Member, Message, MessageId, MessageUpdateEvent, Reaction,
    Ready, Role, RoleId, ShardManager, Timestamp, User, UserId, VoiceState,
};
use serenity::async_trait;
use serenity::model::guild::audit_log::MemberAction;
use sqlx::PgPool;
use sycs_core::metrics::Reporter;
use sycs_core::settings::SettingsCache;
use tracing::{debug, info, warn};

use crate::chat::{self, Chats};
use crate::config::BotConfig;
use crate::earthquake::{self, Deps};
use crate::earthquake_badges::DrawnBadges;
use crate::earthquake_feed::{self, CacheDirectory, FeedConfig, HttpOutbox, JmaDetailUrls};
use crate::groq::Groq;
use crate::log_channel::{self, Author, AvatarColours, LogSink};
use crate::members::{self, LogEntry};
use crate::message_cache::{CachedMessage, MessageCache};
use crate::message_security::{self, DiscordEffects, Judges, Post};
use crate::metal::MetalPrices;
use crate::moderation::Moderation;
use crate::news::{self, DiscordOutlet, News};
use crate::reaction_roles::{self, Change, ReactionEvent};
use crate::security::{self, RaidDetector, SpamDetector, Stripped};
use crate::sticky::{self, StickyCtx, StickyLocks};
use crate::user_state::{self, GuildView};
use crate::vc_notify::{self, Filter, Plan, VcTracker};
use crate::virustotal::VirusTotal;
use crate::welcome::{self, Kind};
use crate::{commands, compat, message_logs, signals};

/// Bot が動いている間ずっと持っているもの。
pub struct AppState {
    /// 設定（環境変数）。
    pub config: BotConfig,
    /// user_state_audit への接続の束。
    pub pool: PgPool,
    /// ギルドごとの設定。
    pub settings: Arc<SettingsCache>,
    /// メトリクスの送り口。
    pub reporter: Arc<Reporter>,
    /// アバターの代表色（ログの Embed の色）。
    pub colours: AvatarColours,
    /// 最近のメッセージの控え（削除・編集のログに使う）。
    pub messages: MessageCache,
    /// 利用者の状態（入退室・BAN・ロールの変更・VC の出入り）を書く口。
    pub user_state: user_state::Recorder,
    /// スティッキーのチャンネルごとの排他。
    pub sticky_locks: StickyLocks,
    /// VC の参加の時刻・メンションの間隔。
    pub vc: VcTracker,
    /// 連投の記録（メッセージの検査で使う）。
    pub spam: SpamDetector,
    /// VC に似た名前の人が続けて入った記録。
    pub raid: RaidDetector,
    /// メッセージの検査に使う VirusTotal と Groq。
    pub judges: Judges,
    /// 地震の通知に付ける、気象庁の詳細ページのリンク（一覧の取得と、決めたリンクの覚え）。
    pub earthquake_urls: JmaDetailUrls,
    /// 地震の電文の受け取り（動いているもの）。つなぎ直すときに止める。
    earthquake_feed: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// ニュースの取得と要約。
    pub news: News,
    /// AI の会話の覚え（応答チャンネルでの受け答え）。
    pub chats: Chats,
    /// 開いている選択の画面（/trusted・/bypass）の覚え。
    pub pickers: commands::picker::Pickers,
    /// 開いている地震の通知の種類の画面（/quake type）の覚え。
    pub quake_screens: commands::quake::Screens,
    /// 貴金属の値段の取り口（/metal。取った値段をしばらく覚える）。
    pub metal: MetalPrices,
    /// 合成の API（声の一覧）。
    pub tts: crate::tts::TtsApi,
    shard_manager: OnceLock<Arc<ShardManager>>,
}

impl AppState {
    /// 作る。シャードの管理役は Discord のクライアントを作ったあとで [`AppState::set_shard_manager`] で渡す。
    pub fn new(
        config: BotConfig,
        pool: PgPool,
        settings: Arc<SettingsCache>,
        reporter: Arc<Reporter>,
    ) -> Self {
        let vt = Arc::new(VirusTotal::new(config.vt.clone()));
        // Groq は用途ごとの枠を共有するので、プロセスに 1 つだけ作って配る（投稿の判定・ニュースの要約・
        // AI の会話）。
        let groq = Arc::new(Groq::new(config.groq.clone()));
        let moderation = Arc::new(Moderation::new(
            Arc::clone(&groq),
            config.moderation_cache_ttl,
        ));
        let chats = Chats::new(Arc::clone(&groq));
        let news = News::new(config.news.clone(), groq);
        let judges = Judges::new(vt, moderation, config.vt_scan_concurrency);
        let user_state = user_state::Recorder::new(pool.clone(), config.user_state.clone());
        let metal = MetalPrices::new(config.metal.clone());
        let tts = crate::tts::TtsApi::new(&config.tts_base_url);
        Self {
            config,
            pool,
            settings,
            reporter,
            colours: AvatarColours::new(),
            messages: MessageCache::default(),
            user_state,
            sticky_locks: StickyLocks::default(),
            vc: VcTracker::default(),
            spam: SpamDetector::default(),
            raid: RaidDetector::default(),
            judges,
            earthquake_urls: JmaDetailUrls::default(),
            earthquake_feed: Mutex::new(None),
            news,
            chats,
            pickers: commands::picker::Pickers::default(),
            quake_screens: commands::quake::Screens::default(),
            metal,
            tts,
            shard_manager: OnceLock::new(),
        }
    }

    /// シャードの管理役を渡す（ゲートウェイの往復時間を測るのに使う）。
    pub fn set_shard_manager(&self, manager: Arc<ShardManager>) {
        let _ = self.shard_manager.set(manager);
    }

    fn sticky<'a>(&'a self, ctx: &'a Context) -> StickyCtx<'a> {
        StickyCtx {
            http: &ctx.http,
            cache: &ctx.cache,
            settings: &self.settings,
            locks: &self.sticky_locks,
        }
    }

    /// 管理画面からの依頼のうち、移した用途を実行する。`payload` は依頼の中身。
    async fn run_task(self: &Arc<Self>, ctx: &Context, task: signals::Task, payload: String) {
        match task {
            signals::Task::Sticky => {
                sticky::process_pending(&self.sticky(ctx), |g| self.config.handles(g)).await;
            }
            signals::Task::NewsFeeds => self.run_news(ctx).await,
            signals::Task::EarthquakeReconnect => self.restart_earthquake_feed(ctx),
            signals::Task::EqReplay => self.replay_earthquake(ctx, &payload).await,
        }
    }

    /// ニュースを 1 回巡回する。Python の `run_news_feeds`。
    async fn run_news(&self, ctx: &Context) {
        let outlet = DiscordOutlet {
            cache: &ctx.cache,
            http: &ctx.http,
            settings: &self.settings,
        };
        news::run_news_feeds(
            &self.news,
            &outlet,
            || self.settings.snapshot(),
            |g| self.config.handles(g),
            news::unix_now(),
        )
        .await;
    }

    /// 地震の電文の受け取りを始める（動いていれば止めてから）。Python の `_signal_earthquake_reconnect`。
    ///
    /// 始め直すと、重複を見るための id の覚えも空になる（Python と同じ）。
    fn restart_earthquake_feed(self: &Arc<Self>, ctx: &Context) {
        let (state, ctx) = (Arc::clone(self), ctx.clone());
        let task = tokio::spawn(earthquake_feed::run_forever(
            FeedConfig::default(),
            move |kind, event| {
                let (state, ctx) = (Arc::clone(&state), ctx.clone());
                async move {
                    state
                        .notify_earthquake(&ctx, kind, &event, None, None)
                        .await;
                }
            },
        ));
        let mut running = self
            .earthquake_feed
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(old) = running.replace(task) {
            old.abort();
        }
    }

    /// 地震の電文を 1 つ通知する。送ったチャンネルの数を返す。
    ///
    /// 震度の札は付ける（[`DrawnBadges`]。Rust で描く）。震度の地図はまだ移していないので付かない。
    async fn notify_earthquake(
        &self,
        ctx: &Context,
        kind: earthquake_feed::Kind,
        event: &serde_json::Value,
        only_guild: Option<u64>,
        override_channel: Option<i64>,
    ) -> usize {
        let settings = self.settings.snapshot();
        let handles = |guild_id: u64| self.config.handles(guild_id);
        let deps = Deps {
            settings: &settings,
            directory: &CacheDirectory(&ctx.cache),
            outbox: &HttpOutbox(&ctx.http),
            images: &DrawnBadges,
            urls: &self.earthquake_urls,
            handles: &handles,
        };
        match kind {
            earthquake_feed::Kind::Quake => {
                earthquake::notify_quake(&deps, event, only_guild, override_channel).await
            }
            earthquake_feed::Kind::Tsunami => earthquake::notify_tsunami(&deps, event).await,
            earthquake_feed::Kind::Eew(notify_type) => {
                earthquake::notify_eew(&deps, event, notify_type).await
            }
        }
    }

    /// 開発者パネルの「地震リプレイ」。記録済みの電文を、本番と同じ経路で流し直す。Python の
    /// `_signal_eq_replay`。
    async fn replay_earthquake(&self, ctx: &Context, payload: &str) {
        let replay = match earthquake::parse_replay(payload) {
            Ok(replay) => replay,
            Err(e) => {
                warn!("[DEV] eq_replay: 依頼を読めないので何もしませんでした: {e}");
                return;
            }
        };
        let sent = self
            .notify_earthquake(
                ctx,
                earthquake_feed::Kind::Quake,
                &replay.event,
                replay.guild_id,
                replay.channel_id,
            )
            .await;
        // 0 件のときの理由は、通知の側が警告で出す。
        info!("[DEV] eq_replay: {sent} 件へ送信");
    }
}

/// 全サーバーを読み終えたら（来なければ [`CACHE_READY_TIMEOUT`] で見切って）、スティッキー・ニュース・
/// 地震の電文の受け取り・管理画面からの依頼の巡回を始める。
async fn start_after_cache_ready(
    ctx: Context,
    state: Arc<AppState>,
    ready: Arc<tokio::sync::Notify>,
) {
    if tokio::time::timeout(CACHE_READY_TIMEOUT, ready.notified())
        .await
        .is_err()
    {
        warn!(
            "{} 秒待っても全サーバーを読み終えませんでした。待たずに始めます",
            CACHE_READY_TIMEOUT.as_secs()
        );
    }
    // 常駐の仕事（スティッキーの巡回・ニュース・地震の受け取り）は、このプロセスが受け持つときだけ動かす
    // （Python の on_ready と同じ分け方。メッセージに応じたスティッキーの貼り直しは、ここに依らず動く）。
    if state.config.background_worker {
        tokio::spawn(sticky_forever(ctx.clone(), Arc::clone(&state)));
        tokio::spawn(news_forever(ctx.clone(), Arc::clone(&state)));
        state.restart_earthquake_feed(&ctx);
    } else {
        info!(
            "BOT_BACKGROUND_WORKER=false: スティッキーの巡回・ニュース・地震の受け取りは動かしません"
        );
    }
    if state.config.dev_signals_enabled {
        let pool = state.pool.clone();
        tokio::spawn(signals::run_forever(pool, move |task, payload| {
            let state = Arc::clone(&state);
            let ctx = ctx.clone();
            async move { state.run_task(&ctx, task, payload).await }
        }));
    } else {
        info!("BOT_DEV_SIGNALS_ENABLED=false: 管理画面からの依頼は取り出しません");
    }
}

/// スティッキーの指示（貼る・消す）を 30 秒ごとに片付ける。Python の pending_sticky_task。
async fn sticky_forever(ctx: Context, state: Arc<AppState>) {
    loop {
        sticky::process_pending(&state.sticky(&ctx), |g| state.config.handles(g)).await;
        tokio::time::sleep(sticky::PENDING_INTERVAL).await;
    }
}

/// ニュースを 5 分ごとに巡回する。Python の news_feed_task。
///
/// 1 回ぶんを別のタスクで走らせる。途中で落ちても（パニック）、次の回は走る（Python の `_safe` と同じ。
/// 取得先が一時的におかしいだけで、配信が止まったままにならないようにする）。
async fn news_forever(ctx: Context, state: Arc<AppState>) {
    loop {
        let (ctx, state) = (ctx.clone(), Arc::clone(&state));
        let run = tokio::spawn(async move { state.run_news(&ctx).await });
        if let Err(e) = run.await {
            warn!("ニュースの巡回が途中で落ちました（次の回は走ります）: {e}");
        }
        tokio::time::sleep(news::INTERVAL).await;
    }
}

/// イベントの受け手。
pub struct Handler {
    state: Arc<AppState>,
    /// 常駐の処理を動かし始めたか。ready は再接続のたびに来るので、2 回目以降は何もしない。
    started: AtomicBool,
    /// 全サーバーを読み終えた合図（serenity の cache_ready）。
    cache_ready: Arc<tokio::sync::Notify>,
}

/// 全サーバーを読み終えるのを待つ上限。過ぎたら待たずに常駐の処理を始める（読めないサーバーが
/// あると合図が来ない。discord.py も一定の時間で見切って on_ready を出す）。
const CACHE_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl Handler {
    /// 作る。
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            started: AtomicBool::new(false),
            cache_ready: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn handles(&self, guild_id: GuildId) -> bool {
        self.state.config.handles(guild_id.get())
    }

    /// ログを 1 件送る。失敗はここで警告にして、同じイベントの他の処理（歓迎など）を巻き込まない
    /// （Python の `_safe` と同じ）。
    async fn log(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        entry: LogEntry,
        author: Author,
        what: &str,
    ) {
        let sink = LogSink {
            cache: &ctx.cache,
            http: &ctx.http,
            settings: &self.state.settings,
            colours: &self.state.colours,
        };
        let sent = log_channel::log_action(
            &sink,
            guild_id,
            entry.level,
            &entry.message,
            Some(&author),
            &entry.fields,
            entry.colour,
        )
        .await;
        if let Err(e) = sent {
            warn!(%guild_id, "{what}のログを送れませんでした: {e}");
        }
    }

    /// 利用者の状態を 1 件記録する。失敗は中でログに残し、同じイベントの他の処理（歓迎など）を巻き込まない
    /// （Python が log_action と record_user_state_event を別々の `_safe` でくるんでいるのと同じ）。
    async fn record_state(&self, event: user_state::Event) {
        let snapshot = self.state.settings.snapshot();
        self.state
            .user_state
            .record(&event, snapshot.guild(event.guild_id))
            .await;
    }

    /// メッセージ 1 件を検査する（危険なら消してロールを剥がす）。Python の `handle_security_for_message`。
    async fn check_security(&self, ctx: &Context, post: &Post) {
        let snapshot = self.state.settings.snapshot();
        let cx = message_security::Context {
            settings: snapshot.guild(post.guild_id.get()),
            spam: &self.state.spam,
            raid: &self.state.raid,
            judges: &self.state.judges,
            clock: message_security::system_clock,
        };
        let fx = DiscordEffects {
            sink: LogSink {
                cache: &ctx.cache,
                http: &ctx.http,
                settings: &self.state.settings,
                colours: &self.state.colours,
            },
            post,
        };
        message_security::check_message(&fx, &cx, post).await;
    }

    /// 応答チャンネルへの投稿に、AI の返事を書く。Python の `handle_chatgpt_message`。
    async fn chat(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        message: &Message,
        author: Option<&Author>,
    ) {
        let snapshot = self.state.settings.snapshot();
        let incoming = chat::Incoming {
            guild_id: guild_id.get(),
            channel_id: message.channel_id.get(),
            user_id: message.author.id.get(),
            content: &message.content,
            from_self: message.author.id == ctx.cache.current_user().id,
        };
        let outlet = chat::DiscordOutlet {
            sink: LogSink {
                cache: &ctx.cache,
                http: &ctx.http,
                settings: &self.state.settings,
                colours: &self.state.colours,
            },
            guild_id,
            channel_id: message.channel_id,
            // サーバーごとのアバターが分かるときはそちら（検査のために組み立てたもの）。
            author: author
                .cloned()
                .unwrap_or_else(|| Author::from_user(&message.author)),
        };
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        chat::handle(
            &self.state.chats,
            snapshot.guild(guild_id.get()),
            &incoming,
            &outlet,
            unix_now,
            log_channel::now_jst(),
        )
        .await;
    }

    /// 歓迎・お別れを送る。失敗は警告にする。
    async fn greet(&self, ctx: &Context, guild: &GuildFacts, kind: Kind, user: &User) {
        let snapshot = self.state.settings.snapshot();
        let mention = compat::mention(user.id);
        let username = compat::user_tag(user);
        let values = welcome::Values {
            user: &mention,
            username: &username,
            server: &guild.name,
            count: guild.member_count,
        };
        let sent = welcome::send(
            &ctx.cache,
            &ctx.http,
            guild.id,
            snapshot.guild(guild.id.get()),
            kind,
            &values,
        )
        .await;
        if let Err(e) = sent {
            warn!(guild_id = %guild.id, ?kind, "歓迎・お別れを送れませんでした: {e}");
        }
    }
}

impl Handler {
    /// VC に入った・移ったときの荒らし対策。Python の `handle_security_for_voice_join`。
    ///
    /// 似た名前の人が続けて入ったら、その人のロールを全部剥がしてログに残す。信頼ユーザー・
    /// バイパスロールの人は数えない（Python と同じく、記録にも入れない）。
    async fn vc_raid_check(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        member: &Member,
        roles: &HashMap<RoleId, Role>,
        channel: u64,
        now: f64,
    ) {
        // discord.py の member.roles と同じく、サーバーにあるロールを低い順に（剥がす順もこれ。上の
        // ロールで権限が足りずに止まっても、それより下は剥がし終えている）。バイパスは @everyone も見る。
        let held = members::sorted_roles(&member.roles, roles, guild_id);
        let mut with_everyone = vec![RoleId::new(guild_id.get())];
        with_everyone.extend(held.iter().copied());
        let snapshot = self.state.settings.snapshot();
        if security::bypass_reason(
            snapshot.guild(guild_id.get()),
            member.user.id,
            &with_everyone,
        )
        .is_some()
        {
            return;
        }
        let name = vc_notify::display_name(
            member.nick.as_deref(),
            member.user.global_name.as_deref(),
            &member.user.name,
        );
        if !self.state.raid.check(channel, name, now) {
            return;
        }
        let stripped = security::strip_roles(&ctx.http, guild_id, member.user.id, &held).await;
        warn!(%guild_id, user_id = %member.user.id, ?stripped, "[SECURITY] VCレイド検出");
        if stripped == Stripped::Forbidden {
            warn!(%guild_id, "VCレイドのロール剥奪に失敗しました（権限が足りません）");
        }
        let entry = LogEntry {
            level: log_channel::Level::Error,
            message: "VCレイド検出".into(),
            fields: vec![("チャンネル".into(), format!("<#{channel}>"))],
            colour: Some(members::RED),
        };
        self.log(
            ctx,
            guild_id,
            entry,
            Author::from_member(member),
            "VCレイド",
        )
        .await;
    }
}

/// いまの時刻（UNIX 秒、小数つき）。Python の `time.time()`。
fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// イベントの時点のサーバーの様子（キャッシュから写す。写したら await をまたいで持ってよい）。
struct GuildFacts {
    id: GuildId,
    name: String,
    /// メンバー数。discord.py と同じく、参加・退出はイベントの前に増減している。
    member_count: Option<u64>,
    roles: HashMap<RoleId, Role>,
    /// 所有者（権限の控えに使う。所有者は全部の権限を持つ）。
    owner_id: Option<UserId>,
}

impl GuildFacts {
    fn of(cache: &Cache, id: GuildId) -> Self {
        match cache.guild(id) {
            Some(g) => Self {
                id,
                name: g.name.clone(),
                member_count: Some(g.member_count),
                roles: g.roles.clone(),
                owner_id: Some(g.owner_id),
            },
            None => Self {
                id,
                name: String::new(),
                member_count: None,
                roles: HashMap::new(),
                owner_id: None,
            },
        }
    }

    fn sorted_roles(&self, roles: &[RoleId]) -> Vec<RoleId> {
        members::sorted_roles(roles, &self.roles, self.id)
    }

    /// 利用者の状態の記録に渡す形。
    fn view(&self) -> GuildView<'_> {
        GuildView {
            id: self.id,
            owner_id: self.owner_id,
            roles: &self.roles,
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!(
            user = %ready.user.name,
            guilds = ready.guilds.len(),
            settings_guilds = self.state.settings.snapshot().guilds.len(),
            "Discord に接続しました"
        );
        // **ready は再接続のたびに来る。** 常駐の処理を毎回動かすと、同じ処理が並んで
        // 走る（Python の on_ready も is_running で守っている）。
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        // 死活はすぐ送り始める（止まって見えないように）。
        tokio::spawn(report_metrics_forever(
            Arc::clone(&self.state),
            Arc::clone(&ctx.cache),
        ));
        // チャンネルを確かめる処理（スティッキー・依頼）は、全サーバーを読み終えてから始める。
        // serenity の ready はサーバーの情報が届く前に来る（discord.py の on_ready は届いてから）。
        // 届く前に回すと、スティッキーの最初の指示がチャンネルを確かめられずに 30 秒遅れた。
        tokio::spawn(start_after_cache_ready(
            ctx.clone(),
            Arc::clone(&self.state),
            Arc::clone(&self.cache_ready),
        ));
        if let Some(only) = self.state.config.only_guild_id {
            warn!(
                only,
                "BOT_ONLY_GUILD_ID が設定されています。このサーバー以外のイベントは扱いません"
            );
        }
        if !self.state.config.commands_enabled {
            info!("BOT_COMMANDS_ENABLED=false: スラッシュコマンドには応えません");
        }
        // 登録は全体の置き換えなので、明示されたときだけ（切り替えまでは Python の Bot が登録している）。
        if self.state.config.sync_commands {
            match commands::sync(&ctx.http).await {
                Ok(count) => info!("[BOT] 同期したコマンド {count} 個"),
                Err(e) => warn!("スラッシュコマンドを登録できませんでした: {e}"),
            }
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        // スラッシュコマンドと、選択の画面の部品と、引数の補完。
        let guild_id = match &interaction {
            Interaction::Command(command) => command.guild_id,
            Interaction::Component(component) => component.guild_id,
            Interaction::Autocomplete(command) => command.guild_id,
            _ => return,
        };
        if !self.state.config.commands_enabled {
            return;
        }
        // BOT_ONLY_GUILD_ID で絞っているときは、そのサーバーの中のものだけ（DM も扱わない）。
        let handled = match guild_id {
            Some(guild_id) => self.handles(guild_id),
            None => self.state.config.only_guild_id.is_none(),
        };
        if !handled {
            return;
        }
        let deps = commands::Deps {
            settings: &self.state.settings,
            cache: &ctx.cache,
            http: &ctx.http,
            pickers: &self.state.pickers,
            admin_site_url: &self.state.config.admin_site_url,
            sticky_locks: &self.state.sticky_locks,
            quake_screens: &self.state.quake_screens,
            metal: &self.state.metal,
            colours: &self.state.colours,
            metals_site_url: &self.state.config.metals_site_url,
            tts: &self.state.tts,
        };
        match &interaction {
            Interaction::Command(command) => commands::dispatch(&deps, command).await,
            Interaction::Component(component) => commands::component(&deps, component).await,
            Interaction::Autocomplete(command) => commands::autocomplete(&deps, command).await,
            _ => {}
        }
    }

    async fn cache_ready(&self, _ctx: Context, guilds: Vec<GuildId>) {
        debug!(guilds = guilds.len(), "全サーバーを読み終えました");
        self.cache_ready.notify_one();
    }

    async fn guild_create(&self, ctx: Context, guild: Guild, _is_new: Option<bool>) {
        if !self.handles(guild.id) {
            return;
        }
        // discord.py は起動時に全メンバーを読み込む（chunk_guilds_at_startup の既定）。serenity は
        // 読み込まないので、そのままだと起動してから一度も見ていない人が抜けたときに、退出の
        // ログとお別れが出ない（変更前のメンバーが無いと、どちらも出せない）。
        ctx.shard
            .chunk_guild(guild.id, None, false, ChunkGuildFilter::None, None);
    }

    async fn message(&self, ctx: Context, new_message: Message) {
        // 控えは、どのサーバーのものでも・DM でも・Bot の発言でも入れる（discord.py と同じ数え方）。
        self.state
            .messages
            .insert(CachedMessage::from_message(&new_message));
        let Some(guild_id) = new_message.guild_id else {
            return;
        };
        if new_message.author.bot || !self.handles(guild_id) {
            return;
        }
        // 検査・スティッキー・AI の会話は並べて走らせる（Python の _dispatch_message の gather と同じ。
        // VirusTotal や Groq の待ちで、ほかを遅らせない）。
        let post = message_security::post_from_message(&ctx.cache, &new_message);
        let security = async {
            if let Some(post) = &post {
                self.check_security(&ctx, post).await;
            }
        };
        let sticky_ctx = self.state.sticky(&ctx);
        let sticky =
            sticky::handle_message(&sticky_ctx, guild_id.get(), new_message.channel_id.get());
        let chat = self.chat(
            &ctx,
            guild_id,
            &new_message,
            post.as_ref().map(|p| &p.author),
        );
        tokio::join!(security, sticky, chat);
    }

    async fn message_delete(
        &self,
        ctx: Context,
        _channel_id: ChannelId,
        deleted_message_id: MessageId,
        _guild_id: Option<GuildId>,
    ) {
        // 控えに無いメッセージの削除は、discord.py もイベントを出さない（中身が分からない）。
        let Some(message) = self.state.messages.remove(deleted_message_id) else {
            return;
        };
        let Some(guild_id) = message.guild_id else {
            return;
        };
        if !self.handles(guild_id) {
            return;
        }
        let entry = message_logs::deleted_entry(&message);
        self.log(
            &ctx,
            guild_id,
            entry,
            message_logs::author_of(&message),
            "メッセージの削除",
        )
        .await;
    }

    async fn message_delete_bulk(
        &self,
        _ctx: Context,
        _channel_id: ChannelId,
        multiple_deleted_messages_ids: Vec<MessageId>,
        _guild_id: Option<GuildId>,
    ) {
        // まとめての削除は、Python もログにしない（控えから外すだけ）。
        for id in multiple_deleted_messages_ids {
            self.state.messages.remove(id);
        }
    }

    async fn message_update(
        &self,
        ctx: Context,
        _old_if_available: Option<Message>,
        _new: Option<Message>,
        event: MessageUpdateEvent,
    ) {
        let attachments = event
            .attachments
            .as_ref()
            .map(|list| list.iter().map(|a| a.url.clone()).collect());
        let Some((before, after)) =
            self.state
                .messages
                .update(event.id, event.content.clone(), attachments)
        else {
            return;
        };
        let Some(guild_id) = before.guild_id else {
            return;
        };
        if !self.handles(guild_id) {
            return;
        }
        if let Some(entry) = message_logs::edited_entry(&before, &after) {
            self.log(
                &ctx,
                guild_id,
                entry,
                message_logs::author_of(&before),
                "メッセージの編集",
            )
            .await;
        }
    }

    async fn reaction_add(&self, ctx: Context, add_reaction: Reaction) {
        let Some(guild_id) = add_reaction.guild_id else {
            return;
        };
        // 付いたときは Discord がメンバーを付けてくる。Bot 自身のリアクションには反応しない。
        let Some(member) = add_reaction.member.as_ref() else {
            return;
        };
        if member.user.bot || !self.handles(guild_id) {
            return;
        }
        let event = ReactionEvent {
            guild_id,
            user_id: member.user.id,
            user_tag: compat::user_tag(&member.user),
            message_id: add_reaction.message_id.get(),
            emoji: &add_reaction.emoji,
            change: Change::Add,
        };
        reaction_roles::apply(&ctx.cache, &ctx.http, &self.state.settings, event).await;
    }

    async fn reaction_remove(&self, ctx: Context, removed_reaction: Reaction) {
        let (Some(guild_id), Some(user_id)) = (removed_reaction.guild_id, removed_reaction.user_id)
        else {
            return;
        };
        if !self.handles(guild_id) {
            return;
        }
        // 外れたときは Discord がメンバーを付けてこない。読み込んであるメンバーから引き、
        // いなければ何もしない（Python と同じ。取りに行かない）。
        let user = ctx
            .cache
            .guild(guild_id)
            .and_then(|g| g.members.get(&user_id).map(|m| m.user.clone()));
        let Some(user) = user else {
            return;
        };
        if user.bot {
            return;
        }
        let event = ReactionEvent {
            guild_id,
            user_id,
            user_tag: compat::user_tag(&user),
            message_id: removed_reaction.message_id.get(),
            emoji: &removed_reaction.emoji,
            change: Change::Remove,
        };
        reaction_roles::apply(&ctx.cache, &ctx.http, &self.state.settings, event).await;
    }

    async fn voice_state_update(&self, ctx: Context, old: Option<VoiceState>, new: VoiceState) {
        let Some(guild_id) = new.guild_id else {
            return;
        };
        let Some(member) = new.member.clone() else {
            return;
        };
        if member.user.bot || !self.handles(guild_id) {
            return;
        }
        // discord.py は前後のチャンネルをキャッシュから引く（無いチャンネルは「VC に居ない」になる）。
        let (before, after, roles, owner_id) = {
            let Some(guild) = ctx.cache.guild(guild_id) else {
                return;
            };
            let pick = |id: Option<ChannelId>| id.and_then(|i| guild.channels.get(&i).cloned());
            (
                pick(old.as_ref().and_then(|o| o.channel_id)),
                pick(new.channel_id),
                guild.roles.clone(),
                guild.owner_id,
            )
        };
        let before_id = before.as_ref().map(|c| c.id.get());
        let after_id = after.as_ref().map(|c| c.id.get());
        let now = unix_now();
        // 荒らし対策は出入りのログより前（Python の _dispatch_voice_state と同じ順）。
        if let Some(channel) = after_id.filter(|a| Some(*a) != before_id) {
            self.vc_raid_check(&ctx, guild_id, &member, &roles, channel, now)
                .await;
        }
        let Some(change) = vc_notify::change_of(before_id, after_id) else {
            return;
        };
        let stay = self
            .state
            .vc
            .track((guild_id.get(), member.user.id.get()), now, change);
        let entry = vc_notify::log_entry(
            change,
            &compat::mention(member.user.id),
            before_id,
            after_id,
        );
        self.log(
            &ctx,
            guild_id,
            entry,
            Author::from_member(&member),
            "VC の出入り",
        )
        .await;
        // ログ → 記録 → 通知の順（Python の _dispatch_voice_state と同じ）。
        let channel = |c: &Option<serenity::all::GuildChannel>| {
            c.as_ref().map(|c| (c.id.get(), c.name.clone()))
        };
        let (was, is) = (channel(&before), channel(&after));
        let view = GuildView {
            id: guild_id,
            owner_id: Some(owner_id),
            roles: &roles,
        };
        self.record_state(user_state::Event::voice(
            change,
            &member,
            &view,
            was.as_ref().map(|(id, name)| (*id, name.as_str())),
            is.as_ref().map(|(id, name)| (*id, name.as_str())),
            stay.as_ref()
                .map(|(seconds, text)| (*seconds, text.as_str())),
            Utc::now(),
        ))
        .await;
        let input = vc_notify::NoticeInput {
            guild_id,
            member: &member,
            change,
            before: before.as_ref(),
            after: after.as_ref(),
            roles: &roles,
            now,
            stay: stay.as_ref().map(|(_, text)| text.as_str()),
            at: Timestamp::now(),
        };
        let snapshot = self.state.settings.snapshot();
        let plan = vc_notify::plan(
            &self.state.vc,
            snapshot.guild(guild_id.get()),
            |id| log_channel::text_channel(&ctx.cache, guild_id, Some(id)).is_some(),
            &input,
        );
        match plan {
            Plan::Nothing
            | Plan::Filtered(Filter::Pass | Filter::Hidden | Filter::MissingRole(false)) => {}
            Plan::Filtered(Filter::MissingRole(true)) => warn!(
                "[BOT_SETUP] VC通知のフィルターロールが guild={guild_id} に見つかりません。                 非公開VCの通知が漏れないよう、見つかるまで通知を止めます。                 ロールを作り直すか、管理画面でフィルターの設定を外してください。"
            ),
            Plan::Send {
                channel_id,
                content,
                embed,
            } => {
                let mut message = CreateMessage::new().embed(*embed);
                if let Some(content) = content {
                    message = message.content(content);
                }
                if let Err(e) = ChannelId::new(channel_id)
                    .send_message(&ctx.http, message)
                    .await
                {
                    warn!(%guild_id, "VC 通知を送れませんでした: {e}");
                }
            }
        }
    }

    async fn guild_member_addition(&self, ctx: Context, new_member: Member) {
        let guild_id = new_member.guild_id;
        if !self.handles(guild_id) {
            return;
        }
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        let entry = members::join_entry(&new_member, guild.member_count.unwrap_or(0));
        self.log(
            &ctx,
            guild_id,
            entry,
            Author::from_member(&new_member),
            "参加",
        )
        .await;
        self.record_state(user_state::Event::member_join(
            &new_member,
            &guild.view(),
            guild.member_count.unwrap_or(0),
            Utc::now(),
        ))
        .await;
        self.greet(&ctx, &guild, Kind::Welcome, &new_member.user)
            .await;
    }

    async fn guild_member_removal(
        &self,
        ctx: Context,
        guild_id: GuildId,
        user: User,
        member_data_if_available: Option<Member>,
    ) {
        if !self.handles(guild_id) {
            return;
        }
        // discord.py は、キャッシュにいたメンバーのときだけ on_member_remove を出す（起動時に
        // 全員を読み込むので、ふつうは居る）。
        let Some(member) = member_data_if_available else {
            debug!(%guild_id, user_id = %user.id, "キャッシュにいないメンバーの退出なので、ログもお別れも出しません");
            return;
        };
        // キックだったかを監査ログで見分ける。Python と同じく、ログより先に調べる（監査ログへの反映が
        // 遅れることがあるので、見つからなければ 0.6 秒おきに 2 回まで読み直す。ふつうの退出では、その
        // ぶんログも遅れる）。Bot に監査ログを見る権限が無ければ、読みに行かない。
        let kick =
            user_state::audit_lookup(&ctx.cache, &ctx.http, guild_id, MemberAction::Kick, user.id)
                .await;
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        let roles = guild.sorted_roles(&member.roles);
        let entry = members::removal_entry(&user, &roles, guild.member_count.unwrap_or(0));
        self.log(&ctx, guild_id, entry, Author::from_member(&member), "退出")
            .await;
        self.record_state(user_state::Event::member_removal(
            &member,
            &guild.view(),
            guild.member_count.unwrap_or(0),
            kick,
            Utc::now(),
        ))
        .await;
        self.greet(&ctx, &guild, Kind::Goodbye, &member.user).await;
    }

    async fn guild_member_update(
        &self,
        ctx: Context,
        old_if_available: Option<Member>,
        new: Option<Member>,
        _event: GuildMemberUpdateEvent,
    ) {
        // discord.py は、キャッシュにいたメンバーのときだけ on_member_update を出す。
        let (Some(before), Some(after)) = (old_if_available, new) else {
            return;
        };
        let guild_id = after.guild_id;
        if !self.handles(guild_id) {
            return;
        }
        let author = Author::from_member(&after);
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        if let Some(entry) = members::nickname_entry(&before, &after) {
            self.log(&ctx, guild_id, entry, author.clone(), "ニックネームの変更")
                .await;
        }
        let nickname =
            user_state::Event::nickname_changed(&before, &after, &guild.view(), Utc::now());
        if let Some(event) = nickname {
            self.record_state(event).await;
        }
        let roles = members::role_entry(
            after.user.id,
            &guild.sorted_roles(&before.roles),
            &guild.sorted_roles(&after.roles),
        );
        if let Some(entry) = roles {
            self.log(&ctx, guild_id, entry, author.clone(), "ロールの変更")
                .await;
        }
        let role = user_state::Event::role_changed(&before, &after, &guild.view(), Utc::now());
        if let Some(event) = role {
            self.record_state(event).await;
        }
        let timeout = members::timeout_entry(
            after.user.id,
            before.communication_disabled_until,
            after.communication_disabled_until,
        );
        if let Some(entry) = timeout {
            self.log(&ctx, guild_id, entry, author, "タイムアウト")
                .await;
        }
        let timeout =
            user_state::Event::timeout_changed(&before, &after, &guild.view(), Utc::now());
        if let Some(event) = timeout {
            self.record_state(event).await;
        }
    }

    async fn guild_ban_addition(&self, ctx: Context, guild_id: GuildId, banned_user: User) {
        if !self.handles(guild_id) {
            return;
        }
        // discord.py は、まだキャッシュに残っていればメンバーを渡す（ロールと権限も控えに入る）。
        // 監査ログを調べる前に取っておく（調べている間に退出のイベントでキャッシュから消える）。
        let cached = ctx
            .cache
            .guild(guild_id)
            .and_then(|g| g.members.get(&banned_user.id).cloned());
        let audit = user_state::audit_lookup(
            &ctx.cache,
            &ctx.http,
            guild_id,
            MemberAction::BanAdd,
            banned_user.id,
        )
        .await;
        let author = match &cached {
            Some(member) => Author::from_member(member),
            None => Author::from_user(&banned_user),
        };
        self.log(
            &ctx,
            guild_id,
            members::ban_entry(&banned_user),
            author,
            "BAN",
        )
        .await;
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        self.record_state(user_state::Event::member_ban(
            &banned_user,
            cached.as_ref(),
            &guild.view(),
            audit,
            Utc::now(),
        ))
        .await;
    }

    async fn guild_ban_removal(&self, ctx: Context, guild_id: GuildId, unbanned_user: User) {
        if !self.handles(guild_id) {
            return;
        }
        let audit = user_state::audit_lookup(
            &ctx.cache,
            &ctx.http,
            guild_id,
            MemberAction::BanRemove,
            unbanned_user.id,
        )
        .await;
        let author = banned_author(&ctx.cache, guild_id, &unbanned_user);
        self.log(
            &ctx,
            guild_id,
            members::unban_entry(&unbanned_user),
            author,
            "BAN の解除",
        )
        .await;
        self.record_state(user_state::Event::member_unban(
            &unbanned_user,
            guild_id,
            audit,
        ))
        .await;
    }
}

/// BAN のログの作者。discord.py と同じく、キャッシュにメンバーとして残っていればメンバー
/// （サーバーごとのアバター）、いなければユーザー。
fn banned_author(cache: &Cache, guild_id: GuildId, user: &User) -> Author {
    let member = cache
        .guild(guild_id)
        .and_then(|g| g.members.get(&user.id).cloned());
    match member {
        Some(member) => Author::from_member(&member),
        None => Author::from_user(user),
    }
}

/// Bot の数値。Python の events/background_tasks.py の _report_metrics と同じ名前。
///
/// CPU とメモリは出さない（Netdata がホスト側で測る）。
pub fn gauges(
    guilds: usize,
    members_visible: u64,
    voice_clients: usize,
    latency: Option<f64>,
) -> Vec<(&'static str, f64)> {
    let mut gauges = vec![
        ("bot_guilds", guilds as f64),
        ("bot_members_visible", members_visible as f64),
        ("bot_voice_clients", voice_clients as f64),
    ];
    // 接続直後は往復時間がまだ無い。無い値を 0 として出すと「速い」と読まれる。
    if let Some(seconds) = latency.filter(|s| s.is_finite()) {
        gauges.push(("bot_gateway_latency_seconds", seconds));
    }
    gauges
}

/// 心拍と数値を送り続ける。**Bot の死活そのもの**（止まると sycs_up が 0 になる）。
async fn report_metrics_forever(state: Arc<AppState>, cache: Arc<Cache>) {
    loop {
        let guild_ids = cache.guilds();
        let members: u64 = guild_ids
            .iter()
            .filter_map(|id| cache.guild(*id).map(|g| g.member_count))
            .sum();
        let latency = match state.shard_manager.get() {
            Some(manager) => manager
                .runners
                .lock()
                .await
                .values()
                .find_map(|runner| runner.latency)
                .map(|d| d.as_secs_f64()),
            None => None,
        };
        // 音声はまだ移していないので 0（移したら songbird の接続数にする）。
        state
            .reporter
            .report_once(&gauges(guild_ids.len(), members, 0, latency))
            .await;
        tokio::time::sleep(state.config.metrics_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 数値の名前が Python の Bot と同じであること。
    ///
    /// 名前が違うと、切り替えた瞬間に Netdata の系列が途切れ、閾値のアラートも外れる。
    #[test]
    fn gauge_names_match_the_python_bot() {
        let python = include_str!("../../../../events/background_tasks.py");
        for (name, _) in gauges(1, 2, 3, Some(0.1)) {
            assert!(
                python.contains(&format!("\"{name}\"")),
                "Python の Bot に無い名前: {name}"
            );
        }
    }

    /// 往復時間がまだ無いときは、その数値を出さないこと（0 として出さない）。
    #[test]
    fn latency_is_left_out_until_it_is_known() {
        assert!(
            !gauges(1, 1, 0, None)
                .iter()
                .any(|(n, _)| *n == "bot_gateway_latency_seconds")
        );
        assert!(
            !gauges(1, 1, 0, Some(f64::INFINITY))
                .iter()
                .any(|(n, _)| *n == "bot_gateway_latency_seconds")
        );
        assert!(
            gauges(1, 1, 0, Some(0.05))
                .iter()
                .any(|(n, v)| *n == "bot_gateway_latency_seconds" && *v == 0.05)
        );
    }
}
