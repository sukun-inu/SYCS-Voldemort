//! Discord のイベントを受ける。Python の `events/` にあたる（今は ready・メンバーの出入りと変更・BAN）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use serenity::all::{
    Cache, ChunkGuildFilter, Context, EventHandler, Guild, GuildId, GuildMemberUpdateEvent, Member,
    Ready, Role, RoleId, ShardManager, User,
};
use serenity::async_trait;
use sqlx::PgPool;
use sycs_core::metrics::Reporter;
use sycs_core::settings::SettingsCache;
use tracing::{debug, info, warn};

use crate::config::BotConfig;
use crate::log_channel::{self, Author, AvatarColours, LogSink};
use crate::members::{self, LogEntry};
use crate::welcome::{self, Kind};
use crate::{compat, signals};

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
        Self {
            config,
            pool,
            settings,
            reporter,
            colours: AvatarColours::new(),
            shard_manager: OnceLock::new(),
        }
    }

    /// シャードの管理役を渡す（ゲートウェイの往復時間を測るのに使う）。
    pub fn set_shard_manager(&self, manager: Arc<ShardManager>) {
        let _ = self.shard_manager.set(manager);
    }
}

/// イベントの受け手。
pub struct Handler {
    state: Arc<AppState>,
    /// 常駐の処理を動かし始めたか。ready は再接続のたびに来るので、2 回目以降は何もしない。
    started: AtomicBool,
}

impl Handler {
    /// 作る。
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            started: AtomicBool::new(false),
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

/// イベントの時点のサーバーの様子（キャッシュから写す。写したら await をまたいで持ってよい）。
struct GuildFacts {
    id: GuildId,
    name: String,
    /// メンバー数。discord.py と同じく、参加・退出はイベントの前に増減している。
    member_count: Option<u64>,
    roles: HashMap<RoleId, Role>,
}

impl GuildFacts {
    fn of(cache: &Cache, id: GuildId) -> Self {
        match cache.guild(id) {
            Some(g) => Self {
                id,
                name: g.name.clone(),
                member_count: Some(g.member_count),
                roles: g.roles.clone(),
            },
            None => Self {
                id,
                name: String::new(),
                member_count: None,
                roles: HashMap::new(),
            },
        }
    }

    fn sorted_roles(&self, roles: &[RoleId]) -> Vec<RoleId> {
        members::sorted_roles(roles, &self.roles, self.id)
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
        tokio::spawn(report_metrics_forever(
            Arc::clone(&self.state),
            Arc::clone(&ctx.cache),
        ));
        if self.state.config.dev_signals_enabled {
            tokio::spawn(signals::run_forever(self.state.pool.clone()));
        } else {
            info!("BOT_DEV_SIGNALS_ENABLED=false: 管理画面からの依頼は取り出しません");
        }
        if let Some(only) = self.state.config.only_guild_id {
            warn!(
                only,
                "BOT_ONLY_GUILD_ID が設定されています。このサーバー以外のイベントは扱いません"
            );
        }
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
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        let roles = guild.sorted_roles(&member.roles);
        let entry = members::removal_entry(&user, &roles, guild.member_count.unwrap_or(0));
        self.log(&ctx, guild_id, entry, Author::from_member(&member), "退出")
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
        if let Some(entry) = members::nickname_entry(&before, &after) {
            self.log(&ctx, guild_id, entry, author.clone(), "ニックネームの変更")
                .await;
        }
        let guild = GuildFacts::of(&ctx.cache, guild_id);
        let roles = members::role_entry(
            after.user.id,
            &guild.sorted_roles(&before.roles),
            &guild.sorted_roles(&after.roles),
        );
        if let Some(entry) = roles {
            self.log(&ctx, guild_id, entry, author.clone(), "ロールの変更")
                .await;
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
    }

    async fn guild_ban_addition(&self, ctx: Context, guild_id: GuildId, banned_user: User) {
        if !self.handles(guild_id) {
            return;
        }
        let author = banned_author(&ctx.cache, guild_id, &banned_user);
        self.log(
            &ctx,
            guild_id,
            members::ban_entry(&banned_user),
            author,
            "BAN",
        )
        .await;
    }

    async fn guild_ban_removal(&self, ctx: Context, guild_id: GuildId, unbanned_user: User) {
        if !self.handles(guild_id) {
            return;
        }
        let author = banned_author(&ctx.cache, guild_id, &unbanned_user);
        self.log(
            &ctx,
            guild_id,
            members::unban_entry(&unbanned_user),
            author,
            "BAN の解除",
        )
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
