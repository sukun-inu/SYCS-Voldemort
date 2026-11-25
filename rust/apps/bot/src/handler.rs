//! Discord のイベントを受ける。Python の `events/` にあたる（今は ready だけ）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use serenity::all::{Cache, Context, EventHandler, Ready, ShardManager};
use serenity::async_trait;
use sqlx::PgPool;
use sycs_core::metrics::Reporter;
use sycs_core::settings::SettingsCache;
use tracing::info;

use crate::config::BotConfig;
use crate::signals;

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
