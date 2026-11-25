//! SYCS-Voldemort の Discord Bot（serenity）。discord.py の Bot（`main.py`）を置き換える。
//!
//! 移行中は機能を 1 つずつ移す（順番は移行トラッカー）。今あるのは骨組みだけ。
//!
//! - ログ: `<SETTINGS_DIR>/logs/<BOT_PROCESS_NAME>.log` と `.jsonl`（Python と同じ形）
//! - 死活と数値: Valkey へ（管理画面の `/metrics` に `sycs_up{app="<BOT_PROCESS_NAME>"}` が出る）
//! - ギルドごとの設定: Postgres から読み、変更は通知で受け取る。起動時に保存済みの null を落とす
//! - 管理画面からの依頼: 30 秒ごとに取り出す（まだ移していない用途は警告して捨てる）
//!
//! 起動の順番には意味がある。**設定を読めるまで Discord にはつながない。** つないでから
//! 設定が空だと、セキュリティの機能が全部切れたように振る舞い、誰も気づかない。

mod config;
mod handler;
mod signals;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serenity::Client;
use sqlx::postgres::PgPoolOptions;
use sycs_core::env::Env;
use sycs_core::metrics::Reporter;
use sycs_core::settings::{CacheOptions, SettingsCache};
use tracing::{error, info, warn};

use crate::config::BotConfig;
use crate::handler::{AppState, Handler};

#[tokio::main]
async fn main() -> ExitCode {
    let env = Env::from_process();
    let (log_dir, process_name) = config::log_target(&env);
    if let Err(e) = sycs_core::log::init(&log_dir, &process_name) {
        eprintln!("ログの置き場を開けません（{}）: {e}", log_dir.display());
        return ExitCode::FAILURE;
    }
    let config = match BotConfig::from_env(&env) {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    info!(process = %config.process_name, "Bot を起動します");

    // つなぐのは最初に使うとき（connect_lazy）。つながらないことの扱いは下の設定の
    // 読み込みが決める。
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy(&sycs_core::db::user_state_url(&env))
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("データベースの接続先が読めません: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(settings) = wait_for_settings(&pool, &config).await else {
        error!(
            "設定を {} 秒以内に読み込めませんでした。空の設定では動かないので止まります",
            config.settings_load_timeout.as_secs()
        );
        return ExitCode::FAILURE;
    };
    // 保存済みの null を起動時にまとめて落とす（Python の main.py と同じ）。書き換えのたびにも
    // 落としているが、誰も書き換えないギルドには古い null が残り続ける。失敗しても止まらない
    // （次に誰かが書けばそのギルドは揃う。読む側は null を未設定として扱う）。
    match settings.drop_stored_nulls().await {
        Ok(0) => {}
        Ok(n) => info!("設定から null を {n} 件取り除きました"),
        Err(e) => warn!("保存済みの null を取り除けませんでした（このまま続けます）: {e}"),
    }

    let state = Arc::new(AppState::new(
        config.clone(),
        pool,
        settings,
        Arc::new(Reporter::new(
            &config.process_name,
            config.valkey_url.as_deref(),
        )),
    ));
    let mut client = match Client::builder(&config.token, config::intents())
        .event_handler(Handler::new(Arc::clone(&state)))
        .await
    {
        Ok(client) => client,
        Err(e) => {
            error!("Discord のクライアントを作れません: {e}");
            return ExitCode::FAILURE;
        }
    };
    state.set_shard_manager(Arc::clone(&client.shard_manager));
    tokio::spawn(shutdown_on_signal(Arc::clone(&client.shard_manager)));

    match client.start().await {
        Ok(()) => {
            info!("Bot を止めました");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("Discord との接続が終わりました: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 設定を読めるまで、間を空けて繰り返す。`settings_load_timeout` を過ぎたら諦める。
async fn wait_for_settings(pool: &sqlx::PgPool, config: &BotConfig) -> Option<Arc<SettingsCache>> {
    let started = Instant::now();
    let mut delay = Duration::from_secs(1);
    loop {
        let options = CacheOptions {
            write_timeout: config.settings_write_timeout,
            ..CacheOptions::new(config.settings_poll_interval)
        };
        match SettingsCache::start_with(pool.clone(), options).await {
            Ok(cache) => return Some(cache),
            Err(e) if started.elapsed() + delay < config.settings_load_timeout => {
                warn!(
                    "設定を読み込めません（{} 秒後にやり直します）: {e}",
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
            Err(e) => {
                warn!("設定を読み込めません: {e}");
                return None;
            }
        }
    }
}

/// SIGTERM（docker stop）か Ctrl+C を受けたら、Discord から行儀よく抜ける。
///
/// 抜けずに落ちると、Discord 側では Bot がしばらく「オンライン」のまま残り、VC にも
/// 居座ったように見える。
async fn shutdown_on_signal(shard_manager: Arc<serenity::all::ShardManager>) {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                warn!("SIGTERM を待てません（Ctrl+C だけで止まります）: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = terminate => info!("SIGTERM を受けました。止めます"),
        _ = tokio::signal::ctrl_c() => info!("Ctrl+C を受けました。止めます"),
    }
    shard_manager.shutdown_all().await;
}
