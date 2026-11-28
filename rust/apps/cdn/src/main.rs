//! DJAudio-DL の配信（`/dlaudio/`）の Rust 版の入口。Python の `cdn_main.py` と、管理画面の `/dlaudio/` を置き換える。
//!
//! - 待ち受け: `CDN_HOST`（既定 0.0.0.0）・`CDN_PORT`（既定 5002。Python の `cdn_main.py` と同じ）
//! - 置き場: `DJAUDIO_CACHE_DIR`（既定 `/app/data/djaudio_cache`。Bot と同じボリューム）
//! - ログ: `<SETTINGS_DIR>/logs/cdn.log` と `cdn.jsonl`（Python の `cdn_main.py` と同じ名前）
//! - 死活と数: Valkey へ（`VALKEY_URL`。管理画面の `/metrics` に `sycs_up{app="cdn"}` が出る）
//! - 信頼するプロキシ: `TRUSTED_PROXY_CIDRS`（Python と同じ読み方）
//!
//! `--self-check` を付けると、127.0.0.1 の空いた口で待ち受けて、自分の `/dlaudio/health` に 1 回尋ね、答えを
//! 読めたら 0 で終わる（イメージの `cpu-check` の段が、本番の CPU のふりでこれを通す）。

use std::process::ExitCode;
use std::sync::Arc;

use sycs_core::env::Env;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};
use sycs_web::serve::{self, Listen};
use tracing::{error, info};

use sycs_cdn::app::{self, APP_NAME, App, Config};

/// 待ち受けのポートの既定（Python の `CDN_PORT` と同じ）。
const DEFAULT_PORT: u16 = 5002;

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--self-check") {
        return self_check().await;
    }
    let env = Env::from_process();
    let log_dir = sycs_web::log_dir(&env);
    if let Err(e) = sycs_core::log::init(&log_dir, APP_NAME) {
        eprintln!("ログの置き場を開けません（{}）: {e}", log_dir.display());
        return ExitCode::FAILURE;
    }
    let listen = Listen::from_env(&env, "CDN_HOST", "CDN_PORT", DEFAULT_PORT);
    let config = Config::from_env(&env);
    info!(
        "配信を起動します: {}:{} 置き場={} 信頼するプロキシ={}（X-Forwarded-For をここからだけ受け取る）",
        listen.host,
        listen.port,
        config.cache_dir.display(),
        config.trusted.setting()
    );
    let reporter = Arc::new(Reporter::from_env(APP_NAME, &env));
    sycs_web::metrics::spawn_reporter(
        Arc::clone(&reporter),
        sycs_web::metrics::report_interval(&env),
    );
    let state = Arc::new(App::new(config, app::system_clock(), reporter));
    let listener = match listen.bind().await {
        Ok(listener) => listener,
        Err(e) => {
            error!("{}:{} で待ち受けられません: {e}", listen.host, listen.port);
            return ExitCode::FAILURE;
        }
    };
    match serve::serve(listener, app::router(state), serve::shutdown_signal()).await {
        Ok(()) => {
            info!("配信を止めました");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("配信の待ち受けが終わりました: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 待ち受けて、自分に 1 回尋ねて、答えを読む（ログは書かない。置き場は一時ディレクトリ）。
async fn self_check() -> ExitCode {
    let config = Config {
        cache_dir: std::env::temp_dir().join("sycs-cdn-self-check"),
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
    };
    let state = Arc::new(App::new(
        config,
        app::system_clock(),
        Arc::new(Reporter::new(APP_NAME, None)),
    ));
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("配信の確かめ: 待ち受けられません: {e}");
            return ExitCode::FAILURE;
        }
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("配信の確かめ: 待ち受けの口が分かりません: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = serve::serve(listener, app::router(state), async move {
        let _ = stopped.await;
    });
    let client = async move {
        let answer = sycs_web::probe::request(addr, "GET", "/dlaudio/health", &[]).await;
        let _ = stop.send(());
        answer
    };
    let (served, answer) = tokio::join!(server, client);
    if let Err(e) = served {
        eprintln!("配信の確かめ: 待ち受けが失敗しました: {e}");
        return ExitCode::FAILURE;
    }
    match answer {
        Ok(answer) if answer.status == 200 && answer.body == sycs_web::health::BODY.as_bytes() => {
            println!(
                "配信の確かめ: 応答を受け取りました（{} {}）",
                answer.status,
                String::from_utf8_lossy(&answer.body)
            );
            ExitCode::SUCCESS
        }
        Ok(answer) => {
            eprintln!(
                "配信の確かめ: 思っていた答えではありません（{} {}）",
                answer.status,
                String::from_utf8_lossy(&answer.body)
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("配信の確かめ: 尋ねられませんでした: {e}");
            ExitCode::FAILURE
        }
    }
}
