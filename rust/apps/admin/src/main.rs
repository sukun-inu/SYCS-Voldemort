//! 管理画面の Rust 版の入口。Python の `admin_main.py`（uvicorn で `webapp_admin.app:app`）を置き換える。
//!
//! - 待ち受け: `ADMIN_HOST`（既定 0.0.0.0）・`ADMIN_PORT`（既定 5001。Python と同じ）
//! - ログ: `<SETTINGS_DIR>/logs/admin.log` と `admin.jsonl`（Python と同じ名前）
//! - セッションの秘密鍵: `ADMIN_FLASK_SECRET_KEY` か `<SETTINGS_DIR>/.admin_session_secret`（Python と同じ順・同じ
//!   ファイル。`sycs_admin::secret`）
//! - 死活と数: Valkey へ（`VALKEY_URL`。`hb:admin`・`c:*`）
//! - 信頼するプロキシ: `TRUSTED_PROXY_CIDRS`（Python と同じ読み方）
//! - `ADMIN_WORKERS` は読まない（1 プロセスで動く。Python も 1 固定で使っている）
//!
//! 監視の巡回（心拍・停止・しきい値）と `/metrics`・設定の読み込みは、あとの塊（A7・A5）が足す。
//!
//! `--self-check` を付けると、127.0.0.1 の空いた口で待ち受けて、自分の旧 URL（`/admin/users/state`）に Cookie 無しで
//! 1 回尋ね、ログイン画面への 303 を読めたら 0 で終わる（イメージの `cpu-check` の段が、本番の CPU のふりでこれを通す）。

use std::process::ExitCode;
use std::sync::Arc;

use sycs_core::env::Env;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};
use sycs_web::serve::{self, Listen};
use tracing::{error, info, warn};

use sycs_admin::APP_NAME;
use sycs_admin::app::{self, AdminApp, Config, Deps, OsRandom};
use sycs_admin::errors::PlainPages;
use sycs_admin::routes;
use sycs_admin::secret;

/// 待ち受けのポートの既定（Python の `ADMIN_PORT` と同じ）。
const DEFAULT_PORT: u16 = 5001;

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
    let settings_dir = env.path("SETTINGS_DIR", "/app/data");
    let raw_secret = match std::env::var_os(secret::SECRET_ENV) {
        None => None,
        Some(value) => match value.into_string() {
            Ok(value) => Some(value),
            Err(_) => {
                error!("{} が UTF-8 ではありません", secret::SECRET_ENV);
                return ExitCode::FAILURE;
            }
        },
    };
    let resolved = match secret::resolve(raw_secret.as_deref(), &settings_dir, || {
        secret::token_hex(32)
    }) {
        Ok(resolved) => resolved,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if env.int("ADMIN_WORKERS", 1, Some(1), None) > 1 {
        warn!("ADMIN_WORKERS は Rust の管理画面では使いません（1 プロセスで動きます）");
    }
    let listen = Listen::from_env(&env, "ADMIN_HOST", "ADMIN_PORT", DEFAULT_PORT);
    let config = Config::from_env(&env);
    info!(
        "管理画面を起動します: {}:{} 秘密鍵={:?} 監視の置き場={} 信頼するプロキシ={}（X-Forwarded-For をここからだけ受け取る）",
        listen.host,
        listen.port,
        resolved.source,
        config.monitor_dir.display(),
        config.trusted.setting()
    );
    let reporter = Arc::new(Reporter::from_env(APP_NAME, &env));
    sycs_web::metrics::spawn_reporter(
        Arc::clone(&reporter),
        sycs_web::metrics::report_interval(&env),
    );
    let deps = Deps {
        clock: app::system_clock(),
        random: Arc::new(OsRandom),
        pages: Arc::new(PlainPages),
        reporter,
    };
    let state = Arc::new(AdminApp::new(
        config,
        &resolved.secret,
        deps,
        routes::default_routes(),
    ));
    let listener = match listen.bind().await {
        Ok(listener) => listener,
        Err(e) => {
            error!("{}:{} で待ち受けられません: {e}", listen.host, listen.port);
            return ExitCode::FAILURE;
        }
    };
    match serve::serve(listener, app::router(state), serve::shutdown_signal()).await {
        Ok(()) => {
            info!("管理画面を止めました");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("管理画面の待ち受けが終わりました: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 待ち受けて、自分に 1 回尋ねて、答えを読む（ログは書かない。監視の置き場は一時ディレクトリ）。
async fn self_check() -> ExitCode {
    let config = Config {
        secure_cookies: false,
        trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        dev_user_id: String::new(),
        monitor_dir: std::env::temp_dir().join("sycs-admin-self-check"),
    };
    let deps = Deps {
        clock: app::system_clock(),
        random: Arc::new(OsRandom),
        pages: Arc::new(PlainPages),
        reporter: Arc::new(Reporter::new(APP_NAME, None)),
    };
    let state = Arc::new(AdminApp::new(
        config,
        &secret::token_hex(32),
        deps,
        routes::default_routes(),
    ));
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("管理画面の確かめ: 待ち受けられません: {e}");
            return ExitCode::FAILURE;
        }
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("管理画面の確かめ: 待ち受けの口が分かりません: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = serve::serve(listener, app::router(state), async move {
        let _ = stopped.await;
    });
    let client = async move {
        let answer = sycs_web::probe::request(addr, "GET", "/admin/users/state", &[]).await;
        let _ = stop.send(());
        answer
    };
    let (served, answer) = tokio::join!(server, client);
    if let Err(e) = served {
        eprintln!("管理画面の確かめ: 待ち受けが失敗しました: {e}");
        return ExitCode::FAILURE;
    }
    match answer {
        Ok(answer) if answer.status == 303 && answer.header("location") == Some("/admin/login") => {
            println!(
                "管理画面の確かめ: 応答を受け取りました（{} → /admin/login）",
                answer.status
            );
            ExitCode::SUCCESS
        }
        Ok(answer) => {
            eprintln!(
                "管理画面の確かめ: 思っていた答えではありません（{} {:?}）",
                answer.status,
                answer.header("location")
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("管理画面の確かめ: 尋ねられませんでした: {e}");
            ExitCode::FAILURE
        }
    }
}
