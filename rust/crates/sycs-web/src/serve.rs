//! 待ち受けと止め方。
//!
//! 待ち受けのアドレスとポートは環境変数から読む（Python の `CDN_PORT`・`ADMIN_PORT`・`WEB_PORT` と同じ名前・同じ既定・
//! 同じ範囲。アドレスは Python では `0.0.0.0` の決め打ちだったので、同じ既定にして `<名前>_HOST` で変えられるようにした）。
//!
//! 接続元（`ConnectInfo<SocketAddr>`）をリクエストに付けて渡す。信頼するプロキシの判定（[`crate::proxy`]）が、
//! 直接つないできた相手を見るため。
//!
//! 止めるのは SIGTERM（`docker stop`）か Ctrl+C。受け付け中のリクエストを返し終えてから止まる。

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use axum::Router;
use sycs_core::env::Env;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// 待ち受けのアドレスの既定（Python の uvicorn の `host="0.0.0.0"` と同じ。IPv4 だけ）。
pub const DEFAULT_HOST: &str = "0.0.0.0";

/// 待ち受けのアドレスとポート。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    /// アドレス（名前でもよい）。
    pub host: String,
    /// ポート（1〜65535）。
    pub port: u16,
}

impl Listen {
    /// 環境変数から読む。ポートは Python と同じく `env_int(…, minimum=1, maximum=65535)`（読めなければ既定）。
    pub fn from_env(env: &Env, host_key: &str, port_key: &str, default_port: u16) -> Self {
        let port = env.int(port_key, i64::from(default_port), Some(1), Some(65535));
        Self {
            host: env.string(host_key, DEFAULT_HOST),
            port: u16::try_from(port).unwrap_or(default_port),
        }
    }

    /// その口で待ち受ける。
    pub async fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind((self.host.as_str(), self.port)).await
    }
}

/// `router` で応え続ける。`shutdown` が終わったら、受け付け中のものを返してから戻る。
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// SIGTERM（`docker stop`）か Ctrl+C を待つ。
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Ctrl+C を待てません（SIGTERM だけを待ちます）: {e}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                warn!("SIGTERM を待てません（Ctrl+C だけを待ちます）: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    info!("止める合図を受けました。受け付け中のものを返してから止まります");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ポートは Python と同じ名前・既定・範囲で読み、読めない値は既定に倒すこと。アドレスの既定は 0.0.0.0。
    #[test]
    fn the_port_is_read_like_python() {
        let env = Env::from_fn(|key| match key {
            "CDN_PORT" => Some("6000".to_string()),
            "BAD_PORT" => Some("abc".to_string()),
            "HIGH_PORT" => Some("70000".to_string()),
            _ => None,
        });
        assert_eq!(
            Listen::from_env(&env, "CDN_HOST", "CDN_PORT", 5002),
            Listen {
                host: "0.0.0.0".to_string(),
                port: 6000
            }
        );
        assert_eq!(Listen::from_env(&env, "X", "BAD_PORT", 5002).port, 5002);
        assert_eq!(Listen::from_env(&env, "X", "HIGH_PORT", 5002).port, 65535);
    }
}
