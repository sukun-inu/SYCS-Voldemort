//! 配信を本当に TCP で待ち受けて、axum の組み立て（経路・接続元・見出しの書き出し）が効いていること。
//!
//! 基準との突き合わせ（`dlaudio_golden.rs`）は [`App::respond`] を直に呼ぶ。ここでは、その前後（axum が渡す
//! パスと見出し、`ConnectInfo` の接続元、spawn_blocking、見出しの書き出し、`/health`）を通す。

use std::path::Path;
use std::sync::Arc;

use sycs_cdn::app::{self, ACCEL_PREFIX, App, Config};
use sycs_core::metrics::Reporter;
use sycs_web::probe::{self, Answer};
use sycs_web::proxy::{DEFAULT_TRUSTED_PROXIES, TrustedHosts};
use sycs_web::serve;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const NO_HEADERS: &[(&str, &str)] = &[];

fn config(dir: &Path, trusted: &str) -> Config {
    Config {
        cache_dir: dir.to_path_buf(),
        secure_cookies: false,
        trusted: TrustedHosts::parse(trusted),
    }
}

/// 待ち受けて、順に尋ね、止める。
async fn ask(config: Config, requests: &[(&str, &str, &[(&str, &str)])]) -> Vec<Answer> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(App::new(
        config,
        app::system_clock(),
        Arc::new(Reporter::new("test", None)),
    ));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = serve::serve(listener, app::router(state), async move {
        let _ = stopped.await;
    });
    let client = async move {
        let mut answers = Vec::new();
        for (method, target, headers) in requests {
            answers.push(probe::request(addr, method, target, headers).await.unwrap());
        }
        let _ = stop.send(());
        answers
    };
    let (served, answers) = tokio::join!(server, client);
    served.unwrap();
    answers
}

#[tokio::test]
async fn a_file_is_handed_to_nginx_over_http() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(format!("{TOKEN}.json")),
        r#"{"guild_id": "999", "filename": "song.mp3", "extension": ".mp3", "expires_at": 99999999999}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join(format!("{TOKEN}.mp3")), b"ID3").unwrap();
    let target = format!("/dlaudio/files/999/{TOKEN}");
    let answers = ask(
        config(dir.path(), DEFAULT_TRUSTED_PROXIES),
        &[
            ("GET", target.as_str(), NO_HEADERS),
            ("GET", "/health", NO_HEADERS),
        ],
    )
    .await;
    let file = &answers[0];
    assert_eq!(file.status, 200);
    assert_eq!(
        file.header("x-accel-redirect"),
        Some(format!("{ACCEL_PREFIX}{TOKEN}.mp3").as_str())
    );
    assert_eq!(file.header("content-type"), Some("audio/mpeg"));
    assert_eq!(
        file.header("content-disposition"),
        Some("attachment; filename=\"song.mp3\"")
    );
    assert_eq!(file.header("x-frame-options"), Some("DENY"));
    assert!(file.body.is_empty(), "中身を送った");
    let health = &answers[1];
    assert_eq!(health.status, 200);
    assert_eq!(health.body, br#"{"status":"ok"}"#);
}

/// 付け替え先の scheme は、信頼するプロキシ（ここでは 127.0.0.1）が `X-Forwarded-Proto` で伝えたもの。信頼しない相手の
/// ものは読まない（uvicorn と同じ）。
#[tokio::test]
async fn only_a_trusted_proxy_decides_the_scheme() {
    let dir = tempfile::tempdir().unwrap();
    let headers: &[(&str, &str)] = &[("host", "mcdn.example.test"), ("x-forwarded-proto", "https")];
    let trusted = ask(
        config(dir.path(), DEFAULT_TRUSTED_PROXIES),
        &[("GET", "/dlaudio/health/", headers)],
    )
    .await;
    assert_eq!(trusted[0].status, 307);
    assert_eq!(
        trusted[0].header("location"),
        Some("https://mcdn.example.test/dlaudio/health")
    );
    let untrusted = ask(
        config(dir.path(), "10.0.0.0/8"),
        &[("GET", "/dlaudio/health/", headers)],
    )
    .await;
    assert_eq!(
        untrusted[0].header("location"),
        Some("http://mcdn.example.test/dlaudio/health")
    );
}

/// HEAD は 405（FastAPI の経路は GET だけ）。本文は送らず、Allow を付けること。
#[tokio::test]
async fn head_is_not_allowed_like_fastapi() {
    let dir = tempfile::tempdir().unwrap();
    let answers = ask(
        config(dir.path(), DEFAULT_TRUSTED_PROXIES),
        &[("HEAD", "/dlaudio/health", NO_HEADERS)],
    )
    .await;
    assert_eq!(answers[0].status, 405);
    assert_eq!(answers[0].header("allow"), Some("GET"));
    assert!(answers[0].body.is_empty());
}
