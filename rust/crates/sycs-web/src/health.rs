//! `/health`。プロセスが応答できることだけを返す（認証も、ほかの状態の確かめもしない）。
//!
//! 本文は Python の配信の `/dlaudio/health`（`{"status": "ok"}`）と同じ。nginx やコンテナの外から「動いているか」を
//! 見るための口で、Python のアプリには無かった（Python と同じ答えを返す経路とは別に、どのアプリにも足す）。

use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::response::Response;

/// 経路。
pub const PATH: &str = "/health";

/// 本文（Python の `JSONResponse({"status": "ok"})` と同じ文字）。
pub const BODY: &str = r#"{"status":"ok"}"#;

/// `/health` の応答。
pub async fn health() -> Response {
    let mut response = Response::new(Body::from(BODY));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
