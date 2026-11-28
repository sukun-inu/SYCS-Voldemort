//! 管理画面（rust-06）。Python の `webapp_admin/`（`admin_main.py` → uvicorn → `webapp_admin.app:app`）を置き換える。
//!
//! nginx の後ろに立ち（`/static/` と `/dlaudio/` は nginx と `apps/cdn` が受ける）、Python の管理画面と同じ答えを返す。
//! この塊（A1）は骨組みで、Python の層を外から順に同じに写している（計画 `PLAN.ja.md` の 1.2）:
//!
//! 1. セッション（starlette の `SessionMiddleware`。いちばん外。Cookie `admin_session` を読み、帰りに書き直す）
//! 2. 既定の回数の制限（slowapi の `SlowAPIMiddleware`。**app に直に足した経路だけ**、接続元とパスごとに 1 分 300 回）
//! 3. セッションの見張り（`session_serialization_guard_middleware`。`admin_guilds` を削る）
//! 4. セキュリティの見出し（`_apply_security_headers`）
//! 5. 数（`metrics_middleware`。`requests_total`・`http_responses_total`、5xx と拾えなかった例外のインシデント）
//! 6. 経路（Starlette の引き方。405・末尾の `/` の 307・404）と、断るときの答え（`_http_exception_response`）
//!
//! - [`app`] 層の組み立てと、経路の係が受け取るもの（[`app::Req`]）・返すもの（[`app::Reply`]・[`errors::Failure`]）
//! - [`routes`] 経路の表（Python の登録の順。塊ごとに 1 行ずつ足す）と、旧 URL・`/static` の受け皿
//! - [`routing`] Starlette の経路の引き方
//! - [`session`] Cookie（itsdangerous の `TimestampSigner` と starlette の `SessionMiddleware` の写し）
//! - [`secret`] セッションの秘密鍵の決め方（`resolve_session_secret`）
//! - [`security`] 4 つの確かめ（`check_login`・`check_guild`・`check_dev`・`check_csrf`）と CSRF の印
//! - [`errors`] 断るときの文と、エラーのページの差し込み口（ページの中身は A2）
//! - [`ratelimit`] 回数の制限（slowapi と limits の固定窓）
//! - [`metrics`] 数とインシデント（`webapp_admin/metrics.py` の `record_*`）
//! - [`python`] Python の値と文字の扱いの写し（`json.dumps`・`base64`・Cookie の読み方など）
//! - [`auth`] Discord のログイン（OAuth）と、Bot のトークンで引く管理者の確かめ（`webapp_admin/auth.py`。A3）
//! - [`views`] ログイン・サーバー選択・シェルの画面と公開ページの経路（`views/`・`_register_public_pages`。A3）

pub mod app;
pub mod auth;
pub mod errors;
pub mod metrics;
pub mod python;
pub mod ratelimit;
pub mod routes;
pub mod routing;
pub mod secret;
pub mod security;
pub mod session;
pub mod templates;
pub mod views;

/// 数のラベル（`app="admin"`）・心拍の名前（`hb:admin`）・ログの名前（`admin.log`・`admin.jsonl`）。Python と同じ。
pub const APP_NAME: &str = "admin";
