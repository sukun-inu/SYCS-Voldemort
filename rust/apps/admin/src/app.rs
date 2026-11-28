//! 層の組み立て。Python の `webapp_admin/app.py` の `create_app`（`_register_middleware` の順と、例外の係）。
//!
//! 外から順に（帰り道は内から外）:
//!
//! 1. セッション（`SessionMiddleware`）。Cookie を読む。署名の合う壊れた中身は、ここで素の 500
//!    （`ServerErrorMiddleware` の `Internal Server Error`。見出しも数も無い）。帰りに `Vary: Cookie` と `Set-Cookie`
//! 2. 既定の回数の制限（`SlowAPIMiddleware`）。app に直に足したデコレータの無い経路だけ。超えたら slowapi の 429
//!    （見出しの層より外なので、セキュリティの見出しも数も無い。セッションにも触らないので `Vary` も無い）
//! 3. セッションの見張り（`session_serialization_guard_middleware`。セッションに触り〔`Vary: Cookie`〕、
//!    `admin_guilds` を削る）
//! 4. セキュリティの見出し（`_apply_security_headers`。500 にも付く）
//! 5. 数（`metrics_middleware`。`/static` 以外を数え、5xx はインシデント。拾えなかった例外はインシデントと
//!    `exceptions_total` だけ数えて、500 の答えにする）
//! 6. 経路（[`crate::routing`]）と係。係が返した [`Failure`] は Python の例外の係と同じ答えにする
//!
//! 経路の係（[`Handler`]）は [`Req`] を受け取り、[`Reply`] か [`Failure`] を返す。確かめは係が書いた順に呼ぶ
//! （[`Req::check_guild`]・[`AdminApp::check_csrf`] など）。デコレータの回数の制限（`@limiter.limit("30/minute")`）は、
//! 確かめとパラメータの検証が通ったあとに [`AdminApp::check_route_limit`] を呼ぶ（Python のデコレータは、FastAPI が
//! 確かめを済ませてから係を呼んだところで数える）。

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use regex::Regex;
use serde_json::{Value, json};
use sycs_core::env::Env;
use sycs_core::metrics::Reporter;
use sycs_web::proxy::{self, TrustedHosts};
use tracing::{error, warn};

use crate::errors::{self, ErrorPage, Failure, HttpError, Pages};
use crate::metrics::{AdminMetrics, Clock, Incidents, Snapshot};
use crate::python;
use crate::ratelimit::{self, Limiter};
use crate::routing::{self, Found, Route};
use crate::security;
use crate::session::{self, Cookies, Session, SessionHandle};

/// 管理画面の CSP（`_apply_security_headers`。ここが唯一の定義と同じ文字）。
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; \
     style-src 'self'; img-src 'self' https://cdn.discordapp.com data:; font-src 'self'; \
     connect-src 'self' https://static.cloudflareinsights.com; base-uri 'none'; form-action 'self'; \
     frame-ancestors 'none'";
/// Starlette の `RedirectResponse` が `Location` を逃がすときに残す記号。
const LOCATION_SAFE: &str = ":/%#?=@[]!$&'()*+,;";
/// 受け取る本文の上限（nginx の `client_max_body_size 100m` と同じ）。
pub const MAX_BODY_BYTES: usize = 100 * 1024 * 1024;

/// 係が返す future。
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Reply, Failure>> + Send>>;
/// 経路の係。
pub type Handler = Arc<dyn Fn(Arc<AdminApp>, Req) -> HandlerFuture + Send + Sync>;

/// async の関数（か closure）を係にする。
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Arc<AdminApp>, Req) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Reply, Failure>> + Send + 'static,
{
    Arc::new(move |app: Arc<AdminApp>, req: Req| -> HandlerFuture { Box::pin(f(app, req)) })
}

/// 乱数（CSRF の印とインシデントの ID）。テストでは決まった並びにする。
pub trait Random: Send + Sync {
    /// `secrets.token_hex(nbytes)`。
    fn token_hex(&self, nbytes: usize) -> String;
    /// `uuid.uuid4().hex`。
    fn uuid_hex(&self) -> String;
}

/// OS の乱数。
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn token_hex(&self, nbytes: usize) -> String {
        crate::secret::token_hex(nbytes)
    }

    fn uuid_hex(&self) -> String {
        let mut bytes = [0u8; 16];
        if let Err(e) = getrandom::fill(&mut bytes) {
            panic!("OS の乱数を取れません: {e}");
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        crate::secret::hex_lower(&bytes)
    }
}

/// 本当の時刻（UNIX 時間の秒。マイクロ秒まで）。
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_micros() as f64 / 1e6)
    })
}

/// 設定（環境変数）。
#[derive(Clone, Debug)]
pub struct Config {
    /// `FLASK_SECURE_COOKIES`（真なら Cookie に `secure`、答えに HSTS）。Python は Cookie の印を起動のときに、HSTS を
    /// 要求のたびに読むが、Rust はどちらも起動のときに 1 回だけ読む。
    pub secure_cookies: bool,
    /// 信頼するプロキシ（`TRUSTED_PROXY_CIDRS`）。
    pub trusted: TrustedHosts,
    /// `DEV_USER_ID`（前後の空白を落としたもの。空なら開発者パネルは無い）。
    pub dev_user_id: String,
    /// 監視の置き場（`incidents.jsonl`）。
    pub monitor_dir: std::path::PathBuf,
}

impl Config {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        Self {
            secure_cookies: env.boolean("FLASK_SECURE_COOKIES", false),
            trusted: proxy::trusted_from_process(),
            dev_user_id: env.string("DEV_USER_ID", ""),
            monitor_dir: crate::metrics::monitor_dir(|key| std::env::var(key).ok()),
        }
    }
}

/// 差し替えられるもの（時刻・乱数・ページ・数の報告口）。
#[derive(Clone)]
pub struct Deps {
    /// 時刻（UNIX 時間の秒）。署名の時刻はこれの整数部（itsdangerous の `int(time.time())`）。
    pub clock: Clock,
    /// 乱数。
    pub random: Arc<dyn Random>,
    /// HTML のページ（A2 が minijinja のものに替える）。
    pub pages: Arc<dyn Pages>,
    /// 数の報告口。
    pub reporter: Arc<Reporter>,
}

/// 届いたリクエスト（答えを決めるのに使うものだけ）。
#[derive(Clone, Debug)]
pub struct Incoming {
    /// メソッド。
    pub method: Method,
    /// 戻す前のパス（`?` より前）。
    pub path: String,
    /// `?` より後（無ければ `None`）。
    pub query: Option<String>,
    /// 見出し。
    pub headers: HeaderMap,
    /// 本文。
    pub body: Bytes,
    /// 直接つないできた相手（IP の文字。分からなければ `None`）。
    pub peer: Option<String>,
}

/// 経路の係が受け取るもの（Python の `Request` にあたる）。
#[derive(Clone, Debug)]
pub struct Req {
    /// メソッド。
    pub method: Method,
    /// 戻したパス（`scope["path"]`）。
    pub path: String,
    /// `request.url.path`。
    pub url_path: String,
    /// 問い合わせ（戻す前）。
    pub query: Option<String>,
    /// 見出し。
    pub headers: HeaderMap,
    /// 本文。
    pub body: Bytes,
    /// 経路のパラメータ（名前と値。形の順）。
    pub params: Vec<(String, String)>,
    /// 接続元（信頼するプロキシで直したあと。Python の `request.client.host`）。
    pub client: Option<String>,
    /// scheme（`http`。信頼するプロキシが伝えたら `https` など）。
    pub scheme: String,
    /// セッション。
    pub session: SessionHandle,
}

impl Req {
    /// 経路のパラメータ。
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// その名前の最初の見出し（latin-1 として読む）。
    pub fn header(&self, name: &str) -> Option<String> {
        security::first_header(&self.headers, name)
    }

    /// `check_login`。
    pub fn check_login(&self) -> Result<(), Failure> {
        self.session.with(|session| security::check_login(session))
    }

    /// `check_guild`。
    pub fn check_guild(&self) -> Result<(), Failure> {
        self.session.with(|session| security::check_guild(session))
    }
}

/// 返す答え（状態・見出し・本文）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// 状態。
    pub status: u16,
    /// 見出し（名前は小文字。足した順）。
    pub headers: Vec<(String, String)>,
    /// 本文。
    pub body: Vec<u8>,
}

impl Reply {
    /// starlette の `Response`（本文の大きさと種類の見出しを足す。1xx・204・304 には大きさを付けない）。
    pub fn new(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Self {
        let mut headers = Vec::new();
        if !(status < 200 || status == 204 || status == 304) {
            headers.push(("content-length".to_string(), body.len().to_string()));
        }
        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type.to_string()));
        }
        Self {
            status,
            headers,
            body,
        }
    }

    /// `JSONResponse`（詰めた書き方。ASCII 以外はそのまま）。
    pub fn json(status: u16, value: &Value) -> Self {
        Self::new(
            status,
            Some("application/json"),
            python::dumps(value, python::COMPACT).into_bytes(),
        )
    }

    /// `HTMLResponse`・`TemplateResponse`。
    pub fn html(status: u16, body: String) -> Self {
        Self::new(status, Some("text/html; charset=utf-8"), body.into_bytes())
    }

    /// `RedirectResponse`（`Location` は `quote` で逃がす）。
    pub fn redirect(status: u16, url: &str) -> Self {
        let mut reply = Self::new(status, None, Vec::new());
        reply.append("location", &python::quote(url, LOCATION_SAFE));
        reply
    }

    /// その名前の最初の見出し。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// 見出しを置き換える（starlette の `headers[name] = value`。最初の位置に入れ、ほかの同じ名前は消す）。
    pub fn set(&mut self, name: &str, value: &str) {
        let mut seen = false;
        self.headers.retain_mut(|(n, v)| {
            if n != name {
                return true;
            }
            if seen {
                return false;
            }
            seen = true;
            *v = value.to_string();
            true
        });
        if !seen {
            self.append(name, value);
        }
    }

    /// 見出しを足す。
    pub fn append(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// `Vary` に足す（starlette の `add_vary_header`。あれば `, ` でつなぐ）。
    pub fn add_vary(&mut self, vary: &str) {
        let value = match self.header("vary") {
            Some(existing) => format!("{existing}, {vary}"),
            None => vary.to_string(),
        };
        self.set("vary", &value);
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        for (name, value) in self.headers {
            let bytes: Vec<u8> = value
                .chars()
                .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
                .collect();
            match (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(&bytes),
            ) {
                (Ok(name), Ok(value)) => {
                    response.headers_mut().append(name, value);
                }
                _ => warn!("見出し {name} に入れられない文字があったので落としました"),
            }
        }
        response
    }
}

/// `ServerErrorMiddleware` の答え（`PlainTextResponse("Internal Server Error", 500)`）。
pub fn plain_server_error() -> Reply {
    Reply::new(
        500,
        Some("text/plain; charset=utf-8"),
        b"Internal Server Error".to_vec(),
    )
}

/// 既定の回数の制限の答え（slowapi の `_rate_limit_exceeded_handler`）。
pub fn default_limit_reply() -> Reply {
    Reply::json(
        429,
        &json!({"error": format!(
            "Rate limit exceeded: {} per 1 minute",
            ratelimit::DEFAULT_PER_MINUTE
        )}),
    )
}

/// starlette の `_HOST_RE`（Host が URL を組み直しても安全な形か）。
fn host_is_safe(host: &str) -> bool {
    static HOST: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        Regex::new(r"(?i)^(?:[a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::[0-9]+)?\z")
            .unwrap_or_else(|e| panic!("Host の形を正規表現にできない: {e}"))
    })
    .is_match(host)
}

/// エラーの答えを決めるのに要る、要求の側のもの。
struct ErrorContext<'a> {
    url_path: &'a str,
    headers: &'a HeaderMap,
}

impl ErrorContext<'_> {
    /// `_is_api`（`/admin/api/` で始まるか、Accept が JSON を求める）。
    fn wants_json(&self) -> bool {
        if self.url_path.starts_with("/admin/api/") {
            return true;
        }
        let accept = security::first_header(self.headers, "accept").unwrap_or_default();
        errors::wants_json(&accept)
    }

    fn is_embedded(&self) -> bool {
        security::first_header(self.headers, "sec-fetch-dest")
            .is_some_and(|dest| dest.to_lowercase() == "iframe")
    }
}

/// 管理画面のアプリ。
pub struct AdminApp {
    config: Config,
    cookies: Cookies,
    routes: Vec<Route>,
    limiter: Limiter,
    metrics: AdminMetrics,
    clock: Clock,
    random: Arc<dyn Random>,
    pages: Arc<dyn Pages>,
}

impl std::fmt::Debug for AdminApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminApp")
            .field("config", &self.config)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl AdminApp {
    /// 作る。`routes` は [`crate::routes::default_routes`]（テストは後ろに足してよい）。
    pub fn new(config: Config, secret: &str, deps: Deps, routes: Vec<Route>) -> Self {
        let random = Arc::clone(&deps.random);
        let incidents = Incidents::new(
            config.monitor_dir.clone(),
            Arc::clone(&deps.clock),
            Arc::new(move || random.uuid_hex()),
        );
        Self {
            cookies: Cookies::new(secret, config.secure_cookies),
            metrics: AdminMetrics::new(deps.reporter, incidents),
            limiter: Limiter::new(),
            routes,
            clock: deps.clock,
            random: deps.random,
            pages: deps.pages,
            config,
        }
    }

    /// 設定。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 数え口。
    pub fn metrics(&self) -> &AdminMetrics {
        &self.metrics
    }

    /// Cookie の読み書き。
    pub fn cookies(&self) -> &Cookies {
        &self.cookies
    }

    /// 乱数。
    pub fn random(&self) -> &dyn Random {
        self.random.as_ref()
    }

    /// いまの時刻（UNIX 時間の秒）。
    pub fn now(&self) -> f64 {
        (self.clock)()
    }

    /// デコレータの回数の制限（`@limiter.limit("N/minute")`）。確かめと検証が通ったあとに呼ぶ。
    pub fn check_route_limit(&self, req: &Req, per_minute: u32) -> Result<(), Failure> {
        let client = ratelimit::client_key(req.client.as_deref());
        if self.limiter.hit(client, &req.path, per_minute, self.now()) {
            Ok(())
        } else {
            Err(Failure::RateLimited)
        }
    }

    /// `check_dev`（通れば `session["user"]`）。
    pub fn check_dev(&self, req: &Req) -> Result<Value, Failure> {
        req.session
            .with(|session| security::check_dev(session, &self.config.dev_user_id))
    }

    /// `check_csrf`。
    pub fn check_csrf(&self, req: &Req) -> Result<(), Failure> {
        req.session.with(|session| {
            security::check_csrf(&req.method, session, &req.headers, &req.body)
        })
    }

    /// 1 つのリクエストに答える（層の順はモジュールの説明）。
    pub async fn respond(self: &Arc<Self>, incoming: Incoming) -> Reply {
        let path = sycs_web::path::decoded(&incoming.path);
        let url_path = python::url_path(&path);
        let forwarded = proxy::resolve(
            &self.config.trusted,
            incoming.peer.as_deref(),
            &incoming.headers,
        );
        let now = self.now();
        let signed_now = now.floor() as i64;
        // 1. セッション。
        let session = match self.cookies.load(&incoming.headers, signed_now) {
            Ok(session) => SessionHandle::new(session),
            Err(session::Broken) => {
                error!("セッションの Cookie の署名は合うのに中身が読めません（素の 500 を返します）");
                return plain_server_error();
            }
        };
        let found = routing::find(&self.routes, &incoming.method, &path);
        // 2. 既定の回数の制限。
        if let Found::Endpoint(route, _) = &found
            && route.default_limit()
        {
            let client = ratelimit::client_key(forwarded.client.as_deref());
            if !self
                .limiter
                .hit(client, &path, ratelimit::DEFAULT_PER_MINUTE, now)
            {
                let mut reply = default_limit_reply();
                self.finish_session(&session, &mut reply, signed_now);
                return reply;
            }
        }
        // 5〜6. 数と、経路と係。
        let snapshot = Snapshot {
            method: incoming.method.to_string(),
            path: url_path.clone(),
            remote_addr: security::first_header(&incoming.headers, "cf-connecting-ip")
                .filter(|ip| !ip.is_empty())
                .or_else(|| forwarded.client.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        };
        let req = Req {
            method: incoming.method.clone(),
            path: path.clone(),
            url_path: url_path.clone(),
            query: incoming.query.clone(),
            headers: incoming.headers.clone(),
            body: incoming.body.clone(),
            params: Vec::new(),
            client: forwarded.client.clone(),
            scheme: forwarded.scheme.clone(),
            session: session.clone(),
        };
        let ctx = ErrorContext {
            url_path: &url_path,
            headers: &incoming.headers,
        };
        let mut reply = match self.dispatch(found, req, &ctx).await {
            Ok(reply) => {
                if !url_path.starts_with("/static") {
                    self.metrics.record_request(now);
                    self.metrics.record_response(reply.status, &snapshot);
                }
                reply
            }
            Err(crash) => {
                self.metrics.record_exception(&crash, &snapshot);
                error!(
                    "Request failed method={} path={url_path} root={} detail={}",
                    incoming.method, crash.kind, crash.message
                );
                self.error_response(&ctx, &session, 500, errors::SERVER_ERROR, None, None, &[])
            }
        };
        // 4. セキュリティの見出し。
        self.add_security_headers(&url_path, &mut reply);
        // 3. セッションの見張り。
        session.with(|session| {
            session.mark_accessed();
            session::sanitize(session);
        });
        // 1. セッションを書く。
        self.finish_session(&session, &mut reply, signed_now);
        reply
    }

    /// 経路を引いた結果を答えにする（拾えなかった例外だけは `Err`）。
    async fn dispatch(
        self: &Arc<Self>,
        found: Found<'_>,
        mut req: Req,
        ctx: &ErrorContext<'_>,
    ) -> Result<Reply, errors::Crash> {
        let session = req.session.clone();
        match found {
            Found::Endpoint(route, params) => {
                req.params = params;
                match (route.handler())(Arc::clone(self), req).await {
                    Ok(reply) => Ok(reply),
                    Err(Failure::Crash(crash)) => Err(crash),
                    Err(failure) => Ok(self.failure_reply(ctx, &session, failure)),
                }
            }
            Found::MethodNotAllowed(route) => {
                let error = HttpError::new(405).header("allow", &route.allow());
                Ok(self.http_error_reply(ctx, &session, &error))
            }
            Found::Redirect(candidate) => Ok(self.slash_redirect(&req, &candidate)),
            Found::NotFound => Ok(self.http_error_reply(ctx, &session, &HttpError::new(404))),
        }
    }

    /// 末尾の `/` の付け替え（Starlette の `redirect_slashes`。Host と scheme から組み立て、問い合わせを付ける）。
    ///
    /// Host が starlette の確かめに通らない（`/` を含むなど）・無いときは、Python は待ち受けの口から組み立てるが、
    /// Rust はパスだけにする（nginx の後ろでは Host はいつもある）。
    fn slash_redirect(&self, req: &Req, candidate: &str) -> Reply {
        let host = req.header("host").filter(|host| host_is_safe(host));
        let mut url = match host {
            Some(host) => format!("{}://{host}{candidate}", req.scheme),
            None => candidate.to_string(),
        };
        if let Some(query) = req.query.as_deref().filter(|q| !q.is_empty()) {
            url.push('?');
            url.push_str(query);
        }
        Reply::redirect(307, &url)
    }

    /// 係が返した失敗を答えにする（Python の例外の係）。
    fn failure_reply(&self, ctx: &ErrorContext<'_>, session: &SessionHandle, failure: Failure) -> Reply {
        match failure {
            Failure::NeedsLogin => Reply::redirect(303, "/admin/login"),
            Failure::NeedsGuild => Reply::redirect(303, "/admin/guilds"),
            Failure::Http(error) => self.http_error_reply(ctx, session, &error),
            Failure::RateLimited => {
                self.error_response(ctx, session, 429, errors::RATE_LIMITED, None, None, &[])
            }
            Failure::Validation(errors) => Reply::json(422, &json!({"detail": errors})),
            Failure::Crash(_) => {
                self.error_response(ctx, session, 500, errors::SERVER_ERROR, None, None, &[])
            }
        }
    }

    /// `_http_exception_response`（理由が英語の既定の文なら落とし、日本語の文と同じなら補足には出さない）。
    fn http_error_reply(&self, ctx: &ErrorContext<'_>, session: &SessionHandle, error: &HttpError) -> Reply {
        let message = errors::message(error.status);
        let detail = error
            .detail
            .as_deref()
            .filter(|d| !d.is_empty() && *d != errors::reason_phrase(error.status));
        let description = detail.filter(|d| *d != message);
        self.error_response(
            ctx,
            session,
            error.status,
            message,
            detail,
            description,
            &error.headers,
        )
    }

    /// `_error_response`。JSON の相手には `{"detail": 理由か文}`（見出しも付ける）、ほかは `error.html`（見出しは
    /// 付けない。描くときに知らせを取り出し、CSRF の印を入れる＝Python の `render()`）。
    #[allow(clippy::too_many_arguments)]
    fn error_response(
        &self,
        ctx: &ErrorContext<'_>,
        session: &SessionHandle,
        status: u16,
        message: &str,
        detail: Option<&str>,
        description: Option<&str>,
        headers: &[(String, String)],
    ) -> Reply {
        if ctx.wants_json() {
            let shown = detail.filter(|d| !d.is_empty()).unwrap_or(message);
            let mut reply = Reply::json(status, &json!({"detail": shown}));
            // starlette は渡した見出しを先に並べ、大きさと種類をあとに足す。
            let mut ordered = headers.to_vec();
            ordered.append(&mut reply.headers);
            reply.headers = ordered;
            return reply;
        }
        let embedded = ctx.is_embedded();
        let body = session.with(|session| {
            let messages = session.pop("_flashes").unwrap_or_else(|| json!([]));
            let csrf_token = security::issue_csrf_token(session, || self.random.token_hex(32));
            let snapshot: Session = session.clone();
            self.pages.error_page(&ErrorPage {
                code: status,
                message,
                description,
                messages: &messages,
                csrf_token: &csrf_token,
                session: &snapshot,
                is_embedded: embedded,
            })
        });
        Reply::html(status, body)
    }

    /// `_apply_security_headers`。
    fn add_security_headers(&self, url_path: &str, reply: &mut Reply) {
        if url_path.starts_with("/static") {
            reply.set("cache-control", "no-cache, max-age=0, must-revalidate");
            reply.set("pragma", "no-cache");
            reply.set("expires", "0");
        }
        reply.set("x-content-type-options", "nosniff");
        reply.set("x-frame-options", "DENY");
        reply.set("referrer-policy", "strict-origin-when-cross-origin");
        if self.config.secure_cookies {
            reply.set(
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            );
        }
        reply.set("content-security-policy", CONTENT_SECURITY_POLICY);
    }

    /// セッションの層の帰り道（[`finish_session`]）。
    fn finish_session(&self, session: &SessionHandle, reply: &mut Reply, now: i64) {
        session.with(|session| finish_session(&self.cookies, session, reply, now));
    }
}

/// セッションの層の帰り道（starlette の `send_wrapper`）。触ったら `Vary: Cookie`、書き換えたら `Set-Cookie`
/// （[`Cookies::set_cookie`]）。この順に足す。
pub fn finish_session(cookies: &Cookies, session: &Session, reply: &mut Reply, now: i64) {
    if session.accessed() {
        reply.add_vary("Cookie");
    }
    if let Some(cookie) = cookies.set_cookie(session, now) {
        reply.append("set-cookie", &cookie);
    }
}

/// axum の組み立て。`/health` と、それ以外の全部（管理画面の経路は [`AdminApp::respond`] が自分で引く）。
pub fn router(app: Arc<AdminApp>) -> Router {
    Router::new()
        .route(sycs_web::health::PATH, get(sycs_web::health::health))
        .fallback(serve_request)
        .with_state(app)
}

async fn serve_request(State(app): State<Arc<AdminApp>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let body = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(e) => {
            warn!("本文を読めませんでした（大きすぎるか、途中で切れた）: {e}");
            return Reply::new(
                413,
                Some("text/plain; charset=utf-8"),
                b"Payload Too Large".to_vec(),
            )
            .into_response();
        }
    };
    let incoming = Incoming {
        method: parts.method,
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        headers: parts.headers,
        body,
        peer,
    };
    app.respond(incoming).await.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::PlainPages;

    fn app(dir: &std::path::Path, extra: Vec<Route>) -> Arc<AdminApp> {
        let config = Config {
            secure_cookies: false,
            trusted: TrustedHosts::parse(proxy::DEFAULT_TRUSTED_PROXIES),
            dev_user_id: String::new(),
            monitor_dir: dir.to_path_buf(),
        };
        let deps = Deps {
            clock: Arc::new(|| 1_798_761_600.25),
            random: Arc::new(OsRandom),
            pages: Arc::new(PlainPages),
            reporter: Arc::new(Reporter::new("test", None)),
        };
        let mut routes = crate::routes::default_routes();
        routes.extend(extra);
        Arc::new(AdminApp::new(config, "secret", deps, routes))
    }

    fn get(path: &str) -> Incoming {
        Incoming {
            method: Method::GET,
            path: path.to_string(),
            query: None,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            peer: Some("testclient".to_string()),
        }
    }

    /// 普通の答えには見張りの層が触った印の Vary: Cookie とセキュリティの見出しが付き、既定の回数の制限の 429 には
    /// どちらも付かず、数にも入らないこと。
    #[tokio::test]
    async fn the_default_limit_answers_outside_the_layers() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path(), Vec::new());
        let mut last = Reply::default();
        for _ in 0..=ratelimit::DEFAULT_PER_MINUTE {
            last = app.respond(get("/admin/users/state")).await;
        }
        assert_eq!(last.status, 429);
        assert_eq!(last.header("vary"), None);
        assert_eq!(last.header("x-frame-options"), None);
        assert_eq!(last.body, br#"{"error":"Rate limit exceeded: 300 per 1 minute"}"#);
        let other = app.respond(get("/admin/settings/logging")).await;
        assert_eq!(other.status, 303);
        assert_eq!(other.header("vary"), Some("Cookie"));
        assert_eq!(other.header("x-frame-options"), Some("DENY"));
        let counted: i64 = app
            .metrics()
            .http()
            .reporter()
            .counters()
            .drain()
            .into_iter()
            .filter(|(name, _, _)| name == "requests_total")
            .map(|(_, _, n)| n)
            .sum();
        assert_eq!(counted, i64::from(ratelimit::DEFAULT_PER_MINUTE) + 1);
    }

    /// 見出しの置き換えと Vary の足し方が starlette と同じこと。
    #[test]
    fn headers_are_set_like_starlette() {
        let mut reply = Reply::new(200, None, Vec::new());
        reply.append("vary", "Accept");
        reply.append("x", "1");
        reply.append("x", "2");
        reply.set("x", "3");
        reply.add_vary("Cookie");
        assert_eq!(reply.header("vary"), Some("Accept, Cookie"));
        assert_eq!(
            reply.headers.iter().filter(|(n, _)| n == "x").count(),
            1
        );
        assert_eq!(reply.header("x"), Some("3"));
    }
}
