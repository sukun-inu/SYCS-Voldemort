//! 配信の経路（`/dlaudio/health`・`/dlaudio/files/<guild_id>/<token>`・`/dlaudio/info/<guild_id>/<token>`）。
//!
//! 本番の Python では、`services/djaudio_cdn.py` の `dlaudio_router` が管理画面のアプリ（`webapp_admin/app.py`）に
//! 入っていて、答えはその層を全部通ったものになる。ここはその層を、外から順に同じに写している。
//!
//! 1. セッション（starlette の `SessionMiddleware`。いちばん外）。配信はセッションを使わないが、管理画面の
//!    セッションの見張り（`session_serialization_guard_middleware`）がセッションに触るので、答えには必ず
//!    `Vary: Cookie` が付く。レート制限（slowapi の `SlowAPIMiddleware`）もこの内側にあるが、既定の 1 分 300 回は
//!    この経路には効いていない（基準の「回数の制限」で 301 回目も 410）。なので Rust も数えない
//! 2. セキュリティの見出し（`_apply_security_headers`。CSP・X-Frame-Options など。`FLASK_SECURE_COOKIES` なら HSTS）
//! 3. 数（`metrics_middleware`。`requests_total`・`http_responses_total`。拾えなかった例外は `exceptions_total` と 500）
//! 4. 経路（Starlette の引き方。戻したパスで引き、`$` は末尾の改行 1 つの前でも当たる。メソッド違いは 405、
//!    末尾の `/` の違いは 307 で付け替え先へ、どれでもなければ 404）
//! 5. 本体（`serve_file`・`file_info`。断るときは HTTPException → `_http_exception_response` → `_error_response`）
//!
//! **ファイルの中身は送らない。** 確かめたら `X-Accel-Redirect` で nginx の内側の場所（[`ACCEL_PREFIX`]）を指し、
//! nginx が置き場から送る（Range・大きいファイル・つなぎ直しは nginx に任せる）。Content-Type と Content-Disposition は
//! nginx がそのまま使い、セキュリティの見出しは nginx の設定が写す（`docker/nginx/sycs.conf.template`）。
//! ファイルの大きさ・日付・ETag は nginx が付けるので、Python（starlette の FileResponse）とは ETag の値だけが違う。
//!
//! Python と違うところ: `/dlaudio/` の外のパスには、管理画面のページの代わりに JSON の 404 を返す（nginx は
//! `/dlaudio/` の下しかここへ回さない）。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};
use sycs_core::env::Env;
use sycs_core::metrics::Reporter;
use sycs_web::metrics::HttpMetrics;
use sycs_web::proxy::{self, Forwarded, TrustedHosts};
use tracing::{error, info, warn};

use crate::cache::{self, Cache, Crash};
use crate::page;
use crate::python;

/// nginx の内側の場所（`internal`）。ここに `<token><拡張子>` を足したものを `X-Accel-Redirect` で返すと、nginx が
/// 置き場（`DJAUDIO_CACHE_DIR`）のそのファイルを送る。nginx の設定の `location /_sycs_djaudio/` と同じであること。
pub const ACCEL_PREFIX: &str = "/_sycs_djaudio/";
/// 置き場の既定（Python の config と Bot と同じ）。
pub const DEFAULT_CACHE_DIR: &str = "/app/data/djaudio_cache";
/// 数のラベル（`app="cdn"`）とログの名前（`cdn.log`・`cdn.jsonl`）。Python の `cdn_main.py` と同じ名前。
pub const APP_NAME: &str = "cdn";

/// 管理画面の CSP（`_apply_security_headers`。配信の応答にも付いている）。
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; \
     style-src 'self'; img-src 'self' https://cdn.discordapp.com data:; font-src 'self'; \
     connect-src 'self' https://static.cloudflareinsights.com; base-uri 'none'; form-action 'self'; \
     frame-ancestors 'none'";
/// Starlette の `RedirectResponse` が `Location` を逃がすときに残す記号。
const LOCATION_SAFE: &str = ":/%#?=@[]!$&'()*+,;";

/// 設定（環境変数）。
#[derive(Clone, Debug)]
pub struct Config {
    /// 置き場（`DJAUDIO_CACHE_DIR`。Bot と同じボリューム。期限切れを消すので書ける必要がある）。
    pub cache_dir: PathBuf,
    /// `FLASK_SECURE_COOKIES`（真なら HSTS を付ける。管理画面と同じ変数）。
    pub secure_cookies: bool,
    /// 信頼するプロキシ（`TRUSTED_PROXY_CIDRS`）。
    pub trusted: TrustedHosts,
}

impl Config {
    /// 環境変数から読む。
    pub fn from_env(env: &Env) -> Self {
        Self {
            cache_dir: env.path("DJAUDIO_CACHE_DIR", DEFAULT_CACHE_DIR),
            secure_cookies: env.boolean("FLASK_SECURE_COOKIES", false),
            trusted: proxy::trusted_from_process(),
        }
    }
}

/// いまの時刻（UNIX 時間の秒）を返すもの。テストでは止める。
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// 本当の時刻（Python の `datetime.now(timezone.utc).timestamp()` と同じく、マイクロ秒まで）。
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_micros() as f64 / 1e6)
    })
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
    /// 直接つないできた相手（分からなければ `None`）。
    pub peer: Option<IpAddr>,
}

impl Incoming {
    /// axum のリクエストから作る（接続元は `ConnectInfo`）。
    pub fn from_request(request: &Request) -> Self {
        let uri = request.uri();
        Self {
            method: request.method().clone(),
            path: uri.path().to_string(),
            query: uri.query().map(str::to_string),
            headers: request.headers().clone(),
            peer: request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip()),
        }
    }
}

/// 返す答え（状態・見出し・本文）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// 状態。
    pub status: u16,
    /// 見出し（名前は小文字）。
    pub headers: Vec<(&'static str, String)>,
    /// 本文。
    pub body: Vec<u8>,
}

impl Reply {
    /// その名前の見出し。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// 見出しを置き換える（Python の `response.headers[name] = value`）。
    fn set(&mut self, name: &'static str, value: &str) {
        self.headers.retain(|(n, _)| *n != name);
        self.headers.push((name, value.to_string()));
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        for (name, value) in self.headers {
            match HeaderValue::from_bytes(value.as_bytes()) {
                Ok(value) => {
                    response.headers_mut().append(name, value);
                }
                Err(_) => warn!("見出し {name} に入れられない文字があったので落としました"),
            }
        }
        response
    }
}

/// 配信の 3 つの経路。Starlette の経路と同じ引き方（[`Route::find`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route<'a> {
    /// `/dlaudio/health`。
    Health,
    /// `/dlaudio/files/{guild_id}/{token}`。
    Files {
        /// URL の guild_id。
        guild_id: &'a str,
        /// URL の印。
        token: &'a str,
    },
    /// `/dlaudio/info/{guild_id}/{token}`。
    Info {
        /// URL の guild_id。
        guild_id: &'a str,
        /// URL の印。
        token: &'a str,
    },
}

impl<'a> Route<'a> {
    /// 戻したパスから経路を引く（メソッドは見ない）。
    ///
    /// Starlette は経路を `^…$` の正規表現にして `re.match` で引く。Python の `$` は末尾の改行 1 つの前でも当たる
    /// ので、`/dlaudio/health` に改行を 1 つ足したもの（`%0A`）も当たる。`{guild_id}`・`{token}` は `/` を含まない
    /// 1 文字以上（`[^/]+`。最後のものは末尾の改行も含む）。
    pub fn find(path: &'a str) -> Option<Self> {
        const HEALTH: &str = "/dlaudio/health";
        if path == HEALTH || path.strip_suffix('\n') == Some(HEALTH) {
            return Some(Self::Health);
        }
        if let Some((guild_id, token)) = two_segments(path, "/dlaudio/files/") {
            return Some(Self::Files { guild_id, token });
        }
        if let Some((guild_id, token)) = two_segments(path, "/dlaudio/info/") {
            return Some(Self::Info { guild_id, token });
        }
        None
    }
}

/// `<prefix>{a}/{b}`（どちらも `/` を含まない 1 文字以上）。
fn two_segments<'a>(path: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = path.strip_prefix(prefix)?;
    let (first, second) = rest.split_once('/')?;
    (!first.is_empty() && !second.is_empty() && !second.contains('/')).then_some((first, second))
}

/// 配信のアプリ。
pub struct App {
    config: Config,
    cache: Cache,
    clock: Clock,
    metrics: HttpMetrics,
}

impl App {
    /// 作る（置き場が無ければ作る）。
    pub fn new(config: Config, clock: Clock, reporter: Arc<Reporter>) -> Self {
        Self {
            cache: Cache::new(config.cache_dir.clone()),
            clock,
            metrics: HttpMetrics::new(APP_NAME, reporter),
            config,
        }
    }

    /// 設定。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 数え口（テストで中身を見る）。
    pub fn metrics(&self) -> &HttpMetrics {
        &self.metrics
    }

    /// 1 つのリクエストに答える（ファイルを読むので、非同期の処理の外で呼ぶこと。[`router`] は spawn_blocking で呼ぶ）。
    pub fn respond(&self, request: &Incoming) -> Reply {
        let path = sycs_web::path::decoded(&request.path);
        let peer = request.peer.map(|ip| ip.to_string());
        let forwarded = proxy::resolve(&self.config.trusted, peer.as_deref(), &request.headers);
        let now = (self.clock)();
        // 3〜5. 数と、経路と本体。
        let mut reply = match self.route(request, &path, &forwarded, now) {
            Ok(reply) => {
                if !path.starts_with("/static") {
                    self.metrics.record_request();
                    self.metrics.record_response(reply.status);
                }
                reply
            }
            Err(crash) => {
                // Python の `_unhandled_request_response`。この経路では requests_total と http_responses_total は
                // 数えない（Python の metrics_middleware も、例外のときは数える前に抜ける）。
                self.metrics.record_exception(crash.kind);
                error!(
                    "Request failed method={} path={path} root={} detail={}",
                    request.method, crash.kind, crash.message
                );
                error_reply(request, &path, 500, page::SERVER_ERROR, None, None)
            }
        };
        // 2. セキュリティの見出し。
        self.add_security_headers(&path, &mut reply);
        // 1. セッション（いちばん外）。
        reply.set("vary", "Cookie");
        reply
    }

    /// 経路を引いて、本体に渡す。Starlette の `Router.__call__`。
    fn route(
        &self,
        request: &Incoming,
        path: &str,
        forwarded: &Forwarded,
        now: f64,
    ) -> Result<Reply, Crash> {
        let Some(route) = Route::find(path) else {
            return Ok(not_routed(request, path, forwarded));
        };
        // 3 つとも GET だけ（FastAPI の経路は HEAD を足さないので、HEAD も 405）。Starlette は理由を渡さずに断るので、
        // 理由には英語の既定の文が入る（管理画面がそれを落とす）。
        if request.method != Method::GET {
            let detail = page::default_reason_phrase(405);
            return Ok(http_exception(request, path, 405, Some(detail), true));
        }
        match route {
            Route::Health => Ok(json_reply(200, &json!({"status": "ok"}))),
            Route::Files { guild_id, token } => {
                self.serve_file(request, path, guild_id, token, now)
            }
            Route::Info { guild_id, token } => self.file_info(request, path, guild_id, token, now),
        }
    }

    /// ファイルを返す。Python の `serve_file`（中身は nginx に送らせる）。
    fn serve_file(
        &self,
        request: &Incoming,
        path: &str,
        guild_id: &str,
        token: &str,
        now: f64,
    ) -> Result<Reply, Crash> {
        if !valid_link(guild_id, token) {
            return Ok(http_exception(
                request,
                path,
                404,
                Some(page::LINK_INVALID),
                false,
            ));
        }
        let Some(meta) = self.cache.get_meta(token, now)? else {
            return Ok(http_exception(
                request,
                path,
                410,
                Some(page::LINK_EXPIRED),
                false,
            ));
        };
        if !same_guild(&meta, guild_id) {
            // リンクを別のサーバーへ転送されたとき。期限切れとは別に、ログに残す。
            warn!(
                "guild_id 不一致: URL={guild_id} meta={} token={token}",
                python::str_of(meta.get("guild_id"))
            );
            return Ok(http_exception(
                request,
                path,
                403,
                Some(page::LINK_WRONG_GUILD),
                false,
            ));
        }
        let Some((payload, extension)) = self.cache.payload_of(token, &meta) else {
            return Ok(http_exception(
                request,
                path,
                410,
                Some(page::LINK_EXPIRED),
                false,
            ));
        };
        let name = download_name(meta.get("filename"), token, extension)?;
        check_regular_file(&payload)?;
        info!("配信: guild={guild_id} token={token} → {name}");
        Ok(file_reply(token, extension, &name))
    }

    /// ファイルの情報を返す。Python の `file_info`（本体は落とさず、残り時間などだけ）。
    fn file_info(
        &self,
        request: &Incoming,
        path: &str,
        guild_id: &str,
        token: &str,
        now: f64,
    ) -> Result<Reply, Crash> {
        if !valid_link(guild_id, token) {
            return Ok(http_exception(
                request,
                path,
                404,
                Some(page::LINK_INVALID),
                false,
            ));
        }
        let Some(meta) = self.cache.get_meta(token, now)? else {
            return Ok(http_exception(
                request,
                path,
                410,
                Some(page::LINK_EXPIRED),
                false,
            ));
        };
        if !same_guild(&meta, guild_id) {
            return Ok(http_exception(
                request,
                path,
                403,
                Some(page::LINK_WRONG_GUILD),
                false,
            ));
        }
        let remaining = remaining_seconds(meta.get("expires_at"), now)?;
        let body = json!({
            "token": token,
            "title": meta.get("title").cloned().unwrap_or_else(|| json!("")),
            "filename": meta.get("filename").cloned().unwrap_or_else(|| json!("")),
            "expires_at": meta.get("expires_at").cloned().unwrap_or(Value::Null),
            "remaining_seconds": remaining,
            "remaining_minutes": remaining / 60,
        });
        Ok(json_reply(200, &body))
    }

    /// セキュリティの見出し。Python の `_apply_security_headers`（ここが CSP の唯一の定義と同じ文字）。
    fn add_security_headers(&self, path: &str, reply: &mut Reply) {
        if path.starts_with("/static") {
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
}

/// どの経路にも当たらなかったとき。Starlette の `redirect_slashes`（末尾の `/` を足す・全部落とすと当たるなら 307）と、
/// 当たらなければ 404。付け替えはメソッドを見ない（POST でも付け替え先へ送る）。
fn not_routed(request: &Incoming, path: &str, forwarded: &Forwarded) -> Reply {
    if path != "/" {
        let candidate = if path.ends_with('/') {
            path.trim_end_matches('/').to_string()
        } else {
            format!("{path}/")
        };
        if Route::find(&candidate).is_some() {
            return redirect(request, &candidate, forwarded);
        }
    }
    // Starlette の `not_found` も理由を渡さずに断る（英語の既定の文が入り、管理画面がそれを落とす）。
    http_exception(
        request,
        path,
        404,
        Some(page::default_reason_phrase(404)),
        false,
    )
}

/// 付け替え先への 307。Starlette の `URL(scope=…)` と `RedirectResponse`（Host の見出しと scheme から組み立て、
/// 問い合わせを付け、`quote` で逃がす）。Host が無ければパスだけにする（Python は待ち受けの口を使う）。
fn redirect(request: &Incoming, candidate: &str, forwarded: &Forwarded) -> Reply {
    let host = request
        .headers
        .get("host")
        .map(|v| proxy::latin1(v.as_bytes()));
    let mut url = match host {
        Some(host) => format!("{}://{host}{candidate}", forwarded.scheme),
        None => candidate.to_string(),
    };
    if let Some(query) = request.query.as_deref().filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(query);
    }
    Reply {
        status: 307,
        headers: vec![("location", python::quote(&url, LOCATION_SAFE))],
        body: Vec::new(),
    }
}

/// HTTPException を答えにする。管理画面の `_http_exception_response`（コードごとの日本語の文と、理由の補足）。
///
/// 理由（`detail`）が英語の既定の文（Starlette が理由を渡さずに断ったときに入れるもの）なら落とす。日本語の文と
/// 同じなら、補足としては出さない。405 には `Allow: GET` を付ける。
fn http_exception(
    request: &Incoming,
    path: &str,
    status: u16,
    detail: Option<&str>,
    allow_get: bool,
) -> Reply {
    let message = page::admin_message(status);
    let detail = detail.filter(|d| !d.is_empty() && *d != page::default_reason_phrase(status));
    let description = detail.filter(|d| *d != message);
    let mut reply = error_reply(request, path, status, message, detail, description);
    if allow_get {
        reply.set("allow", "GET");
    }
    reply
}

/// エラーを、相手に応じて JSON か HTML で返す。管理画面の `_error_response`。
///
/// fetch する相手（`Accept` で判断）には `{"detail": 理由か文}`、配信のリンク（`/dlaudio/`）を開いたブラウザには
/// 単体で立つ案内のページ。管理画面のページ（`error.html`）はここには無いので、`/dlaudio/` の外も JSON にする。
fn error_reply(
    request: &Incoming,
    path: &str,
    status: u16,
    message: &str,
    detail: Option<&str>,
    description: Option<&str>,
) -> Reply {
    let accept = request
        .headers
        .get("accept")
        .map(|v| proxy::latin1(v.as_bytes()))
        .unwrap_or_default();
    if path.starts_with("/admin/api/")
        || page::wants_json(&accept)
        || !path.starts_with("/dlaudio/")
    {
        return json_reply(status, &json!({"detail": detail.unwrap_or(message)}));
    }
    let shown = detail.or(description).unwrap_or(message);
    html_reply(status, page::render_link_error_page(status, shown))
}

fn json_reply(status: u16, value: &Value) -> Reply {
    Reply {
        status,
        headers: vec![("content-type", "application/json".to_string())],
        body: value.to_string().into_bytes(),
    }
}

fn html_reply(status: u16, html: String) -> Reply {
    Reply {
        status,
        headers: vec![("content-type", "text/html; charset=utf-8".to_string())],
        body: html.into_bytes(),
    }
}

/// 印と guild_id の形。Python の `_validate_guild_id`（`isdigit`）と `_validate_token`（`isalnum` で 32 文字）。
///
/// どちらも Python の判定なので、Unicode の数字・英数字も通す（実在の照合は情報の JSON で行う）。
fn valid_link(guild_id: &str, token: &str) -> bool {
    python::isdigit(guild_id) && python::isalnum(token) && token.chars().count() == 32
}

/// 情報の guild_id が URL と同じ文字か（Python の `meta.get("guild_id") != guild_id`。数の 999 は "999" と違う）。
fn same_guild(meta: &Map<String, Value>, guild_id: &str) -> bool {
    matches!(meta.get("guild_id"), Some(Value::String(stored)) if stored == guild_id)
}

/// ダウンロードのときのファイル名。Python の `serve_file` の `safe_name`。
///
/// 情報の `filename`（無ければ `<token><拡張子>`）を Python と同じに回し、英数字と ` ._-` だけを残して前後の空白を
/// 落とし、空なら `<token><拡張子>`、拡張子で終わらなければ拡張子を足す。`filename` が文字でないとき: 並びは中身を、
/// 辞書は鍵を回す（中に文字でないものがあれば例外）。null・数・真偽は回せないので例外（Python と同じく 500）。
fn download_name(raw: Option<&Value>, token: &str, extension: &str) -> Result<String, Crash> {
    let fallback = format!("{token}{extension}");
    let pieces: Vec<String> = match raw {
        None => fallback.chars().map(String::from).collect(),
        Some(Value::String(text)) => text.chars().map(String::from).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(Crash::no_attribute(other, "isalnum")),
            })
            .collect::<Result<_, _>>()?,
        Some(Value::Object(map)) => map.keys().cloned().collect(),
        Some(other) => {
            return Err(Crash::new(
                "TypeError",
                format!("'{}' object is not iterable", python::type_name(other)),
            ));
        }
    };
    // Python の `c.isalnum() or c in " ._-"`（並びの中身は何文字でもよく、`in` は文字の並びとして含まれるかを見る）。
    let kept: String = pieces
        .iter()
        .filter(|piece| python::isalnum(piece) || " ._-".contains(piece.as_str()))
        .map(String::as_str)
        .collect();
    let stripped = python::strip(&kept);
    let mut name = if stripped.is_empty() {
        fallback
    } else {
        stripped.to_string()
    };
    if !name.ends_with(extension) {
        name.push_str(extension);
    }
    Ok(name)
}

/// 本体が普通のファイルか。starlette の `FileResponse` は、送る前に stat して、普通のファイルでなければ例外にする。
fn check_regular_file(path: &Path) -> Result<(), Crash> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(Crash::new(
            "RuntimeError",
            format!("File at path {} is not a file.", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Crash::new(
            "RuntimeError",
            format!("File at path {} does not exist.", path.display()),
        )),
        Err(e) => Err(Crash::from_io(&e)),
    }
}

/// ファイルの答え。Content-Type と Content-Disposition は starlette の `FileResponse` と同じ。中身は nginx が送る。
///
/// ファイル名が `quote` で変わらない（ASCII の英数字と `._-` だけ）なら `filename="…"`、変わるなら
/// `filename*=utf-8''<逃がしたもの>`（空白や日本語を含むとき）。
fn file_reply(token: &str, extension: &str, name: &str) -> Reply {
    let quoted = python::quote(name, "/");
    let disposition = if quoted == name {
        format!("attachment; filename=\"{name}\"")
    } else {
        format!("attachment; filename*=utf-8''{quoted}")
    };
    Reply {
        status: 200,
        headers: vec![
            (
                "content-type",
                cache::content_type_for(extension).to_string(),
            ),
            ("content-disposition", disposition),
            (
                "x-accel-redirect",
                format!("{ACCEL_PREFIX}{token}{extension}"),
            ),
        ],
        body: Vec::new(),
    }
}

/// 残りの秒数。Python の `max(0, int(meta["expires_at"] - now))`（0 の方へ切り捨て）。
fn remaining_seconds(expires_at: Option<&Value>, now: f64) -> Result<i64, Crash> {
    let expires_at = match expires_at {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(other) => {
            return Err(Crash::new(
                "TypeError",
                format!(
                    "unsupported operand type(s) for -: '{}' and 'float'",
                    python::type_name(other)
                ),
            ));
        }
        None => return Err(Crash::new("KeyError", "'expires_at'")),
    };
    Ok(((expires_at - now).trunc() as i64).max(0))
}

/// axum の組み立て。`/health` と、それ以外の全部（配信の経路は [`App::respond`] が自分で引く）。
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route(sycs_web::health::PATH, get(sycs_web::health::health))
        .fallback(dispatch)
        .with_state(app)
}

/// ファイルを読むので、答えは spawn_blocking の中で決める（非同期の処理を止めない）。
async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let incoming = Incoming::from_request(&request);
    match tokio::task::spawn_blocking(move || app.respond(&incoming)).await {
        Ok(reply) => reply.into_response(),
        Err(e) => {
            error!("配信の処理が途中で止まりました: {e}");
            Reply {
                status: 500,
                headers: vec![("content-type", "text/plain; charset=utf-8".to_string())],
                body: b"Internal Server Error".to_vec(),
            }
            .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use sycs_core::metrics::Labels;
    use sycs_web::proxy::DEFAULT_TRUSTED_PROXIES;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app(dir: &Path) -> (App, Arc<Reporter>) {
        let reporter = Arc::new(Reporter::new("test", None));
        let config = Config {
            cache_dir: dir.to_path_buf(),
            secure_cookies: false,
            trusted: TrustedHosts::parse(DEFAULT_TRUSTED_PROXIES),
        };
        (
            App::new(config, Arc::new(|| 1_800_000_000.25), Arc::clone(&reporter)),
            reporter,
        )
    }

    fn get(target: &str) -> Incoming {
        Incoming {
            method: Method::GET,
            path: target.to_string(),
            query: None,
            headers: HeaderMap::new(),
            peer: None,
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// 経路の引き方が Starlette と同じこと（末尾の改行・空の区切り・3 つ目の区切り）。
    #[test]
    fn routes_are_found_like_starlette() {
        assert_eq!(Route::find("/dlaudio/health"), Some(Route::Health));
        assert_eq!(Route::find("/dlaudio/health\n"), Some(Route::Health));
        assert_eq!(Route::find("/dlaudio/health\n\n"), None);
        assert_eq!(
            Route::find("/dlaudio/files/1/t\n"),
            Some(Route::Files {
                guild_id: "1",
                token: "t\n"
            })
        );
        assert_eq!(Route::find("/dlaudio/files//t"), None);
        assert_eq!(Route::find("/dlaudio/files/1/t/"), None);
        assert_eq!(Route::find("/dlaudio/info/1/t/x"), None);
    }

    /// 数え方が管理画面の metrics_middleware と同じこと（断ったものも数え、拾えなかった例外は exceptions_total だけ）。
    #[test]
    fn requests_are_counted_like_the_admin_middleware() {
        let dir = tempfile::tempdir().unwrap();
        let (app, reporter) = app(dir.path());
        assert_eq!(app.respond(&get("/dlaudio/nothing")).status, 404);
        assert_eq!(
            app.respond(&get(&format!("/dlaudio/files/999/{TOKEN}")))
                .status,
            410
        );
        std::fs::create_dir(dir.path().join(format!("{TOKEN}.json"))).unwrap();
        assert_eq!(
            app.respond(&get(&format!("/dlaudio/info/999/{TOKEN}")))
                .status,
            500
        );
        let mut drained = reporter.counters().drain();
        drained.sort();
        assert_eq!(
            drained,
            vec![
                (
                    "exceptions_total".to_string(),
                    labels(&[("app", "cdn"), ("type", "IsADirectoryError")]),
                    1
                ),
                (
                    "http_responses_total".to_string(),
                    labels(&[("app", "cdn"), ("code", "404")]),
                    1
                ),
                (
                    "http_responses_total".to_string(),
                    labels(&[("app", "cdn"), ("code", "410")]),
                    1
                ),
                ("requests_total".to_string(), labels(&[("app", "cdn")]), 2),
            ]
        );
    }

    /// 回数で断らないこと（Python の管理画面の既定の 1 分 300 回は、この経路には効いていない）。
    /// どの答えにも `Vary: Cookie` が付き、全部が数に入ること。
    #[test]
    fn many_requests_are_not_refused_like_python() {
        let dir = tempfile::tempdir().unwrap();
        let (app, reporter) = app(dir.path());
        let files = get(&format!("/dlaudio/files/999/{TOKEN}"));
        for _ in 0..400 {
            let reply = app.respond(&files);
            assert_eq!(reply.status, 410);
            assert_eq!(reply.header("vary"), Some("Cookie"));
        }
        let counted: i64 = reporter
            .counters()
            .drain()
            .into_iter()
            .filter(|(name, _, _)| name == "requests_total")
            .map(|(_, _, n)| n)
            .sum();
        assert_eq!(counted, 400);
    }

    /// ファイルは中身を送らず、nginx の内側の場所を指し、名前の書き方が starlette の FileResponse と同じこと。
    #[test]
    fn files_are_handed_to_nginx() {
        let dir = tempfile::tempdir().unwrap();
        let (app, _) = app(dir.path());
        std::fs::write(
            dir.path().join(format!("{TOKEN}.json")),
            r#"{"guild_id": "999", "filename": "曲 A.ogg", "extension": ".ogg", "expires_at": 1800000600}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(format!("{TOKEN}.ogg")), b"OggS").unwrap();
        let reply = app.respond(&get(&format!("/dlaudio/files/999/{TOKEN}")));
        assert_eq!(reply.status, 200);
        assert!(reply.body.is_empty());
        assert_eq!(
            reply.header("x-accel-redirect"),
            Some(format!("{ACCEL_PREFIX}{TOKEN}.ogg").as_str())
        );
        assert_eq!(reply.header("content-type"), Some("audio/ogg"));
        assert_eq!(
            reply.header("content-disposition"),
            Some("attachment; filename*=utf-8''%E6%9B%B2%20A.ogg")
        );
        assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    }

    /// ダウンロードの名前の作り方が Python と同じこと（記号を落とし、拡張子を足し、空なら印の名前、並びは中身を回す）。
    #[test]
    fn download_names_are_made_like_python() {
        let name = |raw: Value| download_name(Some(&raw), TOKEN, ".mp3");
        assert_eq!(
            name(json!("曲名【公式】 (MV).mp3")).unwrap(),
            "曲名公式 MV.mp3"
        );
        assert_eq!(name(json!("abc")).unwrap(), "abc.mp3");
        assert_eq!(name(json!("???")).unwrap(), format!("{TOKEN}.mp3"));
        assert_eq!(name(json!(["ab", " ", "c?", ".mp3"])).unwrap(), "ab.mp3");
        assert_eq!(name(json!({"x y": 1, "zz": 2})).unwrap(), "zz.mp3");
        assert_eq!(name(json!(null)).unwrap_err().kind, "TypeError");
        assert_eq!(name(json!([1])).unwrap_err().kind, "AttributeError");
        assert_eq!(
            download_name(None, TOKEN, ".zip").unwrap(),
            format!("{TOKEN}.zip")
        );
    }
}
