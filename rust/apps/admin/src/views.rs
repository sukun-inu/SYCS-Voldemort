//! ログイン・サーバー選択・シェルの画面と、公開ページ。Python の `views/auth_views.py`（ログイン・Discord の認可・
//! 戻り・ログアウト）・`views/dashboard_views.py`（`/admin/`・サーバー選択・シェル）・`app.py` の
//! `_register_public_pages`（`/`・`/guide`・`/privacy`・`/terms`・旧 URL の 301 の 3 本）の写し。
//!
//! | 経路 | 確かめ | 答え |
//! |---|---|---|
//! | GET /admin/login（1 分 30 回） | — | ログイン中なら 303（サーバーを選んでいれば /admin/overview、無ければ /admin/guilds）。でなければ `login.html` |
//! | GET /admin/auth（1 分 10 回） | — | `state` をセッションへ → 303 Discord の認可画面 |
//! | GET /admin/callback（1 分 10 回） | — | 確かめてセッションを作り直し → 303 /admin/guilds。どこで失敗しても知らせを積んで 303 /admin/login |
//! | POST /admin/logout | CSRF | セッションを空にして知らせ → 303 /admin/login |
//! | GET /admin/logout | — | 未ログインなら 303 /admin/login。でなければ `logout_confirm.html` |
//! | GET /admin/ | ログイン | 303 /admin/guilds か /admin/overview |
//! | GET /admin/guilds | ログイン | `guild_select.html`（セッションの `admin_guilds`） |
//! | POST /admin/guilds/select | ログイン・CSRF | 一覧に無ければ 303 /admin/guilds。古ければ Discord で確かめ直す → 303 /admin/overview |
//! | GET /admin/overview | サーバー | `shell.html` |
//! | GET / | — | `landing.html`（招待リンク、Bot のサーバー数〔5 分使い回す〕） |
//! | GET /guide・/privacy・/terms | — | それぞれのページ（招待リンク） |
//! | GET /admin/guide・/admin/privacy・/admin/terms | — | 301 → /guide・/privacy・/terms |
//!
//! ルーターの中の経路（`/admin/…`）は既定の回数の制限が掛からず（[`Route::new`]）、公開ページは app に直に足した
//! 経路なので掛かる（[`Route::top_level`]）。デコレータの制限（ログイン・認可・戻り）は、係の最初に数える
//! （確かめが無いので）。基準は `tests/fixtures/auth/`（偽物の Discord に当てた本物の Python の答え）と
//! `tests/fixtures/templates/` の経路の例。

use std::future::Future;
use std::sync::Arc;

use axum::http::Method;
use serde_json::Value;
use tracing::warn;

use crate::app::{AdminApp, Handler, Reply, Req, handler};
use crate::auth::{self, Discord, GuildCount, StoredGuildCount};
use crate::errors::{Crash, Failure};
use crate::python;
use crate::routing::Route;
use crate::security;
use crate::session::{Session, constant_time_eq};
use crate::templates::{self, Page, Pages, Visit};

/// `/admin/login` の 1 分あたりの上限（`@limiter.limit("30/minute")`）。
pub const LOGIN_PER_MINUTE: u32 = 30;
/// `/admin/auth` の 1 分あたりの上限。
pub const OAUTH_START_PER_MINUTE: u32 = 10;
/// `/admin/callback` の 1 分あたりの上限。
pub const CALLBACK_PER_MINUTE: u32 = 10;

/// 戻りで `error` が来たとき。
pub const CANCELLED: &str = "Discord 認証がキャンセルされました。";
/// `state` が合わないとき。
pub const STATE_MISMATCH: &str = "不正なリクエストです（state 不一致）。";
/// `code` が無いとき。
pub const NO_CODE: &str = "認証コードが取得できませんでした。";
/// トークンに換えられなかったとき。
pub const AUTH_FAILED: &str = "Discord 認証に失敗しました。";
/// 本人の情報を取れなかったとき。
pub const USER_INFO_FAILED: &str = "ユーザー情報の取得に失敗しました。";
/// 管理できるサーバーが無いとき（warning）。
pub const NO_ADMIN_GUILDS: &str = "管理者権限を持つサーバーが見つかりませんでした。Bot が参加しているサーバーで管理者権限が必要です。";
/// ログアウトしたとき（info）。
pub const LOGGED_OUT: &str = "ログアウトしました。";
/// 選んだサーバーの ID が整数でないとき。
pub const INVALID_GUILD_ID: &str = "無効なサーバーIDです。";
/// 選んだサーバーが一覧に無いとき。
pub const NOT_IN_LIST: &str = "アクセス権限がありません。";
/// 確かめ直したら管理者でなくなっていたとき。
pub const NO_LONGER_ADMIN: &str = "このサーバーの管理者権限がなくなっています。";

const LOGIN: &str = "/admin/login";
const GUILDS: &str = "/admin/guilds";
const OVERVIEW: &str = "/admin/overview";

/// 認可の `state` を作るもの（Python の `secrets.token_urlsafe(32)`）。テストでは決まった並びにする。
pub type StateToken = Arc<dyn Fn() -> String + Send + Sync>;

/// `secrets.token_urlsafe(32)`（OS の乱数 32 バイトを URL 用の base64 にして `=` を落とした 43 文字）。
pub fn os_state_token() -> StateToken {
    Arc::new(|| {
        let mut bytes = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut bytes) {
            panic!("OS の乱数を取れません: {e}");
        }
        python::b64encode(&bytes, true, false)
    })
}

/// 設定のあるサーバーの数を、まだ読めないとき（設定の置き場は A5 でつなぐ）。Bot のサーバー数が 0 か失敗のときに
/// 警告を残して 0 になる（Python は設定のあるサーバーの数を出す）。
pub fn stored_guilds_not_connected() -> StoredGuildCount {
    Arc::new(|| Err("設定の置き場にまだつないでいない（A5 でつなぐ）".to_string()))
}

/// この画面たちが使うもの（テンプレート・Discord・サーバー数の使い回し・`state` の作り方）。経路の係が持ち回る。
pub struct Site {
    pages: Arc<Pages>,
    discord: Arc<Discord>,
    guild_count: GuildCount,
    state_token: StateToken,
}

impl std::fmt::Debug for Site {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Site")
            .field("discord", &self.discord)
            .field("guild_count", &self.guild_count)
            .finish_non_exhaustive()
    }
}

impl Site {
    /// 作る。`stored` は設定のあるサーバーの数（[`GuildCount`]）。
    pub fn new(
        pages: Arc<Pages>,
        discord: Arc<Discord>,
        stored: StoredGuildCount,
        state_token: StateToken,
    ) -> Self {
        Self {
            pages,
            discord,
            guild_count: GuildCount::new(stored),
            state_token,
        }
    }

    /// テンプレート。
    pub fn pages(&self) -> &Arc<Pages> {
        &self.pages
    }

    /// Discord。
    pub fn discord(&self) -> &Arc<Discord> {
        &self.discord
    }

    /// 「Bot を招待」のリンク（`_build_invite_url`・`_invite_url`。`DISCORD_CLIENT_ID` が空なら無い）。
    pub fn invite_url(&self) -> Option<String> {
        templates::invite_url(&self.discord.config().client_id)
    }
}

/// 経路の係に [`Site`] を持たせる。
fn with_site<F, Fut>(site: &Arc<Site>, f: F) -> Handler
where
    F: Fn(Arc<AdminApp>, Req, Arc<Site>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Reply, Failure>> + Send + 'static,
{
    let site = Arc::clone(site);
    handler(move |app: Arc<AdminApp>, req: Req| f(app, req, Arc::clone(&site)))
}

/// `views/auth_views.py` の経路（`/admin` の下。Python の登録の順。`/admin/logout` は POST が先なので、ほかの
/// メソッドの 405 の `Allow` は `POST`）。
pub fn auth_routes(site: &Arc<Site>) -> Vec<Route> {
    let get = [Method::GET];
    vec![
        Route::new("/admin/login", &get, with_site(site, login)),
        Route::new("/admin/auth", &get, with_site(site, oauth_start)),
        Route::new("/admin/callback", &get, with_site(site, callback)),
        Route::new("/admin/logout", &[Method::POST], with_site(site, logout)),
        Route::new("/admin/logout", &get, with_site(site, logout_confirm)),
    ]
}

/// `views/dashboard_views.py` の経路（`/admin` の下）。`/admin/api/metrics`・`/admin/api/incidents` は A7 が
/// この後ろに足す。
pub fn dashboard_routes(site: &Arc<Site>) -> Vec<Route> {
    let get = [Method::GET];
    vec![
        Route::new("/admin/", &get, with_site(site, admin_root)),
        Route::new("/admin/guilds", &get, with_site(site, guild_select)),
        Route::new(
            "/admin/guilds/select",
            &[Method::POST],
            with_site(site, select_guild),
        ),
        Route::new("/admin/overview", &get, with_site(site, overview)),
    ]
}

/// `_register_public_pages` の経路（app に直に足したもの。既定の 1 分 300 回が掛かる）。
pub fn public_routes(site: &Arc<Site>) -> Vec<Route> {
    let get = [Method::GET];
    let mut routes = vec![Route::top_level("/", &get, with_site(site, landing))];
    for (path, page) in [
        ("/guide", Page::Guide),
        ("/privacy", Page::Privacy),
        ("/terms", Page::Terms),
    ] {
        routes.push(Route::top_level(
            path,
            &get,
            with_site(
                site,
                move |app: Arc<AdminApp>, req: Req, site: Arc<Site>| document(app, req, site, page),
            ),
        ));
    }
    for (old, new) in templates::LEGACY_PUBLIC_REDIRECTS {
        routes.push(Route::top_level(
            old,
            &get,
            handler(move |_app: Arc<AdminApp>, _req: Req| async move {
                Ok::<Reply, Failure>(Reply::redirect(301, new))
            }),
        ));
    }
    routes
}

/// starlette の `request.query_params.get(name)`（`parse_qsl(…, keep_blank_values=True)`。同じ名前は最後の値）。
pub fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let mut found = None;
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if python::form_unquote(key.as_bytes()) == name {
            found = Some(python::form_unquote(value.as_bytes()));
        }
    }
    found
}

/// `templating.flash`（`_flashes` が一覧でなければ Python は `append` で `AttributeError`）。
fn flash(session: &mut Session, message: &str, category: &str) -> Result<(), Failure> {
    let kind = session.get("_flashes").map(python::type_name);
    templates::flash(session, message, category).map_err(|_| {
        Crash::new(
            "AttributeError",
            format!(
                "'{}' object has no attribute 'append'",
                kind.unwrap_or("NoneType")
            ),
        )
        .into()
    })
}

/// 知らせを積んで 303 で送る。
fn flash_redirect(req: &Req, message: &str, category: &str, to: &str) -> Result<Reply, Failure> {
    req.session
        .with(|session| flash(session, message, category))?;
    Ok(Reply::redirect(303, to))
}

/// `templating.render` で描いて 200 の HTML にする（知らせを取り出し、CSRF の印が無ければ入れる）。
fn render(
    app: &AdminApp,
    req: &Req,
    draw: impl FnOnce(&mut Visit<'_>) -> Result<String, minijinja::Error>,
) -> Result<Reply, Failure> {
    let is_embedded = templates::is_embedded(req.header("sec-fetch-dest").as_deref());
    let drawn = req.session.with(|session| {
        let mut token = || app.random().token_hex(32);
        let mut visit = Visit {
            session,
            is_embedded,
            new_csrf_token: &mut token,
        };
        draw(&mut visit)
    });
    match drawn {
        Ok(body) => Ok(Reply::html(200, body)),
        Err(e) => Err(Crash::new("TemplateError", e.to_string()).into()),
    }
}

/// 時刻を JSON の小数にする（`time.time()` をセッションに入れる）。
fn float_value(x: f64) -> Value {
    serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number)
}

/// GET /admin/login（`login`）。
async fn login(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    app.check_route_limit(&req, LOGIN_PER_MINUTE)?;
    let target = req.session.with(|session| {
        session.contains_key("user").then(|| {
            if session.contains_key("guild_id") {
                OVERVIEW
            } else {
                GUILDS
            }
        })
    });
    if let Some(target) = target {
        return Ok(Reply::redirect(303, target));
    }
    let invite = site.invite_url();
    render(&app, &req, |visit| {
        site.pages.login(visit, invite.as_deref())
    })
}

/// GET /admin/auth（`oauth_start`）。`state` をセッションに入れて、Discord の認可画面へ。
async fn oauth_start(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    app.check_route_limit(&req, OAUTH_START_PER_MINUTE)?;
    let state = (site.state_token)();
    req.session
        .with(|session| session.insert("oauth_state", Value::String(state.clone())));
    Ok(Reply::redirect(303, &site.discord.oauth_url(&state)))
}

/// `secrets.compare_digest(state, expected)`（文字どうしは ASCII だけ。違う型や ASCII でない文字は `TypeError`）。
fn compare_digest(state: &str, expected: &Value) -> Result<bool, Crash> {
    let Value::String(expected) = expected else {
        return Err(Crash::new(
            "TypeError",
            format!(
                "unsupported operand types(s) or combination of types: 'str' and '{}'",
                python::type_name(expected)
            ),
        ));
    };
    if !state.is_ascii() || !expected.is_ascii() {
        return Err(Crash::new(
            "TypeError",
            "comparing strings with non-ASCII characters is not supported",
        ));
    }
    Ok(constant_time_eq(state.as_bytes(), expected.as_bytes()))
}

/// `if not token_data or "access_token" not in token_data` を通ったら `token_data["access_token"]`。通らなければ
/// `None`。`in` と添字は Python の型ごとの動き（文字は部分の文字、並びは要素で探し、見つかっても添字で `TypeError`）。
fn access_token_of(token_data: &Value) -> Result<Option<Value>, Crash> {
    if !python::truthy(token_data) {
        return Ok(None);
    }
    let found = match token_data {
        Value::Object(map) => map.contains_key("access_token"),
        Value::Array(items) => items.iter().any(|item| item == "access_token"),
        Value::String(text) => text.contains("access_token"),
        other => {
            return Err(Crash::new(
                "TypeError",
                format!(
                    "argument of type '{}' is not iterable",
                    python::type_name(other)
                ),
            ));
        }
    };
    if !found {
        return Ok(None);
    }
    auth::py_subscript(token_data, "access_token").map(Some)
}

/// セッションの `user`（`{"id": user_info["id"], "username": …, "global_name": …, "avatar": …}`）。
fn user_record(user_info: &Value) -> Result<Value, Crash> {
    let id = auth::py_subscript(user_info, "id")?;
    let fields = auth::py_dict(user_info)?;
    let field = |key: &str, default: Value| fields.get(key).cloned().unwrap_or(default);
    Ok(python::object(vec![
        ("id", id),
        ("username", field("username", Value::String(String::new()))),
        ("global_name", field("global_name", Value::Null)),
        ("avatar", field("avatar", Value::Null)),
    ]))
}

/// GET /admin/callback（`callback`）。Discord からの戻り。
async fn callback(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    app.check_route_limit(&req, CALLBACK_PER_MINUTE)?;
    let query = req.query.as_deref();
    if query_param(query, "error").is_some_and(|error| !error.is_empty()) {
        return flash_redirect(&req, CANCELLED, "danger", LOGIN);
    }
    let state = query_param(query, "state").unwrap_or_default();
    let expected = req.session.with(|session| session.pop("oauth_state"));
    let matched = match expected {
        Some(expected) if python::truthy(&expected) => compare_digest(&state, &expected)?,
        _ => false,
    };
    if !matched {
        return flash_redirect(&req, STATE_MISMATCH, "danger", LOGIN);
    }
    let code = query_param(query, "code").unwrap_or_default();
    if code.is_empty() {
        return flash_redirect(&req, NO_CODE, "danger", LOGIN);
    }
    let token_data = site.discord.exchange_code(&code).await;
    let Some(access_token) = access_token_of(&token_data)? else {
        return flash_redirect(&req, AUTH_FAILED, "danger", LOGIN);
    };
    let user_info = site.discord.user_info(&access_token).await;
    if !python::truthy(&user_info) {
        return flash_redirect(&req, USER_INFO_FAILED, "danger", LOGIN);
    }
    let admin_guilds = site.discord.admin_guilds(&access_token).await?;
    if admin_guilds.is_empty() {
        return flash_redirect(&req, NO_ADMIN_GUILDS, "warning", LOGIN);
    }
    req.session.with(|session| -> Result<(), Failure> {
        // 認証の途中の値（oauth_state など）を持ち越さないよう、空にしてから入れる。
        session.clear();
        let user = user_record(&user_info)?;
        session.insert("user", user);
        session.insert("admin_guilds", Value::Array(admin_guilds));
        session.insert("admin_guilds_at", float_value(app.now()));
        // ログインの確定と同時に CSRF の印を作る（空にしたので必ず新しい印）。
        security::issue_csrf_token(session, || app.random().token_hex(32));
        Ok(())
    })?;
    Ok(Reply::redirect(303, GUILDS))
}

/// POST /admin/logout（`logout`）。CSRF を確かめ、セッションを空にして知らせを積む（未ログインでも同じ）。
async fn logout(app: Arc<AdminApp>, req: Req, _site: Arc<Site>) -> Result<Reply, Failure> {
    app.check_csrf(&req)?;
    req.session.with(|session| {
        session.clear();
        flash(session, LOGGED_OUT, "info")
    })?;
    Ok(Reply::redirect(303, LOGIN))
}

/// GET /admin/logout（`logout_get`）。GET では実行せず、確認のページを出す。
async fn logout_confirm(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    if !req.session.with(|session| session.contains_key("user")) {
        return Ok(Reply::redirect(303, LOGIN));
    }
    render(&app, &req, |visit| site.pages.logout_confirm(visit))
}

/// GET /admin/（`admin_root`）。
async fn admin_root(_app: Arc<AdminApp>, req: Req, _site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_login()?;
    let chosen = req.session.with(|session| session.contains_key("guild_id"));
    Ok(Reply::redirect(303, if chosen { OVERVIEW } else { GUILDS }))
}

/// GET /admin/guilds（`guild_select`）。一覧はログインのときにセッションへ入れたもの（Discord には聞き直さない）。
async fn guild_select(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_login()?;
    render(&app, &req, |visit| site.pages.guild_select(visit))
}

/// GET /admin/overview（`overview`）。
async fn overview(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    render(&app, &req, |visit| site.pages.shell(visit))
}

/// `{int(g["id"]) for g in admin_guilds}` の並び（要素の順。読めなければ Python と同じ例外）。
fn guild_ids(admin_guilds: &Value) -> Result<Vec<String>, Crash> {
    auth::py_iter(admin_guilds)?
        .iter()
        .map(|guild| auth::py_int(&auth::py_subscript(guild, "id")?))
        .collect()
}

/// `float(session.get("admin_guilds_at") or 0)`。
///
/// Python と違うところ: 文字は Rust の小数の読み方（`1_0` や全角の数字は読めない）。セッションには Python も Rust も
/// 小数で入れるので、文字が来るのは秘密鍵を知っている人が作った Cookie だけ。
fn checked_at(value: Option<&Value>) -> Result<f64, Crash> {
    match value.filter(|value| python::truthy(value)) {
        None => Ok(0.0),
        Some(Value::Number(number)) => Ok(number.as_f64().unwrap_or(0.0)),
        Some(Value::Bool(_)) => Ok(1.0),
        Some(Value::String(text)) => python::strip(text).parse::<f64>().map_err(|_| {
            Crash::new(
                "ValueError",
                format!(
                    "could not convert string to float: {}",
                    python::repr(&Value::String(text.clone()))
                ),
            )
        }),
        Some(other) => Err(Crash::new(
            "TypeError",
            format!(
                "float() argument must be a string or a real number, not '{}'",
                python::type_name(other)
            ),
        )),
    }
}

/// `int((session.get("user") or {}).get("id", 0))`。
fn session_user_id(user: Option<&Value>) -> Result<String, Crash> {
    match user.filter(|user| python::truthy(user)) {
        None => Ok("0".to_string()),
        Some(user) => match auth::py_dict(user)?.get("id") {
            None => Ok("0".to_string()),
            Some(id) => auth::py_int(id),
        },
    }
}

/// セッションに入れる `guild_id`（Python の整数）。
///
/// Python と違うところ: 64 ビットに収まらない ID は入れられない（Python は桁を全部持つ）。一覧の ID は Discord の
/// ID なので収まる。収まらないのは秘密鍵を知っている人が作った Cookie だけ。
fn guild_id_value(guild_id: &str) -> Result<Value, Crash> {
    if let Ok(id) = guild_id.parse::<i64>() {
        return Ok(Value::from(id));
    }
    guild_id.parse::<u64>().map(Value::from).map_err(|_| {
        Crash::new(
            "OverflowError",
            format!("サーバーの ID {guild_id} が 64 ビットに収まらない"),
        )
    })
}

/// POST /admin/guilds/select（`select_guild`）。選んだサーバーをセッションに入れる。
///
/// 一覧を取った時刻が `ADMIN_GUILDS_MAX_AGE_SECONDS` より古ければ、いまも管理者かを Discord に聞き直す
/// （違えば一覧から外して /admin/guilds へ。分からなければそのまま通す。管理者なら取った時刻を今にする）。
async fn select_guild(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_login()?;
    app.check_csrf(&req)?;
    let form = security::read_form(&req.headers, &req.body)?;
    let raw = form.get("guild_id").unwrap_or_default();
    let Some(guild_id) = python::int_text(&Value::String(raw.to_string())) else {
        return flash_redirect(&req, INVALID_GUILD_ID, "danger", GUILDS);
    };
    let admin_guilds = req
        .session
        .with(|session| session.get("admin_guilds").cloned())
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let ids = guild_ids(&admin_guilds)?;
    if !ids.contains(&guild_id) {
        return flash_redirect(&req, NOT_IN_LIST, "danger", GUILDS);
    }
    let guilds = auth::py_iter(&admin_guilds)?;
    let checked = req
        .session
        .with(|session| checked_at(session.get("admin_guilds_at")))?;
    let max_age = site.discord.config().guilds_max_age as f64;
    if app.now() - checked > max_age {
        let user_id = req
            .session
            .with(|session| session_user_id(session.get("user")))?;
        match site.discord.user_still_admin(&guild_id, &user_id).await? {
            Some(false) => {
                let kept: Vec<Value> = guilds
                    .iter()
                    .zip(&ids)
                    .filter(|(_, id)| **id != guild_id)
                    .map(|(guild, _)| guild.clone())
                    .collect();
                req.session.with(|session| {
                    session.insert("admin_guilds", Value::Array(kept));
                    session.pop("guild_id");
                    flash(session, NO_LONGER_ADMIN, "danger")
                })?;
                return Ok(Reply::redirect(303, GUILDS));
            }
            Some(true) => {
                let now = app.now();
                req.session
                    .with(|session| session.insert("admin_guilds_at", float_value(now)));
            }
            None => {}
        }
    }
    let chosen = guild_id_value(&guild_id)?;
    req.session.with(|session| {
        session.insert("guild_id", chosen);
        let found = guilds.iter().zip(&ids).find(|(_, id)| **id == guild_id);
        if let Some((Value::Object(guild), _)) = found {
            let name = guild
                .get("name")
                .cloned()
                .unwrap_or_else(|| Value::String("Unknown".to_string()));
            let icon = guild.get("icon").cloned().unwrap_or(Value::Null);
            session.insert("guild_name", name);
            session.insert("guild_icon", icon);
        }
    });
    Ok(Reply::redirect(303, OVERVIEW))
}

/// GET /（`landing`）。Bot のサーバー数は [`GuildCount`]（5 分使い回す）。
async fn landing(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    let invite = site.invite_url();
    let count = site.guild_count.get(&site.discord, || app.now()).await;
    let count = i64::try_from(count).unwrap_or_else(|_| {
        warn!("Bot のサーバー数 {count} が大きすぎる");
        i64::MAX
    });
    render(&app, &req, |visit| {
        site.pages.landing(visit, invite.as_deref(), count)
    })
}

/// GET /guide・/privacy・/terms（`guide`・`privacy`・`terms`）。
async fn document(
    app: Arc<AdminApp>,
    req: Req,
    site: Arc<Site>,
    page: Page,
) -> Result<Reply, Failure> {
    let invite = site.invite_url();
    render(&app, &req, |visit| {
        site.pages.document(page, visit, invite.as_deref())
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;
    use crate::auth::DiscordConfig;
    use crate::templates::PagesConfig;

    /// 単体テスト用の [`Site`]（リポジトリのテンプレート、つながらない Discord、決まった `state`）。
    pub(crate) fn test_site() -> Arc<Site> {
        let config = PagesConfig {
            templates_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../webapp_admin/templates"),
            static_dir: PathBuf::from("/nonexistent-sycs-admin-static/static"),
            asset_version: "admin".to_string(),
        };
        let pages = Arc::new(Pages::load(&config).unwrap());
        let discord = Discord::new(
            DiscordConfig::from_lookup(|_| None),
            "http://127.0.0.1:9/api/v10",
        )
        .unwrap();
        Arc::new(Site::new(
            pages,
            Arc::new(discord),
            Arc::new(|| Ok(0)),
            Arc::new(|| "state".to_string()),
        ))
    }

    /// 問い合わせの読み方が starlette と同じこと（同じ名前は最後、= の無いものは空、+ と %XX を戻す）。
    #[test]
    fn query_params_are_read_like_starlette() {
        let query = Some("state=a&code=x+y%21&state=b&error&&e=%E3%81%82");
        assert_eq!(query_param(query, "state").as_deref(), Some("b"));
        assert_eq!(query_param(query, "code").as_deref(), Some("x y!"));
        assert_eq!(query_param(query, "error").as_deref(), Some(""));
        assert_eq!(query_param(query, "e").as_deref(), Some("あ"));
        assert_eq!(query_param(query, "missing"), None);
        assert_eq!(query_param(None, "state"), None);
    }

    /// state の比べ方（型の違いと ASCII でない文字は TypeError）。
    #[test]
    fn states_are_compared_like_compare_digest() {
        assert_eq!(compare_digest("abc", &json!("abc")), Ok(true));
        assert_eq!(compare_digest("abd", &json!("abc")), Ok(false));
        assert_eq!(compare_digest("", &json!("abc")), Ok(false));
        assert_eq!(
            compare_digest("é", &json!("abc")).unwrap_err().kind,
            "TypeError"
        );
        assert_eq!(
            compare_digest("a", &json!(5)).unwrap_err().message,
            "unsupported operand types(s) or combination of types: 'str' and 'int'"
        );
    }

    /// トークンの取り出し方（偽・鍵の無い辞書は失敗、文字と並びは見つかっても添字で TypeError）。
    #[test]
    fn access_tokens_are_taken_like_python() {
        assert_eq!(access_token_of(&Value::Null), Ok(None));
        assert_eq!(access_token_of(&json!({})), Ok(None));
        assert_eq!(access_token_of(&json!({"error": "x"})), Ok(None));
        assert_eq!(
            access_token_of(&json!({"access_token": 5})),
            Ok(Some(json!(5)))
        );
        assert_eq!(access_token_of(&json!(["a"])), Ok(None));
        assert_eq!(
            access_token_of(&json!(["access_token"]))
                .unwrap_err()
                .message,
            "list indices must be integers or slices, not str"
        );
        assert_eq!(
            access_token_of(&json!("my access_token"))
                .unwrap_err()
                .message,
            "string indices must be integers, not 'str'"
        );
        assert_eq!(
            access_token_of(&json!(1)).unwrap_err().message,
            "argument of type 'int' is not iterable"
        );
    }

    /// セッションの user の作り方（無い鍵は空の文字か null。id が無ければ KeyError）。
    #[test]
    fn the_user_record_is_built_like_python() {
        assert_eq!(
            user_record(&json!({"id": 1, "avatar": "a", "x": 2})),
            Ok(json!({"id": 1, "username": "", "global_name": null, "avatar": "a"}))
        );
        assert_eq!(
            user_record(&json!({"username": "x"})),
            Err(Crash::new("KeyError", "'id'"))
        );
    }

    /// 取った時刻と利用者の ID の読み方（偽は 0、真偽は 1、読めないものは Python と同じ例外）。
    #[test]
    fn session_values_are_read_like_python() {
        assert_eq!(checked_at(None), Ok(0.0));
        assert_eq!(checked_at(Some(&json!(""))), Ok(0.0));
        assert_eq!(checked_at(Some(&json!(true))), Ok(1.0));
        assert_eq!(checked_at(Some(&json!(" 12.5 "))), Ok(12.5));
        assert_eq!(checked_at(Some(&json!([1]))).unwrap_err().kind, "TypeError");
        assert_eq!(
            checked_at(Some(&json!("x"))).unwrap_err().kind,
            "ValueError"
        );
        assert_eq!(session_user_id(None), Ok("0".to_string()));
        assert_eq!(session_user_id(Some(&json!({}))), Ok("0".to_string()));
        assert_eq!(
            session_user_id(Some(&json!({"name": "a"}))),
            Ok("0".to_string())
        );
        assert_eq!(
            session_user_id(Some(&json!({"id": " 7 "}))),
            Ok("7".to_string())
        );
        assert_eq!(
            session_user_id(Some(&json!("x"))).unwrap_err().kind,
            "AttributeError"
        );
        assert_eq!(guild_id_value("-5"), Ok(json!(-5)));
        assert_eq!(guild_id_value("18446744073709551615"), Ok(json!(u64::MAX)));
        assert!(guild_id_value("18446744073709551616").is_err());
    }

    /// 経路の数と並び（auth_views の 5 本・dashboard_views の 4 本・公開ページの 7 本）。
    #[test]
    fn the_routes_are_listed_in_python_order() {
        let site = test_site();
        let paths = |routes: Vec<Route>| -> Vec<String> {
            routes
                .iter()
                .map(|route| format!("{} {}", route.allow(), route.template()))
                .collect()
        };
        assert_eq!(
            paths(auth_routes(&site)),
            [
                "GET /admin/login",
                "GET /admin/auth",
                "GET /admin/callback",
                "POST /admin/logout",
                "GET /admin/logout"
            ]
        );
        assert_eq!(
            paths(dashboard_routes(&site)),
            [
                "GET /admin/",
                "GET /admin/guilds",
                "POST /admin/guilds/select",
                "GET /admin/overview"
            ]
        );
        let public = public_routes(&site);
        assert!(public.iter().all(Route::default_limit));
        assert!(
            auth_routes(&site)
                .iter()
                .all(|route| !route.default_limit())
        );
        assert_eq!(
            paths(public),
            [
                "GET /",
                "GET /guide",
                "GET /privacy",
                "GET /terms",
                "GET /admin/guide",
                "GET /admin/privacy",
                "GET /admin/terms"
            ]
        );
    }

    /// state は 43 文字の URL 用の base64（`token_urlsafe(32)`）。
    #[test]
    fn os_states_look_like_token_urlsafe() {
        let state = os_state_token()();
        assert_eq!(state.len(), 43);
        assert!(
            state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(state, os_state_token()());
    }
}
