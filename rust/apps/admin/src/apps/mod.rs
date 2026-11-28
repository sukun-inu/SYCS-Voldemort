//! 設定パネル（rust-06 の A5 の読む側と A6 の書く側）。Python の `webapp_admin/api/apps.py` と、宣言
//! （`webapp_admin/schema/`）から作る答え。
//!
//! | 経路 | 確かめ | 答え |
//! |---|---|---|
//! | GET /admin/api/apps | サーバー | `{"groups": [{"label", "apps": [タイル…]}…]}`（`PANELS` の並びのままグループ分け。開発者でなければ dev_only を隠す。バッジは数え、0 か失敗なら null） |
//! | GET /admin/api/apps/{app_id} | サーバー | 無い・開発者専用（開発者でない）は 404。custom は宣言だけ。ほかは宣言 ＋ `choices`・`values`・`collections`（1 項目の失敗は既定値か空で埋めて `errors`） |
//! | PUT /admin/api/apps/{app_id} | サーバー・CSRF | 変えた項目だけを検証して書く（A6。[`write`]） |
//! | POST・PUT・DELETE /admin/api/apps/{app_id}/collections/{key}… | サーバー・CSRF | 一覧の 1 件を足す・変える・消す（A6） |
//! | DELETE /admin/api/guild-data | サーバー・CSRF | サーバーのデータを全部消す（A6。[`guild_data`]） |
//!
//! どれもルーターの中の経路（既定の回数の制限は掛からない）で、答えは `SafeJSONResponse`（2^53-1 を超える整数は文字。
//! [`crate::jsonsafe`]）。サーバーの ID は `int(session["guild_id"])`（読めなければ Python と同じ例外で 500）。
//! custom のパネルは ID を読まない（壊れた ID でも 200）。
//!
//! - [`schema`] 宣言（`schema.json` を焼き込む）・`to_json_value`
//! - [`getters`] 値を読む関数（Python の関数の名前で引く）
//! - [`choices`] 選択肢（チャンネル・ロール・声）
//! - [`voices`] 読み上げの声の一覧（TTS の API）
//! - [`store`] 設定の置き場（Postgres。Bot と同じ `sycs_core::settings`。書けば Bot に知らせが届く）
//! - [`validation`] 入力の検証（A6）
//! - [`setters`] 値を書く関数（Python の関数の名前で引く。A6）
//! - [`write`] 書く側の経路（A6）
//! - [`guild_data`] サーバーのデータの削除（設定と利用者の状態。A6）
//!
//! 公開トップの Bot のサーバー数が 0 か失敗のときのフォールバック（設定のあるサーバーの数）も、ここの置き場から数える
//! （[`stored_guild_count`]。A3 の `GuildCount` に渡す）。
//!
//! 基準は `tests/fixtures/apps_read/`（偽物の Discord・TTS に当てた本物の Python の答え）・`tests/fixtures/getters/`
//! （設定の JSON → 読む関数の答え）・`tests/fixtures/validation/`（入力欄 × 入力 → 検証の答え）・
//! `tests/fixtures/apps_write/`（本物の Python に書く要求を送った答えと、書いたあとの設定）。

pub mod choices;
pub mod getters;
pub mod guild_data;
pub mod schema;
pub mod setters;
pub mod store;
pub mod validation;
pub mod voices;
pub mod write;

use std::future::Future;
use std::sync::Arc;

use axum::http::Method;
use serde_json::{Map, Value, json};
use sycs_core::env::Env;
use sycs_core::settings::Settings;
use tracing::error;

use crate::app::{AdminApp, Handler, Reply, Req, handler};
use crate::auth::{self, StoredGuildCount};
use crate::errors::{Crash, Failure, HttpError};
use crate::jsonsafe;
use crate::python;
use crate::routing::Route;
use crate::security;
use crate::views::Site;

use choices::Choices;
use getters::{Ctx, DjaudioDefaults};
use guild_data::UserStateEraser;
use schema::Panel;
use store::SettingsStore;
use voices::Voices;

/// 設定パネルが使うもの（設定の置き場・選択肢・DJAudio の環境変数・利用者の状態を消すもの）。[`Site`] が持ち回る。
pub struct Panels {
    settings: Arc<SettingsStore>,
    choices: Choices,
    djaudio: DjaudioDefaults,
    user_states: Arc<dyn UserStateEraser>,
}

impl std::fmt::Debug for Panels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Panels")
            .field("settings", &self.settings)
            .field("choices", &self.choices)
            .field("djaudio", &self.djaudio)
            .finish_non_exhaustive()
    }
}

impl Panels {
    /// 作る（宣言と入力欄の規則をここで読む。壊れていれば起動で止まる）。利用者の状態を消すものはつないでいない
    /// （[`guild_data::Unconfigured`]。つなぐのは [`Panels::with_user_state_eraser`]）。
    pub fn new(settings: Arc<SettingsStore>, voices: Voices, djaudio: DjaudioDefaults) -> Self {
        let _ = schema::schema();
        let _ = validation::all_rules();
        Self {
            settings,
            choices: Choices::new(voices),
            djaudio,
            user_states: Arc::new(guild_data::Unconfigured),
        }
    }

    /// サーバーのデータの削除で、利用者の状態を消すもの（本番は [`guild_data::PgUserStateEraser`]。A6）を入れる。
    pub fn with_user_state_eraser(mut self, eraser: Arc<dyn UserStateEraser>) -> Self {
        self.user_states = eraser;
        self
    }

    /// 環境変数から作る（`TTS_BASE_URL`・`DJAUDIO_*`）。設定の置き場は [`store::from_env`] で作って渡す。
    pub fn from_env(env: &Env, settings: Arc<SettingsStore>) -> Result<Self, reqwest::Error> {
        Ok(Self::new(
            settings,
            Voices::from_env(env)?,
            DjaudioDefaults::from_env(env),
        ))
    }

    /// どこにもつないでいないもの（設定は読めず、声は空。`--self-check` と、設定パネルを使わないテスト）。
    pub fn unconfigured() -> Self {
        Self::new(
            Arc::new(SettingsStore::unconfigured()),
            Voices::disabled(),
            DjaudioDefaults::PYTHON,
        )
    }

    /// 設定の置き場。
    pub fn settings(&self) -> &Arc<SettingsStore> {
        &self.settings
    }

    fn ctx<'a>(
        &'a self,
        settings: &'a Result<Arc<Settings>, String>,
        guild_id: &'a str,
    ) -> Ctx<'a> {
        Ctx {
            settings,
            guild_id,
            djaudio: &self.djaudio,
        }
    }
}

/// 公開トップのサーバー数のフォールバック（`len(settings_store.get_all_guild_ids())`。待たずに数える）。
pub fn stored_guild_count(settings: &Arc<SettingsStore>) -> StoredGuildCount {
    let settings = Arc::clone(settings);
    Arc::new(move || {
        settings
            .try_snapshot()
            .map(|settings| store::guild_count(&settings))
    })
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

/// `api/apps.py` の経路（`/admin/api` の下。Python の登録の順: 読む側 2 本〔A5〕、書く側 5 本〔A6〕）。同じパスの
/// 経路は、405 の `Allow` が最初の経路のもの（`/admin/api/apps/{app_id}` に POST すれば `Allow: GET`）。
pub fn routes(site: &Arc<Site>) -> Vec<Route> {
    let get = [Method::GET];
    let item = "/admin/api/apps/{app_id}/collections/{key}/{item_id}";
    vec![
        Route::new("/admin/api/apps", &get, with_site(site, list_apps)),
        Route::new("/admin/api/apps/{app_id}", &get, with_site(site, get_app)),
        Route::new(
            "/admin/api/apps/{app_id}",
            &[Method::PUT],
            with_site(site, write::save_app),
        ),
        Route::new(
            "/admin/api/apps/{app_id}/collections/{key}",
            &[Method::POST],
            with_site(site, write::add_item),
        ),
        Route::new(item, &[Method::PUT], with_site(site, write::update_item)),
        Route::new(item, &[Method::DELETE], with_site(site, write::remove_item)),
        Route::new(
            "/admin/api/guild-data",
            &[Method::DELETE],
            with_site(site, write::delete_guild_data),
        ),
    ]
}

/// `int(request.session["guild_id"])`（`check_guild` を通ったあと。読めなければ Python と同じ型の例外）。
pub fn session_guild_id(req: &Req) -> Result<String, Crash> {
    req.session.with(|session| match session.get("guild_id") {
        Some(value) => auth::py_int(value),
        None => Err(Crash::new("KeyError", "'guild_id'")),
    })
}

/// `is_dev_user(request)`。
fn is_dev(app: &AdminApp, req: &Req) -> Result<bool, Crash> {
    req.session
        .with(|session| security::is_dev_user(session, &app.config().dev_user_id))
}

/// `Panel.tile(guild_id)`（バッジは `badge(guild_id) or None`。例外は None）。
fn tile(panel: &Panel, ctx: &Ctx<'_>) -> Value {
    let mut tile = panel.tile.clone();
    let badge = panel
        .badge
        .as_deref()
        .and_then(|name| getters::call(name, ctx).ok())
        .filter(python::truthy)
        .unwrap_or(Value::Null);
    tile.insert("badge".to_string(), badge);
    Value::Object(tile)
}

/// `registry.app_groups`（`visible_panels` の並びのまま、グループの初めて出た順）。
fn app_groups(ctx: &Ctx<'_>, is_dev: bool) -> Value {
    let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
    for panel in schema::schema()
        .panels
        .iter()
        .filter(|panel| is_dev || !panel.dev_only)
    {
        let tile = tile(panel, ctx);
        match groups.iter_mut().find(|(label, _)| *label == panel.group) {
            Some((_, apps)) => apps.push(tile),
            None => groups.push((panel.group.clone(), vec![tile])),
        }
    }
    Value::Array(
        groups
            .into_iter()
            .map(|(label, apps)| {
                python::object(vec![
                    ("label", Value::String(label)),
                    ("apps", Value::Array(apps)),
                ])
            })
            .collect(),
    )
}

/// `_read_values`（1 項目の失敗は既定値で埋め、`errors` に `str(exc)` を積む）。
fn read_values(panel: &Panel, ctx: &Ctx<'_>) -> (Map<String, Value>, Map<String, Value>) {
    let mut values = Map::new();
    let mut errors = Map::new();
    for field in &panel.fields {
        let read = match field.get.as_deref() {
            Some(name) => getters::call(name, ctx),
            None => Err(Crash::new("TypeError", "'NoneType' object is not callable")),
        };
        match read {
            Ok(value) => {
                let value = schema::to_json_value(field.widget, &field.default, &value);
                values.insert(field.key.clone(), value);
            }
            Err(crash) => {
                error!(
                    "設定値の読み取りに失敗 panel={} field={}: {}: {}",
                    panel.id, field.key, crash.kind, crash.message
                );
                values.insert(field.key.clone(), field.default.clone());
                errors.insert(field.key.clone(), Value::String(crash.message));
            }
        }
    }
    (values, errors)
}

/// `_read_collections`（1 つの失敗は空の並びで埋めて `errors` に積む）。
fn read_collections(panel: &Panel, ctx: &Ctx<'_>) -> (Map<String, Value>, Map<String, Value>) {
    let mut rows = Map::new();
    let mut errors = Map::new();
    for collection in &panel.collections {
        let read = match collection.list.as_deref() {
            Some(name) => getters::call(name, ctx),
            None => Err(Crash::new("TypeError", "'NoneType' object is not callable")),
        };
        match read {
            Ok(items) => {
                rows.insert(collection.key.clone(), items);
            }
            Err(crash) => {
                error!(
                    "一覧の読み取りに失敗 panel={} collection={}: {}: {}",
                    panel.id, collection.key, crash.kind, crash.message
                );
                rows.insert(collection.key.clone(), Value::Array(Vec::new()));
                errors.insert(collection.key.clone(), Value::String(crash.message));
            }
        }
    }
    (rows, errors)
}

/// GET /admin/api/apps（`list_apps`）。スタートメニューのタイルの一覧。
async fn list_apps(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    let guild_id = session_guild_id(&req)?;
    let is_dev = is_dev(&app, &req)?;
    let panels = site.panels();
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, &guild_id);
    Ok(jsonsafe::reply(
        200,
        json!({"groups": app_groups(&ctx, is_dev)}),
    ))
}

/// GET /admin/api/apps/{app_id}（`get_app`）。1 枚のパネルの宣言・選択肢・いまの値。
async fn get_app(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    let app_id = req.param("app_id").unwrap_or_default().to_string();
    // `_panel_or_404`（開発者専用のパネルも、存在を漏らさないよう同じ 404）。
    let Some(panel) = schema::schema().panel(&app_id) else {
        return Err(HttpError::new(404).into());
    };
    if panel.dev_only && !is_dev(&app, &req)? {
        return Err(HttpError::new(404).into());
    }
    let mut payload = panel.wire.clone();
    if panel.custom {
        return Ok(jsonsafe::reply(200, Value::Object(payload)));
    }
    let guild_id = session_guild_id(&req)?;
    let panels = site.panels();
    let now = || app.now();
    // 選択肢は供給元ごとに 1 回だけ取る（同じチャンネルの一覧を複数の入力欄で使い回す）。
    let choices = panels
        .choices
        .resolve(site.discord(), &panel.sources, &guild_id, &now)
        .await;
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, &guild_id);
    let (values, mut errors) = read_values(panel, &ctx);
    let (collections, collection_errors) = read_collections(panel, &ctx);
    payload.insert("choices".to_string(), Value::Object(choices));
    payload.insert("values".to_string(), Value::Object(values));
    payload.insert("collections".to_string(), Value::Object(collections));
    // `{**value_errors, **collection_errors}`（同じ鍵なら後の値、位置は先のまま）。
    for (key, message) in collection_errors {
        errors.insert(key, message);
    }
    if !errors.is_empty() {
        payload.insert("errors".to_string(), Value::Object(errors));
    }
    Ok(jsonsafe::reply(200, Value::Object(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{LEGACY_PANELS, default_routes};

    /// 経路が Python の登録の順（dashboard_views の後ろ、api/users・旧 URL の前）に入っていること。
    #[test]
    fn the_routes_sit_after_the_dashboard() {
        let routes = default_routes(&crate::views::tests::test_site());
        let position = |path: &str| {
            routes
                .iter()
                .position(|route| route.template() == path)
                .unwrap_or_else(|| panic!("{path} が無い"))
        };
        let apps = position("/admin/api/apps");
        assert_eq!(position("/admin/api/apps/{app_id}"), apps + 1);
        assert!(position("/admin/overview") < apps);
        assert!(apps < position(LEGACY_PANELS[0].0));
        assert!(
            routes[apps..apps + 2]
                .iter()
                .all(|route| !route.default_limit())
        );
        assert_eq!(routes[apps].allow(), "GET");
    }

    /// 書く側の経路（A6）が読む側の後ろに Python の登録の順で入り、同じパスにほかのメソッドを送ったときの 405 の
    /// `Allow` は最初の経路のもの（`/admin/api/apps/{app_id}` なら GET）であること。
    #[test]
    fn the_write_routes_follow_the_read_routes() {
        let routes = default_routes(&crate::views::tests::test_site());
        let listed: Vec<String> = routes
            .iter()
            .filter(|route| {
                route.template().starts_with("/admin/api/apps")
                    || route.template() == "/admin/api/guild-data"
            })
            .map(|route| format!("{} {}", route.allow(), route.template()))
            .collect();
        let item = "/admin/api/apps/{app_id}/collections/{key}/{item_id}";
        assert_eq!(
            listed,
            [
                "GET /admin/api/apps".to_string(),
                "GET /admin/api/apps/{app_id}".to_string(),
                "PUT /admin/api/apps/{app_id}".to_string(),
                "POST /admin/api/apps/{app_id}/collections/{key}".to_string(),
                format!("PUT {item}"),
                format!("DELETE {item}"),
                "DELETE /admin/api/guild-data".to_string(),
            ]
        );
        let found = crate::routing::find(&routes, &Method::POST, "/admin/api/apps/logging");
        assert!(matches!(
            found,
            crate::routing::Found::MethodNotAllowed(route) if route.allow() == "GET"
        ));
        assert!(routes.iter().all(|route| !route.template().starts_with("/admin/api/")
            || !route.default_limit()));
    }

    /// タイルのグループ分けが PANELS の並びのままで、開発者でなければ dev_only を隠し、設定が読めなければバッジは null。
    #[test]
    fn tiles_are_grouped_like_app_groups() {
        let settings: Result<Arc<Settings>, String> = Err("読めない".to_string());
        let panels = Panels::unconfigured();
        let ctx = panels.ctx(&settings, "1");
        let groups = app_groups(&ctx, false);
        let labels: Vec<&str> = groups
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["label"].as_str().unwrap())
            .collect();
        let want = [
            "概要",
            "基本設定",
            "自動通知",
            "チャンネル機能",
            "メディア",
            "セキュリティ",
        ];
        assert_eq!(labels, want);
        let with_dev = app_groups(&ctx, true);
        assert_eq!(
            with_dev.as_array().unwrap().last().unwrap()["label"],
            "開発者"
        );
        for group in groups.as_array().unwrap() {
            for tile in group["apps"].as_array().unwrap() {
                assert_eq!(tile["badge"], Value::Null);
                let keys: Vec<&String> = tile.as_object().unwrap().keys().collect();
                assert_eq!(keys, ["id", "title", "icon", "url", "badge", "window"]);
            }
        }
    }
}
