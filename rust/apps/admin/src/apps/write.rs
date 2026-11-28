//! 設定パネルの書く側の経路（rust-06 の A6）。Python の `webapp_admin/api/apps.py` の `save_app`・`add_item`・
//! `update_item`・`remove_item`・`delete_guild_data_endpoint`（と `_editable_panel`・`_collection_or_404`・
//! `_json_body`・`_choices_for_keys`）。
//!
//! | 経路 | 確かめ | 答え |
//! |---|---|---|
//! | PUT /admin/api/apps/{app_id} | サーバー・CSRF | `{"values": {…}}`（変えた項目だけ）を検証して 1 項目ずつ書く → `{"saved", "values"}`。誤りがあれば ＋`errors` で 422 |
//! | POST /admin/api/apps/{app_id}/collections/{key} | サーバー・CSRF | 1 件足す → `{"id", "items"}`。add が無ければ 405、上限・検証・書けなければ 422 `{"errors", "items"}` |
//! | PUT /admin/api/apps/{app_id}/collections/{key}/{item_id} | サーバー・CSRF | 1 件変える → `{"id", "items"}`（405・422 は同じ） |
//! | DELETE /admin/api/apps/{app_id}/collections/{key}/{item_id} | サーバー・CSRF | 1 件消す → `{"items"}`（405・422 は同じ） |
//! | DELETE /admin/api/guild-data?confirm= | サーバー・CSRF | 確認の文字がサーバーの ID でなければ 400、いまも管理者でないと分かれば 403 → 設定・履歴・現在の状態を消して `{"removed": {settings, events, states}}` |
//!
//! 順は Python と同じ: 確かめ（`check_guild` → `check_csrf`）→ パネル（無い・開発者専用〔開発者でない〕・custom は
//! 404）→ 一覧（無ければ 404）→ 書く関数が無ければ 405 → `int(session["guild_id"])`（読めなければ 500）→ 本文
//! （JSON でなければ 400 `JSON を解釈できませんでした。`、辞書でなければ 400、`values` が辞書でなければ 400）→ 選択肢
//! （変えた項目・一覧の入力欄の供給元だけ）→ 検証（[`crate::apps::validation`]）→ 書く（[`crate::apps::setters`]。
//! 1 項目ごとに 1 回保存し、変わっていれば Bot に知らせる。[`crate::apps::store`]）→ 書いたあとの値を読み直して答える。
//! 1 項目の失敗はほかの項目の保存を妨げない（`errors` に「保存できませんでした（理由）」）。答えは `SafeJSONResponse`。
//!
//! Python と違うところ:
//!
//! - 本文の JSON は serde_json で読む。Python の `json.loads` が読めて serde_json が読めないもの（`NaN`・`Infinity`・
//!   単独のサロゲート・UTF-16 や UTF-32 の本文）は 400（Python は読む。`Infinity` を数の欄に送ると 500、`NaN` は 422）。
//!   64 ビットに収まらない整数は小数として読む（ID の欄では Python と答えが変わる。Discord の ID は収まる）。
//!   UTF-8 の BOM は Python と同じく読み飛ばす。ブラウザの画面はどれも送らないもの
//! - `multipart/form-data` の本文は、Python は CSRF の確かめで読んだあと（読めなければ python-multipart の文で 400）、
//!   JSON としては読めずに 400。Rust は読まずに 400 `JSON を解釈できませんでした。`（画面は送らない）

use std::sync::Arc;

use serde_json::{Map, Value};
use tracing::{error, warn};

use crate::app::{AdminApp, Reply, Req};
use crate::apps::guild_data;
use crate::apps::schema::{self, ChoiceSource, CollectionSpec, Panel};
use crate::apps::setters::{self, Plan};
use crate::apps::validation::{self, CollectionRules};
use crate::apps::{Panels, getters, is_dev, read_values, session_guild_id};
use crate::auth;
use crate::errors::{Crash, Failure, HttpError};
use crate::jsonsafe;
use crate::params::QueryParams;
use crate::python;
use crate::security;
use crate::views::Site;

/// 本文を JSON として読めない（`_json_body`）。
pub const UNREADABLE_JSON: &str = "JSON を解釈できませんでした。";
/// 本文が辞書でない（`_json_body`）。
pub const NOT_AN_OBJECT: &str = "JSON オブジェクトを送ってください。";
/// `values` が辞書でない。
pub const NO_VALUES: &str = "values オブジェクトが必要です。";
/// add の無い一覧に足そうとした。
pub const CANNOT_ADD: &str = "この一覧には追加できません。";
/// update の無い一覧を変えようとした。
pub const CANNOT_UPDATE: &str = "この一覧は編集できません。";
/// remove の無い一覧から消そうとした。
pub const CANNOT_REMOVE: &str = "この一覧からは削除できません。";
/// 確認の文字がサーバーの ID と違う。
pub const CONFIRM_GUILD_ID: &str = "確認のためサーバーIDを入力してください。";
/// いまはそのサーバーの管理者でない。
pub const NOT_ADMIN: &str = "このサーバーの管理者ではありません。";

fn object(pairs: Vec<(&str, Value)>) -> Value {
    python::object(pairs)
}

/// `_editable_panel`（`_panel_or_404` ＋ custom も 404。開発者専用のパネルは、存在を漏らさないよう同じ 404）。
fn editable_panel(app: &AdminApp, req: &Req) -> Result<&'static Panel, Failure> {
    let app_id = req.param("app_id").unwrap_or_default();
    let Some(panel) = schema::schema().panel(app_id) else {
        return Err(HttpError::new(404).into());
    };
    if panel.dev_only && !is_dev(app, req)? {
        return Err(HttpError::new(404).into());
    }
    if panel.custom {
        return Err(HttpError::new(404).into());
    }
    Ok(panel)
}

/// `_collection_or_404`（宣言と規則の両方を引く）。
fn collection_or_404(
    panel: &'static Panel,
    req: &Req,
) -> Result<(&'static CollectionSpec, &'static CollectionRules), Failure> {
    let key = req.param("key").unwrap_or_default();
    let spec = panel.collections.iter().find(|c| c.key == key);
    let rules = validation::panel_rules(&panel.id).and_then(|rules| rules.collection(key));
    match (spec, rules) {
        (Some(spec), Some(rules)) => Ok((spec, rules)),
        _ => Err(HttpError::new(404).into()),
    }
}

/// `_json_body`（JSON の辞書だけを通す）。`values` も辞書でなければ 400。
///
/// フォームの本文（`application/x-www-form-urlencoded`）は、`check_csrf` が `request.form()` で読み切ったあとなので、
/// Python は JSON として読めずに 400（starlette の `Stream consumed`）。Rust も同じ 400 にする。
fn incoming_values(req: &Req) -> Result<Map<String, Value>, Failure> {
    let unreadable = || Failure::from(HttpError::with_detail(400, UNREADABLE_JSON));
    let kind = security::content_type(&req.headers);
    if kind == "application/x-www-form-urlencoded" || kind == "multipart/form-data" {
        return Err(unreadable());
    }
    // `json.loads(bytes)` は UTF-8 の BOM を読み飛ばす。
    let body = req
        .body
        .strip_prefix(b"\xef\xbb\xbf".as_slice())
        .unwrap_or(&req.body);
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return Err(unreadable());
    };
    let Value::Object(body) = body else {
        return Err(HttpError::with_detail(400, NOT_AN_OBJECT).into());
    };
    match body.get("values") {
        Some(Value::Object(values)) => Ok(values.clone()),
        _ => Err(HttpError::with_detail(400, NO_VALUES).into()),
    }
}

/// 供給元を語の順に並べ、重なりを落とす（`choices.resolve` の `sorted(set(...))`）。
fn sorted_sources(mut sources: Vec<ChoiceSource>) -> Vec<ChoiceSource> {
    sources.sort_by_key(|source| source.as_str());
    sources.dedup();
    sources
}

/// `_choices_for_keys`（変えた項目に関係する供給元だけ）。
fn sources_for_keys(panel: &Panel, incoming: &Map<String, Value>) -> Vec<ChoiceSource> {
    let sources = incoming
        .keys()
        .filter_map(|key| panel.fields.iter().find(|field| &field.key == key))
        .filter_map(|field| field.source)
        .collect();
    sorted_sources(sources)
}

/// 選択肢を解決する（`choice_resolver.resolve(sources, guild_id)`）。
async fn resolve(
    app: &AdminApp,
    site: &Site,
    sources: &[ChoiceSource],
    guild_id: &str,
) -> Map<String, Value> {
    let now = || app.now();
    site.panels()
        .choices
        .resolve(site.discord(), sources, guild_id, &now)
        .await
}

/// `_read_values(panel, guild_id)` の値だけ（書いたあとの手元の設定から読む）。
async fn current_values(panels: &Panels, panel: &Panel, guild_id: &str) -> Value {
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, guild_id);
    let (values, _) = read_values(panel, &ctx);
    Value::Object(values)
}

/// `collection.list(guild_id)`（読めなければ Python と同じく拾わない例外）。
async fn list_items(
    panels: &Panels,
    collection: &CollectionSpec,
    guild_id: &str,
) -> Result<Value, Crash> {
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, guild_id);
    match collection.list.as_deref() {
        Some(name) => getters::call(name, &ctx),
        None => Err(Crash::new("TypeError", "'NoneType' object is not callable")),
    }
}

/// 書く関数が決めた書き換えを、置き場に 1 回だけ当てる（無ければ何もしない）。戻り値は Python の関数の戻り値。
async fn run(panels: &Panels, plan: Result<Plan, Crash>) -> Result<Value, Crash> {
    let plan = plan?;
    if let Some(mutation) = plan.mutation {
        panels.settings.transact(mutation).await?;
    }
    Ok(plan.returns)
}

/// 422 の `{"errors": {"__all__": 文}, "items": 一覧}`。
async fn refused(
    panels: &Panels,
    collection: &CollectionSpec,
    guild_id: &str,
    errors: Value,
) -> Result<Reply, Failure> {
    let items = list_items(panels, collection, guild_id).await?;
    let body = object(vec![("errors", errors), ("items", items)]);
    Ok(jsonsafe::reply(422, body))
}

fn all_errors(message: String) -> Value {
    object(vec![("__all__", Value::String(message))])
}

/// 検証の通った 1 件（`clean`。入力欄の順の辞書）。
fn clean_data(clean: validation::Cleaned) -> Map<String, Value> {
    clean
        .into_iter()
        .map(|(key, value)| (key, value.to_value()))
        .collect()
}

/// PUT /admin/api/apps/{app_id}（`save_app`）。変えた項目だけを保存する。
pub async fn save_app(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    app.check_csrf(&req)?;
    let panel = editable_panel(&app, &req)?;
    let guild_id = session_guild_id(&req)?;
    let incoming = incoming_values(&req)?;
    let panels = site.panels();
    if incoming.is_empty() {
        let values = current_values(panels, panel, &guild_id).await;
        let body = object(vec![("saved", Value::Array(Vec::new())), ("values", values)]);
        return Ok(jsonsafe::reply(200, body));
    }
    let sources = sources_for_keys(panel, &incoming);
    let choices = resolve(&app, &site, &sources, &guild_id).await;
    let (clean, mut errors) = validation::validate_values(panel, &incoming, &choices)?;
    // 1 項目の失敗は failures に積んで続ける（ほかの項目の保存を妨げない）。
    let mut saved = Vec::new();
    for (key, value) in clean {
        let name = panel
            .fields
            .iter()
            .find(|field| field.key == key)
            .and_then(|field| field.set.as_deref());
        let settings = panels.settings.snapshot().await;
        let ctx = panels.ctx(&settings, &guild_id);
        let plan = match name.and_then(setters::setter) {
            Some(setter) => setter(&ctx, &value.to_value()),
            None => Err(setters::missing(name.unwrap_or("None"))),
        };
        match run(panels, plan).await {
            Ok(_) => saved.push(Value::String(key)),
            Err(crash) => {
                error!(
                    "設定の保存に失敗 panel={} field={key}: {}: {}",
                    panel.id, crash.kind, crash.message
                );
                let message = format!("保存できませんでした（{}）", crash.message);
                errors.insert(key, Value::String(message));
            }
        }
    }
    let values = current_values(panels, panel, &guild_id).await;
    let mut body = Map::new();
    body.insert("saved".to_string(), Value::Array(saved));
    body.insert("values".to_string(), values);
    if errors.is_empty() {
        return Ok(jsonsafe::reply(200, Value::Object(body)));
    }
    body.insert("errors".to_string(), Value::Object(errors));
    Ok(jsonsafe::reply(422, Value::Object(body)))
}

/// 一覧の入力欄の選択肢（`{f.choice_source for f in collection.item_fields if f.choice_source}`）。
async fn item_choices(
    app: &AdminApp,
    site: &Site,
    collection: &CollectionSpec,
    guild_id: &str,
) -> Map<String, Value> {
    let sources = sorted_sources(collection.item_sources.clone());
    resolve(app, site, &sources, guild_id).await
}

/// POST /admin/api/apps/{app_id}/collections/{key}（`add_item`）。一覧へ 1 件足す（保存の押し下げを待たずに書く）。
///
/// 件数の上限は検証より前に見る（上限で断ったのに「値がおかしい」ように見せない）。
pub async fn add_item(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    app.check_csrf(&req)?;
    let panel = editable_panel(&app, &req)?;
    let (collection, rules) = collection_or_404(panel, &req)?;
    let Some(add) = collection.add.as_deref() else {
        return Err(HttpError::with_detail(405, CANNOT_ADD).into());
    };
    let guild_id = session_guild_id(&req)?;
    let incoming = incoming_values(&req)?;
    let panels = site.panels();
    if let Some(max_items) = rules.max_items {
        let items = list_items(panels, collection, &guild_id).await?;
        let count = auth::py_len(&items).unwrap_or(0);
        if count >= max_items {
            let message = format!("登録できるのは {max_items} 件までです。");
            return refused(panels, collection, &guild_id, all_errors(message)).await;
        }
    }
    let choices = item_choices(&app, &site, collection, &guild_id).await;
    let (clean, errors) = validation::validate_item(rules, &incoming, &choices)?;
    if !errors.is_empty() {
        return refused(panels, collection, &guild_id, Value::Object(errors)).await;
    }
    let data = clean_data(clean);
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, &guild_id);
    let uuid = || app.random().uuid_hex();
    let plan = match setters::adder(add) {
        Some(adder) => adder(&ctx, &data, &uuid),
        None => Err(setters::missing(add)),
    };
    let returned = match run(panels, plan).await {
        Ok(returned) => returned,
        Err(crash) => {
            error!(
                "一覧への追加に失敗 panel={} collection={}: {}: {}",
                panel.id, collection.key, crash.kind, crash.message
            );
            let message = format!("追加できませんでした（{}）", crash.message);
            return refused(panels, collection, &guild_id, all_errors(message)).await;
        }
    };
    // `None if item_id is None else str(item_id)`。
    let id = match returned {
        Value::Null => Value::Null,
        other => Value::String(python::str_of(&other)),
    };
    let items = list_items(panels, collection, &guild_id).await?;
    Ok(jsonsafe::reply(200, object(vec![("id", id), ("items", items)])))
}

/// PUT /admin/api/apps/{app_id}/collections/{key}/{item_id}（`update_item`）。一覧の 1 件を変える。
pub async fn update_item(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    app.check_csrf(&req)?;
    let panel = editable_panel(&app, &req)?;
    let (collection, rules) = collection_or_404(panel, &req)?;
    let Some(update) = collection.update.as_deref() else {
        return Err(HttpError::with_detail(405, CANNOT_UPDATE).into());
    };
    let item_id = req.param("item_id").unwrap_or_default().to_string();
    let guild_id = session_guild_id(&req)?;
    let incoming = incoming_values(&req)?;
    let panels = site.panels();
    let choices = item_choices(&app, &site, collection, &guild_id).await;
    let (clean, errors) = validation::validate_item(rules, &incoming, &choices)?;
    if !errors.is_empty() {
        return refused(panels, collection, &guild_id, Value::Object(errors)).await;
    }
    let data = clean_data(clean);
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, &guild_id);
    let plan = match setters::updater(update) {
        Some(updater) => updater(&ctx, &item_id, &data),
        None => Err(setters::missing(update)),
    };
    if let Err(crash) = run(panels, plan).await {
        error!(
            "一覧の更新に失敗 panel={} collection={}: {}: {}",
            panel.id, collection.key, crash.kind, crash.message
        );
        let message = format!("更新できませんでした（{}）", crash.message);
        return refused(panels, collection, &guild_id, all_errors(message)).await;
    }
    let items = list_items(panels, collection, &guild_id).await?;
    let body = object(vec![("id", Value::String(item_id)), ("items", items)]);
    Ok(jsonsafe::reply(200, body))
}

/// DELETE /admin/api/apps/{app_id}/collections/{key}/{item_id}（`remove_item`）。一覧の 1 件をすぐ消す（取り消しの確認は
/// 画面の仕事）。
pub async fn remove_item(app: Arc<AdminApp>, req: Req, site: Arc<Site>) -> Result<Reply, Failure> {
    req.check_guild()?;
    app.check_csrf(&req)?;
    let panel = editable_panel(&app, &req)?;
    let (collection, _) = collection_or_404(panel, &req)?;
    let Some(remove) = collection.remove.as_deref() else {
        return Err(HttpError::with_detail(405, CANNOT_REMOVE).into());
    };
    let item_id = req.param("item_id").unwrap_or_default().to_string();
    let guild_id = session_guild_id(&req)?;
    let panels = site.panels();
    let settings = panels.settings.snapshot().await;
    let ctx = panels.ctx(&settings, &guild_id);
    let plan = match setters::remover(remove) {
        Some(remover) => remover(&ctx, &item_id),
        None => Err(setters::missing(remove)),
    };
    if let Err(crash) = run(panels, plan).await {
        error!(
            "一覧からの削除に失敗 panel={} collection={}: {}: {}",
            panel.id, collection.key, crash.kind, crash.message
        );
        let message = format!("削除できませんでした（{}）", crash.message);
        return refused(panels, collection, &guild_id, all_errors(message)).await;
    }
    let items = list_items(panels, collection, &guild_id).await?;
    Ok(jsonsafe::reply(200, object(vec![("items", items)])))
}

/// `int((request.session.get("user") or {}).get("id") or 0)`（ID が偽なら 0。`select_guild` の `.get("id", 0)` とは違う）。
fn deleting_user_id(user: Option<&Value>) -> Result<String, Crash> {
    let empty = Value::Object(Map::new());
    let user = user.filter(|user| python::truthy(user)).unwrap_or(&empty);
    let fields = auth::py_dict(user)?;
    match fields.get("id").filter(|id| python::truthy(id)) {
        Some(id) => auth::py_int(id),
        None => Ok("0".to_string()),
    }
}

/// DELETE /admin/api/guild-data（`delete_guild_data_endpoint`）。いま選んでいるサーバーのデータを全部消す。
///
/// 取り消しが効かないので、確認にサーバーの ID そのものを打たせる（前後の空白は落とす）。セッションを取ったあとに権限を
/// 外された人が消せないよう、いまも管理者かを Discord に聞き直す（分からないときは通す。Python と同じ）。
pub async fn delete_guild_data(
    app: Arc<AdminApp>,
    req: Req,
    site: Arc<Site>,
) -> Result<Reply, Failure> {
    req.check_guild()?;
    app.check_csrf(&req)?;
    let confirm = QueryParams::parse(req.query.as_deref())
        .get("confirm")
        .unwrap_or_default()
        .to_string();
    let guild_id = session_guild_id(&req)?;
    if python::strip(&confirm) != guild_id {
        return Err(HttpError::with_detail(400, CONFIRM_GUILD_ID).into());
    }
    let user_id = req
        .session
        .with(|session| deleting_user_id(session.get("user")))?;
    let still_admin = site.discord().user_still_admin(&guild_id, &user_id).await?;
    if still_admin == Some(false) {
        return Err(HttpError::with_detail(403, NOT_ADMIN).into());
    }
    let removed = guild_data::delete_guild_data(site.panels(), &guild_id).await?;
    warn!(
        "サーバーのデータを削除 guild={guild_id} user={user_id} 設定={} 履歴={} 現在状態={}",
        removed.settings, removed.events, removed.states
    );
    let removed = object(vec![
        ("settings", Value::from(removed.settings)),
        ("events", Value::from(removed.events)),
        ("states", Value::from(removed.states)),
    ]);
    Ok(jsonsafe::reply(200, object(vec![("removed", removed)])))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 断る文が Python のソース（`api/apps.py`）と同じであること。
    #[test]
    fn messages_match_python() {
        let source = include_str!("../../../../../webapp_admin/api/apps.py");
        for message in [
            UNREADABLE_JSON,
            NOT_AN_OBJECT,
            NO_VALUES,
            CANNOT_ADD,
            CANNOT_UPDATE,
            CANNOT_REMOVE,
            CONFIRM_GUILD_ID,
            NOT_ADMIN,
        ] {
            assert!(source.contains(&format!("detail=\"{message}\"")), "{message}");
        }
        for format in [
            "f\"登録できるのは {collection.max_items} 件までです。\"",
            "f\"保存できませんでした（{exc}）\"",
            "f\"追加できませんでした（{exc}）\"",
            "f\"更新できませんでした（{exc}）\"",
            "f\"削除できませんでした（{exc}）\"",
        ] {
            assert!(source.contains(format), "{format}");
        }
    }

    /// 削除する人の ID は `(user or {}).get("id") or 0` を `int()` したもの（偽の ID は 0。辞書でなければ AttributeError）。
    #[test]
    fn the_deleting_user_is_read_like_python() {
        assert_eq!(deleting_user_id(None), Ok("0".to_string()));
        assert_eq!(deleting_user_id(Some(&json!({"id": ""}))), Ok("0".to_string()));
        assert_eq!(deleting_user_id(Some(&json!({"id": " 12 "}))), Ok("12".to_string()));
        assert_eq!(deleting_user_id(Some(&json!([]))), Ok("0".to_string()));
        let crash = deleting_user_id(Some(&json!("x"))).unwrap_err();
        assert_eq!(crash.kind, "AttributeError");
        assert_eq!(deleting_user_id(Some(&json!({"id": "x"}))).unwrap_err().kind, "ValueError");
    }

    /// 変えた項目の供給元だけを、語の順に 1 回ずつ取ること（TTS の声と接続先 VC とチャンネルは別の供給元）。
    #[test]
    fn only_the_sources_of_changed_fields_are_resolved() {
        let tts = schema::schema().panel("tts").unwrap();
        let incoming = json!({
            "default_voice": "x",
            "vc_channel_id": "1",
            "enabled": true,
            "nothing": 1
        });
        let sources = sources_for_keys(tts, incoming.as_object().unwrap());
        assert_eq!(sources, [ChoiceSource::TtsVoices, ChoiceSource::VoiceChannels]);
        let logging = schema::schema().panel("logging").unwrap();
        let incoming = json!({
            "log_channel_id": "1",
            "chatgpt_channel_id": "2",
            "log_level": "INFO"
        });
        let sources = sources_for_keys(logging, incoming.as_object().unwrap());
        assert_eq!(sources, [ChoiceSource::Channels]);
    }
}
