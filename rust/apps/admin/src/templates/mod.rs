//! 管理画面の HTML のページ（テンプレート）。Python の `webapp_admin/templating.py`（`render`・`flash`）と、
//! ページを返す経路の中身（`app.py` の公開ページ・`views/auth_views.py`・`views/dashboard_views.py`・エラーのページ）。
//!
//! テンプレートは Python と同じファイル（`webapp_admin/templates/` の 10 枚）を起動のときに読み、minijinja で描く。
//! 書き方の違い（エスケープ・`None` の形）は [`markup`] で Jinja2 に合わせ、`admin_asset_url`・`icon`・`url_for` は
//! [`globals`] にある。どのページも、本物の Python が書いた HTML とバイトまで同じかを基準
//! （`tests/fixtures/templates/`）で確かめる。
//!
//! Jinja2（starlette の `Jinja2Templates`）と揃えた設定:
//!
//! - 自動のエスケープは、名前によらず全部のテンプレートで有効（starlette は `autoescape=True`）
//! - 未定義は Jinja2 の既定（書くと空・`if` は偽・未定義の属性を引くと誤り）。minijinja の `Lenient` が同じ
//! - 最後の改行 1 つを落とす（`keep_trailing_newline=False`）。`trim_blocks`・`lstrip_blocks` は使わない
//! - 改行は読むときに `\n` に揃える（Jinja2 の字句解析は `\r\n`・`\r` を `\n` にする）
//!
//! 経路（axum）へのつなぎは、骨組み（A1）のあとで足す。ここにあるのは、セッションと経路ごとの値を受けて本文を返す
//! 関数だけ（[`Pages`] のメソッド。状態のコードと見出しはつなぐ側が決める）。

pub mod globals;
pub mod markup;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use minijinja::{AutoEscape, Environment, Error, UndefinedBehavior};
use serde_json::{Map, Value as JsonValue};

use globals::{Assets, DEFAULT_ASSET_VERSION};

/// テンプレートの置き場にあるはずのファイル（Python の `webapp_admin/templates/` の全部）。
///
/// どれか 1 つでも読めなければ起動で止める（Python は描くときに初めて読むが、Rust は起動のときに全部読んで、
/// 書き方の誤りもそこで見つける）。
pub const TEMPLATE_NAMES: [&str; 10] = [
    "_site_footer.html",
    "error.html",
    "guide.html",
    "guild_select.html",
    "landing.html",
    "login.html",
    "logout_confirm.html",
    "privacy.html",
    "shell.html",
    "terms.html",
];

/// テンプレートで描いたページの `Content-Type`（starlette の `HTMLResponse`）。
pub const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// 旧 URL から公開ページへの 301（Python の `redirect_admin_guide` など 3 本）。
pub const LEGACY_PUBLIC_REDIRECTS: [(&str, &str); 3] = [
    ("/admin/guide", "/guide"),
    ("/admin/privacy", "/privacy"),
    ("/admin/terms", "/terms"),
];

/// 経路が描くページ（`_site_footer.html` は公開ページが取り込むだけなので、ここには無い）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// `GET /`（`landing.html`）。
    Landing,
    /// `GET /guide`（`guide.html`）。
    Guide,
    /// `GET /privacy`（`privacy.html`）。
    Privacy,
    /// `GET /terms`（`terms.html`）。
    Terms,
    /// `GET /admin/login`（`login.html`）。
    Login,
    /// `GET /admin/logout`（`logout_confirm.html`）。
    LogoutConfirm,
    /// `GET /admin/guilds`（`guild_select.html`）。
    GuildSelect,
    /// `GET /admin/overview`（`shell.html`）。
    Shell,
    /// エラーのページ（`error.html`。HTML で返す相手のとき）。
    Error,
}

impl Page {
    /// 全部のページ。
    pub const ALL: [Page; 9] = [
        Page::Landing,
        Page::Guide,
        Page::Privacy,
        Page::Terms,
        Page::Login,
        Page::LogoutConfirm,
        Page::GuildSelect,
        Page::Shell,
        Page::Error,
    ];

    /// テンプレートの名前。
    pub fn template(self) -> &'static str {
        match self {
            Page::Landing => "landing.html",
            Page::Guide => "guide.html",
            Page::Privacy => "privacy.html",
            Page::Terms => "terms.html",
            Page::Login => "login.html",
            Page::LogoutConfirm => "logout_confirm.html",
            Page::GuildSelect => "guild_select.html",
            Page::Shell => "shell.html",
            Page::Error => "error.html",
        }
    }

    /// テンプレートの名前からページを引く。
    pub fn from_template(name: &str) -> Option<Page> {
        Page::ALL.into_iter().find(|page| page.template() == name)
    }
}

/// 公開の文書のページの経路（`/guide`・`/privacy`・`/terms`）から、そのページを引く。
pub fn document_for_path(path: &str) -> Option<Page> {
    match path {
        "/guide" => Some(Page::Guide),
        "/privacy" => Some(Page::Privacy),
        "/terms" => Some(Page::Terms),
        _ => None,
    }
}

/// 旧 URL（`/admin/guide` など）なら、301 の行き先。
pub fn legacy_public_redirect(path: &str) -> Option<&'static str> {
    LEGACY_PUBLIC_REDIRECTS
        .iter()
        .find(|(old, _)| *old == path)
        .map(|(_, new)| *new)
}

/// 「Bot を招待」のリンク。Python の `_invite_url`（`app.py`）と `_build_invite_url`（`auth_views.py`）。
///
/// `DISCORD_CLIENT_ID` が空なら None（ボタンを隠す）。値は前後の空白も落とさず、そのまま埋める（Python と同じ）。
pub fn invite_url(client_id: &str) -> Option<String> {
    if client_id.is_empty() {
        return None;
    }
    Some(format!(
        "https://discord.com/api/oauth2/authorize?client_id={client_id}&permissions=8&scope=bot+applications.commands"
    ))
}

/// iframe の中で開かれたか。Python の `render()` の `is_embedded`（`Sec-Fetch-Dest` を小文字にして `iframe` か）。
pub fn is_embedded(sec_fetch_dest: Option<&str>) -> bool {
    sec_fetch_dest.is_some_and(|value| value.to_lowercase() == "iframe")
}

/// セッションの CSRF の印。Python の `security.issue_csrf_token`（無いか偽なら作って入れる）。
///
/// 偽（空の文字など）の印が入っていたときは、その鍵の位置のまま置き換わる（Python の dict と同じ）。
pub fn issue_csrf_token(
    session: &mut Map<String, JsonValue>,
    new_token: &mut dyn FnMut() -> String,
) -> JsonValue {
    if let Some(token) = session
        .get("_csrf_token")
        .filter(|token| markup::json_truthy(token))
    {
        return token.clone();
    }
    let token = JsonValue::String(new_token());
    session.insert("_csrf_token".to_string(), token.clone());
    token
}

/// セッションの `_flashes` が一覧でなかった（Python では `append` が AttributeError になり 500）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashesNotAList;

impl fmt::Display for FlashesNotAList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("セッションの _flashes が一覧ではありません")
    }
}

impl std::error::Error for FlashesNotAList {}

/// 次に描くページで 1 回だけ出す知らせを積む。Python の `templating.flash`（`[種類, 文]` を `_flashes` に足す）。
///
/// 取り出すのは [`Pages::render`]（ここで取り出すと、リダイレクトを挟んで次のページで出す使い方が壊れる）。
pub fn flash(
    session: &mut Map<String, JsonValue>,
    message: &str,
    category: &str,
) -> Result<(), FlashesNotAList> {
    match session
        .entry("_flashes")
        .or_insert_with(|| JsonValue::Array(Vec::new()))
    {
        JsonValue::Array(items) => {
            items.push(JsonValue::Array(vec![category.into(), message.into()]));
            Ok(())
        }
        _ => Err(FlashesNotAList),
    }
}

/// 描くときに要る、要求ごとのもの（Python の `render()` が `request` から読むもの）。
pub struct Visit<'a> {
    /// 読んだセッション。描くと `_flashes` を取り出し、CSRF の印が無ければ入れる（書き戻すのはつなぐ側）。
    pub session: &'a mut Map<String, JsonValue>,
    /// `Sec-Fetch-Dest: iframe` で来たか（[`is_embedded`]。どのテンプレートも使っていない）。
    pub is_embedded: bool,
    /// CSRF の印を新しく作る（Python の `secrets.token_hex(32)`）。セッションに無いときだけ呼ぶ。
    pub new_csrf_token: &'a mut dyn FnMut() -> String,
}

/// テンプレートとファイルの置き場。
#[derive(Debug, Clone)]
pub struct PagesConfig {
    /// テンプレートの置き場（Python の `webapp_admin/templates` と同じファイル）。
    pub templates_dir: PathBuf,
    /// `admin_asset_url` が大きさと時刻を見る置き場（nginx が返す `webapp_admin/static` と同じ中身）。
    pub static_dir: PathBuf,
    /// `admin_asset_url` の版（`ADMIN_ASSET_VERSION`。空でもそのまま使う）。
    pub asset_version: String,
}

impl PagesConfig {
    /// 環境変数から読む: `ADMIN_TEMPLATES_DIR`（既定 `webapp_admin/templates`）・`ADMIN_STATIC_DIR`
    /// （既定 `webapp_admin/static`）・`ADMIN_ASSET_VERSION`（既定 `admin`。Python の `os.environ.get` と同じく、空でも
    /// 既定にはしない）。
    pub fn from_env() -> PagesConfig {
        let dir = |name: &str, default: &str| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map_or_else(|| PathBuf::from(default), PathBuf::from)
        };
        PagesConfig {
            templates_dir: dir("ADMIN_TEMPLATES_DIR", "webapp_admin/templates"),
            static_dir: dir("ADMIN_STATIC_DIR", "webapp_admin/static"),
            asset_version: std::env::var("ADMIN_ASSET_VERSION")
                .unwrap_or_else(|_| DEFAULT_ASSET_VERSION.to_string()),
        }
    }
}

/// テンプレートを読めなかった（起動を止める）。
#[derive(Debug)]
pub enum PagesError {
    /// ファイルを読めなかった。
    Read {
        /// 読もうとしたファイル。
        path: PathBuf,
        /// 読めなかった理由。
        source: std::io::Error,
    },
    /// minijinja が読めない書き方だった。
    Parse {
        /// テンプレートの名前。
        name: &'static str,
        /// minijinja の誤り。
        source: Error,
    },
}

impl fmt::Display for PagesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PagesError::Read { path, source } => {
                write!(f, "テンプレート {} を読めません: {source}", path.display())
            }
            PagesError::Parse { name, source } => {
                write!(f, "テンプレート {name} を minijinja が読めません: {source}")
            }
        }
    }
}

impl std::error::Error for PagesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PagesError::Read { source, .. } => Some(source),
            PagesError::Parse { source, .. } => Some(source),
        }
    }
}

/// Jinja2 と同じく、改行を `\n` に揃える（`\r\n` と `\r`）。
fn normalize_newlines(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

fn optional_text(text: Option<&str>) -> JsonValue {
    text.map_or(JsonValue::Null, |text| JsonValue::String(text.to_string()))
}

/// テンプレートを読み込んだ minijinja の環境。起動のときに 1 回作り、要求ごとに使い回す。
pub struct Pages {
    env: Environment<'static>,
}

impl Pages {
    /// テンプレートを全部読み、Jinja2 と同じ設定（モジュールの説明）の環境を作る。
    pub fn load(config: &PagesConfig) -> Result<Pages, PagesError> {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_name: &str| AutoEscape::Html);
        env.set_undefined_behavior(UndefinedBehavior::Lenient);
        env.set_keep_trailing_newline(false);
        env.set_trim_blocks(false);
        env.set_lstrip_blocks(false);
        env.set_formatter(|out, state, value| {
            markup::write_value(out, state.auto_escape(), value)
        });
        globals::register(
            &mut env,
            Arc::new(Assets::new(
                &config.static_dir,
                config.asset_version.clone(),
            )),
        );
        for name in TEMPLATE_NAMES {
            let path = config.templates_dir.join(name);
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(source) => return Err(PagesError::Read { path, source }),
            };
            env.add_template_owned(name, normalize_newlines(&source))
                .map_err(|source| PagesError::Parse { name, source })?;
        }
        Ok(Pages { env })
    }

    /// ページを描く。Python の `templating.render(request, name, **ctx)`。
    ///
    /// 順番も Python と同じ: 知らせ（`_flashes`）を取り出す → CSRF の印が無ければ入れる → 経路の値（`ctx`）に
    /// `is_embedded` が無ければ足す → `session`（ここまでで変えたあとのもの）・`messages`・`csrf_token` で上書きする。
    pub fn render(
        &self,
        page: Page,
        visit: &mut Visit<'_>,
        mut ctx: Map<String, JsonValue>,
    ) -> Result<String, Error> {
        let messages = visit
            .session
            .shift_remove("_flashes")
            .unwrap_or_else(|| JsonValue::Array(Vec::new()));
        let csrf_token = issue_csrf_token(visit.session, &mut *visit.new_csrf_token);
        ctx.entry("is_embedded")
            .or_insert(JsonValue::Bool(visit.is_embedded));
        ctx.insert(
            "session".to_string(),
            JsonValue::Object(visit.session.clone()),
        );
        ctx.insert("messages".to_string(), messages);
        ctx.insert("csrf_token".to_string(), csrf_token);
        self.env.get_template(page.template())?.render(&ctx)
    }

    /// テンプレートの文字そのものを、同じ環境で描く（Jinja2 の `env.from_string(source).render(ctx)`）。
    ///
    /// 基準のテストが、minijinja と Jinja2 の細かな違い（エスケープ・`None`・添字・改行）を 1 つずつ比べるのに使う。
    pub fn render_source(&self, source: &str, ctx: &JsonValue) -> Result<String, Error> {
        self.env.render_str(&normalize_newlines(source), ctx)
    }

    /// `GET /`。Python の `landing`（招待リンクと Bot のサーバー数）。
    pub fn landing(
        &self,
        visit: &mut Visit<'_>,
        invite_url: Option<&str>,
        guild_count: i64,
    ) -> Result<String, Error> {
        let mut ctx = Map::new();
        ctx.insert("invite_url".to_string(), optional_text(invite_url));
        ctx.insert("guild_count".to_string(), JsonValue::from(guild_count));
        self.render(Page::Landing, visit, ctx)
    }

    /// `GET /guide`・`/privacy`・`/terms`。Python の `guide`・`privacy`・`terms`（招待リンクだけ）。
    pub fn document(
        &self,
        page: Page,
        visit: &mut Visit<'_>,
        invite_url: Option<&str>,
    ) -> Result<String, Error> {
        let mut ctx = Map::new();
        ctx.insert("invite_url".to_string(), optional_text(invite_url));
        self.render(page, visit, ctx)
    }

    /// ログインの画面（`GET /admin/login` で、まだログインしていないとき）。Python の `login` の `render`。
    pub fn login(&self, visit: &mut Visit<'_>, invite_url: Option<&str>) -> Result<String, Error> {
        self.document(Page::Login, visit, invite_url)
    }

    /// ログアウトの確認（`GET /admin/logout` で、ログインしているとき）。Python の `logout_get` の `render`。
    pub fn logout_confirm(&self, visit: &mut Visit<'_>) -> Result<String, Error> {
        self.render(Page::LogoutConfirm, visit, Map::new())
    }

    /// サーバー選択（`GET /admin/guilds`）。Python の `guild_select`（一覧はセッションの `admin_guilds`。無ければ空）。
    pub fn guild_select(&self, visit: &mut Visit<'_>) -> Result<String, Error> {
        let guilds = visit
            .session
            .get("admin_guilds")
            .cloned()
            .unwrap_or_else(|| JsonValue::Array(Vec::new()));
        let mut ctx = Map::new();
        ctx.insert("guilds".to_string(), guilds);
        self.render(Page::GuildSelect, visit, ctx)
    }

    /// デスクトップのシェル（`GET /admin/overview`）。Python の `overview`。
    pub fn shell(&self, visit: &mut Visit<'_>) -> Result<String, Error> {
        self.render(Page::Shell, visit, Map::new())
    }

    /// エラーのページ。Python の `_error_response` の HTML の枝（`code`・`message`・`description`）。
    ///
    /// 文言（`message`）と補足（`description`）の決め方は、エラーの係（A1）が持つ。
    pub fn error(
        &self,
        visit: &mut Visit<'_>,
        code: u16,
        message: &str,
        description: Option<&str>,
    ) -> Result<String, Error> {
        let mut ctx = Map::new();
        ctx.insert("code".to_string(), JsonValue::from(code));
        ctx.insert("message".to_string(), JsonValue::from(message));
        ctx.insert("description".to_string(), optional_text(description));
        self.render(Page::Error, visit, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_templates() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../webapp_admin/templates")
    }

    fn pages() -> Pages {
        let config = PagesConfig {
            templates_dir: repository_templates(),
            static_dir: PathBuf::from("/nonexistent-sycs-admin-static/static"),
            asset_version: DEFAULT_ASSET_VERSION.to_string(),
        };
        Pages::load(&config).unwrap()
    }

    fn session(value: serde_json::Value) -> Map<String, JsonValue> {
        value.as_object().unwrap().clone()
    }

    /// 知らせは描くときに取り出し、CSRF の印は無いときだけ作って入れること（Python の `render`）。
    #[test]
    fn render_takes_the_flashes_and_issues_a_token_once() {
        let pages = pages();
        let mut stored =
            session(serde_json::json!({"a": 1, "_flashes": [["danger", "x<y"]], "b": 2}));
        let mut issued = 0;
        let mut token = || {
            issued += 1;
            "t".repeat(64)
        };
        let mut visit = Visit {
            session: &mut stored,
            is_embedded: false,
            new_csrf_token: &mut token,
        };
        let body = pages.login(&mut visit, None).unwrap();
        assert!(body.contains("<div class=\"grow\">x&lt;y</div>"));
        assert_eq!(
            serde_json::to_string(&stored).unwrap(),
            format!(r#"{{"a":1,"b":2,"_csrf_token":"{}"}}"#, "t".repeat(64))
        );
        let mut visit = Visit {
            session: &mut stored,
            is_embedded: false,
            new_csrf_token: &mut token,
        };
        pages.logout_confirm(&mut visit).unwrap();
        assert_eq!(issued, 1);
    }

    /// 偽の印は、鍵の位置のまま作り直すこと（Python の dict の上書き）。
    #[test]
    fn a_falsy_token_is_replaced_in_place() {
        let mut stored = session(serde_json::json!({"_csrf_token": "", "z": 1}));
        let token = issue_csrf_token(&mut stored, &mut || "n".to_string());
        assert_eq!(token, JsonValue::from("n"));
        assert_eq!(
            serde_json::to_string(&stored).unwrap(),
            r#"{"_csrf_token":"n","z":1}"#
        );
    }

    /// 知らせは `[種類, 文]` で末尾に積み、一覧でなければ断ること。
    #[test]
    fn flash_appends_and_refuses_a_broken_list() {
        let mut stored = Map::new();
        flash(&mut stored, "ログアウトしました。", "info").unwrap();
        flash(&mut stored, "b", "danger").unwrap();
        assert_eq!(
            JsonValue::Object(stored),
            serde_json::json!({"_flashes": [["info", "ログアウトしました。"], ["danger", "b"]]})
        );
        let mut broken = session(serde_json::json!({"_flashes": null}));
        assert_eq!(flash(&mut broken, "x", "info"), Err(FlashesNotAList));
    }

    /// 旧 URL の 3 本・文書の 3 本・招待リンクの形。
    #[test]
    fn public_routes_and_invite_link() {
        assert_eq!(legacy_public_redirect("/admin/terms"), Some("/terms"));
        assert_eq!(legacy_public_redirect("/admin/terms/"), None);
        assert_eq!(document_for_path("/privacy"), Some(Page::Privacy));
        assert_eq!(document_for_path("/admin/guide"), None);
        assert_eq!(invite_url(""), None);
        assert_eq!(
            invite_url("42").as_deref(),
            Some(
                "https://discord.com/api/oauth2/authorize?client_id=42&permissions=8&scope=bot+applications.commands"
            )
        );
        assert!(is_embedded(Some("IFrame")));
        assert!(!is_embedded(Some("document")));
        assert!(!is_embedded(None));
    }

    /// テンプレートの置き場が無ければ、起動で止めること。
    #[test]
    fn a_missing_template_stops_the_start() {
        let config = PagesConfig {
            templates_dir: PathBuf::from("/nonexistent-sycs-admin-templates"),
            static_dir: PathBuf::from("/nonexistent-sycs-admin-static/static"),
            asset_version: DEFAULT_ASSET_VERSION.to_string(),
        };
        match Pages::load(&config) {
            Err(PagesError::Read { path, .. }) => assert!(path.ends_with("_site_footer.html")),
            Err(other) => panic!("読めないのに別の誤り: {other}"),
            Ok(_) => panic!("置き場が無いのに読めた"),
        }
    }

    /// ページとテンプレートの名前が 1 対 1 であること。
    #[test]
    fn every_page_has_its_template() {
        for page in Page::ALL {
            assert_eq!(Page::from_template(page.template()), Some(page));
            assert!(TEMPLATE_NAMES.contains(&page.template()));
        }
        assert_eq!(Page::from_template("_site_footer.html"), None);
    }
}
