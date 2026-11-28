//! 経路の引き方。Starlette の `Router.__call__`（と FastAPI の `APIRoute`）の写し。
//!
//! - 経路は、uvicorn が `%XX` を戻したあとのパスで引く（[`sycs_web::path::decoded`]。`%2F` は区切りになる）
//! - 経路の形は Starlette と同じ正規表現（`{名前}` は `[^/]+`、`{名前:path}` は `.*`）。Python の `$` は末尾の
//!   改行 1 つの前でも当たるので、`\n?\z` で終える（`/admin/dev%0A` も `/admin/dev` に当たる）
//! - 登録した順に見て、パスとメソッドの両方が合う最初の経路で答える。パスだけ合うものがあれば、最初のその経路の
//!   メソッドで 405（`Allow`）。FastAPI の経路は GET に HEAD を足さないので、HEAD も 405
//! - どれでもなければ、`/` 以外は末尾の `/` を付けた・全部落としたパスで引き直し、何か当たれば（メソッドは見ない）
//!   307 で付け替え先へ。それも無ければ 404

use axum::http::Method;
use regex::Regex;

use crate::app::Handler;

/// 1 つの経路。
pub struct Route {
    template: String,
    pattern: Regex,
    names: Vec<String>,
    methods: Option<Vec<Method>>,
    handler: Handler,
    default_limit: bool,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("template", &self.template)
            .field("methods", &self.methods)
            .field("default_limit", &self.default_limit)
            .finish_non_exhaustive()
    }
}

/// 経路の形を Starlette の `compile_path` と同じ正規表現にする（名前の並びも返す）。
fn compile(template: &str) -> (Regex, Vec<String>) {
    let mut pattern = String::from("^");
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|i| open + i) else {
            break;
        };
        pattern.push_str(&regex::escape(&rest[..open]));
        let inner = &rest[open + 1..close];
        let (name, convertor) = inner.split_once(':').unwrap_or((inner, "str"));
        let body = match convertor {
            "path" => ".*",
            "int" => "[0-9]+",
            _ => "[^/]+",
        };
        pattern.push_str(&format!("(?P<{name}>{body})"));
        names.push(name.to_string());
        rest = &rest[close + 1..];
    }
    pattern.push_str(&regex::escape(rest));
    pattern.push_str("\n?\\z");
    let regex = Regex::new(&pattern)
        .unwrap_or_else(|e| panic!("経路の形 {template} を正規表現にできない（コードの書き間違い）: {e}"));
    (regex, names)
}

impl Route {
    /// ルーターに入れた経路（`include_router` の中。既定の回数の制限は掛からない。デコレータの付いた経路もこれ）。
    pub fn new(template: &str, methods: &[Method], handler: Handler) -> Self {
        let (pattern, names) = compile(template);
        Self {
            template: template.to_string(),
            pattern,
            names,
            methods: Some(methods.to_vec()),
            handler,
            default_limit: false,
        }
    }

    /// app に直に足した、デコレータの無い経路（`@app.get`・`app.add_api_route`）。slowapi の既定の 1 分 300 回が掛かる。
    pub fn top_level(template: &str, methods: &[Method], handler: Handler) -> Self {
        Self {
            default_limit: true,
            ..Self::new(template, methods, handler)
        }
    }

    /// `app.mount(prefix, …)`（`{prefix}/{path:path}`。メソッドは見ない。既定の回数の制限は掛からない）。
    pub fn mount(prefix: &str, handler: Handler) -> Self {
        let (pattern, names) = compile(&format!("{prefix}/{{path:path}}"));
        Self {
            template: prefix.to_string(),
            pattern,
            names,
            methods: None,
            handler,
            default_limit: false,
        }
    }

    /// 経路の形（登録した文字）。
    pub fn template(&self) -> &str {
        &self.template
    }

    /// 係。
    pub fn handler(&self) -> &Handler {
        &self.handler
    }

    /// 既定の回数の制限が掛かるか。
    pub fn default_limit(&self) -> bool {
        self.default_limit
    }

    /// 405 の `Allow`（登録したメソッドを `, ` でつなぐ。Python は set の並び）。
    pub fn allow(&self) -> String {
        self.methods
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(Method::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// パスが形に合えば、パラメータ（名前と値）を返す。
    fn capture(&self, path: &str) -> Option<Vec<(String, String)>> {
        let captures = self.pattern.captures(path)?;
        Some(
            self.names
                .iter()
                .map(|name| {
                    let value = captures.name(name).map_or("", |m| m.as_str());
                    (name.clone(), value.to_string())
                })
                .collect(),
        )
    }

    fn accepts(&self, method: &Method) -> bool {
        self.methods
            .as_ref()
            .is_none_or(|methods| methods.contains(method))
    }
}

/// 引いた結果。
#[derive(Debug)]
pub enum Found<'a> {
    /// パスとメソッドが合った経路と、パラメータ。
    Endpoint(&'a Route, Vec<(String, String)>),
    /// パスだけ合った（最初のその経路）。405。
    MethodNotAllowed(&'a Route),
    /// 末尾の `/` を付け替えたパス（307）。
    Redirect(String),
    /// どれにも当たらない（404）。
    NotFound,
}

/// 戻したパスとメソッドで経路を引く（モジュールの説明の順）。
pub fn find<'a>(routes: &'a [Route], method: &Method, path: &str) -> Found<'a> {
    let mut partial: Option<&Route> = None;
    for route in routes {
        let Some(params) = route.capture(path) else {
            continue;
        };
        if route.accepts(method) {
            return Found::Endpoint(route, params);
        }
        partial = partial.or(Some(route));
    }
    if let Some(route) = partial {
        return Found::MethodNotAllowed(route);
    }
    if path != "/" {
        let candidate = if path.ends_with('/') {
            path.trim_end_matches('/').to_string()
        } else {
            format!("{path}/")
        };
        if routes.iter().any(|route| route.capture(&candidate).is_some()) {
            return Found::Redirect(candidate);
        }
    }
    Found::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Reply, handler};
    use crate::errors::Failure;

    fn ok() -> Handler {
        handler(|_, _| async { Ok::<Reply, Failure>(Reply::default()) })
    }

    fn route(template: &str, methods: &[Method]) -> Route {
        Route::new(template, methods, ok())
    }

    fn table() -> Vec<Route> {
        vec![
            Route::mount("/static", ok()),
            route("/admin/users/state", &[Method::GET]),
            route("/admin/apps/{app_id}", &[Method::GET]),
            route("/admin/apps/{app_id}", &[Method::PUT]),
        ]
    }

    fn kind(found: &Found<'_>) -> String {
        match found {
            Found::Endpoint(route, params) => format!("ok {} {params:?}", route.template()),
            Found::MethodNotAllowed(route) => format!("405 {}", route.allow()),
            Found::Redirect(to) => format!("307 {to}"),
            Found::NotFound => "404".to_string(),
        }
    }

    /// 末尾の改行・パラメータ・最初のパスだけ合う経路の Allow・付け替え・mount を Starlette と同じに引くこと。
    #[test]
    fn routes_are_found_like_starlette() {
        let routes = table();
        let get = Method::GET;
        assert_eq!(kind(&find(&routes, &get, "/admin/users/state\n")), "ok /admin/users/state []");
        assert_eq!(kind(&find(&routes, &get, "/admin/users/state\n\n")), "404");
        assert_eq!(
            kind(&find(&routes, &get, "/admin/apps/a\n")),
            "ok /admin/apps/{app_id} [(\"app_id\", \"a\\n\")]"
        );
        assert_eq!(kind(&find(&routes, &Method::POST, "/admin/apps/a")), "405 GET");
        assert_eq!(kind(&find(&routes, &Method::HEAD, "/admin/users/state")), "405 GET");
        assert_eq!(
            kind(&find(&routes, &Method::POST, "/admin/users/state///")),
            "307 /admin/users/state"
        );
        assert_eq!(kind(&find(&routes, &get, "/static")), "307 /static/");
        assert_eq!(kind(&find(&routes, &Method::DELETE, "/static/a.css")), "ok /static [(\"path\", \"a.css\")]");
        assert_eq!(kind(&find(&routes, &get, "/static/a\nb")), "404");
        assert_eq!(kind(&find(&routes, &get, "/")), "404");
    }
}
