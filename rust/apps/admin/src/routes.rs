//! 経路の表。Python の `create_app` の登録の順（並びに意味がある。同じパスに当たる経路は先のものが勝ち、405 の
//! `Allow` は最初にパスの合った経路のもの）。
//!
//! ```text
//! /static（mount）
//! ルーターの中（auth_views・dashboard_views・api/apps・api/users・api/dev・api/sql）
//! パネルの旧 URL（12 本。_register_legacy_redirects）
//! 公開ページ（/・/guide・/privacy・/terms・/admin/guide など。_register_public_pages）
//! /metrics（_register_metrics_endpoint）
//! ```
//!
//! **塊ごとに、決まった場所へ 1 行ずつ足す**（下の [`default_routes`] のコメントの位置）。ルーターの中の経路は
//! [`Route::new`]（既定の回数の制限が掛からない）、app に直に足したデコレータの無い経路は [`Route::top_level`]。
//! デコレータの付いた経路は [`Route::new`] にして、係の中で [`crate::app::AdminApp::check_route_limit`] を呼ぶ。
//!
//! `/dlaudio/` は nginx が `apps/cdn` へ渡すので、ここには無い（Python は同じアプリに入っていた）。

use axum::http::Method;

use crate::app::{Reply, Req, handler};
use crate::errors::{Failure, HttpError};
use crate::routing::Route;

/// パネルの旧 URL と、パネルの ID（`webapp_admin/schema/registry.py` の `PANELS` の並びのうち `path` のあるもの）。
pub const LEGACY_PANELS: [(&str, &str); 12] = [
    ("/admin/users/state", "user-state"),
    ("/admin/settings/logging", "logging"),
    ("/admin/settings/welcome", "welcome"),
    ("/admin/settings/vc-notify", "vc-notify"),
    ("/admin/settings/earthquake", "earthquake"),
    ("/admin/settings/news-feeds", "news-feeds"),
    ("/admin/settings/sticky", "sticky"),
    ("/admin/settings/reaction-roles", "reaction-roles"),
    ("/admin/settings/djaudio", "djaudio"),
    ("/admin/settings/tts", "tts"),
    ("/admin/settings/security", "security"),
    ("/admin/dev", "dev"),
];

/// 管理画面の経路を、Python の登録の順に並べる。
pub fn default_routes() -> Vec<Route> {
    let mut routes = vec![static_mount()];
    // ルーターの中（/admin・/admin/api）: A3（auth_views）、A2・A3（dashboard_views）、A5・A6（api/apps）、
    // A4（api/users）、A8・A9（api/dev）、A10（api/sql）がこの位置に足す。
    routes.extend(legacy_redirects());
    // 公開ページ（A2）と /metrics（A7）がこの位置に足す。
    routes
}

/// `/static`（`app.mount("/static", StaticFiles(...))`）。
///
/// nginx がファイルを返し、無いファイルと GET・HEAD 以外だけをここへ回す（`docker/nginx/sycs.conf.template`）。
/// なので、ここで返すのは StaticFiles の断り方だけ: GET・HEAD 以外は 405（starlette 1.10 は `Allow: GET, HEAD` を
/// 付ける。JSON の答えにだけ出る）、ほかは 404。
/// Python と違うところ: nginx を通さずにファイルを取りに来ても、Rust は 404 にする（中身を返さない）。
pub fn static_mount() -> Route {
    Route::mount(
        "/static",
        handler(|_app, req: Req| async move {
            let error = if req.method != Method::GET && req.method != Method::HEAD {
                HttpError::new(405).header("allow", "GET, HEAD")
            } else {
                HttpError::new(404)
            };
            Err::<Reply, Failure>(error.into())
        }),
    )
}

/// パネルの旧 URL（`_register_legacy_redirects`）。サーバーを選んでいれば 303 で `/admin/overview#{パネル}` へ。
///
/// `check_guild` を通すのは、ログイン前に、どのパネルがあるかを見せないため。app に直に足した経路なので、既定の
/// 1 分 300 回が掛かる。
pub fn legacy_redirects() -> Vec<Route> {
    LEGACY_PANELS
        .iter()
        .map(|&(path, panel)| {
            Route::top_level(
                path,
                &[Method::GET],
                handler(move |_app, req: Req| async move {
                    req.check_guild()?;
                    Ok::<Reply, Failure>(Reply::redirect(303, &format!("/admin/overview#{panel}")))
                }),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    /// 旧 URL の表が、設定パネルの定義の書き出し（schema.json の wire.path と id）と同じ並び・同じ中身であること。
    #[test]
    fn legacy_paths_match_the_panel_schema() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/schema/schema.json"
        );
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let from_schema: Vec<(String, String)> = schema["panels"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|panel| {
                let wire = &panel["wire"];
                Some((
                    wire["path"].as_str()?.to_string(),
                    wire["id"].as_str()?.to_string(),
                ))
            })
            .collect();
        let ours: Vec<(String, String)> = LEGACY_PANELS
            .iter()
            .map(|(path, id)| ((*path).to_string(), (*id).to_string()))
            .collect();
        assert_eq!(ours, from_schema);
    }
}
