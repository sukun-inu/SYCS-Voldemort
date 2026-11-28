//! 断るときの文面とページ。Python の `services/djaudio_cdn.py`（文面・`render_link_error_page`・`wants_json`）と、
//! 管理画面の `webapp_admin/app.py`（`_http_exception_response` のコードごとの文・`_error_response` の振り分け）。
//!
//! ページは外の資材（CSS・スクリプト）に一切頼らない（配信のホストには `/dlaudio/` しか通っていないので、
//! 管理画面の `/static/` は届かない）。文字は Python の f-string と 1 文字も違わないこと（基準が確かめる）。

use crate::python::html_escape;

/// 印やギルドの形が違う（404）。
pub const LINK_INVALID: &str =
    "リンクが正しくありません。Discordに投稿されたリンクをそのまま開いてください。";
/// 情報が無い・期限切れ・本体が無い（410）。
pub const LINK_EXPIRED: &str =
    "このリンクの有効期限が切れました。Discordでもう一度URLを投稿して、新しいリンクを取得してください。";
/// 別のサーバー向けのリンク（403）。
pub const LINK_WRONG_GUILD: &str = "このリンクは別のサーバー向けに発行されたものです。";
/// 拾えなかった例外（500。管理画面の `_unhandled_request_response` と `_exception_group_response`）。
pub const SERVER_ERROR: &str = "サーバーエラーが発生しました。";

/// 配信のエラーのページの見出し。Python の `_LINK_ERROR_TITLES`（無いコードは「エラーが発生しました」）。
pub fn link_error_title(status: u16) -> &'static str {
    match status {
        400 => "リクエストが正しくありません",
        403 => "アクセスできません",
        404 => "リンクが見つかりません",
        405 => "この URL では受け付けていない操作です",
        410 => "リンクの有効期限切れ",
        416 => "要求された範囲を返せません",
        429 => "アクセスが集中しています",
        500 => "処理に失敗しました",
        _ => "エラーが発生しました",
    }
}

/// 管理画面の、コードごとの日本語の文。`_http_exception_response` の `msgs`（無いコードは「エラーが発生しました。」）。
pub fn admin_message(status: u16) -> &'static str {
    match status {
        400 => "不正なリクエストです。",
        403 => "アクセス権限がありません。",
        404 => "ページが見つかりません。",
        405 => "このURLでは受け付けていない操作です。",
        409 => "この内容では処理できません。",
        410 => "リンクの有効期限が切れています。",
        416 => "要求された範囲を返せません。",
        429 => "リクエストが多すぎます。",
        500 => "サーバーエラーが発生しました。",
        _ => "エラーが発生しました。",
    }
}

/// そのコードの英語の既定の文（Python の `HTTPStatus(code).phrase`）。Starlette は理由を渡さずに断るとこれを入れ、
/// 管理画面はそれを「理由ではない」として落とす。
pub fn default_reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        416 => "Requested Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "",
    }
}

/// エラーを JSON で返すべき相手か。Python の `wants_json`（`Accept` に application/json があり、text/html が無い）。
///
/// ブラウザの遷移は text/html を求め、fetch する側は application/json を指定する。大文字小文字はそのまま比べる。
pub fn wants_json(accept: &str) -> bool {
    accept.contains("application/json") && !accept.contains("text/html")
}

const PAGE_HEAD: &str = "<!doctype html>
<html lang=\"ja\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>";

const PAGE_STYLE: &str = r#" - DJAudio-DL</title>
<style>
  :root { color-scheme: dark light; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #10120f; color: #e9ece4;
    font-family: "Hiragino Sans", "Yu Gothic UI", "Noto Sans JP", "Meiryo", system-ui, sans-serif;
    padding: 24px;
  }
  .card {
    max-width: 420px; width: 100%; background: #181c15; border: 1px solid #2c3126;
    border-radius: 16px; padding: 32px 28px; text-align: center;
  }
  h1 { font-size: 20px; margin: 0 0 12px; }
  /* 番号は見出しと同じ行に置く。別の行に「DJAudio-DL ・ 410」と出していた
     ころは、区切りの中黒だけが浮いて見えた。
     番号と見出しの間隔は h1 の中の空白1つぶんだけで、ここでは足さない。 */
  h1 .code { font-family: ui-monospace, "SF Mono", Consolas, monospace;
              letter-spacing: .08em; color: #7fbf8f; }
  p { font-size: 14.5px; line-height: 1.7; color: #b7bfae; margin: 0; }
</style>
</head>
<body>
  <div class="card">
    <h1><span class="code">"#;

/// 配信のリンクをブラウザで開いた人に見せる案内のページ。Python の `render_link_error_page`。
///
/// `detail` が空なら「この操作を完了できませんでした。」にする（白紙を返さない）。見出しと文は HTML として逃がす。
pub fn render_link_error_page(status: u16, detail: &str) -> String {
    let title = html_escape(link_error_title(status));
    let message = html_escape(if detail.is_empty() {
        "この操作を完了できませんでした。"
    } else {
        detail
    });
    let mut page = String::with_capacity(PAGE_HEAD.len() + PAGE_STYLE.len() + 512);
    page.push_str(PAGE_HEAD);
    page.push_str(&title);
    page.push_str(PAGE_STYLE);
    page.push_str(&status.to_string());
    page.push_str("</span> ");
    page.push_str(&title);
    page.push_str("</h1>\n    <p>");
    page.push_str(&message);
    page.push_str("</p>\n  </div>\n</body>\n</html>");
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 番号と見出しが同じ行に並び、文が `<p>` に入り、外の資材も管理画面へのリンクも無いこと。
    #[test]
    fn the_page_stands_on_its_own() {
        let page = render_link_error_page(410, LINK_EXPIRED);
        assert!(page.starts_with("<!doctype html>\n<html lang=\"ja\">"));
        assert!(page.contains("<title>リンクの有効期限切れ - DJAudio-DL</title>"));
        assert!(
            page.contains("<h1><span class=\"code\">410</span> リンクの有効期限切れ</h1>\n    <p>")
        );
        assert!(page.ends_with("</p>\n  </div>\n</body>\n</html>"));
        for absent in ["<link", "<script", "/static/", "/admin/"] {
            assert!(!page.contains(absent), "{absent}");
        }
    }

    /// 文は HTML として逃がし、空なら決まった文にすること。
    #[test]
    fn the_message_is_escaped_and_never_blank() {
        let page = render_link_error_page(404, "<script>alert(1)</script>");
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!page.contains("<script>"));
        assert!(
            render_link_error_page(418, "").contains("<p>この操作を完了できませんでした。</p>")
        );
        assert!(render_link_error_page(418, "").contains("エラーが発生しました</h1>"));
    }

    /// JSON を返すのは、application/json を求めて text/html を求めない相手だけであること。
    #[test]
    fn json_is_for_fetching_clients_only() {
        assert!(wants_json("application/json"));
        assert!(!wants_json("text/html, application/json"));
        assert!(!wants_json("*/*"));
        assert!(!wants_json("Application/JSON"));
        assert!(!wants_json(""));
    }
}
