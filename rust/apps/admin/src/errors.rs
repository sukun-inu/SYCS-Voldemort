//! 断るときの形。Python の `webapp_admin/app.py` の例外の係（`_http_exception_response`・`_error_response`・
//! `rate_limit_handler`・`needs_login_handler`・`needs_guild_handler`）と、FastAPI の 422。
//!
//! 経路の係は [`Failure`] を返す。層（[`crate::app`]）がそれを答えにする:
//!
//! | 失敗 | 答え |
//! |---|---|
//! | [`Failure::NeedsLogin`] | 303 `/admin/login` |
//! | [`Failure::NeedsGuild`] | 303 `/admin/guilds` |
//! | [`Failure::Http`] | コードごとの日本語の文 ＋ 理由（[`message`]。JSON か HTML） |
//! | [`Failure::RateLimited`] | 429「リクエストが多すぎます。しばらく待ってから再試行してください。」 |
//! | [`Failure::Validation`] | 422 `{"detail": [...]}`（経路の種類に関係なく JSON） |
//! | [`Failure::Crash`] | 拾えなかった例外（インシデントと `exceptions_total`、500） |
//!
//! JSON にする相手: `request.url.path` が `/admin/api/` で始まるか、`Accept` に `application/json` があって
//! `text/html` が無いとき（[`wants_json`]）。HTML のページ（`error.html`）の中身は A2 が描く（[`Pages`]）。

use serde_json::Value;

use crate::session::Session;

/// 拾えなかった例外の文（`_unhandled_request_response`）。
pub const SERVER_ERROR: &str = "サーバーエラーが発生しました。";
/// 回数の制限を超えたときの文（`rate_limit_handler`。デコレータの付いた経路）。
pub const RATE_LIMITED: &str = "リクエストが多すぎます。しばらく待ってから再試行してください。";

/// コードごとの日本語の文。`_http_exception_response` の `msgs`（無いコードは「エラーが発生しました。」）。
pub fn message(status: u16) -> &'static str {
    match status {
        400 => "不正なリクエストです。",
        403 => "アクセス権限がありません。",
        404 => "ページが見つかりません。",
        405 => "このURLでは受け付けていない操作です。",
        409 => "この内容では処理できません。",
        410 => "リンクの有効期限が切れています。",
        416 => "要求された範囲を返せません。",
        429 => "リクエストが多すぎます。",
        500 => SERVER_ERROR,
        _ => "エラーが発生しました。",
    }
}

/// そのコードの英語の既定の文（Python 3.13 の `http.HTTPStatus(code).phrase`。無いコードは空）。
///
/// starlette は理由を渡さずに `HTTPException` を投げるとこれを理由に入れ、管理画面はそれを「理由ではない」として落とす。
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// エラーを JSON で返すべき相手か。Python の `services/djaudio_cdn.wants_json`（`Accept` に application/json があり、
/// text/html が無い。大文字小文字はそのまま比べる）。
pub fn wants_json(accept: &str) -> bool {
    accept.contains("application/json") && !accept.contains("text/html")
}

/// 拾えなかった例外（Python の例外の型の名前と `str(exc)`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crash {
    /// 型の名前（`RuntimeError` など。`exceptions_total{type}` とインシデントの見出しになる）。
    pub kind: String,
    /// `str(exc)`。
    pub message: String,
}

impl Crash {
    /// 作る。
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

/// starlette の `HTTPException`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpError {
    /// 状態。
    pub status: u16,
    /// 理由（文字でない理由は `None`。管理画面は文字の理由だけを見る）。
    pub detail: Option<String>,
    /// 見出し（JSON で返すときだけ付く。名前は小文字）。
    pub headers: Vec<(String, String)>,
}

impl HttpError {
    /// 理由を渡さずに投げたもの（starlette が英語の既定の文を理由に入れる）。
    pub fn new(status: u16) -> Self {
        let phrase = reason_phrase(status);
        Self {
            status,
            detail: (!phrase.is_empty()).then(|| phrase.to_string()),
            headers: Vec::new(),
        }
    }

    /// 理由を付けて投げたもの。
    pub fn with_detail(status: u16, detail: &str) -> Self {
        Self {
            status,
            detail: Some(detail.to_string()),
            headers: Vec::new(),
        }
    }

    /// 文字でない理由（辞書など）を付けて投げたもの（管理画面は理由として見ない）。
    pub fn without_text(status: u16) -> Self {
        Self {
            status,
            detail: None,
            headers: Vec::new(),
        }
    }

    /// 見出しを足す（`HTTPException(headers=…)`）。
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
        self
    }
}

/// 経路の係が断るときに返すもの。
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    /// ログインが要る（`_NeedsLogin`）。
    NeedsLogin,
    /// サーバーを選んでいない（`_NeedsGuild`）。
    NeedsGuild,
    /// `HTTPException`。
    Http(HttpError),
    /// デコレータの付いた経路で回数を超えた（slowapi の `RateLimitExceeded`）。
    RateLimited,
    /// パラメータの検証に落ちた（FastAPI の `RequestValidationError`。pydantic の形の並び）。
    Validation(Vec<Value>),
    /// 拾えなかった例外。
    Crash(Crash),
}

impl From<HttpError> for Failure {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<Crash> for Failure {
    fn from(crash: Crash) -> Self {
        Self::Crash(crash)
    }
}

/// エラーのページ（`error.html`）に渡すもの。Python の `render(request, "error.html", code=…, message=…,
/// description=…)` の文脈。
#[derive(Debug)]
pub struct ErrorPage<'a> {
    /// 状態（`code`）。
    pub code: u16,
    /// 見出しの文（`message`）。
    pub message: &'a str,
    /// 補足（`description`。理由が文と違うときだけ）。
    pub description: Option<&'a str>,
    /// 取り出した知らせ（`messages`。セッションの `_flashes` の並び）。
    pub messages: &'a Value,
    /// CSRF の印（`csrf_token`）。
    pub csrf_token: &'a str,
    /// 描くときのセッション（`session`。知らせを取り出し、印を入れたあと）。
    pub session: &'a Session,
    /// `Sec-Fetch-Dest: iframe` か（`is_embedded`）。
    pub is_embedded: bool,
}

/// HTML のページを描くもの（テンプレートは A2 が minijinja で描く。ここは差し込み口）。
pub trait Pages: Send + Sync {
    /// エラーのページ（`error.html`）。
    fn error_page(&self, page: &ErrorPage<'_>) -> String;
}

/// A2 のテンプレートが入るまでの仮のページ。Python の `error.html` とは中身が違う（基準の比べ方も、HTML の本文と
/// 大きさは A2 で比べる）。
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainPages;

impl Pages for PlainPages {
    fn error_page(&self, page: &ErrorPage<'_>) -> String {
        let description = page
            .description
            .map(|text| format!("<p>{}</p>", crate::python::html_escape(text)))
            .unwrap_or_default();
        format!(
            "<!doctype html>\n<html lang=\"ja\">\n<head><meta charset=\"utf-8\"><title>{code}</title></head>\n\
             <body><h1>{code} {message}</h1>{description}</body>\n</html>",
            code = page.code,
            message = crate::python::html_escape(page.message),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 理由を渡さない HTTPException は英語の既定の文を持ち、知らないコードは空になること。
    #[test]
    fn exceptions_without_a_reason_carry_the_english_phrase() {
        assert_eq!(HttpError::new(404).detail.as_deref(), Some("Not Found"));
        assert_eq!(HttpError::new(418).detail.as_deref(), Some("I'm a Teapot"));
        assert_eq!(HttpError::new(499).detail, None);
        assert_eq!(
            HttpError::new(405).header("Allow", "GET").headers,
            vec![("allow".to_string(), "GET".to_string())]
        );
    }

    /// 日本語の文は表に無いコードで「エラーが発生しました。」になること。JSON にする相手の見分け方。
    #[test]
    fn messages_and_json_clients() {
        assert_eq!(message(418), "エラーが発生しました。");
        assert_eq!(message(500), SERVER_ERROR);
        assert!(wants_json("application/json"));
        assert!(!wants_json("text/html, application/json"));
        assert!(!wants_json("Application/JSON"));
        assert!(!wants_json("*/*"));
    }
}
