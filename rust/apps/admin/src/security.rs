//! 4 つの確かめと CSRF の印。Python の `webapp_admin/security.py`（`check_login`・`check_guild`・`check_csrf`・
//! `issue_csrf_token`・`is_dev_user`・`dev_user_id`）と `webapp_admin/api/dev.py` の `check_dev`。
//!
//! | 確かめ | 通さないとき |
//! |---|---|
//! | [`check_login`] | セッションに `user` が無い → 303 `/admin/login` |
//! | [`check_guild`] | `user` が無い → 303 `/admin/login`。`guild_id` が無い → 303 `/admin/guilds` |
//! | [`check_dev`] | `DEV_USER_ID` が空 → 404。`user` が偽 → 303。`str(user["id"])` が違う → 403「開発者専用です。」 |
//! | [`check_csrf`] | POST・PUT・PATCH・DELETE で、ログイン中なのに、フォームの `csrf_token` も見出し `X-CSRFToken` も セッションの `_csrf_token` と合わない → 403。未ログインは素通し |
//!
//! 経路の係は、Python の `Depends` の書いた順に呼ぶ。**パラメータの検証（422）とデコレータの回数の制限は、確かめの
//! あと**（FastAPI は確かめが通ってから検証の誤りを投げ、デコレータは確かめが通ってから係の中で数える）。
//!
//! フォームは starlette の `request.form()` と同じに読む（`application/x-www-form-urlencoded` だけ。[`read_form`]）。
//! Python と違うところ: `multipart/form-data` は読まない（Python は読む）。管理画面の画面はどれも
//! urlencoded か JSON ＋ 見出しで送るので、multipart で印を送ってくる相手はいない。読まないので、multipart で印だけを
//! 送ったものは 403 になる（安全な側に外れる）。

use axum::http::{HeaderMap, Method};
use serde_json::Value;

use crate::errors::{Crash, Failure, HttpError};
use crate::python;
use crate::session::{Session, constant_time_eq};

/// 開発者でない人への 403 の理由（`check_dev`）。
pub const DEV_ONLY: &str = "開発者専用です。";
/// starlette のフォームの上限（`max_fields`）。
pub const MAX_FIELDS: usize = 1000;
/// starlette のフォームの 1 つの欄の上限（`max_part_size`。名前と値の生のバイトの合計）。
pub const MAX_PART_SIZE: usize = 1024 * 1024;

/// `check_login`。
pub fn check_login(session: &Session) -> Result<(), Failure> {
    if session.contains_key("user") {
        Ok(())
    } else {
        Err(Failure::NeedsLogin)
    }
}

/// `check_guild`（いまも管理者かは見ない）。
pub fn check_guild(session: &Session) -> Result<(), Failure> {
    check_login(session)?;
    if session.contains_key("guild_id") {
        Ok(())
    } else {
        Err(Failure::NeedsGuild)
    }
}

/// `is_dev_user`。`DEV_USER_ID`（前後の空白を落としたもの）が空なら偽。`user` が偽なら `{}` として見る。
///
/// `user` が辞書でないのに偽でもないとき（文字など）、Python は `.get` で `AttributeError` になる。
pub fn is_dev_user(session: &Session, dev_user_id: &str) -> Result<bool, Crash> {
    if dev_user_id.is_empty() {
        return Ok(false);
    }
    let user = session.get("user").filter(|user| python::truthy(user));
    let id = match user {
        None => String::new(),
        Some(Value::Object(user)) => user.get("id").map(python::str_of).unwrap_or_default(),
        Some(other) => {
            return Err(Crash::new(
                "AttributeError",
                format!(
                    "'{}' object has no attribute 'get'",
                    python::type_name(other)
                ),
            ));
        }
    };
    Ok(id == dev_user_id)
}

/// `check_dev`。通れば `session["user"]` を返す。
pub fn check_dev(session: &Session, dev_user_id: &str) -> Result<Value, Failure> {
    if dev_user_id.is_empty() {
        return Err(HttpError::new(404).into());
    }
    let Some(user) = session.get("user").filter(|user| python::truthy(user)) else {
        return Err(Failure::NeedsLogin);
    };
    let user = user.clone();
    if !is_dev_user(session, dev_user_id)? {
        return Err(HttpError::with_detail(403, DEV_ONLY).into());
    }
    Ok(user)
}

/// `issue_csrf_token`。セッションの印が偽なら `token()` で作って入れ、印（`str()` したもの）を返す。
pub fn issue_csrf_token(session: &mut Session, token: impl FnOnce() -> String) -> String {
    match session.get("_csrf_token") {
        Some(existing) if python::truthy(existing) => python::str_of(existing),
        _ => {
            let fresh = token();
            session.insert("_csrf_token", Value::String(fresh.clone()));
            fresh
        }
    }
}

/// `check_csrf`。フォームは `body` から読む（読めなければ 400）。
pub fn check_csrf(
    method: &Method,
    session: &Session,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Failure> {
    if !matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return Ok(());
    }
    if !session.contains_key("user") {
        return Ok(());
    }
    let form = read_form(headers, body)?;
    // `form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")`。
    let token = match form.get("csrf_token") {
        Some(value) if !value.is_empty() => value.to_string(),
        _ => first_header(headers, "x-csrftoken").unwrap_or_default(),
    };
    let forbidden = || Failure::Http(HttpError::new(403));
    let Some(expected) = session.get("_csrf_token").filter(|v| python::truthy(v)) else {
        return Err(forbidden());
    };
    if token.is_empty() {
        return Err(forbidden());
    }
    // `secrets.compare_digest(token, expected)`。
    let Value::String(expected) = expected else {
        return Err(Crash::new(
            "TypeError",
            format!(
                "unsupported operand types(s) or combination of types: 'str' and '{}'",
                python::type_name(expected)
            ),
        )
        .into());
    };
    if !token.is_ascii() || !expected.is_ascii() {
        return Err(Crash::new(
            "TypeError",
            "comparing strings with non-ASCII characters is not supported",
        )
        .into());
    }
    if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// その名前の最初の見出し（latin-1 として読む。starlette の `request.headers.get`）。
pub fn first_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|value| python::latin1(value.as_bytes()))
}

/// 読んだフォーム（starlette の `FormData`。同じ名前が並べば、`get` は最後のもの）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Form {
    items: Vec<(String, String)>,
}

impl Form {
    /// 欄の並び（来た順）。
    pub fn items(&self) -> &[(String, String)] {
        &self.items
    }

    /// その名前の最後の値。
    pub fn get(&self, name: &str) -> Option<&str> {
        self.items
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// `Content-Type` の種類。python-multipart 0.0.34（requirements.txt の版）の `parse_options_header` の答え。
///
/// `;` が無ければ小文字にして前後の空白とタブを落とす。あれば最初の `;` まで（`_parseparam` の最初の区切り）の前後の
/// 空白とタブを落として小文字にする。**どちらも小文字にする**（種類は大文字小文字を区別しない。0.0.32 までは `;` の
/// あるときに小文字にしなかった）。落とすのは空白とタブだけ（ほかの空白の文字は残る）。見出しが無ければ空。
pub fn content_type(headers: &HeaderMap) -> String {
    const BLANK: [char; 2] = [' ', '\t'];
    let Some(value) = first_header(headers, "content-type").filter(|v| !v.is_empty()) else {
        return String::new();
    };
    if !value.contains(';') {
        return value.to_lowercase().trim_matches(BLANK).to_string();
    }
    let first = first_segment(&value);
    let first = match first.split_once('=') {
        // `=` を含む最初の区切り（種類の形ではない）。
        Some((key, rest)) => format!(
            "{}={}",
            key.trim_end_matches(BLANK).to_lowercase(),
            rest.trim_start_matches(BLANK)
        ),
        None => first,
    };
    first.trim_matches(BLANK).to_lowercase()
}

/// python-multipart の `_parseparam` の最初の区切り（`"` の中の `;` は区切りにしない。Python の書き方のまま写した）。
fn first_segment(value: &str) -> String {
    let s: Vec<char> = std::iter::once(';').chain(value.chars()).collect();
    let len = s.len() as isize;
    let start: isize = 1;
    let mut end = find(&s, ';', start);
    let (mut ind, mut diff) = (start, 0isize);
    while end > 0 {
        diff += count(&s, "\"", ind, end) - count(&s, "\\\"", ind, end);
        if diff % 2 == 0 {
            break;
        }
        let next = find(&s, ';', end + 1);
        end = ind;
        ind = next;
    }
    if end < 0 {
        end = len;
    }
    let (from, to) = (
        usize::try_from(start).unwrap_or(0),
        usize::try_from(end).unwrap_or(0),
    );
    if from >= to {
        return String::new();
    }
    s[from..to].iter().collect()
}

/// Python の `s.find(c, start)`（見つからなければ -1）。
fn find(s: &[char], c: char, start: isize) -> isize {
    let start = usize::try_from(start.max(0)).unwrap_or(0);
    s.iter()
        .skip(start)
        .position(|x| *x == c)
        .map_or(-1, |i| isize::try_from(start + i).unwrap_or(-1))
}

/// Python の `s.count(sub, start, end)`（負の位置は後ろから数え、重ならないように数える）。
fn count(s: &[char], sub: &str, start: isize, end: isize) -> isize {
    let len = s.len() as isize;
    let clamp = |i: isize| {
        let i = if i < 0 { i + len } else { i };
        i.clamp(0, len)
    };
    let (from, to) = (clamp(start), clamp(end));
    if from >= to {
        return 0;
    }
    let window: String = s[usize::try_from(from).unwrap_or(0)..usize::try_from(to).unwrap_or(0)]
        .iter()
        .collect();
    isize::try_from(window.matches(sub).count()).unwrap_or(0)
}

/// `request.form()`。`application/x-www-form-urlencoded` なら欄を読み、ほかの種類は空のフォーム。
///
/// 欄は `&` で区切り（空の区切りは飛ばす）、最初の `=` で名前と値に分け（無ければ値は空）、どちらも latin-1 で
/// 読んでから `unquote_plus`（[`python::form_unquote`]）。欄が 1000 を超える・1 つの欄が 1MB を超えると 400
/// （理由は python-multipart の文）。
pub fn read_form(headers: &HeaderMap, body: &[u8]) -> Result<Form, HttpError> {
    if content_type(headers) != "application/x-www-form-urlencoded" {
        return Ok(Form::default());
    }
    let mut items = Vec::new();
    for field in body.split(|b| *b == b'&').filter(|field| !field.is_empty()) {
        let (name, value) = match field.iter().position(|b| *b == b'=') {
            Some(i) => (&field[..i], &field[i + 1..]),
            None => (field, &field[field.len()..]),
        };
        if name.len() + value.len() > MAX_PART_SIZE {
            return Err(HttpError::with_detail(
                400,
                &format!("Field exceeded maximum size of {}KB.", MAX_PART_SIZE / 1024),
            ));
        }
        items.push((python::form_unquote(name), python::form_unquote(value)));
        if items.len() > MAX_FIELDS {
            return Err(HttpError::with_detail(
                400,
                &format!("Too many fields. Maximum number of fields is {MAX_FIELDS}."),
            ));
        }
    }
    Ok(Form { items })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn session(value: Value) -> Session {
        Session::loaded(value.as_object().unwrap().clone())
    }

    fn form_headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_str(content_type).unwrap());
        headers
    }

    /// check_login は鍵があるかだけ、check_dev は user が偽かを見ること（{"user": {}} の違い）。
    #[test]
    fn login_and_dev_checks_differ_on_an_empty_user() {
        let empty_user = session(json!({"user": {}}));
        assert_eq!(check_login(&empty_user), Ok(()));
        assert_eq!(check_guild(&empty_user), Err(Failure::NeedsGuild));
        assert_eq!(check_dev(&empty_user, "1"), Err(Failure::NeedsLogin));
        assert_eq!(check_dev(&empty_user, ""), Err(HttpError::new(404).into()));
        let dev = session(json!({"user": {"id": 1.0}}));
        assert_eq!(check_dev(&dev, "1.0"), Ok(json!({"id": 1.0})));
        assert_eq!(
            check_dev(&dev, "1"),
            Err(HttpError::with_detail(403, DEV_ONLY).into())
        );
        let text_user = session(json!({"user": "x"}));
        assert_eq!(
            check_dev(&text_user, "1"),
            Err(Crash::new("AttributeError", "'str' object has no attribute 'get'").into())
        );
    }

    /// CSRF: 未ログインと GET は素通し、フォームの値が空なら見出し、型や ASCII の違いは例外になること。
    #[test]
    fn csrf_is_checked_like_python() {
        let logged_in = session(json!({"user": {"id": "1"}, "_csrf_token": TOKEN}));
        let mut headers = form_headers("application/x-www-form-urlencoded");
        let post = Method::POST;
        assert_eq!(check_csrf(&Method::GET, &logged_in, &headers, b""), Ok(()));
        assert_eq!(
            check_csrf(&post, &session(json!({})), &headers, b""),
            Ok(())
        );
        let good = format!("csrf_token={TOKEN}");
        assert_eq!(
            check_csrf(&post, &logged_in, &headers, good.as_bytes()),
            Ok(())
        );
        headers.insert("x-csrftoken", HeaderValue::from_static(TOKEN));
        assert_eq!(
            check_csrf(&post, &logged_in, &headers, b"csrf_token="),
            Ok(())
        );
        assert_eq!(
            check_csrf(&post, &logged_in, &headers, b"csrf_token=bad"),
            Err(HttpError::new(403).into())
        );
        assert!(matches!(
            check_csrf(&post, &logged_in, &headers, b"csrf_token=%C3%A9"),
            Err(Failure::Crash(crash)) if crash.kind == "TypeError"
        ));
        let numeric = session(json!({"user": {"id": "1"}, "_csrf_token": 5}));
        assert!(matches!(
            check_csrf(&post, &numeric, &headers, b""),
            Err(Failure::Crash(crash)) if crash.message.ends_with("'str' and 'int'")
        ));
    }

    /// Content-Type は ; の有無に関係なく小文字にし（大文字の種類に引数が付いてもフォームとして読む）、前後の空白と
    /// タブだけを落とすこと（python-multipart 0.0.34）。
    #[test]
    fn the_content_type_is_read_like_python_multipart() {
        assert_eq!(
            content_type(&form_headers("APPLICATION/X-WWW-FORM-URLENCODED")),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            content_type(&form_headers(
                "Application/X-WWW-Form-Urlencoded; charset=utf-8"
            )),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            content_type(&form_headers(" \tapplication/x-www-form-urlencoded\t ; a=b")),
            "application/x-www-form-urlencoded"
        );
        let mut nbsp = HeaderMap::new();
        nbsp.insert(
            "content-type",
            HeaderValue::from_bytes(b"\xa0application/x-www-form-urlencoded").unwrap(),
        );
        assert_eq!(content_type(&nbsp), "\u{a0}application/x-www-form-urlencoded");
        assert_eq!(content_type(&form_headers("A\";B\"; c=d")), "a\";b\"");
        assert_eq!(content_type(&HeaderMap::new()), "");
    }

    /// フォームの欄の読み方（空の区切り・= の無い欄・+ と %XX・最後の値・上限）。
    #[test]
    fn forms_are_read_like_starlette() {
        let headers = form_headers("application/x-www-form-urlencoded");
        let form = read_form(&headers, b"&&a=1&b&c=x+y%21&a=2&=v").unwrap();
        assert_eq!(form.get("a"), Some("2"));
        assert_eq!(form.get("b"), Some(""));
        assert_eq!(form.get("c"), Some("x y!"));
        assert_eq!(form.get(""), Some("v"));
        let many = "a=1&".repeat(MAX_FIELDS + 1);
        assert_eq!(
            read_form(&headers, many.as_bytes()).unwrap_err().status,
            400
        );
        assert!(read_form(&headers, "a=1&".repeat(MAX_FIELDS).as_bytes()).is_ok());
        let big = format!("a={}", "x".repeat(MAX_PART_SIZE));
        assert_eq!(
            read_form(&headers, big.as_bytes())
                .unwrap_err()
                .detail
                .as_deref(),
            Some("Field exceeded maximum size of 1024KB.")
        );
        assert!(
            read_form(&form_headers("application/json"), b"a=1")
                .unwrap()
                .items()
                .is_empty()
        );
    }

    /// 印は無ければ作って入れ（書き換えた印が立つ）、あればそれを返すこと。
    #[test]
    fn tokens_are_issued_once() {
        let mut fresh = Session::new();
        assert_eq!(issue_csrf_token(&mut fresh, || "t1".to_string()), "t1");
        assert!(fresh.modified());
        assert_eq!(issue_csrf_token(&mut fresh, || "t2".to_string()), "t1");
        let mut empty = session(json!({"_csrf_token": ""}));
        assert_eq!(issue_csrf_token(&mut empty, || "t3".to_string()), "t3");
    }
}
