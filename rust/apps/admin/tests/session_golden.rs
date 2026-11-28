//! セッションの Cookie・秘密鍵・Python の値の扱いが、本物の Python と同じであること。
//!
//! 基準は `fixtures/session/expected.json`（generate.py が、本物の starlette・itsdangerous・管理画面の部品に例を通して
//! 作った。例は cases.json）。表ごとに、同じ入力を Rust の部品に渡して、答えをバイトまで比べる。`rust_skip` の付いた
//! 例は、Rust では違う答えになると決めたもの（理由は例に書いてある。HANDBACK にもある）。

use std::path::Path;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value, json};
use sycs_admin::app::{Reply, finish_session};
use sycs_admin::python;
use sycs_admin::secret::{self, Source};
use sycs_admin::security;
use sycs_admin::session::{self, Cookies, Session, Signer};

/// 長い値は、基準には長さと頭だけ書いてある（generate.py の LONG_VALUE）。
const LONG_VALUE: usize = 200;

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/session/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("文字ではない: {value}"))
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// 文字を latin-1 のバイトにする（基準の見出しは latin-1 で読んだ文字で書いてある）。
fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("latin-1 の外の文字"))
        .collect()
}

fn cookie_headers(values: &Value) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values.as_array().unwrap() {
        headers.append(
            HeaderName::from_static("cookie"),
            HeaderValue::from_bytes(&latin1_bytes(text(value))).unwrap(),
        );
    }
    headers
}

fn skipped(case: &Value) -> bool {
    if let Some(reason) = case["rust_skip"].as_str() {
        eprintln!("飛ばす: {}（{reason}）", case["name"]);
        return true;
    }
    false
}

fn report(wrong: &[String]) {
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// セッションの中身・秘密鍵・時刻から作った Cookie の値と、json.dumps の書き方が、Python と同じこと。
#[test]
fn cookies_are_signed_like_starlette() {
    let data = expected();
    let mut wrong = Vec::new();
    for case in data["signing"].as_array().unwrap() {
        let name = text(&case["name"]);
        let session = Session::loaded(object(&case["session"]));
        let json = python::dumps(&case["session"], python::DEFAULT);
        if json != text(&case["json"]) {
            wrong.push(format!(
                "「{name}」の JSON: Python {} / Rust {json}",
                case["json"]
            ));
        }
        let cookies = Cookies::new(text(&case["secret"]), false);
        let got = cookies.encode(&session, case["signed_at"].as_i64().unwrap());
        if got != text(&case["cookie"]) {
            wrong.push(format!(
                "「{name}」の Cookie: Python {} / Rust {got}",
                case["cookie"]
            ));
        }
    }
    for case in data["raw"].as_array().unwrap() {
        let signer = Signer::new(text(&case["secret"]));
        let payload = latin1_bytes(text(&case["payload"]));
        let signed = signer.sign(&payload, case["signed_at"].as_u64().unwrap());
        let got = String::from_utf8(signed).unwrap();
        if got != text(&case["cookie"]) {
            wrong.push(format!(
                "「{}」の Cookie: Python {} / Rust {got}",
                case["name"], case["cookie"]
            ));
        }
    }
    report(&wrong);
}

/// 操作を当てる（generate.py の _apply と同じ）。
fn apply(session: &mut Session, ops: &Value) {
    for op in ops.as_array().unwrap() {
        let op = op.as_array().unwrap();
        match text(&op[0]) {
            "access" => session.mark_accessed(),
            "set" => session.insert(text(&op[1]), op[2].clone()),
            "pop" => {
                session.pop(text(&op[1]));
            }
            "delete" => {
                session.remove(text(&op[1]));
            }
            "clear" => session.clear(),
            "setdefault" => {
                session.set_default(text(&op[1]), op[2].clone());
            }
            "update" => session.update(object(&op[1])),
            other => panic!("知らない操作: {other}"),
        }
    }
}

/// Cookie の見出しから読んだセッション（か、層の外へ抜ける壊れた中身）と、操作のあとの Vary・Set-Cookie が、
/// starlette の SessionMiddleware と同じこと。
#[test]
fn cookies_are_read_and_rewritten_like_starlette() {
    let data = expected();
    let now = data["now"].as_i64().unwrap();
    let secret = text(&data["secret"]);
    let mut wrong = Vec::new();
    let mut compared = 0;
    for case in data["reading"].as_array().unwrap() {
        if skipped(case) {
            continue;
        }
        let name = text(&case["name"]);
        let cookies = Cookies::new(secret, case["secure"].as_bool().unwrap_or(false));
        let loaded = cookies.load(&cookie_headers(&case["cookies"]), now);
        compared += 1;
        let mut session = match (loaded, case["raised"].as_str()) {
            (Err(session::Broken), Some(_)) => continue,
            (Err(session::Broken), None) => {
                wrong.push(format!("「{name}」: Python は読めたのに Rust は壊れた扱い"));
                continue;
            }
            (Ok(_), Some(raised)) => {
                wrong.push(format!(
                    "「{name}」: Python は {raised} で落ちるのに Rust は読めた"
                ));
                continue;
            }
            (Ok(session), None) => session,
        };
        let read = python::dumps(&Value::Object(session.data().clone()), python::DEFAULT);
        if read != text(&case["session_json"]) {
            wrong.push(format!(
                "「{name}」の読んだ中身: Python {} / Rust {read}",
                case["session_json"]
            ));
        }
        apply(&mut session, &case["ops"]);
        let mut reply = Reply::new(200, Some("text/plain"), b"ok".to_vec());
        finish_session(&cookies, &session, &mut reply, now);
        let got: Vec<Value> = reply
            .headers
            .iter()
            .filter(|(n, _)| n == "vary" || n == "set-cookie")
            .map(|(n, v)| json!([n, v]))
            .collect();
        if Value::Array(got.clone()) != case["headers"] {
            wrong.push(format!(
                "「{name}」の見出し:\n    Python {}\n    Rust   {}",
                case["headers"],
                json!(got)
            ));
        }
    }
    assert!(compared >= 50, "読み方の例が足りない（{compared}）");
    report(&wrong);
}

/// 秘密鍵の置き場を、generate.py の _setup_secret_case と同じに作る。
fn setup_secret(root: &Path, case: &Value) -> std::path::PathBuf {
    let settings = root.join("settings");
    match case["setup"].as_str().unwrap_or("dir") {
        "missing" => return root.join("a").join("b"),
        "file_as_settings" => {
            std::fs::write(&settings, b"x").unwrap();
            return settings;
        }
        _ => std::fs::create_dir(&settings).unwrap(),
    }
    let file = settings.join(secret::SECRET_FILENAME);
    if case["setup"].as_str() == Some("secret_dir") {
        std::fs::create_dir(&file).unwrap();
    }
    if let Some(content) = case["file_text"].as_str() {
        std::fs::write(&file, content.as_bytes()).unwrap();
    }
    if let Some(hex) = case["file_hex"].as_str() {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        std::fs::write(&file, bytes).unwrap();
    }
    settings
}

/// 秘密鍵の決め方（どこから得たか・鍵・ファイルの中身・作ったファイルの権限）が Python と同じこと。
#[test]
fn secrets_are_resolved_like_python() {
    let data = expected();
    let generated = "c0ffee".repeat(10) + "abcd";
    let mut wrong = Vec::new();
    for want in data["secrets"].as_array().unwrap() {
        let case = &want["case"];
        let name = text(&case["name"]);
        let root = tempfile::tempdir().unwrap();
        let settings = setup_secret(root.path(), case);
        let got = secret::resolve(case["env"].as_str(), &settings, || generated.clone());
        let got = match (got, want["raised"].as_str()) {
            (Err(_), Some(_)) => continue,
            (Ok(got), None) => got,
            (got, raised) => {
                wrong.push(format!(
                    "「{name}」: Python の例外 {raised:?} / Rust {got:?}"
                ));
                continue;
            }
        };
        let source = match got.source {
            Source::Env => "env",
            Source::File => "file",
            Source::Generated => "generated",
            Source::Temporary => "temporary",
        };
        if source != text(&want["source"]) {
            wrong.push(format!(
                "「{name}」の出どころ: Python {} / Rust {source}",
                want["source"]
            ));
        }
        if let Some(secret) = want["secret"].as_str()
            && secret != got.secret
        {
            wrong.push(format!(
                "「{name}」の鍵: Python {secret:?} / Rust {:?}",
                got.secret
            ));
        }
        let file = settings.join(secret::SECRET_FILENAME);
        let after = std::fs::metadata(&file)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map(|_| std::fs::read(&file).unwrap());
        let python_after = want["file_after_hex"].as_str().map(str::to_string);
        let rust_after = after.as_ref().map(|bytes| secret::hex_lower(bytes));
        match source {
            // 作った鍵は乱数なので、Python の中身とは比べない。どちらも「ファイルの中身＝返した鍵」。
            "generated" => {
                if rust_after.as_deref() != Some(secret::hex_lower(generated.as_bytes()).as_str()) {
                    wrong.push(format!("「{name}」: 作った鍵をファイルに書いていない"));
                }
                if want["file_is_the_secret"].as_bool() != Some(true) {
                    wrong.push(format!(
                        "「{name}」: Python のファイルが返した鍵と違う（{want}）"
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
                    if Some(format!("{mode:#o}").as_str()) != want["mode"].as_str() {
                        wrong.push(format!(
                            "「{name}」の権限: Python {} / Rust {mode:#o}",
                            want["mode"]
                        ));
                    }
                }
            }
            _ => {
                if python_after != rust_after {
                    wrong.push(format!(
                        "「{name}」のファイル: Python {python_after:?} / Rust {rust_after:?}"
                    ));
                }
            }
        }
        // 作った・その場限りの鍵は、Python も 64 文字の 16 進（token_hex(32)）。
        if matches!(source, "generated" | "temporary")
            && (want["length"].as_u64() != Some(64) || want["is_hex"].as_bool() != Some(true))
        {
            wrong.push(format!(
                "「{name}」: Python の鍵が 64 文字の 16 進ではない（{want}）"
            ));
        }
    }
    report(&wrong);
}

/// 長い値の書き方（generate.py の _short）。
fn short(value: &str) -> Value {
    if value.chars().count() <= LONG_VALUE {
        return json!(value);
    }
    json!({"length": value.chars().count(), "head": value.chars().take(20).collect::<String>()})
}

fn form_body(pieces: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    for piece in pieces.as_array().unwrap() {
        if let Some(hex) = piece["hex"].as_str() {
            for i in (0..hex.len()).step_by(2) {
                body.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
            }
        } else {
            let unit = latin1_bytes(text(&piece[0]));
            for _ in 0..piece[1].as_u64().unwrap() {
                body.extend_from_slice(&unit);
            }
        }
    }
    body
}

/// フォームの読み方（Content-Type の見分け・欄の分け方・戻し方・上限）が starlette の request.form() と同じこと。
#[test]
fn forms_are_read_like_starlette() {
    let data = expected();
    let mut wrong = Vec::new();
    for case in data["forms"].as_array().unwrap() {
        if skipped(case) {
            continue;
        }
        let name = text(&case["name"]);
        let mut headers = HeaderMap::new();
        if let Some(content_type) = case["content_type"].as_str() {
            headers.insert(
                "content-type",
                HeaderValue::from_bytes(&latin1_bytes(content_type)).unwrap(),
            );
        }
        let body = form_body(&case["body"]);
        match (
            security::read_form(&headers, &body),
            case["status"].as_u64(),
        ) {
            (Ok(form), None) => {
                let got: Vec<Value> = form
                    .items()
                    .iter()
                    .map(|(k, v)| json!([k, short(v)]))
                    .collect();
                if Value::Array(got.clone()) != case["items"] {
                    wrong.push(format!(
                        "「{name}」の欄: Python {} / Rust {}",
                        case["items"],
                        json!(got)
                    ));
                }
            }
            (Err(error), Some(status)) => {
                if u64::from(error.status) != status
                    || error.detail.as_deref() != case["detail"].as_str()
                {
                    wrong.push(format!(
                        "「{name}」: Python {status} {} / Rust {error:?}",
                        case["detail"]
                    ));
                }
            }
            (got, status) => wrong.push(format!(
                "「{name}」: Python の状態 {status:?} / Rust {got:?}"
            )),
        }
    }
    report(&wrong);
}

/// json.dumps の 2 つの書き方・小数の repr・base64 の緩い読み方が Python と同じこと。
#[test]
fn python_values_are_written_and_read_alike() {
    let data = expected();
    let mut wrong = Vec::new();
    for case in data["dumps"].as_array().unwrap() {
        let value = &case["value"];
        let default = python::dumps(value, python::DEFAULT);
        let compact = python::dumps(value, python::COMPACT);
        if default != text(&case["default"]) || compact != text(&case["compact"]) {
            wrong.push(format!(
                "dumps {value}: Python {} {} / Rust {default} {compact}",
                case["default"], case["compact"]
            ));
        }
    }
    for case in data["floats"].as_array().unwrap() {
        let got = python::float_repr(case["value"].as_f64().unwrap());
        if got != text(&case["repr"]) {
            wrong.push(format!(
                "repr {}: Python {} / Rust {got}",
                case["value"], case["repr"]
            ));
        }
    }
    for case in data["b64decode"].as_array().unwrap() {
        let input = latin1_bytes(text(&case["input"]));
        let standard = python::b64decode(&input, false).map(|b| secret::hex_lower(&b));
        let signed = python::itsdangerous_b64decode(&input).map(|b| secret::hex_lower(&b));
        if standard.as_deref() != case["standard"].as_str()
            || signed.as_deref() != case["itsdangerous"].as_str()
        {
            wrong.push(format!(
                "b64decode {}: Python {} {} / Rust {standard:?} {signed:?}",
                case["input"], case["standard"], case["itsdangerous"]
            ));
        }
    }
    report(&wrong);
}

/// Cookie の見出しの読み方・str(int(x))・サーバーの一覧の削り方が Python と同じこと。
#[test]
fn cookie_headers_ints_and_guilds_match_python() {
    let data = expected();
    let mut wrong = Vec::new();
    for case in data["cookie_headers"].as_array().unwrap() {
        let parsed: Vec<Value> = python::parse_cookies(&cookie_headers(&case["headers"]))
            .into_iter()
            .map(|(k, v)| json!([k, v]))
            .collect();
        if Value::Array(parsed.clone()) != case["cookies"] {
            wrong.push(format!(
                "Cookie {}: Python {} / Rust {}",
                case["headers"],
                case["cookies"],
                json!(parsed)
            ));
        }
    }
    for case in data["ints"].as_array().unwrap() {
        let got = python::int_text(&case["value"]);
        if got.as_deref() != case["text"].as_str() {
            wrong.push(format!(
                "int {}: Python {} {} / Rust {got:?}",
                case["value"], case["text"], case["raised"]
            ));
        }
    }
    for case in data["compact"].as_array().unwrap() {
        let got = session::compact_admin_guilds(Some(&case["value"]));
        if got != case["compact"] {
            wrong.push(format!(
                "compact {}: Python {} / Rust {got}",
                case["value"], case["compact"]
            ));
        }
    }
    report(&wrong);
}
