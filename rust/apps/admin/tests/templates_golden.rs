//! テンプレート（`sycs_admin::templates`）が、本物の Python（Jinja2・markupsafe と `webapp_admin/templating.py`）と
//! バイトまで同じ HTML を書くこと。
//!
//! 基準は `fixtures/templates/expected.json`（generate.py が本物の Python から作った。例は cases.json）。テンプレートの
//! ファイルは Python と同じもの（リポジトリの `webapp_admin/templates/`）を読む。static は、基準に書いてある大きさ・
//! 更新時刻・リンクのとおりに一時ディレクトリへ作り直す（Python も同じものを作って描いた）。
//!
//! - functions: `admin_asset_url`・`icon`・`url_for`・招待リンク・エスケープ・小数の形
//! - snippets: 短いテンプレートの文字（minijinja と Jinja2 の違いを 1 つずつ）
//! - pages: `render` を直に呼んだもの（本文・描いたあとのセッション・CSRF の印を作った回数）
//! - cases: 本物の管理画面の経路が返した本文と、Set-Cookie から読んだセッション。経路の値（招待リンク・サーバー数・
//!   エラーの文言）は例に書いてあるものを、ページの関数に渡す。状態のコード・見出しの全部は、経路をつないでから比べる

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value};
use sycs_admin::templates::globals::{Assets, DEFAULT_ASSET_VERSION, icon_markup, url_for};
use sycs_admin::templates::markup::{markupsafe_escape, python_float_repr};
use sycs_admin::templates::{
    HTML_CONTENT_TYPE, Page, Pages, PagesConfig, TEMPLATE_NAMES, Visit, document_for_path,
    invite_url, is_embedded, legacy_public_redirect,
};

fn expected() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/templates/expected.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "基準が読めません（{path}）: {e}。CI の「基準」が作ったものを取ってきてコミットすること"
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn repository_templates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../webapp_admin/templates")
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map(Vec::as_slice).unwrap_or_default()
}

/// 基準の static を、Python（generate.py の `_make_static`）と同じに作り直す。返すのは static のパス。
fn build_static(spec: &Value, base: &Path) -> PathBuf {
    let root = base.join("static");
    std::fs::create_dir_all(&root).unwrap();
    let default_mtime = spec["mtime_ns"].as_u64().unwrap();
    let mut placed: Vec<(PathBuf, u64)> = Vec::new();
    for (dir, key) in [(root.clone(), "files"), (base.to_path_buf(), "outside")] {
        for item in items(spec, key) {
            let path = dir.join(item["path"].as_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let size = usize::try_from(item["size"].as_u64().unwrap()).unwrap();
            std::fs::write(&path, vec![b'x'; size]).unwrap();
            placed.push((path, item["mtime_ns"].as_u64().unwrap_or(default_mtime)));
        }
    }
    for item in items(spec, "symlinks") {
        let link = root.join(item["path"].as_str().unwrap());
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(item["target"].as_str().unwrap(), link).unwrap();
    }
    for (path, mtime) in placed {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(UNIX_EPOCH + Duration::from_nanos(mtime))
            .unwrap();
    }
    root
}

/// 基準と、それに合わせて作った static（一時ディレクトリは、この値が生きているあいだ残る）。
struct Fixture {
    _dir: tempfile::TempDir,
    static_dir: PathBuf,
    data: Value,
}

fn fixture() -> Fixture {
    let data = expected();
    let dir = tempfile::tempdir().unwrap();
    let static_dir = build_static(&data["static"], dir.path());
    Fixture {
        _dir: dir,
        static_dir,
        data,
    }
}

fn pages_for(static_dir: &Path, version: Option<&str>) -> Pages {
    let config = PagesConfig {
        templates_dir: repository_templates(),
        static_dir: static_dir.to_path_buf(),
        asset_version: version.unwrap_or(DEFAULT_ASSET_VERSION).to_string(),
    };
    Pages::load(&config).unwrap_or_else(|e| panic!("テンプレートを読めません: {e}"))
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// `[[名前, 値], …]` の見出しから 1 つ引く。
fn pair_value<'a>(pairs: &'a Value, name: &str) -> Option<&'a str> {
    for pair in pairs.as_array()? {
        if pair[0].as_str() == Some(name) {
            return pair[1].as_str();
        }
    }
    None
}

/// Python が CSRF の印を作った回数（`token_hex` の呼び出しの数）。
fn issued_in(calls: &Value) -> usize {
    calls
        .as_array()
        .map(|calls| {
            calls
                .iter()
                .filter(|call| call["fn"] == "token_hex")
                .count()
        })
        .unwrap_or_default()
}

/// 描く。CSRF の印は基準の issued_token を返し、作った回数を数える。
fn draw<E: std::fmt::Display>(
    session: &mut Map<String, Value>,
    embedded: bool,
    token: &str,
    render: impl FnOnce(&mut Visit<'_>) -> Result<String, E>,
) -> (Result<String, String>, usize) {
    let mut issued = 0;
    let mut new_token = || {
        issued += 1;
        token.to_string()
    };
    let result = {
        let mut visit = Visit {
            session,
            is_embedded: embedded,
            new_csrf_token: &mut new_token,
        };
        render(&mut visit).map_err(|e| e.to_string())
    };
    (result, issued)
}

/// 本文・セッション（鍵の並びまで）・印を作った回数を比べ、違うところを並べる。
fn compare(
    label: &str,
    body: &Result<String, String>,
    want_body: &Value,
    session: &Map<String, Value>,
    want_session: &Value,
    issued: usize,
    want_issued: usize,
) -> Vec<String> {
    let mut wrong = Vec::new();
    match (body, want_body.as_str()) {
        (Ok(got), Some(want)) if got == want => {}
        (Ok(got), Some(want)) => wrong.push(format!(
            "{label}: 本文が違う（{}）\n    Python {want:?}\n    Rust   {got:?}",
            first_difference(want, got)
        )),
        (Err(e), _) => wrong.push(format!("{label}: Rust が描けない: {e}")),
        (Ok(_), None) => wrong.push(format!("{label}: 基準に本文が無い")),
    }
    let got_session = serde_json::to_string(session).unwrap();
    let want_session = serde_json::to_string(want_session).unwrap();
    if got_session != want_session {
        wrong.push(format!(
            "{label}: 描いたあとのセッションが違う\n    Python {want_session}\n    Rust   {got_session}"
        ));
    }
    if issued != want_issued {
        wrong.push(format!(
            "{label}: CSRF の印を作った回数が違う（Python {want_issued} / Rust {issued}）"
        ));
    }
    wrong
}

/// 最初に違う文字のあたり（長い HTML のどこが違うかを読むため）。
fn first_difference(want: &str, got: &str) -> String {
    let at = want
        .chars()
        .zip(got.chars())
        .take_while(|(a, b)| a == b)
        .count();
    let around = |text: &str| -> String { text.chars().skip(at.saturating_sub(40)).take(80).collect() };
    format!(
        "{at} 文字目から。Python …{:?}… / Rust …{:?}…",
        around(want),
        around(got)
    )
}

fn finish(wrong: &[String]) {
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// テンプレートの関数を直に呼んだ答えが、Python と同じであること。
#[test]
fn functions_answer_like_python() {
    let fx = fixture();
    let functions = &fx.data["functions"];
    let mut wrong = Vec::new();

    let assets_cases = items(functions, "admin_asset_url");
    assert!(assets_cases.len() >= 20, "admin_asset_url の例が足りない");
    for item in assets_cases {
        let filename = item["filename"].as_str().unwrap();
        let version = item["asset_version"]
            .as_str()
            .unwrap_or(DEFAULT_ASSET_VERSION);
        let got = Assets::new(&fx.static_dir, version).url(filename);
        if Some(got.as_str()) != item["url"].as_str() {
            wrong.push(format!(
                "admin_asset_url({filename:?}, 版 {version:?}): Python {} / Rust {got:?}",
                item["url"]
            ));
        }
    }

    for item in items(functions, "icon") {
        let name = item["name"].as_str().unwrap();
        let css_class = item["css_class"].as_str().unwrap_or("icon");
        let got = icon_markup(name, css_class);
        if Some(got.as_str()) != item["markup"].as_str() {
            wrong.push(format!(
                "icon({name:?}, {css_class:?}): Python {} / Rust {got:?}",
                item["markup"]
            ));
        }
    }

    for item in items(functions, "url_for") {
        let name = item["name"].as_str().unwrap();
        let params: Vec<(String, String)> = items(item, "params")
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_string(),
                    pair[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let got = url_for(name, &params);
        if Some(got.as_str()) != item["path"].as_str() {
            wrong.push(format!(
                "url_for({name:?}, {params:?}): Python {} / Rust {got:?}",
                item["path"]
            ));
        }
    }

    for item in items(functions, "invite_url") {
        let client_id = item["client_id"].as_str().unwrap();
        let got = invite_url(client_id);
        if got.as_deref() != item["url"].as_str() {
            wrong.push(format!(
                "招待リンク（{client_id:?}）: Python {} / Rust {got:?}",
                item["url"]
            ));
        }
    }

    for item in items(functions, "escape") {
        let text = item["text"].as_str().unwrap();
        let got = markupsafe_escape(text);
        if Some(got.as_str()) != item["escaped"].as_str() {
            wrong.push(format!(
                "escape({text:?}): Python {} / Rust {got:?}",
                item["escaped"]
            ));
        }
    }

    for item in items(functions, "float_repr") {
        let number = item["number"].as_f64().unwrap();
        let got = python_float_repr(number);
        if Some(got.as_str()) != item["text"].as_str() {
            wrong.push(format!(
                "str({number:?}): Python {} / Rust {got:?}",
                item["text"]
            ));
        }
    }
    finish(&wrong);
}

/// 短いテンプレートの文字を描いた答えが、Jinja2 と同じであること（minijinja との違いを 1 つずつ）。
#[test]
fn snippets_render_like_jinja2() {
    let fx = fixture();
    let pages = pages_for(&fx.static_dir, None);
    let snippets = items(&fx.data, "snippets");
    assert!(snippets.len() >= 20, "snippets の例が足りない");
    let mut wrong = Vec::new();
    for snippet in snippets {
        let name = snippet["name"].as_str().unwrap();
        let source = snippet["source"].as_str().unwrap();
        let want = snippet["body"].as_str().unwrap();
        match pages.render_source(source, &snippet["context"]) {
            Ok(got) if got == want => {}
            Ok(got) => wrong.push(format!(
                "「{name}」 {source:?}:\n    Jinja2   {want:?}\n    minijinja {got:?}"
            )),
            Err(e) => wrong.push(format!("「{name}」 {source:?}: minijinja が描けない: {e}")),
        }
    }
    finish(&wrong);
}

/// `render` を直に呼んだ答え（本文・描いたあとのセッション・印を作った回数）が、Python と同じであること。
#[test]
fn pages_render_like_python() {
    let fx = fixture();
    let token = fx.data["issued_token"].as_str().unwrap();
    let mut by_version: HashMap<Option<String>, Pages> = HashMap::new();
    let cases = items(&fx.data, "pages");
    assert!(cases.len() >= 15, "pages の例が足りない");
    let mut wrong = Vec::new();
    for item in cases {
        let name = item["name"].as_str().unwrap();
        let template = item["template"].as_str().unwrap();
        let version = item["asset_version"].as_str();
        let pages: &Pages = by_version
            .entry(version.map(str::to_string))
            .or_insert_with(|| pages_for(&fx.static_dir, version));
        let page = Page::from_template(template)
            .unwrap_or_else(|| panic!("「{name}」: 知らないテンプレート {template}"));
        if item["content_type"].as_str() != Some(HTML_CONTENT_TYPE) {
            wrong.push(format!("「{name}」: Content-Type が {}", item["content_type"]));
        }
        let mut session = object(&item["session"]);
        let embedded = is_embedded(pair_value(&item["headers"], "sec-fetch-dest"));
        let ctx = object(&item["ctx"]);
        let (body, issued) = draw(&mut session, embedded, token, |visit| {
            pages.render(page, visit, ctx)
        });
        wrong.extend(compare(
            &format!("「{name}」（{template}）"),
            &body,
            &item["body"],
            &session,
            &item["session_after"],
            issued,
            issued_in(&item["calls"]),
        ));
    }
    finish(&wrong);
}

/// 本物の管理画面の経路が返した本文と描いたあとのセッションを、ページの関数が同じに作ること。
#[test]
fn routes_render_like_python() {
    let fx = fixture();
    let pages = pages_for(&fx.static_dir, None);
    let invite = invite_url(fx.data["client_id"].as_str().unwrap());
    let token = fx.data["issued_token"].as_str().unwrap();
    let cases = items(&fx.data, "cases");
    assert!(cases.len() >= 25, "cases の例が足りない");
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let spec = &case["page"];
        let response = &case["response"];
        let status = response["status"].as_u64().unwrap();
        let target = case["request"]["target"].as_str().unwrap();
        let path = target.split('?').next().unwrap_or(target);
        let kind = spec["name"].as_str().unwrap();
        if kind == "redirect" {
            let location = pair_value(&response["headers"], "location");
            if status != 301 || legacy_public_redirect(path) != location {
                wrong.push(format!(
                    "「{name}」: Python {status} {location:?} / Rust {:?}",
                    legacy_public_redirect(path)
                ));
            }
            continue;
        }
        let want_status = if kind == "error" {
            spec["code"].as_u64().unwrap()
        } else {
            200
        };
        if status != want_status {
            wrong.push(format!("「{name}」: 状態が {status}（例では {want_status}）"));
        }
        if pair_value(&response["headers"], "content-type") != Some(HTML_CONTENT_TYPE) {
            wrong.push(format!("「{name}」: Content-Type が HTML でない"));
        }
        let mut session = case["session"]
            .as_str()
            .map(|session| object(&fx.data["sessions"][session]))
            .unwrap_or_default();
        let embedded = is_embedded(pair_value(&case["request"]["headers"], "sec-fetch-dest"));
        let invite = invite.as_deref();
        let (body, issued) = draw(&mut session, embedded, token, |visit| match kind {
            "landing" => {
                let count = case["service"]["guild_count"].as_i64().unwrap();
                pages.landing(visit, invite, count)
            }
            "document" => {
                let page = document_for_path(path)
                    .unwrap_or_else(|| panic!("「{name}」: 文書のページでない {path}"));
                pages.document(page, visit, invite)
            }
            "login" => pages.login(visit, invite),
            "logout_confirm" => pages.logout_confirm(visit),
            "guild_select" => pages.guild_select(visit),
            "shell" => pages.shell(visit),
            "error" => {
                let code = u16::try_from(spec["code"].as_u64().unwrap()).unwrap();
                let message = spec["message"].as_str().unwrap();
                pages.error(visit, code, message, spec["description"].as_str())
            }
            other => panic!("「{name}」: 知らないページの種類 {other}"),
        });
        wrong.extend(compare(
            &format!("「{name}」（{} {target}）", case["request"]["method"]),
            &body,
            &response["body"],
            &session,
            &case["session_after"],
            issued,
            issued_in(&case["calls"]),
        ));
    }
    finish(&wrong);
}

/// 基準が、全部のページを 1 回は描いていること（例を削っても気づけるように）。
#[test]
fn every_page_is_covered_by_the_fixture() {
    let fx = fixture();
    let drawn: Vec<&str> = items(&fx.data, "pages")
        .iter()
        .filter_map(|item| item["template"].as_str())
        .collect();
    let routed: Vec<&str> = items(&fx.data, "cases")
        .iter()
        .filter_map(|case| case["page"]["name"].as_str())
        .collect();
    for page in Page::ALL {
        assert!(
            drawn.contains(&page.template()),
            "pages に {} の例が無い",
            page.template()
        );
    }
    for kind in [
        "landing",
        "document",
        "redirect",
        "login",
        "logout_confirm",
        "guild_select",
        "shell",
        "error",
    ] {
        assert!(routed.contains(&kind), "cases に {kind} の例が無い");
    }
}

/// Python のテンプレートの置き場にあるファイルを、Rust が全部読み込んでいること（足したら Rust も知る）。
#[test]
fn every_python_template_is_loaded() {
    let mut on_disk: Vec<String> = std::fs::read_dir(repository_templates())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".html"))
        .collect();
    on_disk.sort();
    let mut known: Vec<String> = TEMPLATE_NAMES.iter().map(|name| name.to_string()).collect();
    known.sort();
    assert_eq!(on_disk, known);
}
