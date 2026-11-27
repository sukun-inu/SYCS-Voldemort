//! ニュースの部品（RSS の読み方・説明の整え方・日付・要約の整え方・favicon・行き先）が、本物の Python と
//! 同じ結果を出すこと。
//!
//! 基準（`fixtures/news/pure_expected.json`）は、同じ入力（`pure_cases.json` と `rss/*.xml`）を本物の Python の
//! `services/news_service.py` に与えた結果（`generate.py pure`。時刻帯は UTC に固定）。
//!
//! Python と違えてあるところ（[`DIFFERENT`]）は、Python の結果と Rust の結果の両方をここに書いて固定する
//! （知らないうちに変わらないように）。

use serde_json::{Value, json};
use sycs_bot::news::{self, Article, NaiveZone};

fn fixture(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/news");
    std::fs::read_to_string(format!("{dir}/{name}")).unwrap()
}

fn rss(name: &str) -> Vec<u8> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/news/rss");
    std::fs::read(format!("{dir}/{name}.xml")).unwrap()
}

fn article_json(a: &Article) -> Value {
    json!({
        "title": a.title,
        "link": a.link,
        "pubDate": a.pub_date,
        "desc": a.desc,
        "source": a.source,
        "sourceUrl": a.source_url,
    })
}

/// Python と違えてあるところ: (種類, 入力, Rust の結果)。
fn different() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        // ASCII 以外の数字は読まない（Python の int() は読んで「2026年11月27日 10:23」にする）。
        (
            "pub_date",
            "Fri, ２７ Nov 2026 01:23:45 GMT",
            json!("Fri, ２７ Nov 2026 01:23:45 GMT"),
        ),
        // Shift_JIS は読まない（Python は ValueError で巡回ごと止まる）。
        ("parse", "sjis", json!([])),
        // DTD のある XML は読まない（Python は内部の実体を展開して 1 件読む）。
        ("parse", "doctype", json!([])),
    ]
}

/// 種類ごとに、全部の入力で Python と同じ結果になること（違えてあるところは、その結果になること）。
#[test]
fn the_parts_agree_with_python() {
    let cases: Value = serde_json::from_str(&fixture("pure_cases.json")).unwrap();
    let expected: Value = serde_json::from_str(&fixture("pure_expected.json")).unwrap();
    let different = different();
    let mut wrong = Vec::new();
    let mut checked = 0;
    let mut pinned = 0;
    let mut check = |kind: &str, input: &Value, got: Value, want: &Value| {
        checked += 1;
        let key = input.as_str().unwrap_or("");
        if let Some((_, _, ours)) = different.iter().find(|(k, i, _)| *k == kind && *i == key) {
            pinned += 1;
            if got != *ours || got == *want {
                wrong.push(format!(
                    "{kind} {input}（違えてあるはず）\n  py {want}\n  rs {got}\n  決めた値 {ours}"
                ));
            }
        } else if got != *want {
            wrong.push(format!("{kind} {input}\n  py {want}\n  rs {got}"));
        }
    };
    let pairs = |kind: &str| -> Vec<(Value, Value)> {
        let inputs = cases[kind].as_array().unwrap();
        let wants = expected[kind].as_array().unwrap();
        assert_eq!(inputs.len(), wants.len(), "{kind} の基準と例の数が違う");
        inputs.iter().cloned().zip(wants.iter().cloned()).collect()
    };
    for (input, want) in pairs("strip_html") {
        let got = news::strip_html(input.as_str().unwrap(), news::DESC_MAX_CHARS);
        check("strip_html", &input, json!(got), &want);
    }
    for (input, want) in pairs("pub_date") {
        let got = news::format_pub_date(input.as_str().unwrap(), NaiveZone::Utc);
        check("pub_date", &input, json!(got), &want);
    }
    for (input, want) in pairs("normalize") {
        let got = news::normalize_summary(input.as_str().unwrap(), news::SUMMARY_MAX_CHARS);
        check("normalize", &input, json!(got), &want);
    }
    for (input, want) in pairs("favicon") {
        // Python は壊れた URL で ValueError を投げる。こちらは Err（どちらも、その記事を送らない）。
        let got = match news::favicon_url(input.as_str().unwrap()) {
            Ok(url) => json!(url),
            Err(_) => json!({"error": "ValueError"}),
        };
        check("favicon", &input, got, &want);
    }
    for (input, want) in pairs("hash") {
        check(
            "hash",
            &input,
            json!(news::url_hash(input.as_str().unwrap())),
            &want,
        );
    }
    for (input, want) in pairs("quote") {
        check(
            "quote",
            &input,
            json!(news::quote(input.as_str().unwrap())),
            &want,
        );
    }
    for (input, want) in pairs("parse") {
        let articles = news::parse_rss(&rss(input.as_str().unwrap()));
        let got = Value::Array(articles.iter().map(article_json).collect());
        check("parse", &input, got, &want);
    }
    for (input, want) in pairs("source_text") {
        let text = |k: &str| input[k].as_str().unwrap().to_string();
        let article = Article {
            title: text("title"),
            link: text("link"),
            pub_date: String::new(),
            desc: text("desc"),
            source: text("source"),
            source_url: String::new(),
        };
        check(
            "source_text",
            &Value::Null,
            json!(news::source_text(&article)),
            &want,
        );
    }
    assert!(
        wrong.is_empty(),
        "{} 件が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(checked > 200, "確かめた数が少なすぎる: {checked}");
    assert_eq!(
        pinned,
        different.len(),
        "違えてあるところを全部は通っていない"
    );
}

/// 行き先の `q=` が、aiohttp が実際に送った形と同じであること（偽物の配信元で取った値）。
///
/// `'` だけは `%27` のまま送る（reqwest が `'` を `%27` に直す。配信元から見た意味は同じ）。
#[test]
fn the_query_is_sent_the_way_aiohttp_sends_it() {
    // (検索の語, aiohttp が送った q= の値)。
    let sent = [
        ("AI ニュース", "AI%20%E3%83%8B%E3%83%A5%E3%83%BC%E3%82%B9"),
        ("a+b", "a%2Bb"),
        ("C++", "C%2B%2B"),
        ("a&b=c", "a%26b%3Dc"),
        ("a/b", "a/b"),
        ("50%", "50%25"),
        ("a%20b", "a%2520b"),
        ("a~b_c-d.e", "a~b_c-d.e"),
        ("x#y", "x%23y"),
        ("a?b", "a?b"),
        ("'q' \"w\"", "'q'%20%22w%22"),
        ("!*(),;:@$", "!*(),%3B:@$"),
        ("<>[]{}|\\^`", "%3C%3E%5B%5D%7B%7D%7C%5C%5E%60"),
        ("emoji 😀", "emoji%20%F0%9F%98%80"),
        ("tab\there", "tab%09here"),
        ("%E3%81%82", "%25E3%2581%2582"),
        ("%zz", "%25zz"),
        ("%", "%25"),
    ];
    for (query, aiohttp) in sent {
        let url = news::rss_url("http://fake", query);
        let want = format!(
            "http://fake/rss/search?q={}&hl=ja&gl=JP&ceid=JP:ja",
            aiohttp.replace('\'', "%27")
        );
        assert_eq!(url, want, "{query}");
        // reqwest（url）が、送る前に書き換えないこと。
        assert_eq!(reqwest::Url::parse(&url).unwrap().as_str(), want, "{query}");
    }
}
