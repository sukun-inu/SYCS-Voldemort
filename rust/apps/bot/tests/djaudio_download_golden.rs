//! DJAudio の「落として登録する」段が、本物の Python と同じに yt-dlp を呼び、同じ題で、同じ情報を置き場に書くこと。
//!
//! 基準（`fixtures/djaudio/download_expected.jsonl`）は、本物の `_download_and_register` を、台本どおりに動く偽物の
//! yt-dlp（`fixtures/djaudio/fake-yt-dlp.sh`）で動かしたもの（`generate_download.py`）。ここでも同じ偽物を同じ台本で
//! 置き、[`Service`] に落とさせて比べる: yt-dlp に渡した引数（回ごと。SoundCloud の client_id を付けたやり直しを
//! 含む）、client_id をページから探しに行った回数（偽物のページをテストの中に立てる）、題と印、置き場のファイルの
//! 名前と中身（情報の JSON は文字そのまま。期限の時刻だけは、いまの時刻 + 有効期間に近いことを別に確かめる）。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use sycs_bot::djaudio::Service;
use sycs_bot::djaudio::cache::{self, Cache};
use sycs_bot::djaudio::download::{SoundCloudIds, Tools};
use sycs_bot::djaudio::flow::Downloader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const GUILD: u64 = 1_399_617_700_363_370_556;
const EXPECTED: &str = include_str!("fixtures/djaudio/download_expected.jsonl");
const FAKE_YTDLP: &str = include_str!("fixtures/djaudio/fake-yt-dlp.sh");

/// 偽物の SoundCloud のページ（`/` を取られるたびに数え、その回の台本の client_id を JS に書く）。
async fn start_fake_soundcloud(scrape: Vec<Value>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let pages = Arc::new(AtomicUsize::new(0));
    let (counter, base_for_task) = (Arc::clone(&pages), base.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (counter, base, scrape) =
                (Arc::clone(&counter), base_for_task.clone(), scrape.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                let body = if path == "/" {
                    let k = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    format!("<html><script src=\"{base}/app-{k}.js\"></script></html>")
                } else {
                    let k: usize = path
                        .trim_start_matches("/app-")
                        .trim_end_matches(".js")
                        .parse()
                        .unwrap_or(0);
                    match scrape.get(k.wrapping_sub(1)).and_then(Value::as_str) {
                        Some(id) => format!("var a={{client_id:\"{id}\"}};"),
                        None => "var nothing=1;".to_string(),
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, pages)
}

/// 偽物の yt-dlp の置き場を作る（bin/yt-dlp と、回ごとの台本）。
fn make_plan(root: &Path, case: &Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let script = root.join("bin").join("yt-dlp");
    std::fs::write(&script, FAKE_YTDLP).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (i, step) in case["steps"].as_array().into_iter().flatten().enumerate() {
        let dir = root.join("steps").join((i + 1).to_string());
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let bytes = |v: &Value| match v {
            Value::Object(o) => hex::decode(o["hex"].as_str().unwrap()).unwrap(),
            other => other.as_str().unwrap().as_bytes().to_vec(),
        };
        for (name, content) in step["files"].as_object().into_iter().flatten() {
            std::fs::write(dir.join("out").join(name), bytes(content)).unwrap();
        }
        if let Some(err) = step.get("stderr") {
            std::fs::write(dir.join("stderr"), bytes(err)).unwrap();
        }
        std::fs::write(
            dir.join("exit"),
            step["exit"].as_i64().unwrap_or(0).to_string(),
        )
        .unwrap();
    }
    script
}

/// 偽物の yt-dlp が記録した引数を、呼んだ回ごとに分ける（-o の置き場は <tmp> にする）。
fn read_calls(root: &Path) -> Value {
    let Ok(text) = std::fs::read_to_string(root.join("args.log")) else {
        return json!([]);
    };
    let mut calls = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in text.split('\n').filter(|_| true) {
        if line.is_empty() && current.is_empty() {
            continue;
        }
        if line == "----" {
            calls.push(std::mem::take(&mut current));
        } else {
            current.push(line.to_string());
        }
    }
    for call in &mut calls {
        for i in 1..call.len() {
            if call[i - 1] == "-o" {
                let name = call[i].rsplit('/').next().unwrap().to_string();
                call[i] = format!("<tmp>/{name}");
            }
        }
    }
    json!(calls)
}

/// 印を <tokenN> に、期限の時刻を <expires> に置き換える。
fn normalize(text: &str, tokens: &[String]) -> String {
    let mut out = text.to_string();
    for (i, token) in tokens.iter().enumerate() {
        out = out.replace(token, &format!("<token{}>", i + 1));
    }
    match out.find("\"expires_at\": ") {
        Some(start) => {
            let value_start = start + "\"expires_at\": ".len();
            let end = out[value_start..]
                .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | 'e' | '+' | '-')))
                .map_or(out.len(), |e| value_start + e);
            format!("{}\"<expires>\"{}", &out[..value_start], &out[end..])
        }
        None => out,
    }
}

/// 置き場のファイルの名前と中身（並べ替えて比べる。印は乱数なので、名前の順は例ごとに変わる）。
fn listing(cache: &Cache, tokens: &[String]) -> Vec<Value> {
    let mut out: Vec<Value> = std::fs::read_dir(cache.dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let content = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
            json!([normalize(&name, tokens), normalize(&content, tokens)])
        })
        .collect();
    out.sort_by_key(Value::to_string);
    out
}

/// 例を 1 つ回して、答え（Python と同じ形）を返す。期限の時刻は、ここで確かめる。
async fn run(case: &Value) -> Value {
    let root = tempfile::tempdir().unwrap();
    let script = make_plan(root.path(), case);
    let (page, pages) =
        start_fake_soundcloud(case["scrape"].as_array().cloned().unwrap_or_default()).await;
    let service = Service {
        tools: Tools {
            ytdlp: script.to_string_lossy().into_owned(),
            ffmpeg: "/usr/bin/ffmpeg".to_string(),
            soundcloud_client_id: case["env_client_id"].as_str().unwrap_or("").to_string(),
            soundcloud_page: format!("{page}/"),
        },
        ids: SoundCloudIds::default(),
        cache: Cache::new(root.path().join("cache")),
        // Deezer はつながらない場所に向ける（Python の基準も補いを止めて作った。つながらなければ補わずに登録する）。
        deezer: sycs_bot::djaudio_meta::Deezer::new("http://127.0.0.1:9"),
    };
    let runs = case["runs"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![json!({})]);
    let mut answers = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    for spec in &runs {
        let url = spec["url"]
            .as_str()
            .or(case["url"].as_str())
            .unwrap_or("https://youtu.be/a");
        let ttl = spec["ttl"].as_i64().or(case["ttl"].as_i64()).unwrap_or(600);
        let before = cache::now_timestamp();
        match service.download(url, GUILD, i128::from(ttl)).await {
            Ok(results) => {
                for (_, token) in &results {
                    tokens.push(token.clone());
                    let meta: Value = serde_json::from_str(
                        &std::fs::read_to_string(service.cache.dir().join(format!("{token}.json")))
                            .unwrap(),
                    )
                    .unwrap();
                    let expires = meta["expires_at"].as_f64().unwrap();
                    let expected = before + ttl as f64;
                    assert!(
                        (expires - expected).abs() < 30.0,
                        "{}: 期限 {expires} がいま + {ttl} から遠い",
                        case["id"]
                    );
                }
                let list: Vec<Value> = results
                    .iter()
                    .map(|(title, token)| json!([title, normalize(token, &tokens)]))
                    .collect();
                answers.push(json!({"results": list}));
            }
            Err(e) => answers.push(json!({"error": e})),
        }
    }
    json!({
        "calls": read_calls(root.path()),
        "scrapes": pages.load(Ordering::SeqCst),
        "runs": answers,
        "cache": listing(&service.cache, &tokens),
    })
}

/// 全部の例で、yt-dlp の呼び方・探しに行った回数・題と印・置き場の中身が Python と同じであること。
///
/// 失敗の文は、Python が `RuntimeError` で返すもの（yt-dlp の失敗の末尾 400 文字・MP3 が無い）だけを比べる
/// （ほかは Python の例外の文なので、失敗したことだけを比べる）。
#[tokio::test]
async fn djaudio_download_matches_python() {
    let mut count = 0;
    let mut wrong = Vec::new();
    for line in EXPECTED.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let mut want = row[1].clone();
        let mut got = run(&row[0]).await;
        // Python の失敗の文が null の例は、失敗したことだけを比べる。
        for (w, g) in want["runs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(got["runs"].as_array_mut().unwrap())
        {
            if w.get("error") == Some(&Value::Null) && g.get("error").is_some() {
                *g = json!({"error": null});
            }
        }
        if let Some(list) = want["cache"].as_array_mut() {
            list.sort_by_key(Value::to_string);
        }
        if got != want {
            wrong.push(format!(
                "{}\n  Python: {want}\n  Rust:   {got}",
                row[0]["id"]
            ));
        }
        count += 1;
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(count >= 35, "例が少ない: {count}");
}
