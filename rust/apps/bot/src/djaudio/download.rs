//! URL を yt-dlp で MP3 にする。Python の `services/djaudio_service.py` の `_extract_urls`・`_normalize_text`・
//! `_format_title_from_metadata`・`_load_info_json`・`_is_soundcloud_url`・`_run_ytdlp`・`_download_as_mp3`・
//! `_fetch_soundcloud_client_id`・`_scrape_sc_client_id_via_aiohttp`。
//!
//! yt-dlp には Python と同じ引数を渡す（音質・メタデータ・カバー画像の埋め込みまで同じ MP3 になる）。
//! SoundCloud の client_id が切れたときだけ、取り直してやり直す。
//!
//! Python との違い: client_id の取り直しのうち「yt-dlp の Python のライブラリから取る」段は持ち込まない（Rust からは
//! 呼べない。Python ではライブラリと実行ファイルの版が違うことがあって意味があったが、Rust のイメージの yt-dlp は
//! 1 つだけで、同じ処理をもう一度回すことになる）。環境変数 `SOUNDCLOUD_CLIENT_ID` と、ページから探す段は同じ。

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sycs_core::url_safety::hostname_of;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::commands::settings::python_truthy;
use crate::python_chars::{self, Class};
use crate::python_repr::python_str;

use super::site::detect_site;

/// yt-dlp が SoundCloud の client_id を取れなかったときの文。
pub const SOUNDCLOUD_CLIENT_ID_ERROR: &str = "Unable to extract client id";

/// client_id を覚えておく長さ（12 時間。Python と同じ）。
const CLIENT_ID_TTL: Duration = Duration::from_secs(43_200);

/// ページから探すときの名乗り（Python と同じ）。
const SCRAPER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// メッセージの本文から URL を拾う。Python の `_extract_urls`（`https?://[^\s]+` を順に、前後の飾りを落として、
/// 重複なしで `max_urls` 件まで）。
pub fn extract_urls(content: &str, max_urls: usize) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let rest = &chars[i..];
        let scheme = if starts_with(rest, "https://") {
            8
        } else if starts_with(rest, "http://") {
            7
        } else {
            0
        };
        // `[^\s]+` は 1 文字以上要る。
        if scheme == 0 || rest.len() <= scheme || python_chars::is(Class::Space, rest[scheme]) {
            i += 1;
            continue;
        }
        let end = rest
            .iter()
            .position(|c| python_chars::is(Class::Space, *c))
            .unwrap_or(rest.len());
        let raw: String = rest[..end].iter().collect();
        i += end;
        let cleaned = raw
            .trim_matches(|c: char| crate::commands::server::python::is_space(c))
            .trim_matches(['<', '>'])
            .trim_end_matches([')', ']', '}', '>', '.', ',', '!', '?', ';', ':']);
        if cleaned.is_empty() || urls.iter().any(|u| u == cleaned) {
            continue;
        }
        urls.push(cleaned.to_string());
        if urls.len() >= max_urls {
            break;
        }
    }
    urls
}

fn starts_with(chars: &[char], prefix: &str) -> bool {
    let mut it = chars.iter();
    prefix.chars().all(|p| it.next() == Some(&p))
}

/// Python の `re.sub(r"\s+", " ", text).strip()`。
fn collapse_spaces(text: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in text.chars() {
        if python_chars::is(Class::Space, c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    crate::commands::server::python::strip(&out).to_string()
}

/// Python の `_normalize_text`（`str(value or "")` の空白を 1 つにまとめて前後を落とす）。
pub fn normalize_text(value: Option<&Value>) -> String {
    let text = if python_truthy(value) {
        value.map(python_str).unwrap_or_default()
    } else {
        String::new()
    };
    collapse_spaces(&text)
}

/// Python の `a or b or c`（最初の真の値）。
fn first_truthy<'a>(meta: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .map(|key| meta.get(*key))
        .find(|v| python_truthy(*v))
        .flatten()
}

/// Python の `str.lower()`。
fn lower(text: &str) -> String {
    crate::python_chars::lower(text)
}

/// 「アーティスト - 曲名」にまとめる（曲名がすでにアーティストの名前で始まっていれば、曲名だけ）。
fn with_artist(first: &str, second: &str) -> String {
    if first.is_empty() {
        return second.to_string();
    }
    if second.is_empty() {
        return first.to_string();
    }
    if lower(second).starts_with(&lower(first)) {
        return second.to_string();
    }
    format!("{first} - {second}")
}

/// info.json から、表示する題（「アーティスト - 曲名」）を作る。Python の `_format_title_from_metadata`。
pub fn format_title(meta: &Map<String, Value>) -> String {
    let title = normalize_text(meta.get("title"));
    let artist = normalize_text(first_truthy(
        meta,
        &["artist", "album_artist", "creator", "uploader"],
    ));
    let track = normalize_text(first_truthy(meta, &["track", "alt_title", "release_title"]));
    let site = detect_site(meta);

    if title.is_empty() {
        return [artist, track]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
    }
    match site {
        "youtube" => {
            if !artist.is_empty() && !track.is_empty() {
                return with_artist(&artist, &track);
            }
            if !artist.is_empty() {
                return with_artist(&artist, &title);
            }
            if python_truthy(meta.get("uploader")) {
                return with_artist(&normalize_text(meta.get("uploader")), &title);
            }
            title
        }
        "soundcloud" => {
            if artist.is_empty() {
                title
            } else {
                with_artist(&artist, &title)
            }
        }
        "nicovideo" => title,
        "tiktok" => {
            let uploader = normalize_text(meta.get("uploader"));
            if uploader.is_empty() {
                title
            } else {
                with_artist(&uploader, &title)
            }
        }
        // bandcamp と、それ以外。
        _ => {
            if !artist.is_empty() {
                return with_artist(&artist, &title);
            }
            if track.is_empty() {
                title
            } else {
                with_artist(&track, &title)
            }
        }
    }
}

/// Python の `Path.stem`（最後の拡張子を除いた名前）。
pub fn stem(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[..i].to_string(),
        _ => name,
    }
}

/// Python の `mp3_path.with_suffix(".info.json")`。
pub fn info_json_path(mp3: &Path) -> PathBuf {
    mp3.with_file_name(format!("{}.info.json", stem(mp3)))
}

/// yt-dlp が書いた info.json を読む。Python の `_load_info_json`。
///
/// 無いとき・JSON として読めないとき・読めないときは `Ok(None)`（題はファイル名になる）。UTF-8 として読めない
/// ときは `Err`（Python は `UnicodeDecodeError` を捕まえないので、その URL は失敗になる）。
pub fn load_info_json(mp3: &Path) -> Result<Option<Value>, String> {
    let path = info_json_path(mp3);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("info.json の読み込みに失敗しました: {e}");
            return Ok(None);
        }
    };
    let text = String::from_utf8(bytes).map_err(|e| format!("info.json が UTF-8 でない: {e}"))?;
    // Python の read_text は先頭の BOM を残すので、json.loads が読めずに None になる（serde_json も同じく読めない）。
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            warn!("info.json の読み込みに失敗しました: {e}");
            Ok(None)
        }
    }
}

/// SoundCloud の URL か（client_id の取り直しをしてよいか）。Python の `_is_soundcloud_url`。
pub fn is_soundcloud_url(url: &str) -> bool {
    let host = hostname_of(url).ok().flatten().unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    matches!(host, "soundcloud.com" | "on.soundcloud.com")
}

/// yt-dlp・ffmpeg の場所と、SoundCloud の client_id の取り方。
#[derive(Clone, Debug)]
pub struct Tools {
    /// yt-dlp の実行ファイル（既定は PATH の `yt-dlp`。Python と同じ）。
    pub ytdlp: String,
    /// ffmpeg の場所（`DJAUDIO_FFMPEG_PATH`。無ければ PATH の ffmpeg）。
    pub ffmpeg: String,
    /// 環境変数 `SOUNDCLOUD_CLIENT_ID`（空なら探しに行く）。
    pub soundcloud_client_id: String,
    /// client_id を探しに行くページ（既定は `https://soundcloud.com`。テストでは偽物に向ける）。
    pub soundcloud_page: String,
}

/// yt-dlp に渡す引数。Python の `_run_ytdlp` と同じ並び（URL は `--` の後ろ）。
pub fn ytdlp_args(
    url: &str,
    output_dir: &Path,
    ffmpeg: &str,
    client_id: Option<&str>,
) -> Vec<String> {
    let template = output_dir.join("%(title).80s.%(ext)s");
    let mut args: Vec<String> = [
        "-x",
        "--audio-format",
        "mp3",
        "--audio-quality",
        "0",
        "-f",
        "bestaudio/best",
        "--format-sort",
        "asr,abr,acodec:opus",
        "--postprocessor-args",
        "ffmpeg:-q:a 0",
        "--write-info-json",
        "--embed-thumbnail",
        "--convert-thumbnails",
        "jpg",
        "--embed-metadata",
        "--concurrent-fragments",
        "4",
        "--buffer-size",
        "1M",
        "--http-chunk-size",
        "10M",
        "--retries",
        "5",
        "--socket-timeout",
        "30",
        "--no-playlist",
        "-o",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.push(template.to_string_lossy().into_owned());
    args.push("--ffmpeg-location".into());
    args.push(ffmpeg.into());
    args.push("--no-warnings".into());
    if let Some(id) = client_id {
        args.push("--extractor-args".into());
        args.push(format!("soundcloud:client_id={id}"));
    }
    args.push("--".into());
    args.push(url.into());
    args
}

/// yt-dlp を 1 回動かす。終了コード（シグナルで止まったら -1）と、標準エラーの全文（UTF-8 として読めないところは
/// U+FFFD）。動かせなかったら `Err`。
async fn run_ytdlp(
    tools: &Tools,
    url: &str,
    output_dir: &Path,
    client_id: Option<&str>,
) -> Result<(i32, String), String> {
    let output = tokio::process::Command::new(&tools.ytdlp)
        .args(ytdlp_args(url, output_dir, &tools.ffmpeg, client_id))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("yt-dlp を動かせませんでした: {e}"))?;
    let code = output.status.code().unwrap_or(-1);
    Ok((code, String::from_utf8_lossy(&output.stderr).into_owned()))
}

/// 末尾の `n` 文字（Python の `text[-n:]`）。
pub fn last_chars(text: &str, n: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(n)).collect()
}

/// SoundCloud の client_id を覚えておくところ。Python の `_sc_client_id`・`_sc_client_id_fetched_at`（と錠）。
#[derive(Default)]
pub struct SoundCloudIds {
    inner: Mutex<(Option<String>, Option<Instant>)>,
}

impl SoundCloudIds {
    /// client_id を返す（覚えていて 12 時間以内ならそれ、`force` なら取り直す）。Python の `_fetch_soundcloud_client_id`。
    pub async fn fetch(&self, tools: &Tools, force: bool) -> Option<String> {
        let mut state = self.inner.lock().await;
        let env = tools.soundcloud_client_id.as_str();
        if !env.is_empty() {
            if !force && state.0.as_deref() == Some(env) {
                return state.0.clone();
            }
            info!("SOUNDCLOUD_CLIENT_ID 環境変数を使用: {}…", head(env, 8));
            *state = (Some(env.to_string()), Some(Instant::now()));
            return state.0.clone();
        }
        if !force
            && state.0.as_deref().is_some_and(|id| !id.is_empty())
            && state.1.is_some_and(|at| at.elapsed() < CLIENT_ID_TTL)
        {
            return state.0.clone();
        }
        info!(
            "SoundCloud client_id を動的取得中 (force={})...",
            python_bool(force)
        );
        let found = scrape_client_id(&tools.soundcloud_page).await;
        match &found {
            Some(id) => *state = (Some(id.clone()), Some(Instant::now())),
            None => error!(
                "すべての方法で SoundCloud client_id の取得に失敗した。ブラウザの DevTools (Network タブ) で \
                 api-v2.soundcloud.com へのリクエストURLから client_id=XXXX を見つけて環境変数 \
                 SOUNDCLOUD_CLIENT_ID に設定してください。"
            ),
        }
        found
    }
}

fn python_bool(flag: bool) -> &'static str {
    if flag { "True" } else { "False" }
}

/// 先頭の `n` 文字。
fn head(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// ページの `src="….js"`・`src='….js'` を順に拾う。Python の `re.findall(r'src=["\']([^"\']+\.js)["\']', html)`。
pub fn script_urls(html: &str) -> Vec<String> {
    let chars: Vec<char> = html.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 < chars.len() {
        if !(chars[i..].starts_with(&['s', 'r', 'c', '=']) && matches!(chars[i + 4], '"' | '\'')) {
            i += 1;
            continue;
        }
        // 引用符でない文字が 1 つ以上続き、その最後が `.js` で、次が引用符。
        let start = i + 5;
        let end = chars[start..]
            .iter()
            .position(|c| matches!(c, '"' | '\''))
            .map(|p| start + p);
        match end {
            Some(end)
                if end > start
                    && chars[start..end].ends_with(&['.', 'j', 's'])
                    && end - start >= 4 =>
            {
                out.push(chars[start..end].iter().collect());
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// JS の中から client_id を探す。Python の `_SC_CLIENT_ID_PATTERNS` を順に `search` する。
pub fn find_client_id(js: &str) -> Option<String> {
    let chars: Vec<char> = js.chars().collect();
    // (前の部分, 区切り, 引用符)。区切りの前後には空白（Python の \s）を挟める。
    let patterns: [(&str, char, char); 4] = [
        ("client_id", ':', '"'),
        ("\"client_id\"", ':', '"'),
        ("client_id", '=', '"'),
        ("client_id", ':', '\''),
    ];
    patterns
        .iter()
        .find_map(|(lead, sep, quote)| search_id(&chars, lead, *sep, *quote))
}

fn search_id(chars: &[char], lead: &str, sep: char, quote: char) -> Option<String> {
    let lead: Vec<char> = lead.chars().collect();
    (0..chars.len()).find_map(|start| {
        let mut i = start;
        if !chars[i..].starts_with(&lead) {
            return None;
        }
        i += lead.len();
        while i < chars.len() && python_chars::is(Class::Space, chars[i]) {
            i += 1;
        }
        if chars.get(i) != Some(&sep) {
            return None;
        }
        i += 1;
        while i < chars.len() && python_chars::is(Class::Space, chars[i]) {
            i += 1;
        }
        if chars.get(i) != Some(&quote) {
            return None;
        }
        i += 1;
        let run = chars[i..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count();
        // `([A-Za-z0-9]{20,64})"`: 64 文字を超えて続くと、すぐ後ろが引用符にならないので当たらない。
        ((20..=64).contains(&run) && chars.get(i + run) == Some(&quote))
            .then(|| chars[i..i + run].iter().collect())
    })
}

/// SoundCloud のページから client_id を探す。Python の `_scrape_sc_client_id_via_aiohttp`（30 秒で見切る）。
pub async fn scrape_client_id(page: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .user_agent(SCRAPER_USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .ok()?;
    let html = match async { client.get(page).send().await?.text().await }.await {
        Ok(html) => html,
        Err(e) => {
            error!("SoundCloud HTML fetch に失敗: {e}");
            return None;
        }
    };
    info!("SoundCloud HTML 取得: len={}", html.chars().count());
    let urls = script_urls(&html);
    info!("スクリプト URL {} 件発見", urls.len());
    if urls.is_empty() {
        error!(
            "SoundCloud HTML にスクリプト URL がない (先頭500文字: {})",
            head(&html, 500)
        );
        return None;
    }
    for url in urls.iter().rev().take(12) {
        match async { client.get(url).send().await?.text().await }.await {
            Ok(js) => {
                if let Some(id) = find_client_id(&js) {
                    info!("aiohttp scraper で client_id 取得成功: {}…", head(&id, 8));
                    return Some(id);
                }
            }
            Err(e) => warn!("スクリプト fetch 失敗 [{url}]: {e}"),
        }
    }
    error!(
        "全スクリプトに client_id パターンが見つからなかった (試行 {} 件)",
        urls.len().min(12)
    );
    None
}

/// URL を MP3 にして、できたファイルを名前の順に返す。Python の `_download_as_mp3`。
///
/// SoundCloud の client_id が切れていたときだけ、覚えている値（無ければ探す）でやり直し、それでも駄目なら取り直して
/// もう 1 回だけやり直す。最後まで失敗したら、標準エラーの末尾 400 文字を `Err` にする。
pub async fn download_as_mp3(
    tools: &Tools,
    ids: &SoundCloudIds,
    url: &str,
    output_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let (mut code, mut err) = run_ytdlp(tools, url, output_dir, None).await?;
    if code != 0 && err.contains(SOUNDCLOUD_CLIENT_ID_ERROR) && is_soundcloud_url(url) {
        error!("SoundCloud client_id エラーを検知。動的取得を試みる [{url}]");
        let id = ids.fetch(tools, false).await;
        match &id {
            Some(id) => {
                error!(
                    "client_id 取得成功 ({}…)。リトライ開始 [{url}]",
                    head(id, 8)
                );
                (code, err) = run_ytdlp(tools, url, output_dir, Some(id)).await?;
            }
            None => error!("client_id 取得失敗。リトライ不可 [{url}]"),
        }
        if code != 0 && err.contains(SOUNDCLOUD_CLIENT_ID_ERROR) {
            error!("client_id 指定でもエラー継続。強制再取得を試みる [{url}]");
            let fresh = ids.fetch(tools, true).await;
            if let Some(fresh) = fresh.filter(|f| Some(f) != id.as_ref()) {
                error!("新 client_id ({}…) で最終リトライ [{url}]", head(&fresh, 8));
                (code, err) = run_ytdlp(tools, url, output_dir, Some(&fresh)).await?;
            }
        }
    }
    if code != 0 {
        let tail = last_chars(&err, 400);
        error!("yt-dlp エラー [{url}]: {tail}");
        return Err(tail);
    }
    mp3_files(output_dir)
}

/// 置き場の `*.mp3` を名前の順に。Python の `sorted(Path(output_dir).glob("*.mp3"))`。
fn mp3_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("置き場を読めませんでした: {e}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".mp3"))
        })
        .collect();
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// URL は前後の飾りを落とし、重複を除いて、上限まで拾うこと。
    #[test]
    fn urls_are_extracted_like_python() {
        let got = extract_urls(
            "見て <https://youtu.be/a>, (https://youtu.be/b). https://youtu.be/a http:// https://x.y/z!?",
            10,
        );
        assert_eq!(
            got,
            ["https://youtu.be/a", "https://youtu.be/b", "https://x.y/z"]
        );
        assert_eq!(
            extract_urls("https://a.b https://c.d https://e.f", 2).len(),
            2
        );
        assert!(extract_urls("HTTPS://upper.case", 3).is_empty());
    }

    /// 題は、サービスごとの組み立て方で「アーティスト - 曲名」にすること。
    #[test]
    fn titles_follow_python() {
        let map = |v: Value| v.as_object().unwrap().clone();
        let yt = map(json!({"extractor": "youtube", "title": "Song", "uploader": "Chan  nel"}));
        assert_eq!(format_title(&yt), "Chan nel - Song");
        let dup = map(
            json!({"extractor": "youtube", "title": "x", "artist": "ABC", "track": "abc - Song"}),
        );
        assert_eq!(format_title(&dup), "abc - Song");
        assert_eq!(format_title(&map(json!({"title": "", "track": "T"}))), "T");
        assert_eq!(format_title(&map(json!({}))), "unknown");
        assert_eq!(
            format_title(&map(
                json!({"extractor": "niconico", "title": " a\tb ", "artist": "z"})
            )),
            "a b"
        );
    }

    /// yt-dlp の引数は、Python と同じ並びで、URL を `--` の後ろに置くこと。
    #[test]
    fn ytdlp_args_match_python() {
        let args = ytdlp_args(
            "https://youtu.be/x",
            Path::new("/tmp/d"),
            "/usr/bin/ffmpeg",
            Some("abc"),
        );
        let n = args.len();
        assert_eq!(
            &args[n - 4..],
            [
                "--extractor-args",
                "soundcloud:client_id=abc",
                "--",
                "https://youtu.be/x"
            ]
        );
        assert_eq!(args[0], "-x");
        assert!(args.contains(&"/tmp/d/%(title).80s.%(ext)s".to_string()));
    }

    /// client_id は 20〜64 文字の英数字で、すぐ後ろが引用符のものだけを拾うこと。
    #[test]
    fn client_ids_are_found_like_python() {
        let id = "a".repeat(32);
        assert_eq!(
            find_client_id(&format!("x={{client_id : \"{id}\"}}")),
            Some(id.clone())
        );
        assert_eq!(
            find_client_id(&format!("client_id: '{id}'")),
            Some(id.clone())
        );
        assert_eq!(
            find_client_id(&format!("client_id = \"{id}\"")),
            Some(id.clone())
        );
        // Python の 4 つの形のどれにも当たらない（`=` のあとは二重引用符だけ）。
        assert_eq!(find_client_id(&format!("client_id='{id}'")), None);
        assert_eq!(
            find_client_id(&format!("client_id:\"{}\"", "b".repeat(65))),
            None
        );
        assert_eq!(find_client_id("client_id:\"short\""), None);
        assert_eq!(
            script_urls(r#"<script src="https://a/x.js"></script><script src='/y.js'>"#),
            ["https://a/x.js", "/y.js"]
        );
    }
}
