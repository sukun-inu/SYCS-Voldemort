//! DJAudio のメタデータの補い（`services/djaudio_isrc_meta.py`）。yt-dlp が作った MP3 の題・アーティスト・
//! アルバム・年・トラック番号・ディスク番号・カバー画像を、Deezer の公開 API で探して ID3 タグに書く。
//!
//! 1. info.json に ISRC があれば `/track/isrc:{isrc}` で引く（Deezer は未登録でも 200 で `{"error": …}` を返す）
//! 2. 無いか見つからなければ、媒体ごとに組み立てた検索語を順に `/search` へ投げ、題（0.65）とアーティスト（0.35）
//!    の似ている度合い（`difflib.SequenceMatcher`）で点を付ける。0.80 以上が出たらすぐ採る。最後までなければ
//!    0.45 以上の最善を採る
//! 3. 見つかったものの値で、mutagen 1.48.1 と同じに ID3 タグを書き直す（[`id3`]）
//!
//! Python の振る舞いはそのまま写す。値の型が想定と違うときに Python が例外を外へ出す所（`resp.json` の
//! JSONDecodeError、辞書でないものへの `.get` など。捕まえているのは `aiohttp.ClientError` と
//! `asyncio.TimeoutError` だけ）は、[`EnrichError`] にして返す。

pub mod difflib;
pub mod id3;
pub mod pyint;
pub mod text;
pub mod yarl;

use std::path::Path;
use std::time::Duration;

use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::python_repr::{python_repr, python_str, repr_str};

/// Deezer の API の既定の場所（Python の `_DEEZER_ISRC`・`_DEEZER_SEARCH` の前の部分）。
pub const DEFAULT_BASE: &str = "https://api.deezer.com";
/// ISRC と検索の時間切れ（Python の `aiohttp.ClientTimeout(total=10)`）。
pub const API_TIMEOUT: Duration = Duration::from_secs(10);
/// カバー画像の時間切れ（Python の `aiohttp.ClientTimeout(total=15)`）。
pub const COVER_TIMEOUT: Duration = Duration::from_secs(15);
/// これ以上の点が出たら、残りの検索語を試さずに採る（Python の `_HIGH_SCORE`）。
pub const HIGH_SCORE: f64 = 0.80;
/// 最善でもこれに届かなければ「該当なし」（Python の `_MIN_SCORE`）。
pub const MIN_SCORE: f64 = 0.45;
/// aiohttp の `max_redirects`（この回数目の転送の応答で TooManyRedirects）。
const MAX_REDIRECTS: usize = 10;

/// Deezer の API（既定は <https://api.deezer.com>。テストでは偽物に向ける）。
#[derive(Clone, Debug)]
pub struct Deezer {
    base: String,
    client: reqwest::Client,
    api_timeout: Duration,
    cover_timeout: Duration,
}

impl Deezer {
    /// 作る。base は `https://api.deezer.com` の形（末尾の `/` は付けない）。
    pub fn new(base: &str) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // aiohttp は転送の応答を数え、10 回目で TooManyRedirects（ClientError）にする。
                if attempt.previous().len() >= MAX_REDIRECTS {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .unwrap_or_default();
        Self {
            base: base.to_string(),
            client,
            api_timeout: API_TIMEOUT,
            cover_timeout: COVER_TIMEOUT,
        }
    }

    /// 時間切れを変える（テスト用。本番は Python と同じ 10 秒・15 秒）。
    pub fn with_timeouts(mut self, api: Duration, cover: Duration) -> Self {
        self.api_timeout = api;
        self.cover_timeout = cover;
        self
    }

    /// ISRC で引く URL（`_DEEZER_ISRC.format(isrc)` を yarl が読んだもの）。
    pub fn isrc_url(&self, isrc: &Value) -> Result<yarl::Url, yarl::InvalidUrl> {
        yarl::parse(&format!("{}/track/isrc:{}", self.base, python_str(isrc)))
    }

    /// 検索の URL（`_DEEZER_SEARCH` に `params={"q": q, "limit": 5}`）。
    pub fn search_url(&self, q: &str) -> Result<yarl::Url, yarl::InvalidUrl> {
        let mut url = yarl::parse(&format!("{}/search", self.base))?;
        url.extend_query(&[("q", q), ("limit", "5")]);
        Ok(url)
    }
}

/// Python で例外が `enrich_metadata` の外へ抜ける場合（B10a はその URL を「失敗」として扱う）。
#[derive(Debug)]
pub enum EnrichError {
    /// 値の型が想定と違う（Python の TypeError・AttributeError）。
    Type(String),
    /// Deezer の応答が JSON として読めない（Python の JSONDecodeError・UnicodeDecodeError）。
    Json(String),
}

impl std::fmt::Display for EnrichError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Type(m) => write!(f, "TypeError: {m}"),
            Self::Json(m) => write!(f, "JSONDecodeError: {m}"),
        }
    }
}

impl std::error::Error for EnrichError {}

// ---- Python の値の扱い（JSON から読んだもの） ----

static EMPTY_STR: Value = Value::String(String::new());
static NULL: Value = Value::Null;

/// Python の真偽（None・False・0・空の文字列・空のリスト・空の辞書が偽）。
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => {
            n.as_f64().is_some_and(|f| f != 0.0) || n.as_i64().is_some_and(|i| i != 0)
        }
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python の型の名前（例外の文に使う）。
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `a or b`。
fn or<'a>(a: &'a Value, b: &'a Value) -> &'a Value {
    if truthy(a) { a } else { b }
}

/// `value.get(key)`（辞書でなければ AttributeError）。
fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value, EnrichError> {
    match value {
        Value::Object(map) => Ok(map.get(key).unwrap_or(&NULL)),
        other => Err(EnrichError::Type(format!(
            "'{}' object has no attribute 'get'",
            type_name(other)
        ))),
    }
}

/// `(value or {}).get(key)`。
fn get_or_empty<'a>(value: &'a Value, key: &str) -> Result<&'a Value, EnrichError> {
    if truthy(value) {
        get(value, key)
    } else {
        Ok(&NULL)
    }
}

/// 文字列でなければ TypeError（`unicodedata.normalize`・`re.sub` に渡したときの例外）。
fn as_str<'a>(value: &'a Value, what: &str) -> Result<&'a str, EnrichError> {
    match value {
        Value::String(s) => Ok(s),
        other => Err(EnrichError::Type(format!(
            "{what} must be str, not {}",
            type_name(other)
        ))),
    }
}

// ---- 点の付け方（`_similarity`・`_score_result`） ----

/// Python の `_similarity`: 整えた 2 つの文字列の似ている度合い（0〜1）。どちらかが空なら 0.0。
pub fn similarity(a: &str, b: &str) -> f64 {
    let na: Vec<char> = text::normalize_for_compare(a).chars().collect();
    let nb: Vec<char> = text::normalize_for_compare(b).chars().collect();
    if na.is_empty() || nb.is_empty() {
        return 0.0;
    }
    difflib::ratio(&na, &nb)
}

fn similarity_values(a: &Value, b: &Value) -> Result<f64, EnrichError> {
    let a = as_str(a, "normalize() argument 2")?;
    let b = as_str(b, "normalize() argument 2")?;
    Ok(similarity(a, b))
}

/// Python の `_score_result`: Deezer の検索結果 1 件の点（題 0.65・アーティスト 0.35。アーティストが分からなければ題だけ）。
pub fn score_result(item: &Value, ref_title: &str, ref_artist: &Value) -> Result<f64, EnrichError> {
    let dz_title = or(get(item, "title")?, &EMPTY_STR);
    let dz_artist = or(get_or_empty(get(item, "artist")?, "name")?, &EMPTY_STR);
    let title_sim = similarity_values(&Value::String(ref_title.to_string()), dz_title)?;
    if truthy(ref_artist) {
        return Ok(title_sim * 0.65 + similarity_values(ref_artist, dz_artist)? * 0.35);
    }
    Ok(title_sim)
}

// ---- 検索語の組み立て（`_build_search_queries`） ----

/// `str(info.get(key) or "").strip()`。
fn info_text(info: &Map<String, Value>, key: &str) -> String {
    let value = or(info.get(key).unwrap_or(&NULL), &EMPTY_STR);
    text::py_strip(&python_str(value)).to_string()
}

/// Python の `_build_search_queries`: 検索語を有力そうな順に組み立てる（重複と空は除く）。
pub fn build_search_queries(
    title: &str,
    artist: &Value,
    site: &str,
    info: &Map<String, Value>,
) -> Vec<String> {
    let clean = text::clean_title(title);
    let has_artist = truthy(artist);
    let artist_s = python_str(artist);
    let mut queries: Vec<String> = Vec::new();
    match site {
        "youtube" => {
            let uploader_raw = python_str(or(info.get("uploader").unwrap_or(&NULL), &EMPTY_STR));
            let uploader = text::py_strip(&text::remove_topic_suffix(&uploader_raw)).to_string();
            if text::has_dash(&clean) {
                let parts = text::dash_split_once(&clean);
                let (a, t) = (text::py_strip(&parts[0]), text::py_strip(&parts[1]));
                queries.push(format!("artist:\"{a}\" track:\"{t}\""));
                queries.push(format!("track:\"{t}\""));
            }
            if has_artist {
                queries.push(format!("artist:\"{artist_s}\" track:\"{clean}\""));
            } else if !uploader.is_empty() {
                queries.push(format!("artist:\"{uploader}\" track:\"{clean}\""));
            }
            queries.push(format!("track:\"{clean}\""));
            if clean != title {
                let raw_clean = if text::has_dash(title) {
                    let parts = text::dash_split_once(title);
                    text::clean_title(parts.last().map_or("", String::as_str))
                } else {
                    clean.clone()
                };
                // Python は整えた語そのものが検索語の中にあるかを見ている（書いたとおり）。
                if !raw_clean.is_empty() && !queries.contains(&raw_clean) {
                    queries.push(format!("track:\"{raw_clean}\""));
                }
            }
        }
        "soundcloud" => {
            if has_artist {
                queries.push(format!("artist:\"{artist_s}\" track:\"{clean}\""));
            }
            queries.push(format!("track:\"{clean}\""));
            if has_artist {
                queries.push(format!("\"{artist_s}\" \"{clean}\""));
            }
        }
        "bandcamp" => {
            let album = info_text(info, "album");
            if has_artist && !clean.is_empty() {
                queries.push(format!("artist:\"{artist_s}\" track:\"{clean}\""));
            }
            if has_artist && !album.is_empty() {
                queries.push(format!("artist:\"{artist_s}\" album:\"{album}\""));
            }
            queries.push(format!("track:\"{clean}\""));
        }
        "tiktok" => {
            let music_title = info_text(info, "music_title");
            let music_artist = info_text(info, "music_author");
            if !music_artist.is_empty() && !music_title.is_empty() {
                queries.push(format!("artist:\"{music_artist}\" track:\"{music_title}\""));
            }
            if !music_title.is_empty() {
                queries.push(format!("track:\"{music_title}\""));
            }
            if has_artist && !clean.is_empty() {
                queries.push(format!("artist:\"{artist_s}\" track:\"{clean}\""));
            }
            queries.push(format!("track:\"{clean}\""));
        }
        "nicovideo" => {
            queries.push(format!("track:\"{clean}\""));
            if clean != title {
                queries.push(format!("track:\"{title}\""));
            }
        }
        _ => {
            if has_artist {
                queries.push(format!("artist:\"{artist_s}\" track:\"{clean}\""));
            }
            queries.push(format!("track:\"{clean}\""));
        }
    }
    let bare = if clean.is_empty() {
        title.to_string()
    } else {
        clean.clone()
    };
    if !queries.contains(&bare) {
        queries.push(bare);
    }
    let mut deduped: Vec<String> = Vec::new();
    for q in queries {
        if !q.is_empty() && !deduped.contains(&q) {
            deduped.push(q);
        }
    }
    deduped
}

/// `_fetch_by_search` の比べる相手（題とアーティスト）。題が「アーティスト - 曲名」の形なら分ける。
pub fn reference(title: &str, artist: &Value) -> (String, Value) {
    let clean = text::clean_title(title);
    if text::has_dash(&clean) {
        let parts = text::dash_split_once(&clean);
        let ref_artist = if truthy(artist) {
            artist.clone()
        } else {
            Value::String(text::py_strip(&parts[0]).to_string())
        };
        return (text::py_strip(&parts[1]).to_string(), ref_artist);
    }
    (clean, artist.clone())
}

// ---- Deezer への問い合わせ ----

/// aiohttp の ClientError・TimeoutError に当たる失敗（Python はここで握りつぶす）。
struct ClientError(String);

/// 200 の応答の本文を、aiohttp の `resp.json(content_type=None)` と同じに読む。
///
/// 前後の ASCII の空白を除いて空なら None（JSON の null と同じ扱い）。文字は UTF-8 で読む。
fn parse_json(body: &[u8]) -> Result<Value, EnrichError> {
    let ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
    let start = body.iter().position(|b| !ws(b)).unwrap_or(body.len());
    let end = body.iter().rposition(|b| !ws(b)).map_or(start, |e| e + 1);
    let stripped = &body[start..end.max(start)];
    if stripped.is_empty() {
        return Ok(Value::Null);
    }
    let text = std::str::from_utf8(stripped)
        .map_err(|e| EnrichError::Json(format!("UnicodeDecodeError: {e}")))?;
    serde_json::from_str(text).map_err(|e| EnrichError::Json(e.to_string()))
}

impl Deezer {
    /// GET して (状態, 本文) を返す。本文は 200 のときだけ読む（aiohttp も 200 以外は読まない）。
    async fn get(
        &self,
        url: &yarl::Url,
        timeout: Duration,
    ) -> Result<(u16, Option<Vec<u8>>), ClientError> {
        if !matches!(url.scheme.as_str(), "http" | "https") || url.netloc.is_empty() {
            return Err(ClientError(format!(
                "unsupported URL: {}",
                url.to_request_url()
            )));
        }
        let work = async {
            // aiohttp は、つないだあとで相手が答えずに切ったとき（ServerDisconnectedError・ClientOSError）に
            // GET を 1 回だけやり直す（retry_persistent_connection）。つなげなかった・時間切れはやり直さない。
            let mut retried = false;
            let resp = loop {
                match self.client.get(url.to_request_url()).send().await {
                    Ok(resp) => break resp,
                    Err(e)
                        if !retried
                            && !e.is_connect()
                            && !e.is_timeout()
                            && !e.is_redirect()
                            && !e.is_builder() =>
                    {
                        retried = true;
                    }
                    Err(e) => return Err(ClientError(e.to_string())),
                }
            };
            let status = resp.status().as_u16();
            if status != 200 {
                return Ok((status, None));
            }
            let body = resp.bytes().await.map_err(|e| ClientError(e.to_string()))?;
            Ok((status, Some(body.to_vec())))
        };
        // 時間切れは本文を読み終えるまでの全体（aiohttp の ClientTimeout(total=…)）。
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| ClientError("timeout".into()))?
    }

    /// Python の `_fetch_by_isrc`。Ok(None) は Python の None（見つからない・失敗。検索に回る）。
    async fn fetch_by_isrc(&self, isrc: &Value) -> Result<Option<Value>, EnrichError> {
        let isrc_text = python_str(isrc);
        let url = match self.isrc_url(isrc) {
            Ok(u) => u,
            Err(e) => {
                warn!("Deezer ISRC 検索エラー: {}", e.0);
                return Ok(None);
            }
        };
        match self.get(&url, self.api_timeout).await {
            Err(ClientError(e)) => {
                warn!("Deezer ISRC 検索エラー: {e}");
                Ok(None)
            }
            Ok((status, None)) => {
                warn!("Deezer: ISRC={isrc_text} の検索で HTTP {status} エラー");
                Ok(None)
            }
            Ok((_, Some(body))) => {
                let data = parse_json(&body)?;
                // `"error" in data`（辞書なら鍵、リストなら要素、文字列なら部分文字列。ほかは TypeError）。
                let has_error = match &data {
                    Value::Object(map) => map.contains_key("error"),
                    Value::Array(items) => items.iter().any(|v| v.as_str() == Some("error")),
                    Value::String(s) => s.contains("error"),
                    other => {
                        return Err(EnrichError::Type(format!(
                            "argument of type '{}' is not iterable",
                            type_name(other)
                        )));
                    }
                };
                if has_error {
                    info!("Deezer: ISRC={isrc_text} 未登録");
                    return Ok(None);
                }
                Ok(Some(data))
            }
        }
    }

    /// Python の `_fetch_by_search`。
    async fn fetch_by_search(
        &self,
        title: &Value,
        artist: &Value,
        site: &str,
        info: &Map<String, Value>,
    ) -> Result<Option<Value>, EnrichError> {
        let title = as_str(title, "expected string or bytes-like object, got")?;
        let (ref_title, ref_artist) = reference(title, artist);
        let queries = build_search_queries(title, artist, site, info);
        let mut best: Option<Value> = None;
        let mut best_score = 0.0f64;
        for q in &queries {
            let url = match self.search_url(q) {
                Ok(u) => u,
                Err(e) => {
                    warn!("Deezer テキスト検索エラー (q={}): {}", repr_str(q), e.0);
                    continue;
                }
            };
            let body = match self.get(&url, self.api_timeout).await {
                Err(ClientError(e)) => {
                    warn!("Deezer テキスト検索エラー (q={}): {e}", repr_str(q));
                    continue;
                }
                Ok((status, None)) => {
                    warn!(
                        "Deezer テキスト検索 HTTP {status} エラー (q={})",
                        repr_str(q)
                    );
                    continue;
                }
                Ok((_, Some(body))) => body,
            };
            let data = parse_json(&body)?;
            let items = or(get(&data, "data")?, &NULL).clone();
            // `for item in items`（リストは要素、辞書は鍵、文字列は 1 文字ずつ。数・真偽は TypeError）。
            let items: Vec<Value> = match items {
                Value::Null => Vec::new(),
                Value::Array(a) => a,
                Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
                Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
                other => {
                    return Err(EnrichError::Type(format!(
                        "'{}' object is not iterable",
                        type_name(&other)
                    )));
                }
            };
            for item in items {
                let score = score_result(&item, &ref_title, &ref_artist)?;
                if score > best_score {
                    best_score = score;
                    best = Some(item.clone());
                }
                if score >= HIGH_SCORE {
                    let title = get(&item, "title").map(python_repr).unwrap_or_default();
                    info!(
                        "Deezer 高精度ヒット (score={score:.2}): q={} → {title}",
                        repr_str(q)
                    );
                    return Ok(Some(item));
                }
            }
        }
        match best {
            Some(item) if truthy(&item) && best_score >= MIN_SCORE => {
                let title = get(&item, "title").map(python_repr).unwrap_or_default();
                info!("Deezer ベストマッチ採用 (score={best_score:.2}): {title}");
                Ok(Some(item))
            }
            _ => Ok(None),
        }
    }

    /// Python の `_download_bytes`（カバー画像。失敗は None）。url が文字列でなければ TypeError。
    async fn download_bytes(&self, url_value: &Value) -> Result<Option<Vec<u8>>, EnrichError> {
        let url_text = match url_value {
            Value::String(s) => s.as_str(),
            other => {
                return Err(EnrichError::Type(format!(
                    "Constructor parameter should be str, not {}",
                    type_name(other)
                )));
            }
        };
        let url = match yarl::parse(url_text) {
            Ok(u) => u,
            Err(e) => {
                warn!("カバー画像取得エラー: URL={url_text}, {}", e.0);
                return Ok(None);
            }
        };
        match self.get(&url, self.cover_timeout).await {
            Ok((200, Some(body))) => Ok(Some(body)),
            Ok((status, _)) => {
                warn!("カバー画像取得エラー: URL={url_text}, HTTP {status}");
                Ok(None)
            }
            Err(ClientError(e)) => {
                warn!("カバー画像取得エラー: URL={url_text}, {e}");
                Ok(None)
            }
        }
    }
}

/// Python の `_cover_url`: カバー画像の URL を大きい順に探す（cover_xl → cover_big → cover）。
pub fn cover_url(data: &Value) -> Result<Value, EnrichError> {
    let album = or(get(data, "album")?, &NULL);
    if !truthy(album) {
        return Ok(Value::Null);
    }
    let xl = get(album, "cover_xl")?;
    let big = get(album, "cover_big")?;
    let small = get(album, "cover")?;
    Ok(or(xl, or(big, small)).clone())
}

/// Python の `enrich_metadata`: Deezer から曲の情報を取って MP3 のタグを書き直す。
///
/// `site` は Python の `detect_site(info)` の結果。Ok(true) = 書いた、Ok(false) = 飛ばした・見つからない・
/// 書けなかった、Err = Python ならここから例外が外へ抜ける場合。
pub async fn enrich_metadata(
    deezer: &Deezer,
    mp3: &Path,
    info: &Value,
    site: &str,
) -> Result<bool, EnrichError> {
    let Value::Object(info_map) = info else {
        return Err(EnrichError::Type(format!(
            "'{}' object has no attribute 'get'",
            type_name(info)
        )));
    };
    let field = |key: &str| info_map.get(key).unwrap_or(&NULL);
    let isrc = field("isrc");
    let title = or(field("track"), or(field("title"), field("alt_title")));
    let artist = or(
        field("artist"),
        or(
            field("album_artist"),
            or(field("creator"), field("uploader")),
        ),
    );
    if !truthy(isrc) && !truthy(title) {
        return Ok(false);
    }
    let name = mp3
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut data: Option<Value> = None;
    if truthy(isrc) {
        data = deezer.fetch_by_isrc(isrc).await?;
    }
    if data.is_none() && truthy(title) {
        data = deezer
            .fetch_by_search(title, artist, site, info_map)
            .await?;
    }
    let Some(data) = data.filter(truthy) else {
        info!("Deezer: 該当なし ({name})");
        return Ok(false);
    };
    let url = cover_url(&data)?;
    let cover = if truthy(&url) {
        deezer.download_bytes(&url).await?
    } else {
        None
    };
    let path = mp3.to_path_buf();
    let written =
        tokio::task::spawn_blocking(move || id3::write_tags(&path, &data, cover.as_deref())).await;
    match written {
        Ok(Ok(())) => {
            info!("Deezer メタデータ適用完了: {name}");
            Ok(true)
        }
        Ok(Err(e)) => {
            warn!("タグ書き込みエラー ({name}): {e}");
            Ok(false)
        }
        Err(e) => {
            warn!("タグ書き込みエラー ({name}): {e}");
            Ok(false)
        }
    }
}
