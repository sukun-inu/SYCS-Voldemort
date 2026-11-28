//! ニュースの配信。Python の `services/news_service.py`。
//!
//! 設定はギルドの `news_feeds`（フィードの ID → `channel_id`・`query`・`interval`〔分〕・`last_run`・
//! `seen_hashes`）。5 分ごと（と、管理画面からの依頼 `news_feeds`）に全ギルド・全フィードを巡回し、
//! `interval` が経ったフィードだけ Google News の RSS を取りに行く。まだ送っていない記事（リンクの md5 で
//! 覚える）を新しい方から 5 件まで選び、**古い順に** Embed で送る（RSS は新しい順なので、そのまま送ると
//! チャンネルの中で時系列が逆になる）。Groq の鍵があれば要約（400 文字まで）を付ける。巡回のあと、
//! 取得に失敗していても `last_run` を書き、`seen_hashes` は直近 300 件だけ残す（[`SEEN_KEEP`]）。
//!
//! 送れなかった記事は「送った」に入れないので、次の巡回でまた送ろうとする（Python と同じ）。
//!
//! # Python と揃えてあるもの
//!
//! - 行き先: `quote()` で作った URL を aiohttp が送り直す形まで同じ（`' ` だけ `%27` のまま送る。意味は同じ）
//! - RSS の読み方（`xml.etree`）: `channel` の直下の `item`、名前空間つきは読まない、子要素より前の文字だけ、
//!   題の最後の ` - ` から後ろを配信元にする、説明は実体参照とタグを落として 300 文字、題と同じ始まりなら消す
//! - 日付の読み方（`email.utils`）と書き方、要約の整え方、favicon の URL、Embed の形
//! - Groq に送る問い（`temperature` 0.2・システムへの指示・「タイトル: …」の並び）と、要約を 6 時間覚えること
//!
//! # Python と違うところ（どれも安全な側）
//!
//! - 設定が壊れている（`interval` が数でない、など）とき、Python は例外で**巡回ごと止まる**（ほかのギルドも
//!   送られない）。こちらはそのフィードだけ飛ばして警告する
//! - RSS の文字コード: UTF-8・US-ASCII・ISO-8859-1・UTF-16 だけ読む（Python はほかの 1 バイトの文字コードも
//!   読み、Shift_JIS などでは例外で巡回ごと止まる）。DTD のある XML は読まない（Python は内部の実体を展開する）
//! - 書き戻すとき、ギルドの設定が消えていたら何もしない（Python は空のギルドを作り直す）

use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{
    Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, Offset, TimeZone, Utc,
};
use md5::{Digest, Md5};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::{Value, json};
use serenity::all::{
    Cache, ChannelId, CreateEmbed, CreateEmbedAuthor, CreateEmbedFooter, CreateMessage, GuildId,
    Http,
};
use sycs_core::env::Env;
use sycs_core::settings::{Settings, SettingsCache};
use sycs_core::ttl_cache::TtlCache;
use sycs_core::url_safety;
use tracing::{error, warn};

use crate::groq::{Groq, python_float, python_is_space};
use crate::{email_date, html_unescape, log_channel};

/// 巡回の間隔。Python の news_feed_task と同じ 5 分。
pub const INTERVAL: Duration = Duration::from_secs(300);
/// 1 回の巡回で 1 フィードから送る記事の上限。
pub const MAX_PER_RUN: usize = 5;
/// 覚えておく「送った記事」の数（Python の `NEWS_SEEN_HASHES_KEEP`）。
///
/// **フィードが一度に返す記事の数より多くなければならない。** 少ないと、古い記事の印から押し出されて
/// 「まだ送っていない」に戻り、巡回のたびに同じ記事を送り直し続ける。Google News の RSS は 1 回に
/// 100〜106 件ほど返すので、以前の 100 件では実際にこれが起きうる。余裕を持たせて 300 件。
pub const SEEN_KEEP: usize = 300;
/// `interval` が無いときの分数。
pub const DEFAULT_INTERVAL_MINUTES: i64 = 60;
/// 説明の上限（文字）。
pub const DESC_MAX_CHARS: usize = 300;
/// 要約の上限（文字）。
pub const SUMMARY_MAX_CHARS: usize = 400;
/// RSS を取るときの待ち時間。
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// RSS を取るときに名乗る名前。
pub const USER_AGENT: &str = "Mozilla/5.0 (compatible; DiscordBot/1.0)";
/// Google News の場所。
pub const RSS_BASE: &str = "https://news.google.com";
/// Groq の用途の名前。
pub const BUCKET: &str = "news_summary";
/// 要約の 1 回の送信の上限。
pub const SUMMARY_TIMEOUT: Duration = Duration::from_secs(20);
/// 要約に使うモデルの既定（`NEWS_SUMMARY_MODEL`）。
pub const DEFAULT_SUMMARY_MODEL: &str = "openai/gpt-oss-120b";
/// 要約を覚えておく長さ（6 時間）と件数。
const SUMMARY_CACHE_TTL_SECONDS: f64 = 6.0 * 3600.0;
const SUMMARY_CACHE_MAX: usize = 1000;
/// Embed の色（discord.py の `Color.blue()`）。
pub const BLUE: u32 = 0x34_98_DB;
/// フッターに付ける Bot のアイコン。Python の `config.BOT_ICON_URL`。
pub const BOT_ICON_URL: &str = "https://cdn.discordapp.com/avatars/1350672236612288633/9d80744c9723eba8795a7eb3659552b3.webp?size=1024";
/// 要約のシステムへの指示。
pub const SUMMARY_SYSTEM_PROMPT: &str = "あなたはニュース要約アシスタントです。事実のみを簡潔に日本語で要約してください。推測・断定・誇張表現は避け、400文字以内で出力してください。前置きや箇条書き記号は不要です。";

/// 時刻帯の書いていない日付を、どの時刻帯の時刻として読むか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NaiveZone {
    /// その場の時刻帯（Python の `astimezone` と同じ。本番は `TZ=Asia/Tokyo`）。
    System,
    /// UTC（テストで固定する）。
    Utc,
}

/// 設定。
#[derive(Clone, Debug)]
pub struct NewsConfig {
    /// 要約に使うモデル（`NEWS_SUMMARY_MODEL`）。
    pub summary_model: String,
    /// RSS を取りに行く場所（本番は Google News。テストで偽物に向ける）。
    pub rss_base: String,
    /// RSS を取るときの待ち時間。
    pub fetch_timeout: Duration,
    /// 時刻帯の書いていない日付の読み方。
    pub naive_zone: NaiveZone,
}

impl NewsConfig {
    /// 環境変数から読む（空の `NEWS_SUMMARY_MODEL` は既定のモデルにする。Python は空のまま送って失敗する）。
    pub fn from_env(env: &Env) -> Self {
        Self {
            summary_model: env.string("NEWS_SUMMARY_MODEL", DEFAULT_SUMMARY_MODEL),
            rss_base: RSS_BASE.into(),
            fetch_timeout: FETCH_TIMEOUT,
            naive_zone: NaiveZone::System,
        }
    }
}

/// RSS の記事 1 件。Python の `_parse_rss` が作る辞書と同じ中身。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Article {
    /// 題（最後の ` - 配信元` を除いたもの）。
    pub title: String,
    /// 記事へのリンク。
    pub link: String,
    /// 公開日時（書いてあるまま）。
    pub pub_date: String,
    /// 説明（タグを落としたもの。題と同じ始まりなら空）。
    pub desc: String,
    /// 配信元の名前。
    pub source: String,
    /// 配信元のサイト（favicon を引くのに使う）。
    pub source_url: String,
}

/// 記事のリンクを、送った記事の印と要約の鍵にする（md5 の 16 進）。Python の `_url_hash`。
pub fn url_hash(url: &str) -> String {
    hex::encode(Md5::digest(url.as_bytes()))
}

/// Python の `urllib.parse.quote`（英数字と `_.-~/` 以外を `%XX` にする）。
const QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'/');

/// Python の `urllib.parse.quote(text)`。
pub fn quote(text: &str) -> String {
    utf8_percent_encode(text, QUOTE).to_string()
}

/// 行き先の `q=` の値。Python は `quote()` で作り、aiohttp（yarl）が送るときに `?:@!$'()*,` を元の文字に
/// 戻す。こちらは `'` だけ `%27` のまま送る（reqwest が `'` を `%27` に直すため。意味は同じ）。
const RSS_QUERY: &AsciiSet = &QUOTE
    .remove(b'?')
    .remove(b':')
    .remove(b'@')
    .remove(b'!')
    .remove(b'$')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b',');

/// RSS の行き先。Python の `_RSS_BASE.format(query=quote(query))`（を aiohttp が送る形）。
pub fn rss_url(base: &str, query: &str) -> String {
    format!(
        "{}/rss/search?q={}&hl=ja&gl=JP&ceid=JP:ja",
        base.trim_end_matches('/'),
        utf8_percent_encode(query, RSS_QUERY)
    )
}

/// Python の `\s`（文字列の正規表現）。Rust の `\s` に区切りの制御文字（U+001C〜U+001F）を足したもの。
const PY_SPACE: &str = r"[\s\x1C-\x1F]";

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("正しい正規表現"));
static SPACES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("{PY_SPACE}+")).expect("正しい正規表現"));
static BLANKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t]+").expect("正しい正規表現"));
static EMPTY_LINES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n{3,}").expect("正しい正規表現"));
static SUMMARY_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^要約[:：]{PY_SPACE}*")).expect("正しい正規表現"));

fn strip(text: &str) -> &str {
    text.trim_matches(python_is_space)
}

fn first_chars(text: &str, count: usize) -> &str {
    match text.char_indices().nth(count) {
        Some((i, _)) => &text[..i],
        None => text,
    }
}

/// HTML のタグと実体参照を落として、ただの文にする。Python の `_strip_html`。
///
/// 上限を超えたら、上限までの最後の空白で切って「…」を付ける（空白が無ければ上限で切る）。
pub fn strip_html(raw: &str, max_chars: usize) -> String {
    let text = html_unescape::unescape(raw);
    let text = TAG.replace_all(&text, " ");
    let text = SPACES.replace_all(&text, " ");
    let text = strip(&text);
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let head = first_chars(text, max_chars);
    let head = head.rsplit_once(' ').map_or(head, |(before, _)| before);
    format!("{head}…")
}

/// 公開日時を「2026年11月27日 10:23」（日本時間）にする。読めなければそのまま返す。Python の
/// `_format_pub_date`。
pub fn format_pub_date(raw: &str, naive_zone: NaiveZone) -> String {
    jst_of(raw, naive_zone).map_or_else(
        || raw.to_string(),
        |at| {
            use chrono::{Datelike, Timelike};
            format!(
                "{}年{}月{}日 {}:{:02}",
                at.year(),
                at.month(),
                at.day(),
                at.hour(),
                at.minute()
            )
        },
    )
}

/// Python の datetime が表せる範囲（1〜9999 年）か。
fn in_python_range(at: &NaiveDateTime) -> bool {
    use chrono::Datelike;
    (1..=9999).contains(&at.year())
}

fn jst_of(raw: &str, naive_zone: NaiveZone) -> Option<NaiveDateTime> {
    let parsed = email_date::parse(raw)?;
    let utc = match parsed.offset_seconds {
        Some(offset) => parsed
            .local
            .checked_sub_signed(ChronoDuration::seconds(i64::from(offset)))?,
        // 時刻帯が書いていなければ、その場の時刻帯の時刻として読む（Python の astimezone と同じ）。
        None => match naive_zone {
            NaiveZone::Utc => naive_to_utc(&Utc, parsed.local)?,
            NaiveZone::System => naive_to_utc(&Local, parsed.local)?,
        },
    };
    let jst = utc.checked_add_signed(ChronoDuration::hours(9))?;
    (in_python_range(&utc) && in_python_range(&jst)).then_some(jst)
}

/// 時刻帯の書いていない日時を、その時刻帯の時刻として UTC に直す。Python の `datetime.astimezone`
/// （時刻帯なしの日時に対するもの）と同じ決め方:
///
/// - まず「書いてある日時を UTC とみなした時刻」をその時刻帯の時刻に直す。それが 9999 年を超えると失敗する
/// - 2 回ある時刻（夏時間の終わり）は、先に来る方
/// - 無い時刻（夏時間の始まりで飛ばされた時刻）は、飛ぶ前の時刻帯で読む
fn naive_to_utc<Tz: TimeZone>(zone: &Tz, local: NaiveDateTime) -> Option<NaiveDateTime> {
    let seconds =
        |offset: Tz::Offset| ChronoDuration::seconds(i64::from(offset.fix().local_minus_utc()));
    let probe = local.checked_add_signed(seconds(zone.offset_from_utc_datetime(&local)))?;
    if !in_python_range(&probe) {
        return None;
    }
    let offset = match zone.offset_from_local_datetime(&local) {
        LocalResult::Single(offset) => offset,
        // 先に来る方は、UTC からのずれが大きい方（chrono が返す 2 つの並びは、時間の順とは限らない）。
        LocalResult::Ambiguous(a, b) => {
            if a.fix().local_minus_utc() >= b.fix().local_minus_utc() {
                a
            } else {
                b
            }
        }
        LocalResult::None => {
            zone.offset_from_utc_datetime(&local.checked_sub_signed(ChronoDuration::days(1))?)
        }
    };
    local.checked_sub_signed(seconds(offset))
}

/// 要約を表示用に整える。Python の `_normalize_summary_text`。
///
/// 空白の並びを 1 つに、3 行以上の空行を 2 行に、先頭の「要約:」を落とす。上限を超えたら「…」で切る
/// （指示しても守らないことがあるので、必ず Embed の項目に収める）。
pub fn normalize_summary(text: &str, max_chars: usize) -> String {
    let clean = strip(text);
    let clean = BLANKS.replace_all(clean, " ");
    let clean = EMPTY_LINES.replace_all(&clean, "\n\n");
    let clean = SUMMARY_PREFIX.replace(&clean, "");
    if clean.chars().count() <= max_chars {
        return clean.into_owned();
    }
    let head = first_chars(&clean, max_chars.saturating_sub(1));
    format!("{}…", head.trim_end_matches(python_is_space))
}

/// 配信元の favicon の URL。配信元のサイトが分からなければ `None`。Python の `_favicon_url`。
///
/// 分解できない URL（`https://[broken` など）は `Err`（Python では ValueError になり、その記事は送られない）。
pub fn favicon_url(source_url: &str) -> Result<Option<String>, String> {
    let netloc = url_safety::netloc(source_url).map_err(|e| e.to_string())?;
    Ok((!netloc.is_empty()).then(|| {
        format!(
            "https://www.google.com/s2/favicons?sz=128&domain={}",
            quote(&netloc)
        )
    }))
}

/// 文字コードに合わせて文字にする。読めない文字コードなら `None`。
///
/// XML の読み手（expat）がそのまま読める UTF-8・US-ASCII・ISO-8859-1・UTF-16 だけを読む。
fn decode_xml(raw: &[u8]) -> Option<String> {
    let utf16 = |bytes: &[u8], big: bool| {
        let (pairs, rest) = bytes.as_chunks::<2>();
        let units: Vec<u16> = pairs
            .iter()
            .map(|p| {
                if big {
                    u16::from_be_bytes(*p)
                } else {
                    u16::from_le_bytes(*p)
                }
            })
            .collect();
        rest.is_empty()
            .then(|| String::from_utf16(&units).ok())
            .flatten()
    };
    match raw {
        [0xEF, 0xBB, 0xBF, rest @ ..] => return String::from_utf8(rest.to_vec()).ok(),
        [0xFF, 0xFE, rest @ ..] => return utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => return utf16(rest, true),
        [b'<', 0, ..] => return utf16(raw, false),
        [0, b'<', ..] => return utf16(raw, true),
        _ => {}
    }
    static DECLARED: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::Regex::new(r#"^<\?xml[^>]*?encoding\s*=\s*["']([A-Za-z0-9._-]+)["']"#)
            .expect("正しい正規表現")
    });
    let declared = DECLARED
        .captures(raw)
        .and_then(|c| c.get(1))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).to_ascii_lowercase());
    match declared.as_deref() {
        None | Some("utf-8") => String::from_utf8(raw.to_vec()).ok(),
        Some("us-ascii") => raw
            .is_ascii()
            .then(|| String::from_utf8(raw.to_vec()).ok())
            .flatten(),
        Some("iso-8859-1") => Some(raw.iter().map(|b| char::from(*b)).collect()),
        Some(_) => None,
    }
}

/// 要素の文字（最初の子要素より前）。Python の `Element.text`（コメントは飛ばす）。
fn text_of(node: roxmltree::Node<'_, '_>) -> String {
    let mut text = String::new();
    for child in node.children() {
        if child.is_element() {
            break;
        }
        if child.is_text() {
            text.push_str(child.text().unwrap_or(""));
        }
    }
    text
}

/// 名前空間の無い、その名前の要素か（Python の `find("item")` は、名前空間つきの要素には当たらない）。
fn is_named(node: &roxmltree::Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace().is_none() && node.tag_name().name() == name
}

/// その名前の最初の子要素。Python の `Element.find(name)`。
fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children().find(|n| is_named(n, name))
}

/// RSS のバイト列から記事の一覧を作る。読めなければ空（1 つのフィードの失敗で巡回を止めない）。
/// Python の `_parse_rss`。
pub fn parse_rss(raw: &[u8]) -> Vec<Article> {
    let Some(text) = decode_xml(raw) else {
        error!("[news_service] RSS parse error: 読めない文字コードです");
        return Vec::new();
    };
    let doc = match roxmltree::Document::parse(&text) {
        Ok(doc) => doc,
        Err(e) => {
            error!("[news_service] RSS parse error: {e}");
            return Vec::new();
        }
    };
    let Some(channel) = child(doc.root_element(), "channel") else {
        return Vec::new();
    };
    let mut articles = Vec::new();
    for item in channel.children().filter(|n| is_named(n, "item")) {
        let (Some(title_el), Some(link_el)) = (child(item, "title"), child(item, "link")) else {
            continue;
        };
        // 題に「 - 配信元」が付いていることがあるので、最後の区切りで分ける。
        let full_title = text_of(title_el);
        let full_title = strip(&full_title);
        let (title, source_from_title) = full_title.rsplit_once(" - ").unwrap_or((full_title, ""));
        let source_el = child(item, "source");
        let source = match source_el {
            Some(el) => strip(&text_of(el)).to_string(),
            None => source_from_title.to_string(),
        };
        // <source url="https://..."> に配信元のサイトが入っている（記事へのリンクとは別物）。
        let source_url = source_el
            .and_then(|el| el.attribute("url"))
            .map(|u| strip(u).to_string())
            .unwrap_or_default();
        let desc_raw = child(item, "description").map(text_of).unwrap_or_default();
        let mut desc = strip_html(&desc_raw, DESC_MAX_CHARS);
        // 題と同じ始まりなら説明にしない（Google News の説明は題の繰り返しであることが多い）。
        let title_head: String = title.to_lowercase().chars().take(30).collect();
        if desc.to_lowercase().starts_with(&title_head) {
            desc.clear();
        }
        articles.push(Article {
            title: title.to_string(),
            link: strip(&text_of(link_el)).to_string(),
            pub_date: child(item, "pubDate").map(text_of).unwrap_or_default(),
            desc,
            source,
            source_url,
        });
    }
    articles
}

/// Groq に渡す記事の文。渡すものが無ければ `None`。Python の `_summarize_article` の前半。
///
/// 中身が空の行（「配信元:」だけ）は落とす。行が `:` で終わるかで見ているので、題が `:` で終わる記事は
/// 題の行も落ちる（Python と同じ）。
pub fn source_text(article: &Article) -> Option<String> {
    let lines = [
        format!("タイトル: {}", article.title),
        format!("配信元: {}", article.source),
        format!("本文抜粋: {}", article.desc),
        format!("URL: {}", article.link),
    ];
    let kept: Vec<&str> = lines
        .iter()
        .map(|l| strip(l))
        .filter(|l| !l.is_empty() && !l.ends_with(':'))
        .collect();
    (!kept.is_empty()).then(|| kept.join("\n"))
}

/// 要約の鍵（リンク・題・説明のどれが違っても別の要約）。
pub fn summary_key(article: &Article) -> String {
    url_hash(&format!(
        "{}|{}|{}",
        article.link, article.title, article.desc
    ))
}

/// Groq へ送る本文。
pub fn summary_request(model: &str, text: &str) -> Value {
    json!({
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
    })
}

/// 記事を送る Embed。Python の `run_news_feeds` の中の組み立て。
///
/// 記事の写真は取れない（Google News のリンクは配信元へ直接は飛ばない）ので、配信元の favicon を出す。
/// 配信元の URL が分解できなければ `Err`（その記事は送らない。Python と同じ）。
pub fn article_embed(
    article: &Article,
    summary: &str,
    naive_zone: NaiveZone,
) -> Result<CreateEmbed, String> {
    let mut embed = CreateEmbed::new().colour(BLUE);
    // discord.py は、空の題・URL・説明を送らない。
    if !article.title.is_empty() {
        embed = embed.title(&article.title);
    }
    if !article.link.is_empty() {
        embed = embed.url(&article.link);
    }
    if !article.desc.is_empty() {
        embed = embed.description(&article.desc);
    }
    if !summary.is_empty() {
        embed = embed.field("要約 (Groq)", summary, false);
    }
    let favicon = favicon_url(&article.source_url)?;
    if !article.source.is_empty() {
        let mut author = CreateEmbedAuthor::new(&article.source);
        if let Some(icon) = &favicon {
            author = author.icon_url(icon);
        }
        embed = embed.author(author);
    }
    if let Some(icon) = favicon {
        embed = embed.thumbnail(icon);
    }
    if !article.pub_date.is_empty() {
        let footer = CreateEmbedFooter::new(format_pub_date(&article.pub_date, naive_zone))
            .icon_url(BOT_ICON_URL);
        embed = embed.footer(footer);
    }
    Ok(embed)
}

/// 1 フィードぶんの設定（巡回する番のもの）。
#[derive(Clone, Debug, PartialEq)]
pub struct Feed {
    /// 送る先のチャンネル。
    pub channel_id: u64,
    /// 検索の語。
    pub query: String,
    /// 送った記事の印（設定に入っているまま。文字列でないものが混じっていても残す）。
    pub seen: Vec<Value>,
}

/// フィードの設定を読んだ結果。
#[derive(Clone, Debug, PartialEq)]
pub enum FeedTurn {
    /// 巡回する。
    Due(Feed),
    /// まだ `interval` が経っていない。
    NotDue,
    /// 検索の語かチャンネルが未設定。
    Incomplete,
    /// 設定が読めない（Python は例外で巡回ごと止まる。こちらはこのフィードだけ飛ばす）。
    Unreadable(&'static str),
}

/// Python の `float(value)`（設定に入りうるもの）。
fn python_float_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::String(s) => python_float(s),
        _ => None,
    }
}

/// フィードの設定を読み、巡回する番かを決める。Python の `run_news_feeds` の先頭と同じ順に読む
/// （`interval` と `last_run` を見て、番でなければほかは読まない）。
pub fn feed_turn(feed: &Value, now: f64) -> FeedTurn {
    let Some(feed) = feed.as_object() else {
        return FeedTurn::Unreadable("フィードの設定が辞書ではありません");
    };
    let interval = match feed.get("interval") {
        None => Some(DEFAULT_INTERVAL_MINUTES),
        Some(v) => log_channel::python_int(v),
    };
    let Some(interval) = interval else {
        return FeedTurn::Unreadable("interval が数ではありません");
    };
    let last_run = match feed.get("last_run") {
        None => Some(0.0),
        Some(v) => python_float_value(v),
    };
    let Some(last_run) = last_run else {
        return FeedTurn::Unreadable("last_run が数ではありません");
    };
    if now - last_run < (interval as f64) * 60.0 {
        return FeedTurn::NotDue;
    }
    let query = match feed.get("query") {
        None => "",
        Some(Value::String(q)) => q.as_str(),
        // Python の「偽」（null・0・false・空の並び）は未設定と同じ。それ以外は URL にできずに失敗する。
        Some(Value::Null) => "",
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => "",
        Some(Value::Bool(false)) => "",
        Some(Value::Array(a)) if a.is_empty() => "",
        Some(Value::Object(o)) if o.is_empty() => "",
        Some(_) => return FeedTurn::Unreadable("query が文字列ではありません"),
    };
    let channel = match feed.get("channel_id") {
        None => Some(0),
        Some(v) => log_channel::python_int(v),
    };
    let Some(channel) = channel else {
        return FeedTurn::Unreadable("channel_id が数ではありません");
    };
    // Python の list(value): 並びはそのまま、文字列は 1 文字ずつ、辞書は鍵。
    let seen = match feed.get("seen_hashes") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        Some(Value::Object(o)) => o.keys().map(|k| json!(k)).collect(),
        Some(_) => return FeedTurn::Unreadable("seen_hashes が並びではありません"),
    };
    if query.is_empty() || channel == 0 {
        return FeedTurn::Incomplete;
    }
    // 負の ID などは、どのチャンネルにも当たらない（Python は get_channel が None を返して飛ばす）。
    FeedTurn::Due(Feed {
        channel_id: u64::try_from(channel).unwrap_or(0),
        query: query.to_string(),
        seen,
    })
}

/// まだ送っていない記事を、送る順（古い順）に並べる。新しい方から [`MAX_PER_RUN`] 件まで。
///
/// 「送ったか」は巡回の始めの印で決める（同じ RSS に同じリンクが 2 回あれば 2 回送る。Python と同じ）。
pub fn articles_to_send<'a>(articles: &'a [Article], seen: &[Value]) -> Vec<&'a Article> {
    let is_seen = |hash: &str| seen.iter().any(|s| s.as_str() == Some(hash));
    let mut fresh: Vec<&Article> = articles
        .iter()
        .filter(|a| !is_seen(&url_hash(&a.link)))
        .take(MAX_PER_RUN)
        .collect();
    fresh.reverse();
    fresh
}

/// 巡回の結果を設定へ書く。Python の `_news_feed_state_mutator`。
///
/// フィードが無くなっていたら何もしない（消したフィードを作り直さない）。`seen` は直近 [`SEEN_KEEP`] 件だけ残す。
pub fn apply_feed_state(
    settings: &mut Settings,
    guild_id: u64,
    feed_id: &str,
    last_run: f64,
    seen: &[Value],
) {
    let Some(row) = settings
        .guilds
        .get_mut(&guild_id.to_string())
        .and_then(|g| g.get_mut("news_feeds"))
        .and_then(Value::as_object_mut)
        .and_then(|feeds| feeds.get_mut(feed_id))
    else {
        return;
    };
    if !row.is_object() {
        *row = json!({});
    }
    let kept = &seen[seen.len().saturating_sub(SEEN_KEEP)..];
    if let Some(row) = row.as_object_mut() {
        row.insert("last_run".into(), json!(last_run));
        row.insert("seen_hashes".into(), json!(kept));
    }
}

/// プロセスの中の時刻（秒）。Python の `time.monotonic()`。
fn monotonic() -> f64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_secs_f64()
}

/// ニュースを取って要約する口。1 つを使い回す（要約を覚えておくため）。
pub struct News {
    config: NewsConfig,
    http: reqwest::Client,
    groq: Arc<Groq>,
    summaries: Mutex<TtlCache<String, String>>,
}

impl News {
    /// 作る。Groq は、ほかの用途（投稿の判定など）と同じものを渡す（用途ごとの枠を共有するため）。
    pub fn new(config: NewsConfig, groq: Arc<Groq>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.fetch_timeout)
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            groq,
            summaries: Mutex::new(TtlCache::new(SUMMARY_CACHE_TTL_SECONDS, SUMMARY_CACHE_MAX)),
        }
    }

    /// 時刻帯の書いていない日付の読み方。
    pub fn naive_zone(&self) -> NaiveZone {
        self.config.naive_zone
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, TtlCache<String, String>> {
        self.summaries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Google News の RSS を取って読む。通信の失敗も読めない XML も空にする（1 つのフィードの失敗で、
    /// ほかのギルド・ほかのフィードを止めない）。Python の `_fetch_articles`。
    pub async fn fetch_articles(&self, query: &str) -> Vec<Article> {
        let url = rss_url(&self.config.rss_base, query);
        let mut sent = self.http.get(&url).send().await;
        // 応答の前に接続が切れたら、もう 1 回だけ送り直す（Python が使う aiohttp と同じ。時間切れや、
        // リダイレクトが終わらないときは送り直さない）。つなげなかったときも 1 回だけやり直す
        // （相手には届かないので、aiohttp が同じことをしているかは外からは見分けられない）。
        let dropped = |e: &reqwest::Error| !e.is_timeout() && (e.is_connect() || e.is_request());
        if sent.as_ref().is_err_and(dropped) {
            sent = self.http.get(&url).send().await;
        }
        let raw = match sent {
            Ok(response) if response.status().as_u16() != 200 => {
                warn!(
                    "[news_service] RSS fetch status={} query={query}",
                    response.status().as_u16()
                );
                return Vec::new();
            }
            Ok(response) => match response.bytes().await {
                Ok(raw) => raw,
                Err(e) => {
                    error!("[news_service] RSS fetch error query={query}: {e}");
                    return Vec::new();
                }
            },
            Err(e) => {
                error!("[news_service] RSS fetch error query={query}: {e}");
                return Vec::new();
            }
        };
        // 読むのは CPU の仕事なので、別のスレッドでする（記事 100 件ぶんがまとめて走る）。
        tokio::task::spawn_blocking(move || parse_rss(&raw))
            .await
            .unwrap_or_else(|e| {
                error!("[news_service] RSS parse error: {e}");
                Vec::new()
            })
    }

    /// Groq で 400 文字までの要約を作る。鍵が無い・失敗したときは空（要約なしで送る）。
    /// Python の `_summarize_article`。
    pub async fn summarize(&self, article: &Article) -> String {
        let Some(text) = source_text(article) else {
            return String::new();
        };
        let key = summary_key(article);
        if let Some(cached) = self.cache().get(&key, monotonic()) {
            return cached;
        }
        if !self.groq.has_key() {
            return String::new();
        }
        let body = summary_request(&self.config.summary_model, &text);
        let response = match self
            .groq
            .chat_completion(BUCKET, SUMMARY_TIMEOUT, &body)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                warn!("[news_service] summarize failed url={}: {e}", article.link);
                return String::new();
            }
        };
        // 答えの文が無い（null）ときは空。文字列でないものも空にする（Python は警告を出して空にする）。
        let content = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("");
        let summary = normalize_summary(content, SUMMARY_MAX_CHARS);
        if !summary.is_empty() {
            self.cache().set(key, summary.clone(), monotonic());
        }
        summary
    }
}

/// 巡回の出口（Discord への送信と、設定の書き戻し）。テストでは記録するだけの偽物に差し替える。
pub trait Outlet: Sync {
    /// そのギルドのテキストチャンネル（お知らせを含む）か。ギルドやチャンネルが見えなければ偽。
    fn is_text_channel(&self, guild_id: u64, channel_id: u64) -> bool;
    /// Embed を送る。
    fn send(
        &self,
        channel_id: u64,
        embed: CreateEmbed,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// 巡回の結果（時刻と、送った記事の印）を設定へ書く。
    fn save_state(
        &self,
        guild_id: u64,
        feed_id: &str,
        last_run: f64,
        seen: &[Value],
    ) -> impl Future<Output = ()> + Send;
}

/// 全ギルド・全フィードを巡回する。Python の `run_news_feeds`。
///
/// `snapshot` はいまの設定（ギルドごとに取り直す。Python もギルドごとに読む）。`handles` が偽のギルドは
/// 飛ばす（`BOT_ONLY_GUILD_ID`）。`now` は巡回の始めの時刻（UNIX 秒。全フィードに同じ値を書く）。
pub async fn run_news_feeds<O, S, H>(news: &News, outlet: &O, snapshot: S, handles: H, now: f64)
where
    O: Outlet,
    S: Fn() -> Arc<Settings> + Sync,
    H: Fn(u64) -> bool + Sync,
{
    let guild_ids: Vec<u64> = snapshot()
        .guilds
        .keys()
        .filter_map(|k| k.parse().ok())
        .collect();
    for guild_id in guild_ids {
        if !handles(guild_id) {
            continue;
        }
        let settings = snapshot();
        let Some(feeds) = settings.guild(guild_id).and_then(|g| g.get("news_feeds")) else {
            continue;
        };
        let Some(feeds) = feeds.as_object() else {
            warn!(
                guild_id,
                "[news_service] news_feeds が辞書ではないので、このギルドを飛ばします"
            );
            continue;
        };
        for (feed_id, value) in feeds {
            let feed = match feed_turn(value, now) {
                FeedTurn::Due(feed) => feed,
                FeedTurn::NotDue | FeedTurn::Incomplete => continue,
                FeedTurn::Unreadable(why) => {
                    warn!(
                        guild_id,
                        feed = %feed_id,
                        "[news_service] フィードの設定を読めないので飛ばします: {why}"
                    );
                    continue;
                }
            };
            if !outlet.is_text_channel(guild_id, feed.channel_id) {
                continue;
            }
            let articles = news.fetch_articles(&feed.query).await;
            let mut seen = feed.seen;
            for article in articles_to_send(&articles, &seen) {
                let summary = news.summarize(article).await;
                let sent = match article_embed(article, &summary, news.naive_zone()) {
                    Ok(embed) => outlet.send(feed.channel_id, embed).await,
                    Err(e) => Err(e),
                };
                match sent {
                    Ok(()) => seen.push(json!(url_hash(&article.link))),
                    Err(e) => error!("[news_service] send error feed={feed_id}: {e}"),
                }
            }
            outlet.save_state(guild_id, feed_id, now, &seen).await;
        }
    }
}

/// 本物の Discord と設定への出口。
pub struct DiscordOutlet<'a> {
    /// serenity のキャッシュ（チャンネルを確かめる）。
    pub cache: &'a Cache,
    /// Discord へ送る口。
    pub http: &'a Http,
    /// ギルドごとの設定（巡回の結果を書く）。
    pub settings: &'a SettingsCache,
}

impl Outlet for DiscordOutlet<'_> {
    fn is_text_channel(&self, guild_id: u64, channel_id: u64) -> bool {
        guild_id > 0
            && channel_id > 0
            && log_channel::text_channel(self.cache, GuildId::new(guild_id), Some(channel_id))
                .is_some()
    }

    async fn send(&self, channel_id: u64, embed: CreateEmbed) -> Result<(), String> {
        ChannelId::new(channel_id)
            .send_message(self.http, CreateMessage::new().embed(embed))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn save_state(&self, guild_id: u64, feed_id: &str, last_run: f64, seen: &[Value]) {
        let written = self
            .settings
            .transact(|s| apply_feed_state(s, guild_id, feed_id, last_run, seen))
            .await;
        if let Err(e) = written {
            warn!(
                guild_id,
                feed = %feed_id,
                "[news_service] 巡回の結果を書けませんでした（次の巡回で同じ記事を送り直すことがあります）: {e}"
            );
        }
    }
}

/// いまの時刻（UNIX 秒）。Python の `time.time()`。
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn article(title: &str, link: &str) -> Article {
        Article {
            title: title.into(),
            link: link.into(),
            pub_date: String::new(),
            desc: String::new(),
            source: String::new(),
            source_url: String::new(),
        }
    }

    /// フッターのアイコンが Python の設定と同じであること。
    #[test]
    fn the_footer_icon_matches_python() {
        let config = include_str!("../../../../config.py").replace("\" \"", "");
        assert!(
            config.contains(BOT_ICON_URL),
            "config.py の BOT_ICON_URL と違う"
        );
    }

    /// 行き先: quote() と同じ符号化で、aiohttp が戻す文字は戻した形。
    #[test]
    fn the_rss_url_is_what_aiohttp_sends() {
        assert_eq!(
            rss_url("https://news.google.com", "AI ニュース"),
            "https://news.google.com/rss/search?q=AI%20%E3%83%8B%E3%83%A5%E3%83%BC%E3%82%B9&hl=ja&gl=JP&ceid=JP:ja"
        );
        let q = |query: &str| {
            let url = rss_url("http://x/", query);
            url["http://x/rss/search?q=".len()..url.len() - "&hl=ja&gl=JP&ceid=JP:ja".len()]
                .to_string()
        };
        assert_eq!(q("C++ a&b=c;d"), "C%2B%2B%20a%26b%3Dc%3Bd");
        assert_eq!(q("a/b?c:d@e!$()*,"), "a/b?c:d@e!$()*,");
        assert_eq!(q("50% #x 'y'"), "50%25%20%23x%20%27y%27");
        assert_eq!(quote("a/b?c:d@e ~_.-"), "a/b%3Fc%3Ad%40e%20~_.-");
    }

    /// 巡回する番の決め方: interval（分）が経ったら。番でなければほかの値は読まない。
    #[test]
    fn a_feed_is_due_after_its_interval() {
        let feed = |extra: Value| {
            let mut v = json!({"channel_id": 5, "query": "q", "interval": 30, "last_run": 1000.0});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };
        let due = |v: &Value, now: f64| matches!(feed_turn(v, now), FeedTurn::Due(_));
        assert!(!due(&feed(json!({})), 1000.0 + 1799.9));
        assert!(due(&feed(json!({})), 1000.0 + 1800.0));
        // interval の既定は 60 分、last_run の既定は 0。
        assert_eq!(
            feed_turn(&json!({"channel_id": 5, "query": "q"}), 3599.0),
            FeedTurn::NotDue
        );
        assert!(due(&json!({"channel_id": 5, "query": "q"}), 3600.0));
        // 文字列の数も読む（Python の int()・float()）。
        assert!(due(
            &feed(json!({"interval": "1", "last_run": "940", "channel_id": " 5 "})),
            1000.0
        ));
        // 番でなければ、壊れたチャンネルも読まない。
        assert_eq!(
            feed_turn(&feed(json!({"channel_id": "x"})), 1000.0),
            FeedTurn::NotDue
        );
        assert!(matches!(
            feed_turn(&feed(json!({"channel_id": "x"})), 9999.0),
            FeedTurn::Unreadable(_)
        ));
    }

    /// 検索の語かチャンネルが無ければ巡回しない。読めない設定はそのフィードだけ飛ばす。
    #[test]
    fn incomplete_and_unreadable_feeds_are_skipped() {
        for v in [
            json!({"query": "q"}),
            json!({"channel_id": 5}),
            json!({"channel_id": 0, "query": "q"}),
            json!({"channel_id": 5, "query": ""}),
            json!({"channel_id": 5, "query": 0}),
            json!({"channel_id": 5, "query": []}),
        ] {
            assert_eq!(feed_turn(&v, 1e9), FeedTurn::Incomplete, "{v}");
        }
        for v in [
            json!("feed"),
            json!({"channel_id": 5, "query": "q", "interval": "soon"}),
            json!({"channel_id": 5, "query": "q", "last_run": []}),
            json!({"channel_id": 5, "query": 7}),
            json!({"channel_id": 5, "query": "q", "seen_hashes": 3}),
        ] {
            assert!(matches!(feed_turn(&v, 1e9), FeedTurn::Unreadable(_)), "{v}");
        }
        // 負のチャンネルは、どのチャンネルにも当たらない ID（0）にする。
        let FeedTurn::Due(feed) = feed_turn(&json!({"channel_id": -5, "query": "q"}), 1e9) else {
            panic!("巡回する番のはず");
        };
        assert_eq!(feed.channel_id, 0);
        // 送った記事の印: 文字列は 1 文字ずつ、辞書は鍵（Python の list()）。
        let FeedTurn::Due(feed) = feed_turn(
            &json!({"channel_id": 5, "query": "q", "seen_hashes": "ab"}),
            1e9,
        ) else {
            panic!("巡回する番のはず");
        };
        assert_eq!(feed.seen, [json!("a"), json!("b")]);
    }

    /// 新しい方から 5 件までを、古い順に送ること。送った記事は選ばないこと。
    #[test]
    fn up_to_five_new_articles_go_out_oldest_first() {
        let articles: Vec<Article> = (1..=8)
            .map(|i| article(&format!("t{i}"), &format!("https://x/{i}")))
            .collect();
        let titles = |seen: &[Value]| -> Vec<String> {
            articles_to_send(&articles, seen)
                .iter()
                .map(|a| a.title.clone())
                .collect()
        };
        assert_eq!(titles(&[]), ["t5", "t4", "t3", "t2", "t1"]);
        let seen = [
            json!(url_hash("https://x/1")),
            json!(url_hash("https://x/3")),
            json!(7),
        ];
        assert_eq!(titles(&seen), ["t7", "t6", "t5", "t4", "t2"]);
        assert_eq!(MAX_PER_RUN, 5);
    }

    fn settings(guilds: Value) -> Settings {
        Settings {
            version: 1,
            root: Default::default(),
            guilds: guilds
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    /// 書き戻し: 時刻と、直近 300 件の印。ほかの値は触らない。無いフィードは作らない。
    #[test]
    fn the_state_keeps_the_last_hashes() {
        let mut s = settings(json!({"1": {"news_feeds": {
            "a": {"channel_id": 5, "query": "q", "interval": 30, "last_run": 0.0, "seen_hashes": []},
            "broken": "x",
        }}}));
        let seen: Vec<Value> = (0..330).map(|i| json!(format!("h{i}"))).collect();
        apply_feed_state(&mut s, 1, "a", 123.5, &seen);
        let row = &s.guilds["1"]["news_feeds"]["a"];
        assert_eq!(row["last_run"], 123.5);
        assert_eq!(row["seen_hashes"].as_array().unwrap().len(), SEEN_KEEP);
        assert_eq!(row["seen_hashes"][0], "h30");
        assert_eq!(row["seen_hashes"][299], "h329");
        assert_eq!(
            (&row["channel_id"], &row["query"], &row["interval"]),
            (&json!(5), &json!("q"), &json!(30))
        );
        // 辞書でない行は、時刻と印だけの辞書にする（Python と同じ）。
        apply_feed_state(&mut s, 1, "broken", 1.0, &[]);
        assert_eq!(
            s.guilds["1"]["news_feeds"]["broken"],
            json!({"last_run": 1.0, "seen_hashes": []})
        );
        let before = s.clone();
        apply_feed_state(&mut s, 1, "gone", 9.0, &seen);
        apply_feed_state(&mut s, 2, "a", 9.0, &seen);
        assert_eq!(s, before, "無いフィード・無いギルドを作った");
    }

    /// 要約の鍵は、リンク・題・説明のどれが違っても変わること。
    #[test]
    fn the_summary_key_covers_link_title_and_description() {
        let base = article("t", "l");
        let key = summary_key(&base);
        assert_eq!(key, url_hash("l|t|"));
        let mut other = base.clone();
        other.desc = "d".into();
        assert_ne!(summary_key(&other), key);
        let mut other = base.clone();
        other.title = "u".into();
        assert_ne!(summary_key(&other), key);
        // 配信元は鍵に入れない（Python と同じ）。
        let mut other = base.clone();
        other.source = "s".into();
        assert_eq!(summary_key(&other), key);
    }

    /// 問いの形（モデル・temperature・システムへの指示）。
    #[test]
    fn the_summary_request_matches_python() {
        let python = include_str!("../../../../services/news_service.py");
        for part in [
            "あなたはニュース要約アシスタントです。",
            "事実のみを簡潔に日本語で要約してください。",
            "推測・断定・誇張表現は避け、400文字以内で出力してください。",
            "前置きや箇条書き記号は不要です。",
        ] {
            assert!(
                python.contains(part) && SUMMARY_SYSTEM_PROMPT.contains(part),
                "{part}"
            );
        }
        assert!(python.contains(&format!("\"{DEFAULT_SUMMARY_MODEL}\"")));
        let body = summary_request("m", "本文");
        assert_eq!(body["model"], "m");
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["messages"][0]["content"], SUMMARY_SYSTEM_PROMPT);
        assert_eq!(
            body["messages"][1],
            json!({"role": "user", "content": "本文"})
        );
    }

    /// 時刻帯の書いていない日付は、渡した時刻帯の時刻として読むこと。
    #[test]
    fn naive_dates_use_the_given_zone() {
        assert_eq!(
            format_pub_date("Fri, 27 Nov 2026 01:23:45 GMT", NaiveZone::Utc),
            "2026年11月27日 10:23"
        );
        assert_eq!(
            format_pub_date("Fri, 27 Nov 2026 01:23:45", NaiveZone::Utc),
            "2026年11月27日 10:23"
        );
        assert_eq!(format_pub_date("あとで", NaiveZone::Utc), "あとで");
        // 日本時間にしたときに 9999 年を超えるものは、そのまま返す（Python は OverflowError）。
        let late = "Fri, 31 Dec 9999 23:59:59 GMT";
        assert_eq!(format_pub_date(late, NaiveZone::Utc), late);
    }

    /// 時刻帯の書いていない日時は、その時刻帯のずれを引いて UTC にすること。その時刻帯の時刻に直して
    /// 9999 年を超えるものは失敗にすること（Python と同じ。本番は TZ=Asia/Tokyo）。
    #[test]
    fn naive_times_are_read_in_the_zone() {
        let tokyo = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
        let at = |text: &str| email_date::parse(text).unwrap().local;
        assert_eq!(
            naive_to_utc(&tokyo, at("27 Nov 2026 09:00:00")),
            Some(at("27 Nov 2026 00:00:00"))
        );
        assert_eq!(
            naive_to_utc(&Utc, at("27 Nov 2026 09:00:00")),
            Some(at("27 Nov 2026 09:00:00"))
        );
        // 15:00 を足すと 10000 年になる。UTC に直した結果（14:59）は範囲の中でも、失敗にする。
        assert_eq!(naive_to_utc(&tokyo, at("31 Dec 9999 23:59:59")), None);
        assert_eq!(
            naive_to_utc(&tokyo, at("31 Dec 9999 14:59:59")),
            Some(at("31 Dec 9999 05:59:59"))
        );
    }

    /// 夏時間のある時刻帯の代わり（単体テスト用）。X から Y の間だけ 1 時間進む。
    ///
    /// chrono の決まりに合わせて、2 回ある時刻では「標準時・夏時間」の順に返す（時間の順ではない）。
    #[derive(Clone)]
    struct Summer;

    impl Summer {
        fn starts() -> NaiveDateTime {
            email_date::parse("28 Mar 2027 01:00:00").unwrap().local
        }

        fn ends() -> NaiveDateTime {
            email_date::parse("31 Oct 2027 01:00:00").unwrap().local
        }

        fn offset(hours: i32) -> chrono::FixedOffset {
            chrono::FixedOffset::east_opt(hours * 3600).unwrap()
        }
    }

    impl TimeZone for Summer {
        type Offset = chrono::FixedOffset;

        fn from_offset(_: &Self::Offset) -> Self {
            Summer
        }

        fn offset_from_local_date(&self, _: &chrono::NaiveDate) -> LocalResult<Self::Offset> {
            LocalResult::Single(Self::offset(0))
        }

        fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<Self::Offset> {
            let hour = ChronoDuration::hours(1);
            // 始まり: 01:00 が 02:00 に飛ぶ（01:00〜01:59 は無い）。終わり: 02:00 が 01:00 に戻る（01:00〜01:59 が 2 回）。
            if *local >= Self::starts() && *local < Self::starts() + hour {
                LocalResult::None
            } else if *local >= Self::ends() && *local < Self::ends() + hour {
                LocalResult::Ambiguous(Self::offset(0), Self::offset(1))
            } else if *local >= Self::starts() + hour && *local < Self::ends() {
                LocalResult::Single(Self::offset(1))
            } else {
                LocalResult::Single(Self::offset(0))
            }
        }

        fn offset_from_utc_date(&self, _: &chrono::NaiveDate) -> Self::Offset {
            Self::offset(0)
        }

        fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> Self::Offset {
            Self::offset(i32::from(*utc >= Self::starts() && *utc < Self::ends()))
        }
    }

    /// 夏時間の境: 2 回ある時刻は先に来る方（夏時間）、無い時刻は飛ぶ前の時刻帯（標準時）で読むこと。
    /// Python の astimezone と同じ（6 つの時刻帯で突き合わせた。本番は夏時間の無い Asia/Tokyo）。
    #[test]
    fn summer_time_edges_are_read_like_python() {
        let at = |text: &str| email_date::parse(text).unwrap().local;
        // ふつうの時刻: 夏は 1 時間引く、冬は引かない。
        assert_eq!(
            naive_to_utc(&Summer, at("1 Jul 2027 12:00:00")),
            Some(at("1 Jul 2027 11:00:00"))
        );
        assert_eq!(
            naive_to_utc(&Summer, at("1 Dec 2027 12:00:00")),
            Some(at("1 Dec 2027 12:00:00"))
        );
        // 2 回ある 01:30: 先に来るのは夏時間の 01:30（UTC 00:30）。
        assert_eq!(
            naive_to_utc(&Summer, at("31 Oct 2027 01:30:00")),
            Some(at("31 Oct 2027 00:30:00"))
        );
        // 無い 01:30: 飛ぶ前（標準時）の 01:30 として読む。
        assert_eq!(
            naive_to_utc(&Summer, at("28 Mar 2027 01:30:00")),
            Some(at("28 Mar 2027 01:30:00"))
        );
    }

    /// 既定値が Python と同じであること。
    #[test]
    fn the_defaults_match_python() {
        let c = NewsConfig::from_env(&Env::from_fn(|_| None));
        assert_eq!(c.summary_model, "openai/gpt-oss-120b");
        assert_eq!(c.rss_base, "https://news.google.com");
        assert_eq!(c.fetch_timeout, Duration::from_secs(15));
        assert_eq!(c.naive_zone, NaiveZone::System);
        let c = NewsConfig::from_env(&Env::from_fn(|k| {
            (k == "NEWS_SUMMARY_MODEL").then(|| "other/model".to_string())
        }));
        assert_eq!(c.summary_model, "other/model");
        assert_eq!(
            (INTERVAL, MAX_PER_RUN, SEEN_KEEP),
            (Duration::from_secs(300), 5, 300)
        );
        // 覚える印の数は、Python の settings_store の値そのものと比べる（片方だけ変えると、送り直しの直しが
        // 片方にしか効かない）。
        let python = include_str!("../../../../services/settings_store.py");
        assert!(
            python.contains(&format!("\nNEWS_SEEN_HASHES_KEEP = {SEEN_KEEP}\n")),
            "Python の NEWS_SEEN_HASHES_KEEP と SEEN_KEEP が違う"
        );
        assert_eq!(
            (DESC_MAX_CHARS, SUMMARY_MAX_CHARS, BLUE),
            (300, 400, 0x3498DB)
        );
    }
}
