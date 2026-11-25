//! ギルドのログチャンネルへ Embed で書く。Python の `services/logging_service.py`。
//!
//! 移行の途中で Python と Rust の Bot が同じログチャンネルへ書くので、見た目（題・本文・
//! 色・作者・項目・時刻の書き方）と、送るかどうかの判断（ログレベル）を揃えてある。
//! 一致は、同じ入力から Python の `build_log_embed(...).to_dict()` と Rust の Embed の JSON を
//! 作って突き合わせて確かめた（変更のコミットに記録）。
//!
//! Discord の上限を超えると送信ごと拒否される（ログが届かない）ので、上限は印も含めて守る
//! （Python で印を上限の外に足していた不具合を直してから写した。86cbaac）。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use serde_json::Value;
use serenity::all::{
    Cache, ChannelId, ChannelType, CreateEmbed, CreateEmbedAuthor, CreateEmbedFooter,
    CreateMessage, GuildId, Http, Member, User,
};
use sycs_core::settings::SettingsCache;
use tracing::debug;

use crate::{colorthief, compat};

/// Embed の項目の値の上限（Discord）。
pub const FIELD_VALUE_LIMIT: usize = 1024;
/// 切り詰めたことを示す印。上限の内側に入れる。
pub const TRUNCATED_MARK: &str = "... (省略)";
const DESCRIPTION_LIMIT: usize = 4096;
const AUTHOR_NAME_LIMIT: usize = 256;
/// 代表色を覚えておく人数。Python と同じく、あふれたら最初に覚えた人から忘れる。
const COLOUR_CACHE_MAX: usize = 1024;
/// アバターを取りに行く待ち時間（Python と同じ 10 秒）。
const AVATAR_TIMEOUT: Duration = Duration::from_secs(10);

/// ログの細かさ。数が大きいほど細かい（NONE < ERROR < INFO < DEBUG）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// 何も出さない設定。メッセージの側に使うと、設定に関係なく必ず通る（Python と同じ）。
    None,
    /// 失敗。
    Error,
    /// ふつうの出来事。
    Info,
    /// 細かい出来事。
    Debug,
}

impl Level {
    /// 名前から。大文字・小文字は問わない。知らない名前は `None`（Rust の Option の None）。
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_uppercase().as_str() {
            "NONE" => Some(Self::None),
            "ERROR" => Some(Self::Error),
            "INFO" => Some(Self::Info),
            "DEBUG" => Some(Self::Debug),
            _ => None,
        }
    }

    /// 大文字の名前（Embed の題に出る）。
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Error => "ERROR",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Error => 1,
            Self::Info => 2,
            Self::Debug => 3,
        }
    }

    /// 既定の色（アバターの色が取れないとき）。discord.py の `Color.red()` などと同じ値。
    pub fn colour(self) -> u32 {
        match self {
            Self::Error => 0xE7_4C_3C,
            Self::Info => 0x34_98_DB,
            Self::Debug => 0x60_7D_8B,
            Self::None => 0x97_9C_9F,
        }
    }
}

/// ギルドのログの設定。Python の `get_log_settings` が返すもの。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogSettings {
    /// ログチャンネル。未設定・読めない値なら `None`。
    pub channel_id: Option<u64>,
    /// 設定されたレベルの名前（大文字）。未設定なら `INFO`。知らない名前もそのまま持つ。
    pub level: String,
}

/// ギルドの設定（JSON）からログの設定を読む。保存の鍵は `log_channel_id`・`log_level`。
pub fn log_settings(guild: Option<&Value>) -> LogSettings {
    let get = |key: &str| guild.and_then(|g| g.get(key));
    let level = match get("log_level") {
        None => "INFO".to_string(),
        Some(v) => python_str(v).to_uppercase(),
    };
    LogSettings {
        channel_id: get("log_channel_id").and_then(as_channel_id),
        level,
    }
}

/// Python の `str(value)` のうち、設定に入りうるもの。
fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

/// チャンネル ID として読む。数か数の文字列で、0 より大きいものだけ。
///
/// Python は読めない文字列で例外を投げ、呼び出し側がそれをログに残して送らない。こちらは
/// 送らないことだけ揃える（どちらも届かない）。
fn as_channel_id(value: &Value) -> Option<u64> {
    let id = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }?;
    (id > 0).then_some(id)
}

/// このレベルのメッセージを送るか。設定より細かいものは送らない。
///
/// 設定が空なら INFO、知らない名前なら INFO と同じ扱い（Python の `.get(current, 2)`）。
pub fn should_log(settings: &LogSettings, level: Level) -> bool {
    let current = if settings.level.is_empty() {
        "INFO"
    } else {
        settings.level.as_str()
    };
    level.priority() <= Level::parse(current).map_or(2, Level::priority)
}

/// 項目の値を、印も含めて上限（1024 文字）に収める。Python の `fit_field_value`。
pub fn fit_field_value(value: &str) -> String {
    fit(value, FIELD_VALUE_LIMIT, TRUNCATED_MARK)
}

/// 文字数（Python の len と同じくコードポイント）で `limit` に収める。超えたら `mark` を付ける。
fn fit(value: &str, limit: usize, mark: &str) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let keep = limit - mark.chars().count();
    let mut out: String = value.chars().take(keep).collect();
    out.push_str(mark);
    out
}

/// Embed の作者として出す人。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Author {
    /// ユーザー ID（代表色を覚える鍵）。
    pub id: u64,
    /// 名前（`str(user)` と同じ形）。
    pub name: String,
    /// アバターの URL（`display_avatar.url` と同じ形）。
    pub avatar_url: String,
}

impl Author {
    /// ユーザーから。
    pub fn from_user(user: &User) -> Self {
        Self {
            id: user.id.get(),
            name: compat::user_tag(user),
            avatar_url: compat::user_avatar_url(user),
        }
    }

    /// サーバーのメンバーから（サーバーごとのアバターがあればそちら）。
    pub fn from_member(member: &Member) -> Self {
        Self {
            id: member.user.id.get(),
            name: compat::user_tag(&member.user),
            avatar_url: compat::member_avatar_url(member),
        }
    }
}

/// 日本時間（Python の `config.JST`）。
fn jst() -> FixedOffset {
    FixedOffset::east_opt(9 * 3600).expect("+09:00 は正しいオフセット")
}

/// いまの日本時間。
pub fn now_jst() -> DateTime<FixedOffset> {
    Utc::now().with_timezone(&jst())
}

/// ログの Embed を組み立てる。Python の `build_log_embed`（色は決めたものを渡す）。
pub fn build_log_embed(
    level: Level,
    message: &str,
    author: Option<&Author>,
    fields: &[(String, String)],
    colour: u32,
    now: DateTime<FixedOffset>,
) -> CreateEmbed {
    let mut embed = CreateEmbed::new()
        .title(format!("[{}] ボットログ", level.name()))
        .description(fit(message, DESCRIPTION_LIMIT, "..."))
        .colour(colour);
    if let Some(author) = author {
        embed = embed.author(
            CreateEmbedAuthor::new(fit(&author.name, AUTHOR_NAME_LIMIT, "..."))
                .icon_url(&author.avatar_url),
        );
    }
    for (name, value) in fields {
        embed = embed.field(name, fit_field_value(value), false);
    }
    embed.footer(CreateEmbedFooter::new(format!(
        "時刻 (JST): {}",
        now.format("%Y-%m-%d %H:%M:%S")
    )))
}

/// アバターの代表色。取りに行った結果を人ごとに覚える。
pub struct AvatarColours {
    http: reqwest::Client,
    cache: Mutex<ColourCache>,
}

#[derive(Default)]
struct ColourCache {
    colours: HashMap<u64, u32>,
    /// 覚えた順。あふれたら先頭から忘れる。
    order: VecDeque<u64>,
}

impl ColourCache {
    fn insert(&mut self, id: u64, colour: u32) {
        if self.colours.contains_key(&id) {
            return;
        }
        if self.colours.len() >= COLOUR_CACHE_MAX
            && let Some(oldest) = self.order.pop_front()
        {
            self.colours.remove(&oldest);
        }
        self.colours.insert(id, colour);
        self.order.push_back(id);
    }
}

impl Default for AvatarColours {
    fn default() -> Self {
        Self::new()
    }
}

impl AvatarColours {
    /// 作る。アバターの取得は 10 秒で諦める。
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(AVATAR_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self {
            http,
            cache: Mutex::new(ColourCache::default()),
        }
    }

    /// この人のアバターの代表色。取れなければ `None`（ログの色はレベルの色になる）。
    ///
    /// 取れなかったことは覚えない（Python と同じ。次のログでまた試す）。
    pub async fn colour_of(&self, author: &Author) -> Option<u32> {
        if let Some(colour) = self.lock().colours.get(&author.id) {
            return Some(*colour);
        }
        let response = self.http.get(&author.avatar_url).send().await.ok()?;
        if response.status() != reqwest::StatusCode::OK {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        // 復号と色の計算は数十ミリ秒かかる。イベントを受ける側を止めないよう、別の
        // スレッドで行う（Python はループの上でそのまま計算していた）。
        let colour = tokio::task::spawn_blocking(move || colour_of_image(&bytes))
            .await
            .ok()??;
        self.lock().insert(author.id, colour);
        Some(colour)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ColourCache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// 画像のバイト列から代表色（0xRRGGBB）。読めない画像や、数える画素が無ければ `None`。
pub fn colour_of_image(bytes: &[u8]) -> Option<u32> {
    let image = image::load_from_memory(bytes).ok()?.to_rgba8();
    let (r, g, b) = colorthief::dominant_color(image.as_raw(), 10)?;
    Some((u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b))
}

/// ログを送るのに要るもの。
pub struct LogSink<'a> {
    /// serenity のキャッシュ（チャンネルを引く）。
    pub cache: &'a Cache,
    /// Discord へ送る口。
    pub http: &'a Http,
    /// ギルドごとの設定。
    pub settings: &'a SettingsCache,
    /// アバターの代表色。
    pub colours: &'a AvatarColours,
}

/// 送るかどうかを決めて、ログチャンネルへ送る。Python の `log_action`。
///
/// 送らなかった（設定より細かい・チャンネルが未設定・見つからない・テキストチャンネルでない）
/// ときは `Ok(false)`。送信の失敗は `Err`（呼び出し側がログに残す。serenity の誤りは大きいので
/// 箱に入れて返す）。
pub async fn log_action(
    sink: &LogSink<'_>,
    guild_id: GuildId,
    level: Level,
    message: &str,
    author: Option<&Author>,
    fields: &[(String, String)],
    colour: Option<u32>,
) -> Result<bool, Box<serenity::Error>> {
    let snapshot = sink.settings.snapshot();
    let settings = log_settings(snapshot.guild(guild_id.get()));
    if !should_log(&settings, level) {
        return Ok(false);
    }
    let Some(channel) = text_channel(sink.cache, guild_id, settings.channel_id) else {
        debug!(%guild_id, channel_id = ?settings.channel_id, "ログチャンネルが未設定か、テキストチャンネルでない");
        return Ok(false);
    };
    let colour = match (colour, author) {
        (Some(c), _) => c,
        (None, Some(a)) => sink.colours.colour_of(a).await.unwrap_or(level.colour()),
        (None, None) => level.colour(),
    };
    let embed = build_log_embed(level, message, author, fields, colour, now_jst());
    channel
        .send_message(sink.http, CreateMessage::new().embed(embed))
        .await
        .map_err(Box::new)?;
    Ok(true)
}

/// そのギルドのテキストチャンネル（お知らせチャンネルを含む）。Python の
/// `isinstance(bot.get_channel(id), discord.TextChannel)`（discord.py ではお知らせも TextChannel）。
///
/// **探すのはログのギルドの中だけ。** Python はキャッシュ全体から引くので、設定に別のサーバーの
/// チャンネルが入っていると、そのサーバーへこのサーバーのログを書いてしまう。こちらは書かない。
fn text_channel(cache: &Cache, guild_id: GuildId, channel_id: Option<u64>) -> Option<ChannelId> {
    let channel_id = ChannelId::new(channel_id?);
    let guild = cache.guild(guild_id)?;
    let channel = guild.channels.get(&channel_id)?;
    is_text(channel.kind).then_some(channel_id)
}

/// ログを書けるチャンネルか。テキストとお知らせだけ（スレッド・VC のチャット・フォーラムは除く。
/// discord.py の TextChannel に入るものと同じ）。
fn is_text(kind: ChannelType) -> bool {
    matches!(kind, ChannelType::Text | ChannelType::News)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn settings(level: &str) -> LogSettings {
        LogSettings {
            channel_id: Some(1),
            level: level.into(),
        }
    }

    /// 保存の鍵（log_channel_id・log_level）から読み、レベルは大文字にそろえること。
    #[test]
    fn settings_are_read_from_the_stored_keys() {
        let s = log_settings(Some(&json!({"log_channel_id": 123, "log_level": "debug"})));
        assert_eq!(s.channel_id, Some(123));
        assert_eq!(s.level, "DEBUG");
        // 文字列の ID も読む。0・負・読めない値は未設定。
        assert_eq!(
            log_settings(Some(&json!({"log_channel_id": " 456 "}))).channel_id,
            Some(456)
        );
        for bad in [json!(0), json!(-5), json!("abc"), json!(""), json!(false)] {
            assert_eq!(
                log_settings(Some(&json!({"log_channel_id": bad}))).channel_id,
                None
            );
        }
        // 未設定なら INFO。
        assert_eq!(log_settings(None).level, "INFO");
        assert_eq!(log_settings(Some(&json!({}))).level, "INFO");
    }

    /// 設定より細かいレベルは送らないこと。NONE なら ERROR も送らない。
    #[test]
    fn messages_finer_than_the_setting_are_not_sent() {
        assert!(should_log(&settings("INFO"), Level::Error));
        assert!(should_log(&settings("INFO"), Level::Info));
        assert!(!should_log(&settings("INFO"), Level::Debug));
        assert!(!should_log(&settings("NONE"), Level::Error));
        assert!(should_log(&settings("DEBUG"), Level::Debug));
        // 空・知らない名前は INFO と同じ。
        assert!(!should_log(&settings(""), Level::Debug));
        assert!(should_log(&settings("WARNING"), Level::Info));
        assert!(!should_log(&settings("WARNING"), Level::Debug));
    }

    /// 上限を超える値は、印も含めてちょうど 1024 文字。ちょうど 1024 文字なら切らない。
    #[test]
    fn field_values_fit_in_1024_characters_including_the_mark() {
        let long = "あ".repeat(1100);
        let fitted = fit_field_value(&long);
        assert_eq!(fitted.chars().count(), 1024);
        assert!(fitted.ends_with(TRUNCATED_MARK));
        let exact = "y".repeat(1024);
        assert_eq!(fit_field_value(&exact), exact);
    }

    fn embed_json(embed: CreateEmbed) -> Value {
        serde_json::to_value(embed).unwrap()
    }

    /// 題・本文・色・作者・項目・時刻が Python と同じ形になること。
    #[test]
    fn the_embed_has_the_same_shape_as_python() {
        let at = jst().with_ymd_and_hms(2026, 11, 25, 9, 5, 7).unwrap();
        let author = Author {
            id: 1,
            name: "nelly".into(),
            avatar_url: "https://cdn.discordapp.com/embed/avatars/0.png".into(),
        };
        let fields = vec![("チャンネル".to_string(), "<#1>".to_string())];
        let v = embed_json(build_log_embed(
            Level::Info,
            "本文",
            Some(&author),
            &fields,
            0x12_34_56,
            at,
        ));
        assert_eq!(v["title"], "[INFO] ボットログ");
        assert_eq!(v["description"], "本文");
        assert_eq!(v["color"], 0x12_34_56);
        assert_eq!(v["author"]["name"], "nelly");
        assert_eq!(v["author"]["icon_url"], author.avatar_url);
        assert_eq!(
            v["fields"],
            json!([{"name": "チャンネル", "value": "<#1>", "inline": false}])
        );
        assert_eq!(v["footer"]["text"], "時刻 (JST): 2026-11-25 09:05:07");
    }

    /// 本文は 4096 文字、作者名は 256 文字に、印「...」込みで収めること。
    #[test]
    fn long_texts_fit_their_limits() {
        let author = Author {
            id: 1,
            name: "な".repeat(300),
            avatar_url: String::new(),
        };
        let v = embed_json(build_log_embed(
            Level::Error,
            &"x".repeat(5000),
            Some(&author),
            &[],
            0,
            now_jst(),
        ));
        let description = v["description"].as_str().unwrap();
        assert_eq!(description.chars().count(), 4096);
        assert!(description.ends_with("..."));
        let name = v["author"]["name"].as_str().unwrap();
        assert_eq!(name.chars().count(), 256);
        assert!(name.ends_with("..."));
    }

    /// レベルの色が discord.py の色と同じ値であること。
    #[test]
    fn level_colours_match_discord_py() {
        assert_eq!(Level::Error.colour(), 0xE74C3C); // Color.red()
        assert_eq!(Level::Info.colour(), 0x3498DB); // Color.blue()
        assert_eq!(Level::Debug.colour(), 0x607D8B); // Color.dark_grey()
        assert_eq!(Level::None.colour(), 0x979C9F); // Color.light_grey()
    }

    /// 覚える人数を超えたら、最初に覚えた人から忘れること。
    #[test]
    fn the_colour_cache_forgets_the_oldest_first() {
        let mut c = ColourCache::default();
        for id in 0..COLOUR_CACHE_MAX as u64 {
            c.insert(id, 1);
        }
        c.insert(9_999, 2);
        assert_eq!(c.colours.len(), COLOUR_CACHE_MAX);
        assert!(!c.colours.contains_key(&0));
        assert!(c.colours.contains_key(&1));
        assert_eq!(c.colours[&9_999], 2);
    }

    /// テキストとお知らせだけに書き、スレッド・VC・フォーラムには書かないこと。
    #[test]
    fn only_text_and_news_channels_take_logs() {
        assert!(is_text(ChannelType::Text));
        assert!(is_text(ChannelType::News));
        for kind in [
            ChannelType::Voice,
            ChannelType::PublicThread,
            ChannelType::Forum,
            ChannelType::Stage,
            ChannelType::Category,
        ] {
            assert!(!is_text(kind), "{kind:?}");
        }
    }

    /// 画像のバイト列から代表色が取れ、読めないものは色なしになること。
    #[test]
    fn colours_come_from_image_bytes() {
        let mut png = Vec::new();
        let img = image::RgbaImage::from_pixel(8, 8, image::Rgba([200, 40, 10, 255]));
        img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(colour_of_image(&png), Some(0xCC_2C_0C));
        assert_eq!(colour_of_image(b"not an image"), None);
    }
}
