//! Discord のログイン（OAuth）と、Bot のトークンで引く管理者の確かめ。Python の `webapp_admin/auth.py` のうち、
//! ログイン・サーバー選択・公開ページが使うものの写し（`get_oauth_url`・`exchange_code`・`get_user_info`・
//! `get_user_guilds`・`_get_bot_guild_ids`・`get_admin_guilds`・`get_bot_guild_count`・`user_still_admin`）。
//!
//! 基準は 2 つ（どちらも本物の Python を偽物の Discord に当てて作った）:
//!
//! - `tests/fixtures/auth/`: ログイン・戻り・サーバー選択・公開ページの HTTP の答えと、偽物の Discord に届いた要求
//! - `tests/fixtures/admin_check/`: `user_still_admin`（Discord の答え → 管理者か・分からないか・例外か）
//!
//! Python の aiohttp の読み方を写したところ:
//!
//! - 400 以上は失敗（`raise_for_status`）。答えの本文は JSON として読む前に、`Content-Type` が
//!   `application/…json` かを見る（`resp.json()` の既定。違えば失敗）。本文が空白だけなら null
//! - 失敗は例外にせず、呼ぶ側が「失敗」として扱う形で返す（`exchange_code`・`get_user_info` は null、
//!   `get_user_guilds` は空の並び、Bot のサーバーの一覧は空、サーバー数は 0）
//! - 答えの中身の形が変なとき（並びでない・`id` が無いなど）は、Python で例外になるところを [`Crash`] にする
//!   （Python の型の名前と文。例外の係が 500 とインシデントにする）
//!
//! Python と違うところ（どれも Discord が返さない形）: 本文は UTF-8 としてだけ読む（`charset` に別の文字の組を
//! 書かれても見ない）。JSON の `NaN`・`Infinity`・単独のサロゲートは読めない（Python は読む）。64 ビットを超える
//! 整数の数は小数として読む（Python は桁を全部持つ。Discord の ID は文字で来る）。

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value};
use sycs_core::env::Env;
use tracing::warn;

use crate::errors::Crash;
use crate::python;

/// Discord の API（`_API`）。
pub const DISCORD_API: &str = "https://discord.com/api/v10";
/// 認可の画面（`get_oauth_url`）。
pub const AUTHORIZE_URL: &str = "https://discord.com/api/oauth2/authorize";
/// 求める範囲（`_SCOPES`）。
pub const SCOPES: &str = "identify guilds";
/// `DISCORD_REDIRECT_URI` の既定。
pub const DEFAULT_REDIRECT_URI: &str = "http://localhost:5001/admin/callback";
/// `ADMIN_GUILDS_MAX_AGE_SECONDS` の既定と下限。
pub const DEFAULT_GUILDS_MAX_AGE: i64 = 300;
/// `ADMIN_GUILDS_MAX_AGE_SECONDS` の下限。
pub const MIN_GUILDS_MAX_AGE: i64 = 60;
/// 管理者の権限の印（`_ADMINISTRATOR_BIT`）。
pub const ADMINISTRATOR_BIT: u8 = 0x8;
/// 1 回の問い合わせの待ち時間（`aiohttp.ClientTimeout(total=10)`）。
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// Bot のサーバー数を使い回す長さ（秒。`_GUILD_COUNT_TTL`）。
pub const GUILD_COUNT_TTL: f64 = 300.0;
/// Discord へ名乗る名前。
pub const USER_AGENT: &str = "sycs-admin";

/// Discord のログインの設定（環境変数）。Python の `webapp_admin/auth.py` の冒頭と同じ読み方。
#[derive(Clone, PartialEq, Eq)]
pub struct DiscordConfig {
    /// `DISCORD_CLIENT_ID`（前後の空白も落とさず、そのまま。Python の `os.environ.get`）。
    pub client_id: String,
    /// `DISCORD_CLIENT_SECRET`（そのまま）。
    pub client_secret: String,
    /// `DISCORD_REDIRECT_URI`（そのまま。無ければ [`DEFAULT_REDIRECT_URI`]。空にすれば空）。
    pub redirect_uri: String,
    /// `DISCORD_BOT_TOKEN`（前後の空白を落とす。空なら無い。`env_raw`）。
    pub bot_token: String,
    /// `DISCORD_OAUTH_PROMPT`（前後の空白を落として小文字。`none`・`consent` のほかは空）。
    pub prompt: String,
    /// `ADMIN_GUILDS_MAX_AGE_SECONDS`（既定 300、下限 60。`env_int`）。
    pub guilds_max_age: i64,
}

impl fmt::Debug for DiscordConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscordConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &if self.client_secret.is_empty() { "無し" } else { "…" })
            .field("redirect_uri", &self.redirect_uri)
            .field("bot_token", &if self.bot_token.is_empty() { "無し" } else { "…" })
            .field("prompt", &self.prompt)
            .field("guilds_max_age", &self.guilds_max_age)
            .finish()
    }
}

impl DiscordConfig {
    /// このプロセスの環境変数から読む。
    pub fn from_process() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 引き方を渡して読む（テストはプロセスの環境変数を書き換えずに済む）。
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
    {
        let env = Env::from_fn(lookup.clone());
        let prompt = lookup("DISCORD_OAUTH_PROMPT")
            .map(|value| python::strip(&value).to_lowercase())
            .unwrap_or_default();
        let prompt = if prompt.is_empty() || prompt == "none" || prompt == "consent" {
            prompt
        } else {
            warn!("DISCORD_OAUTH_PROMPT={prompt} は無効なため無視します。");
            String::new()
        };
        Self {
            client_id: lookup("DISCORD_CLIENT_ID").unwrap_or_default(),
            client_secret: lookup("DISCORD_CLIENT_SECRET").unwrap_or_default(),
            redirect_uri: lookup("DISCORD_REDIRECT_URI")
                .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string()),
            bot_token: env.raw("DISCORD_BOT_TOKEN").unwrap_or_default(),
            prompt,
            guilds_max_age: env.int(
                "ADMIN_GUILDS_MAX_AGE_SECONDS",
                DEFAULT_GUILDS_MAX_AGE,
                Some(MIN_GUILDS_MAX_AGE),
                None,
            ),
        }
    }
}

/// `urllib.parse.quote_plus(text, safe="")`（空白は `+`、英数字と `_.-~` のほかは `%XX`）。
pub fn quote_plus(text: &str) -> String {
    python::quote(text, " ").replace(' ', "+")
}

/// `urllib.parse.urlencode(pairs)`（名前と値を [`quote_plus`] で逃がして `=` と `&` でつなぐ）。
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", quote_plus(name), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 届いた答え（状態・`Content-Type`・本文）。
#[derive(Clone, Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// aiohttp の `ClientResponse.content_type`（無ければ `application/octet-stream`。`;` より前を小文字にし、`/` が
/// ちょうど 1 つでなければ `text/plain`。`email` の `get_content_type`）。
pub fn mimetype(content_type: Option<&str>) -> String {
    let Some(raw) = content_type else {
        return "application/octet-stream".to_string();
    };
    let first = python::strip(raw.split(';').next().unwrap_or_default()).to_lowercase();
    if first.matches('/').count() == 1 {
        first
    } else {
        "text/plain".to_string()
    }
}

/// aiohttp の `resp.json()` が JSON として読む種類か（`^application/(?:[\w.+-]+?\+)?json` に頭から当たるか）。
pub fn is_json_mimetype(mimetype: &str) -> bool {
    static JSON: OnceLock<Regex> = OnceLock::new();
    JSON.get_or_init(|| {
        Regex::new(r"^application/(?:[\w.+-]+?\+)?json")
            .unwrap_or_else(|e| panic!("JSON の種類の形を正規表現にできない: {e}"))
    })
    .is_match(mimetype)
}

/// `bytes.strip()`（ASCII の空白 6 つ）。
fn strip_ascii(bytes: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = bytes.iter().position(|b| !space(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &bytes[start..end.max(start)]
}

/// `resp.raise_for_status()` のあとの `await resp.json()`。失敗は理由の文。
fn read_json(answer: &Answer) -> Result<Value, String> {
    if answer.status >= 400 {
        return Err(format!("{} が返った", answer.status));
    }
    let kind = mimetype(answer.content_type.as_deref());
    if !is_json_mimetype(&kind) {
        return Err(format!("JSON ではない答え（{kind}）"));
    }
    let stripped = strip_ascii(&answer.body);
    if stripped.is_empty() {
        return Ok(Value::Null);
    }
    let text = std::str::from_utf8(stripped).map_err(|e| format!("UTF-8 で読めない: {e}"))?;
    serde_json::from_str(text).map_err(|e| format!("JSON として読めない: {e}"))
}

/// Python で `for x in value` としたときの並び（辞書は鍵、文字は 1 文字ずつ）。並べられない値は `TypeError`。
pub fn py_iter(value: &Value) -> Result<Vec<Value>, Crash> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map.keys().map(|key| Value::String(key.clone())).collect()),
        Value::String(text) => Ok(text
            .chars()
            .map(|c| Value::String(c.to_string()))
            .collect()),
        other => Err(Crash::new(
            "TypeError",
            format!("'{}' object is not iterable", python::type_name(other)),
        )),
    }
}

/// Python で `value.get(…)` を呼べるか（辞書だけ）。辞書でなければ `AttributeError`。
pub fn py_dict(value: &Value) -> Result<&Map<String, Value>, Crash> {
    match value {
        Value::Object(map) => Ok(map),
        other => Err(Crash::new(
            "AttributeError",
            format!(
                "'{}' object has no attribute 'get'",
                python::type_name(other)
            ),
        )),
    }
}

/// Python の `value[key]`（`key` は文字）。辞書に無ければ `KeyError`、辞書でなければ `TypeError`。
pub fn py_subscript(value: &Value, key: &str) -> Result<Value, Crash> {
    match value {
        Value::Object(map) => map.get(key).cloned().ok_or_else(|| {
            Crash::new("KeyError", python::repr(&Value::String(key.to_string())))
        }),
        Value::Array(_) => Err(Crash::new(
            "TypeError",
            "list indices must be integers or slices, not str",
        )),
        Value::String(_) => Err(Crash::new(
            "TypeError",
            "string indices must be integers, not 'str'",
        )),
        other => Err(Crash::new(
            "TypeError",
            format!("'{}' object is not subscriptable", python::type_name(other)),
        )),
    }
}

/// Python の `int(value)`（10 進の文字にしたもの）。読めなければ Python と同じ型の例外。
pub fn py_int(value: &Value) -> Result<String, Crash> {
    if let Some(text) = python::int_text(value) {
        return Ok(text);
    }
    Err(match value {
        Value::String(_) => Crash::new(
            "ValueError",
            format!(
                "invalid literal for int() with base 10: {}",
                python::repr(value)
            ),
        ),
        other => Crash::new(
            "TypeError",
            format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                python::type_name(other)
            ),
        ),
    })
}

/// 10 進の整数（`-` が付くこともある）の下の 4 ビット。Python の負の数の `&`（2 の補数を無限に伸ばしたもの）と
/// 同じ答えになるように、16 で割った余りを 0〜15 で取る。
pub fn low_bits(int_text: &str) -> u8 {
    let (negative, digits) = match int_text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, int_text),
    };
    let mut rest: u32 = 0;
    for byte in digits.bytes().filter(u8::is_ascii_digit) {
        rest = (rest * 10 + u32::from(byte - b'0')) % 16;
    }
    let rest = if negative { (16 - rest) % 16 } else { rest };
    u8::try_from(rest).unwrap_or(0)
}

/// `int(value) & 8` が真か。`int()` で読めなければ `None`（Python の `TypeError`・`ValueError`）。
pub fn has_admin_bit(value: &Value) -> Option<bool> {
    python::int_text(value).map(|text| low_bits(&text) & ADMINISTRATOR_BIT != 0)
}

/// Bot の参加しているサーバーの ID（`_get_bot_guild_ids` の `{int(g["id"]) for g in …}`）。どれか 1 つでも読めなければ
/// 全体を失敗にする（Python は例外を拾って空の集合を返す）。
pub fn bot_guild_ids_of(value: &Value) -> Result<HashSet<String>, String> {
    let items = py_iter(value).map_err(|crash| crash.message)?;
    let mut ids = HashSet::new();
    for item in &items {
        let id = py_subscript(item, "id").map_err(|crash| crash.message)?;
        ids.insert(py_int(&id).map_err(|crash| crash.message)?);
    }
    Ok(ids)
}

/// 管理者（permissions の 0x8）で、Bot もいるサーバーだけを `{"id", "name", "icon"}` にする（`get_admin_guilds` の
/// 後半）。
///
/// 一覧が並べられない値なら `TypeError`、辞書の要素に `id` が無ければ `KeyError`（どちらも Python は拾わない）。
/// 辞書でない要素と、`id`・`permissions` を `int()` で読めない要素は飛ばす。
pub fn admin_guilds_from(
    user_guilds: &Value,
    bot_ids: &HashSet<String>,
) -> Result<Vec<Value>, Crash> {
    let mut result = Vec::new();
    for guild in py_iter(user_guilds)? {
        let Value::Object(fields) = &guild else {
            continue;
        };
        let id = py_subscript(&guild, "id")?;
        let Some(guild_id) = python::int_text(&id) else {
            continue;
        };
        let zero = Value::from(0);
        let Some(admin) = has_admin_bit(fields.get("permissions").unwrap_or(&zero)) else {
            continue;
        };
        if !admin || !bot_ids.contains(&guild_id) {
            continue;
        }
        let name = match fields.get("name") {
            Some(name) if python::truthy(name) => python::str_of(name),
            _ => "Unknown".to_string(),
        };
        let icon = match fields.get("icon") {
            Some(Value::String(icon)) => Value::String(icon.clone()),
            _ => Value::Null,
        };
        result.push(python::object(vec![
            ("id", Value::String(guild_id)),
            ("name", Value::String(name)),
            ("icon", icon),
        ]));
    }
    Ok(result)
}

/// その利用者がいまもそのサーバーの管理者か（`user_still_admin` の後半。サーバーとメンバーを取れたあと）。
///
/// 持ち主なら真。でなければ、持っているロールと @everyone（ID がサーバーの ID のロール）の permissions を OR して
/// 0x8 を見る。`int()` で読めない permissions は飛ばす。サーバーやメンバーが辞書でない・ロールの並びが並べられない・
/// ロールが辞書でないときは、Python と同じ例外。
pub fn admin_from(
    guild: &Value,
    member: &Value,
    guild_id: &str,
    user_id: &str,
) -> Result<bool, Crash> {
    let guild_fields = py_dict(guild)?;
    let owner = guild_fields.get("owner_id").unwrap_or(&Value::Null);
    if python::str_of(owner) == user_id {
        return Ok(true);
    }
    let empty = Value::Array(Vec::new());
    let member_fields = py_dict(member)?;
    let held: HashSet<String> = py_iter(member_fields.get("roles").unwrap_or(&empty))?
        .iter()
        .map(python::str_of)
        .collect();
    let mut bits = 0u8;
    for role in py_iter(guild_fields.get("roles").unwrap_or(&empty))? {
        let fields = py_dict(&role)?;
        let role_id = python::str_of(fields.get("id").unwrap_or(&Value::Null));
        if !held.contains(&role_id) && role_id != guild_id {
            continue;
        }
        let zero = Value::from(0);
        if let Some(text) = python::int_text(fields.get("permissions").unwrap_or(&zero)) {
            bits |= low_bits(&text);
        }
    }
    Ok(bits & ADMINISTRATOR_BIT != 0)
}

/// Python の `len(value)`（並び・辞書・文字。文字は文字の数）。ほかは `None`（`TypeError`）。
pub fn py_len(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::Object(map) => Some(map.len()),
        Value::String(text) => Some(text.chars().count()),
        _ => None,
    }
}

/// Discord の API を呼ぶ口（1 つを使い回す）。
pub struct Discord {
    config: DiscordConfig,
    api_base: String,
    http: reqwest::Client,
}

impl fmt::Debug for Discord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Discord")
            .field("config", &self.config)
            .field("api_base", &self.api_base)
            .finish_non_exhaustive()
    }
}

/// サーバーとメンバーを取った答え（`user_still_admin` の前半）。
enum Fetched {
    Json(Value),
    NotFound,
    Failed(String),
}

impl Discord {
    /// 作る。`api_base` は本番なら [`DISCORD_API`]（テストは偽物の Discord）。
    ///
    /// 環境変数のプロキシ（`HTTPS_PROXY` など）は使わない（aiohttp の `ClientSession` の既定 `trust_env=False` と同じ）。
    pub fn new(config: DiscordConfig, api_base: &str) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            .no_proxy()
            .build()?;
        Ok(Self {
            config,
            api_base: api_base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// 設定。
    pub fn config(&self) -> &DiscordConfig {
        &self.config
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api_base)
    }

    fn bot_header(&self) -> String {
        format!("Bot {}", self.config.bot_token)
    }

    async fn send(request: reqwest::RequestBuilder) -> Result<Answer, String> {
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let body = response.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok(Answer {
            status,
            content_type,
            body,
        })
    }

    async fn get_json(&self, path: &str, authorization: &str) -> Result<Value, String> {
        let request = self
            .http
            .get(self.url(path))
            .header(reqwest::header::AUTHORIZATION, authorization);
        read_json(&Self::send(request).await?)
    }

    /// 認可の画面の URL（`get_oauth_url`）。`state` はセッションに入れて戻りで比べる（呼ぶ側の仕事）。
    pub fn oauth_url(&self, state: &str) -> String {
        let config = &self.config;
        let mut params = vec![
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", SCOPES),
            ("state", state),
        ];
        if config.prompt == "none" || config.prompt == "consent" {
            params.push(("prompt", config.prompt.as_str()));
        }
        format!("{AUTHORIZE_URL}?{}", urlencode(&params))
    }

    /// 認可のコードをトークンに換える（`exchange_code`。POST `/oauth2/token`、フォーム）。失敗は null。
    pub async fn exchange_code(&self, code: &str) -> Value {
        let config = &self.config;
        let body = urlencode(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
        ]);
        let request = self
            .http
            .post(self.url("/oauth2/token"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body);
        Self::send(request)
            .await
            .and_then(|answer| read_json(&answer))
            .unwrap_or(Value::Null)
    }

    /// ログインした本人（`get_user_info`。GET `/users/@me`、Bearer）。失敗は null。
    ///
    /// トークンは JSON の値のまま受け、`str()` して見出しに入れる（Python の f-string）。
    pub async fn user_info(&self, access_token: &Value) -> Value {
        let authorization = format!("Bearer {}", python::str_of(access_token));
        self.get_json("/users/@me", &authorization)
            .await
            .unwrap_or(Value::Null)
    }

    /// 本人のサーバー（`get_user_guilds`。GET `/users/@me/guilds`、Bearer）。失敗は空の並び。
    pub async fn user_guilds(&self, access_token: &Value) -> Value {
        let authorization = format!("Bearer {}", python::str_of(access_token));
        self.get_json("/users/@me/guilds", &authorization)
            .await
            .unwrap_or_else(|_| Value::Array(Vec::new()))
    }

    /// Bot のいるサーバーの ID（`_get_bot_guild_ids`。GET `/users/@me/guilds`、Bot。**limit を付けない**）。
    /// トークンが無い・取れない・読めないときは空（誰にとっても「管理できるサーバーが無い」）。
    pub async fn bot_guild_ids(&self) -> HashSet<String> {
        if self.config.bot_token.is_empty() {
            warn!("DISCORD_BOT_TOKEN が未設定のため Bot ギルド一覧を取得できません。");
            return HashSet::new();
        }
        let ids = self
            .get_json("/users/@me/guilds", &self.bot_header())
            .await
            .and_then(|value| bot_guild_ids_of(&value));
        match ids {
            Ok(ids) => {
                if ids.is_empty() {
                    warn!("Bot がどのサーバーにも参加していません。");
                }
                ids
            }
            Err(e) => {
                warn!("Bot ギルド一覧取得失敗: {e}");
                HashSet::new()
            }
        }
    }

    /// 本人が管理者で、Bot もいるサーバー（`get_admin_guilds`。本人と Bot の一覧を並べて取る）。
    pub async fn admin_guilds(&self, access_token: &Value) -> Result<Vec<Value>, Crash> {
        let (user_guilds, bot_ids) =
            tokio::join!(self.user_guilds(access_token), self.bot_guild_ids());
        admin_guilds_from(&user_guilds, &bot_ids)
    }

    /// Bot のサーバー数を Discord に聞く（`get_bot_guild_count` の前半。GET `/users/@me/guilds?limit=200`、Bot）。
    /// トークンが無い・失敗・数えられない答えは 0。
    pub async fn bot_guild_count(&self) -> usize {
        if self.config.bot_token.is_empty() {
            return 0;
        }
        let counted = self
            .get_json("/users/@me/guilds?limit=200", &self.bot_header())
            .await
            .and_then(|value| {
                py_len(&value).ok_or_else(|| {
                    format!(
                        "object of type '{}' has no len()",
                        python::type_name(&value)
                    )
                })
            });
        match counted {
            Ok(count) => count,
            Err(e) => {
                warn!("get_bot_guild_count: Discord API 失敗、フォールバックを使用: {e}");
                0
            }
        }
    }

    async fn fetch_for_check(&self, path: &str) -> Fetched {
        let request = self
            .http
            .get(self.url(path))
            .header(reqwest::header::AUTHORIZATION, self.bot_header());
        match Self::send(request).await {
            Ok(answer) if answer.status == 404 => Fetched::NotFound,
            Ok(answer) => match read_json(&answer) {
                Ok(value) => Fetched::Json(value),
                Err(e) => Fetched::Failed(e),
            },
            Err(e) => Fetched::Failed(e),
        }
    }

    /// その利用者がいまもそのサーバーの管理者か（`user_still_admin`）。`guild_id`・`user_id` は 10 進の文字
    /// （Python の `str(int)`）。
    ///
    /// `Some(true)`＝管理者、`Some(false)`＝違う（サーバーかメンバーが 404）、`None`＝分からない（Bot のトークンが
    /// 無い・ほかの失敗。Discord の障害でログイン中の人を締め出さない）。答えの形が変なら Python と同じ例外。
    pub async fn user_still_admin(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Option<bool>, Crash> {
        if self.config.bot_token.is_empty() {
            return Ok(None);
        }
        let guild = match self.fetch_for_check(&format!("/guilds/{guild_id}")).await {
            Fetched::Json(value) => value,
            Fetched::NotFound => return Ok(Some(false)),
            Fetched::Failed(e) => {
                warn!("user_still_admin: 確認できませんでした guild={guild_id}: {e}");
                return Ok(None);
            }
        };
        let member = match self
            .fetch_for_check(&format!("/guilds/{guild_id}/members/{user_id}"))
            .await
        {
            Fetched::Json(value) => value,
            Fetched::NotFound => return Ok(Some(false)),
            Fetched::Failed(e) => {
                warn!("user_still_admin: 確認できませんでした guild={guild_id}: {e}");
                return Ok(None);
            }
        };
        admin_from(&guild, &member, guild_id, user_id).map(Some)
    }
}

/// 設定のあるサーバーの数（`settings_store.get_all_guild_ids()` の数）。Bot のサーバー数が 0 か失敗のときに使う。
/// 読めなければ理由の文。
pub type StoredGuildCount = Arc<dyn Fn() -> Result<usize, String> + Send + Sync>;

/// Bot のサーバー数を 5 分使い回すもの（`get_bot_guild_count`）。
///
/// 使い回しは「いまの時刻 − 取った時刻 < 300 秒」のあいだ（ちょうど 300 秒で取り直す）。取りに行くのは 1 つずつ
/// （待っているあいだに別の要求が取ってきていれば、それを使う）。Discord が 0 か失敗なら、設定のあるサーバーの数
/// （それも失敗なら 0）。0 も使い回す。取った時刻は、取りに行く前に見た時刻。
pub struct GuildCount {
    stored: StoredGuildCount,
    cache: Mutex<Option<(usize, f64)>>,
    gate: tokio::sync::Mutex<()>,
}

impl fmt::Debug for GuildCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuildCount")
            .field("cache", &self.cached_value())
            .finish_non_exhaustive()
    }
}

impl GuildCount {
    /// 作る（使い回しは空）。
    pub fn new(stored: StoredGuildCount) -> Self {
        Self {
            stored,
            cache: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    fn cached_value(&self) -> Option<(usize, f64)> {
        *self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fresh(&self, now: f64) -> Option<usize> {
        self.cached_value()
            .filter(|(_, at)| now - at < GUILD_COUNT_TTL)
            .map(|(count, _)| count)
    }

    /// サーバー数。`now` はいまの時刻（UNIX 時間の秒）を返すもの。
    pub async fn get(&self, discord: &Discord, now: impl Fn() -> f64 + Send + Sync) -> usize {
        if let Some(count) = self.fresh(now()) {
            return count;
        }
        let _turn = self.gate.lock().await;
        let at = now();
        if let Some(count) = self.fresh(at) {
            return count;
        }
        let mut count = discord.bot_guild_count().await;
        if count == 0 {
            match (self.stored)() {
                Ok(stored) => count = stored,
                Err(e) => warn!("get_bot_guild_count: settings_store フォールバックも失敗: {e}"),
            }
        }
        *self.cache.lock().unwrap_or_else(PoisonError::into_inner) = Some((count, at));
        count
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(pairs: &'static [(&'static str, &'static str)]) -> DiscordConfig {
        DiscordConfig::from_lookup(move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_string())
        })
    }

    /// 環境変数の読み方が Python と同じこと（ID とリダイレクト先はそのまま、トークンは前後の空白を落とす、prompt は
    /// 小文字にして none・consent だけ、期限は下限 60）。
    #[test]
    fn the_config_is_read_like_python() {
        let empty = config(&[]);
        assert_eq!(empty.client_id, "");
        assert_eq!(empty.redirect_uri, DEFAULT_REDIRECT_URI);
        assert_eq!(empty.bot_token, "");
        assert_eq!(empty.prompt, "");
        assert_eq!(empty.guilds_max_age, 300);
        let set = config(&[
            ("DISCORD_CLIENT_ID", " 42 "),
            ("DISCORD_REDIRECT_URI", ""),
            ("DISCORD_BOT_TOKEN", "  tok \n"),
            ("DISCORD_OAUTH_PROMPT", " Consent "),
            ("ADMIN_GUILDS_MAX_AGE_SECONDS", "10"),
        ]);
        assert_eq!(set.client_id, " 42 ");
        assert_eq!(set.redirect_uri, "");
        assert_eq!(set.bot_token, "tok");
        assert_eq!(set.prompt, "consent");
        assert_eq!(set.guilds_max_age, 60);
        assert_eq!(config(&[("DISCORD_OAUTH_PROMPT", "login")]).prompt, "");
        assert_eq!(config(&[("DISCORD_OAUTH_PROMPT", "NONE")]).prompt, "none");
        let shown = format!("{set:?}");
        assert!(!shown.contains("\"tok\""), "{shown}");
    }

    /// urlencode が Python の quote_plus と同じに逃がすこと（空白は +、: と / も逃がす、~ は残す）。
    #[test]
    fn forms_are_encoded_like_urlencode() {
        assert_eq!(
            urlencode(&[("a b", "http://x/y?z=1&w=~ü*")]),
            "a+b=http%3A%2F%2Fx%2Fy%3Fz%3D1%26w%3D~%C3%BC%2A"
        );
        assert_eq!(quote_plus("identify guilds"), "identify+guilds");
        assert_eq!(quote_plus("a+b"), "a%2Bb");
    }

    /// aiohttp の種類の読み方（引数を落として小文字、/ が 1 つでなければ text/plain、+json も JSON）。
    #[test]
    fn json_answers_are_recognised_like_aiohttp() {
        assert_eq!(mimetype(None), "application/octet-stream");
        assert_eq!(
            mimetype(Some("Application/JSON; charset=UTF-8")),
            "application/json"
        );
        assert_eq!(mimetype(Some("json")), "text/plain");
        assert!(is_json_mimetype("application/json"));
        assert!(is_json_mimetype("application/vnd.discord+json"));
        assert!(is_json_mimetype("application/jsonx"));
        assert!(!is_json_mimetype("text/json"));
        let answer = |body: &[u8]| Answer {
            status: 200,
            content_type: Some("application/json".to_string()),
            body: body.to_vec(),
        };
        assert_eq!(read_json(&answer(b" \x0b\n")), Ok(Value::Null));
        assert_eq!(read_json(&answer(b" [1] ")), Ok(json!([1])));
        assert!(read_json(&answer(b"{")).is_err());
        let rejected = Answer {
            status: 400,
            ..answer(b"{}")
        };
        assert!(read_json(&rejected).is_err());
    }

    /// 負の数の & 8 が Python と同じになること（2 の補数を無限に伸ばした形）。
    #[test]
    fn low_bits_follow_python_twos_complement() {
        assert_eq!(low_bits("8"), 8);
        assert_eq!(low_bits("2147483647"), 15);
        assert_eq!(low_bits("-8"), 8);
        assert_eq!(low_bits("-9"), 7);
        assert_eq!(low_bits("0"), 0);
        assert_eq!(low_bits("340282366920938463463374607431768211464"), 8);
        assert_eq!(has_admin_bit(&json!(" 8 ")), Some(true));
        assert_eq!(has_admin_bit(&json!(8.9)), Some(true));
        assert_eq!(has_admin_bit(&json!(true)), Some(false));
        assert_eq!(has_admin_bit(&json!("0x8")), None);
        assert_eq!(has_admin_bit(&Value::Null), None);
    }

    /// 管理できるサーバーの絞り方（飛ばす要素・KeyError・並べられない一覧・名前と icon の直し方）。
    #[test]
    fn admin_guilds_are_picked_like_python() {
        let bot: HashSet<String> = ["1", "2", "3"].iter().map(|s| (*s).to_string()).collect();
        let user = json!([
            "x",
            null,
            [1],
            {"id": " 1 ", "permissions": "8", "name": "", "icon": 5},
            {"id": "2", "permissions": "7"},
            {"id": "3", "permissions": 8, "name": 12},
            {"id": "4", "permissions": "8"},
            {"id": null, "permissions": "8"}
        ]);
        assert_eq!(
            admin_guilds_from(&user, &bot).unwrap(),
            vec![
                json!({"id": "1", "name": "Unknown", "icon": null}),
                json!({"id": "3", "name": "12", "icon": null}),
            ]
        );
        assert_eq!(
            admin_guilds_from(&json!([{"permissions": "8"}]), &bot).unwrap_err(),
            Crash::new("KeyError", "'id'")
        );
        assert_eq!(
            admin_guilds_from(&Value::Null, &bot).unwrap_err(),
            Crash::new("TypeError", "'NoneType' object is not iterable")
        );
        assert!(admin_guilds_from(&json!({"a": 1}), &bot).unwrap().is_empty());
    }

    /// 権限の組み立て（持ち主・@everyone・持っているロール・読めない permissions・形の崩れた答え）。
    #[test]
    fn admin_is_decided_like_user_still_admin() {
        let guild = json!({"owner_id": "9", "roles": [
            {"id": "100", "permissions": "8"},
            {"id": "200", "permissions": "x"},
            {"id": 300, "permissions": "8"}
        ]});
        assert_eq!(admin_from(&guild, &json!({"roles": []}), "100", "7"), Ok(true));
        assert_eq!(admin_from(&guild, &json!({"roles": [200]}), "1", "7"), Ok(false));
        assert_eq!(admin_from(&guild, &json!({"roles": [300]}), "1", "7"), Ok(true));
        assert_eq!(admin_from(&guild, &json!([]), "1", "9"), Ok(true));
        assert_eq!(
            admin_from(&guild, &json!([]), "1", "7"),
            Err(Crash::new(
                "AttributeError",
                "'list' object has no attribute 'get'"
            ))
        );
        assert_eq!(
            admin_from(&json!({"roles": ["x"]}), &json!({}), "1", "7"),
            Err(Crash::new(
                "AttributeError",
                "'str' object has no attribute 'get'"
            ))
        );
        assert_eq!(
            admin_from(&json!({}), &json!({"roles": null}), "1", "7"),
            Err(Crash::new("TypeError", "'NoneType' object is not iterable"))
        );
    }

    /// Python の例外の型と文（int・添字）。
    #[test]
    fn python_errors_carry_the_same_words() {
        assert_eq!(py_int(&json!(" 0042 ")), Ok("42".to_string()));
        assert_eq!(
            py_int(&json!("abc")),
            Err(Crash::new(
                "ValueError",
                "invalid literal for int() with base 10: 'abc'"
            ))
        );
        assert_eq!(
            py_int(&Value::Null).unwrap_err().message,
            "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'"
        );
        assert_eq!(
            py_subscript(&json!(5), "id").unwrap_err().message,
            "'int' object is not subscriptable"
        );
        assert_eq!(py_len(&json!("日本")), Some(2));
        assert_eq!(py_len(&Value::Null), None);
    }
}
