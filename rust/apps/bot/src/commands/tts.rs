//! 読み上げの設定のコマンド（/tts・/voice・/dict）。Python の `commands/tts_commands.py` と
//! `services/tts_store.py` の書き方。
//!
//! - /tts（enable・disable・add_watch・remove_watch・vc・status・default_voice・read_name・default_rate）は管理者だけ
//!   （Python の ensure_admin）
//! - /voice（set・reset・info）と /dict（add・remove・list）は、サーバーの中なら誰でも
//! - /tts default_voice・/voice set の `voice` には、合成の API の声の一覧から補完を出す（権限は見ない）
//!
//! /tts join・leave は VC への接続が要るので、ここには無い（B9b）。
//!
//! /tts status はチャンネルがサーバーにあるかを見るので、[`super::plan`] は通さず、[`super::run`] が先にここ（[`run`]）
//! へ回す。片付け方を決めるところ（[`plan`]）は Discord にも DB にも触らない。

use serde_json::{Map, Value, json};
use serenity::all::{
    AutocompleteChoice, ChannelId, CommandDataOption, CommandDataOptionValue, CommandInteraction,
    CreateAutocompleteResponse, CreateEmbed, CreateInteractionResponse, GuildId,
};
use sycs_core::settings::Settings;
use tracing::warn;

use super::guards::{self, Standing};
use super::reply::{self, EMBED_DESCRIPTION_BUDGET, Reply, cap_list_for_message};
use super::server::python::strip;
use super::server::{child, guild_entry};
use super::settings::{BLURPLE, python_truthy};
use super::{CommandError, Deps, Route};
use crate::python_repr::python_str;
use crate::tts::{self, DEFAULT_RATE, DEFAULT_VOICE, TTS_KEY};

/// 緑（discord.py の `Color.green()`）。
pub const GREEN: u32 = 0x2E_CC_71;
/// 赤（discord.py の `Color.red()`）。
pub const RED: u32 = 0xE7_4C_3C;
/// 青（discord.py の `Color.blue()`）。
pub const BLUE: u32 = 0x34_98_DB;
/// 速度の下限と上限（両端を含む）。
pub const RATE_RANGE: std::ops::RangeInclusive<i64> = 100..=400;
/// 辞書の見出し語・読みの長さの上限。
pub const WORD_LIMIT: usize = 50;
/// 読みの長さの上限。
pub const READING_LIMIT: usize = 100;

/// 読み上げの設定のコマンド。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtsRoute {
    /// `/tts enable`
    Enable,
    /// `/tts disable`
    Disable,
    /// `/tts add_watch`
    AddWatch,
    /// `/tts remove_watch`
    RemoveWatch,
    /// `/tts vc`
    Vc,
    /// `/tts status`
    Status,
    /// `/tts default_voice`
    DefaultVoice,
    /// `/tts read_name`
    ReadName,
    /// `/tts default_rate`
    DefaultRate,
    /// `/voice set`
    VoiceSet,
    /// `/voice reset`
    VoiceReset,
    /// `/voice info`
    VoiceInfo,
    /// `/dict add`
    DictAdd,
    /// `/dict remove`
    DictRemove,
    /// `/dict list`
    DictList,
}

impl TtsRoute {
    /// 管理者だけのコマンドか（/tts の全部）。
    pub fn admin_only(self) -> bool {
        matches!(
            self,
            Self::Enable
                | Self::Disable
                | Self::AddWatch
                | Self::RemoveWatch
                | Self::Vc
                | Self::Status
                | Self::DefaultVoice
                | Self::ReadName
                | Self::DefaultRate
        )
    }
}

/// 片付け方。
pub enum Plan {
    /// 設定に触らずに返す。
    Reply(Box<Reply>),
    /// 設定を書き換えて返す（[`sycs_core::settings::SettingsCache::transact`] の中で呼ぶ）。
    Write(Box<dyn FnOnce(&mut Settings) -> Reply + Send>),
}

/// 片付け方を決めるのに要るもの。
pub struct Input<'a> {
    /// 打った人の立場。
    pub standing: Standing,
    /// 打たれたサーバー。
    pub guild_id: Option<GuildId>,
    /// 打った人。
    pub user_id: u64,
    /// 末端の引数。
    pub options: &'a [CommandDataOption],
    /// そのサーバーのいまの設定。
    pub guild_settings: Option<&'a Value>,
    /// そのチャンネルがサーバーにあるか（/tts status。discord.py の `guild.get_channel`）。
    pub channel_exists: &'a dyn Fn(u64) -> bool,
}

fn option<'a>(options: &'a [CommandDataOption], name: &str) -> Option<&'a CommandDataOptionValue> {
    options.iter().find(|o| o.name == name).map(|o| &o.value)
}

fn channel_option(options: &[CommandDataOption], name: &str) -> Option<u64> {
    match option(options, name)? {
        CommandDataOptionValue::Channel(id) => Some(id.get()),
        _ => None,
    }
}

fn string_option<'a>(options: &'a [CommandDataOption], name: &str) -> Option<&'a str> {
    match option(options, name)? {
        CommandDataOptionValue::String(text) => Some(text),
        _ => None,
    }
}

fn integer_option(options: &[CommandDataOption], name: &str) -> Option<i64> {
    match option(options, name)? {
        CommandDataOptionValue::Integer(number) => Some(*number),
        _ => None,
    }
}

/// `tts` のまとまりに重ねて書く。Python の `_update_nested(guild_id, "tts", …)` と `set_tts_channels`
/// （サーバーの設定・まとまりが辞書でなければ空から。既にある鍵は場所を変えずに値だけ変える）。
fn update_tts(settings: &mut Settings, guild_id: u64, patch: Vec<(&'static str, Value)>) {
    let tts = child(guild_entry(settings, guild_id), TTS_KEY);
    for (key, value) in patch {
        tts.insert(key.to_string(), value);
    }
}

/// 書いて、決まった文を返す。
fn write(
    guild: u64,
    patch: Vec<(&'static str, Value)>,
    text: String,
) -> Result<Plan, CommandError> {
    Ok(Plan::Write(Box::new(move |s| {
        update_tts(s, guild, patch);
        Reply::ephemeral(text)
    })))
}

fn say(text: &str) -> Result<Plan, CommandError> {
    Ok(Plan::Reply(Box::new(Reply::ephemeral(text))))
}

/// 打たれたコマンドをどう片付けるかを決める（権限・引数・いまの設定を見る。Discord にも DB にも触らない）。
pub fn plan(route: TtsRoute, input: &Input<'_>) -> Result<Plan, CommandError> {
    use TtsRoute as R;
    let refusal = if route.admin_only() {
        guards::refusal_for_admin_only(input.standing)
    } else {
        (input.standing == Standing::OutsideGuild).then_some(reply::NOT_IN_GUILD)
    };
    if let Some(text) = refusal {
        return say(text);
    }
    let Some(guild_id) = input.guild_id else {
        return say(reply::NOT_IN_GUILD);
    };
    let guild = guild_id.get();
    let options = input.options;
    let channel =
        || channel_option(options, "channel").ok_or(CommandError::MissingOption("channel"));
    let text =
        |name: &'static str| string_option(options, name).ok_or(CommandError::MissingOption(name));
    // 設定を読むのは、Python が読むコマンドだけ（ほかは、壊れた `tts` を空から書き直すか、触らない）。
    let stored = || tts::settings(input.guild_settings);
    match route {
        R::Enable => write(
            guild,
            vec![("enabled", json!(true))],
            "✅ TTS読み上げを有効にした。".into(),
        ),
        R::Disable => write(
            guild,
            vec![("enabled", json!(false))],
            "❌ TTS読み上げを無効にした。".into(),
        ),
        R::AddWatch => {
            let id = channel()?;
            let stored = stored()?;
            let mut watch = tts::watch_channel_ids(stored)?;
            if !watch.iter().any(|w| u64::try_from(*w) == Ok(id)) {
                watch.push(id as i64);
            }
            // VC は、保存されているものをそのまま書き戻す（数に直さない。Python と同じ）。
            let vc = stored.get("vc_channel_id").cloned().unwrap_or(Value::Null);
            let patch = vec![("watch_channel_ids", json!(watch)), ("vc_channel_id", vc)];
            write(
                guild,
                patch,
                format!("✅ <#{id}> を読み上げ対象に追加した。"),
            )
        }
        R::RemoveWatch => {
            let id = channel()?;
            let stored = stored()?;
            let watch: Vec<i64> = tts::watch_channel_ids(stored)?
                .into_iter()
                .filter(|w| u64::try_from(*w) != Ok(id))
                .collect();
            let vc = stored.get("vc_channel_id").cloned().unwrap_or(Value::Null);
            let patch = vec![("watch_channel_ids", json!(watch)), ("vc_channel_id", vc)];
            write(
                guild,
                patch,
                format!("✅ <#{id}> を読み上げ対象から削除した。"),
            )
        }
        R::Vc => {
            let id = channel()?;
            let watch = tts::watch_channel_ids(stored()?)?;
            let patch = vec![
                ("watch_channel_ids", json!(watch)),
                ("vc_channel_id", json!(id)),
            ];
            write(
                guild,
                patch,
                format!("✅ VCチャンネルを <#{id}> に設定した。"),
            )
        }
        R::Status => Ok(Plan::Reply(Box::new(Reply {
            content: None,
            embeds: vec![status_embed(stored()?, input.channel_exists)?],
            components: Vec::new(),
            ephemeral: true,
        }))),
        R::DefaultVoice => {
            let voice = strip(text("voice")?).to_string();
            if voice.is_empty() {
                return say("❌ 声の名前は空白のみでは指定できぬ。");
            }
            let reply = format!("✅ デフォルト声を `{voice}` に設定した。");
            write(guild, vec![("default_voice", json!(voice))], reply)
        }
        R::ReadName => {
            let on = text("enabled")? == "on";
            let reply = if on {
                "✅ 発言者名を読み上げるようにした。"
            } else {
                "✅ 発言者名を読み上げないようにした。"
            };
            write(guild, vec![("read_name", json!(on))], reply.into())
        }
        R::DefaultRate => {
            let rate =
                integer_option(options, "rate").ok_or(CommandError::MissingOption("rate"))?;
            if !RATE_RANGE.contains(&rate) {
                return say("❌ 速度は100〜400の範囲で指定せよ。");
            }
            write(
                guild,
                vec![("default_rate", json!(rate))],
                format!("✅ デフォルト速度を `{rate}` に設定した。"),
            )
        }
        R::VoiceSet => voice_set(guild, input.user_id, options, stored().ok()),
        R::VoiceReset => {
            let user = input.user_id;
            Ok(Plan::Write(Box::new(move |s| {
                reset_user(s, guild, user);
                Reply::ephemeral("✅ 声設定をリセットした。")
            })))
        }
        R::VoiceInfo => Ok(Plan::Reply(Box::new(Reply {
            content: None,
            embeds: vec![voice_info_embed(stored()?, input.user_id)?],
            components: Vec::new(),
            ephemeral: true,
        }))),
        R::DictAdd => {
            let word = strip(text("word")?).to_string();
            let reading = strip(text("reading")?).to_string();
            if word.is_empty() || reading.is_empty() {
                return say("❌ 単語・読みのいずれも空白のみは指定できぬ。");
            }
            if word.chars().count() > WORD_LIMIT || reading.chars().count() > READING_LIMIT {
                return say("❌ 単語は50文字以内、読みは100文字以内にせよ。");
            }
            Ok(Plan::Write(Box::new(move |s| {
                add_entry(s, guild, &word, &reading);
                Reply::ephemeral(format!("✅ `{word}` → `{reading}` を辞書に登録した。"))
            })))
        }
        R::DictRemove => {
            // 返事に出すのは打ったままの文字（Python も、消すときだけ前後の空白を落とす）。
            let shown = text("word")?.to_string();
            Ok(Plan::Write(Box::new(move |s| {
                if remove_entry(s, guild, strip(&shown)) {
                    Reply::ephemeral(format!("✅ `{shown}` を辞書から削除した。"))
                } else {
                    Reply::ephemeral(format!("❌ `{shown}` は辞書に存在しない。"))
                }
            })))
        }
        R::DictList => dict_list(stored()?),
    }
}

/// /voice set。Python の `voice_set` と `set_user_tts_settings`。
fn voice_set(
    guild: u64,
    user: u64,
    options: &[CommandDataOption],
    stored: Option<&Map<String, Value>>,
) -> Result<Plan, CommandError> {
    // 空白だけの声は「指定なし」。
    let voice = string_option(options, "voice")
        .map(|v| strip(v).to_string())
        .filter(|v| !v.is_empty());
    let rate = integer_option(options, "rate");
    if voice.is_none() && rate.is_none() {
        return say("❌ voice か rate のどちらかを指定せよ。");
    }
    if rate.is_some_and(|r| !RATE_RANGE.contains(&r)) {
        return say("❌ 速度は100〜400の範囲で指定せよ。");
    }
    // いまの上書きが辞書にできない形なら、Python は書く前に例外になる（`tts` そのものが壊れていれば、空から書く）。
    if let Some(stored) = stored {
        tts::user_settings(stored, user)?;
    }
    let mut parts = Vec::new();
    if let Some(v) = &voice {
        parts.push(format!("声: `{v}`"));
    }
    if let Some(r) = rate {
        parts.push(format!("速度: `{r}`"));
    }
    let text = format!("✅ 声設定を更新した（{}）。", parts.join(", "));
    Ok(Plan::Write(Box::new(move |s| {
        set_user(s, guild, user, voice, rate);
        Reply::ephemeral(text)
    })))
}

/// `user_settings` の入れ物（辞書でなければ、その場所で空に置き換える）。
fn users_of(tts: &mut Map<String, Value>) -> &mut Map<String, Value> {
    child(tts, "user_settings")
}

/// その人の声・速度を書く。Python の `set_user_tts_settings`（渡したものだけ上書き。ほかの項目は残す）。
fn set_user(
    settings: &mut Settings,
    guild: u64,
    user: u64,
    voice: Option<String>,
    rate: Option<i64>,
) {
    let tts = child(guild_entry(settings, guild), TTS_KEY);
    let users = users_of(tts);
    let key = user.to_string();
    let mut entry = match users.get(&key) {
        Some(Value::Object(entry)) => entry.clone(),
        _ => Map::new(),
    };
    if let Some(voice) = voice {
        entry.insert("voice".into(), json!(voice));
    }
    if let Some(rate) = rate {
        entry.insert("rate".into(), json!(rate));
    }
    users.insert(key, Value::Object(entry));
}

/// その人の上書きを消す。Python の `reset_user_tts_settings`。
///
/// `tts` が辞書でなければ何もしない（サーバーの入れ物だけは作る）。無ければ空の `tts` と `user_settings` を作る
/// （Python が、取り出したものを必ず書き戻すため）。`user_settings` が辞書でなければ、そのまま書き戻す。
fn reset_user(settings: &mut Settings, guild: u64, user: u64) {
    let current = guild_entry(settings, guild);
    if current.get(TTS_KEY).is_some_and(|v| !v.is_object()) {
        return;
    }
    let tts = child(current, TTS_KEY);
    match tts.get_mut("user_settings") {
        Some(Value::Object(users)) => {
            users.shift_remove(&user.to_string());
        }
        Some(_) => {}
        None => {
            tts.insert("user_settings".into(), json!({}));
        }
    }
}

/// 辞書に 1 件書く（同じ語は読みを上書き）。Python の `add_tts_dictionary_entry`。
fn add_entry(settings: &mut Settings, guild: u64, word: &str, reading: &str) {
    let tts = child(guild_entry(settings, guild), TTS_KEY);
    child(tts, "dictionary").insert(word.to_string(), json!(reading));
}

/// 辞書から 1 件消す。消したら `true`。Python の `remove_tts_dictionary_entry`（サーバーの入れ物だけは作る）。
fn remove_entry(settings: &mut Settings, guild: u64, word: &str) -> bool {
    let current = guild_entry(settings, guild);
    let Some(Value::Object(tts)) = current.get_mut(TTS_KEY) else {
        return false;
    };
    let Some(Value::Object(dictionary)) = tts.get_mut("dictionary") else {
        return false;
    };
    dictionary.shift_remove(word).is_some()
}

/// /tts status の Embed。Python の `tts_status`。
fn status_embed(
    stored: &Map<String, Value>,
    channel_exists: &dyn Fn(u64) -> bool,
) -> Result<CreateEmbed, CommandError> {
    let enabled = python_truthy(stored.get("enabled"));
    let mention_of = |raw: &Value| -> Result<String, CommandError> {
        let id = python_id(raw)?;
        Ok(match id {
            Some(id) if channel_exists(id) => format!("<#{id}>"),
            _ => format!("（不明: {}）", python_str(raw)),
        })
    };
    let watch: Vec<String> = watch_items(stored)?
        .iter()
        .map(mention_of)
        .collect::<Result<_, _>>()?;
    let vc = match stored.get("vc_channel_id") {
        Some(raw) if python_truthy(Some(raw)) => match python_id(raw)? {
            Some(id) if channel_exists(id) => format!("<#{id}>"),
            _ => "未設定".into(),
        },
        _ => "未設定".into(),
    };
    let voice = stored
        .get("default_voice")
        .map_or_else(|| DEFAULT_VOICE.into(), python_str);
    let rate = stored
        .get("default_rate")
        .map_or_else(|| DEFAULT_RATE.to_string(), python_str);
    let read_name = stored
        .get("read_name")
        .is_none_or(|v| python_truthy(Some(v)));
    let words = tts::dictionary(stored).len();
    Ok(CreateEmbed::new()
        .title("TTS 設定状況")
        .colour(if enabled { GREEN } else { RED })
        .field("状態", if enabled { "✅ 有効" } else { "❌ 無効" }, false)
        .field(
            "読み上げチャンネル",
            if watch.is_empty() {
                "未設定".to_string()
            } else {
                watch.join("\n")
            },
            false,
        )
        .field("VCチャンネル", vc, true)
        .field("デフォルト声", voice, true)
        .field("デフォルト速度", rate, true)
        .field(
            "名前読み上げ",
            if read_name {
                "✅ あり"
            } else {
                "❌ なし"
            },
            true,
        )
        .field("辞書登録数", words.to_string(), true))
}

/// `watch_channel_ids` を回したときの要素（Python の `for cid in settings.get("watch_channel_ids", [])`）。
fn watch_items(stored: &Map<String, Value>) -> Result<Vec<Value>, CommandError> {
    Ok(match stored.get("watch_channel_ids") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(Value::String(text)) => text.chars().map(|c| Value::String(c.to_string())).collect(),
        Some(Value::Object(map)) => map.keys().map(|k| Value::String(k.clone())).collect(),
        Some(_) => return Err(CommandError::BrokenSetting("watch_channel_ids")),
    })
}

/// `int(値)` で引く ID（0 以下は、どのチャンネルにも当たらない）。読めなければ `Err`。
fn python_id(raw: &Value) -> Result<Option<u64>, CommandError> {
    let id = tts::python_int(raw, "watch_channel_ids")?;
    Ok(u64::try_from(id).ok().filter(|id| *id > 0))
}

/// /voice info の Embed。Python の `voice_info`。
fn voice_info_embed(stored: &Map<String, Value>, user: u64) -> Result<CreateEmbed, CommandError> {
    let custom = tts::user_settings(stored, user)?;
    let pick = |user_key: &str, server_key: &str, fallback: String| {
        [custom.and_then(|c| c.get(user_key)), stored.get(server_key)]
            .into_iter()
            .flatten()
            .find(|v| python_truthy(Some(v)))
            .map_or(fallback, python_str)
    };
    let voice = pick("voice", "default_voice", DEFAULT_VOICE.into());
    let rate = pick("rate", "default_rate", DEFAULT_RATE.to_string());
    let has_custom = custom.is_some_and(|c| !c.is_empty());
    Ok(CreateEmbed::new()
        .title("貴様の声設定")
        .colour(BLURPLE)
        .field("声", voice, true)
        .field("速度", rate, true)
        .field(
            "カスタム設定",
            if has_custom {
                "✅ あり（個別設定）"
            } else {
                "❌ なし（サーバーデフォルト）"
            },
            false,
        ))
}

/// /dict list。Python の `dict_list`。
fn dict_list(stored: &Map<String, Value>) -> Result<Plan, CommandError> {
    let entries = tts::dictionary(stored);
    if entries.is_empty() {
        return say("辞書は空だ。");
    }
    let lines: Vec<String> = entries
        .iter()
        .map(|(w, r)| format!("`{w}` → `{r}`"))
        .collect();
    let description = cap_list_for_message(&lines, EMBED_DESCRIPTION_BUDGET, "件", "\n", None, "");
    Ok(Plan::Reply(Box::new(Reply {
        content: None,
        embeds: vec![
            CreateEmbed::new()
                .title("TTS 辞書")
                .description(description)
                .colour(BLUE),
        ],
        components: Vec::new(),
        ephemeral: true,
    })))
}

/// 振り分けの先から、読み上げの設定のコマンドを引く。
pub fn route_of(route: Route) -> Option<TtsRoute> {
    match route {
        Route::Tts(route) => Some(route),
        _ => None,
    }
}

/// 打たれた読み上げの設定のコマンドを実行して、返事を作る。読み上げのコマンドでなければ `None`。
pub async fn run(
    deps: &Deps<'_>,
    route: Route,
    command: &CommandInteraction,
    options: &[CommandDataOption],
) -> Option<Result<Reply, CommandError>> {
    let which = route_of(route)?;
    // 決めるところは、書く前に終える（キャッシュを引く関数を、書き込みの待ちをまたいで持たない）。
    let planned = {
        let snapshot = deps.settings.snapshot();
        let guild_id = command.guild_id;
        let channel_exists = |id: u64| {
            guild_id
                .and_then(|g| deps.cache.guild(g))
                .is_some_and(|g| g.channels.contains_key(&ChannelId::new(id)))
        };
        let input = Input {
            standing: super::standing_of(deps.cache, command),
            guild_id,
            user_id: command.user.id.get(),
            options,
            guild_settings: guild_id.and_then(|g| snapshot.guild(g.get())),
            channel_exists: &channel_exists,
        };
        plan(which, &input)
    };
    Some(match planned {
        Ok(Plan::Reply(reply)) => Ok(*reply),
        Ok(Plan::Write(write)) => deps
            .settings
            .transact(write)
            .await
            .map_err(CommandError::from),
        Err(e) => Err(e),
    })
}

/// 声の補完（/tts default_voice・/voice set の `voice`）。この補完でなければ `false`（ほかの補完へ回す）。
pub async fn autocomplete(deps: &Deps<'_>, interaction: &CommandInteraction) -> bool {
    let (path, _) = super::command_path(&interaction.data.name, &interaction.data.options);
    let Some(focused) = interaction.data.autocomplete() else {
        return false;
    };
    let ours =
        matches!(path.as_str(), "tts default_voice" | "voice set") && focused.name == "voice";
    if !ours {
        return false;
    }
    let voices = deps.tts.fetch_voices().await;
    let list: Vec<AutocompleteChoice> = tts::voice_choices(&voices, focused.value)
        .into_iter()
        .map(|v| AutocompleteChoice::new(v.clone(), v))
        .collect();
    let response = CreateInteractionResponse::Autocomplete(
        CreateAutocompleteResponse::new().set_choices(list),
    );
    if let Err(e) = interaction.create_response(deps.http, response).await {
        warn!("[CMD] /{path} の声の補完を送れませんでした: {e}");
    }
    true
}
