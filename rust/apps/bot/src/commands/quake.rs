//! 地震アラートの設定のコマンド（/quake channel・min_scale・status・type）。Python の `commands/server/quake.py`
//! と、そこから呼ぶ `services/settings_store.py` の `set_earthquake_channel`・`set_earthquake_min_scale`・
//! `get_earthquake_settings`・`get_earthquake_notify_types`・`set_earthquake_notify_types`・`_update_nested`。
//!
//! 書く先は、そのサーバーの設定の `earthquake`（`channel_id`・`min_scale`・`notify_types`）。通知の側
//! （[`crate::earthquake`]）が同じ形で読む。
//!
//! `/quake type` は、通知の種類ごとの入・切のボタンと「保存して閉じる」のボタンの画面を出す（Python の
//! `_NotifyTypeView`）。押しても Bot の中の覚えが変わるだけで、**保存を押すまで設定には書かない**。覚えは
//! [`Screens`] が印（部品の ID に入れる乱数）ごとに持ち、最後に触ってから 180 秒で忘れる（Python の View の
//! timeout と同じ）。作りは [`super::picker`] と同じで、純粋な状態機械（[`Screens`] が [`Step`] を返す）と
//! 部品を作る関数（[`components`]）に分け、Discord への応答は [`component`] がする。
//!
//! 権限の見方がコマンドごとに違う（status は誰でも打てる）ので、[`super::plan`] は通さず、[`super::run`] が
//! 先にここ（[`run`]）へ回す。片付け方を決めるところ（[`plan`]）は Discord にも DB にも触らない。

use std::sync::Mutex;
use std::time::Instant;

use serde_json::{Map, Value, json};
use serenity::all::{
    ButtonStyle, ChannelId, CommandDataOption, CommandDataOptionValue, CommandInteraction,
    ComponentInteraction, ComponentInteractionDataKind, CreateActionRow, CreateButton, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage, GuildId,
};
use sycs_core::settings::Settings;
use sycs_core::ttl_cache::TtlCache;
use tracing::{error, warn};

use super::guards::{self, Standing};
use super::overview::admin_site_row;
use super::picker::NOT_YOURS;
use super::reply::{self, Reply};
use super::settings::python_truthy;
use super::{CommandError, Deps, Route};
use crate::log_channel::python_str;

/// 設定の鍵: 地震アラートのまとまり。
pub const BLOCK_KEY: &str = "earthquake";
/// 通知の種類（設定の鍵と、画面に出す名前）。並びは Python の `_NOTIFY_TYPE_LABELS`・`_NOTIFY_TYPE_KEYS`。
pub const NOTIFY_TYPES: [(&str, &str); 5] = [
    ("eew_forecast", "緊急地震速報（予報）"),
    ("eew_warning", "緊急地震速報（警報）"),
    ("tsunami", "津波情報"),
    ("quake_info", "地震情報"),
    ("bot_news", "ボットに関するお知らせ"),
];
/// 震度の階級（P2P地震情報の数値と、表示）。Python の `config.SCALE_LABELS`。
pub const SCALE_LABELS: [(i64, &str); 9] = [
    (10, "1"),
    (20, "2"),
    (30, "3"),
    (40, "4"),
    (45, "5弱"),
    (50, "5強"),
    (55, "6弱"),
    (60, "6強"),
    (70, "7"),
];
/// 「通知する最小震度」が未設定のときの値（震度 3）。
pub const DEFAULT_MIN_SCALE: i64 = 30;
/// Embed の色（discord.py の `Color.orange()`）。
pub const ORANGE: u32 = 0xE6_7E_22;
/// 画面を触らずに置いておける秒数（Python の `_NotifyTypeView` の `timeout=180`）。
pub const TIMEOUT_SECONDS: f64 = 180.0;
/// 同時に覚えておく画面の数。
const MAX_OPEN: usize = 1024;
/// 部品の ID の先頭。
pub const ID_PREFIX: &str = "quake";
/// 保存したときの本文。
pub const SAVED: &str = "✅ 余の意志を刻んだ。";
/// 「保存して閉じる」のボタンの文。
pub const SAVE_LABEL: &str = "保存して閉じる";
/// 項目の区切りに置く、幅の無い空白（1 文字）。Embed の横並びをここで折り返させる。
const ZERO_WIDTH_SPACE: &str = "\u{200b}";

/// どの /quake か。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `/quake channel`
    Channel,
    /// `/quake min_scale`
    MinScale,
    /// `/quake status`
    Status,
    /// `/quake type`
    Type,
}

/// 振り分けの先から、どの /quake かを引く。/quake でなければ `None`。
pub fn command_of(route: Route) -> Option<Command> {
    match route {
        Route::QuakeChannel => Some(Command::Channel),
        Route::QuakeMinScale => Some(Command::MinScale),
        Route::QuakeStatus => Some(Command::Status),
        Route::QuakeType => Some(Command::Type),
        _ => None,
    }
}

/// 通知の種類ごとの入・切（並びは [`NOTIFY_TYPES`]）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyTypes(pub [bool; 5]);

impl NotifyTypes {
    /// 設定に書く形（鍵は [`NOTIFY_TYPES`] の並び、値は真偽）。Python の `set_earthquake_notify_types` の `patch`。
    pub fn to_value(self) -> Value {
        let map: Map<String, Value> = NOTIFY_TYPES
            .iter()
            .zip(self.0)
            .map(|((key, _), enabled)| (key.to_string(), Value::Bool(enabled)))
            .collect();
        Value::Object(map)
    }
}

/// 設定の中の辞書を読む。Python の `dict(value)`（無ければ空。辞書にできない値は失敗）。
///
/// 空の配列・空の文字は、Python の `dict()` では空の辞書になる。null は失敗（保存のときに落ちるので、
/// ふつうは入っていない）。
fn dict_of<'a>(
    value: Option<&'a Value>,
    what: &'static str,
) -> Result<Option<&'a Map<String, Value>>, CommandError> {
    match value {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(Value::Array(items)) if items.is_empty() => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(_) => Err(CommandError::BrokenSetting(what)),
    }
}

/// そのサーバーの `earthquake` のまとまり。Python の `get_earthquake_settings`。
fn block(guild: Option<&Value>) -> Result<Option<&Map<String, Value>>, CommandError> {
    let guild = dict_of(guild, "サーバーの設定")?;
    dict_of(guild.and_then(|g| g.get(BLOCK_KEY)), BLOCK_KEY)
}

/// 通知の種類ごとの入・切を読む。書いていない種類は入。Python の `get_earthquake_notify_types`。
///
/// `notify_types` が辞書でなければ失敗（Python は `.get` で例外になる。空の配列でも同じ）。
pub fn notify_types(guild: Option<&Value>) -> Result<NotifyTypes, CommandError> {
    let stored = match block(guild)?.and_then(|b| b.get("notify_types")) {
        None => None,
        Some(Value::Object(types)) => Some(types),
        Some(_) => {
            return Err(CommandError::BrokenSetting("notify_types"));
        }
    };
    let enabled = |key: &str| match stored.and_then(|types| types.get(key)) {
        None => true,
        Some(value) => python_truthy(Some(value)),
    };
    Ok(NotifyTypes(NOTIFY_TYPES.map(|(key, _)| enabled(key))))
}

/// まとまりの一部だけを重ねて書く。Python の `_update_nested`。
///
/// そのサーバーの設定・まとまりのどちらも、辞書でなければ空から作り直す。既にある鍵は場所を変えずに値だけ
/// 変え、新しい鍵は末尾に足す。
pub fn update_nested(
    settings: &mut Settings,
    guild_id: u64,
    top_key: &str,
    patch: impl IntoIterator<Item = (&'static str, Value)>,
) {
    let key = guild_id.to_string();
    let mut current = settings
        .guilds
        .get(&key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut nested = current
        .get(top_key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, value) in patch {
        nested.insert(name.to_string(), value);
    }
    current.insert(top_key.to_string(), Value::Object(nested));
    settings.guilds.insert(key, Value::Object(current));
}

/// `/quake channel`: 地震アラートを送るチャンネルを決める（通知の種類には触らない）。
pub fn set_channel(settings: &mut Settings, guild_id: u64, channel_id: u64) -> Reply {
    update_nested(
        settings,
        guild_id,
        BLOCK_KEY,
        [("channel_id", json!(channel_id))],
    );
    Reply::ephemeral(format!(
        "<#{channel_id}> を地震アラートチャンネルと定めた。"
    ))
}

/// 震度の表示。表に無い数は、数のまま（Python の `SCALE_LABELS.get(scale, scale)`）。
pub fn scale_label(scale: i64) -> String {
    SCALE_LABELS
        .iter()
        .find(|(code, _)| *code == scale)
        .map_or_else(|| scale.to_string(), |(_, label)| label.to_string())
}

/// `/quake min_scale`: この震度に届かない地震は通知しない、という下限を決める。
pub fn set_min_scale(settings: &mut Settings, guild_id: u64, scale: i64) -> Reply {
    update_nested(settings, guild_id, BLOCK_KEY, [("min_scale", json!(scale))]);
    Reply::ephemeral(format!(
        "地震アラートの最小震度を 震度{} と定めた。",
        scale_label(scale)
    ))
}

/// 保存を押したときの書き込み。Python の `set_earthquake_notify_types`（`notify_types` を丸ごと置き換える）。
pub fn save_notify_types(settings: &mut Settings, guild_id: u64, types: NotifyTypes) {
    update_nested(
        settings,
        guild_id,
        BLOCK_KEY,
        [("notify_types", types.to_value())],
    );
}

fn enabled_text(enabled: bool) -> &'static str {
    if enabled { "✅ 有効" } else { "❌ 無効" }
}

/// 通知の種類の画面の Embed。Python の `_build_notify_type_embed`。
pub fn notify_type_embed(types: NotifyTypes) -> CreateEmbed {
    let mut embed = CreateEmbed::new()
        .title("地震通知タイプ設定")
        .description("ボタンをクリックしてオン/オフを切り替え、「保存」で確定します。")
        .colour(ORANGE);
    for ((_, label), enabled) in NOTIFY_TYPES.iter().zip(types.0) {
        embed = embed.field(*label, enabled_text(enabled), true);
    }
    embed
}

/// `/quake status` の Embed（いまの設定）。Python の `eq_settings_cmd`。
pub fn status_embed(guild: Option<&Value>) -> Result<CreateEmbed, CommandError> {
    let block = block(guild)?;
    let types = notify_types(guild)?;
    let channel = block.and_then(|b| b.get("channel_id"));
    let channel_text = match channel {
        Some(value) if python_truthy(channel) => format!("<#{}>", python_str(value)),
        _ => "未設定".to_string(),
    };
    // 階級の表示（5弱 など）ではなく、保存されている数をそのまま出す（Python と同じ）。
    let min_scale = block
        .and_then(|b| b.get("min_scale"))
        .map_or_else(|| DEFAULT_MIN_SCALE.to_string(), python_str);
    let mut embed = CreateEmbed::new()
        .title("地震アラート設定")
        .colour(ORANGE)
        .field("チャンネル", channel_text, true)
        .field("最小震度", min_scale, true)
        .field(ZERO_WIDTH_SPACE, ZERO_WIDTH_SPACE, false);
    for ((_, label), enabled) in NOTIFY_TYPES.iter().zip(types.0) {
        embed = embed.field(*label, enabled_text(enabled), true);
    }
    Ok(embed)
}

/// 部品のどれが触られたか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// 通知の種類の入・切のボタン（[`NOTIFY_TYPES`] の何番目か）。
    Toggle(usize),
    /// 「保存して閉じる」のボタン。
    Save,
}

/// 部品の ID（`quake:<画面の印>:toggle:<種類の鍵>` か `quake:<画面の印>:save`）。
pub fn custom_id(token: &str, part: Part) -> String {
    match part {
        Part::Toggle(index) => format!("{ID_PREFIX}:{token}:toggle:{}", NOTIFY_TYPES[index].0),
        Part::Save => format!("{ID_PREFIX}:{token}:save"),
    }
}

/// 部品の ID から、画面の印とどの部品かを読む。この画面のものでなければ `None`。
pub fn parse_custom_id(id: &str) -> Option<(&str, Part)> {
    let mut parts = id.split(':');
    if parts.next()? != ID_PREFIX {
        return None;
    }
    let token = parts.next()?;
    let part = match parts.next()? {
        "save" => Part::Save,
        "toggle" => {
            let key = parts.next()?;
            Part::Toggle(NOTIFY_TYPES.iter().position(|(k, _)| *k == key)?)
        }
        _ => return None,
    };
    (parts.next().is_none() && !token.is_empty()).then_some((token, part))
}

/// 画面の部品。種類ごとのボタンを 2 つずつ並べ、最後の行に「保存して閉じる」。Python の `_rebuild`。
pub fn components(token: &str, types: NotifyTypes) -> Vec<CreateActionRow> {
    let toggles: Vec<CreateButton> = NOTIFY_TYPES
        .iter()
        .zip(types.0)
        .enumerate()
        .map(|(index, ((_, label), enabled))| {
            let mark = if enabled { "✅" } else { "❌" };
            CreateButton::new(custom_id(token, Part::Toggle(index)))
                .label(format!("{mark} {label}"))
                .style(if enabled {
                    ButtonStyle::Success
                } else {
                    ButtonStyle::Secondary
                })
        })
        .collect();
    let mut rows: Vec<CreateActionRow> = toggles
        .chunks(2)
        .map(|pair| CreateActionRow::Buttons(pair.to_vec()))
        .collect();
    let save = CreateButton::new(custom_id(token, Part::Save))
        .label(SAVE_LABEL)
        .style(ButtonStyle::Primary);
    rows.push(CreateActionRow::Buttons(vec![save]));
    rows
}

/// 開いている画面 1 つぶんの覚え。
#[derive(Clone, Debug, PartialEq, Eq)]
struct Open {
    author: u64,
    guild: u64,
    types: NotifyTypes,
}

/// 触られた結果、どうするか。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// 何もしない（この Bot が開いた画面でない・時間切れ・保存済み）。Python の View も応えない。
    Ignore,
    /// 本人でない人が触った。その人にだけ見える文を返す。
    NotYours,
    /// 入・切を切り替えた。Embed と部品を描き直す（まだ書かない）。
    Redraw {
        /// 切り替えたあとの入・切。
        types: NotifyTypes,
    },
    /// 保存を押した。設定を書いて、画面を結果に置き換える。
    Save {
        /// 画面を開いたサーバー。
        guild: u64,
        /// 保存する入・切。
        types: NotifyTypes,
    },
}

/// 開いている画面の覚え。1 つを使い回す。
pub struct Screens {
    open: Mutex<TtlCache<String, Open>>,
    started: Instant,
}

impl Default for Screens {
    fn default() -> Self {
        Self {
            open: Mutex::new(TtlCache::new(TIMEOUT_SECONDS, MAX_OPEN)),
            started: Instant::now(),
        }
    }
}

impl Screens {
    fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TtlCache<String, Open>> {
        self.open.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 画面を開く。部品の ID に入れる印を返す。
    pub fn open(&self, author: u64, guild: u64, types: NotifyTypes) -> String {
        self.open_at(author, guild, types, self.now())
    }

    /// 入・切のボタンが押された。
    pub fn toggle(&self, token: &str, user: u64, index: usize) -> Step {
        self.toggle_at(token, user, index, self.now())
    }

    /// 「保存して閉じる」が押された。
    pub fn save(&self, token: &str, user: u64) -> Step {
        self.save_at(token, user, self.now())
    }

    /// 画面を閉じる（保存できたあと。Python の `self.stop()`）。
    pub fn close(&self, token: &str) {
        self.lock().pop(&token.to_string());
    }

    fn open_at(&self, author: u64, guild: u64, types: NotifyTypes, now: f64) -> String {
        let token = random_token();
        let state = Open {
            author,
            guild,
            types,
        };
        self.lock().set(token.clone(), state, now);
        token
    }

    /// 覚えを取り出し、触られた時刻を新しくする（本人でない人が触っても延びる。Python の View と同じ）。
    fn touch(&self, token: &str, now: f64) -> Option<Open> {
        let mut open = self.lock();
        let state = open.get(&token.to_string(), now)?;
        open.set(token.to_string(), state.clone(), now);
        Some(state)
    }

    fn toggle_at(&self, token: &str, user: u64, index: usize, now: f64) -> Step {
        let Some(mut state) = self.touch(token, now) else {
            return Step::Ignore;
        };
        if state.author != user {
            return Step::NotYours;
        }
        let Some(enabled) = state.types.0.get_mut(index) else {
            return Step::Ignore;
        };
        *enabled = !*enabled;
        let types = state.types;
        self.lock().set(token.to_string(), state, now);
        Step::Redraw { types }
    }

    fn save_at(&self, token: &str, user: u64, now: f64) -> Step {
        let Some(state) = self.touch(token, now) else {
            return Step::Ignore;
        };
        if state.author != user {
            return Step::NotYours;
        }
        // 画面を閉じるのは、設定を書けてから（[`Screens::close`]）。書けなかったときは、もう一度押せる。
        Step::Save {
            guild: state.guild,
            types: state.types,
        }
    }
}

/// 部品の ID に入れる印（当てずっぽうで他人の画面を触れないよう、乱数にする）。
fn random_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::with_capacity(32);
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        out.push_str(&format!("{:016x}", hasher.finish()));
    }
    out
}

/// 実行の段取り。すぐ返事するか、設定を書き換えてから返事するか。
pub enum Plan {
    /// 設定に触らずに返す（断るとき・いまの設定の表示・画面を開くとき）。
    Reply(Box<Reply>),
    /// 設定を書き換えて、その結果から返事を作る（`SettingsCache::transact` の中で呼ぶ）。
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
    /// 開いている画面の覚え。
    pub screens: &'a Screens,
    /// 管理画面の場所（リンクのボタン）。
    pub admin_site_url: &'a str,
}

/// 打たれた /quake をどう片付けるかを決める（権限・引数を見る。Discord にも DB にも触らない）。
pub fn plan(command: Command, input: &Input<'_>) -> Result<Plan, CommandError> {
    let reply = |reply: Reply| Ok(Plan::Reply(Box::new(reply)));
    // status は誰でも打てる（サーバーの中なら）。ほかは管理者だけ（Python の ensure_admin）。
    if command == Command::Status {
        if input.standing == Standing::OutsideGuild {
            return reply(Reply::ephemeral(reply::NOT_IN_GUILD));
        }
        return reply(Reply {
            content: None,
            embeds: vec![status_embed(input.guild_settings)?],
            components: admin_site_row(input.admin_site_url),
            ephemeral: true,
        });
    }
    if let Some(text) = guards::refusal_for_admin_only(input.standing) {
        return reply(Reply::ephemeral(text));
    }
    let Some(guild_id) = input.guild_id else {
        return reply(Reply::ephemeral(reply::NOT_IN_GUILD));
    };
    let guild = guild_id.get();
    let option = |name: &str| {
        input
            .options
            .iter()
            .find(|o| o.name == name)
            .map(|o| &o.value)
    };
    match command {
        Command::Channel => {
            let Some(CommandDataOptionValue::Channel(channel)) = option("channel") else {
                return Err(CommandError::MissingOption("channel"));
            };
            let channel = ChannelId::get(*channel);
            Ok(Plan::Write(Box::new(move |s| {
                set_channel(s, guild, channel)
            })))
        }
        Command::MinScale => {
            let Some(CommandDataOptionValue::Integer(scale)) = option("scale") else {
                return Err(CommandError::MissingOption("scale"));
            };
            let scale = *scale;
            Ok(Plan::Write(Box::new(move |s| {
                set_min_scale(s, guild, scale)
            })))
        }
        Command::Type => {
            let types = notify_types(input.guild_settings)?;
            let token = input.screens.open(input.user_id, guild, types);
            reply(Reply {
                content: None,
                embeds: vec![notify_type_embed(types)],
                components: components(&token, types),
                ephemeral: true,
            })
        }
        // 上で返している。
        Command::Status => reply(Reply::default()),
    }
}

/// 打たれた /quake を実行して、返事を作る。/quake でなければ `None`（[`super::run`] が続きをする）。
pub async fn run(
    deps: &Deps<'_>,
    route: Route,
    command: &CommandInteraction,
    options: &[CommandDataOption],
) -> Option<Result<Reply, CommandError>> {
    let which = command_of(route)?;
    let snapshot = deps.settings.snapshot();
    let input = Input {
        standing: super::standing_of(deps.cache, command),
        guild_id: command.guild_id,
        user_id: command.user.id.get(),
        options,
        guild_settings: command.guild_id.and_then(|g| snapshot.guild(g.get())),
        screens: deps.quake_screens,
        admin_site_url: deps.admin_site_url,
    };
    Some(match plan(which, &input) {
        Ok(Plan::Reply(reply)) => Ok(*reply),
        Ok(Plan::Write(write)) => deps
            .settings
            .transact(write)
            .await
            .map_err(CommandError::from),
        Err(e) => Err(e),
    })
}

/// 触られた部品（入・切のボタン・保存のボタン）を 1 つ片付ける。[`super::component`] が、ID の先頭が
/// `quake:` のものをここへ回す。
///
/// この Bot が開いた画面でない・時間切れ・保存済みのものには応えない（Python の View も応えない）。
pub async fn component(deps: &Deps<'_>, interaction: &ComponentInteraction) {
    let Some((token, part)) = parse_custom_id(&interaction.data.custom_id) else {
        return;
    };
    if !matches!(interaction.data.kind, ComponentInteractionDataKind::Button) {
        return;
    }
    let user = interaction.user.id.get();
    let step = match part {
        Part::Toggle(index) => deps.quake_screens.toggle(token, user, index),
        Part::Save => deps.quake_screens.save(token, user),
    };
    let say = |text: &str| {
        CreateInteractionResponse::Message(super::response_message(Reply::ephemeral(text)))
    };
    let response = match step {
        Step::Ignore => return,
        Step::NotYours => say(NOT_YOURS),
        // 切り替えただけではまだ書かない。Embed と部品を描き直す（Python の `edit_message(embed=…, view=self)`）。
        Step::Redraw { types } => CreateInteractionResponse::UpdateMessage(
            CreateInteractionResponseMessage::new()
                .embed(notify_type_embed(types))
                .components(components(token, types)),
        ),
        Step::Save { guild, types } => {
            let written = deps
                .settings
                .transact(move |s| save_notify_types(s, guild, types))
                .await;
            match written {
                Ok(()) => {
                    // 書けたら画面は終わり（Python の `clear_items()` と `stop()`）。部品を外す。
                    deps.quake_screens.close(token);
                    CreateInteractionResponse::UpdateMessage(
                        CreateInteractionResponseMessage::new()
                            .content(SAVED)
                            .embed(notify_type_embed(types))
                            .components(Vec::new()),
                    )
                }
                Err(e) => {
                    // 画面は残す（もう一度「保存して閉じる」を押せる。Python も、書けなかったときは View を止めない）。
                    error!("[CMD] 地震の通知の種類を保存できませんでした guild={guild}: {e}");
                    say(reply::FAILED)
                }
            }
        }
    };
    if let Err(e) = interaction.create_response(deps.http, response).await {
        warn!("[CMD] 地震の通知の種類の画面への応答を送れませんでした: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ON: NotifyTypes = NotifyTypes([true; 5]);

    /// 部品の ID は行って戻れること。この画面のものでない ID・知らない種類は読まないこと。
    #[test]
    fn custom_ids_round_trip() {
        assert_eq!(
            custom_id("abc", Part::Toggle(2)),
            "quake:abc:toggle:tsunami"
        );
        assert_eq!(custom_id("abc", Part::Save), "quake:abc:save");
        for index in 0..NOTIFY_TYPES.len() {
            let id = custom_id("t", Part::Toggle(index));
            assert_eq!(
                parse_custom_id(&id),
                Some(("t", Part::Toggle(index))),
                "{id}"
            );
        }
        assert_eq!(parse_custom_id("quake:t:save"), Some(("t", Part::Save)));
        for other in [
            "",
            "quake",
            "quake:t",
            "quake::save",
            "quake:t:other",
            "quake:t:save:x",
            "quake:t:toggle",
            "quake:t:toggle:unknown",
            "quake:t:toggle:tsunami:x",
            "picker:t:select",
            "eq_toggle_tsunami",
        ] {
            assert_eq!(parse_custom_id(other), None, "{other}");
        }
    }

    /// 切り替え → 描き直し → 保存、の流れ。保存して閉じたあとは応えないこと。
    #[test]
    fn toggle_then_save() {
        let screens = Screens::default();
        let token = screens.open_at(7, 99, ALL_ON, 0.0);
        assert_eq!(
            screens.toggle_at(&token, 7, 2, 1.0),
            Step::Redraw {
                types: NotifyTypes([true, true, false, true, true])
            }
        );
        // もう一度押すと戻る。別の種類は別々に切り替わる。
        assert_eq!(
            screens.toggle_at(&token, 7, 2, 2.0),
            Step::Redraw { types: ALL_ON }
        );
        screens.toggle_at(&token, 7, 0, 3.0);
        screens.toggle_at(&token, 7, 4, 4.0);
        let want = NotifyTypes([false, true, true, true, false]);
        assert_eq!(
            screens.save_at(&token, 7, 5.0),
            Step::Save {
                guild: 99,
                types: want
            }
        );
        // 書けるまでは閉じない（書けなかったら、もう一度押せる）。閉じたら終わり。
        assert!(matches!(screens.save_at(&token, 7, 6.0), Step::Save { .. }));
        screens.close(&token);
        assert_eq!(screens.save_at(&token, 7, 7.0), Step::Ignore);
        assert_eq!(screens.toggle_at(&token, 7, 0, 7.0), Step::Ignore);
    }

    /// 本人でない人は切り替えも保存もできないこと。知らない印・範囲の外の種類は無視すること。
    #[test]
    fn only_the_author_may_use_the_screen() {
        let screens = Screens::default();
        let token = screens.open_at(7, 99, ALL_ON, 0.0);
        assert_eq!(screens.toggle_at(&token, 8, 0, 1.0), Step::NotYours);
        assert_eq!(screens.save_at(&token, 8, 1.0), Step::NotYours);
        // 他人が触っても、本人の入・切は変わらない。
        assert_eq!(
            screens.save_at(&token, 7, 2.0),
            Step::Save {
                guild: 99,
                types: ALL_ON
            }
        );
        assert_eq!(screens.toggle_at("nope", 7, 0, 3.0), Step::Ignore);
        assert_eq!(screens.toggle_at(&token, 7, 5, 3.0), Step::Ignore);
        // 画面ごとに別々に覚える。
        let other = screens.open_at(7, 99, ALL_ON, 3.0);
        screens.toggle_at(&other, 7, 1, 4.0);
        assert_eq!(
            screens.save_at(&token, 7, 5.0),
            Step::Save {
                guild: 99,
                types: ALL_ON
            }
        );
    }

    /// 最後に触ってから 180 秒で終わること。触るたびに延びること。
    #[test]
    fn screens_expire_180_seconds_after_the_last_touch() {
        let screens = Screens::default();
        let token = screens.open_at(7, 99, ALL_ON, 0.0);
        assert!(matches!(
            screens.toggle_at(&token, 7, 0, 179.0),
            Step::Redraw { .. }
        ));
        // 179 秒に触ったので、そこから 180 秒。他人が触っても延びる（Python の View と同じ）。
        assert_eq!(screens.save_at(&token, 8, 358.0), Step::NotYours);
        assert!(matches!(
            screens.save_at(&token, 7, 537.0),
            Step::Save { .. }
        ));
        assert_eq!(
            screens.save_at(&token, 7, 717.0),
            Step::Ignore,
            "ちょうど 180 秒で終わる"
        );
        let token = screens.open_at(7, 99, ALL_ON, 1000.0);
        assert_eq!(screens.toggle_at(&token, 7, 0, 1180.5), Step::Ignore);
    }

    /// 印は毎回違い、32 文字の 16 進であること。
    #[test]
    fn tokens_are_random() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 震度の表示は Python の SCALE_LABELS と同じ。表に無い数は数のまま。
    #[test]
    fn scale_labels_match_python() {
        assert_eq!(scale_label(10), "1");
        assert_eq!(scale_label(45), "5弱");
        assert_eq!(scale_label(50), "5強");
        assert_eq!(scale_label(55), "6弱");
        assert_eq!(scale_label(60), "6強");
        assert_eq!(scale_label(70), "7");
        assert_eq!(scale_label(35), "35");
        assert_eq!(scale_label(-1), "-1");
    }

    /// 振り分けの先との組み合わせ。/quake でないものは引かない。
    #[test]
    fn routes_map_to_commands() {
        assert_eq!(command_of(Route::QuakeChannel), Some(Command::Channel));
        assert_eq!(command_of(Route::QuakeMinScale), Some(Command::MinScale));
        assert_eq!(command_of(Route::QuakeStatus), Some(Command::Status));
        assert_eq!(command_of(Route::QuakeType), Some(Command::Type));
        assert_eq!(command_of(Route::InfoServer), None);
        assert_eq!(command_of(Route::LogChannel), None);
    }
}
