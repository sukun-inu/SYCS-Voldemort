//! 貴金属の値段のコマンド（/metal gold・silver・platinum・all）。Python の `commands/metal_commands.py` と、
//! そこから呼ぶ `services/discord_utils.py` の `create_embed`、`commands/interaction_utils.py` の
//! `metals_site_view`・`send_interaction`、`config.py` の `METAL_COMMANDS`。
//!
//! 値段は外の API から取る（[`crate::metal`]）。Discord は最初の応答を 3 秒しか待たないので、取りに行く前に
//! 「考え中」（種類 5）を返し、あとから本文を送る（followup）。ほかのコマンドと応答のしかたが違うので、
//! `plan`・`Planned` は通さず、[`super::dispatch`] が先にここへ回す。
//!
//! 順番は Python のまま:
//!
//! - 金属 1 種（`_handle_metal_command`）: 考え中 → 使われた記録（ログチャンネル）→ グラム数の確認 → 値段 → 本文。
//!   **0 以下のグラム数も、考え中を返したあとで断る**（Python がそうしている。断りは followup になる）
//! - まとめて（`_handle_all_metals`）: グラム数の確認（0 以下は**考え中の前に**、本人にだけ見える形で断る）→
//!   考え中 → 3 種の値段 → 本文 → 使われた記録
//!
//! 流れ（[`handle`]）は、外への働きかけ（[`Outlet`]）を差し替えられる形にしてある。本番は Discord
//! （[`DiscordOutlet`]）、突き合わせのテストは記録するだけの偽物。

use std::future::Future;

use chrono::{DateTime, FixedOffset};
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CreateActionRow, CreateButton,
    CreateEmbed, CreateEmbedFooter, CreateInteractionResponse, CreateInteractionResponseFollowup,
    CreateInteractionResponseMessage, GuildId, Http, HttpError,
};
use tracing::warn;

use super::reply::{self, Reply};
use super::{Deps, Route};
use crate::earthquake::python_float_repr;
use crate::log_channel::{self, Author, Level, LogSink};
use crate::metal::{MetalError, MetalPrices};

/// 0 以下のグラム数を断る文。
pub const NOT_POSITIVE: &str = "グラム数は正の値で指定せよ。";
/// 値段を取れなかったときの文。
pub const PRICE_FAILED: &str =
    "エラーだ。余の力をもってしても処理できなかった。しばらく待ってから試せ。";
/// Embed の下に付ける文。
pub const FOOTER: &str = "Powered by MetalpriceAPI Free";
/// まとめて表示するときの本文。
pub const ALL_DESCRIPTION: &str = "金、銀、プラチナの力を見せてやろう。";
/// 貴金属トラッカーへのボタンの文。
pub const METALS_SITE_LABEL: &str = "📊 貴金属トラッカーを開く";
/// 貴金属トラッカーの場所の既定（`METALS_SITE_URL` が無いとき。Python の config と同じ）。
pub const DEFAULT_METALS_SITE_URL: &str = "https://metals.kawasaki-n3t.f5.si/";
/// discord.py の `Color.gold()`。
pub const GOLD_COLOUR: u32 = 0xF1_C4_0F;
/// discord.py の `Color.light_grey()`。
pub const LIGHT_GREY_COLOUR: u32 = 0x97_9C_9F;
/// discord.py の `Color.blue()`。
pub const BLUE_COLOUR: u32 = 0x34_98_DB;

/// 金属 1 種の決まりごと。Python の `MetalSpec`。
#[derive(Debug, PartialEq)]
pub struct Spec {
    /// コマンドの名前（`gold` など）。
    pub key: &'static str,
    /// Python の `key.title()`（まとめて表示するときの項目の名前に使う）。
    pub title: &'static str,
    /// API での金属の名前（`XAU` など）。
    pub code: &'static str,
    /// 純度の名前と、含まれる割合（並べた順に出る）。
    pub purity: &'static [(&'static str, f64)],
    /// 表示の名前。
    pub display_name: &'static str,
    /// Embed の本文。
    pub description: &'static str,
    /// Embed の色。
    pub colour: u32,
}

/// 金。Python の `METAL_COMMANDS["gold"]`（純度は `CARAT_PURITY`）。
pub const GOLD: Spec = Spec {
    key: "gold",
    title: "Gold",
    code: "XAU",
    purity: &[
        ("24K", 1.0),
        ("22K", 0.9167),
        ("18K", 0.75),
        ("14K", 0.5833),
    ],
    display_name: "金",
    description: "これが金の力だ。リアルタイムの価格を見よ。",
    colour: GOLD_COLOUR,
};

/// 銀。Python の `METAL_COMMANDS["silver"]`（純度は `SILVER_PURITY`）。
pub const SILVER: Spec = Spec {
    key: "silver",
    title: "Silver",
    code: "XAG",
    purity: &[
        ("Sv1000", 1.0),
        ("Sv950", 0.95),
        ("Sv925", 0.925),
        ("Sv900", 0.9),
        ("Sv850", 0.85),
        ("Sv800", 0.8),
    ],
    display_name: "銀",
    description: "銀の輝きが示す価格だ。",
    colour: LIGHT_GREY_COLOUR,
};

/// プラチナ。Python の `METAL_COMMANDS["platinum"]`（純度は `PLATINUM_PURITY`）。
pub const PLATINUM: Spec = Spec {
    key: "platinum",
    title: "Platinum",
    code: "XPT",
    purity: &[
        ("Pt1000", 1.0),
        ("Pt950", 0.95),
        ("Pt925", 0.925),
        ("Pt900", 0.9),
        ("Pt850", 0.85),
    ],
    display_name: "プラチナ",
    description: "プラチナの価値を知るがいい。",
    colour: BLUE_COLOUR,
};

/// まとめて表示するときの並び（Python の `METAL_COMMANDS.values()`）。
pub const SPECS: [&Spec; 3] = [&GOLD, &SILVER, &PLATINUM];

/// どの /metal か。
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// 金属 1 種（`/metal gold` など）。
    Single(&'static Spec),
    /// `/metal all`
    All,
}

/// 振り分けの先から、どの /metal かを引く。/metal でなければ `None`。
pub fn kind_of(route: Route) -> Option<Kind> {
    match route {
        Route::MetalGold => Some(Kind::Single(&GOLD)),
        Route::MetalSilver => Some(Kind::Single(&SILVER)),
        Route::MetalPlatinum => Some(Kind::Single(&PLATINUM)),
        Route::MetalAll => Some(Kind::All),
        _ => None,
    }
}

/// 円の書き方。Python の `format(整数, ",")`（3 桁ごとに区切る）。`yen` は小数を切り捨て済みの値。
///
/// 大きなグラム数だと 64 ビットの整数に収まらないので、小数のまま桁を書き出す（Python の整数は桁に上限が無い）。
pub fn yen_text(yen: f64) -> String {
    if yen == 0.0 {
        return "0".into();
    }
    let digits = format!("{:.0}", yen.abs());
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if yen < 0.0 {
        out.push('-');
    }
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// 純度ごとの値段を 1 行ずつ。Python の `_format_prices`。
pub fn format_prices(prices: &[(&'static str, f64)]) -> String {
    let lines: Vec<String> = prices
        .iter()
        .map(|(grade, yen)| format!("{grade}: {}円", yen_text(*yen)))
        .collect();
    lines.join("\n")
}

/// 項目を横並びにして、下に時刻を付けた Embed。Python の `services/discord_utils.py` の `create_embed`。
pub fn create_embed(
    title: String,
    description: &str,
    fields: &[(String, String)],
    colour: u32,
    footer_text: &str,
    now: DateTime<FixedOffset>,
) -> CreateEmbed {
    let mut embed = CreateEmbed::new()
        .title(title)
        .description(description)
        .colour(colour);
    for (name, value) in fields {
        embed = embed.field(name, value, true);
    }
    let suffix = if footer_text.is_empty() {
        String::new()
    } else {
        format!(" | {footer_text}")
    };
    embed.footer(CreateEmbedFooter::new(format!(
        "タイムスタンプ: {}{suffix}",
        now.format("%Y-%m-%d %H:%M:%S")
    )))
}

/// 金属 1 種の Embed。Python の `_handle_single_metal` が組み立てるもの。
pub fn single_embed(
    grams: f64,
    spec: &Spec,
    prices: &[(&'static str, f64)],
    now: DateTime<FixedOffset>,
) -> CreateEmbed {
    create_embed(
        format!(
            "{}グラムの{}価格",
            python_float_repr(grams),
            spec.display_name
        ),
        spec.description,
        &[("現在の価格".to_string(), format_prices(prices))],
        spec.colour,
        FOOTER,
        now,
    )
}

/// 3 種をまとめた Embed。Python の `_all_metals_embed`。`prices` は [`SPECS`] の並び。
pub fn all_embed(
    grams: f64,
    prices: &[Vec<(&'static str, f64)>; 3],
    now: DateTime<FixedOffset>,
) -> CreateEmbed {
    let fields: Vec<(String, String)> = SPECS
        .iter()
        .zip(prices)
        .map(|(spec, prices)| {
            (
                format!("{} ({})", spec.display_name, spec.title),
                format_prices(prices),
            )
        })
        .collect();
    create_embed(
        format!("{}グラムの金属価格", python_float_repr(grams)),
        ALL_DESCRIPTION,
        &fields,
        GOLD_COLOUR,
        FOOTER,
        now,
    )
}

/// 貴金属トラッカーへのリンクのボタン（1 行）。Python の `metals_site_view`。
pub fn metals_site_row(url: &str) -> Vec<CreateActionRow> {
    vec![CreateActionRow::Buttons(vec![
        CreateButton::new_link(url).label(METALS_SITE_LABEL),
    ])]
}

/// 貴金属トラッカーの場所を、Python の config と同じ形にそろえる（末尾の `/` を 1 つにする）。
pub fn normalize_site_url(raw: Option<&str>) -> String {
    let base = raw.unwrap_or(DEFAULT_METALS_SITE_URL);
    format!("{}/", base.trim_end_matches('/'))
}

/// /metal の、外への働きかけ（応答とログ）。失敗の文は Python の `str(例外)` にあたる。
pub trait Outlet: Sync {
    /// 「考え中」を返す（最初の応答、種類 5）。Python の `interaction.response.defer()`。
    fn defer(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// 最初の応答として送る（種類 4）。Python の `interaction.response.send_message`。
    fn respond(&self, reply: Reply) -> impl Future<Output = Result<(), String>> + Send;
    /// 応答のあとから送る。Python の `interaction.followup.send`。
    fn followup(&self, reply: Reply) -> impl Future<Output = Result<(), String>> + Send;
    /// ログチャンネルへ 1 件書く（作者は打った人）。Python の `log_action`。
    fn log(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// 打たれた /metal 1 つぶん。
#[derive(Clone, Debug)]
pub struct Request<'a> {
    /// どの /metal か。
    pub kind: Kind,
    /// グラム数。
    pub grams: f64,
    /// サーバーの中で打たれたか（外ならログを書かない）。
    pub in_guild: bool,
    /// 打たれたチャンネルの書き方（ログの「チャンネル」に出る。Python の `_channel_label`）。
    pub channel_label: String,
    /// 貴金属トラッカーの場所（リンクのボタン）。
    pub metals_site_url: &'a str,
}

/// 応答を済ませたかを覚えながら送る。discord.py の `interaction.response.is_done()` の代わり。
struct Answer<'a, O: Outlet> {
    outlet: &'a O,
    done: bool,
}

impl<O: Outlet> Answer<'_, O> {
    /// まだ何も返していなければ「考え中」にする。Python の `_defer`（失敗しても続ける）。
    async fn defer(&mut self) {
        if self.done {
            return;
        }
        match self.outlet.defer().await {
            Ok(()) => self.done = true,
            Err(e) => warn!("defer に失敗: {e}"),
        }
    }

    /// 最初の応答でも、考え中のあとでも、同じ呼び方で送る。Python の `send_interaction`。
    async fn send(&mut self, reply: Reply) -> Result<(), String> {
        if self.done {
            return self.outlet.followup(reply).await;
        }
        self.outlet.respond(reply).await?;
        self.done = true;
        Ok(())
    }

    /// 本人にだけ見える断りを送る。Python の `_respond_error`（送れなくても握りつぶす）。
    async fn respond_error(&mut self, text: &str) {
        let _ = self.send(Reply::ephemeral(text)).await;
    }
}

/// 値段の Embed とリンクのボタンの返事（全員に見える）。
fn price_reply(embed: CreateEmbed, metals_site_url: &str) -> Reply {
    Reply {
        content: None,
        embeds: vec![embed],
        components: metals_site_row(metals_site_url),
        ephemeral: false,
    }
}

/// 値段を取れなかったことをログチャンネルへ書く（サーバーの中だけ）。書けなければ失敗を返す。
async fn log_failure<O: Outlet>(
    outlet: &O,
    request: &Request<'_>,
    title: String,
    error: String,
) -> Result<(), String> {
    if !request.in_guild {
        return Ok(());
    }
    let fields = [("エラー内容".to_string(), error)];
    outlet.log(Level::Error, &title, &fields).await
}

/// コマンドが使われたことをログチャンネルへ書く（サーバーの中だけ）。Python の `_log_command_use`。
async fn log_use<O: Outlet>(
    outlet: &O,
    request: &Request<'_>,
    title: String,
    fields: &[(String, String)],
) -> Result<(), String> {
    if !request.in_guild {
        return Ok(());
    }
    outlet.log(Level::Info, &title, fields).await
}

/// 金属 1 種。Python の `_handle_metal_command` と `_handle_single_metal`。
async fn handle_single<O: Outlet>(
    answer: &mut Answer<'_, O>,
    prices: &MetalPrices,
    request: &Request<'_>,
    spec: &'static Spec,
    clock: fn() -> DateTime<FixedOffset>,
) -> Result<(), String> {
    let grams = request.grams;
    // ログを書くのも Discord への往復なので、3 秒の持ち時間を使い切らないよう、先に考え中を返す。
    answer.defer().await;
    log_use(
        answer.outlet,
        request,
        format!("/metal {} 実行", spec.key),
        &[
            ("チャンネル".to_string(), request.channel_label.clone()),
            ("グラム数".to_string(), python_float_repr(grams)),
        ],
    )
    .await?;
    if grams <= 0.0 {
        answer.respond_error(NOT_POSITIVE).await;
        return Ok(());
    }
    answer.defer().await;
    match prices.value(grams, spec.code, spec.purity).await {
        Ok(prices) => {
            let embed = single_embed(grams, spec, &prices, clock());
            answer
                .send(price_reply(embed, request.metals_site_url))
                .await
        }
        // 値段を取れなかった（想定の内）ときだけ、ログに残して断る。ほかはコマンドの失敗として外へ出す。
        Err(error) if error.is_expected() => {
            let title = format!("/metal {} エラー", spec.key);
            log_failure(answer.outlet, request, title, error.to_string()).await?;
            answer.respond_error(PRICE_FAILED).await;
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// 3 種の値段を取って Embed にする。Python の `_all_metals_embed`。
///
/// 3 つとも最後まで待ってから、並びの先頭の失敗を返す（1 つ失敗しても、ほかを途中でやめない）。
async fn all_metals_embed(
    prices: &MetalPrices,
    grams: f64,
    clock: fn() -> DateTime<FixedOffset>,
) -> Result<CreateEmbed, MetalError> {
    let value = |spec: &'static Spec| prices.value(grams, spec.code, spec.purity);
    let (gold, silver, platinum) = tokio::join!(value(&GOLD), value(&SILVER), value(&PLATINUM));
    let all = [gold?, silver?, platinum?];
    Ok(all_embed(grams, &all, clock()))
}

/// まとめて。Python の `_handle_all_metals`。
async fn handle_all<O: Outlet>(
    answer: &mut Answer<'_, O>,
    prices: &MetalPrices,
    request: &Request<'_>,
    clock: fn() -> DateTime<FixedOffset>,
) -> Result<(), String> {
    let grams = request.grams;
    // 考え中を返したあとでは、本人にだけ見える最初の応答が使えない。0 以下は先に断る。
    if grams <= 0.0 {
        answer.respond_error(NOT_POSITIVE).await;
        return Ok(());
    }
    answer.defer().await;
    let shown: Result<(), String> = async {
        let embed = all_metals_embed(prices, grams, clock)
            .await
            .map_err(|e| e.to_string())?;
        answer
            .send(price_reply(embed, request.metals_site_url))
            .await?;
        let fields = [("グラム数".to_string(), python_float_repr(grams))];
        log_use(
            answer.outlet,
            request,
            "/metal all 実行".to_string(),
            &fields,
        )
        .await
    }
    .await;
    // Python は `except Exception` で全部受ける（本文を送れなかった・使われた記録を書けなかった、も含む）。
    if let Err(error) = shown {
        log_failure(
            answer.outlet,
            request,
            "/metal all エラー".to_string(),
            error,
        )
        .await?;
        answer.respond_error(PRICE_FAILED).await;
    }
    Ok(())
}

/// /metal を 1 つ片付ける（応答まで済ませる）。
///
/// `Err` は「コマンドの中で失敗した」（Python の `CommandInvokeError`）。そのときは、ほかのコマンドと同じ
/// 断りの文（[`reply::FAILED`]）を送ってから返す（Python の `_on_tree_error`）。`clock` は Embed に書く時刻。
pub async fn handle<O: Outlet>(
    outlet: &O,
    prices: &MetalPrices,
    request: &Request<'_>,
    clock: fn() -> DateTime<FixedOffset>,
) -> Result<(), String> {
    let mut answer = Answer {
        outlet,
        done: false,
    };
    let outcome = match request.kind {
        Kind::Single(spec) => handle_single(&mut answer, prices, request, spec, clock).await,
        Kind::All => handle_all(&mut answer, prices, request, clock).await,
    };
    if outcome.is_err() {
        // 送れなくても、これ以上はできない（Python でも、ここでの失敗は discord.py がログに残すだけ）。
        let _ = answer.send(Reply::ephemeral(reply::FAILED)).await;
    }
    outcome
}

/// Discord の失敗の文。discord.py の `str(HTTPException)`（`403 Forbidden (error code: 50013): Missing Permissions`）
/// に寄せる。Discord が断ったもの以外は serenity の文のまま。
pub fn discord_error_text(error: &serenity::Error) -> String {
    let serenity::Error::Http(HttpError::UnsuccessfulRequest(response)) = error else {
        return error.to_string();
    };
    let status = response.status_code;
    let mut text = format!(
        "{} {} (error code: {})",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        response.error.code
    );
    if !response.error.message.is_empty() {
        text.push_str(": ");
        text.push_str(&response.error.message);
    }
    text
}

/// 本番の働きかけ: 打たれたコマンドへ応答し、そのサーバーのログチャンネルへ書く。
pub struct DiscordOutlet<'a> {
    /// Discord へ送る口。
    pub http: &'a Http,
    /// 打たれたコマンド。
    pub command: &'a CommandInteraction,
    /// ログの送り先を決めるもの。
    pub sink: LogSink<'a>,
    /// 打たれたサーバー（外なら `None`）。
    pub guild_id: Option<GuildId>,
    /// ログの作者（打った人）。
    pub author: Author,
}

impl Outlet for DiscordOutlet<'_> {
    async fn defer(&self) -> Result<(), String> {
        self.command
            .create_response(
                self.http,
                CreateInteractionResponse::Defer(CreateInteractionResponseMessage::new()),
            )
            .await
            .map_err(|e| discord_error_text(&e))
    }

    async fn respond(&self, reply: Reply) -> Result<(), String> {
        super::respond(self.http, self.command, reply)
            .await
            .map_err(|e| discord_error_text(&e))
    }

    async fn followup(&self, reply: Reply) -> Result<(), String> {
        self.command
            .create_followup(self.http, followup_message(reply))
            .await
            .map(|_| ())
            .map_err(|e| discord_error_text(&e))
    }

    async fn log(
        &self,
        level: Level,
        message: &str,
        fields: &[(String, String)],
    ) -> Result<(), String> {
        let Some(guild_id) = self.guild_id else {
            return Ok(());
        };
        log_channel::log_action(
            &self.sink,
            guild_id,
            level,
            message,
            Some(&self.author),
            fields,
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| discord_error_text(&e))
    }
}

/// 返事を、あとから送る形にする。本人にだけ見せるときだけ flags を付ける（discord.py と同じ）。
pub fn followup_message(reply: Reply) -> CreateInteractionResponseFollowup {
    let mut message = CreateInteractionResponseFollowup::new();
    if reply.ephemeral {
        message = message.ephemeral(true);
    }
    if let Some(content) = reply.content {
        message = message.content(content);
    }
    if !reply.embeds.is_empty() {
        message = message.embeds(reply.embeds);
    }
    if !reply.components.is_empty() {
        message = message.components(reply.components);
    }
    message
}

/// 引数 `g`（グラム数）。discord.py は数の引数を必ず小数にして渡す（`float(value)`）。
fn grams_option(options: &[CommandDataOption]) -> Option<f64> {
    match &options.iter().find(|o| o.name == "g")?.value {
        CommandDataOptionValue::Number(grams) => Some(*grams),
        CommandDataOptionValue::Integer(grams) => Some(*grams as f64),
        _ => None,
    }
}

/// 打たれた /metal を 1 つ片付ける（[`super::dispatch`] から呼ぶ）。`Err` はコマンドの中の失敗（ログに残す文）。
pub async fn run(
    deps: &Deps<'_>,
    command: &CommandInteraction,
    options: &[CommandDataOption],
    kind: Kind,
) -> Result<(), String> {
    let Some(grams) = grams_option(options) else {
        // 定義では必須。届かなければ、ほかのコマンドと同じ断りを返す。
        let failed = Reply::ephemeral(reply::FAILED);
        if let Err(e) = super::respond(deps.http, command, failed).await {
            warn!("[CMD] /metal 返事を送れませんでした: {e}");
        }
        return Err(super::CommandError::MissingOption("g").to_string());
    };
    let author = match command.member.as_deref() {
        Some(member) => Author::from_member(member),
        None => Author::from_user(&command.user),
    };
    let outlet = DiscordOutlet {
        http: deps.http,
        command,
        sink: LogSink {
            cache: deps.cache,
            http: deps.http,
            settings: deps.settings,
            colours: deps.colours,
        },
        guild_id: command.guild_id,
        author,
    };
    let request = Request {
        kind,
        grams,
        in_guild: command.guild_id.is_some(),
        // サーバーの中のチャンネル・スレッドは、どれも `<#ID>`（discord.py の `mention`）。
        channel_label: format!("<#{}>", command.channel_id),
        metals_site_url: deps.metals_site_url,
    };
    handle(&outlet, deps.metal, &request, log_channel::now_jst).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 3 桁ごとの区切り。64 ビットに収まらない大きさも、負の値も Python と同じに書くこと。
    #[test]
    fn yen_is_grouped_by_thousands() {
        for (yen, want) in [
            (0.0, "0"),
            (-0.0, "0"),
            (7.0, "7"),
            (999.0, "999"),
            (1000.0, "1,000"),
            (123_456.0, "123,456"),
            (1_234_567.0, "1,234,567"),
            (-1_234_567.0, "-1,234,567"),
            (-100.0, "-100"),
            // 2 の 70 乗（Python の `format(2**70, ",")`）。
            (
                1_180_591_620_717_411_303_424.0,
                "1,180,591,620,717,411,303,424",
            ),
        ] {
            assert_eq!(yen_text(yen), want, "{yen}");
        }
    }

    /// 純度は決めた順に 1 行ずつ。
    #[test]
    fn prices_are_listed_in_order() {
        assert_eq!(
            format_prices(&[("24K", 100_000.0), ("22K", 91_670.0)]),
            "24K: 100,000円\n22K: 91,670円"
        );
        assert_eq!(format_prices(&[]), "");
    }

    /// 振り分けの先と金属の組み合わせ。/metal でないものは引かない。
    #[test]
    fn routes_map_to_metals() {
        assert_eq!(kind_of(Route::MetalGold), Some(Kind::Single(&GOLD)));
        assert_eq!(kind_of(Route::MetalSilver), Some(Kind::Single(&SILVER)));
        assert_eq!(kind_of(Route::MetalPlatinum), Some(Kind::Single(&PLATINUM)));
        assert_eq!(kind_of(Route::MetalAll), Some(Kind::All));
        assert_eq!(kind_of(Route::QuakeStatus), None);
        assert_eq!(kind_of(Route::LogChannel), None);
        assert_eq!(
            SPECS.map(|s| (s.key, s.code)),
            [("gold", "XAU"), ("silver", "XAG"), ("platinum", "XPT")]
        );
    }

    /// 貴金属トラッカーの場所は、末尾の `/` をちょうど 1 つにする（Python の config と同じ）。
    #[test]
    fn the_site_url_ends_with_one_slash() {
        assert_eq!(
            normalize_site_url(None),
            "https://metals.kawasaki-n3t.f5.si/"
        );
        assert_eq!(
            normalize_site_url(Some("https://m.example")),
            "https://m.example/"
        );
        assert_eq!(
            normalize_site_url(Some("https://m.example/x//")),
            "https://m.example/x/"
        );
    }

    /// あとから送る形: 本人にだけ見せるときだけ flags（64）を付けること。
    #[test]
    fn followups_carry_flags_only_when_ephemeral() {
        let public = serde_json::to_value(followup_message(price_reply(
            CreateEmbed::new().title("t"),
            "https://m.example/",
        )))
        .unwrap();
        assert!(public.get("flags").is_none(), "{public}");
        assert_eq!(public["embeds"][0]["title"], "t");
        assert_eq!(
            public["components"][0]["components"][0]["url"],
            "https://m.example/"
        );
        let private = serde_json::to_value(followup_message(Reply::ephemeral("だめ"))).unwrap();
        assert_eq!(private["flags"], 64);
        assert_eq!(private["content"], "だめ");
    }

    /// 引数は、整数で届いても小数として読むこと（Discord は 5 を整数で送ることがある）。
    #[test]
    fn grams_are_read_as_floats() {
        let options = |value: serde_json::Value| -> Vec<CommandDataOption> {
            serde_json::from_value(serde_json::json!([{"name": "g", "type": 10, "value": value}]))
                .unwrap()
        };
        assert_eq!(grams_option(&options(serde_json::json!(5))), Some(5.0));
        assert_eq!(grams_option(&options(serde_json::json!(0.5))), Some(0.5));
        assert_eq!(grams_option(&[]), None);
    }
}
