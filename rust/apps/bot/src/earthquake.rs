//! 地震の通知（地震情報・津波情報・緊急地震速報）。Python の `services/earthquake_service.py` のうち、
//! 電文の読み方・送り先の決め方・Embed の組み立て・送る流れ。
//!
//! 電文は P2P地震情報の JSON API v2 の形（`code` が 551 地震情報・552 津波予報・554 緊急地震速報の検出・
//! 556 緊急地震速報〔予報〕）。受け取り（WebSocket）と気象庁の一覧の取得は [`crate::earthquake_feed`]。
//!
//! 送る流れは Python と同じ:
//!
//! 1. 最大震度を読む（[`max_scale`]。電文の形ごとに置き場が違う）
//! 2. **送り先を先に決める**（[`collect_targets`]）。誰も受け取らないなら、リンクも画像も作らない
//! 3. 気象庁の詳細ページのリンク（[`best_detail_url`]）・震度の札・震度の地図を用意する
//! 4. Embed を組み立てて、全部の送り先へ並べて送る（[`dispatch`]。1 つの失敗で他を止めない）
//!
//! 送り先の判定（[`evaluate_guild`]）は 1 か所にまとめてある（Python の `_evaluate_guild`）。順番は
//! チャンネル未設定 → 最小震度 → 通知の種類 → サーバーが読めているか → テキストチャンネルか。理由の文も
//! Python と同じ（開発者パネルのリプレイで「なぜ届かなかったか」をログに出す）。
//!
//! 画像（札と地図）は [`Images`] の向こうに置く。画像が作れなくても通知は出す（Python と同じ）。
//!
//! Python と違うところ: 形の崩れた電文（`earthquake` が null など）は、Python では例外になってその通知が
//! 出ない。こちらは読めるところだけで出す（速報を落とさない側）。

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use regex::Regex;
use serde_json::{Map, Value};
use serenity::all::{CreateActionRow, CreateButton, CreateEmbed, CreateEmbedFooter, Timestamp};
use sycs_core::settings::Settings;
use tracing::{error, warn};

use crate::groq::python_float;
use crate::log_channel::{self, python_int, python_str};

/// Embed の足元に出す Bot のアイコン。Python の `config.BOT_ICON_URL`。
pub const BOT_ICON_URL: &str = "https://cdn.discordapp.com/avatars/1350672236612288633/9d80744c9723eba8795a7eb3659552b3.webp?size=1024";
/// 震度の札のファイル名（Embed のサムネイル）。
pub const BADGE_FILE: &str = "intensity_badge.png";
/// 震度の地図のファイル名（Embed の画像）。
pub const MAP_FILE: &str = "earthquake_map.png";
/// 詳細のボタンの文字。
pub const DETAIL_LABEL: &str = "詳細（気象庁）";
/// 気象庁の統合地図のページ。`?contents=earthquake_map&id=<eid>` でその地震を開く。
pub const JMA_DETAIL_BASE: &str = "https://www.jma.go.jp/bosai/map.html";
/// 個別のページを決められないときのリンク。
pub const JMA_FALLBACK_URL: &str = "https://www.jma.go.jp/bosai/map.html#contents=earthquake_map";
/// 一覧のうち、先頭から何件を見るか。
const JMA_ITEMS_LIMIT: usize = 400;
/// これ未満の点数なら、個別のページにしない。
const JMA_MIN_SCORE: f64 = 10.0;

// discord.py の色。
const RED: u32 = 0xE7_4C_3C;
const GREEN: u32 = 0x2E_CC_71;
const ORANGE: u32 = 0xE6_7E_22;
const YELLOW: u32 = 0xFE_E7_5C;
const GREYPLE: u32 = 0x99_AA_B5;

/// 震度の表示（`5弱` など）。知らない値は `None`。Python の `config.SCALE_LABELS`。
///
/// 値は P2P地震情報の仕様のもの（10=震度1 … 45=5弱・50=5強・55=6弱・60=6強・70=7）。
pub fn scale_label(scale: i64) -> Option<&'static str> {
    Some(match scale {
        10 => "1",
        20 => "2",
        30 => "3",
        40 => "4",
        45 => "5弱",
        50 => "5強",
        55 => "6弱",
        60 => "6強",
        70 => "7",
        _ => return None,
    })
}

/// 震度ごとの Embed の色。Python の `_SCALE_COLORS`。
pub fn scale_colour(scale: i64) -> Option<u32> {
    let (r, g, b): (u32, u32, u32) = match scale {
        10 => (0, 64, 255),
        20 => (0, 148, 255),
        30 => (0, 200, 200),
        40 => (250, 230, 20),
        45 => (255, 175, 0),
        50 => (255, 120, 0),
        55 => (255, 60, 0),
        60 => (220, 0, 0),
        70 => (110, 0, 130),
        _ => return None,
    };
    Some((r << 16) | (g << 8) | b)
}

/// 題の絵文字（震度ごと）。知らない震度は白丸。Python の `_SCALE_TITLE_EMOJI`。
pub fn scale_emoji(scale: i64) -> &'static str {
    match scale {
        10 | 20 | 30 => "🔵",
        40 => "🟡",
        45 | 50 => "🟠",
        55 | 60 | 70 => "🔴",
        _ => "⚪",
    }
}

/// 緊急地震速報（予報）の `forecastMaxInt` の文字 → 震度の値。Python の `_FORECAST_INT_TO_SCALE`。
fn forecast_scale(text: &str) -> i64 {
    match text {
        "1" => 10,
        "2" => 20,
        "3" => 30,
        "4" => 40,
        "5-" => 45,
        "5+" => 50,
        "6-" => 55,
        "6+" => 60,
        "7" => 70,
        _ => -1,
    }
}

/// Python の真偽（`bool(value)`）。
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// 整数として読む（小数は 0 へ向けて切り捨て）。数でなければ `None`。
fn int_of(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
}

/// 電文全体の最大震度。分からなければ -1。Python の `_max_scale`。
///
/// 置き場は電文の形ごとに違う: 観測点（`points`）→ 緊急地震速報（予報）の地域（`areas` の
/// `scaleTo`、無ければ `scaleFrom`）→ `earthquake.maxScale` → `intensity.forecastMaxInt.to`。
pub fn max_scale(event: &Value) -> i64 {
    if let Some(points) = event["points"].as_array().filter(|p| !p.is_empty()) {
        return points
            .iter()
            .map(|p| p.get("scale").and_then(int_of).unwrap_or(-1))
            .max()
            .unwrap_or(-1);
    }
    if let Some(areas) = event["areas"].as_array().filter(|a| !a.is_empty()) {
        return areas
            .iter()
            .map(|a| {
                a.get("scaleTo")
                    .or_else(|| a.get("scaleFrom"))
                    .and_then(int_of)
                    .unwrap_or(-1)
            })
            .max()
            .unwrap_or(-1);
    }
    if let Some(scale) = event["earthquake"]["maxScale"]
        .as_f64()
        .filter(|s| *s >= 0.0)
    {
        return scale as i64;
    }
    forecast_scale(
        event["intensity"]["forecastMaxInt"]["to"]
            .as_str()
            .unwrap_or(""),
    )
}

/// 緯度・経度を数にする。`N35.8`・`E137.7`・数のどれでも受ける。0 と ±180 を超える値（P2P地震情報の
/// 「分からない」の印）は `None`。Python の `_parse_coord`。
pub fn parse_coord(raw: &Value) -> Option<f64> {
    let valid = |v: f64| (v != 0.0 && v.abs() <= 180.0).then_some(v);
    match raw {
        Value::Null => None,
        Value::Number(n) => n.as_f64().and_then(valid),
        Value::Bool(b) => valid(f64::from(u8::from(*b))),
        other => {
            let text = python_str(other);
            let s = text.trim();
            // 向きの字を 1 つ落とす（小文字も落とすが、符号を変えるのは大文字の S・W だけ。Python と同じ）。
            let sign = if s.starts_with(['S', 'W']) { -1.0 } else { 1.0 };
            let rest = s
                .strip_prefix(['N', 'S', 'E', 'W', 'n', 's', 'e', 'w'])
                .unwrap_or(s);
            python_float(rest).map(|v| sign * v).and_then(valid)
        }
    }
}

/// 震源の深さの表示。0 は「ごく浅い」、負・欠けは「不明」。文字でも数でも受ける。Python の `_parse_depth`。
pub fn parse_depth(raw: &Value) -> String {
    let km = |v: i64| match v {
        v if v < 0 => "不明".to_string(),
        0 => "ごく浅い".to_string(),
        v => format!("{v} km"),
    };
    match raw {
        Value::String(s) => {
            if s.contains('浅') {
                return "ごく浅い".into();
            }
            match python_float(s).filter(|v| v.is_finite()) {
                Some(v) => km(v as i64),
                // 数として読めない文字はそのまま出す（空なら「不明」）。
                None if s.is_empty() => "不明".into(),
                None => s.clone(),
            }
        }
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .map_or_else(|| "不明".into(), km),
        Value::Bool(b) => km(i64::from(*b)),
        _ => "不明".into(),
    }
}

/// Python の `float(raw)`（設定や電文に入りうるもの）。
fn python_float_of(raw: &Value) -> Option<f64> {
    match raw {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::String(s) => python_float(s),
        _ => None,
    }
}

/// Python の `repr(float)`（`5.0`・`4.6`・`1e+16`）。
pub fn python_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf" } else { "-inf" }.into();
    }
    // いちばん短く書ける桁（往復しても同じ値になる桁）を取り、Python と同じ決まりで並べる。
    let short = format!("{v:e}");
    let (mantissa, exponent) = short.split_once('e').unwrap_or((&short, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let body = if (-4..16).contains(&exponent) {
        if exponent >= 0 {
            let whole = exponent as usize + 1;
            if digits.len() <= whole {
                format!("{digits}{}.0", "0".repeat(whole - digits.len()))
            } else {
                format!("{}.{}", &digits[..whole], &digits[whole..])
            }
        } else {
            format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize))
        }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        let head = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits
        };
        format!("{head}e{sign}{:02}", exponent.abs())
    };
    if negative { format!("-{body}") } else { body }
}

/// マグニチュードの表示（`M5.2`）と数。負・読めない値は（「不明」, -1）。Python の `_parse_magnitude`。
pub fn parse_magnitude(raw: &Value) -> (String, f64) {
    match python_float_of(raw) {
        Some(v) if v >= 0.0 => (format!("M{}", python_float_repr(v)), v),
        _ => ("不明".into(), -1.0),
    }
}

/// 日本時間。
fn jst() -> FixedOffset {
    log_channel::jst()
}

/// Python の `datetime.strptime(text, "%Y/%m/%d %H:%M:%S")` が受ける形（各欄は 1〜2 桁でもよい）。
/// 全角の数字は読まない（Python は読む。配信元は ASCII しか送らない）。
static P2P_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([0-9]{4})/(1[0-2]|0[1-9]|[1-9])/(3[0-1]|[1-2][0-9]|0[1-9]|[1-9]| [1-9])\s+(2[0-3]|[0-1][0-9]|[0-9]):([0-5][0-9]|[0-9]):(6[0-1]|[0-5][0-9]|[0-9])$",
    )
    .expect("正しい正規表現")
});

/// `2026/11/25 09:05:00` の形を日本時間の時刻として読む。読めなければ `None`。
fn parse_p2p_time(text: &str) -> Option<DateTime<FixedOffset>> {
    let caps = P2P_TIME.captures(text)?;
    let number = |i: usize| caps[i].trim().parse::<u32>().ok();
    let year: i32 = caps[1].parse().ok()?;
    // Python の datetime は 1 年から。秒の 60・61 は形としては通るが、時刻にできない。
    if year < 1 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year, number(2)?, number(3)?)?;
    let time = date.and_hms_opt(number(4)?, number(5)?, number(6)?)?;
    jst().from_local_datetime(&time).single()
}

/// 時刻の文字を「25日 9時05分ごろ」の形にする。読めない形は、元の文字に「ごろ」を付ける（通知は止めない）。
/// Python の `_format_time`。
pub fn format_time(text: &str) -> (String, Option<DateTime<FixedOffset>>) {
    use chrono::{Datelike, Timelike};
    if text.is_empty() {
        return ("不明".into(), None);
    }
    match parse_p2p_time(text) {
        Some(dt) => (
            format!("{}日 {}時{:02}分ごろ", dt.day(), dt.hour(), dt.minute()),
            Some(dt),
        ),
        None => (format!("{text}ごろ"), None),
    }
}

fn text_of<'a>(value: &'a Value, default: &'a str) -> &'a str {
    value.as_str().unwrap_or(default)
}

fn timestamp(dt: Option<DateTime<FixedOffset>>) -> Option<Timestamp> {
    dt.and_then(|d| Timestamp::from_unix_timestamp(d.timestamp()).ok())
}

fn footer(text: &str) -> CreateEmbedFooter {
    CreateEmbedFooter::new(text).icon_url(BOT_ICON_URL)
}

/// 津波の一文。Python の `_TSUNAMI_TEXT`。
fn tsunami_text(domestic: Option<&Value>) -> &'static str {
    // 鍵が無ければ「心配なし」、知らない値は「不明」（Python の `.get(…, "None")` と同じ）。
    let key = match domestic {
        None => "None",
        Some(v) => v.as_str().unwrap_or(""),
    };
    match key {
        "None" | "NonEffective" => "この地震による津波の心配はありません。",
        "Unknown" | "Checking" => "津波の有無を調査中です。",
        "Watch" => "⚠️ 津波注意報が発令されています。",
        "Warning" => "🚨 津波警報が発令されています！",
        _ => "津波情報は不明です。",
    }
}

/// 発表の種類の表示。Python の `_ISSUE_LABELS`。
fn issue_label(kind: &str) -> &'static str {
    match kind {
        "ScalePrompt" => "気象庁 震度速報",
        "Destination" => "気象庁 震源に関する情報",
        "ScaleAndDestination" => "気象庁 震度・震源に関する情報",
        "DetailScale" => "気象庁 各地の震度に関する情報",
        "Foreign" => "気象庁 遠地地震に関する情報",
        _ => "気象庁",
    }
}

/// 震源の名前（空・欠けは「不明」）。
fn hypocenter_name(hypo: &Value) -> &str {
    hypo["name"]
        .as_str()
        .filter(|n| !n.is_empty())
        .unwrap_or("不明")
}

/// 地震情報（551）の Embed。Python の `_build_embed`。
///
/// 分からない項目は「不明」と書かず、その行ごと出さない。
pub fn build_embed(event: &Value, max_scale: i64, has_badge: bool) -> CreateEmbed {
    let eq = &event["earthquake"];
    let hypo = &eq["hypocenter"];
    let issue = &event["issue"];
    let (time_label, _) = format_time(text_of(&eq["time"], ""));
    let (_, issued_at) = format_time(text_of(&issue["time"], ""));
    let name = hypocenter_name(hypo);
    let (magnitude, _) = parse_magnitude(&hypo["magnitude"]);
    let depth = parse_depth(&hypo["depth"]);

    let mut lines: Vec<String> = Vec::new();
    if time_label != "不明" {
        lines.push(format!("{time_label}、"));
    }
    lines.push(match scale_label(max_scale) {
        Some(label) => format!("最大震度 {label} の地震がありました。"),
        None => "地震がありました。".into(),
    });
    lines.push(tsunami_text(eq.get("domesticTsunami")).into());

    let mut embed = CreateEmbed::new()
        .title(format!("{} 地震情報", scale_emoji(max_scale)))
        .description(lines.join("\n"))
        .colour(scale_colour(max_scale).unwrap_or(RED));
    if let Some(at) = timestamp(issued_at) {
        embed = embed.timestamp(at);
    }
    if name != "不明" {
        embed = embed.field("震源", name, true);
    }
    if magnitude != "不明" {
        embed = embed.field("規模", magnitude, true);
    }
    if depth != "不明" {
        embed = embed.field("深さ", depth, true);
    }
    embed = embed.footer(footer(issue_label(text_of(&issue["type"], ""))));
    if has_badge {
        embed = embed.thumbnail(format!("attachment://{BADGE_FILE}"));
    }
    embed
}

/// 緊急地震速報（554 検出・556 予報）の Embed。Python の `_build_eew_embed`。
///
/// 554 は震源を持たない（チャイムが鳴ったことの検出だけ）。無い情報は埋めずに、検出だけを伝える。
/// 取り消し（`cancelled`）は、外れだったことを伝える。
pub fn build_eew_embed(event: &Value) -> CreateEmbed {
    let is_forecast = event.get("code").is_some_and(|c| c.as_f64() == Some(556.0));
    let cancelled = truthy(&event["cancelled"]);
    let eq = &event["earthquake"];
    let hypo = &eq["hypocenter"];
    let has_quake_data = truthy(&hypo["name"]);
    // 続報の番号は issue.serial。値が 0 や "0" でも、あればそれを使う（無いときだけ 1）。
    let serial = match &event["issue"]["serial"] {
        Value::Null => "1".to_string(),
        v => python_str(v),
    };

    if cancelled {
        let description = if has_quake_data {
            format!(
                "**{}** 付近を震源とする緊急地震速報は取り消されました。",
                python_str(&hypo["name"])
            )
        } else {
            "直前の緊急地震速報は取り消されました。".into()
        };
        return CreateEmbed::new()
            .title("✅ 緊急地震速報は取り消されました")
            .description(description)
            .colour(GREEN)
            .footer(footer(if is_forecast {
                "気象庁 緊急地震速報（予報）"
            } else {
                "気象庁 緊急地震速報"
            }));
    }

    if !has_quake_data {
        return CreateEmbed::new()
            .title("🚨 緊急地震速報を検出しました")
            .description("緊急地震速報の受信を検出しました。震源・規模の詳細は、後続の情報でご確認ください。")
            .colour(ORANGE)
            .footer(footer("気象庁 緊急地震速報"));
    }

    let title_base = if is_forecast {
        "⚠️ 緊急地震速報（予報）"
    } else {
        "🚨 緊急地震速報（警報）"
    };
    let name = python_str(&hypo["name"]);
    // 556 は originTime、554 は time。
    let time_raw = match &eq["originTime"] {
        v if truthy(v) => text_of(v, ""),
        _ => text_of(&eq["time"], ""),
    };
    let (time_label, at) = format_time(time_raw);
    let (magnitude, _) = parse_magnitude(&hypo["magnitude"]);
    let scale = max_scale(event);

    let mut lines: Vec<String> = Vec::new();
    if time_label != "不明" {
        lines.push(format!("{time_label}、"));
    }
    lines.push(format!("**{name}** 付近を震源とする地震が発生しました。"));
    if let Some(label) = scale_label(scale) {
        lines.push(format!("予想最大震度 **{label}**"));
    }

    let mut embed = CreateEmbed::new()
        .title(format!("{title_base}（第{serial}報）"))
        .description(lines.join("\n"))
        .colour(scale_colour(scale).unwrap_or(ORANGE));
    if let Some(at) = timestamp(at) {
        embed = embed.timestamp(at);
    }
    if name != "不明" {
        embed = embed.field("予想震源", name, true);
    }
    if magnitude != "不明" {
        embed = embed.field("予想規模", magnitude, true);
    }
    embed.footer(footer(if is_forecast {
        "気象庁 緊急地震速報（予報）"
    } else {
        "気象庁 緊急地震速報（警報）"
    }))
}

/// 津波の階級の表示。知らない階級は `None`。Python の `_TSUNAMI_GRADE_LABELS`。
fn grade_label(grade: &str) -> Option<&'static str> {
    Some(match grade {
        "MajorWarning" => "🔴 大津波警報",
        "Warning" => "🟠 津波警報",
        "Watch" => "🟡 津波注意報",
        "Unknown" => "❓ 不明",
        _ => return None,
    })
}

/// 津波の階級の重さ。知らない階級は 0。Python の `_TSUNAMI_GRADE_ORDER`。
fn grade_order(grade: &str) -> u8 {
    match grade {
        "MajorWarning" => 3,
        "Warning" => 2,
        "Watch" => 1,
        _ => 0,
    }
}

/// 津波予報（552）の Embed。Python の `_build_tsunami_embed`。
pub fn build_tsunami_embed(event: &Value) -> CreateEmbed {
    let (_, issued_at) = format_time(text_of(&event["issue"]["time"], ""));
    let with_time = |embed: CreateEmbed| match timestamp(issued_at) {
        Some(at) => embed.timestamp(at),
        None => embed,
    };
    if truthy(&event["cancelled"]) {
        return with_time(
            CreateEmbed::new()
                .title("津波予報（解除）")
                .description("すべての津波予報が解除されました。")
                .colour(GREEN),
        )
        .footer(footer("気象庁 津波情報"));
    }
    let empty = Vec::new();
    let areas = event["areas"].as_array().unwrap_or(&empty);
    let grade_of = |area: &Value| -> String {
        match area.get("grade") {
            None => "Unknown".into(),
            Some(g) => text_of(g, "").to_string(),
        }
    };
    // いちばん重い階級（同じ重さなら先に出てきたもの）。
    let mut max_grade = "Unknown".to_string();
    let mut heaviest: Option<u8> = None;
    for area in areas {
        let grade = grade_of(area);
        let order = grade_order(&grade);
        if heaviest.is_none_or(|h| order > h) {
            heaviest = Some(order);
            max_grade = grade;
        }
    }
    let colour = match max_grade.as_str() {
        "MajorWarning" => RED,
        "Warning" => ORANGE,
        "Watch" => YELLOW,
        _ => GREYPLE,
    };
    let mut embed = with_time(
        CreateEmbed::new()
            .title("津波情報")
            .description(format!(
                "{}が発令されています。",
                grade_label(&max_grade).unwrap_or("津波情報")
            ))
            .colour(colour),
    );
    let mut by_grade: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for area in areas {
        let name = match area.get("name") {
            None => "不明".to_string(),
            Some(n) => python_str(n),
        };
        by_grade.entry(grade_of(area)).or_default().push(name);
    }
    for grade in ["MajorWarning", "Warning", "Watch", "Unknown"] {
        let Some(names) = by_grade.get(grade) else {
            continue;
        };
        let mut regions = names
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("、");
        if names.len() > 10 {
            regions.push_str(&format!(" 他{}地域", names.len() - 10));
        }
        embed = embed.field(grade_label(grade).unwrap_or(grade), regions, false);
    }
    embed.footer(footer("気象庁 津波情報"))
}

/// 気象庁の詳細ページへ飛ぶボタン。Python の `_EqView`。
pub fn detail_button(url: &str) -> CreateActionRow {
    CreateActionRow::Buttons(vec![CreateButton::new_link(url).label(DETAIL_LABEL)])
}

// ── 気象庁の詳細ページを選ぶ ─────────────────────────────

/// 震度の書き方の揺れ（全角の数字・「最大」「震度」・空白）をそろえる。Python の `_normalize_scale_text`。
pub fn normalize_scale_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '０'..='７' => char::from(b'0' + (u32::from(c) - u32::from('０')) as u8),
            other => other,
        })
        .collect::<String>()
        .replace("最大", "")
        .replace("震度", "")
        .replace([' ', '　'], "")
}

static SCALE_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([1-7])(弱|強)?").expect("正しい正規表現"));

/// 「5強」のような震度の文字を数にする。Python の `_scale_from_text`。
///
/// **5弱→50・5強→55・6弱→60・6強→65 と、P2P地震情報の値（45・50・55・60）から 1 段ずれている。**
/// Python のままを写した（使うのは気象庁の一覧との突き合わせの点数だけ。見直しの候補）。
pub fn scale_from_text(text: &str) -> i64 {
    let norm = normalize_scale_text(text);
    let Some(caps) = SCALE_TEXT.captures(&norm) else {
        return -1;
    };
    let base: i64 = caps[1].parse().unwrap_or(0);
    let modifier = caps.get(2).map_or("", |m| m.as_str());
    match (base, modifier) {
        (4, "強") => 45,
        (5, "弱") => 50,
        (5, "強") => 55,
        (6, "弱") => 60,
        (6, "強") => 65,
        (7, _) => 70,
        _ => base * 10,
    }
}

/// マグニチュードを数にする（`M5.2` の M は落とす）。負・読めない値は `None`。Python の
/// `_parse_magnitude_value`。
pub fn parse_magnitude_value(raw: &Value) -> Option<f64> {
    let v = match raw {
        Value::Null => return None,
        Value::Number(n) => n.as_f64()?,
        other => python_float(&python_str(other).trim().to_uppercase().replace('M', ""))?,
    };
    (v >= 0.0).then_some(v)
}

/// ISO 8601 の日時のうち、よくある形（`2026-08-24T12:54:00+09:00`・`…Z`・時差なし・日付だけ・区切りなし）。
/// Python の `datetime.fromisoformat` はもっと多くの形を読む。
static ISO_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([0-9]{4})-?([0-9]{2})-?([0-9]{2})(?:.([0-9]{2})(?::?([0-9]{2})(?::?([0-9]{2})(?:[.,]([0-9]+))?)?)?)?(?:([+-])([0-9]{2}):?([0-9]{2})?(?::?([0-9]{2}))?)?$",
    )
    .expect("正しい正規表現")
});

/// いろいろな形の時刻を、1970 年からのマイクロ秒にする。読めなければ `None`。Python の `_parse_any_time`
/// （`年/月/日 時:分:秒` と ISO 8601。時差が無ければ日本時間とみなす）。
pub fn parse_any_time(raw: &Value) -> Option<i64> {
    if !truthy(raw) {
        return None;
    }
    let text = python_str(raw);
    let s = text.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(dt) = parse_p2p_time(s) {
        return Some(dt.timestamp_micros());
    }
    let iso = s.replace('Z', "+00:00");
    let caps = ISO_TIME.captures(&iso)?;
    let number = |i: usize| -> Option<u32> {
        match caps.get(i) {
            Some(m) => m.as_str().parse().ok(),
            None => Some(0),
        }
    };
    let year: i32 = caps[1].parse().ok()?;
    if year < 1 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year, number(2)?, number(3)?)?;
    let naive = date.and_hms_opt(number(4)?, number(5)?, number(6)?)?;
    // 小数の秒は 6 桁まで（それより先は切り捨て）。
    let micros: i64 = caps.get(7).map_or(0, |m| {
        let digits: String = m.as_str().chars().chain("000000".chars()).take(6).collect();
        digits.parse().unwrap_or(0)
    });
    let offset_seconds: i64 = match caps.get(8) {
        None => i64::from(jst().local_minus_utc()),
        Some(sign) => {
            let seconds =
                i64::from(number(9)?) * 3600 + i64::from(number(10)?) * 60 + i64::from(number(11)?);
            if sign.as_str() == "-" {
                -seconds
            } else {
                seconds
            }
        }
    };
    Some((naive.and_utc().timestamp() - offset_seconds) * 1_000_000 + micros)
}

/// 一覧の 1 件から、地域の名前らしいものを拾う（`anm`・`name`・`epicenter` の順）。Python の
/// `_item_area_name`。
pub fn item_area_name(item: &Value) -> &str {
    ["anm", "name", "epicenter"]
        .iter()
        .filter_map(|key| item[*key].as_str())
        .map(str::trim)
        .find(|v| !v.is_empty())
        .unwrap_or("")
}

/// 一覧の 1 件から、気象庁のページへのリンクを作る（`eid` から）。Python の `_item_detail_url`。
pub fn item_detail_url(item: &Value) -> Option<String> {
    let eid = item["eid"].as_str()?.trim();
    (!eid.is_empty()).then(|| format!("{JMA_DETAIL_BASE}?contents=earthquake_map&id={eid}"))
}

/// 地震の時刻（`originTime`、無ければ `time`）。
fn quake_time(eq: &Value) -> &Value {
    if truthy(&eq["originTime"]) {
        &eq["originTime"]
    } else {
        &eq["time"]
    }
}

/// リンクを覚えておく鍵（種類・時刻・最大震度・震源の名前）。Python の `_cache_key_for_event`。
pub fn cache_key_for_event(event: &Value, max_scale: i64) -> String {
    let eq = &event["earthquake"];
    let text = |v: Option<&Value>| v.map_or_else(String::new, python_str);
    let time = match quake_time(eq) {
        Value::Null if eq.get("time").is_none() => String::new(),
        v => python_str(v),
    };
    [
        text(event.get("code")),
        time,
        max_scale.to_string(),
        text(eq["hypocenter"].get("name")),
    ]
    .join("|")
}

/// 一覧の 1 件が、通知しようとしている地震とどれだけ合いそうかの点数。Python の `_score_jma_item`。
///
/// 時刻の近さ（15 分を超えたら別の地震として大きな負の値）・地域の名前・マグニチュード・震度の合計。
pub fn score_jma_item(
    item: &Value,
    target_micros: Option<i64>,
    target_name: &str,
    target_magnitude: Option<f64>,
    target_scale: i64,
) -> f64 {
    let mut score = 0.0;
    let item_time = ["at", "time", "datetime"]
        .iter()
        .map(|key| &item[*key])
        .find(|v| truthy(v))
        .and_then(parse_any_time);
    match (target_micros, item_time) {
        (Some(target), Some(at)) => {
            let delta = (at - target).abs() as f64 / 1e6;
            if delta > 900.0 {
                return -1e9;
            }
            score += (110.0 - delta / 6.0).max(0.0);
        }
        (Some(_), None) => score -= 30.0,
        _ => {}
    }
    let item_name = item_area_name(item);
    if !target_name.is_empty() && !item_name.is_empty() {
        if item_name == target_name {
            score += 30.0;
        } else if item_name.contains(target_name) || target_name.contains(item_name) {
            score += 15.0;
        }
    }
    if let (Some(target), Some(magnitude)) = (target_magnitude, parse_magnitude_value(&item["mag"]))
    {
        let diff = (magnitude - target).abs();
        if diff <= 0.1 {
            score += 18.0;
        } else if diff <= 0.3 {
            score += 10.0;
        } else if diff <= 0.6 {
            score += 4.0;
        }
    }
    if target_scale >= 0 {
        let ttl = match &item["ttl"] {
            v if truthy(v) => python_str(v),
            _ => String::new(),
        };
        let item_scale = scale_from_text(&ttl);
        if item_scale >= 0 {
            if item_scale == target_scale {
                score += 18.0;
            } else if (item_scale - target_scale).abs() <= 10 {
                score += 8.0;
            }
        }
    }
    score
}

/// 突き合わせる相手（通知しようとしている地震の時刻・震源の名前・規模・最大震度）。
pub struct ScoreTarget {
    micros: Option<i64>,
    name: String,
    magnitude: Option<f64>,
    scale: i64,
}

impl ScoreTarget {
    /// 電文から取り出す。
    pub fn of(event: &Value, max_scale: i64) -> Self {
        let eq = &event["earthquake"];
        let hypo = &eq["hypocenter"];
        Self {
            micros: parse_any_time(quake_time(eq)),
            name: match &hypo["name"] {
                v if truthy(v) => python_str(v),
                _ => String::new(),
            },
            magnitude: parse_magnitude_value(&hypo["magnitude"]),
            scale: max_scale,
        }
    }

    /// 一覧の 1 件の点数。
    pub fn score(&self, item: &Value) -> f64 {
        score_jma_item(item, self.micros, &self.name, self.magnitude, self.scale)
    }
}

/// 気象庁の一覧から、この地震にいちばん近いページを選ぶ。十分に合うもの（10 点以上）が無ければ
/// 統合地図のページ。Python の `_resolve_jma_detail_url` の選び方。
pub fn best_detail_url(items: &[Value], event: &Value, max_scale: i64) -> String {
    let target = ScoreTarget::of(event, max_scale);
    let mut best: Option<(f64, String)> = None;
    for item in items.iter().take(JMA_ITEMS_LIMIT) {
        if !item.is_object() {
            continue;
        }
        let Some(url) = item_detail_url(item) else {
            continue;
        };
        let score = target.score(item);
        if best.as_ref().is_none_or(|(top, _)| score > *top) {
            best = Some((score, url));
        }
    }
    match best {
        Some((score, url)) if score >= JMA_MIN_SCORE => url,
        _ => JMA_FALLBACK_URL.into(),
    }
}

// ── 送り先 ───────────────────────────────────────────────

/// 通知の種類（ギルドごとに入・切できる）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyType {
    /// 地震情報（551）。
    QuakeInfo,
    /// 津波情報（552）。
    Tsunami,
    /// 緊急地震速報（警報。554 の検出）。
    EewWarning,
    /// 緊急地震速報（予報。556）。
    EewForecast,
}

impl NotifyType {
    /// 設定の鍵。
    pub fn key(self) -> &'static str {
        match self {
            Self::QuakeInfo => "quake_info",
            Self::Tsunami => "tsunami",
            Self::EewWarning => "eew_warning",
            Self::EewForecast => "eew_forecast",
        }
    }

    /// 表示の名前。Python の `_NOTIFY_TYPE_LABELS`。
    pub fn label(self) -> &'static str {
        match self {
            Self::QuakeInfo => "地震情報",
            Self::Tsunami => "津波情報",
            Self::EewWarning => "緊急地震速報（警報）",
            Self::EewForecast => "緊急地震速報（予報）",
        }
    }
}

/// サーバーとチャンネルの様子を引く口（本物は serenity のキャッシュ）。
pub trait Directory: Sync {
    /// そのサーバーを読めているか（Python の `bot.get_guild`）。
    fn has_guild(&self, guild_id: u64) -> bool;
    /// そのサーバーのテキストチャンネル（お知らせを含む）か。
    fn is_text_channel(&self, guild_id: u64, channel_id: i64) -> bool;
}

/// 1 つのサーバーが送り先かどうか。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evaluation {
    /// 送り先（チャンネル）。
    Target(u64),
    /// 対象外。最初に引っかかった理由だけ。
    Skip(String),
    /// 設定が壊れていて判定できない（Python では例外。そのサーバーだけ飛ばす）。
    Broken(String),
}

/// 設定の中の辞書を読む。Python の `dict(value)`（無ければ空。辞書にできない値は失敗）。
fn dict_of<'a>(
    value: Option<&'a Value>,
    what: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match value {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        // 空の配列・空の文字は、Python の dict() では空の辞書になる。
        Some(Value::Array(a)) if a.is_empty() => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(_) => Err(format!("{what} が辞書ではありません")),
    }
}

/// 1 つのサーバーが送り先かどうかを判定する。Python の `_evaluate_guild`。
///
/// `guild_settings` はそのサーバーの設定の全体（`earthquake` の鍵を持つ）。
pub fn evaluate_guild(
    guild_settings: Option<&Value>,
    directory: &dyn Directory,
    guild_id: u64,
    notify_type: NotifyType,
    max_scale: i64,
    apply_min_scale: bool,
) -> Evaluation {
    let block = match dict_of(guild_settings, "サーバーの設定")
        .and_then(|g| dict_of(g.and_then(|g| g.get("earthquake")), "earthquake"))
    {
        Ok(block) => block,
        Err(e) => return Evaluation::Broken(e),
    };
    let get = |key: &str| block.and_then(|b| b.get(key));
    let Some(channel) = get("channel_id").filter(|v| truthy(v)) else {
        return Evaluation::Skip("「アラートを送るチャンネル」が未設定です".into());
    };
    if apply_min_scale {
        // 読めない値は既定の 30（震度 3）。
        let min_scale = match get("min_scale") {
            None => 30,
            Some(v) => python_int(v).unwrap_or(30),
        };
        if max_scale < min_scale {
            return Evaluation::Skip(format!(
                "「通知する最小震度」が {min_scale} で、今回の震度 {max_scale} は届いていません"
            ));
        }
    }
    // 通知の種類は、書いていなければ入（True）。
    let enabled = match get("notify_types") {
        None => true,
        Some(Value::Object(types)) => types.get(notify_type.key()).is_none_or(truthy),
        Some(_) => return Evaluation::Broken("notify_types が辞書ではありません".into()),
    };
    if !enabled {
        return Evaluation::Skip(format!(
            "通知タイプ「{}」がオフになっています",
            notify_type.label()
        ));
    }
    if !directory.has_guild(guild_id) {
        return Evaluation::Skip(
            "bot がこのギルドをまだキャッシュしていません（未参加、または再起動直後）".into(),
        );
    }
    let Some(channel_id) = python_int(channel) else {
        return Evaluation::Broken(format!(
            "channel_id（{}）を数として読めません",
            python_str(channel)
        ));
    };
    if !directory.is_text_channel(guild_id, channel_id) {
        return Evaluation::Skip(format!(
            "設定されているチャンネル（{}）が見つからないか、テキストチャンネルではありません",
            python_str(channel)
        ));
    }
    // テキストチャンネルと分かったので、正の数。
    Evaluation::Target(u64::try_from(channel_id).unwrap_or_default())
}

/// 送り先（サーバー, チャンネル）。
pub type Target = (u64, u64);

/// 送り先を集める。Python の `_collect_targets`。
///
/// `only_guild` を渡すとそのサーバーだけ（開発者パネルのリプレイ）。1 つのサーバーの設定が壊れていても、
/// 他のサーバーへの通知は止めない。`handles` は、このプロセスが扱うサーバーか（`BOT_ONLY_GUILD_ID` の柵）。
pub fn collect_targets(
    settings: &Settings,
    directory: &dyn Directory,
    handles: &dyn Fn(u64) -> bool,
    notify_type: NotifyType,
    max_scale: i64,
    apply_min_scale: bool,
    only_guild: Option<u64>,
) -> Vec<Target> {
    let guild_ids: Vec<u64> = match only_guild {
        Some(id) => vec![id],
        None => settings
            .guilds
            .keys()
            .filter_map(|key| key.trim().parse().ok())
            .collect(),
    };
    let mut targets = Vec::new();
    for guild_id in guild_ids {
        if !handles(guild_id) {
            continue;
        }
        match evaluate_guild(
            settings.guild(guild_id),
            directory,
            guild_id,
            notify_type,
            max_scale,
            apply_min_scale,
        ) {
            Evaluation::Target(channel_id) => targets.push((guild_id, channel_id)),
            Evaluation::Skip(_) => {}
            Evaluation::Broken(e) => {
                error!("[earthquake] guild={guild_id} の対象判定に失敗: {e}");
            }
        }
    }
    targets
}

/// 1 つのサーバーに絞ったのに送り先が無かったときの理由（1 文）。Python の `_diagnose_no_target`。
///
/// 判定は [`evaluate_guild`] と同じものを使う（説明用に条件を書き写すと、実際とずれて嘘の理由を出す）。
pub fn diagnose_no_target(
    settings: &Settings,
    directory: &dyn Directory,
    guild_id: u64,
    notify_type: NotifyType,
    max_scale: i64,
    apply_min_scale: bool,
) -> String {
    match evaluate_guild(
        settings.guild(guild_id),
        directory,
        guild_id,
        notify_type,
        max_scale,
        apply_min_scale,
    ) {
        Evaluation::Skip(reason) => reason,
        Evaluation::Broken(e) => format!("設定の読み取りに失敗しました（{e}）"),
        Evaluation::Target(_) => "条件はすべて満たしていますが、送信の直前で対象から外れました（一時的な状態変化の可能性）".into(),
    }
}

/// 開発者パネル専用: 地震の設定を見ずに、指定のチャンネルへ送る。Python の `_override_target`。
///
/// 送れないときは、ここで理由をログに出す。
pub fn override_target(directory: &dyn Directory, guild_id: u64, channel_id: i64) -> Vec<Target> {
    if !directory.has_guild(guild_id) {
        warn!(
            "[earthquake] guild={guild_id}: bot がこのギルドをまだキャッシュしていません（未参加、または再起動直後）"
        );
        return Vec::new();
    }
    if !directory.is_text_channel(guild_id, channel_id) {
        warn!(
            "[earthquake] guild={guild_id}: 指定チャンネル（{channel_id}）が見つからないか、テキストチャンネルではありません"
        );
        return Vec::new();
    }
    vec![(guild_id, u64::try_from(channel_id).unwrap_or_default())]
}

// ── 画像に渡すもの ───────────────────────────────────────

/// 地図の副題（震源・規模・深さ・時刻を 1 行に）。Python の `_map_subtitle`。
pub fn map_subtitle(event: &Value) -> String {
    let eq = &event["earthquake"];
    let hypo = &eq["hypocenter"];
    let (time_label, _) = format_time(text_of(&eq["time"], ""));
    let (magnitude, _) = parse_magnitude(&hypo["magnitude"]);
    let name = match &hypo["name"] {
        v if truthy(v) => python_str(v),
        _ => String::new(),
    };
    let time = if time_label == "不明" {
        String::new()
    } else {
        time_label
    };
    [name, magnitude, parse_depth(&hypo["depth"]), time]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("  ")
}

/// 地図の題。Python の `_quake_map` の `map_title`。
pub fn map_title(max_scale: i64) -> String {
    match scale_label(max_scale) {
        Some(label) => format!("最大震度 {label}"),
        None => "震度分布".into(),
    }
}

/// 地図に渡すもの。
#[derive(Clone, Debug, PartialEq)]
pub struct MapRequest {
    /// 震源の緯度。
    pub lat: f64,
    /// 震源の経度。
    pub lon: f64,
    /// 観測点（電文の `points` のまま）。
    pub points: Vec<Value>,
    /// 題。
    pub title: String,
    /// 副題。
    pub subtitle: String,
}

/// 地図を作るか。震度 1・2（小さい表示）や、震源の座標・観測点が無いときは作らない。Python の `_quake_map`。
pub fn map_request(event: &Value, max_scale: i64) -> Option<MapRequest> {
    let hypo = &event["earthquake"]["hypocenter"];
    let lat = parse_coord(&hypo["latitude"])?;
    let lon = parse_coord(&hypo["longitude"])?;
    let points = event["points"].as_array().filter(|p| !p.is_empty())?;
    if max_scale <= 20 {
        return None;
    }
    Some(MapRequest {
        lat,
        lon,
        points: points.clone(),
        title: map_title(max_scale),
        subtitle: map_subtitle(event),
    })
}

/// 画像を作る口。作れなければ `None`（通知は画像なしで出す）。
pub trait Images: Sync {
    /// 最大震度の札（PNG）。
    fn badge(&self, scale: i64) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// 震度の地図（PNG）。
    fn map(&self, request: &MapRequest) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// 画像を作らない（画像の生成を移すまでの間）。
pub struct NoImages;

impl Images for NoImages {
    async fn badge(&self, _scale: i64) -> Option<Vec<u8>> {
        None
    }

    async fn map(&self, _request: &MapRequest) -> Option<Vec<u8>> {
        None
    }
}

// ── 送る ─────────────────────────────────────────────────

/// 1 つのチャンネルへ送るもの。
#[derive(Clone, Debug)]
pub struct Notice {
    /// Embed。
    pub embed: CreateEmbed,
    /// 詳細のボタンのリンク（津波には無い）。
    pub detail_url: Option<String>,
    /// 添付（ファイル名, 中身）。
    pub attachments: Vec<(&'static str, Vec<u8>)>,
}

/// Discord へ送る口。
pub trait Outbox: Sync {
    /// 1 つのチャンネルへ送る。
    fn send(
        &self,
        guild_id: u64,
        channel_id: u64,
        notice: &Notice,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// 気象庁の詳細ページのリンクを決める口（一覧の取得と、決めたリンクを覚えるところ）。
pub trait DetailUrls: Sync {
    /// この地震のリンク。決められなければ統合地図のページ。
    fn resolve(&self, event: &Value, max_scale: i64) -> impl Future<Output = String> + Send;
}

/// 通知に要るもの。
pub struct Deps<'a, D, O, I, U> {
    /// ギルドごとの設定。
    pub settings: &'a Settings,
    /// サーバーとチャンネルの様子。
    pub directory: &'a D,
    /// 送る口。
    pub outbox: &'a O,
    /// 画像を作る口。
    pub images: &'a I,
    /// 詳細のリンクを決める口。
    pub urls: &'a U,
    /// このプロセスが扱うサーバーか。
    pub handles: &'a (dyn Fn(u64) -> bool + Sync),
}

/// 全部の送り先へ並べて送り、送れた数を返す。Python の `_dispatch`。
pub async fn dispatch<O: Outbox>(
    outbox: &O,
    targets: &[Target],
    tag: &str,
    notice: &Notice,
) -> usize {
    let sends = targets
        .iter()
        .map(|&(guild_id, channel_id)| outbox.send(guild_id, channel_id, notice));
    let results = futures_util::future::join_all(sends).await;
    let mut ok = 0;
    for (&(guild_id, channel_id), result) in targets.iter().zip(results) {
        match result {
            Ok(()) => ok += 1,
            Err(e) => error!("[{tag}] send error guild={guild_id} ch={channel_id}: {e}"),
        }
    }
    ok
}

/// 開発者パネルのリプレイの依頼。
#[derive(Clone, Debug, PartialEq)]
pub struct Replay {
    /// 流し直す電文。
    pub event: Value,
    /// このサーバーだけに送る（無ければ全サーバー）。
    pub guild_id: Option<u64>,
    /// 地震の設定を見ずに、このチャンネルへ送る（`guild_id` と組で）。
    pub channel_id: Option<i64>,
}

/// リプレイの依頼の中身を読む。Python の `_signal_eq_replay`。
///
/// 新しい形は `{"event": …, "guild_id": …, "channel_id": …}`。`event` の鍵が無ければ、全体を電文として扱う。
pub fn parse_replay(payload: &str) -> Result<Replay, String> {
    let value: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let (event, guild_id, channel_id) = match value {
        Value::Object(mut map) if map.contains_key("event") => {
            let event = match map.remove("event") {
                Some(v) if truthy(&v) => v,
                _ => Value::Object(Map::new()),
            };
            // **読めない送り先を「指定なし」にしない。** 指定なしは全サーバーへの配信になる。
            let guild_id = match map.get("guild_id") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_u64()
                        .filter(|id| *id > 0)
                        .ok_or_else(|| format!("guild_id（{v}）を読めません"))?,
                ),
            };
            let channel_id = match map.get("channel_id") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    Some(python_int(v).ok_or_else(|| format!("channel_id（{v}）を読めません"))?)
                }
            };
            (event, guild_id, channel_id)
        }
        event => (event, None, None),
    };
    if !event.is_object() {
        return Err("電文が辞書ではありません".into());
    }
    Ok(Replay {
        event,
        guild_id,
        channel_id,
    })
}

/// 地震情報（551）を送る。送ったチャンネルの数を返す。Python の `_notify_all_guilds`。
///
/// `only_guild` を渡すとそのサーバーだけ（設定はそのまま当てる）。`override_channel` も渡すと、設定を
/// 見ずにそのチャンネルへ送る（開発者パネルでの確認用）。
pub async fn notify_quake<D: Directory, O: Outbox, I: Images, U: DetailUrls>(
    deps: &Deps<'_, D, O, I, U>,
    event: &Value,
    only_guild: Option<u64>,
    override_channel: Option<i64>,
) -> usize {
    let scale = max_scale(event);
    // 送り先を先に決める。誰も受け取らないなら、リンクも画像も作らない。
    let targets = quake_targets(deps, scale, only_guild, override_channel);
    if targets.is_empty() {
        return 0;
    }
    let detail_url = deps.urls.resolve(event, scale).await;
    // 震度が分からない電文（遠地地震など）で「最大震度 -1」の札を作らない。
    let badge = if scale < 0 {
        None
    } else {
        deps.images.badge(scale).await
    };
    let map = match map_request(event, scale) {
        Some(request) => deps.images.map(&request).await,
        None => None,
    };
    let mut embed = build_embed(event, scale, badge.is_some());
    let mut attachments = Vec::new();
    if let Some(png) = badge {
        attachments.push((BADGE_FILE, png));
    }
    if let Some(png) = map {
        // 添付するだけだと、Embed には出ない。
        embed = embed.image(format!("attachment://{MAP_FILE}"));
        attachments.push((MAP_FILE, png));
    }
    let notice = Notice {
        embed,
        detail_url: Some(detail_url),
        attachments,
    };
    dispatch(deps.outbox, &targets, "earthquake", &notice).await
}

/// 地震情報の送り先。**重い処理より先に呼ぶこと。** Python の `_quake_targets`。
fn quake_targets<D: Directory, O, I, U>(
    deps: &Deps<'_, D, O, I, U>,
    scale: i64,
    only_guild: Option<u64>,
    override_channel: Option<i64>,
) -> Vec<Target> {
    if let (Some(guild_id), Some(channel_id)) = (only_guild, override_channel) {
        if !(deps.handles)(guild_id) {
            warn!("[earthquake] guild={guild_id}: このプロセスが扱わないサーバーなので送りません");
            return Vec::new();
        }
        return override_target(deps.directory, guild_id, channel_id);
    }
    let targets = collect_targets(
        deps.settings,
        deps.directory,
        deps.handles,
        NotifyType::QuakeInfo,
        scale,
        true,
        only_guild,
    );
    // 1 つのサーバーに絞ったとき（リプレイ）だけ、届かない理由を出す。全サーバーへの本番の配信では、
    // ほとんどのサーバーが対象外なのがふつうなので出さない（ログが警告で埋まる）。
    if let (true, Some(guild_id)) = (targets.is_empty(), only_guild) {
        warn!(
            "[earthquake] guild={guild_id}: 送信先が0件でした（理由: {}）",
            diagnose_no_target(
                deps.settings,
                deps.directory,
                guild_id,
                NotifyType::QuakeInfo,
                scale,
                true
            )
        );
    }
    targets
}

/// 津波情報（552）を送る。Python の `_notify_tsunami_guilds`（津波は震度を持たないので、最小震度は当てない）。
pub async fn notify_tsunami<D: Directory, O: Outbox, I, U>(
    deps: &Deps<'_, D, O, I, U>,
    event: &Value,
) -> usize {
    let targets = collect_targets(
        deps.settings,
        deps.directory,
        deps.handles,
        NotifyType::Tsunami,
        -1,
        false,
        None,
    );
    if targets.is_empty() {
        return 0;
    }
    let notice = Notice {
        embed: build_tsunami_embed(event),
        detail_url: None,
        attachments: Vec::new(),
    };
    dispatch(deps.outbox, &targets, "tsunami", &notice).await
}

/// 緊急地震速報（554・556）を送る。Python の `_notify_eew_guilds`。
///
/// 震度が分からない（554 の検出・取り消し）ときは、最小震度で弾かずに必ず届ける（安全側）。
pub async fn notify_eew<D: Directory, O: Outbox, I: Images, U: DetailUrls>(
    deps: &Deps<'_, D, O, I, U>,
    event: &Value,
    notify_type: NotifyType,
) -> usize {
    let scale = max_scale(event);
    let cancelled = truthy(&event["cancelled"]);
    let targets = collect_targets(
        deps.settings,
        deps.directory,
        deps.handles,
        notify_type,
        scale,
        scale >= 0,
        None,
    );
    if targets.is_empty() {
        return 0;
    }
    let detail_url = deps.urls.resolve(event, scale).await;
    // 分からない震度・外れた震度（取り消し）は札にしない。
    let badge = if scale >= 0 && !cancelled {
        deps.images.badge(scale).await
    } else {
        None
    };
    let mut embed = build_eew_embed(event);
    let mut attachments = Vec::new();
    if let Some(png) = badge {
        embed = embed.thumbnail(format!("attachment://{BADGE_FILE}"));
        attachments.push((BADGE_FILE, png));
    }
    let notice = Notice {
        embed,
        detail_url: Some(detail_url),
        attachments,
    };
    dispatch(deps.outbox, &targets, "eew", &notice).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    const GUILD: u64 = 10;
    const OTHER: u64 = 20;
    const CHANNEL: u64 = 555;

    /// どのサーバーも読めていて、555 だけがテキストチャンネル。
    struct AllCached;

    impl Directory for AllCached {
        fn has_guild(&self, _guild_id: u64) -> bool {
            true
        }

        fn is_text_channel(&self, _guild_id: u64, channel_id: i64) -> bool {
            channel_id == 555
        }
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(u64, u64)>>);

    impl Outbox for Recorder {
        async fn send(
            &self,
            guild_id: u64,
            channel_id: u64,
            _notice: &Notice,
        ) -> Result<(), String> {
            self.0.lock().unwrap().push((guild_id, channel_id));
            Ok(())
        }
    }

    struct FixedUrl;

    impl DetailUrls for FixedUrl {
        async fn resolve(&self, _event: &Value, _max_scale: i64) -> String {
            JMA_FALLBACK_URL.into()
        }
    }

    fn settings() -> Settings {
        let block = json!({"earthquake": {"channel_id": CHANNEL, "min_scale": 30}});
        Settings {
            guilds: [
                (GUILD.to_string(), block.clone()),
                (OTHER.to_string(), block),
            ]
            .into_iter()
            .collect(),
            ..Settings::default()
        }
    }

    fn quake() -> Value {
        json!({
            "code": 551,
            "earthquake": {"time": "2026/08/24 12:54:41", "hypocenter": {"name": "茨城県沖"}},
            "points": [{"pref": "茨城県", "scale": 40}],
        })
    }

    /// このプロセスが扱わないサーバーへは送らないこと（本番のトークンで手元から確かめるときの柵）。
    #[tokio::test]
    async fn guilds_outside_the_fence_get_nothing() {
        let settings = settings();
        let outbox = Recorder::default();
        let only_first = |guild_id: u64| guild_id == GUILD;
        let deps = Deps {
            settings: &settings,
            directory: &AllCached,
            outbox: &outbox,
            images: &NoImages,
            urls: &FixedUrl,
            handles: &only_first,
        };
        assert_eq!(notify_quake(&deps, &quake(), None, None).await, 1);
        assert_eq!(notify_tsunami(&deps, &json!({"code": 552})).await, 1);
        let eew = json!({"code": 554});
        assert_eq!(notify_eew(&deps, &eew, NotifyType::EewWarning).await, 1);
        // 1 つのサーバーに絞っても、設定を見ずに送る指定でも、柵の外へは送らない。
        assert_eq!(notify_quake(&deps, &quake(), Some(OTHER), None).await, 0);
        let direct = notify_quake(&deps, &quake(), Some(OTHER), Some(555)).await;
        assert_eq!(direct, 0);
        assert_eq!(
            notify_quake(&deps, &quake(), Some(GUILD), Some(555)).await,
            1
        );
        let sent = outbox.0.lock().unwrap().clone();
        assert_eq!(sent, [(GUILD, CHANNEL); 4]);
    }

    /// 画像を作らない間は、札も地図も付けずに通知を出すこと。
    #[tokio::test]
    async fn notices_go_out_without_images() {
        struct Capture(Mutex<Vec<Notice>>);
        impl Outbox for Capture {
            async fn send(&self, _g: u64, _c: u64, notice: &Notice) -> Result<(), String> {
                self.0.lock().unwrap().push(notice.clone());
                Ok(())
            }
        }
        let settings = settings();
        let outbox = Capture(Mutex::default());
        let deps = Deps {
            settings: &settings,
            directory: &AllCached,
            outbox: &outbox,
            images: &NoImages,
            urls: &FixedUrl,
            handles: &|_| true,
        };
        assert_eq!(notify_quake(&deps, &quake(), Some(GUILD), None).await, 1);
        let sent = outbox.0.lock().unwrap();
        assert!(sent[0].attachments.is_empty());
        let embed = serde_json::to_value(&sent[0].embed).unwrap();
        assert!(embed.get("thumbnail").is_none() && embed.get("image").is_none());
        assert_eq!(sent[0].detail_url.as_deref(), Some(JMA_FALLBACK_URL));
    }

    /// リプレイの送り先が読めないときは、全サーバーへの配信にせず、依頼ごと断ること。
    #[test]
    fn an_unreadable_replay_target_is_refused() {
        let event = quake();
        let with = |extra: Value| {
            let mut payload = json!({ "event": event });
            for (k, v) in extra.as_object().unwrap() {
                payload[k] = v.clone();
            }
            parse_replay(&payload.to_string())
        };
        let ok = with(json!({"guild_id": 10, "channel_id": "555"})).unwrap();
        assert_eq!((ok.guild_id, ok.channel_id), (Some(10), Some(555)));
        let all = with(json!({"guild_id": null})).unwrap();
        assert_eq!((all.guild_id, all.channel_id), (None, None));
        for bad in [
            json!({"guild_id": "10"}),
            json!({"guild_id": 0}),
            json!({"guild_id": -5}),
            json!({"guild_id": 1.5}),
            json!({"guild_id": [10]}),
            json!({"guild_id": 10, "channel_id": "abc"}),
            json!({"guild_id": 10, "channel_id": []}),
        ] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
        // 電文が辞書でなければ断る（配列を「中身の無い地震」として全サーバーへ流さない）。
        assert!(parse_replay("[1, 2]").is_err());
        assert!(parse_replay("\"text\"").is_err());
        assert!(parse_replay(&json!({"event": [1]}).to_string()).is_err());
        // 古い形（電文そのもの）は全サーバーへ。
        let old = parse_replay(&event.to_string()).unwrap();
        assert_eq!((old.event, old.guild_id), (event, None));
    }

    /// 小数の書き方が Python の repr と同じこと（Python 3.13 の出力）。
    #[test]
    fn floats_are_written_like_python() {
        for (v, want) in [
            (5.0, "5.0"),
            (4.6, "4.6"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1e-5, "1e-05"),
            (0.0003, "0.0003"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1e22, "1e+22"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (9999999999999998.0, "9999999999999998.0"),
            (0.30000000000000004, "0.30000000000000004"),
            (12345.678, "12345.678"),
            (100.0, "100.0"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
        ] {
            assert_eq!(python_float_repr(v), want, "{v:e}");
        }
        assert_eq!(python_float_repr(f64::NAN), "nan");
    }

    /// 場所とファイル名が Python と同じであること。
    #[test]
    fn the_constants_match_python() {
        let service = include_str!("../../../../services/earthquake_service.py");
        let config = include_str!("../../../../config.py");
        for needle in [
            format!("\"{JMA_FALLBACK_URL}\""),
            format!("\"{JMA_DETAIL_BASE}\""),
            format!("\"{BADGE_FILE}\""),
            format!("\"{MAP_FILE}\""),
            format!("label=\"{DETAIL_LABEL}\""),
        ] {
            assert!(service.contains(&needle), "Python に無い: {needle}");
        }
        // アイコンの URL は、Python では 2 つの文字に分けて書いてある。
        let (head, tail) = BOT_ICON_URL.split_at(BOT_ICON_URL.find("/9d").unwrap());
        assert!(config.contains(head) && config.contains(tail));
        assert_eq!((JMA_ITEMS_LIMIT, JMA_MIN_SCORE), (400, 10.0));
        assert!(service.contains("items[:400]") && service.contains("best_score < 10"));
    }

    /// 震度の表示が、Python の `config.SCALE_LABELS` と同じ対応であること。
    ///
    /// ここを 1 段ずらすと、震度 5 弱を「4 強」と伝えることになる（Python で実際にあった）。
    #[test]
    fn scale_labels_match_the_p2p_specification() {
        let config = include_str!("../../../../config.py");
        for (scale, label) in [
            (10, "1"),
            (20, "2"),
            (30, "3"),
            (40, "4"),
            (45, "5弱"),
            (50, "5強"),
            (55, "6弱"),
            (60, "6強"),
            (70, "7"),
        ] {
            assert_eq!(scale_label(scale), Some(label));
            assert!(
                config.contains(&format!("{scale}: \"{label}\",")),
                "{scale}"
            );
        }
        for unknown in [-1, 0, 15, 46, 99] {
            assert_eq!(scale_label(unknown), None);
            assert_eq!(scale_colour(unknown), None);
            assert_eq!(scale_emoji(unknown), "⚪");
        }
    }
}
