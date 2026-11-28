//! サーバーのデータをいつ消すか。Python の `services/guild_retention.py`（`is_abandoned`・`_parse`・
//! `purge_abandoned_guilds`・`delete_guild_data`）と、それが使う `services/settings_store.py` の
//! `known_guild_ids`・`touched_at`・`delete_guild_settings`。
//!
//! **消すのは利用者が決める。** 自動で消すのは放棄されたものだけ:
//!
//! ```text
//! Bot がもう そのサーバーに居ない   かつ   設定が最後に触られてから決めた日数（既定 10 年）
//! ```
//!
//! 片方だけでは足りない（Bot が居ないだけなら「一時的に外して戻す」で設定が消え、日数だけなら「設定して
//! 放置しているが現役」のサーバーが初期化される）。**触られた時刻が無い・読めない設定は消さない**（無いもの
//! を「ずっと前」と読むと、既存の設定が一斉に消える）。**居るサーバーが 0 件で呼ばれたら掃除しない**（一覧が
//! まだ無いときに、現役のサーバーまで消さないため）。自動の掃除は設定だけを消す（利用者の状態の履歴には
//! 別の保管期間があり、そちらの掃除が持っている）。
//!
//! 時刻の読み方は Python の `datetime.fromisoformat`（3.13 の C の実装）をそのまま写した
//! （[`parse_isoformat`]。`2026-11-25T09:44:26.553123+00:00` のほか、`Z`・日付だけ・区切りなし・週の日付・
//! 任意の 1 文字の区切りなど。本物の Python と多くの文字で突き合わせた）。
//!
//! Python と変えたところ: サーバーの設定が JSON のオブジェクトでも空でもないとき（配列や文字など）、Python は
//! `dict(…)` で読もうとして、2 つ組の並びなら読み、そうでなければ例外で掃除をやめる。こちらは常に掃除を
//! やめる（消さない側。設定は管理画面と Bot が書くのでオブジェクトしか入らない）。

use std::collections::HashSet;

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde_json::Value;
use sycs_core::settings::{SettingsCache, TOUCHED_AT_KEY, WriteError};
use tracing::{error, info, warn};

use crate::groq::python_is_space;
use crate::user_state::Recorder;
use crate::user_state_repair::{self, pyjson};

/// 放棄とみなすまでの日数の既定（利用者の状態の履歴と同じ 10 年）。
pub const ABANDONED_AFTER_DAYS: i64 = 3650;

/// 1 日のマイクロ秒。
const DAY_MICROS: i128 = 86_400_000_000;
/// Python の `datetime.min`（0001-01-01T00:00:00）の UNIX マイクロ秒。
const MIN_MICROS: i128 = -62_135_596_800_000_000;
/// Python の `timedelta` の日数の上限。
const MAX_TIMEDELTA_DAYS: i64 = 999_999_999;

/// 掃除をやめた理由。Python ではどれも例外で、呼んだ側（巡回）がログに残す。
#[derive(Debug)]
pub enum PurgeError {
    /// サーバーの設定が JSON のオブジェクトではない（Python の `dict(…)` が失敗する）。
    NotAnObject(String),
    /// 日数が大きすぎて「いつより前か」の時刻が作れない（Python の OverflowError）。
    Overflow(i64),
    /// 設定を消せなかった。
    Write(WriteError),
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject(key) => write!(f, "ギルド {key} の設定がオブジェクトではありません"),
            Self::Overflow(days) => write!(f, "date value out of range（{days} 日前は表せません）"),
            Self::Write(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PurgeError {}

/// Python の `int(key)`（ASCII の数字だけ）を、正規の 10 進の文字に（`" 007 "` → `"7"`、`"-0"` → `"0"`）。
///
/// 読めなければ `None`（Python の `known_guild_ids` が飛ばす）。ASCII 以外の数字は読まない（Python は読むが、
/// 読んだ ID で引く設定の鍵は正規の文字なので、そちらの鍵として別に回ってくる）。
pub fn python_int_key(key: &str) -> Option<String> {
    let t = key.trim_matches(python_is_space);
    let (negative, digits) = match t.strip_prefix(['+', '-']) {
        Some(rest) => (t.starts_with('-'), rest),
        None => (false, t),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return None;
    }
    let shaped = bytes.iter().enumerate().all(|(i, b)| match b {
        b'0'..=b'9' => true,
        b'_' => bytes[i - 1].is_ascii_digit(),
        _ => false,
    });
    if !shaped {
        return None;
    }
    let plain: String = digits.chars().filter(char::is_ascii_digit).collect();
    let plain = plain.trim_start_matches('0');
    if plain.is_empty() {
        return Some("0".into());
    }
    Some(if negative {
        format!("-{plain}")
    } else {
        plain.to_string()
    })
}

/// Python の `str(value) if value else None`（触られた時刻の値を文字に）。
fn stamp_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                (i != 0).then(|| i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                let f = n.as_f64()?;
                (f != 0.0).then(|| pyjson::float_repr(f))
            }
        }
        // True・空でない配列やオブジェクトは、文字にしても時刻としては読めない。
        _ => None,
    }
}

/// そのサーバーの「最後に触られた時刻」の文字。Python の `settings_store.touched_at`。
fn touched_at(guild: Option<&Value>, key: &str) -> Result<Option<String>, PurgeError> {
    match guild {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(map.get(TOUCHED_AT_KEY).and_then(stamp_text)),
        // Python の dict([])・dict("") は空。
        Some(Value::Array(items)) if items.is_empty() => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(_) => Err(PurgeError::NotAnObject(key.to_string())),
    }
}

/// そのサーバーの設定を自動で消してよいか。Python の `is_abandoned`。
///
/// `present` は「Bot がいまそのサーバーに居るか」。居るなら何年経っていても消さない。時刻が無い・読めない
/// ものも消さない。`now` は UNIX マイクロ秒。
pub fn is_abandoned(
    stamp: Option<&str>,
    present: bool,
    now_micros: i64,
    abandoned_after_days: i64,
) -> Result<bool, PurgeError> {
    if present {
        return Ok(false);
    }
    let Some(stamp) = stamp.filter(|s| !s.is_empty()).and_then(parse_isoformat) else {
        return Ok(false);
    };
    if abandoned_after_days > MAX_TIMEDELTA_DAYS {
        return Err(PurgeError::Overflow(abandoned_after_days));
    }
    let limit = i128::from(now_micros) - i128::from(abandoned_after_days) * DAY_MICROS;
    if limit < MIN_MICROS {
        return Err(PurgeError::Overflow(abandoned_after_days));
    }
    Ok(i128::from(stamp) < limit)
}

/// サーバーの設定（`guild`、無ければ `None`）から、自動で消してよいかを決める。Python の `is_abandoned`
/// （居るかを先に見て、居なければ `touched_at` で時刻を読む）。`key` は誤りのときに名前として出す。
pub fn guild_is_abandoned(
    guild: Option<&Value>,
    key: &str,
    present: bool,
    now_micros: i64,
    abandoned_after_days: i64,
) -> Result<bool, PurgeError> {
    if present {
        return Ok(false);
    }
    let stamp = touched_at(guild, key)?;
    is_abandoned(stamp.as_deref(), false, now_micros, abandoned_after_days)
}

/// Python の数の並び（`[1, 2]`）の形でログに出す。
fn python_list(ids: &[String]) -> String {
    format!("[{}]", ids.join(", "))
}

/// 放棄されたサーバーの設定を掃除する。消したサーバー（正規の 10 進の文字）を返す。Python の
/// `purge_abandoned_guilds`。
///
/// `present` は Bot がいま居るサーバー。**居るものは 1 つも消さない。** 1 つずつ別に消す（途中で失敗したら
/// そこでやめて誤りを返す。それまでに消したものは消えたまま）。
///
/// **居るサーバーが 0 件なら掃除しない**（警告を出して飛ばす）。サーバーの一覧がまだ届いていないなどで空が
/// 渡ると、現役のサーバーまで「居ない」ことになり、時刻の古い設定が消えうる（消さない側へ倒す）。
pub async fn purge_abandoned_guilds(
    settings: &SettingsCache,
    present: &HashSet<u64>,
    abandoned_after_days: i64,
    now: DateTime<Utc>,
) -> Result<Vec<String>, PurgeError> {
    if present.is_empty() {
        warn!(
            "[retention] 居るギルドが 0 件なので、放棄ギルドの設定の掃除を飛ばします（ギルドの一覧がまだ無い等）"
        );
        return Ok(Vec::new());
    }
    let now_micros = now.timestamp_micros();
    let snapshot = settings.snapshot();
    let known: Vec<String> = snapshot
        .guilds
        .keys()
        .filter_map(|key| python_int_key(key))
        .collect();
    let mut removed = Vec::new();
    for id in known {
        let is_present = id.parse::<u64>().is_ok_and(|g| present.contains(&g));
        // 読んだ ID で引き直す（Python の get_guild_settings(guild_id) は str(guild_id) で引く）。
        let current = settings.snapshot();
        if !guild_is_abandoned(
            current.guilds.get(&id),
            &id,
            is_present,
            now_micros,
            abandoned_after_days,
        )? {
            continue;
        }
        let key = id.clone();
        let deleted = settings
            .transact(move |data| data.guilds.remove(&key).is_some())
            .await
            .map_err(PurgeError::Write)?;
        info!("[settings] delete_guild_settings guild={id}");
        if deleted {
            removed.push(id);
        }
    }
    if !removed.is_empty() {
        warn!(
            "[retention] {}年以上触られていない退出済みギルドの設定を削除 guilds={}",
            abandoned_after_days.div_euclid(365),
            python_list(&removed)
        );
    }
    Ok(removed)
}

/// 1 サーバーぶんで消した数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovedData {
    /// 設定（消せたら 1）。
    pub settings: u64,
    /// 利用者の状態の履歴。
    pub events: u64,
    /// 利用者の状態の最新状態。
    pub states: u64,
}

/// 1 サーバーぶんのデータを、残っているところ全部から消す（利用者が自分で消すための口）。Python の
/// `delete_guild_data`。
///
/// **利用者の状態も一緒に消す**（別の口にすると、消したつもりの人に消し残しを覚えていてもらうことになる）。
/// 利用者の状態を消せなくても設定は消す。設定を消せなければ誤りを返す。いまの Bot からは呼ばない（管理画面が
/// 呼ぶ口。管理画面を移すときのために置いてある）。
pub async fn delete_guild_data(
    recorder: &Recorder,
    settings: &SettingsCache,
    guild_id: u64,
) -> Result<RemovedData, WriteError> {
    let mut removed = RemovedData::default();
    match user_state_repair::delete_guild_user_states(recorder, guild_id).await {
        Ok(counts) => {
            removed.events = counts.events;
            removed.states = counts.states;
        }
        Err(e) => {
            error!(
                "[retention] 監査履歴を消せませんでした guild={guild_id}（設定は消します）: {e}"
            );
        }
    }
    let key = guild_id.to_string();
    let deleted = settings
        .transact(move |data| data.guilds.remove(&key).is_some())
        .await?;
    info!("[settings] delete_guild_settings guild={guild_id}");
    removed.settings = u64::from(deleted);
    warn!(
        "[retention] ギルドのデータを削除 guild={guild_id} 設定={} 履歴={} 現在状態={}",
        removed.settings, removed.events, removed.states
    );
    Ok(removed)
}

/// UTF-8 の文字列を、C の文字列のように読む（終わりより先は 0）。
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn at(&self, i: isize) -> u8 {
        usize::try_from(i)
            .ok()
            .and_then(|i| self.0.get(i).copied())
            .unwrap_or(0)
    }

    fn digits(&self, p: &mut isize, n: isize) -> Option<i64> {
        let mut v = 0i64;
        for _ in 0..n {
            let c = self.at(*p);
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + i64::from(c - b'0');
            *p += 1;
        }
        Some(v)
    }
}

/// 時・分・秒・マイクロ秒。C の `parse_hh_mm_ss_ff` の結果（負は失敗、0 は終わりまで読めた、1 は続きがある）。
struct Clock {
    rv: i32,
    hms: [i64; 3],
    micros: i64,
}

/// C の `parse_hh_mm_ss_ff`。`[HH[:?MM[:?SS]]][.,ffffff]` を `start` から `end` の手前まで読む。
fn hh_mm_ss_ff(b: &Bytes<'_>, start: isize, end: isize) -> Clock {
    let mut out = Clock {
        rv: 0,
        hms: [0; 3],
        micros: 0,
    };
    let mut p = start;
    let mut has_sep = true;
    // 3 つ目（秒）の後に `:` や数字が続いても、C はそのまま先へ進み、残りを小数として読む。
    for i in 0..3 {
        let Some(v) = b.digits(&mut p, 2) else {
            out.rv = -3;
            return out;
        };
        out.hms[i] = v;
        let c = b.at(p);
        p += 1;
        if i == 0 {
            has_sep = c == b':';
        }
        if c == b'.' || c == b',' {
            if p >= end {
                out.rv = -3;
                return out;
            }
            break;
        } else if p >= end {
            out.rv = i32::from(c != 0);
            return out;
        } else if has_sep && c == b':' {
            continue;
        } else if !has_sep {
            p -= 1;
        } else {
            out.rv = -4;
            return out;
        }
    }
    let remains = end - p;
    let to_parse = remains.min(6);
    let Some(mut us) = b.digits(&mut p, to_parse) else {
        out.rv = -3;
        return out;
    };
    if to_parse < 6 {
        us *= [100_000, 10_000, 1_000, 100, 10][(to_parse - 1).max(0) as usize];
    }
    while b.at(p).is_ascii_digit() {
        p += 1;
    }
    out.micros = us;
    out.rv = i32::from(b.at(p) != 0);
    out
}

/// 日付の部分の終わり（区切りの位置）。C の `_find_isoformat_datetime_separator`。
fn find_separator(b: &Bytes<'_>, len: isize) -> isize {
    if len == 7 {
        return 7;
    }
    if b.at(4) == b'-' {
        if b.at(5) == b'W' {
            if len < 8 {
                return -1;
            }
            if len > 8 && b.at(8) == b'-' {
                if len == 9 {
                    return -1;
                }
                if len > 10 && b.at(10).is_ascii_digit() {
                    return 8;
                }
                return 10;
            }
            return 8;
        }
        return 10;
    }
    if b.at(4) == b'W' {
        let mut idx = 7;
        while idx < len && b.at(idx).is_ascii_digit() {
            idx += 1;
        }
        if idx < 9 {
            return idx;
        }
        return if idx % 2 == 0 { 7 } else { 8 };
    }
    8
}

/// Python の日の通し番号（0001-01-01 が 1）。
fn ordinal(y: i64, m: u32, d: u32) -> Option<i64> {
    NaiveDate::from_ymd_opt(i32::try_from(y).ok()?, m, d).map(|x| i64::from(x.num_days_from_ce()))
}

/// 週の日付（年・週・曜日）を年月日に。C の `iso_to_ymd`。
fn iso_to_ymd(year: i64, week: i64, day: i64) -> Option<(i64, u32, u32)> {
    if !(1..=9999).contains(&year) {
        return None;
    }
    let first_day = ordinal(year, 1, 1)?;
    // 0 が月曜。
    let first_weekday = (first_day + 6) % 7;
    if week <= 0 || week >= 53 {
        let leap = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, 2, 29).is_some();
        let fits = week == 53 && (first_weekday == 3 || (first_weekday == 2 && leap));
        if !fits {
            return None;
        }
    }
    if !(1..=7).contains(&day) {
        return None;
    }
    let mut week1_monday = first_day - first_weekday;
    if first_weekday > 3 {
        week1_monday += 7;
    }
    let ord = week1_monday + (week - 1) * 7 + day - 1;
    let date = NaiveDate::from_num_days_from_ce_opt(i32::try_from(ord).ok()?)?;
    Some((i64::from(date.year()), date.month(), date.day()))
}

/// C の `parse_isoformat_date`。
fn parse_date(b: &Bytes<'_>, len: isize) -> Option<(i64, u32, u32)> {
    let mut p = 0;
    let year = b.digits(&mut p, 4)?;
    let uses_sep = b.at(p) == b'-';
    if uses_sep {
        p += 1;
    }
    if b.at(p) == b'W' {
        p += 1;
        let week = b.digits(&mut p, 2)?;
        let day = if p < len {
            if uses_sep {
                if b.at(p) != b'-' {
                    return None;
                }
                p += 1;
            }
            b.digits(&mut p, 1)?
        } else {
            1
        };
        return iso_to_ymd(year, week, day);
    }
    let month = b.digits(&mut p, 2)?;
    if uses_sep {
        if b.at(p) != b'-' {
            return None;
        }
        p += 1;
    }
    let day = b.digits(&mut p, 2)?;
    Some((year, u32::try_from(month).ok()?, u32::try_from(day).ok()?))
}

/// Python の `datetime.fromisoformat`（3.13、C の実装）。読めれば UTC の UNIX マイクロ秒（時差が無ければ UTC と
/// みなす。Python の `_parse` と同じ）。読めなければ `None`。
pub fn parse_isoformat(text: &str) -> Option<i64> {
    if text.chars().count() < 7 {
        return None;
    }
    let b = Bytes(text.as_bytes());
    let len = isize::try_from(text.len()).ok()?;
    let sep = find_separator(&b, len);
    if sep < 0 {
        return None;
    }
    let (year, month, day) = parse_date(&b, sep)?;
    let mut clock = Clock {
        rv: 0,
        hms: [0; 3],
        micros: 0,
    };
    let mut offset_micros: i64 = 0;
    if len > sep {
        // 区切りは任意の 1 文字（UTF-8 の何バイトでも）。
        let lead = b.at(sep);
        let width = if lead & 0x80 == 0 {
            1
        } else {
            match lead & 0xf0 {
                0xe0 => 3,
                0xf0 => 4,
                _ => 2,
            }
        };
        let p = sep + width;
        let p_end = len;
        let mut tz = p;
        loop {
            if matches!(b.at(tz), b'Z' | b'+' | b'-') {
                break;
            }
            tz += 1;
            if tz >= p_end {
                break;
            }
        }
        clock = hh_mm_ss_ff(&b, p, tz);
        if clock.rv < 0 {
            return None;
        }
        if tz == p_end {
            if clock.rv == 1 {
                return None;
            }
        } else if b.at(tz) == b'Z' {
            if b.at(tz + 1) != 0 {
                return None;
            }
        } else {
            let sign = if b.at(tz) == b'-' { -1 } else { 1 };
            let zone = hh_mm_ss_ff(&b, tz + 1, p_end);
            if zone.rv != 0 {
                return None;
            }
            let seconds = zone.hms[0] * 3600 + zone.hms[1] * 60 + zone.hms[2];
            offset_micros = sign * (seconds * 1_000_000 + zone.micros);
            // 時差は ±24 時間より内側（Python の timezone の決まり）。
            if offset_micros.abs() >= DAY_MICROS as i64 {
                return None;
            }
        }
    }
    let [hour, minute, second] = clock.hms;
    if !(1..=9999).contains(&year) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?;
    let local = date
        .and_hms_micro_opt(
            u32::try_from(hour).ok()?,
            u32::try_from(minute).ok()?,
            u32::try_from(second).ok()?,
            u32::try_from(clock.micros).ok()?,
        )?
        .and_utc()
        .timestamp_micros();
    Some(local - offset_micros)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(text: &str) -> Option<String> {
        parse_isoformat(text).map(|us| {
            DateTime::from_timestamp_micros(us)
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%S%.6f")
                .to_string()
        })
    }

    /// Python で確かめた読み方（基準の照合とは別に、手元で読める例）。
    #[test]
    fn the_python_examples() {
        for (text, want) in [
            (
                "2026-11-25T09:44:26.553123+00:00",
                Some("2026-11-25T09:44:26.553123"),
            ),
            ("2026-11-25T09:44:26Z", Some("2026-11-25T09:44:26.000000")),
            ("2026-11-25 09:44:26", Some("2026-11-25T09:44:26.000000")),
            ("20261125", Some("2026-11-25T00:00:00.000000")),
            (
                "2026-11-25T09:44:26.1234567",
                Some("2026-11-25T09:44:26.123456"),
            ),
            ("2026-11-25T09:44:26,5", Some("2026-11-25T09:44:26.500000")),
            (
                "2026-11-25T09:44:26+09:00",
                Some("2026-11-25T00:44:26.000000"),
            ),
            (
                "2026-11-25T09:44:26-05:30",
                Some("2026-11-25T15:14:26.000000"),
            ),
            ("2026-W48-3", Some("2026-11-25T00:00:00.000000")),
            ("2026-W48", Some("2026-11-23T00:00:00.000000")),
            ("2026-11-25X09:44:26", Some("2026-11-25T09:44:26.000000")),
            (
                "2026-11-25T09:44:26.553123 +00:00",
                Some("2026-11-25T09:44:26.553123"),
            ),
            ("2026-11-25T09:44:26z", None),
            ("2026-11-25T24:00:00", None),
            ("2026-02-30T00:00:00", None),
            (" 2026-11-25T09:44:26", None),
            ("2026-11-25T09:44:26 ", None),
            ("2026-11-25T09:44:26.+00:00", None),
            ("2026-11-25T09:44:26+24:00", None),
            ("２０２６-11-25", None),
            ("abc", None),
            ("", None),
        ] {
            assert_eq!(iso(text).as_deref(), want, "{text:?}");
        }
    }

    /// 居るサーバー・時刻の無い設定は消さず、日数が経ったものだけ消すこと。
    #[test]
    fn only_old_absent_guilds_are_abandoned() {
        let now = parse_isoformat("2036-11-25T00:00:00+00:00").unwrap();
        let old = Some("2026-11-24T23:59:59+00:00");
        assert!(is_abandoned(old, false, now, 3650).unwrap());
        assert!(!is_abandoned(old, true, now, 3650).unwrap());
        assert!(!is_abandoned(None, false, now, 3650).unwrap());
        assert!(!is_abandoned(Some("not a time"), false, now, 3650).unwrap());
        assert!(!is_abandoned(Some("2026-11-29T00:00:00+00:00"), false, now, 3650).unwrap());
        assert!(is_abandoned(old, false, now, 800_000).is_err());
        assert!(
            !is_abandoned(None, false, now, 800_000).unwrap(),
            "時刻が無ければ日数を見ない"
        );
    }

    /// 設定の鍵を Python の int() と同じに読むこと。
    #[test]
    fn keys_are_read_like_python_int() {
        for (key, want) in [
            ("123", Some("123")),
            (" 123 ", Some("123")),
            ("+123", Some("123")),
            ("-5", Some("-5")),
            ("1_000", Some("1000")),
            ("007", Some("7")),
            ("-0", Some("0")),
            ("\u{3000} 7\u{3000}", Some("7")),
            ("1__0", None),
            ("_1", None),
            ("1e3", None),
            ("", None),
            ("12a", None),
        ] {
            assert_eq!(python_int_key(key).as_deref(), want, "{key:?}");
        }
    }

    /// 触られた時刻の値を Python の str() と同じに文字にすること（偽の値は無いのと同じ）。
    #[test]
    fn stamps_are_stringified_like_python() {
        use serde_json::json;
        assert_eq!(stamp_text(&json!("x")).as_deref(), Some("x"));
        assert_eq!(stamp_text(&json!("")), None);
        assert_eq!(stamp_text(&json!(0)), None);
        assert_eq!(stamp_text(&json!(20261125)).as_deref(), Some("20261125"));
        assert_eq!(
            stamp_text(&json!(20261125.0)).as_deref(),
            Some("20261125.0")
        );
        assert_eq!(stamp_text(&json!(true)), None);
        assert!(touched_at(Some(&json!([1])), "1").is_err());
        assert_eq!(touched_at(Some(&json!([])), "1").unwrap(), None);
    }
}
