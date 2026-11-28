//! デスクトップの「システムモニター」が読む 2 本（`GET /admin/api/metrics`・`GET /admin/api/incidents`）の中身。
//! Python の `webapp_admin/metrics.py` の `collect_host_metrics`・`list_incidents` と、その下の整形の関数
//! （`load_tone`・`sla_tone`・`_clamp_percent`・`_format_bytes`・`_format_duration`）と SLA の計算
//! （`_month_to_date_sla_percent`・`_downtime_seconds_for_period`）。
//!
//! - インシデントは `incidents.jsonl` を全部読み、`str.splitlines()` で割って 1 行ずつ JSON として読む（読めない行・
//!   辞書でない行は飛ばす）。一覧は新しい順（後ろから）に 30 件、画面向けの形（[`public_incident`]）にする
//! - SLA は「月初（UTC）から今まで」のうち、`downtime` のインシデントと重なった秒数を引いた割合
//! - 画面の時刻（`updated_at`）は日本時間の `%H:%M:%S`（Python は地方時。本番は `TZ=Asia/Tokyo`）
//!
//! Python と違うところ: Rust の JSON の読み方（serde_json）は、`NaN`・`Infinity`・64 ビットに収まらない整数を
//! 読めない（その行は飛ばす。Python は読む）。17 桁の小数は 1 つ隣の値に読むことがある（`float_roundtrip` を
//! 入れていないため。秒の 1000 万分の 1 より小さいずれ）。どれも Python と Rust の書き手は書かない。

use std::path::Path;

use chrono::{DateTime, Datelike, NaiveDate};
use serde_json::{Map, Value, json};

use crate::app::AdminApp;
use crate::errors::Crash;
use crate::metrics::INCIDENTS_FILE;
use crate::monitor::host::{HostSample, os_error};
use crate::monitor::pyfloat::{fixed, general, py_max, py_min, round, trunc};
use crate::monitor::Settings;
use crate::python;

/// 一覧に出す件数（`list_incidents(limit=30)`。表示欄の分量）。
pub const INCIDENT_LIMIT: usize = 30;
/// 日本時間の時差（秒）。
const JST_SECONDS: i64 = 9 * 3600;

/// 1 つのメーター（`label`・`percent`・`display`・`detail`・`tone`）。
#[derive(Clone, Debug, PartialEq)]
pub struct Meter {
    /// 名前（`CPU`・`Memory`・`TPS`・`SLA`）。
    pub label: String,
    /// 目盛り（0〜100 に丸めたもの）。
    pub percent: f64,
    /// 見せる数字。
    pub display: String,
    /// 補足。
    pub detail: String,
    /// 色（`success`・`warning`・`danger`）。
    pub tone: String,
}

impl Meter {
    fn to_json(&self) -> Value {
        json!({
            "label": self.label,
            "percent": self.percent,
            "display": self.display,
            "detail": self.detail,
            "tone": self.tone,
        })
    }
}

/// `collect_host_metrics()` の答え。
#[derive(Clone, Debug, PartialEq)]
pub struct HostMetrics {
    /// 測った時刻（日本時間の `%H:%M:%S`）。
    pub updated_at: String,
    /// CPU。
    pub cpu: Meter,
    /// メモリ。
    pub memory: Meter,
    /// 秒あたりの要求の数。
    pub tps: Meter,
    /// 月初からの稼働率。
    pub sla: Meter,
    /// 管理画面のプロセスが起きてからの長さ。
    pub runtime_admin: String,
    /// ホストが起きてからの長さ。
    pub runtime_host: String,
}

impl HostMetrics {
    /// 画面へ返す JSON（鍵の順は Python の辞書と同じ）。
    pub fn to_json(&self) -> Value {
        json!({
            "updated_at": self.updated_at,
            "metrics": {
                "cpu": self.cpu.to_json(),
                "memory": self.memory.to_json(),
                "tps": self.tps.to_json(),
                "sla": self.sla.to_json(),
            },
            "runtime": {
                "admin_app": self.runtime_admin,
                "host": self.runtime_host,
            },
        })
    }
}

/// `load_tone`（しきい値以上は danger、その 8 割以上は warning、ほかは success）。
pub fn load_tone(percent: f64, alert_at: f64) -> &'static str {
    if percent >= alert_at {
        return "danger";
    }
    if percent >= alert_at * 0.8 {
        return "warning";
    }
    "success"
}

/// `sla_tone`（99.9% 以上は success、99.0% 以上は warning、ほかは danger。固定のしきい値）。
pub fn sla_tone(percent: f64) -> &'static str {
    if percent >= 99.9 {
        return "success";
    }
    if percent >= 99.0 {
        return "warning";
    }
    "danger"
}

/// `_clamp_percent`（0〜100 に寄せて小数 2 桁に丸める）。
pub fn clamp_percent(value: f64) -> f64 {
    round(py_min(py_max(value, 0.0), 100.0), 2)
}

/// `_format_bytes`（`1.2 GB` のように、1024 で割っていって 1024 未満になった単位で小数 1 桁）。
pub fn format_bytes(value: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value;
    for (i, unit) in UNITS.iter().enumerate() {
        if size < 1024.0 || i == UNITS.len() - 1 {
            return format!("{} {unit}", fixed(size, 1));
        }
        size /= 1024.0;
    }
    format!("{} TB", fixed(size, 1))
}

/// `_format_duration`（上 2 つの単位まで。`2d 3h`・`4h 5m`・`6m 7s`・`8s`。負は 0）。
pub fn format_duration(seconds: f64) -> String {
    let total = trunc(seconds).max(0);
    let days = total / 86400;
    let remainder = total % 86400;
    let hours = remainder / 3600;
    let remainder = remainder % 3600;
    let minutes = remainder / 60;
    let seconds = remainder % 60;
    if days > 0 {
        return format!("{days}d {hours}h");
    }
    if hours > 0 {
        return format!("{hours}h {minutes}m");
    }
    if minutes > 0 {
        return format!("{minutes}m {seconds}s");
    }
    format!("{seconds}s")
}

/// Python の `datetime.fromtimestamp(epoch)` の秒（マイクロ秒を偶数への丸めで決めてから、繰り上がりを秒に足す）。
fn whole_seconds(epoch: f64) -> i64 {
    let whole = epoch.trunc();
    let micros = ((epoch - whole) * 1e6).round_ties_even();
    let mut seconds = whole as i64;
    if micros >= 1e6 {
        seconds += 1;
    } else if micros < 0.0 {
        seconds -= 1;
    }
    seconds
}

/// その時刻の月初（UTC）の UNIX 時間。`datetime.fromtimestamp(now, timezone.utc).replace(day=1, hour=0, …)`。
pub fn month_start(now: f64) -> f64 {
    let Some(at) = DateTime::from_timestamp(whole_seconds(now), 0) else {
        return now;
    };
    NaiveDate::from_ymd_opt(at.year(), at.month(), 1)
        .and_then(|day| day.and_hms_opt(0, 0, 0))
        .map_or(now, |start| start.and_utc().timestamp() as f64)
}

/// 日本時間の `%H:%M:%S`（`datetime.now().strftime(...)`。本番の地方時は日本時間）。
pub fn local_clock(now: f64) -> String {
    let seconds = whole_seconds(now) + JST_SECONDS;
    DateTime::from_timestamp(seconds, 0).map_or_else(String::new, |at| at.format("%H:%M:%S").to_string())
}

/// JSON の値を Python の `isinstance(x, (int, float))` として読む（真偽も数に入る）。
pub fn py_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        _ => None,
    }
}

/// `incidents.jsonl` を読む（無ければ `None`）。UTF-8 でなければ Python と同じく例外（`UnicodeDecodeError`）。
pub fn read_incidents(path: &Path) -> Result<Option<String>, Crash> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
            Crash::new(
                "UnicodeDecodeError",
                format!("'utf-8' codec can't decode the file: {e}"),
            )
        }),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => {
            Ok(None)
        }
        Err(e) => Err(os_error(&e, path)),
    }
}

/// 1 行を JSON として読み、辞書なら返す（`json.loads` に失敗した行と、辞書でない行は `None`）。
fn incident_of(line: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// `_iter_incidents`（全部の行を前から。整形しない）。
pub fn all_incidents(text: &str) -> Vec<Map<String, Value>> {
    python::splitlines(text).into_iter().filter_map(incident_of).collect()
}

/// `_public_incident`（画面へ返す 1 件の形。時刻の数そのものは出さない）。
pub fn public_incident(incident: &Map<String, Value>) -> Value {
    let get = |key: &str, default: Value| incident.get(key).cloned().unwrap_or(default);
    let duration = incident
        .get("duration_seconds")
        .and_then(py_number)
        .map_or(Value::Null, |seconds| json!(format_duration(seconds)));
    json!({
        "id": get("id", Value::Null),
        "kind": get("kind", json!("unknown")),
        "severity": get("severity", json!("info")),
        "title": get("title", json!("Incident")),
        "message": get("message", json!("")),
        "created_at": get("created_at", json!("")),
        "duration": duration,
        "metadata": get("metadata", json!({})),
    })
}

/// `list_incidents(limit)`（新しい順に `limit` 件。空白だけの行・読めない行・辞書でない行は飛ばす）。
pub fn list_incidents(text: &str, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for line in python::splitlines(text).into_iter().rev() {
        if python::strip(line).is_empty() {
            continue;
        }
        if let Some(incident) = incident_of(line) {
            out.push(public_incident(&incident));
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// `_downtime_seconds_for_period`（`downtime` のインシデントのうち、期間と重なった秒数を前から足す）。
pub fn downtime_seconds_for_period(incidents: &[Map<String, Value>], start: f64, end: f64) -> f64 {
    let mut total = 0.0;
    for incident in incidents {
        if incident.get("kind") != Some(&json!("downtime")) {
            continue;
        }
        let (Some(from), Some(to)) = (
            incident.get("start_epoch").and_then(py_number),
            incident.get("end_epoch").and_then(py_number),
        ) else {
            continue;
        };
        let overlap_start = py_max(from, start);
        let overlap_end = py_min(to, end);
        if overlap_end > overlap_start {
            total += overlap_end - overlap_start;
        }
    }
    total
}

/// `_month_to_date_sla_percent`（期間が 1 秒に満たなければ 1 秒とみなす）。
pub fn month_to_date_sla_percent(incidents: &[Map<String, Value>], now: f64) -> f64 {
    let start = month_start(now);
    let period = py_max(now - start, 1.0);
    let downtime = downtime_seconds_for_period(incidents, start, now);
    let uptime = py_max(period - downtime, 0.0);
    clamp_percent((uptime / period) * 100.0)
}

/// `_downtime_seconds_month_to_date`。
pub fn downtime_month_to_date(incidents: &[Map<String, Value>], now: f64) -> f64 {
    downtime_seconds_for_period(incidents, month_start(now), now)
}

/// 測ったものから画面の答えを組み立てる（`collect_host_metrics` の辞書の部分）。
///
/// `now` は測り始めの時刻、`updated` は組み立てるときの時刻（Python は `datetime.now()` を別に読む）。
pub fn build(
    sample: &HostSample,
    tps: f64,
    incidents: &[Map<String, Value>],
    settings: &Settings,
    now: f64,
    started_at: f64,
    updated: f64,
) -> HostMetrics {
    let tps_percent = clamp_percent((tps / settings.tps_target) * 100.0);
    let sla_percent = month_to_date_sla_percent(incidents, now);
    let cpu = sample.cpu_percent;
    let memory = &sample.memory;
    HostMetrics {
        updated_at: local_clock(updated),
        cpu: Meter {
            label: "CPU".to_string(),
            percent: clamp_percent(cpu),
            display: format!("{}%", fixed(cpu, 1)),
            detail: format!("論理コア {}", sample.cpu_count.filter(|n| *n > 0).unwrap_or(1)),
            tone: load_tone(cpu, settings.cpu_alert_percent).to_string(),
        },
        memory: Meter {
            label: "Memory".to_string(),
            percent: clamp_percent(memory.percent),
            display: format!("{}%", fixed(memory.percent, 1)),
            detail: format!(
                "{} / {}",
                format_bytes(memory.used as f64),
                format_bytes(memory.total as f64)
            ),
            tone: load_tone(memory.percent, settings.memory_alert_percent).to_string(),
        },
        tps: Meter {
            label: "TPS".to_string(),
            percent: tps_percent,
            display: format!("{} req/s", fixed(tps, 2)),
            detail: format!(
                "目標 {} req/s の {}%",
                general(settings.tps_target),
                fixed(tps_percent, 0)
            ),
            tone: load_tone(tps_percent, settings.tps_alert_percent).to_string(),
        },
        sla: Meter {
            label: "SLA".to_string(),
            percent: clamp_percent(sla_percent),
            display: format!("{}%", fixed(sla_percent, 2)),
            detail: format!(
                "記録済み停止 {}",
                format_duration(downtime_month_to_date(incidents, now))
            ),
            tone: sla_tone(sla_percent).to_string(),
        },
        runtime_admin: format_duration(now - started_at),
        runtime_host: format_duration(now - sample.boot_time),
    }
}

/// `collect_host_metrics()`。ホストを測り（0.1 秒）、要求の数と、インシデントのファイル（SLA）を読む。
pub async fn collect(app: &AdminApp) -> Result<HostMetrics, Crash> {
    let monitor = app.monitor();
    let now = monitor.now();
    let sample = monitor.host().sample().await?;
    let tps = app.metrics().request_tps(now);
    let text = read_incidents(&app.config().monitor_dir.join(INCIDENTS_FILE))?;
    let incidents = text.as_deref().map(all_incidents).unwrap_or_default();
    Ok(build(
        &sample,
        tps,
        &incidents,
        monitor.settings(),
        now,
        monitor.started_at(),
        monitor.now(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 上 2 つの単位までにすること。
    #[test]
    fn durations_keep_two_units() {
        assert_eq!(format_duration(0.0), "0s");
        assert_eq!(format_duration(59.9), "59s");
        assert_eq!(format_duration(3600.0), "1h 0m");
        assert_eq!(format_duration(90061.5), "1d 1h");
        assert_eq!(format_duration(-5.0), "0s");
    }

    /// 月初は UTC で決めること（日本時間の 1 日 0 時ではない）。
    #[test]
    fn the_month_starts_in_utc() {
        // 2027-01-01T00:00:00Z。
        assert_eq!(month_start(1_798_761_600.25), 1_798_761_600.0);
        assert_eq!(month_start(1_798_761_599.0), 1_796_083_200.0);
        assert_eq!(local_clock(1_798_761_600.25), "09:00:00");
    }

    /// 一覧は新しい順で、読めない行と空白の行を飛ばし、足りない鍵は既定で埋めること。
    #[test]
    fn incidents_are_listed_newest_first() {
        let text = "{\"id\":\"a\",\"duration_seconds\":61}\nnot json\n  \n[1]\n{\"id\":\"b\"}\n";
        let listed = list_incidents(text, 30);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["id"], "b");
        assert_eq!(listed[0]["kind"], "unknown");
        assert_eq!(listed[0]["duration"], Value::Null);
        assert_eq!(listed[1]["duration"], "1m 1s");
        assert_eq!(list_incidents(text, 1).len(), 1);
    }
}
