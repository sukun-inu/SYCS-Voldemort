//! 監視の巡回。Python の `webapp_admin/metrics.py` の `start_background_monitor`・`_monitor_loop` と、その中で呼ぶ
//! `_record_startup_downtime`・`_write_heartbeat`・`_record_threshold_alerts`・`_record_alert_with_cooldown`。
//!
//! - 起動のとき: 置き場を作り、前の心拍（`heartbeat.json` の `last_seen_epoch`）から今までの空白が
//!   `ADMIN_DOWNTIME_GRACE_SECONDS`（既定 120 秒）を超えていれば、停止（`downtime`）のインシデントを書く。それから心拍を書く
//! - `ADMIN_MONITOR_INTERVAL_SECONDS`（既定 30 秒・下限 5 秒）ごとに: ホストを測り（[`super::dashboard::collect`]）、
//!   心拍を書き、CPU・メモリ・TPS の割合がしきい値以上なら警告（`resource_alert`）のインシデントを書く。同じ種類は
//!   `ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS`（既定 300 秒）あける
//! - 心拍は Python と同じファイル・同じ形（`json.dumps(…, ensure_ascii=False, indent=2)`。`.tmp` に書いてから
//!   入れ替える）。**Python と Rust を同時に動かさないこと**（巡回が二重になる。計画の 10.）
//!
//! Python は巡回をスレッドで回すが、Rust は tokio のタスクで回す（測るときの 0.1 秒も sleep で待つ）。1 回の失敗で
//! 巡回が止まらないのは Python と同じ（警告を残して次の回へ）。
//!
//! Python と違うところ: 心拍のファイルに `NaN` が書いてあると、Python は読んで（`nan` の停止を）書くが、Rust は読めない
//! ものとして飛ばす（Python も Rust も書かない値）。

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tracing::warn;

use crate::app::AdminApp;
use crate::metrics::{Incidents, NewIncident, iso};
use crate::monitor::dashboard::{self, Meter, py_number};
use crate::monitor::pyfloat::{fixed, general};
use crate::monitor::Settings;
use crate::python;

/// 心拍のファイルの名前。
pub const HEARTBEAT_FILE: &str = "heartbeat.json";

/// 心拍の中身（`_write_heartbeat`。字下げ 2 の JSON。最後に改行は付けない）。
pub fn heartbeat_text(now: f64, started_at: f64, pid: u32) -> String {
    let fields = [
        ("last_seen_epoch", json!(now)),
        ("last_seen_at", json!(iso(now))),
        ("pid", json!(pid)),
        ("app_started_epoch", json!(started_at)),
        ("app_started_at", json!(iso(started_at))),
    ];
    let lines: Vec<String> = fields
        .iter()
        .map(|(key, value)| {
            format!(
                "  {}: {}",
                python::dumps(&json!(key), python::COMPACT),
                python::dumps(value, python::COMPACT)
            )
        })
        .collect();
    format!("{{\n{}\n}}", lines.join(",\n"))
}

/// 心拍を書く（`_write_json`。置き場を作り、`heartbeat.json.tmp` に書いてから入れ替える）。
pub fn write_heartbeat(dir: &Path, now: f64, started_at: f64, pid: u32) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(HEARTBEAT_FILE);
    let tmp = dir.join(format!("{HEARTBEAT_FILE}.tmp"));
    std::fs::write(&tmp, heartbeat_text(now, started_at, pid))?;
    std::fs::rename(&tmp, path)
}

/// 前の心拍の `last_seen_epoch`（`_read_json` と `_record_startup_downtime` の頭）。
///
/// 無い・読めない・JSON でない・辞書でない・数でない（真偽は数に入る）なら `Ok(None)`。UTF-8 でなければ、Python と
/// 同じく例外（`Err`。起動のときの処理がそこで止まり、心拍もその回は書かない）。
pub fn last_seen(dir: &Path) -> Result<Option<f64>, String> {
    let Ok(bytes) = std::fs::read(dir.join(HEARTBEAT_FILE)) else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes)
        .map_err(|e| format!("UnicodeDecodeError: 心拍のファイルが UTF-8 ではありません（{e}）"))?;
    let Ok(Value::Object(heartbeat)) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    Ok(heartbeat.get("last_seen_epoch").and_then(py_number))
}

/// `_record_startup_downtime`（前の心拍からの空白が猶予を超えていれば、停止のインシデントを書く）。
pub fn record_startup_downtime(
    incidents: &Incidents,
    dir: &Path,
    now: f64,
    grace: f64,
) -> Result<(), String> {
    let Some(last_seen) = last_seen(dir)? else {
        return Ok(());
    };
    let downtime = now - last_seen;
    if downtime <= grace {
        return Ok(());
    }
    let mut metadata = Map::new();
    metadata.insert("grace_seconds".to_string(), json!(grace));
    metadata.insert("source".to_string(), json!("startup_heartbeat_gap"));
    incidents.record(NewIncident {
        kind: "downtime".to_string(),
        severity: "critical".to_string(),
        title: "管理UIダウンタイム".to_string(),
        message: "前回 heartbeat から復帰までの空白をダウンタイムとして記録しました。".to_string(),
        metadata,
        start_epoch: Some(last_seen),
        end_epoch: Some(now),
        duration_seconds: Some(downtime),
    });
    Ok(())
}

/// しきい値の警告の、最後に書いた時刻（`_LAST_ALERT_AT`。種類ごと）。
#[derive(Debug, Default)]
pub struct Alerts {
    last: Mutex<HashMap<String, f64>>,
}

impl Alerts {
    /// `_record_threshold_alerts`（CPU・メモリ・TPS の順に、割合がしきい値以上なら、間をあけて警告を書く）。
    pub fn record(
        &self,
        incidents: &Incidents,
        meters: [(&str, &Meter); 3],
        settings: &Settings,
        now: f64,
    ) {
        let thresholds = [
            settings.cpu_alert_percent,
            settings.memory_alert_percent,
            settings.tps_alert_percent,
        ];
        for ((key, meter), threshold) in meters.into_iter().zip(thresholds) {
            let percent = meter.percent;
            if percent < threshold {
                continue;
            }
            let mut metadata = Map::new();
            metadata.insert("metric".to_string(), json!(key));
            metadata.insert("percent".to_string(), json!(percent));
            metadata.insert("threshold".to_string(), json!(threshold));
            metadata.insert("detail".to_string(), json!(meter.detail));
            self.record_with_cooldown(
                incidents,
                &format!("threshold:{key}"),
                settings.alert_cooldown_seconds,
                now,
                NewIncident {
                    kind: "resource_alert".to_string(),
                    severity: "warning".to_string(),
                    title: format!("{} 使用率アラート", meter.label),
                    message: format!(
                        "{}% がしきい値 {}% を超えました。",
                        fixed(percent, 1),
                        general(threshold)
                    ),
                    metadata,
                    ..NewIncident::default()
                },
            );
        }
    }

    /// `_record_alert_with_cooldown`（前に書いてから `cooldown` 秒たっていなければ書かない。初めては 0 から数える）。
    fn record_with_cooldown(
        &self,
        incidents: &Incidents,
        key: &str,
        cooldown: f64,
        now: f64,
        incident: NewIncident,
    ) {
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            let last_at = last.get(key).copied().unwrap_or(0.0);
            if now - last_at < cooldown {
                return;
            }
            last.insert(key.to_string(), now);
        }
        incidents.record(incident);
    }
}

/// 1 回分の巡回（`_monitor_loop` の中身。測る → 心拍 → しきい値）。失敗は理由の文。
pub async fn tick(app: &AdminApp) -> Result<(), String> {
    let metrics = dashboard::collect(app)
        .await
        .map_err(|crash| format!("{}: {}", crash.kind, crash.message))?;
    let monitor = app.monitor();
    write_heartbeat(
        &app.config().monitor_dir,
        monitor.now(),
        monitor.started_at(),
        std::process::id(),
    )
    .map_err(|e| e.to_string())?;
    monitor.alerts().record(
        app.metrics().incidents(),
        [
            ("cpu", &metrics.cpu),
            ("memory", &metrics.memory),
            ("tps", &metrics.tps),
        ],
        monitor.settings(),
        monitor.now(),
    );
    Ok(())
}

/// 起動のときの処理（置き場を作る → 停止の記録 → 心拍）。`start_background_monitor` と `_monitor_loop` の頭。
pub fn startup(app: &AdminApp) {
    let dir = &app.config().monitor_dir;
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!("監視の置き場を作れません（{}）: {e}", dir.display());
    }
    let monitor = app.monitor();
    let started = record_startup_downtime(
        app.metrics().incidents(),
        dir,
        monitor.now(),
        monitor.settings().downtime_grace_seconds,
    )
    .and_then(|()| {
        write_heartbeat(dir, monitor.now(), monitor.started_at(), std::process::id())
            .map_err(|e| e.to_string())
    });
    if let Err(e) = started {
        warn!("監視の起動の処理に失敗しました: {e}");
    }
}

/// 監視の巡回を始める（起動のときの処理のあと、間隔ごとに [`tick`]）。止めるのはプロセスの終わり。
pub fn spawn(app: Arc<AdminApp>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        startup(&app);
        // 大きすぎる間隔は「ずっと待つ」にする（Python は time.sleep が OverflowError になって巡回が止まる）。
        let interval = Duration::try_from_secs_f64(app.monitor().settings().interval_seconds)
            .unwrap_or(Duration::MAX);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = tick(&app).await {
                warn!("監視の巡回の 1 回に失敗しました（次の回で続けます）: {e}");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 心拍の形が Python の json.dumps(indent=2) と同じこと。
    #[test]
    fn the_heartbeat_is_written_like_python() {
        assert_eq!(
            heartbeat_text(1_798_761_600.25, 1_798_760_000.0, 42),
            "{\n  \"last_seen_epoch\": 1798761600.25,\n  \"last_seen_at\": \"2027-01-01T00:00:00.250000+00:00\",\n  \
             \"pid\": 42,\n  \"app_started_epoch\": 1798760000.0,\n  \"app_started_at\": \"2026-12-31T23:33:20+00:00\"\n}"
        );
        let dir = tempfile::tempdir().unwrap();
        write_heartbeat(&dir.path().join("a/b"), 2.5, 1.0, 7).unwrap();
        assert_eq!(last_seen(&dir.path().join("a/b")).unwrap(), Some(2.5));
        assert!(!dir.path().join("a/b/heartbeat.json.tmp").exists());
        assert_eq!(last_seen(dir.path()).unwrap(), None);
    }
}
