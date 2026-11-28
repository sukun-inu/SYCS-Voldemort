//! 要求の数と、5xx・拾えなかった例外のインシデント。Python の `webapp_admin/metrics.py` の `record_request`・
//! `record_error_response`・`record_exception`・`record_incident`（と `_append_jsonl`・`_trim_jsonl`）。
//!
//! - 数は `sycs_web::metrics::HttpMetrics`（`requests_total{app="admin"}`・`http_responses_total{app,code}`・
//!   `exceptions_total{app,type}`。Valkey へは背景のループが送る）
//! - 秒あたりの要求の数（TPS）のために、直近 60 秒の要求の時刻を持つ（`/admin/api/metrics` と `/metrics` は A7）
//! - インシデントは `incidents.jsonl`（`ADMIN_MONITOR_DIR`、無ければ `SETTINGS_DIR/admin_monitor`）。**Python と
//!   同じファイルを同じ形で書く**（切り替えても SLA の履歴が続くように）。1 行は
//!   `json.dumps(ensure_ascii=False, separators=(",", ":"))` で、鍵の順も Python と同じ
//!
//! Python と違うところ: インシデントを書けないとき（置き場に書けない・ファイルが UTF-8 でない）、Python は例外が
//! 層の外まで抜けて素の 500 になるが、Rust は警告を残して答えはそのまま返す。

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use chrono::DateTime;
use serde_json::{Map, Value, json};
use sycs_core::metrics::Reporter;
use sycs_web::metrics::HttpMetrics;
use tracing::warn;

use crate::errors::Crash;
use crate::python;

/// 要求の時刻を持つ長さ（秒）。Python の `_REQUEST_HISTORY_SECONDS`。
pub const HISTORY_SECONDS: f64 = 60.0;
/// TPS を測る窓（秒）。Python の `_TPS_WINDOW_SECONDS`。
pub const TPS_WINDOW_SECONDS: f64 = 15.0;
/// インシデントの行の上限。
pub const INCIDENT_MAX_LINES: usize = 2000;
/// これを超えたときだけ行を数えに行く（バイト）。
pub const INCIDENT_TRIM_BYTES: u64 = 512 * 1024;
/// インシデントのファイルの名前。
pub const INCIDENTS_FILE: &str = "incidents.jsonl";

/// 監視の置き場。Python の `_monitor_dir`（`ADMIN_MONITOR_DIR` > `SETTINGS_DIR/admin_monitor` > 既定）。
///
/// Python はここだけ `os.getenv` で読む（空白を落とさず、空の文字も「設定してある」とみなす）。同じにする。
pub fn monitor_dir(lookup: impl Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(dir) = lookup("ADMIN_MONITOR_DIR") {
        return PathBuf::from(dir);
    }
    let settings = lookup("SETTINGS_DIR").unwrap_or_else(|| "/app/data".to_string());
    PathBuf::from(settings).join("admin_monitor")
}

/// UTC の ISO 8601。Python の `datetime.fromtimestamp(epoch, timezone.utc).isoformat()`（マイクロ秒は偶数への丸め。
/// 0 なら書かない）。
pub fn iso(epoch: f64) -> String {
    let whole = epoch.trunc();
    let mut micros = ((epoch - whole) * 1e6).round_ties_even();
    let mut seconds = whole;
    if micros >= 1e6 {
        micros -= 1e6;
        seconds += 1.0;
    } else if micros < 0.0 {
        micros += 1e6;
        seconds -= 1.0;
    }
    let seconds = seconds as i64;
    let micros = micros as u32;
    let Some(when) = DateTime::from_timestamp(seconds, 0) else {
        return String::new();
    };
    let base = when.format("%Y-%m-%dT%H:%M:%S");
    if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    }
}

/// インシデントに添える要求の素性。Python の `_request_snapshot`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// メソッド。
    pub method: String,
    /// `request.url.path`。
    pub path: String,
    /// `CF-Connecting-IP`（空でなければ）か、直したあとの接続元か `unknown`。
    pub remote_addr: String,
}

impl Snapshot {
    /// `{"method", "path", "endpoint": null, "remote_addr"}`。
    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("method".to_string(), json!(self.method));
        map.insert("path".to_string(), json!(self.path));
        map.insert("endpoint".to_string(), Value::Null);
        map.insert("remote_addr".to_string(), json!(self.remote_addr));
        map
    }
}

/// 書くインシデント（`record_incident` の引数）。
#[derive(Clone, Debug, Default)]
pub struct NewIncident {
    /// 種類（`http_error`・`exception`・`downtime`・`resource_alert`）。
    pub kind: String,
    /// 重さ（`critical`・`warning`）。
    pub severity: String,
    /// 見出し。
    pub title: String,
    /// 文。
    pub message: String,
    /// 添えるもの（鍵の順のまま書く）。
    pub metadata: Map<String, Value>,
    /// 始まり（UNIX 時間の秒）。
    pub start_epoch: Option<f64>,
    /// 終わり。
    pub end_epoch: Option<f64>,
    /// 長さ（秒。小数 3 桁に丸める）。
    pub duration_seconds: Option<f64>,
}

/// 時刻を返すもの（UNIX 時間の秒）。
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;
/// インシデントの ID を作るもの（Python の `uuid.uuid4().hex`）。
pub type IdSource = Arc<dyn Fn() -> String + Send + Sync>;

/// `incidents.jsonl` の書き手。
pub struct Incidents {
    dir: PathBuf,
    clock: Clock,
    ids: IdSource,
    lock: Mutex<()>,
}

impl std::fmt::Debug for Incidents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incidents")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

fn epoch_value(epoch: Option<f64>) -> Value {
    epoch.map_or(Value::Null, |x| json!(x))
}

impl Incidents {
    /// 作る（`dir` は [`monitor_dir`]）。
    pub fn new(dir: PathBuf, clock: Clock, ids: IdSource) -> Self {
        Self {
            dir,
            clock,
            ids,
            lock: Mutex::new(()),
        }
    }

    /// ファイルの場所。
    pub fn file(&self) -> PathBuf {
        self.dir.join(INCIDENTS_FILE)
    }

    /// 1 件を書く。Python の `record_incident`（書いた行の中身を返す）。
    pub fn record(&self, incident: NewIncident) -> Value {
        let now = (self.clock)();
        let mut map = Map::new();
        map.insert("id".to_string(), json!((self.ids)()));
        map.insert("kind".to_string(), json!(incident.kind));
        map.insert("severity".to_string(), json!(incident.severity));
        map.insert("title".to_string(), json!(incident.title));
        map.insert("message".to_string(), json!(incident.message));
        map.insert("created_epoch".to_string(), json!(now));
        map.insert("created_at".to_string(), json!(iso(now)));
        map.insert("start_epoch".to_string(), epoch_value(incident.start_epoch));
        // Python は `_iso(start_epoch) if start_epoch else None`（0 も無いものとみなす）。
        let at = |epoch: Option<f64>| {
            epoch
                .filter(|x| *x != 0.0)
                .map_or(Value::Null, |x| json!(iso(x)))
        };
        map.insert("start_at".to_string(), at(incident.start_epoch));
        map.insert("end_epoch".to_string(), epoch_value(incident.end_epoch));
        map.insert("end_at".to_string(), at(incident.end_epoch));
        map.insert(
            "duration_seconds".to_string(),
            epoch_value(incident.duration_seconds.map(|d| (d * 1000.0).round_ties_even() / 1000.0)),
        );
        map.insert("metadata".to_string(), Value::Object(incident.metadata));
        let value = Value::Object(map);
        let line = python::dumps(&value, python::COMPACT);
        if let Err(e) = self.append(&line) {
            warn!("インシデントを書けませんでした（{}）: {e}", self.file().display());
        }
        value
    }

    fn append(&self, line: &str) -> std::io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        fs::create_dir_all(&self.dir)?;
        let path = self.file();
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(format!("{line}\n").as_bytes())?;
        drop(file);
        trim(&path);
        Ok(())
    }
}

/// 行の上限を超えたら古い行から捨てる。Python の `_trim_jsonl`（512KB を超えたときだけ数え、`str.splitlines()` で
/// 割って最後の 2000 行を `.tmp` に書いて入れ替える。読めない・書けないときは何もしない）。
fn trim(path: &Path) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if metadata.len() <= INCIDENT_TRIM_BYTES {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let lines = python::splitlines(&text);
    if lines.len() <= INCIDENT_MAX_LINES {
        return;
    }
    let kept = &lines[lines.len() - INCIDENT_MAX_LINES..];
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let tmp = PathBuf::from(name);
    let body = format!("{}\n", kept.join("\n"));
    if fs::write(&tmp, body).is_ok() {
        let _ = fs::rename(&tmp, path);
    }
}

/// 管理画面の数え口（数・TPS の時刻・インシデント）。
pub struct AdminMetrics {
    http: HttpMetrics,
    recent: Mutex<VecDeque<f64>>,
    incidents: Incidents,
}

impl std::fmt::Debug for AdminMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminMetrics")
            .field("incidents", &self.incidents)
            .finish_non_exhaustive()
    }
}

impl AdminMetrics {
    /// 作る。
    pub fn new(reporter: Arc<Reporter>, incidents: Incidents) -> Self {
        Self {
            http: HttpMetrics::new(crate::APP_NAME, reporter),
            recent: Mutex::new(VecDeque::new()),
            incidents,
        }
    }

    /// 数（テストで中身を見る・背景のループに渡す）。
    pub fn http(&self) -> &HttpMetrics {
        &self.http
    }

    /// インシデントの書き手。
    pub fn incidents(&self) -> &Incidents {
        &self.incidents
    }

    /// 1 件の要求。Python の `record_request`（`/static` 以外の全部）。
    pub fn record_request(&self, now: f64) {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent.push_back(now);
        prune(&mut recent, now);
        drop(recent);
        self.http.record_request();
    }

    /// 応答の状態。Python の `record_error_response`（4xx も数え、5xx はインシデントにする）。
    pub fn record_response(&self, status: u16, snapshot: &Snapshot) {
        self.http.record_response(status);
        if status < 500 {
            return;
        }
        let mut metadata = Map::new();
        metadata.insert("status_code".to_string(), json!(status));
        metadata.extend(snapshot.to_map());
        self.incidents.record(NewIncident {
            kind: "http_error".to_string(),
            severity: "critical".to_string(),
            title: format!("HTTP {status}"),
            message: "管理UIで 5xx レスポンスが発生しました。".to_string(),
            metadata,
            ..NewIncident::default()
        });
    }

    /// 拾えなかった例外。Python の `record_exception`（文は 500 文字で切り、空なら `Unhandled exception`）。
    pub fn record_exception(&self, crash: &Crash, snapshot: &Snapshot) {
        self.http.record_exception(&crash.kind);
        let message: String = crash.message.chars().take(500).collect();
        self.incidents.record(NewIncident {
            kind: "exception".to_string(),
            severity: "critical".to_string(),
            title: crash.kind.clone(),
            message: if message.is_empty() {
                "Unhandled exception".to_string()
            } else {
                message
            },
            metadata: snapshot.to_map(),
            ..NewIncident::default()
        });
    }

    /// 直近 15 秒の平均の要求の数（秒あたり）。Python の `_request_tps`。
    pub fn request_tps(&self, now: f64) -> f64 {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        prune(&mut recent, now);
        let start = now - TPS_WINDOW_SECONDS;
        let count = recent.iter().filter(|t| **t >= start).count();
        count as f64 / TPS_WINDOW_SECONDS
    }
}

/// 60 秒より古い時刻を先頭から捨てる（`_prune_requests`）。
fn prune(recent: &mut VecDeque<f64>, now: f64) {
    let cutoff = now - HISTORY_SECONDS;
    while recent.front().is_some_and(|t| *t < cutoff) {
        recent.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incidents(dir: &Path) -> Incidents {
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Incidents::new(
            dir.to_path_buf(),
            Arc::new(|| 1_798_761_600.25),
            Arc::new(move || {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                format!("{:032x}", 0x1d00_0000_u64 + n)
            }),
        )
    }

    /// 時刻の書き方が Python の isoformat と同じこと（マイクロ秒が 0 なら書かない）。
    #[test]
    fn times_are_written_like_isoformat() {
        assert_eq!(iso(1_798_761_600.0), "2027-01-01T00:00:00+00:00");
        assert_eq!(iso(1_798_761_600.25), "2027-01-01T00:00:00.250000+00:00");
        assert_eq!(iso(0.000_000_5), "1970-01-01T00:00:00+00:00");
    }

    /// 5xx と例外のインシデントの行が、Python と同じ鍵の順・同じ書き方になること。
    #[test]
    fn incidents_are_written_like_python() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = AdminMetrics::new(Arc::new(Reporter::new("test", None)), incidents(dir.path()));
        let snapshot = Snapshot {
            method: "GET".to_string(),
            path: "/x".to_string(),
            remote_addr: "testclient".to_string(),
        };
        metrics.record_response(404, &snapshot);
        metrics.record_response(503, &snapshot);
        metrics.record_exception(&Crash::new("RuntimeError", ""), &snapshot);
        let text = std::fs::read_to_string(dir.path().join(INCIDENTS_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "{\"id\":\"0000000000000000000000001d000001\",\"kind\":\"http_error\",\"severity\":\"critical\",\
             \"title\":\"HTTP 503\",\"message\":\"管理UIで 5xx レスポンスが発生しました。\",\
             \"created_epoch\":1798761600.25,\"created_at\":\"2027-01-01T00:00:00.250000+00:00\",\
             \"start_epoch\":null,\"start_at\":null,\"end_epoch\":null,\"end_at\":null,\"duration_seconds\":null,\
             \"metadata\":{\"status_code\":503,\"method\":\"GET\",\"path\":\"/x\",\"endpoint\":null,\
             \"remote_addr\":\"testclient\"}}"
        );
        assert!(lines[1].contains("\"title\":\"RuntimeError\",\"message\":\"Unhandled exception\""));
    }

    /// 2000 行を超え、512KB を超えたら、最後の 2000 行だけを残すこと。
    #[test]
    fn the_file_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INCIDENTS_FILE);
        let line = "x".repeat(300);
        std::fs::write(&path, format!("{line}\n").repeat(2100)).unwrap();
        trim(&path);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), INCIDENT_MAX_LINES);
        assert!(text.ends_with(&format!("{line}\n")));
    }

    /// 置き場は ADMIN_MONITOR_DIR が先で、空の文字もそのまま使うこと。
    #[test]
    fn the_monitor_dir_is_read_like_python() {
        let both = |key: &str| match key {
            "ADMIN_MONITOR_DIR" => Some("/m".to_string()),
            "SETTINGS_DIR" => Some("/s".to_string()),
            _ => None,
        };
        assert_eq!(monitor_dir(both), PathBuf::from("/m"));
        assert_eq!(
            monitor_dir(|key| (key == "SETTINGS_DIR").then(|| "/s".to_string())),
            PathBuf::from("/s/admin_monitor")
        );
        assert_eq!(monitor_dir(|_| None), PathBuf::from("/app/data/admin_monitor"));
        assert_eq!(
            monitor_dir(|key| (key == "ADMIN_MONITOR_DIR").then(String::new)),
            PathBuf::new()
        );
    }

    /// TPS は直近 15 秒の数を 15 で割ること。
    #[test]
    fn tps_counts_the_last_fifteen_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = AdminMetrics::new(Arc::new(Reporter::new("test", None)), incidents(dir.path()));
        for t in [100.0, 130.0, 140.0, 144.0] {
            metrics.record_request(t);
        }
        assert!((metrics.request_tps(145.0) - 3.0 / 15.0).abs() < 1e-12);
    }
}
