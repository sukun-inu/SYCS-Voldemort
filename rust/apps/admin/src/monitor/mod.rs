//! 監視（A7）。Python の `webapp_admin/metrics.py`（ホストの測り方・インシデント・SLA・監視の巡回）と
//! `webapp_admin/prometheus_view.py`（Netdata が読む `/metrics`）と、`views/dashboard_views.py` の 2 本の API。
//!
//! | 経路 | 権限 | 中身 |
//! |---|---|---|
//! | `GET /admin/api/metrics` | サーバーを選んでいる | CPU（0.1 秒で測る）・メモリ・TPS・SLA と、起きてからの長さ（[`dashboard`]） |
//! | `GET /admin/api/incidents` | サーバーを選んでいる | 直近 30 件のインシデント（[`dashboard::list_incidents`]） |
//! | `GET /metrics`（`METRICS_PATH`） | 接続元で絞る | Prometheus のテキスト（[`prometheus`]。Valkey の中身は [`valkey`]） |
//!
//! - 監視の巡回（心拍・停止・しきい値）は [`watch`]。インシデントの書き手は A1 の [`crate::metrics::Incidents`]
//!   （`incidents.jsonl`。Python と同じファイル・同じ形）
//! - ホストの読み方は [`host`]（psutil の写し）、Python の小数の書き方は [`pyfloat`]
//! - メトリクスの報告（`hb:admin` と要求の数）は A1 が `main.rs` で始めている（`sycs_web::metrics::spawn_reporter`。
//!   Python の `report_forever("admin")` と同じく、ゲージは無い）
//!
//! 設定（環境変数）は起動のときに 1 回だけ読む（Python は要求のたびに読むが、プロセスの中で変わらない）。

pub mod dashboard;
pub mod host;
pub mod prometheus;
pub mod pyfloat;
pub mod valkey;
pub mod watch;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::Method;
use serde_json::json;
use sycs_core::env::Env;
use sycs_web::proxy::Network;

use crate::app::{AdminApp, Reply, Req, handler};
use crate::errors::Failure;
use crate::metrics::{Clock, INCIDENTS_FILE};
use crate::routing::Route;
use host::{HostProbe, ProcFs};
use valkey::{MetricsStore, Unconfigured, ValkeyStore};

/// 監視の設定（Python が `env_float` などで読む値。既定と下限も Python と同じ）。
#[derive(Clone, Debug)]
pub struct Settings {
    /// `ADMIN_TPS_TARGET`（既定 50、下限 0.01）。TPS の目盛りの 100%。
    pub tps_target: f64,
    /// `ADMIN_CPU_ALERT_PERCENT`（既定 90）。
    pub cpu_alert_percent: f64,
    /// `ADMIN_MEMORY_ALERT_PERCENT`（既定 90）。
    pub memory_alert_percent: f64,
    /// `ADMIN_TPS_ALERT_PERCENT`（既定 100）。
    pub tps_alert_percent: f64,
    /// `ADMIN_MONITOR_INTERVAL_SECONDS`（既定 30、下限 5）。
    pub interval_seconds: f64,
    /// `ADMIN_DOWNTIME_GRACE_SECONDS`（既定 120、下限 1）。
    pub downtime_grace_seconds: f64,
    /// `ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS`（既定 300、下限 0）。
    pub alert_cooldown_seconds: f64,
    /// `METRICS_ALLOWED_CIDRS`（読めた帯域だけ）。
    pub allowed: Vec<Network>,
    /// `METRICS_STALE_AFTER_SECONDS`（既定 90、下限 5）。
    pub stale_after_seconds: f64,
    /// `BACKUP_STATUS_FILE`（既定 `/backups/status.json`）。
    pub backup_status_file: PathBuf,
}

impl Settings {
    /// 引き方を渡して読む（テストは例の環境変数を渡す）。
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String> + Clone + Send + Sync + 'static,
    {
        let env = Env::from_fn(lookup.clone());
        Self {
            tps_target: env.float("ADMIN_TPS_TARGET", 50.0, Some(0.01), None),
            cpu_alert_percent: env.float("ADMIN_CPU_ALERT_PERCENT", 90.0, None, None),
            memory_alert_percent: env.float("ADMIN_MEMORY_ALERT_PERCENT", 90.0, None, None),
            tps_alert_percent: env.float("ADMIN_TPS_ALERT_PERCENT", 100.0, None, None),
            interval_seconds: env.float("ADMIN_MONITOR_INTERVAL_SECONDS", 30.0, Some(5.0), None),
            downtime_grace_seconds: env.float(
                "ADMIN_DOWNTIME_GRACE_SECONDS",
                120.0,
                Some(1.0),
                None,
            ),
            alert_cooldown_seconds: env.float(
                "ADMIN_MONITOR_ALERT_COOLDOWN_SECONDS",
                300.0,
                Some(0.0),
                None,
            ),
            allowed: prometheus::allowed_networks(lookup("METRICS_ALLOWED_CIDRS").as_deref()),
            stale_after_seconds: env
                .float("METRICS_STALE_AFTER_SECONDS", 90.0, Some(5.0), None)
                .max(1.0),
            backup_status_file: env
                .path("BACKUP_STATUS_FILE", prometheus::DEFAULT_BACKUP_STATUS_FILE),
        }
    }

    /// このプロセスの環境変数から読む。
    pub fn from_process() -> Self {
        Self::from_lookup(|key: &str| std::env::var(key).ok())
    }
}

impl Default for Settings {
    /// 環境変数を何も設定していないときの値。
    fn default() -> Self {
        Self::from_lookup(|_: &str| None)
    }
}

/// 監視が使うもの（設定・ホストの測り口・Valkey の読み口・時計・起きた時刻・警告の間隔）。
pub struct Monitor {
    settings: Settings,
    host: Arc<dyn HostProbe>,
    store: Arc<dyn MetricsStore>,
    clock: Clock,
    started_at: f64,
    alerts: watch::Alerts,
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor")
            .field("settings", &self.settings)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

impl Monitor {
    /// 作る。起きた時刻（Python の `_APP_STARTED_AT`）は、いまの時刻にする。
    pub fn new(
        settings: Settings,
        host: Arc<dyn HostProbe>,
        store: Arc<dyn MetricsStore>,
        clock: Clock,
    ) -> Self {
        let started_at = clock();
        Self {
            settings,
            host,
            store,
            clock,
            started_at,
            alerts: watch::Alerts::default(),
        }
    }

    /// 起きた時刻を決める（テスト用）。
    pub fn with_started_at(mut self, started_at: f64) -> Self {
        self.started_at = started_at;
        self
    }

    /// 環境変数から作る（このホストの `/proc` と、`VALKEY_URL` の Valkey）。
    pub fn from_env(env: &Env, clock: Clock) -> Self {
        Self::new(
            Settings::from_process(),
            Arc::new(ProcFs::system()),
            Arc::new(ValkeyStore::from_env(env)),
            clock,
        )
    }

    /// つなぎ先の無いもの（既定の設定・このホストの `/proc`・Valkey なし）。[`crate::app::AdminApp::new`] の既定。
    pub fn unconfigured(clock: Clock) -> Self {
        Self::new(
            Settings::default(),
            Arc::new(ProcFs::system()),
            Arc::new(Unconfigured),
            clock,
        )
    }

    /// 設定。
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// ホストの測り口。
    pub fn host(&self) -> &dyn HostProbe {
        self.host.as_ref()
    }

    /// Valkey の読み口。
    pub fn store(&self) -> &dyn MetricsStore {
        self.store.as_ref()
    }

    /// いまの時刻（UNIX 時間の秒）。
    pub fn now(&self) -> f64 {
        (self.clock)()
    }

    /// プロセスが起きた時刻。
    pub fn started_at(&self) -> f64 {
        self.started_at
    }

    /// しきい値の警告の間隔の控え。
    pub fn alerts(&self) -> &watch::Alerts {
        &self.alerts
    }
}

/// `views/dashboard_views.py` の 2 本（`/admin` の下のルーター。既定の回数の制限は掛からない）。
pub fn dashboard_routes() -> Vec<Route> {
    let get = [Method::GET];
    vec![
        Route::new("/admin/api/metrics", &get, handler(system_metrics)),
        Route::new("/admin/api/incidents", &get, handler(monitor_incidents)),
    ]
}

/// `/metrics`（`_register_metrics_endpoint`。app に直に足した経路なので、既定の 1 分 300 回が掛かる）。パスは
/// `METRICS_PATH`（Python と同じく、経路を組むときに 1 回読む）。
pub fn metrics_routes() -> Vec<Route> {
    let path = prometheus::metrics_path(std::env::var("METRICS_PATH").ok().as_deref());
    vec![Route::top_level(
        &path,
        &[Method::GET],
        handler(prometheus::metrics_endpoint),
    )]
}

/// `GET /admin/api/metrics`（`system_metrics`）。
async fn system_metrics(app: Arc<AdminApp>, req: Req) -> Result<Reply, Failure> {
    req.check_guild()?;
    let metrics = dashboard::collect(&app).await?;
    Ok(Reply::json(200, &metrics.to_json()))
}

/// `GET /admin/api/incidents`（`monitor_incidents`。直近 30 件）。
async fn monitor_incidents(app: Arc<AdminApp>, req: Req) -> Result<Reply, Failure> {
    req.check_guild()?;
    let text = dashboard::read_incidents(&app.config().monitor_dir.join(INCIDENTS_FILE))?;
    let incidents = text
        .as_deref()
        .map(|text| dashboard::list_incidents(text, dashboard::INCIDENT_LIMIT))
        .unwrap_or_default();
    Ok(Reply::json(200, &json!({ "incidents": incidents })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 環境変数の既定と下限が Python と同じこと。
    #[test]
    fn settings_use_the_python_defaults() {
        let defaults = Settings::default();
        assert_eq!(defaults.tps_target, 50.0);
        assert_eq!(defaults.interval_seconds, 30.0);
        assert_eq!(defaults.downtime_grace_seconds, 120.0);
        assert_eq!(defaults.alert_cooldown_seconds, 300.0);
        assert_eq!(defaults.stale_after_seconds, 90.0);
        assert_eq!(defaults.allowed.len(), 3);
        assert_eq!(
            defaults.backup_status_file,
            PathBuf::from("/backups/status.json")
        );
        let low = Settings::from_lookup(|key: &str| match key {
            "ADMIN_TPS_TARGET" => Some("0".to_string()),
            "ADMIN_MONITOR_INTERVAL_SECONDS" => Some("1".to_string()),
            "METRICS_STALE_AFTER_SECONDS" => Some("2".to_string()),
            _ => None,
        });
        assert_eq!(low.tps_target, 0.01);
        assert_eq!(low.interval_seconds, 5.0);
        assert_eq!(low.stale_after_seconds, 5.0);
    }
}
