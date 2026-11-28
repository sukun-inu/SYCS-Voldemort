//! リクエストの数え方。Python の `webapp_admin/metrics.py` と同じ名前・同じラベルの数を、`sycs_core::metrics` 越しに
//! Valkey へ流す（管理画面の `/metrics` が出し、Netdata が読む）。
//!
//! | 数 | ラベル | Python |
//! |---|---|---|
//! | `requests_total` | `app` | `record_request`（`/static` 以外の全部） |
//! | `http_responses_total` | `app`・`code` | `record_error_response`（4xx も数える） |
//! | `exceptions_total` | `app`・`type` | `record_exception`（拾えなかった例外。型の名前ごと） |
//!
//! 数えるのはプロセスの中に溜めるだけで、Valkey へは [`spawn_reporter`] の背景のループがまとめて送る
//! （数えるためにリクエストを遅くしない。Python の `services/metrics_reporter.py` と同じ）。
//!
//! Python と違うところ: 5xx のインシデント（管理画面の `incidents.jsonl`）は書かない。あれは管理画面のプロセスの
//! 持ち物で、ほかのプロセスが同じファイルへ書くと、管理画面の切り詰めと競り合う。数とログには残る。

use std::sync::Arc;
use std::time::Duration;

use sycs_core::env::Env;
use sycs_core::metrics::{Labels, Reporter};

/// 報告の間隔の既定（秒）。Python の `METRICS_REPORT_INTERVAL_SECONDS` の既定と同じ。
pub const DEFAULT_REPORT_INTERVAL_SECONDS: f64 = 30.0;

/// 1 つのアプリの、リクエストの数え口。
pub struct HttpMetrics {
    app: String,
    reporter: Arc<Reporter>,
}

impl HttpMetrics {
    /// 作る。`app` は数のラベル（`app="cdn"` など）。
    pub fn new(app: &str, reporter: Arc<Reporter>) -> Self {
        Self {
            app: app.to_string(),
            reporter,
        }
    }

    /// 数を溜めている報告口（テストで中身を見る・背景のループに渡す）。
    pub fn reporter(&self) -> &Arc<Reporter> {
        &self.reporter
    }

    /// 1 件のリクエスト。Python の `record_request`（`requests_total{app}`）。
    pub fn record_request(&self) {
        self.add("requests_total", &[]);
    }

    /// 応答の状態。Python の `record_error_response`（`http_responses_total{app, code}`。4xx も数える）。
    pub fn record_response(&self, status: u16) {
        self.add("http_responses_total", &[("code", status.to_string())]);
    }

    /// 拾えなかった例外。Python の `record_exception`（`exceptions_total{app, type}`。型の名前は Python の例外の名前に揃える）。
    pub fn record_exception(&self, kind: &str) {
        self.add("exceptions_total", &[("type", kind.to_string())]);
    }

    fn add(&self, name: &str, extra: &[(&str, String)]) {
        let mut labels = Labels::new();
        labels.insert("app".to_string(), self.app.clone());
        for (key, value) in extra {
            labels.insert((*key).to_string(), value.clone());
        }
        self.reporter.counters().add(name, &labels, 1);
    }
}

/// 報告の間隔（`METRICS_REPORT_INTERVAL_SECONDS`。既定 30 秒・下限 1 秒。Python と同じ）。
pub fn report_interval(env: &Env) -> Duration {
    Duration::from_secs_f64(env.float(
        "METRICS_REPORT_INTERVAL_SECONDS",
        DEFAULT_REPORT_INTERVAL_SECONDS,
        Some(1.0),
        None,
    ))
}

/// 心拍と溜まった数を、`interval` ごとに Valkey へ送る背景のループを始める（ゲージは無い）。
///
/// `VALKEY_URL` が無ければ何もしない報告口なので、ループは回るが何も送らない（`sycs_core::metrics` の作り）。
pub fn spawn_reporter(reporter: Arc<Reporter>, interval: Duration) {
    tokio::spawn(async move { reporter.report_forever(interval, Vec::new).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 数の名前とラベルが、Python の管理画面と同じ形で溜まること（`/metrics` で同じ系列に並ぶように）。
    #[test]
    fn counts_use_the_python_names_and_labels() {
        let reporter = Arc::new(Reporter::new("cdn", None));
        let metrics = HttpMetrics::new("cdn", Arc::clone(&reporter));
        metrics.record_request();
        metrics.record_response(410);
        metrics.record_exception("IsADirectoryError");
        let labels = |pairs: &[(&str, &str)]| -> Labels {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };
        let mut drained = reporter.counters().drain();
        drained.sort();
        assert_eq!(
            drained,
            vec![
                (
                    "exceptions_total".to_string(),
                    labels(&[("app", "cdn"), ("type", "IsADirectoryError")]),
                    1
                ),
                (
                    "http_responses_total".to_string(),
                    labels(&[("app", "cdn"), ("code", "410")]),
                    1
                ),
                ("requests_total".to_string(), labels(&[("app", "cdn")]), 1),
            ]
        );
    }

    /// 間隔は既定 30 秒、1 秒より短くはしないこと。
    #[test]
    fn the_interval_has_a_floor() {
        let env = Env::from_fn(|key| {
            (key == "METRICS_REPORT_INTERVAL_SECONDS").then(|| "0.2".to_string())
        });
        assert_eq!(report_interval(&env), Duration::from_secs(1));
        assert_eq!(
            report_interval(&Env::from_fn(|_| None)),
            Duration::from_secs(30)
        );
    }
}
