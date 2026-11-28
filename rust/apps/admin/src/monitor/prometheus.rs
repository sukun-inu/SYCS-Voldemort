//! Netdata が読む `/metrics`（Prometheus のテキスト）。Python の `webapp_admin/prometheus_view.py`（接続元の判定・
//! その場で測るもの・バックアップの状態）と `services/metrics_registry.py` の `MetricsRegistry.render`（Valkey の中身 →
//! 本文）の写し。
//!
//! ■ 接続元の判定（いちばん大事）
//!
//! 見るのは **信頼するプロキシ（`TRUSTED_PROXY_CIDRS`）で直したあとの接続元**（Python の `request.client.host`。
//! uvicorn の `ProxyHeadersMiddleware` が直したもの。Rust は [`crate::app::Req::client`]）。それが
//! `METRICS_ALLOWED_CIDRS`（既定 `127.0.0.1/32,::1/128,172.16.0.0/12`）のどれかに入っていなければ 403・`Forbidden\n`。
//! **TCP の相手（nginx のコンテナ。172.16.0.0/12 の中）では判定しない。** そうすると、Cloudflare のトンネルから
//! nginx を通って来た外の利用者にも `/metrics` が見えてしまう。nginx は `X-Forwarded-For` に自分の前の相手を足すので、
//! 直したあとの接続元は、ホストの Netdata ならブリッジのゲートウェイ（許す帯域）、外からなら外の IP（許さない）になる。
//! 接続元が分からない・IP として読めないときも許さない。帯域の書き方が壊れた 1 件は捨てて、ほかを使う
//! （`ip_network(…, strict=False)`）。何が許されているかは答えに出さない。
//!
//! ■ 本文
//!
//! Valkey の `sycs:metrics:` の下（[`super::valkey`]）を鍵の順に読み、値を小数として読めないものは捨てる:
//!
//! - `hb:<アプリ>` → `sycs_up{app}`（最後の報告からの秒数が `METRICS_STALE_AFTER_SECONDS`〔既定 90〕未満なら 1）と
//!   `sycs_heartbeat_age_seconds{app}`
//! - `sycs_shared_cache_available`（Valkey を読めたか。**必ず出す**）
//! - `g:<アプリ>:<名前>` → `sycs_<名前>{app}`（ゲージ）、`c:<名前>|<ラベル>` → `sycs_<名前>{…}`（カウンタ）
//! - その場で測るもの: `sycs_admin_request_tps`・`sycs_admin_uptime_seconds`、バックアップの状態のファイル
//!   （`BACKUP_STATUS_FILE`）の置き場があれば `sycs_backup_status`、最後が成功なら `sycs_backup_age_seconds`
//!
//! 名前ごとに `# HELP`・`# TYPE` を 1 回、系列はラベルの順。値は整数なら小数点なし（[`pyfloat::format_value`]）。
//!
//! Python と同じく、既定の回数の制限（1 分 300 回。接続元とパスごと）が掛かる（Python の
//! `_register_metrics_endpoint` の説明は「掛からない」と書いているが、A1 の基準で 301 回目が 429 になった）。
//! Netdata は 10 秒ごとなので当たらない。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use sycs_web::proxy::{self, Network};

use crate::app::{AdminApp, Reply, Req};
use crate::errors::{Crash, Failure};
use crate::monitor::dashboard::py_number;
use crate::monitor::pyfloat::{self, py_max};
use crate::monitor::valkey::Scan;
use crate::python;

/// 既定の許す帯域（ループバックと Docker のブリッジ）。Python の `DEFAULT_ALLOWED_CIDRS`。
pub const DEFAULT_ALLOWED_CIDRS: &str = "127.0.0.1/32,::1/128,172.16.0.0/12";
/// 既定のパス。
pub const DEFAULT_PATH: &str = "/metrics";
/// 既定のバックアップの状態のファイル（`docker/postgres-backup.sh` が書く）。
pub const DEFAULT_BACKUP_STATUS_FILE: &str = "/backups/status.json";
/// 答えの種類（Prometheus のテキスト形式）。
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// 断るときの本文。
pub const FORBIDDEN: &[u8] = b"Forbidden\n";
/// 名前の頭（`sycs_`）。
pub const METRIC_PREFIX: &str = "sycs";

const UP_HELP: &str = "1 なら報告が届いている、0 なら止まっている";
const AGE_HELP: &str = "最後の報告からの経過秒数";
const SHARED_CACHE_HELP: &str = "共有キャッシュ（Valkey）へ書き読みできているか";
const TPS_HELP: &str = "管理画面の直近の秒間リクエスト数";
const UPTIME_HELP: &str = "管理画面のプロセスが起きてからの秒数";
const BACKUP_AGE_HELP: &str = "最後に成功した Postgres バックアップからの経過秒数";
const BACKUP_STATUS_HELP: &str = "最後の Postgres バックアップが成功していれば 1、それ以外は 0";

/// `METRICS_PATH`（`os.getenv(…, "/metrics").strip() or "/metrics"`。未設定と空白だけは既定）。
pub fn metrics_path(raw: Option<&str>) -> String {
    match raw.map(python::strip) {
        Some(path) if !path.is_empty() => path.to_string(),
        _ => DEFAULT_PATH.to_string(),
    }
}

/// `METRICS_ALLOWED_CIDRS` の値（`env_str(…, 既定) or 既定`。前後の空白を落として空なら既定）。
pub fn allowed_setting(raw: Option<&str>) -> String {
    match raw.map(python::strip) {
        Some(setting) if !setting.is_empty() => setting.to_string(),
        _ => DEFAULT_ALLOWED_CIDRS.to_string(),
    }
}

/// `allowed_networks()`（`,` で区切り、前後の空白を落とし、空は飛ばす。読めない 1 件は警告を残して捨てる）。
pub fn allowed_networks(raw: Option<&str>) -> Vec<Network> {
    let setting = allowed_setting(raw);
    let mut networks = Vec::new();
    for token in setting.split(',') {
        let token = python::strip(token);
        if token.is_empty() {
            continue;
        }
        match Network::parse_loose(token) {
            Some(network) => networks.push(network),
            None => tracing::warn!("METRICS_ALLOWED_CIDRS に読めない値があります（無視します）: {token}"),
        }
    }
    networks
}

/// `client_allowed`（直したあとの接続元が、許す帯域のどれかに入るか。分からない・読めない接続元は許さない）。
pub fn client_allowed(client: Option<&str>, allowed: &[Network]) -> bool {
    let Some(client) = client.filter(|client| !client.is_empty()) else {
        return false;
    };
    let Some(peer) = proxy::ip_address(client) else {
        return false;
    };
    allowed.iter().any(|network| network.contains(peer))
}

/// `backup_age_seconds`（状態のファイルの `result` が `ok` のときだけ、`finished_at_epoch` からの秒数。負は 0）。
/// 読めない・JSON でない・辞書でない・数でないときは `None`。
pub fn backup_age_seconds(path: &Path, now: f64) -> Option<f64> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let status = serde_json::from_str::<Value>(&text).ok()?;
    let status = status.as_object()?;
    if status.get("result").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let finished = py_number(status.get("finished_at_epoch")?)?;
    Some(py_max(0.0, now - finished))
}

/// `backup_is_configured`（状態のファイルの**置き場のディレクトリ**があるか。ファイルの有無ではない）。
pub fn backup_is_configured(path: &Path) -> bool {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new(".").is_dir(),
        Some(parent) => parent.is_dir(),
        None => path.is_dir(),
    }
}

/// その場で測る 1 つの系列（`_extra_series` の 1 件。ラベルは無い）。
#[derive(Clone, Debug, PartialEq)]
pub struct Extra {
    /// 名前（`sycs_` を付ける前）。
    pub name: &'static str,
    /// 値。
    pub value: f64,
    /// 種類（`gauge`）。
    pub kind: &'static str,
    /// 説明。
    pub help: &'static str,
}

/// `_extra_series`（秒あたりの要求の数・起きてからの秒数・バックアップの経過秒数と状態）。
pub fn extra_series(tps: f64, uptime: f64, backup_status_file: &Path, now: f64) -> Vec<Extra> {
    let gauge = |name: &'static str, value: f64, help: &'static str| Extra {
        name,
        value,
        kind: "gauge",
        help,
    };
    let mut extra = vec![
        gauge("admin_request_tps", tps, TPS_HELP),
        gauge("admin_uptime_seconds", uptime, UPTIME_HELP),
    ];
    let age = backup_age_seconds(backup_status_file, now);
    if let Some(age) = age {
        extra.push(gauge("backup_age_seconds", age, BACKUP_AGE_HELP));
    }
    if backup_is_configured(backup_status_file) {
        let status = if age.is_some() { 1.0 } else { 0.0 };
        extra.push(gauge("backup_status", status, BACKUP_STATUS_HELP));
    }
    extra
}

/// ラベル（名前の順）。
pub type Labels = BTreeMap<String, String>;

/// 1 つの名前の系列（ラベルと値。入れた順）。
type Series = Vec<(Labels, f64)>;

fn app_label(app: &str) -> Labels {
    Labels::from([("app".to_string(), app.to_string())])
}

/// `_decode_counter_key`（`名前|k=v,k=v`。`=` の無い項目・名前の空な項目は捨てる。同じ名前はあとのもの）。
pub fn decode_counter_key(key: &str) -> (String, Labels) {
    let (name, joined) = key.split_once('|').unwrap_or((key, ""));
    let mut labels = Labels::new();
    if joined.is_empty() {
        return (name.to_string(), labels);
    }
    for pair in joined.split(',') {
        if let Some((label, value)) = pair.split_once('=')
            && !label.is_empty()
        {
            labels.insert(label.to_string(), value.to_string());
        }
    }
    (name.to_string(), labels)
}

/// `_escape_label_value`（`\`・`"`・改行を逃がす）。
fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// `_format_labels`（`{k="v",…}`。空なら空）。
fn format_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape_label_value(value)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

/// `_block`（`# HELP`・`# TYPE` と、ラベルの順に並べた値の行。系列が無ければ何も足さない）。
fn block(lines: &mut Vec<String>, name: &str, kind: &str, help: &str, mut series: Series) -> Result<(), Crash> {
    if series.is_empty() {
        return Ok(());
    }
    let full = format!("{METRIC_PREFIX}_{name}");
    lines.push(format!("# HELP {full} {help}"));
    lines.push(format!("# TYPE {full} {kind}"));
    // Python は sorted(..., key=ラベルの (鍵, 値) の並び)。同じものは入れた順のまま（安定な並べ替え）。
    series.sort_by(|a, b| a.0.iter().cmp(b.0.iter()));
    for (labels, value) in series {
        lines.push(format!(
            "{full}{} {}",
            format_labels(&labels),
            pyfloat::format_value(value)?
        ));
    }
    Ok(())
}

/// `MetricsRegistry.render`（Valkey の中身・使えるか・その場で測るもの → 本文。最後に改行）。
///
/// 値に NaN・無限大があると Python は例外で 500 になるので、同じく [`Crash`] を返す。
pub fn render(scan: &Scan, now: f64, stale_after: f64, extra: &[Extra]) -> Result<String, Crash> {
    let mut up: Series = Vec::new();
    let mut age: Series = Vec::new();
    let mut gauges: BTreeMap<String, Series> = BTreeMap::new();
    let mut counters: BTreeMap<String, Series> = BTreeMap::new();
    for (key, raw) in &scan.items {
        let Some(value) = pyfloat::py_float(raw) else {
            continue;
        };
        if let Some(app) = key.strip_prefix("hb:") {
            let seconds = py_max(0.0, now - value);
            up.push((app_label(app), if seconds < stale_after { 1.0 } else { 0.0 }));
            age.push((app_label(app), seconds));
        } else if let Some(rest) = key.strip_prefix("g:") {
            let (app, name) = rest.split_once(':').unwrap_or((rest, ""));
            if !name.is_empty() {
                gauges.entry(name.to_string()).or_default().push((app_label(app), value));
            }
        } else if let Some(rest) = key.strip_prefix("c:") {
            let (name, labels) = decode_counter_key(rest);
            counters.entry(name).or_default().push((labels, value));
        }
    }
    let mut lines = Vec::new();
    if !up.is_empty() {
        block(&mut lines, "up", "gauge", UP_HELP, up)?;
        block(&mut lines, "heartbeat_age_seconds", "gauge", AGE_HELP, age)?;
    }
    let available = if scan.available { 1.0 } else { 0.0 };
    block(
        &mut lines,
        "shared_cache_available",
        "gauge",
        SHARED_CACHE_HELP,
        vec![(Labels::new(), available)],
    )?;
    for (name, series) in gauges {
        let help = format!("{name}（各アプリが報告した瞬間値）");
        block(&mut lines, &name, "gauge", &help, series)?;
    }
    for (name, series) in counters {
        let help = format!("{name}（累積）");
        block(&mut lines, &name, "counter", &help, series)?;
    }
    for series in extra {
        block(
            &mut lines,
            series.name,
            series.kind,
            series.help,
            vec![(Labels::new(), series.value)],
        )?;
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// `GET /metrics`（`render_metrics`）。許さない接続元には 403、許すなら本文。
pub async fn metrics_endpoint(app: Arc<AdminApp>, req: Req) -> Result<Reply, Failure> {
    let monitor = Arc::clone(app.monitor());
    let settings = monitor.settings();
    if !client_allowed(req.client.as_deref(), &settings.allowed) {
        return Ok(Reply::new(
            403,
            Some("text/plain; charset=utf-8"),
            FORBIDDEN.to_vec(),
        ));
    }
    let now = monitor.now();
    let extra = extra_series(
        app.metrics().request_tps(now),
        py_max(0.0, now - monitor.started_at()),
        &settings.backup_status_file,
        now,
    );
    let scan = monitor.store().scan().await;
    let body = render(&scan, now, settings.stale_after_seconds, &extra)?;
    Ok(Reply::new(200, Some(CONTENT_TYPE), body.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 説明の文と既定の値が Python のファイルと同じこと（基準の本文でも確かめるが、ここで先に気づく）。
    #[test]
    fn help_texts_match_python() {
        let view = include_str!("../../../../../webapp_admin/prometheus_view.py");
        let registry = include_str!("../../../../../services/metrics_registry.py");
        for text in [TPS_HELP, UPTIME_HELP, BACKUP_AGE_HELP, BACKUP_STATUS_HELP] {
            assert!(view.contains(&format!("\"{text}\"")), "{text}");
        }
        for text in [UP_HELP, AGE_HELP, SHARED_CACHE_HELP] {
            assert!(registry.contains(&format!("\"{text}\"")), "{text}");
        }
        assert!(view.contains(&format!("DEFAULT_ALLOWED_CIDRS = \"{DEFAULT_ALLOWED_CIDRS}\"")));
        assert!(view.contains(&format!("CONTENT_TYPE = \"{CONTENT_TYPE}\"")));
    }

    /// 直したあとの接続元で判定し、読めない接続元と、読めない帯域は使わないこと。
    #[test]
    fn clients_are_checked_against_the_allowed_networks() {
        let allowed = allowed_networks(None);
        assert!(client_allowed(Some("127.0.0.1"), &allowed));
        assert!(client_allowed(Some("172.17.0.1"), &allowed));
        assert!(!client_allowed(Some("203.0.113.5"), &allowed));
        assert!(!client_allowed(Some("testclient"), &allowed));
        assert!(!client_allowed(None, &allowed));
        assert!(!client_allowed(Some(""), &allowed));
        let custom = allowed_networks(Some(" nonsense , 10.0.0.1/8 ,, "));
        assert_eq!(custom.len(), 1);
        assert!(client_allowed(Some("10.9.9.9"), &custom));
        assert_eq!(allowed_networks(Some("   ")).len(), 3);
        assert!(allowed_networks(Some("nonsense")).is_empty());
    }

    /// 本文の並び（心拍 → 使えるか → ゲージ → カウンタ → その場で測るもの）と、ラベルの逃がし方。
    #[test]
    fn the_body_is_rendered_like_the_registry() {
        let items = [
            ("hb:bot", "990"),
            ("g:bot:guilds", "7"),
            ("c:requests_total|app=a\"b", "3"),
            ("c:events", "2.5"),
            ("x:ignored", "1"),
            ("g:admin", "1"),
            ("hb:web", "abc"),
        ];
        let scan = Scan {
            items: items
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            available: true,
        };
        let body = render(&scan, 1000.0, 90.0, &[]).unwrap();
        assert_eq!(
            body,
            "# HELP sycs_up 1 なら報告が届いている、0 なら止まっている\n# TYPE sycs_up gauge\nsycs_up{app=\"bot\"} 1\n\
             # HELP sycs_heartbeat_age_seconds 最後の報告からの経過秒数\n# TYPE sycs_heartbeat_age_seconds gauge\n\
             sycs_heartbeat_age_seconds{app=\"bot\"} 10\n\
             # HELP sycs_shared_cache_available 共有キャッシュ（Valkey）へ書き読みできているか\n\
             # TYPE sycs_shared_cache_available gauge\nsycs_shared_cache_available 1\n\
             # HELP sycs_guilds guilds（各アプリが報告した瞬間値）\n# TYPE sycs_guilds gauge\nsycs_guilds{app=\"bot\"} 7\n\
             # HELP sycs_events events（累積）\n# TYPE sycs_events counter\nsycs_events 2.5\n\
             # HELP sycs_requests_total requests_total（累積）\n# TYPE sycs_requests_total counter\n\
             sycs_requests_total{app=\"a\\\"b\"} 3\n"
        );
    }
}
