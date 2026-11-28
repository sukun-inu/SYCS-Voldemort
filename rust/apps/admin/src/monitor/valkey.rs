//! `/metrics` が Valkey から読むもの。Python の `services/shared_cache.py` の `scan_values`（と `available`、
//! 遮断器）の写し。全プロセス（Python と Rust の Bot・Web・配信・管理画面）が `sycs:metrics:` の下へ書いたものを、
//! 管理画面がまとめて読む（memory の netdata-metrics-endpoint）。
//!
//! - `SCAN 0 MATCH sycs:metrics:* COUNT 256` を、カーソルが 0 に戻るまで回し、1 ページごとに `MGET` でまとめて取る。
//!   鍵は `sycs:metrics:` を外したもの。値の無い鍵（読むまでの間に期限が切れた）は飛ばす
//! - 鍵か値が UTF-8 でない・つながらない・答えない（`VALKEY_TIMEOUT_SECONDS`、既定 0.5 秒）なら、そのページで止めて、
//!   それまでに読めた分を返す（Python も途中まで読めた分を返す）。そのあと遮断器を開き、
//!   `VALKEY_BREAKER_COOLDOWN_SECONDS`（既定 30 秒）は Valkey へ行かない
//! - 「使えるか」（`sycs_shared_cache_available`）は、読んだあとの遮断器の状態（`VALKEY_URL` が無ければいつも偽）
//!
//! Python と違うところ: Python は報告（心拍の書き込み）と読み出しが同じ遮断器を使うので、報告が失敗すると 30 秒は
//! `/metrics` も Valkey を読まない。Rust の報告口（`sycs_core::metrics::Reporter`）は別の接続なので、読み出しは
//! 読み出しの失敗でだけ止まる。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sycs_core::env::Env;
use sycs_core::metrics::full_key;
use tracing::{info, warn};

/// 1 回の `SCAN` で頼む数（Python の `count=256`）。
pub const SCAN_COUNT: u32 = 256;
/// 待つ時間の既定（秒。Python の `_DEFAULT_TIMEOUT_SECONDS`）。
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 0.5;
/// 遮断器を開いておく時間の既定（秒。Python の `_DEFAULT_BREAKER_COOLDOWN_SECONDS`）。
pub const DEFAULT_COOLDOWN_SECONDS: f64 = 30.0;

/// 読んだもの（鍵は `sycs:metrics:` を外したもの。鍵の順に並ぶ）と、読んだあとに Valkey を使えるか。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// 鍵 → 値。
    pub items: BTreeMap<String, String>,
    /// `SharedCache.available`（読んだあと）。
    pub available: bool,
}

/// [`MetricsStore::scan`] の future。
pub type ScanFuture<'a> = Pin<Box<dyn Future<Output = Scan> + Send + 'a>>;

/// メトリクスの置き場を読む口（本番は [`ValkeyStore`]。テストは決まったものを返す偽物）。
pub trait MetricsStore: Send + Sync {
    /// `metrics` の下を全部読む。失敗しても panic しない（読めた分と「使えない」を返す）。
    fn scan(&self) -> ScanFuture<'_>;
}

/// つなぐ先が無い置き場（`VALKEY_URL` が無いとき。何も読まず、いつも「使えない」）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Unconfigured;

impl MetricsStore for Unconfigured {
    fn scan(&self) -> ScanFuture<'_> {
        Box::pin(async { Scan::default() })
    }
}

/// 遮断器（`_blocked_until` と、落ちた時刻 `_down_since`）。
#[derive(Debug, Default)]
struct Breaker {
    blocked_until: Option<Instant>,
    down_since: Option<Instant>,
}

/// Valkey（Redis 互換）の `sycs:metrics:` の下を読む。
pub struct ValkeyStore {
    url: String,
    timeout: Duration,
    cooldown: Duration,
    conn: tokio::sync::Mutex<Option<ConnectionManager>>,
    breaker: Mutex<Breaker>,
}

impl std::fmt::Debug for ValkeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyStore")
            .field("configured", &self.configured())
            .field("timeout", &self.timeout)
            .field("cooldown", &self.cooldown)
            .finish_non_exhaustive()
    }
}

impl ValkeyStore {
    /// 作る（つなぐのは最初に読むとき）。`url` が空なら、何もしない置き場になる。
    pub fn new(url: &str, timeout: Duration, cooldown: Duration) -> Self {
        Self {
            url: url.trim().to_string(),
            timeout,
            cooldown,
            conn: tokio::sync::Mutex::new(None),
            breaker: Mutex::new(Breaker::default()),
        }
    }

    /// 環境変数から作る（`VALKEY_URL`・`VALKEY_TIMEOUT_SECONDS`〔下限 0.05〕・`VALKEY_BREAKER_COOLDOWN_SECONDS`
    /// 〔下限 1〕。Python の `shared_cache()` と同じ読み方）。
    pub fn from_env(env: &Env) -> Self {
        let timeout = env
            .float("VALKEY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS, Some(0.05), None)
            .max(0.05);
        let cooldown = env
            .float("VALKEY_BREAKER_COOLDOWN_SECONDS", DEFAULT_COOLDOWN_SECONDS, Some(1.0), None)
            .max(1.0);
        Self::new(
            &env.raw("VALKEY_URL").unwrap_or_default(),
            Duration::from_secs_f64(timeout),
            Duration::from_secs_f64(cooldown),
        )
    }

    /// つなぐ先が決まっているか（`SharedCache.configured`）。
    pub fn configured(&self) -> bool {
        !self.url.is_empty()
    }

    /// 今この瞬間に使ってよいか（`SharedCache.available`。決まっていて、遮断器が閉じている）。
    pub fn available(&self) -> bool {
        if !self.configured() {
            return false;
        }
        let breaker = self.breaker.lock().unwrap_or_else(PoisonError::into_inner);
        breaker
            .blocked_until
            .is_none_or(|until| Instant::now() >= until)
    }

    async fn connection(&self) -> Result<ConnectionManager, String> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let client = redis::Client::open(self.url.as_str()).map_err(|e| e.to_string())?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.timeout))
            .set_response_timeout(Some(self.timeout));
        let connect = ConnectionManager::new_with_config(client, config);
        match tokio::time::timeout(self.timeout * 2, connect).await {
            Ok(Ok(conn)) => {
                *guard = Some(conn.clone());
                Ok(conn)
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("つなぐのに時間がかかりすぎた".to_string()),
        }
    }

    /// 遮断器を開く（`_trip`。開くときだけ警告を残す）。
    fn trip(&self, error: &str) {
        let now = Instant::now();
        let mut breaker = self.breaker.lock().unwrap_or_else(PoisonError::into_inner);
        let already_open = breaker.blocked_until.is_some_and(|until| now < until);
        breaker.blocked_until = Some(now + self.cooldown);
        if already_open {
            return;
        }
        let down_since = breaker.down_since;
        match down_since {
            None => {
                breaker.down_since = Some(now);
                warn!(
                    "メトリクスの置き場（Valkey）を {:.0} 秒間読みません（{error}）。/metrics は sycs_shared_cache_available 0 を出します",
                    self.cooldown.as_secs_f64()
                );
            }
            Some(since) => warn!(
                "メトリクスの置き場（Valkey）にまだ届きません（落ちてから {:.0} 秒。{error}）",
                now.duration_since(since).as_secs_f64()
            ),
        }
    }

    /// 落ちていたあとに 1 回通った（`_recovered`。そのときだけ 1 行残す）。
    fn recovered(&self) {
        let mut breaker = self.breaker.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(since) = breaker.down_since.take() {
            info!(
                "メトリクスの置き場（Valkey）が戻りました（{:.0} 秒ぶり）",
                since.elapsed().as_secs_f64()
            );
        }
    }
}

/// `SCAN`・`MGET` を回して `items` に入れる（`_scan_get`）。1 ページの鍵か値が UTF-8 でなければ、そのページは
/// 1 つも入れずに止める（Python は答えを読むときに文字にするので、そのページの答えごと失敗する）。
async fn scan_pages(
    conn: &mut ConnectionManager,
    items: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let prefix = full_key("");
    let pattern = format!("{prefix}*");
    let skip = prefix.chars().count();
    let mut cursor: u64 = 0;
    loop {
        let page: (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(SCAN_COUNT)
            .query_async(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
        let (next, raw_keys) = page;
        let keys = raw_keys
            .into_iter()
            .map(|key| String::from_utf8(key).map_err(|e| format!("鍵が UTF-8 ではありません: {e}")))
            .collect::<Result<Vec<String>, String>>()?;
        if !keys.is_empty() {
            let raw_values: Vec<Option<Vec<u8>>> = redis::cmd("MGET")
                .arg(&keys)
                .query_async(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;
            let values = raw_values
                .into_iter()
                .map(|value| {
                    value
                        .map(String::from_utf8)
                        .transpose()
                        .map_err(|e| format!("値が UTF-8 ではありません: {e}"))
                })
                .collect::<Result<Vec<Option<String>>, String>>()?;
            for (key, value) in keys.iter().zip(values) {
                let Some(value) = value else {
                    continue;
                };
                items.insert(key.chars().skip(skip).collect(), value);
            }
        }
        if next == 0 {
            return Ok(());
        }
        cursor = next;
    }
}

impl MetricsStore for ValkeyStore {
    fn scan(&self) -> ScanFuture<'_> {
        Box::pin(async move {
            let mut items = BTreeMap::new();
            if self.available() {
                match self.connection().await {
                    Ok(mut conn) => match scan_pages(&mut conn, &mut items).await {
                        Ok(()) => self.recovered(),
                        Err(e) => {
                            // 壊れた接続を使い回さない（Python も捨てて、次は作り直す）。
                            *self.conn.lock().await = None;
                            self.trip(&e);
                        }
                    },
                    Err(e) => self.trip(&e),
                }
            }
            Scan {
                items,
                available: self.available(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// つなぐ先が無ければ、何もしないで「使えない」。
    #[tokio::test]
    async fn without_a_url_nothing_is_read() {
        let store = ValkeyStore::new("  ", Duration::from_millis(50), Duration::from_secs(30));
        assert!(!store.configured());
        assert_eq!(store.scan().await, Scan::default());
        assert_eq!(Unconfigured.scan().await, Scan::default());
    }

    /// つながらなければ panic せず、遮断器を開いて「使えない」を返し、間は行かない。
    #[tokio::test]
    async fn an_unreachable_valkey_trips_the_breaker() {
        let store = ValkeyStore::new(
            "redis://127.0.0.1:1/0",
            Duration::from_millis(200),
            Duration::from_secs(30),
        );
        assert!(store.available());
        let scan = store.scan().await;
        assert!(scan.items.is_empty());
        assert!(!scan.available);
        assert!(!store.available());
        let broken = ValkeyStore::new("not-a-url", Duration::from_millis(50), Duration::from_secs(30));
        assert!(!broken.scan().await.available);
    }
}
