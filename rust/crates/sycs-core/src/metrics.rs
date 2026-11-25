//! メトリクスを Valkey へ流す。Python の `services/metrics_registry.py` と
//! `services/metrics_reporter.py` と同じ鍵・同じ形にしてある。
//!
//! 全プロセスが Valkey へ書き、管理画面の `/metrics` が読んで Netdata へ出す
//! （ホストの Netdata が 1 か所だけを読めば済むように）。Rust のプロセスも同じ鍵へ
//! 書けば、管理画面にも Netdata にも手を入れずに、Rust のプロセスの死活
//! （`sycs_up{app="…"}`）と数値が並ぶ。
//!
//! 鍵（どれも `sycs:metrics:` の下）:
//!
//! | 鍵 | 中身 | 期限 |
//! |---|---|---|
//! | `hb:<アプリ>` | 最後に報告した時刻（エポック秒） | **付けない**（死活は消えるのではなく 0 になる） |
//! | `g:<アプリ>:<名前>` | 瞬間値（ゲージ） | 120 秒（死んだプロセスの最後の値が残り続けないように） |
//! | `c:<名前>\|<ラベル>` | 累積値（カウンタ）を INCRBY で足す | **付けない**（消えると「減った」と読まれる） |
//!
//! **名前に `sycs_` を付けないこと。** `/metrics` が出すときに頭へ付ける。付けて数えると
//! `sycs_sycs_events` のように二重になり、Netdata 側の設定が拾わない（確かめるときに
//! 実際にこれを間違えた）。
//!
//! **メトリクスの都合で本体を止めない。** Valkey に届かなければ警告を出して諦め、
//! 送れなかったカウンタは戻して次の回で送り直す（Valkey が落ちている間の計数を捨てない）。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::AsyncCommands;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use tracing::warn;

/// 鍵の頭に必ず付ける。Python の `shared_cache.KEY_PREFIX`。
pub const KEY_PREFIX: &str = "sycs";
/// メトリクスの名前空間。Python の `metrics_registry.NAMESPACE`。
pub const NAMESPACE: &str = "metrics";
/// ゲージの寿命（秒）。Python の `_DEFAULT_GAUGE_TTL_SECONDS`。
pub const GAUGE_TTL_SECONDS: u64 = 120;
/// Valkey を待つ時間。Python の `shared_cache._DEFAULT_TIMEOUT_SECONDS`。
///
/// 長くする意味は無い。応答しない Valkey を待つのは、メトリクスが無いより常に悪い。
pub const TIMEOUT: Duration = Duration::from_millis(500);

/// ラベル（並びは鍵の名前順に固定する）。
pub type Labels = BTreeMap<String, String>;

/// 実際に Valkey へ渡す鍵。
pub fn full_key(key: &str) -> String {
    format!("{KEY_PREFIX}:{NAMESPACE}:{key}")
}

/// カウンタの鍵。名前とラベルを `|` で、ラベル同士を `,` でつなぐ。
///
/// ラベルの並びを固定している（`BTreeMap` が名前順）。**固定しないと、同じカウンタが
/// ラベルの順番違いで別の鍵になり、2 つに分かれて数えられる。** Python の
/// `_encode_counter_key` と同じ形なので、Python と Rust が同じカウンタを足し合える。
pub fn counter_key(name: &str, labels: &Labels) -> String {
    if labels.is_empty() {
        return name.to_string();
    }
    let joined: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{name}|{}", joined.join(","))
}

/// 値を書く形。
///
/// Python の `_format_value` は整数を小数点なしで書き、大きな値が指数表記になるのを
/// 避けている。Rust の小数の表示はもともと `.0` も指数表記も付けない（`3`・`0.25`・
/// `100000000000000000000`）ので、そのまま同じ見た目になる。読む側（`/metrics`）は
/// どちらも float として読むので、意味の上でも揃っている。
pub fn format_value(value: f64) -> String {
    format!("{value}")
}

/// カウンタをプロセスの中に溜めておく入れ物。
///
/// 数えるたびに Valkey へ行くと、その往復が処理の途中に乗る。溜めて、報告のときに
/// 差分をまとめて INCRBY する。差分で持つので、誰が再起動しても Valkey 側の累積は減らない。
#[derive(Default)]
pub struct CounterBuffer {
    counts: Mutex<BTreeMap<CounterId, i64>>,
}

/// カウンタを見分ける鍵（名前と、名前順に並んだラベル）。
type CounterId = (String, Vec<(String, String)>);

impl CounterBuffer {
    /// 1 件（amount 件）数える。ここは panic しないこと（処理の途中から呼ばれる）。
    pub fn add(&self, name: &str, labels: &Labels, amount: i64) {
        let key = (
            name.to_string(),
            labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        );
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        *counts.entry(key).or_insert(0) += amount;
    }

    /// 溜まった分を取り出して空にする。取り出しと空にするのを 1 つのロックの中で行う
    /// （分けると、その隙間に入った数え上げが失われる）。
    pub fn drain(&self) -> Vec<(String, Labels, i64)> {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *counts)
            .into_iter()
            .map(|((name, labels), amount)| (name, labels.into_iter().collect(), amount))
            .collect()
    }

    /// 送れなかった分を戻す。**これが無いと、Valkey が落ちている間の計数が捨てられる。**
    pub fn restore(&self, items: Vec<(String, Labels, i64)>) {
        for (name, labels, amount) in items {
            self.add(&name, &labels, amount);
        }
    }
}

/// Valkey へ報告する口。1 プロセスに 1 つ。
pub struct Reporter {
    app: String,
    url: Option<String>,
    conn: tokio::sync::Mutex<Option<ConnectionManager>>,
    counters: CounterBuffer,
}

impl Reporter {
    /// 作る。つなぎに行くのは最初の報告のとき（つなげないことで起動を止めない）。
    ///
    /// `valkey_url` が `None`（`VALKEY_URL` が未設定）なら、何もしない報告口になる。
    pub fn new(app: &str, valkey_url: Option<&str>) -> Self {
        Self {
            app: app.to_string(),
            url: valkey_url.map(str::to_string),
            conn: tokio::sync::Mutex::new(None),
            counters: CounterBuffer::default(),
        }
    }

    /// 環境変数 `VALKEY_URL` から作る。
    pub fn from_env(app: &str, env: &crate::env::Env) -> Self {
        Self::new(app, env.raw("VALKEY_URL").as_deref())
    }

    async fn open(url: &str) -> redis::RedisResult<ConnectionManager> {
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(TIMEOUT))
            .set_response_timeout(Some(TIMEOUT));
        ConnectionManager::new_with_config(client, config).await
    }

    /// つながっていればその接続、まだなら今つなぎに行く。
    ///
    /// **起動したときに Valkey が落ちていても、あとで戻れば報告を再開する。** 最初の
    /// 1 回しかつなぎに行かない形にすると、起動の順番しだいで、そのプロセスの報告が
    /// 再起動まで二度と届かない（管理画面では sycs_up が 0 のまま）。一度つながれば、
    /// 切れたあとのつなぎ直しは ConnectionManager が受け持つ。
    async fn connection(&self, url: &str) -> Result<ConnectionManager, String> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        match tokio::time::timeout(TIMEOUT * 2, Self::open(url)).await {
            Ok(Ok(conn)) => {
                *guard = Some(conn.clone());
                Ok(conn)
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("つなぐのに時間がかかりすぎた".to_string()),
        }
    }

    /// カウンタの入れ物。処理の途中で数えるときに使う。
    pub fn counters(&self) -> &CounterBuffer {
        &self.counters
    }

    /// 1 回報告する。心拍・ゲージ・溜まったカウンタ。
    ///
    /// 失敗しても panic しない。届かなかったカウンタは戻して、次の回で送る。
    pub async fn report_once(&self, gauges: &[(&str, f64)]) {
        let drained = self.counters.drain();
        let Some(url) = self.url.as_deref() else {
            // 報告先が無い。持っていても送る先が無いので捨てる（溜め続けると育ち続ける）。
            return;
        };
        let result = match self.connection(url).await {
            Ok(conn) => self
                .send(conn, gauges, &drained)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            self.counters.restore(drained);
            warn!("メトリクスの報告に失敗しました（次の回で送り直します）: {e}");
        }
    }

    async fn send(
        &self,
        mut conn: ConnectionManager,
        gauges: &[(&str, f64)],
        counters: &[(String, Labels, i64)],
    ) -> redis::RedisResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let () = conn
            .set(full_key(&format!("hb:{}", self.app)), format!("{now:.6}"))
            .await?;
        for (name, value) in gauges {
            let () = conn
                .set_ex(
                    full_key(&format!("g:{}:{name}", self.app)),
                    format_value(*value),
                    GAUGE_TTL_SECONDS,
                )
                .await?;
        }
        for (name, labels, amount) in counters {
            let _: i64 = conn
                .incr(
                    full_key(&format!("c:{}", counter_key(name, labels))),
                    *amount,
                )
                .await?;
        }
        Ok(())
    }

    /// 止められるまで `interval` ごとに報告し続ける。`gauges` は毎回呼ばれる。
    ///
    /// `gauges` に重い処理を渡さないこと。その間このループが止まる。ホストの CPU と
    /// メモリは Netdata 自身が測るので、ここで測る必要は無い。
    pub async fn report_forever(
        &self,
        interval: Duration,
        gauges: impl Fn() -> Vec<(&'static str, f64)>,
    ) {
        let interval = interval.max(Duration::from_secs(1));
        loop {
            self.report_once(&gauges()).await;
            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// カウンタの鍵が Python と同じ形で、ラベルの順番に左右されないこと。
    ///
    /// 形が違うと、Python と Rust のプロセスが同じカウンタを別々の鍵へ足し、管理画面には
    /// 2 本に分かれて出る。順番で鍵が変わると、同じプロセスの中でも分かれる。
    #[test]
    fn counter_keys_match_python_and_ignore_label_order() {
        assert_eq!(counter_key("requests", &Labels::new()), "requests");
        let a = labels(&[("status", "200"), ("app", "bot")]);
        let b = labels(&[("app", "bot"), ("status", "200")]);
        assert_eq!(counter_key("requests", &a), "requests|app=bot,status=200");
        assert_eq!(counter_key("requests", &a), counter_key("requests", &b));
    }

    /// 鍵の頭が Python と同じであること（管理画面はこの下だけを走査する）。
    #[test]
    fn keys_live_under_the_same_namespace_as_python() {
        assert_eq!(full_key("hb:bot"), "sycs:metrics:hb:bot");
        let registry = include_str!("../../../../services/metrics_registry.py");
        let cache = include_str!("../../../../services/shared_cache.py");
        assert!(registry.contains(&format!("NAMESPACE = \"{NAMESPACE}\"")));
        assert!(registry.contains(&format!("_DEFAULT_GAUGE_TTL_SECONDS = {GAUGE_TTL_SECONDS}")));
        assert!(cache.contains(&format!("KEY_PREFIX = \"{KEY_PREFIX}\"")));
    }

    /// 整数は小数点なしで書くこと（Python の _format_value と同じ）。
    #[test]
    fn whole_numbers_are_written_without_a_decimal_point() {
        assert_eq!(format_value(3.0), "3");
        assert_eq!(format_value(0.25), "0.25");
        assert_eq!(format_value(-2.0), "-2");
    }

    /// 取り出したら空になり、戻したら次の取り出しに入ること。
    ///
    /// 戻さないと、Valkey が落ちている間の計数がまるごと消える。
    #[test]
    fn drained_counts_can_be_put_back_for_the_next_report() {
        let buffer = CounterBuffer::default();
        let l = labels(&[("kind", "tts")]);
        buffer.add("events", &l, 2);
        buffer.add("events", &l, 3);
        let drained = buffer.drain();
        assert_eq!(drained, vec![("events".to_string(), l.clone(), 5)]);
        assert!(buffer.drain().is_empty());
        buffer.restore(drained);
        buffer.add("events", &l, 1);
        assert_eq!(buffer.drain(), vec![("events".to_string(), l, 6)]);
    }

    /// Valkey につながらなくても panic せず、報告が黙って終わること。
    ///
    /// 監視のために本体を落とすのは本末転倒になる。
    #[tokio::test]
    async fn an_unreachable_valkey_does_not_stop_the_process_and_keeps_the_counts() {
        let reporter = Reporter::new("test", Some("redis://127.0.0.1:1/0"));
        reporter.counters().add("events", &Labels::new(), 1);
        reporter.report_once(&[("guilds", 3.0)]).await;
        // 届かなかった分は戻っていて、次の報告で送られる。
        assert_eq!(
            reporter.counters().drain(),
            vec![("events".to_string(), Labels::new(), 1)]
        );
        let none = Reporter::new("test", None);
        none.report_once(&[]).await;
    }
}
