//! レート制限（経路ごと・接続元ごとに、決まった秒数の窓で何回まで）。
//!
//! Python の管理画面は slowapi を `default_limits=["300/minute"]` で使っていて、`/dlaudio/` の 3 つの経路にも
//! 経路ごと・接続元（`request.client.host`）ごとに 1 分 300 回が掛かっている。数え方は limits の固定の窓
//! （`FixedWindowRateLimiter`）: 最初の 1 回から窓が始まり、窓の中の回数を数え、断った回も数える（窓は延びない）。
//! 窓が終わったら数え直す。
//!
//! Python と違うところ: 本番の Python は数を Valkey（1 番）に置いているが、ここはプロセスの中で数える（配信は
//! 1 プロセスなので、Python の `memory://` で 1 ワーカーのときと同じ）。配信を再起動すると数は 0 に戻る。

use std::collections::HashMap;
use std::sync::Mutex;

/// これより多く覚えたら、終わった窓を掃除する（攻撃のときに覚える数が増え続けないように）。
const PRUNE_OVER: usize = 4096;

/// 固定の窓で数えるレート制限。
pub struct FixedWindow {
    limit: u32,
    window: f64,
    state: Mutex<Windows>,
}

/// 経路と接続元ごとの、窓の終わりと回数。
#[derive(Default)]
struct Windows {
    entries: HashMap<(String, String), (f64, u32)>,
    last_prune: f64,
}

impl FixedWindow {
    /// `window_seconds` 秒の窓で `limit` 回まで。
    pub fn new(limit: u32, window_seconds: f64) -> Self {
        Self {
            limit,
            window: window_seconds,
            state: Mutex::new(Windows::default()),
        }
    }

    /// 1 回数え、まだ上限の内なら真。`scope` は経路（Python の関数の名前）、`key` は接続元。`now` は秒。
    pub fn hit(&self, scope: &str, key: &str, now: f64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.entries.len() > PRUNE_OVER && now - state.last_prune >= self.window {
            state.entries.retain(|_, (ends, _)| *ends > now);
            state.last_prune = now;
        }
        let entry = state
            .entries
            .entry((scope.to_string(), key.to_string()))
            .or_insert((now + self.window, 0));
        if entry.0 <= now {
            // 窓が終わっていた（limits の MemoryStorage と同じく、終わりの時刻ちょうどで終わる）。
            *entry = (now + self.window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 上限までは通し、次で断り、断った回も数え、窓が終わったら数え直すこと。経路と接続元は別々に数えること。
    #[test]
    fn a_fixed_window_counts_per_route_and_client() {
        let limit = FixedWindow::new(3, 60.0);
        for _ in 0..3 {
            assert!(limit.hit("files", "a", 1000.0));
        }
        assert!(!limit.hit("files", "a", 1001.0));
        assert!(!limit.hit("files", "a", 1059.9));
        assert!(limit.hit("info", "a", 1001.0));
        assert!(limit.hit("files", "b", 1001.0));
        assert!(limit.hit("files", "a", 1060.0));
    }
}
