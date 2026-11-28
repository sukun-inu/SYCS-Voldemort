//! 回数の制限。Python の slowapi 0.1.10（`webapp_admin/extensions.py` の `limiter`）と limits 5.8.0 の固定窓の写し。
//!
//! - 数える鍵は「接続元（uvicorn が転送ヘッダで直したあとの `request.client.host`。無ければ `127.0.0.1`）・パス
//!   （戻したもの。`{guild_id}` のような経路は、値ごとに別に数える）・上限」
//! - 窓は **最初の 1 回から** 60 秒（limits の `MemoryStorage.incr` と Redis の `INCRBY`＋`EXPIRE`。分の区切りには
//!   そろえない）。窓の終わりちょうどで切れる。断った回も数に入る（数えてから比べる）
//! - 既定の 1 分 300 回（`default_limits`）が掛かるのは、**app に直に足した、デコレータの無い経路だけ**。FastAPI 0.14x
//!   からは `include_router` で入れた経路が app の一覧に `_IncludedRouter` として入り、slowapi の
//!   `_find_route_handler` が係を見つけられないので、ルーターの中の経路（管理画面の画面と API のほとんど）には効いて
//!   いない（配信の基準 W1 で 301 回目も普通に答えた。管理画面の経路でも A1 の基準で確かめる）
//! - 既定の制限で断るのは `SlowAPIMiddleware`（見出しや数の層より外）。答えは slowapi の
//!   `_rate_limit_exceeded_handler`（`{"error": "Rate limit exceeded: 300 per 1 minute"}`。管理画面の
//!   `rate_limit_handler` は非同期なので使われない）。デコレータの制限は係の中で断る（[`crate::errors::Failure::RateLimited`]）
//!
//! 置き場はプロセスの中だけ（Python の本番は Valkey の db 1。Rust の管理画面は 1 プロセスで動き、Python と同時には
//! 動かさないので、揃えない。計画の 1.7）。

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// 窓の長さ（秒）。
pub const WINDOW_SECONDS: f64 = 60.0;
/// 既定の上限（1 分あたり）。
pub const DEFAULT_PER_MINUTE: u32 = 300;
/// 数を溜める鍵がこれを超えたら、切れたものを捨てる。
const SWEEP_AT: usize = 4096;

#[derive(Clone, Copy, Debug)]
struct Window {
    count: u64,
    expires_at: f64,
}

/// 固定窓の数え口。
#[derive(Debug, Default)]
pub struct Limiter {
    windows: Mutex<HashMap<(String, String, u32), Window>>,
}

impl Limiter {
    /// 空で作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 回数えて、上限の中なら真（limits の `FixedWindowRateLimiter.hit`）。`now` は UNIX 時間の秒。
    pub fn hit(&self, client: &str, path: &str, per_minute: u32, now: f64) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() > SWEEP_AT {
            windows.retain(|_, window| window.expires_at > now);
        }
        let key = (client.to_string(), path.to_string(), per_minute);
        let window = windows.entry(key).or_insert(Window {
            count: 0,
            expires_at: now,
        });
        if window.expires_at <= now {
            window.count = 0;
        }
        window.count += 1;
        if window.count == 1 {
            window.expires_at = now + WINDOW_SECONDS;
        }
        window.count <= u64::from(per_minute)
    }

    /// 数を全部捨てる（limits の `reset`）。
    pub fn reset(&self) {
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// slowapi の鍵の接続元（`get_remote_address`。分からない・空なら `127.0.0.1`）。
pub fn client_key(client: Option<&str>) -> &str {
    client.filter(|c| !c.is_empty()).unwrap_or("127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 窓は最初の 1 回から 60 秒で、ちょうどで切れ、接続元・パス・上限ごとに別に数えること。
    #[test]
    fn windows_start_at_the_first_hit() {
        let limiter = Limiter::new();
        let t0 = 1_000.5;
        assert!(limiter.hit("a", "/x", 2, t0));
        assert!(limiter.hit("a", "/x", 2, t0 + 59.0));
        assert!(!limiter.hit("a", "/x", 2, t0 + 59.9));
        assert!(limiter.hit("b", "/x", 2, t0 + 59.9));
        assert!(limiter.hit("a", "/y", 2, t0 + 59.9));
        assert!(limiter.hit("a", "/x", 3, t0 + 59.9));
        assert!(limiter.hit("a", "/x", 2, t0 + 60.0));
        limiter.reset();
        assert!(limiter.hit("a", "/x", 1, t0));
        assert!(!limiter.hit("a", "/x", 1, t0));
        assert_eq!(client_key(None), "127.0.0.1");
        assert_eq!(client_key(Some("")), "127.0.0.1");
        assert_eq!(client_key(Some("203.0.113.5")), "203.0.113.5");
    }
}
