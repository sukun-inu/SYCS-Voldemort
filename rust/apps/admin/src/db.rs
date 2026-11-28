//! `user_state_audit`（設定・Bot への依頼・利用者の状態）への接続の束。Python の `services/user_state_db.py` の
//! `engine`（`create_async_engine(…, pool_pre_ping=True, pool_size, max_overflow, pool_timeout, pool_recycle)`）。
//!
//! 接続先は sycs-core の [`sycs_core::db::user_state_url`]（Python と同じ環境変数・同じ順）。つなぐのは最初に
//! 使うとき（Python の engine も同じ。起動のときに Postgres が落ちていても、管理画面は立ち上がる）。
//!
//! 大きさは Python と同じ環境変数・既定・下限（専用の `USER_STATE_DB_*` があればそれ、無ければ共通の `DB_*`）:
//!
//! | Python | 環境変数 | 既定 | 下限 | sqlx |
//! |---|---|---|---|---|
//! | `pool_size` ＋ `max_overflow` | `USER_STATE_DB_POOL_SIZE`→`DB_POOL_SIZE` ＋ `USER_STATE_DB_MAX_OVERFLOW`→`DB_MAX_OVERFLOW` | 5 ＋ 10 | 1・0 | `max_connections` |
//! | `pool_timeout` | `USER_STATE_DB_POOL_TIMEOUT`→`DB_POOL_TIMEOUT` | 30 秒 | 5 | `acquire_timeout` |
//! | `pool_recycle` | `USER_STATE_DB_POOL_RECYCLE`→`DB_POOL_RECYCLE` | 1800 秒 | 60 | `max_lifetime` |
//!
//! `pool_pre_ping` は sqlx の既定（`test_before_acquire`）と同じ。Python と違うところ: SQLAlchemy は 5 本を持ち続けて
//! 溢れた分は返したら閉じるが、sqlx は最大 15 本のどれも、使わなければ 10 分で閉じる（sqlx の既定の `idle_timeout`）。

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sycs_core::env::Env;

/// 接続の束の大きさ。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// 束の数（`pool_size + max_overflow`）。
    pub max_connections: u32,
    /// 束が空くのを待つ時間（`pool_timeout`）。
    pub acquire_timeout: Duration,
    /// 1 本を使い回す時間（`pool_recycle`）。
    pub max_lifetime: Duration,
}

/// `_pooled_int`。専用の名前（`USER_STATE_DB_<name>`）に値があればそれを、無ければ共通の名前（`DB_<name>`）を読む
/// （どちらも既定と下限は同じ）。
fn pooled_int(env: &Env, name: &str, default: i64, minimum: i64) -> i64 {
    let primary = format!("USER_STATE_DB_{name}");
    let key = if env.raw(&primary).is_some() {
        primary
    } else {
        format!("DB_{name}")
    };
    env.int(&key, default, Some(minimum), None)
}

/// 秒を時間に（負は来ない。下限が 5 と 60）。
fn seconds(value: i64) -> Duration {
    Duration::from_secs(u64::try_from(value).unwrap_or_default())
}

impl PoolConfig {
    /// 環境変数から（Python の `DB_POOL_SIZE` などと同じ読み方）。
    pub fn from_env(env: &Env) -> Self {
        let size = pooled_int(env, "POOL_SIZE", 5, 1);
        let overflow = pooled_int(env, "MAX_OVERFLOW", 10, 0);
        let timeout = pooled_int(env, "POOL_TIMEOUT", 30, 5);
        let recycle = pooled_int(env, "POOL_RECYCLE", 1800, 60);
        let connections = size.saturating_add(overflow);
        Self {
            max_connections: u32::try_from(connections).unwrap_or(u32::MAX),
            acquire_timeout: seconds(timeout),
            max_lifetime: seconds(recycle),
        }
    }
}

/// 接続の束を作る（まだつながない）。接続先の文字が読めなければ失敗。
pub fn connect_lazy(env: &Env) -> Result<PgPool, sqlx::Error> {
    let config = PoolConfig::from_env(env);
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .max_lifetime(config.max_lifetime)
        .connect_lazy(&sycs_core::db::user_state_url(env))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    /// 既定は Python と同じ（5 ＋ 10 本、30 秒、1800 秒）。
    #[test]
    fn the_defaults_match_python() {
        let config = PoolConfig::from_env(&env(&[]));
        assert_eq!(config.max_connections, 15);
        assert_eq!(config.acquire_timeout, Duration::from_secs(30));
        assert_eq!(config.max_lifetime, Duration::from_secs(1800));
    }

    /// 専用の名前が勝ち、無ければ共通の名前。下限より小さい値は下限（Python の env_int の minimum）。
    #[test]
    fn the_dedicated_names_win_and_minimums_hold() {
        let config = PoolConfig::from_env(&env(&[
            ("USER_STATE_DB_POOL_SIZE", "2"),
            ("DB_POOL_SIZE", "50"),
            ("DB_MAX_OVERFLOW", "3"),
            ("DB_POOL_TIMEOUT", "1"),
            ("USER_STATE_DB_POOL_RECYCLE", "10"),
        ]));
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.acquire_timeout, Duration::from_secs(5));
        assert_eq!(config.max_lifetime, Duration::from_secs(60));
        let python = include_str!("../../../../services/user_state_db.py");
        for line in [
            "_pooled_int(\"USER_STATE_DB_POOL_SIZE\", \"DB_POOL_SIZE\", 5, minimum=1)",
            "_pooled_int(\"USER_STATE_DB_MAX_OVERFLOW\", \"DB_MAX_OVERFLOW\", 10, minimum=0)",
            "_pooled_int(\"USER_STATE_DB_POOL_TIMEOUT\", \"DB_POOL_TIMEOUT\", 30, minimum=5)",
            "_pooled_int(\"USER_STATE_DB_POOL_RECYCLE\", \"DB_POOL_RECYCLE\", 1800, minimum=60)",
        ] {
            assert!(python.contains(line), "{line}");
        }
    }
}
