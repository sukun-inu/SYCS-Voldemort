//! Rust の web のアプリ（配信 `apps/cdn`、のちに管理画面と公開サイト）が共通で使う土台。
//!
//! Python では 3 つのアプリ（`cdn_main.py`・`admin_main.py`・`web_main.py`）がそれぞれ uvicorn を起動し、
//! 同じ作法（ログの置き場・Valkey へのメトリクス・信頼するプロキシ）を別々に書いていた。Rust では、その作法を
//! ここに 1 つだけ置く。どれも Python 側と規則を揃えてあり、揃っていることをテストで確かめている。
//!
//! - [`serve`] 待ち受けのアドレスとポート（環境変数）と止め方（SIGTERM・Ctrl+C）
//! - [`proxy`] 信頼するプロキシ（`TRUSTED_PROXY_CIDRS`。uvicorn の `ProxyHeadersMiddleware` と同じ読み方）
//! - [`path`] URL のパスの戻し方（uvicorn と同じ。Starlette はこれで経路を引く）
//! - [`metrics`] リクエストの数え方（Python の `webapp_admin/metrics.py` と同じ名前の数を Valkey へ）
//! - [`health`] `/health`
//! - [`probe`] 自分に 1 回だけ HTTP で尋ねる小さな道具（本番の CPU で起動できるかの確かめと、テスト）
//!
//! ログは `sycs_core::log`（Python と同じ `<アプリ>.log`・`<アプリ>.jsonl`）。置き場は [`log_dir`]。

use std::path::PathBuf;

use sycs_core::env::Env;

pub mod health;
pub mod metrics;
pub mod path;
pub mod probe;
pub mod proxy;
pub mod serve;

/// ログの置き場（`<SETTINGS_DIR>/logs`。既定は `/app/data/logs`）。Python の `cdn_main.py`・`web_main.py` と同じ。
pub fn log_dir(env: &Env) -> PathBuf {
    env.path("SETTINGS_DIR", "/app/data").join("logs")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ログの置き場が、Python と同じく `SETTINGS_DIR` の下の `logs` になること。
    #[test]
    fn logs_live_under_the_settings_dir() {
        let env = Env::from_fn(|key| (key == "SETTINGS_DIR").then(|| "/srv/data".to_string()));
        assert_eq!(log_dir(&env), PathBuf::from("/srv/data/logs"));
        let unset = Env::from_fn(|_| None);
        assert_eq!(log_dir(&unset), PathBuf::from("/app/data/logs"));
    }
}
