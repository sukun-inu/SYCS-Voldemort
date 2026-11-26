//! Rust のプロセスが共通で使う土台。
//!
//! discord.py をやめて Rust へ移す間、Python と Rust のプロセスは同じ環境変数を読み、
//! 同じデータベースにつなぎ、同じディレクトリへログを書く。ここにあるのは、その
//! 「同じ」を Rust 側で守るためのもの。どれも Python 側の実装と規則を揃えてあり、
//! 揃っていることをテストで確かめている。
//!
//! - [`env`]  環境変数の読み方（Python の `envutil.py`）
//! - [`db`]   `user_state_audit` への接続先（Python の `services/user_state_db.py`）
//! - [`log`]  テキストと JSONL のログ（Python の `services/log_setup.py`）
//! - [`metrics`] Valkey への心拍と数値（Python の `services/metrics_registry.py`）
//! - [`settings`] ギルドごとの設定の読み込み（Python の `services/settings_pg.py`）
//! - [`signals`] 管理画面から Bot への依頼の取り出し（Python の `services/dev_signals.py`）

pub mod db;
pub mod env;
pub mod log;
pub mod metrics;
pub mod settings;
pub mod signals;
pub mod ttl_cache;
pub mod url_safety;
