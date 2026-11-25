//! SYCS-Voldemort の Discord Bot（serenity）の中身。実行ファイル（`main.rs`）はこれを組み立てて動かす。
//!
//! 移行中は機能を 1 つずつ移すので、作ってからイベントにつなぐまでの間がある。部品を
//! ライブラリに置くのは、その間も Python との突き合わせやテストから呼べるようにするため。

pub mod colorthief;
pub mod compat;
pub mod config;
pub mod handler;
pub mod log_channel;
pub mod members;
pub mod message_cache;
pub mod message_logs;
pub mod reaction_roles;
pub mod signals;
pub mod sticky;
pub mod vc_notify;
pub mod welcome;
