//! SYCS-Voldemort の Discord Bot（serenity）の中身。実行ファイル（`main.rs`）はこれを組み立てて動かす。
//!
//! 移行中は機能を 1 つずつ移すので、作ってからイベントにつなぐまでの間がある。部品を
//! ライブラリに置くのは、その間も Python との突き合わせやテストから呼べるようにするため。

pub mod chat;
pub mod colorthief;
pub mod commands;
pub mod compat;
pub mod config;
pub mod earthquake;
pub mod earthquake_badges;
pub mod earthquake_feed;
pub mod earthquake_text;
pub mod email_date;
pub mod groq;
pub mod guild_retention;
pub mod handler;
pub mod html_unescape;
pub mod log_channel;
pub mod members;
pub mod message_cache;
pub mod message_logs;
pub mod message_security;
pub mod metal;
pub mod moderation;
pub mod news;
pub mod python_chars;
pub mod python_repr;
pub mod reaction_roles;
pub mod security;
pub mod signals;
pub mod sticky;
pub mod tts;
pub mod user_state;
pub mod user_state_repair;
pub mod user_state_sync;
pub mod vc_notify;
pub mod virustotal;
pub mod welcome;
