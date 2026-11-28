//! DJAudio-DL の配信（`/dlaudio/`）。Python の `services/djaudio_cdn.py`（管理画面のアプリに入っている
//! `dlaudio_router`）を置き換える。
//!
//! nginx の後ろに立ち、リンク（`/dlaudio/files/<guild_id>/<token>`）を確かめたら `X-Accel-Redirect` を返す。
//! ファイルそのものは nginx が置き場（`DJAUDIO_CACHE_DIR`。Bot と同じボリューム）から送る。答え（状態・見出し・
//! 本文・ファイル名の書き方・期限切れ・壊れた情報・別のサーバー）は、本物の Python から作った基準
//! （`tests/fixtures/dlaudio/`）と突き合わせて、Python と同じにしてある。
//!
//! - [`app`] 経路と答え（管理画面の層の写し）
//! - [`cache`] 置き場の読み方（Python の `services/djaudio_cache.py` の配信が使う分）
//! - [`page`] 断るときの文面とページ
//! - [`python`] Python の文字の判定・`quote`・`html.escape`
//!
//! 回数で断ることはしない（Python の管理画面の既定の 1 分 300 回は、この経路には効いていなかった。基準の
//! 「回数の制限」）。

pub mod app;
pub mod cache;
pub mod page;
pub mod python;
