//! サーバーのデータの削除（rust-06 の A6）。Python の `services/guild_retention.py` の `delete_guild_data` と、そこから
//! 呼ぶ `services/user_state_service.py` の `delete_guild_user_states`・`services/settings_store.py` の
//! `delete_guild_settings`。
//!
//! **消すのは利用者が決める**（管理画面の「このサーバーのデータを削除」）。消すのは、そのサーバーについて残っている
//! もの全部:
//!
//! 1. 利用者の状態の監査履歴と現在の状態（Postgres の `user_state_event`・`user_state_current`。同じトランザクションで
//!    消す。表が無いなどの失敗では表を作り直して 1 回だけやり直す）。**失敗しても設定は消す**（ログに残し、消した数は 0）
//! 2. 設定（`bot_settings_guild` の 1 行。[`crate::apps::store::SettingsStore::transact`] で消すので、版番号が上がり、
//!    Bot に知らせが届く）。こちらの失敗はそのまま返す（Python も拾わない。500）
//!
//! 何をいくつ消したかを返す（[`Removed`]。画面とログに出す）。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use sqlx::PgPool;
use sycs_core::user_state::is_repairable;
use tracing::{error, warn};

use crate::apps::setters;
use crate::apps::store;
use crate::apps::Panels;
use crate::errors::Crash;
use crate::python;
use crate::users::store::PgUserStates;

/// 消した数（`{"settings", "events", "states"}`）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// 設定（消したら 1、無ければ 0）。
    pub settings: i64,
    /// 監査履歴の行。
    pub events: i64,
    /// 現在の状態の行。
    pub states: i64,
}

/// 利用者の状態を消した数（`delete_guild_user_states` の `{"events", "states"}`）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// 監査履歴の行。
    pub events: i64,
    /// 現在の状態の行。
    pub states: i64,
}

/// 消す処理の future（失敗は理由の文。呼ぶ側はログに残して 0 として続ける）。
pub type EraseFuture<'a> = Pin<Box<dyn Future<Output = Result<Counts, String>> + Send + 'a>>;

/// 利用者の状態を消すもの（`delete_guild_user_states`）。本番は [`PgUserStateEraser`]、テストは偽物。
pub trait UserStateEraser: Send + Sync {
    /// そのサーバーの監査履歴と現在の状態を消す（`guild_id` は 10 進の文字）。
    fn delete_guild(&self, guild_id: &str) -> EraseFuture<'_>;
}

/// つないでいないもの（消すたびに失敗する。設定は消える。`--self-check` と、設定パネルを使わないテスト）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Unconfigured;

impl UserStateEraser for Unconfigured {
    fn delete_guild(&self, _guild_id: &str) -> EraseFuture<'_> {
        Box::pin(async { Err("利用者の状態の置き場につないでいません".to_string()) })
    }
}

/// 監査履歴の行を消す文。
const DELETE_EVENTS: &str = "DELETE FROM user_state_event WHERE guild_id = $1";
/// 現在の状態の行を消す文。
const DELETE_STATES: &str = "DELETE FROM user_state_current WHERE guild_id = $1";

/// Postgres（`user_state_audit`）から消すもの。表を作ったかは、利用者の状態の読み出し（A4）と同じものが覚えている。
pub struct PgUserStateEraser {
    pool: PgPool,
    users: Arc<PgUserStates>,
}

impl std::fmt::Debug for PgUserStateEraser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUserStateEraser").finish_non_exhaustive()
    }
}

impl PgUserStateEraser {
    /// 作る（`users` は利用者の状態の読み出しに渡すものと同じもの）。
    pub fn new(pool: PgPool, users: Arc<PgUserStates>) -> Self {
        Self { pool, users }
    }

    async fn delete_once(&self, guild_id: i64) -> Result<Counts, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let events = sqlx::query(DELETE_EVENTS)
            .bind(guild_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let states = sqlx::query(DELETE_STATES)
            .bind(guild_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(Counts {
            events: i64::try_from(events).unwrap_or(i64::MAX),
            states: i64::try_from(states).unwrap_or(i64::MAX),
        })
    }

    /// `delete_guild_user_states`（`ensure_user_state_db` のあと、直りうる失敗なら 1 回だけ作り直してやり直す）。
    async fn delete(&self, guild_id: &str) -> Result<Counts, String> {
        self.users
            .ensure_tables(false)
            .await
            .map_err(|e| e.to_string())?;
        // Postgres の bigint に収まらない ID は、Python では asyncpg が断る（同じく失敗として扱う）。
        let guild: i64 = guild_id
            .parse()
            .map_err(|_| format!("guild_id {guild_id} is out of int64 range"))?;
        let mut first = true;
        loop {
            match self.delete_once(guild).await {
                Ok(counts) => return Ok(counts),
                Err(e) if first && is_repairable(&e) => {
                    warn!(
                        "[user_state_service] delete_guild_user_states failed with DB error. trying self-heal: {e}"
                    );
                    if let Err(heal) = self.users.ensure_tables(true).await {
                        error!(
                            "[user_state_service] DB self-heal failed at delete_guild_user_states: {heal}"
                        );
                        return Err(e.to_string());
                    }
                    first = false;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

impl UserStateEraser for PgUserStateEraser {
    fn delete_guild(&self, guild_id: &str) -> EraseFuture<'_> {
        let guild_id = guild_id.to_string();
        Box::pin(async move { self.delete(&guild_id).await })
    }
}

/// `guild_retention.delete_guild_data`（利用者の状態 → 設定の順に消す）。
pub async fn delete_guild_data(panels: &Panels, guild_id: &str) -> Result<Removed, Crash> {
    let mut removed = Removed::default();
    match panels.user_states.delete_guild(guild_id).await {
        Ok(counts) => {
            removed.events = counts.events;
            removed.states = counts.states;
        }
        Err(e) => {
            error!(
                "[retention] 監査履歴を消せませんでした guild={guild_id}（設定は消します）: {e}"
            );
        }
    }
    // `awrite(delete_guild_settings, guild_id)`（失敗はそのまま返す）。
    let deleted: Value = panels
        .settings()
        .transact(setters::delete_guild_settings(guild_id))
        .await?;
    store::log_write("delete_guild_settings", guild_id);
    removed.settings = i64::from(python::truthy(&deleted));
    warn!(
        "[retention] ギルドのデータを削除 guild={guild_id} 設定={} 履歴={} 現在状態={}",
        removed.settings, removed.events, removed.states
    );
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sycs_core::settings::Settings;

    use super::*;
    use crate::apps::getters::DjaudioDefaults;
    use crate::apps::store::{SettingsStore, settings_from_document};
    use crate::apps::voices::Voices;

    struct Failing;

    impl UserStateEraser for Failing {
        fn delete_guild(&self, _guild_id: &str) -> EraseFuture<'_> {
            Box::pin(async { Err("つながらない".to_string()) })
        }
    }

    struct Fixed;

    impl UserStateEraser for Fixed {
        fn delete_guild(&self, _guild_id: &str) -> EraseFuture<'_> {
            Box::pin(async {
                Ok(Counts {
                    events: 3,
                    states: 2,
                })
            })
        }
    }

    fn make_panels(settings: SettingsStore, eraser: Arc<dyn UserStateEraser>) -> Panels {
        Panels::new(Arc::new(settings), Voices::disabled(), DjaudioDefaults::PYTHON)
            .with_user_state_eraser(eraser)
    }

    fn stored(guilds: serde_json::Value) -> Settings {
        let mut settings = settings_from_document(&json!({ "guilds": guilds }));
        settings.version = 1;
        settings
    }

    /// 設定と利用者の状態を両方消し、消した数を返すこと。設定が無ければ 0。
    #[tokio::test]
    async fn both_settings_and_user_states_are_removed() {
        let store = SettingsStore::memory(stored(json!({"1": {"a": 1}, "2": {}})), "STAMP");
        let panels = make_panels(store, Arc::new(Fixed));
        let removed = delete_guild_data(&panels, "1").await.unwrap();
        assert_eq!(
            removed,
            Removed {
                settings: 1,
                events: 3,
                states: 2
            }
        );
        let after = panels.settings().try_snapshot().unwrap();
        assert!(!after.guilds.contains_key("1"));
        assert_eq!(after.version, 2);
        let again = delete_guild_data(&panels, "1").await.unwrap();
        assert_eq!(again.settings, 0);
    }

    /// 利用者の状態を消せなくても設定は消し、設定を読み込めなければ例外のまま返すこと。
    #[tokio::test]
    async fn a_failed_user_state_deletion_still_removes_the_settings() {
        let store = SettingsStore::memory(stored(json!({"1": {"a": 1}})), "STAMP");
        let panels = make_panels(store, Arc::new(Failing));
        let removed = delete_guild_data(&panels, "1").await.unwrap();
        assert_eq!(
            removed,
            Removed {
                settings: 1,
                events: 0,
                states: 0
            }
        );
        let failing = make_panels(SettingsStore::failing("読めない"), Arc::new(Fixed));
        let crash = delete_guild_data(&failing, "1").await.unwrap_err();
        assert_eq!(crash.kind, "SettingsNotLoaded");
    }
}
