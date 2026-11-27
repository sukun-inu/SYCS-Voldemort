//! 管理画面からの依頼（`dev_signal` 表）を巡回して実行する。Python の `events/background_tasks.py` の
//! `_process_dev_signals` と `_handle_dev_signal` にあたる。
//!
//! 取り出しは `sycs_core::signals::claim`（取り出すと同時に消える）。どの処理にも当たらない
//! 依頼は**必ず警告を出す。** 黙って消えると「受信」「完了」のログだけが残り、何も実行されない
//! まま成功に見える（Python で実際にあった）。
//!
//! まだ Rust に移していない用途の依頼も、取り出した時点で消える。名指しで警告して、
//! 何が届かなかったかを分かるようにする。

use std::future::Future;
use std::time::Duration;

use sqlx::PgPool;
use sycs_core::signals::{self, Signal};
use tracing::{info, warn};

/// 巡回の間隔。Python の dev_signal_task と同じ 30 秒。
pub const INTERVAL: Duration = Duration::from_secs(30);

/// 管理画面が置く依頼の用途名（Python の webapp_admin/api/dev.py の VALID_TASKS と、
/// 通知テストの `test_*`・地震リプレイ）。
pub const KNOWN_TASKS: &[&str] = &[
    "news_feeds",
    "sticky",
    "djaudio_cache",
    "earthquake_reconnect",
    "user_state_repair",
    "eq_replay",
];

/// Rust に移した用途。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// スティッキーの指示（貼る・消す）をいま片付ける。
    Sticky,
    /// ニュースをいま巡回する（`interval` が経ったフィードだけ。Python と同じ）。
    NewsFeeds,
    /// 地震の電文の受け取りをつなぎ直す。
    EarthquakeReconnect,
    /// 地震の電文を、本番と同じ経路で流し直す（中身は依頼の `payload`）。
    EqReplay,
}

/// 1 件をどう扱ったか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 移した用途なので実行する。
    Run(Task),
    /// 管理画面が置く用途だが、まだ Rust に移していない。
    NotPortedYet,
    /// 知らない用途（打ち間違いか、実装漏れ）。
    Unknown,
}

/// 用途名から扱いを決める（用途を移すたびにここへ足す）。
pub fn route(task: &str) -> Outcome {
    match task {
        "sticky" => Outcome::Run(Task::Sticky),
        "news_feeds" => Outcome::Run(Task::NewsFeeds),
        "earthquake_reconnect" => Outcome::Run(Task::EarthquakeReconnect),
        "eq_replay" => Outcome::Run(Task::EqReplay),
        t if KNOWN_TASKS.contains(&t) || t.starts_with("test_") => Outcome::NotPortedYet,
        _ => Outcome::Unknown,
    }
}

/// 取り出した依頼を順に扱い、ログを残す。扱いの結果を返す（テストで確かめるため）。
pub fn handle_all(batch: &[Signal]) -> Vec<Outcome> {
    batch
        .iter()
        .map(|signal| {
            info!(task = %signal.task, id = signal.id, "シグナル受信");
            let outcome = route(&signal.task);
            match outcome {
                Outcome::Run(_) => {}
                Outcome::NotPortedYet => warn!(
                    task = %signal.task,
                    "まだ Rust に移していない用途なので何もしませんでした（依頼は消えています）"
                ),
                Outcome::Unknown => {
                    warn!(task = %signal.task, "未知のシグナルなので何もしませんでした")
                }
            }
            outcome
        })
        .collect()
}

/// 止められるまで巡回する。移した用途は `run` で実行する（依頼の中身 `payload` も渡す）。データベースに届かなければ警告を
/// 出して次の巡回で取り直す（取り出しと削除は同じ文なので、取り出せなかった依頼は表に残っている）。
pub async fn run_forever<F, Fut>(pool: PgPool, run: F)
where
    F: Fn(Task, String) -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        match signals::claim(&pool, signals::CLAIM_BATCH).await {
            Ok(batch) => {
                for (signal, outcome) in batch.iter().zip(handle_all(&batch)) {
                    if let Outcome::Run(task) = outcome {
                        run(task, signal.payload.clone()).await;
                        info!(task = %signal.task, id = signal.id, "シグナル完了");
                    }
                }
            }
            Err(e) => warn!("シグナルを取り出せませんでした（次の巡回で取り直します）: {e}"),
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(task: &str) -> Signal {
        Signal {
            id: 1,
            task: task.into(),
            payload: "{}".into(),
        }
    }

    /// 移した用途は実行し、管理画面が置くほかの用途は「まだ移していない」、それ以外は「未知」。
    ///
    /// 区別しないと、移し忘れ（いつか移す）と打ち間違い（直す）の見分けが付かない。
    #[test]
    fn known_tasks_are_not_ported_yet_and_others_are_unknown() {
        assert_eq!(route("sticky"), Outcome::Run(Task::Sticky));
        assert_eq!(route("news_feeds"), Outcome::Run(Task::NewsFeeds));
        assert_eq!(route("djaudio_cache"), Outcome::NotPortedYet);
        assert_eq!(route("eq_replay"), Outcome::Run(Task::EqReplay));
        assert_eq!(
            route("earthquake_reconnect"),
            Outcome::Run(Task::EarthquakeReconnect)
        );
        assert_eq!(route("user_state_repair"), Outcome::NotPortedYet);
        assert_eq!(route("test_welcome"), Outcome::NotPortedYet);
        assert_eq!(route("mystery"), Outcome::Unknown);
    }

    /// 管理画面の用途名の一覧が、Python 側と揃っていること。
    ///
    /// 管理画面に用途を足して Rust に足し忘れると、その依頼は「未知」として捨てられる。
    #[test]
    fn the_task_list_matches_the_admin_panel() {
        let admin = include_str!("../../../../webapp_admin/api/dev.py");
        let start = admin
            .find("VALID_TASKS: dict[str, str] = {")
            .expect("VALID_TASKS が見つからない");
        let block = &admin[start..start + admin[start..].find('}').unwrap()];
        for line in block.lines().skip(1) {
            if let Some(name) = line
                .trim()
                .strip_prefix('"')
                .and_then(|l| l.split('"').next())
            {
                assert!(
                    KNOWN_TASKS.contains(&name),
                    "Rust の KNOWN_TASKS に無い: {name}"
                );
            }
        }
    }

    /// 1 件ずつ扱い、件数ぶんの結果が返ること。
    #[test]
    fn every_claimed_signal_is_handled_in_order() {
        let outcomes = handle_all(&[signal("sticky"), signal("djaudio_cache"), signal("nope")]);
        assert_eq!(
            outcomes,
            [
                Outcome::Run(Task::Sticky),
                Outcome::NotPortedYet,
                Outcome::Unknown
            ]
        );
    }
}
