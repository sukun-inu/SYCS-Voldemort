//! 管理画面から Bot への依頼を取り出す。Python の `services/dev_signals.py` と同じ表・同じ取り出し方。
//!
//! 管理画面が `dev_signal` 表に 1 行置き、Bot が巡回のたびに取り出して実行する。移行中は
//! Python の管理画面が置き、Rust の Bot が取り出すことになるので、取り出しの SQL を揃える。
//!
//! **取り出すと同時に消す**（1 文の `DELETE … RETURNING`）。処理の途中で Bot が落ちれば
//! その依頼は失われるが、二重に実行されるよりよい（テスト通知や地震リプレイが 2 回飛ぶ）。
//! 行ロックを取って、ロックされている行は飛ばす（`FOR UPDATE SKIP LOCKED`）ので、Bot を
//! 複数動かしても、Python と Rust の Bot が並んでいても、同じ依頼を 2 つが拾わない。
//! 処理は置かれた順（`id` の昇順）。`RETURNING` の返す順は保証されないので並べ直す。

use sqlx::PgPool;

/// 1 回の巡回で取り出す上限。Python の `dev_signals.CLAIM_BATCH`。
pub const CLAIM_BATCH: i64 = 50;

/// 取り出しの SQL。Python が組み立てる文と同じ形（古い順に上限つきで選び、ロック中の行は飛ばし、
/// 選んだ行を消して返す）。
pub const CLAIM_SQL: &str = "DELETE FROM dev_signal WHERE id IN (\
    SELECT id FROM dev_signal ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED\
) RETURNING id, task, payload";

/// 取り出した依頼 1 件。`payload` は置いたときの文字列（JSON）のまま。
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Signal {
    /// 置かれた順の番号。
    pub id: i64,
    /// 用途名（`news_feeds`・`eq_replay` など）。
    pub task: String,
    /// 中身。
    pub payload: String,
}

/// 待っている依頼を置かれた順に `limit` 件まで取り出し、表から消す。
pub async fn claim(pool: &PgPool, limit: i64) -> Result<Vec<Signal>, sqlx::Error> {
    let mut signals: Vec<Signal> = sqlx::query_as(CLAIM_SQL)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    signals.sort_by_key(|s| s.id);
    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 取り出しの文が、行ロックを取ってロック中の行を飛ばし、古い順に選ぶこと。
    ///
    /// SKIP LOCKED が無いと、Bot が 2 つあるとき（移行中は Python と Rust の Bot が並び
    /// うる）同じ依頼を両方が拾い、地震リプレイやテスト通知が二重に飛ぶ。
    #[test]
    fn the_claim_skips_locked_rows_and_takes_the_oldest_first() {
        assert!(CLAIM_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assert!(CLAIM_SQL.contains("ORDER BY id LIMIT"));
        assert!(!CLAIM_SQL.contains("DESC"));
        assert!(CLAIM_SQL.starts_with("DELETE FROM dev_signal"));
        assert!(CLAIM_SQL.ends_with("RETURNING id, task, payload"));
    }

    /// 上限が Python と同じであること。
    #[test]
    fn the_batch_size_matches_python() {
        let python = include_str!("../../../../services/dev_signals.py");
        assert!(python.contains(&format!("CLAIM_BATCH = {CLAIM_BATCH}")));
    }
}
