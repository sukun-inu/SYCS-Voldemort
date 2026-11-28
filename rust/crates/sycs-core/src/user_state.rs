//! 利用者の状態の 2 つの表（`user_state_current`・`user_state_event`）の形と、自己修復で直りうる失敗の見分け方。
//!
//! Python では `webapp/models.py` の `UserStateCurrent`・`UserStateEvent`（SQLAlchemy が作る表）と、
//! `services/user_state_service.py` の `_is_repairable_db_error`。
//!
//! 同じ表を Bot（書く側。`apps/bot` の `user_state`・同期・修復）と管理画面（読む側。`apps/admin` の `users`）が
//! 使う。どちらも、表が無ければ作り（Python の `ensure_user_state_db`）、表が消えたなどの失敗では作り直して 1 回だけ
//! やり直す。形を 1 か所にしておかないと、片方だけ列や索引が食い違う（形が Python と同じことは、Bot の
//! `tests/user_state_golden.rs` の `the_tables_have_the_python_shape` が本物の Postgres で比べている）。

/// 表と索引を作る文。Python（SQLAlchemy）が作るものと同じ形（突き合わせで確かめた）。
pub const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS user_state_current (\
        id SERIAL NOT NULL, \
        guild_id BIGINT NOT NULL, \
        user_id BIGINT NOT NULL, \
        username VARCHAR(128), \
        display_name VARCHAR(128), \
        avatar_url VARCHAR(512), \
        status VARCHAR(32) NOT NULL, \
        is_in_guild BOOLEAN NOT NULL, \
        is_banned BOOLEAN NOT NULL, \
        is_timed_out BOOLEAN NOT NULL, \
        timed_out_until TIMESTAMP WITH TIME ZONE, \
        roles_json TEXT NOT NULL, \
        abilities_json TEXT NOT NULL, \
        last_event_type VARCHAR(48), \
        last_event_at TIMESTAMP WITH TIME ZONE, \
        first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        last_joined_at TIMESTAMP WITH TIME ZONE, \
        last_left_at TIMESTAMP WITH TIME ZONE, \
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        PRIMARY KEY (id), \
        CONSTRAINT uq_user_state_current_guild_user UNIQUE (guild_id, user_id))",
    "CREATE INDEX IF NOT EXISTS ix_user_state_current_guild_last_event_at \
        ON user_state_current (guild_id, last_event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_current_guild_status \
        ON user_state_current (guild_id, status)",
    "CREATE TABLE IF NOT EXISTS user_state_event (\
        id SERIAL NOT NULL, \
        guild_id BIGINT NOT NULL, \
        user_id BIGINT NOT NULL, \
        event_type VARCHAR(48) NOT NULL, \
        status_after VARCHAR(32) NOT NULL, \
        actor_user_id BIGINT, \
        actor_name VARCHAR(128), \
        reason TEXT, \
        payload_json TEXT NOT NULL, \
        event_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \
        PRIMARY KEY (id))",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_event_at ON user_state_event (event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_guild_event_type_event_at \
        ON user_state_event (guild_id, event_type, event_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_state_event_guild_user_event_at \
        ON user_state_event (guild_id, user_id, event_at)",
];

/// 自己修復（表の作り直し）で直りうる失敗か。Python の `_is_repairable_db_error`。
///
/// Python（SQLAlchemy ＋ asyncpg）で実際に当たるのは、SQLSTATE 42 系（表や列が無い・権限が無いなど）
/// だけ。接続の失敗などは当たらず、そのまま失敗になる。
pub fn is_repairable(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| code.starts_with("42"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表を作る文が、Python の列の名前を全部持っていること（形そのものは Postgres のテストで比べる）。
    #[test]
    fn the_ddl_names_the_python_tables() {
        let python = include_str!("../../../../webapp/models.py");
        assert!(python.contains("__tablename__ = \"user_state_current\""));
        assert!(python.contains("__tablename__ = \"user_state_event\""));
        let ddl = DDL.join("\n");
        for name in [
            "uq_user_state_current_guild_user",
            "ix_user_state_current_guild_status",
            "ix_user_state_current_guild_last_event_at",
            "ix_user_state_event_guild_user_event_at",
            "ix_user_state_event_guild_event_type_event_at",
            "ix_user_state_event_event_at",
        ] {
            assert!(python.contains(name) && ddl.contains(name), "{name}");
        }
        assert!(DDL.iter().all(|d| d.contains("IF NOT EXISTS")));
    }

    /// 自己修復するのは SQLSTATE 42 系だけ（接続の失敗などはしない）。
    #[test]
    fn only_schema_errors_are_repairable() {
        assert!(!is_repairable(&sqlx::Error::PoolTimedOut));
        assert!(!is_repairable(&sqlx::Error::RowNotFound));
    }
}
