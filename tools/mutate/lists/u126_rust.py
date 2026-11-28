"""決めごとの U1・U2・U6（利用者の状態の記録）の Rust の変異。"""

KIND = "rust"
MUTS = [
    (
        "変異なし（通るはず）",
        "rust/apps/bot/src/user_state.rs",
        "const AUDIT_LIMIT: u8 = 50;",
        "const AUDIT_LIMIT: u8 = 50;",
    ),
    (
        "監査ログを 10 件に戻す",
        "rust/apps/bot/src/user_state.rs",
        "const AUDIT_LIMIT: u8 = 50;",
        "const AUDIT_LIMIT: u8 = 10;",
    ),
    (
        "定期の同期の既定を偽に戻す",
        "rust/apps/bot/src/user_state_sync.rs",
        'env.boolean("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", true)',
        'env.boolean("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", false)',
    ),
]
