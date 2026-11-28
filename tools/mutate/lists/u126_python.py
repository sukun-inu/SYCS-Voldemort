"""決めごとの U1・U2・U6（利用者の状態の記録）の Python の変異。"""

KIND = "python"
MUTS = [
    (
        "変異なし（通るはず）",
        "events/user_state_sync.py",
        "_AUDIT_LOG_LIMIT = 50",
        "_AUDIT_LOG_LIMIT = 50",
    ),
    (
        "監査ログを 10 件に戻す",
        "events/user_state_sync.py",
        "_AUDIT_LOG_LIMIT = 50",
        "_AUDIT_LOG_LIMIT = 10",
    ),
    (
        "定期の同期の既定を偽に戻す",
        "events/user_state_sync.py",
        'env_bool("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", True)',
        'env_bool("USER_STATE_AUTO_REPAIR_WRITE_EVENTS", False)',
    ),
    (
        "監査ログをお別れより先に読む",
        "events/members.py",
        '    await _safe(send_goodbye(member), "on_member_remove goodbye")\n\n    try:\n        kick_entry = await _find_recent_audit_entry(\n            member.guild,\n            action=discord.AuditLogAction.kick,\n            target_user_id=member.id,\n        )\n        if kick_entry is not None:\n            event_type = "member_kick"\n            status_after = "kicked"\n            actor_user = kick_entry.user\n            audit_reason = kick_entry.reason\n    except Exception as e:\n        logger.debug("[BOT_SETUP] on_member_remove kick lookup failed: %s", e)\n',
        '    try:\n        kick_entry = await _find_recent_audit_entry(\n            member.guild,\n            action=discord.AuditLogAction.kick,\n            target_user_id=member.id,\n        )\n        if kick_entry is not None:\n            event_type = "member_kick"\n            status_after = "kicked"\n            actor_user = kick_entry.user\n            audit_reason = kick_entry.reason\n    except Exception as e:\n        logger.debug("[BOT_SETUP] on_member_remove kick lookup failed: %s", e)\n\n    await _safe(send_goodbye(member), "on_member_remove goodbye")\n',
    ),
]
