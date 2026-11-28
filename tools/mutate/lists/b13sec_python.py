"""B13-sec（セキュリティの判定の作り直し。本人が決めた S1〜S8）の Python の変異。"""

KIND = "python"
MUTS = [
    (
        "変異なし（通るはず）",
        "services/spam_detection.py",
        "is_repeat = len(same) >= SPAM_REPEAT_COUNT",
        "is_repeat = len(same) >= SPAM_REPEAT_COUNT",
    ),
    (
        "S3 繰り返しを 1 回遅らせる",
        "services/spam_detection.py",
        "is_repeat = len(same) >= SPAM_REPEAT_COUNT",
        "is_repeat = len(same) > SPAM_REPEAT_COUNT",
    ),
    (
        "S3 casefold の代わりに lower で揃える",
        "services/spam_detection.py",
        'unicodedata.normalize("NFKC", content or "").casefold().split()',
        'unicodedata.normalize("NFKC", content or "").lower().split()',
    ),
    (
        "S2 一度返した投稿をまた返す（消し直す）",
        "services/spam_detection.py",
        "fresh = [p for p in counted if not p.taken]",
        "fresh = list(counted)",
    ),
    (
        "S1 権限があってもロールを外す",
        "services/security_service.py",
        "    if use_timeout(member.guild):\n        return await timeout_member(member, seconds), None",
        "    if False:\n        return await timeout_member(member, seconds), None",
    ),
    (
        "切り替え 既定を有効にする（未設定のサーバーでもタイムアウトする）",
        "services/settings_store.py",
        'return bool(get_guild_settings(guild_id).get("security_timeout_enabled", False))',
        'return bool(get_guild_settings(guild_id).get("security_timeout_enabled", True))',
    ),
    (
        "切り替え 権限だけで決める（無効にしてあってもタイムアウトする）",
        "services/security_service.py",
        "return can_timeout(guild) and timeout_enabled(guild.id)",
        "return can_timeout(guild)",
    ),
    (
        "切り替え 設定だけで決める（権限が無くてもタイムアウトを試す）",
        "services/security_service.py",
        "return can_timeout(guild) and timeout_enabled(guild.id)",
        "return timeout_enabled(guild.id)",
    ),
    (
        "切り替え 読めない設定を有効とみなす",
        "services/security_service.py",
        "            exc_info=True,\n        )\n        return False\n\n\ndef use_timeout",
        "            exc_info=True,\n        )\n        return True\n\n\ndef use_timeout",
    ),
    (
        "S1 タイムアウトが断られてもロールを外す",
        "services/security_service.py",
        "return await timeout_member(member, seconds), None",
        "return await timeout_member(member, seconds), await strip_roles(member)",
    ),
    (
        "S2 スパムだけでも 24 時間",
        "services/security_service.py",
        "timeout_member(member, SECURITY_TIMEOUT_SPAM_SECONDS)",
        "timeout_member(member, SECURITY_TIMEOUT_DANGER_SECONDS)",
    ),
    (
        "S2 スパムと数えた前の投稿を消さない",
        "services/security_service.py",
        "posts = list(findings.spam_posts)",
        "posts = []",
    ),
    (
        "S4 数に入っていない常連も VC_RAID にする",
        "services/raid_detection.py",
        "return len(people) >= VC_RAID_THRESHOLD and user_id in people",
        "return len(people) >= VC_RAID_THRESHOLD",
    ),
    (
        "S4 入って間もなくない人も数える",
        "services/security_service.py",
        "    if not channel or not is_fresh_joiner(member):",
        "    if not channel:",
    ),
    (
        "S5 7 日ちょうども新しいアカウントにする",
        "services/security_service.py",
        "return (discord.utils.utcnow() - created).days < content_moderation.NEW_ACCOUNT_THRESHOLD_DAYS",
        "return (discord.utils.utcnow() - created).days <= content_moderation.NEW_ACCOUNT_THRESHOLD_DAYS",
    ),
    (
        "S6 隠しリンクの文ごと拾う",
        "services/security_service.py",
        "found.append((m.start(), m.group(1)))",
        "found.append((m.start(), m.group(0)))",
    ),
    (
        "S6 対になった ) も落とす",
        "services/security_service.py",
        'if u.endswith(")") and u.count("(") < u.count(")"):',
        'if u.endswith(")"):',
    ),
    (
        "S7 管理者を飛ばさない",
        "services/security_service.py",
        '    if _is_administrator(member):\n        return BypassResult(True, "administrator")',
        '    if False:\n        return BypassResult(True, "administrator")',
    ),
    (
        "S7 サーバーの管理の権限で飛ばす",
        "services/security_service.py",
        'return getattr(member.guild_permissions, "administrator", False) is True',
        'return getattr(member.guild_permissions, "manage_guild", False) is True',
    ),
    (
        "S8 スパムの見出しも赤にする",
        "services/security_service.py",
        'return title, discord.Color.red() if enforcement.action == "danger" else discord.Color.orange()',
        "return title, discord.Color.red()",
    ),
    (
        "S8 措置しても INFO で報告する",
        "services/security_service.py",
        'level = "ERROR" if acted else "INFO"',
        'level = "INFO"',
    ),
]
