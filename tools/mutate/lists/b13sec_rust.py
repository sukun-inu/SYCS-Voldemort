"""B13-sec（セキュリティの判定の作り直し。本人が決めた S1〜S8）の Rust の変異。"""

KIND = "rust"
MUTS = [
    (
        "変異なし（通るはず）",
        "rust/apps/bot/src/security.rs",
        "let repeat = repeat_count >= rules.repeat_count;",
        "let repeat = repeat_count >= rules.repeat_count;",
    ),
    (
        "S3 繰り返しを 1 回遅らせる",
        "rust/apps/bot/src/security.rs",
        "let repeat = repeat_count >= rules.repeat_count;",
        "let repeat = repeat_count > rules.repeat_count;",
    ),
    (
        "S3 casefold の代わりに to_lowercase で揃える",
        "rust/apps/bot/src/security.rs",
        "let folded = casefold(&content.nfkc().collect::<String>());",
        "let folded = content.nfkc().collect::<String>().to_lowercase();",
    ),
    (
        "S3 量の窓ちょうど前の投稿も数える",
        "rust/apps/bot/src/security.rs",
        "let in_flood = |p: &SpamPost| now - p.at < rules.flood_window as f64;",
        "let in_flood = |p: &SpamPost| now - p.at <= rules.flood_window as f64;",
    ),
    (
        "S2 一度返した投稿をまた返す（消し直す）",
        "rust/apps/bot/src/security.rs",
        "            if !p.taken {",
        "            if true {",
    ),
    (
        "S1 権限があってもロールを外す",
        "rust/apps/bot/src/message_security.rs",
        "    if post.bot_can_timeout {",
        "    if false {",
    ),
    (
        "S1 断られたタイムアウトを成功と書く",
        "rust/apps/bot/src/message_security.rs",
        "failure: sent.err(),",
        "failure: None,",
    ),
    (
        "S2 スパムだけでも 24 時間",
        "rust/apps/bot/src/message_security.rs",
        "_ => cx.config.timeout_spam_seconds,",
        "_ => cx.config.timeout_danger_seconds,",
    ),
    (
        "S2 スパムと数えた前の投稿を消さない",
        "rust/apps/bot/src/message_security.rs",
        "let mut posts = findings.spam_posts.clone();",
        "let mut posts: Vec<(u64, u64)> = Vec::new();",
    ),
    (
        "S4 数に入っていない常連も VC_RAID にする",
        "rust/apps/bot/src/security.rs",
        "if people.len() < self.rules.threshold || !people.contains(&user_id) {",
        "if people.len() < self.rules.threshold {",
    ),
    (
        "S4 入り直しを別の人に数える",
        "rust/apps/bot/src/security.rs",
        "if now - t < window && !people.contains(&user) {",
        "if now - t < window {",
    ),
    (
        "S4 措置済みの人にもう一度措置する",
        "rust/apps/bot/src/security.rs",
        ".filter(|u| !done.contains_key(u))",
        ".filter(|_| true)",
    ),
    (
        "S5 7 日ちょうども新しいアカウントにする",
        "rust/apps/bot/src/security.rs",
        "seconds.div_euclid(86_400) < days",
        "seconds.div_euclid(86_400) <= days",
    ),
    (
        "S5 新しいアカウントの印を付けない",
        "rust/apps/bot/src/message_security.rs",
        '        flags.push("NEW_ACCOUNT".into());\n',
        "",
    ),
    (
        "S6 隠しリンクの文ごと拾う",
        "rust/apps/bot/src/security.rs",
        "found.push((whole.start(), url.as_str().to_string()));",
        "found.push((whole.start(), whole.as_str().to_string()));",
    ),
    (
        "S6 対になった ) も落とす",
        "rust/apps/bot/src/security.rs",
        "if u.ends_with(')') && u.matches('(').count() < u.matches(')').count() {",
        "if u.ends_with(')') {",
    ),
    (
        "S7 管理者を飛ばさない",
        "rust/apps/bot/src/security.rs",
        '    if is_admin {\n        return Some("administrator");',
        '    if false && is_admin {\n        return Some("administrator");',
    ),
    (
        "S8 スパムの見出しも赤にする",
        "rust/apps/bot/src/security.rs",
        "Action::Spam => ORANGE,",
        "Action::Spam => RED,",
    ),
    (
        "S8 措置しても INFO で報告する",
        "rust/apps/bot/src/message_security.rs",
        "let level = if acted { Level::Error } else { Level::Info };",
        "let level = Level::Info;",
    ),
]
