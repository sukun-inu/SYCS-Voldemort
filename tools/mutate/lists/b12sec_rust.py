"""B12-sec（rust-09 の直し 9 つ）の Rust の変異。"""

KIND = "rust"
MUTS = [
    (
        "変異なし（通るはず）",
        "rust/apps/bot/src/groq.rs",
        "after.min(max_retry_after)",
        "after.min(max_retry_after)",
    ),
    (
        "IPv4 のマルチキャストを通す",
        "rust/crates/sycs-core/src/url_safety.rs",
        "IpAddr::V4(v4) => v4_is_global(v4) && !v4.is_multicast(),",
        "IpAddr::V4(v4) => v4_is_global(v4),",
    ),
    (
        "IPv6 のマルチキャストを通す",
        "rust/crates/sycs-core/src/url_safety.rs",
        "IpAddr::V6(v6) => !v6_is_private(v6) && !v6.is_multicast(),",
        "IpAddr::V6(v6) => !v6_is_private(v6),",
    ),
    (
        "retry-after に上限を付けない",
        "rust/apps/bot/src/groq.rs",
        "after.min(max_retry_after)",
        "after",
    ),
    (
        "時間切れの理由の秒を取り違える",
        "rust/apps/bot/src/virustotal.rs",
        "python_seconds(self.config.analysis_timeout)\n",
        "python_seconds(self.config.poll_interval)\n",
    ),
    (
        "VT の判定を先頭だけで決める",
        "rust/apps/bot/src/moderation.rs",
        "let max_malicious = results.iter().map(|r| r.malicious).max()?;",
        "let max_malicious = results.iter().map(|r| r.malicious).next()?;",
    ),
    (
        "発言も荒らしに数える",
        "rust/apps/bot/src/message_security.rs",
        "Some(channel) => cx.raid.peek(channel, post.user_id.get(), (cx.clock)()),",
        "Some(channel) => {\n            cx.raid.check(channel, post.user_id.get(), (cx.clock)());\n            cx.raid.peek(channel, post.user_id.get(), (cx.clock)())\n        }",
    ),
    (
        "畳んだ印をいちばん軽いものにする",
        "rust/apps/bot/src/security.rs",
        ".max_by_key(|i| icon_weight(i))",
        ".min_by_key(|i| icon_weight(i))",
    ),
    (
        "権限不足を失敗と書く",
        "rust/apps/bot/src/security.rs",
        'Some(StripFailure::Forbidden) => "権限不足",',
        'Some(StripFailure::Forbidden) => "失敗",',
    ),
]
