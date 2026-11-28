"""W0・W1（Rust の web の土台 sycs-web と、配信 /dlaudio/ の apps/cdn。rust-07）の Rust の変異。

配信は Python の管理画面の /dlaudio/ と同じ答えを返すこと（基準 rust/apps/cdn/tests/fixtures/dlaudio/）、土台の
信頼するプロキシは uvicorn と同じに読むこと（基準 rust/crates/sycs-web/tests/fixtures/proxy/）を確かめている。
そのどちらか（とユニットテスト）が、下の壊れをそれぞれ捕まえること。
"""

KIND = "rust"
A = "rust/apps/cdn/src/app.rs"
C = "rust/apps/cdn/src/cache.rs"
P = "rust/apps/cdn/src/page.rs"
X = "rust/crates/sycs-web/src/proxy.rs"
MUTS = [
    (
        "変異なし（通るはず）",
        A,
        "    python::isdigit(guild_id) && python::isalnum(token) && token.chars().count() == 32",
        "    python::isdigit(guild_id) && python::isalnum(token) && token.chars().count() == 32",
    ),
    ("印の長さ 31 も通す", A, "token.chars().count() == 32", "token.chars().count() >= 31"),
    (
        "guild_id を数字ではなく英数字で確かめる",
        A,
        "python::isdigit(guild_id) && python::isalnum(token)",
        "python::isalnum(guild_id) && python::isalnum(token)",
    ),
    (
        "情報の guild_id が数の 999 でも URL の 999 と同じとみなす",
        A,
        'matches!(meta.get("guild_id"), Some(Value::String(stored)) if stored == guild_id)',
        'matches!(meta.get("guild_id"), Some(stored) if python::str_of(Some(stored)) == guild_id)',
    ),
    (
        "付け替えで末尾の / を 1 つだけ落とす",
        A,
        "            path.trim_end_matches('/').to_string()",
        "            path[..path.len() - 1].to_string()",
    ),
    (
        "付け替え先に問い合わせを付けない",
        A,
        "    if let Some(query) = request.query.as_deref().filter(|q| !q.is_empty()) {",
        "    if let Some(query) = None::<&str> {",
    ),
    (
        "HEAD も受け付ける（FastAPI は 405）",
        A,
        "        if request.method != Method::GET {",
        "        if request.method != Method::GET && request.method != Method::HEAD {",
    ),
    (
        "X-Frame-Options を SAMEORIGIN にする",
        A,
        '        reply.set("x-frame-options", "DENY");',
        '        reply.set("x-frame-options", "SAMEORIGIN");',
    ),
    ("HSTS をいつも付ける", A, "        if self.config.secure_cookies {", "        if true {"),
    (
        "Vary: Cookie を付けない（管理画面のセッションの層は、どの答えにも付ける）",
        A,
        '        reply.set("vary", "Cookie");',
        '        reply.set("x-vary", "Cookie");',
    ),
    (
        "残りの分を 61 秒で割る",
        A,
        '            "remaining_minutes": remaining / 60,',
        '            "remaining_minutes": remaining / 61,',
    ),
    (
        "Starlette の英語の既定の文（Not Found など）を理由として残す",
        A,
        "    let detail = detail.filter(|d| !d.is_empty() && *d != page::default_reason_phrase(status));",
        "    let detail = detail.filter(|d| !d.is_empty());",
    ),
    (
        "空白や日本語の名前でも filename= の形にする",
        A,
        "    let disposition = if quoted == name {",
        "    let disposition = if true {",
    ),
    (
        "ファイル名の前後の空白を落とさない",
        A,
        "    let stripped = python::strip(&kept);",
        "    let stripped = kept.as_str();",
    ),
    (
        "拡張子で終わらない名前に拡張子を足さない",
        A,
        "        name.push_str(extension);",
        '        name.push_str("");',
    ),
    (
        "/dlaudio/health に改行を 1 つ足したものを当てない（Python の $ は当てる）",
        A,
        "        if path == HEALTH || path.strip_suffix('\\n') == Some(HEALTH) {",
        "        if path == HEALTH {",
    ),
    (
        "本体がディレクトリでも送る（starlette は 500）",
        A,
        "        Ok(metadata) if metadata.is_file() => Ok(()),",
        "        Ok(_) => Ok(()),",
    ),
    ("期限ちょうどで切れたとみなす", C, "        if now > expires_at {", "        if now >= expires_at {"),
    ("期限切れを消さない", C, "            self.delete_entry(token);", "            let _ = token;"),
    (
        "UTF-8 でない情報を、置き換えて読む（Python は 500）",
        C,
        "String::from_utf8(bytes)",
        "Ok::<String, std::string::FromUtf8Error>(String::from_utf8_lossy(&bytes).into_owned())",
    ),
    (
        "拡張子の大文字小文字を問わない（Python は .MP3 を配信できない拡張子とみなす）",
        C,
        "                .find(|(known, _)| *known == text.as_str())",
        "                .find(|(known, _)| known.eq_ignore_ascii_case(text))",
    ),
    (
        "text/html も求める相手にも JSON を返す",
        P,
        '    accept.contains("application/json") && !accept.contains("text/html")',
        '    accept.contains("application/json")',
    ),
    (
        "X-Forwarded-For を左から見る",
        X,
        "        for host in hosts.iter().rev() {",
        "        for host in hosts.iter() {",
    ),
    (
        "見出しの値の NBSP などを空白とみなさない",
        X,
        "    c.is_whitespace() || ('\\u{1c}'..='\\u{1f}').contains(&c)",
        "    c.is_ascii_whitespace()",
    ),
    (
        "信頼しない相手の転送の見出しも読む",
        X,
        "    if !trusted.contains(peer) {",
        "    if false {",
    ),
    (
        "X-Forwarded-For の項目のポートを落とさない",
        X,
        "            .map(|host| without_port(host.as_str()))",
        "            .map(|host| host.clone())",
    ),
    (
        "数でないポートも落とす（uvicorn は int() で読めるときだけ落とす）",
        X,
        "        && digits.chars().all(|c| c.is_ascii_digit() || c == '_')",
        "        && digits.chars().all(|c| c != ':')",
    ),
    (
        "X-Forwarded-For が 2 つあるとき、最後の 1 つだけを読む（uvicorn はつなぐ）",
        X,
        '        let host = trusted.client_host(&x_forwarded_for.join(", "));',
        '        let host = trusted.client_host(x_forwarded_for.last().map_or("", String::as_str));',
    ),
]
