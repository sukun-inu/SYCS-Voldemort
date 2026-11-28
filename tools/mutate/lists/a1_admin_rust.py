"""A1（管理画面の骨組み。rust/apps/admin）の Rust の変異。

セッションの Cookie と秘密鍵（基準 rust/apps/admin/tests/fixtures/session/）、エラーの答え・経路・確かめ・回数の制限・
数とインシデント（基準 rust/apps/admin/tests/fixtures/errors/）を、本物の Python と突き合わせて確かめている。その基準と
ユニットテストが、下の壊れをそれぞれ捕まえること。
"""

KIND = "rust"
APP = "rust/apps/admin/src/app.rs"
ERR = "rust/apps/admin/src/errors.rs"
MET = "rust/apps/admin/src/metrics.rs"
PY = "rust/apps/admin/src/python.rs"
RL = "rust/apps/admin/src/ratelimit.rs"
RT = "rust/apps/admin/src/routing.rs"
SEC = "rust/apps/admin/src/security.rs"
SECRET = "rust/apps/admin/src/secret.rs"
SES = "rust/apps/admin/src/session.rs"
MUTS = [
    (
        "変異なし（通るはず）",
        SES,
        "    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0",
        "    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0",
    ),
    (
        "期限ちょうど（3600 秒前）の Cookie を読まない",
        SES,
        "        if age > i128::from(max_age) || age < 0 {",
        "        if age >= i128::from(max_age) || age < 0 {",
    ),
    ("1 秒未来の Cookie も読む", SES, "|| age < 0 {", "|| age < -1 {"),
    (
        "触っただけのセッションも書き直す（starlette 1.x は書き換えたときだけ）",
        SES,
        "        if !session.modified() {",
        "        if !session.modified() && !session.accessed() {",
    ),
    (
        "空にしたとき、読んだセッションでも消す Cookie を出さない",
        SES,
        "        session.was_loaded().then(|| {",
        "        (!session.was_loaded()).then(|| {",
    ),
    (
        "見張りの層が admin_guilds を削らない",
        SES,
        '    if session.contains_key("admin_guilds") {',
        '    if session.contains_key("admin_guild") {',
    ),
    (
        "既定の書き方で 0x7F を逃がさない",
        PY,
        "            c if ensure_ascii && !(' '..='~').contains(&c) => {",
        "            c if ensure_ascii && !(' '..='\\u{7f}').contains(&c) => {",
    ),
    (
        "小数の repr が 1e15 から指数の形になる",
        PY,
        "    let body = if point <= -4 || point > 16 {",
        "    let body = if point <= -4 || point > 15 {",
    ),
    (
        "base64 の詰め物で止まらない",
        PY,
        "                if quad + pads >= 4 {",
        "                if quad + pads >= 5 {",
    ),
    (
        "Cookie の 8 進の先頭に 4〜7 も許す",
        PY,
        "            ('0'..='3').contains(&digits[0])",
        "            ('0'..='7').contains(&digits[0])",
    ),
    (
        "; のある Content-Type も小文字にする（python-multipart はしない）",
        SEC,
        "    python::strip(&first).to_string()",
        "    python::strip(&first.to_lowercase()).to_string()",
    ),
    (
        "フォームの csrf_token が空でも見出しへ回らない",
        SEC,
        "        Some(value) if !value.is_empty() => value.to_string(),",
        "        Some(value) => value.to_string(),",
    ),
    (
        "ASCII でない印を例外にせず 403 にする",
        SEC,
        "    if !token.is_ascii() || !expected.is_ascii() {",
        "    if false {",
    ),
    (
        "check_dev が user の偽を見ない（{\"user\": {}} を 303 にしない）",
        SEC,
        '    let Some(user) = session.get("user").filter(|user| python::truthy(user)) else {',
        '    let Some(user) = session.get("user") else {',
    ),
    (
        "フォームの欄を 1001 まで許す",
        SEC,
        "        if items.len() > MAX_FIELDS {",
        "        if items.len() > MAX_FIELDS + 1 {",
    ),
    (
        "Accept に text/html があっても JSON にする",
        ERR,
        '    accept.contains("application/json") && !accept.contains("text/html")',
        '    accept.contains("application/json")',
    ),
    (
        "/staticx を数える（Python は /static で始まるものを全部数えない）",
        APP,
        '                if !url_path.starts_with("/static") {',
        '                if !url_path.starts_with("/static/") {',
    ),
    (
        "拾えなかった例外をインシデントにしない",
        APP,
        "                self.metrics.record_exception(&crash, &snapshot);",
        "                let _ = &snapshot;",
    ),
    (
        "例外の文を 501 文字で切る",
        MET,
        "        let message: String = crash.message.chars().take(500).collect();",
        "        let message: String = crash.message.chars().take(501).collect();",
    ),
    (
        "500 ちょうどをインシデントにしない",
        MET,
        "        if status < 500 {",
        "        if status <= 500 {",
    ),
    (
        "上限ちょうどの回で断る",
        RL,
        "        window.count <= u64::from(per_minute)",
        "        window.count < u64::from(per_minute)",
    ),
    (
        "app に直に足した経路にも既定の回数の制限を掛けない",
        RT,
        "            default_limit: true,",
        "            default_limit: false,",
    ),
    (
        "末尾の / を 1 つだけ落として付け替える",
        RT,
        "            path.trim_end_matches('/').to_string()",
        "            path[..path.len() - 1].to_string()",
    ),
    (
        "Python の $ と違い、末尾の改行の前で当てない",
        RT,
        '    pattern.push_str("\\n?\\\\z");',
        '    pattern.push_str("\\\\z");',
    ),
    (
        "秘密鍵のファイルの長さをバイトで数える",
        SECRET,
        "    Ok((content.chars().count() >= MIN_SECRET_LEN).then(|| content.to_string()))",
        "    Ok((content.len() >= MIN_SECRET_LEN).then(|| content.to_string()))",
    ),
]
