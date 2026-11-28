"""A2（管理画面のテンプレート。rust-06）の Rust の変異。

テンプレートは Python と同じ HTML を書くこと（基準 rust/apps/admin/tests/fixtures/templates/。Jinja2・markupsafe と
webapp_admin/templating.py から作った）を、rust/apps/admin/tests/templates_golden.rs とユニットテストが確かめている。
下の壊れを、そのどちらかがそれぞれ捕まえること。
"""

KIND = "rust"
M = "rust/apps/admin/src/templates/markup.rs"
G = "rust/apps/admin/src/templates/globals.rs"
T = "rust/apps/admin/src/templates/mod.rs"
MUTS = [
    ("変異なし（通るはず）", M, """'"' => out.push_str("&#34;"),""", """'"' => out.push_str("&#34;"),"""),
    (
        "' を minijinja の既定と同じ &#x27; にする",
        M,
        r"""'\'' => out.push_str("&#39;"),""",
        r"""'\'' => out.push_str("&#x27;"),""",
    ),
    (
        '" を minijinja の既定と同じ &quot; にする',
        M,
        """'"' => out.push_str("&#34;"),""",
        """'"' => out.push_str("&quot;"),""",
    ),
    (
        "/ も逃がす（minijinja の既定。招待リンクと static の URL が変わる）",
        M,
        """'"' => out.push_str("&#34;"),""",
        """'"' => out.push_str("&#34;"),\n            '/' => out.push_str("&#x2f;"),""",
    ),
    (
        "None を minijinja と同じ none と書く",
        M,
        'ValueKind::None => "None".to_string(),',
        'ValueKind::None => "none".to_string(),',
    ),
    (
        "True・False を小文字で書く",
        M,
        'String::from(if value.is_true() { "True" } else { "False" })',
        'String::from(if value.is_true() { "true" } else { "false" })',
    ),
    (
        "未定義を None と書く",
        M,
        "    if value.is_undefined() {\n        return Ok(());",
        '    if value.is_undefined() {\n        return out.write_str("None").map_err(|_| Error::new(ErrorKind::InvalidOperation, "x"));',
    ),
    ("印の付いた値（icon）も逃がす", M, "if value.is_safe() {", "if false && value.is_safe() {"),
    ("小数の指数の境を 17 にする", M, "(-4..16).contains(&exponent)", "(-4..17).contains(&exponent)"),
    ("小数も整数と同じ形で書く", M, "if number.is_f64() =>", "if false =>"),
    (
        "アイコンの名前の bi- を落とさない",
        G,
        'let ident = name.strip_prefix("bi-").unwrap_or(name);',
        "let ident = name;",
    ),
    (
        "アイコンの名前の末尾の改行を通さない",
        G,
        "let core = ident.strip_suffix('\\n').unwrap_or(ident);",
        "let core = ident;",
    ),
    ("点つきの名前を _ にして引かない", G, """.or_else(|| route(&name.replace('.', "_")))""", ".or_else(|| None)"),
    (
        "パスを Python の realpath ではなく canonicalize で解く",
        G,
        "let resolved = python_realpath(&joined);",
        "let resolved = std::fs::canonicalize(&joined).ok()?.to_str()?.to_string();",
    ),
    ("static の外を指しても版を付ける", G, "if !Path::new(&resolved).starts_with(&self.root) {", "if false {"),
    (
        "大きさを 10 進で書く",
        G,
        '"{}-{mtime}-{:x}", self.version, meta.len()',
        '"{}-{mtime}-{}", self.version, meta.len()',
    ),
    ("更新時刻をマイクロ秒にする", G, "after.as_nanos()", "after.as_micros()"),
    (
        "NUL を含む名前を確かめない（Python は ValueError で版を付けない）",
        G,
        "if filename.contains('\\0') {",
        "if false {",
    ),
    ("知らせを取り出さない", T, '.shift_remove("_flashes")', '.get("_flashes").cloned()'),
    (
        "知らせを swap_remove で取り出す（Cookie の鍵の並びが変わる）",
        T,
        '.shift_remove("_flashes")',
        '.swap_remove("_flashes")',
    ),
    ("CSRF の印をいつも作り直す", T, ".filter(|token| markup::json_truthy(token))", ".filter(|_| false)"),
    (
        "空の CSRF の印もそのまま使う",
        T,
        ".filter(|token| markup::json_truthy(token))",
        ".filter(|token| !token.is_null())",
    ),
    (
        "最後の改行を残す",
        T,
        "env.set_keep_trailing_newline(false);",
        "env.set_keep_trailing_newline(true);",
    ),
    ("自動のエスケープを切る", T, "|_name: &str| AutoEscape::Html", "|_name: &str| AutoEscape::None"),
    ("改行を揃えない", T, """source.replace("\\r\\n", "\\n").replace('\\r', "\\n")""", "source.to_string()"),
    (
        "招待リンクの権限を 0 にする",
        T,
        "client_id={client_id}&permissions=8",
        "client_id={client_id}&permissions=0",
    ),
    ("旧 URL の行き先に / を足す", T, '("/admin/terms", "/terms"),', '("/admin/terms", "/terms/"),'),
]
