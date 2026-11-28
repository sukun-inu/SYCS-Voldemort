"""A3（管理画面のログインとサーバー選択。rust-06）の Rust の変異。

ログイン・認可・戻り・ログアウト・サーバー選択・公開ページの経路と Discord の確かめが Python と同じ答えを
返すこと（基準 rust/apps/admin/tests/fixtures/auth/・admin_check/・templates/。本物の Python を偽物の Discord に
当てて作った）を、rust/apps/admin/tests/views_golden.rs とユニットテストが確かめている。下の壊れを、
そのどちらかがそれぞれ捕まえること。
"""

KIND = "rust"
V = "rust/apps/admin/src/views.rs"
A = "rust/apps/admin/src/auth.rs"
MUTS = [
    ("変異なし（通るはず）", V, "pub const LOGIN_PER_MINUTE: u32 = 30;", "pub const LOGIN_PER_MINUTE: u32 = 30;"),
    (
        "ログイン画面の上限を 1 分 31 回にする",
        V,
        "pub const LOGIN_PER_MINUTE: u32 = 30;",
        "pub const LOGIN_PER_MINUTE: u32 = 31;",
    ),
    (
        "ログイン中のとき、サーバーを選んでいてもサーバー選択へ送る",
        V,
        'if session.contains_key("guild_id") {',
        'if session.contains_key("guild_name_x") {',
    ),
    (
        "戻りの error が空でも「キャンセル」にする",
        V,
        ".is_some_and(|error| !error.is_empty())",
        ".is_some()",
    ),
    (
        "oauth_state を取り出さずに読むだけにする",
        V,
        'session.pop("oauth_state")',
        'session.get("oauth_state").cloned()',
    ),
    (
        "ASCII でない state も比べてしまう（Python は TypeError で 500）",
        V,
        "if !state.is_ascii() || !expected.is_ascii() {",
        "if false {",
    ),
    (
        "ログインの確定でセッションを空にしない",
        V,
        "        session.clear();\n        let user = user_record(&user_info)?;",
        "        let user = user_record(&user_info)?;",
    ),
    (
        "ログアウトで知らせを積んでから空にする",
        V,
        '        session.clear();\n        flash(session, LOGGED_OUT, "info")',
        '        flash(session, LOGGED_OUT, "info")?;\n        session.clear();\n        Ok::<(), Failure>(())',
    ),
    (
        "ログアウトの GET を POST より先に並べる（405 の Allow が変わる）",
        V,
        '        Route::new("/admin/logout", &[Method::POST], with_site(site, logout)),\n'
        '        Route::new("/admin/logout", &get, with_site(site, logout_confirm)),',
        '        Route::new("/admin/logout", &get, with_site(site, logout_confirm)),\n'
        '        Route::new("/admin/logout", &[Method::POST], with_site(site, logout)),',
    ),
    (
        "選んだサーバーの ID を Python の int() でなく Rust の parse で読む",
        V,
        "let Some(guild_id) = python::int_text(&Value::String(raw.to_string())) else {",
        "let Some(guild_id) = raw.parse::<u64>().ok().map(|id| id.to_string()) else {",
    ),
    ("一覧が古いかを >= で比べる", V, "if app.now() - checked > max_age {", "if app.now() - checked >= max_age {"),
    (
        "管理者と分かっても、取った時刻を新しくしない",
        V,
        '.with(|session| session.insert("admin_guilds_at", float_value(now)));',
        '.with(|session| session.insert("admin_guilds_at_x", float_value(now)));',
    ),
    ("管理者でなくなったとき、選んでいたサーバーを外さない", V, 'session.pop("guild_id");', 'session.get("guild_id");'),
    (
        "文書のページに既定の回数の制限を掛けない",
        V,
        "        routes.push(Route::top_level(\n            path,",
        "        routes.push(Route::new(\n            path,",
    ),
    (
        "空白を + でなく %20 にする（quote_plus でなく quote）",
        A,
        'python::quote(text, " ").replace(\' \', "+")',
        'python::quote(text, "")',
    ),
    ("400 番台の答えも JSON として読む", A, "if answer.status >= 400 {", "if answer.status >= 500 {"),
    (
        "Content-Type を見ずに JSON として読む",
        A,
        "if !is_json_mimetype(&kind) {",
        "if false && !is_json_mimetype(&kind) {",
    ),
    (
        "負の数の permissions を 2 の補数にしない",
        A,
        "let rest = if negative { (16 - rest) % 16 } else { rest };",
        "let rest = if negative { rest } else { rest };",
    ),
    (
        "本人のサーバーに id が無い要素を飛ばす（Python は KeyError で 500）",
        A,
        'let id = py_subscript(&guild, "id")?;',
        'let Ok(id) = py_subscript(&guild, "id") else {\n            continue;\n        };',
    ),
    (
        "サーバー数をちょうど 300 秒まで使い回す",
        A,
        ".filter(|(_, at)| now - at < GUILD_COUNT_TTL)",
        ".filter(|(_, at)| now - at <= GUILD_COUNT_TTL)",
    ),
    ("Discord が 0 でも設定のあるサーバーの数を見ない", A, "if count == 0 {", "if count == usize::MAX {"),
    (
        "サーバーかメンバーの 404 を「分からない」にする",
        A,
        "Ok(answer) if answer.status == 404 => Fetched::NotFound,",
        "Ok(answer) if answer.status == 4040 => Fetched::NotFound,",
    ),
    (
        "持ち主かをサーバーの ID と比べる",
        A,
        "if python::str_of(owner) == user_id {",
        "if python::str_of(owner) == guild_id {",
    ),
    (
        "@everyone（ID がサーバーの ID のロール）を見ない",
        A,
        "if !held.contains(&role_id) && role_id != guild_id {",
        "if !held.contains(&role_id) {",
    ),
    (
        "prompt を認可の URL に付けない",
        A,
        'if config.prompt == "none" || config.prompt == "consent" {',
        "if false {",
    ),
]
