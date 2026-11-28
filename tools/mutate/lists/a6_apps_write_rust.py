"""A6（管理画面の設定パネルの書く側。rust-06）の Rust の変異。

入力の検証・書く関数・書く側の経路・サーバーのデータの削除が Python と同じ答えを返し、同じ設定を同じ鍵の並びで書き、
同じ回数だけ版番号を上げること（基準 rust/apps/admin/tests/fixtures/validation/・apps_write/。本物の Python を偽物の
Discord・読み上げの API と、SQLite に向けた本物の settings_pg の置き場で回して作った）を、
rust/apps/admin/tests/validation_golden.rs・apps_write_golden.rs とユニットテストが確かめている。下の壊れを、そのどれかが
それぞれ捕まえること。
"""

KIND = "rust"
V = "rust/apps/admin/src/apps/validation.rs"
S = "rust/apps/admin/src/apps/setters.rs"
W = "rust/apps/admin/src/apps/write.rs"
G = "rust/apps/admin/src/apps/guild_data.rs"
MUTS = [
    (
        "変異なし（通るはず）",
        V,
        'pub const CHOOSE: &str = "選択してください。";',
        'pub const CHOOSE: &str = "選択してください。";',
    ),
    (
        "0 の ID（00 など）を通す",
        V,
        '    if number == "0" {',
        '    if number == "-0" {',
    ),
    (
        "上付きの数字を、拾われない ValueError（500）ではなく誤りの文にする",
        V,
        '        return Err(Refused::Crash(Crash::new("ValueError", message)));',
        "        return Err(invalid(NOT_AN_ID));",
    ),
    (
        "ID が取れた一覧の中かを見ない",
        V,
        "    if !options.is_empty() && !rule.free_text && !options.contains(&Value::String(text)) {",
        "    if !options.is_empty() && rule.free_text && !options.contains(&Value::String(text)) {",
    ),
    (
        "数の欄が空のとき既定値を使わない",
        V,
        "    if empty && !rule.default.is_null() {",
        "    if empty && rule.default.is_null() {",
    ),
    (
        "数の下限を見ない",
        V,
        "        && compare_int(&value, min) == Ordering::Less",
        "        && compare_int(&value, min) == Ordering::Greater",
    ),
    (
        "期間の範囲の文を単位なしにする",
        V,
        "        Widget::Duration => validate_number(rule, raw, NOT_A_DURATION, humanize),",
        "        Widget::Duration => validate_number(rule, raw, NOT_A_DURATION, plain),",
    ),
    (
        "一覧が取れないとき、手入力を許していない選択も通す",
        V,
        "        return Err(invalid(NO_CHOICES));",
        "        return Ok(Clean::Text(text));",
    ),
    (
        "文字の長さを、NUL と改行をそろえたあとで数える",
        V,
        "        && text.chars().count() > max_len",
        "        && sanitize(&text, usize::MAX).chars().count() > max_len",
    ),
    (
        "1 行の文字の前後の空白を落とさない",
        V,
        "    if rule.widget != Widget::Textarea {",
        "    if rule.widget == Widget::Textarea {",
    ),
    (
        "一覧の入力欄に無い鍵を誤りにしない",
        V,
        "            errors.insert(key.clone(), Value::String(UNKNOWN_ITEM_FIELD.to_string()));",
        "            let _ = key;",
    ),
    (
        "DJAudio の古い平らな鍵（djaudio_cooldown）を書かない",
        S,
        '        current.insert("djaudio_cooldown".to_string(), cooldown);',
        "        let _ = cooldown;",
    ),
    (
        "ブロックを書き戻すとき、もとの位置ではなく末尾に入れる（鍵の並びが Python と変わる）",
        S,
        "        current.insert(name.to_string(), Value::Object(nested));",
        "        current.shift_remove(name);\n        current.insert(name.to_string(), Value::Object(nested));",
    ),
    (
        "信頼済み・バイパスの ID の重なりを落とさない",
        S,
        "        ids.dedup();",
        "        ids.truncate(ids.len());",
    ),
    (
        "地震の通知の種類で、外したものを偽として書かない",
        S,
        "            patch.insert(key.clone(), Value::Bool(selected.contains(key)));",
        "            if selected.contains(key) {\n                patch.insert(key.clone(), Value::Bool(true));\n            }",
    ),
    (
        "スティッキーを差し替えるとき、投稿済みのメッセージの ID を残さない",
        S,
        '            Some(Value::Object(existing)) => existing.get("message_id").cloned(),',
        "            Some(Value::Object(_)) => None,",
    ),
    (
        "読み上げの全体の上限を変えるとき、本文の上限をいまの設定から読み直さない",
        S,
        "    let max_length = getters::call(TTS_MAX_LENGTH, ctx)?;",
        "    let max_length = Value::from(100);",
    ),
    (
        "スティッキーを消すとき、削除待ちの印を立てない",
        S,
        '            entry.insert("pending".to_string(), Value::String("delete".to_string()));',
        "            let _ = entry;",
    ),
    (
        "ニュースのフィードの最後に回した時刻を整数の 0 で書く（Python は 0.0）",
        S,
        '            ("last_run", Value::from(0.0_f64)),',
        '            ("last_run", Value::from(0)),',
    ),
    (
        "件数の上限ちょうどでも足せる",
        W,
        "        if count >= max_items {",
        "        if count > max_items {",
    ),
    (
        "フォームの本文を JSON として読む（Python は CSRF の確かめで読み切っていて 400）",
        W,
        '    if kind == "application/x-www-form-urlencoded" || kind == "multipart/form-data" {',
        '    if kind == "multipart/form-data" {',
    ),
    (
        "入力欄の保存で CSRF を確かめない",
        W,
        "    app.check_csrf(&req)?;\n    let panel = editable_panel(&app, &req)?;\n    let guild_id = session_guild_id(&req)?;\n"
        "    let incoming = incoming_values(&req)?;",
        "    let panel = editable_panel(&app, &req)?;\n    let guild_id = session_guild_id(&req)?;\n"
        "    let incoming = incoming_values(&req)?;",
    ),
    (
        "確認の文字の前後の空白を落とさない",
        W,
        "    if python::strip(&confirm) != guild_id {",
        "    if confirm != guild_id {",
    ),
    (
        "いまは管理者でないと分かっても消す",
        W,
        "    if still_admin == Some(false) {",
        "    if still_admin == Some(false) && false {",
    ),
    (
        "サーバーのデータの削除で、消した監査履歴の数を答えに入れない",
        G,
        "            removed.events = counts.events;",
        "            removed.events = 0;",
    ),
]
