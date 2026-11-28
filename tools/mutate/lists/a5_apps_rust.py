"""A5（管理画面の設定パネルの読む側。rust-06）の Rust の変異。

タイルの一覧・1 枚のパネル（宣言・選択肢・値・一覧・誤り）・選択肢の使い回しと 429 の待ち・声の見切り・公開トップの
サーバー数のフォールバックが Python と同じ答えを返すこと（基準 rust/apps/admin/tests/fixtures/apps_read/・getters/。
本物の Python を偽物の Discord・読み上げの API に当てて作った）を、rust/apps/admin/tests/apps_read_golden.rs・
getters_golden.rs とユニットテストが確かめている。下の壊れを、そのどれかがそれぞれ捕まえること。
"""

KIND = "rust"
M = "rust/apps/admin/src/apps/mod.rs"
G = "rust/apps/admin/src/apps/getters.rs"
C = "rust/apps/admin/src/apps/choices.rs"
S = "rust/apps/admin/src/apps/schema.rs"
V = "rust/apps/admin/src/apps/voices.rs"
MUTS = [
    (
        "変異なし（通るはず）",
        S,
        'pub const SCHEMA_JSON: &str = include_str!("../../tests/fixtures/schema/schema.json");',
        'pub const SCHEMA_JSON: &str = include_str!("../../tests/fixtures/schema/schema.json");',
    ),
    (
        "開発者にも dev_only のタイルを隠す",
        M,
        ".filter(|panel| is_dev || !panel.dev_only)",
        ".filter(|panel| !panel.dev_only)",
    ),
    (
        "開発者かどうかを、開発者専用でないパネルでも確かめる（壊れた user で 500 になる）",
        M,
        "if panel.dev_only && !is_dev(&app, &req)? {",
        "if !is_dev(&app, &req)? && panel.dev_only {",
    ),
    (
        "custom のパネルでもサーバーの ID を読む（壊れた ID で 500 になる）",
        M,
        "    if panel.custom {\n        return Ok(jsonsafe::reply(200, Value::Object(payload)));\n    }\n"
        "    let guild_id = session_guild_id(&req)?;",
        "    let guild_id = session_guild_id(&req)?;\n    if panel.custom {\n"
        "        return Ok(jsonsafe::reply(200, Value::Object(payload)));\n    }",
    ),
    (
        "0 のバッジも数のまま出す（Python は null）",
        M,
        ".filter(python::truthy)",
        ".filter(|_| true)",
    ),
    (
        "パネルの答えで大きい整数を文字にしない（SafeJSONResponse を通さない）",
        M,
        "    Ok(jsonsafe::reply(200, Value::Object(payload)))",
        "    Ok(Reply::json(200, &Value::Object(payload)))",
    ),
    (
        "一覧の読み取りの誤りを errors に足さない",
        M,
        "    for (key, message) in collection_errors {\n        errors.insert(key, message);\n    }",
        "    let _ = collection_errors;",
    ),
    (
        "読めなかった入力欄を既定値でなく null で埋める",
        M,
        "values.insert(field.key.clone(), field.default.clone());",
        "values.insert(field.key.clone(), Value::Null);",
    ),
    (
        "公開トップのフォールバックで、int() できない鍵も数える",
        M,
        ".map(|settings| store::guild_count(&settings))",
        ".map(|settings| settings.guilds.len())",
    ),
    (
        "地震の最小震度で、読めない値を 30 に倒さない",
        G,
        'catch(read(), "30".to_string()).map(|text| int_value(&text))',
        "read().map(|text| int_value(&text))",
    ),
    (
        "DJAudio の古い平らな鍵（djaudio_cooldown など）を見ない",
        G,
        'get(guild, &format!("djaudio_{key}"))',
        "get(guild, key)",
    ),
    (
        "URL の上限を 10 で頭打ちにしない",
        G,
        'djaudio_limit(ctx, "max_urls", 1, Some(10), ctx.djaudio.max_urls)',
        'djaudio_limit(ctx, "max_urls", 1, None, ctx.djaudio.max_urls)',
    ),
    (
        "読み上げの対象チャンネルの鍵を取り違える",
        G,
        '.get("watch_channel_ids")',
        '.get("watch_channel_id")',
    ),
    (
        "保存されていない地震の通知の種類を偽にする（Python は真）",
        G,
        "Value::Bool(truthy_or(stored, key, true))",
        "Value::Bool(truthy_or(stored, key, false))",
    ),
    (
        "設定の並びを dict() の組として読まない",
        G,
        "        Value::Array(items) => {\n            let mut out = Map::new();",
        "        Value::Array(items) if items.is_empty() => {\n            let mut out = Map::new();",
    ),
    (
        "ロールの一覧から @everyone を除かない",
        C,
        'if fields.get("name") != Some(&Value::String("@everyone".to_string())) {',
        'if fields.contains_key("id") || fields.is_empty() {',
    ),
    (
        "チャンネルの一覧を 60 秒ちょうどまで使い回す",
        C,
        ".filter(|(_, at)| now - at < CHANNELS_TTL)",
        ".filter(|(_, at)| now - at <= CHANNELS_TTL)",
    ),
    (
        "429 の待ちの終わりちょうども待つ",
        C,
        "if at < self.cooling_until(guild_id) {",
        "if at <= self.cooling_until(guild_id) {",
    ),
    (
        "Retry-After を 300 秒で頭打ちにしない",
        C,
        "let wait = retry_after(answer.retry_after.as_deref()).min(COOLDOWN_MAX);",
        "let wait = retry_after(answer.retry_after.as_deref());",
    ),
    (
        "読めない Retry-After で待たない（Python は 30 秒）",
        C,
        "        None => COOLDOWN_DEFAULT,",
        "        None => 0.0,",
    ),
    (
        "取れなかったとき、古い一覧を返さない",
        C,
        "let stale = || cached.clone().unwrap_or_default();",
        "let stale = || cached.clone().map(|_| Vec::new()).unwrap_or_default();",
    ),
    (
        "錠を取ったあとに使い回しを見直さない（TTS のパネルで 2 回取りに行く）",
        C,
        "        if let Some(channels) = fresh {\n            return channels;\n        }",
        "        let _ = fresh;",
    ),
    (
        "声の一覧を 3 秒で見切らない",
        V,
        "match tokio::time::timeout(self.timeout, self.fetch_voices()).await {",
        "match tokio::time::timeout(Duration::from_secs(5), self.fetch_voices()).await {",
    ),
    (
        "声の名前を str() する（Python はそのまま）",
        V,
        "        .cloned()\n        .collect()",
        "        .map(|name| Value::String(python::str_of(name)))\n        .collect()",
    ),
    (
        "ID の入力欄で False を未設定として扱わない",
        S,
        "        Value::Bool(b) => !*b,",
        "        Value::Bool(_) => false,",
    ),
]
