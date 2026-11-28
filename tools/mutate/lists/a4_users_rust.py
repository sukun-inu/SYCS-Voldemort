"""A4（管理画面の利用者の状態。rust-06）の Rust の変異。

利用者の状態の 2 本の API が Python と同じ答えを返すこと（基準 rust/apps/admin/tests/fixtures/users_state/。A0）と、
読み出しが Python の services と同じ行を返すこと（基準 users_state_db/。空の Postgres に同じ行を入れて作った）を、
rust/apps/admin/tests/users_state_golden.rs・users_state_db_golden.rs（Postgres が要る。CI の変異テストは
--include-ignored で回す）とユニットテストが確かめている。下の壊れを、そのどれかがそれぞれ捕まえること。
"""

KIND = "rust"
P = "rust/apps/admin/src/params.rs"
J = "rust/apps/admin/src/jsonsafe.rs"
L = "rust/apps/admin/src/users/labels.rs"
U = "rust/apps/admin/src/users/mod.rs"
S = "rust/apps/admin/src/users/store.rs"
MUTS = [
    (
        "変異なし（通るはず）",
        P,
        "pub const MAX_INT_TEXT: usize = 4300;",
        "pub const MAX_INT_TEXT: usize = 4300;",
    ),
    (
        "期限ちょうどもタイムアウト中にする",
        L,
        "until.is_some_and(|until| until > now)",
        "until.is_some_and(|until| until >= now)",
    ),
    (
        "いまタイムアウト中かを記録の旗で決める（ec10a3e の前に戻す）",
        U,
        "let timed_out = labels::timed_out_now(state.timed_out_until, now);",
        "let timed_out = state.is_timed_out;",
    ),
    (
        "空の状態を「不明」にしない",
        L,
        'let value = value.filter(|value| !value.is_empty()).unwrap_or("unknown");',
        'let value = value.unwrap_or("unknown");',
    ),
    (
        "定期同期の起点を日本語にしない",
        L,
        "let source = lookup(&SYNC_SOURCE_LABELS, source).unwrap_or(source);",
        "let source = source;",
    ),
    ("権限の日本語を並べ替えない", L, "    labels.sort();", "    // 並べ替えない"),
    (
        "名前が偽のロールも並べる",
        L,
        '.filter_map(|role| role.get("name").filter(|name| python::truthy(name)))',
        '.filter_map(|role| role.get("name"))',
    ),
    (
        "最後のページの先にも「次へ」を出す",
        U,
        "next.is_some_and(|next| next < i128::from(total))",
        "next.is_some_and(|next| next <= i128::from(total))",
    ),
    ("行の無いページでも「次へ」を出す", U, "let has_more = !rows.is_empty() && ", "let has_more = "),
    (
        "検索語の前後の空白を落とさない",
        U,
        "let keyword = Some(python::strip(&q)).filter(|k| !k.is_empty());",
        "let keyword = Some(q.as_str()).filter(|k| !k.is_empty());",
    ),
    (
        "2^53-1 ちょうども文字にする",
        J,
        "return i.unsigned_abs() > JS_SAFE_MAX;",
        "return i.unsigned_abs() >= JS_SAFE_MAX;",
    ),
    (
        "並びの中の大きい整数を文字にしない",
        J,
        "Value::Array(items) => Value::Array(items.into_iter().map(stringify_big_ints).collect()),",
        "Value::Array(items) => Value::Array(items),",
    ),
    ("検索語の長さをバイトで数える", P, "raw.chars().count() > *max", "raw.len() > *max"),
    ("同じ名前の問い合わせは最初の値を使う", P, "            .rev()", "            .skip(0)"),
    ("ge の端を含めない", P, "Self::Small(value) => *value >= bound,", "Self::Small(value) => *value > bound,"),
    (
        "小数点のあとの 0 を落として読み直さない",
        P,
        "if let Some(stripped) = strip_decimal_zeros(text) {",
        "if let Some(stripped) = None::<&str> {",
    ),
    ("4300 バイトちょうどを長すぎるとする", P, "if len > MAX_INT_TEXT {", "if len >= MAX_INT_TEXT {"),
    ("パスの引数の誤りを query と書く", P, 'let loc = "path";', 'let loc = "query";'),
    ("ID の前方一致を部分一致にする", S, 'let prefix = format!("{q}%");', 'let prefix = format!("%{q}%");'),
    (
        "上付きの数字を数字と見ない（int() で落ちない）",
        S,
        "digit_only || python::decimal_value(c).is_some()",
        "python::decimal_value(c).is_some()",
    ),
    (
        "件数 0 を 1 に丸めない",
        S,
        "let limit = limit.clamp(1, MAX_LIMIT);",
        "let limit = limit.clamp(0, MAX_LIMIT);",
    ),
    (
        "同じ時刻の履歴を ID の古い順にする",
        S,
        "ORDER BY event_at DESC, id DESC LIMIT $3",
        "ORDER BY event_at DESC, id ASC LIMIT $3",
    ),
    (
        "ほかのサーバーの行も一覧に出す",
        S,
        '"WHERE guild_id = $1 ",',
        '"WHERE guild_id = $1 OR guild_id <> $1 ",',
    ),
    (
        "詳細で表が消えていても作り直さない",
        S,
        'if first && self.heal("get_user_state_detail", &failure).await {',
        'if false && self.heal("get_user_state_detail", &failure).await {',
    ),
    (
        "最初に見た時刻に最後のイベントの時刻を読む",
        S,
        "first_seen_at: from_micros(row.try_get(14)?),",
        "first_seen_at: from_micros(row.try_get(13)?),",
    ),
]
