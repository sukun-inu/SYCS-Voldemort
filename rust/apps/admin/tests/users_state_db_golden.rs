//! 利用者の状態の読み出し（`sycs_admin::users::store`）が、本物の Python の services と同じ答えを返すこと。
//!
//! 基準は `fixtures/users_state_db/expected.json`（generate.py が、空の Postgres に cases.json の行を入れ、
//! `services/user_state_service.py` の `list_recent_user_states`・`count_user_states`・`get_user_state_detail` を
//! 呼んだ答え）。ここでも、空のスキーマに表（sycs-core の DDL。Bot と同じ形）を作り、同じ行を同じ文で入れ、
//! [`PgUserStates`] の 3 つを同じ引数で呼んで、答えを同じ書き方（admin_harness の encode。時刻は
//! `{"$datetime": isoformat}`）にして比べる。表を消してからの自己修復の手順も同じ順に回す。
//!
//! - 本物の Postgres が要るものは `SYCS_TEST_DATABASE_URL` を使う。手元では飛ばし（`#[ignore]`）、CI は Postgres 16 を
//!   立てて `--include-ignored` で必ず回す
//! - 文字の種類の表（[`DIGIT_ONLY`]）は、DB が無くても比べる
//!
//! テスト同士がぶつからないよう、テストごとに別のスキーマを使う。

use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_admin::users::store::{DIGIT_ONLY, PgUserStates};
use sycs_admin::users::{Detail, EventRow, StateRow};

static COUNTER: AtomicU32 = AtomicU32::new(0);

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/users_state_db");

fn read(name: &str) -> Value {
    let path = format!("{DIR}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{path} が読めません: {e}。CI の「基準」が作ったものを取ってきてコミットすること")
    });
    serde_json::from_str(&text).unwrap()
}

/// Python の `datetime.isoformat()`（UTC。マイクロ秒が 0 なら小数なし、あれば 6 桁）。
fn isoformat(at: DateTime<Utc>) -> String {
    let micros = at.timestamp_subsec_micros();
    let base = at.format("%Y-%m-%dT%H:%M:%S");
    if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    }
}

fn time(at: Option<DateTime<Utc>>) -> Value {
    at.map_or(Value::Null, |at| json!({"$datetime": isoformat(at)}))
}

fn text(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.clone()))
}

/// `_row_to_state_payload` の辞書と同じ鍵の順。
fn state_json(row: &StateRow) -> Value {
    let mut map = Map::new();
    let mut put = |key: &str, value: Value| {
        map.insert(key.to_string(), value);
    };
    put("guild_id", Value::from(row.guild_id));
    put("user_id", Value::from(row.user_id));
    put("username", text(row.username.as_ref()));
    put("display_name", text(row.display_name.as_ref()));
    put("avatar_url", text(row.avatar_url.as_ref()));
    put("status", text(row.status.as_ref()));
    put("is_in_guild", Value::Bool(row.is_in_guild));
    put("is_banned", Value::Bool(row.is_banned));
    put("is_timed_out", Value::Bool(row.is_timed_out));
    put("timed_out_until", time(row.timed_out_until));
    put("roles", row.roles.clone());
    put("abilities", row.abilities.clone());
    put("last_event_type", text(row.last_event_type.as_ref()));
    put("last_event_at", time(row.last_event_at));
    put("first_seen_at", time(row.first_seen_at));
    put("last_joined_at", time(row.last_joined_at));
    put("last_left_at", time(row.last_left_at));
    put("updated_at", time(row.updated_at));
    Value::Object(map)
}

/// `_event_to_payload` の辞書と同じ鍵の順。
fn event_json(row: &EventRow) -> Value {
    let mut map = Map::new();
    let mut put = |key: &str, value: Value| {
        map.insert(key.to_string(), value);
    };
    let actor = row.actor_user_id.map_or(Value::Null, Value::from);
    put("id", Value::from(row.id));
    put("event_type", text(row.event_type.as_ref()));
    put("status_after", text(row.status_after.as_ref()));
    put("actor_user_id", actor);
    put("actor_name", text(row.actor_name.as_ref()));
    put("reason", text(row.reason.as_ref()));
    put("event_at", time(row.event_at));
    put("payload", Value::Object(row.payload.clone()));
    Value::Object(map)
}

fn detail_json(detail: Option<&Detail>) -> Value {
    let Some(detail) = detail else {
        return Value::Null;
    };
    let current = detail.current.as_ref().map_or(Value::Null, state_json);
    let events: Vec<Value> = detail.events.iter().map(event_json).collect();
    json!({"current": current, "events": events})
}

/// 例の数（`{"$int": "…"}` も）を Python の int の代わりの `i128` に。
fn int(value: &Value) -> i128 {
    if let Some(text) = value.get("$int").and_then(Value::as_str) {
        return text.parse().unwrap();
    }
    if let Some(small) = value.as_i64() {
        return i128::from(small);
    }
    i128::from(value.as_u64().unwrap())
}

/// 文字の種類の表が Python 3.13 の `str.isdigit() and not str.isdecimal()` と同じこと。
#[test]
fn digit_only_matches_python() {
    let data = read("expected.json");
    let python: Vec<(u32, u32)> = data["digit_only"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let start = u32::try_from(pair[0].as_u64().unwrap()).unwrap();
            let end = u32::try_from(pair[1].as_u64().unwrap()).unwrap();
            (start, end)
        })
        .collect();
    assert_eq!(DIGIT_ONLY, python.as_slice());
}

/// テスト 1 本ぶんの、空のスキーマにつないだ接続の束。
async fn isolated_pool(name: &str) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "t_adm_{}_{}_{}",
        name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let admin = PgPool::connect(&url)
        .await
        .expect("Postgres につながらない");
    // スキーマ名はこのテストが英数字だけで作ったもの（外から来た文字列は入らない）。
    sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let options: PgConnectOptions = url
        .parse::<PgConnectOptions>()
        .unwrap()
        .options([("search_path", schema.as_str())])
        .application_name(&schema);
    PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap()
}

/// generate.py の `insert_sql` と同じ文（`$n` の書き方）。
fn insert_sql(table: &str, columns: &[String]) -> String {
    let values: Vec<String> = columns
        .iter()
        .enumerate()
        .map(|(i, column)| {
            let n = i + 1;
            if is_timestamp(column) {
                format!("(${n})::text::timestamptz")
            } else {
                format!("${n}")
            }
        })
        .collect();
    format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        columns.join(", "),
        values.join(", ")
    )
}

fn is_timestamp(column: &str) -> bool {
    matches!(
        column,
        "timed_out_until"
            | "last_event_at"
            | "first_seen_at"
            | "last_joined_at"
            | "last_left_at"
            | "created_at"
            | "updated_at"
            | "event_at"
    )
}

/// generate.py の `merged_rows`（defaults に行を上書きし、列を全部そろえる）。
fn merged(defaults: &Value, row: &Value, columns: &[String]) -> Map<String, Value> {
    let mut full = defaults.as_object().unwrap().clone();
    full.extend(row.as_object().unwrap().clone());
    for column in columns {
        assert!(full.contains_key(column), "列 {column} が無い");
    }
    full
}

/// 例の文書の 1 つの表の行を全部入れる（`kind` は列と既定の鍵の頭、`rows` は行の鍵）。
async fn insert_rows(pool: &PgPool, cases: &Value, table: &str, kind: &str, rows: &str) {
    let columns: Vec<String> = cases[format!("{kind}_columns").as_str()]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    let defaults = &cases[format!("{kind}_defaults").as_str()];
    for row in cases[rows].as_array().unwrap() {
        let full = merged(defaults, row, &columns);
        insert(pool, table, &columns, &full).await;
    }
}

/// 1 行を入れる（列の型は表の形のとおり）。
async fn insert(pool: &PgPool, table: &str, columns: &[String], row: &Map<String, Value>) {
    let sql = insert_sql(table, columns);
    let mut query = sqlx::query(AssertSqlSafe(sql));
    for column in columns {
        let value = &row[column.as_str()];
        query = match column.as_str() {
            "id" => query.bind(i32::try_from(value.as_i64().unwrap()).unwrap()),
            "guild_id" | "user_id" => query.bind(value.as_i64().unwrap()),
            "actor_user_id" => query.bind(value.as_i64()),
            "is_in_guild" | "is_banned" | "is_timed_out" => query.bind(value.as_bool().unwrap()),
            _ => query.bind(value.as_str().map(str::to_string)),
        };
    }
    query.execute(pool).await.unwrap();
}

#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn reads_match_python_in_postgres() {
    let cases = read("cases.json");
    let expected = read("expected.json");
    let pool = isolated_pool("users").await;
    let store = PgUserStates::new(pool.clone());
    store.ensure_tables(false).await.unwrap();
    insert_rows(&pool, &cases, "user_state_current", "current", "current").await;
    insert_rows(&pool, &cases, "user_state_event", "event", "events").await;
    let steps = cases["steps"].as_array().unwrap();
    let results = expected["steps"].as_array().unwrap();
    assert_eq!(steps.len(), results.len(), "基準が例の文書と食い違う");
    let mut wrong = Vec::new();
    for (step, want) in steps.iter().zip(results) {
        let name = step["name"].as_str().unwrap();
        assert_eq!(want["name"], step["name"], "基準の並びが例の文書と違う");
        if let Some(sql) = step["sql"].as_str() {
            sqlx::query(AssertSqlSafe(sql.to_string()))
                .execute(&pool)
                .await
                .unwrap();
            continue;
        }
        let guild = int(&step["guild_id"]);
        let query = step["query"].as_str();
        let got = match step["fn"].as_str().unwrap() {
            "list" => {
                let limit = i64::try_from(int(&step["limit"])).unwrap();
                let offset = int(&step["offset"]);
                let rows = store.list_recent(guild, query, limit, offset).await;
                Value::Array(rows.unwrap().iter().map(state_json).collect())
            }
            "count" => Value::from(store.count_states(guild, query).await.unwrap()),
            "detail" => {
                let user = int(&step["user_id"]);
                let limit = i64::try_from(int(&step["event_limit"])).unwrap();
                let detail = store.user_detail(guild, user, limit).await.unwrap();
                detail_json(detail.as_ref())
            }
            other => panic!("知らない fn: {other}"),
        };
        // 鍵の並びまで比べる（どちらも serde_json で書き直した文字で）。
        let python = serde_json::to_string(&want["result"]).unwrap();
        let rust = serde_json::to_string(&got).unwrap();
        if python != rust {
            wrong.push(format!(
                "「{name}」:\n    Python {python}\n    Rust   {rust}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "Python と違う（{} 件）:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
