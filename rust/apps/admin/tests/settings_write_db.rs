//! 設定パネルの書く側（A6）を本物の Postgres に当てるテスト。`SYCS_TEST_DATABASE_URL` が要る（手元では飛ばす
//! `#[ignore]`。CI は Postgres 16 を立てて `--include-ignored` で必ず回す。sycs-core の `tests/postgres.rs` と同じ）。
//!
//! - 管理画面が書いた設定が、Bot の置き場（同じ `SettingsCache`。LISTEN で追う）に通知で数秒以内に届くこと。
//!   届かないと、管理画面で変えた設定が Bot に効かない（Python の管理画面と同じ `bot_settings_changed` に、新しい
//!   版番号を流す）。何も変えない書き込みは、版番号を上げず、行も書き直さないこと
//! - サーバーのデータの削除で、そのサーバーの監査履歴と現在の状態だけが消え、消した数が返ること
//!
//! テスト同士がぶつからないよう、テストごとに別のスキーマを使う。通知はデータベース全体に届くので、版番号は
//! このテストにしか無い大きな値から始める。

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_admin::apps::getters::{Ctx, DjaudioDefaults};
use sycs_admin::apps::guild_data::{PgUserStateEraser, UserStateEraser};
use sycs_admin::apps::setters;
use sycs_admin::apps::store::{SettingsStore, StoreConfig};
use sycs_admin::users::store::PgUserStates;
use sycs_core::settings::{SettingsCache, TOUCHED_AT_KEY};

static COUNTER: AtomicU32 = AtomicU32::new(0);

const GUILD: &str = "900000000000000001";

/// テスト 1 本ぶんの、空のスキーマにつないだ接続の束（設定の 2 つの表を Python と同じ形で作る）。
async fn isolated_pool(name: &str) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "a6_{}_{}_{}",
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
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    for ddl in [
        "CREATE TABLE bot_settings_guild (guild_key text PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE bot_settings_state (id smallint PRIMARY KEY, version bigint NOT NULL, root jsonb NOT NULL, imported_from text, imported_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now())",
    ] {
        sqlx::query(ddl).execute(&pool).await.unwrap();
    }
    pool
}

async fn seed(pool: &PgPool, version: i64, guild: Value) {
    sqlx::query("INSERT INTO bot_settings_state (id, version, root) VALUES (1, $1, '{}')")
        .bind(version)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bot_settings_guild (guild_key, data) VALUES ($1, $2)")
        .bind(GUILD)
        .bind(guild)
        .execute(pool)
        .await
        .unwrap();
}

async fn stored_version(pool: &PgPool) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT version FROM bot_settings_state WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap();
    row.0
}

/// この接続の束の LISTEN が `count` 本張られるまで待つ（Bot と管理画面の置き場が 1 本ずつ張る。張られる前の通知は
/// 届かないので、決め打ちで待たずに pg_stat_activity を見る。sycs-core の `wait_for_listener` と同じ考え方）。
async fn wait_for_listeners(pool: &PgPool, count: i64) {
    let app: (String,) = sqlx::query_as("SELECT current_setting('application_name')")
        .fetch_one(pool)
        .await
        .unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        let found: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1 AND query LIKE 'LISTEN%'",
        )
        .bind(&app.0)
        .fetch_one(pool)
        .await
        .unwrap();
        if found.0 >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("15 秒待っても LISTEN が {count} 本張られない");
}

async fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// 書く関数を名前で引いて、いまの設定から書き換えを作り、置き場に当てる（経路の係と同じ順）。
async fn set(store: &SettingsStore, name: &str, value: Value) {
    let settings = store.snapshot().await;
    let ctx = Ctx {
        settings: &settings,
        guild_id: GUILD,
        djaudio: &DjaudioDefaults::PYTHON,
    };
    let setter = setters::setter(name).unwrap_or_else(|| panic!("{name} が無い"));
    let plan = setter(&ctx, &value).unwrap();
    let mutation = plan.mutation.expect("書き換えが無い");
    store.transact(mutation).await.unwrap();
}

/// 管理画面が書いた設定が、Bot の置き場に通知で届き、変えない書き込みは版番号を上げないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn admin_writes_reach_the_bot_through_the_notification() {
    let pool = isolated_pool("notify").await;
    let base = 8_000_000_000_i64 + i64::from(COUNTER.fetch_add(1, Ordering::SeqCst)) * 1000;
    seed(&pool, base, json!({"log_level": "INFO"})).await;
    // Bot の置き場（版番号の確認は止め、通知だけで追う）。
    let bot = SettingsCache::start(pool.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    let config = StoreConfig {
        poll_interval: Duration::from_secs(3600),
        write_timeout: Duration::from_secs(10),
        load_timeout: Duration::from_secs(30),
    };
    let admin = Arc::new(SettingsStore::start_postgres(pool.clone(), &config));
    assert_eq!(admin.snapshot().await.unwrap().version, base);
    wait_for_listeners(&pool, 2).await;

    set(&admin, "services.logging_service.set_log_level", json!("DEBUG")).await;
    assert_eq!(stored_version(&pool).await, base + 1);
    let arrived = wait_until(Duration::from_secs(10), || bot.version() == base + 1).await;
    assert!(arrived, "10 秒で Bot に届かない");
    let guild = bot.snapshot().guild(900_000_000_000_000_001).cloned().unwrap();
    assert_eq!(guild["log_level"], "DEBUG");
    assert!(guild.get(TOUCHED_AT_KEY).is_some(), "時刻が押されていない: {guild}");
    // 管理画面の手元も、通知を待たずに新しい中身を読む。
    assert_eq!(admin.try_snapshot().unwrap().version, base + 1);

    // 同じ値をもう一度書いても、版番号は上がらない（通知も出ない）。
    set(&admin, "services.logging_service.set_log_level", json!("DEBUG")).await;
    assert_eq!(stored_version(&pool).await, base + 1);
}

/// サーバーのデータの削除で、そのサーバーの監査履歴と現在の状態だけが消え、消した数が返ること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn user_states_of_the_guild_are_erased() {
    let pool = isolated_pool("erase").await;
    let users = Arc::new(PgUserStates::new(pool.clone()));
    users.ensure_tables(false).await.unwrap();
    for (guild, user) in [(1_i64, 10_i64), (1, 11), (2, 20)] {
        sqlx::query(
            "INSERT INTO user_state_current (guild_id, user_id, status, is_in_guild, is_banned, \
             is_timed_out, roles_json, abilities_json) VALUES ($1, $2, 'active', true, false, false, '[]', '{}')",
        )
        .bind(guild)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO user_state_event (guild_id, user_id, event_type, status_after, payload_json) \
                 VALUES ($1, $2, 'member_join', 'active', '{}')",
            )
            .bind(guild)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    let eraser = PgUserStateEraser::new(pool.clone(), Arc::clone(&users));
    let counts = eraser.delete_guild("1").await.unwrap();
    assert_eq!((counts.events, counts.states), (4, 2));
    let left: (i64,) = sqlx::query_as("SELECT count(*) FROM user_state_event WHERE guild_id = 2")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left.0, 2);
    let again = eraser.delete_guild("1").await.unwrap();
    assert_eq!((again.events, again.states), (0, 0));
    assert!(eraser.delete_guild("99999999999999999999").await.is_err());
}
