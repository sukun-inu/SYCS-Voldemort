//! 本物の Postgres に当てるテスト。`SYCS_TEST_DATABASE_URL` が要る。
//!
//! 手元の `cargo test` では飛ばす（`#[ignore]`）。CI（.github/workflows/rust.yml）は
//! Postgres 16 を立てて `--include-ignored` で必ず回す。**CI で接続先が無ければ落とす**
//! （素通りさせると、何も確かめずに緑になる。CONTRIBUTING 8.）。
//!
//! 表は Python（services/settings_pg.py・services/dev_signals.py）と同じ形でここで作る。
//! 今は表を作るのが Python 側なので、形が揃っていることは、Python が作った表を Rust が
//! 読む確認（変更のコミットに記録）で別に確かめている。
//!
//! テスト同士がぶつからないよう、テストごとに別のスキーマを使う。通知（NOTIFY）は
//! データベース全体に届くので、他のテストの通知も来るが、版番号を見て読み直すだけなので害は無い。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_core::{settings, signals};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// テスト 1 本ぶんの、空のスキーマにつないだ接続の束。
async fn isolated_pool(name: &str) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "t_{}_{}_{}",
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
        "CREATE TABLE dev_signal (id bigserial PRIMARY KEY, task text NOT NULL, dedupe_key text UNIQUE, payload text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())",
    ] {
        sqlx::query(ddl).execute(&pool).await.unwrap();
    }
    pool
}

/// Python の管理画面が書くのと同じ形で、1 ギルドを書き換えて版番号を上げ、通知を流す。
async fn python_style_write(pool: &PgPool, guild: &str, data: &str, version: i64) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO bot_settings_guild (guild_key, data) VALUES ($1, $2::jsonb) ON CONFLICT (guild_key) DO UPDATE SET data = EXCLUDED.data")
        .bind(guild).bind(data).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO bot_settings_state (id, version, root) VALUES (1, $1, '{}'::jsonb) ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version")
        .bind(version).execute(&mut *tx).await.unwrap();
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(settings::CHANNEL)
        .bind(version.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if done() {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

/// 表の中身を、ギルドと guilds 以外のキーと版番号まで、そのまま読むこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn load_reads_every_guild_the_root_and_the_version() {
    let pool = isolated_pool("load").await;
    sqlx::query(
        "INSERT INTO bot_settings_state (id, version, root) VALUES (1, 3, '{\"schema\": \"v1\"}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO bot_settings_guild (guild_key, data) VALUES ('111', '{\"welcome\": {\"channel_id\": 1}}'), ('222', '{}')")
        .execute(&pool).await.unwrap();

    let s = settings::load(&pool).await.unwrap();
    assert_eq!(s.version, 3);
    assert_eq!(s.root["schema"], "v1");
    assert_eq!(s.guild(111).unwrap()["welcome"]["channel_id"], 1);
    assert!(s.guild(222).is_some());
    assert!(s.guild(333).is_none());
}

/// 別のプロセスの書き込みが、通知だけで数秒以内に届くこと（版番号の確認は止めてある）。
///
/// 移行中は Python の管理画面が書き、Rust の Bot が読む。届かないと、管理画面で変えた
/// 設定が Bot に効かない。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_write_from_another_process_arrives_through_the_notification() {
    let pool = isolated_pool("notify").await;
    python_style_write(&pool, "111", "{\"n\": 1}", 1).await;
    let cache = settings::SettingsCache::start(pool.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(cache.snapshot().guild(111).unwrap()["n"], 1);
    // LISTEN が張られるまで少し待つ
    tokio::time::sleep(Duration::from_millis(300)).await;

    python_style_write(&pool, "111", "{\"n\": 2}", 2).await;
    let took = wait_until(Duration::from_secs(3), || cache.version() == 2).await;
    assert!(took.is_some(), "3 秒で届かない");
    assert_eq!(cache.snapshot().guild(111).unwrap()["n"], 2);
}

/// LISTEN の接続を切られても、つなぎ直して、その間の書き込みに追いつくこと。
///
/// 追いつかないと、Postgres の再起動やネットワークの瞬断のあと、次に誰かが設定を書くまで
/// （版番号の確認が回るまで）古い設定で動き続ける。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_dropped_listener_reconnects_and_catches_up() {
    let pool = isolated_pool("reconnect").await;
    python_style_write(&pool, "111", "{\"n\": 1}", 1).await;
    let cache = settings::SettingsCache::start(pool.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let app: (String,) = sqlx::query_as("SELECT current_setting('application_name')")
        .fetch_one(&pool)
        .await
        .unwrap();
    let killed: Vec<(bool,)> = sqlx::query_as(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1 AND query LIKE 'LISTEN%'",
    )
    .bind(&app.0)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!killed.is_empty(), "LISTEN の接続が見つからない");

    python_style_write(&pool, "111", "{\"n\": 2}", 2).await;
    let took = wait_until(Duration::from_secs(10), || cache.version() == 2).await;
    assert!(took.is_some(), "10 秒で追いつかない");
}

/// 通知を取りこぼしても、版番号の確認で追いつくこと。
///
/// 通知は LISTEN の接続が切れている間に流れたものが届かない。版番号の確認が効いて
/// いないと、次に誰かが設定を書くまで古い設定で動き続ける。ここでは通知を出さずに書き、
/// 確認（1 秒ごと）だけで届くことを見る。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_missed_notification_is_caught_by_the_version_poll() {
    let pool = isolated_pool("poll").await;
    python_style_write(&pool, "111", "{\"n\": 1}", 1).await;
    // LISTEN を張らない。他のテストが流す通知（データベース全体に届く）で読み直してしまうと、
    // 版番号の確認が効いているかを見分けられない。
    let cache = settings::SettingsCache::start_with(pool.clone(), Duration::from_secs(1), false)
        .await
        .unwrap();

    sqlx::query("UPDATE bot_settings_guild SET data = '{\"n\": 2}' WHERE guild_key = '111'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE bot_settings_state SET version = 2 WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    let took = wait_until(Duration::from_secs(5), || cache.version() == 2).await;
    assert!(
        took.is_some(),
        "5 秒で追いつかない（版番号の確認が効いていない）"
    );
    assert_eq!(cache.snapshot().guild(111).unwrap()["n"], 2);
}

/// 置かれた順に、上限つきで取り出し、取り出したものは消えること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn claim_takes_the_oldest_first_and_removes_them() {
    let pool = isolated_pool("claim").await;
    for (task, payload) in [("sticky", "a"), ("eq_replay", "b"), ("news_feeds", "c")] {
        sqlx::query("INSERT INTO dev_signal (task, payload) VALUES ($1, $2)")
            .bind(task)
            .bind(payload)
            .execute(&pool)
            .await
            .unwrap();
    }
    let first = signals::claim(&pool, 2).await.unwrap();
    assert_eq!(
        first.iter().map(|s| s.task.as_str()).collect::<Vec<_>>(),
        ["sticky", "eq_replay"]
    );
    let rest = signals::claim(&pool, signals::CLAIM_BATCH).await.unwrap();
    assert_eq!(
        rest.iter().map(|s| s.payload.as_str()).collect::<Vec<_>>(),
        ["c"]
    );
    assert!(
        signals::claim(&pool, signals::CLAIM_BATCH)
            .await
            .unwrap()
            .is_empty()
    );
}

/// 別の取り出し手がロックしている行は、待たずに飛ばし、同じ依頼を拾わないこと。
///
/// 待ってしまうと、もう 1 つの Bot（移行中の Python の Bot）の処理が終わるまで巡回が止まる。
/// 拾ってしまうと、同じ依頼が二重に実行される。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn locked_rows_are_skipped_without_waiting() {
    let pool = isolated_pool("skiplocked").await;
    for n in 0..6 {
        sqlx::query("INSERT INTO dev_signal (task, payload) VALUES ('eq_replay', $1)")
            .bind(n.to_string())
            .execute(&pool)
            .await
            .unwrap();
    }
    let mut other = pool.begin().await.unwrap();
    // 本番の取り出しの文から、返す列だけを変えたもの（外から来た文字列は入らない）。
    let held: Vec<(i64,)> = sqlx::query_as(AssertSqlSafe(
        signals::CLAIM_SQL.replace("RETURNING id, task, payload", "RETURNING id"),
    ))
    .bind(2_i64)
    .fetch_all(&mut *other)
    .await
    .unwrap();

    let started = Instant::now();
    let mine = tokio::time::timeout(Duration::from_secs(3), signals::claim(&pool, 10))
        .await
        .expect("ロック中の行を待ってしまった")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    other.rollback().await.unwrap();

    let held: Vec<i64> = held.into_iter().map(|(id,)| id).collect();
    assert_eq!(held.len(), 2);
    assert_eq!(mine.len(), 4);
    assert!(
        mine.iter().all(|s| !held.contains(&s.id)),
        "ロック中の依頼を拾った"
    );
}
