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

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_core::settings::{CacheOptions, LOCK_KEY, SettingsCache, TOUCHED_AT_KEY, WriteError};
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

/// この接続の束の LISTEN が張られるまで待つ。張られる前に書いたり切ったりすると、試験が
/// 確かめたいこと（通知が届くか、切れたあと追いつくか）ではなく、張られる早さを見てしまう。
///
/// 決め打ちで 300 ms 待っていたころは、CI（テストを QEMU で Sandy Bridge のふりをして動かす
/// ので遅い）で張られる前に切りに行き、「LISTEN の接続が見つからない」で落ちることがあった。
async fn wait_for_listener(pool: &PgPool) {
    let app: (String,) = sqlx::query_as("SELECT current_setting('application_name')")
        .fetch_one(pool)
        .await
        .unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        let found: Option<(i32,)> = sqlx::query_as(
            "SELECT pid FROM pg_stat_activity WHERE application_name = $1 AND query LIKE 'LISTEN%'",
        )
        .bind(&app.0)
        .fetch_optional(pool)
        .await
        .unwrap();
        if found.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("15 秒待っても LISTEN が張られない");
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

/// LISTEN を張らない動かし方。書き込みのテストは、他のテストの通知（データベース全体に届く）で
/// 手元が読み直されると、書いた直後に手元へ入れたかどうかを見分けられないので、これを使う。
fn quiet(poll: Duration) -> CacheOptions {
    CacheOptions {
        listen: false,
        ..CacheOptions::new(poll)
    }
}

/// 版番号と guilds 以外のキーを入れ、ギルドの行を入れる。行の updated_at は 2000 年にしておく
/// （書き直されたかどうかを、あとで updated_at で見分けるため）。
async fn seed(pool: &PgPool, version: i64, guilds: &[(&str, Value)]) {
    sqlx::query(
        "INSERT INTO bot_settings_state (id, version, root) VALUES (1, $1, '{\"schema\": \"v1\"}')",
    )
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
    for (key, data) in guilds {
        sqlx::query("INSERT INTO bot_settings_guild (guild_key, data, updated_at) VALUES ($1, $2, '2000-01-01T00:00:00Z')")
            .bind(key)
            .bind(data)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// 表にあるギルドの行。鍵 → (中身, 2000 年のまま＝書き直されていないか)。
async fn stored(pool: &PgPool) -> std::collections::BTreeMap<String, (Value, bool)> {
    let rows: Vec<(String, Value, bool)> =
        sqlx::query_as("SELECT guild_key, data, updated_at < '2001-01-01' FROM bot_settings_guild")
            .fetch_all(pool)
            .await
            .unwrap();
    rows.into_iter().map(|(k, d, old)| (k, (d, old))).collect()
}

async fn stored_version(pool: &PgPool) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT version FROM bot_settings_state WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap();
    row.0
}

/// 押された時刻が、Python の読み方（ISO 8601 の UTC）で読めて、いまに近いこと。
fn assert_fresh_stamp(data: &Value) {
    let stamp = data[TOUCHED_AT_KEY]
        .as_str()
        .unwrap_or_else(|| panic!("時刻が押されていない: {data}"));
    let at = chrono::DateTime::parse_from_rfc3339(stamp).unwrap();
    assert_eq!(at.offset().local_minus_utc(), 0, "UTC でない: {stamp}");
    let age = chrono::Utc::now().signed_duration_since(at);
    assert!(age.num_seconds().abs() < 60, "いまの時刻でない: {stamp}");
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
    wait_for_listener(&pool).await;

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
    wait_for_listener(&pool).await;

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
    let cache = settings::SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(1)))
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

/// 変わったギルドの行だけを書き、版番号を上げ、その版番号を通知し、手元もすぐ差し替えること。
///
/// 触っていないギルドまで書き直すと、行の更新時刻が意味を失い、書き込みのたびに全ギルドぶんの
/// 書き込みが走る。通知が出ないと、Python の管理画面に Bot の変更が届かない。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_write_saves_only_what_changed_and_announces_the_new_version() {
    let pool = isolated_pool("write").await;
    // 版番号はこのテストにしか無い大きな値にする。通知はデータベース全体に届くので、他の
    // テストの通知と取り違えないため。
    let base = 7_000_000_000_i64;
    seed(
        &pool,
        base,
        &[("111", json!({"n": 1})), ("222", json!({"n": 1}))],
    )
    .await;
    let cache = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();
    let mut listener = PgListener::connect_with(&pool).await.unwrap();
    listener.listen(settings::CHANNEL).await.unwrap();

    let got = cache
        .transact(|s| {
            s.guilds.get_mut("111").unwrap()["n"] = json!(2);
            "戻り値"
        })
        .await
        .unwrap();
    assert_eq!(got, "戻り値");
    // 通知を待たずに手元へ入っている。
    assert_eq!(cache.version(), base + 1);
    assert_eq!(cache.snapshot().guild(111).unwrap()["n"], 2);

    assert_eq!(stored_version(&pool).await, base + 1);
    let rows = stored(&pool).await;
    assert_eq!(rows["111"].0["n"], 2);
    assert!(!rows["111"].1, "変えた行が書き直されていない");
    assert_eq!(
        rows["222"],
        (json!({"n": 1}), true),
        "触っていない行を書き直した"
    );
    let root: (Value,) = sqlx::query_as("SELECT root FROM bot_settings_state WHERE id = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(root.0, json!({"schema": "v1"}));

    let expected = (base + 1).to_string();
    let heard = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = listener.recv().await.unwrap();
            if n.payload() == expected {
                return;
            }
        }
    })
    .await;
    assert!(heard.is_ok(), "新しい版番号の通知が届かない");
}

/// 何も変わらない書き込みは保存しないこと（版番号も上げない・時刻も押さない）。
///
/// 保存すると、読む側全員が無駄に読み直し、触っていないギルドが「最近触られた」になる。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_write_that_changes_nothing_is_not_saved() {
    let pool = isolated_pool("nochange").await;
    seed(&pool, 1, &[("111", json!({"n": 1}))]).await;
    let cache = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();

    cache
        .transact(|s| s.guilds.get_mut("111").unwrap()["n"] = json!(1))
        .await
        .unwrap();
    assert_eq!(stored_version(&pool).await, 1);
    assert_eq!(stored(&pool).await["111"], (json!({"n": 1}), true));
    assert_eq!(cache.version(), 1);
}

/// 書き込みで null を落とし、中身が変わったギルドにだけ時刻を押すこと（Python と同じ規則）。
///
/// 別のギルドに残っていた null も落として保存するが、そちらには時刻を押さない（利用者が
/// 触ったのではない）。押すと、放棄された設定の掃除が永久に動かなくなる。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn nulls_are_dropped_and_only_the_touched_guild_is_stamped() {
    let pool = isolated_pool("nulls").await;
    seed(
        &pool,
        1,
        &[
            ("111", json!({"a": 1, "x": null})),
            ("222", json!({"b": {"c": null}, "keep": 1})),
        ],
    )
    .await;
    let cache = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();

    cache
        .transact(|s| {
            let g = s.guilds.get_mut("111").unwrap();
            g["a"] = json!(2);
            // 書き換えで入れた null も保存しない。
            g["y"] = Value::Null;
        })
        .await
        .unwrap();

    let rows = stored(&pool).await;
    let touched = &rows["111"].0;
    assert_fresh_stamp(touched);
    let mut without = touched.clone();
    without.as_object_mut().unwrap().remove(TOUCHED_AT_KEY);
    assert_eq!(without, json!({"a": 2}));
    assert_eq!(
        rows["222"].0,
        json!({"keep": 1}),
        "他のギルドの null が残った・時刻が押された"
    );
}

/// ギルドを消したこと、新しいギルド、guilds 以外のキーの変更も保存すること。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn removed_and_added_guilds_and_root_changes_are_saved() {
    let pool = isolated_pool("shape").await;
    seed(
        &pool,
        1,
        &[("111", json!({"n": 1})), ("222", json!({"n": 2}))],
    )
    .await;
    let cache = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();

    cache
        .transact(|s| {
            s.guilds.remove("222");
            s.guilds.insert("333".into(), json!({"n": 3}));
            s.root.insert("schema".into(), json!("v2"));
        })
        .await
        .unwrap();

    let rows = stored(&pool).await;
    assert_eq!(rows.keys().collect::<Vec<_>>(), ["111", "333"]);
    assert_fresh_stamp(&rows["333"].0);
    let root: (Value,) = sqlx::query_as("SELECT root FROM bot_settings_state WHERE id = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(root.0, json!({"schema": "v2"}));
    assert!(cache.snapshot().guild(222).is_none());

    // guilds 以外のキーだけを変えても保存する（ギルドが変わらないから書かない、にしない）。
    cache
        .transact(|s| {
            s.root.insert("note".into(), json!(1));
        })
        .await
        .unwrap();
    assert_eq!(stored_version(&pool).await, 3);
}

/// 同時に書いても、1 つも取りこぼさないこと。
///
/// 移行中は Python（管理画面・Python の Bot）と Rust（Bot）が同じ表へ書く。排他が無いと、
/// 2 つが同じ版を読んでそれぞれ書き、後から書いた方が先の変更を消す。ここでは 2 つの手元
/// （別のプロセスに見立てる）から 4 本並べて同じ数を 1 ずつ増やす。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn concurrent_writers_never_lose_an_increment() {
    let pool = isolated_pool("race").await;
    seed(&pool, 1, &[("111", json!({"n": 0}))]).await;
    let a = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();
    let b = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for cache in [&a, &b, &a, &b] {
        let cache = std::sync::Arc::clone(cache);
        tasks.push(tokio::spawn(async move {
            for _ in 0..25 {
                cache
                    .transact(|s| {
                        let g = s.guilds.get_mut("111").unwrap();
                        g["n"] = json!(g["n"].as_i64().unwrap() + 1);
                    })
                    .await
                    .unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(stored(&pool).await["111"].0["n"], 100, "増やした数が欠けた");
    assert_eq!(stored_version(&pool).await, 101);
}

/// 排他を持ったまま止まった書き手がいても、待ち続けずに諦め、何も書かないこと。
///
/// 待ち続けると、止まったプロセスが 1 つあるだけで Bot の書き込みが全部返らなくなる
/// （Python も SETTINGS_LOCK_TIMEOUT_SECONDS で諦める）。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_stuck_writer_makes_others_give_up_instead_of_waiting_forever() {
    let pool = isolated_pool("stuck").await;
    seed(&pool, 1, &[("111", json!({"n": 1}))]).await;
    let cache = SettingsCache::start_with(
        pool.clone(),
        CacheOptions {
            write_timeout: Duration::from_millis(300),
            ..quiet(Duration::from_secs(3600))
        },
    )
    .await
    .unwrap();

    // 別の接続が排他を持ったまま止まっている（Python の書き込みが止まったのに見立てる）。
    let mut holder = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *holder)
        .await
        .unwrap();

    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        cache.transact(|s| s.guilds.get_mut("111").unwrap()["n"] = json!(2)),
    )
    .await;
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *holder)
        .await
        .unwrap();
    let outcome = outcome.expect("排他を待ち続けた");
    assert!(
        matches!(outcome, Err(WriteError::Timeout(_))),
        "待ちきれなかったことが分からない: {outcome:?}"
    );
    assert_eq!(
        stored(&pool).await["111"].0,
        json!({"n": 1}),
        "書いてしまった"
    );
    assert_eq!(stored_version(&pool).await, 1);

    // 排他が空けば書ける。
    cache
        .transact(|s| s.guilds.get_mut("111").unwrap()["n"] = json!(2))
        .await
        .unwrap();
    assert_eq!(stored(&pool).await["111"].0["n"], 2);
}

/// 起動時の掃除は、null を落として保存するが時刻は押さず、落とすものが無ければ書かないこと。
#[tokio::test]
#[ignore = "Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn dropping_stored_nulls_does_not_stamp_and_skips_clean_data() {
    let pool = isolated_pool("dropnulls").await;
    seed(
        &pool,
        1,
        &[
            ("111", json!({"a": null, "b": 1})),
            ("222", json!({"c": 1})),
        ],
    )
    .await;
    let cache = SettingsCache::start_with(pool.clone(), quiet(Duration::from_secs(3600)))
        .await
        .unwrap();

    assert_eq!(cache.drop_stored_nulls().await.unwrap(), 1);
    let rows = stored(&pool).await;
    assert_eq!(
        rows["111"].0,
        json!({"b": 1}),
        "時刻を押した・null が残った"
    );
    assert!(rows["222"].1, "null の無い行を書き直した");
    assert_eq!(stored_version(&pool).await, 2);

    assert_eq!(cache.drop_stored_nulls().await.unwrap(), 0);
    assert_eq!(stored_version(&pool).await, 2, "落とすものが無いのに書いた");
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
