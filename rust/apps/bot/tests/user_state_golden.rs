//! 利用者の状態の記録が、本物の Python と同じ行を書くこと。
//!
//! 基準（`fixtures/user_state/expected.json`）は、本物の Python のイベント処理（events/members.py・
//! events/voice.py）に discord.py の本物の Member・User・Role を渡し、本物の `record_user_state_event` に
//! 本物の Postgres へ書かせて、行を読み出したもの（`generate.py`）。こちらは同じ Discord の JSON を serenity
//! に読ませ、同じ順に記録して、行を比べる。
//!
//! - 履歴の行（種類・状態・実行者・理由・中身の JSON の文字・時刻）は、DB が無くても比べられる
//!   （[`user_state::plan`] の結果）。手元の `cargo test` でも回る
//! - 最新状態の行と表の形は、本物の Postgres で比べる。`SYCS_TEST_DATABASE_URL` が要るので、手元では飛ばし
//!   （`#[ignore]`）、CI は Postgres 16 を立てて `--include-ignored` で必ず回す
//!
//! テスト同士がぶつからないよう、テストごとに別のスキーマを使う。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use serenity::all::{GuildId, Member, Role, RoleId, User, UserId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_bot::user_state::{
    self, AuditHit, AuditRow, Event, GuildView, Person, Recorder, UserStateConfig,
};
use sycs_bot::vc_notify::Change;

/// 例と基準。
struct World {
    guild_id: GuildId,
    owner_id: UserId,
    roles: HashMap<RoleId, Role>,
    settings: Value,
    steps: Vec<Value>,
    audit: Vec<Value>,
    expected: Value,
}

fn load() -> World {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/user_state");
    let read = |name: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{name}")).unwrap()).unwrap()
    };
    let cases = read("cases.json");
    let id = |v: &Value| -> u64 { v.as_str().unwrap().parse().unwrap() };
    World {
        guild_id: GuildId::new(id(&cases["guild"]["id"])),
        owner_id: UserId::new(id(&cases["guild"]["owner_id"])),
        roles: cases["guild"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let role: Role = serde_json::from_value(r.clone()).unwrap();
                (role.id, role)
            })
            .collect(),
        settings: cases["settings"].clone(),
        steps: cases["steps"].as_array().unwrap().clone(),
        audit: cases["audit"].as_array().unwrap().clone(),
        expected: read("expected.json"),
    }
}

fn member(v: &Value) -> Member {
    serde_json::from_value(v.clone()).unwrap()
}

fn user(v: &Value) -> User {
    serde_json::from_value(v.clone()).unwrap()
}

/// 1 つの手順から、イベントの処理（handler）と同じ呼び方でイベントを作る。返すのは（イベント, 相手の ID）。
fn events_of(world: &World, step: &Value, now: DateTime<Utc>) -> (Vec<Event>, u64) {
    let view = GuildView {
        id: world.guild_id,
        owner_id: Some(world.owner_id),
        roles: &world.roles,
    };
    // 監査ログから分かった実行者（キャッシュのメンバーか、応答のユーザー）と理由。
    let audit = |a: &Value| -> Option<AuditHit> {
        if a.is_null() {
            return None;
        }
        let actor = match a.get("member") {
            Some(m) => Person::from_member(&member(m), &view, now),
            None => Person::from_user(&user(&a["user"])),
        };
        Some(AuditHit {
            actor: Some(actor),
            reason: a["reason"].as_str().map(str::to_string),
        })
    };
    let count = step["count"].as_u64().unwrap_or(0);
    match step["kind"].as_str().unwrap() {
        "join" => {
            let m = member(&step["member"]);
            (
                vec![Event::member_join(&m, &view, count, now)],
                m.user.id.get(),
            )
        }
        "remove" => {
            let m = member(&step["member"]);
            let kick = audit(&step["audit"]);
            (
                vec![Event::member_removal(&m, &view, count, kick, now)],
                m.user.id.get(),
            )
        }
        "update" => {
            let (before, after) = (member(&step["before"]), member(&step["after"]));
            let events = [
                Event::nickname_changed(&before, &after, &view, now),
                Event::role_changed(&before, &after, &view, now),
                Event::timeout_changed(&before, &after, &view, now),
            ];
            (events.into_iter().flatten().collect(), after.user.id.get())
        }
        "ban" => {
            let u = user(&step["user"]);
            let cached = step.get("cached").filter(|c| !c.is_null()).map(member);
            let hit = audit(&step["audit"]);
            (
                vec![Event::member_ban(&u, cached.as_ref(), &view, hit, now)],
                u.id.get(),
            )
        }
        "unban" => {
            let u = user(&step["user"]);
            let hit = audit(&step["audit"]);
            (
                vec![Event::member_unban(&u, world.guild_id, hit)],
                u.id.get(),
            )
        }
        "voice" => {
            let m = member(&step["member"]);
            let change = match step["change"].as_str().unwrap() {
                "join" => Change::Join,
                "leave" => Change::Leave,
                _ => Change::Move,
            };
            let channel = |c: &Value| -> Option<(u64, String)> {
                c.as_object().map(|_| {
                    (
                        c["id"].as_str().unwrap().parse().unwrap(),
                        c["name"].as_str().unwrap().to_string(),
                    )
                })
            };
            let (before, after) = (channel(&step["before"]), channel(&step["after"]));
            let stay = step["stay"]
                .as_array()
                .map(|s| (s[0].as_i64().unwrap(), s[1].as_str().unwrap().to_string()));
            let event = Event::voice(
                change,
                &m,
                &view,
                before.as_ref().map(|(id, name)| (*id, name.as_str())),
                after.as_ref().map(|(id, name)| (*id, name.as_str())),
                stay.as_ref().map(|(secs, text)| (*secs, text.as_str())),
                now,
            );
            (vec![event], m.user.id.get())
        }
        other => panic!("知らない手順: {other}"),
    }
}

fn at_of(step: &Value) -> DateTime<Utc> {
    step["at"].as_str().unwrap().parse().unwrap()
}

/// 履歴の行（種類・状態・実行者・理由・中身の JSON の文字・時刻）が Python と同じこと。DB は要らない。
#[test]
fn event_rows_match_python() {
    let world = load();
    let mut wrong = Vec::new();
    let mut total = 0;
    for (i, step) in world.steps.iter().enumerate() {
        let now = at_of(step);
        let (events, _) = events_of(&world, step, now);
        let got: Vec<Value> = events
            .iter()
            .map(|e| {
                let w = user_state::plan(e, Some(&world.settings), now);
                json!([
                    w.event_type,
                    w.status_after,
                    w.actor_user_id,
                    w.actor_name,
                    w.reason,
                    w.payload_json,
                    w.at.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
                ])
            })
            .collect();
        total += got.len();
        let want = &world.expected["steps"][i]["events"];
        if &Value::Array(got.clone()) != want {
            wrong.push(format!(
                "手順 {i}（{}）\n  py {want}\n  rs {}",
                step["kind"],
                Value::Array(got)
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 手順が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(json!(total), world.expected["totals"]["events"]);
    assert_eq!(world.steps.len(), 26, "例が減っている");
}

/// 監査ログの選び方と読み直す回数が Python と同じこと。
#[tokio::test]
async fn audit_selection_matches_python() {
    let world = load();
    assert_eq!(world.audit.len(), 9, "例が減っている");
    for (case, want) in world
        .audit
        .iter()
        .zip(world.expected["audit"].as_array().unwrap())
    {
        let now = DateTime::from_timestamp_millis(case["now_ms"].as_i64().unwrap()).unwrap();
        let target: u64 = case["target"].as_str().unwrap().parse().unwrap();
        let pages = case["pages"].as_array().unwrap().clone();
        let calls = AtomicU32::new(0);
        let hit = user_state::find_recent_audit_entry(
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst) as usize;
                let page = pages.get(n).cloned().unwrap_or(json!([]));
                async move {
                    if page == "raise" {
                        return Err("boom");
                    }
                    Ok(page
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| AuditRow {
                            id: e[0].as_str().unwrap().parse().unwrap(),
                            target_id: e[1].as_str().map(|t| t.parse().unwrap()),
                            actor: None,
                            reason: None,
                        })
                        .collect())
                }
            },
            target,
            || now,
            user_state::AUDIT_RETRIES,
            Duration::ZERO,
        )
        .await;
        let got = json!([
            case["id"],
            hit.map(|h| h.id.to_string()),
            calls.load(Ordering::SeqCst)
        ]);
        assert_eq!(got, json!([want[0], want[1], want[2]]), "{}", case["id"]);
        // Python は、読んだ回数より 1 つ少ない回数だけ待つ（見つかった回・最後の回のあとは待たない）。
        let waits = want[3].as_array().unwrap();
        assert!(
            waits.iter().all(|w| *w == json!(0.6)),
            "待ちが 0.6 秒でない"
        );
    }
    assert_eq!(user_state::AUDIT_RETRY_DELAY, Duration::from_millis(600));
    assert_eq!(user_state::AUDIT_WINDOW_SECONDS, 20);
}

// ── ここから下は本物の Postgres が要る ──────────────────────────────────

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// テスト 1 本ぶんの、空のスキーマにつないだ接続の束。
async fn isolated_pool(name: &str) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "t_us_{}_{}_{}",
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
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap()
}

const EVENTS_AFTER: &str = "SELECT json_build_array(id, event_type, status_after, actor_user_id, actor_name, reason, \
    payload_json, to_char(event_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'))::text \
    FROM user_state_event WHERE id > $1 ORDER BY id";

const CURRENT_OF: &str = "SELECT json_build_array(username, display_name, avatar_url, status, is_in_guild, is_banned, \
    is_timed_out, to_char(timed_out_until AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), roles_json, \
    abilities_json, last_event_type, \
    to_char(last_event_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(last_joined_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(last_left_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    first_seen_at IS NOT NULL, created_at IS NOT NULL)::text \
    FROM user_state_current WHERE guild_id = $1 AND user_id = $2";

const SCHEMA_COLUMNS: &str = "SELECT COALESCE(json_agg(json_build_array(table_name, column_name, data_type, \
    character_maximum_length, is_nullable, column_default) ORDER BY table_name, ordinal_position), '[]')::text \
    FROM information_schema.columns WHERE table_schema = current_schema() \
    AND table_name IN ('user_state_current', 'user_state_event')";

const SCHEMA_INDEXES: &str = "SELECT COALESCE(json_agg(json_build_array(tablename, indexname, \
    replace(indexdef, current_schema() || '.', '')) ORDER BY tablename, indexname), '[]')::text \
    FROM pg_indexes WHERE schemaname = current_schema() \
    AND tablename IN ('user_state_current', 'user_state_event')";

const SCHEMA_CONSTRAINTS: &str = "SELECT COALESCE(json_agg(json_build_array(c.relname, n.conname, n.contype::text, \
    pg_get_constraintdef(n.oid)) ORDER BY c.relname, n.conname), '[]')::text \
    FROM pg_constraint n JOIN pg_class c ON c.oid = n.conrelid \
    WHERE n.connamespace = current_schema()::regnamespace \
    AND c.relname IN ('user_state_current', 'user_state_event')";

async fn json_rows(pool: &PgPool, sql: &'static str, a: i64, b: Option<i64>) -> Vec<Value> {
    let mut query = sqlx::query_scalar::<_, String>(sql).bind(a);
    if let Some(b) = b {
        query = query.bind(b);
    }
    query
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .collect()
}

async fn json_one(pool: &PgPool, sql: &'static str) -> Value {
    let text: String = sqlx::query_scalar(sql).fetch_one(pool).await.unwrap();
    serde_json::from_str(&text).unwrap()
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

fn recorder(pool: &PgPool) -> Recorder {
    Recorder::new(pool.clone(), UserStateConfig::default())
}

/// 表の形（列・型・既定値・索引・制約）が、Python（SQLAlchemy）が作るものと同じこと。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_tables_have_the_python_shape() {
    let world = load();
    let pool = isolated_pool("schema").await;
    let r = recorder(&pool);
    r.ensure_tables(false).await.unwrap();
    // もう一度呼んでも、作り直しを強いても壊れない。
    r.ensure_tables(false).await.unwrap();
    r.ensure_tables(true).await.unwrap();
    for (name, sql) in [
        ("columns", SCHEMA_COLUMNS),
        ("indexes", SCHEMA_INDEXES),
        ("constraints", SCHEMA_CONSTRAINTS),
    ] {
        assert_eq!(
            json_one(&pool, sql).await,
            world.expected["schema"][name],
            "{name}"
        );
    }
}

/// 同じイベントを同じ順に記録すると、履歴の行と最新状態の行が Python と同じになること。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn rows_match_python_in_postgres() {
    let world = load();
    let pool = isolated_pool("rows").await;
    let r = recorder(&pool);
    let guild = world.guild_id.get() as i64;
    let mut last = 0;
    let mut wrong = Vec::new();
    for (i, step) in world.steps.iter().enumerate() {
        let now = at_of(step);
        let (events, user_id) = events_of(&world, step, now);
        for event in &events {
            r.record_at(event, Some(&world.settings), now).await;
        }
        let added = json_rows(&pool, EVENTS_AFTER, last, None).await;
        if let Some(row) = added.last() {
            last = row[0].as_i64().unwrap();
        }
        let added: Vec<Value> = added
            .iter()
            .map(|row| Value::Array(row.as_array().unwrap()[1..].to_vec()))
            .collect();
        let current = json_rows(&pool, CURRENT_OF, guild, Some(user_id as i64))
            .await
            .into_iter()
            .next()
            .unwrap_or(Value::Null);
        let got = json!({"events": added, "current": current});
        let want = &world.expected["steps"][i];
        if &got != want {
            wrong.push(format!(
                "手順 {i}（{}）\n  py {want}\n  rs {got}",
                step["kind"]
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 手順が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    let totals = json!({
        "events": count(&pool, "SELECT count(*) FROM user_state_event").await,
        "current": count(&pool, "SELECT count(*) FROM user_state_current").await,
    });
    assert_eq!(totals, world.expected["totals"]);
}

fn simple_event(user_id: u64, event_type: &str, status: &str) -> Event {
    Event {
        guild_id: 1,
        user_id,
        event_type: event_type.into(),
        status_after: status.into(),
        user: None,
        actor: None,
        reason: None,
        in_guild: None,
        is_banned: None,
        timed_out_until: None,
        payload: serde_json::Map::new(),
    }
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

/// 表が消えていても、作り直して書くこと（自己修復）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_missing_table_is_recreated_and_the_event_is_written() {
    let pool = isolated_pool("heal").await;
    let r = recorder(&pool);
    let now = at("2026-11-25T00:00:00Z");
    r.record_at(&simple_event(7, "member_join", "active"), None, now)
        .await;
    for table in ["user_state_event", "user_state_current"] {
        sqlx::query(AssertSqlSafe(format!("DROP TABLE {table}")))
            .execute(&pool)
            .await
            .unwrap();
        r.record_at(&simple_event(8, "member_ban", "banned"), None, now)
            .await;
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM user_state_event WHERE user_id = 8"
            )
            .await,
            1,
            "{table} を消したあとのイベントが残っていない"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM user_state_current WHERE user_id = 8 AND is_banned"
            )
            .await,
            1
        );
        sqlx::query("DELETE FROM user_state_event WHERE user_id = 8")
            .execute(&pool)
            .await
            .unwrap();
    }
}

/// 履歴と最新状態は一緒に書くか、どちらも書かないこと。失敗しても呼んだ側は止めない。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn history_and_current_state_are_written_together_or_not_at_all() {
    let pool = isolated_pool("atomic").await;
    let r = recorder(&pool);
    let now = at("2026-11-25T00:00:00Z");
    r.record_at(&simple_event(7, "member_join", "active"), None, now)
        .await;
    // 最新状態の書き換えだけを失敗させる（表を作り直しても直らない種類の失敗）。
    sqlx::query(
        "ALTER TABLE user_state_current ADD CONSTRAINT no_banned CHECK (status <> 'banned')",
    )
    .execute(&pool)
    .await
    .unwrap();
    r.record_at(&simple_event(7, "member_ban", "banned"), None, now)
        .await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_event").await,
        1,
        "最新状態を書けなかったのに履歴だけ残った"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM user_state_current WHERE status = 'active'"
        )
        .await,
        1
    );
    // 閉じた接続の束でも落ちない（ログに残して戻る）。
    let closed = isolated_pool("closed").await;
    let r = recorder(&closed);
    closed.close().await;
    r.record_at(&simple_event(7, "member_join", "active"), None, now)
        .await;
}

/// 行が無い人のイベントが同時に来ても、全部残すこと（最新状態は 1 行）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn simultaneous_first_events_are_all_kept() {
    let pool = isolated_pool("race").await;
    let r = Arc::new(recorder(&pool));
    r.ensure_tables(false).await.unwrap();
    let now = at("2026-11-25T00:00:00Z");
    for round in 0..5u64 {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let r = Arc::clone(&r);
            set.spawn(async move {
                r.record_at(
                    &simple_event(100 + round, "voice_join", "active"),
                    None,
                    now,
                )
                .await;
            });
        }
        while set.join_next().await.is_some() {}
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_event").await,
        40
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_current").await,
        5
    );
}

/// 保管期間を過ぎた履歴だけを消し、間隔が経つまでは次の掃除をしないこと。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn old_history_is_swept_once_per_interval() {
    let pool = isolated_pool("sweep").await;
    let r = recorder(&pool);
    r.ensure_tables(false).await.unwrap();
    let now = at("2026-11-25T00:00:00Z");
    let insert_old = |days: i64| {
        let when = (now - TimeDelta::days(days)).to_rfc3339();
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO user_state_event (guild_id, user_id, event_type, status_after, payload_json, event_at) \
                 VALUES (1, 9, 'old', 'active', '{}', $1::timestamptz)",
            )
            .bind(when)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    let olds = "SELECT count(*) FROM user_state_event WHERE event_type = 'old'";
    insert_old(3651).await;
    insert_old(3649).await;
    r.record_at(&simple_event(7, "member_join", "active"), None, now)
        .await;
    assert_eq!(count(&pool, olds).await, 1, "3651 日前だけが消える");
    // 間隔（6 時間）の中では掃除しない。
    insert_old(4000).await;
    let soon = now + TimeDelta::seconds(21_599);
    r.record_at(&simple_event(7, "voice_join", "active"), None, soon)
        .await;
    assert_eq!(count(&pool, olds).await, 2, "間隔の中で掃除した");
    // 間隔が経ったら掃除する。
    let later = now + TimeDelta::seconds(21_600);
    r.record_at(&simple_event(7, "voice_leave", "active"), None, later)
        .await;
    assert_eq!(count(&pool, olds).await, 1);
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM user_state_event WHERE user_id = 7"
        )
        .await,
        3,
        "記録そのものは毎回残る"
    );
}

/// 名前の分からないイベント（相手の情報なし）では、覚えている名前とアバターを消さないこと。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn names_survive_events_without_a_user() {
    let pool = isolated_pool("names").await;
    let r = recorder(&pool);
    let now = at("2026-11-25T00:00:00Z");
    let mut named = simple_event(7, "member_ban", "banned");
    named.user = Some(Person {
        id: 7,
        username: "nelly".into(),
        display_name: "ネリー".into(),
        avatar_url: "https://cdn.discordapp.com/embed/avatars/1.png".into(),
        member: None,
    });
    r.record_at(&named, None, now).await;
    r.record_at(&simple_event(7, "member_unban", "unbanned"), None, now)
        .await;
    let kept = "SELECT count(*) FROM user_state_current WHERE user_id = 7 AND username = 'nelly' \
        AND display_name = 'ネリー' AND avatar_url LIKE '%avatars/1.png' AND status = 'unbanned' \
        AND roles_json = '[]' AND abilities_json = '{}'";
    assert_eq!(count(&pool, kept).await, 1, "名前かアバターが消えた");
}

/// 掃除が失敗しても、記録は残すこと（掃除は付随の処理）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_failed_sweep_does_not_stop_recording() {
    let pool = isolated_pool("sweepfail").await;
    let r = recorder(&pool);
    r.ensure_tables(false).await.unwrap();
    // 履歴の削除だけを失敗させる（表を作り直しても直らない種類の失敗）。
    for sql in [
        "CREATE FUNCTION refuse_delete() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'no delete'; END $$ LANGUAGE plpgsql",
        "CREATE TRIGGER refuse_delete BEFORE DELETE ON user_state_event FOR EACH STATEMENT EXECUTE FUNCTION refuse_delete()",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    r.record_at(
        &simple_event(7, "member_join", "active"),
        None,
        at("2026-11-25T00:00:00Z"),
    )
    .await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_event").await,
        1,
        "掃除の失敗で記録まで止まった"
    );
}
