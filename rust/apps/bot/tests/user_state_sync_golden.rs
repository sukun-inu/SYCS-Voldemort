//! 利用者の状態の同期・修復・掃除が、本物の Python と同じ行を書き、同じ数を返すこと。
//!
//! 基準（`fixtures/user_state_sync/expected.json`）は、本物の Python の `sync_guild_user_states`・
//! `repair_user_state_integrity`・`record_user_state_event` に discord.py の本物の Member・User を渡して本物の
//! Postgres へ書かせ、行を読み出したもの（`generate.py`）。Discord からの取り方・修復の 1 行・JSON の読み書き・
//! 時刻の読み方・設定の鍵の読み方・放棄の判断・掃除も、本物の Python の関数の結果。
//!
//! - DB の要らないもの（JSON・時刻・鍵・放棄の判断・修復の 1 行・偽物の Discord からの取り方）は手元でも回る
//! - 表の行と掃除は本物の Postgres で比べる。`SYCS_TEST_DATABASE_URL` が要るので、手元では飛ばし（`#[ignore]`）、
//!   CI は Postgres 16 を立てて `--include-ignored` で必ず回す
//!
//! 退出とみなした人の履歴の並びは、Python では表を読む順（並びを指定しない SELECT。Postgres の実行計画で
//! 変わる）で決まる。比べるときは、人ごとの並びだけを見る（同じ人の履歴の前後は決まっている）。

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use serenity::all::{Cache, GuildCreateEvent, GuildId, Member, Role, RoleId, User, UserId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use sycs_bot::guild_retention::{self, parse_isoformat, python_int_key};
use sycs_bot::user_state::{Event, GuildView, Recorder, UserStateConfig};
use sycs_bot::user_state_repair::{self, RepairStats, pyjson};
use sycs_bot::user_state_sync::{
    self, CurrentRow, SyncConfig, SyncRequest, SyncStats, Syncer, sync_guild_user_states_at,
};
use sycs_core::settings::{CacheOptions, SettingsCache};
use tokio::sync::Mutex;

fn read(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/user_state_sync/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases() -> &'static Value {
    static CASES: OnceLock<Value> = OnceLock::new();
    CASES.get_or_init(|| read("cases.json"))
}

fn expected() -> &'static Value {
    static EXPECTED: OnceLock<Value> = OnceLock::new();
    EXPECTED.get_or_init(|| read("expected.json"))
}

fn at(text: &str) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(parse_isoformat(text).unwrap()).unwrap()
}

fn id(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

/// JSON の読み書きが Python の json.loads・json.dumps(ensure_ascii=False) と文字まで同じこと。
#[test]
fn json_matches_python() {
    let mut wrong = Vec::new();
    for (raw, want) in cases()["json"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["json"].as_array().unwrap())
    {
        let raw = raw.as_str().unwrap();
        let got = match pyjson::loads_dumps(raw) {
            None => Value::Null,
            Some(p) => {
                let kind = match p.kind {
                    pyjson::Kind::List => "list",
                    pyjson::Kind::Dict => "dict",
                    pyjson::Kind::Other => "other",
                };
                json!([kind, p.text, p.lone_surrogate])
            }
        };
        if &got != want {
            wrong.push(format!("{raw:?}\n  py {want}\n  rs {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// 時刻の読み方が Python の datetime.fromisoformat（guild_retention._parse）と同じこと。
#[test]
fn isoformat_matches_python() {
    let mut wrong = Vec::new();
    let all = cases()["iso"].as_array().unwrap();
    for (text, want) in all.iter().zip(expected()["iso"].as_array().unwrap()) {
        let text = text.as_str().unwrap();
        let got = parse_isoformat(text).map_or(Value::Null, |us| json!(us));
        if &got != want {
            wrong.push(format!("{text:?} py {want} rs {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(all.len() > 300);
}

/// 設定の鍵の読み方が Python の int() と同じこと（ASCII の数字の範囲）。
#[test]
fn guild_keys_match_python_int() {
    for (key, want) in cases()["int_keys"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["int_keys"].as_array().unwrap())
    {
        let got = python_int_key(key.as_str().unwrap()).map_or(Value::Null, Value::String);
        assert_eq!(&got, want, "{key}");
    }
}

/// 放棄の判断（触られた時刻の読み方・居るか・日数・あふれ）が Python の is_abandoned と同じこと。
#[test]
fn abandonment_matches_python() {
    for (case, want) in cases()["abandoned"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["abandoned"].as_array().unwrap())
    {
        let got = guild_retention::guild_is_abandoned(
            Some(&case["settings"]),
            "77",
            case["present"].as_bool().unwrap(),
            at(case["now"].as_str().unwrap()).timestamp_micros(),
            case["days"].as_i64().unwrap(),
        );
        let got = match got {
            Ok(b) => json!(b),
            Err(_) => json!("error"),
        };
        assert_eq!(&got, want, "{case}");
    }
}

fn stats_json(s: &RepairStats) -> Value {
    json!({
        "rows_scanned": s.rows_scanned, "rows_fixed": s.rows_fixed, "status_fixed": s.status_fixed,
        "json_fixed": s.json_fixed, "flag_fixed": s.flag_fixed, "timeout_fixed": s.timeout_fixed,
    })
}

fn sync_json(s: &SyncStats) -> Value {
    json!({
        "members_seen": s.members_seen, "bans_seen": s.bans_seen, "created": s.created,
        "updated": s.updated, "left_reconciled": s.left_reconciled, "events_written": s.events_written,
    })
}

/// 修復の 1 行が Python の _repair_row と同じ値・同じ数になること（328 例。対になっていないサロゲートの
/// 入った控えは、U+FFFD にした文字まで同じ）。
#[test]
fn repaired_rows_match_python() {
    let now = at(cases()["repair_now"].as_str().unwrap());
    let mut wrong = Vec::new();
    for (case, want) in cases()["repair_rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["repair_rows"].as_array().unwrap())
    {
        let mut row = CurrentRow::blank(1, case["is_banned"].as_bool().unwrap());
        row.status = case["status"].as_str().unwrap().into();
        row.is_in_guild = case["is_in_guild"].as_bool().unwrap();
        row.is_timed_out = case["is_timed_out"].as_bool().unwrap();
        row.timed_out_until = case["timed_out_until"].as_str().map(at);
        row.roles_json = case["roles_json"].as_str().unwrap().into();
        row.abilities_json = case["abilities_json"].as_str().unwrap().into();
        let mut stats = RepairStats::default();
        user_state_repair::repair_row(&mut row, now, &mut stats);
        let got_row = json!([
            row.status,
            row.is_in_guild,
            row.is_banned,
            row.is_timed_out,
            row.roles_json,
            row.abilities_json,
            row.updated_at.is_some()
        ]);
        // Python は、直したあとに送れない文字（対になっていないサロゲート）が残ると "unwritable" を立て、その列を
        // null にする。直したあとの Python では残らない（Rust の文字列には、そもそも入らない）。
        let got = json!({"row": got_row, "unwritable": false, "stats": stats_json(&stats)});
        if &got != want {
            wrong.push(format!("{case}\n  py {want}\n  rs {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} 例が違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(
        cases()["repair_rows"].as_array().unwrap().len(),
        328,
        "例が減っている"
    );
}

// ── 偽物の Discord からの取り方 ──

/// 偽物の Discord が返すメンバー（ID は base + i）。generate.py の page_member と同じ形。
fn page_member(i: u64, base: u64) -> Value {
    json!({
        "user": {"id": (base + i).to_string(), "username": format!("m{i}"), "discriminator": "0",
                 "avatar": null, "global_name": null},
        "roles": [], "joined_at": "2026-11-01T00:00:00+00:00", "deaf": false, "mute": false, "flags": 0,
    })
}

fn fetch_case(guild: u64) -> Option<&'static Value> {
    cases()["fetch"]
        .as_array()?
        .iter()
        .find(|c| id(&c["guild"]) == guild)
}

fn query(path: &str) -> HashMap<String, String> {
    path.split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// 偽物の Discord: メンバー・BAN の一覧を、after より後ろから limit 件返す。決めたページなら失敗する。
fn respond_lists(_method: &str, path: &str) -> (u16, String) {
    let parts: Vec<&str> = path.split('?').next().unwrap().split('/').collect();
    // /api/v10/guilds/{id}/members
    let Some(case) = parts
        .get(4)
        .and_then(|g| g.parse().ok())
        .and_then(fetch_case)
    else {
        return (404, "{}".into());
    };
    let q = query(path);
    let limit: u64 = q["limit"].parse().unwrap();
    let after: Option<u64> = q.get("after").map(|a| a.parse().unwrap());
    let base = case["base"].as_u64().unwrap();
    let page = after.map_or(0, |a| (a - base) / 1000);
    if case["fail_page"].as_u64() == Some(page) {
        let status = case["status"].as_u64().unwrap() as u16;
        return (status, json!({"message": "x", "code": 50001}).to_string());
    }
    let items: Vec<Value> = (1..=case["total"].as_u64().unwrap())
        .filter(|i| base + i > after.unwrap_or(0))
        .take(limit as usize)
        .map(|i| {
            if parts.get(5) == Some(&"bans") {
                json!({"user": page_member(i, base)["user"], "reason": null})
            } else {
                page_member(i, base)
            }
        })
        .collect();
    (200, Value::Array(items).to_string())
}

/// Discord からの取り方（1000 件ずつ・after・上限・ページの中の逆順・失敗のときの代わり）が、discord.py と
/// Python（_fetch_guild_members_for_sync・_fetch_guild_bans_for_sync）と同じこと。
#[tokio::test]
async fn fetching_matches_python() {
    let (base_url, seen) = support::start_fake_discord(respond_lists).await;
    let http = support::http_to(&base_url);
    for (case, want) in cases()["fetch"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["fetch"].as_array().unwrap())
    {
        seen.lock().unwrap().clear();
        let guild = GuildId::new(id(&case["guild"]));
        let base = case["base"].as_u64().unwrap();
        let (ids, fetched_all): (Vec<u64>, Value) = if case["what"] == "members" {
            let cached = || -> Vec<Member> {
                case["cached"]
                    .as_array()
                    .map(|c| c.iter().map(|i| i.as_u64().unwrap()).collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|i| {
                        let mut m = page_member(i, base);
                        m["guild_id"] = json!(guild.get().to_string());
                        serde_json::from_value(m).unwrap()
                    })
                    .collect()
            };
            let (members, all) =
                user_state_sync::fetch_members(&http, guild, case["max"].as_i64().unwrap(), cached)
                    .await;
            (
                members.iter().map(|m| m.user.id.get()).collect(),
                json!(all),
            )
        } else {
            let users = user_state_sync::fetch_bans(&http, guild).await;
            (users.iter().map(|u| u.id.get()).collect(), Value::Null)
        };
        let requests: Vec<Value> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| {
                let q = query(&s.path);
                let after: Option<u64> = q.get("after").map(|a| a.parse().unwrap());
                json!([q["limit"].parse::<u64>().unwrap(), after])
            })
            .collect();
        let got = json!({
            "id": case["id"], "requests": requests,
            "ids": ids.iter().map(u64::to_string).collect::<Vec<_>>(), "fetched_all": fetched_all,
        });
        assert_eq!(&got, want, "{}", case["id"]);
    }
}

// ── 本物の Postgres ──

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// テスト 1 本ぶんの、空のスキーマにつないだ接続の束。
async fn isolated_pool(name: &str) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "t_uss_{}_{}_{}",
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
        .options([("search_path", schema.as_str())]);
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap()
}

const SEED_ROW: &str = "INSERT INTO user_state_current (guild_id, user_id, username, display_name, avatar_url, \
    status, is_in_guild, is_banned, is_timed_out, timed_out_until, roles_json, abilities_json, last_event_type, \
    last_event_at, last_joined_at, last_left_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
    $10::timestamptz, $11, $12, $13, $14::timestamptz, $15::timestamptz, $16::timestamptz, $17::timestamptz)";

const SEED_EVENT: &str = "INSERT INTO user_state_event (guild_id, user_id, event_type, status_after, payload_json, \
    event_at) VALUES ($1, $2, $3, $4, $5, $6::timestamptz)";

const EVENTS_AFTER: &str = "SELECT json_build_array(id, guild_id::text, user_id::text, event_type, status_after, \
    actor_user_id::text, actor_name, reason, payload_json, \
    to_char(event_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'))::text \
    FROM user_state_event WHERE id > $1 ORDER BY id";

const CURRENT_OF: &str = "SELECT json_build_array(guild_id::text, user_id::text, username, display_name, \
    avatar_url, status, is_in_guild, is_banned, is_timed_out, \
    to_char(timed_out_until AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), roles_json, abilities_json, \
    last_event_type, to_char(last_event_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(last_joined_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(last_left_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), \
    first_seen_at IS NOT NULL, created_at IS NOT NULL)::text \
    FROM user_state_current WHERE guild_id = $1 ORDER BY user_id";

async fn json_rows(pool: &PgPool, sql: &'static str, bind: i64) -> Vec<Value> {
    sqlx::query_scalar::<_, String>(sql)
        .bind(bind)
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect()
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

async fn seed(pool: &PgPool, step: &Value) {
    for r in step["rows"].as_array().into_iter().flatten() {
        sqlx::query(SEED_ROW)
            .bind(id(&r["guild_id"]) as i64)
            .bind(id(&r["user_id"]) as i64)
            .bind(text(&r["username"]))
            .bind(text(&r["display_name"]))
            .bind(text(&r["avatar_url"]))
            .bind(text(&r["status"]))
            .bind(r["is_in_guild"].as_bool())
            .bind(r["is_banned"].as_bool())
            .bind(r["is_timed_out"].as_bool())
            .bind(text(&r["timed_out_until"]))
            .bind(text(&r["roles_json"]))
            .bind(text(&r["abilities_json"]))
            .bind(text(&r["last_event_type"]))
            .bind(text(&r["last_event_at"]))
            .bind(text(&r["last_joined_at"]))
            .bind(text(&r["last_left_at"]))
            .bind(text(&r["updated_at"]))
            .execute(pool)
            .await
            .unwrap();
    }
    for e in step["events"].as_array().into_iter().flatten() {
        sqlx::query(SEED_EVENT)
            .bind(id(&e["guild_id"]) as i64)
            .bind(id(&e["user_id"]) as i64)
            .bind(text(&e["event_type"]))
            .bind(text(&e["status_after"]))
            .bind(text(&e["payload_json"]))
            .bind(text(&e["event_at"]))
            .execute(pool)
            .await
            .unwrap();
    }
}

fn guild_roles() -> HashMap<RoleId, Role> {
    cases()["guild"]["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let role: Role = serde_json::from_value(r.clone()).unwrap();
            (role.id, role)
        })
        .collect()
}

/// 履歴を人ごとにまとめる（同じ人の中の並びは保つ）。
fn by_user(events: &[Value]) -> Vec<Value> {
    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e[1].as_str().unwrap_or_default().to_string());
    sorted
}

/// 同期・記録・修復を同じ順に流すと、手順ごとの数・足された履歴・最新状態の行・履歴の数が Python と同じこと
/// （25 手順。BAN の直後の退出・キックが BAN を残し、そのあとの同期が BAN の履歴を足さないこと、BAN を解除した
/// あとの退出はふつうの退出になること、メンバー一覧に期限の無い人のタイムアウトを下ろすこと、対になっていない
/// サロゲートの行があるサーバーも全部の行を直すこと、保管期間を過ぎた履歴を 6 時間おきに消すことも入っている）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn sync_and_repair_rows_match_python() {
    assert_eq!(
        cases()["steps"].as_array().unwrap().len(),
        25,
        "例が減っている"
    );
    let pool = isolated_pool("steps").await;
    let recorder = Recorder::new(pool.clone(), UserStateConfig::default());
    recorder.ensure_tables(false).await.unwrap();
    let roles = guild_roles();
    let guild_id = GuildId::new(id(&cases()["guild"]["id"]));
    let view = GuildView {
        id: guild_id,
        owner_id: Some(UserId::new(id(&cases()["guild"]["owner_id"]))),
        roles: &roles,
    };
    let settings = &cases()["settings"];
    let mut last = 0;
    let mut wrong = Vec::new();
    for (i, (step, want)) in cases()["steps"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expected()["steps"].as_array().unwrap())
        .enumerate()
    {
        let stats = match step["kind"].as_str().unwrap() {
            "seed" => {
                seed(&pool, step).await;
                Value::Null
            }
            "record" => {
                let event = Event {
                    guild_id: id(&step["guild_id"]),
                    user_id: id(&step["user_id"]),
                    event_type: step["event_type"].as_str().unwrap().into(),
                    status_after: step["status_after"].as_str().unwrap().into(),
                    user: None,
                    actor: None,
                    reason: None,
                    in_guild: step["in_guild"].as_bool(),
                    is_banned: step["is_banned"].as_bool(),
                    timed_out_until: None,
                    payload: Map::new(),
                };
                let now = at(step["at"].as_str().unwrap());
                recorder.record_at(&event, Some(settings), now).await;
                Value::Null
            }
            "sync" => {
                let members: Vec<Member> = step["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| serde_json::from_value(m.clone()).unwrap())
                    .collect();
                let bans: Vec<User> = step["bans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|u| serde_json::from_value(u.clone()).unwrap())
                    .collect();
                let request = SyncRequest {
                    guild: view,
                    members: &members,
                    banned_users: &bans,
                    source: step["source"].as_str().unwrap(),
                    reconcile_missing: step["reconcile"].as_bool().unwrap(),
                    write_events: step["write_events"].as_bool().unwrap(),
                };
                let now = at(step["at"].as_str().unwrap());
                let stats = sync_guild_user_states_at(&recorder, Some(settings), request, now)
                    .await
                    .unwrap();
                sync_json(&stats)
            }
            "repair" => {
                let now = at(step["at"].as_str().unwrap());
                let stats = user_state_repair::repair_user_state_integrity_at(
                    &recorder,
                    step["guild"].as_str().map(|g| g.parse().unwrap()),
                    step["max_rows"].as_i64().unwrap(),
                    now,
                )
                .await
                .unwrap();
                stats_json(&stats)
            }
            other => panic!("{other}"),
        };
        let added = json_rows(&pool, EVENTS_AFTER, last).await;
        if let Some(row) = added.last() {
            last = row[0].as_i64().unwrap();
        }
        let added: Vec<Value> = added
            .iter()
            .map(|row| Value::Array(row.as_array().unwrap()[1..].to_vec()))
            .collect();
        let mut current = Vec::new();
        for g in step["dump"].as_array().into_iter().flatten() {
            current.extend(json_rows(&pool, CURRENT_OF, id(g) as i64).await);
        }
        let got = json!({
            "stats": stats,
            "events": by_user(&added),
            "current": current,
            "event_count": count(&pool, "SELECT count(*) FROM user_state_event").await,
        });
        let mut want = want.clone();
        want["events"] = Value::Array(by_user(want["events"].as_array().unwrap()));
        for key in ["stats", "events", "current", "event_count"] {
            if got[key] != want[key] {
                wrong.push(format!(
                    "手順 {i}（{}）の {key}\n  py {}\n  rs {}",
                    step["kind"], want[key], got[key]
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} か所が Python と違う:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    let totals = json!({
        "events": count(&pool, "SELECT count(*) FROM user_state_event").await,
        "current": count(&pool, "SELECT count(*) FROM user_state_current").await,
    });
    assert_eq!(totals, expected()["totals"]);
}

/// 設定の表（Python の settings_pg と同じ形）に、ギルドの設定を入れる。
async fn settings_with(guilds: &Map<String, Value>) -> (PgPool, Arc<SettingsCache>) {
    let mut keys = guilds.iter();
    let (first, data) = keys.next().unwrap();
    let pool = support::settings_pool(first, data).await;
    for (key, data) in keys {
        sqlx::query("INSERT INTO bot_settings_guild (guild_key, data) VALUES ($1, $2::jsonb)")
            .bind(key)
            .bind(data.to_string())
            .execute(&pool)
            .await
            .unwrap();
    }
    let options = CacheOptions {
        poll_interval: Duration::from_secs(1),
        listen: false,
        write_timeout: Duration::from_secs(10),
    };
    let cache = SettingsCache::start_with(pool.clone(), options)
        .await
        .unwrap();
    (pool, cache)
}

async fn stored_guilds(pool: &PgPool) -> Value {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT guild_key, data::text FROM bot_settings_guild ORDER BY guild_key")
            .fetch_all(pool)
            .await
            .unwrap();
    Value::Object(
        rows.into_iter()
            .map(|(k, v)| (k, serde_json::from_str(&v).unwrap()))
            .collect(),
    )
}

/// Bot が抜けたサーバーの設定の掃除が、Python と同じものを消し、同じものを残すこと（居るもの・新しいもの・
/// 時刻の無いもの・読めないもの・正規でない鍵は残す。残したものの中身と時刻は変えない）。先に「居るサーバーが
/// 0 件」で呼び、何も消さないことも Python と比べる（サーバーの一覧がまだ無いときに当たる）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn purge_matches_python() {
    let p = &cases()["purge"];
    let (pool, cache) = settings_with(p["guilds"].as_object().unwrap()).await;
    let want = &expected()["purge"];
    let nobody = guild_retention::purge_abandoned_guilds(
        &cache,
        &HashSet::new(),
        p["days"].as_i64().unwrap(),
        at(p["now"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(json!(nobody), want["removed_when_none_present"]);
    assert_eq!(stored_guilds(&pool).await, want["guilds_when_none_present"]);
    let present: HashSet<u64> = p["present"].as_array().unwrap().iter().map(id).collect();
    let removed = guild_retention::purge_abandoned_guilds(
        &cache,
        &present,
        p["days"].as_i64().unwrap(),
        at(p["now"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(json!(removed), want["removed"]);
    assert_eq!(stored_guilds(&pool).await, want["guilds"]);
    // 何も残っていなければ、もう一度回しても何も消さない。
    let again = guild_retention::purge_abandoned_guilds(
        &cache,
        &present,
        p["days"].as_i64().unwrap(),
        at(p["now"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert!(again.is_empty());
}

/// 居るサーバーが 1 つだけでも掃除はすること（飛ばすのは 0 件のときだけ）。Rust の中だけで確かめる（Python の
/// `GuildRetentionTests.test_purging_skips_every_guild_the_bot_is_in` と同じ形）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn purge_runs_with_a_single_present_guild() {
    let old = json!({"_updated_at": "2000-01-01T00:00:00+00:00", "log_channel_id": 1});
    let mut guilds = Map::new();
    guilds.insert("1430000000000000010".into(), old.clone());
    guilds.insert("1430000000000000011".into(), old);
    let (pool, cache) = settings_with(&guilds).await;
    let removed = guild_retention::purge_abandoned_guilds(
        &cache,
        &HashSet::from([1_430_000_000_000_000_010]),
        3650,
        at("2036-11-25T00:00:00+00:00"),
    )
    .await
    .unwrap();
    assert_eq!(removed, vec!["1430000000000000011".to_string()]);
    let left = stored_guilds(&pool).await;
    assert_eq!(
        left.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["1430000000000000010"]
    );
}

// ── 巡回（Rust の中だけで確かめるもの） ──

const SG_A: u64 = 1_430_000_000_000_000_001;
const SG_B: u64 = 1_430_000_000_000_000_002;

fn small_member(guild: u64, user: u64) -> Value {
    json!({
        "guild_id": guild.to_string(),
        "user": {"id": user.to_string(), "username": format!("u{user}"), "discriminator": "0", "avatar": null,
                 "global_name": null},
        "roles": [], "joined_at": "2026-11-01T00:00:00+00:00", "deaf": false, "mute": false, "flags": 0,
    })
}

/// 巡回の偽物の Discord: A はメンバー 2 人・BAN 1 人。B はメンバーが 403（キャッシュで代わり）・BAN が 500。
fn respond_tour(_method: &str, path: &str) -> (u16, String) {
    let a = SG_A.to_string();
    let b = SG_B.to_string();
    if path.contains(&format!("/guilds/{a}/members")) {
        let mut v = vec![small_member(SG_A, 11), small_member(SG_A, 12)];
        for m in &mut v {
            m.as_object_mut().unwrap().remove("guild_id");
        }
        return (200, Value::Array(v).to_string());
    }
    if path.contains(&format!("/guilds/{a}/bans")) {
        let ban = json!([{"user": small_member(SG_A, 13)["user"], "reason": "spam"}]);
        return (200, ban.to_string());
    }
    if path.contains(&format!("/guilds/{b}/members")) {
        return (
            403,
            json!({"message": "Missing Access", "code": 50001}).to_string(),
        );
    }
    if path.contains(&format!("/guilds/{b}/bans")) {
        return (500, json!({"message": "boom", "code": 0}).to_string());
    }
    (404, "{}".into())
}

fn tour_cache() -> Cache {
    let cache = Cache::new();
    for (guild, mut members) in [(SG_A, vec![]), (SG_B, vec![small_member(SG_B, 21)])] {
        // サーバーの読み込みのメンバーには guild_id が無い（serenity が足す）。
        for m in &mut members {
            m.as_object_mut().unwrap().remove("guild_id");
        }
        let g = support::guild(
            &guild.to_string(),
            "99",
            json!([support::role(&guild.to_string(), 0, 0)]),
            Value::Array(members),
            json!([]),
            json!([]),
        );
        let mut event: GuildCreateEvent = serde_json::from_value(g).unwrap();
        cache.update(&mut event);
    }
    cache
}

fn quick_config() -> SyncConfig {
    SyncConfig {
        sync_delay: Duration::ZERO,
        guild_pause: Duration::from_millis(60),
        repair_start_delay: Duration::ZERO,
        ..SyncConfig::default()
    }
}

async fn states_of(pool: &PgPool, guild: u64) -> Vec<(i64, String, bool)> {
    sqlx::query_as(
        "SELECT user_id, status, is_banned FROM user_state_current WHERE guild_id = $1 ORDER BY user_id",
    )
    .bind(guild as i64)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// 全部のサーバーを順に同期し、取れなかったサーバーはキャッシュで代わりにして（退出の突き合わせはせず）、
/// 合計を返すこと。サーバーの間は決めた時間だけ空けること（下限だけを見る）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_tour_syncs_every_guild_and_totals_them() {
    let (base, _seen) = support::start_fake_discord(respond_tour).await;
    let http = support::http_to(&base);
    let cache = tour_cache();
    let (pool, settings) = settings_with(json!({"1": {}}).as_object().unwrap()).await;
    let recorder = Recorder::new(pool.clone(), UserStateConfig::default());
    recorder.ensure_tables(false).await.unwrap();
    // B に、もう居ない人の行を置く（一覧が全部ではないので、退出にしてはいけない）。
    sqlx::query(
        "INSERT INTO user_state_current (guild_id, user_id, status, is_in_guild, is_banned, is_timed_out, \
         roles_json, abilities_json) VALUES ($1, 29, 'active', TRUE, FALSE, FALSE, '[]', '{}')",
    )
    .bind(SG_B as i64)
    .execute(&pool)
    .await
    .unwrap();
    let config = quick_config();
    let syncer = Syncer {
        http: &http,
        cache: &cache,
        recorder: &recorder,
        settings: &settings,
        config: &config,
        only_guild_id: None,
    };
    let lock = Mutex::new(());
    let started = Instant::now();
    let totals = syncer.sync_all_guilds("on_ready", true, true, &lock).await;
    assert!(
        started.elapsed() >= Duration::from_millis(120),
        "サーバーの間を空ける"
    );
    assert_eq!(
        totals.sync,
        SyncStats {
            members_seen: 3,
            bans_seen: 1,
            created: 4,
            updated: 0,
            left_reconciled: 0,
            events_written: 4,
        }
    );
    assert_eq!(totals.repair_rows, 5);
    assert_eq!(
        states_of(&pool, SG_A).await,
        vec![
            (11, "active".into(), false),
            (12, "active".into(), false),
            (13, "banned".into(), true)
        ]
    );
    assert_eq!(
        states_of(&pool, SG_B).await,
        vec![(21, "active".into(), false), (29, "active".into(), false)],
        "キャッシュで代わりにしたときは退出の突き合わせをしない"
    );

    // BOT_ONLY_GUILD_ID があれば、そのサーバーだけ。
    sqlx::query("DELETE FROM user_state_current")
        .execute(&pool)
        .await
        .unwrap();
    let only = Syncer {
        only_guild_id: Some(SG_B),
        ..syncer
    };
    let totals = only
        .sync_all_guilds("auto_repair", false, false, &lock)
        .await;
    assert_eq!(totals.sync.members_seen, 1);
    assert_eq!(totals.repair_rows, 0, "頼まれなければ修復しない");
    assert!(states_of(&pool, SG_A).await.is_empty());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM user_state_event WHERE payload_json LIKE '%auto_repair%'"
        )
        .await,
        0
    );
}

/// 起動の後の同期と定期の同期が、1 つの錠で順に走ること（錠を持っている間は同期が始まらない）。定期の巡回は
/// 同期のあとに、抜けたサーバーの設定を掃除すること。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn the_lock_serialises_and_the_loop_purges() {
    let (base, _seen) = support::start_fake_discord(respond_tour).await;
    let http = Arc::new(support::http_to(&base));
    let cache = Arc::new(tour_cache());
    // 抜けたサーバー（消える）と、居るサーバー（時刻が古くても残る）。
    let old = json!({"_updated_at": "2000-01-01T00:00:00+00:00"});
    let mut guilds = Map::new();
    guilds.insert("1440000000000000009".into(), old.clone());
    guilds.insert(SG_A.to_string(), old.clone());
    let (pool, settings) = settings_with(&guilds).await;
    let recorder = Arc::new(Recorder::new(pool.clone(), UserStateConfig::default()));
    let config = Arc::new(quick_config());
    let lock = Arc::new(Mutex::new(()));
    let held = lock.lock().await;
    let task = {
        let (http, cache, recorder, settings, config, lock) = (
            Arc::clone(&http),
            Arc::clone(&cache),
            Arc::clone(&recorder),
            Arc::clone(&settings),
            Arc::clone(&config),
            Arc::clone(&lock),
        );
        tokio::spawn(async move {
            let syncer = Syncer {
                http: &http,
                cache: &cache,
                recorder: &recorder,
                settings: &settings,
                config: &config,
                only_guild_id: None,
            };
            syncer.run_auto_repair(&lock).await;
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let tables: i64 = count(&pool, "SELECT count(*) FROM pg_tables WHERE tablename = 'user_state_current' AND schemaname = current_schema()").await;
    assert_eq!(tables, 0, "錠を持っている間は同期が始まらない");
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let left = stored_guilds(&pool).await;
        if !left
            .as_object()
            .unwrap()
            .contains_key("1440000000000000009")
        {
            assert_eq!(
                left,
                json!({SG_A.to_string(): old}),
                "居るサーバーは消さない"
            );
            break;
        }
        assert!(Instant::now() < deadline, "掃除されない: {left}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        states_of(&pool, SG_A).await.len(),
        3,
        "掃除の前に同期している"
    );
    let quiet = count(&pool, "SELECT count(*) FROM user_state_event").await;
    assert_eq!(quiet, 0, "定期の同期は、既定では履歴を書かない");
    task.abort();
}

/// 起動の後の同期は、履歴を書き、修復もすること（Python の `_sync_user_state_on_ready`）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn on_ready_writes_history_and_repairs() {
    let (base, _seen) = support::start_fake_discord(respond_tour).await;
    let http = support::http_to(&base);
    let cache = tour_cache();
    let (pool, settings) = settings_with(json!({"1": {}}).as_object().unwrap()).await;
    let recorder = Recorder::new(pool.clone(), UserStateConfig::default());
    recorder.ensure_tables(false).await.unwrap();
    // 状態は BAN なのに旗が立っていない行（同期は触らず、修復が直す）。
    sqlx::query(
        "INSERT INTO user_state_current (guild_id, user_id, status, is_in_guild, is_banned, is_timed_out, \
         roles_json, abilities_json) VALUES ($1, 19, 'banned', FALSE, FALSE, FALSE, '[]', '{}')",
    )
    .bind(SG_A as i64)
    .execute(&pool)
    .await
    .unwrap();
    let config = quick_config();
    let syncer = Syncer {
        http: &http,
        cache: &cache,
        recorder: &recorder,
        settings: &settings,
        config: &config,
        only_guild_id: None,
    };
    syncer.run_on_ready(&Mutex::new(())).await;
    let on_ready = count(
        &pool,
        "SELECT count(*) FROM user_state_event WHERE payload_json = '{\"source\": \"on_ready\"}'",
    )
    .await;
    assert_eq!(on_ready, 4);
    let states = states_of(&pool, SG_A).await;
    assert!(states.contains(&(19, "banned".into(), true)), "{states:?}");
}

/// 表が無くなっていても、作り直して 1 回だけやり直すこと（同期も修復も）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn a_missing_table_is_recreated_and_the_work_retried() {
    let pool = isolated_pool("heal").await;
    let recorder = Recorder::new(pool.clone(), UserStateConfig::default());
    recorder.ensure_tables(false).await.unwrap();
    sqlx::query("DROP TABLE user_state_current")
        .execute(&pool)
        .await
        .unwrap();
    let roles = HashMap::new();
    let view = GuildView {
        id: GuildId::new(5),
        owner_id: None,
        roles: &roles,
    };
    let members: Vec<Member> = vec![serde_json::from_value(small_member(5, 51)).unwrap()];
    let request = SyncRequest {
        guild: view,
        members: &members,
        banned_users: &[],
        source: "on_ready",
        reconcile_missing: true,
        write_events: true,
    };
    let now = at("2026-11-28T00:00:00Z");
    let stats = sync_guild_user_states_at(&recorder, None, request, now)
        .await
        .unwrap();
    assert_eq!((stats.created, stats.events_written), (1, 1));
    sqlx::query("DROP TABLE user_state_current")
        .execute(&pool)
        .await
        .unwrap();
    let repaired = user_state_repair::repair_user_state_integrity_at(&recorder, Some(5), 10, now)
        .await
        .unwrap();
    assert_eq!(repaired, RepairStats::default(), "作り直した空の表を見る");
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_current").await,
        0
    );
}

/// 同期は、変わった列だけを書き換えること。あいだに他から書かれた列（ここではロールの控え）は残る
/// （SQLAlchemy と同じ。行ごと書くと、同期の前に読んだ古い値で上書きしてしまう）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn only_changed_columns_are_written() {
    let pool = isolated_pool("cols").await;
    let recorder = Arc::new(Recorder::new(pool.clone(), UserStateConfig::default()));
    recorder.ensure_tables(false).await.unwrap();
    sqlx::query(
        "INSERT INTO user_state_current (guild_id, user_id, status, is_in_guild, is_banned, is_timed_out, \
         roles_json, abilities_json) VALUES (6, 61, 'active', TRUE, FALSE, FALSE, '[]', '{}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    // 他の書き手が行の錠を持ったまま、ロールの控えを書き換えている。
    let mut other = pool.begin().await.unwrap();
    sqlx::query("UPDATE user_state_current SET roles_json = '[\"concurrent\"]' WHERE user_id = 61")
        .execute(&mut *other)
        .await
        .unwrap();
    let sync = {
        let recorder = Arc::clone(&recorder);
        tokio::spawn(async move {
            let roles = HashMap::new();
            let view = GuildView {
                id: GuildId::new(6),
                owner_id: None,
                roles: &roles,
            };
            let bans: Vec<User> =
                vec![serde_json::from_value(small_member(6, 61)["user"].clone()).unwrap()];
            let request = SyncRequest {
                guild: view,
                members: &[],
                banned_users: &bans,
                source: "on_ready",
                reconcile_missing: false,
                write_events: false,
            };
            sync_guild_user_states_at(&recorder, None, request, at("2026-11-28T00:00:00Z"))
                .await
                .unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    other.commit().await.unwrap();
    let stats = sync.await.unwrap();
    assert_eq!(stats.updated, 1);
    let (status, roles): (String, String) =
        sqlx::query_as("SELECT status, roles_json FROM user_state_current WHERE user_id = 61")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (status.as_str(), roles.as_str()),
        ("banned", "[\"concurrent\"]")
    );
}

/// 1 サーバーぶんの削除が、そのサーバーの履歴と最新状態と設定だけを消すこと（利用者が消す口）。
#[tokio::test]
#[ignore = "本物の Postgres が要る（SYCS_TEST_DATABASE_URL）"]
async fn deleting_a_guild_removes_only_that_guild() {
    let (pool, settings) =
        settings_with(json!({"7": {"a": 1}, "8": {"b": 2}}).as_object().unwrap()).await;
    let recorder = Recorder::new(pool.clone(), UserStateConfig::default());
    recorder.ensure_tables(false).await.unwrap();
    for (guild, user) in [(7, 71), (7, 72), (8, 81)] {
        sqlx::query(
            "INSERT INTO user_state_current (guild_id, user_id, status, is_in_guild, is_banned, is_timed_out, \
             roles_json, abilities_json) VALUES ($1, $2, 'active', TRUE, FALSE, FALSE, '[]', '{}')",
        )
        .bind(guild)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
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
    let removed = guild_retention::delete_guild_data(&recorder, &settings, 7)
        .await
        .unwrap();
    assert_eq!(
        (removed.settings, removed.events, removed.states),
        (1, 2, 2)
    );
    assert_eq!(stored_guilds(&pool).await, json!({"8": {"b": 2}}));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_current").await,
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM user_state_event").await,
        1
    );
    let again = guild_retention::delete_guild_data(&recorder, &settings, 7)
        .await
        .unwrap();
    assert_eq!((again.settings, again.events, again.states), (0, 0, 0));
}
