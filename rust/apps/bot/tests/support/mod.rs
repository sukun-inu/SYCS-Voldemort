//! 結合テストで共通に使う道具: テストの中に立てる偽物の Discord、設定の表、サーバーの JSON。
//!
//! 「元に戻せない処理」や「Discord への応答の形」は本物の Discord では試せない（人を巻き込む・本番の
//! Bot の設定を書き換える）。serenity の送り先を偽物に向けて（`HttpBuilder::proxy`）、HTTP の形を確かめる。
//!
//! 使わない道具があるテストもあるので、未使用の警告は止めてある。
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use serenity::all::{Cache, GuildCreateEvent, Http, HttpBuilder};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 空のスキーマに設定の表を作り、このサーバーの設定を 1 行入れる。`SYCS_TEST_DATABASE_URL` が要る
/// （CI では必須。無ければ落とす。素通りさせない）。
pub async fn settings_pool(guild_id: &str, guild_settings: &Value) -> PgPool {
    let url = std::env::var("SYCS_TEST_DATABASE_URL")
        .expect("SYCS_TEST_DATABASE_URL が無い（CI では必須。手元では Postgres を立てて渡す）");
    let schema = format!(
        "t_bot_{}_{}",
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
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    for ddl in [
        "CREATE TABLE bot_settings_guild (guild_key text PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE bot_settings_state (id smallint PRIMARY KEY, version bigint NOT NULL, root jsonb NOT NULL, imported_from text, imported_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now())",
        "INSERT INTO bot_settings_state (id, version, root) VALUES (1, 1, '{}')",
    ] {
        sqlx::query(ddl).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO bot_settings_guild (guild_key, data) VALUES ($1, $2::jsonb)")
        .bind(guild_id)
        .bind(guild_settings.to_string())
        .execute(&pool)
        .await
        .unwrap();
    pool
}

/// ロールの JSON。
pub fn role(id: &str, position: i64, permissions: u64) -> Value {
    json!({
        "id": id, "name": format!("r{id}"), "color": 0,
        "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
        "hoist": false, "position": position, "permissions": permissions.to_string(),
        "managed": false, "mentionable": false, "flags": 0,
    })
}

/// テキストチャンネルの JSON。
pub fn text_channel(guild_id: &str, id: &str, name: &str) -> Value {
    json!({
        "id": id, "type": 0, "guild_id": guild_id, "name": name, "position": 0,
        "permission_overwrites": [], "nsfw": false, "rate_limit_per_user": 0,
    })
}

/// ユーザーの JSON。
pub fn user(id: &str, bot: bool) -> Value {
    json!({"id": id, "username": "nelly", "discriminator": "0", "avatar": null,
           "global_name": "表示名", "bot": bot})
}

/// サーバーの JSON（ゲートウェイの GUILD_CREATE の形。serenity が読める最小限）。
pub fn guild(
    guild_id: &str,
    owner_id: &str,
    roles: Value,
    members: Value,
    channels: Value,
    voice_states: Value,
) -> Value {
    json!({
        "id": guild_id, "name": "Media Server", "owner_id": owner_id,
        "verification_level": 0, "default_message_notifications": 0, "explicit_content_filter": 0,
        "roles": roles, "emojis": [], "features": [], "mfa_level": 0, "system_channel_flags": 0,
        "premium_tier": 0, "preferred_locale": "ja", "nsfw_level": 0, "stickers": [],
        "premium_progress_bar_enabled": false, "joined_at": "2026-01-01T00:00:00+00:00",
        "large": false, "member_count": 2,
        "voice_states": voice_states, "members": members, "channels": channels,
        "threads": [], "presences": [], "stage_instances": [], "guild_scheduled_events": [],
    })
}

/// サーバーを 1 つ読み込んだキャッシュ。
pub fn cache_with(guild: Value) -> Cache {
    let cache = Cache::new();
    let mut event: GuildCreateEvent = serde_json::from_value(guild).expect("サーバーの JSON");
    cache.update(&mut event);
    cache
}

/// 送り先を偽物に向けた serenity の HTTP。
pub fn http_to(base: &str) -> Http {
    HttpBuilder::new("test-token")
        .proxy(base)
        .ratelimiter_disabled(true)
        .build()
}

/// Bot が送ったメッセージとして偽物が返す JSON。
pub fn sent_message(channel_id: &str) -> String {
    json!({
        "id": "900", "channel_id": channel_id, "author": user("1350672236612288633", true),
        "content": "", "timestamp": "2026-11-27T00:00:00+00:00", "edited_timestamp": null,
        "tts": false, "mention_everyone": false, "mentions": [], "mention_roles": [],
        "attachments": [], "embeds": [], "pinned": false, "type": 0,
    })
    .to_string()
}

/// 偽物の Discord が受けた要求。
#[derive(Clone, Debug)]
pub struct Seen {
    /// メソッド。
    pub method: String,
    /// 道すじ（`/api/v10/…`）。
    pub path: String,
    /// 監査ログの理由（`X-Audit-Log-Reason`）。
    pub reason: Option<String>,
    /// 本文（JSON でなければ null）。
    pub body: Value,
}

/// 要求（メソッドと道すじ）から、返す状態と本文を決める。
pub type Responder = fn(&str, &str) -> (u16, String);

/// 偽物の Discord を立てる。受けた要求は順に記録する。
pub async fn start_fake_discord(respond: Responder) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let header_end = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let length: usize = header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + length {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let mut first = head.lines().next().unwrap_or("").split(' ');
                let method = first.next().unwrap_or("").to_string();
                let path = first.next().unwrap_or("").to_string();
                let body = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                let (status, text) = respond(&method, &path);
                seen.lock().unwrap().push(Seen {
                    method,
                    path,
                    reason: header("x-audit-log-reason"),
                    body,
                });
                let response = format!(
                    "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}",
                    text.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}
