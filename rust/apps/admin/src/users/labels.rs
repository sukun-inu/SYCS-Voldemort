//! 表示用の言葉と時刻。Python の `webapp_admin/api/users.py` の表（`STATUS_LABELS`・`STATUS_TONES`・`EVENT_LABELS`・
//! `SYNC_PREFIX_LABELS`・`SYNC_SOURCE_LABELS`・`ABILITY_LABELS`）と、`status_label`・`status_tone`・`event_label`・
//! `ability_label`・`format_jst`・`_roles`・`_enabled_abilities`・`_timed_out_now`。
//!
//! 表は Python と同じ中身・同じ並び（`event_label` は `SYNC_PREFIX_LABELS` を並びの順に見る）。表が Python のソースと
//! 同じことは、このモジュールのテストが `users.py` を読んで確かめる。

use chrono::{DateTime, FixedOffset, Utc};
use serde_json::{Map, Value};

use crate::python;

/// 状態の日本語（`STATUS_LABELS`）。
pub const STATUS_LABELS: [(&str, &str); 6] = [
    ("active", "在籍"),
    ("left", "退出"),
    ("kicked", "KICK"),
    ("banned", "BAN中"),
    ("unbanned", "BAN解除"),
    ("unknown", "不明"),
];

/// バッジの色（`STATUS_TONES`）。無い状態は `accent`。
pub const STATUS_TONES: [(&str, &str); 5] = [
    ("active", "success"),
    ("banned", "danger"),
    ("kicked", "danger"),
    ("left", "warning"),
    ("unbanned", "warning"),
];

/// イベントの日本語（`EVENT_LABELS`）。
pub const EVENT_LABELS: [(&str, &str); 15] = [
    ("member_join", "サーバー参加"),
    ("member_leave", "サーバー退出"),
    ("member_kick", "KICK"),
    ("member_ban", "BAN"),
    ("member_unban", "BAN解除"),
    ("member_nickname_changed", "ニック変更"),
    ("member_role_changed", "ロール変更"),
    ("member_timeout_set", "タイムアウト設定"),
    ("member_timeout_cleared", "タイムアウト解除"),
    ("voice_join", "VC参加"),
    ("voice_leave", "VC退出"),
    ("voice_move", "VC移動"),
    ("sync_discovered_member", "定期同期で検出（メンバー）"),
    ("sync_discovered_ban", "定期同期で検出（BAN）"),
    ("sync_mark_left", "定期同期で退出を反映"),
];

/// 定期同期のイベント（`sync_member_<起点>` など）の接頭辞と日本語（`SYNC_PREFIX_LABELS`。この順に見る）。
pub const SYNC_PREFIX_LABELS: [(&str, &str); 3] = [
    ("sync_member_", "メンバー状態を同期"),
    ("sync_ban_", "BAN状態を同期"),
    ("sync_left_", "退出を同期反映"),
];

/// 定期同期の起点の日本語（`SYNC_SOURCE_LABELS`）。無い起点はそのまま。
pub const SYNC_SOURCE_LABELS: [(&str, &str); 4] = [
    ("on_ready", "起動時"),
    ("auto_repair", "自動修復"),
    ("manual_signal", "手動実行"),
    ("startup_sync", "起動時"),
];

/// 権限の日本語（`ABILITY_LABELS`）。無い鍵はそのまま。
pub const ABILITY_LABELS: [(&str, &str); 9] = [
    ("administrator", "管理者権限"),
    ("manage_guild", "サーバー管理"),
    ("kick_members", "メンバーをキック"),
    ("ban_members", "メンバーをBAN"),
    ("moderate_members", "タイムアウト権限"),
    ("manage_roles", "ロール管理"),
    ("trusted_user", "信頼済みユーザー"),
    ("bypass_role", "セキュリティバイパス"),
    ("is_bot", "BOT"),
];

/// 日本時間の時差（秒。Python の `config.JST` は `timezone(timedelta(hours=9))`）。
const JST_SECONDS: i32 = 9 * 3600;

fn lookup(table: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, label)| *label)
}

/// `status_label`。空・`None` は `STATUS_LABELS["unknown"]`（不明）、表に無い状態はそのまま。
pub fn status_label(value: Option<&str>) -> String {
    let value = value.filter(|value| !value.is_empty()).unwrap_or("unknown");
    lookup(&STATUS_LABELS, value).unwrap_or(value).to_string()
}

/// `status_tone`。表に無い状態（空・`None` も）は `accent`。
pub fn status_tone(value: Option<&str>) -> &'static str {
    let value = value.unwrap_or_default();
    lookup(&STATUS_TONES, value).unwrap_or("accent")
}

/// `event_label`。空・`None` は `-`。表に無ければ定期同期の接頭辞を見て「日本語（起点）」、それも無ければそのまま。
pub fn event_label(value: Option<&str>) -> String {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return "-".to_string();
    };
    if let Some(label) = lookup(&EVENT_LABELS, value) {
        return label.to_string();
    }
    for (prefix, base) in SYNC_PREFIX_LABELS {
        if let Some(source) = value.strip_prefix(prefix) {
            let source = lookup(&SYNC_SOURCE_LABELS, source).unwrap_or(source);
            return format!("{base}（{source}）");
        }
    }
    value.to_string()
}

/// `ability_label`。表に無い鍵はそのまま。
pub fn ability_label(key: &str) -> String {
    lookup(&ABILITY_LABELS, key).unwrap_or(key).to_string()
}

/// 日本時間（9 時間は時差の範囲の中なので、作れないことは無い）。
fn jst() -> FixedOffset {
    FixedOffset::east_opt(JST_SECONDS).expect("JST")
}

/// `format_jst`。`None` は `-`、ほかは日本時間の `%Y/%m/%d %H:%M:%S`（秒より下は落とす）。
pub fn format_jst(value: Option<DateTime<Utc>>) -> String {
    match value {
        None => "-".to_string(),
        Some(value) => value
            .with_timezone(&jst())
            .format("%Y/%m/%d %H:%M:%S")
            .to_string(),
    }
}

/// `_roles`。並びでなければ空、並びなら辞書の要素だけ。
pub fn roles(raw: &Value) -> Vec<Map<String, Value>> {
    match raw {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_object().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

/// `_row` のロールの名前（`str(role.get("name"))`。名前が偽のロールは飛ばす）。
pub fn role_names(roles: &[Map<String, Value>]) -> Vec<String> {
    roles
        .iter()
        .filter_map(|role| role.get("name").filter(|name| python::truthy(name)))
        .map(python::str_of)
        .collect()
}

/// `_enabled_abilities`。辞書でなければ空、辞書なら値が真の鍵を日本語にして、文字の順に並べる。
pub fn enabled_abilities(raw: &Value) -> Vec<String> {
    let Value::Object(abilities) = raw else {
        return Vec::new();
    };
    let mut labels: Vec<String> = abilities
        .iter()
        .filter(|(_, enabled)| python::truthy(enabled))
        .map(|(key, _)| ability_label(key))
        .collect();
    labels.sort();
    labels
}

/// `_timed_out_now`。記録の旗ではなく、期限と今の時刻で決める（期限が無ければタイムアウト中ではない）。
///
/// 記録の `is_timed_out` は、期限が過ぎても、その人の次のイベントか 30 分ごとの修復まで立ったまま残る（本人の決定
/// 2026-11-28、トラッカーの rust-10 の (e)・決めごとの U4。Python は ec10a3e）。Python の、期限が datetime でない・
/// 時差が無いときの枝は、Postgres（timestamptz）からは来ないので無い。
pub fn timed_out_now(until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    until.is_some_and(|until| until > now)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    /// 表が Python のソース（webapp_admin/api/users.py）と同じ中身・同じ並びであること。
    #[test]
    fn the_tables_match_the_python_source() {
        let python = include_str!("../../../../../webapp_admin/api/users.py");
        let tables: [(&str, &[(&str, &str)]); 6] = [
            ("STATUS_LABELS", &STATUS_LABELS),
            ("STATUS_TONES", &STATUS_TONES),
            ("EVENT_LABELS", &EVENT_LABELS),
            ("SYNC_PREFIX_LABELS", &SYNC_PREFIX_LABELS),
            ("SYNC_SOURCE_LABELS", &SYNC_SOURCE_LABELS),
            ("ABILITY_LABELS", &ABILITY_LABELS),
        ];
        for (name, table) in tables {
            let start = python
                .find(&format!("{name}: dict[str, str] = {{"))
                .unwrap_or_else(|| panic!("{name} が users.py に無い"));
            let body = &python[start..];
            let body = &body[..body.find("\n}").unwrap()];
            let lines: Vec<String> = body
                .lines()
                .skip(1)
                .map(|line| line.trim().to_string())
                .collect();
            let ours: Vec<String> = table
                .iter()
                .map(|(key, label)| format!("\"{key}\": \"{label}\","))
                .collect();
            assert_eq!(lines, ours, "{name}");
        }
    }

    /// 状態・色・イベント・権限の言葉（空・None・表に無いもの・定期同期の起点）。
    #[test]
    fn labels_follow_python() {
        assert_eq!(status_label(None), "不明");
        assert_eq!(status_label(Some("")), "不明");
        assert_eq!(status_label(Some("unknown")), "不明");
        assert_eq!(status_label(Some("banned")), "BAN中");
        assert_eq!(status_label(Some("weird")), "weird");
        assert_eq!(status_tone(None), "accent");
        assert_eq!(status_tone(Some("unknown")), "accent");
        assert_eq!(status_tone(Some("left")), "warning");
        assert_eq!(event_label(None), "-");
        assert_eq!(event_label(Some("")), "-");
        assert_eq!(event_label(Some("voice_move")), "VC移動");
        assert_eq!(event_label(Some("sync_mark_left")), "定期同期で退出を反映");
        let synced = event_label(Some("sync_member_on_ready"));
        assert_eq!(synced, "メンバー状態を同期（起動時）");
        assert_eq!(event_label(Some("sync_ban_x")), "BAN状態を同期（x）");
        assert_eq!(event_label(Some("sync_left_")), "退出を同期反映（）");
        assert_eq!(event_label(Some("custom")), "custom");
        assert_eq!(ability_label("is_bot"), "BOT");
        assert_eq!(ability_label("x"), "x");
    }

    /// 日本時間で秒まで（秒より下は切り捨て、日付をまたぐ）。
    #[test]
    fn times_are_shown_in_japan_time() {
        assert_eq!(format_jst(None), "-");
        let late = at("2026-12-31T23:59:59.999999Z");
        assert_eq!(format_jst(Some(late)), "2027/01/01 08:59:59");
        let epoch = at("1970-01-01T00:00:00Z");
        assert_eq!(format_jst(Some(epoch)), "1970/01/01 09:00:00");
    }

    /// ロールは辞書だけ、名前は真のものだけを str() で。権限は真の鍵を日本語にして並べる。
    #[test]
    fn roles_and_abilities_are_picked_like_python() {
        let raw = json!([
            {"name": "A"}, "x", {"id": 2}, {"name": ""}, {"name": 1.5}, {"name": true}
        ]);
        let picked = roles(&raw);
        assert_eq!(picked.len(), 5);
        assert_eq!(role_names(&picked), ["A", "1.5", "True"]);
        assert!(roles(&json!("not-a-list")).is_empty());
        let raw = json!({"kick_members": true, "is_bot": 0, "z": "yes", "": 1, "b": []});
        assert_eq!(enabled_abilities(&raw), ["", "z", "メンバーをキック"]);
        assert!(enabled_abilities(&json!([1])).is_empty());
    }

    /// いまタイムアウト中かは、期限と今で決める（期限ちょうどは終わっている）。
    #[test]
    fn timeouts_end_at_the_deadline() {
        let now = at("2027-01-01T00:00:00Z");
        assert!(timed_out_now(Some(at("2027-01-01T00:00:00.000001Z")), now));
        assert!(!timed_out_now(Some(now), now));
        assert!(!timed_out_now(None, now));
    }
}
