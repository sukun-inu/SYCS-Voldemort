//! 利用者の状態の、表の値の揃え直し（整合性の修復）と、サーバー 1 つぶんの削除。
//!
//! Python の `services/user_state_service.py` の `repair_user_state_integrity`（`_empty_repair_stats`・
//! `_repair_status`・`_repair_json_columns`・`_repair_flags`・`_repair_timeout`・`_repair_row`・`_repair_attempt`）
//! と `delete_guild_user_states`。
//!
//! 揃えてあるもの（本物の Python の修復に同じ行を与えて、直した値と数を比べて確かめた）:
//!
//! - 状態を保存用の形に（前後の空白を落として小文字に。空なら `unknown`。32 文字まで）
//! - ロール・権限の控えの JSON を、Python の `json.loads` で読み `json.dumps(ensure_ascii=False)` で書いた
//!   文字に揃える（**文字まで同じ**。読めない・型が違うものは空の `[]`・`{}` に）。揃えておかないと、同じ中身
//!   なのに Python と Rust が交互に「直した」と数え続ける。読み書きは [`pyjson`] が Python と同じ規則でする
//!   （数の書き方・重なった鍵・文字の逃がし方・`NaN` など）
//! - 状態から決まる在室・BAN の旗を揃える（**active では在室に手を出さない**。在室かは同期が Discord に問い
//!   合わせて決める）。期限を過ぎたタイムアウトの旗を下ろす
//! - **直した行だけ**最後に書き換えた時刻を進める。見る行は ID の順に上限まで（100〜200000 に収める）
//! - 失敗したら取り消して、表が無いなどなら作り直して 1 回だけやり直す。それでも駄目なら 0 件として返す
//!   （数えかけの値を返さない）
//!
//! - 控えの JSON に対になっていないサロゲート（`\ud800` など）が入った行は、それを U+FFFD にして書き直す
//!   （Python の `_replace_lone_surrogates`）。直す前の Python は書き直した文字を Postgres へ送れず、その
//!   サーバーの修復が毎回まるごと取り消されていた（ほかの壊れた行も直らなかった）

use chrono::{DateTime, Utc};
use tracing::error;

use crate::user_state::{self, Recorder};
use crate::user_state_sync::{self, CurrentRow};

/// 修復で数えたもの。Python の `_empty_repair_stats`。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepairStats {
    /// 見た行。
    pub rows_scanned: u64,
    /// 直した行。
    pub rows_fixed: u64,
    /// 状態を直した数。
    pub status_fixed: u64,
    /// 控えの JSON を直した数（1 行で 2 列直せば 2）。
    pub json_fixed: u64,
    /// 旗を直した数（1 行で 2 つ直せば 2）。
    pub flag_fixed: u64,
    /// タイムアウトの旗を直した数。
    pub timeout_fixed: u64,
}

/// 控えの JSON 1 つを揃える。書き換えるなら新しい文字（そのままでよければ `None`）。Python の
/// `_repair_json_columns` の 1 列ぶん。
///
/// 対になっていないサロゲートは U+FFFD にした文字で書き換える（Python の `_replace_lone_surrogates`。
/// [`pyjson::loads_dumps`] の文字は、もとから U+FFFD に置いてある）。
fn fix_json(raw: &str, want: pyjson::Kind) -> Option<String> {
    let empty = match want {
        pyjson::Kind::List => "[]",
        _ => "{}",
    };
    // 空の文字と読めない文字は、空の入れ物として読む（Python の `_safe_json_loads` の代わりの値）。
    let parsed = if raw.is_empty() {
        None
    } else {
        pyjson::loads_dumps(raw)
    };
    let Some(parsed) = parsed else {
        return (raw != empty).then(|| empty.into());
    };
    if parsed.kind != want {
        return Some(empty.into());
    }
    (parsed.text != raw).then_some(parsed.text)
}

/// 1 行を直す。Python の `_repair_row`。
///
/// **直した行だけ**最後に書き換えた時刻を進める（全部の行に触ると、誰がいつ抜けたのかが読めなくなる）。
pub fn repair_row(row: &mut CurrentRow, now: DateTime<Utc>, stats: &mut RepairStats) {
    let mut changed = false;

    // 状態（Python の `_repair_status`）。
    let normalized = user_state::sanitize_status(&row.status);
    if row.status != normalized {
        row.status = normalized;
        stats.status_fixed += 1;
        changed = true;
    }

    // 控えの JSON（Python の `_repair_json_columns`）。
    for (column, want) in [
        (&mut row.roles_json, pyjson::Kind::List),
        (&mut row.abilities_json, pyjson::Kind::Dict),
    ] {
        if let Some(text) = fix_json(column, want) {
            *column = text;
            stats.json_fixed += 1;
            changed = true;
        }
    }

    // 状態から決まる旗（Python の `_repair_flags`）。active では在室に手を出さない。
    let mut expected_in_guild = row.is_in_guild;
    let mut expected_banned = row.is_banned;
    match row.status.as_str() {
        "banned" => {
            expected_banned = true;
            expected_in_guild = false;
        }
        "left" | "kicked" => expected_in_guild = false,
        "active" => expected_banned = false,
        _ => {}
    }
    if row.is_in_guild != expected_in_guild {
        row.is_in_guild = expected_in_guild;
        stats.flag_fixed += 1;
        changed = true;
    }
    if row.is_banned != expected_banned {
        row.is_banned = expected_banned;
        stats.flag_fixed += 1;
        changed = true;
    }

    // タイムアウトの旗（Python の `_repair_timeout`）。
    let expected = row.timed_out_until.is_some_and(|until| until > now);
    if row.is_timed_out != expected {
        row.is_timed_out = expected;
        stats.timeout_fixed += 1;
        changed = true;
    }

    if changed {
        row.updated_at = Some(now);
        stats.rows_fixed += 1;
    }
}

/// 走査と修復を 1 回ぶん。失敗したら誤りを返す（取り消しとやり直しは呼んだ側）。Python の `_repair_attempt`。
async fn repair_attempt(
    recorder: &Recorder,
    guild_id: Option<i64>,
    max_rows: i64,
    now: DateTime<Utc>,
) -> Result<RepairStats, sqlx::Error> {
    let mut stats = RepairStats::default();
    let mut tx = recorder.pool().begin().await?;
    let fetched = match guild_id {
        Some(guild_id) => {
            sqlx::query(user_state_sync::SELECT_REPAIR_GUILD_ROWS)
                .bind(guild_id)
                .bind(max_rows)
                .fetch_all(&mut *tx)
                .await?
        }
        None => {
            sqlx::query(user_state_sync::SELECT_REPAIR_ALL_ROWS)
                .bind(max_rows)
                .fetch_all(&mut *tx)
                .await?
        }
    };
    let rows = fetched
        .iter()
        .map(user_state_sync::decode_row)
        .collect::<Result<Vec<_>, _>>()?;
    stats.rows_scanned = rows.len() as u64;
    let mut repaired = Vec::with_capacity(rows.len());
    for before in rows {
        let mut after = before.clone();
        repair_row(&mut after, now, &mut stats);
        repaired.push((before, after));
    }
    for (before, after) in &repaired {
        user_state_sync::update_changed(&mut tx, before, after).await?;
    }
    tx.commit().await?;
    Ok(stats)
}

/// 保存済みの最新状態の行を見て、決まりに反した値を直す（今の時刻で）。
pub async fn repair_user_state_integrity(
    recorder: &Recorder,
    guild_id: Option<u64>,
    max_rows: i64,
) -> Result<RepairStats, sqlx::Error> {
    repair_user_state_integrity_at(recorder, guild_id, max_rows, Utc::now()).await
}

/// 保存済みの最新状態の行を見て、決まりに反した値を直す（渡した時刻で）。Python の
/// `repair_user_state_integrity`。
///
/// 表を用意できなければ `Err`。見る・書く段で失敗したら、取り消して（直りうる失敗なら表を作り直して 1 回だけ
/// やり直して）0 件を返す（前の試行で数えた分を残すと、直した数が倍に見える）。
pub async fn repair_user_state_integrity_at(
    recorder: &Recorder,
    guild_id: Option<u64>,
    max_rows: i64,
    now: DateTime<Utc>,
) -> Result<RepairStats, sqlx::Error> {
    recorder.ensure_tables(false).await?;
    let now = user_state::micros(now);
    let safe_max_rows = max_rows.clamp(100, 200_000);
    let guild_id = guild_id.map(|g| i64::try_from(g).unwrap_or(i64::MAX));
    for attempt in 0..2 {
        match repair_attempt(recorder, guild_id, safe_max_rows, now).await {
            Ok(stats) => return Ok(stats),
            Err(e) => {
                if attempt == 0
                    && recorder
                        .try_self_heal("repair_user_state_integrity", &e)
                        .await
                {
                    continue;
                }
                let shown = guild_id.map_or("None".to_string(), |g| g.to_string());
                error!(
                    "[user_state_service] repair_user_state_integrity failed guild_id={shown}: {e}"
                );
                return Ok(RepairStats::default());
            }
        }
    }
    Ok(RepairStats::default())
}

/// 消した件数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeletedStates {
    /// 履歴の行。
    pub events: u64,
    /// 最新状態の行。
    pub states: u64,
}

/// 1 サーバーぶんの履歴と最新状態を消す。Python の `delete_guild_user_states`。
///
/// 利用者が「このサーバーのデータを削除」を選んだときの片側（[`crate::guild_retention::delete_guild_data`]
/// が呼ぶ）。保管期間の掃除とは別の口で、期間を見ずに全部消す。履歴と最新状態は同じトランザクションで消す
/// （片方だけ残ると、誰も居ないのに「BAN されている人が 1 人」といった表示が残る）。
pub async fn delete_guild_user_states(
    recorder: &Recorder,
    guild_id: u64,
) -> Result<DeletedStates, sqlx::Error> {
    recorder.ensure_tables(false).await?;
    let guild_id = i64::try_from(guild_id).unwrap_or(i64::MAX);
    let mut attempt = 0;
    loop {
        let result = async {
            let mut tx = recorder.pool().begin().await?;
            let events = sqlx::query("DELETE FROM user_state_event WHERE guild_id = $1")
                .bind(guild_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let states = sqlx::query("DELETE FROM user_state_current WHERE guild_id = $1")
                .bind(guild_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            tx.commit().await?;
            Ok::<_, sqlx::Error>(DeletedStates { events, states })
        }
        .await;
        match result {
            Ok(deleted) => return Ok(deleted),
            Err(e) => {
                if attempt == 0 && recorder.try_self_heal("delete_guild_user_states", &e).await {
                    attempt += 1;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// Python の `json.loads` と `json.dumps(value, ensure_ascii=False)` を、文字まで同じ規則で。
///
/// 値の木は作らず、読みながら書き直した文字を組み立てる（入れ子が深くても再帰しない）。
///
/// - 読み: 空白は ` \t\n\r` だけ。先頭の BOM は読めない。文字列の中の制御文字は読めない。`\uXXXX` は
///   サロゲートの対を 1 文字にし、対になっていないものはそのまま残す。数は `-?(0|[1-9][0-9]*)` に小数と指数が
///   付けば小数（`float`）、付かなければ整数（4300 桁を超えると読めない）。`NaN`・`Infinity`・`-Infinity` も
///   読む。鍵が重なれば、最初の位置に最後の値。入れ子は 9998 段まで（Python の再帰の上限）
/// - 書き: 区切りは `", "` と `": "`。整数は桁のまま（`-0` は `0`）。小数は Python の `repr`。文字は `"`・`\`・
///   制御文字だけ逃がす（`\n` などの短い形、ほかは `\u00XX`）
pub mod pyjson {
    use std::collections::HashMap;

    /// 一番外の値の種類。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Kind {
        /// 配列（Python の list）。
        List,
        /// オブジェクト（Python の dict）。
        Dict,
        /// それ以外。
        Other,
    }

    /// 読んで書き直した結果。
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Parsed {
        /// 一番外の値の種類。
        pub kind: Kind,
        /// 書き直した文字（対になっていないサロゲートは U+FFFD に置いてある）。
        pub text: String,
        /// 対になっていないサロゲートが残っているか（Python なら、その文字は UTF-8 にできない）。
        pub lone_surrogate: bool,
    }

    /// Python で読める入れ子の深さ（入れ物の数）。
    pub const MAX_DEPTH: usize = 9998;
    /// Python が整数として読む桁の上限（`sys.get_int_max_str_digits()` の既定）。
    pub const MAX_INT_DIGITS: usize = 4300;

    /// 書いた値 1 つ。
    struct Rendered {
        text: String,
        surrogate: bool,
    }

    enum Frame {
        List(Vec<Rendered>),
        Dict {
            entries: Vec<(Rendered, Rendered)>,
            index: HashMap<Vec<u32>, usize>,
            key: Vec<u32>,
        },
    }

    fn is_ws(c: char) -> bool {
        matches!(c, ' ' | '\t' | '\n' | '\r')
    }

    fn skip_ws(s: &[char], mut i: usize) -> usize {
        while i < s.len() && is_ws(s[i]) {
            i += 1;
        }
        i
    }

    fn starts_with(s: &[char], i: usize, word: &str) -> bool {
        let w: Vec<char> = word.chars().collect();
        s.len() >= i + w.len() && s[i..i + w.len()] == w[..]
    }

    fn hex4(s: &[char], from: usize) -> Option<u32> {
        let mut v = 0u32;
        for c in s.get(from..from + 4)? {
            v = (v << 4) | c.to_digit(16)?;
        }
        Some(v)
    }

    /// 文字列を読む（`start` は開きの `"` の次）。返すのは（符号位置の列, 閉じの `"` の次）。Python の
    /// `scanstring`（strict）。
    fn scan_string(s: &[char], start: usize) -> Option<(Vec<u32>, usize)> {
        let mut out: Vec<u32> = Vec::new();
        let mut end = start;
        loop {
            let mut next = end;
            let mut c = '\0';
            while next < s.len() {
                c = s[next];
                if c == '"' || c == '\\' {
                    break;
                }
                if (c as u32) <= 0x1f {
                    return None;
                }
                next += 1;
            }
            if next >= s.len() {
                return None;
            }
            out.extend(s[end..next].iter().map(|&ch| ch as u32));
            next += 1;
            if c == '"' {
                return Some((out, next));
            }
            let escaped = *s.get(next)?;
            if escaped != 'u' {
                end = next + 1;
                out.push(match escaped {
                    '"' => '"' as u32,
                    '\\' => '\\' as u32,
                    '/' => '/' as u32,
                    'b' => 0x08,
                    'f' => 0x0c,
                    'n' => 0x0a,
                    'r' => 0x0d,
                    't' => 0x09,
                    _ => return None,
                });
                continue;
            }
            next += 1;
            end = next + 4;
            if end >= s.len() {
                return None;
            }
            let mut cp = hex4(s, next)?;
            // 上位のサロゲートの直後に `\u` が続けば、対として読む（下位でなければ別の 1 文字に戻す）。
            if (0xD800..=0xDBFF).contains(&cp)
                && end + 6 < s.len()
                && s[end] == '\\'
                && s[end + 1] == 'u'
            {
                let low = hex4(s, end + 2)?;
                if (0xDC00..=0xDFFF).contains(&low) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    end += 6;
                }
            }
            out.push(cp);
        }
    }

    /// 文字列を Python の `json.dumps(ensure_ascii=False)` の形に書く。
    fn render_string(cps: &[u32]) -> Rendered {
        let mut text = String::with_capacity(cps.len() + 2);
        let mut surrogate = false;
        text.push('"');
        for &cp in cps {
            match cp {
                0x22 => text.push_str("\\\""),
                0x5c => text.push_str("\\\\"),
                0x0a => text.push_str("\\n"),
                0x0d => text.push_str("\\r"),
                0x09 => text.push_str("\\t"),
                0x08 => text.push_str("\\b"),
                0x0c => text.push_str("\\f"),
                0..=0x1f => text.push_str(&format!("\\u{cp:04x}")),
                _ => match char::from_u32(cp) {
                    Some(ch) => text.push(ch),
                    None => {
                        surrogate = true;
                        text.push('\u{FFFD}');
                    }
                },
            }
        }
        text.push('"');
        Rendered { text, surrogate }
    }

    /// 数を読む（`-Infinity` 以外）。Python の `_match_number`。返すのは（書いた形, 次の位置）。
    fn scan_number(s: &[char], start: usize) -> Option<(String, usize)> {
        let len = s.len();
        let digit = |i: usize| s.get(i).is_some_and(char::is_ascii_digit);
        let mut i = start;
        if s.get(i) == Some(&'-') {
            i += 1;
            if i >= len {
                return None;
            }
        }
        match s.get(i) {
            Some('1'..='9') => {
                i += 1;
                while digit(i) {
                    i += 1;
                }
            }
            Some('0') => i += 1,
            _ => return None,
        }
        let mut is_float = false;
        if i + 1 < len && s[i] == '.' && digit(i + 1) {
            is_float = true;
            i += 2;
            while digit(i) {
                i += 1;
            }
        }
        if i + 1 < len && (s[i] == 'e' || s[i] == 'E') {
            let e_start = i;
            i += 1;
            if i + 1 < len && (s[i] == '-' || s[i] == '+') {
                i += 1;
            }
            while digit(i) {
                i += 1;
            }
            if digit(i - 1) {
                is_float = true;
            } else {
                i = e_start;
            }
        }
        let lexeme: String = s[start..i].iter().collect();
        if is_float {
            let value: f64 = lexeme.parse().ok()?;
            return Some((float_json(value), i));
        }
        let digits = lexeme.trim_start_matches('-');
        if digits.len() > MAX_INT_DIGITS {
            return None;
        }
        let text = if digits == "0" {
            "0".to_string()
        } else {
            lexeme
        };
        Some((text, i))
    }

    /// 小数を Python の `json.dumps` の形に（`NaN`・`Infinity`・`-Infinity` と、ほかは `repr`）。
    fn float_json(value: f64) -> String {
        if value.is_nan() {
            "NaN".into()
        } else if value.is_infinite() {
            if value > 0.0 { "Infinity" } else { "-Infinity" }.into()
        } else {
            float_repr(value)
        }
    }

    /// Python の `repr(float)`（最短で元に戻る桁。指数が -4 以下か 17 以上なら `1e+16` の形、ほかは
    /// `100.0` の形）。
    pub fn float_repr(value: f64) -> String {
        if value.is_nan() {
            return "nan".into();
        }
        if value.is_infinite() {
            return if value > 0.0 { "inf" } else { "-inf" }.into();
        }
        // Rust の `{:e}` も最短で元に戻る桁を出す（例: 1.5e16・5e-324・-0e0）。
        let sci = format!("{value:e}");
        let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
        let exp: i32 = exp.parse().unwrap_or(0);
        let negative = mantissa.starts_with('-');
        let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
        let decpt = exp + 1;
        let body = if decpt > -4 && decpt <= 16 {
            let n = digits.len() as i32;
            if decpt <= 0 {
                format!("0.{}{digits}", "0".repeat((-decpt) as usize))
            } else if decpt >= n {
                format!("{digits}{}.0", "0".repeat((decpt - n) as usize))
            } else {
                let (a, b) = digits.split_at(decpt as usize);
                format!("{a}.{b}")
            }
        } else {
            let (first, rest) = digits.split_at(1);
            let rest = if rest.is_empty() {
                String::new()
            } else {
                format!(".{rest}")
            };
            let sign = if exp < 0 { '-' } else { '+' };
            format!("{first}{rest}e{sign}{:02}", exp.unsigned_abs())
        };
        if negative { format!("-{body}") } else { body }
    }

    fn close_list(items: Vec<Rendered>) -> Rendered {
        let surrogate = items.iter().any(|r| r.surrogate);
        let parts: Vec<String> = items.into_iter().map(|r| r.text).collect();
        Rendered {
            text: format!("[{}]", parts.join(", ")),
            surrogate,
        }
    }

    fn close_dict(entries: Vec<(Rendered, Rendered)>) -> Rendered {
        let surrogate = entries.iter().any(|(k, v)| k.surrogate || v.surrogate);
        let parts: Vec<String> = entries
            .into_iter()
            .map(|(k, v)| format!("{}: {}", k.text, v.text))
            .collect();
        Rendered {
            text: format!("{{{}}}", parts.join(", ")),
            surrogate,
        }
    }

    /// オブジェクトの鍵と `:` を読む（`i` は鍵の開きの `"` のはず）。返すのは（鍵, 値の位置）。
    fn scan_key(s: &[char], i: usize) -> Option<(Vec<u32>, usize)> {
        if s.get(i) != Some(&'"') {
            return None;
        }
        let (key, next) = scan_string(s, i + 1)?;
        let i = skip_ws(s, next);
        if s.get(i) != Some(&':') {
            return None;
        }
        Some((key, skip_ws(s, i + 1)))
    }

    /// 読んで、Python と同じ文字に書き直す。読めなければ `None`（Python は例外を上げる）。
    pub fn loads_dumps(raw: &str) -> Option<Parsed> {
        let s: Vec<char> = raw.chars().collect();
        if s.first() == Some(&'\u{feff}') {
            return None;
        }
        let mut i = skip_ws(&s, 0);
        let kind = match s.get(i) {
            Some('[') => Kind::List,
            Some('{') => Kind::Dict,
            _ => Kind::Other,
        };
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            // 値を 1 つ読む（入れ物を開いたら、中の最初の値へ進む）。
            let mut value = match s.get(i)? {
                '"' => {
                    let (cps, next) = scan_string(&s, i + 1)?;
                    i = next;
                    render_string(&cps)
                }
                '[' | '{' if stack.len() >= MAX_DEPTH => return None,
                '[' => {
                    i = skip_ws(&s, i + 1);
                    if s.get(i) == Some(&']') {
                        i += 1;
                        close_list(Vec::new())
                    } else {
                        stack.push(Frame::List(Vec::new()));
                        continue;
                    }
                }
                '{' => {
                    i = skip_ws(&s, i + 1);
                    if s.get(i) == Some(&'}') {
                        i += 1;
                        close_dict(Vec::new())
                    } else {
                        let (key, next) = scan_key(&s, i)?;
                        i = next;
                        stack.push(Frame::Dict {
                            entries: Vec::new(),
                            index: HashMap::new(),
                            key,
                        });
                        continue;
                    }
                }
                'n' if starts_with(&s, i, "null") => {
                    i += 4;
                    plain("null")
                }
                't' if starts_with(&s, i, "true") => {
                    i += 4;
                    plain("true")
                }
                'f' if starts_with(&s, i, "false") => {
                    i += 5;
                    plain("false")
                }
                'N' if starts_with(&s, i, "NaN") => {
                    i += 3;
                    plain("NaN")
                }
                'I' if starts_with(&s, i, "Infinity") => {
                    i += 8;
                    plain("Infinity")
                }
                '-' if starts_with(&s, i, "-Infinity") => {
                    i += 9;
                    plain("-Infinity")
                }
                _ => {
                    let (text, next) = scan_number(&s, i)?;
                    i = next;
                    plain(&text)
                }
            };
            // 読んだ値を入れ物に入れる。入れ物が閉じたら、その外の入れ物へ。
            loop {
                match stack.last_mut() {
                    None => {
                        if skip_ws(&s, i) != s.len() {
                            return None;
                        }
                        return Some(Parsed {
                            kind,
                            lone_surrogate: value.surrogate,
                            text: value.text,
                        });
                    }
                    Some(Frame::List(items)) => {
                        items.push(value);
                        i = skip_ws(&s, i);
                        match s.get(i)? {
                            ']' => {
                                i += 1;
                                let Some(Frame::List(items)) = stack.pop() else {
                                    return None;
                                };
                                value = close_list(items);
                            }
                            ',' => {
                                i = skip_ws(&s, i + 1);
                                break;
                            }
                            _ => return None,
                        }
                    }
                    Some(Frame::Dict {
                        entries,
                        index,
                        key,
                    }) => {
                        // 鍵が重なれば、最初の位置に最後の値（Python の dict）。
                        let taken = std::mem::take(key);
                        match index.get(&taken) {
                            Some(&pos) => entries[pos].1 = value,
                            None => {
                                index.insert(taken.clone(), entries.len());
                                entries.push((render_string(&taken), value));
                            }
                        }
                        i = skip_ws(&s, i);
                        match s.get(i)? {
                            '}' => {
                                i += 1;
                                let Some(Frame::Dict { entries, .. }) = stack.pop() else {
                                    return None;
                                };
                                value = close_dict(entries);
                            }
                            ',' => {
                                let (next_key, next) = scan_key(&s, skip_ws(&s, i + 1))?;
                                *key = next_key;
                                i = next;
                                break;
                            }
                            _ => return None,
                        }
                    }
                }
            }
        }
    }

    fn plain(text: &str) -> Rendered {
        Rendered {
            text: text.to_string(),
            surrogate: false,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn dumped(raw: &str) -> Option<String> {
            loads_dumps(raw).map(|p| p.text)
        }

        /// Python で確かめた読み書き（基準の照合とは別に、手元で読める例）。
        #[test]
        fn the_python_examples() {
            assert_eq!(dumped("[1,2]").as_deref(), Some("[1, 2]"));
            assert_eq!(
                dumped(r#" {"a":1,"b":[true,false,null]} "#).as_deref(),
                Some(r#"{"a": 1, "b": [true, false, null]}"#)
            );
            assert_eq!(
                dumped(r#"{"a": 1, "a": 2, "b": 3}"#).as_deref(),
                Some(r#"{"a": 2, "b": 3}"#)
            );
            assert_eq!(
                dumped("[1.0, 1e100, 1e16, 1e15, 1e-5, 0.0001, 1E2, -0, -0.0]").as_deref(),
                Some("[1.0, 1e+100, 1e+16, 1000000000000000.0, 1e-05, 0.0001, 100.0, 0, -0.0]")
            );
            assert_eq!(
                dumped("[NaN, Infinity, -Infinity, 1e400]").as_deref(),
                Some("[NaN, Infinity, -Infinity, Infinity]")
            );
            assert_eq!(
                dumped(r#"["é", "😀", "\n\t\u0001\u007f", "\/"]"#).as_deref(),
                Some("[\"é\", \"😀\", \"\\n\\t\\u0001\u{7f}\", \"/\"]")
            );
            assert!(loads_dumps(r#"["\ud800"]"#).unwrap().lone_surrogate);
            assert_eq!(
                dumped(r#"["\ud83dA"]"#).map(|t| t.replace('\u{FFFD}', "?")),
                Some(r#"["?A"]"#.to_string())
            );
            for bad in [
                "[1, 2",
                "",
                "\u{feff}[]",
                "[01]",
                "[1.]",
                "[.5]",
                "[+1]",
                "[1,]",
                "{\"a\":1,}",
                "{1: 2}",
                "[\"a\tb\"]",
                "[1]x",
                "[-NaN]",
                "[1e]",
                "[\u{3000}]",
                "[\u{c}1]",
            ] {
                assert_eq!(loads_dumps(bad), None, "{bad:?}");
            }
            assert_eq!(dumped("\n[1]\n").as_deref(), Some("[1]"));
            assert_eq!(loads_dumps("null").unwrap().kind, Kind::Other);
        }

        /// 深い入れ子は 9998 段まで読み、それより深いと読めないこと（再帰しないので落ちない）。
        #[test]
        fn deep_nesting_stops_where_python_stops() {
            let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
            assert_eq!(loads_dumps(&ok).unwrap().text, ok);
            let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
            assert_eq!(loads_dumps(&deep), None);
        }

        /// 4300 桁までの整数は読み、それを超えると読めないこと（符号は数えない）。
        #[test]
        fn long_integers_stop_at_the_python_limit() {
            let ok = format!("[-{}]", "1".repeat(MAX_INT_DIGITS));
            assert_eq!(dumped(&ok).as_deref(), Some(ok.as_str()));
            assert_eq!(
                loads_dumps(&format!("[{}]", "1".repeat(MAX_INT_DIGITS + 1))),
                None
            );
        }

        /// 小数の書き方が Python の repr と同じこと。
        #[test]
        fn float_repr_matches_python() {
            for (v, want) in [
                (2.5e-7, "2.5e-07"),
                (5e-324, "5e-324"),
                (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
                (0.1, "0.1"),
                (100.0, "100.0"),
                (1e22, "1e+22"),
                (1.5e16, "1.5e+16"),
                (12_345_678.9, "12345678.9"),
                (-0.0, "-0.0"),
                (0.0, "0.0"),
                (123_456_789_012_345_680.0, "1.2345678901234568e+17"),
                (0.002, "0.002"),
            ] {
                assert_eq!(float_repr(v), want);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// 直した行だけ時刻を進め、active では在室に触らず、項目ごとに数えること。
    #[test]
    fn only_broken_rows_are_touched() {
        let now = at("2026-11-28T00:00:00Z");
        let mut stats = RepairStats::default();
        let mut fine = CurrentRow::blank(1, false);
        fine.status = "active".into();
        let before = fine.clone();
        repair_row(&mut fine, now, &mut stats);
        assert_eq!(fine, before);
        assert_eq!(stats, RepairStats::default());

        let mut broken = CurrentRow::blank(2, false);
        broken.status = " BANNED ".into();
        broken.is_in_guild = true;
        broken.roles_json = "[1,2]".into();
        broken.abilities_json = "[]".into();
        broken.is_timed_out = true;
        broken.timed_out_until = Some(at("2026-11-27T00:00:00Z"));
        repair_row(&mut broken, now, &mut stats);
        assert_eq!(broken.status, "banned");
        assert!(broken.is_banned && !broken.is_in_guild && !broken.is_timed_out);
        assert_eq!(broken.roles_json, "[1, 2]");
        assert_eq!(broken.abilities_json, "{}");
        assert_eq!(broken.updated_at, Some(now));
        assert_eq!(
            stats,
            RepairStats {
                rows_scanned: 0,
                rows_fixed: 1,
                status_fixed: 1,
                json_fixed: 2,
                flag_fixed: 2,
                timeout_fixed: 1,
            }
        );

        let mut away = CurrentRow::blank(3, true);
        away.status = "active".into();
        repair_row(&mut away, now, &mut stats);
        assert!(
            !away.is_banned && !away.is_in_guild,
            "active では在室に手を出さない"
        );
    }

    /// 読めない・空の控えは空の入れ物に、対になっていないサロゲートは U+FFFD にして書き直すこと
    /// （Python の `_replace_lone_surrogates`）。書き直したものは、次の修復で直したと数えない。
    #[test]
    fn unreadable_json_and_lone_surrogates() {
        assert_eq!(fix_json("", pyjson::Kind::List), Some("[]".into()));
        assert_eq!(fix_json("[", pyjson::Kind::List), Some("[]".into()));
        assert_eq!(fix_json("[]", pyjson::Kind::List), None);
        assert_eq!(fix_json("null", pyjson::Kind::Dict), Some("{}".into()));
        assert_eq!(
            fix_json(r#"["\ud800"]"#, pyjson::Kind::List),
            Some("[\"\u{FFFD}\"]".into())
        );
        assert_eq!(
            fix_json(r#"{"a": "\ud800", "a": 1}"#, pyjson::Kind::Dict),
            Some(r#"{"a": 1}"#.into())
        );
        assert_eq!(fix_json("[\"\u{FFFD}\"]", pyjson::Kind::List), None);
        let now = at("2026-11-28T00:00:00Z");
        let mut stats = RepairStats::default();
        let mut row = CurrentRow::blank(1, false);
        row.status = "active".into();
        row.roles_json = r#"["\udc00", "😀"]"#.into();
        repair_row(&mut row, now, &mut stats);
        assert_eq!(row.roles_json, "[\"\u{FFFD}\", \"\u{1F600}\"]");
        assert_eq!(row.updated_at, Some(now));
        assert_eq!((stats.rows_fixed, stats.json_fixed), (1, 1));
        let again = row.clone();
        repair_row(&mut row, now, &mut stats);
        assert_eq!(row, again);
        assert_eq!((stats.rows_fixed, stats.json_fixed), (1, 1));
    }
}
