//! ログをテキストと JSONL の両方へ落とす。Python の `services/log_setup.py` と同じ形にしてある。
//!
//! 移行中は Python と Rust のプロセスが同じ `data/logs/` へ書き、管理画面の開発者パネルが
//! `<名前>.jsonl` の末尾を読んで絞り込む。形が違うと、Rust のプロセスのログだけ
//! レベルで絞れない・カテゴリが出ない、という形で食い違う。だから揃える。
//!
//! - テキスト: `2026-11-25 12:34:56,789 [INFO] [voice] voice_check: 本文`（人が tail -f する）
//! - JSONL: `{"time", "level", "category", "logger", "message", …追加の項目}`（画面が絞る）
//! - レベルの名前は Python と同じ（`WARN` ではなく `WARNING`）。画面の絞り込みが
//!   `DEBUG/INFO/WARNING/ERROR/CRITICAL` で比べるので、`WARN` のままだと警告が全部落ちる
//! - 日付で回す。今書いているファイルは `bot.log`、回したものは `bot.log.2026-11-24.gz`。
//!   `LOG_RETENTION_DAYS`（既定 3650）個を超えた古いものから消す
//! - **今書いているファイルは畳まない**（`tail -f` で追えなくなる）
//! - **ログの都合で本体を止めない。** 書けない・畳めないときは標準エラーへ出して続ける

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, FixedOffset, Local, NaiveDate};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::env::Env;

/// 既定の保管個数（日数）。Python の `DEFAULT_RETENTION_DAYS` と同じ。
pub const DEFAULT_RETENTION_DAYS: i64 = 3650;

/// どの規則にも当たらなかった target のカテゴリ。Python の `DEFAULT_CATEGORY` と同じ。
///
/// 機械的に導出（crate 名をそのまま使うなど）すると、分類し忘れたものが
/// 「それらしいカテゴリ」を名乗って紛れ込む。当たらないものは当たらないと分かる形にする。
pub const DEFAULT_CATEGORY: &str = "other";

/// target（モジュールのパス）からカテゴリを引く表。素の前方一致で、長いものが勝つ。
///
/// カテゴリの名前は Python の `CATEGORY_RULES` にあるものだけを使う（テストで確かめている）。
/// 名前が揃っていれば、管理画面のカテゴリの絞り込みで Python と Rust のログが同じ棚に並ぶ。
pub const CATEGORY_RULES: &[(&str, &str)] = &[
    ("sycs_core::env", "system"),
    ("sycs_core::db", "system"),
    ("sycs_core::log", "system"),
    // Python の services.settings_pg・dev_signals・metrics_reporter と同じ棚。
    ("sycs_core::settings", "settings"),
    ("sycs_core::signals", "dev"),
    ("sycs_core::metrics", "metrics"),
    // Python の services.url_safety（security）・ttl_cache（system）と同じ棚。
    ("sycs_core::url_safety", "security"),
    ("sycs_core::ttl_cache", "system"),
    ("sycs_bot", "bot"),
    ("voice_check", "voice"),
    ("songbird", "voice"),
    ("davey", "voice"),
    ("serenity", "discord"),
    ("tokio_tungstenite", "discord"),
    ("tungstenite", "discord"),
    ("reqwest", "http"),
    ("hyper", "http"),
    ("hyper_util", "http"),
    ("h2", "http"),
    ("rustls", "system"),
    ("sqlx", "system"),
    ("tracing", "system"),
];

/// [`CATEGORY_RULES`] を長い順に並べたもの。表の記載順に依存させないため、1 回だけ作る。
fn sorted_rules() -> &'static [(&'static str, &'static str)] {
    static SORTED: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    SORTED.get_or_init(|| sort_longest_first(CATEGORY_RULES))
}

fn sort_longest_first(rules: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut sorted = rules.to_vec();
    sorted.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
    sorted
}

/// 長い順に並んだ表から、target に当たる最初のカテゴリを引く。
fn category_in(sorted: &[(&'static str, &'static str)], target: &str) -> &'static str {
    sorted
        .iter()
        .find(|(prefix, _)| target.starts_with(prefix))
        .map_or(DEFAULT_CATEGORY, |(_, category)| category)
}

/// target からカテゴリを引く。当たらなければ [`DEFAULT_CATEGORY`]。
pub fn category_for(target: &str) -> &'static str {
    category_in(sorted_rules(), target)
}

/// tracing のレベルを、Python の logging と同じ名前にする。
///
/// Python に TRACE は無いので DEBUG に寄せる（画面は TRACE を知らず、知らない名前は
/// 最も低い扱いになって絞り込みで消える）。
pub fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::TRACE | Level::DEBUG => "DEBUG",
        Level::INFO => "INFO",
        Level::WARN => "WARNING",
        Level::ERROR => "ERROR",
    }
}

/// 追加の項目の値 1 つあたりに許す文字数。Python の `_EXTRA_VALUE_MAX` と同じ。
///
/// 長い本文をそのまま入れると 1 行が肥大し、画面が末尾を読む費用が跳ね上がる。
const EXTRA_VALUE_MAX: usize = 512;

/// 1 件のログ。
#[derive(Debug, Clone)]
pub struct Record {
    /// 出した時刻（ローカル時刻＋オフセット）。
    pub time: DateTime<FixedOffset>,
    /// Python と同じ名前のレベル。
    pub level: &'static str,
    /// tracing の target（モジュールのパス）。Python のロガー名にあたる。
    pub target: String,
    /// 本文。
    pub message: String,
    /// `message` 以外の項目（guild_id など）。
    pub fields: Vec<(String, Value)>,
}

impl Record {
    /// テキストの 1 行。Python の `LOG_FORMAT` と同じ並び（asctime はカンマでミリ秒）。
    pub fn text_line(&self) -> String {
        format!(
            "{} [{}] [{}] {}: {}",
            self.time.format("%Y-%m-%d %H:%M:%S,%3f"),
            self.level,
            category_for(&self.target),
            self.target,
            self.message
        )
    }

    /// JSONL の 1 行。改行は JSON の中で `\n` へ逃がされるので、1 件が必ず 1 行に収まる。
    pub fn json_line(&self) -> String {
        let mut payload = Map::new();
        payload.insert(
            "time".into(),
            Value::String(self.time.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()),
        );
        payload.insert("level".into(), Value::String(self.level.into()));
        payload.insert(
            "category".into(),
            Value::String(category_for(&self.target).into()),
        );
        payload.insert("logger".into(), Value::String(self.target.clone()));
        payload.insert("message".into(), Value::String(self.message.clone()));
        for (key, value) in &self.fields {
            payload.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(payload).to_string()
    }
}

/// tracing の項目を集める。`message` は本文に、それ以外は追加の項目にする。
#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    fields: Vec<(String, Value)>,
}

impl FieldCollector {
    fn push(&mut self, field: &Field, value: Value) {
        let name = field.name();
        // `_` で始まるものと、log クレートからの橋渡しが付ける `log.` 系は載せない
        // （Python の _extra_fields が `_` で始まるものを外すのと同じ）。
        if name.starts_with('_') || name.starts_with("log.") {
            return;
        }
        self.fields.push((name.to_string(), value));
    }
}

fn truncated(text: &str) -> String {
    text.chars().take(EXTRA_VALUE_MAX).collect()
}

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.push(field, Value::String(truncated(value)));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // NaN と無限大は JSON に書けない。書けないものは文字列にして残す。
        let json = serde_json::Number::from_f64(value)
            .map_or_else(|| Value::String(value.to_string()), Value::Number);
        self.push(field, json);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, Value::Bool(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.push(field, Value::String(truncated(&format!("{value:?}"))));
        }
    }
}

/// 日付で回すファイル 1 つ。`<name>` に書き、日付が変わったら `<name>.<日付>.gz` へ畳む。
pub struct RotatingFile {
    dir: PathBuf,
    name: String,
    retention: usize,
    day: NaiveDate,
    file: Option<File>,
}

impl RotatingFile {
    /// 開く。既にファイルがあれば、最後に書かれた日をそのファイルの日とする。
    ///
    /// 前日のファイルが残ったまま起動したとき、最初の 1 行で回すため（Python の
    /// TimedRotatingFileHandler も、ファイルの更新時刻から次に回す時刻を決める）。
    pub fn open(dir: &Path, name: &str, retention: usize, today: NaiveDate) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(name);
        let day = fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| DateTime::<Local>::from(t).date_naive())
            .unwrap_or(today);
        Ok(Self {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            retention: retention.max(1),
            day,
            file: None,
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// 1 行書く。日付が変わっていたら、先に回す。
    pub fn write_line(&mut self, line: &str, today: NaiveDate) -> io::Result<()> {
        if today != self.day {
            self.rotate();
            self.day = today;
        }
        if self.file.is_none() {
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.path())?,
            );
        }
        let file = self.file.as_mut().expect("直前で開いた");
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")
    }

    /// 今のファイルを `<name>.<その日>` へ移して gzip で畳み、保管個数を超えた古いものを消す。
    fn rotate(&mut self) {
        self.file = None;
        let current = self.path();
        if !current.exists() {
            return;
        }
        let dated = self
            .dir
            .join(format!("{}.{}", self.name, self.day.format("%Y-%m-%d")));
        let packed = self
            .dir
            .join(format!("{}.{}.gz", self.name, self.day.format("%Y-%m-%d")));
        if let Err(e) = fs::rename(&current, &dated) {
            eprintln!(
                "[sycs_core::log] ログを回せませんでした（{}）: {e}",
                current.display()
            );
            return;
        }
        if let Err(e) = gzip_file(&dated, &packed) {
            // 素のまま残す。素のファイルは保管個数の掃除に入らないので、気づけるように出す。
            let _ = fs::remove_file(&packed);
            eprintln!(
                "[sycs_core::log] ログを畳めませんでした（{} を素のまま残しました。このファイルは保管日数の掃除に入りません）: {e}",
                dated.display()
            );
            return;
        }
        let _ = fs::remove_file(&dated);
        self.prune();
    }

    /// 畳んだファイルのうち、保管個数を超えた古いものを消す。
    ///
    /// 名前は `<name>.YYYY-MM-DD.gz` で、日付の文字列はそのまま古い順に並ぶ。
    fn prune(&self) {
        let prefix = format!("{}.", self.name);
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut packed: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix(&prefix))
                    .and_then(|rest| rest.strip_suffix(".gz"))
                    .is_some_and(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok())
            })
            .collect();
        packed.sort();
        if packed.len() > self.retention {
            for old in &packed[..packed.len() - self.retention] {
                if let Err(e) = fs::remove_file(old) {
                    eprintln!(
                        "[sycs_core::log] 古いログを消せませんでした（{}）: {e}",
                        old.display()
                    );
                }
            }
        }
    }
}

fn gzip_file(source: &Path, dest: &Path) -> io::Result<()> {
    let mut input = File::open(source)?;
    let mut encoder = GzEncoder::new(File::create(dest)?, Compression::default());
    io::copy(&mut input, &mut encoder)?;
    encoder.finish()?.sync_all()
}

/// テキストと JSONL の 2 つを、同じ日付で回して書く。
///
/// 片方だけ回ると「テキストには残っているのに JSON には無い日」ができ、端末と画面で
/// 見える範囲が食い違う。だから 1 つのロックの下で両方を書く。
pub struct LogFiles {
    text: RotatingFile,
    jsonl: RotatingFile,
}

impl LogFiles {
    /// `<dir>/<name>.log` と `<dir>/<name>.jsonl` を開く。
    pub fn open(dir: &Path, name: &str, retention: usize, today: NaiveDate) -> io::Result<Self> {
        Ok(Self {
            text: RotatingFile::open(dir, &format!("{name}.log"), retention, today)?,
            jsonl: RotatingFile::open(dir, &format!("{name}.jsonl"), retention, today)?,
        })
    }

    /// 1 件を両方へ書く。
    pub fn write(&mut self, record: &Record) -> io::Result<()> {
        let today = record.time.date_naive();
        self.text.write_line(&record.text_line(), today)?;
        self.jsonl.write_line(&record.json_line(), today)
    }
}

/// tracing の Layer。イベントを [`Record`] にして、ファイルと標準エラーへ書く。
pub struct FileLayer {
    files: Mutex<LogFiles>,
    console: bool,
}

impl FileLayer {
    /// 作る。`console` が真なら標準エラーにもテキストで出す（`docker logs` で見えるように）。
    pub fn new(files: LogFiles, console: bool) -> Self {
        Self {
            files: Mutex::new(files),
            console,
        }
    }
}

impl<S: Subscriber> Layer<S> for FileLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut collector = FieldCollector::default();
        event.record(&mut collector);
        let meta = event.metadata();
        let record = Record {
            time: Local::now().fixed_offset(),
            level: level_name(meta.level()),
            target: meta.target().to_string(),
            message: collector.message.unwrap_or_default(),
            fields: collector.fields,
        };
        if self.console {
            eprintln!("{}", record.text_line());
        }
        // 毒されたロックでも書き続ける（ログの都合で本体を止めない）。
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(e) = files.write(&record) {
            eprintln!("[sycs_core::log] ログを書けませんでした: {e}");
        }
    }
}

/// プロセスのログを設置する。`<dir>/<name>.log` と `<dir>/<name>.jsonl` に書く。
///
/// 絞り込みは `RUST_LOG`（既定 `info`）。保管個数は `LOG_RETENTION_DAYS`（Python と同じ変数）。
/// 2 回目以降の呼び出しは何もしない（既に設置されていれば、tracing がそれを返す）。
pub fn init(dir: &Path, name: &str) -> io::Result<()> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, registry};

    let env = Env::from_process();
    let retention = env.int("LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, Some(1), None);
    let retention = usize::try_from(retention).unwrap_or(usize::MAX);
    let files = LogFiles::open(dir, name, retention, Local::now().date_naive())?;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = registry()
        .with(filter)
        .with(FileLayer::new(files, true))
        .try_init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use chrono::TimeZone;
    use flate2::read::GzDecoder;

    use super::*;

    fn at(date: &str, time: &str) -> DateTime<FixedOffset> {
        FixedOffset::east_opt(9 * 3600)
            .unwrap()
            .from_local_datetime(
                &chrono::NaiveDateTime::parse_from_str(
                    &format!("{date} {time}"),
                    "%Y-%m-%d %H:%M:%S%.3f",
                )
                .unwrap(),
            )
            .unwrap()
    }

    fn record(
        time: DateTime<FixedOffset>,
        level: &'static str,
        target: &str,
        message: &str,
    ) -> Record {
        Record {
            time,
            level,
            target: target.into(),
            message: message.into(),
            fields: vec![],
        }
    }

    /// テキストの 1 行が Python の LOG_FORMAT と同じ並びであること。
    ///
    /// 運用者は Python と Rust のログを同じ目で読む（tail -f と grep）。並びが違うと、
    /// レベルやカテゴリで grep したときに片方だけ拾えない。
    #[test]
    fn the_text_line_matches_the_python_format() {
        let r = record(
            at("2026-11-25", "12:34:56.789"),
            "WARNING",
            "voice_check",
            "鳴らし始める",
        );
        assert_eq!(
            r.text_line(),
            "2026-11-25 12:34:56,789 [WARNING] [voice] voice_check: 鳴らし始める"
        );
    }

    /// JSONL の 1 行が、管理画面の読む項目と形を持ち、追加の項目も載ること。
    #[test]
    fn the_json_line_has_the_fields_the_admin_panel_reads() {
        let mut r = record(
            at("2026-11-25", "12:34:56.789"),
            "INFO",
            "serenity::gateway",
            "1行目\n2行目",
        );
        r.fields.push(("guild_id".into(), Value::from(123_u64)));
        let line = r.json_line();
        assert!(
            !line.contains('\n'),
            "改行が逃がされず、1 件が 2 行に割れた"
        );
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["time"], "2026-11-25T12:34:56.789+09:00");
        assert_eq!(parsed["level"], "INFO");
        assert_eq!(parsed["category"], "discord");
        assert_eq!(parsed["logger"], "serenity::gateway");
        assert_eq!(parsed["message"], "1行目\n2行目");
        assert_eq!(parsed["guild_id"], 123);
    }

    /// 警告のレベル名が WARNING であること。
    ///
    /// 管理画面は DEBUG/INFO/WARNING/ERROR/CRITICAL で比べる。tracing の WARN のままだと
    /// 知らない名前として最も低く扱われ、「警告以上」で絞った瞬間に警告が全部消える。
    #[test]
    fn warn_is_written_as_warning_and_trace_as_debug() {
        assert_eq!(level_name(&Level::WARN), "WARNING");
        assert_eq!(level_name(&Level::TRACE), "DEBUG");
        assert_eq!(level_name(&Level::ERROR), "ERROR");
    }

    /// 長い接頭辞が勝ち、どれにも当たらなければ other になること。
    ///
    /// 表の記載順で決まると、系列の中の例外（Python の `services.djaudio` に対する
    /// `services.djaudio_cdn`）を足したときに、並べた場所しだいで効いたり効かなかったりする。
    /// 今の表には重なる接頭辞でカテゴリが違う組が無いので、テスト用の表で確かめる。
    #[test]
    fn the_longest_prefix_wins_and_unknown_targets_are_other() {
        let rules = sort_longest_first(&[("bot", "bot"), ("bot::voice", "voice")]);
        assert_eq!(category_in(&rules, "bot::voice::join"), "voice");
        assert_eq!(category_in(&rules, "bot::events"), "bot");
        assert_eq!(category_for("sycs_core::env"), "system");
        // sycs_core のモジュールは、どれも「その他」に落ちないこと（lib.rs の pub mod から拾う
        // ので、モジュールを足して表に書き忘れるとここで落ちる）。設定の読み込みのログが
        // [other] に出ていたのを、本物の Discord につないだ確認で見つけた。
        let lib = include_str!("lib.rs");
        let modules: Vec<&str> = lib
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub mod "))
            .map(|l| l.trim_end_matches(';'))
            .collect();
        assert!(modules.len() >= 6, "{modules:?}");
        for m in modules {
            let target = format!("sycs_core::{m}");
            assert_ne!(category_for(&target), "other", "{target}");
        }
        assert_eq!(category_for("sycs_core::settings"), "settings");
        // Bot のログは Python の Bot と同じ棚（bot）に並ぶこと。
        assert_eq!(category_for("sycs_bot::handler"), "bot");
        assert_eq!(category_for("something_new"), DEFAULT_CATEGORY);
    }

    /// Rust で使うカテゴリの名前が、すべて Python の表にもあること。
    ///
    /// 管理画面のカテゴリの選択肢は、ログに出てきた名前から作られる。Rust だけが
    /// 違う綴り（"discord_gateway" など）を使うと、同じ種類のログが 2 つの棚に分かれる。
    #[test]
    fn every_category_name_exists_in_the_python_table() {
        let source = include_str!("../../../../services/log_setup.py");
        for (_, category) in CATEGORY_RULES {
            assert!(
                source.contains(&format!("\"{category}\")")),
                "Python の CATEGORY_RULES に無いカテゴリ: {category}"
            );
        }
        assert!(source.contains(&format!("DEFAULT_CATEGORY = \"{DEFAULT_CATEGORY}\"")));
    }

    /// 日付が変わったら、前の日のファイルを <name>.<日付>.gz に畳み、新しいファイルへ書くこと。
    ///
    /// 名前を Python と揃えておかないと、移行中に同じディレクトリで 2 通りの名前が混ざり、
    /// どちらかの掃除が相手のファイルを見つけられず、保管日数を過ぎても消えない。
    #[test]
    fn a_new_day_packs_yesterday_and_starts_a_fresh_file() {
        let dir = tempfile::tempdir().unwrap();
        let day1 = NaiveDate::from_ymd_opt(2026, 11, 24).unwrap();
        let mut files = LogFiles::open(dir.path(), "bot", 10, day1).unwrap();
        files
            .write(&record(
                at("2026-11-24", "23:59:59.000"),
                "INFO",
                "x",
                "昨日",
            ))
            .unwrap();
        files
            .write(&record(
                at("2026-11-25", "00:00:01.000"),
                "INFO",
                "x",
                "今日",
            ))
            .unwrap();

        let current = fs::read_to_string(dir.path().join("bot.log")).unwrap();
        assert!(current.contains("今日") && !current.contains("昨日"));
        let mut yesterday = String::new();
        GzDecoder::new(File::open(dir.path().join("bot.log.2026-11-24.gz")).unwrap())
            .read_to_string(&mut yesterday)
            .unwrap();
        assert!(yesterday.contains("昨日"));
        assert!(
            dir.path().join("bot.jsonl.2026-11-24.gz").exists(),
            "JSONL だけ回っていない"
        );
        assert!(
            !dir.path().join("bot.log.2026-11-24").exists(),
            "畳んだあとの素のファイルが残った"
        );
    }

    /// 保管個数を超えた古いものから消え、新しいものは残ること。
    #[test]
    fn only_the_newest_packed_files_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        let mut file = RotatingFile::open(dir.path(), "bot.log", 3, start).unwrap();
        for offset in 0..6 {
            let day = start + chrono::Days::new(offset);
            file.write_line(&format!("day {offset}"), day).unwrap();
        }
        let mut packed: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".gz"))
            .collect();
        packed.sort();
        assert_eq!(
            packed,
            [
                "bot.log.2026-11-03.gz",
                "bot.log.2026-11-04.gz",
                "bot.log.2026-11-05.gz"
            ]
        );
    }

    /// 前の日のファイルが残ったまま起動したら、最初の 1 行で回すこと。
    ///
    /// 起動した日をファイルの日としてしまうと、前の日の分が今日のファイルに混ざる。
    #[test]
    fn a_file_left_from_an_earlier_day_is_rotated_on_the_first_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bot.log");
        fs::write(&path, "前の起動のとき\n").unwrap();
        let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 86_400);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(earlier)
            .unwrap();
        let earlier_day = DateTime::<Local>::from(earlier).date_naive();

        let today = Local::now().date_naive();
        let mut file = RotatingFile::open(dir.path(), "bot.log", 10, today).unwrap();
        file.write_line("今回", today).unwrap();

        let packed = dir
            .path()
            .join(format!("bot.log.{}.gz", earlier_day.format("%Y-%m-%d")));
        assert!(packed.exists(), "前の日のファイルが回っていない");
        assert_eq!(fs::read_to_string(&path).unwrap(), "今回\n");
    }

    /// 追加の項目の長い文字列は 512 文字で切ること（Python と同じ）。
    #[test]
    fn long_extra_values_are_cut_at_512_characters() {
        assert_eq!(truncated(&"あ".repeat(600)).chars().count(), 512);
    }
}
