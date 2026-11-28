//! 配信するファイルの置き場。Python の `services/djaudio_cache.py`（Bot が使う分）。
//!
//! ファイルは `<置き場>/<token>.mp3`、その情報は `<置き場>/<token>.json`。配信するのは別のプロセス（いまは Python の
//! CDN。`cdn_main.py`）で、同じ置き場を読む。なので情報の JSON は、Python が書くのと**同じ文字**で書く
//! （鍵の並び・区切り・時刻の小数の書き方まで。`json.dump(meta, f, ensure_ascii=False)`）。書くときは一時ファイルに
//! 書いてから置き換える（読む側が書きかけを読まないように）。
//!
//! 期限を過ぎたものは、Bot が 60 秒ごとに消す（リンクを載せた Discord のメッセージも消す）。

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use tracing::{info, warn};

use crate::python_chars::{self, Class};
use crate::python_repr::python_str;
use crate::user_state::python_json;

/// 配信できる拡張子（Python の `_CONTENT_TYPES` の鍵。消すときもこの順に試す）。
pub const EXTENSIONS: [&str; 4] = [".mp3", ".zip", ".ogg", ".wav"];

/// 書きかけの一時ファイルを「落ちて残った」とみなすまでの秒数。
const TMP_ORPHAN_MAX_AGE_SECONDS: f64 = 300.0;

/// いまの時刻（UNIX 時間の秒。Python の `datetime.now(timezone.utc).timestamp()` と同じく、マイクロ秒の整数を
/// 1e6 で割った値）。
pub fn now_timestamp() -> f64 {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    micros as f64 / 1e6
}

/// ダウンロードのときのファイル名として安全な文字にする。Python の `_sanitize_filename`。
///
/// 区切りの `/`・`\` は空白に、Windows で使えない記号は落とし、空白を 1 つにまとめ、英数字（Python の `isalnum`）と
/// ` ._-()[]{}` だけを残して 120 文字に切る。空になったら `fallback`。
pub fn sanitize_filename(value: &str, fallback: &str) -> String {
    use crate::commands::server::python::strip;
    let value = strip(value).replace(['/', '\\'], " ");
    let value: String = value
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\'))
        .collect();
    let mut collapsed = String::new();
    let mut in_space = false;
    for c in value.chars() {
        if python_chars::is(Class::Space, c) {
            if !in_space {
                collapsed.push(' ');
            }
            in_space = true;
        } else {
            collapsed.push(c);
            in_space = false;
        }
    }
    // `isalnum()` は `\w` から `_` を除いたもの。`_` は残す記号に入っているので、`\w` をそのまま使える。
    let safe: String = strip(&collapsed)
        .chars()
        .filter(|c| python_chars::is(Class::Word, *c) || " ._-()[]{}".contains(*c))
        .collect();
    let safe: String = strip(&safe).chars().take(120).collect();
    if safe.is_empty() {
        fallback.to_string()
    } else {
        safe
    }
}

/// 新しい印（Python の `uuid.uuid4().hex`。32 桁の 16 進。版と変種の桁も uuid4 と同じ）。
pub fn new_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("乱数を作れませんでした: {e}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(bytes))
}

/// 置き場。
#[derive(Clone, Debug)]
pub struct Cache {
    dir: PathBuf,
}

/// 登録するファイルの情報。
pub struct Entry<'a> {
    /// できたファイル（置き場へ移す）。
    pub file: &'a Path,
    /// 元の URL。
    pub source_url: &'a str,
    /// 表示する題。
    pub title: &'a str,
    /// どのサーバーのものか（配信のときに URL と突き合わせる）。
    pub guild_id: u64,
    /// 有効期間（秒）。
    pub ttl: i128,
}

impl Cache {
    /// 置き場を決める（無ければ作る。Python は読み込んだときに `mkdir(parents=True, exist_ok=True)`）。
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!(
                "DJAudio のキャッシュの置き場を作れませんでした {}: {e}",
                dir.display()
            );
        }
        Self { dir }
    }

    /// 置き場の場所。
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn meta_path(&self, token: &str) -> PathBuf {
        self.dir.join(format!("{token}.json"))
    }

    /// ファイルを置き場へ移して登録し、印を返す。Python の `register_file`（`kind` は `djaudio`）。
    pub fn register(&self, entry: &Entry<'_>, token: &str) -> Result<(), String> {
        let name = entry
            .file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let suffix = match name.rfind('.') {
            Some(i) if i > 0 && i + 1 < name.len() => name[i..].to_lowercase(),
            _ => String::new(),
        };
        let extension = if suffix.is_empty() {
            ".mp3".to_string()
        } else {
            suffix
        };
        if !EXTENSIONS.contains(&extension.as_str()) {
            return Err(format!("配信できない拡張子です: {extension}"));
        }
        let dest = self.dir.join(format!("{token}{extension}"));
        move_file(entry.file, &dest)?;
        let size = std::fs::metadata(&dest)
            .map_err(|e| format!("移したファイルを読めませんでした: {e}"))?
            .len();
        let safe_title = sanitize_filename(entry.title, token);
        let expires_at = now_timestamp() + entry.ttl as f64;
        let meta = json!({
            "token": token,
            "guild_id": entry.guild_id.to_string(),
            "title": entry.title,
            "source_url": entry.source_url,
            "filename": format!("{safe_title}{extension}"),
            "extension": extension,
            "kind": "djaudio",
            "size_bytes": size,
            "expires_at": expires_at,
        });
        self.write_meta(token, &meta)?;
        info!(
            "キャッシュ登録: {token} guild={} ({safe_title}) TTL={}s",
            entry.guild_id, entry.ttl
        );
        Ok(())
    }

    /// 情報の JSON を一時ファイル経由で書く。Python の `_write_meta_atomic`。
    fn write_meta(&self, token: &str, meta: &Value) -> Result<(), String> {
        let path = self.meta_path(token);
        let tmp = self.dir.join(format!("{token}.json.tmp"));
        std::fs::write(&tmp, python_json(meta))
            .map_err(|e| format!("情報を書けませんでした: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("情報を置き換えられませんでした: {e}"))
    }

    /// 登録に、リンクを載せた Discord のメッセージを書き足す。Python の `update_discord_message`（失敗は警告だけ）。
    pub fn set_discord_message(&self, token: &str, channel_id: u64, message_id: u64) {
        let outcome = (|| -> Result<(), String> {
            let text = std::fs::read_to_string(self.meta_path(token)).map_err(|e| e.to_string())?;
            let mut meta: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let map = meta
                .as_object_mut()
                .ok_or_else(|| "情報が辞書でない".to_string())?;
            map.insert("discord_channel_id".into(), json!(channel_id.to_string()));
            map.insert("discord_message_id".into(), json!(message_id.to_string()));
            self.write_meta(token, &meta)
        })();
        if let Err(e) = outcome {
            warn!("Discord メッセージ情報の更新失敗 {token}: {e}");
        }
    }

    /// 期限を過ぎた登録（情報の辞書）を集める。Python の `_scan_expired`（名前の順に見る。読めないものは警告して飛ばす）。
    ///
    /// Python との違い: 情報が辞書でない・期限が数でないものは、Python では例外で掃除の巡回ごと止まる。Rust は
    /// 警告してそれだけ飛ばす（壊れた 1 件で期限切れが残り続けないように）。
    pub fn scan_expired(&self, now: f64) -> Vec<Map<String, Value>> {
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with(".json"))
            })
            .collect();
        paths.sort();
        let mut expired = Vec::new();
        for path in paths {
            let meta = match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
            {
                Ok(Value::Object(meta)) => meta,
                Ok(_) => {
                    warn!("掃除中にエラー {}: 情報が辞書でない", path.display());
                    continue;
                }
                Err(e) => {
                    warn!("掃除中にエラー {}: {e}", path.display());
                    continue;
                }
            };
            let expires_at = match meta.get("expires_at") {
                None => 0.0,
                Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::INFINITY),
                Some(Value::Bool(b)) => f64::from(u8::from(*b)),
                Some(_) => {
                    warn!("掃除中にエラー {}: 期限が数でない", path.display());
                    continue;
                }
            };
            if now > expires_at {
                if !meta.contains_key("token") {
                    warn!("掃除中にエラー {}: 'token'", path.display());
                    continue;
                }
                expired.push(meta);
            }
        }
        expired
    }

    /// 印のファイル（あり得る拡張子の全部と情報の JSON）を消す。Python の `_delete_entry`。
    pub fn delete_entry(&self, token: &str) {
        for suffix in EXTENSIONS.iter().copied().chain([".json"]) {
            let path = self.dir.join(format!("{token}{suffix}"));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("削除失敗 {}: {e}", path.display()),
            }
        }
        info!("キャッシュ削除: {token}");
    }

    /// 書きかけのまま残った `*.json.tmp`（5 分より古いもの）を消す。Python の `_cleanup_orphaned_tmp_files`。
    pub fn cleanup_orphaned_tmp(&self, now: f64) {
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut removed = 0;
        for path in dir.filter_map(Result::ok).map(|e| e.path()) {
            if !path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".json.tmp"))
            {
                continue;
            }
            let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
                continue;
            };
            let mtime = modified
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
            if now - mtime <= TMP_ORPHAN_MAX_AGE_SECONDS {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => removed += 1,
                Err(e) => warn!("一時ファイルの削除に失敗 {}: {e}", path.display()),
            }
        }
        if removed > 0 {
            info!("DJAudio 書き込み中に残った一時ファイル {removed} 件を削除");
        }
    }
}

/// 期限を過ぎた登録の、印（文字にしたもの）と、リンクを載せたメッセージ（両方が真のときだけ）。
pub fn token_and_message(meta: &Map<String, Value>) -> (String, Option<(String, String)>) {
    let token = meta.get("token").map(python_str).unwrap_or_default();
    let truthy = |key: &str| {
        meta.get(key)
            .filter(|v| crate::commands::settings::python_truthy(Some(v)))
            .map(python_str)
    };
    let message = match (truthy("discord_channel_id"), truthy("discord_message_id")) {
        (Some(c), Some(m)) => Some((c, m)),
        _ => None,
    };
    (token, message)
}

/// ファイルを移す（別のファイルシステムなら写してから消す）。Python の `shutil.move`。
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to).map_err(|e| format!("ファイルを移せませんでした: {e}"))?;
    std::fs::remove_file(from).map_err(|e| format!("元のファイルを消せませんでした: {e}"))
}

/// 掃除の間隔（60 秒。Python の `cache_cleanup_loop(bot=bot, interval=60)`）。
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    /// ファイル名は、使えない記号を落とし、空白を 1 つにまとめ、120 文字に切り、空なら代わりの名前にすること。
    #[test]
    fn filenames_are_sanitized_like_python() {
        assert_eq!(sanitize_filename(" a/b\\c:d*e  f ", "t"), "a b cde f");
        assert_eq!(
            sanitize_filename("曲名【公式】 (MV) [4K] {x} 😀", "t"),
            "曲名公式 (MV) [4K] {x}"
        );
        assert_eq!(sanitize_filename("???", "tok"), "tok");
        assert_eq!(
            sanitize_filename(&"あ".repeat(130), "t").chars().count(),
            120
        );
        assert_eq!(sanitize_filename("a_b-c.d", "t"), "a_b-c.d");
    }

    /// 印は uuid4 と同じ形（32 桁の 16 進、版の桁が 4、変種の桁が 8〜b）であること。
    #[test]
    fn tokens_look_like_uuid4() {
        let token = new_token().unwrap();
        assert_eq!(token.len(), 32);
        assert_eq!(&token[12..13], "4");
        assert!("89ab".contains(&token[16..17]));
        assert_ne!(token, new_token().unwrap());
    }

    /// 期限ちょうどの登録は、まだ消さないこと（Python の `now > expires_at`。過ぎてから消す）。
    #[test]
    fn expiry_is_strictly_after() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        std::fs::write(
            dir.path().join("t.json"),
            r#"{"token": "t", "expires_at": 1000.5}"#,
        )
        .unwrap();
        assert!(
            cache.scan_expired(1000.5).is_empty(),
            "期限ちょうどで消した"
        );
        assert_eq!(cache.scan_expired(1_000.500_001).len(), 1);
        assert!(cache.scan_expired(999.0).is_empty());
    }

    /// 登録すると、ファイルを移し、Python と同じ並びの情報を書き、メッセージを書き足せること。
    #[test]
    fn register_writes_python_shaped_meta() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().join("cache"));
        let src = dir.path().join("Song.MP3");
        std::fs::write(&src, b"abc").unwrap();
        let entry = Entry {
            file: &src,
            source_url: "https://youtu.be/x",
            title: "A/B",
            guild_id: 5,
            ttl: 600,
        };
        cache
            .register(&entry, "0123456789abcdef0123456789abcdef")
            .unwrap();
        let text =
            std::fs::read_to_string(cache.dir().join("0123456789abcdef0123456789abcdef.json"))
                .unwrap();
        assert!(text.starts_with(
            "{\"token\": \"0123456789abcdef0123456789abcdef\", \"guild_id\": \"5\", \"title\": \"A/B\", \
             \"source_url\": \"https://youtu.be/x\", \"filename\": \"A B.mp3\", \"extension\": \".mp3\", \
             \"kind\": \"djaudio\", \"size_bytes\": 3, \"expires_at\": "
        ), "{text}");
        cache.set_discord_message("0123456789abcdef0123456789abcdef", 7, 8);
        let text =
            std::fs::read_to_string(cache.dir().join("0123456789abcdef0123456789abcdef.json"))
                .unwrap();
        assert!(
            text.ends_with(", \"discord_channel_id\": \"7\", \"discord_message_id\": \"8\"}"),
            "{text}"
        );
        assert!(!src.exists());
    }
}
