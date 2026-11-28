//! 配信するファイルの置き場を読む。Python の `services/djaudio_cache.py` のうち配信が使う分（`get_meta`・
//! `payload_path`・`content_type_for`・`_delete_entry`）。
//!
//! 置き場の形は Bot と同じ: ファイルは `<置き場>/<token><拡張子>`、その情報は `<置き場>/<token>.json`（書くのは Bot。
//! Rust の Bot は `sycs_bot::djaudio::cache`）。Bot の crate は serenity などを抱えていて配信からは使えないので、
//! 読む側の分をここに置く（拡張子の並びと型は Bot の `EXTENSIONS` と同じ）。
//!
//! 情報の JSON は、Python と同じ順で確かめる。
//!
//! 1. `<token>.json` が無い → 無い（期限切れとして断る）
//! 2. 読めない（ディレクトリなど）・UTF-8 でない → 例外（500。Python もここは拾っていない）
//! 3. JSON として壊れている → 警告を残して、無い
//! 4. 本体のファイルが無い → 無い（拡張子は情報の `extension`。無い・空なら `.mp3`）
//! 5. 期限（`expires_at`。無ければ 0）を過ぎている → 本体と情報を消して、無い
//!
//! 情報が辞書でないとき（`[1]` など）や、期限が数でないとき（`"x"`・null）は、Python では例外になる（500）。
//! その形も [`Crash`] で同じに返す。

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::python::{truthy, type_name};

/// 配信できる拡張子と、その Content-Type。Python の `_CONTENT_TYPES`（消すときもこの順に試す）。
pub const EXTENSIONS: [(&str, &str); 4] = [
    (".mp3", "audio/mpeg"),
    (".zip", "application/zip"),
    (".ogg", "audio/ogg"),
    (".wav", "audio/wav"),
];

/// 拡張子の Content-Type。Python の `content_type_for`（小文字にして引く。知らないものは application/octet-stream）。
pub fn content_type_for(extension: &str) -> &'static str {
    let lowered = extension.to_lowercase();
    EXTENSIONS
        .iter()
        .find(|(known, _)| *known == lowered)
        .map_or("application/octet-stream", |(_, content_type)| *content_type)
}

/// 情報の `extension` から、本体の拡張子を決める。Python の `str(meta.get("extension") or ".mp3")` が
/// 配信できる拡張子（大文字小文字も含めてそのまま）なら、それ。
///
/// 偽の値（無い・null・空・0）は `.mp3`。文字でない真の値（数など）は `str()` しても拡張子にならないので、無い。
pub fn extension_of(value: Option<&Value>) -> Option<&'static str> {
    match value {
        Some(value) if truthy(value) => match value {
            Value::String(text) => EXTENSIONS
                .iter()
                .find(|(known, _)| *known == text.as_str())
                .map(|(known, _)| *known),
            _ => None,
        },
        _ => Some(".mp3"),
    }
}

/// Python で例外になったもの（拾われずに 500 になる）。`kind` は Python の例外の型の名前（数のラベルに使う）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crash {
    /// 例外の型の名前（`IsADirectoryError`・`UnicodeDecodeError`・`AttributeError` など）。
    pub kind: &'static str,
    /// 例外の文面（ログに出す）。
    pub message: String,
}

impl Crash {
    /// 作る。
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// ファイルを読めなかったときの例外（Python の `OSError` の下の型の名前に揃える）。
    pub fn from_io(error: &io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => "FileNotFoundError",
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::IsADirectory => "IsADirectoryError",
            io::ErrorKind::NotADirectory => "NotADirectoryError",
            _ => "OSError",
        };
        Self::new(kind, error.to_string())
    }

    /// 辞書でないものの属性を引いたときの例外（Python の `AttributeError`）。
    pub fn no_attribute(value: &Value, attribute: &str) -> Self {
        Self::new(
            "AttributeError",
            format!("'{}' object has no attribute '{attribute}'", type_name(value)),
        )
    }
}

/// 置き場。
#[derive(Clone, Debug)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// 置き場を決める（無ければ作る。Python は読み込んだときに `mkdir(parents=True, exist_ok=True)`）。
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!("DJAudio のキャッシュの置き場を作れませんでした {}: {e}", dir.display());
        }
        Self { dir }
    }

    /// 置き場の場所。
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 本体のファイル。Python の `payload_path`（拡張子は [`extension_of`]。ファイルが無ければ無い）。
    ///
    /// 情報が辞書でなく真の値（`[1]`・`"x"`・`5`）なら、Python では `.get` が無くて例外になる。偽の値（`[]`・`0`）は
    /// 空の辞書として読む（Python の `(meta or {})`）。
    pub fn payload_path(&self, token: &str, meta: &Value) -> Result<Option<PathBuf>, Crash> {
        let extension = match meta {
            Value::Object(map) => extension_of(map.get("extension")),
            other if !truthy(other) => extension_of(None),
            other => return Err(Crash::no_attribute(other, "get")),
        };
        Ok(extension.and_then(|extension| self.existing(token, extension)))
    }

    /// 情報が辞書のときの本体のファイルと拡張子（[`Cache::payload_path`] と同じ決め方。辞書なので例外にならない）。
    pub fn payload_of(
        &self,
        token: &str,
        meta: &Map<String, Value>,
    ) -> Option<(PathBuf, &'static str)> {
        let extension = extension_of(meta.get("extension"))?;
        self.existing(token, extension).map(|path| (path, extension))
    }

    /// `<token><拡張子>` があれば、その場所（Python の `path.exists()`。ディレクトリでも、あればある）。
    fn existing(&self, token: &str, extension: &str) -> Option<PathBuf> {
        let path = self.dir.join(format!("{token}{extension}"));
        path.exists().then_some(path)
    }

    /// 情報を返す。Python の `get_meta`（無い・壊れている・本体が無い・期限切れなら無い。期限切れは消す）。
    ///
    /// 戻るのは、期限内で本体のある辞書だけ。期限の比べ方は Python と同じく「今が期限より後なら切れている」
    /// （ちょうどのときは、まだ切れていない）。
    pub fn get_meta(&self, token: &str, now: f64) -> Result<Option<Map<String, Value>>, Crash> {
        let meta_path = self.dir.join(format!("{token}.json"));
        if !meta_path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&meta_path).map_err(|e| Crash::from_io(&e))?;
        let text = String::from_utf8(bytes)
            .map_err(|e| Crash::new("UnicodeDecodeError", e.to_string()))?;
        let meta: Value = match serde_json::from_str(&text) {
            Ok(meta) => meta,
            Err(e) => {
                // 書き込み途中を読んだ、または壊れて残った。利用者には期限切れとして返すが、理由は残す（Python と同じ）。
                let name = meta_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                warn!("キャッシュメタデータが壊れています {name}: {e}");
                return Ok(None);
            }
        };
        if self.payload_path(token, &meta)?.is_none() {
            return Ok(None);
        }
        let map = match meta {
            Value::Object(map) => map,
            // 偽の値（`[]`・`0`）で本体があるときは、ここで `.get` が無くて例外になる（Python と同じ）。
            other => return Err(Crash::no_attribute(&other, "get")),
        };
        let expires_at = match map.get("expires_at") {
            None => 0.0,
            Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::INFINITY),
            Some(Value::Bool(b)) => f64::from(u8::from(*b)),
            Some(other) => {
                return Err(Crash::new(
                    "TypeError",
                    format!(
                        "'>' not supported between instances of 'float' and '{}'",
                        type_name(other)
                    ),
                ));
            }
        };
        if now > expires_at {
            self.delete_entry(token);
            return Ok(None);
        }
        Ok(Some(map))
    }

    /// 本体（あり得る拡張子の全部）と情報を消す。Python の `_delete_entry`（無いものは黙って飛ばす）。
    pub fn delete_entry(&self, token: &str) {
        for suffix in EXTENSIONS.iter().map(|(extension, _)| *extension).chain([".json"]) {
            let path = self.dir.join(format!("{token}{suffix}"));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => warn!("削除失敗 {}: {e}", path.display()),
            }
        }
        info!("キャッシュ削除: {token}");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 拡張子の型が Python の表と同じで、知らないものは octet-stream になること。
    #[test]
    fn content_types_match_python() {
        assert_eq!(content_type_for(".mp3"), "audio/mpeg");
        assert_eq!(content_type_for(".ZIP"), "application/zip");
        assert_eq!(content_type_for(".flac"), "application/octet-stream");
    }

    /// 拡張子は、偽なら `.mp3`、配信できる文字ならそれ、ほかは無いこと（大文字は配信できる拡張子ではない）。
    #[test]
    fn the_extension_is_read_like_python() {
        assert_eq!(extension_of(None), Some(".mp3"));
        assert_eq!(extension_of(Some(&json!(""))), Some(".mp3"));
        assert_eq!(extension_of(Some(&json!(null))), Some(".mp3"));
        assert_eq!(extension_of(Some(&json!(".ogg"))), Some(".ogg"));
        assert_eq!(extension_of(Some(&json!(".MP3"))), None);
        assert_eq!(extension_of(Some(&json!(5))), None);
    }

    /// 期限ちょうどは返し、過ぎたら本体と情報を消すこと。
    #[test]
    fn expired_entries_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        std::fs::write(dir.path().join("t.json"), r#"{"expires_at": 100.5}"#).unwrap();
        std::fs::write(dir.path().join("t.mp3"), b"x").unwrap();
        assert!(cache.get_meta("t", 100.5).unwrap().is_some());
        assert!(cache.get_meta("t", 100.6).unwrap().is_none());
        assert!(!dir.path().join("t.json").exists());
        assert!(!dir.path().join("t.mp3").exists());
    }
}
