//! セッションの秘密鍵の決め方。Python の `webapp_admin/core/config.py` の `resolve_session_secret` と同じ順・同じファイル。
//!
//! 1. `ADMIN_FLASK_SECRET_KEY`（前後の空白を落とし、空でなければ）
//! 2. `SETTINGS_DIR/.admin_session_secret`（前後の空白を落として 32 文字以上なら）
//! 3. 無ければ `token_hex(32)` を作り、そのファイルを O_EXCL（0600）で作って書く。先に誰かが作っていたら読み直す。
//!    書けなければ、その場限りの鍵（再起動でログインが切れる）
//!
//! **同じ秘密鍵なら、Python と Rust が同じ Cookie を読み書きできる**（切り替えても戻しても、ログインが切れない）。
//!
//! Python と同じところで気をつけること:
//!
//! - ファイルは UTF-8 で、改行は読むときに `\n` へそろう（`read_text` の universal newlines。`\r\n` と `\r`）。
//!   UTF-8 でないファイルは Python では起動が落ちる（`UnicodeDecodeError` は `OSError` ではないので拾われない）。
//!   Rust も起動しない（[`resolve`] が `Err`）
//! - 32 文字は Unicode の文字の数（バイトの数ではない）
//! - `SETTINGS_DIR` がファイルのときは、作る前の `mkdir` が「もうある」で失敗し、読み直しにも失敗して、その場限り

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::python;

/// 秘密鍵の環境変数。
pub const SECRET_ENV: &str = "ADMIN_FLASK_SECRET_KEY";
/// 秘密鍵のファイルの名前（`SETTINGS_DIR` の下）。
pub const SECRET_FILENAME: &str = ".admin_session_secret";
/// ファイルの鍵として使える最短の長さ（文字の数）。
pub const MIN_SECRET_LEN: usize = 32;

/// 鍵をどこから得たか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// 環境変数。
    Env,
    /// 前からあったファイル（作ろうとして、先に作られていたものを読み直したときも）。
    File,
    /// いま作って、ファイルに書いた。
    Generated,
    /// ファイルに書けなかったので、その場限り。
    Temporary,
}

/// 決めた鍵。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// 鍵。
    pub secret: String,
    /// どこから得たか。
    pub source: Source,
}

/// UTF-8 として読めないファイル（Python では起動が落ちる）。
#[derive(Debug)]
pub struct Unreadable {
    /// ファイル。
    pub path: PathBuf,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} が UTF-8 として読めません（Python の管理画面も起動しません）",
            self.path.display()
        )
    }
}

/// ファイルの鍵。Python の `_read_secret_file`（読めなければ・短ければ `None`）。
fn read_secret_file(path: &Path) -> Result<Option<String>, Unreadable> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Err(Unreadable {
            path: path.to_path_buf(),
        });
    };
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let content = python::strip(&text);
    Ok((content.chars().count() >= MIN_SECRET_LEN).then(|| content.to_string()))
}

/// 新しいファイルを O_EXCL で作って書く（0600）。
fn create_exclusive(path: &Path, secret: &str) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(secret.as_bytes())
}

/// 先に作られていたファイルを読み直す。読めなければその場限り。
fn reread_or_temporary(path: &Path, generated: String) -> Result<Resolved, Unreadable> {
    if let Some(existing) = read_secret_file(path)? {
        return Ok(Resolved {
            secret: existing,
            source: Source::File,
        });
    }
    warn!("セッションシークレットファイルを読み込めませんでした。一時キーを使用します。");
    Ok(Resolved {
        secret: generated,
        source: Source::Temporary,
    })
}

/// 鍵を決める。`env_value` は `ADMIN_FLASK_SECRET_KEY` の生の値、`settings_dir` は `SETTINGS_DIR`、`generate` は
/// 新しい鍵を作るもの（本番は `token_hex(32)`。Python と同じく、使うかどうかに関わらず先に 1 回だけ作る）。
pub fn resolve(
    env_value: Option<&str>,
    settings_dir: &Path,
    generate: impl FnOnce() -> String,
) -> Result<Resolved, Unreadable> {
    let from_env = python::strip(env_value.unwrap_or(""));
    if !from_env.is_empty() {
        return Ok(Resolved {
            secret: from_env.to_string(),
            source: Source::Env,
        });
    }
    let secret_file = settings_dir.join(SECRET_FILENAME);
    if let Some(existing) = read_secret_file(&secret_file)? {
        return Ok(Resolved {
            secret: existing,
            source: Source::File,
        });
    }
    let generated = generate();
    let created = fs::create_dir_all(settings_dir).and_then(|()| create_exclusive(&secret_file, &generated));
    match created {
        Ok(()) => {
            info!(
                "セッションシークレットを生成して保存しました: {}",
                secret_file.display()
            );
            Ok(Resolved {
                secret: generated,
                source: Source::Generated,
            })
        }
        // Python の `except FileExistsError`（mkdir が「もうある」で落ちたときも同じ枝に入る）。
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            reread_or_temporary(&secret_file, generated)
        }
        Err(e) => {
            warn!(
                "セッションシークレットの保存に失敗しました ({e})。{SECRET_ENV} を設定してください。\
                 設定しない場合、再起動やワーカー切り替えでセッションが失効します。"
            );
            Ok(Resolved {
                secret: generated,
                source: Source::Temporary,
            })
        }
    }
}

/// OS の乱数で `secrets.token_hex(nbytes)`（小文字の 16 進）。乱数が取れなければ止まる（Python も例外で落ちる）。
pub fn token_hex(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    if let Err(e) = getrandom::fill(&mut bytes) {
        panic!("OS の乱数を取れません: {e}");
    }
    hex_lower(&bytes)
}

/// バイトを小文字の 16 進に。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> String {
        "f".repeat(64)
    }

    /// 環境変数は前後の空白を落として使い、空白だけなら無いものとしてファイルへ進むこと。
    #[test]
    fn the_environment_wins_unless_blank() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve(Some("  env-secret  "), dir.path(), fixed).unwrap();
        assert_eq!(got.secret, "env-secret");
        assert_eq!(got.source, Source::Env);
        let got = resolve(Some("   "), dir.path(), fixed).unwrap();
        assert_eq!(got.source, Source::Generated);
    }

    /// 作った鍵をファイルに書き、次は同じものを読むこと（再起動してもログインが切れない）。
    #[test]
    fn a_generated_secret_is_kept_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = resolve(None, &dir.path().join("a/b"), fixed).unwrap();
        assert_eq!(first.source, Source::Generated);
        let second = resolve(None, &dir.path().join("a/b"), || "x".repeat(64)).unwrap();
        assert_eq!(second, Resolved { secret: fixed(), source: Source::File });
    }

    /// 短すぎるファイルは使わず、上書きもせず、その場限りの鍵になること。改行は \n にそろえてから数えること。
    #[test]
    fn a_short_file_gives_a_temporary_secret() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_FILENAME), "short").unwrap();
        let got = resolve(None, dir.path(), fixed).unwrap();
        assert_eq!(got.source, Source::Temporary);
        assert_eq!(std::fs::read(dir.path().join(SECRET_FILENAME)).unwrap(), b"short");
        std::fs::write(dir.path().join(SECRET_FILENAME), format!("{}\r\n{}", "a".repeat(20), "b".repeat(20))).unwrap();
        let got = resolve(None, dir.path(), fixed).unwrap();
        assert_eq!(got.secret, format!("{}\n{}", "a".repeat(20), "b".repeat(20)));
    }

    /// UTF-8 でないファイルでは起動しないこと（Python と同じ）。
    #[test]
    fn a_file_that_is_not_utf8_stops_the_start() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_FILENAME), b"\xff\xfe abc").unwrap();
        assert!(resolve(None, dir.path(), fixed).is_err());
    }

    /// 16 進は小文字で、バイトの 2 倍の長さであること。
    #[test]
    fn tokens_are_lower_hex() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0x0f]), "00ab0f");
        let token = token_hex(32);
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
