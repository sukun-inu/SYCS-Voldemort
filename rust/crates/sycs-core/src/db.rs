//! データベースの接続先。Python の `services/user_state_db.py` と同じ順で組み立てる。
//!
//! Bot と管理画面が共有する `user_state_audit`（設定・Bot への依頼・利用者状態）へ
//! つなぐ。移行中は Python と Rust が同じデータベースを使うので、同じ環境変数から
//! 同じ接続先を組み立てないと、片方だけ別のデータベースを見て食い違う。
//!
//! 優先順:
//!   1. `USER_STATE_POSTGRES_DSN` があれば、そのまま使う（ドライバ名だけ落とす）
//!   2. 各要素を `USER_STATE_POSTGRES_*` → `POSTGRES_*` → 既定値の順に拾う
//!      パスワードは `*_PASSWORD` → `*_PASSWORD_FILE`（Docker secret）の順
//!
//! Python と違うところ: 空文字は「未設定」として扱う（envutil の規則）。Python の
//! user_state_db はユーザー名・ホスト・ポートを素の `os.getenv` で読むので、空文字の
//! ときに既定値へ倒れない。本番の compose はどれも値を入れているので、食い違わない。

use std::fs;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use tracing::warn;

use crate::env::Env;

/// URL の userinfo に入れるときに逃がす文字（RFC 3986 の userinfo で使えないもの）。
const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// `*_FILE` の環境変数が指すファイルからパスワードを読む。
///
/// パスが指定されているのに読めないのは設定の誤りなので、理由を警告に残す。
/// 黙って次の候補（最後は既定の "postgres"）へ倒れると、なぜつながらないのかが
/// 分からなくなる。
fn read_secret_file(path: Option<String>) -> Option<String> {
    let path = path?;
    match fs::read_to_string(&path) {
        Ok(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Err(e) => {
            warn!("シークレットファイルを読めませんでした {path}: {e}");
            None
        }
    }
}

/// `user_state_audit` への接続先（`postgresql://…`）。
pub fn user_state_url(env: &Env) -> String {
    if let Some(dsn) = env.raw("USER_STATE_POSTGRES_DSN") {
        return without_driver(&dsn);
    }
    let pick = |own: &str, shared: &str, default: &str| {
        env.raw(own)
            .or_else(|| env.raw(shared))
            .unwrap_or_else(|| default.to_string())
    };
    let user = pick("USER_STATE_POSTGRES_USER", "POSTGRES_USER", "postgres");
    let password = env
        .raw("USER_STATE_POSTGRES_PASSWORD")
        .or_else(|| read_secret_file(env.raw("USER_STATE_POSTGRES_PASSWORD_FILE")))
        .or_else(|| env.raw("POSTGRES_PASSWORD"))
        .or_else(|| read_secret_file(env.raw("POSTGRES_PASSWORD_FILE")))
        .unwrap_or_else(|| "postgres".to_string());
    let host = pick("USER_STATE_POSTGRES_HOST", "POSTGRES_HOST", "localhost");
    let port = pick("USER_STATE_POSTGRES_PORT", "POSTGRES_PORT", "5432");
    let db = env.string("USER_STATE_POSTGRES_DB", "user_state_audit");
    format!(
        "postgresql://{}:{}@{host}:{port}/{db}",
        utf8_percent_encode(&user, USERINFO),
        utf8_percent_encode(&password, USERINFO),
    )
}

/// `postgresql+asyncpg://…` のような SQLAlchemy のドライバ指定を落とす。
///
/// Python 側の DSN は SQLAlchemy の形で書かれていることがある。同じ値を Rust でも
/// 使えるように、スキームの `+ドライバ` だけを外す。
fn without_driver(dsn: &str) -> String {
    match dsn.split_once("://") {
        Some((scheme, rest)) => {
            let base = scheme.split('+').next().unwrap_or(scheme);
            format!("{base}://{rest}")
        }
        None => dsn.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    /// 本番の compose と同じ渡し方（共通の POSTGRES_* とパスワードファイル）で組み立てられること。
    #[test]
    fn the_production_compose_settings_build_the_shared_database_url() {
        let mut secret = tempfile::NamedTempFile::new().unwrap();
        writeln!(secret, "s3cretPassw0rd").unwrap();
        let e = env(&[
            ("POSTGRES_HOST", "postgres"),
            ("POSTGRES_PORT", "5432"),
            ("POSTGRES_USER", "metal_user"),
            ("POSTGRES_PASSWORD_FILE", secret.path().to_str().unwrap()),
            ("USER_STATE_POSTGRES_DB", "user_state_audit"),
        ]);
        assert_eq!(
            user_state_url(&e),
            "postgresql://metal_user:s3cretPassw0rd@postgres:5432/user_state_audit"
        );
    }

    /// 専用の USER_STATE_POSTGRES_* が共通の POSTGRES_* より優先されること。
    #[test]
    fn the_dedicated_settings_win_over_the_shared_ones() {
        let e = env(&[
            ("POSTGRES_HOST", "shared"),
            ("USER_STATE_POSTGRES_HOST", "dedicated"),
            ("POSTGRES_PASSWORD", "shared-pw"),
            ("USER_STATE_POSTGRES_PASSWORD", "dedicated-pw"),
        ]);
        assert_eq!(
            user_state_url(&e),
            "postgresql://postgres:dedicated-pw@dedicated:5432/user_state_audit"
        );
    }

    /// DSN が渡されたら、そのまま使い、SQLAlchemy のドライバ指定だけ落とすこと。
    #[test]
    fn a_dsn_is_used_as_is_without_the_sqlalchemy_driver() {
        let e = env(&[("USER_STATE_POSTGRES_DSN", "postgresql+asyncpg://u:p@h:1/d")]);
        assert_eq!(user_state_url(&e), "postgresql://u:p@h:1/d");
    }

    /// 記号を含むパスワードが URL を壊さないこと（@ や : がそのまま入ると別の意味になる）。
    #[test]
    fn symbols_in_the_password_are_escaped() {
        let e = env(&[("POSTGRES_PASSWORD", "a@b:c/d")]);
        assert_eq!(
            user_state_url(&e),
            "postgresql://postgres:a%40b%3Ac%2Fd@localhost:5432/user_state_audit"
        );
    }

    /// パスワードファイルが読めなければ次の候補へ進むこと（理由は警告に残す）。
    #[test]
    fn an_unreadable_password_file_falls_through_to_the_next_source() {
        // USER_STATE_POSTGRES_PASSWORD_FILE は POSTGRES_PASSWORD より先に見る候補。
        // それが読めないときに、黙って止まらず次の候補へ進むこと。
        let e = env(&[
            ("USER_STATE_POSTGRES_PASSWORD_FILE", "/does/not/exist"),
            ("POSTGRES_PASSWORD", "from-env"),
        ]);
        assert!(user_state_url(&e).contains(":from-env@"));
    }
}
