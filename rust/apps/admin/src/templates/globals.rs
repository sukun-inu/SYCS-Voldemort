//! テンプレートから呼ぶ関数。Python の `webapp_admin/templating.py` の `_admin_asset_url`・`_icon`・`_url_for`。
//!
//! - [`Assets::url`]（`admin_asset_url(path)`）: `/static/{path}?v={版}-{更新時刻 ns の 16 進}-{大きさの 16 進}`。
//!   static の外を指す・読めないときは `?v={版}` だけ。パスの解き方は Python の `Path.resolve()`
//!   （`os.path.realpath(strict=False)`）を写した [`python_realpath`]
//! - [`icon_markup`]（`icon(name, css_class="icon")`）: 同梱のスプライトを指す `<svg>`（印の付いた値で返す）
//! - [`url_for`]（`url_for(name, **kwargs)`）: 名前の表を引くだけ（経路は見ない）
//!
//! [`register`] がこの 3 つを minijinja の環境に足す。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use minijinja::value::{Kwargs, Value};
use minijinja::{Environment, Error, ErrorKind};

use super::markup::python_str;

/// `url_for` が引く表。Python の `_ROUTE_MAP`（テンプレートが引く名前だけ）。
pub const ROUTE_MAP: [(&str, &str); 14] = [
    ("landing", "/"),
    ("guide", "/guide"),
    ("privacy", "/privacy"),
    ("terms", "/terms"),
    ("login", "/admin/login"),
    ("oauth_start", "/admin/auth"),
    ("callback", "/admin/callback"),
    ("logout", "/admin/logout"),
    ("index", "/admin/"),
    ("admin_root", "/admin/"),
    ("guild_select", "/admin/guilds"),
    ("select_guild", "/admin/guilds/select"),
    ("overview", "/admin/overview"),
    ("static", "/static/{path}"),
];

/// `admin_asset_url` の版の既定（`ADMIN_ASSET_VERSION` が無いとき）。
pub const DEFAULT_ASSET_VERSION: &str = "admin";

fn route(name: &str) -> Option<&'static str> {
    ROUTE_MAP
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, path)| *path)
}

/// `url_for(name, **params)` の答え。Python の `_url_for`。
///
/// 点つきの名前（`auth.login`）は最後の部分で引き、無ければ点を `_` にした名前で引く。表に無い名前は `/{name}`
/// （書き間違いは実行時の誤りにならず、リンク切れとして現れる）。`params` は `{鍵}` を順に置き換える。
pub fn url_for(name: &str, params: &[(String, String)]) -> String {
    let found = if name.contains('.') {
        let short = name.rsplit('.').next().unwrap_or(name);
        route(short)
            .or_else(|| route(&name.replace('.', "_")))
            .or_else(|| route(name))
    } else {
        route(name)
    };
    let mut path = found.map_or_else(|| format!("/{name}"), str::to_string);
    for (key, value) in params {
        path = path.replace(&format!("{{{key}}}"), value);
    }
    path
}

/// アイコンの名前として通すか。Python の `re.match(r"^[a-z0-9-]+$", ident)`。
///
/// Python の `$` は、末尾の改行 1 つの前でも合う（`"book\n"` は通る）。それも写す。
fn is_icon_name(ident: &str) -> bool {
    let core = ident.strip_suffix('\n').unwrap_or(ident);
    !core.is_empty()
        && core
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `icon(name, css_class)` の HTML。Python の `_icon`（先頭の `bi-` を 1 回落とし、名前の形でなければ空）。
///
/// Python と同じく `css_class` は逃がさない（Python は `Markup` の f-string に埋めている。テンプレートは既定の
/// `icon` しか使っていない）。
pub fn icon_markup(name: &str, css_class: &str) -> String {
    let ident = name.strip_prefix("bi-").unwrap_or(name);
    if !is_icon_name(ident) {
        return String::new();
    }
    format!(
        "<svg class=\"{css_class}\" aria-hidden=\"true\" focusable=\"false\"><use href=\"/static/icons/sprite.svg#{ident}\"></use></svg>"
    )
}

/// `admin_asset_url` が見る置き場と版。
#[derive(Debug, Clone)]
pub struct Assets {
    root: PathBuf,
    version: String,
}

impl Assets {
    /// 置き場（`webapp_admin/static` と同じ中身）と版（`ADMIN_ASSET_VERSION`。無ければ [`DEFAULT_ASSET_VERSION`]）。
    ///
    /// Python の置き場は `Path(__file__).resolve().parent / "static"`（親までを解いて、最後の名前は解かない）。
    /// 同じく、親を解いてから最後の名前を足す（親が解けなければ渡されたまま）。
    pub fn new(static_dir: &Path, version: impl Into<String>) -> Assets {
        let root = match (static_dir.parent(), static_dir.file_name()) {
            (Some(parent), Some(name)) => {
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .unwrap_or_else(|_| static_dir.to_path_buf())
            }
            _ => static_dir.to_path_buf(),
        };
        Assets {
            root,
            version: version.into(),
        }
    }

    /// `admin_asset_url(filename)` の答え。Python の `_admin_asset_url`。
    pub fn url(&self, filename: &str) -> String {
        let version = self
            .versioned(filename)
            .unwrap_or_else(|| self.version.clone());
        format!("/static/{filename}?v={version}")
    }

    /// 置き場の中の読めるファイルなら `{版}-{更新時刻 ns の 16 進}-{大きさの 16 進}`。でなければ None。
    ///
    /// Python は `(_static_root / filename).resolve()` を `relative_to(_static_root)` で確かめてから `stat()` する。
    /// `filename` が `/` で始まれば置き場を足さない（pathlib の `/` と同じ）。NUL を含むと Python の `lstat` は
    /// ValueError を投げ、それも「読めない」に落ちる。
    fn versioned(&self, filename: &str) -> Option<String> {
        if filename.contains('\0') {
            return None;
        }
        let root = self.root.to_str()?;
        let joined = if filename.starts_with('/') {
            filename.to_string()
        } else {
            format!("{root}/{filename}")
        };
        let resolved = python_realpath(&joined);
        if !Path::new(&resolved).starts_with(&self.root) {
            return None;
        }
        let meta = std::fs::metadata(resolved).ok()?;
        let modified = meta.modified().ok()?;
        let mtime_ns = match modified.duration_since(UNIX_EPOCH) {
            Ok(after) => i128::try_from(after.as_nanos()).ok()?,
            Err(before) => -i128::try_from(before.duration().as_nanos()).ok()?,
        };
        let mtime = if mtime_ns < 0 {
            format!("-{:x}", mtime_ns.unsigned_abs())
        } else {
            format!("{mtime_ns:x}")
        };
        Some(format!("{}-{mtime}-{:x}", self.version, meta.len()))
    }
}

/// [`python_realpath`] の積み荷。Python の `rest` の 1 つ（名前か、「このリンクの先が解けた」の印）。
enum Part {
    Name(String),
    Resolved(String),
}

/// Python 3.13 の `os.path.realpath(filename, strict=False)`（`posixpath._realpath`）の写し。
///
/// `std::fs::canonicalize` とは違うところがある: 無い名前は、そこで止めずに字面のまま進む（`nope/../a` は `a`）。
/// ファイルの後ろの `..` も字面で戻る（`a.png/../b` は `b`）。読めないリンク・輪になったリンクは、そのリンクの
/// パスのまま進む。どれも Python の `Path.resolve()` と同じ答えにするため。
pub fn python_realpath(filename: &str) -> String {
    let mut rest: Vec<Part> = filename
        .split('/')
        .rev()
        .map(|name| Part::Name(name.to_string()))
        .collect();
    let mut part_count = rest.len();
    let mut path = if filename.starts_with('/') {
        "/".to_string()
    } else {
        std::env::current_dir()
            .ok()
            .and_then(|dir| dir.to_str().map(str::to_string))
            .unwrap_or_else(|| "/".to_string())
    };
    let mut seen: HashMap<String, Option<String>> = HashMap::new();
    while part_count > 0 {
        let Some(part) = rest.pop() else {
            break;
        };
        let name = match part {
            Part::Resolved(link) => {
                seen.insert(link, Some(path.clone()));
                continue;
            }
            Part::Name(name) => name,
        };
        part_count -= 1;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            path = match path.rfind('/') {
                Some(0) | None => "/".to_string(),
                Some(index) => path[..index].to_string(),
            };
            continue;
        }
        let newpath = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        // 読めない名前（無い・長すぎる）は、Python と同じく字面のまま進む（strict=False）。
        let is_link =
            std::fs::symlink_metadata(&newpath).is_ok_and(|meta| meta.file_type().is_symlink());
        if !is_link {
            path = newpath;
            continue;
        }
        if let Some(known) = seen.get(&newpath) {
            path = known.clone().unwrap_or(newpath);
            continue;
        }
        let Some(target) = std::fs::read_link(&newpath)
            .ok()
            .and_then(|target| target.to_str().map(str::to_string))
        else {
            path = newpath;
            continue;
        };
        if target.starts_with('/') {
            path = "/".to_string();
        }
        seen.insert(newpath.clone(), None);
        rest.push(Part::Resolved(newpath));
        let parts: Vec<&str> = target.split('/').collect();
        part_count += parts.len();
        for part in parts.into_iter().rev() {
            rest.push(Part::Name(part.to_string()));
        }
    }
    path
}

fn type_error(function: &str, value: &Value) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("{function}() には文字を渡すこと（{:?}）", value.kind()),
    )
}

/// `admin_asset_url`・`icon`・`url_for` を minijinja の環境に足す。
///
/// Python では `url_for` だけは `render()` が文脈に入れていた（starlette の同じ名前の関数を隠すため）。minijinja には
/// 隠すものが無いので、ほかの 2 つと同じく環境の関数にする（テンプレートから見た呼び方は同じ）。
pub fn register(env: &mut Environment<'static>, assets: Arc<Assets>) {
    env.add_function(
        "admin_asset_url",
        move |filename: Value| -> Result<Value, Error> {
            match filename.as_str() {
                Some(name) => Ok(Value::from(assets.url(name))),
                None => Err(type_error("admin_asset_url", &filename)),
            }
        },
    );
    env.add_function(
        "icon",
        |name: Value, css_class: Option<Value>, kwargs: Kwargs| -> Result<Value, Error> {
            let keyword: Option<Value> = kwargs.get("css_class")?;
            kwargs.assert_all_used()?;
            let css_class = match (css_class, keyword) {
                (Some(_), Some(_)) => {
                    return Err(Error::new(
                        ErrorKind::TooManyArguments,
                        "icon() の css_class が 2 回渡された",
                    ));
                }
                (Some(value), None) | (None, Some(value)) => python_str(&value),
                (None, None) => "icon".to_string(),
            };
            Ok(Value::from_safe_string(icon_markup(
                &python_str(&name),
                &css_class,
            )))
        },
    );
    env.add_function(
        "url_for",
        |name: Value, kwargs: Kwargs| -> Result<Value, Error> {
            let Some(text) = name.as_str() else {
                return Err(type_error("url_for", &name));
            };
            let mut params = Vec::new();
            for key in kwargs.args() {
                let value: Value = kwargs.get(key)?;
                params.push((key.to_string(), python_str(&value)));
            }
            kwargs.assert_all_used()?;
            Ok(Value::from(url_for(text, &params)))
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表の名前・点つきの名前・表に無い名前・置き換えが Python の `_url_for` と同じであること。
    #[test]
    fn url_for_is_a_table_lookup() {
        assert_eq!(url_for("auth.oauth_start", &[]), "/admin/auth");
        assert_eq!(url_for("dashboard.index", &[]), "/admin/");
        assert_eq!(url_for("guild.select", &[]), "/admin/guilds");
        assert_eq!(url_for("x.nope", &[]), "/x.nope");
        assert_eq!(url_for("", &[]), "/");
        assert_eq!(
            url_for("static", &[("path".to_string(), "css/a.css".to_string())]),
            "/static/css/a.css"
        );
    }

    /// 名前の形でなければ空、`bi-` は 1 回だけ落とし、末尾の改行 1 つは Python の `$` と同じく通すこと。
    #[test]
    fn icon_checks_the_name_like_python() {
        assert_eq!(
            icon_markup("bi-book", "icon"),
            "<svg class=\"icon\" aria-hidden=\"true\" focusable=\"false\"><use href=\"/static/icons/sprite.svg#book\"></use></svg>"
        );
        assert!(icon_markup("bi-bi-book", "icon").contains("#bi-book\""));
        assert_eq!(icon_markup("Book", "icon"), "");
        assert_eq!(icon_markup("bi-", "icon"), "");
        assert!(icon_markup("book\n", "icon").contains("#book\n\""));
        assert_eq!(icon_markup("book\n\n", "icon"), "");
    }

    /// 無い名前と、ファイルの後ろの `..` を、Python の realpath と同じく字面で進むこと。
    #[test]
    fn realpath_walks_missing_names_like_python() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let base = base.to_str().unwrap();
        std::fs::write(format!("{base}/a.png"), b"x").unwrap();
        assert_eq!(
            python_realpath(&format!("{base}/nope/../a.png")),
            format!("{base}/a.png")
        );
        assert_eq!(
            python_realpath(&format!("{base}/a.png/../b")),
            format!("{base}/b")
        );
        assert_eq!(python_realpath("/../.."), "/");
        assert_eq!(python_realpath("//x//y/."), "/x/y");
    }
}
