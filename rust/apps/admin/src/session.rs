//! セッションの Cookie（`admin_session`）。starlette の `SessionMiddleware` と itsdangerous 2.2.0 の
//! `TimestampSigner` の写し。**Python と Rust で同じ Cookie を読み書きできる**（切り替えても戻しても、ログインが
//! 切れない）。基準 `tests/fixtures/session/` で、作った Cookie の文字と、読んだ中身を突き合わせる。
//!
//! 値 = `base64(json.dumps(session))` ＋ `.` ＋ 時刻 ＋ `.` ＋ 署名
//!
//! - `json.dumps` は既定の書き方（[`python::DEFAULT`]）。base64 は標準の字で `=` の詰め物あり
//! - 時刻は秒の整数を、前の 0 を落とした big-endian のバイト列にして、URL 用の base64（`-_`）で `=` を落としたもの
//! - 署名は HMAC-SHA1。鍵は `SHA1(b"itsdangerous.Signer" + b"signer" + 秘密鍵)`（django-concat）、対象は
//!   「値 ＋ `.` ＋ 時刻」。URL 用の base64 で `=` を落とす
//!
//! 読むとき（`TimestampSigner.unsign`）: 署名が合わない・時刻が読めない・期限（3600 秒）を過ぎた・未来の時刻 →
//! 空のセッション。期限ちょうど（3600 秒前）はまだ読める。署名が合うのに中身が base64 や JSON として読めないもの
//! （秘密鍵を知っている人しか作れない）は、Python ではセッションの層の外の `ServerErrorMiddleware` まで例外が
//! 抜けて素の 500 になる（[`Broken`]）。
//!
//! 書くとき（starlette 1.x の `Session`）: **触ったら** `Vary: Cookie`、**書き換えて空でなければ** `Set-Cookie`、
//! 読んだときは空でなかったのに書き換えて空になったら、消す Cookie。読んだだけでは書き直さない（期限は延びない。
//! 基準 `users_state` の `list_with_minimal_session` で確かめた）。
//!
//! Python と違うところ（どれも秘密鍵を知っている人が作った Cookie にしか出てこない）: 中身の JSON の `NaN`・
//! `Infinity`・64 ビットを超える整数・単独のサロゲートは読めず、[`Broken`]（Python は読む）。中身が辞書でなく
//! 組の並びのときは、鍵が文字のものだけ読む。

use std::sync::{Arc, Mutex, PoisonError};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};

use crate::python;

/// Cookie の名前（`_register_middleware` の `session_cookie`）。
pub const COOKIE_NAME: &str = "admin_session";
/// 期限（秒）。`max_age=3600`。
pub const MAX_AGE: i64 = 3600;
/// itsdangerous が時刻を日時にできる上限（Python の `datetime` は 9999 年まで）。署名が合って期限の外のとき、これ以上の
/// 時刻は日時にできずに例外になる（`SignatureExpired` を作る前に落ちる）。
pub const DATETIME_LIMIT: u64 = 253_402_300_800;

type HmacSha1 = Hmac<Sha1>;

/// itsdangerous の `TimestampSigner`（既定の塩・SHA1・django-concat）。
#[derive(Clone)]
pub struct Signer {
    key: Vec<u8>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer(…)")
    }
}

/// [`Signer::unsign`] の答え。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unsigned {
    /// 署名が合い、期限の中。中身（base64 のまま）。
    Value(Vec<u8>),
    /// 読めない（Python の `BadSignature`。空のセッションになる）。
    Bad,
    /// Python では `BadSignature` でない例外になる（素の 500）。
    Broken,
}

impl Signer {
    /// 秘密鍵から作る（UTF-8 のバイトを使う）。
    pub fn new(secret: &str) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(b"itsdangerous.Signer");
        hasher.update(b"signer");
        hasher.update(secret.as_bytes());
        Self {
            key: hasher.finalize().to_vec(),
        }
    }

    fn mac(&self, value: &[u8]) -> Vec<u8> {
        let Ok(mut mac) = HmacSha1::new_from_slice(&self.key) else {
            return Vec::new();
        };
        mac.update(value);
        mac.finalize().into_bytes().to_vec()
    }

    /// 署名する（`TimestampSigner.sign`。時刻は `timestamp`）。
    pub fn sign(&self, value: &[u8], timestamp: u64) -> Vec<u8> {
        let mut signed = value.to_vec();
        signed.push(b'.');
        signed.extend_from_slice(python::b64encode(&int_to_bytes(timestamp), true, false).as_bytes());
        let signature = python::b64encode(&self.mac(&signed), true, false);
        signed.push(b'.');
        signed.extend_from_slice(signature.as_bytes());
        signed
    }

    /// 署名を確かめる（`TimestampSigner.unsign(signed, max_age)`。いまは `now`）。
    pub fn unsign(&self, signed: &[u8], now: i64, max_age: i64) -> Unsigned {
        let Some(dot) = signed.iter().rposition(|b| *b == b'.') else {
            return Unsigned::Bad;
        };
        let (value, signature) = (&signed[..dot], &signed[dot + 1..]);
        let signature_ok = python::itsdangerous_b64decode(signature)
            .is_some_and(|got| constant_time_eq(&got, &self.mac(value)));
        // 署名が合わなくても、時刻を取り出すところまでは進む（どちらにしても読めない）。
        let Some(dot) = value.iter().rposition(|b| *b == b'.') else {
            return Unsigned::Bad;
        };
        let (payload, stamp) = (&value[..dot], &value[dot + 1..]);
        if !signature_ok {
            return Unsigned::Bad;
        }
        let Some(timestamp) = python::itsdangerous_b64decode(stamp).and_then(|b| bytes_to_int(&b))
        else {
            return Unsigned::Bad;
        };
        let age = i128::from(now) - i128::from(timestamp);
        if age > i128::from(max_age) || age < 0 {
            if timestamp >= DATETIME_LIMIT {
                return Unsigned::Broken;
            }
            return Unsigned::Bad;
        }
        Unsigned::Value(payload.to_vec())
    }
}

/// itsdangerous の `int_to_bytes`（8 バイトの big-endian から前の 0 を落とす。0 は空）。
pub fn int_to_bytes(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// itsdangerous の `bytes_to_int`（8 バイトより長ければ読めない）。
pub fn bytes_to_int(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    Some(u64::from_be_bytes(padded))
}

/// `hmac.compare_digest`（長さが違えば偽。中身は時間の揺れない比べ方）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Python ではセッションの層の外へ例外が抜ける（素の 500）Cookie。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Broken;

/// 1 つの要求のセッション（starlette 1.x の `Session`。中身は入れた順）。
///
/// 触った（`accessed`）・書き換えた（`modified`）の印は Python と同じ操作で立つ。読むだけ（`get`）では立たない
/// （Python では `request.session` を引いた時点で触った印が立つが、管理画面はどの要求でも見張りの層が引くので、
/// その層で [`Session::mark_accessed`] を呼ぶ）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Session {
    data: Map<String, Value>,
    accessed: bool,
    modified: bool,
    loaded: bool,
}

impl Session {
    /// Cookie が無い・読めないときの空のセッション。
    pub fn new() -> Self {
        Self::default()
    }

    /// Cookie から読んだセッション（空でも「読んだ」扱い。空にしても消す Cookie は出さない、の判定に使う）。
    pub fn loaded(data: Map<String, Value>) -> Self {
        Self {
            data,
            loaded: true,
            ..Self::default()
        }
    }

    /// 中身。
    pub fn data(&self) -> &Map<String, Value> {
        &self.data
    }

    /// 値（印は立たない）。
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.data.get(key)
    }

    /// 鍵があるか（`key in session`）。
    pub fn contains_key(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// `session[key] = value`（あった鍵は同じ位置のまま値だけ替わる）。
    pub fn insert(&mut self, key: &str, value: Value) {
        self.mark_modified();
        self.data.insert(key.to_string(), value);
    }

    /// `session.pop(key, None)`（あった鍵を取り出したときだけ書き換えた印）。
    pub fn pop(&mut self, key: &str) -> Option<Value> {
        let value = self.data.shift_remove(key);
        self.modified |= value.is_some();
        value
    }

    /// `del session[key]`（無い鍵でも書き換えた印は立つ。Python は印を立ててから `KeyError`）。
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.mark_modified();
        self.data.shift_remove(key)
    }

    /// `session.clear()`。
    pub fn clear(&mut self) {
        self.mark_modified();
        self.data.clear();
    }

    /// `session.update(items)`（空でも書き換えた印）。
    pub fn update(&mut self, items: Map<String, Value>) {
        self.mark_modified();
        for (key, value) in items {
            self.data.insert(key, value);
        }
    }

    /// `session.setdefault(key, default)`（無い鍵だけ書き換えた印）。
    pub fn set_default(&mut self, key: &str, default: Value) -> &mut Value {
        if !self.data.contains_key(key) {
            self.mark_modified();
        }
        self.data.entry(key.to_string()).or_insert(default)
    }

    /// 中の値をその場で変える（Python で `session["x"].append(…)` のように中を変えたとき。印は立たない）。
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.data.get_mut(key)
    }

    /// 触った印（`request.session` を引いた）。
    pub fn mark_accessed(&mut self) {
        self.accessed = true;
    }

    fn mark_modified(&mut self) {
        self.accessed = true;
        self.modified = true;
    }

    /// 触ったか。
    pub fn accessed(&self) -> bool {
        self.accessed
    }

    /// 書き換えたか。
    pub fn modified(&self) -> bool {
        self.modified
    }

    /// Cookie から読んだか（`initial_session_was_empty` の逆）。
    pub fn was_loaded(&self) -> bool {
        self.loaded
    }
}

/// 経路の係と層が同じセッションを見るための入れ物。
#[derive(Clone, Debug, Default)]
pub struct SessionHandle(Arc<Mutex<Session>>);

impl SessionHandle {
    /// 包む。
    pub fn new(session: Session) -> Self {
        Self(Arc::new(Mutex::new(session)))
    }

    /// 中で `f` を回す（待つ処理をまたいで持たないこと）。
    pub fn with<R>(&self, f: impl FnOnce(&mut Session) -> R) -> R {
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    /// いまの写し。
    pub fn snapshot(&self) -> Session {
        self.with(|session| session.clone())
    }
}

/// Cookie の読み書き（秘密鍵と `https_only`）。
#[derive(Clone, Debug)]
pub struct Cookies {
    signer: Signer,
    secure: bool,
}

impl Cookies {
    /// 作る。`secure` は `FLASK_SECURE_COOKIES`（真なら `; secure` を付ける）。
    pub fn new(secret: &str, secure: bool) -> Self {
        Self {
            signer: Signer::new(secret),
            secure,
        }
    }

    /// 署名する道具。
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// 要求の Cookie からセッションを読む（`SessionMiddleware.__call__` の前半。いまは `now` 秒）。
    pub fn load(&self, headers: &HeaderMap, now: i64) -> Result<Session, Broken> {
        let Some(raw) = python::cookie_value(headers, COOKIE_NAME) else {
            return Ok(Session::new());
        };
        // starlette は Cookie の文字（latin-1 で読んだもの）を UTF-8 にしてから確かめる。
        match self.signer.unsign(raw.as_bytes(), now, MAX_AGE) {
            Unsigned::Bad => Ok(Session::new()),
            Unsigned::Broken => Err(Broken),
            Unsigned::Value(payload) => decode_payload(&payload).map(Session::loaded),
        }
    }

    /// Cookie の値（`signer.sign(b64encode(json.dumps(session)))`）。
    pub fn encode(&self, session: &Session, now: i64) -> String {
        let json = python::dumps(&Value::Object(session.data().clone()), python::DEFAULT);
        let data = python::b64encode(json.as_bytes(), false, true);
        let timestamp = u64::try_from(now).unwrap_or(0);
        String::from_utf8_lossy(&self.signer.sign(data.as_bytes(), timestamp)).into_owned()
    }

    /// 帰りに付ける `Set-Cookie`（`send_wrapper`）。書き換えて空でなければ書き直し、読んだときは空でなかったのに
    /// 空になったら消す。どちらでもなければ `None`。
    pub fn set_cookie(&self, session: &Session, now: i64) -> Option<String> {
        if !session.modified() {
            return None;
        }
        let flags = if self.secure {
            "httponly; samesite=lax; secure"
        } else {
            "httponly; samesite=lax"
        };
        if !session.is_empty() {
            let value = self.encode(session, now);
            return Some(format!(
                "{COOKIE_NAME}={value}; path=/; Max-Age={MAX_AGE}; {flags}"
            ));
        }
        session.was_loaded().then(|| {
            format!("{COOKIE_NAME}=null; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; {flags}")
        })
    }
}

/// 署名の合った中身を読む。`Session(json.loads(b64decode(data)))`。
fn decode_payload(payload: &[u8]) -> Result<Map<String, Value>, Broken> {
    let bytes = python::b64decode(payload, false).ok_or(Broken)?;
    let text = json_text(&bytes).ok_or(Broken)?;
    let value: Value = serde_json::from_str(&text).map_err(|_| Broken)?;
    match value {
        Value::Object(map) => Ok(map),
        // dict() に並びや文字を渡したとき（2 つ組の並び・2 文字の文字）。
        Value::Array(items) => pairs_to_map(&items),
        Value::String(text) if text.is_empty() => Ok(Map::new()),
        _ => Err(Broken),
    }
}

fn pairs_to_map(items: &[Value]) -> Result<Map<String, Value>, Broken> {
    let mut map = Map::new();
    for item in items {
        match item {
            Value::Array(pair) if pair.len() == 2 => {
                let Value::String(key) = &pair[0] else {
                    return Err(Broken);
                };
                map.insert(key.clone(), pair[1].clone());
            }
            Value::String(text) if text.chars().count() == 2 => {
                let mut chars = text.chars();
                let (Some(key), Some(value)) = (chars.next(), chars.next()) else {
                    return Err(Broken);
                };
                map.insert(key.to_string(), Value::String(value.to_string()));
            }
            _ => return Err(Broken),
        }
    }
    Ok(map)
}

/// `json.loads(bytes)` の文字の読み方（`detect_encoding`。BOM と 0 のバイトの並びで UTF-8・16・32 を見分ける）。
fn json_text(bytes: &[u8]) -> Option<String> {
    let starts = |prefix: &[u8]| bytes.starts_with(prefix);
    if starts(&[0, 0, 0xfe, 0xff]) {
        return utf32(&bytes[4..], true);
    }
    if starts(&[0xff, 0xfe, 0, 0]) {
        return utf32(&bytes[4..], false);
    }
    if starts(&[0xfe, 0xff]) {
        return utf16(&bytes[2..], true);
    }
    if starts(&[0xff, 0xfe]) {
        return utf16(&bytes[2..], false);
    }
    if starts(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(bytes[3..].to_vec()).ok();
    }
    if bytes.len() >= 4 {
        if bytes[0] == 0 {
            return if bytes[1] != 0 {
                utf16(bytes, true)
            } else {
                utf32(bytes, true)
            };
        }
        if bytes[1] == 0 {
            return if bytes[2] != 0 || bytes[3] != 0 {
                utf16(bytes, false)
            } else {
                utf32(bytes, false)
            };
        }
    } else if bytes.len() == 2 {
        if bytes[0] == 0 {
            return utf16(bytes, true);
        }
        if bytes[1] == 0 {
            return utf16(bytes, false);
        }
    }
    String::from_utf8(bytes.to_vec()).ok()
}

fn utf16(bytes: &[u8], big_endian: bool) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units = bytes.chunks(2).map(|pair| {
        if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(units).collect::<Result<String, _>>().ok()
}

fn utf32(bytes: &[u8], big_endian: bool) -> Option<String> {
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    bytes
        .chunks(4)
        .map(|quad| {
            let raw = [quad[0], quad[1], quad[2], quad[3]];
            let code = if big_endian {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            };
            char::from_u32(code)
        })
        .collect()
}

/// Cookie に書く前にセッションを削る。Python の `_sanitize_session_payload`（`admin_guilds` があれば
/// [`compact_admin_guilds`] で置き換える。置き換えると書き換えた印が立つので、`Set-Cookie` が出る）。
///
/// Python の後半（`json.dumps` できないものを文字にする）は Rust では起きない（中身はいつも JSON の値）。
pub fn sanitize(session: &mut Session) {
    if session.contains_key("admin_guilds") {
        let compact = compact_admin_guilds(session.get("admin_guilds"));
        session.insert("admin_guilds", compact);
    }
}

/// サーバーの一覧を `id`・`name`・`icon` だけにする。Python の `_compact_admin_guilds`。
///
/// 並びでなければ空。辞書でない要素と、`id` を `int()` で読めない要素は捨てる。`id` は `str(int(id))`、`name` は
/// 偽なら `"Unknown"`、それ以外は `str(name)`、`icon` は文字でなければ null。
pub fn compact_admin_guilds(value: Option<&Value>) -> Value {
    let Some(Value::Array(guilds)) = value else {
        return Value::Array(Vec::new());
    };
    let mut compact = Vec::new();
    for guild in guilds {
        let Value::Object(guild) = guild else {
            continue;
        };
        let Some(id) = python::int_text(guild.get("id").unwrap_or(&Value::Null)) else {
            continue;
        };
        let name = match guild.get("name") {
            Some(name) if python::truthy(name) => python::str_of(name),
            _ => "Unknown".to_string(),
        };
        let icon = match guild.get("icon") {
            Some(Value::String(icon)) => Value::String(icon.clone()),
            _ => Value::Null,
        };
        compact.push(python::object(vec![
            ("id", Value::String(id)),
            ("name", Value::String(name)),
            ("icon", icon),
        ]));
    }
    Value::Array(compact)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    const SECRET: &str = "w2-admin-fixture-secret-0123456789abcdef0123456789abcdef";
    const NOW: i64 = 1_798_761_600;

    fn headers(cookie: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.append("cookie", HeaderValue::from_str(cookie).unwrap());
        map
    }

    /// 基準 users_state の Cookie（Python が作ったもの）と、同じ中身・同じ時刻で同じ文字になること。
    #[test]
    fn cookies_match_the_python_ones() {
        let cookies = Cookies::new(SECRET, false);
        let session = Session::loaded(
            json!({"user": {"id": "1"}, "guild_id": 999})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert_eq!(
            cookies.encode(&session, NOW),
            "eyJ1c2VyIjogeyJpZCI6ICIxIn0sICJndWlsZF9pZCI6IDk5OX0=.azbsgA.Zh87TcwXM4f3iqQ-4KMqu3kvyUc"
        );
    }

    /// 期限ちょうどは読め、1 秒過ぎた・1 秒未来・署名の違うものは空になること。9999 年より先の時刻は壊れた扱い。
    #[test]
    fn the_age_is_checked_like_itsdangerous() {
        let cookies = Cookies::new(SECRET, false);
        let signer = cookies.signer();
        let data = python::b64encode(br#"{"a": 1}"#, false, true);
        for (signed_at, loaded) in [(NOW - MAX_AGE, true), (NOW - MAX_AGE - 1, false), (NOW + 1, false)] {
            let value = signer.sign(data.as_bytes(), u64::try_from(signed_at).unwrap());
            let cookie = format!("admin_session={}", String::from_utf8(value).unwrap());
            let session = cookies.load(&headers(&cookie), NOW).unwrap();
            assert_eq!(session.was_loaded(), loaded, "{signed_at}");
        }
        let far = signer.sign(data.as_bytes(), DATETIME_LIMIT);
        let cookie = format!("admin_session={}", String::from_utf8(far).unwrap());
        assert_eq!(cookies.load(&headers(&cookie), NOW), Err(Broken));
        let other = Cookies::new("another-secret", false);
        let value = other.signer().sign(data.as_bytes(), u64::try_from(NOW).unwrap());
        let cookie = format!("admin_session={}", String::from_utf8(value).unwrap());
        assert!(!cookies.load(&headers(&cookie), NOW).unwrap().was_loaded());
    }

    /// 署名の合う壊れた中身は Broken、空の辞書・空の並び・空の文字は「読んだ空のセッション」になること。
    #[test]
    fn signed_payloads_are_read_like_starlette() {
        let cookies = Cookies::new(SECRET, false);
        let load = |payload: &[u8]| {
            let value = cookies.signer().sign(payload, u64::try_from(NOW).unwrap());
            let cookie = format!("admin_session={}", String::from_utf8(value).unwrap());
            cookies.load(&headers(&cookie), NOW)
        };
        assert_eq!(load(b"!!!"), Err(Broken));
        assert_eq!(load(b"e30"), Err(Broken));
        assert_eq!(load(b"WzFd"), Err(Broken));
        for payload in ["e30=", "W10=", "IiI=", "77u/e30="].map(str::as_bytes) {
            let session = load(payload).unwrap();
            assert!(session.was_loaded() && session.is_empty());
        }
        let pairs = load(python::b64encode(br#"[["k", 1], "ab"]"#, false, true).as_bytes()).unwrap();
        assert_eq!(Value::Object(pairs.data().clone()), json!({"k": 1, "a": "b"}));
    }

    /// 読んだだけなら Set-Cookie を出さず、書き換えたら出し、空にしたら消す Cookie を出すこと（secure の印も）。
    #[test]
    fn set_cookie_follows_the_modified_mark() {
        let cookies = Cookies::new(SECRET, true);
        let mut session = Session::loaded(json!({"a": 1}).as_object().unwrap().clone());
        assert_eq!(cookies.set_cookie(&session, NOW), None);
        assert_eq!(session.pop("missing"), None);
        assert!(!session.modified());
        session.insert("b", json!(2));
        let written = cookies.set_cookie(&session, NOW).unwrap();
        assert!(written.ends_with("; path=/; Max-Age=3600; httponly; samesite=lax; secure"));
        session.clear();
        assert_eq!(
            cookies.set_cookie(&session, NOW).unwrap(),
            "admin_session=null; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly; samesite=lax; secure"
        );
        let mut fresh = Session::new();
        fresh.clear();
        assert_eq!(cookies.set_cookie(&fresh, NOW), None);
    }

    /// サーバーの一覧の削り方が Python と同じこと（壊れた要素を捨て、ID を整え、名前と icon を直す）。
    #[test]
    fn admin_guilds_are_compacted_like_python() {
        let raw = json!([
            {"id": "123", "name": "鯖", "icon": null, "permissions": "8"},
            {"id": 222, "name": null, "icon": 5},
            {"id": " 0042 ", "name": 0, "icon": "abc"},
            {"id": "x", "name": "壊れた"},
            {"name": "ID 無し"},
            "not-a-dict"
        ]);
        assert_eq!(
            compact_admin_guilds(Some(&raw)),
            json!([
                {"id": "123", "name": "鯖", "icon": null},
                {"id": "222", "name": "Unknown", "icon": null},
                {"id": "42", "name": "Unknown", "icon": "abc"}
            ])
        );
        assert_eq!(compact_admin_guilds(Some(&json!({"a": 1}))), json!([]));
        let mut session = Session::loaded(json!({"admin_guilds": null, "x": 1}).as_object().unwrap().clone());
        sanitize(&mut session);
        assert!(session.modified());
        assert_eq!(dumps_of(&session), r#"{"admin_guilds": [], "x": 1}"#);
    }

    fn dumps_of(session: &Session) -> String {
        python::dumps(&Value::Object(session.data().clone()), python::DEFAULT)
    }
}
