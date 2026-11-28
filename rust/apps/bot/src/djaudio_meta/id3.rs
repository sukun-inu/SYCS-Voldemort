//! mutagen 1.48.1 で MP3 の ID3 タグを書き直すところ（`_write_tags` が使う `MP3(path, ID3=ID3)`・`add_tags`・
//! フレームの置き換え・`tags.save(path)`）の写し。書いたあとのファイルのバイト列が mutagen と同じになる。
//!
//! 写したもの（mutagen のどこか）:
//! - 読み込み（`ID3.load`）: ヘッダー（`ID3Header`）・拡張ヘッダー・非同期化・v2.4 のフレームの長さの読み方の
//!   判定（`determine_bpi`）・フレームの読み方（`read_frames`・`Frame._fromData`）・重なったフレームのまとめ方
//!   （`ID3Tags._add`）・ID3v1 からの取り込み（`find_id3v1`・`ParseID3v1`）・v2.4 への直し（`update_to_v24`）
//! - MPEG のフレームが見つかるか（`MPEGInfo`。見つからなければ mutagen は例外を出す）: [`mpeg`]
//! - 保存（`ID3.save`）: フレームの並べ方（`ID3Tags._write`）・詰め物の決め方（`PaddingInfo`）・ID3v1 の書き直し
//!   （`v1=1`: あれば書き直し、無ければ足さない。`MakeID3v1`）

pub(crate) mod frames;
mod mpeg;

use std::path::Path;

use serde_json::Value;

use frames::{
    Frame, Kind, ReadCtx, ReadError, Stamp, Val, WriteError, frame_def, frame_def_22, save_frame,
    tcon_genres, unsynch_decode,
};

use crate::djaudio_meta::pyint::py_int;
use crate::python_repr::python_str;

/// タグを書けなかった理由（Python では `_write_tags` の中の例外。`enrich_metadata` は False を返す）。
#[derive(Debug)]
pub struct TagError {
    /// 何が起きたか（ログに出す）。
    pub message: String,
    /// ファイルを書き換えたあとで起きたか（mutagen は v2 を書いてから ID3v1 を作るので、そこで落ちると
    /// v2 だけ書き換わったファイルが残る）。
    pub file_changed: bool,
}

impl TagError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            file_changed: false,
        }
    }
}

impl std::fmt::Display for TagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TagError {}

/// ID3 のフレームの入れ物（mutagen の `ID3Tags`。HashKey を鍵にした、入れた順の辞書）。
#[derive(Clone, Debug)]
pub(crate) struct Tags {
    entries: Vec<(String, Frame)>,
    /// 知らないフレーム（ヘッダーごとの生のバイト列）。
    unknown: Vec<Vec<u8>>,
    /// 知らないフレームを読んだときの版（同じ版で保存するときだけ書き戻す）。
    unknown_version: u8,
}

const ORDER: [&str; 7] = ["TIT2", "TPE1", "TRCK", "TALB", "TPOS", "TDRC", "TCON"];

impl Tags {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            unknown: Vec::new(),
            unknown_version: 4,
        }
    }

    fn index(&self, key: &str) -> Option<usize> {
        self.entries.iter().position(|(k, _)| k == key)
    }

    pub(crate) fn contains(&self, key: &str) -> bool {
        self.index(key).is_some()
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Frame> {
        self.index(key).map(|i| &self.entries[i].1)
    }

    /// `self[key] = frame`（あれば同じ場所で置き換え、無ければ最後に足す）。
    pub(crate) fn set(&mut self, key: String, frame: Frame) {
        match self.index(&key) {
            Some(i) => self.entries[i].1 = frame,
            None => self.entries.push((key, frame)),
        }
    }

    fn remove(&mut self, key: &str) -> Option<Frame> {
        self.index(key).map(|i| self.entries.remove(i).1)
    }

    /// `getall(key)`（鍵そのもの、無ければ `key:` で始まる鍵の全部）。
    fn getall_keys(&self, key: &str) -> Vec<String> {
        if self.contains(key) {
            return vec![key.to_string()];
        }
        let prefix = format!("{key}:");
        self.entries
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// `delall(key)`。
    pub(crate) fn delall(&mut self, key: &str) {
        for k in self.getall_keys(key) {
            self.remove(&k);
        }
    }

    /// `add(frame)`（`_add(frame, strict=True)`: 同じ鍵があれば置き換える）。
    pub(crate) fn add(&mut self, frame: Frame) {
        self.add_frame(frame, true);
    }

    /// `ID3Tags._add`。
    fn add_frame(&mut self, frame: Frame, strict: bool) {
        let Some(mut frame) = frame.upgrade() else {
            return;
        };
        let mut hash_key = frame.hash_key();
        if strict || !self.contains(&hash_key) {
            self.set(hash_key, frame);
            return;
        }
        loop {
            let i = self.index(&hash_key).expect("鍵はある");
            let old = &mut self.entries[i].1;
            match old.def.kind {
                Kind::Text | Kind::Stamp | Kind::Tcon | Kind::TextWithDesc => {
                    // TextFrame._merge_frame: 無い文だけ足し、そのときだけ符号化を大きい方にする。
                    merge_text(old, &frame);
                    return;
                }
                Kind::Apic => {
                    frame.salt.push(' ');
                    let new_hash = frame.hash_key();
                    if !self.contains(&new_hash) {
                        self.set(new_hash, frame);
                        return;
                    }
                    hash_key = new_hash;
                }
                Kind::Plain => {
                    self.entries[i].1 = frame;
                    return;
                }
            }
        }
    }

    /// `ID3Tags._read`（読んだフレームを足し、残り（詰め物）を返す）。
    pub(crate) fn read(&mut self, ctx: ReadCtx, data: &[u8]) -> Result<Vec<u8>, ReadError> {
        let (frames, unknown, rest) = read_frames(ctx, data)?;
        for frame in frames {
            self.add_frame(frame, false);
        }
        self.unknown = unknown;
        self.unknown_version = ctx.major;
        Ok(rest)
    }

    /// `ID3Tags._write`（v2.4。並べ方は「重要な順・中身の短い順（APIC は入れた順）・鍵の順」）。
    pub(crate) fn write(&self) -> Result<Vec<u8>, WriteError> {
        let mut items = Vec::with_capacity(self.entries.len());
        for (i, (_, frame)) in self.entries.iter().enumerate() {
            let data = save_frame(frame)?;
            let prio = match ORDER.iter().position(|id| *id == frame.id()) {
                Some(p) => p,
                None if frame.id() == "APIC" => ORDER.len() + 1,
                None => ORDER.len(),
            };
            let secondary = if frame.id() == "APIC" { i } else { data.len() };
            items.push((prio, secondary, frame.hash_key(), data));
        }
        items.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
        let mut out = Vec::new();
        for (_, _, _, data) in items {
            out.extend_from_slice(&data);
        }
        if self.unknown_version == 4 {
            for raw in &self.unknown {
                if raw.len() > 10 {
                    out.extend_from_slice(raw);
                }
            }
        }
        Ok(out)
    }

    /// `ID3Tags.update_to_v24`。
    pub(crate) fn update_to_v24(&mut self) {
        self.update_common();
        // TYER・TDAT・TIME を TDRC にまとめる。
        let mut take = |key: &str| -> Vec<String> {
            self.remove(key)
                .and_then(|f| f.texts().cloned())
                .unwrap_or_default()
        };
        let (tyer, tdat, time) = (take("TYER"), take("TDAT"), take("TIME"));
        let longest = tyer.len().max(tdat.len()).max(time.len());
        let mut timestamps = Vec::new();
        for i in 0..longest {
            let at = |v: &Vec<String>| v.get(i).cloned().unwrap_or_default();
            if let Some(ts) = v23_timestamp(&at(&tyer), &at(&tdat), &at(&time)) {
                timestamps.push(ts);
            }
        }
        if !timestamps.is_empty() && !self.contains("TDRC") {
            let stamps = timestamps.iter().map(|t| Stamp::parse(t)).collect();
            self.add(new_frame("TDRC", vec![Val::Int(0), Val::Stamps(stamps)]));
        }
        // TORY は TDOR の始めに。
        if let Some(f) = self.remove("TORY")
            && !self.contains("TDOR")
        {
            let text = f.text_str();
            let stamps = text.split(',').map(Stamp::parse).collect();
            self.add(new_frame("TDOR", vec![Val::Int(0), Val::Stamps(stamps)]));
        }
        // IPLS は TIPL に。
        if let Some(f) = self.remove("IPLS")
            && !self.contains("TIPL")
        {
            let people = match f.vals.get(1) {
                Some(Val::Pairs(p)) => p
                    .iter()
                    .map(|r| r.iter().take(2).cloned().collect())
                    .collect(),
                _ => Vec::new(),
            };
            self.add(new_frame(
                "TIPL",
                vec![Val::Int(f.encoding()), Val::Pairs(people)],
            ));
        }
        for key in ["RVAD", "EQUA", "TRDA", "TSIZ", "TDAT", "TIME"] {
            self.remove(key);
        }
        for id in ["CHAP", "CTOC"] {
            for key in self.getall_keys(id) {
                if let Some(i) = self.index(&key)
                    && let Some(sub) = self.entries[i].1.sub_frames_mut()
                {
                    sub.update_to_v24();
                }
            }
        }
    }

    /// v2.3・v2.4 への直しの共通部分（TCON のジャンルの読み直し・v2.2 の画像の MIME の直し）。
    fn update_common(&mut self) {
        if let Some(i) = self.index("TCON") {
            let genres = tcon_genres(self.entries[i].1.texts().map_or(&[][..], |t| t.as_slice()));
            if let Some(texts) = self.entries[i].1.texts_mut() {
                *texts = genres;
            }
        }
        let pics: Vec<Frame> = self
            .getall_keys("APIC")
            .iter()
            .filter_map(|k| self.get(k).cloned())
            .collect();
        for pic in pics {
            let mime = match pic.vals.get(1) {
                Some(Val::Text(m)) if m == "PNG" => "image/png",
                Some(Val::Text(m)) if m == "JPG" => "image/jpeg",
                _ => continue,
            };
            let mut vals = pic.vals.clone();
            vals[1] = Val::Text(mime.into());
            self.add(new_frame("APIC", vals));
        }
    }
}

/// TextFrame._merge_frame（old に other の文のうち無いものを足す）。
fn merge_text(old: &mut Frame, other: &Frame) {
    let other_encoding = other.encoding();
    let mut raise_encoding = false;
    match (other.texts(), other.stamps()) {
        (Some(texts), _) => {
            let texts = texts.clone();
            if let Some(mine) = old.texts_mut() {
                for t in texts {
                    if !mine.contains(&t) {
                        mine.push(t);
                        raise_encoding = true;
                    }
                }
            }
        }
        (None, Some(stamps)) => {
            let stamps = stamps.clone();
            if let Some(Val::Stamps(mine)) = old.vals.get_mut(1) {
                for s in stamps {
                    if !mine.iter().any(|m| m.text() == s.text()) {
                        mine.push(s);
                        raise_encoding = true;
                    }
                }
            }
        }
        _ => {}
    }
    if raise_encoding && other_encoding > old.encoding() {
        old.vals[0] = Val::Int(other_encoding);
    }
}

/// v2.3 の年・日付・時刻から TDRC の文（`update_to_v24` の 1 組ぶん）。
fn v23_timestamp(tyer: &str, tdat: &str, time: &str) -> Option<String> {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    // ([0-9]{4})(-[0-9]{2}-[0-9]{2})?\Z
    let ym = if digits(tyer, 4) {
        Some((tyer.to_string(), None))
    } else if tyer.len() == 10
        && digits(&tyer[..4], 4)
        && tyer.as_bytes()[4] == b'-'
        && digits(&tyer[5..7], 2)
        && tyer.as_bytes()[7] == b'-'
        && digits(&tyer[8..], 2)
    {
        Some((tyer[..4].to_string(), Some(tyer[4..].to_string())))
    } else {
        None
    };
    let (year, mut month_day) = ym?;
    let mut ts = year;
    if digits(tdat, 4) {
        month_day = Some(format!("-{}-{}", &tdat[2..], &tdat[..2]));
    }
    if let Some(md) = month_day {
        ts.push_str(&md);
        if digits(time, 4) {
            ts.push_str(&format!("T{}:{}:00", &time[..2], &time[2..]));
        }
    }
    Some(ts)
}

fn new_frame(name: &str, vals: Vec<Val>) -> Frame {
    Frame::new(frame_def(name).expect("定義のあるフレーム"), vals)
}

/// ASCII の名前が mutagen の `is_valid_frame_id`（`isalnum() and isupper()`）を満たすか。
fn is_valid_frame_id(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
        && name.bytes().any(|b| b.is_ascii_uppercase())
        && !name.bytes().any(|b| b.is_ascii_lowercase())
}

/// 同期安全な整数（7 ビットずつ）。mutagen の `BitPaddedInt(bytes)`。
fn bit_padded(data: &[u8]) -> u64 {
    data.iter()
        .fold(0u64, |acc, b| (acc << 7) | u64::from(b & 0x7F))
}

/// `BitPaddedInt(int)`（数として読んだ 4 バイトを、下の桁から 7 ビットずつに読み直す）。
fn bit_padded_int(value: u32) -> u64 {
    let mut value = value;
    let mut out = 0u64;
    let mut shift = 0;
    while value != 0 {
        out += u64::from(value & 0x7F) << shift;
        value >>= 8;
        shift += 7;
    }
    out
}

/// mutagen の `determine_bpi`（v2.4 のフレームの長さが同期安全な整数か、ただの整数か）。true なら同期安全。
fn determine_bpi(data: &[u8]) -> bool {
    let scan = |synchsafe: bool| -> (i64, i64) {
        let len = data.len() as i64;
        let mut o: i64 = 0;
        let mut count = 0;
        while o < len - 10 {
            let part = &data[o as usize..o as usize + 10];
            if part.iter().all(|b| *b == 0) {
                return (count, -((len - o) % 10));
            }
            let raw = u32::from_be_bytes([part[4], part[5], part[6], part[7]]);
            let size = if synchsafe {
                bit_padded_int(raw)
            } else {
                u64::from(raw)
            };
            o += 10 + size as i64;
            if let Ok(name) = std::str::from_utf8(&part[..4])
                && part[..4].is_ascii()
                && frame_def(name).is_some()
            {
                count += 1;
            }
        }
        (count, o - len)
    };
    let (asbpi, bpioff) = scan(true);
    let (asint, intoff) = scan(false);
    !(asint > asbpi || (asint == asbpi && (bpioff >= 1 && intoff <= 1)))
}

type ReadResult = (Vec<Frame>, Vec<Vec<u8>>, Vec<u8>);

/// mutagen の `read_frames`（読めないフレームは捨てるか生のまま取っておく）。
fn read_frames(ctx: ReadCtx, data: &[u8]) -> Result<ReadResult, ReadError> {
    let mut data: Vec<u8> = data.to_vec();
    let mut result = Vec::new();
    let mut unknown = Vec::new();
    if ctx.major < 4
        && ctx.unsynch
        && let Some(decoded) = unsynch_decode(&data)
    {
        data = decoded;
    }
    if ctx.major >= 3 {
        let synchsafe = ctx.major >= 4 && determine_bpi(&data);
        loop {
            if data.len() < 10 {
                break;
            }
            let header = data[..10].to_vec();
            if header[..4].iter().all(|b| *b == 0) {
                break;
            }
            let raw = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            let size = if synchsafe {
                bit_padded_int(raw)
            } else {
                u64::from(raw)
            } as usize;
            let flags = u16::from_be_bytes([header[8], header[9]]);
            let end = 10usize.saturating_add(size).min(data.len());
            let framedata = data[10.min(data.len())..end].to_vec();
            data.drain(..end);
            if size == 0 {
                continue;
            }
            if !header[..4].is_ascii() {
                continue;
            }
            let mut name: String = header[..4].iter().map(|b| char::from(*b)).collect();
            let mut def = None;
            if name.ends_with('\0') {
                // v2.2 の 3 文字の名前に NUL を足したもの（古い iTunes）。親のクラスの名前で引き直す。
                if let Some(d) = frame_def_22(&name[..3]) {
                    name = d.base.unwrap_or("").to_string();
                    def = frame_def(&name);
                }
            } else {
                def = frame_def(&name);
            }
            match def {
                None => {
                    if is_valid_frame_id(&name) {
                        unknown.push([header.as_slice(), &framedata].concat());
                    }
                }
                Some(def) => match Frame::from_data(def, ctx, flags, &framedata) {
                    Ok(Some(frame)) => result.push(frame),
                    Ok(None) => unknown.push([header.as_slice(), &framedata].concat()),
                    Err(ReadError::Junk) => {}
                    Err(ReadError::Fatal) => return Err(ReadError::Fatal),
                },
            }
        }
    } else {
        loop {
            if data.len() < 6 {
                break;
            }
            let header = data[..6].to_vec();
            let size = u32::from_be_bytes([0, header[3], header[4], header[5]]) as usize;
            if header[..3].iter().all(|b| *b == 0) {
                break;
            }
            let end = 6usize.saturating_add(size).min(data.len());
            let framedata = data[6.min(data.len())..end].to_vec();
            data.drain(..end);
            if size == 0 {
                continue;
            }
            if !header[..3].is_ascii() {
                continue;
            }
            let name: String = header[..3].iter().map(|b| char::from(*b)).collect();
            match frame_def_22(&name) {
                None => {
                    if is_valid_frame_id(&name) {
                        unknown.push([header.as_slice(), &framedata].concat());
                    }
                }
                Some(def) => match Frame::from_data(def, ctx, 0, &framedata) {
                    Ok(Some(frame)) => result.push(frame),
                    Ok(None) => unknown.push([header.as_slice(), &framedata].concat()),
                    Err(ReadError::Junk) => {}
                    Err(ReadError::Fatal) => return Err(ReadError::Fatal),
                },
            }
        }
    }
    Ok((result, unknown, data))
}

/// ID3v2 のヘッダー（`ID3Header`）。
struct Header {
    major: u8,
    flags: u8,
    /// タグ全体の大きさ（ヘッダーの 10 バイトを含む）。
    size: u64,
    /// 拡張ヘッダーがあれば、その中身の長さ。
    ext_len: Option<u64>,
}

enum HeaderError {
    /// ID3NoHeaderError。
    NoHeader,
    /// ID3UnsupportedVersionError。
    Unsupported,
    /// そのほか（mutagen.id3.error・IOError）。
    Broken(&'static str),
}

/// `ID3Header(fileobj)`（ファイルの先頭から）。
fn parse_header(file: &[u8]) -> Result<Header, HeaderError> {
    if file.len() < 10 {
        return Err(HeaderError::NoHeader);
    }
    let mut flags = file[5];
    let size = bit_padded(&file[6..10]) + 10;
    if &file[..3] != b"ID3" {
        return Err(HeaderError::NoHeader);
    }
    let major = file[3];
    if !(2..=4).contains(&major) {
        return Err(HeaderError::Unsupported);
    }
    if file[6..10].iter().any(|b| b & 0x80 != 0) {
        return Err(HeaderError::Broken("Header size not synchsafe"));
    }
    if (major >= 4 && flags & 0x0F != 0) || (major == 3 && flags & 0x1F != 0) {
        return Err(HeaderError::Broken("invalid flags"));
    }
    let mut ext_len = None;
    if flags & 0x40 != 0 {
        let Some(ext) = file.get(10..14) else {
            return Err(HeaderError::Broken("extended header truncated"));
        };
        let as_name = std::str::from_utf8(ext).ok().filter(|s| s.is_ascii());
        if as_name.is_some_and(|n| frame_def(n).is_some()) {
            flags ^= 0x40;
        } else {
            let extsize: i64 = if major >= 4 {
                if ext.iter().any(|b| b & 0x80 != 0) {
                    return Err(HeaderError::Broken("Extended header size not synchsafe"));
                }
                bit_padded(ext) as i64 - 4
            } else {
                i64::from(u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]))
            };
            if extsize < 0 {
                return Err(HeaderError::Broken("invalid extended header size"));
            }
            if (file.len() as u64) < 14 + extsize as u64 {
                return Err(HeaderError::Broken("extended header truncated"));
            }
            ext_len = Some(extsize as u64);
        }
    }
    Ok(Header {
        major,
        flags,
        size,
        ext_len,
    })
}

/// ID3v1 を探す（`find_id3v1`）。(見つけた位置（ファイルの終わりからの負の距離）, 中身) を返す。
fn find_id3v1(file: &[u8]) -> Option<(usize, &[u8])> {
    let start = file.len().saturating_sub(131);
    let data = &file[start..];
    let idx = data.windows(3).position(|w| w == b"TAG")?;
    if let Some(ape) = data.windows(8).position(|w| w == b"APETAGEX")
        && idx == ape + 3
    {
        return None;
    }
    let tag = &data[idx..];
    if tag.len() > 128 || tag.len() < 124 {
        return None;
    }
    Some((data.len() - idx, tag))
}

/// `ParseID3v1`（ID3v1 の欄を v2 のフレームにする）。v2_major は 3 か 4（年を TYER にするか TDRC にするか）。
fn parse_id3v1(tag: &[u8], v2_major: u8) -> Vec<Frame> {
    let year_len = tag.len() - 124;
    let field = |from: usize, len: usize| &tag[from..from + len];
    let (title, artist, album) = (field(3, 30), field(33, 30), field(63, 30));
    let year = field(93, year_len);
    let mut comment = field(93 + year_len, 30);
    let genre = tag[93 + year_len + 30];
    let mut track = 0u8;
    if comment[28] == 0 {
        track = comment[29];
        comment = &comment[..28];
    }
    let fix = |data: &[u8]| -> String {
        let first = data.split(|b| *b == 0).next().unwrap_or(&[]);
        let trimmed = trim_ascii_ws(first);
        trimmed.iter().map(|b| char::from(*b)).collect()
    };
    let (title, artist, album, year, comment) =
        (fix(title), fix(artist), fix(album), fix(year), fix(comment));
    let text = |name: &str, t: &str| {
        new_frame(
            name,
            vec![
                Val::Int(0),
                Val::Texts(t.split('\0').map(String::from).collect()),
            ],
        )
    };
    let mut frames = Vec::new();
    if !title.is_empty() {
        frames.push(text("TIT2", &title));
    }
    if !artist.is_empty() {
        frames.push(new_frame(
            "TPE1",
            vec![Val::Int(0), Val::Texts(vec![artist])],
        ));
    }
    if !album.is_empty() {
        frames.push(text("TALB", &album));
    }
    if !year.is_empty() {
        if v2_major == 3 {
            frames.push(text("TYER", &year));
        } else {
            let stamps = year.split(',').map(Stamp::parse).collect();
            frames.push(new_frame("TDRC", vec![Val::Int(0), Val::Stamps(stamps)]));
        }
    }
    if !comment.is_empty() {
        let texts = comment.split('\0').map(String::from).collect();
        frames.push(new_frame(
            "COMM",
            vec![
                Val::Int(0),
                Val::Text("eng".into()),
                Val::Text("ID3v1 Comment".into()),
                Val::Texts(texts),
            ],
        ));
    }
    if track != 0 {
        frames.push(text("TRCK", &track.to_string()));
    }
    if genre != 255 {
        frames.push(text("TCON", &genre.to_string()));
    }
    frames
}

/// bytes.strip()（ASCII の空白）。
fn trim_ascii_ws(data: &[u8]) -> &[u8] {
    let ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
    let start = data.iter().position(|b| !ws(b)).unwrap_or(data.len());
    let end = data.iter().rposition(|b| !ws(b)).map_or(start, |e| e + 1);
    &data[start..end.max(start)]
}

/// 読み込んだタグ（`MP3(path).tags`）。None は「タグが無い」（`add_tags` で空のタグを作る）。
struct Loaded {
    tags: Option<Tags>,
    /// MPEG を探し始める位置（`tags.size`）。
    offset: u64,
}

/// `ID3(fileobj)`（ID3FileType.load の中の、タグの読み込み）。
fn load_tags(file: &[u8]) -> Result<Loaded, TagError> {
    match parse_header(file) {
        Err(HeaderError::Broken(why)) => Err(TagError::new(why)),
        Err(kind @ (HeaderError::NoHeader | HeaderError::Unsupported)) => {
            // v2 が無い（か版が違う）ときは、ID3v1 だけを読む。
            let Some((_, tag)) = find_id3v1(file) else {
                return match kind {
                    HeaderError::NoHeader => Ok(Loaded {
                        tags: None,
                        offset: 0,
                    }),
                    _ => Err(TagError::new("ID3v2 version not supported")),
                };
            };
            let mut tags = Tags::new();
            for frame in parse_id3v1(tag, 4) {
                if tags.getall_keys(&frame.hash_key()).is_empty() {
                    tags.add(frame);
                }
            }
            tags.update_to_v24();
            Ok(Loaded {
                tags: Some(tags),
                offset: 0,
            })
        }
        Ok(header) => {
            let mut start = 10u64;
            let mut size = header.size as i64 - 10;
            if let Some(ext) = header.ext_len {
                start += 4 + ext;
                size -= 4 + ext as i64;
            }
            if size < 0 {
                return Err(TagError::new("size must not be negative"));
            }
            let end = start + size as u64;
            if (file.len() as u64) < end {
                return Err(TagError::new("tag data truncated"));
            }
            let data = &file[start as usize..end as usize];
            let ctx = ReadCtx {
                major: header.major,
                unsynch: header.flags & 0x80 != 0,
            };
            let mut tags = Tags::new();
            tags.read(ctx, data)
                .map_err(|_| TagError::new("frame parse error"))?;
            let v1_major = if header.major == 4 { 4 } else { 3 };
            if let Some((_, tag)) = find_id3v1(file) {
                for frame in parse_id3v1(tag, v1_major) {
                    if tags.getall_keys(&frame.hash_key()).is_empty() {
                        tags.add(frame);
                    }
                }
            }
            tags.update_to_v24();
            Ok(Loaded {
                tags: Some(tags),
                offset: header.size,
            })
        }
    }
}

/// `MakeID3v1`（v2.4 のフレームから ID3v1.1 の 128 バイト）。
fn make_id3v1(tags: &Tags) -> Result<Vec<u8>, TagError> {
    let first_text = |id: &str| -> Result<Vec<u8>, TagError> {
        let Some(frame) = tags.get(id) else {
            return Ok(Vec::new());
        };
        let text = frame
            .texts()
            .and_then(|t| t.first())
            .ok_or_else(|| TagError::new("IndexError"))?;
        let mut out: Vec<u8> = text
            .chars()
            .map(|c| if u32::from(c) <= 0xFF { c as u8 } else { b'?' })
            .collect();
        out.truncate(30);
        Ok(out)
    };
    let pad = |mut v: Vec<u8>, n: usize| {
        v.resize(n, 0);
        v
    };
    let title = pad(first_text("TIT2")?, 30);
    let artist = pad(first_text("TPE1")?, 30);
    let album = pad(first_text("TALB")?, 30);
    let mut comment = pad(first_text("COMM")?, 30);
    let mut track = Vec::new();
    if let Some(frame) = tags.get("TRCK") {
        let first = frame
            .texts()
            .and_then(|t| t.first())
            .ok_or_else(|| TagError::new("IndexError"))?;
        let number = py_int(first.split('/').next().unwrap_or(""))
            .and_then(|v| v.to_u64())
            .filter(|v| *v <= 255);
        if let Some(n) = number {
            comment.truncate(28);
            track = vec![0, n as u8];
        }
    }
    let mut genre = 0xFFu8;
    if let Some(frame) = tags.get("TCON") {
        let genres = tcon_genres(frame.texts().map_or(&[][..], |t| t.as_slice()));
        if let Some(g) = genres.first()
            && let Some(i) = frames::GENRES.iter().position(|x| x == g)
        {
            genre = i as u8;
        }
    }
    let year: Vec<u8> = match tags.get("TDRC").or_else(|| tags.get("TYER")) {
        Some(frame) => frame.text_str().into_bytes(),
        None => Vec::new(),
    };
    let mut year = [year.as_slice(), b"\x00\x00\x00\x00"].concat();
    year.truncate(4);
    let mut out = b"TAG".to_vec();
    for part in [&title, &artist, &album, &year, &comment, &track] {
        out.extend_from_slice(part);
    }
    out.push(genre);
    Ok(out)
}

/// 保存の失敗。`partial` があれば、mutagen が途中まで書いたファイルの中身（v2 だけ書き換わったもの）。
struct SaveError {
    error: TagError,
    partial: Option<Vec<u8>>,
}

/// `ID3.save(path)`（v2.4・v1=1・詰め物は既定）。新しいファイルの中身を返す。
fn save(tags: &Tags, file: &[u8]) -> Result<Vec<u8>, SaveError> {
    let fail = |error: TagError| SaveError {
        error,
        partial: None,
    };
    let old_size = match parse_header(file) {
        Ok(h) => h.size,
        Err(HeaderError::NoHeader) => 0,
        Err(HeaderError::Unsupported) => {
            return Err(fail(TagError::new("ID3v2 version not supported")));
        }
        Err(HeaderError::Broken(why)) => return Err(fail(TagError::new(why))),
    };
    // _prepare_data: フレームを並べ、詰め物を決める（既定: 足りなければ 1 KiB＋0.1%、多すぎれば減らす）。
    let framedata = tags
        .write()
        .map_err(|_| fail(TagError::new("frame write error")))?;
    let needed = framedata.len() as i64 + 10;
    let trailing = file.len() as i64;
    let available = old_size as i64 - needed;
    let high = 1024 * 10 + trailing / 100;
    let low = 1024 + trailing / 1000;
    let padding = if available >= 0 {
        if available > high { low } else { available }
    } else {
        low
    };
    let new_size = needed + padding;
    let body = (new_size - 10) as u64;
    if body >= 1 << 28 {
        return Err(fail(TagError::new("Value too wide")));
    }
    let mut out = Vec::with_capacity(new_size as usize + file.len());
    out.extend_from_slice(b"ID3\x04\x00\x00");
    for shift in [21, 14, 7, 0] {
        out.push(((body >> shift) & 0x7F) as u8);
    }
    out.extend_from_slice(&framedata);
    out.resize(new_size as usize, 0);
    out.extend_from_slice(&file[(old_size as usize).min(file.len())..]);
    // ID3v1（v1=1）: 見つかった所から 128 バイトを書く（短い古いタグなら、その分ファイルが伸びる）。無ければ足さない。
    if let Some((from_end, _)) = find_id3v1(&out) {
        let at = out.len() - from_end;
        match make_id3v1(tags) {
            Ok(v1) => {
                out.truncate(at);
                out.extend_from_slice(&v1);
            }
            Err(error) => {
                return Err(SaveError {
                    error,
                    partial: Some(out),
                });
            }
        }
    }
    Ok(out)
}

/// Deezer の値（JSON）を、mutagen の MultiSpec の検証（`TIT2(text=値)`）のとおりに文の並びにする。
fn text_values(value: &Value) -> Result<Vec<String>, TagError> {
    match value {
        Value::String(s) => Ok(s.split('\0').map(String::from).collect()),
        Value::Array(items) => Ok(items.iter().map(python_str).collect()),
        _ => Err(TagError::new("Invalid MultiSpec data")),
    }
}

/// `TDRC(text=値)`（`,` で分けて、それぞれ ID3TimeStamp。文字列でないものは ValueError）。
fn stamp_values(value: &Value) -> Result<Vec<Stamp>, TagError> {
    match value {
        Value::String(s) => Ok(s.split(',').map(Stamp::parse).collect()),
        Value::Array(items) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(Stamp::parse(s)),
                _ => Err(TagError::new("Invalid ID3TimeStamp")),
            })
            .collect(),
        _ => Err(TagError::new("Invalid MultiSpec data")),
    }
}

fn truthy(value: &Value) -> bool {
    crate::djaudio_meta::truthy(value)
}

/// `dict.get(key)`（辞書でなければ AttributeError）。
fn dict_get<'a>(value: &'a Value, key: &str) -> Result<&'a Value, TagError> {
    match value {
        Value::Object(map) => Ok(map.get(key).unwrap_or(&Value::Null)),
        _ => Err(TagError::new(format!(
            "'{}' object has no attribute 'get'",
            crate::djaudio_meta::type_name(value)
        ))),
    }
}

/// `x or {}` を辞書として使う（偽なら空の辞書と同じ）。
fn or_empty_get<'a>(value: &'a Value, key: &str) -> Result<&'a Value, TagError> {
    if truthy(value) {
        dict_get(value, key)
    } else {
        Ok(&Value::Null)
    }
}

/// Python の `_write_tags`: Deezer の結果（data）とカバー画像で、MP3 の ID3 タグを書き直す。
///
/// Err は Python ならここで例外が出る場合（`enrich_metadata` は False を返す）。`file_changed` が真なら、
/// mutagen と同じく v2 のタグだけ書き換えたファイルを残している。
pub fn write_tags(mp3: &Path, data: &Value, cover: Option<&[u8]>) -> Result<(), TagError> {
    let file = std::fs::read(mp3).map_err(|e| TagError::new(e.to_string()))?;
    let loaded = load_tags(&file)?;
    mpeg::check(&file, loaded.offset).map_err(|_| TagError::new("can't sync to MPEG frame"))?;
    let mut tags = loaded.tags.unwrap_or_else(Tags::new);

    let set_text = |tags: &mut Tags, id: &str, value: &Value| -> Result<(), TagError> {
        let texts = text_values(value)?;
        tags.set(
            id.to_string(),
            new_frame(id, vec![Val::Int(3), Val::Texts(texts)]),
        );
        Ok(())
    };
    let title = dict_get(data, "title")?;
    if truthy(title) {
        set_text(&mut tags, "TIT2", title)?;
    }
    let artist_name = or_empty_get(dict_get(data, "artist")?, "name")?;
    if truthy(artist_name) {
        set_text(&mut tags, "TPE1", artist_name)?;
    }
    let album_title = or_empty_get(dict_get(data, "album")?, "title")?;
    if truthy(album_title) {
        set_text(&mut tags, "TALB", album_title)?;
    }
    let release_date = dict_get(data, "release_date")?;
    if truthy(release_date) {
        let head = match release_date {
            Value::String(s) => Value::String(s.chars().take(4).collect()),
            Value::Array(items) => Value::Array(items.iter().take(4).cloned().collect()),
            _ => return Err(TagError::new("object is not subscriptable")),
        };
        let stamps = stamp_values(&head)?;
        tags.set(
            "TDRC".into(),
            new_frame("TDRC", vec![Val::Int(3), Val::Stamps(stamps)]),
        );
    }
    for (key, id) in [("track_position", "TRCK"), ("disk_number", "TPOS")] {
        let value = dict_get(data, key)?;
        if truthy(value) {
            set_text(&mut tags, id, &Value::String(python_str(value)))?;
        }
    }
    if let Some(cover) = cover.filter(|c| c.starts_with(b"\xff\xd8\xff")) {
        tags.delall("APIC");
        tags.add(new_frame(
            "APIC",
            vec![
                Val::Int(3),
                Val::Text("image/jpeg".into()),
                Val::Int(3),
                Val::Text("Cover".into()),
                Val::Bytes(cover.to_vec()),
            ],
        ));
    }
    match save(&tags, &file) {
        Ok(out) => std::fs::write(mp3, out).map_err(|e| TagError::new(e.to_string())),
        Err(SaveError {
            error,
            partial: Some(partial),
        }) => {
            // ID3v1 を作るところで落ちた。mutagen と同じく、v2 だけ書き換えたファイルを残す。
            std::fs::write(mp3, partial).map_err(|e| TagError::new(e.to_string()))?;
            Err(TagError {
                message: error.message,
                file_changed: true,
            })
        }
        Err(SaveError {
            error,
            partial: None,
        }) => Err(error),
    }
}
