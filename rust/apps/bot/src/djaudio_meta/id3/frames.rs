//! mutagen 1.48.1 の ID3v2 のフレームの定義と、中身の読み書き（`mutagen/id3/_frames.py`・`_specs.py`）。
//!
//! mutagen はフレームの種類ごとに「中身の並び（spec の列）」を持ち、読むときも書くときもその列に従う。ここでも
//! 同じ列を表にして、spec ごとの読み方・書き方をそのまま写す（v2.4 で書く場合だけ。mutagen は既定で v2.4 で書く）。

use std::io::Write as _;

use super::Tags;
use crate::djaudio_meta::pyint::{PyInt, py_int};
use crate::djaudio_meta::text::is_space;

/// 中身の 1 項目の型（mutagen の Spec の子クラス）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Spec {
    /// ByteSpec・ChannelSpec・PictureTypeSpec・CTOCFlagsSpec（1 バイトの数）。
    Byte,
    /// EncodingSpec（文字の符号化。0〜3 以外は読めない）。
    Encoding,
    /// SizedIntegerSpec（決まった長さの数。ビッグエンディアン）。
    Sized(usize),
    /// IntegerSpec（残り全部を 1 つの数として読む）。
    Integer,
    /// StringSpec・FrameIDSpec（決まった長さの ASCII）。
    Fixed(usize),
    /// Latin1TextSpec（NUL で終わる Latin-1）。
    Latin1,
    /// EncodedTextSpec（フレームの符号化で、終わりの印まで）。
    Encoded,
    /// BinaryDataSpec（残り全部）。
    Binary,
    /// MultiSpec(EncodedTextSpec)（文の並び）。
    MultiText,
    /// MultiSpec(TimeStampSpec)（日時の並び）。
    MultiStamp,
    /// MultiSpec(EncodedTextSpec, EncodedTextSpec)（2 つ組の並び）。
    MultiPair,
    /// RVASpec（RVAD。読むだけで、v2.4 に直すときに消える）。
    Rva(bool),
    /// ID3FramesSpec（中に入れ子のフレーム）。
    Frames,
    /// Latin1TextListSpec（個数と Latin-1 の並び）。
    Latin1List,
    /// VolumeAdjustmentSpec。
    VolumeAdjustment,
    /// VolumePeakSpec。
    VolumePeak,
    /// SynchronizedTextSpec。
    SyncText,
    /// KeyEventSpec。
    KeyEvents,
    /// VolumeAdjustmentsSpec。
    VolumeAdjustments,
    /// ASPIIndexSpec。
    AspiIndex,
}

impl Spec {
    /// mutagen の `handle_nodata`（中身が残っていなくても読める）。
    fn handle_nodata(self) -> bool {
        matches!(self, Self::Binary | Self::Frames)
    }
}

/// mutagen の ID3TimeStamp（年・月・日・時・分・秒。読めなかった所から後ろは無い）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    parts: [Option<PyInt>; 6],
}

impl Stamp {
    /// `ID3TimeStamp(text)`（`set_text`: `[-T:/.]|\s+` で分けて、それぞれ `int()`）。
    pub(crate) fn parse(text: &str) -> Self {
        let mut pieces: Vec<String> = vec![String::new()];
        let full = format!("{text}:::::");
        let mut chars = full.chars().peekable();
        while let Some(c) = chars.next() {
            if matches!(c, '-' | 'T' | ':' | '/' | '.') {
                pieces.push(String::new());
            } else if is_space(c) {
                while chars.peek().is_some_and(|n| is_space(*n)) {
                    chars.next();
                }
                pieces.push(String::new());
            } else if let Some(last) = pieces.last_mut() {
                last.push(c);
            }
        }
        let mut parts: [Option<PyInt>; 6] = Default::default();
        for (slot, piece) in parts.iter_mut().zip(pieces.iter()) {
            *slot = py_int(piece);
        }
        Self { parts }
    }

    /// `ID3TimeStamp.text`（`get_text`）。
    pub(crate) fn text(&self) -> String {
        const SEPS: [char; 6] = ['-', '-', ' ', ':', ':', 'x'];
        let mut out = String::new();
        for (i, part) in self.parts.iter().enumerate() {
            let Some(v) = part else { break };
            out.push_str(&v.zero_pad(if i == 0 { 4 } else { 2 }));
            out.push(SEPS[i]);
        }
        out.pop();
        out
    }
}

/// 項目の値。
#[derive(Clone, Debug)]
pub(crate) enum Val {
    /// 小さな数（バイト・符号化・決まった長さの数）。
    Int(u64),
    /// IntegerSpec の数（ビッグエンディアン、先頭の 0 を除く）。
    Big(Vec<u8>),
    /// 文。
    Text(String),
    /// バイト列。
    Bytes(Vec<u8>),
    /// 文の並び。
    Texts(Vec<String>),
    /// 日時の並び。
    Stamps(Vec<Stamp>),
    /// 2 つ組の並び（読んだものは 2 つずつ。足りなければ短い）。
    Pairs(Vec<Vec<String>>),
    /// Latin-1 の並び。
    Strings(Vec<String>),
    /// 小数（音量）。
    Float(f64),
    /// 時刻つきの文。
    Sync(Vec<(String, u32)>),
    /// 出来事と時刻。
    Events(Vec<(i8, u32)>),
    /// 周波数と調整。
    Adjustments(Vec<(f64, f64)>),
    /// 位置の表。
    Indexes(Vec<u32>),
    /// RVAD の値（v2.4 に直すときに消えるので、中身は持たない）。
    Rva,
    /// 入れ子のフレーム。
    Tags(Box<Tags>),
}

/// フレームの系統（mutagen のクラスの親）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// TextFrame・NumericTextFrame・NumericPartTextFrame。
    Text,
    /// TimeStampTextFrame。
    Stamp,
    /// TCON（TextFrame。ジャンルの読み直しがある）。
    Tcon,
    /// TXXX・COMM（TextFrame の子。説明・言語つき）。
    TextWithDesc,
    /// APIC（同じ説明が重なると salt を足す）。
    Apic,
    /// そのほか。
    Plain,
}

/// HashKey（同じフレームかどうかの鍵）の作り方。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    /// FrameID だけ。
    Id,
    /// `FrameID:項目`。
    Field(usize),
    /// `FrameID:説明:言語`。
    DescLang(usize, usize),
    /// `APIC:説明salt`。
    Apic,
    /// `LINK:frameid:url:data`。
    Link,
    /// `PRIV:owner:data`。
    Priv,
    /// `SIGN:group:sig`。
    Sign,
    /// `COMR:中身`。
    Comr,
}

/// 1 種類のフレームの定義。
#[derive(Debug)]
pub(crate) struct FrameDef {
    /// クラスの名前（= FrameID）。
    pub(crate) name: &'static str,
    /// 系統。
    pub(crate) kind: Kind,
    /// 中身の並び。
    pub(crate) specs: &'static [Spec],
    /// 省いてよい後ろの並び。
    pub(crate) optional: &'static [Spec],
    /// HashKey の作り方。
    pub(crate) key: Key,
    /// v2.2 の 3 文字のクラスなら、直す先（親のクラス）の名前。`Frame` なら直せない（捨てる）。
    pub(crate) base: Option<&'static str>,
}

use Spec as S;

const TEXT: &[Spec] = &[S::Encoding, S::MultiText];
const STAMP: &[Spec] = &[S::Encoding, S::MultiStamp];
const PAIRED: &[Spec] = &[S::Encoding, S::MultiPair];
const URL: &[Spec] = &[S::Latin1];
const NONE: &[Spec] = &[];

macro_rules! def {
    ($name:literal, $kind:ident, $specs:expr) => {
        FrameDef {
            name: $name,
            kind: Kind::$kind,
            specs: $specs,
            optional: NONE,
            key: Key::Id,
            base: None,
        }
    };
    ($name:literal, $kind:ident, $specs:expr, $key:expr) => {
        FrameDef {
            name: $name,
            kind: Kind::$kind,
            specs: $specs,
            optional: NONE,
            key: $key,
            base: None,
        }
    };
}

/// v2.3・v2.4 のフレーム（mutagen の `Frames`。105 種類）。
static FRAMES: &[FrameDef] = &[
    def!(
        "AENC",
        Plain,
        &[S::Latin1, S::Sized(2), S::Sized(2), S::Binary],
        Key::Field(0)
    ),
    def!(
        "APIC",
        Apic,
        &[S::Encoding, S::Latin1, S::Byte, S::Encoded, S::Binary],
        Key::Apic
    ),
    def!(
        "ASPI",
        Plain,
        &[S::Sized(4), S::Sized(4), S::Sized(2), S::Byte, S::AspiIndex]
    ),
    def!(
        "CHAP",
        Plain,
        &[
            S::Latin1,
            S::Sized(4),
            S::Sized(4),
            S::Sized(4),
            S::Sized(4),
            S::Frames
        ],
        Key::Field(0)
    ),
    def!(
        "COMM",
        TextWithDesc,
        &[S::Encoding, S::Fixed(3), S::Encoded, S::MultiText],
        Key::DescLang(2, 1)
    ),
    FrameDef {
        name: "COMR",
        kind: Kind::Plain,
        specs: &[
            S::Encoding,
            S::Latin1,
            S::Fixed(8),
            S::Latin1,
            S::Byte,
            S::Encoded,
            S::Encoded,
        ],
        optional: &[S::Latin1, S::Binary],
        key: Key::Comr,
        base: None,
    },
    def!(
        "CTOC",
        Plain,
        &[S::Latin1, S::Byte, S::Latin1List, S::Frames],
        Key::Field(0)
    ),
    def!(
        "ENCR",
        Plain,
        &[S::Latin1, S::Byte, S::Binary],
        Key::Field(0)
    ),
    def!(
        "EQU2",
        Plain,
        &[S::Byte, S::Latin1, S::VolumeAdjustments],
        Key::Field(1)
    ),
    def!("ETCO", Plain, &[S::Byte, S::KeyEvents]),
    def!(
        "GEOB",
        Plain,
        &[S::Encoding, S::Latin1, S::Encoded, S::Encoded, S::Binary],
        Key::Field(3)
    ),
    def!(
        "GRID",
        Plain,
        &[S::Latin1, S::Byte, S::Binary],
        Key::Field(1)
    ),
    def!("GRP1", Text, TEXT),
    def!("IPLS", Plain, PAIRED),
    def!(
        "LINK",
        Plain,
        &[S::Fixed(4), S::Latin1, S::Binary],
        Key::Link
    ),
    def!("MCDI", Plain, &[S::Binary]),
    def!(
        "MLLT",
        Plain,
        &[
            S::Sized(2),
            S::Sized(3),
            S::Sized(3),
            S::Byte,
            S::Byte,
            S::Binary
        ]
    ),
    def!("MVIN", Text, TEXT),
    def!("MVNM", Text, TEXT),
    def!(
        "OWNE",
        Plain,
        &[S::Encoding, S::Latin1, S::Fixed(8), S::Encoded]
    ),
    def!("PCNT", Plain, &[S::Integer]),
    def!("PCST", Plain, &[S::Integer]),
    FrameDef {
        name: "POPM",
        kind: Kind::Plain,
        specs: &[S::Latin1, S::Byte],
        optional: &[S::Integer],
        key: Key::Field(0),
        base: None,
    },
    def!("POSS", Plain, &[S::Byte, S::Integer]),
    def!("PRIV", Plain, &[S::Latin1, S::Binary], Key::Priv),
    FrameDef {
        name: "RBUF",
        kind: Kind::Plain,
        specs: &[S::Sized(3)],
        optional: &[S::Byte, S::Sized(4)],
        key: Key::Id,
        base: None,
    },
    def!(
        "RVA2",
        Plain,
        &[S::Latin1, S::Byte, S::VolumeAdjustment, S::VolumePeak],
        Key::Field(0)
    ),
    def!("RVAD", Plain, &[S::Rva(false)]),
    def!(
        "RVRB",
        Plain,
        &[
            S::Sized(2),
            S::Sized(2),
            S::Byte,
            S::Byte,
            S::Byte,
            S::Byte,
            S::Byte,
            S::Byte,
            S::Byte,
            S::Byte
        ]
    ),
    def!("SEEK", Plain, &[S::Integer]),
    def!("SIGN", Plain, &[S::Byte, S::Binary], Key::Sign),
    def!(
        "SYLT",
        Plain,
        &[
            S::Encoding,
            S::Fixed(3),
            S::Byte,
            S::Byte,
            S::Encoded,
            S::SyncText
        ],
        Key::DescLang(4, 1)
    ),
    def!("SYTC", Plain, &[S::Byte, S::Binary]),
    def!("TALB", Text, TEXT),
    def!("TBPM", Text, TEXT),
    def!("TCAT", Text, TEXT),
    def!("TCMP", Text, TEXT),
    def!("TCOM", Text, TEXT),
    def!("TCON", Tcon, TEXT),
    def!("TCOP", Text, TEXT),
    def!("TDAT", Text, TEXT),
    def!("TDEN", Stamp, STAMP),
    def!("TDES", Text, TEXT),
    def!("TDLY", Text, TEXT),
    def!("TDOR", Stamp, STAMP),
    def!("TDRC", Stamp, STAMP),
    def!("TDRL", Stamp, STAMP),
    def!("TDTG", Stamp, STAMP),
    def!("TENC", Text, TEXT),
    def!("TEXT", Text, TEXT),
    def!("TFLT", Text, TEXT),
    def!("TGID", Text, TEXT),
    def!("TIME", Text, TEXT),
    def!("TIPL", Plain, PAIRED),
    def!("TIT1", Text, TEXT),
    def!("TIT2", Text, TEXT),
    def!("TIT3", Text, TEXT),
    def!("TKEY", Text, TEXT),
    def!("TKWD", Text, TEXT),
    def!("TLAN", Text, TEXT),
    def!("TLEN", Text, TEXT),
    def!("TMCL", Plain, PAIRED),
    def!("TMED", Text, TEXT),
    def!("TMOO", Text, TEXT),
    def!("TOAL", Text, TEXT),
    def!("TOFN", Text, TEXT),
    def!("TOLY", Text, TEXT),
    def!("TOPE", Text, TEXT),
    def!("TORY", Text, TEXT),
    def!("TOWN", Text, TEXT),
    def!("TPE1", Text, TEXT),
    def!("TPE2", Text, TEXT),
    def!("TPE3", Text, TEXT),
    def!("TPE4", Text, TEXT),
    def!("TPOS", Text, TEXT),
    def!("TPRO", Text, TEXT),
    def!("TPUB", Text, TEXT),
    def!("TRCK", Text, TEXT),
    def!("TRDA", Text, TEXT),
    def!("TRSN", Text, TEXT),
    def!("TRSO", Text, TEXT),
    def!("TSIZ", Text, TEXT),
    def!("TSO2", Text, TEXT),
    def!("TSOA", Text, TEXT),
    def!("TSOC", Text, TEXT),
    def!("TSOP", Text, TEXT),
    def!("TSOT", Text, TEXT),
    def!("TSRC", Text, TEXT),
    def!("TSSE", Text, TEXT),
    def!("TSST", Text, TEXT),
    def!(
        "TXXX",
        TextWithDesc,
        &[S::Encoding, S::Encoded, S::MultiText],
        Key::Field(1)
    ),
    def!("TYER", Text, TEXT),
    def!("UFID", Plain, &[S::Latin1, S::Binary], Key::Field(0)),
    def!(
        "USER",
        Plain,
        &[S::Encoding, S::Fixed(3), S::Encoded],
        Key::Field(1)
    ),
    def!(
        "USLT",
        Plain,
        &[S::Encoding, S::Fixed(3), S::Encoded, S::Encoded],
        Key::DescLang(2, 1)
    ),
    def!("WCOM", Plain, URL, Key::Field(0)),
    def!("WCOP", Plain, URL),
    def!("WFED", Plain, URL),
    def!("WOAF", Plain, URL),
    def!("WOAR", Plain, URL, Key::Field(0)),
    def!("WOAS", Plain, URL),
    def!("WORS", Plain, URL),
    def!("WPAY", Plain, URL),
    def!("WPUB", Plain, URL),
    def!(
        "WXXX",
        Plain,
        &[S::Encoding, S::Encoded, S::Latin1],
        Key::Field(1)
    ),
];

/// v2.2 の 3 文字のフレーム（mutagen の `Frames_2_2`。71 種類）。(名前, 親, 自分の並び)。
/// 自分の並びが None なら親と同じ並び。
static FRAMES_22: &[(&str, &str, Option<&[Spec]>)] = &[
    ("BUF", "RBUF", None),
    ("CNT", "PCNT", None),
    ("COM", "COMM", None),
    ("CRA", "AENC", None),
    ("CRM", "Frame", Some(&[S::Latin1, S::Latin1, S::Binary])),
    ("ETC", "ETCO", None),
    ("GEO", "GEOB", None),
    ("GP1", "GRP1", None),
    ("IPL", "IPLS", None),
    ("LNK", "LINK", Some(&[S::Fixed(3), S::Latin1, S::Binary])),
    ("MCI", "MCDI", None),
    ("MLL", "MLLT", None),
    ("MVI", "MVIN", None),
    ("MVN", "MVNM", None),
    (
        "PIC",
        "APIC",
        Some(&[S::Encoding, S::Fixed(3), S::Byte, S::Encoded, S::Binary]),
    ),
    ("POP", "POPM", None),
    ("REV", "RVRB", None),
    ("RVA", "RVAD", Some(&[S::Rva(true)])),
    ("SLT", "SYLT", None),
    ("STC", "SYTC", None),
    ("TAL", "TALB", None),
    ("TBP", "TBPM", None),
    ("TCM", "TCOM", None),
    ("TCO", "TCON", None),
    ("TCP", "TCMP", None),
    ("TCR", "TCOP", None),
    ("TDA", "TDAT", None),
    ("TDY", "TDLY", None),
    ("TEN", "TENC", None),
    ("TFT", "TFLT", None),
    ("TIM", "TIME", None),
    ("TKE", "TKEY", None),
    ("TLA", "TLAN", None),
    ("TLE", "TLEN", None),
    ("TMT", "TMED", None),
    ("TOA", "TOPE", None),
    ("TOF", "TOFN", None),
    ("TOL", "TOLY", None),
    ("TOR", "TORY", None),
    ("TOT", "TOAL", None),
    ("TP1", "TPE1", None),
    ("TP2", "TPE2", None),
    ("TP3", "TPE3", None),
    ("TP4", "TPE4", None),
    ("TPA", "TPOS", None),
    ("TPB", "TPUB", None),
    ("TRC", "TSRC", None),
    ("TRD", "TRDA", None),
    ("TRK", "TRCK", None),
    ("TS2", "TSO2", None),
    ("TSA", "TSOA", None),
    ("TSC", "TSOC", None),
    ("TSI", "TSIZ", None),
    ("TSP", "TSOP", None),
    ("TSS", "TSSE", None),
    ("TST", "TSOT", None),
    ("TT1", "TIT1", None),
    ("TT2", "TIT2", None),
    ("TT3", "TIT3", None),
    ("TXT", "TEXT", None),
    ("TXX", "TXXX", None),
    ("TYE", "TYER", None),
    ("UFI", "UFID", None),
    ("ULT", "USLT", None),
    ("WAF", "WOAF", None),
    ("WAR", "WOAR", None),
    ("WAS", "WOAS", None),
    ("WCM", "WCOM", None),
    ("WCP", "WCOP", None),
    ("WPB", "WPUB", None),
    ("WXX", "WXXX", None),
];

/// v2.2 のフレームの定義（親の定義から作って、1 回だけ持つ）。
fn frames_22() -> &'static [FrameDef] {
    static DEFS: std::sync::OnceLock<Vec<FrameDef>> = std::sync::OnceLock::new();
    DEFS.get_or_init(|| {
        FRAMES_22
            .iter()
            .map(|(name, base, own)| {
                let parent = frame_def(base);
                FrameDef {
                    name,
                    kind: parent.map_or(Kind::Plain, |p| p.kind),
                    specs: own.or(parent.map(|p| p.specs)).unwrap_or(NONE),
                    optional: if own.is_some() {
                        NONE
                    } else {
                        parent.map_or(NONE, |p| p.optional)
                    },
                    key: if own.is_some() {
                        Key::Id
                    } else {
                        parent.map_or(Key::Id, |p| p.key)
                    },
                    base: Some(base),
                }
            })
            .collect()
    })
}

/// v2.3・v2.4 のフレームの定義を名前で引く。
pub(crate) fn frame_def(name: &str) -> Option<&'static FrameDef> {
    FRAMES.iter().find(|d| d.name == name)
}

/// v2.2 のフレームの定義を名前で引く。
pub(crate) fn frame_def_22(name: &str) -> Option<&'static FrameDef> {
    frames_22().iter().find(|d| d.name == name)
}

/// mutagen の `TCON.GENRES`。
pub(crate) const GENRES: [&str; 192] = [
    "Blues",
    "Classic Rock",
    "Country",
    "Dance",
    "Disco",
    "Funk",
    "Grunge",
    "Hip-Hop",
    "Jazz",
    "Metal",
    "New Age",
    "Oldies",
    "Other",
    "Pop",
    "R&B",
    "Rap",
    "Reggae",
    "Rock",
    "Techno",
    "Industrial",
    "Alternative",
    "Ska",
    "Death Metal",
    "Pranks",
    "Soundtrack",
    "Euro-Techno",
    "Ambient",
    "Trip-Hop",
    "Vocal",
    "Jazz+Funk",
    "Fusion",
    "Trance",
    "Classical",
    "Instrumental",
    "Acid",
    "House",
    "Game",
    "Sound Clip",
    "Gospel",
    "Noise",
    "Alt. Rock",
    "Bass",
    "Soul",
    "Punk",
    "Space",
    "Meditative",
    "Instrumental Pop",
    "Instrumental Rock",
    "Ethnic",
    "Gothic",
    "Darkwave",
    "Techno-Industrial",
    "Electronic",
    "Pop-Folk",
    "Eurodance",
    "Dream",
    "Southern Rock",
    "Comedy",
    "Cult",
    "Gangsta Rap",
    "Top 40",
    "Christian Rap",
    "Pop/Funk",
    "Jungle",
    "Native American",
    "Cabaret",
    "New Wave",
    "Psychedelic",
    "Rave",
    "Showtunes",
    "Trailer",
    "Lo-Fi",
    "Tribal",
    "Acid Punk",
    "Acid Jazz",
    "Polka",
    "Retro",
    "Musical",
    "Rock & Roll",
    "Hard Rock",
    "Folk",
    "Folk-Rock",
    "National Folk",
    "Swing",
    "Fast-Fusion",
    "Bebop",
    "Latin",
    "Revival",
    "Celtic",
    "Bluegrass",
    "Avantgarde",
    "Gothic Rock",
    "Progressive Rock",
    "Psychedelic Rock",
    "Symphonic Rock",
    "Slow Rock",
    "Big Band",
    "Chorus",
    "Easy Listening",
    "Acoustic",
    "Humour",
    "Speech",
    "Chanson",
    "Opera",
    "Chamber Music",
    "Sonata",
    "Symphony",
    "Booty Bass",
    "Primus",
    "Porn Groove",
    "Satire",
    "Slow Jam",
    "Club",
    "Tango",
    "Samba",
    "Folklore",
    "Ballad",
    "Power Ballad",
    "Rhythmic Soul",
    "Freestyle",
    "Duet",
    "Punk Rock",
    "Drum Solo",
    "A Cappella",
    "Euro-House",
    "Dance Hall",
    "Goa",
    "Drum & Bass",
    "Club-House",
    "Hardcore",
    "Terror",
    "Indie",
    "BritPop",
    "Afro-Punk",
    "Polsk Punk",
    "Beat",
    "Christian Gangsta Rap",
    "Heavy Metal",
    "Black Metal",
    "Crossover",
    "Contemporary Christian",
    "Christian Rock",
    "Merengue",
    "Salsa",
    "Thrash Metal",
    "Anime",
    "JPop",
    "Synthpop",
    "Abstract",
    "Art Rock",
    "Baroque",
    "Bhangra",
    "Big Beat",
    "Breakbeat",
    "Chillout",
    "Downtempo",
    "Dub",
    "EBM",
    "Eclectic",
    "Electro",
    "Electroclash",
    "Emo",
    "Experimental",
    "Garage",
    "Global",
    "IDM",
    "Illbient",
    "Industro-Goth",
    "Jam Band",
    "Krautrock",
    "Leftfield",
    "Lounge",
    "Math Rock",
    "New Romantic",
    "Nu-Breakz",
    "Post-Punk",
    "Post-Rock",
    "Psytrance",
    "Shoegaze",
    "Space Rock",
    "Trop Rock",
    "World Music",
    "Neoclassical",
    "Audiobook",
    "Audio Theatre",
    "Neue Deutsche Welle",
    "Podcast",
    "Indie Rock",
    "G-Funk",
    "Dubstep",
    "Garage Rock",
    "Psybient",
];

// ---- 文字の符号化（mutagen の EncodedTextSpec・decode_terminated・encode_endian） ----

/// フレームの符号化の番号から、読み方の種類。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    Latin1,
    Utf16,
    Utf16Be,
    Utf8,
}

fn codec(encoding: u64) -> Codec {
    match encoding {
        0 => Codec::Latin1,
        1 => Codec::Utf16,
        2 => Codec::Utf16Be,
        _ => Codec::Utf8,
    }
}

/// UTF-16 を 1 バイトずつ読む Python の逐次の読み手（`codecs.getincrementaldecoder`）と同じ判定。
/// NUL の文字まで読んだら (文, 残り) を返す。読めない並びは Err。
fn decode_utf16_terminated(
    data: &[u8],
    with_bom: bool,
    strict: bool,
) -> Result<(String, &[u8]), ()> {
    // BOM つき（utf-16）の読み手は、最初の 2 バイトが BOM でなければ「BOM で始まらない」で失敗する。
    let (little, start) = if with_bom {
        if data.len() < 2 {
            // 1 バイトだけなら、最後に「途中で切れた」で失敗する。空なら空の文。
            return if data.is_empty() && !strict {
                Ok((String::new(), data))
            } else {
                Err(())
            };
        }
        match (data[0], data[1]) {
            (0xFF, 0xFE) => (true, 2),
            (0xFE, 0xFF) => (false, 2),
            _ => return Err(()),
        }
    } else {
        (false, 0)
    };
    let mut out = String::new();
    let mut pending: Option<u16> = None;
    let mut i = start;
    while i + 1 < data.len() {
        let unit = if little {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };
        i += 2;
        match pending.take() {
            Some(high) => {
                if !(0xDC00..=0xDFFF).contains(&unit) {
                    return Err(());
                }
                let code =
                    0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                out.push(char::from_u32(code).ok_or(())?);
            }
            None => {
                if (0xD800..=0xDBFF).contains(&unit) {
                    pending = Some(unit);
                } else if (0xDC00..=0xDFFF).contains(&unit) {
                    return Err(());
                } else if unit == 0 {
                    return Ok((out, &data[i..]));
                } else {
                    out.push(char::from_u32(u32::from(unit)).ok_or(())?);
                }
            }
        }
    }
    // 終わり: 半端なバイトや、相手の無い上位サロゲートが残っていれば失敗。
    if pending.is_some() || i < data.len() || strict {
        return Err(());
    }
    Ok((out, &data[data.len()..]))
}

/// mutagen の `decode_terminated`。
fn decode_terminated(data: &[u8], c: Codec, strict: bool) -> Result<(String, &[u8]), ()> {
    match c {
        Codec::Latin1 | Codec::Utf8 => {
            let (body, rest, found) = match data.iter().position(|b| *b == 0) {
                Some(i) => (&data[..i], &data[i + 1..], true),
                None => (data, &data[data.len()..], false),
            };
            let text = if c == Codec::Latin1 {
                body.iter().map(|b| char::from(*b)).collect()
            } else {
                std::str::from_utf8(body).map_err(|_| ())?.to_string()
            };
            if !found && strict {
                return Err(());
            }
            Ok((text, rest))
        }
        Codec::Utf16 => decode_utf16_terminated(data, true, strict),
        Codec::Utf16Be => decode_utf16_terminated(data, false, strict),
    }
}

/// EncodedTextSpec.read（`iter_text_fixups` の直しを順に試す）。
fn read_encoded(v22_or_23: bool, encoding: u64, data: &[u8]) -> Result<(String, Vec<u8>), ()> {
    let c = codec(encoding);
    let mut tries: Vec<Vec<u8>> = vec![data.to_vec()];
    match c {
        Codec::Utf16Be => tries.push([data, b"\x00"].concat()),
        Codec::Utf16 => {
            tries.push([data, b"\x00"].concat());
            tries.push([b"\xff\xfe", data].concat());
            tries.push([b"\xff\xfe", data, b"\x00"].concat());
        }
        _ => {}
    }
    for t in &tries {
        if let Ok((value, rest)) = decode_terminated(t, c, false) {
            let rest = if v22_or_23 && rest.iter().all(|b| *b == 0) {
                Vec::new()
            } else {
                rest.to_vec()
            };
            return Ok((value, rest));
        }
    }
    Err(())
}

/// EncodedTextSpec.write（符号化して終わりの印を付ける）。
fn write_encoded(encoding: u64, value: &str, out: &mut Vec<u8>) -> Result<(), WriteError> {
    match codec(encoding) {
        Codec::Latin1 => {
            for ch in value.chars() {
                let code = u32::from(ch);
                if code > 0xFF {
                    return Err(WriteError);
                }
                out.push(code as u8);
            }
            out.push(0);
        }
        Codec::Utf16 => {
            out.extend_from_slice(b"\xff\xfe");
            for unit in value.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(b"\x00\x00");
        }
        Codec::Utf16Be => {
            for unit in value.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
            out.extend_from_slice(b"\x00\x00");
        }
        Codec::Utf8 => {
            out.extend_from_slice(value.as_bytes());
            out.push(0);
        }
    }
    Ok(())
}

/// Latin1TextSpec.read。
fn read_latin1(data: &[u8]) -> (String, &[u8]) {
    match data.iter().position(|b| *b == 0) {
        Some(i) => (
            data[..i].iter().map(|b| char::from(*b)).collect(),
            &data[i + 1..],
        ),
        None => (
            data.iter().map(|b| char::from(*b)).collect(),
            &data[data.len()..],
        ),
    }
}

fn write_latin1(value: &str, out: &mut Vec<u8>) -> Result<(), WriteError> {
    for ch in value.chars() {
        let code = u32::from(ch);
        if code > 0xFF {
            return Err(WriteError);
        }
        out.push(code as u8);
    }
    out.push(0);
    Ok(())
}

/// バイト列を Latin-1 の文字列にする（mutagen の `_bytes2key`）。
pub(crate) fn latin1_key(data: &[u8]) -> String {
    data.iter().map(|b| char::from(*b)).collect()
}

/// 読みの失敗。
#[derive(Debug)]
pub(crate) enum ReadError {
    /// SpecError（そのフレームだけ捨てる。ID3JunkFrameError）。
    Junk,
    /// spec の外の例外（struct.error など）。タグ全体の読み込みが失敗する。
    Fatal,
}

/// 書きの失敗（mutagen.id3.error・UnicodeEncodeError など。保存が失敗する）。
#[derive(Debug)]
pub(crate) struct WriteError;

/// ヘッダーのうち、フレームの読み方に効くもの。
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadCtx {
    /// ID3v2 の版（2・3・4）。
    pub(crate) major: u8,
    /// タグ全体の非同期化の印。
    pub(crate) unsynch: bool,
}

fn big_from(data: &[u8]) -> Vec<u8> {
    let start = data.iter().position(|b| *b != 0).unwrap_or(data.len());
    data[start..].to_vec()
}

fn u64_from(data: &[u8]) -> u64 {
    data.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

/// 1 項目を読む。
fn read_spec<'a>(
    spec: Spec,
    ctx: ReadCtx,
    vals: &[Val],
    encoding: u64,
    data: &'a [u8],
) -> Result<(Val, std::borrow::Cow<'a, [u8]>), ReadError> {
    use std::borrow::Cow;
    let old = ctx.major < 4;
    Ok(match spec {
        S::Byte => (Val::Int(u64::from(data[0])), Cow::Borrowed(&data[1..])),
        S::Encoding => {
            if data[0] > 3 {
                return Err(ReadError::Junk);
            }
            (Val::Int(u64::from(data[0])), Cow::Borrowed(&data[1..]))
        }
        S::Sized(n) => {
            let n = n.min(data.len());
            (Val::Int(u64_from(&data[..n])), Cow::Borrowed(&data[n..]))
        }
        S::Integer => (Val::Big(big_from(data)), Cow::Borrowed(&data[data.len()..])),
        S::Fixed(n) => {
            let n = n.min(data.len());
            if !data[..n].is_ascii() {
                return Err(ReadError::Junk);
            }
            let text = data[..n].iter().map(|b| char::from(*b)).collect();
            (Val::Text(text), Cow::Borrowed(&data[n..]))
        }
        S::Latin1 => {
            let (text, rest) = read_latin1(data);
            (Val::Text(text), Cow::Borrowed(rest))
        }
        S::Encoded => {
            let (text, rest) = read_encoded(old, encoding, data).map_err(|()| ReadError::Junk)?;
            (Val::Text(text), Cow::Owned(rest))
        }
        S::Binary => (
            Val::Bytes(data.to_vec()),
            Cow::Borrowed(&data[data.len()..]),
        ),
        S::MultiText | S::MultiStamp => {
            let mut rest = data.to_vec();
            let mut texts = Vec::new();
            while !rest.is_empty() {
                let (text, next) =
                    read_encoded(old, encoding, &rest).map_err(|()| ReadError::Junk)?;
                texts.push(text);
                rest = next;
            }
            let val = if spec == S::MultiText {
                Val::Texts(texts)
            } else {
                Val::Stamps(texts.iter().map(|t| Stamp::parse(t)).collect())
            };
            (val, Cow::Owned(rest))
        }
        S::MultiPair => {
            let mut rest = data.to_vec();
            let mut pairs = Vec::new();
            while !rest.is_empty() {
                let mut record = Vec::new();
                for _ in 0..2 {
                    let (text, next) =
                        read_encoded(old, encoding, &rest).map_err(|()| ReadError::Junk)?;
                    record.push(text);
                    rest = next;
                }
                pairs.push(record);
            }
            (Val::Pairs(pairs), Cow::Owned(rest))
        }
        S::Rva(stereo_only) => {
            let max_values = if stereo_only { 4 } else { 12 };
            let flags = data[0];
            let data = &data[1..];
            if data.is_empty() {
                return Err(ReadError::Junk);
            }
            let bits = data[0];
            let mut data = &data[1..];
            if bits == 0 {
                return Err(ReadError::Junk);
            }
            let per = usize::from(bits).div_ceil(8);
            let mut values: Vec<i64> = Vec::new();
            while data.len() >= per && values.len() < max_values {
                values.push(u64_from(&data[..per.min(8)]) as i64);
                data = &data[per..];
            }
            if values.len() < 2 {
                return Err(ReadError::Junk);
            }
            for (bit, index) in [0, 1, 4, 5, 8, 10].into_iter().enumerate() {
                if flags & (1 << bit) == 0 {
                    match values.get_mut(index) {
                        Some(v) => *v = -*v,
                        None => break,
                    }
                }
            }
            (Val::Rva, Cow::Borrowed(data))
        }
        S::Frames => {
            let mut tags = Tags::new();
            let rest = tags.read(ctx, data)?;
            (Val::Tags(Box::new(tags)), Cow::Owned(rest))
        }
        S::Latin1List => {
            let count = data[0];
            let mut rest = &data[1..];
            let mut entries = Vec::new();
            for _ in 0..count {
                let (text, next) = read_latin1(rest);
                entries.push(text);
                rest = next;
            }
            (Val::Strings(entries), Cow::Borrowed(rest))
        }
        S::VolumeAdjustment => {
            if data.len() < 2 {
                // struct.unpack('>h', data[0:2]) の struct.error（SpecError ではないので、読み込み全体が落ちる）。
                return Err(ReadError::Fatal);
            }
            let v = i16::from_be_bytes([data[0], data[1]]);
            (Val::Float(f64::from(v) / 512.0), Cow::Borrowed(&data[2..]))
        }
        S::VolumePeak => {
            let bits = data[0];
            let vol_bytes = 4usize.min((usize::from(bits) + 7) >> 3);
            if vol_bytes + 1 > data.len() {
                return Err(ReadError::Junk);
            }
            let shift = ((8 - u32::from(bits & 7)) & 7) + (4 - vol_bytes as u32) * 8;
            let mut peak: u64 = 0;
            for b in &data[1..=vol_bytes] {
                peak = peak * 256 + u64::from(*b);
            }
            let peak = (peak as f64) * 2f64.powi(shift as i32);
            (
                Val::Float(peak / 2_147_483_647.0),
                Cow::Borrowed(&data[1 + vol_bytes..]),
            )
        }
        S::SyncText => {
            let c = codec(encoding);
            let mut texts = Vec::new();
            let mut rest = data;
            while !rest.is_empty() {
                let (value, next) =
                    decode_terminated(rest, c, true).map_err(|()| ReadError::Junk)?;
                if next.len() < 4 {
                    return Err(ReadError::Junk);
                }
                let time = u32::from_be_bytes([next[0], next[1], next[2], next[3]]);
                texts.push((value, time));
                rest = &next[4..];
            }
            (Val::Sync(texts), Cow::Borrowed(&data[data.len()..]))
        }
        S::KeyEvents => {
            let mut events = Vec::new();
            let mut rest = data;
            while rest.len() >= 5 {
                events.push((
                    rest[0] as i8,
                    u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]),
                ));
                rest = &rest[5..];
            }
            (Val::Events(events), Cow::Borrowed(rest))
        }
        S::VolumeAdjustments => {
            let mut adjustments: Vec<(f64, f64)> = Vec::new();
            let mut rest = data;
            while rest.len() >= 4 {
                let freq = f64::from(u16::from_be_bytes([rest[0], rest[1]])) / 2.0;
                let adj = f64::from(i16::from_be_bytes([rest[2], rest[3]])) / 512.0;
                rest = &rest[4..];
                match adjustments.iter_mut().find(|(f, _)| *f == freq) {
                    Some(slot) => slot.1 = adj,
                    None => adjustments.push((freq, adj)),
                }
            }
            adjustments.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            (Val::Adjustments(adjustments), Cow::Borrowed(rest))
        }
        S::AspiIndex => {
            let b = match vals.get(3) {
                Some(Val::Int(b)) => *b,
                _ => 0,
            };
            let n = match vals.get(2) {
                Some(Val::Int(n)) => *n as usize,
                _ => 0,
            };
            let size = match b {
                16 => 2,
                8 => 1,
                _ => return Err(ReadError::Junk),
            };
            let take = (n * size).min(data.len());
            let (indexes, rest) = data.split_at(take);
            if indexes.len() != n * size {
                return Err(ReadError::Junk);
            }
            let values = indexes
                .chunks(size)
                .map(|c| {
                    if size == 2 {
                        u32::from(u16::from_be_bytes([c[0], c[1]]))
                    } else {
                        u32::from(c[0])
                    }
                })
                .collect();
            (Val::Indexes(values), Cow::Borrowed(rest))
        }
    })
}

/// Python の `intround`（偶数への丸め）。
fn intround(value: f64) -> f64 {
    value.round_ties_even()
}

/// 1 項目を書く（v2.4）。
fn write_spec(spec: Spec, frame: &Frame, val: &Val, out: &mut Vec<u8>) -> Result<(), WriteError> {
    let encoding = frame.encoding();
    match (spec, val) {
        (S::Byte | S::Encoding, Val::Int(v)) => out.push(*v as u8),
        (S::Sized(n), Val::Int(v)) => {
            if n < 8 && *v >> (8 * n) != 0 {
                return Err(WriteError);
            }
            for i in (0..n).rev() {
                out.push(if i >= 8 { 0 } else { (*v >> (8 * i)) as u8 });
            }
        }
        (S::Integer, Val::Big(bytes)) => {
            out.resize(out.len() + 4 - bytes.len().min(4), 0);
            out.extend_from_slice(bytes);
        }
        (S::Fixed(n), Val::Text(t)) => {
            if !t.is_ascii() {
                return Err(WriteError);
            }
            let mut b = t.as_bytes().to_vec();
            b.resize(b.len() + n, 0);
            b.truncate(n);
            out.extend_from_slice(&b);
        }
        (S::Latin1, Val::Text(t)) => write_latin1(t, out)?,
        (S::Encoded, Val::Text(t)) => write_encoded(encoding, t, out)?,
        (S::Binary, Val::Bytes(b)) => out.extend_from_slice(b),
        (S::MultiText, Val::Texts(texts)) => {
            for t in texts {
                write_encoded(encoding, t, out)?;
            }
        }
        (S::MultiStamp, Val::Stamps(stamps)) => {
            for s in stamps {
                write_encoded(encoding, &s.text().replace(' ', "T"), out)?;
            }
        }
        (S::MultiPair, Val::Pairs(pairs)) => {
            for record in pairs {
                for t in record.iter().take(2) {
                    write_encoded(encoding, t, out)?;
                }
            }
        }
        (S::Frames, Val::Tags(tags)) => out.extend_from_slice(&tags.write()?),
        (S::Latin1List, Val::Strings(entries)) => {
            out.push(u8::try_from(entries.len()).map_err(|_| WriteError)?);
            for e in entries {
                write_latin1(e, out)?;
            }
        }
        (S::VolumeAdjustment, Val::Float(v)) => {
            let number = intround(v * 512.0);
            if !(-32768.0..=32767.0).contains(&number) {
                return Err(WriteError);
            }
            out.extend_from_slice(&(number as i16).to_be_bytes());
        }
        (S::VolumePeak, Val::Float(v)) => {
            let number = intround(v * 32768.0);
            if !(0.0..=65535.0).contains(&number) {
                return Err(WriteError);
            }
            out.push(0x10);
            out.extend_from_slice(&(number as u16).to_be_bytes());
        }
        (S::SyncText, Val::Sync(texts)) => {
            for (text, time) in texts {
                write_encoded(encoding, text, out)?;
                out.extend_from_slice(&time.to_be_bytes());
            }
        }
        (S::KeyEvents, Val::Events(events)) => {
            for (kind, time) in events {
                out.push(*kind as u8);
                out.extend_from_slice(&time.to_be_bytes());
            }
        }
        (S::VolumeAdjustments, Val::Adjustments(adjs)) => {
            let mut sorted = adjs.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            for (freq, adj) in sorted {
                out.extend_from_slice(&((freq * 2.0) as u16).to_be_bytes());
                out.extend_from_slice(&((adj * 512.0) as i16).to_be_bytes());
            }
        }
        (S::AspiIndex, Val::Indexes(values)) => {
            let b = match frame.vals.get(3) {
                Some(Val::Int(b)) => *b,
                _ => 0,
            };
            for v in values {
                match b {
                    16 => out.extend_from_slice(&(*v as u16).to_be_bytes()),
                    8 => out.push(*v as u8),
                    _ => return Err(WriteError),
                }
            }
        }
        _ => return Err(WriteError),
    }
    Ok(())
}

/// 1 つのフレーム（mutagen の Frame の子クラスの 1 つの実体）。
#[derive(Clone, Debug)]
pub(crate) struct Frame {
    /// 種類。
    pub(crate) def: &'static FrameDef,
    /// 中身（`specs` の数だけ。省いてよい後ろの項目は読めた分だけ続く）。
    pub(crate) vals: Vec<Val>,
    /// APIC の salt（同じ説明の APIC が重なったときに足す空白）。
    pub(crate) salt: String,
}

fn text_of(val: Option<&Val>) -> String {
    match val {
        Some(Val::Text(t)) => t.clone(),
        Some(Val::Int(v)) => v.to_string(),
        Some(Val::Bytes(b)) => latin1_key(b),
        _ => String::new(),
    }
}

impl Frame {
    /// フレームを作る（中身は呼ぶ側が spec の並びのとおりに渡す）。
    pub(crate) fn new(def: &'static FrameDef, vals: Vec<Val>) -> Self {
        Self {
            def,
            vals,
            salt: String::new(),
        }
    }

    /// FrameID（クラスの名前）。
    pub(crate) fn id(&self) -> &'static str {
        self.def.name
    }

    /// 符号化（EncodingSpec が先頭にあるフレームだけ）。
    pub(crate) fn encoding(&self) -> u64 {
        match (self.def.specs.first(), self.vals.first()) {
            (Some(S::Encoding), Some(Val::Int(e))) => *e,
            _ => 0,
        }
    }

    /// TextFrame の文の並び（`text`）。
    pub(crate) fn texts(&self) -> Option<&Vec<String>> {
        self.vals.iter().find_map(|v| match v {
            Val::Texts(t) => Some(t),
            _ => None,
        })
    }

    /// TextFrame の文の並びを書き換える。
    pub(crate) fn texts_mut(&mut self) -> Option<&mut Vec<String>> {
        self.vals.iter_mut().find_map(|v| match v {
            Val::Texts(t) => Some(t),
            _ => None,
        })
    }

    /// TimeStampTextFrame の日時の並び。
    pub(crate) fn stamps(&self) -> Option<&Vec<Stamp>> {
        self.vals.iter().find_map(|v| match v {
            Val::Stamps(s) => Some(s),
            _ => None,
        })
    }

    /// 入れ子のフレーム（CHAP・CTOC の `sub_frames`）。
    pub(crate) fn sub_frames_mut(&mut self) -> Option<&mut Tags> {
        self.vals.iter_mut().find_map(|v| match v {
            Val::Tags(t) => Some(t.as_mut()),
            _ => None,
        })
    }

    /// TextFrame の系統か（保存のときに空なら書かない・重なったら文を足す）。
    pub(crate) fn is_text_frame(&self) -> bool {
        matches!(
            self.def.kind,
            Kind::Text | Kind::Stamp | Kind::Tcon | Kind::TextWithDesc
        )
    }

    /// Python の `str(frame)`（TextFrame は文を NUL でつなぐ。日時は `,` でつなぐ）。
    pub(crate) fn text_str(&self) -> String {
        if let Some(stamps) = self.stamps() {
            return stamps.iter().map(Stamp::text).collect::<Vec<_>>().join(",");
        }
        self.texts().map(|t| t.join("\u{0}")).unwrap_or_default()
    }

    /// mutagen の `HashKey`。
    pub(crate) fn hash_key(&self) -> String {
        let id = self.id();
        let field = |i: usize| text_of(self.vals.get(i));
        match self.def.key {
            Key::Id => id.to_string(),
            Key::Field(i) => format!("{id}:{}", field(i)),
            Key::DescLang(d, l) => format!("{id}:{}:{}", field(d), field(l)),
            Key::Apic => format!("{id}:{}{}", field(3), self.salt),
            Key::Link => format!("{id}:{}:{}:{}", field(0), field(1), field(2)),
            Key::Priv => format!("{id}:{}:{}", field(0), field(1)),
            Key::Sign => format!("{id}:{}:{}", field(0), field(1)),
            Key::Comr => format!(
                "{id}:{}",
                latin1_key(&self.write_data().unwrap_or_default())
            ),
        }
    }

    /// mutagen の `_writeData`（v2.4）。
    pub(crate) fn write_data(&self) -> Result<Vec<u8>, WriteError> {
        let mut out = Vec::new();
        for (spec, val) in self.def.specs.iter().zip(&self.vals) {
            write_spec(*spec, self, val, &mut out)?;
        }
        for (spec, val) in self
            .def
            .optional
            .iter()
            .zip(self.vals.iter().skip(self.def.specs.len()))
        {
            write_spec(*spec, self, val, &mut out)?;
        }
        Ok(out)
    }

    /// mutagen の `Frame._fromData`（フラグの処理のあとに中身を読む）。
    ///
    /// Ok(None) は「暗号化されていて読めない」（mutagen は知らないフレームとして生のまま持つ）。
    pub(crate) fn from_data(
        def: &'static FrameDef,
        ctx: ReadCtx,
        flags: u16,
        data: &[u8],
    ) -> Result<Option<Frame>, ReadError> {
        let mut data = data.to_vec();
        if ctx.major >= 4 {
            let mut datalen = Vec::new();
            if flags & (0x0008 | 0x0001) != 0 {
                let n = data.len().min(4);
                datalen = data[..n].to_vec();
                data.drain(..n);
            }
            if (flags & 0x0002 != 0 || ctx.unsynch)
                && let Some(decoded) = unsynch_decode(&data)
            {
                data = decoded;
            }
            if flags & 0x0004 != 0 {
                return Ok(None);
            }
            if flags & 0x0008 != 0 {
                data = match zlib_decompress(&data) {
                    Some(d) => d,
                    None => zlib_decompress(&[datalen.as_slice(), &data].concat())
                        .ok_or(ReadError::Junk)?,
                };
            }
        } else if ctx.major >= 3 {
            if flags & 0x0080 != 0 {
                if data.len() < 4 {
                    return Err(ReadError::Junk);
                }
                data.drain(..4);
            }
            if flags & 0x0040 != 0 {
                return Ok(None);
            }
            if flags & 0x0080 != 0 {
                data = zlib_decompress(&data).ok_or(ReadError::Junk)?;
            }
        }
        let mut frame = Frame::new(def, Vec::new());
        frame.read_data(ctx, &data)?;
        Ok(Some(frame))
    }

    /// mutagen の `_readData`。
    fn read_data(&mut self, ctx: ReadCtx, data: &[u8]) -> Result<(), ReadError> {
        let mut rest: Vec<u8> = data.to_vec();
        for spec in self.def.specs {
            if rest.is_empty() && !spec.handle_nodata() {
                return Err(ReadError::Junk);
            }
            let (val, next) = read_spec(*spec, ctx, &self.vals, self.encoding(), &rest)?;
            let next = next.into_owned();
            self.vals.push(val);
            rest = next;
        }
        for spec in self.def.optional {
            if rest.is_empty() && !spec.handle_nodata() {
                break;
            }
            let (val, next) = read_spec(*spec, ctx, &self.vals, self.encoding(), &rest)?;
            let next = next.into_owned();
            self.vals.push(val);
            rest = next;
        }
        Ok(())
    }

    /// mutagen の `_upgrade_frame`（v2.2 の 3 文字のフレームを v2.3/2.4 の親に直す。直せなければ None）。
    pub(crate) fn upgrade(self) -> Option<Frame> {
        let Some(base) = self.def.base else {
            return Some(self);
        };
        let parent = frame_def(base)?;
        let mut vals = self.vals;
        if self.def.name == "LNK" {
            // LNK._to_other: 参照先の 3 文字の ID を親の 4 文字の名前に直す（無ければ 4 文字に詰める）。
            if let Some(Val::Text(id)) = vals.first() {
                let new_id = match FRAMES_22.iter().find(|(n, _, _)| n == id) {
                    Some((_, parent_name, _)) => (*parent_name).to_string(),
                    None => format!("{id:<4}"),
                };
                vals[0] = Val::Text(new_id);
            }
        }
        Some(Frame {
            def: parent,
            vals,
            salt: String::new(),
        })
    }
}

/// mutagen の `unsynch.decode`（読めなければ None）。
pub(crate) fn unsynch_decode(value: &[u8]) -> Option<Vec<u8>> {
    let fragments: Vec<&[u8]> = value.split(|b| *b == 0xFF).collect();
    if fragments.len() > 1 && fragments.last().is_some_and(|f| f.is_empty()) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len());
    for (i, f) in fragments.iter().enumerate() {
        if i == 0 {
            out.extend_from_slice(f);
            continue;
        }
        if f.is_empty() || f[0] >= 0xE0 {
            return None;
        }
        out.push(0xFF);
        out.extend_from_slice(if f[0] == 0 { &f[1..] } else { f });
    }
    Some(out)
}

/// Python の `zlib.decompress`（終わりの印まで読めたものだけ。後ろの余りは無視）。
fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut d = flate2::Decompress::new(true);
    let mut out = Vec::with_capacity(data.len() * 4 + 64);
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let input = &data[usize::try_from(d.total_in()).ok()?..];
        let status = d
            .decompress_vec(input, &mut out, flate2::FlushDecompress::Finish)
            .ok()?;
        match status {
            flate2::Status::StreamEnd => return Some(out),
            _ => {
                if out.len() == out.capacity() {
                    out.reserve(out.capacity().max(64));
                } else if d.total_in() == before_in && d.total_out() == before_out {
                    return None;
                }
            }
        }
    }
}

/// TCON のジャンルの読み直し（mutagen の `TCON.genres` の取り出し）。
pub(crate) fn tcon_genres(texts: &[String]) -> Vec<String> {
    let mut genres = Vec::new();
    for value in texts {
        let decimal = !value.is_empty() && value.chars().all(crate::djaudio_meta::text::is_digit);
        if decimal && py_int(value).is_some_and(|v| v.lt(256)) {
            let index = py_int(value).and_then(|v| v.to_u64()).unwrap_or(u64::MAX);
            genres.push(
                GENRES
                    .get(index as usize)
                    .copied()
                    .unwrap_or("Unknown")
                    .to_string(),
            );
        } else if value == "CR" {
            genres.push("Cover".into());
        } else if value == "RX" {
            genres.push("Remix".into());
        } else if !value.is_empty() {
            // ((?:\((?P<id>[0-9]+|RX|CR)\))*)(?P<str>.+)?
            let chars: Vec<char> = value.chars().collect();
            let mut i = 0;
            let mut ids: Vec<String> = Vec::new();
            loop {
                if chars.get(i) != Some(&'(') {
                    break;
                }
                let mut j = i + 1;
                let mut id = String::new();
                while j < chars.len() && chars[j].is_ascii_digit() {
                    id.push(chars[j]);
                    j += 1;
                }
                if id.is_empty() {
                    let rest: String = chars[i + 1..chars.len().min(i + 3)].iter().collect();
                    if rest == "RX" || rest == "CR" {
                        id = rest;
                        j = i + 3;
                    }
                }
                if id.is_empty() || chars.get(j) != Some(&')') {
                    break;
                }
                ids.push(id);
                i = j + 1;
            }
            let mut genrename: String = chars[i..].iter().take_while(|c| **c != '\n').collect();
            let mut newgenres: Vec<String> = Vec::new();
            for gid in &ids {
                if gid.chars().all(|c| c.is_ascii_digit())
                    && py_int(gid).is_some_and(|v| v.lt(GENRES.len() as u64))
                {
                    let index = py_int(gid).and_then(|v| v.to_u64()).unwrap_or(0) as usize;
                    newgenres.push(GENRES[index].to_string());
                } else if gid == "CR" {
                    newgenres.push("Cover".into());
                } else if gid == "RX" {
                    newgenres.push("Remix".into());
                } else {
                    newgenres.push("Unknown".into());
                }
            }
            if !genrename.is_empty() {
                if genrename.starts_with("((") {
                    genrename.remove(0);
                }
                if !newgenres.contains(&genrename) {
                    newgenres.push(genrename);
                }
            }
            genres.extend(newgenres);
        }
    }
    genres
}

/// 書き出しの道具（`save_frame`: ヘッダーを付けた 1 フレーム。TextFrame で中身が空なら何も書かない）。
pub(crate) fn save_frame(frame: &Frame) -> Result<Vec<u8>, WriteError> {
    if frame.is_text_frame() && frame.text_str().is_empty() {
        return Ok(Vec::new());
    }
    let data = frame.write_data()?;
    let size = data.len();
    if size >= 1 << 28 {
        return Err(WriteError);
    }
    let mut out = Vec::with_capacity(size + 10);
    let name = frame.id().as_bytes();
    out.extend_from_slice(&name[..name.len().min(4)]);
    out.resize(out.len() + 4 - name.len().min(4), 0);
    for shift in [21, 14, 7, 0] {
        out.push(((size >> shift) & 0x7F) as u8);
    }
    out.extend_from_slice(&[0, 0]);
    out.write_all(&data).map_err(|_| WriteError)?;
    Ok(out)
}
