"""入力にする MP3 を作る（`generate.py mp3`）。

- yt-dlp が作るのと同じ形: 本番の `_run_ytdlp`（services/djaudio_service.py）と同じ引数を `yt_dlp.parse_options` に
  渡して後処理（FFmpegThumbnailsConvertor → FFmpegExtractAudio → FFmpegMetadata → EmbedThumbnail）を組み、
  手元で作った音（webm/opus）と縮小画像にそのまま当てる（ネットにはつながない）
- それ以外: ffmpeg で作った小さな MPEG の音に、ここで組み立てた ID3（v2.2・v2.3・v2.4・v1、壊れたもの）を付ける
"""

import base64
import os
import random
import shutil
import struct
import subprocess
import zlib

import yt_dlp

FFMPEG = shutil.which("ffmpeg") or "ffmpeg"

# 本番の _run_ytdlp と同じ引数（URL・出力先・ネットの設定を除く）。
YTDLP_ARGS = [
    "-x",
    "--audio-format",
    "mp3",
    "--audio-quality",
    "0",
    "-f",
    "bestaudio/best",
    "--format-sort",
    "asr,abr,acodec:opus",
    "--postprocessor-args",
    "ffmpeg:-q:a 0",
    "--write-info-json",
    "--embed-thumbnail",
    "--convert-thumbnails",
    "jpg",
    "--embed-metadata",
    "--no-playlist",
    "--no-warnings",
]


def run(cmd):
    """コマンドを動かす（失敗したら止める）。"""
    subprocess.run(cmd, check=True, capture_output=True)


def ffmpeg(*args):
    """ffmpeg を静かに動かす。"""
    run([FFMPEG, "-loglevel", "error", "-y", *args])


# ---- ID3 を組み立てる道具 ----


def syncsafe(n):
    """同期安全な 4 バイトの整数。"""
    return bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])


def f23(fid, data, flags=0):
    """v2.3 のフレーム（長さはただの整数）。"""
    return fid.encode("latin-1") + struct.pack(">IH", len(data), flags) + data


def f24(fid, data, flags=0, plain_size=False):
    """v2.4 のフレーム（長さは同期安全。plain_size なら iTunes の古い書き方のただの整数）。"""
    size = struct.pack(">I", len(data)) if plain_size else syncsafe(len(data))
    return fid.encode("latin-1") + size + struct.pack(">H", flags) + data


def f22(fid, data):
    """v2.2 のフレーム（3 文字の名前と 3 バイトの長さ）。"""
    return fid.encode("latin-1") + struct.pack(">I", len(data))[1:] + data


def tag(version, body, flags=0, padding=0, size=None):
    """ID3v2 のヘッダーを付ける。size を渡せば、その大きさを書く（壊れたタグ用）。"""
    total = len(body) + padding if size is None else size
    return b"ID3" + bytes([version, 0, flags]) + syncsafe(total) + body + b"\x00" * padding


def lat(s):
    """Latin-1 の文（符号化の番号 0 と NUL）。"""
    return b"\x00" + s.encode("latin-1") + b"\x00"


def u16(s):
    """BOM つき UTF-16 の文（番号 1）。"""
    return b"\x01" + b"\xff\xfe" + s.encode("utf-16-le") + b"\x00\x00"


def u16be(s):
    """UTF-16BE の文（番号 2）。"""
    return b"\x02" + s.encode("utf-16-be") + b"\x00\x00"


def u8(s):
    """UTF-8 の文（番号 3）。"""
    return b"\x03" + s.encode("utf-8") + b"\x00"


def v1(title=b"", artist=b"", album=b"", year=b"", comment=b"", track=None, genre=255):
    """ID3v1(.1) の 128 バイト。"""

    def fit(value, n):
        """n バイトに詰める（NUL で埋める）。"""
        return (value + b"\x00" * n)[:n]

    if track is None:
        body = fit(comment, 30)
    else:
        body = fit(comment, 28) + b"\x00" + bytes([track])
    return b"TAG" + fit(title, 30) + fit(artist, 30) + fit(album, 30) + fit(year, 4) + body + bytes([genre])


def tiny_jpeg(seed=0):
    """小さな JPEG（8×8）。"""
    path = f"/tmp/jpeg{seed}.jpg"
    ffmpeg("-f", "lavfi", "-i", f"color=c=0x{seed * 40 % 256:02x}4080:s=8x8", "-frames:v", "1", path)
    with open(path, "rb") as f:
        return f.read()


def tiny_png():
    """小さな PNG（8×8）。"""
    path = "/tmp/tiny.png"
    ffmpeg("-f", "lavfi", "-i", "color=c=blue:s=8x8", "-frames:v", "1", path)
    with open(path, "rb") as f:
        return f.read()


def audio(kind):
    """タグの無い MPEG の音。cbr: 8 kHz・1 ch・8 kbps（Xing なし）、vbr: Xing つき、stereo: 44.1 kHz・2 ch。"""
    path = f"/tmp/audio_{kind}.mp3"
    src = ["-f", "lavfi", "-i", "sine=frequency=440:duration=0.2:sample_rate=8000"]
    if kind == "cbr":
        ffmpeg(*src, "-ac", "1", "-c:a", "libmp3lame", "-b:a", "8k", "-id3v2_version", "0", "-write_xing", "0", path)
    elif kind == "vbr":
        ffmpeg(*src, "-ac", "1", "-c:a", "libmp3lame", "-q:a", "0", "-id3v2_version", "0", path)
    else:
        stereo = ["-f", "lavfi", "-i", "sine=frequency=440:duration=0.05:sample_rate=44100"]
        ffmpeg(*stereo, "-ac", "2", "-c:a", "libmp3lame", "-q:a", "0", "-id3v2_version", "0", path)
    with open(path, "rb") as f:
        return f.read()


# ---- yt-dlp の後処理で作るもの ----


def ytdlp_file(out_path, info, thumb_ext="webp", seconds=0.05):
    """手元の音と縮小画像に、本番と同じ yt-dlp の後処理を当てて MP3 を作る。"""
    work = "/tmp/ytwork"
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    src = f"{work}/media.webm"
    sine = f"sine=frequency=440:duration={seconds}:sample_rate=48000"
    ffmpeg("-f", "lavfi", "-i", sine, "-ac", "2", "-c:a", "libopus", "-b:a", "16k", src)
    thumb = f"{work}/media.{thumb_ext}"
    ffmpeg("-f", "lavfi", "-i", "color=c=red:s=8x8", "-frames:v", "1", thumb)
    args = [*YTDLP_ARGS, "-o", f"{work}/%(title).80s.%(ext)s", "--ffmpeg-location", FFMPEG, "--", "http://x.invalid"]
    ydl = yt_dlp.YoutubeDL(yt_dlp.parse_options(args).ydl_opts)
    full = {
        "id": "id0",
        "ext": "webm",
        "filepath": src,
        "vcodec": "none",
        "acodec": "opus",
        "thumbnails": [{"url": f"http://x.invalid/t.{thumb_ext}", "id": "0", "filepath": thumb}],
        "__files_to_move": {thumb: thumb},
        **info,
    }
    full = ydl.run_all_pps("before_dl", full)
    full = ydl.post_process(src, full)
    shutil.copyfile(full["filepath"], out_path)


YTDLP_INPUTS = {
    "yt_basic": {
        "title": "Artist - Song (Official Video)",
        "uploader": "Artist - Topic",
        "upload_date": "20240102",
        "description": "desc line",
        "webpage_url": "https://www.youtube.com/watch?v=abc",
        "extractor": "youtube",
        "chapters": [
            {"start_time": 0, "end_time": 0.02, "title": "Intro"},
            {"start_time": 0.02, "end_time": 0.05, "title": "Main"},
        ],
    },
    "yt_music": {
        "title": "夜に駆ける",
        "track": "夜に駆ける",
        "artists": ["YOASOBI", "Ayase"],
        "album": "THE BOOK",
        "upload_date": "20191215",
        "description": "🎵 " + "説明" * 1500,
        "webpage_url": "https://music.youtube.com/watch?v=xyz",
        "uploader": "YOASOBI - Topic",
        "extractor": "youtube",
    },
    "sc_track": {
        "title": "Track Name (Extended Mix)",
        "uploader": "DJ X",
        "genre": "Electronic",
        "upload_date": "20230505",
        "description": "",
        "webpage_url": "https://soundcloud.com/djx/track-name",
        "extractor": "soundcloud",
    },
    "bc_track": {
        "title": "Song Three",
        "artist": "Band",
        "album": "Album Name",
        "album_artist": "Band",
        "track_number": 3,
        "disc_number": 1,
        "tags": ["rock", "indie"],
        "upload_date": "20200101",
        "webpage_url": "https://band.bandcamp.com/track/song-three",
        "extractor": "Bandcamp",
    },
    "nico_video": {
        "title": "【初音ミク】曲名【オリジナル】",
        "uploader": "ボカロP",
        "tags": ["VOCALOID", "初音ミク"],
        "upload_date": "20110707",
        "description": "<b>説明</b>",
        "webpage_url": "https://www.nicovideo.jp/watch/sm9",
        "extractor": "niconico",
    },
    "tiktok_clip": {
        "title": "original sound - user123",
        "track": "Some Song",
        "artist": "Some Artist",
        "upload_date": "20240301",
        "webpage_url": "https://www.tiktok.com/@user/video/1",
        "extractor": "TikTok",
    },
}


# ---- 手で組み立てるもの ----


def crafted_inputs(cbr, vbr, stereo):
    """名前 → 中身のバイト列（タグを手で組み立てたもの）。"""
    jpg, jpg2, png = tiny_jpeg(1), tiny_jpeg(2), tiny_png()
    out = {}
    out.update(simple_inputs(cbr, vbr, stereo, jpg, png))
    out.update(frame_zoo_inputs(cbr, jpg, jpg2, png))
    out.update(broken_inputs(cbr, jpg))
    out.update(no_mpeg_inputs(cbr, vbr))
    return out


def simple_inputs(cbr, vbr, stereo, jpg, png):
    """タグ無し・v1 だけ・v2.4 の基本など。"""
    v1_full = v1(b"V1 Title", b"V1 Artist", b"V1 Album", b"1999", b"v1 comment", 7, 17)
    v24 = (
        f24("TIT2", u8("Title 24"))
        + f24("TPE1", u16("Artist 24"))
        + f24("TDRC", u8("2020-05-06"))
        + f24("TRCK", lat("3/10"))
        + f24("TCON", lat("(17)Rock"))
        + f24("TXXX", u8("key") + "value".encode() + b"\x00")
        + f24("COMM", b"\x03eng" + b"desc\x00" + "コメント".encode() + b"\x00")
        + f24("APIC", b"\x00image/png\x00\x03png\x00" + png)
        + f24("APIC", b"\x00image/jpeg\x00\x03\x00" + jpg)
    )
    return {
        "notag": cbr,
        "notag_vbr": vbr,
        "notag_stereo": stereo,
        "v1only": cbr + v1_full,
        "v1only_notrack": cbr + v1(b"T", b"A", b"", b"", b"c" * 30, None, 255),
        "v1only_empty": cbr + v1(),
        "v1_short": cbr + v1(b"Short", b"A", b"B", b"2", b"c", 2, 12)[:125],
        "v1_latin1": cbr + v1("Ünïcödé".encode("latin-1"), b"  pad  ", b"x\x00y", b"20a1", b"", 32, 200),
        "v24_basic": tag(4, v24, padding=100) + cbr + v1_full,
        "v24_basic_nov1": tag(4, v24, padding=0) + cbr,
        "v23_small_pad": tag(3, f23("TIT2", lat("Old")), padding=3) + cbr,
        "v23_big_pad": tag(3, f23("TIT2", lat("Old")), padding=20000) + cbr,
        "v24_ext_padding": tag(4, f24("TIT2", lat("Fits")), padding=1500) + cbr,
    }


def frame_zoo_inputs(cbr, jpg, jpg2, png):
    """いろいろな種類のフレーム（mutagen の全部の形に近いもの）。"""
    v23 = b"".join(
        [
            f23("TIT2", lat("Zoo")),
            f23("TPE1", u16("Ärtist 🎵")),
            f23("TALB", u16be("Album BE")),
            f23("TYER", lat("2001")),
            f23("TDAT", lat("0302")),
            f23("TIME", lat("0405")),
            f23("TORY", lat("1990")),
            f23("TCON", lat("17")),
            f23("TRDA", lat("x")),
            f23("TSIZ", lat("123")),
            f23("IPLS", b"\x00producer\x00Bob\x00mix\x00Al\x00"),
            f23("RVAD", b"\x03\x10\x00\x10\x00\x20"),
            f23("EQUA", b"\x10\x00\x01\x00\x02"),
            f23("USLT", b"\x00eng" + b"lyr\x00la la"),
            f23("SYLT", b"\x00eng\x02\x01desc\x00one\x00\x00\x00\x00\x10two\x00\x00\x00\x00\x20"),
            f23("ETCO", b"\x02\x01\x00\x00\x00\x10\x02\x00\x00\x00\x20"),
            f23("MLLT", b"\x00\x01\x00\x00\x02\x00\x00\x03\x08\x08\xaa"),
            f23("SYTC", b"\x01\x10\x20"),
            f23("PCNT", b"\x05"),
            f23("POPM", b"me@example.com\x00\xc8\x01\x02"),
            f23("GEOB", b"\x00text/plain\x00f.txt\x00obj\x00DATA"),
            f23("PRIV", b"owner\x00\x00\x01\x02"),
            f23("UFID", b"http://id\x00ID123"),
            f23("USER", b"\x00engterms"),
            f23("OWNE", b"\x00USD1.00\x0020200101Seller"),
            f23("COMR", b"\x00USD1\x0020301231http://c\x00\x01seller\x00desc\x00image/png\x00" + png[:20]),
            f23("ENCR", b"enc@x\x00\x81data"),
            f23("GRID", b"grp@x\x00\x82gdata"),
            f23("LINK", b"TIT2http://l\x00extra"),
            f23("POSS", b"\x02\x00\x01\x00"),
            f23("AENC", b"aenc@x\x00\x00\x01\x00\x02key"),
            f23("WCOM", b"http://shop/1"),
            f23("WCOM", b"http://shop/2"),
            f23("WOAR", b"http://artist"),
            f23("WXXX", b"\x00site\x00http://w"),
            f23("TXXX", lat("k1") + b"v1\x00"),
            f23("TXXX", lat("k1") + b"v2\x00"),
            f23("TXXX", u16("k2") + "v".encode("utf-16-le") + b"\x00\x00"),
            f23("COMM", b"\x00en" + b"\x00short lang"),
            f23("RBUF", b"\x00\x10\x00\x01\x00\x00\x00\x05"),
            f23("SEEK", b"\x00\x00\x00\x09"),
            f23("SIGN", b"\x81sig"),
            f23("PCST", b"\x00\x00\x00\x01"),
            f23("TBPM", lat("120")),
            f23("APIC", b"\x00image/jpeg\x00\x03cover\x00" + jpg),
            f23("APIC", b"\x00image/jpeg\x00\x04cover\x00" + jpg2),
            f23("APIC", b"\x00image/png\x00\x00\x00" + png),
            f23("XYZ1", b"unknown"),
        ]
    )
    v24 = b"".join(
        [
            f24("TIT2", u8("Zoo 24")),
            f24("TDRC", u8("2020-01-02T03:04:05")),
            f24("TDOR", lat("1999-12")),
            f24("TDRL", lat("2021")),
            f24("TCON", u8("(17)(18)Rock\x00((foo)\x00RX\x00CR\x00(RX)\x00255\x00٣\x00Rock\nPop\x00(99)")),
            f24("TIPL", u8("a") + b"b\x00c\x00"),
            f24("TMCL", u8("guitar") + b"Ann\x00"),
            f24("RVA2", b"track\x00\x01\xff\x00\x10\x7f\xff"),
            f24("EQU2", b"\x01eq\x00\x00\x10\x00\x20\x00\x10\x00\x30"),
            f24("ASPI", b"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x02\x08\x05\x06"),
            f24("MCDI", b"\x01\x02\x03"),
            f24(
                "CHAP",
                b"c1\x00\x00\x00\x00\x00\x00\x00\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff" + f24("TIT2", lat("Ch")),
            ),
            f24("CTOC", b"toc\x00\x03\x01c1\x00" + f24("TIT2", lat("TOC"))),
            f24("XYZ2", b"raw v24 unknown"),
            f24("abcd", b"invalid id"),
            f24("WOAF", b"http://file"),
            f24("TXXX", b"\x03" + "絵文字".encode() + b"\x00" + "😀𝔸".encode() + b"\x00"),
            f24("APIC", b"\x03image/jpeg\x00\x03" + "表紙".encode() + b"\x00" + jpg),
        ]
    )
    v22 = b"".join(
        [
            f22("TT2", lat("V22 Title")),
            f22("TP1", u16("V22 Artist")),
            f22("TAL", lat("V22 Album")),
            f22("TYE", lat("1985")),
            f22("TDA", lat("1112")),
            f22("TIM", lat("1314")),
            f22("TRK", lat("4")),
            f22("TCO", lat("(13)")),
            f22("COM", b"\x00eng\x00c22"),
            f22("ULT", b"\x00engd\x00lyrics"),
            f22("PIC", b"\x00JPG\x03jp\x00" + jpg),
            f22("PIC", b"\x00PNG\x00pn\x00" + png),
            f22("PIC", b"\x00GIF\x00gf\x00GIF89a"),
            f22("PIC", b"\x00JPG\x03jp\x00" + jpg2),
            f22("TXX", lat("k") + b"v\x00"),
            f22("WXX", b"\x00d\x00http://x"),
            f22("UFI", b"own\x00id"),
            f22("CNT", b"\x00\x00\x01\x00"),
            f22("POP", b"e@x\x00\x10"),
            f22("GEO", b"\x00m\x00f\x00d\x00xx"),
            f22("LNK", b"TT2http://a\x00"),
            f22("LNK", b"XYZhttp://b\x00"),
            f22("LNK", b"CRMhttp://c\x00"),
            f22("CRM", b"o\x00d\x00x"),
            f22("RVA", b"\x03\x10\x00\x10\x00\x20"),
            f22("BUF", b"\x00\x10\x00"),
            f22("ZZZ", b"unknown22"),
        ]
    )
    dups = b"".join(
        [
            f23("TIT2", lat("One")),
            f23("TIT2", u16("Two")),
            f23("TIT2", lat("One")),
            f23("APIC", b"\x00image/jpeg\x00\x03same\x00" + jpg),
            f23("APIC", b"\x00image/jpeg\x00\x03same\x00" + jpg2),
            f23("APIC", b"\x00image/jpeg\x00\x03same\x00" + jpg),
            f23("PRIV", b"o\x00a"),
            f23("PRIV", b"o\x00a"),
            f23("TDRC", lat("2001")),
            f23("TYER", lat("1999")),
            f23("TCON", lat("")),
        ]
    )
    nul_names = (
        b"TT2\x00" + struct.pack(">IH", 6, 0) + lat("nul!") + b"PIC\x00" + struct.pack(">IH", 6, 0) + b"\x00JPG\x03\x00"
    )
    nul_names += b"CRM\x00" + struct.pack(">IH", 3, 0) + b"a\x00b" + b"QQQ\x00" + struct.pack(">IH", 1, 0) + b"z"
    timestamps = b"".join(
        [
            f23("TYER", lat("2020")),
            f23("TYER", lat("2021")),
            f23("TDAT", lat("3112")),
            f23("TIME", lat("2359")),
        ]
    )
    stamps24 = f24("TDRC", u8("2020-1-2\x0020201\x00abcd\x002020 01\x00+2020\x002_020\x00２０２０\x00-5\x00"))
    stamps24 += f24("TDEN", lat("2020-01-02T03:04:05.6")) + f24("TDTG", lat(""))
    return {
        "zoo_v23": tag(3, v23, padding=64) + cbr + v1(b"V1", b"V1A", b"", b"2002", b"", 1, 2),
        "zoo_v24": tag(4, v24, padding=64) + cbr,
        "zoo_v22": tag(2, v22, padding=16) + cbr,
        "dups_v23": tag(3, dups) + cbr,
        "nul_names_v23": tag(3, nul_names) + cbr,
        "stamps_v23": tag(3, timestamps) + cbr,
        "stamps_v23_odd": tag(3, f23("TYER", lat("20")) + f23("TYER", lat("2020-03-04")) + f23("TDAT", lat("1"))) + cbr,
        "stamps_v24": tag(4, stamps24) + cbr,
        "long_text": tag(3, f23("TIT2", u16("長い" * 300)) + f23("TXXX", lat("d") + b"x" * 5000 + b"\x00")) + cbr,
        "big_apic": tag(4, f24("APIC", b"\x00image/jpeg\x00\x03\x00" + jpg + bytes(range(256)) * 12)) + cbr,
        "nonbmp_v23": tag(3, f23("TIT2", u16("😀🎶𝔘𝔫𝔦")) + f23("TPE1", u16("𠮷野家"))) + cbr,
        "nonbmp_v24": tag(4, f24("TIT2", u8("😀🎶𝔘𝔫𝔦")) + f24("TPE1", u16be("𠮷野家"))) + cbr,
        "utf16_fixups": tag(
            3,
            f23("TIT2", b"\x01\xff\xfeA\x00B")
            + f23("TPE1", b"\x01" + "noBOM".encode("utf-16-le"))
            + f23("TALB", b"\x01\xff\xfe\x00\xd8\x41\x00\x00\x00")
            + f23("TCOM", b"\x02\x00A\x00")
            + f23("TEXT", b"\x01\xfe\xff\x00B\x00C\x00\x00"),
        )
        + cbr,
        "latin1_high": tag(3, f23("TPE1", b"\x00\xe9\xe0\xff") + f23("TALB", u16("日本語アルバム"))) + cbr + v1(b"x"),
    }


def unsynch_encode(value):
    """mutagen の `unsynch.encode`（0xFF のあとに 0x00 を挟む）。"""
    fragments = bytearray(value).split(b"\xff")
    for f in fragments[1:]:
        if (not f) or (f[0] >= 0xE0) or (f[0] == 0x00):
            f.insert(0, 0x00)
    return bytes(bytearray(b"\xff").join(fragments))


def compressed_frame23(data, flags=0x0080, raw=None):
    """v2.3 の圧縮フレームの中身（元の長さの 4 バイトと zlib）。"""
    body = raw if raw is not None else zlib.compress(data)
    return struct.pack(">I", len(data)) + body


def broken_inputs(cbr, jpg):
    """壊れたタグ・変わった印のあるタグ。"""
    unsynced = b"\x00image/jpeg\x00\x03\x00" + b"\xff\xe0\xff\x00ab\xff"
    title24 = lat("unsync24")
    escaped24 = b"\x00a\xff\x00\xe0b\x00"
    datalen24 = struct.pack(">I", len(title24)) + title24
    v24_flags = f24("TIT2", escaped24, flags=0x0002) + f24("TPE1", datalen24, flags=0x0001)
    v24_flags += f24("TALB", struct.pack(">I", 6) + zlib.compress(lat("zlib")), flags=0x0009)
    v24_flags += f24("TCOM", zlib.compress(lat("nolen")), flags=0x0008)
    v24_flags += f24("TEXT", b"bad zlib", flags=0x0008)
    v24_flags += f24("TOLY", lat("enc"), flags=0x0004)
    v23_flags = f23("TIT2", compressed_frame23(lat("zlib23")), flags=0x0080)
    v23_flags += f23("TPE1", compressed_frame23(lat("x"), raw=b"garbage"), flags=0x0080)
    v23_flags += f23("TALB", b"\x00\x00", flags=0x0080)
    v23_flags += f23("TCOM", compressed_frame23(lat("tail"), raw=zlib.compress(lat("tail")) + b"extra"), flags=0x0080)
    v23_flags += f23("TEXT", lat("encrypted"), flags=0x0040)
    v23_flags += f23("TOLY", lat("grouped"), flags=0x0020)
    junk = b"".join(
        [
            f23("TIT2", b"\x05bad encoding\x00"),
            f23("TPE1", b"\x01"),
            f23("TALB", b"\x00"),
            f23("APIC", b"\x00"),
            f23("COMM", b"\x00e\xffg"),
            f23("TXXX", b"\x03\xff\xfe\x00"),
            f23("USLT", b"\x00eng\x00"),
            f23("TCOM", b""),
            b"T\xe9ST" + struct.pack(">IH", 2, 0) + b"\x00x",
            f23("TIT3", lat("after junk")),
            f23("ASPI", b"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x05\x07"),
            f23("RVA2", b"d\x00\x01\x00\x10"),
            f23("SYLT", b"\x00eng\x01\x01\x00no time"),
        ]
    )
    ext23 = b"\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00"
    ext24 = syncsafe(6) + b"\x01\x00"
    frames_int = f24("TXXX", lat("big") + b"y" * 200 + b"\x00", plain_size=True) + f24(
        "TIT2", lat("int sizes"), plain_size=True
    )
    footer = tag(4, f24("TIT2", lat("footer")), flags=0x10)
    two = tag(3, f23("TIT2", lat("first"))) + tag(3, f23("TIT2", lat("second"))) + cbr
    ape = cbr + b"APETAGEX" + b"\x00" * 24 + b"APETAGEX" + b"\xd0\x07\x00\x00" + b"\x00" * 20
    return {
        "unsync_v23": tag(3, unsynch_encode(f23("APIC", unsynced) + f23("TIT2", lat("u\xfft"))), flags=0x80) + cbr,
        "unsync_v24_frames": tag(4, v24_flags) + cbr,
        "unsync_v24_header": tag(4, f24("TIT2", b"\x00h\xff\x00\xe0\x00"), flags=0x80) + cbr,
        "flags_v23": tag(3, v23_flags) + cbr,
        "junk_v23": tag(3, junk) + cbr,
        "fatal_rva2_v24": tag(4, f24("TIT2", lat("x")) + f24("RVA2", b"d\x00\x01\x10")) + cbr,
        "ext_v23": tag(3, ext23 + f23("TIT2", lat("ext23")), flags=0x40) + cbr,
        "ext_v24": tag(4, ext24 + f24("TIT2", lat("ext24")), flags=0x40) + cbr,
        "ext_is_frame_v23": tag(3, f23("TIT2", lat("not ext")), flags=0x40) + cbr,
        "ext_negative_v24": tag(4, syncsafe(2) + f24("TIT2", lat("neg")), flags=0x40) + cbr,
        "ext_huge_v23": tag(3, b"\x00\x10\x00\x00" + f23("TIT2", lat("huge")), flags=0x40) + cbr,
        "int_sizes_v24": tag(4, frames_int) + cbr,
        "footer_v24": footer + b"3DI\x04\x00\x10" + footer[6:10] + cbr,
        "two_tags": two,
        "ape_tag": ape,
        "badflags_v24": tag(4, f24("TIT2", lat("x")), flags=0x01) + cbr,
        "badflags_v23": tag(3, f23("TIT2", lat("x")), flags=0x10) + cbr,
        "bad_synchsafe": b"ID3\x03\x00\x00\x00\x00\x00\x8f" + f23("TIT2", lat("x")) + cbr,
        "truncated_tag": tag(3, f23("TIT2", lat("x")), size=100000) + cbr,
        "v25_with_v1": b"ID3\x05\x00\x00\x00\x00\x00\x10" + b"\x00" * 16 + cbr + v1(b"V25", b"A"),
        "v25_no_v1": b"ID3\x05\x00\x00\x00\x00\x00\x10" + b"\x00" * 16 + cbr,
        "v22_flag40": tag(2, f22("TT2", lat("x")), flags=0x40) + cbr,
        "frame_overflow_v23": tag(3, f23("TIT2", lat("ok")) + b"TPE1" + struct.pack(">IH", 9999, 0) + b"\x00abc") + cbr,
        "zero_size_frames_v24": tag(4, f24("TIT2", b"") + f24("TPE1", lat("after zero"))) + cbr,
    }


def no_mpeg_inputs(cbr, vbr):
    """MPEG のフレームが見つからない（か、ぎりぎり見つかる）もの。"""
    rnd = random.Random(10)
    first = frame_at(cbr, 0)
    second = frame_at(cbr, len(first))
    xing_first = frame_at(vbr, 0)
    vbri = bytearray(first)
    # VBRI の頭（版 1・目次 0 件・目次の 1 件 2 バイト）。Xing の位置（13）には何も無い。
    vbri[36:62] = b"VBRI\x00\x01" + bytes(14) + b"\x00\x00\x00\x02\x00\x00"
    assert len(vbri) == len(first)
    return {
        "empty": b"",
        "text_file": "これは MP3 ではない。ただの文。\n".encode() * 20,
        "id3_then_zeros": tag(3, f23("TIT2", lat("zeros"))) + b"\x00" * 2000,
        "random_bytes": bytes(rnd.randrange(256) for _ in range(3000)).replace(b"\xff", b"\x00"),
        "one_frame": tag(3, f23("TIT2", lat("one"))) + first,
        "two_frames": tag(3, f23("TIT2", lat("two"))) + first + second,
        "one_xing_frame": tag(3, f23("TIT2", lat("xing"))) + xing_first,
        "one_vbri_frame": tag(3, f23("TIT2", lat("vbri"))) + bytes(vbri) + b"\x00" * 64,
        "sync_garbage_then_audio": tag(3, f23("TIT2", lat("g"))) + b"\xff\xe0\xff\xfb\x00" * 5 + cbr,
    }


def frame_at(data, offset):
    """MPEG のフレーム 1 つ分のバイト列（頭から長さを計算して切り出す）。"""
    head = struct.unpack(">I", data[offset : offset + 4])[0]
    version = (head >> 19) & 3
    bitrate_index = (head >> 12) & 0xF
    rate_index = (head >> 10) & 3
    padding = (head >> 9) & 1
    rates = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}[version]
    if version == 3:
        bitrate = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320][bitrate_index] * 1000
        size = 1152 // 8 * bitrate // rates[rate_index] + padding
    else:
        bitrate = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160][bitrate_index] * 1000
        size = 576 // 8 * bitrate // rates[rate_index] + padding
    return data[offset : offset + size]


def make_all(out_dir):
    """入力の MP3 を全部作り、名前の一覧と、テストで使う画像（base64）を返す。"""
    os.makedirs(out_dir, exist_ok=True)
    for name, info in YTDLP_INPUTS.items():
        ytdlp_file(f"{out_dir}/{name}.mp3", info, thumb_ext="jpg" if name == "sc_track" else "webp")
    cbr, vbr, stereo = audio("cbr"), audio("vbr"), audio("stereo")
    for name, data in crafted_inputs(cbr, vbr, stereo).items():
        with open(f"{out_dir}/{name}.mp3", "wb") as f:
            f.write(data)
    images = {
        "jpeg": base64.b64encode(tiny_jpeg(3)).decode(),
        "jpeg2": base64.b64encode(tiny_jpeg(4)).decode(),
        "png": base64.b64encode(tiny_png()).decode(),
    }
    return sorted(n[:-4] for n in os.listdir(out_dir) if n.endswith(".mp3")), images
