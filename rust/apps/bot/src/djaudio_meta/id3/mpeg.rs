//! mutagen 1.48.1 の `MPEGInfo` のうち、「MPEG のフレームが見つかるか」の判定（`mutagen/mp3/__init__.py`）。
//!
//! `MP3(path)` は、ID3 のあとから同期の印（0xFF のあとに上位 3 ビットが立ったバイト）を探し、そこから MPEG の
//! フレームの頭を読む。続けて 2 つ以上読めるか、Xing・VBRI の頭のある 1 つが読めれば成功、どこからも読めなければ
//! HeaderNotFoundError（`_write_tags` は例外で失敗）。長さ・ビットレートなどの値は使わないので求めない。

/// 探しはじめの位置から読む上限（`max_read`）。
const MAX_READ: usize = 1024 * 1024;
/// 試す同期の印の数の上限（`max_syncs`）。
const MAX_SYNCS: usize = 1500;

/// 1 つの MPEG のフレームの頭（`MPEGFrame`）を読んだ結果。
struct FrameHead {
    /// 次のフレームの位置。
    next: usize,
    /// Xing・VBRI の頭が無い（mutagen の `sketchy`）。
    sketchy: bool,
}

fn read_at(data: &[u8], pos: usize, len: usize) -> &[u8] {
    let start = pos.min(data.len());
    let end = pos.saturating_add(len).min(data.len());
    &data[start..end]
}

/// `MPEGFrame(fileobj)`。読めなければ None（HeaderNotFoundError）。
fn read_frame(data: &[u8], pos: usize) -> Option<FrameHead> {
    let head = read_at(data, pos, 4);
    if head.len() < 4 {
        return None;
    }
    let bits = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if bits >> 21 != 0x7FF {
        return None;
    }
    let version = (bits >> 19) & 3;
    let layer = (bits >> 17) & 3;
    let bitrate_index = ((bits >> 12) & 0xF) as usize;
    let sample_rate_index = ((bits >> 10) & 3) as usize;
    let padding = u64::from((bits >> 9) & 1);
    let mode = (bits >> 6) & 3;
    if version == 1
        || layer == 0
        || sample_rate_index == 3
        || bitrate_index == 0xF
        || bitrate_index == 0
    {
        return None;
    }
    // version: 0 → 2.5、2 → 2、3 → 1。layer: 3 → 1、2 → 2、1 → 3。
    let mpeg1 = version == 3;
    let layer = 4 - layer;
    const V1: [[u64; 15]; 3] = [
        [
            0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
        ],
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
        ],
        [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
        ],
    ];
    const V2: [[u64; 15]; 2] = [
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
        ],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ];
    let bitrate = 1000
        * if mpeg1 {
            V1[(layer - 1) as usize][bitrate_index]
        } else {
            V2[if layer == 1 { 0 } else { 1 }][bitrate_index]
        };
    let sample_rate: u64 = match version {
        3 => [44100, 48000, 32000][sample_rate_index],
        2 => [22050, 24000, 16000][sample_rate_index],
        _ => [11025, 12000, 8000][sample_rate_index],
    };
    let (frame_size, slot): (u64, u64) = if layer == 1 {
        (384, 4)
    } else if !mpeg1 && layer == 3 {
        (576, 1)
    } else {
        (1152, 1)
    };
    let frame_length = ((frame_size / 8 * bitrate) / sample_rate + padding) * slot;
    let mut sketchy = true;
    if layer == 3 {
        // XingHeader.get_offset
        let xing_offset = match (mpeg1, mode == 3) {
            (true, false) => 36,
            (true, true) => 21,
            (false, false) => 21,
            (false, true) => 13,
        };
        if xing_ok(data, pos + xing_offset) || vbri_ok(data, pos + 36) {
            sketchy = false;
        }
    }
    Some(FrameHead {
        next: pos + frame_length as usize,
        sketchy,
    })
}

/// `XingHeader(fileobj)` が成り立つか（LAME の頭の読み違いは握りつぶされるので見ない）。
fn xing_ok(data: &[u8], pos: usize) -> bool {
    let head = read_at(data, pos, 8);
    if head.len() != 8 || !(&head[..4] == b"Xing" || &head[..4] == b"Info") {
        return false;
    }
    let flags = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let mut at = pos + 8;
    for (bit, len) in [(1, 4), (2, 4), (4, 100), (8, 4)] {
        if flags & bit != 0 {
            if read_at(data, at, len).len() != len {
                return false;
            }
            at += len;
        }
    }
    true
}

/// `VBRIHeader(fileobj)` が成り立つか。
fn vbri_ok(data: &[u8], pos: usize) -> bool {
    let head = read_at(data, pos, 26);
    if head.len() != 26 || !head.starts_with(b"VBRI") {
        return false;
    }
    let u16_at = |i: usize| usize::from(u16::from_be_bytes([head[i], head[i + 1]]));
    if u16_at(4) != 1 {
        return false;
    }
    let entries = u16_at(18);
    let entry_size = u16_at(22);
    let toc_size = entry_size * entries;
    if read_at(data, pos + 26, toc_size).len() != toc_size {
        return false;
    }
    entry_size == 2 || entry_size == 4
}

/// `skip_id3`（続く ID3v2 のタグを飛ばす）。
fn skip_id3(data: &[u8], mut pos: usize) -> usize {
    loop {
        let head = read_at(data, pos, 10);
        if head.len() != 10 || &head[..3] != b"ID3" {
            return pos;
        }
        let size = head[6..10]
            .iter()
            .fold(0usize, |acc, b| (acc << 7) | usize::from(b & 0x7F));
        if size == 0 {
            return pos;
        }
        pos += 10 + size;
    }
}

/// `MPEGInfo(fileobj, offset)` が例外を出さないか。
pub(super) fn check(data: &[u8], offset: u64) -> Result<(), ()> {
    let start = skip_id3(data, usize::try_from(offset).unwrap_or(usize::MAX));
    // iter_sync: 0xFF のあとに 0xE0 の立ったバイトが続く位置を、前から順に（読む上限の中で）。
    let end = data.len().min(start.saturating_add(MAX_READ));
    let mut syncs_left = MAX_SYNCS;
    let mut first_found = false;
    let mut p = start;
    while p + 1 < end {
        if data[p] != 0xFF || data[p + 1] & 0xE0 != 0xE0 {
            p += 1;
            continue;
        }
        syncs_left -= 1;
        if syncs_left == 0 {
            break;
        }
        let mut count = 0;
        let mut last_sketchy = true;
        let mut at = p;
        for _ in 0..4 {
            let Some(frame) = read_frame(data, at) else {
                break;
            };
            count += 1;
            last_sketchy = frame.sketchy;
            at = frame.next;
            if !frame.sketchy {
                break;
            }
        }
        if count >= 2 {
            first_found = true;
        }
        if (count > 0 && !last_sketchy) || count >= 4 {
            return Ok(());
        }
        p += 1;
    }
    if first_found { Ok(()) } else { Err(()) }
}
