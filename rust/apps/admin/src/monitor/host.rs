//! ホストの CPU・メモリ・起動の時刻・論理コアの数。Python の `collect_host_metrics` が psutil 7.2.2 から読むもの
//! （`psutil.cpu_percent(interval=0.1)`・`virtual_memory()`・`boot_time()`・`cpu_count(logical=True)`）を、
//! psutil の Linux の実装（`psutil/_pslinux.py` と `psutil/__init__.py`）と同じ読み方・同じ計算で写した。
//!
//! - CPU: `/proc/stat` の 1 行目を 0.1 秒あけて 2 回読み、項目ごとの差（負は 0）から「忙しかった割合」を出して小数
//!   1 桁に丸める。合計は Python の `sum()`（Neumaier）で、guest・guest_nice は user・nice に含まれるので引く。
//!   忙しくない時間は idle と iowait。**0.1 秒の待ちは tokio の sleep**（Python はイベントループごと止めていた）
//! - メモリ: `/proc/meminfo` の `MemAvailable`（無いか 0 なら `/proc/zoneinfo` の low の水位から見積もる）。
//!   使用中 = 合計 − 使える量、割合は小数 1 桁
//! - 起動の時刻: `/proc/stat` の `btime`
//! - 論理コアの数: psutil は `os.sysconf("SC_NPROCESSORS_ONLN")`（glibc が `/sys/devices/system/cpu/online` を
//!   読む）。Rust は同じファイルを読み、読めなければ `/proc/stat` の `cpuN` の行を数える（基準では確かめられない。
//!   画面の「論理コア N」にだけ出る）
//!
//! 1 秒あたりの刻み（`SC_CLK_TCK`）は 100、ページの大きさは 4096 に決め打ちにしている（x86_64 と arm64 の Linux の
//! 値。CPU の割合は比なので、刻みの数は丸めの手前の浮動小数の誤差にしか響かない）。
//!
//! 読み方の突き合わせは基準 `tests/fixtures/monitor/` の procfs（偽物の `/proc` を psutil の `PROCFS_PATH` に向けて
//! 読ませた答え）。

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use crate::errors::Crash;
use crate::monitor::pyfloat;

/// `/proc/stat` の時間の単位（1 秒あたりの刻み）。psutil の `CLOCK_TICKS`（`os.sysconf("SC_CLK_TCK")`）。
pub const CLOCK_TICKS: f64 = 100.0;
/// ページの大きさ（バイト）。psutil の `PAGESIZE`。
pub const PAGE_SIZE: i64 = 4096;
/// CPU を測る間（`cpu_percent(interval=0.1)`）。
pub const CPU_SAMPLE: Duration = Duration::from_millis(100);

/// `virtual_memory()` のうち、画面が使うもの。
#[derive(Clone, Debug, PartialEq)]
pub struct Memory {
    /// 合計（バイト）。
    pub total: i64,
    /// 使用中（合計 − 使える量）。
    pub used: i64,
    /// 使用中の割合（小数 1 桁に丸めたもの）。
    pub percent: f64,
}

/// `collect_host_metrics` が psutil から読むもの一式。
#[derive(Clone, Debug, PartialEq)]
pub struct HostSample {
    /// `cpu_percent(interval=0.1)`。
    pub cpu_percent: f64,
    /// `virtual_memory()`。
    pub memory: Memory,
    /// `cpu_count(logical=True)`（分からなければ `None`。画面は 1 にする）。
    pub cpu_count: Option<u64>,
    /// `boot_time()`（UNIX 時間の秒）。
    pub boot_time: f64,
}

/// [`HostProbe::sample`] の future。
pub type SampleFuture<'a> = Pin<Box<dyn Future<Output = Result<HostSample, Crash>> + Send + 'a>>;

/// ホストを測る口（本番は [`ProcFs`]。テストは決まった値を返す偽物）。
pub trait HostProbe: Send + Sync {
    /// 1 回測る（CPU のために 0.1 秒待つ）。読めなければ Python の例外にあたる [`Crash`]。
    fn sample(&self) -> SampleFuture<'_>;
}

/// `/proc`（と `/sys/devices/system/cpu/online`）を読んで測る。
#[derive(Clone, Debug)]
pub struct ProcFs {
    proc_dir: PathBuf,
    cpu_online: PathBuf,
}

impl ProcFs {
    /// このホストの `/proc` を読む。
    pub fn system() -> Self {
        Self::new("/proc", "/sys/devices/system/cpu/online")
    }

    /// 置き場を指定して作る（テストで偽物の `/proc` を読ませる。psutil の `PROCFS_PATH`）。
    pub fn new(proc_dir: impl Into<PathBuf>, cpu_online: impl Into<PathBuf>) -> Self {
        Self {
            proc_dir: proc_dir.into(),
            cpu_online: cpu_online.into(),
        }
    }

    fn read(&self, name: &str) -> Result<String, Crash> {
        read_text(&self.proc_dir.join(name))
    }

    /// `cpu_times()`（1 行目の項目を刻みで割ったもの）。
    pub fn cpu_times(&self) -> Result<Vec<f64>, Crash> {
        parse_cpu_times(&self.read("stat")?)
    }

    /// `virtual_memory()`。
    pub fn virtual_memory(&self) -> Result<Memory, Crash> {
        let meminfo = self.read("meminfo")?;
        let zoneinfo = std::fs::read(self.proc_dir.join("zoneinfo"))
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        virtual_memory(&meminfo, zoneinfo.as_deref())
    }

    /// `boot_time()`。
    pub fn boot_time(&self) -> Result<f64, Crash> {
        boot_time(&self.read("stat")?)
    }

    /// `cpu_count(logical=True)`。
    pub fn cpu_count(&self) -> Option<u64> {
        if let Ok(online) = std::fs::read_to_string(&self.cpu_online)
            && let Some(count) = parse_cpu_list(&online)
        {
            return Some(count);
        }
        let stat = self.read("stat").ok()?;
        let count = stat
            .lines()
            .filter(|line| {
                let name = line.split(' ').next().unwrap_or("");
                name.strip_prefix("cpu")
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            })
            .count() as u64;
        (count > 0).then_some(count)
    }
}

impl HostProbe for ProcFs {
    fn sample(&self) -> SampleFuture<'_> {
        Box::pin(async move {
            let first = self.cpu_times()?;
            tokio::time::sleep(CPU_SAMPLE).await;
            let second = self.cpu_times()?;
            let cpu_percent = cpu_percent(&first, &second);
            let memory = self.virtual_memory()?;
            let boot_time = self.boot_time()?;
            Ok(HostSample {
                cpu_percent,
                memory,
                cpu_count: self.cpu_count(),
                boot_time,
            })
        })
    }
}

/// ファイルを読めないときの Python の例外の名前（`open()` が出すもの）。
pub fn os_error(error: &std::io::Error, path: &Path) -> Crash {
    use std::io::ErrorKind;
    let kind = match error.kind() {
        ErrorKind::NotFound => "FileNotFoundError",
        ErrorKind::PermissionDenied => "PermissionError",
        ErrorKind::IsADirectory => "IsADirectoryError",
        ErrorKind::NotADirectory => "NotADirectoryError",
        _ => "OSError",
    };
    Crash::new(kind, format!("{error}: '{}'", path.display()))
}

/// バイトのまま読んで文字にする（psutil は `open_binary` で読む。中身は ASCII）。
fn read_text(path: &Path) -> Result<String, Crash> {
    let bytes = std::fs::read(path).map_err(|e| os_error(&e, path))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Python の `bytes.split()`（空白は ASCII の 6 つ: 空白・`\t`・`\n`・`\r`・`\x0b`・`\x0c`。空の項目は作らない）。
fn split_fields(line: &str) -> Vec<&str> {
    line.split([' ', '\t', '\n', '\r', '\u{b}', '\u{c}'])
        .filter(|field| !field.is_empty())
        .collect()
}

/// Python の `bytes.strip()`（[`split_fields`] と同じ 6 つの空白）。
fn strip_fields(line: &str) -> &str {
    line.trim_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}'])
}

/// Python の `int(bytes)`（10 進。符号と、数字の間の `_` を 1 つずつ許す）。読めなければ `ValueError`。
fn int_field(text: &str) -> Result<i64, Crash> {
    let invalid = || {
        Crash::new(
            "ValueError",
            format!("invalid literal for int() with base 10: b'{text}'"),
        )
    };
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return Err(invalid());
    }
    let value: i64 = digits.replace('_', "").parse().map_err(|_| invalid())?;
    Ok(if negative { -value } else { value })
}

/// Python の `float(bytes)`。
fn float_field(text: &str) -> Result<f64, Crash> {
    pyfloat::py_float(text).ok_or_else(|| {
        Crash::new(
            "ValueError",
            format!("could not convert string to float: b'{text}'"),
        )
    })
}

/// 1 行ずつ（Python のバイナリのファイルを `for line in f` で回したときの行。`\n` を含む。最後の行は `\n` が無くてもよい）。
fn lines_of(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

/// `cpu_times()`。`/proc/stat` の 1 行目の、`cpu` のあとの項目を刻みで割る。
///
/// 項目の数は psutil と同じく、7 つ（user〜softirq）に、8 つ目があれば steal、9 つ目で guest、10 個目で guest_nice を
/// 足したもの（それより後ろは読まない）。7 つに満たなければ読めない。
pub fn parse_cpu_times(stat: &str) -> Result<Vec<f64>, Crash> {
    let first = lines_of(stat).next().unwrap_or("");
    let values = split_fields(first);
    let count = values.len().saturating_sub(1);
    let fields = 7 + usize::from(count >= 8) + usize::from(count >= 9) + usize::from(count >= 10);
    if count < fields {
        return Err(Crash::new(
            "TypeError",
            format!("scputimes の項目が足りない（{count} 個）"),
        ));
    }
    values[1..=fields]
        .iter()
        .map(|value| Ok(float_field(value)? / CLOCK_TICKS))
        .collect()
}

/// CPU の時間の合計（`_cpu_tot_time`。guest と guest_nice は user・nice に含まれるので引く）。
fn total_time(times: &[f64]) -> f64 {
    let mut total = pyfloat::pysum(times);
    if let Some(guest) = times.get(8) {
        total -= guest;
    }
    if let Some(guest_nice) = times.get(9) {
        total -= guest_nice;
    }
    total
}

/// `cpu_percent` の `calculate(t1, t2)`。項目ごとの差（負は 0）の合計のうち、idle・iowait 以外の割合（小数 1 桁）。
/// 合計が 0 なら 0.0。
pub fn cpu_percent(first: &[f64], second: &[f64]) -> f64 {
    let deltas: Vec<f64> = first
        .iter()
        .zip(second)
        .map(|(a, b)| {
            let delta = b - a;
            if delta > 0.0 { delta } else { 0.0 }
        })
        .collect();
    let all = total_time(&deltas);
    let mut busy = total_time(&deltas);
    busy -= deltas.get(3).copied().unwrap_or(0.0);
    busy -= deltas.get(4).copied().unwrap_or(0.0);
    if all == 0.0 {
        return 0.0;
    }
    pyfloat::round((busy / all) * 100.0, 1)
}

/// `/proc/meminfo` を読む（`{名前: 値 × 1024}`。名前は `MemTotal:` のように `:` まで。同じ名前はあとのもの）。
fn meminfo_values(meminfo: &str) -> Result<HashMap<String, i64>, Crash> {
    let mut values = HashMap::new();
    for line in lines_of(meminfo) {
        let fields = split_fields(line);
        let (Some(name), Some(value)) = (fields.first(), fields.get(1)) else {
            return Err(Crash::new("IndexError", "list index out of range"));
        };
        values.insert((*name).to_string(), int_field(value)? * 1024);
    }
    Ok(values)
}

/// `virtual_memory()`（psutil 7.2.2 の `_pslinux.virtual_memory`）。`MemTotal`・`MemFree` が無ければ `KeyError`。
pub fn virtual_memory(meminfo: &str, zoneinfo: Option<&str>) -> Result<Memory, Crash> {
    let mems = meminfo_values(meminfo)?;
    let required = |name: &str| {
        mems.get(name)
            .copied()
            .ok_or_else(|| Crash::new("KeyError", format!("b'{name}'")))
    };
    let total = required("MemTotal:")?;
    let free = required("MemFree:")?;
    let mut avail = match mems.get("MemAvailable:").copied() {
        None | Some(0) => calculate_avail(&mems, free, zoneinfo)?,
        Some(avail) => avail,
    };
    if avail < 0 {
        avail = 0;
    } else if avail > total {
        avail = free;
    }
    let used = total - avail;
    let percent = if total == 0 {
        0.0
    } else {
        pyfloat::round(((total - avail) as f64 / total as f64) * 100.0, 1)
    };
    Ok(Memory {
        total,
        used,
        percent,
    })
}

/// `calculate_avail_vmem`（`MemAvailable` が無いか 0 のときの見積もり）。`Active(file)`・`Inactive(file)`・
/// `SReclaimable` のどれかが無いか、`/proc/zoneinfo` が読めなければ `MemFree + Cached`。
fn calculate_avail(
    mems: &HashMap<String, i64>,
    free: i64,
    zoneinfo: Option<&str>,
) -> Result<i64, Crash> {
    let fallback = free + mems.get("Cached:").copied().unwrap_or(0);
    let (Some(active), Some(inactive), Some(slab)) = (
        mems.get("Active(file):").copied(),
        mems.get("Inactive(file):").copied(),
        mems.get("SReclaimable:").copied(),
    ) else {
        return Ok(fallback);
    };
    let Some(zoneinfo) = zoneinfo else {
        return Ok(fallback);
    };
    let mut low: i64 = 0;
    for line in lines_of(zoneinfo) {
        let line = strip_fields(line);
        if line.starts_with("low") {
            let fields = split_fields(line);
            let Some(value) = fields.get(1) else {
                return Err(Crash::new("IndexError", "list index out of range"));
            };
            low += int_field(value)?;
        }
    }
    let low = (low * PAGE_SIZE) as f64;
    // Python は int と float が混ざる計算だが、どれも 2^53 より小さいので f64 で同じ値になる。
    let mut avail = free as f64 - low;
    let mut pagecache = (active + inactive) as f64;
    pagecache -= pyfloat::py_min(pagecache / 2.0, low);
    avail += pagecache;
    let slab = slab as f64;
    avail += slab - pyfloat::py_min(slab / 2.0, low);
    Ok(pyfloat::trunc(avail))
}

/// `boot_time()`（`btime` で始まる最初の行の 2 つ目の項目）。無ければ `RuntimeError`。
pub fn boot_time(stat: &str) -> Result<f64, Crash> {
    for line in lines_of(stat) {
        if line.starts_with("btime") {
            let fields = split_fields(strip_fields(line));
            let Some(value) = fields.get(1) else {
                return Err(Crash::new("IndexError", "list index out of range"));
            };
            return float_field(value);
        }
    }
    Err(Crash::new(
        "RuntimeError",
        "line 'btime' not found in /proc/stat",
    ))
}

/// `/sys/devices/system/cpu/online` の書き方（`0-7` や `0,2-5`）から、CPU の数を数える。
fn parse_cpu_list(text: &str) -> Option<u64> {
    let mut count = 0u64;
    for part in text.trim().split(',') {
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (start.parse::<u64>().ok()?, end.parse::<u64>().ok()?),
            None => {
                let single = part.parse::<u64>().ok()?;
                (single, single)
            }
        };
        if end < start {
            return None;
        }
        count += end - start + 1;
    }
    (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 差が負の項目は 0 にし、guest は合計から引き、idle と iowait は忙しくない時間に数えること。
    #[test]
    fn cpu_percent_follows_psutil() {
        let first = parse_cpu_times("cpu  100 0 100 800 0 0 0 0 0 0\n").unwrap();
        let second = parse_cpu_times("cpu  150 0 150 850 50 0 0 0 0 0\n").unwrap();
        // 忙しい 100、合計 200 → 50.0。
        assert_eq!(cpu_percent(&first, &second), 50.0);
        assert_eq!(cpu_percent(&first, &first), 0.0);
        let guest_first = parse_cpu_times("cpu 0 0 0 0 0 0 0 0 0 0").unwrap();
        let guest_second = parse_cpu_times("cpu 30 0 0 70 0 0 0 0 10 0").unwrap();
        // 合計 110 − guest 10 = 100、忙しい 30 → 30.0。
        assert_eq!(cpu_percent(&guest_first, &guest_second), 30.0);
        assert!(parse_cpu_times("cpu 1 2 3\n").is_err());
    }

    /// MemAvailable を使い、無ければ zoneinfo の水位から見積もること。
    #[test]
    fn memory_follows_psutil() {
        let meminfo = "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n";
        let memory = virtual_memory(meminfo, None).unwrap();
        assert_eq!(memory.total, 1_024_000);
        assert_eq!(memory.used, 750 * 1024);
        assert_eq!(memory.percent, 75.0);
        let without = "MemTotal: 1000 kB\nMemFree: 100 kB\nCached: 50 kB\n";
        assert_eq!(virtual_memory(without, None).unwrap().used, 850 * 1024);
        assert_eq!(
            virtual_memory("MemFree: 1 kB\n", None).unwrap_err().kind,
            "KeyError"
        );
        assert_eq!(
            virtual_memory("MemTotal: 1 kB\n\n", None).unwrap_err().kind,
            "IndexError"
        );
    }

    /// 起動の時刻と、CPU の一覧の数え方。
    #[test]
    fn boot_time_and_cpu_list() {
        assert_eq!(
            boot_time("cpu 1\nbtime 1798000000\n").unwrap(),
            1_798_000_000.0
        );
        assert_eq!(boot_time("cpu 1\n").unwrap_err().kind, "RuntimeError");
        assert_eq!(parse_cpu_list("0-7\n"), Some(8));
        assert_eq!(parse_cpu_list("0,2-5"), Some(5));
        assert_eq!(parse_cpu_list(""), None);
    }
}
