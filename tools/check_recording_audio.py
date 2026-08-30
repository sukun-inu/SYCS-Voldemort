#!/usr/bin/env python3
"""録音した音が「人の声のまま」かを確かめる。

    python tools/check_recording_audio.py
    python tools/check_recording_audio.py --images        # 目で見る用
    python tools/check_recording_audio.py <録音.mp3>      # 実物を測る

長さもトラック数も正しいのに中身が雑音になっている、という壊れ方が実際に
起きた。通ったかどうかでは分からないので、書き出した音の中身を測る。

指標は「周期性」。声は準周期的なので自己相関の山が立ち、雑音では立たない。
実測した分かれ方:

    正常                        0.60
    デコーダを2ストリームで共有  0.54
    20ms 断片を全体にわたり撹拌  0.52
    白色雑音                    0.13

つまりこの検査が捕まえるのは「音が雑音になった」ところまでで、順序の乱れ
程度の劣化までは分けられない。そこは目で見るしかないので --images を用意
している。

（スペクトル平坦度も試したが、mp3 のローパスに支配されて白色雑音でも 0.065
  にしかならず、声と区別できなかったので使っていない。）
"""

import argparse
import array
import math
import os
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="recaudio-"))
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="recaudio-cache-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")

import discord.opus as opus  # noqa: E402
import services.recording_service as rec  # noqa: E402
from config import DJAUDIO_FFMPEG_PATH  # noqa: E402

SR = rec.SAMPLE_RATE
FRAME_SAMPLES = 960  # 20ms
VOICE_LIMIT = 0.30  # これを下回ったら声として成立していない
WINDOW_SECONDS = 0.04
PITCH_LOW_HZ, PITCH_HIGH_HZ = 60, 400  # 人の声の高さ
_MAX_WINDOWS = 40  # 全部見ると遅い。散らして拾う。
_STRIDE = 4  # 自己相関を間引く

failures: list[str] = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"  [{'OK' if condition else 'NG'}] {label}" + (f"  ({extra})" if extra else ""))
    if not condition:
        failures.append(label)


# ── 測る ──────────────────────────────────────────────────────


def to_mono(path: Path) -> array.array:
    result = subprocess.run(
        [
            DJAUDIO_FFMPEG_PATH,
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(path),
            "-f",
            "s16le",
            "-ar",
            str(SR),
            "-ac",
            "1",
            "-",
        ],
        capture_output=True,
        timeout=300,
    )
    samples = array.array("h")
    samples.frombytes(result.stdout[: len(result.stdout) - len(result.stdout) % 2])
    return samples


def periodicity(samples: array.array) -> float:
    """鳴っている窓ごとの自己相関の山（0〜1）の中央値。

    声は準周期的なので山が立つ。雑音では立たない。
    """
    size = int(SR * WINDOW_SECONDS)
    low, high = SR // PITCH_HIGH_HZ, min(SR // PITCH_LOW_HZ, size - 1)
    starts = [s for s in range(0, max(1, len(samples) - size), size)]
    loud = []
    for start in starts:
        seg = samples[start : start + size]
        if sum(v * v for v in seg) >= size * (900**2):
            loud.append(start)
    if not loud:
        return float("nan")
    if len(loud) > _MAX_WINDOWS:  # 全体に散らして間引く
        step = len(loud) / _MAX_WINDOWS
        loud = [loud[int(i * step)] for i in range(_MAX_WINDOWS)]

    scores = []
    for start in loud:
        seg = samples[start : start + size]
        best = 0.0
        for lag in range(low, high):
            span = range(0, size - lag, _STRIDE)
            num = sum(seg[i] * seg[i + lag] for i in span)
            left = sum(seg[i] * seg[i] for i in span)
            right = sum(seg[i + lag] * seg[i + lag] for i in span)
            denom = math.sqrt(left * right) or 1.0
            best = max(best, num / denom)
        scores.append(best)
    return statistics.median(scores)


# ── 通す ──────────────────────────────────────────────────────


def speech_like(seconds: float = 5.0) -> bytes:
    """声に近い信号。倍音列にフォルマントの山谷があり、基本周波数が揺れる。

    正弦波1本では「基本周波数が保たれたか」しか見えず、声の構造が壊れて
    いても気づけない。発話の切れ目（無音区間）も入れる。
    """
    out = array.array("h")
    formants = ((700.0, 90.0, 1.0), (1220.0, 110.0, 0.55), (2600.0, 160.0, 0.30))
    for i in range(int(SR * seconds)):
        t = i / SR
        if 0.9 < t < 1.4 or 3.2 < t < 3.8:
            out.append(0)
            out.append(0)
            continue
        f0 = 130.0 + 25.0 * math.sin(2 * math.pi * 0.7 * t)
        value = 0.0
        for harmonic in range(1, 40):
            freq = f0 * harmonic
            if freq > SR / 2:
                break
            gain = sum(w / (1.0 + ((freq - c) / bw) ** 2) for c, bw, w in formants)
            value += gain * math.sin(2 * math.pi * freq * t) / harmonic
        sample = max(-32000, min(32000, int(value * 5200)))
        out.append(sample)
        out.append(sample)
    return out.tobytes()


def encode(pcm: bytes) -> list[bytes]:
    encoder = opus.Encoder()
    step = FRAME_SAMPLES * 4
    return [encoder.encode(pcm[o : o + step], FRAME_SAMPLES) for o in range(0, len(pcm) - step + 1, step)]


def delivery_order(count: int, rng: random.Random) -> list[int]:
    """本番ログに出ていた乱れ方を再現する。

        8 packets were lost being flushed in decoder-24233
         --> (last=27692) [27696, 27691, 27700, 27693, 27694, 27695, ...]

    近い範囲で入れ替わり、いくつか落ちる。
    """
    order: list[int] = []
    index = 0
    while index < count:
        chunk = list(range(index, min(index + 9, count)))
        rng.shuffle(chunk)
        if len(chunk) > 5:
            chunk = chunk[:-1]
        order += chunk
        index += 9
    return order


class _Packet:
    def __init__(self, ssrc: int, sequence: int, timestamp: int):
        self.ssrc = ssrc
        self.sequence = sequence
        self.timestamp = timestamp


def record(frames: list[bytes], order: list[int]) -> tuple[Path, dict]:
    """sink をそのまま使って1本録る。"""
    from discord.ext.voice_recv.rtp import OPUS_SILENCE

    session = rec.RecordingSession(
        guild_id=999,
        channel_id=1,
        channel_name="VC",
        started_by_id=1,
        started_by_name="t",
        started_at=time.monotonic(),
        max_seconds=0,
        retention_days=1,
    )
    session.workdir = Path(tempfile.mkdtemp(prefix="recaudio-work-"))
    sink = rec._make_sink_class()(session)
    user = Mock()
    user.id = 1
    user.display_name = "A"
    ssrc, base_seq, base_ts = 24233, 27000, 5_000_000

    for n, idx in enumerate(order):
        packet = _Packet(ssrc, (base_seq + idx) % 65536, (base_ts + idx * FRAME_SAMPLES) % (2**32))
        data = Mock()
        data.packet = packet
        data.opus = frames[idx]
        sink.write(user, data)
        if n % 37 == 36:
            # 発話の切れ目に来る無音パケット（sequence は常に -1）
            for _ in range(5):
                silence = _Packet(ssrc, -1, (base_ts + idx * FRAME_SAMPLES) % (2**32))
                sdata = Mock()
                sdata.packet = silence
                sdata.opus = OPUS_SILENCE
                sink.write(user, sdata)

    sink.flush_pending()
    track = session.tracks[1]
    track.close(session.elapsed)
    stream = next(iter(sink._streams.values()))
    return track.out_path, {
        "failed": session.dropped_packets,
        "lost": stream.lost,
        "late": stream.late,
        "silence": stream.silence,
    }


def spectrogram(src: Path, dest: Path) -> Path:
    subprocess.run(
        [
            DJAUDIO_FFMPEG_PATH,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(src),
            "-lavfi",
            "showspectrumpic=s=860x340:mode=combined:color=intensity:scale=log:legend=1",
            str(dest),
        ],
        check=True,
        timeout=300,
    )
    return dest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("audio", nargs="?", help="実物の録音を測る（省略すると合成した声で通す）")
    parser.add_argument("--images", action="store_true", help="スペクトログラムも書き出す")
    args = parser.parse_args()

    tmp = Path(tempfile.gettempdir())

    # 実物を渡された場合は、それだけを測る
    if args.audio:
        path = Path(args.audio)
        if not path.exists():
            print(f"見つかりません: {path}")
            return 1
        score = periodicity(to_mono(path))
        print(f"{path.name}: 周期性 {score:.3f}")
        check("人の声として成立している", score >= VOICE_LIMIT, f"{score:.3f}（下限 {VOICE_LIMIT}）")
        if args.images:
            print("  スペクトログラム:", spectrogram(path, tmp / "recaudio-real.png"))
        print()
        print("RESULT:", "all passed" if not failures else "失敗")
        return 1 if failures else 0

    if not opus.is_loaded():
        try:
            opus._load_default()
        except Exception:
            print("libopus が読み込めない環境のためスキップします。")
            return 0

    source = speech_like()
    frames = encode(source)
    order = delivery_order(len(frames), random.Random(11))
    print(f"入力 {len(frames)} フレーム（5秒）/ 届く順序は本番ログと同じ乱れ方\n")

    out_mp3, counters = record(frames, order)
    print(
        f"  デコード失敗 {counters['failed']} / 欠落 {counters['lost']} / "
        f"手遅れ {counters['late']} / 無音 {counters['silence']}\n"
    )

    source_wav = tmp / "recaudio-input.wav"
    subprocess.run(
        [
            DJAUDIO_FFMPEG_PATH,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "s16le",
            "-ar",
            str(SR),
            "-ac",
            "2",
            "-i",
            "pipe:0",
            str(source_wav),
        ],
        input=source,
        check=True,
        timeout=300,
    )

    before = periodicity(to_mono(source_wav))
    after = periodicity(to_mono(out_mp3))

    check("元の信号が声として成立している（前提の確認）", before >= VOICE_LIMIT, f"周期性 {before:.3f}")
    check("録音した音が雑音になっていない", after >= VOICE_LIMIT, f"周期性 {after:.3f}（下限 {VOICE_LIMIT}）")
    check("元の信号から大きく崩れていない", after >= before * 0.6, f"入力 {before:.3f} → 出力 {after:.3f}")
    check(
        "欠落が入力の3割を超えていない", counters["lost"] <= len(frames) * 0.30, f"{counters['lost']} / {len(frames)}"
    )
    check("デコードに失敗していない", counters["failed"] == 0, str(counters["failed"]))

    if args.images:
        print()
        print("  入力:", spectrogram(source_wav, tmp / "recaudio-in.png"))
        print("  出力:", spectrogram(out_mp3, tmp / "recaudio-out.png"))

    print()
    print("RESULT:", "all passed" if not failures else f"{len(failures)} 件失敗: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
