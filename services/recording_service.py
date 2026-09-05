"""VC録音（Craig の代わり）。ユーザーごとに別トラックで録る。

仕組み:
  discord.py 本体に音声受信は無いので、discord-ext-voice-recv の
  VoiceRecvClient を使う。これは discord.VoiceClient のサブクラスで送信
  （読み上げ）と受信（録音）を同時に持てるため、接続は services/voice_session.py
  で TTS と共有する。録音中は voice_session の hold を立て、TTS 側の
  「VCが空になったら切る」で接続ごと落とされないようにする。

トラックの作り方:
  受信できるのは「誰かが喋っているあいだの音声パケット」だけで、黙っている
  あいだは何も来ない。素直に繋ぐと無音が詰まってトラック同士がずれるため、
  録音開始からの経過時間を基準に、足りない分を無音で埋めてから書く。結果、
  全トラックが同じ長さ・同じ時間軸に揃い、そのまま重ねて編集できる。

  PCM をそのままディスクに置くと 1人あたり毎時 約690MB になるので、
  ユーザーごとに ffmpeg を1つ立ち上げ、パイプへ流しながら mp3 にする。
"""

from __future__ import annotations

import array
import base64
import asyncio
import json
import logging
import math
import shutil
import statistics
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import discord

from config import DJAUDIO_FFMPEG_PATH, JST as _JST
from envutil import env_path
from services import dave, voice_jitter, voice_session
from services.djaudio_cache import register_file

logger = logging.getLogger(__name__)

# Discord の音声は 48kHz / 2ch / 16bit 固定
SAMPLE_RATE = 48000
CHANNELS = 2
SAMPLE_WIDTH = 2
BYTES_PER_SECOND = SAMPLE_RATE * CHANNELS * SAMPLE_WIDTH
FRAME_BYTES = 3840  # 20ms
_SILENCE_CHUNK = b"\x00" * (BYTES_PER_SECOND // 10)  # 100ms

_MAX_PAD_SECONDS = 3600 * 8  # これを超える穴埋めは異常値として切り捨てる

# 波形表示用のデータ。書き出したあとに mp3 を読み直すより、書きながら拾うほうが安い。
#
# 1目盛りの長さ。以前は 0.25 秒だったが、2時間の録音では間引きが効いて
# 1点 2.75 秒になり、**波形が数秒単位の塊にしか見えなかった**（1つの塊の中に
# 相槌が丸ごと収まってしまう）。DAW と同じ「1画素ごとに山と谷」を出すには、
# 画面の画素より細かい目盛りが要る。0.05 秒なら、1画面に1分を出す幅
# 1200px でも 1画素あたり 1点を下回らない。
PEAK_BUCKET_SECONDS = 0.05
PEAK_BUCKET_BYTES = int(PEAK_BUCKET_SECONDS * BYTES_PER_SECOND)
# 書き出し時に、この点数まで間引く。**2時間45分までは間引かない**
# （0.05 秒のまま）。ここを 60,000 にしていたときは2時間の録音で1点 0.15 秒に
# なり、ミキサーを 0.1 秒/画素あたりまで拡大すると1画素に1〜2点しか無くて
# 階段に見えた。画素より粗い目盛りは、そのまま粗さとして目に見える。
# 6時間なら 432,000 目盛り → 2 で間引いて 1点 0.1 秒。
# **間引いた結果は索引の bucket_seconds に必ず書く**（書かないと波形が
# 時間軸の先頭へ圧縮される。過去に実際そうなっていた）。
PEAK_MAX_POINTS = 200000
# 振幅を見るときにサンプルを間引く間隔。表示用なので全部は見ない。
_PEAK_STRIDE = 32

# ZIP に入れる索引の名前。ミキサー（管理画面）がこれを読んでトラックを並べる。
MANIFEST_NAME = "mixer.json"


def _peak_and_energy(pcm: bytes) -> tuple[int, float, int]:
    """PCM 断片の (最大振幅, 二乗和, 見たサンプル数) を1度の走査で返す。

    実効値（RMS）を別に測るのは、山だけの波形が**どこも同じ高さに見える**
    ため。人の声は瞬間的な山が揃いやすく、山だけ塗ると密度の差が出ない。
    DAW の波形が濃淡2層に見えるのは、薄い層が山・濃い層が実効値だから。

    表示用なので全サンプルは見ず、_peak_of と同じ間隔で拾う。書き込みの
    たびに走るので、安いことを優先する。
    """
    usable = len(pcm) - (len(pcm) % 2)
    if usable <= 0:
        return 0, 0.0, 0
    samples = array.array("h")
    samples.frombytes(pcm[:usable])
    picked = samples[::_PEAK_STRIDE]
    if not picked:
        return 0, 0.0, 0
    peak = 0
    energy = 0.0
    for value in picked:
        magnitude = -value if value < 0 else value
        if magnitude > peak:
            peak = magnitude
        energy += float(value) * float(value)
    return peak, energy, len(picked)


def _grouped(values: list[int], group: int, points: int | None) -> list[float]:
    """目盛りをまとめて 0.0〜1.0 に均す。points を渡すと末尾を無音で揃える。

    書き込みに失敗して途中で終わったトラックは短い。末尾を揃えないと、
    そのトラックだけ横に引き伸ばされて表示される。
    """
    if group > 1:
        values = [max(values[i : i + group]) for i in range(0, len(values), group)]
    series = [round(min(1.0, value / 32767.0), 4) for value in values]
    if points is not None:
        del series[points:]
        series.extend([0.0] * (points - len(series)))
    return series


def _encode_series(values: list[float]) -> str:
    """0.0〜1.0 の並びを base64 の1バイト列にする。

    素の JSON 配列（"0.1234," の形）だと1点あたり 7 文字前後になり、
    2時間×5トラックで数MBの索引になってしまう。表示は高さ数十画素なので
    256 段階あれば足り、1点1バイトなら**同じ点数でも 1/7 以下**に収まる。
    """
    raw = bytes(min(255, max(0, int(round(value * 255)))) for value in values)
    return base64.b64encode(raw).decode("ascii")


def _peak_of(pcm: bytes) -> int:
    """PCM 断片のおおよその最大振幅（0〜32767）。

    表示用なので全サンプルは見ず、一定間隔で拾う。長時間の録音でも
    書き込みのたびに走るため、安いことを優先する。
    """
    usable = len(pcm) - (len(pcm) % 2)
    if usable <= 0:
        return 0
    samples = array.array("h")
    samples.frombytes(pcm[:usable])
    picked = samples[::_PEAK_STRIDE]
    if not picked:
        return 0
    return max(max(picked), -min(picked))


# max_minutes に 0 を指定すると「時間では止めない」。VC が無人になるまで録り続ける。
UNLIMITED = 0
# 設定の許容範囲。管理画面・スラッシュコマンドの両方がここを見る
# （片方だけ古いと、入れられた値が黙って弾かれたり丸められたりする）。
MAX_MINUTES_LIMIT = 720  # 12時間
RETENTION_DAYS_MIN = 1
RETENTION_DAYS_MAX = 30
_GUARD_INTERVAL_SEC = 15.0
_EMPTY_GRACE_SEC = 20.0  # 開始直後は参加者のキャッシュが揃っていないことがある

# guild_id -> RecordingSession
_sessions: dict[int, "RecordingSession"] = {}


class RecordingError(RuntimeError):
    """利用者にそのまま見せてよいエラー。"""


# ── トラック1本 ───────────────────────────────────────────────


class _TrackWriter:
    """1ユーザー分の音声を、無音で位置合わせしながら mp3 へ書く。"""

    def __init__(self, user_id: int, display_name: str, out_path: Path, started_at: float):
        """ユーザー1人ぶんの ffmpeg プロセスを起動する。

        ここで Popen が失敗（ffmpeg が無い等）すると例外がそのまま外へ出る。
        呼び出し元の RecordingSession.feed() はこれを Exception で受けて
        そのユーザーのトラックだけ諦める設計なので、ここで握りつぶす必要はない。
        """
        self.user_id = user_id
        self.display_name = display_name
        self.out_path = out_path
        self.started_at = started_at
        self.written_bytes = 0
        self.voiced_bytes = 0  # 実際に声が入っていた分（無音埋めを除く）
        self.peaks: list[int] = []  # 波形表示用（目盛りごとの最大振幅）
        # 目盛りごとの二乗和と、見たサンプル数。割って平方根を取ると実効値になる。
        # 山と別に持つのは、山だけの波形ではどこも同じ高さに見えるため。
        self._energy: list[float] = []
        self._energy_n: list[int] = []
        self.failed = False
        self._process = subprocess.Popen(
            [
                DJAUDIO_FFMPEG_PATH,
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "s16le",
                "-ar",
                str(SAMPLE_RATE),
                "-ac",
                str(CHANNELS),
                "-i",
                "pipe:0",
                "-c:a",
                "libmp3lame",
                "-q:a",
                "5",
                str(out_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def _raw(self, payload: bytes, *, silence: bool = False) -> None:
        """ffmpeg の stdin へ生の PCM/無音を書き込む。

        書き込みに失敗したら failed を立てて以降は何もしない。1トラックの
        書き込み失敗で例外を外へ投げると、write() を呼ぶ受信スレッド側の
        ループごと止まり、他の全ユーザーの録音も巻き添えで止まる。
        """
        if self.failed or self._process.stdin is None:
            return
        try:
            self._accumulate_peaks(payload, silence=silence)
            self._process.stdin.write(payload)
            self.written_bytes += len(payload)
        except (BrokenPipeError, OSError, ValueError) as e:
            # 閉じたパイプへの書き込みは ValueError（write to closed file）で来る。
            # OSError の仲間ではないので、明示的に受けないとここから飛び出す。
            self.failed = True
            logger.warning("[recording] トラック書き込み失敗 user=%s: %s", self.user_id, e)

    def _accumulate_peaks(self, payload: bytes, *, silence: bool) -> None:
        """書いた位置に合わせて、目盛りごとの最大振幅を記録する。

        無音の穴埋めは中身を見ずに 0 として扱う（録音時間の大半が無音なので、
        ここで手を抜けるかどうかが効いてくる）。
        """
        position = self.written_bytes
        end = position + len(payload)
        while position < end:
            bucket = position // PEAK_BUCKET_BYTES
            bucket_end = (bucket + 1) * PEAK_BUCKET_BYTES
            stop = min(end, bucket_end)

            while len(self.peaks) <= bucket:
                self.peaks.append(0)
                self._energy.append(0.0)
                self._energy_n.append(0)
            if not silence:
                piece = payload[position - self.written_bytes : stop - self.written_bytes]
                value, energy, count = _peak_and_energy(piece)
                if value > self.peaks[bucket]:
                    self.peaks[bucket] = value
                self._energy[bucket] += energy
                self._energy_n[bucket] += count

            position = stop

    def peak_series(self, *, group: int = 1, points: int | None = None) -> list[float]:
        """0.0〜1.0 に均した波形データ。

        group は「1点が何目盛りぶんか」、points は返す点数。どちらも
        **全トラックで同じ値を渡すこと**。ここで各トラックが自分の長さから
        間引き幅を決めていたため、1点あたりの秒数がトラックごとに変わり、
        同じ時間軸に並べられなくなっていた（間引いたことを索引にも書いて
        いなかったので、12.5分を超える録音では波形が先頭へ圧縮された）。
        """
        return _grouped(self.peaks, group, points)

    def rms_series(self, *, group: int = 1, points: int | None = None) -> list[float]:
        """0.0〜1.0 に均した実効値（RMS）。点の並びは peak_series と1対1で対応する。

        山だけの波形は**どこも同じ高さに見える**。人の声は瞬間的な山が
        揃いやすく、密度の差が出ないためで、濃淡2層にするとそこが読める。
        目盛りをまたぐときは二乗和ごと足してから割る（平均の平均にすると、
        目盛りごとのサンプル数が違うときにずれる）。
        """
        rms: list[float] = []
        for index in range(0, len(self._energy), max(1, group)):
            energy = sum(self._energy[index : index + group])
            count = sum(self._energy_n[index : index + group])
            rms.append(math.sqrt(energy / count) if count else 0.0)
        series = [round(min(1.0, value / 32767.0), 4) for value in rms]
        if points is not None:
            del series[points:]
            series.extend([0.0] * (points - len(series)))
        return series

    def pad_until(self, elapsed: float) -> None:
        """録音開始から elapsed 秒の位置まで無音で埋める。"""
        target = int(elapsed * BYTES_PER_SECOND)
        target -= target % FRAME_BYTES
        gap = target - self.written_bytes
        if gap <= 0:
            return
        if gap > _MAX_PAD_SECONDS * BYTES_PER_SECOND:
            logger.warning("[recording] 異常な無音幅を切り詰めます user=%s gap=%s", self.user_id, gap)
            gap = _MAX_PAD_SECONDS * BYTES_PER_SECOND
        while gap > 0 and not self.failed:
            chunk = _SILENCE_CHUNK if gap >= len(_SILENCE_CHUNK) else b"\x00" * gap
            self._raw(chunk, silence=True)
            gap -= len(chunk)

    def write(self, pcm: bytes, elapsed: float) -> None:
        """pcm を書く前に、経過秒 elapsed までの無音を埋める。

        無音埋めを先にしないと、直前の発話との間の沈黙ぶんだけ詰めずに
        後続のPCMがそのままくっつき、全トラックの時間軸がずれる。
        """
        self.pad_until(elapsed)
        self._raw(pcm)
        self.voiced_bytes += len(pcm)

    def close(self, total_elapsed: float, timeout: float = 60.0) -> None:
        """末尾まで無音で埋めてから ffmpeg を終わらせる。

        stdin はここでは閉じない。communicate() が閉じてくれるうえ、先に閉じると
        communicate() の中の stdin.flush() が ValueError（flush of closed file）に
        なる。Windows の communicate() は閉じ済みの stdin を許容するが、POSIX は
        しないため、Linux の本番だけで書き出しが落ちていた。
        """
        self.pad_until(total_elapsed)

        # 書き込み失敗などで既に閉じている場合は、communicate() に触らせない。
        stdin = self._process.stdin
        if stdin is not None and stdin.closed:
            self._process.stdin = None

        try:
            _, stderr = self._process.communicate(timeout=timeout)
            if self._process.returncode not in (0, None) and stderr:
                logger.warning(
                    "[recording] ffmpeg 終了コード %s user=%s: %s",
                    self._process.returncode,
                    self.user_id,
                    stderr.decode("utf-8", "replace")[:300],
                )
        except subprocess.TimeoutExpired:
            logger.warning("[recording] ffmpeg が終了しないため強制終了 user=%s", self.user_id)
            self._process.kill()

    @property
    def voiced_seconds(self) -> float:
        """実際に声が入っていた秒数（無音埋めの分は含まない）。"""
        return self.voiced_bytes / BYTES_PER_SECOND


# ── Sink ─────────────────────────────────────────────────────

# ── 書き出した音が声として成立しているか ──────────────────────

# 長さもトラック数も正しいのに中身が雑音になっている、という壊れ方をした。
# 数字が正しいことと、音が聞けることは別なので、書き出したものを測る。
#
# 指標は周期性（自己相関の山の高さ）。声は準周期的なので山が立ち、雑音では
# 立たない。実測での分かれ方は 正常 0.51 / 白色雑音 0.17。
# スペクトル平坦度も試したが、mp3 のローパスに支配されて白色雑音でも 0.065
# にしかならず、声と区別できなかったので使っていない。
VOICE_PERIODICITY_MIN = 0.30
_VOICE_RATE = 8000  # 声の高さは 60〜400Hz。これで足りる。
_VOICE_WINDOW = 0.04
_VOICE_PROBES = 8  # 何箇所から抜き出すか（長さに依らず一定にする）
_VOICE_PROBE_SECONDS = 0.5
_VOICE_MAX_WINDOWS = 16
_VOICE_FLOOR = 900  # これを下回る窓は無音とみなす


def _probe_samples(path: Path, duration: float) -> array.array:
    """録音の各所から少しずつ抜き出して 8kHz モノラルで返す。

    全体をデコードすると 6 時間で 2GB 近くになる。測るのに全部は要らない。
    """
    samples = array.array("h")
    span = max(duration - _VOICE_PROBE_SECONDS, 0.0)
    for i in range(_VOICE_PROBES):
        at = 0.0 if _VOICE_PROBES == 1 else span * i / (_VOICE_PROBES - 1)
        try:
            result = subprocess.run(
                [
                    DJAUDIO_FFMPEG_PATH,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-ss",
                    f"{at:.3f}",
                    "-t",
                    str(_VOICE_PROBE_SECONDS),
                    "-i",
                    str(path),
                    "-f",
                    "s16le",
                    "-ar",
                    str(_VOICE_RATE),
                    "-ac",
                    "1",
                    "-",
                ],
                capture_output=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, OSError) as e:
            logger.warning("[recording] 音の抜き出しに失敗 %s: %s", path.name, e)
            continue
        raw = result.stdout
        samples.frombytes(raw[: len(raw) - len(raw) % 2])
    return samples


def _periodicity(samples: array.array) -> float | None:
    """鳴っている窓ごとの自己相関の山（0〜1）の中央値。測れなければ None。"""
    size = int(_VOICE_RATE * _VOICE_WINDOW)
    if len(samples) < size * 2:
        return None
    low = _VOICE_RATE // 400
    high = min(_VOICE_RATE // 60, size - 1)
    loud = [
        i
        for i in range(0, len(samples) - size, size)
        if sum(v * v for v in samples[i : i + size]) >= size * (_VOICE_FLOOR**2)
    ]
    if not loud:
        return None  # 全部無音。良し悪しは判定できない。
    if len(loud) > _VOICE_MAX_WINDOWS:
        step = len(loud) / _VOICE_MAX_WINDOWS
        loud = [loud[int(i * step)] for i in range(_VOICE_MAX_WINDOWS)]

    scores = []
    for start in loud:
        seg = samples[start : start + size]
        best = 0.0
        for lag in range(low, high):
            count = size - lag
            num = sum(seg[i] * seg[i + lag] for i in range(count))
            left = sum(seg[i] * seg[i] for i in range(count))
            right = sum(seg[i + lag] * seg[i + lag] for i in range(count))
            denom = math.sqrt(left * right) or 1.0
            best = max(best, num / denom)
        scores.append(best)
    return round(statistics.median(scores), 3)


def measure_voice(path: Path, duration: float) -> float | None:
    """書き出したトラックが声として成立しているかを測る。

    戻り値は 0〜1。VOICE_PERIODICITY_MIN を下回るなら雑音の疑いがある。
    無音しか入っていない、または測れなかった場合は None。
    """
    try:
        return _periodicity(_probe_samples(path, duration))
    except Exception as e:
        # 測れないことが録音の失敗になってはいけない。
        logger.warning("[recording] 音の確認に失敗 %s: %s", path.name, e)
        return None


# ── E2EE（DAVE）────────────────────────────────────────────────

# 判定と復号は services/dave.py に置いてある。ここでは「録れないと決める
# しきい値」だけを持つ。
#
# 何割が復号できなければ「このセッションは録れない」と判断するか。
# 切り替わりの途中で数フレームだけ暗号化されていることがあるため、
# 少ない件数では決めつけない。
_DAVE_MIN_SAMPLES = 40
_DAVE_RATIO = 0.15

# 後方互換: これまで recording_service.is_dave_frame を参照していた箇所と
# テスト向けに、そのまま使えるようにしておく。
is_dave_frame = dave.is_dave_frame


# ── RTP のパディング ──────────────────────────────────────────


def strip_rtp_padding(packet, payload: bytes | None) -> bytes | None:
    """RTP のパディングを取り除く。中身が全部パディングなら None。

    voice_recv は剥がさない（rtp.py に「discord はこのビットを使っていない
    ようだ」と書かれている）。実際には使われていて、本番でこう届いていた:

        247 バイト、全部 0xF7 … 0xF7 = 247 = 全体の長さ
        255 バイト、全部 0xFF … 0xFF = 255 = 全体の長さ

    RFC 3550 では最終バイトがパディング長（自身を含む）を表す。それが全体の
    長さと等しいなら、音声は1バイトも入っていない。帯域推定のための探査
    パケットで、Opus に渡しても「壊れている」と言われるだけ。

    パディングが一部だけの場合もある。E2EE のフレームでは、末尾のマーカーが
    パディングに隠れて見えなくなる（本番で ... 010dfafa0202 として観測した）。

    **ヘッダのビットが立っていないときは、長さの一致だけで決めないこと。**
    もとは「最終バイト＝全体の長さ」だけで詰め物と決めていて、「平文の Opus が
    そうなる確率は無視できる」と書いてあったが、無視できなかった。最終バイトは
    レンジ符号器の出力でほぼ一様なので 1/256 で一致する。毎秒50パケットなら
    2〜4秒に1回、**普通の音声パケットが捨てられる**。捨てられた番号は skip()
    されるので drain() が欠落補間も作らず、その 20ms がまるごと無音になり、
    録音が途切れ途切れになっていた（実録音を Discord と同じ条件で載せ直すと
    1097枚中 64kbps で5枚 / 96kbps で10枚が消えていた）。

    上に載せた本番の実測 2 件は、どちらも**全バイトが同じ値**だった。そこまで
    見れば偶然の一致と分けられる（誤認 0 件になることを同じ 1097 枚で確認）。
    ビットが立っているときは RFC どおりに信じてよいので、そちらは変えない。
    """
    # 空も「音声が入っていない」に含める。b"" を素通しすると、呼び出し側の
    # `if encoded` が偽になってどのカウンタにも入らず、番号だけ消費した状態で
    # 消える。**その番号は drain() から穴に見えるので、欠落として数えられる。**
    if not payload:
        return None
    count = payload[-1]
    flagged = bool(getattr(packet, "padding", False))
    if not flagged and (count != len(payload) or payload.count(payload[0]) != len(payload)):
        return payload
    if count <= 0 or count > len(payload):
        return payload  # 壊れた値。触らないでおく。
    if count == len(payload):
        return None  # 中身はパディングだけ
    return payload[:-count]


# Opus の TOC（先頭バイト）から、1フレームのサンプル数を引く表。
# RFC 6716 の config が、モードと帯域と**フレーム長**をまとめて表す。
#   config  0〜11 SILK   : 10 / 20 / 40 / 60 ms
#   config 12〜15 Hybrid : 10 / 20 ms
#   config 16〜31 CELT   : 2.5 / 5 / 10 / 20 ms
_OPUS_CONFIG_MS = (
    [(10, 20, 40, 60)[c % 4] for c in range(12)]
    + [(10, 20)[c % 2] for c in range(12, 16)]
    + [(2.5, 5, 10, 20)[c % 4] for c in range(16, 32)]
)


def opus_frame_samples(packet: bytes | None) -> int | None:
    """Opus パケットが何サンプルぶんかを TOC から読む。読めなければ None。

    **TOC に入っているのは「長さ」だけで、位置は入っていない。** タイムスタンプも
    連番も無い（Opus は時間情報を持たない素の符号器で、だから RTP 側が運ぶ）。
    ここで読むのは位置を決めるためではなく、**位置を決める式の前提を見張るため**。

    _FRAME_SAMPLES = 960（20ms）が欠落補間の位置計算に埋め込まれている。
    Discord は 20ms 固定だが、それはクライアントの実装であってプロトコルの
    保証ではない。Opus は1パケットに 60ms まで入れられる（実測で確認した）。
    崩れたときに黙って位置がずれるのではなく、数として出るようにする。
    """
    if not packet:
        return None
    toc = packet[0]
    config = toc >> 3
    code = toc & 0b11
    if code == 0:
        frames = 1
    elif code in (1, 2):
        frames = 2
    else:
        if len(packet) < 2:
            return None
        frames = packet[1] & 0b00111111
    if frames <= 0:
        return None
    return int(_OPUS_CONFIG_MS[config] * frames * SAMPLE_RATE / 1000)


# ── 受信ストリームの組み立て ──────────────────────────────────

# 順番待ちで抱えておく上限。これを過ぎたら穴は諦めて先へ進む。
_REORDER_HOLD_SEC = 0.2
# 一度に抱える上限（異常時に無制限へ膨らませない）
_REORDER_MAX = 100
# 誰の音か分かるまで抱えておける上限（→ _RecordingSinkBase.write）。
# 20秒ぶん。_REORDER_MAX より十分大きくすること（あちらは「穴を待つ」上限、
# こちらは「持ち主が分かるのを待つ」上限で、役割が違う）。
_PENDING_MAX = 1000
# 「音声が入っていない」と覚えておく番号の上限（→ _StreamAssembler.skip）。
# 並べ直しの窓を十分に覆えればよく、超えたら捨てる（捨てても今までの
# 振る舞いに戻るだけで、悪化はしない）。
_SKIP_MAX = 1000
# これ以上うしろへ戻る位置を渡されたら、相手の時計が飛んだとみなす。
# 欠落補間は次のパケットの手前へ置くので、わずかな戻りは正常に起きる。
_BACKWARD_TOLERANCE_SEC = 1.0
# 張り直しの警告を出す上限（あとは数だけ log_summary に残す）。
_REBASE_SAMPLES = 5
_FRAME_SAMPLES = 960  # 20ms ぶんのサンプル数（RTP タイムスタンプの刻み）
# 欠けたぶんを Opus の欠落補間で埋める上限。これを超える穴は無音のままにする。
_PLC_MAX_FRAMES = 5
# デコード失敗の中身をログに残す件数（ストリームごと）。全部出すと洪水になる。
_FAILURE_SAMPLES = 3
# 届いたパケットをそのまま控える枚数（ストリームごと）。
#
# **全部は残せない。** 6時間の録音は1人あたり 100万枚を超え、そのまま書くと
# 200MB になる。実際に切り分けに要ったのは2種類だけだった。
#
#   1. 接続直後 … SSRC と人の対応が付くまでのやりとりと、帯域推定の探査が
#                 ここに集中する（実測では詰め物50枚と E2EE不可7枚が、
#                 すべて接続後 0.1 秒のひとかたまりに入っていた）
#   2. 普通の音声として扱えなかったもの … 詰め物・E2EE不可・無音
#
# なので、冒頭は種類を問わず控え、そのあとは 2. だけ控える。
_CAPTURE_HEAD = 80  # 冒頭のこの枚数は種類を問わず控える
_CAPTURE_MAX = 280  # ストリームごとの上限。超えたぶんは数だけ残す
# 「普通に扱えた」とみなす種別。冒頭を過ぎたらこれは控えない。
#
# **"E2EE" を必ず入れること。** 復号は取り出すときまで遅らせているので、
# 受信の時点では「暗号文だった」までしか分からない。DAVE が必須になった今、
# 音声フレームは全部が暗号文で来るので、これを異常扱いすると普通の音声で枠が
# 埋まる。本番実測では、控えた 280 枚に対し 1579 枚が上限に当たって省かれ、
# 55秒の録音のうち冒頭6秒ぶんしか残っていなかった。
_CAPTURE_ORDINARY = frozenset({"音声", "E2EE", "E2EE復号"})
# 復号の結果が出るまで、控えるかどうかを保留にしておける枚数。並べ直しの窓を
# 覆えればよい（_REORDER_HOLD_SEC は 0.2 秒 ＝ 10 枚ぶん）ので十分な余裕がある。
_CAPTURE_AWAITING_MAX = 100
CAPTURE_NAME = "packets.jsonl"

_SEQ_MOD = 1 << 16  # RTP シーケンス番号は 16bit
_TS_MOD = 1 << 32  # RTP タイムスタンプは 32bit（48kHz 刻み）


def _wrapped_delta(a: int, b: int, mod: int) -> int:
    """a - b を、折り返しを考慮した符号つきの差として返す。"""
    return ((a - b + mod // 2) % mod) - mod // 2


class _StreamAssembler:
    """SSRC 1本ぶんの受信ストリームを、順序どおりに組み立てる。

    voice_recv のジッタバッファは、順番待ちの穴が空いた瞬間にバッファ全体を
    捨てて1つだけ返す（router 側が timeout=0 で pop するため）。実際に本番の
    ログではこうなっていた:

        8 packets were lost being flushed in decoder-18295
         --> (last=5487) [5491, 5482, 5492, 5484, 5485, 5486, 5490, 5488, 5489]

    大量に落ちるうえ、残ったものも順不同で出てくる。Opus は直前の状態を使って
    復号するので、順不同のまま入れると音が壊れる（実測: 440Hz の音が 719Hz に
    化け、振幅も振り切れた）。そこで、こちら側でもう一度並べ直してから渡す。

    位置合わせも到着時刻ではなく RTP タイムスタンプ（48kHz 刻み）で行う。
    到着時刻で置くと、ジッタのぶんだけ無音が挟まって時間軸が歪む。
    """

    def __init__(self, ssrc: int):
        """1つの SSRC 分の状態を初期化する。

        ここで作るカウンタ類は log_summary() でそのまま出力されるデバッグ用の
        内訳で、録音そのものの動作には使わない。
        """
        self.ssrc = ssrc
        # discord.opus.Decoder は使うときに初めて作る（読み込み時に opus が
        # 無い環境でも import は通したいため）。None 始まりなので型を書く。
        self.decoder: Any | None = None
        # seq -> (受信時刻, RTPタイムスタンプ, opus)
        self._pending: dict[int, tuple[float, int, bytes]] = {}
        self._next_seq: int | None = None
        self._anchor_ts: int | None = None  # 最初のパケットの RTP タイムスタンプ
        self._anchor_elapsed: float = 0.0  # そのときの録音経過秒
        # 音声が入っていないと分かっている番号（→ skip）。穴と区別するために持つ。
        self._skipped: set[int] = set()
        self._last_offset: float | None = None  # 直前に返した位置（戻りの判定に使う）
        self.rebased = 0  # 時計が飛んで起点を張り直した回数
        self.unknown = 0  # 誰の音か分からないまま受け取った数
        self.overflow = 0  # 抱えきれずに捨てた数
        self.jumped = 0  # 時計が飛んだだけで、落ちてはいない番号の数
        self.odd_frames = 0  # 20ms でない長さのパケット
        self._last_ts: int | None = None  # 直前に出したパケットの RTP タイムスタンプ
        self.lost = 0  # 待っても来なかったパケット数
        self.late = 0  # 出したあとに届いた／溢れて捨てたパケット数
        self.silence = 0  # 発話の切れ目に来る無音パケット（並べ直しには入れない）
        self.failed = 0  # デコードできなかったパケット
        self.decoded = 0  # デコードできたパケット（失敗数だけでは割合が分からない）
        self.encrypted = 0  # E2EE（DAVE）で、復号できなかったフレーム
        self.decrypted = 0  # E2EE（DAVE）を復号できたフレーム
        self.padding_only = 0  # 中身がパディングだけのパケット（音声ではない）
        self.received = 0  # 受け取った音声フレームの総数
        self.payload_types: dict[int, int] = {}  # RTP のペイロードタイプ別の数
        self.captured: list[dict] = []  # そのまま控えたパケット（→ capture）
        self.capture_skipped = 0  # 上限に当たって控えなかった数
        self._capture_seen = 0  # capture() に来た総数（冒頭かどうかの判定用）
        # 復号の結果待ちの控え。RTP タイムスタンプ -> 控えた記録（→ stamp_capture）。
        # 控えた数が上限で頭打ちになるので、こちらも際限なくは増えない。
        self._capture_awaiting: dict[int, tuple[dict, bool]] = {}
        self.undecryptable_run = 0  # 続けて復号できなかった数（→ _emit）

    def capture(self, packet, payload: bytes | None, kind: str, *, user_known: bool, awaiting: bool = False) -> None:
        """届いたパケットを、手を加える前のまま控える。

        **詰め物を剥がす前・復号する前を残すこと。** 剥がしたあとを控えると、
        剥がすと決めた判断そのものが正しかったのかを後から確かめられない。
        疑うために残すので、疑う対象を残す。

        枚数は絞る（→ _CAPTURE_HEAD / _CAPTURE_MAX）。RTP 拡張の番号まで
        残すのは、実測でこれが決め手になったため。帯域推定の探査は {9,3} を
        持ち、直前の音声パケットと同じタイムスタンプで届いていた（音声は
        {1,3} で 960 ずつ進む）。番号が無いと、探査と音声を後から見分ける
        手がかりが無い。
        """
        self._capture_seen += 1
        extension = getattr(packet, "extension_data", None) or {}
        # 突き合わせの鍵にも使うので、entry から読み直さず先に整数で持つ
        # （entry は値の型が混ざるので、そこから取ると鍵として使えない）。
        timestamp = int(getattr(packet, "timestamp", 0) or 0)
        entry = {
            "seq": int(getattr(packet, "sequence", -1)),
            "ts": timestamp,
            "pt": getattr(packet, "payload", None),
            "padding": bool(getattr(packet, "padding", False)),
            "ext": sorted(extension),
            "size": len(payload or b""),
            "kind": kind,
            "user_known": user_known,
            "opus_b64": base64.b64encode(payload or b"").decode("ascii"),
        }
        keep = self._capture_seen <= _CAPTURE_HEAD or kind not in _CAPTURE_ORDINARY
        kept = self._keep(entry) if keep else False
        if awaiting:
            # 種別が確定するのは復号のあと（→ stamp_capture）。控えたかどうかも
            # 一緒に覚えておき、結果が「普通ではなかった」ならそのときに拾う。
            # 拾えるようにしておかないと、冒頭を過ぎてから起きた本物の鍵の
            # 問題が、数としてしか残らない。
            if len(self._capture_awaiting) >= _CAPTURE_AWAITING_MAX:
                # 結果が出ないまま溜まっている。古いほうから捨てる
                # （dict は入れた順を保つ）。
                self._capture_awaiting.pop(next(iter(self._capture_awaiting)))
            self._capture_awaiting[timestamp] = (entry, kept)

    def _keep(self, entry: dict) -> bool:
        """控えの列へ入れる。上限に当たったら False。"""
        if len(self.captured) >= _CAPTURE_MAX:
            # 黙って打ち切ると、読んだ人が「これで全部」と受け取る。
            self.capture_skipped += 1
            return False
        self.captured.append(entry)
        return True

    def stamp_capture(self, timestamp: int, kind: str) -> None:
        """控えた記録に、あとから分かった結果を書き入れる。

        復号は取り出すときまで遅らせている（→ _emit）ので、受信の時点では
        「暗号文だった」までしか分からない。結果まで残さないと、控えたものを
        見ても E2EE の扱いが追えない（それが控える目的だった）。

        突き合わせに RTP タイムスタンプを使うのは、_emit まで届くのがこれと
        中身だけで、連番はそこまで来ないため。音声フレームのタイムスタンプは
        1ストリーム内で重ならない（探査パケットは重なるが、あちらは暗号文
        ではないのでここには来ない）。
        """
        found = self._capture_awaiting.pop(timestamp, None)
        if found is None:
            return
        entry, kept = found
        entry["kind"] = kind
        if not kept and kind not in _CAPTURE_ORDINARY:
            # 受信の時点では普通に見えたので控えていなかった。結果が出て
            # はじめて「普通ではなかった」と分かったので、ここで拾う。
            self._keep(entry)

    def snapshot(self) -> dict[str, Any]:
        """このストリームの内訳。ログと info.json の**唯一の出どころ**。

        以前はログの書式文字列に直接カウンタを並べていた。ZIP へも同じ数字を
        載せるにあたって二度書くと、片方だけ足したときに黙って食い違う。
        読み手が「ログと ZIP のどちらが正しいのか」を判断できなくなるので、
        組み立てはここ1箇所に寄せる。
        """
        return {
            "ssrc": self.ssrc,
            "received": self.received,
            "decoded": self.decoded,
            "failed": self.failed,
            "decrypted": self.decrypted,
            "encrypted": self.encrypted,
            "padding_only": self.padding_only,
            "lost": self.lost,
            "late": self.late,
            "silence": self.silence,
            "rebased": self.rebased,
            "unknown": self.unknown,
            "overflow": self.overflow,
            "jumped": self.jumped,
            "odd_frames": self.odd_frames,
            "payload_types": dict(self.payload_types),
        }

    def decode(self, encoded: bytes | None) -> bytes:
        """encoded が None のときは欠落補間（PLC）。

        落ちたフレームを黙って飛ばすと、Opus は直前の状態を引きずったまま次を
        復号するので継ぎ目が濁る。1フレーム分「無かった」と教えるほうが素直。
        """
        if self.decoder is None:
            from discord.opus import Decoder

            self.decoder = Decoder()
        # opus は型情報を出していないので戻りは Any。bytes を返す約束なので
        # ここで明示する（実体は bytes）。
        return cast(bytes, self.decoder.decode(encoded, fec=False))

    def offset_for(self, timestamp: int, elapsed: float) -> float:
        """RTP タイムスタンプを、録音開始からの秒数に直す。

        **前と後ろの両方を見ること。** もとは offset<0 と offset>elapsed+60 しか
        見ておらず、再接続で相手のタイムスタンプ基準が下がった場合は素通り
        していた。素通りすると pad_until は前にしか進まないので、そのトラックは
        無音を書かなくなって発話が詰まって並び、追い付いたあとは残りの録音ぶん
        ずっと手前に置かれ続ける。ずれ幅はトラックごとに違い、録音の途中から
        始まる。しかも**何も記録が残らない**ので、ログを見ても分からなかった。

        戻りに 1 秒の遊びを持たせているのは、欠落補間を次のパケットの手前へ
        置くため（drain）。そこで毎回張り直すと、到着時刻を起点にすることに
        なってジッタのぶん時間軸が歪む。
        """
        if self._anchor_ts is None:
            self._anchor_ts = timestamp
            self._anchor_elapsed = elapsed
        offset = self._anchor_elapsed + _wrapped_delta(timestamp, self._anchor_ts, _TS_MOD) / SAMPLE_RATE
        jumped_ahead = offset < 0 or offset > elapsed + 60.0
        jumped_back = self._last_offset is not None and offset < self._last_offset - _BACKWARD_TOLERANCE_SEC
        if jumped_ahead or jumped_back:
            self.rebased += 1
            if self.rebased <= _REBASE_SAMPLES:
                logger.warning(
                    "[recording] ssrc=%s タイムスタンプが%sへ飛んだので現在時刻に合わせ直します"
                    " (要求 %.2f 秒 / 直前 %s / 経過 %.2f 秒)",
                    self.ssrc,
                    "うしろ" if jumped_back else "まえ",
                    offset,
                    "-" if self._last_offset is None else f"{self._last_offset:.2f} 秒",
                    elapsed,
                )
            self._anchor_ts = timestamp
            self._anchor_elapsed = elapsed
            offset = elapsed
        self._last_offset = offset
        return offset

    def push(self, sequence: int, timestamp: int, encoded: bytes, now: float) -> None:
        """受信したパケットを並べ直し待ちの列に積む。

        sequence が既に出した番号より後ろ（手遅れ）なら、いま差し込んでも
        出力順を乱すだけなので late としてカウントして捨てる。
        """
        if self._next_seq is not None and _wrapped_delta(sequence, self._next_seq, _SEQ_MOD) < 0:
            self.late += 1  # 既に出したところより後ろ。今さら差し込めない。
            return
        if len(self._pending) >= _PENDING_MAX:
            # 持ち主が分からないまま溜め込み続けないための上限。**古いほうから
            # 捨てる。** 新しいほうを捨てると、対応が付いた瞬間に直近の発話が
            # 欠ける（いちばん失いたくないところが消える）。
            oldest = min(self._pending, key=lambda k: self._pending[k][0])
            del self._pending[oldest]
            self.overflow += 1
        self._pending[sequence] = (now, timestamp, encoded)

    def skip(self, sequence: int) -> None:
        """音声が入っていないパケットの番号を、穴として数えないよう覚える。

        詰め物（帯域推定の探査）と、復号できなかった E2EE フレームは push()
        しない。**番号だけは消費されている**ので、伝えないと drain() が
        「届かなかった」と見なし、欠落に数えたうえで Opus に無い音を作らせる
        （欠落補間）。本番では、報告される欠落のおよそ半分がこれだった
        （受信637,109 に対し報告17,323 / うち詰め物由来8,548）。
        """
        if self._next_seq is not None and _wrapped_delta(sequence, self._next_seq, _SEQ_MOD) < 0:
            return  # もう通り過ぎた番号。覚えても使わない。
        self._skipped.add(sequence)
        if len(self._skipped) > _SKIP_MAX:
            self._skipped.clear()

    def _forget_passed(self, seq: int) -> None:
        """seq より手前の「音声なし」の記憶を捨てる。

        **ここで捨てないと、連番が1周したときに本物の音声を食う。**

        ストリームの冒頭は帯域推定の探査（詰め物）から始まることがある。その
        あいだ _next_seq はまだ決まっておらず、skip() は渡された番号を無条件に
        覚える。ところが起点は「抱えているうちで最も若い音声の番号」で決まる
        （→ _earliest_seq）ので、覚えた番号がその手前に落ちることがある。drain()
        は前へしか進まないので誰も消費せず、_SKIP_MAX にも当たらないまま残る。

        16bit の連番は 65536枚（発話 22分ぶん）で1周する。戻ってきた同じ番号は
        今度は本物の音声だが、覚えている番号に当たって捨てられていた。実録音
        （2026-09-05 / 221分36秒）では、冒頭の詰め物14枚を持つ話者だけ
        `時計の飛び=-14` と負の値で出ていた。詰め物の枚数とちょうど一致する。
        """
        self._skipped = {s for s in self._skipped if _wrapped_delta(s, seq, _SEQ_MOD) >= 0}

    def _hold_expired(self, now: float) -> bool:
        """順番待ちを打ち切るか。

        抱えすぎたときに古いほうを捨てると、いちばん欲しい音から消える。
        待たずに出すほうへ倒す。
        """
        if len(self._pending) >= _REORDER_MAX:
            return True
        return now - min(entry[0] for entry in self._pending.values()) >= _REORDER_HOLD_SEC

    def _earliest_seq(self) -> int:
        """抱えているなかで、いちばん若い番号（折り返しを考慮）。"""
        ref = min(self._pending, key=lambda k: self._pending[k][0])
        return min(self._pending, key=lambda k: _wrapped_delta(k, ref, _SEQ_MOD))

    def drain(self, now: float) -> list[tuple[int, bytes | None, float]]:
        """出せるぶんを、順序どおりに (RTPタイムスタンプ, opus, 受信時刻) で返す。

        受信時刻も返すのは、時間軸の起点をここで決めるため。呼び出し側が
        「出したときの時刻」で起点を取ると、抱えていたあいだのぶんだけ
        トラックまるごと後ろへずれる（→ offset_for）。
        """
        out: list[tuple[int, bytes | None, float]] = []
        while self._pending:
            if self._next_seq is None:
                # まだ1つも出していない。ここで先頭を決め打つと、あとから届く
                # 若い番号を全部捨てることになる。少し待ってから最小値で始める。
                if not self._hold_expired(now):
                    break
                self._next_seq = self._earliest_seq()
                self._forget_passed(self._next_seq)
            # 音声が入っていないと分かっている番号は、穴ではない（→ skip）。
            # 欠落に数えず、欠落補間も作らずに次へ進む。
            if self._next_seq in self._skipped:
                self._skipped.discard(self._next_seq)
                self._next_seq = (self._next_seq + 1) % _SEQ_MOD
                continue
            item = self._pending.pop(self._next_seq, None)
            if item is not None:
                out.append((item[1], item[2], item[0]))
                self._last_ts = item[1]
                self._next_seq = (self._next_seq + 1) % _SEQ_MOD
                continue
            # 穴が空いている。少しだけ待ち、それでも来なければ諦めて飛ばす。
            if not self._hold_expired(now):
                break
            # 直上で None を弾いているが、lambda の中までは絞り込みが届かない。
            next_seq = self._next_seq
            assert next_seq is not None
            skipped = min(self._pending, key=lambda k: _wrapped_delta(k, next_seq, _SEQ_MOD))
            gap = _wrapped_delta(skipped, next_seq, _SEQ_MOD)
            # 飛ばす範囲に「音声が入っていない」と分かっている番号が混じって
            # いれば、そのぶんは届かなかったのではない。範囲の側ではなく
            # 覚えている側を回す（再接続で gap が数万になることがあるため）。
            known = 0
            for seq in list(self._skipped):
                if 0 <= _wrapped_delta(seq, next_seq, _SEQ_MOD) < gap:
                    self._skipped.discard(seq)
                    known += 1
            missing = gap - known
            next_ts = self._pending[skipped][1]
            # 欠けたぶんには受信時刻が無い。次に届いたものの時刻で代用する。
            next_at = self._pending[skipped][0]

            # **その番号のパケットが本当に送られていたのかを確かめる。**
            #
            # 番号が飛んでいても、原因は2つある。片方は本物の損失、もう片方は
            # 送信側の連番が振り直されたとき（再接続）。番号の差だけでは区別が
            # 付かず、まとめて欠落に数えていたので、本番の損失率に「本当に
            # 落ちた」と「再接続で飛んだ」が混ざっていた。
            #
            # タイムスタンプの進みを見れば分かる。落ちたパケットが本当に
            # 送られていたなら、その数ぶんの時間が進んでいるはず。**Opus は
            # 1パケットに 60ms しか入らない**ので、欠けた数で説明できないほど
            # 時刻が進んでいる（または戻っている）なら、落ちたのではなく
            # 時計が変わったということ。
            expected = (gap + 1) * _FRAME_SAMPLES
            ts_gap = None if self._last_ts is None else _wrapped_delta(next_ts, self._last_ts, _TS_MOD)
            if ts_gap is not None and not 0 < ts_gap <= expected * 3 + _FRAME_SAMPLES:
                # 時計が変わった。欠落には数えず、**補間も作らない**
                # （位置の計算が next_ts を基準にするので、飛んだ時刻から
                # 引くと、まったく無関係な場所に無い音を置くことになる）。
                self.jumped += missing
                self._last_ts = None
                self._next_seq = skipped
                continue

            self.lost += missing
            # 欠けたぶんは Opus に「無かった」と伝えて補間させる。
            for i in range(min(gap, _PLC_MAX_FRAMES)):
                out.append(((next_ts - (gap - i) * _FRAME_SAMPLES) % _TS_MOD, None, next_at))
            self._next_seq = skipped
        return out

    def flush(self) -> list[tuple[int, bytes | None, float]]:
        """残っている全パケットを、待たずに出す。

        録音停止時に呼ぶ。drain(now) は「まだ来るかもしれない」と一定時間
        待ってから出すが、停止後はもう届かないので float("inf") を渡して
        即座に全部吐き出させる。
        """
        return self.drain(float("inf"))


class _RecordingSinkBase:
    """Opus のまま受け取り、並べ直してから自前でデコードする。

    wants_opus() を False にするとライブラリ側がデコードするが、そこで
    1つでも壊れたパケットに当たると OpusError が上がり、受信スレッドごと
    落ちて stop_listening() まで呼ばれる（router.py の run/finally）。
    つまり壊れたパケット1個で録音が黙って止まる。

    デコーダは SSRC ごとに持つ。Opus は直前の状態を使って復号するので、
    別々のストリームを1つのデコーダに入れると音が壊れる。user_id で持つと、
    同じ人が付け直した SSRC が1つのデコーダに混ざる。

    **`voice_recv.AudioSink` をここでは継承していない。** 受信拡張が入って
    いない環境ではその import そのものができず、モジュールを読み込めなく
    なるため。継ぎ足すのは _make_sink_class() の仕事で、そちらが返す
    クラスだけが `listen()` に渡せる。
    """

    def __init__(self, session: "RecordingSession"):
        """録音セッションに紐づくシンクを初期化する。

        SSRC ごとの _StreamAssembler と直近の話者（VoiceRecvClient から
        渡されるユーザー情報）を、guild 単位ではなくこのシンク単位
        （＝録音セッション単位）で保持する。
        """
        super().__init__()
        self.session = session
        self._streams: dict[int, _StreamAssembler] = {}
        self._users: dict[int, object] = {}  # ssrc -> 直近の話者

    def wants_opus(self) -> bool:
        """常に True。

        ライブラリ側にデコードを任せると、壊れたパケット1個で OpusError が
        受信スレッドごと殺し、stop_listening() まで呼ばれて録音が黙って
        止まる（クラス docstring 参照）。自前でデコードして例外を握り
        つぶすためにここで断る。
        """
        return True

    def _client(self):
        """繋がっていない状態でも例外にしない。

        voice_recv の AudioSink.voice_client は、接続前だと
        AttributeError を投げる（_voice_client がまだ無い）。
        """
        return getattr(self, "_voice_client", None)

    def _stream_for(self, ssrc: int) -> _StreamAssembler:
        """ssrc に対応する _StreamAssembler を返す。無ければ新規に作って保持する。"""
        stream = self._streams.get(ssrc)
        if stream is None:
            stream = _StreamAssembler(ssrc)
            self._streams[ssrc] = stream
        return stream

    def _resolve_user(self, ssrc: int):
        """この SSRC が誰かを返す。分からなければ None。

        直近に渡された相手を覚えておき（_users）、まだなら voice_recv の
        対応表を直接引く。**引くほうも要る。** 覚えているほうは「対応が
        付いたあとに1つでもパケットが来た」ときにしか埋まらないので、
        発話の終わり際に対応が付いた場合は最後まで空のままになる。
        """
        user = self._users.get(ssrc)
        if user is not None:
            return user
        client = self._client()
        if client is None:
            return None
        # ライブラリ内部の対応表を読む。形が変わっても録音は止めない。
        try:
            user_id = client._get_id_from_ssrc(ssrc)
            guild = getattr(client, "guild", None)
            found = guild.get_member(int(user_id)) if user_id and guild is not None else None
        except Exception:
            return None
        if found is None:
            return None
        if int(getattr(found, "id", 0) or 0) in self.session.excluded_user_ids:
            self._streams.pop(ssrc, None)
            return None
        self._users[ssrc] = found
        return found

    def write(self, user, data) -> None:
        # voice_recv の受信スレッドから呼ばれる。ここでイベントループには触らない。
        """1パケット受信のたびに voice_recv から呼ばれる（別スレッド、イベント
        ループには触れない）。

        DAVE（E2EE）の復号と並べ替えキューへの投入までを行い、実際の
        デコードと書き込みは _emit() に任せる。ここで例外を外に出すと
        stop_listening() まで呼ばれて録音全体が止まる。
        """
        packet = getattr(data, "packet", None)
        if packet is None:
            return
        ssrc = int(getattr(packet, "ssrc", 0) or 0)
        if not ssrc:
            return

        # **user が None でも捨てないこと。**
        #
        # 音そのものは UDP で届くが、「その SSRC が誰か」はゲートウェイの
        # SPEAKING イベントという別経路で届く。対応が付くまで voice_recv は
        # user=None で渡してくる（opus.py の _get_cached_member）。ここで
        # 捨てると3つ同時に起きる。
        #
        #   1. その音は録音から永久に失われる（届いているのに捨てている）
        #   2. 番号だけ消費されるので drain() から穴に見え、**欠落として
        #      計上される**
        #   3. payload_types に入れる前に返すので、どのカウンタにも現れず、
        #      起きていること自体が分からない
        #
        # 対応が外れるのは主に再接続（SSRC が振り直され、次にその人が喋り
        # 出すまで対応が付かない）と CLIENT_DISCONNECT。本番では 0.7〜4.5 秒の
        # 穴が数十回という形で出ていた。発話の途中で起きると、その発言の
        # 残り全部が消える。
        if user is not None:
            user_id = int(getattr(user, "id", 0) or 0)
            if not user_id:
                return
            if user_id in self.session.excluded_user_ids:
                # 除外された人。抱えていたぶんごと捨てる。
                self._streams.pop(ssrc, None)
                self._users.pop(ssrc, None)
                return
            self._users[ssrc] = user
        else:
            # **ここで必ず束縛すること。** user_id は上の分岐の中でしか
            # 代入されないのに、下の DAVE 復号はその外で使っている。user=None
            # のまま暗号化フレームが来ると UnboundLocalError になり、例外は
            # voice_recv の router スレッドまで抜けてスレッドごと死ぬ
            # （＝そこから先が全員ぶん無音になる）。再接続直後は SSRC の
            # 対応が付く前に音が届くので、実際に起こりうる並びである。
            #
            # 直前まで同じ SSRC で喋っていた人が分かっていれば、その id で
            # 復号できる。分からなければ 0 を渡し、復号は失敗して欠落として
            # 扱われる（下の分岐）。
            user_id = int(getattr(self._users.get(ssrc), "id", 0) or 0)

        stream = self._stream_for(ssrc)
        if user is None:
            stream.unknown += 1
        # Discord の音声は 120。別の番号が混ざっているなら、音声以外の
        # パケットが音声として流れてきている。
        ptype = getattr(packet, "payload", None)
        if ptype is not None:
            stream.payload_types[ptype] = stream.payload_types.get(ptype, 0) + 1

        now = time.monotonic()
        sequence = int(getattr(packet, "sequence", -1))
        encoded = strip_rtp_padding(packet, data.opus)
        known = user is not None
        if encoded is None:
            # 中身がパディングだけ（帯域推定の探査）か、そもそも空。音声ではない。
            # **番号は消費されているので、組み立て側へ必ず伝えること。**
            stream.padding_only += 1
            stream.capture(packet, data.opus, "詰め物", user_known=known)
            if sequence >= 0:
                stream.skip(sequence)
            return
        # **ここでは復号しない（→ _emit）。**
        #
        # DAVE の復号には user_id が要る。ところが音は UDP で届くのに、
        # 「その SSRC が誰か」はゲートウェイの SPEAKING イベントという別経路で
        # 遅れて届く。受信の時点で復号すると、対応が付く前に届いたぶんは
        # user_id が無いので必ず失敗する。本番実測（09:31）の E2EE不可=7 は
        # 7枚とも接続直後のかたまりで、鍵の問題ではなくこれだった。その人が
        # 既に喋っていれば、発話の頭 150ms ほどが毎回落ちることになる。
        #
        # 並べ直しの列（_pending）は**もともと持ち主が分かるまで抱える**作りな
        # ので、復号を取り出すときまで遅らせれば、抱えていたぶんも復号できる。
        # _emit は持ち主が分かっている場合しか回らないので、あちらでは user_id が
        # 必ずある。
        encrypted_frame = bool(encoded) and dave.is_dave_frame(encoded)
        if encoded and sequence >= 0:
            stream.received += 1
            stream.capture(
                packet,
                data.opus,
                "E2EE" if encrypted_frame else "音声",
                user_known=known,
                awaiting=encrypted_frame,
            )
            stream.push(sequence, int(packet.timestamp), encoded, now)
        elif encoded:
            # voice_recv の SilencePacket は sequence が常に -1（rtp.py）。
            # 連番で並べ直す仕組みに入れると、すべて同じ鍵で衝突したうえ、
            # 「もう出した番号より後ろ」と見なされて捨てられる。
            # 中身は無音なので、時間軸の穴埋めに任せて数えるだけにする。
            stream.silence += 1
            stream.capture(packet, data.opus, "無音", user_known=known)

        # 抱えている全ストリームを見る。喋り終えた人の最後のぶんが
        # 出されないまま残り続けないように。
        for other_ssrc, other in list(self._streams.items()):
            # まだ持ち主が分からないものは出さずに抱えておく。ここで drain
            # すると、書き込み先が無いまま _pending から消えて、捨てるのと
            # 同じになる。対応が付いた時点でまとめて出る。
            if self._resolve_user(other_ssrc) is None:
                continue
            self._emit(other_ssrc, other, other.drain(now))

    def _emit(self, ssrc: int, stream: _StreamAssembler, ready) -> None:
        """並べ直しが完了したパケット群をデコードし、トラックへ書き込む。

        時間軸の起点をどう取るかで実際に時間がずれるバグを踏んでいるため、
        起点の選び方はメソッド内のコメントを必ず読むこと。
        """
        if not ready:
            return
        user = self._users.get(ssrc)
        if user is None:
            return
        # 時間軸の起点は「受信した時刻」で取る。ここで self.session.elapsed
        # （＝出したときの時刻）を使っていたため、並べ直しで抱えていた
        # あいだのぶんだけトラックまるごと後ろへずれていた。
        #
        # drain() は誰かのパケットが届いたときにしか回らない。ある人が
        # 一言だけ話して黙ると、その声は「次に誰かが話すまで」抱えられた
        # ままになり、そのときの時刻を起点にされる。実測では 5.00 秒に
        # 話した声が 20.00 秒の位置に書き込まれた（次の発話が 20.00 秒
        # だったため）。しかも起点は最初のパケットで決まるので、以後の
        # 音は全部そのぶんずれたまま。トラックごとにずれ幅が違うのは、
        # 「次に誰かが話した時刻」がトラックごとに違うため。
        started_at = self.session.started_at
        user_id = int(getattr(user, "id", 0) or 0)
        for timestamp, encoded, arrived_at in ready:
            if encoded is not None and dave.is_dave_frame(encoded):
                # 端から端まで暗号化されている。復号してから渡す。
                # 暗号文のまま Opus に食わせると、例外にならず雑音が返る。
                plain = dave.decrypt_opus(self._client(), user_id, encoded)
                if plain is None:
                    stream.encrypted += 1
                    self.session.note_encrypted()
                    stream.stamp_capture(timestamp, "E2EE不可")
                    stream.undecryptable_run += 1
                    # **黙って飛ばさないこと。** 飛ばすとその 20ms が
                    # pad_until でまるごと無音になり、発話の途中に穴が開いて
                    # 途切れ途切れに聞こえる。None を渡して前後を繋がせる。
                    #
                    # ただし続けて失敗しているなら話は別で、そこは「取り
                    # 出せなかった」ではなく「そもそも鍵が無い」である。
                    # 無い音を作り続けても仕方がないので、drain() の欠落補間と
                    # 同じ上限で打ち切る。
                    if stream.undecryptable_run > _PLC_MAX_FRAMES:
                        continue
                    encoded = None
                else:
                    encoded = plain
                    stream.decrypted += 1
                    stream.undecryptable_run = 0
                    stream.stamp_capture(timestamp, "E2EE復号")
            if encoded is not None:
                # 位置の計算は 20ms 固定を前提にしている（_FRAME_SAMPLES）。
                # 崩れたら黙ってずれるのではなく、数として出す。復号したあと
                # でないと Opus の TOC が読めないので、受信時ではなくここで見る。
                samples = opus_frame_samples(encoded)
                if samples is not None and samples != _FRAME_SAMPLES:
                    stream.odd_frames += 1
            try:
                pcm = stream.decode(encoded)
            except Exception as e:
                # 壊れたパケットは捨てて続ける。毎回ログを出すと洪水になるので
                # 数は最後にまとめて残し、中身は最初の数件だけ記録する
                # （数だけ見ても何が起きたのか分からなかったため）。
                self.session.dropped_packets += 1
                stream.failed += 1
                if stream.failed <= _FAILURE_SAMPLES:
                    logger.warning(
                        "[recording] デコード失敗 ssrc=%s %s: %s / %d バイト "
                        "先頭=%s 末尾=%s ここまで成功=%d 失敗=%d 種別=%s",
                        ssrc,
                        type(e).__name__,
                        e,
                        0 if encoded is None else len(encoded),
                        "（欠落補間）" if encoded is None else encoded[:12].hex(),
                        "-" if encoded is None else encoded[-6:].hex(),
                        stream.decoded,
                        stream.failed,
                        stream.payload_types,
                    )
                continue
            stream.decoded += 1
            elapsed = arrived_at - started_at
            self.session.feed(user, pcm, at=stream.offset_for(timestamp, elapsed))

    def flush_pending(self) -> None:
        """停止時に、抱えたままのパケットを書き出す。"""
        for ssrc, stream in list(self._streams.items()):
            # 最後にもう一度、持ち主が分かるか試す。ここまで分からなければ
            # 書き出す先が無いので、抱えていた数を溢れとして残して捨てる。
            if self._resolve_user(ssrc) is None:
                stream.overflow += len(stream._pending)
                stream._pending.clear()
                continue
            self._emit(ssrc, stream, stream.flush())
        self._collect_stats()
        self.log_summary()

    def _collect_stats(self) -> None:
        """ストリームごとの内訳をセッションへ写す。

        **sink から直接読ませないこと。** 停止時、voice_recv の
        `AudioReader.stop()` は cleanup() を別スレッドで起こす（reader.py）
        ので、cleanup() は flush_pending() と競走する。書き出し（_finalize）は
        さらにそのあと別スレッドで走るため、そこで sink を見に行くと空の
        ことがある。負けた側が空で上書きしないよう、中身があるときだけ書く。
        """
        if not self._streams:
            return
        stats = []
        capture = []
        for ssrc, stream in self._streams.items():
            entry = stream.snapshot()
            user = self._users.get(ssrc)
            entry["user_id"] = int(getattr(user, "id", 0) or 0)
            entry["name"] = str(getattr(user, "display_name", "") or "")
            stats.append(entry)
            if stream.captured:
                capture.append(
                    {
                        "ssrc": ssrc,
                        "name": entry["name"],
                        "packets": stream.captured,
                        "skipped": stream.capture_skipped,
                    }
                )
        self.session.receive_stats = stats
        self.session.packet_capture = capture

    def log_summary(self) -> None:
        """ストリームごとの内訳。数だけでは何が起きたか分からないため。

        数字は _collect_stats() が集めたものをそのまま出す。ログと ZIP で
        別々に組み立てると、片方だけ直したときに黙って食い違う。
        """
        jitter = voice_jitter.stats()
        if not jitter["installed"]:
            # 差し替えに失敗している。穴が空くたびにライブラリ側が
            # パケットを捨てるので、下の「欠落」はそのぶん多く出る。
            logger.warning("[recording] ジッタバッファを差し替えられていません（損失が増えます）")
        elif jitter["late_rejected"]:
            # 差し込むには遅すぎた到着。こちらの並べ直しを延ばしても届かない。
            logger.info(
                "[recording] 遅すぎて受け取れなかったパケット=%d（プロセス全体の累計）",
                jitter["late_rejected"],
            )
        for entry in self.session.receive_stats:
            logger.info(
                "[recording] ssrc=%s (%s) 受信=%d 成功=%d 失敗=%d "
                "E2EE復号=%d E2EE不可=%d 詰め物=%d 欠落=%d 手遅れ=%d 無音=%d "
                "張り直し=%d 不明=%d 溢れ=%d 飛び=%d 異長=%d "
                "RTP種別=%s",
                entry["ssrc"],
                entry["name"] or entry["ssrc"],
                entry["received"],
                entry["decoded"],
                entry["failed"],
                entry["decrypted"],
                entry["encrypted"],
                entry["padding_only"],
                entry["lost"],
                entry["late"],
                entry["silence"],
                entry["rebased"],
                entry["unknown"],
                entry["overflow"],
                entry["jumped"],
                entry["odd_frames"],
                entry["payload_types"],
            )

    def cleanup(self) -> None:
        """録音停止後にストリーム状態を解放する。参照を残すとセッションのたびに
        メモリが積み上がる。

        捨てる前に内訳を写す。flush_pending() より先にここへ来ることがある
        （→ _collect_stats）ので、写さずに捨てると内訳がまるごと消える。
        """
        self._collect_stats()
        self._streams.clear()
        self._users.clear()


def _make_sink_class():
    """AudioSink の実装を返す。受信拡張が無い環境では import 自体ができない。

    中身は _RecordingSinkBase にある。ここでやるのは、それに
    `voice_recv.AudioSink` を継ぎ足すことだけ。**継承の形を変えないこと** —
    `listen()` は AudioSink のサブクラスしか受け取らないので、外すと単体
    テストは全部通るのに本番で録音の開始そのものが失敗する。
    """
    from discord.ext import voice_recv

    class _RecordingSink(_RecordingSinkBase, voice_recv.AudioSink):
        """_RecordingSinkBase に AudioSink を継ぎ足しただけの実体。"""

    return _RecordingSink


# ── セッション ────────────────────────────────────────────────


@dataclass
class RecordingSession:
    guild_id: int
    channel_id: int
    channel_name: str
    started_by_id: int
    started_by_name: str
    started_at: float
    max_seconds: int
    retention_days: int
    excluded_user_ids: set[int] = field(default_factory=set)
    workdir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="rec-")))
    tracks: dict[int, _TrackWriter] = field(default_factory=dict)
    stopping: bool = False
    dropped_packets: int = 0  # デコードできず捨てたパケット数
    encrypted_frames: int = 0  # E2EE（DAVE）で復号できなかったフレーム数
    voice_frames: int = 0  # 受け取った音声フレームの総数
    # ストリーム（SSRC）ごとの受信の内訳。停止時に sink から写す（→ _collect_stats）。
    # sink 側に置いたままだと、書き出しの時点では解放済みかもしれない。
    receive_stats: list[dict] = field(default_factory=list)
    # そのまま控えたパケット（ストリームごと）。同じく停止時に sink から写す。
    packet_capture: list[dict] = field(default_factory=list)
    announce_message: discord.Message | None = None
    sink: object | None = None  # 停止時に、並べ直し待ちのパケットを書き出す
    _guard_task: asyncio.Task | None = None

    @property
    def elapsed(self) -> float:
        """録音開始からの経過秒数（monotonic 時計基準）。"""
        return time.monotonic() - self.started_at

    @property
    def is_unlimited(self) -> bool:
        """時間では止めない設定か（VC が無人になるまで録り続ける）。"""
        return self.max_seconds <= 0

    @property
    def output_bytes(self) -> int:
        """書き出し済みファイルの合計バイト数。stat に失敗したトラック
        （書き込み中に消えた等）は黙って0扱いで無視する。
        """
        total = 0
        for track in self.tracks.values():
            try:
                total += track.out_path.stat().st_size
            except OSError:
                continue
        return total

    def note_encrypted(self) -> None:
        """E2EE のフレームを受け取ったことを記録する。

        受信スレッドから呼ばれる。ここで停止処理はせず、数を残すだけにする
        （見張りの側で、割合を見てから判断する）。
        """
        self.encrypted_frames += 1
        self.voice_frames += 1

    @property
    def is_end_to_end_encrypted(self) -> bool:
        """このセッションは E2EE で、まともな音を録れないか。

        まだ数が少ないうちは判断しない（切り替わりの途中で数フレームだけ
        暗号化されていることがあるため）。
        """
        return self.voice_frames >= _DAVE_MIN_SAMPLES and self.encrypted_frames >= self.voice_frames * _DAVE_RATIO

    def feed(self, user, pcm: bytes, at: float | None = None) -> None:
        """PCM を書く。at は録音開始からの秒数（None なら現在時刻）。

        at には RTP タイムスタンプから求めた位置を渡す。到着時刻で置くと、
        ジッタのぶんだけ無音が挟まったり詰まったりして時間軸が歪む。
        """
        if self.stopping or not pcm:
            return
        self.voice_frames += 1
        user_id = int(getattr(user, "id", 0) or 0)
        if not user_id or user_id in self.excluded_user_ids:
            return

        track = self.tracks.get(user_id)
        if track is None:
            display = getattr(user, "display_name", None) or getattr(user, "name", None) or str(user_id)
            index = len(self.tracks) + 1
            safe = "".join(c for c in str(display) if c.isalnum() or c in " ._-()").strip()[:40]
            out = self.workdir / f"{index:02d}-{safe or user_id}.mp3"
            try:
                track = _TrackWriter(user_id, str(display), out, self.started_at)
            except Exception as e:
                logger.exception("[recording] トラックを開始できません user=%s: %s", user_id, e)
                return
            self.tracks[user_id] = track
            logger.info("[recording] guild=%s トラック追加: %s", self.guild_id, display)

        track.write(pcm, self.elapsed if at is None else at)

    def status(self) -> dict:
        """管理画面や停止時の embed に渡す、このセッションのスナップショット。"""
        return {
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "channel_name": self.channel_name,
            "started_by": self.started_by_name,
            "started_at": self.started_at,
            "elapsed_seconds": int(self.elapsed),
            "max_seconds": self.max_seconds,
            "unlimited": self.is_unlimited,
            "speakers": [
                {"user_id": t.user_id, "name": t.display_name, "voiced_seconds": round(t.voiced_seconds, 1)}
                for t in self.tracks.values()
            ],
            "output_bytes": self.output_bytes,
            "dropped_packets": self.dropped_packets,
            "excluded": sorted(self.excluded_user_ids),
        }


# ── 開始 / 停止 ───────────────────────────────────────────────


# 管理画面は Bot とは別プロセスなので、メモリ上の状態が見えない。
# 開始・停止のたびに共有ディレクトリへ書き出して、そちらから読めるようにする
# （開発者パネルのシグナルと同じ考え方）。
def _state_file() -> Path:
    # settings_store.py と同じ SETTINGS_DIR を見る。素の os.getenv(..., 既定値) は
    # SETTINGS_DIR="" （空文字で宣言だけされている）のとき既定値へ倒れず
    # Path("") = カレントディレクトリになる。Bot と管理画面プロセスとで
    # カレントディレクトリが違うと、書いた場所と読む場所がずれて「録音中」の
    # 表示が黙って更新されなくなる。
    """録音状態ファイルのパスを返す。settings_store.py と同じ SETTINGS_DIR を
    見ることで、Bot と管理画面が別プロセスでも同じ場所を読み書きできる。
    """
    default_dir = Path(__file__).resolve().parent.parent / "data"
    return env_path("SETTINGS_DIR", default_dir) / "_recording_state.json"


def _write_state() -> None:
    """現在の全セッションの状態を共有ファイルへ書き出す。

    settings.json と同様に一時ファイル経由でアトミックに置き換える。
    書き込みに失敗しても録音自体は止めない（表示が古いままになるだけに
    留める）。
    """
    try:
        path = _state_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.time(),
            "sessions": {str(s.guild_id): s.status() for s in _sessions.values()},
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as e:
        logger.warning("[recording] 状態ファイルを書けませんでした: %s", e)


def read_state() -> dict:
    """管理画面から読む用。Bot 側が書いた状態をそのまま返す。"""
    try:
        return cast(dict, json.loads(_state_file().read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return {"updated_at": 0, "sessions": {}}


def get_session(guild_id: int) -> RecordingSession | None:
    """実行中の録音セッションを返す（無ければ None）。"""
    return _sessions.get(guild_id)


def is_recording(guild_id: int) -> bool:
    """このギルドで録音中かどうか。"""
    return guild_id in _sessions


async def start_recording(
    bot,
    guild: discord.Guild,
    channel: discord.VoiceChannel,
    *,
    started_by: discord.abc.User,
    announce_to: discord.abc.Messageable | None = None,
) -> RecordingSession:
    """録音を開始する。既に録音中なら RecordingError。"""
    from services.settings_store import get_recording_settings

    if not voice_session.RECEIVE_AVAILABLE:
        raise RecordingError(
            "この環境では音声を受信できないため録音できません"
            f"（{voice_session.receive_unavailable_reason() or 'discord-ext-voice-recv が未導入'}）。"
        )
    if guild.id in _sessions:
        raise RecordingError("このサーバーでは既に録音中です。先に停止してください。")

    settings = get_recording_settings(guild.id)
    if not settings.get("enabled", True):
        raise RecordingError("録音機能が無効になっています。管理画面で有効にしてください。")

    client = await voice_session.acquire(guild, channel.id, purpose="recording")
    if client is None:
        raise RecordingError("VC に接続できませんでした。")
    if not voice_session.can_receive(client):
        raise RecordingError(
            "今の接続では音声を受信できません。読み上げが先に接続している場合は、"
            "一度 VC から退出させてからもう一度お試しください。"
        )

    session = RecordingSession(
        guild_id=guild.id,
        channel_id=channel.id,
        channel_name=channel.name,
        started_by_id=int(getattr(started_by, "id", 0) or 0),
        started_by_name=str(getattr(started_by, "display_name", None) or started_by),
        started_at=time.monotonic(),
        max_seconds=max(0, int(settings.get("max_minutes", 360))) * 60,
        retention_days=int(settings.get("retention_days", 7)),
        excluded_user_ids={int(u) for u in settings.get("excluded_user_ids", [])},
    )

    sink_cls = _make_sink_class()
    session.sink = sink_cls(session)
    # listen() より前に置くこと。ジッタバッファは SSRC ごとの decoder が
    # 自分で作るので、聞き始めたあとに差し替えても既存の decoder には
    # 効かない（services/voice_jitter.py）。
    voice_jitter.install()
    try:
        # listen は受信拡張（VoiceRecvClient）側の API。discord.py 本体の
        # 型には無いので、型検査にだけ黙ってもらう。
        client.listen(session.sink)  # type: ignore[attr-defined]
    except Exception as e:
        shutil.rmtree(session.workdir, ignore_errors=True)
        raise RecordingError(f"録音を開始できませんでした（{e}）。") from e

    _sessions[guild.id] = session
    voice_session.hold(guild.id, "recording")
    _write_state()

    # 録音していることは必ず知らせる。黙って録るための機能ではない。
    session.announce_message = await _announce_start(channel, session, announce_to)
    session._guard_task = asyncio.create_task(_guard(bot, guild.id))
    logger.info(
        "[recording] guild=%s ch=%s 開始（上限 %d 分 / %s）",
        guild.id,
        channel.id,
        session.max_seconds // 60,
        session.started_by_name,
    )
    return session


def preferred_vc_channel_id(guild_id: int) -> int | None:
    """このギルドで「録るのが自然な VC」。

    設定していなければ読み上げの対象VCに従う。読み上げと録音は同じ音声接続を
    共有するので、既定では同じ VC を見る（「両方オンなら両方使う」という状態を、
    設定を2箇所書かずに作れるように）。録音だけ別の VC を狙いたいときだけ
    vc_channel_id を明示する。

    自動録音のスイッチとは無関係に返す。手動で始めるときの初期値としても使う
    （毎回ゼロから選び直させないため）。
    """
    from services.settings_store import get_recording_settings

    explicit = get_recording_settings(guild_id).get("vc_channel_id")
    if explicit:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            return None

    # TTS 側の対象VCに合わせる。TTS が無効でも「どのVCか」の設定は読める。
    try:
        from services.tts_service import get_effective_vc_watch
        from services.tts_store import get_tts_settings

        watched, _ = get_effective_vc_watch(guild_id, get_tts_settings(guild_id))
        return int(watched) if watched else None
    except Exception as e:
        logger.debug("[recording] TTS の対象VCを読めませんでした guild=%s: %s", guild_id, e)
        return None


def auto_start_channel_id(guild_id: int) -> int | None:
    """自動録音の対象VC。スイッチが両方オンのときだけ返す。"""
    from services.settings_store import get_recording_settings

    settings = get_recording_settings(guild_id)
    if not settings.get("enabled", True) or not settings.get("auto_start"):
        return None
    return preferred_vc_channel_id(guild_id)


async def maybe_start_for_channel(bot, guild, channel, *, trigger: str = "自動") -> None:
    """その VC で自動録音の条件が揃っていれば録り始める。

    「人が入った」だけでなく、読み上げが VC に入った（/tts join など）ときの
    入口でもある。読み上げと録音は独立したスイッチなので、両方オンなら
    どちらの入口から入っても両方が動く、という状態にするため。

    条件が揃わない場合は静かに何もしない（呼ばれるたびに警告を出さない）。
    """
    if guild is None or channel is None:
        return
    if guild.id in _sessions:
        return  # すでに録音中
    if not voice_session.RECEIVE_AVAILABLE:
        return
    if auto_start_channel_id(guild.id) != channel.id:
        return
    # 誰もいない VC を録りに行かない（bot だけが入った直後など）。
    # 参加者を読めない相手のときは判断を保留し、開始を妨げない
    # （空のまま録れてしまっても、無人判定で程なく書き出される）。
    try:
        members = list(getattr(channel, "members", None) or [])
    except TypeError:
        members = None
    if members is not None and not any(m for m in members if not getattr(m, "bot", False)):
        return

    try:
        await start_recording(bot, guild, channel, started_by=guild.me or bot.user)
        logger.info(
            "[recording] guild=%s ch=%s 自動録音を開始しました（きっかけ: %s）",
            guild.id,
            channel.id,
            trigger,
        )
    except RecordingError as e:
        # 自動で走る経路なので、失敗しても呼び出し元の処理は妨げない。
        logger.warning("[recording] guild=%s 自動録音を開始できませんでした: %s", guild.id, e)


async def maybe_auto_start(bot, member, channel) -> None:
    """人が VC に入ったときの入口。"""
    if getattr(member, "bot", False):
        return
    await maybe_start_for_channel(
        bot,
        getattr(member, "guild", None),
        channel,
        trigger="入室",
    )


def resolve_announce_channel(guild, *, fallback=None):
    """録音の通知先。設定してあればそこ、無ければ渡された代替先。

    「通知チャンネル」の設定は保存も表示もされていたのに、通知を送る側が
    一度も読んでいなかった（設定しても何も起きない状態だった）。開始告知と
    完了通知の両方がここを通る。
    """
    if guild is None:
        return fallback
    try:
        from services.settings_store import get_recording_settings

        channel_id = get_recording_settings(guild.id).get("announce_channel_id")
    except Exception as e:
        logger.debug("[recording] 通知先の設定を読めませんでした guild=%s: %s", guild.id, e)
        return fallback
    if not channel_id:
        return fallback

    channel = guild.get_channel(int(channel_id))
    if channel is None or not isinstance(channel, discord.abc.Messageable):
        logger.warning(
            "[recording] guild=%s 通知チャンネル（%s）が見つからないか送信できません。" "既定の送信先を使います",
            guild.id,
            channel_id,
        )
        return fallback
    return channel


async def _announce_start(
    channel: discord.VoiceChannel,
    session: RecordingSession,
    announce_to: discord.abc.Messageable | None,
) -> discord.Message | None:
    """録音開始を告知するメッセージを送る。

    設定した通知先→呼び出し元のチャンネル→VCのチャット欄の順で試し、
    送れた最初の1つを使う。全滅なら None を返し、以降の停止処理は
    「告知メッセージの編集」を諦める。
    """
    embed = discord.Embed(
        title="🔴 このボイスチャンネルの録音を開始しました",
        description=(
            f"**{channel.name}** の音声を録音しています。参加者ごとに別トラックで記録されます。\n"
            "録音されたくない場合は、VC から退出するか、管理者に除外を依頼してください。"
        ),
        color=discord.Color.red(),
    )
    embed.add_field(name="開始した人", value=session.started_by_name, inline=True)
    embed.add_field(
        name="自動停止",
        value="全員が退出したとき" if session.is_unlimited else f"{session.max_seconds // 60} 分後",
        inline=True,
    )
    embed.set_footer(text="停止すると、ダウンロード用のリンクが投稿されます。")

    # 設定した通知先が最優先。次にコマンドを打った場所、最後に VC のチャット欄。
    configured = resolve_announce_channel(getattr(channel, "guild", None))
    targets = [t for t in (configured, announce_to, channel) if t is not None]
    for target in targets:
        try:
            return await target.send(embed=embed)
        except Exception as e:
            logger.debug("[recording] 開始通知を送れませんでした: %s", e)
    logger.warning("[recording] guild=%s 開始を知らせる先がありませんでした", session.guild_id)
    return None


def _is_receiving(guild_id: int) -> bool:
    """まだ音声を受信できている状態か。

    voice_recv は受信スレッドで例外が起きると stop_listening() を呼んで
    黙って受信をやめる（デコードできないパケット1つでも起きうる）。
    接続そのものは生きているので、listening かどうかで見分ける。
    """
    client = voice_session.get(guild_id)
    if client is None:
        return False
    is_listening = getattr(client, "is_listening", None)
    if is_listening is None:
        return True  # 判断できないなら止めない
    try:
        return bool(is_listening())
    except Exception as e:
        # is_listening() 自体が例外を投げるのは想定外だが、ここでも方針は
        # 上と同じ「判断できないなら止めない」。ただし想定外の失敗である
        # ことは分かるようにしておく（voice_recv 側の変化に気づく手がかり）。
        logger.debug("[recording] guild=%s is_listening() が失敗しました: %s", guild_id, e)
        return True


def _vc_is_empty(bot, session: "RecordingSession") -> bool:
    """録音中の VC から人間が居なくなったか。判断できないときは False。"""
    guild = bot.get_guild(session.guild_id)
    if guild is None:
        return False
    channel = guild.get_channel(session.channel_id)
    members = getattr(channel, "members", None)
    if members is None:
        return False
    return not any(m for m in members if not m.bot)


async def _announce_stop(bot, session: "RecordingSession", result: dict) -> None:
    """guard が自分の判断で止めた結果を知らせる。

    手動停止（スラッシュコマンド／管理画面）は呼び出し元が build_result_embed を
    送るが、guard がここで自発的に止める経路には送り先を持つ人がいない。
    開始告知と同じ優先順位（設定した通知先 → 開始告知を出した場所 →
    VC のチャット欄）で送る。ダウンロードリンクを一切知らせないまま
    ファイルだけ出来上がる、という状態を避けるため。
    """
    guild = bot.get_guild(session.guild_id) if bot is not None else None
    embed = build_result_embed(session.guild_id, result)
    configured = resolve_announce_channel(guild)
    announced = session.announce_message.channel if session.announce_message else None
    channel = guild.get_channel(session.channel_id) if guild is not None else None
    for target in (configured, announced, channel):
        if target is None or not isinstance(target, discord.abc.Messageable):
            continue
        try:
            await target.send(embed=embed)
            return
        except Exception as e:
            logger.debug("[recording] 停止通知を送れませんでした: %s", e)
    logger.warning(
        "[recording] guild=%s 停止結果を知らせる先がありませんでした（token=%s）",
        session.guild_id,
        result.get("token"),
    )


async def _guard_stop(bot, guild_id: int, session: "RecordingSession", reason: str) -> None:
    """guard が停止条件を見つけたときの共通処理: 止めて、結果を知らせる。"""
    result = await stop_recording(bot, guild_id, reason=reason)
    await _announce_stop(bot, session, result)


async def _guard(bot, guild_id: int) -> None:
    """上限時間に達したら自動で停止する。あわせて VC の無人化も見張る。

    無人化は on_voice_state_update でも拾っているが、イベントを取り逃す
    （bot の再接続中に全員が抜けた等）と誰も止める人がいなくなる。上限時間なし
    で録っているときはそれが「無音を録り続ける」ではなく「永久に止まらない」に
    なるため、ここでも定期的に確かめる。
    """
    session = _sessions.get(guild_id)
    if session is None:
        return
    try:
        while guild_id in _sessions and not session.stopping:
            if not session.is_unlimited:
                remaining = session.max_seconds - session.elapsed
                if remaining <= 0:
                    logger.info("[recording] guild=%s 上限時間に達したので停止します", guild_id)
                    await _guard_stop(bot, guild_id, session, "上限時間に達しました")
                    return
                interval = min(_GUARD_INTERVAL_SEC, max(1.0, remaining))
            else:
                interval = _GUARD_INTERVAL_SEC

            # 端から端まで暗号化されていたら、録れているのは雑音だけ。
            # 気づかずに録り続けても、聞けないものが出来上がるだけなので止める。
            if session.is_end_to_end_encrypted:
                logger.warning(
                    "[recording] guild=%s この通話は端から端まで暗号化されている"
                    "（DAVE）ため録音できません。%d/%d フレームが暗号化されていました",
                    guild_id,
                    session.encrypted_frames,
                    session.voice_frames,
                )
                await _guard_stop(bot, guild_id, session, dave.unavailable_reason())
                return

            # 受信スレッドが落ちていないか。voice_recv は内部でエラーが起きると
            # stop_listening() を呼んで受信をやめるが、こちらのセッションは
            # 「録音中」のまま残る。放っておくと、途中で切れた録音が最後まで
            # 録れたように見えてしまうので、気づいた時点で書き出す。
            if not _is_receiving(guild_id):
                logger.warning(
                    "[recording] guild=%s 音声の受信が止まっていたので書き出します",
                    guild_id,
                )
                await _guard_stop(bot, guild_id, session, "音声の受信が止まりました")
                return

            # 開始直後は参加者のキャッシュが揃っていないことがあるので少し待つ
            if session.elapsed > _EMPTY_GRACE_SEC and _vc_is_empty(bot, session):
                logger.info("[recording] guild=%s VC が無人になったので停止します", guild_id)
                await _guard_stop(bot, guild_id, session, "VC が空になりました")
                return

            _write_state()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        raise
    except RecordingError as e:
        # 他の経路（コマンド／管理画面／on_voice_state_update）と競合して
        # 既に止められていた、などのレース。二重停止自体は害がないので、
        # 「なぜ何もしなかったか」だけ残して終える。
        logger.info("[recording] guild=%s guard: 既に停止済みでした（%s）", guild_id, e)
    except Exception as e:
        logger.exception("[recording] guard error guild=%s: %s", guild_id, e)


async def stop_recording(bot, guild_id: int, *, reason: str = "") -> dict:
    """録音を止めて ZIP にまとめ、ダウンロード用のトークンを返す。"""
    session = _sessions.get(guild_id)
    if session is None:
        raise RecordingError("このサーバーでは録音していません。")
    if session.stopping:
        raise RecordingError("停止処理中です。")

    # 先に受信を止め、並べ直し待ちのぶんを書き出してから停止扱いにする。
    # 順序を入れ替えると feed() が stopping で弾かれ、末尾の音（最大 0.2 秒）が
    # 毎回失われる。await を挟まないので、この間に二重停止は入り込めない。
    client = voice_session.get(guild_id)
    if client is not None and hasattr(client, "stop_listening"):
        try:
            client.stop_listening()
        except Exception as e:
            logger.debug("[recording] stop_listening: %s", e)
    if session.sink is not None:
        try:
            # flush_pending はこのファイルで定義している Sink の API。
            # session.sink の型が広いので、型の上では見えない。
            session.sink.flush_pending()  # type: ignore[attr-defined]
        except Exception:
            logger.exception("[recording] 残りのパケットを書き出せませんでした")

    session.stopping = True
    total_elapsed = session.elapsed
    _sessions.pop(guild_id, None)
    _write_state()

    # guard 自身が上限時間・DAVE検出・受信停止・VC無人化を見つけて
    # stop_recording() を呼ぶ場合、ここでの caller は guard タスクそのもの。
    # asyncio の Task.cancel() は「自分自身」に対して呼んでも即座には効かず、
    # 次に本当にサスペンドする await（_release_if_unused の中の
    # client.disconnect() など）で CancelledError が飛んでくる。その結果
    # asyncio.to_thread(_finalize, ...) まで辿り着けず、ZIP 化もアーカイブの
    # 登録も完了通知も一切行われないまま、ログも残さず黙って終わっていた
    # （cancel されたタスクは「例外を拾われなかった」警告の対象にもならない）。
    # guard は stop_recording() の直後に return するだけなので、自分自身を
    # キャンセルする意味はそもそもない。他のタスク（コマンド／管理画面）から
    # 呼ばれた場合だけ、まだ回っている guard ループを止める。
    if session._guard_task and not session._guard_task.done() and session._guard_task is not asyncio.current_task():
        session._guard_task.cancel()

    voice_session.unhold(guild_id, "recording")
    await _release_if_unused(guild_id)

    # ffmpeg の終了とアーカイブ作成はブロッキングなので別スレッドで行う。
    try:
        result = await asyncio.to_thread(_finalize, session, total_elapsed, reason)
    except Exception as e:
        # ここで作業ディレクトリを消すと、録れていた音まで道連れになる。
        # 書き出しの手前までは成功しているかもしれないので、場所を残して知らせる。
        logger.exception(
            "[recording] guild=%s 書き出しに失敗: %s。" "録れた音は %s に残してあります（手動で回収できます）",
            guild_id,
            e,
            session.workdir,
        )
        raise RecordingError(
            f"録音の書き出しに失敗しました（{e}）。" f"録れた音はサーバー上の {session.workdir} に残してあります。"
        ) from e

    logger.info(
        "[recording] guild=%s 停止（%s / %d トラック / %.1f 分 / 取りこぼし %d パケット）",
        guild_id,
        result["token"],
        result["track_count"],
        total_elapsed / 60,
        session.dropped_packets,
    )
    return result


async def _release_if_unused(guild_id: int) -> None:
    """録音が終わったあと、他に使う人がいなければ VC から出る。

    録音だけのために入った接続を掴んだままにすると、bot が VC に居座る。
    読み上げが同じ VC を使っているあいだは残す（そちらの退出条件に任せる）。
    """
    if voice_session.is_held(guild_id):
        return

    try:
        from services.tts_service import get_effective_vc_watch
        from services.tts_store import get_tts_settings

        settings = get_tts_settings(guild_id)
        if settings.get("enabled"):
            watched, _ = get_effective_vc_watch(guild_id, settings)
            if watched and int(watched) == voice_session.channel_id(guild_id):
                return
    except Exception as e:
        logger.debug("[recording] 読み上げの利用状況を読めませんでした guild=%s: %s", guild_id, e)

    if await voice_session.release(guild_id):
        logger.info("[recording] guild=%s 録音の終了に伴い VC から退出しました", guild_id)


def _has_audio(track: _TrackWriter) -> bool:
    """書き出しに成功したトラックか。

    索引(manifest)と ZIP の両方がこの1つの判定を使う。別々に書くと、
    **索引にはあるのに ZIP に無い**トラックができ、ミキサーがその1本
    だけ 404 になる。書き出し自体は成功するので、開くまで気づけない。
    """
    return track.out_path.exists() and track.out_path.stat().st_size > 0


# 受信カウンタの日本語名。並び順がそのまま info.json と info.txt の並びになる。
# 先に来るものほど、途切れの原因を切り分けるときに先に見たいもの。
_STAT_LABELS = (
    ("received", "受信"),
    # decoded は欠落補間で作ったぶんも数えるので、「受信」より多くなることが
    # ある。ラベルにそう書いておかないと、読んだ人が数え違いを疑う。
    ("decoded", "デコードできた(補間込み)"),
    ("lost", "欠落"),
    ("padding_only", "詰め物"),
    ("encrypted", "E2EE不可"),
    ("decrypted", "E2EE復号"),
    ("failed", "デコード失敗"),
    ("late", "手遅れ"),
    ("silence", "無音"),
    ("rebased", "起点の張り直し"),
    ("jumped", "時計の飛び"),
    ("unknown", "持ち主不明のまま受信"),
    ("overflow", "溢れ"),
    ("odd_frames", "20msでない長さ"),
)
# info.txt に出す価値がない（0 でなくても正常な）カウンタ。
# 「無音」は発話の切れ目ごとに必ず来るし、「受信」「復号できた」は多いのが
# 正常なので、並べると本当に見るべきものが埋もれる。
_STAT_QUIET = frozenset({"received", "decoded", "silence", "decrypted"})


def _receive_breakdown(session: RecordingSession) -> dict:
    """info.json に載せる「受信の内訳」。

    これまで内訳はログの `[recording] ssrc=…` 行にしか出ていなかった。実際に
    「音が途切れ途切れになる」を追ったとき、本番のログが手元に無く、書き出した
    mp3 の波形を測って穴の幅と間隔から原因を絞り込む羽目になった。**録音を
    受け取った人の手元にある ZIP だけで切り分けられる**ようにしておく。

    話者ごとにまとめるのは、再接続すると同じ人に別の SSRC が振られるため。
    SSRC のまま並べると、1人が複数行に散って読み手が足し算をすることになる。
    持ち主が分からないまま終わったストリームは、混ぜずに別立てで残す
    （そこに数が溜まっていること自体が、対応が付いていないという情報になる）。
    """
    jitter = voice_jitter.stats()
    by_speaker: dict[int, dict] = {}
    for entry in session.receive_stats:
        user_id = int(entry.get("user_id", 0) or 0)
        name = entry.get("name") or f"（不明 ssrc={entry['ssrc']}）"
        row = by_speaker.setdefault(user_id, {"名前": name})
        for key, label in _STAT_LABELS:
            row[label] = row.get(label, 0) + int(entry.get(key, 0) or 0)

    speakers = []
    for row in by_speaker.values():
        # 「音があったのに使えなかった」割合。
        #
        # **詰め物を入れないこと。** 詰め物（帯域推定の探査）にははじめから
        # 音が入っていないので、取り出し損ねたのではない。数えると健全な
        # 録音が壊れて見える。本番の実測では、接続直後に探査が 50 枚まとめて
        # 届いた録音が 7.28%（詰め物込み）と 0.89%（詰め物なし）で 8 倍
        # ちがった。読んだ人が回線を疑うところから始めてしまう。
        #
        # 分母には欠落を足す。received は「音声として受け取った数」なので、
        # 届かなかったぶんはそこに入っていない。
        missed = row["欠落"] + row["E2EE不可"] + row["デコード失敗"]
        total = row["受信"] + row["欠落"]
        row["取り出せなかった割合(%)"] = round(missed / total * 100, 2) if total else 0.0
        speakers.append(row)

    kept = sum(len(c["packets"]) for c in session.packet_capture)
    return {
        "ジッタバッファ": {
            "差し替え済み": bool(jitter["installed"]),
            "手遅れで受け取れなかった": int(jitter["late_rejected"]),
        },
        "控えたパケット": {
            "件数": kept,
            "控えきれず省いた": sum(int(c["skipped"]) for c in session.packet_capture),
            "ファイル": CAPTURE_NAME if kept else None,
        },
        "話者別": speakers,
    }


def _breakdown_lines(info: dict) -> list[str]:
    """info.txt へ出す、内訳のうち 0 でないものだけ。

    全部並べると健全な録音でも十数行になり、読み飛ばされる。**行が出て
    いること自体が「見るべきものがある」の合図**になるようにしておく。
    """
    breakdown = cast("dict[str, Any]", info.get("受信の内訳") or {})
    jitter = cast("dict[str, Any]", breakdown.get("ジッタバッファ") or {})
    lines: list[str] = []
    for row in cast("list[dict[str, Any]]", breakdown.get("話者別") or []):
        noted = [f"{label}={row[label]}" for key, label in _STAT_LABELS if key not in _STAT_QUIET and row.get(label)]
        if noted:
            lines.append(
                f"  {row['名前']}  " + " ".join(noted) + f"  取り出せなかった割合 {row['取り出せなかった割合(%)']}%"
            )
    if not jitter.get("差し替え済み", True):
        lines.append("  ジッタバッファを差し替えられていません（損失が増えます）")
    elif jitter.get("手遅れで受け取れなかった"):
        lines.append(f"  遅すぎて受け取れなかったパケット {jitter['手遅れで受け取れなかった']}（プロセス全体の累計）")
    if not lines:
        return []
    return ["", "受信の内訳（0 のものは省いています。詳細は info.json）:", *lines]


def _capture_lines(info: dict) -> list[str]:
    """packets.jsonl があることを知らせる1行。

    **「受信の内訳」とは分けること。** あちらは 0 でないものだけを出して、
    行が出ていること自体を「見るべきものがある」の合図にしている。控えた
    パケットは健全な録音でも必ずあるので、同じ枠に入れると合図が潰れる。
    かといって黙っていると、ファイルがあることに誰も気づかない。
    """
    kept = cast("dict[str, Any]", (info.get("受信の内訳") or {}).get("控えたパケット") or {})
    if not kept.get("件数"):
        return []
    note = f"届いたパケットを {kept['件数']} 枚、手を加えずに {kept['ファイル']} へ控えてあります。"
    if kept.get("控えきれず省いた"):
        note += f"（上限に当たった {kept['控えきれず省いた']} 枚は入っていません）"
    return ["", note]


def _finalize_info(session: RecordingSession, total_elapsed: float, reason: str, started_jst: datetime) -> dict:
    """ZIP へ同梱する info.json の中身（人が読む要約の元でもある）。"""
    return {
        "サーバーID": str(session.guild_id),
        "チャンネル": session.channel_name,
        "開始した人": session.started_by_name,
        "書き出し日時": started_jst.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "長さ": f"{int(total_elapsed // 60)}分{int(total_elapsed % 60)}秒",
        "停止理由": reason or "手動停止",
        "取りこぼしたパケット": session.dropped_packets,
        "受信の内訳": _receive_breakdown(session),
        "トラック": [
            {"ファイル": t.out_path.name, "名前": t.display_name, "発話時間(秒)": round(t.voiced_seconds, 1)}
            for t in session.tracks.values()
        ],
    }


def _peak_scale(session: RecordingSession, total_elapsed: float) -> tuple[int, int, float]:
    """波形の縮尺を決める。(間引き幅, 点数, 1点あたりの秒数) を返す。

    縮尺は全トラックで1つに揃え、間引いたあとの「1点＝何秒か」を索引に
    書く。以前は各トラックが自分の長さから間引き幅を決めたうえで、索引には
    間引く前の 0.25 秒を書いていたため、12.5分を超える録音では波形が時間軸の
    先頭へ圧縮され（6時間なら全体が先頭12.4分ぶんに潰れる）、長さの違う
    トラック同士でも縮尺が食い違っていた。
    """
    peak_buckets = max(
        [len(t.peaks) for t in session.tracks.values()] + [math.ceil(max(total_elapsed, 0.0) / PEAK_BUCKET_SECONDS)]
    )
    peak_group = max(1, math.ceil(peak_buckets / PEAK_MAX_POINTS))
    peak_points = math.ceil(peak_buckets / peak_group)
    peak_seconds = round(PEAK_BUCKET_SECONDS * peak_group, 6)
    return peak_group, peak_points, peak_seconds


def _build_stems(
    session: RecordingSession,
    total_elapsed: float,
    peak_group: int,
    peak_points: int,
    peak_seconds: float,
) -> list[dict]:
    """ミキサー（管理画面）が使う索引のトラック一覧。

    index は**全トラックの中での位置**で、ミキサーはこの番号で1本を指す。
    書き出せなかったトラックを飛ばしたぶん番号を詰めると、残りが1つずつ
    ずれて別人の音を指すので、enumerate は絞り込む前に回す。
    """
    stems = []
    for index, track in enumerate(session.tracks.values()):
        if not _has_audio(track):
            continue
        voice = measure_voice(track.out_path, total_elapsed)
        if voice is not None and voice < VOICE_PERIODICITY_MIN:
            logger.warning(
                "[recording] guild=%s %s のトラックが声として成立していない可能性" "（周期性 %.3f < %.2f）",
                session.guild_id,
                track.display_name,
                voice,
                VOICE_PERIODICITY_MIN,
            )
        stems.append(
            {
                "index": index,
                "periodicity": voice,
                "file": track.out_path.name,
                "name": track.display_name,
                "user_id": track.user_id,
                "voiced_seconds": round(track.voiced_seconds, 2),
                "size_bytes": track.out_path.stat().st_size,
                # 波形は base64 の1バイト列で持つ（素の JSON 配列だと同じ
                # 点数で7倍以上になる）。読み手が古い索引も開けるよう、
                # 名前を分けてある（旧 "peaks" は float の配列だった）。
                "peaks_b64": _encode_series(track.peak_series(group=peak_group, points=peak_points)),
                "rms_b64": _encode_series(track.rms_series(group=peak_group, points=peak_points)),
                "point_count": peak_points,
                # 1点が何秒ぶんか。索引全体の bucket_seconds と同じ値だが、
                # トラック単位で読めるほうが読み手が迷わない。
                "bucket_seconds": peak_seconds,
            }
        )
    return stems


def _info_text(session: RecordingSession, info: dict) -> str:
    """ZIP を開いた人が最初に読む要約。索引(JSON)と違って読み手は人。"""
    return "\n".join(
        [
            f"チャンネル: {session.channel_name}",
            f"開始した人: {session.started_by_name}",
            f"書き出し: {info['書き出し日時']}",
            f"長さ: {info['長さ']}",
            f"停止理由: {info['停止理由']}",
            "",
            "各トラックは同じ時間軸に揃えてあります（そのまま重ねれば同期します）。",
            "",
            *[
                f"  {t['ファイル']}  {t['名前']}  発話 {t['発話時間(秒)']}秒"
                for t in cast("list[dict[str, Any]]", info["トラック"])
            ],
            *_breakdown_lines(info),
            *_capture_lines(info),
        ]
    )


def _write_archive(session: RecordingSession, manifest: dict, info: dict) -> Path:
    """トラックと索引を1つの ZIP に固める。"""
    zip_path = session.workdir / "archive.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for track in session.tracks.values():
            if _has_audio(track):
                # mp3 は既に圧縮済みなので縮まない。無圧縮で入れておくと、
                # ZIP の中の1本を「その位置から何バイト」で直接読めるようになり、
                # ミキサーの頭出し（Range リクエスト）が素直に通る。
                archive.write(track.out_path, arcname=track.out_path.name, compress_type=zipfile.ZIP_STORED)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False))
        archive.writestr("info.json", json.dumps(info, ensure_ascii=False, indent=2))
        archive.writestr("info.txt", _info_text(session, info))
        # 1行1パケットにするのは、長い録音でも grep と1行ずつの読み込みで
        # 扱えるようにするため。1つの JSON にすると全部読み込まないと開けない。
        lines = [
            json.dumps({"ssrc": group["ssrc"], "name": group["name"], **packet}, ensure_ascii=False)
            for group in session.packet_capture
            for packet in group["packets"]
        ]
        if lines:
            archive.writestr(CAPTURE_NAME, "\n".join(lines))
    return zip_path


def _finalize(session: RecordingSession, total_elapsed: float, reason: str) -> dict:
    """録音を音声ファイルへ書き出し、ZIP にまとめて登録する（停止処理の本体）。

    トラックを閉じる→索引(manifest)を作る→ZIPに固める、の順で行う。
    戻り値はコマンド応答やAPIがそのまま使う結果セットで、ダウンロードに
    必要な token や、声として怪しいトラックの一覧まで含む。
    """
    for track in session.tracks.values():
        track.close(total_elapsed)

    started_jst = datetime.now(_JST)
    stamp = started_jst.strftime("%Y%m%d_%H%M")
    title = f"録音 {session.channel_name} {stamp}"

    info = _finalize_info(session, total_elapsed, reason, started_jst)

    # ミキサー（管理画面）が使う索引。トラックの並び・波形・長さをここで確定させる。
    # ZIP の中にも入れておくので、落としたあとでも同じ情報が手元に残る。
    peak_group, peak_points, peak_seconds = _peak_scale(session, total_elapsed)
    stems = _build_stems(session, total_elapsed, peak_group, peak_points, peak_seconds)
    manifest = {
        "version": 1,
        "channel_name": session.channel_name,
        "started_by": session.started_by_name,
        "duration_seconds": round(total_elapsed, 2),
        "bucket_seconds": peak_seconds,
        "periodicity_min": VOICE_PERIODICITY_MIN,
        "dropped_packets": session.dropped_packets,
        "stems": stems,
    }

    zip_path = _write_archive(session, manifest, info)

    size_bytes = zip_path.stat().st_size
    token = register_file(
        zip_path,
        source_url=f"voice://{session.guild_id}/{session.channel_id}",
        title=title,
        guild_id=session.guild_id,
        ttl=session.retention_days * 24 * 3600,
        kind="recording",
    )
    shutil.rmtree(session.workdir, ignore_errors=True)

    return {
        "token": token,
        "title": title,
        "track_count": len(session.tracks),
        "duration_seconds": int(total_elapsed),
        "size_bytes": size_bytes,
        "retention_days": session.retention_days,
        "channel_id": session.channel_id,
        "channel_name": session.channel_name,
        "reason": reason or "手動停止",
        "dropped_packets": session.dropped_packets,
        "speakers": [t.display_name for t in session.tracks.values()],
        # 声として成立していないトラック。黙って渡すと、落として聞くまで
        # 気づけない。
        "suspect_tracks": [
            s["name"]
            for s in stems
            if s.get("periodicity") is not None and cast(float, s["periodicity"]) < VOICE_PERIODICITY_MIN
        ],
    }


def download_url(guild_id: int, token: str) -> str:
    """この録音のダウンロードURLを組み立てる。"""
    from config import DJAUDIO_BASE_URL

    return f"{DJAUDIO_BASE_URL}/dlaudio/files/{guild_id}/{token}"


def build_result_embed(guild_id: int, result: dict) -> discord.Embed:
    """停止時に投稿する結果 embed を組み立てる。"""
    minutes, seconds = divmod(result["duration_seconds"], 60)
    embed = discord.Embed(
        title="⏹️ 録音を保存しました",
        description=f"**{result['channel_name']}** / {minutes}分{seconds}秒",
        color=discord.Color.green(),
    )
    embed.add_field(name="トラック数", value=f"{result['track_count']} 人", inline=True)
    embed.add_field(name="サイズ", value=f"{result['size_bytes'] / 1024 / 1024:.1f} MB", inline=True)
    embed.add_field(name="保存期間", value=f"{result['retention_days']} 日", inline=True)
    if result["speakers"]:
        embed.add_field(name="参加者", value="、".join(result["speakers"][:20]), inline=False)
    # 取りこぼしがあったなら黙っていない。音が欠けている可能性を伝える。
    dropped = result.get("dropped_packets", 0)
    if dropped:
        embed.add_field(
            name="⚠️ 取りこぼし",
            value=f"{dropped} パケットを復元できませんでした（その分だけ音が欠けています）。",
            inline=False,
        )
    suspects = result.get("suspect_tracks") or []
    if suspects:
        embed.add_field(
            name="⚠️ 音が壊れている可能性",
            value=(
                "次のトラックが声として成立していません（雑音の疑い）:\n"
                + "、".join(suspects[:10])
                + "\n管理画面のミキサーで波形を確認してください。"
            ),
            inline=False,
        )
    url = download_url(guild_id, result["token"])
    embed.add_field(name="ダウンロード", value=f"[ZIP をダウンロード]({url})\n`{url}`", inline=False)
    embed.set_footer(text=f"停止理由: {result['reason']}")
    return embed


async def stop_all(bot, reason: str = "bot 停止") -> None:
    """全ギルドの録音を止める（終了処理用）。録り逃しを残さないため。"""
    for guild_id in list(_sessions):
        try:
            await stop_recording(bot, guild_id, reason=reason)
        except Exception as e:
            logger.exception("[recording] guild=%s の停止に失敗: %s", guild_id, e)
