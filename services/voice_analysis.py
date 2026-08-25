"""録音した声に加工が入っていないかを調べる。

■ できること / できないこと

できる:
  - ボイスチェンジャー（リサンプリングによるピッチ・フォルマント変換）の検出
  - その倍率の推定と、打ち消すためのフィルタの組み立て

できない:
  - RVC など、話者の音色を別人のモデルで置き換える方式からの原声の復元。
    元話者の声道特性は「変換」ではなく「破棄」されるため、逆関数が存在しない
  - 話者の同定。ここが出せるのは「加工されているか」までで「誰か」は出せない

そもそも Discord の VC では、どのトラックがどのアカウントかは分かっている
（SSRC → ユーザーID）。ボイスチェンジャーが隠すのは「どんな声か」であって
「誰か」ではない。ここで意味があるのは、録音を資料として扱うときに
「この音声は本人の地声ではない」と分かることまで。

■ 何を見ているか

声道は片側が閉じた管に近く、共鳴（フォルマント）は概ね等間隔に並ぶ。その
間隔 ΔF から声道長が求まる（Fitch の formant dispersion）:

    声道長 ≒ 音速 / (2 × ΔF)

人の声道長はおよそ 10〜19cm。ここから外れる値が出たら、声そのものではなく
加工の結果とみなせる。リサンプリング方式のボイスチェンジャーは F0 と
フォルマントを同じ倍率でずらすので、間隔の比がそのまま倍率になる。

■ フォルマントの取り方（ここが肝）

LPC の極を1フレームずつ独立に拾って中央値を採る、という素朴なやり方では
使いものにならなかった。低域に出た余計な極が第1の位置に入り込み、間隔が
実際より小さく出る。実測では 1.7 倍に加工した声の声道長が 13.2cm（人の
正常範囲の中）と出て、加工を見逃した。

そこで、フレームをまたいだ連続性で選ぶ。本物の共鳴はなめらかに動くが、
余計な極はフレームごとに飛ぶので、系列全体で見れば区別できる。

絶対的な周波数の事前分布は使わない。「第1は 300〜900Hz」といった枠を
当てると、加工された声を正常な範囲へ引き戻してしまい、検出できなくなる。
判断材料は帯域幅（共鳴は鋭い）と連続性（共鳴はなめらか）だけにする。

追跡した3本が第1から始まっている必要はない。必要なのは間隔であり、
連続したフォルマントでありさえすれば第2〜第4でも同じ値になる。
"""

from __future__ import annotations

import logging
import math
import subprocess
from itertools import combinations
from pathlib import Path

import numpy as np

from config import DJAUDIO_FFMPEG_PATH

logger = logging.getLogger(__name__)

# 解析はこの標本化周波数で行う。第3フォルマントまで見られればよい。
RATE = 16000
FRAME_SECONDS = 0.032
HOP_SECONDS = 0.016
LPC_ORDER = 16                 # 16kHz なら 2 + 標本化周波数/1000 が目安
PRE_EMPHASIS = 0.97

# 抜き出す箇所と長さ。録音の長さに依らず一定のコストにする。
PROBES = 8
PROBE_SECONDS = 1.0

# 声とみなす下限。無音や物音、子音の部分で判定しない。
_MIN_RMS = 700
_MIN_PERIODICITY = 0.70
_MIN_FRAMES = 25
# 追跡は途切れない区間ごとに行う。短すぎる区間は連続性を使えない。
_MIN_RUN = 6

# 極をフォルマント候補とみなす条件
_MAX_BANDWIDTH_HZ = 500.0
_MIN_FORMANT_HZ = 150.0
_MAX_FORMANT_HZ = 5500.0
_MIN_FORMANT_GAP_HZ = 200.0
_MAX_CANDIDATES = 8
_TRACK_COUNT = 3

# 追跡の重み。連続性を主にする（余計な極はフレームごとに飛ぶ）。
_CONTINUITY_WEIGHT = 8.0

# 人の声の範囲
F0_MIN_HZ, F0_MAX_HZ = 60.0, 400.0
SPEED_OF_SOUND_CM = 35000.0    # 体温の気道でおよそ 350 m/s
VTL_NATURAL = (10.0, 19.0)     # 子どもから大人まで
VTL_IMPLAUSIBLE = (8.5, 22.0)  # ここを外れたら人の声道ではありえない
REFERENCE_SPACING_HZ = 1075.0  # 倍率を推す基準（大人の平均的な間隔）

# 声の高さと声道長は結びついている（体が大きいほど声道が長く、声が低い）。
# 大人の男性 F0 85〜155 / 声道長 16〜18.5cm、大人の女性 165〜255 / 14〜16cm、
# 子ども 250〜400 / 10〜13.5cm。これを直線で近似したもの。
_VTL_FROM_F0_INTERCEPT = 20.5
_VTL_FROM_F0_SLOPE = 0.027
# 個人差は大きいので、許容は広めにとる。ここを狭めると地声の人を
# 加工扱いしてしまう。
_VTL_F0_TOLERANCE_CM = 4.0

# 倍音誤りを避ける閾値。最良の山とこれだけ近ければ短いほうの周期を採る。
_OCTAVE_GUARD = 0.90


# ── 取り込み ──────────────────────────────────────────────────

def _decode(source: bytes | Path, at: float, length: float) -> list[float]:
    """指定の位置から length 秒を 16kHz モノラルで取り出す。"""
    piped = isinstance(source, bytes)
    command = [
        DJAUDIO_FFMPEG_PATH, "-hide_banner", "-loglevel", "error",
        "-ss", f"{at:.3f}", "-t", f"{length:.3f}",
        "-i", "pipe:0" if piped else str(source),
        "-f", "s16le", "-ar", str(RATE), "-ac", "1", "-",
    ]
    try:
        result = subprocess.run(command, input=source if piped else None,
                                capture_output=True, timeout=120)
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("[voice] 音の取り出しに失敗: %s", e)
        return []
    raw = result.stdout
    usable = len(raw) - (len(raw) % 2)
    return [int.from_bytes(raw[i:i + 2], "little", signed=True)
            for i in range(0, usable, 2)]


def _probe(source: bytes | Path, duration: float) -> list[list[float]]:
    """録音の各所から少しずつ取り出す。"""
    span = max(duration - PROBE_SECONDS, 0.0)
    out = []
    for i in range(PROBES):
        at = 0.0 if PROBES == 1 else span * i / (PROBES - 1)
        chunk = _decode(source, at, PROBE_SECONDS)
        if chunk:
            out.append(chunk)
    return out


# ── 基本周波数 ────────────────────────────────────────────────

def _f0_and_periodicity(frame: list[float]) -> tuple[float, float]:
    """自己相関で基本周波数と、山の高さ（0〜1）を求める。

    素直に最大値を採ると、周期の2倍・3倍の位置も同じくらいの高さになるため
    実際より低い値を返す（実測で 220Hz が 73Hz になった）。最良とほぼ同じ
    高さなら、短いほうの周期を採る。
    """
    size = len(frame)
    low = int(RATE / F0_MAX_HZ)
    high = min(int(RATE / F0_MIN_HZ), size - 1)
    scores = []
    best = 0.0
    for lag in range(low, high):
        count = size - lag
        num = left = right = 0.0
        for i in range(0, count, 2):
            a, b = frame[i], frame[i + lag]
            num += a * b
            left += a * a
            right += b * b
        score = num / (math.sqrt(left * right) or 1.0)
        scores.append(score)
        if score > best:
            best = score
    if best <= 0 or not scores:
        return 0.0, 0.0

    threshold = best * _OCTAVE_GUARD
    for index, score in enumerate(scores):
        if score < threshold:
            continue
        peak = index
        while peak + 1 < len(scores) and scores[peak + 1] >= scores[peak]:
            peak += 1
        return RATE / (low + peak), scores[peak]
    return RATE / (low + scores.index(best)), best


# ── フォルマントの候補 ────────────────────────────────────────

def _lpc(frame: list[float], order: int) -> list[float] | None:
    """線形予測係数（Levinson-Durbin）。"""
    size = len(frame)
    auto = []
    for lag in range(order + 1):
        total = 0.0
        for i in range(size - lag):
            total += frame[i] * frame[i + lag]
        auto.append(total)
    if auto[0] <= 0:
        return None

    a = [0.0] * (order + 1)
    a[0] = 1.0
    error = auto[0]
    for m in range(1, order + 1):
        acc = auto[m]
        for i in range(1, m):
            acc += a[i] * auto[m - i]
        k = -acc / error
        if not math.isfinite(k) or abs(k) >= 1.0:
            return None
        updated = a[:]
        for i in range(1, m):
            updated[i] = a[i] + k * a[m - i]
        updated[m] = k
        a = updated
        error *= (1.0 - k * k)
        if error <= 0:
            return None
    return a


def _candidates(frame: list[float]) -> list[tuple[float, float]]:
    """フォルマント候補 (周波数, 帯域幅) を、周波数の順で返す。

    LPC の分母多項式の根がそのまま共鳴に対応する。角度が周波数、原点からの
    距離が鋭さ（帯域幅）になる。ここでは絞り込みすぎず、選ぶのは追跡に任せる。
    """
    shaped = [frame[0]]
    for i in range(1, len(frame)):
        shaped.append(frame[i] - PRE_EMPHASIS * frame[i - 1])
    size = len(shaped)
    windowed = [shaped[i] * (0.54 - 0.46 * math.cos(2 * math.pi * i / (size - 1)))
                for i in range(size)]

    coeffs = _lpc(windowed, LPC_ORDER)
    if coeffs is None:
        return []
    try:
        roots = np.roots(np.asarray(coeffs, dtype=float))
    except (np.linalg.LinAlgError, ValueError):
        return []

    found = []
    for root in roots:
        if root.imag <= 0:
            continue                       # 共役の片方だけを見る
        magnitude = abs(root)
        if not 0.0 < magnitude < 1.0:
            continue                       # 単位円の外は不安定な極
        freq = math.atan2(root.imag, root.real) * RATE / (2 * math.pi)
        bandwidth = -math.log(magnitude) * RATE / math.pi
        if not (_MIN_FORMANT_HZ < freq < _MAX_FORMANT_HZ):
            continue
        if bandwidth > _MAX_BANDWIDTH_HZ:
            continue
        found.append((freq, bandwidth))

    found.sort()
    return found[:_MAX_CANDIDATES]


# ── 追跡 ──────────────────────────────────────────────────────

def _states(count: int) -> list[tuple[int, ...]]:
    """そのフレームで選びうる組み合わせ。"""
    if count < _TRACK_COUNT:
        return []
    return list(combinations(range(count), _TRACK_COUNT))


def _emission(state: tuple[int, ...], poles: list[tuple[float, float]]) -> float:
    """そのフレーム単体での選びにくさ。

    共鳴は鋭い（帯域幅が狭い）。近すぎる2本は、ひとつの共鳴が割れたものか
    片方が偽物なので避ける。
    """
    cost = 0.0
    previous = None
    for index in state:
        freq, bandwidth = poles[index]
        cost += bandwidth / _MAX_BANDWIDTH_HZ
        if previous is not None and freq - previous < _MIN_FORMANT_GAP_HZ:
            cost += 3.0
        previous = freq
    return cost


def _transition(before: tuple[int, ...], after: tuple[int, ...],
                left: list[tuple[float, float]], right: list[tuple[float, float]]) -> float:
    """フレーム間の飛び具合。

    比で測る（対数距離）。こうしておくと、全体が一定倍率でずれていても
    余計な費用が乗らない。加工された声を不利にしないため。
    """
    cost = 0.0
    for a, b in zip(before, after):
        cost += abs(math.log(right[b][0] / left[a][0]))
    return cost * _CONTINUITY_WEIGHT


def _track(run: list[list[tuple[float, float]]]) -> list[list[float]]:
    """途切れない区間のフォルマントを、系列として選び直す（Viterbi）。"""
    frames = [(poles, _states(len(poles))) for poles in run]
    frames = [(poles, states) for poles, states in frames if states]
    if len(frames) < _MIN_RUN:
        return []

    poles0, states0 = frames[0]
    costs = {state: _emission(state, poles0) for state in states0}
    back: list[dict] = [{}]

    for index in range(1, len(frames)):
        poles, states = frames[index]
        previous_poles = frames[index - 1][0]
        step: dict = {}
        best_costs = {}
        for state in states:
            best_cost = None
            best_from = None
            emission = _emission(state, poles)
            for prior, prior_cost in costs.items():
                total = (prior_cost + emission
                         + _transition(prior, state, previous_poles, poles))
                if best_cost is None or total < best_cost:
                    best_cost, best_from = total, prior
            best_costs[state] = best_cost
            step[state] = best_from
        costs = best_costs
        back.append(step)

    state = min(costs, key=costs.get)
    chosen = [state]
    for index in range(len(frames) - 1, 0, -1):
        state = back[index][state]
        chosen.append(state)
    chosen.reverse()

    return [[frames[i][0][j][0] for j in chosen[i]] for i in range(len(frames))]


# ── まとめ ────────────────────────────────────────────────────

def _median(values: list[float], trim: float = 0.2) -> float:
    """外れ値を落としてから中央値を採る。"""
    ordered = sorted(values)
    if not ordered:
        return 0.0
    cut = int(len(ordered) * trim / 2)
    if cut and len(ordered) - 2 * cut >= 3:
        ordered = ordered[cut:len(ordered) - cut]
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _runs(chunk: list[float]) -> list[list[list[tuple[float, float]]]]:
    """声が続いているあいだを1区間として、フレームごとの候補を並べる。"""
    frame_size = int(RATE * FRAME_SECONDS)
    hop = int(RATE * HOP_SECONDS)
    runs: list[list] = []
    current: list = []
    for start in range(0, len(chunk) - frame_size, hop):
        frame = chunk[start:start + frame_size]
        rms = math.sqrt(sum(v * v for v in frame) / frame_size)
        voiced = False
        if rms >= _MIN_RMS:
            _, periodicity = _f0_and_periodicity(frame)
            voiced = periodicity >= _MIN_PERIODICITY
        if not voiced:
            if current:
                runs.append(current)
                current = []
            continue
        current.append(_candidates(frame))
    if current:
        runs.append(current)
    return runs


def analyse(source: bytes | Path, duration: float) -> dict:
    """1トラックを調べる。

    verdict は3つ。
      natural … 人の声として無理のない値だった
      suspect … 加工されている形跡がある
      unknown … 判定できるだけの声が入っていない
    """
    spacings: list[float] = []
    formant_sets: list[list[float]] = []
    f0s: list[float] = []

    frame_size = int(RATE * FRAME_SECONDS)
    hop = int(RATE * HOP_SECONDS)

    for chunk in _probe(source, duration):
        for start in range(0, len(chunk) - frame_size, hop):
            frame = chunk[start:start + frame_size]
            if math.sqrt(sum(v * v for v in frame) / frame_size) < _MIN_RMS:
                continue
            f0, periodicity = _f0_and_periodicity(frame)
            if periodicity >= _MIN_PERIODICITY:
                f0s.append(f0)
        for run in _runs(chunk):
            for formants in _track(run):
                formant_sets.append(formants)
                spacings.append((formants[-1] - formants[0]) / (len(formants) - 1))

    if len(spacings) < _MIN_FRAMES:
        return {
            "verdict": "unknown",
            "reason": "判定できるだけの声が入っていません。",
            "frames": len(spacings),
        }

    f0 = _median(f0s) if f0s else 0.0
    spacing = _median(spacings)
    vtl = SPEED_OF_SOUND_CM / (2 * spacing) if spacing > 0 else 0.0
    factor = spacing / REFERENCE_SPACING_HZ if spacing > 0 else 0.0

    expected_vtl = _VTL_FROM_F0_INTERCEPT - _VTL_FROM_F0_SLOPE * f0 if f0 else 0.0
    mismatch = abs(vtl - expected_vtl) if (vtl and expected_vtl) else 0.0

    reasons = []
    if f0 and not (F0_MIN_HZ <= f0 <= F0_MAX_HZ):
        reasons.append(f"基本周波数が人の声の範囲外です（{f0:.0f} Hz）。")
    if vtl and not (VTL_IMPLAUSIBLE[0] <= vtl <= VTL_IMPLAUSIBLE[1]):
        reasons.append(
            f"フォルマントの間隔から求めた声道長が {vtl:.1f} cm で、"
            "人の声道としてありえない値です。")
    elif vtl and not (VTL_NATURAL[0] <= vtl <= VTL_NATURAL[1]):
        reasons.append(
            f"フォルマントの間隔から求めた声道長が {vtl:.1f} cm で、"
            "人の範囲の外側寄りです。")
    elif mismatch > _VTL_F0_TOLERANCE_CM:
        # 声の高さと体格が食い違う。地声ではこうならない。
        reasons.append(
            f"声の高さ（{f0:.0f} Hz）に対して声道長 {vtl:.1f} cm は食い違います"
            f"（この高さなら {expected_vtl:.1f} cm 前後）。")

    verdict = "suspect" if reasons else "natural"
    return {
        "verdict": verdict,
        "reason": " ".join(reasons) if reasons else "人の声として無理のない値でした。",
        "frames": len(spacings),
        "f0_hz": round(f0, 1),
        "formants_hz": [round(v, 1) for v in _median_formants(formant_sets)],
        "formant_spacing_hz": round(spacing, 1),
        "vocal_tract_cm": round(vtl, 2),
        "expected_vocal_tract_cm": round(expected_vtl, 2),
        "vocal_tract_mismatch_cm": round(mismatch, 2),
        # 「話者が平均的な大人だったと仮定したときの」倍率。本人の地声が
        # 分からない以上、これは出発点の目安でしかない。復元は、この値を
        # そのまま当てるのではなく、操作する人が耳で決められるようにする。
        "estimated_factor": round(factor, 3),
        "restorable": verdict == "suspect" and 0.5 <= factor <= 2.0,
        # ここで言えるのは「加工されているか」までで、「誰か」は言えない。
        "identifies_speaker": False,
    }


def _median_formants(sets: list[list[float]]) -> list[float]:
    """追跡した3本それぞれの代表値。"""
    complete = [s for s in sets if len(s) == _TRACK_COUNT]
    if not complete:
        return []
    return [_median([s[i] for s in complete]) for i in range(_TRACK_COUNT)]


# 復元フィルタを組み立てるときの基準。入力の標本化周波数はファイルごとに
# 違うので、いったんここへ揃えてから当てる。解析用の 16kHz を使うと、
# 48kHz のファイルでは倍率が狂う（実際にそれで復元が 1.57 倍ずれた）。
RESTORE_RATE = 48000


def restore_command(factor: float, rate: int = RESTORE_RATE) -> list[str]:
    """倍率 factor の変換を打ち消す ffmpeg のフィルタ。

    リサンプリングでピッチを変えた音は、標本化周波数を逆向きにずらして
    長さを合わせ直せば元に戻る。フォルマントを保ったまま変換する方式や
    RVC には効かない（それらは逆変換が定義できない別物の加工）。

    どの倍率を打ち消すかは、操作する人が決める。本人の地声が分からない
    以上、正しい倍率を機械が決めることはできない。
    """
    if not (0.1 < factor < 10.0):
        raise ValueError("倍率が範囲外です。")

    # atempo は 0.5〜2.0 しか受け付けないので、必要なら分ける。
    tempos = []
    remaining = factor
    while remaining > 2.0:
        tempos.append(2.0)
        remaining /= 2.0
    while remaining < 0.5:
        tempos.append(0.5)
        remaining /= 0.5
    tempos.append(remaining)

    chain = [
        f"aresample={rate}",                  # 入力の周波数を揃える
        f"asetrate={int(rate / factor)}",     # 逆向きにずらす（長さも変わる）
        f"aresample={rate}",
    ]
    chain += [f"atempo={t:.6f}" for t in tempos]   # 長さを戻す
    return chain
