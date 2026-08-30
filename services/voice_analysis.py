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

追跡した組が第1から始まっている必要はない。必要なのは間隔であり、
連続したフォルマントでありさえすれば第2〜第5でも同じ値になる。

■ 「連続した」が効いていなかった話

上の「連続したフォルマントでありさえすれば」が、実は保証されていなかった。
選ぶ組に「隣り合っていること」の条件が無く、1本飛ばした組を選んでも罰が
無かったためである。

実録音で測ると、同じ話者の同じ録音でも、区間ごとに選ばれる組が
1198/2659/3664 → 512/2206/4392 → 632/3360/4656 と変わっていた。後ろの2つは
明らかに間を飛ばしている。そこから出る間隔は 1255〜1923Hz（声道長
9.1〜13.9cm）に散らばり、どの区間を選ぶかで「加工の形跡あり」と「なし」が
入れ替わった。正解の分かる合成音でも、子どもの声（間隔が広い）で 12.5cm を
8.7cm と測り、地声を加工扱いしていた。

そこで、飛ばしの印を罰する。1本飛ばすとその間隔だけが突出して広くなるので、
「いちばん広い間隔が、真ん中の広さの何倍か」を見る。間隔を3つ取るために
4本を1組として追う（候補が足りない区間だけ3本に落とす）。

  あ（正しい組）    間隔 360/1350/960 → 真ん中 960、最大 1350 → 1.41 倍
  1本飛ばした組     間隔 900/1800/900 → 真ん中 900、最大 1800 → 2.00 倍

「間隔がそろっていること」を求めてはいけない。実際の母音は等間隔ではないので
（上の「あ」を見よ）、そろえと言うと、正しい組より「たまたま等間隔に見える
誤った組」を選んでしまう。見るのは飛ばしの印だけにする。比で測るので、声全体に
倍率が掛かっていても値は変わらない（加工された声を不利にしない）。

これで、正解の分かる声では成人男性 17.5cm・成人女性 15.0cm・子ども 12.5cm を
いずれも 1cm 以内で当てる。雑音（SNR 5dB）で -0.9cm、残響で +0.2cm、
4kHz への帯域制限で +0.7cm と、現実的な劣化でもほとんど動かない。

■ 測り切れていない区間では何も言わない

それでも実際の録音では、区間によって値が散らばる。四分位で見た声道長の幅が
中央値の3分の1を超えたら（成人男性と成人女性を跨ぐほどの幅）、中央値がどこに
落ちていても unknown を返す。中央値がたまたまどちら側に落ちたかで人を疑うのは、
断定を作るだけだからである。
"""

from __future__ import annotations

import logging
import math
import subprocess
from itertools import combinations
from pathlib import Path
from typing import Any

import numpy as np

from config import DJAUDIO_FFMPEG_PATH

logger = logging.getLogger(__name__)

# 解析はこの標本化周波数で行う。第3フォルマントまで見られればよい。
RATE = 16000
FRAME_SECONDS = 0.032
HOP_SECONDS = 0.016
LPC_ORDER = 16  # 16kHz なら 2 + 標本化周波数/1000 が目安
PRE_EMPHASIS = 0.97

# 範囲を指定されなかったときに抜き出す箇所と長さ。録音の長さに依らず
# 一定のコストにする代わりに、喋っている所へ当たるかどうかは運任せになる。
PROBES = 8
PROBE_SECONDS = 1.0

# 範囲を指定されたときの上限と下限。
#
# 自動で散らす方式は、長い録音になるほど当たらない。4時間22分の実録音5本で
# 試すと、8箇所×1秒＝8秒（全体の 0.05%）しか見ないため5本とも判定不能に
# なり、うち4本は使えるフレームが1枚も取れなかった。無音や相槌に当たれば
# そうなるのが道理で、閾値をいじって直る類の外れ方ではない。
#
# 操作する人は波形を見て「ここで喋っている」と分かっているので、その範囲を
# そのまま渡してもらう。上限は、誤って全体を選んだときに1リクエストが
# 何分も走らないようにするためのもの。
SELECTION_MAX_SECONDS = 30.0
# これより短いとフレームが足りず、必ず判定不能になる。
SELECTION_MIN_SECONDS = 0.5

# 声とみなす下限。無音や物音、子音の部分で判定しない。
_MIN_RMS = 700
_MIN_PERIODICITY = 0.70
_MIN_FRAMES = 25

# 倍音の構造を確かめる条件。
#
# 自己相関の山（周期性）だけでは「周期的な音」までしか言えない。純音・電源
# ハム・送風音・楽器の持続音はどれも山が立つが、声ではないので LPC の極を
# フォルマントとして読むと意味の無い値になる。声道長はフォルマントの間隔から
# 求めているので、こういうフレームが混ざると中央値ごと引きずられ、地声を
# 加工扱いしたり、その逆をしたりする。
#
# 人の有声音は声帯の準周期パルスを声道が濾したものなので、基音 F0 とその
# 整数倍に確かに山が並ぶ。そこを直接確かめる。
_HARMONIC_COUNT = 8  # 見る倍音の本数（F0 の 1〜8 倍）
_HARMONIC_MIN_RESOLVED = 3  # このうち何本が立っていれば声とみなすか
_HARMONIC_TOLERANCE = 0.25  # 山を探す幅（F0 に対する割合）
# 倍音の山が、倍音と倍音のあいだ（谷）に対して何倍あれば「立っている」か。
_HARMONIC_MIN_PROMINENCE = 2.0
# 山が「いちばん強い倍音」に対して最低これだけの大きさを持つこと。
#
# 比だけで見ると、純音のように倍音がほぼ無い信号で谷も山も 0 に近くなり、
# 窓の漏れ（数値的な裾）どうしの比が条件を満たしてしまう。実際これで純音と
# 電源ハムが「声」として通った。分母が小さいときの比は意味を持たないので、
# 絶対量の下限を併せて課す。
_HARMONIC_MIN_LEVEL = 0.02  # 最大の倍音に対して -34dB

# 倍音を見るときだけ使う窓の長さ。
#
# フォルマントを取る 32ms のフレームをそのまま使うと、周波数分解能が 31Hz に
# しかならない。倍音の谷（F0/2 だけ離れた位置）は F0 120Hz で 1.9 bin しか
# 離れず、山と谷が混ざって「倍音が立っていない」と読める。実際これで、
# 120Hz の地声を全フレーム落として判定不能にした。
#
#   32ms  分解能 31.2Hz … F0 120Hz の谷まで 1.9 bin （分離できない）
#   96ms  分解能 10.4Hz … F0 120Hz の谷まで 5.8 bin
#
# 倍音があるかどうかは 100ms 程度では変わらないので、この判定にだけ前後を
# 含めた広い窓を使う。フォルマントの追跡は 32ms のままにする（そちらは
# 音が変わっていく様子を見る必要があるため）。
_HARMONIC_WINDOW_SECONDS = 0.096
# 追跡は途切れない区間ごとに行う。短すぎる区間は連続性を使えない。
_MIN_RUN = 6

# 極をフォルマント候補とみなす条件
_MAX_BANDWIDTH_HZ = 500.0
_MIN_FORMANT_HZ = 150.0
# 上限を 5500Hz にしていたころは、高い倍率へ加工された声で第4フォルマントが
# 枠の外へ出て、追跡に必要な本数が揃わなかった（1.7倍で判定不能になった）。
# 16kHz で解析しているので、7000Hz までは意味のある極が取れる。
_MAX_FORMANT_HZ = 7000.0
_MIN_FORMANT_GAP_HZ = 200.0
_MAX_CANDIDATES = 8
# 何本を1組として追うか。4本あれば間隔が3つ取れるので、「そろっているか」を
# 見られる（3本だと2つしか無く、1本飛ばしを見分けにくい）。候補がそれだけ
# 無い区間では3本に落とす。
_TRACK_COUNT = 4
_TRACK_COUNT_MIN = 3

# 追跡の重み。連続性を主にする（余計な極はフレームごとに飛ぶ）。
_CONTINUITY_WEIGHT = 8.0
# 「1本飛ばした組」への罰。
#
# 声道の共鳴は概ね等間隔に並ぶので、連続した組を選べば間隔はそろい、1本飛ばすと
# そこだけ倍に開く。ここに罰を置かないと、飛ばした組を選んでも損をしない。
#
# 実際そうなっていた。同じ話者の区間ごとに、選ばれる組が
# 1198/2659/3664 → 512/2206/4392 → 632/3360/4656 と変わり、そこから出る
# 間隔が 1255〜1923Hz（声道長 9.1〜13.9cm）に散らばっていた。どの区間を
# 選ぶかで「加工の形跡あり」と「なし」が入れ替わる原因がこれ。
#
# ただし「間隔がそろっていること」を求めてはいけない。実際の母音は等間隔では
# ない（あ = 730/1090/2440/3400 で、間隔は 360/1350/960）。そろえと言うと、
# 正しい組より「たまたま等間隔に見える誤った組」を選んでしまう。
#
# 見るのは飛ばしの印だけにする。1本飛ばすとその1つだけが突出して広くなるので、
# 「いちばん広い間隔が、真ん中の広さの何倍か」で測る。
#   あ（正しい組）      間隔 360/1350/960 → 真ん中 960、最大 1350 → 1.41 倍
#   1本飛ばした組       間隔 900/1800/900 → 真ん中 900、最大 1800 → 2.00 倍
# 比で測るので、声全体に倍率が掛かっても値は変わらない（加工された声を不利に
# しない、というこのファイルの方針を守る）。
_SKIP_RATIO = 1.6  # ここを超えた分だけ罰する
_SKIP_WEIGHT = 8.0

# 人の声の範囲
F0_MIN_HZ, F0_MAX_HZ = 60.0, 400.0
SPEED_OF_SOUND_CM = 35000.0  # 体温の気道でおよそ 350 m/s
VTL_NATURAL = (10.0, 19.0)  # 子どもから大人まで
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

# その区間の測定が、そもそも何かを言えるだけ定まっているか。
# 四分位で見た声道長の幅を、中央値で割った比で測る。
#
# 追跡を直したあと、正解の分かる合成音ではこの比が 0.002〜0.03 に収まる
# （成人男性 17.62〜17.65cm、子ども 12.68〜13.0cm）。実際の録音では 0.06〜0.92
# まで開く。0.35 を超えると幅が中央値の3分の1より広い——成人男性（16〜18.5cm）と
# 成人女性（14〜16cm）を跨ぐほどの幅で、体格ひとつ言い当てられない。
# そこを超えたら、中央値がどこに落ちていても「この区間では測り切れていない」
# と答える。
#
# ここを natural にも課すのは、追跡を直して地声が締まってからできるようになった。
# 前の実装では地声でも幅が広く、課すと軒並み判定不能になっていた。
_MAX_RELATIVE_SPREAD = 0.35

# 倍音誤りを避ける閾値。最良の山とこれだけ近ければ短いほうの周期を採る。
_OCTAVE_GUARD = 0.90


# ── 取り込み ──────────────────────────────────────────────────


def _decode(source: bytes | Path, at: float, length: float) -> np.ndarray:
    """指定の位置から length 秒を 16kHz モノラルで取り出す。"""
    piped = isinstance(source, bytes)
    command = [
        DJAUDIO_FFMPEG_PATH,
        "-hide_banner",
        "-loglevel",
        "error",
        "-ss",
        f"{at:.3f}",
        "-t",
        f"{length:.3f}",
        "-i",
        "pipe:0" if piped else str(source),
        "-f",
        "s16le",
        "-ar",
        str(RATE),
        "-ac",
        "1",
        "-",
    ]
    try:
        input_data: bytes | None
        if piped:
            # Since we checked with isinstance, source is bytes when piped is True
            assert isinstance(source, bytes)
            input_data = source
        else:
            input_data = None
        result = subprocess.run(command, input=input_data, capture_output=True, timeout=120)
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("[voice] 音の取り出しに失敗: %s", e)
        return np.array([], dtype=np.float64)
    raw = result.stdout
    usable = len(raw) - (len(raw) % 2)
    # 1標本ずつ int.from_bytes で組み立てていたころは、ここだけで 30 秒ぶん
    # （48万標本）に数秒かかっていた。選択範囲をまとめて読むようになると
    # 効いてくるので、まとめて変換する。
    return np.frombuffer(raw[:usable], dtype="<i2").astype(np.float64)


def _spread(source: bytes | Path, begin: float, span: float, slices: int, seconds: float) -> list[np.ndarray]:
    """begin から span 秒のあいだに、seconds 秒を slices 回ぶん散らして取る。"""
    room = max(span - seconds, 0.0)
    out: list[np.ndarray] = []
    for i in range(slices):
        at = begin + (0.0 if slices == 1 else room * i / (slices - 1))
        chunk = _decode(source, at, seconds)
        if chunk.size:
            out.append(chunk)
    return out


def _probe(
    source: bytes | Path, duration: float, start: float | None = None, end: float | None = None
) -> list[np.ndarray]:
    """調べる音を取り出す。

    範囲を渡されたら、そこだけを続けて読む（散らさない）。渡されなければ
    録音の各所から少しずつ取る。どちらを使ったかは analyse() が返す。
    """
    if start is None or end is None:
        return _spread(source, 0.0, duration, PROBES, PROBE_SECONDS)

    length = max(0.0, end - start)
    if length <= SELECTION_MAX_SECONDS:
        # 選ばれた区間をそのまま、切れ目なく1つとして読む。区切ると
        # 区切り目でフォルマントの追跡が途切れ、そのぶん判断材料が減る。
        chunk = _decode(source, start, length)
        return [chunk] if chunk.size else []

    # 上限を超えて選ばれたときは、その範囲の中だけで散らす（録音全体へは
    # 広げない）。合計は上限に収める。
    return _spread(source, start, length, PROBES, SELECTION_MAX_SECONDS / PROBES)


# ── 基本周波数 ────────────────────────────────────────────────


def _f0_and_periodicity(frame: list[float]) -> tuple[float, float]:
    """自己相関で基本周波数と、山の高さ（0〜1）を求める。

    素直に最大値を採ると、周期の2倍・3倍の位置も同じくらいの高さになるため
    実際より低い値を返す（実測で 220Hz が 73Hz になった）。最良とほぼ同じ
    高さなら、短いほうの周期を採る。
    """
    samples = np.asarray(frame, dtype=np.float64)
    size = samples.size
    low = int(RATE / F0_MAX_HZ)
    high = min(int(RATE / F0_MIN_HZ), size - 1)
    if high <= low:
        return 0.0, 0.0

    # 遅延ごとの正規化相互相関。1標本ずつ回すと1フレームで 11 万回の乗算に
    # なり、選択範囲（数十秒）を調べるには重すぎる。遅延の数（200 強）だけ
    # numpy を呼ぶ形に置き換える。標本を1つ飛ばしで見るのは元のまま
    # （粗くしても山の位置は変わらず、費用は半分になる）。
    scores = np.empty(high - low, dtype=np.float64)
    for index, lag in enumerate(range(low, high)):
        count = size - lag
        a = samples[0:count:2]
        b = samples[lag : lag + count : 2]
        denominator = math.sqrt(float(a @ a) * float(b @ b)) or 1.0
        scores[index] = float(a @ b) / denominator

    best = float(scores.max())
    if best <= 0:
        return 0.0, 0.0

    # 山の2倍・3倍の遅延にも同じ高さの山が立つ（＝1オクターブ低く読む）。
    # 最良とほぼ同じ高さなら、短いほうの周期を採る。
    threshold = best * _OCTAVE_GUARD
    reached = np.flatnonzero(scores >= threshold)
    if reached.size:
        peak = int(reached[0])
        while peak + 1 < scores.size and scores[peak + 1] >= scores[peak]:
            peak += 1
        return RATE / (low + peak), float(scores[peak])
    return RATE / (low + int(scores.argmax())), best


# ── フォルマントの候補 ────────────────────────────────────────


def _lpc(frame: list[float], order: int) -> list[float] | None:
    """線形予測係数（Levinson-Durbin）。"""
    samples = np.asarray(frame, dtype=np.float64)
    size = samples.size
    if size <= order:
        return None
    auto = [float(samples[: size - lag] @ samples[lag:]) for lag in range(order + 1)]
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
        error *= 1.0 - k * k
        if error <= 0:
            return None
    return a


def _candidates(frame: list[float]) -> list[tuple[float, float]]:
    """フォルマント候補 (周波数, 帯域幅) を、周波数の順で返す。

    LPC の分母多項式の根がそのまま共鳴に対応する。角度が周波数、原点からの
    距離が鋭さ（帯域幅）になる。ここでは絞り込みすぎず、選ぶのは追跡に任せる。
    """
    samples = np.asarray(frame, dtype=np.float64)
    size = samples.size
    if size < 2:
        return []
    shaped = samples.copy()
    shaped[1:] -= PRE_EMPHASIS * samples[:-1]
    windowed = shaped * np.hamming(size)

    coeffs = _lpc(windowed.tolist(), LPC_ORDER)
    if coeffs is None:
        return []
    try:
        roots = np.roots(np.asarray(coeffs, dtype=float))
    except (np.linalg.LinAlgError, ValueError):
        return []

    found = []
    for root in roots:
        if root.imag <= 0:
            continue  # 共役の片方だけを見る
        magnitude = abs(root)
        if not 0.0 < magnitude < 1.0:
            continue  # 単位円の外は不安定な極
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


def _states(count: int, size: int = _TRACK_COUNT) -> list[tuple[int, ...]]:
    """そのフレームで選びうる組み合わせ。"""
    if count < size:
        return []
    return list(combinations(range(count), size))


def _emission(state: tuple[int, ...], poles: list[tuple[float, float]]) -> float:
    """そのフレーム単体での選びにくさ。

    共鳴は鋭い（帯域幅が狭い）。近すぎる2本は、ひとつの共鳴が割れたものか
    片方が偽物なので避ける。

    そして、選んだ組の間隔がそろっていること。声道の共鳴は概ね等間隔に
    並ぶので、連続した組なら間隔はそろい、1本飛ばすとそこだけ倍に開く。
    ここを見ないと、飛ばした組を選んでも損をしない（→ _UNIFORMITY_WEIGHT）。
    """
    cost = 0.0
    previous = None
    gaps: list[float] = []
    for index in state:
        freq, bandwidth = poles[index]
        cost += bandwidth / _MAX_BANDWIDTH_HZ
        if previous is not None:
            if freq - previous < _MIN_FORMANT_GAP_HZ:
                cost += 3.0
            gaps.append(freq - previous)
        previous = freq

    # 飛ばしの印（突出して広い間隔が1つある）だけを罰する。
    # 真ん中の広さと比べるので、間隔が3つ以上（＝4本追う）ときに効く。
    if len(gaps) >= 3:
        ordered = sorted(gaps)
        middle = ordered[len(ordered) // 2]
        if middle > 0:
            cost += _SKIP_WEIGHT * max(0.0, ordered[-1] / middle - _SKIP_RATIO)
    return cost


def _transition(
    before: tuple[int, ...], after: tuple[int, ...], left: list[tuple[float, float]], right: list[tuple[float, float]]
) -> float:
    """フレーム間の飛び具合。

    比で測る（対数距離）。こうしておくと、全体が一定倍率でずれていても
    余計な費用が乗らない。加工された声を不利にしないため。
    """
    cost = 0.0
    for a, b in zip(before, after):
        cost += abs(math.log(right[b][0] / left[a][0]))
    return cost * _CONTINUITY_WEIGHT


def _track(run: list[list[tuple[float, float]]]) -> list[list[float]]:
    """途切れない区間のフォルマントを、系列として選び直す（Viterbi）。

    追う本数は区間ごとに決める。候補が 4本に足りないフレームがあるなら
    3本に落とす（本数がフレームごとに変わると系列として繋げられないので、
    区間の中では揃える）。
    """
    if not run:
        return []

    # 4本で組めるフレームが足りなければ3本に落とす。候補の少ないフレームが
    # 1枚あるだけで区間ごと捨てると、使える所まで失う。
    frames: list[tuple[list[tuple[float, float]], list[tuple[int, ...]]]] = []
    for size in (_TRACK_COUNT, _TRACK_COUNT_MIN):
        frames = [(poles, _states(len(poles), size)) for poles in run]
        frames = [(poles, states) for poles, states in frames if states]
        if len(frames) >= _MIN_RUN:
            break
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
            emission = _emission(state, poles)
            best_cost = float("inf")
            best_from = None
            for prior, prior_cost in costs.items():
                total = prior_cost + emission + _transition(prior, state, previous_poles, poles)
                if total < best_cost:
                    best_cost, best_from = total, prior
            best_costs[state] = best_cost
            step[state] = best_from
        costs = best_costs
        back.append(step)

    state = min(costs, key=lambda k: costs[k])
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
        ordered = ordered[cut : len(ordered) - cut]
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def harmonic_prominence(frame: list[float], f0: float) -> tuple[int, float]:
    """基音 f0 の倍音がどれだけ立っているか。(立っている本数, 山と谷の比)。

    有声音は声帯の準周期パルスを声道が濾したものなので、f0 の整数倍に確かに
    山が並ぶ。山（k×f0 のあたりの最大値）と谷（倍音と倍音の中間）の比を見る。

      純音       … 第1倍音しか無いので本数で落ちる
      雑音       … 山と谷に差が出ないので比で落ちる
      電源ハム等 … 倍音は並ぶが本数が足りない／比が伸びない
      有声音     … 4本以上が谷の数倍で立つ
    """
    if f0 <= 0 or len(frame) < 2:
        return 0, 0.0

    data = np.asarray(frame, dtype=float)
    data = data * np.hanning(len(data))
    spectrum = np.abs(np.fft.rfft(data))
    if spectrum.size < 2:
        return 0, 0.0
    freqs = np.fft.rfftfreq(len(data), 1.0 / RATE)
    nyquist = RATE / 2.0

    def band_max(centre: float) -> float:
        width = f0 * _HARMONIC_TOLERANCE
        picked = spectrum[(freqs >= centre - width) & (freqs <= centre + width)]
        return float(picked.max()) if picked.size else 0.0

    peaks: list[float] = []
    valleys: list[float] = []
    for k in range(1, _HARMONIC_COUNT + 1):
        centre = f0 * k
        if centre >= nyquist:
            break
        peaks.append(band_max(centre))
        middle = centre + f0 / 2.0  # 倍音と倍音のあいだ
        if middle < nyquist:
            valleys.append(band_max(middle))

    if not peaks or not valleys:
        return 0, 0.0

    floor = float(np.median(valleys)) or 1e-9
    strongest = max(peaks) or 1e-9
    resolved = sum(
        1 for peak in peaks if peak >= floor * _HARMONIC_MIN_PROMINENCE and peak >= strongest * _HARMONIC_MIN_LEVEL
    )
    ratio = float(np.median(peaks)) / floor
    return resolved, ratio


def voiced_f0(frame: list[float], context: list[float] | None = None) -> float | None:
    """このフレームを解析に使ってよいか。使えるなら基音を返す。

    判定はここ1箇所に持つ。以前は analyse() と _runs() がそれぞれ RMS と
    周期性を見ていて、片方だけ条件を足すと両者の選ぶフレームがずれていた。

    条件は4つ。
      1. 鳴っていること（無音・子音を除く）
      2. 周期的であること（自己相関の山）
      3. 基音が人の声の範囲にあること
      4. 基音の倍音が実際に並んでいること

    4 が無いと「周期的な音」までしか言えない。純音や電源ハムでも山は立つが、
    そこから取った LPC の極はフォルマントではないので、声道長の推定ごと
    引きずられる。

    context には、そのフレームの前後を含む広い窓を渡す（→
    _HARMONIC_WINDOW_SECONDS）。4 の判定にだけ使う。渡さなければフレーム
    自身を使うが、F0 が低い声では分解能が足りずに落としてしまう。
    """
    samples = np.asarray(frame, dtype=np.float64)
    size = samples.size
    if size <= 0:
        return None
    if math.sqrt(float(samples @ samples) / size) < _MIN_RMS:
        return None
    f0, periodicity = _f0_and_periodicity(frame)
    if periodicity < _MIN_PERIODICITY:
        return None
    if not (F0_MIN_HZ <= f0 <= F0_MAX_HZ):
        return None
    # context は numpy 配列で渡ることがある。真偽で見ると「要素が複数ある
    # 配列の真偽は決まらない」で落ちるので、渡されたかどうかで判断する。
    resolved, _ = harmonic_prominence(frame if context is None else context, f0)
    if resolved < _HARMONIC_MIN_RESOLVED:
        return None
    return f0


def _runs(chunk: list[float]) -> tuple[list[list[list[tuple[float, float]]]], list[float]]:
    """声が続いているあいだを1区間として、フレームごとの候補を並べる。

    あわせて、採用したフレームの基音も返す。フォルマントを取るフレームと
    基音を取るフレームが違うと、「この高さならこの声道長のはず」という
    突き合わせが別々の音を見ることになる。
    """
    frame_size = int(RATE * FRAME_SECONDS)
    hop = int(RATE * HOP_SECONDS)
    window = int(RATE * _HARMONIC_WINDOW_SECONDS)
    runs: list[list] = []
    current: list = []
    f0s: list[float] = []
    for start in range(0, len(chunk) - frame_size, hop):
        frame = chunk[start : start + frame_size]
        # 倍音を見るための窓。フレームを中心に前後へ広げる（端では寄せる）。
        centre = start + frame_size // 2
        begin = max(0, min(centre - window // 2, len(chunk) - window))
        context = chunk[begin : begin + window]
        f0 = voiced_f0(frame, context if len(context) >= frame_size else None)
        if f0 is None:
            if current:
                runs.append(current)
                current = []
            continue
        f0s.append(f0)
        current.append(_candidates(frame))
    if current:
        runs.append(current)
    return runs, f0s


def selection_bounds(duration: float, start: float | None, end: float | None) -> tuple[float, float] | None:
    """指定された範囲を、この録音の中に収まる形へ整える。

    範囲として成立しないものは None を返し、呼び出し側は録音全体を見る形に
    落ちる。ここを1箇所に置いて、API と解析で同じ規則を使う。
    """
    if start is None or end is None:
        return None
    try:
        begin, finish = float(start), float(end)
    except (TypeError, ValueError):
        return None
    if not (math.isfinite(begin) and math.isfinite(finish)):
        return None
    limit = duration if duration > 0 else max(begin, finish)
    begin = min(max(begin, 0.0), limit)
    finish = min(max(finish, 0.0), limit)
    if finish - begin < SELECTION_MIN_SECONDS:
        return None
    return begin, finish


def analyse(source: bytes | Path, duration: float, start: float | None = None, end: float | None = None) -> dict:
    """1トラックを調べる。

    start / end を渡すと、その区間だけを見る。渡さなければ録音の各所から
    少しずつ取って見るが、長い録音ではまず当たらないので、画面からは
    範囲を選んで呼ぶ形にしてある。

    verdict は3つ。
      natural … 人の声として無理のない値だった
      suspect … 加工されている形跡がある
      unknown … 判定できるだけの声が入っていない
    """
    spacings: list[float] = []
    formant_sets: list[list[float]] = []
    f0s: list[float] = []

    bounds = selection_bounds(duration, start, end)
    if bounds is None:
        chunks = _probe(source, duration)
    else:
        chunks = _probe(source, duration, bounds[0], bounds[1])
    analysed = sum(chunk.size for chunk in chunks) / RATE

    # フレームの選別は _runs（= voiced_f0）に一本化してある。以前はここでも
    # 別に RMS と周期性を見ていたため、基音を取るフレームとフォルマントを取る
    # フレームが違い、「この高さならこの声道長のはず」の突き合わせが別々の音を
    # 見ていた。
    for chunk in chunks:
        runs, chunk_f0s = _runs(chunk.tolist())
        f0s.extend(chunk_f0s)
        for run in runs:
            for formants in _track(run):
                formant_sets.append(formants)
                spacings.append((formants[-1] - formants[0]) / (len(formants) - 1))

    scope: dict[str, Any] = {
        "scope": "selection" if bounds else "whole",
        "analysed_seconds": round(analysed, 2),
    }
    if bounds:
        scope["range"] = {"start": round(bounds[0], 3), "end": round(bounds[1], 3)}

    if len(spacings) < _MIN_FRAMES:
        # 何が足りなかったのかを言う。ここを「判定できません」だけで返して
        # いたころは、範囲を選び直せば済むのか、そもそも無理なのかが
        # 操作する人に伝わらなかった。
        if bounds:
            reason = (
                f"選んだ範囲（{bounds[1] - bounds[0]:.1f} 秒）に、判定できるだけの"
                "声が入っていません。その人がはっきり喋っている所を選び直してください"
                "（数秒あれば足ります）。"
            )
        else:
            reason = (
                "録音全体から少しずつ抜き出して調べましたが、判定できるだけの声を"
                "拾えませんでした。長い録音ではまず当たりません。波形を見て、"
                "その人が喋っている区間を選んでから調べてください。"
            )
        return {
            "verdict": "unknown",
            "reason": reason,
            "frames": len(spacings),
            **scope,
        }

    f0 = _median(f0s) if f0s else 0.0
    spacing = _median(spacings)
    vtl = SPEED_OF_SOUND_CM / (2 * spacing) if spacing > 0 else 0.0
    factor = spacing / REFERENCE_SPACING_HZ if spacing > 0 else 0.0

    expected_vtl = _VTL_FROM_F0_INTERCEPT - _VTL_FROM_F0_SLOPE * f0 if f0 else 0.0
    mismatch = abs(vtl - expected_vtl) if (vtl and expected_vtl) else 0.0

    verdict, reasons = _judge(vtl, f0, expected_vtl)

    # その範囲の中で、フレームごとの間隔がどれだけ散らばっていたか。
    # 中央値だけを見ると、散らばりの大小に関わらず同じ顔で答えが返る。
    low_vtl, high_vtl = _vtl_band(spacings)
    spread = (high_vtl - low_vtl) / vtl if (vtl and high_vtl) else 0.0

    # まず「そもそも測り切れているか」。ここが緩いと、たまたま中央値が
    # どちらへ落ちたかで答えが決まる。実測では、同じ人の同じ録音でも
    # 区間を変えるだけで「加工の形跡あり」と「なし」が入れ替わっていた。
    if not vtl or spread > _MAX_RELATIVE_SPREAD:
        return {
            "verdict": "unknown",
            "reason": (
                f"この区間では声道長が {low_vtl:.1f}〜{high_vtl:.1f} cm に散らばっており"
                f"（中央値 {vtl:.1f} cm）、体格ひとつ言い当てられません。"
                "加工の有無は判断できません。その人がひと続きにはっきり喋っている所を、"
                "もう少し長めに選んでください。"
            ),
            "frames": len(spacings),
            "f0_hz": round(f0, 1),
            "formant_spacing_hz": round(spacing, 1),
            "vocal_tract_cm": round(vtl, 2),
            "vocal_tract_low_cm": round(low_vtl, 2),
            "vocal_tract_high_cm": round(high_vtl, 2),
            "measurement_settled": False,
            "identifies_speaker": False,
            **scope,
        }

    settled = _is_settled(verdict, low_vtl, high_vtl, f0, expected_vtl)
    if not settled:
        # 同じ範囲の中で答えが割れている。中央値がたまたまどちら側に
        # 落ちたかで「加工の形跡あり」と言い切るのは、断定を作るだけになる。
        verdict = "unknown"
        reasons = [
            f"中央値だけを見れば加工の形跡がありますが（声道長 {vtl:.1f} cm）、"
            f"同じ範囲の中で {low_vtl:.1f}〜{high_vtl:.1f} cm に散らばっており、"
            "加工の有無を分ける境目をまたいでいます。この範囲は根拠になりません。"
            "その人がひと続きにはっきり喋っている所を、もう少し長めに選んでください。"
        ]

    return {
        "verdict": verdict,
        "reason": " ".join(reasons) if reasons else "人の声として無理のない値でした。",
        "frames": len(spacings),
        "f0_hz": round(f0, 1),
        "formants_hz": [round(v, 1) for v in _median_formants(formant_sets)],
        "formant_spacing_hz": round(spacing, 1),
        "vocal_tract_cm": round(vtl, 2),
        # 中央値だけでなく、その範囲の中でどこからどこまで散らばっていたかを
        # 併せて返す。画面はこれを併記して、値の硬さが見えるようにする。
        "vocal_tract_low_cm": round(low_vtl, 2),
        "vocal_tract_high_cm": round(high_vtl, 2),
        "measurement_settled": settled,
        "expected_vocal_tract_cm": round(expected_vtl, 2),
        "vocal_tract_mismatch_cm": round(mismatch, 2),
        # 「話者が平均的な大人だったと仮定したときの」倍率。本人の地声が
        # 分からない以上、これは出発点の目安でしかない。復元は、この値を
        # そのまま当てるのではなく、操作する人が耳で決められるようにする。
        "estimated_factor": round(factor, 3),
        "restorable": verdict == "suspect" and 0.5 <= factor <= 2.0,
        # ここで言えるのは「加工されているか」までで、「誰か」は言えない。
        "identifies_speaker": False,
        **scope,
    }


def _judge(vtl: float, f0: float, expected_vtl: float) -> tuple[str, list[str]]:
    """測った値ひと組から判定と理由を出す。

    判定の規則をここ1箇所に持つ。中央値だけでなく、散らばりの端でも同じ
    規則を当てて「範囲の中で答えが割れていないか」を見るため、条件を
    2箇所に書くと必ずどちらかが古くなる。
    """
    reasons: list[str] = []
    if f0 and not (F0_MIN_HZ <= f0 <= F0_MAX_HZ):
        reasons.append(f"基本周波数が人の声の範囲外です（{f0:.0f} Hz）。")
    if vtl and not (VTL_IMPLAUSIBLE[0] <= vtl <= VTL_IMPLAUSIBLE[1]):
        reasons.append(f"フォルマントの間隔から求めた声道長が {vtl:.1f} cm で、" "人の声道としてありえない値です。")
    elif vtl and not (VTL_NATURAL[0] <= vtl <= VTL_NATURAL[1]):
        reasons.append(f"フォルマントの間隔から求めた声道長が {vtl:.1f} cm で、" "人の範囲の外側寄りです。")
    elif expected_vtl and vtl and abs(vtl - expected_vtl) > _VTL_F0_TOLERANCE_CM:
        # 声の高さと体格が食い違う。地声ではこうならない。
        reasons.append(
            f"声の高さ（{f0:.0f} Hz）に対して声道長 {vtl:.1f} cm は食い違います"
            f"（この高さなら {expected_vtl:.1f} cm 前後）。"
        )
    return ("suspect" if reasons else "natural"), reasons


def _vtl_band(spacings: list[float]) -> tuple[float, float]:
    """その範囲の中で、声道長がどこからどこまで散らばっていたか。

    四分位で見る（最小・最大だと、たまたま1枚外した極で端が決まる）。
    間隔と声道長は反比例なので、上下が入れ替わることに注意。
    """
    values = np.asarray(spacings, dtype=np.float64)
    q1, q3 = (float(v) for v in np.percentile(values, [25, 75]))
    if q1 <= 0 or q3 <= 0:
        return 0.0, 0.0
    return SPEED_OF_SOUND_CM / (2 * q3), SPEED_OF_SOUND_CM / (2 * q1)


def _is_settled(verdict: str, low_vtl: float, high_vtl: float, f0: float, expected_vtl: float) -> bool:
    """「加工の形跡あり」と言い切ってよいだけ、値が落ち着いているか。

    実際の録音で測ると、6秒の中でも声道長が 9.8〜18.5cm に散らばることが
    ある（人の範囲ほぼ全体）。この状態の中央値は、どちら側に落ちるかが
    たまたまで決まる。実測では同じ人・同じ録音で、選ぶ区間を変えただけで
    「加工の形跡あり」と「形跡なし」が入れ替わった（あるトラックで 5対2、
    別のトラックで 2対4）。中央値だけを見ていると、この揺れが見えないまま
    断定が出る。

    そこで、散らばりの端まで同じ判定になるときだけ suspect を出す。

    natural には同じ条件を課さない。natural は「加工の形跡が見つからな
    かった」であって、何かを言い当てた主張ではない。両方に厳しくすると、
    地声を録っただけの音が軒並み「判定できず」になり、警告そのものが
    使われなくなる。厳しくするのは、人を疑う側の答えだけでよい。
    """
    if verdict != "suspect":
        return True
    if not (low_vtl and high_vtl):
        return False
    return all(_judge(edge, f0, expected_vtl)[0] == "suspect" for edge in (low_vtl, high_vtl))


def _median_formants(sets: list[list[float]]) -> list[float]:
    """追跡した各本の代表値。

    区間によって追った本数が違うことがある（候補が足りなければ3本に落とす）。
    数の多いほうに揃えてから代表値を出す。
    """
    if not sets:
        return []
    sizes = [len(s) for s in sets]
    size = max(set(sizes), key=sizes.count)
    complete = [s for s in sets if len(s) == size]
    if not complete:
        return []
    return [_median([s[i] for s in complete]) for i in range(size)]


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
        f"aresample={rate}",  # 入力の周波数を揃える
        f"asetrate={int(rate / factor)}",  # 逆向きにずらす（長さも変わる）
        f"aresample={rate}",
    ]
    chain += [f"atempo={t:.6f}" for t in tempos]  # 長さを戻す
    return chain
