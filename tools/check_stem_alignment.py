#!/usr/bin/env python3
"""録音 ZIP の中で、各トラックの音が時間軸のどこに載っているかを測る。

  python tools/check_stem_alignment.py <archive.zip>

■ 何を見ているか

録音は「RTP タイムスタンプは無音のあいだも実時間ぶん進む」ことを前提に、
そこから求めた位置へ音を書いている（services/recording_service.py の
offset_for）。この前提が崩れていると、送られてこなかった無音のぶんだけ音が
前へ詰まり、**トラックごとに違う量だけ時間軸が縮む。**

縮んでいるなら、こう見える。

  最後の音の位置 ≒ 発話時間     … 無音が時間軸に載っていない（前へ詰まっている）
  最後の音の位置 ≒ 録音の長さ   … 正しく載っている

索引（mixer.json）の波形は書き込み位置そのものから作られるので、音声を
デコードしなくてもこれで分かる。判定に使うのは索引だけで、ZIP は書き換えない。
"""

import base64
import json
import sys
import zipfile
from pathlib import Path


def series(stem: dict) -> list[int]:
    """波形の点列。新しい索引は base64、古いものは float の配列。"""
    raw = stem.get("peaks_b64")
    if isinstance(raw, str):
        return list(base64.b64decode(raw))
    return [int(round(float(v) * 255)) for v in (stem.get("peaks") or [])]


def edges(points: list[int], bucket: float) -> tuple[float | None, float | None]:
    """音が入っている最初と最後の位置（秒）。"""
    hit = [i for i, v in enumerate(points) if v > 0]
    if not hit:
        return None, None
    return hit[0] * bucket, (hit[-1] + 1) * bucket


def main(path: Path) -> int:
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("mixer.json").decode("utf-8"))

    duration = float(manifest.get("duration_seconds") or 0)
    stems = manifest.get("stems") or []
    if not stems or duration <= 0:
        print("索引にトラックか長さがありません。")
        return 2

    print(f"録音の長さ: {duration:.1f} 秒")
    print(f"{'トラック':<20}{'最初の音':>10}{'最後の音':>10}{'発話時間':>10}{'末尾の空き':>12}")
    squashed = []
    for stem in stems:
        bucket = float(stem.get("bucket_seconds") or manifest.get("bucket_seconds") or 0.25)
        first, last = edges(series(stem), bucket)
        voiced = float(stem.get("voiced_seconds") or 0)
        name = str(stem.get("name", ""))[:18]
        if last is None:
            print(f"{name:<20}{'（無音）':>10}")
            continue
        print(f"{name:<20}{first:>9.1f}s{last:>9.1f}s{voiced:>9.1f}s{duration - last:>11.1f}s")
        # 「最後の音」が録音の終わりよりずっと手前で、しかも発話時間に近い
        if duration - last > max(60.0, duration * 0.05) and abs(last - voiced) < duration * 0.05:
            squashed.append(name)

    print()
    if squashed:
        print("**時間軸が前へ詰まっています。**", ", ".join(squashed))
        print("最後の音の位置が発話時間とほぼ同じで、録音の終わりよりずっと手前です。")
        print("無音が時間軸に載っていない（offset_for の前提が崩れている）ときの形です。")
        return 1
    print("前詰まりの兆候はありません。ずれは別の原因です。")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1])))
