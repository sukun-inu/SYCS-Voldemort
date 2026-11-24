"""本番の CPU（Sandy Bridge）で、入っている依存が Illegal instruction を起こさないか検査する。

    python tools/check_cpu_baseline.py

なぜ要るか:
    本番の VM は CPU の種類が Sandy Bridge に固定されている（target-cpu=sandybridge）。
    AVX は使えるが、AVX2・FMA・BMI は無い。依存の配布物（wheel）が、より新しい CPU を
    前提にした作りで出てくると、本番だけで起動した瞬間に Illegal instruction で落ちる。
    手元の WSL も GitHub の CI も新しい CPU なので、テストを全部通しても気づけない。
    本番で落ちて初めて分かる形を、CI で先に捕まえる。

何をするか:
    1. 対照実験。AVX2 の命令を1つ使う小さなプログラムを gcc で作り、QEMU で
       Haswell のふりでは動き、Sandy Bridge のふりでは弾かれることを確かめる。
       **弾かれなければここで落とす。** 古い QEMU は CPU の種類を真似ても命令までは
       止めないことがあり、そのまま 2. を通すと、何も確かめずに緑になる。
    2. 同じ Python を QEMU の Sandy Bridge のふりで動かし、ネイティブの拡張を全部
       import して、少しずつ計算させる（import だけでは使われない命令がある）。
       地震の札と地図も描く（numpy と Pillow をいちばん重く使う経路）。

    1. と 2. の両方が通って初めて「本番の CPU で動く」と言える。

要るもの: qemu-user（qemu-x86_64）と gcc。CI では apt で入れる。無ければ落とす
（入っていないのに通すと、検査したふりだけが残る。CONTRIBUTING 8.）。

--inner は 2. の中身で、QEMU の下で自分自身を呼ぶときに使う。手では打たない。
"""

from __future__ import annotations

import importlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 本番で使うネイティブの拡張（C・Rust で書かれた部分を持つもの）。足したら、ここにも足す。
NATIVE_MODULES = [
    "numpy",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL.ImageFont",
    "PIL.ImageFilter",
    "orjson",
    "asyncpg",
    "cryptography.hazmat.primitives.asymmetric.ec",
    "sqlalchemy",
    "greenlet",
    "pydantic_core",
    "nacl.secret",
    "davey",
    "mutagen",
    "psutil",
    "aiohttp",
    "yarl",
    "multidict",
    "frozenlist",
    "rcssmin",
    "rjsmin",
]

AVX2_PROGRAM = r"""
#include <immintrin.h>
#include <stdio.h>
int main(void) {
    __m256i a = _mm256_set1_epi32(1);
    __m256i b = _mm256_add_epi32(a, a);
    printf("%d\n", _mm256_extract_epi32(b, 0));
    return 0;
}
"""


def _killed_by_sigill(returncode: int) -> bool:
    """Illegal instruction（SIGILL）で止まったか。

    subprocess はシグナルで止まったプロセスの終了コードを -4 のように負の数で返す。
    シェル経由だと 128 + 4 = 132 になる。最初は 132 だけを見ていて、弾かれているのに
    「弾かない」と判定していた（手元の WSL で見つけた）。
    """
    return returncode in (-signal.SIGILL, 128 + signal.SIGILL)


def _inner() -> int:
    """QEMU の Sandy Bridge のふりの下で動く側。import と計算と描画をする。"""
    for name in NATIVE_MODULES:
        importlib.import_module(name)

    import numpy as np

    matrix = np.random.default_rng(0).random((256, 256))
    (matrix @ matrix.T).sum()
    np.fft.fft(matrix[0])

    import orjson

    orjson.loads(orjson.dumps({"values": list(range(1000))}))

    from cryptography.hazmat.primitives.asymmetric import ec

    ec.generate_private_key(ec.SECP256R1())

    import nacl.secret
    import nacl.utils

    nacl.secret.SecretBox(nacl.utils.random(32)).encrypt(b"voice")

    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="cpu-baseline-"))
    import services.earthquake_service as eq

    for scale in (10, 40, 55, 70):
        eq._generate_badge(scale)
    eq._compose_intensity_map(
        [(0, 0)], [None], 0.0, 0.0, 7, [(38.7, 141.0, 60, "宮城県")], 38.7, 141.0, "最大震度 6強", "検査用"
    )
    print(f"  ネイティブの拡張 {len(NATIVE_MODULES)} 個の import・計算と、地震画像の描画が通った")
    return 0


def _control(qemu: str, gcc: str) -> bool:
    """AVX2 のプログラムが Haswell のふりでは動き、Sandy Bridge のふりでは弾かれるか。"""
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "avx2.c"
        exe = Path(tmp) / "avx2"
        src.write_text(AVX2_PROGRAM, encoding="utf-8")
        subprocess.run([gcc, "-O0", "-mavx2", str(src), "-o", str(exe)], check=True)
        newer = subprocess.run([qemu, "-cpu", "Haswell", str(exe)], capture_output=True).returncode
        sandy = subprocess.run([qemu, "-cpu", "SandyBridge", str(exe)], capture_output=True).returncode
    print(f"  対照実験: Haswell のふり → 終了コード {newer} / Sandy Bridge のふり → 終了コード {sandy}")
    return newer == 0 and _killed_by_sigill(sandy)


def main() -> int:
    """対照実験のあと、自分自身を QEMU の Sandy Bridge のふりで動かす。"""
    if "--inner" in sys.argv:
        return _inner()

    qemu = shutil.which("qemu-x86_64")
    gcc = shutil.which("gcc")
    if not qemu or not gcc:
        print("qemu-x86_64 か gcc が無い（apt install qemu-user gcc）。検査せずに通すことはしない。")
        return 1
    print(subprocess.run([qemu, "--version"], capture_output=True, text=True).stdout.splitlines()[0])

    if not _control(qemu, gcc):
        print("RESULT: この QEMU は Sandy Bridge のふりで AVX2 を弾かない。この先を通しても何も確かめていない。")
        return 1

    print("  Sandy Bridge のふりで Python を動かす（数十秒かかる）")
    inner = subprocess.run([qemu, "-cpu", "SandyBridge", sys.executable, __file__, "--inner"])
    if inner.returncode != 0:
        hint = "（Illegal instruction）" if _killed_by_sigill(inner.returncode) else ""
        print(f"RESULT: 本番の CPU では動かない依存がある。終了コード {inner.returncode}{hint}")
        return 1
    print("RESULT: 全て通過")
    return 0


if __name__ == "__main__":
    sys.exit(main())
