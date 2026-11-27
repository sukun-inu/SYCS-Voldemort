"""震度の札（badge_<震度の値>.png）を、本物の Python から作り直す。

札は震度の値だけで決まる（9 通り）ので、Rust の Bot は作らずにこの画像を持っている。絵柄を変えたときだけ
作り直す。**本番と同じ環境で動かすこと**（Dockerfile と同じ apt のパッケージ〔fonts-noto-cjk・ffmpeg〕と
requirements.txt。フォントが無いと和字が出ず、別の絵柄になる）。

    python generate.py <出力先のディレクトリ>

リポジトリの直下を /app に置いて動かす。作ったら、Rust のテスト（earthquake_badges.rs）のハッシュも
書き換える（240×240 の RGBA の並びの SHA-256）。
"""

import hashlib
import io
import os
import sys
import tempfile

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
from PIL import Image  # noqa: E402
from services import earthquake_service as eq  # noqa: E402

SCALES = [10, 20, 30, 40, 45, 50, 55, 60, 70]


def main(out: str) -> None:
    """9 枚を書き出し、Rust のテストに書くハッシュを表示する。"""
    if not eq._has_cjk_font():
        raise SystemExit("和字のフォント（fonts-noto-cjk）がありません。本番と同じ環境で動かしてください。")
    os.makedirs(out, exist_ok=True)
    for scale in SCALES:
        png = eq._generate_badge(scale).getvalue()
        with open(os.path.join(out, f"badge_{scale}.png"), "wb") as f:
            f.write(png)
        pixels = Image.open(io.BytesIO(png)).convert("RGBA").tobytes()
        print(f'        ({scale}, "{hashlib.sha256(pixels).hexdigest()}"),')


if __name__ == "__main__":
    main(sys.argv[1])
