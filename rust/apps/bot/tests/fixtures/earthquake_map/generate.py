"""震度の地図の基準を、本物の Python（services/earthquake_service.py と Pillow）から作る。

    python generate.py <出力先> [--dump <生の画素を書き出す先>] [--with-text <文字ありの PNG を書き出す先>]

出力（rust/apps/bot/tests/earthquake_map_golden.rs が読む）:

  shapes.json    図形・ぼかし・重ね合わせ・拡大縮小の例と、Pillow が描いた画素のハッシュ（gen_shapes.py）
  tiles.json     タイルの PNG（色の形いろいろ）と、明るさにして塗り替えた結果のハッシュ
  mercator.json  緯度 → tan・asinh・タイルの y（最後の桁まで比べるための見本）
  plans.json     震源と観測点 → ズーム・範囲・要るタイル（境の値を含む）
  pieces.json    札・震源の印・地名の札・帯と凡例・県の塗りを 1 つずつ描いた結果
  maps.json      地図の全体（段ごとの画素のハッシュ・文字を描く呼び出し・文字ありの最終のハッシュ）
  tiles/         地図の全体の例で配るタイルの見本（PNG）

**本番と同じ環境で動かすこと。** Dockerfile と同じ apt のパッケージ（fonts-noto-cjk・ffmpeg）と
requirements.txt を入れ、リポジトリの直下を /app に置く。加えて、**本番の CPU（Sandy Bridge）と同じ計算に
なるように、FMA を使わない設定で動かす**（下の `require_production_like_cpu`）。glibc は CPU に FMA が
あると tan・log1p・pow などを別の版に切り替え、結果の最後の桁が変わる（緯度 160 万件のうち tan が 6 件、
asinh が 610 件）。
"""

import math
import os
import random
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp())
sys.path.insert(0, "/app")
sys.path.insert(0, HERE)
import gen_maps  # noqa: E402
import gen_shapes  # noqa: E402
import numpy as np  # noqa: E402
from services import earthquake_service as eq  # noqa: E402

# glibc に FMA・AVX2 の版を選ばせない（本番の Sandy Bridge には無い）。numpy も同じにする。
PRODUCTION_LIKE = {
    "GLIBC_TUNABLES": "glibc.cpu.hwcaps=-FMA,-FMA4,-AVX2,-AVX512F",
    "NPY_DISABLE_CPU_FEATURES": "AVX2 FMA3 X86_V3",
}


def require_production_like_cpu() -> None:
    """本番と同じ計算になる設定でなければ、その設定を付けて自分を起動し直す。"""
    if all(os.environ.get(key) == value for key, value in PRODUCTION_LIKE.items()):
        return
    os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, **PRODUCTION_LIKE})


def sample_rings() -> list[list[list[float]]]:
    """県の輪を、大きいもの・小さいもの取り混ぜて 14 本（タイルの座標に直したもの）。"""
    shapes = eq._load_prefecture_shapes()
    rings = []
    for name in ("北海道", "東京都", "長崎県", "沖縄県", "宮城県", "石川県", "香川県"):
        ordered = sorted(shapes[name], key=len)
        for ring in (ordered[-1], ordered[len(ordered) // 2]):
            rings.append([[float(x), float(y)] for x, y in eq._project(ring, 8)])
    return rings


def mercator_samples() -> list[list[str]]:
    """緯度の見本（県庁所在地・県の形の点・でたらめな緯度）と、Python が出した tan・asinh・タイルの y。"""
    rng = random.Random(1923)
    lats = [lat for lat, _ in eq._PREF_CENTERS.values()]
    vertices = [float(p[1]) for rings in eq._load_prefecture_shapes().values() for ring in rings for p in ring]
    lats += rng.sample(vertices, 1200)
    lats += [rng.uniform(20.0, 50.0) for _ in range(600)]
    lats += [rng.uniform(-63.0, 63.0) for _ in range(200)]
    lats += [round(rng.uniform(20.0, 50.0), 1) for _ in range(200)]
    out = []
    for lat in lats:
        tan = math.tan(math.radians(lat))
        _, ty = eq._latlon_to_tile_float(lat, 139.0, 8)
        projected = eq._project(np.array([[139.0, lat]]), 8)
        assert float(projected[0][1]) == ty * 256, "numpy の式と math の式で値が違う"
        out.append([gen_maps.bits(v) for v in (lat, tan, math.asinh(tan), ty)])
    return out


def write(out: str, name: str, value: object) -> None:
    """JSON を書く（行末は LF）。"""
    with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(gen_shapes.dumps(value))


def option(name: str) -> str | None:
    """`--名前 値` の値。無ければ None。"""
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else None


def main() -> None:
    """基準を全部作り直す。"""
    require_production_like_cpu()
    if not eq._has_cjk_font():
        raise SystemExit("和字のフォント（fonts-noto-cjk）がありません。本番と同じ環境で動かしてください。")
    out = sys.argv[1]
    dump, with_text = option("--dump"), option("--with-text")
    for path in (out, os.path.join(out, "tiles"), dump, with_text):
        if path:
            os.makedirs(path, exist_ok=True)

    shapes = gen_shapes.shape_fixture(sample_rings(), dump)
    write(out, "shapes.json", shapes)
    tiles = gen_shapes.tile_fixture(eq._recolour_tile, dump)
    write(out, "tiles.json", tiles)
    write(out, "mercator.json", mercator_samples())

    plans = gen_maps.plan_inputs(eq)
    for case in plans:
        case["plan"] = gen_maps.plan_of(eq, case)
    write(out, "plans.json", plans)

    write(out, "pieces.json", gen_maps.piece_fixture(eq, dump))

    samples = gen_maps.sample_tiles()
    for index, data in enumerate(samples):
        with open(os.path.join(out, "tiles", f"tile_{index}.png"), "wb") as f:
            f.write(data)
    maps = gen_maps.map_fixture(eq, samples, dump, with_text)
    write(out, "maps.json", maps)

    errors = sum(1 for case in shapes if case["sha256"] == "error")
    raised = sum(1 for case in plans if "raises" in case["plan"])
    empty = sum(1 for case in plans if "none" in case["plan"])
    print(f"shapes {len(shapes)} 例（うち Pillow が断るもの {errors}）・tiles {len(tiles)} 例")
    print(f"plans {len(plans)} 例（例外 {raised}・地図なし {empty}）・maps {len(maps['cases'])} 例")


if __name__ == "__main__":
    main()
