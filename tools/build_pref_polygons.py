"""地球地図日本（国土地理院）の行政界から、都道府県の輪郭を作る。

出力は assets/jp_prefectures.json。震度分布の画像で「揺れた県を塗る」ために使う。

元データ:
  地球地図日本 第2.1版 行政界 polbnda_jpn（国土地理院）
  https://www.gsi.go.jp/kankyochiri/gm_jpn.html
  公共データ利用規約（PDL1.0）— 出典表記と、加工した旨の記載が条件。

元は市区町村ごとの 2914 ポリゴンで 3.2MB ある。1200px の地図に落とすと
1px 未満の凹凸まで持っていることになるので、ここで間引いて配布用にする。
市区町村の境は残したままでよい（同じ県は同じ色で塗るので、内側の境界線は
描かれない）。県ごとに融合する幾何計算をせずに済む。

使い方:
    python tools/build_pref_polygons.py <polbnda_jpn.shp のあるディレクトリ>
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

# 座標の刻み。1/1000 度 ≒ 110m。下の間引き幅より細かいので、量子化で形は崩れない。
_UNIT = 1000
# 間引きの許容誤差（度）。0.004° ≒ 400m。日本全体を写すと 1px ≒ 900m、
# 数県だけの地震で寄ったときでも 1px ≒ 300m 程度なので、その前後に置く。
_TOLERANCE = 0.004
# これより小さい輪は捨てる（バウンディングボックスの面積、度^2）。
# 0.0009 ≒ 3km 四方。塗っても 1px に満たない岩礁まで抱えても意味がない。
_MIN_BOX = 0.0009

# JIS の都道府県コード順。services/earthquake_service.py の _PREF_CENTERS と同じ並び。
_PREFS = [
    "北海道",
    "青森県",
    "岩手県",
    "宮城県",
    "秋田県",
    "山形県",
    "福島県",
    "茨城県",
    "栃木県",
    "群馬県",
    "埼玉県",
    "千葉県",
    "東京都",
    "神奈川県",
    "新潟県",
    "富山県",
    "石川県",
    "福井県",
    "山梨県",
    "長野県",
    "岐阜県",
    "静岡県",
    "愛知県",
    "三重県",
    "滋賀県",
    "京都府",
    "大阪府",
    "兵庫県",
    "奈良県",
    "和歌山県",
    "鳥取県",
    "島根県",
    "岡山県",
    "広島県",
    "山口県",
    "徳島県",
    "香川県",
    "愛媛県",
    "高知県",
    "福岡県",
    "佐賀県",
    "長崎県",
    "熊本県",
    "大分県",
    "宮崎県",
    "鹿児島県",
    "沖縄県",
]


def read_dbf(path: Path, encoding: str = "cp932") -> list[dict]:
    """DBF の全レコード。属性は文字列のまま返す。"""
    raw = path.read_bytes()
    count, header_len, record_len = struct.unpack_from("<IHH", raw, 4)
    fields, off = [], 32
    while raw[off] != 0x0D:
        name = raw[off : off + 11].split(b"\x00")[0].decode("ascii")
        fields.append((name, raw[off + 16]))
        off += 32
    rows = []
    for index in range(count):
        pos = header_len + index * record_len + 1  # 先頭 1 バイトは削除フラグ
        row = {}
        for name, size in fields:
            row[name] = raw[pos : pos + size].decode(encoding, "replace").strip()
            pos += size
        rows.append(row)
    return rows


def read_shp_polygons(path: Path) -> list[list[list[tuple[float, float]]]]:
    """SHP のポリゴン。レコードごとに「輪のリスト」を返す。

    shapefile は仕様が短いので、依存を1つ増やすより読んだ方が早い。
    ヘッダ100バイトのあと、レコードは「番号(BE) 長さ(BE) 中身」の繰り返し。
    """
    raw = path.read_bytes()
    total = struct.unpack_from(">I", raw, 24)[0] * 2  # 16bit ワード数
    pos: int = 100
    shapes: list[list[list[tuple[float, float]]]] = []
    while pos < total:
        length = struct.unpack_from(">I", raw, pos + 4)[0] * 2
        body = pos + 8
        shape_type = struct.unpack_from("<i", raw, body)[0]
        if shape_type != 5:  # 5 = Polygon
            shapes.append([])
            pos = body + length
            continue
        part_count, point_count = struct.unpack_from("<ii", raw, body + 36)
        parts = struct.unpack_from(f"<{part_count}i", raw, body + 44)
        coords_at = body + 44 + part_count * 4
        flat = struct.unpack_from(f"<{point_count * 2}d", raw, coords_at)
        rings = []
        for index, start in enumerate(parts):
            end = parts[index + 1] if index + 1 < part_count else point_count
            rings.append([(flat[i * 2], flat[i * 2 + 1]) for i in range(start, end)])
        shapes.append(rings)
        pos = body + length
    return shapes


def simplify(ring: list[tuple[float, float]], tolerance: float) -> list[tuple[float, float]]:
    """Douglas-Peucker。再帰ではなく明示スタックで回す（長い海岸線で深くなる）。"""
    if len(ring) < 3:
        return ring
    keep = [False] * len(ring)
    keep[0] = keep[-1] = True
    stack = [(0, len(ring) - 1)]
    while stack:
        first, last = stack.pop()
        if last <= first + 1:
            continue
        ax, ay = ring[first]
        bx, by = ring[last]
        dx, dy = bx - ax, by - ay
        span = dx * dx + dy * dy
        worst, at = -1.0, first
        for i in range(first + 1, last):
            px, py = ring[i]
            if span == 0:
                dist = (px - ax) ** 2 + (py - ay) ** 2
            else:
                # 線分 AB への垂線の足までの距離（двойной面積 / |AB|）を二乗のまま比べる
                cross = dx * (py - ay) - dy * (px - ax)
                dist = cross * cross / span
            if dist > worst:
                worst, at = dist, i
        if worst > tolerance * tolerance:
            keep[at] = True
            stack.append((first, at))
            stack.append((at, last))
    return [point for point, hold in zip(ring, keep) if hold]


def _encode(ring: list[tuple[float, float]]) -> list[int]:
    """輪を整数の差分列にする。[x0, y0, dx1, dy1, dx2, dy2, ...]（単位 1/_UNIT 度）。

    そのまま小数で書くと 1 点あたり 19 バイトほどになり、全体で 1.2MB を超える。
    隣り合う点は近いので、差分にすると 1 桁か 2 桁の整数になり 1/4 に収まる。
    読む側は足し戻すだけ（services/earthquake_service.py の _load_prefecture_shapes）。
    """
    out: list[int] = []
    prev_x = prev_y = 0
    for index, (x, y) in enumerate(ring):
        ix, iy = round(x * _UNIT), round(y * _UNIT)
        if index == 0:
            out += [ix, iy]
        else:
            out += [ix - prev_x, iy - prev_y]
        prev_x, prev_y = ix, iy
    return out


def main(source: Path) -> None:
    rows = read_dbf(source / "polbnda_jpn.dbf")
    shapes = read_shp_polygons(source / "polbnda_jpn.shp")
    if len(rows) != len(shapes):
        raise SystemExit(f"属性 {len(rows)} 件とポリゴン {len(shapes)} 件が合いません")

    out: dict[str, list] = {name: [] for name in _PREFS}
    dropped = kept = 0
    for row, rings in zip(rows, shapes):
        code = row.get("adm_code", "")[:2]
        if not code.isdigit() or not (1 <= int(code) <= 47):
            continue
        name = _PREFS[int(code) - 1]
        for ring in rings:
            xs = [p[0] for p in ring]
            ys = [p[1] for p in ring]
            if (max(xs) - min(xs)) * (max(ys) - min(ys)) < _MIN_BOX:
                dropped += 1
                continue
            thin = simplify(ring, _TOLERANCE)
            if len(thin) < 4:
                dropped += 1
                continue
            kept += 1
            out[name].append(_encode(thin))

    empty = [name for name, rings in out.items() if not rings]
    if empty:
        raise SystemExit(f"輪郭が1つも残らなかった県があります: {empty}")

    payload = {
        "source": "地球地図日本 第2.1版 行政界（国土地理院） " "https://www.gsi.go.jp/kankyochiri/gm_jpn.html",
        "licence": "公共データ利用規約（PDL1.0）",
        "note": f"市区町村ポリゴンを都道府県ごとにまとめ、{_TOLERANCE}度で間引いて作成",
        "unit": _UNIT,
        "encoding": "各輪は [x0, y0, dx1, dy1, ...] の整数列。単位は 1/unit 度、経度が先。",
        "prefectures": out,
    }
    # data/ は実行時の状態置き場で .gitignore の対象。輪郭はコードと一緒に
    # 配るアセットなので assets/ に置く。
    target = Path(__file__).resolve().parent.parent / "assets" / "jp_prefectures.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    points = sum(len(r) // 2 for rings in out.values() for r in rings)
    print(f"{target}: 輪 {kept}（捨てた {dropped}）/ 点 {points} / " f"{target.stat().st_size / 1024:.0f}KB")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
