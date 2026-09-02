"""services/ 層のテスト。

    python -m unittest discover -s tests -t .

これまで services/ にはテストが1つも無く（70件はすべて管理画面 API と UI 向け）、
地震通知の不具合は毎回「本番で気付いて、使い捨てスクリプトで確かめる」流れに
なっていた。監査で洗い出した分岐をここに固定して、次からは自動で捕まえる。

Discord とネットワークには一切触らない。discord.py の型は Mock(spec=...) で
差し替え、設定ストアは一時ディレクトリを使う。
"""

import ast
import asyncio
import contextlib
import json
import logging
import os
import sys
import tempfile
import time
import unittest
import zipfile
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# services/* は読み込み時に SETTINGS_DIR を解決するため、import より前に差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="services-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
# 配信キャッシュは SETTINGS_DIR とは別の設定なので、明示的に隔離する。
# 忘れるとテストの録音がリポジトリの data/djaudio_cache に溜まり続ける。
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="services-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.earthquake_service as eq  # noqa: E402
from services import settings_store as store  # noqa: E402
from services.news_service import _favicon_url  # noqa: E402
from services.url_safety import URLSafetyError, validate_public_http_url  # noqa: E402
from services.welcome_service import DEFAULT_GOODBYE, DEFAULT_WELCOME, render_template  # noqa: E402
from webapp_admin.schema.validation import InvalidValue, validate_field  # noqa: E402


def _record_command_source() -> str:
    """/record のコマンド定義の原文をひと続きで返す。

    commands/recording_commands.py は register_recording_commands の分割で
    29行のディスパッチャになり、コマンドの実体は commands/record/ 以下へ
    移った（経緯は commands/record/__init__.py を参照）。ディスパッチャ側の
    原文を読んでも、管理者チェックも共有定数も、もうそこには無い。

    ここを「分割後もディスパッチャを読む」ままにすると、管理者チェックを
    全部外しても素通りで緑になる。読む先は必ず実体側に合わせること。
    連結順は register_recording_commands が register() を呼ぶ順と同じで、
    分割前のファイル内の記述順（start → stop → status → auto → config →
    exclude）に一致する。
    """
    import inspect

    from commands.record import config, exclude, session

    return "\n".join(inspect.getsource(m) for m in (session, config, exclude))


def text_channel(channel_id: int = 555):
    channel = Mock(spec=discord.TextChannel)
    channel.id = channel_id
    return channel


def guild_with(channel, channel_id: int = 555, name: str = "テスト鯖", members: int = 7):
    guild = Mock()
    guild.name = name
    guild.member_count = members
    guild.get_channel.side_effect = lambda i: channel if int(i) == channel_id else None
    return guild


def bot_with(guild, guild_id: int = 1):
    bot = Mock()
    bot.get_guild.side_effect = lambda g: guild if int(g) == guild_id else None
    return bot


QUAKE_551 = {
    "code": 551,
    "id": "q1",
    "earthquake": {
        "time": "2026/08/24 12:54:41",
        "maxScale": 40,
        "domesticTsunami": "None",
        "hypocenter": {"name": "茨城県沖", "latitude": 36.5, "longitude": 141.0, "depth": 40, "magnitude": 5.2},
    },
    "issue": {"type": "DetailScale", "time": "2026/08/24 12:57:23"},
    "points": [{"addr": "水戸市", "pref": "茨城県", "scale": 40}],
}

# 遠地地震。points も areas も maxScale も無く、震度が決まらない。
QUAKE_FOREIGN = {
    "code": 551,
    "id": "q2",
    "earthquake": {
        "time": "2026/08/24 13:00:00",
        "domesticTsunami": "None",
        "hypocenter": {"name": "南太平洋", "magnitude": 7.1, "depth": 10},
    },
    "issue": {"type": "Foreign", "time": "2026/08/24 13:02:00"},
}


class MaxScaleTests(unittest.TestCase):
    """震度の取り出し。ペイロードの形ごとに経路が違う。"""

    def test_points_win(self):
        self.assertEqual(eq._max_scale(QUAKE_551), 40)

    def test_eew_forecast_uses_areas(self):
        """556 は points ではなく areas に scaleFrom/scaleTo が入る。

        以前は intensity.forecastMaxInt を見ており、実データにその形が
        現れないため 556 の予想最大震度が常に不明になっていた。
        """
        event = {"code": 556, "areas": [{"scaleFrom": 30, "scaleTo": 45}, {"scaleFrom": 20, "scaleTo": 30}]}
        self.assertEqual(eq._max_scale(event), 45)

    def test_areas_fall_back_to_scale_from(self):
        self.assertEqual(eq._max_scale({"code": 556, "areas": [{"scaleFrom": 50}]}), 50)

    def test_max_scale_field_is_used_when_no_points(self):
        self.assertEqual(eq._max_scale({"earthquake": {"maxScale": 55}}), 55)

    def test_unknown_returns_minus_one(self):
        self.assertEqual(eq._max_scale(QUAKE_FOREIGN), -1)
        self.assertEqual(eq._max_scale({}), -1)


class ScaleLabelTests(unittest.TestCase):
    """震度の数値と階級の対応が、配信元の仕様と一致していること。

    P2PQuake JSON API v2 の仕様（swagger-ui/specification.yaml）に
      -1(不明) 0(震度0) 10(震度1) 20(震度2) 30(震度3) 40(震度4)
      45(震度5弱) 50(震度5強) 55(震度6弱) 60(震度6強) 70(震度7) 99(～程度以上)
    と定義されている。

    ここは以前 45 を「4強」、50 を「5弱」…と1段ずつずらして持っていた。
    震度5弱の地震を「震度4強」（気象庁に存在しない階級）、震度6強を
    「震度6弱」と、実際より低く伝えていたことになる。災害速報として
    致命的なので、表を触ったら必ずここで気づけるようにする。
    """

    # 配信元の仕様そのまま。ここを実装に合わせて書き換えないこと。
    SPEC = {10: "1", 20: "2", 30: "3", 40: "4", 45: "5弱", 50: "5強", 55: "6弱", 60: "6強", 70: "7"}

    def test_the_labels_match_the_upstream_spec(self):
        from config import SCALE_LABELS

        self.assertEqual(dict(SCALE_LABELS), self.SPEC)

    def test_every_table_covers_exactly_the_spec_values(self):
        """階級ごとの表（全角・バッジ・色・絵文字）に抜けや余りが無いこと。

        以前は存在しない 65 が各表に入っており、選べるのに一致しない
        設定値になっていた。
        """
        from webapp_admin.schema.panels.earthquake import VALID_SCALES

        tables = {
            "全角表記": eq._SCALE_MAP,
            "バッジ": eq._SCALE_BADGE_LABEL,
            "地図の色": eq._MAP_FILL_RGB,
            "帯の色": eq._SCALE_RGB,
            "絵文字": eq._SCALE_TITLE_EMOJI,
        }
        for name, table in tables.items():
            with self.subTest(name):
                self.assertEqual(sorted(table), sorted(self.SPEC), f"{name} の階級が仕様と違う")
        self.assertEqual(sorted(VALID_SCALES), sorted(self.SPEC), "設定画面で選べる震度が仕様と違う")

    def test_the_forecast_notation_maps_to_the_same_levels(self):
        """緊急地震速報の表記（5- など）と、地震情報の数値が同じ階級を指すこと。

        以前は EEW の "5-" を 50、地震情報の 45 を「4強」と読んでいたため、
        同じ震度5弱でも経路によって内部の数値が違い、通知する最小震度の
        判定が経路ごとにずれていた。
        """
        pairs = {"1": 10, "2": 20, "3": 30, "4": 40, "5-": 45, "5+": 50, "6-": 55, "6+": 60, "7": 70}
        self.assertEqual(dict(eq._FORECAST_INT_TO_SCALE), pairs)
        # 表記 → 数値 → 表示 が元の表記へ戻ること
        for text, value in pairs.items():
            with self.subTest(text):
                self.assertEqual(eq._SCALE_BADGE_LABEL[value], text)


class BadgeTests(unittest.TestCase):
    def test_known_scale_produces_an_image(self):
        buf = eq._generate_badge(40)
        self.assertIsNotNone(buf)
        self.assertGreater(len(buf.getvalue()), 0)

    def test_the_badge_is_smooth_at_the_corners(self):
        """等倍で描くと角が階段状になる（PIL はアンチエイリアスしない）。

        倍で描いてから縮めているので、角の内側には中間色の画素が並ぶはず。
        全部が「透明か不透明か」の2値なら、縮小が効いていない。
        """
        from PIL import Image

        image = Image.open(eq._generate_badge(40)).convert("RGBA")
        alpha = image.getchannel("A")
        corner = alpha.crop((0, 0, 24, 24)).getdata()
        midtones = [v for v in corner if 8 < v < 247]
        self.assertGreater(len(midtones), 12, "角に中間色が無い（等倍で描いている）")

    def test_the_number_stays_readable_on_light_scales(self):
        """震度4 は明るい黄色。白抜きだと沈むので黒にしている。"""
        light = eq._MAP_FILL_RGB[40]
        dark = eq._MAP_FILL_RGB[70]
        self.assertEqual(eq._ink_for(light)[:3], (16, 20, 26))
        self.assertEqual(eq._ink_for(dark)[:3], (255, 255, 255))

    def test_notify_does_not_build_a_badge_for_unknown_scale(self):
        """震度不明のまま作ると「最大震度 -1」と大書きした画像になる。"""
        made = []
        channel = text_channel()
        bot = bot_with(guild_with(channel))

        async def no_jma(event, scale):
            return "https://example.invalid/jma"

        with (
            patch.object(eq, "_resolve_jma_detail_url", no_jma),
            patch.object(eq, "_generate_badge", lambda s: made.append(s)),
            patch.object(eq, "get_all_guild_ids", lambda: [1]),
            patch.object(eq, "get_earthquake_settings", lambda g: {"channel_id": 555, "min_scale": -1}),
            patch.object(eq, "get_earthquake_notify_types", lambda g: {}),
        ):
            asyncio.run(eq._notify_all_guilds(bot, QUAKE_FOREIGN))

        self.assertEqual(made, [])


class IntensityMapTests(unittest.TestCase):
    """地図の組み立て。タイルは取りに行かず、描画の道筋だけを見る。"""

    def test_the_tile_source_needs_no_api_key(self):
        """配信元が鍵を要求するようになると、画像に文字が刷り込まれて届く。

        実際 CARTO がそうなり、「API KEY REQUIRED」と斜めに書かれた地図を
        そのまま Discord へ流していた。鍵の要らない地理院タイルを使う。
        """
        self.assertIn("cyberjapandata.gsi.go.jp", eq._TILE_URL)
        self.assertIn("国土地理院", eq._TILE_ATTRIBUTION)

    def test_a_white_map_is_repainted_dark(self):
        from PIL import Image

        tile = Image.new("L", (4, 4), 255)  # 白＝面
        tile.putpixel((0, 0), 0)  # 黒＝線
        out = eq._recolour_tile(tile)
        self.assertEqual(out.getpixel((1, 1)), eq._MAP_LAND)
        self.assertEqual(out.getpixel((0, 0)), eq._MAP_LINE)

    def test_it_draws_even_when_no_tile_arrives(self):
        """タイルが1枚も取れなくても、震度は出す。"""
        from PIL import Image

        # (緯度, 経度, 震度, 地名)
        plot = [(38.7, 141.0, 60, "宮城県"), (37.7, 140.4, 40, "福島県"), (35.6, 139.7, 10, "東京都")]
        buf = eq._compose_intensity_map(
            [(0, 0)], [None], 0.0, 0.0, 7, plot, 38.7, 141.0, "最大震度 6弱", "宮城県沖  M6.8"
        )
        image = Image.open(buf)
        self.assertEqual(image.size, (eq._MAP_W, eq._MAP_H))

    def _render(self, plot, lat, lon, zoom=8, centre=None):
        """タイルなしで地図を描き、画像と「緯度経度→画素」の変換を返す。

        原点を渡さないと札はすべて画面の外へ出る。それに気づかず面積だけを
        数えていたときは、見出しの「最大震度」の色札を数えてしまい、地図から
        札が消えていても通る検査になっていた。中心を明示して原点を決める。
        """
        from PIL import Image

        cx, cy = centre or (lat, lon)
        px, py = eq._latlon_to_tile_float(cx, cy, zoom)
        origin_x = px * eq._TILE_SZ - eq._MAP_W / 2
        origin_y = py * eq._TILE_SZ - eq._MAP_H / 2
        buf = eq._compose_intensity_map(
            [(0, 0)], [None], origin_x, origin_y, zoom, plot, lat, lon, "最大震度", "検査用"
        )

        def to_px(point_lat, point_lon):
            tx, ty = eq._latlon_to_tile_float(point_lat, point_lon, zoom)
            return (tx * eq._TILE_SZ - origin_x, ty * eq._TILE_SZ - origin_y)

        return Image.open(buf).convert("RGB"), to_px

    def _badge_area(self, image, at, rgb, span=26, tol=26):
        """その座標のまわりに、その色がどれだけ出ているか。

        見出しの色札や凡例のチップを数えないよう、地図上の一点だけを見る。
        """
        x, y = at
        box = image.crop((int(x - span), int(y - span), int(x + span), int(y + span)))
        return sum(
            1
            for r, g, b in box.getdata()
            if abs(r - rgb[0]) <= tol and abs(g - rgb[1]) <= tol and abs(b - rgb[2]) <= tol
        )

    def test_every_prefecture_outline_sits_where_that_prefecture_is(self):
        """輪郭と県名の対応がずれていないか。

        輪郭は市区町村コードの上2桁を JIS の都道府県コードとみなして束ねている。
        並びが1つずれても図としては成立してしまい、宮城の震度で福島が塗られる。
        画像を見ても気づけないので、県庁所在地との距離で押さえる。
        """
        import numpy as np

        shapes = eq._load_prefecture_shapes()
        self.assertEqual(len(shapes), 47)
        for name, (lat, lon) in eq._PREF_CENTERS.items():
            rings = shapes.get(name)
            self.assertTrue(rings, f"{name} の輪郭が無い")
            lons = np.concatenate([ring[:, 0] for ring in rings])
            lats = np.concatenate([ring[:, 1] for ring in rings])
            nearest = float(np.min(np.hypot(lons - lon, lats - lat)))
            self.assertLess(nearest, 0.35, f"{name} の輪郭が県庁所在地から離れすぎている")

    def test_a_shaken_prefecture_is_painted(self):
        """揺れた県は面でも塗る。

        札（点）だけでは「県のどこか1点が揺れた」ようにしか見えず、揺れが
        どちらへ広がったのかが伝わらない。
        """
        plot = [(38.268, 140.872, 50, "宮城県")]
        image, to_px = self._render(plot, 38.268, 140.872, zoom=8)
        # 県庁所在地から少し離れた、札には隠れない位置を見る。
        x, y = to_px(38.60, 140.70)
        patch = image.crop((int(x - 6), int(y - 6), int(x + 6), int(y + 6)))
        rgb = eq._MAP_FILL_RGB[50]
        # 塗られていれば、地の色（暗い青灰）より赤が強くなる。
        reds = [r for r, g, b in patch.getdata()]
        self.assertGreater(sum(reds) / len(reds), eq._MAP_LAND[0] + 25, "揺れた県が塗られていない")
        self.assertLess(sum(reds) / len(reds), rgb[0], "塗りが濃すぎて札より目立っている")

    def test_the_map_does_not_repeat_the_max_intensity_badge(self):
        """最大震度の札を地図の中に持たない。

        Discord の埋め込みには最大震度だけの画像がサムネイルとして付く
        （_generate_badge / attachment://intensity_badge.png）。地図の右上にも
        同じものを置くと、ひとつの吹き出しに同じ札が2つ出る。
        最大震度は見出しの文字列（「最大震度 4」）で足りる。
        """
        plot = [(36.341, 140.447, 40, "茨城県"), (35.605, 140.123, 30, "千葉県")]
        image, _ = self._render(plot, 35.5, 140.9, zoom=7)
        # 右上（凡例も出典も無い側）に、その震度の色の面が無いこと。
        corner = image.crop((image.width - 150, 0, image.width, 90))
        rgb = eq._MAP_FILL_RGB[40]
        hits = sum(
            1
            for r, g, b in corner.getdata()
            if abs(r - rgb[0]) <= 26 and abs(g - rgb[1]) <= 26 and abs(b - rgb[2]) <= 26
        )
        self.assertLess(hits, 60, "地図の中に最大震度の札が戻っている")

    def test_the_epicentre_shadow_fades_without_a_hard_edge(self):
        """震源印の後ろの影が、四角く切れずに滑らかに消える。

        影は「円を描いてガウスぼかし」で作っていたが、ぼかす版が円の外接矩形
        ちょうどの大きさしかなく、にじみが版の縁で切り落とされていた。丸い影の
        つもりが、角の取れた四角い影が震源印の後ろに出ていた。

        斜め45度に外へ向かって明るさを測り、隣り合う標本の段差を見る。
        矩形で切れていると、縁のところで急に地色へ戻る。
        暗い海の上では影そのものが見えない（地色と影の色がほぼ同じ）ので、
        影が本来効くべき「塗られた県の上」で測る。
        """
        plot = [(36.341, 140.447, 40, "茨城県")]
        image, to_px = self._render(plot, 36.55, 140.30, zoom=8)
        ex, ey = to_px(36.55, 140.30)
        walk = [sum(image.getpixel((int(ex + d), int(ey + d)))) for d in (19, 21, 23, 25, 27)]
        steps = [abs(b - a) for a, b in zip(walk, walk[1:])]
        self.assertLess(max(steps), 15, f"影が縁で切れている（斜めの明るさ {walk}）")

    def test_the_map_credits_the_outline_source(self):
        """輪郭は国土地理院のデータ。出典と、加工した旨を画像に載せる（PDL1.0）。"""
        self.assertIn("地球地図日本", eq._TILE_ATTRIBUTION)
        self.assertIn("加工", eq._TILE_ATTRIBUTION)

    def test_the_strongest_badge_survives_the_epicentre(self):
        """震央と最寄りの観測点が同じ場所でも、最大震度の札は残る。

        震源の位置を「札を置かない枠」として先に押さえていたころは、内陸の
        地震（震央＝県庁所在地の近く）で最大震度の札が丸ごと弾かれ、見出しに
        「最大震度6強」と書いてあるのに地図には 6強 がどこにも無かった。
        その後は震源印を最後に上から描いていたので、今度は札の数字が印の下に
        隠れた。速報として最初に読む値なので、どちらでも消えてはいけない。
        """
        plot = [(32.80, 130.71, 60, "熊本県"), (33.59, 130.40, 30, "福岡県")]
        image, to_px = self._render(plot, 32.80, 130.71)  # 震央＝最大震度の点
        area = self._badge_area(image, to_px(32.80, 130.71), eq._MAP_FILL_RGB[60])
        self.assertGreater(area, 400, "最大震度の札が震源印に消されている")

    def test_every_observation_point_carries_its_number(self):
        """札は色だけでなく数字を持つ。

        震度4(黄)と5弱(橙)は色が隣同士で、Discord に縮小されて届くと色だけでは
        見分けられない。「一目だと分かりにくい」の直接の原因だった。
        数字が入っていれば、札の中心付近に地の色ではない画素が現れる。
        """
        plot = [(38.70, 141.00, 40, "宮城県")]
        image, to_px = self._render(plot, 38.70, 141.00, centre=(38.70, 141.00))
        x, y = to_px(38.70, 141.00)
        core = image.crop((int(x - 5), int(y - 5), int(x + 5), int(y + 5)))
        rgb = eq._MAP_FILL_RGB[40]
        ink = sum(
            1 for r, g, b in core.getdata() if abs(r - rgb[0]) > 40 or abs(g - rgb[1]) > 40 or abs(b - rgb[2]) > 40
        )
        self.assertGreater(ink, 12, "札の中心に数字が入っていない")

    def test_a_weaker_badge_is_dropped_before_a_stronger_one(self):
        """重なったときに消えるのは弱い方。"""
        # ほぼ同じ場所に 6強 と 1。片方しか置けない。
        plot = [(38.700, 141.000, 60, "A"), (38.702, 141.002, 10, "B")]
        image, to_px = self._render(plot, 40.0, 143.0, zoom=9, centre=(38.70, 141.00))
        self.assertGreater(self._badge_area(image, to_px(38.700, 141.000), eq._MAP_FILL_RGB[60]), 400)
        self.assertLess(
            self._badge_area(image, to_px(38.702, 141.002), eq._MAP_FILL_RGB[10]),
            40,
            "弱い方が残って強い方を押しのけている",
        )

    def test_points_in_the_same_prefecture_keep_the_strongest(self):
        """観測点の座標は県庁所在地に丸めている。

        同じ県の点を全部描くと、ひとつの座標に何枚も丸が重なり、札の重なり
        避けで肝心の最大震度が弾かれる。
        """
        import asyncio

        captured = {}

        def fake_compose(coords, tiles, ox, oy, zoom, plot, lat, lon, title, sub):
            captured["plot"] = plot
            import io as _io

            return _io.BytesIO(b"x")

        async def no_tile(session, z, x, y):
            return None

        points = [
            {"addr": "宮城県栗原市", "pref": "宮城県", "scale": 60},
            {"addr": "宮城県登米市", "pref": "宮城県", "scale": 55},
            {"addr": "岩手県一関市", "pref": "岩手県", "scale": 50},
        ]
        with patch.object(eq, "_compose_intensity_map", fake_compose), patch.object(eq, "_fetch_tile", no_tile):
            asyncio.run(eq._generate_intensity_map(None, 38.7, 141.0, points))

        scales = sorted(point[2] for point in captured["plot"])
        self.assertEqual(scales, [50, 60], "同じ県の点がまとまっていない")


class EvaluateGuildTests(unittest.TestCase):
    """対象判定。ここが地震・津波・EEW・診断の唯一の判定元。"""

    def evaluate(self, settings, notify_types, *, max_scale=40, guild=None, **kw):
        bot = bot_with(guild) if guild is not None else bot_with(None)
        with (
            patch.object(eq, "get_earthquake_settings", lambda g: settings),
            patch.object(eq, "get_earthquake_notify_types", lambda g: notify_types),
        ):
            return eq._evaluate_guild(
                bot,
                1,
                notify_type=kw.get("notify_type", "quake_info"),
                max_scale=max_scale,
                apply_min_scale=kw.get("apply_min_scale", True),
            )

    def test_missing_channel_is_the_first_reason(self):
        channel, reason = self.evaluate({}, {})
        self.assertIsNone(channel)
        self.assertIn("チャンネル", reason)

    def test_min_scale_reason_names_both_numbers(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 50}, {})
        self.assertIn("50", reason)
        self.assertIn("40", reason)

    def test_notify_type_off_uses_a_japanese_label(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {"quake_info": False})
        self.assertIn("地震情報", reason)
        self.assertIn("オフ", reason)

    def test_uncached_guild_is_reported(self):
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {})
        self.assertIn("キャッシュ", reason)

    def test_channel_of_wrong_type_is_reported(self):
        voice = Mock(spec=discord.VoiceChannel)
        _, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {}, guild=guild_with(voice))
        self.assertIn("テキストチャンネル", reason)

    def test_eligible_guild_returns_the_channel(self):
        channel = text_channel()
        got, reason = self.evaluate({"channel_id": 555, "min_scale": 10}, {}, guild=guild_with(channel))
        self.assertIs(got, channel)
        self.assertEqual(reason, "")

    def test_broken_min_scale_falls_back_to_the_default(self):
        """設定が壊れていても例外にせず、既定の閾値で判定する。"""
        channel = text_channel()
        got, _ = self.evaluate({"channel_id": 555, "min_scale": "こわれた"}, {}, guild=guild_with(channel))
        self.assertIs(got, channel)

    def test_min_scale_can_be_skipped(self):
        """津波は震度を持たないので閾値を当てない。"""
        channel = text_channel()
        got, _ = self.evaluate(
            {"channel_id": 555, "min_scale": 70},
            {},
            max_scale=-1,
            apply_min_scale=False,
            notify_type="tsunami",
            guild=guild_with(channel),
        )
        self.assertIs(got, channel)


class DiagnoseTests(unittest.TestCase):
    def test_diagnosis_matches_the_filter(self):
        """説明用に条件を書き写すと実際のフィルタとずれて嘘の理由が出る。"""
        bot = bot_with(None)
        settings = {"channel_id": 555, "min_scale": 50}
        with (
            patch.object(eq, "get_earthquake_settings", lambda g: settings),
            patch.object(eq, "get_earthquake_notify_types", lambda g: {}),
        ):
            _, reason = eq._evaluate_guild(bot, 1, notify_type="quake_info", max_scale=40, apply_min_scale=True)
            diagnosed = eq._diagnose_no_target(bot, 1, notify_type="quake_info", max_scale=40)
        self.assertEqual(reason, diagnosed)

    def test_settings_failure_does_not_crash_the_diagnosis(self):
        def boom(_):
            raise RuntimeError("設定が読めない")

        with patch.object(eq, "get_earthquake_settings", boom):
            reason = eq._diagnose_no_target(bot_with(None), 1, notify_type="quake_info", max_scale=40)
        self.assertIn("読み取りに失敗", reason)


class CollectTargetsTests(unittest.TestCase):
    def test_a_broken_guild_does_not_stop_the_others(self):
        """1ギルドの設定不正で全ギルドへの通知が巻き添えで止まらないこと。"""
        channel = text_channel()
        guild = Mock()
        guild.get_channel.side_effect = lambda i: channel

        def settings(guild_id):
            if guild_id == 2:
                raise RuntimeError("この設定は壊れている")
            return {"channel_id": 555, "min_scale": 10}

        bot = Mock()
        bot.get_guild.side_effect = lambda g: guild
        with (
            patch.object(eq, "get_all_guild_ids", lambda: [1, 2, 3]),
            patch.object(eq, "get_earthquake_settings", settings),
            patch.object(eq, "get_earthquake_notify_types", lambda g: {}),
            self.assertLogs(eq.logger, level="ERROR") as captured,
        ):
            targets = eq._collect_targets(bot, notify_type="quake_info", max_scale=40)

        self.assertEqual([g for g, _ in targets], [1, 3])
        self.assertIn("guild=2", "\n".join(captured.output))

    def test_only_guild_id_narrows_to_one(self):
        channel = text_channel()
        bot = bot_with(guild_with(channel), guild_id=2)
        with (
            patch.object(eq, "get_all_guild_ids", lambda: [1, 2, 3]),
            patch.object(eq, "get_earthquake_settings", lambda g: {"channel_id": 555, "min_scale": 10}),
            patch.object(eq, "get_earthquake_notify_types", lambda g: {}),
        ):
            targets = eq._collect_targets(bot, notify_type="quake_info", max_scale=40, only_guild_id=2)
        self.assertEqual([g for g, _ in targets], [2])


class OverrideTargetTests(unittest.TestCase):
    """開発者パネル専用の経路。本番設定が無いギルドでも送れること。"""

    def test_override_ignores_settings(self):
        channel = text_channel(42)
        bot = bot_with(guild_with(channel, channel_id=42), guild_id=7)
        self.assertEqual(eq._override_target(bot, 7, 42), [(7, channel)])

    def test_missing_channel_is_reported(self):
        bot = bot_with(guild_with(text_channel(42), channel_id=42), guild_id=7)
        with self.assertLogs(eq.logger, level="WARNING") as captured:
            self.assertEqual(eq._override_target(bot, 7, 99), [])
        self.assertIn("指定チャンネル", "\n".join(captured.output))

    def test_uncached_guild_is_reported(self):
        with self.assertLogs(eq.logger, level="WARNING") as captured:
            self.assertEqual(eq._override_target(bot_with(None), 7, 42), [])
        self.assertIn("キャッシュ", "\n".join(captured.output))


class DispatchTests(unittest.TestCase):
    def test_send_failure_keeps_the_traceback(self):
        """gather の結果ループは except の外。exc_info を渡さないとトレースが
        "NoneType: None" になり、どこで落ちたかログに残らない。"""
        channel = text_channel(777)

        async def boom(**kwargs):
            raise RuntimeError("discord が 403 を返した")

        channel.send = boom
        with self.assertLogs(eq.logger, level="ERROR") as captured:
            ok = asyncio.run(eq._dispatch([(1, channel)], tag="earthquake", embed=discord.Embed(title="t")))
        self.assertEqual(ok, 0)
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertIsNotNone(record.exc_info)
        self.assertIsInstance(record.exc_info[1], RuntimeError)

    def test_successful_sends_are_counted(self):
        channels = []
        for i in range(3):
            channel = text_channel(i)
            channel.send = Mock(return_value=asyncio.sleep(0))
            channels.append(channel)
        ok = asyncio.run(
            eq._dispatch([(i, c) for i, c in enumerate(channels)], tag="earthquake", embed=discord.Embed(title="t"))
        )
        self.assertEqual(ok, 3)

    def test_each_channel_gets_its_own_file_object(self):
        """discord.File は送信で消費されるので使い回せない。"""
        seen = []

        def make(**kwargs):
            seen.append(kwargs.get("files"))
            return asyncio.sleep(0)

        channels = []
        for i in range(2):
            channel = text_channel(i)
            channel.send = make
            channels.append((i, channel))
        asyncio.run(
            eq._dispatch(channels, tag="earthquake", embed=discord.Embed(title="t"), attachments=[("a.png", b"xyz")])
        )
        self.assertEqual(len(seen), 2)
        self.assertIsNot(seen[0][0], seen[1][0])


class DedupTests(unittest.TestCase):
    def test_oldest_ids_are_evicted_not_the_whole_set(self):
        """全消しだと、消した直後の再配信を弾けず二重通知になる。"""
        seen, order = set(), deque()
        for i in range(eq._SEEN_ID_LIMIT + 10):
            seen.add(i)
            order.append(i)
            while len(order) > eq._SEEN_ID_LIMIT:
                seen.discard(order.popleft())
        self.assertEqual(len(seen), eq._SEEN_ID_LIMIT)
        self.assertIn(eq._SEEN_ID_LIMIT + 9, seen)  # 直近は残る
        self.assertNotIn(0, seen)  # 最古は落ちる


class DetailUrlTests(unittest.TestCase):
    def test_eid_becomes_a_human_readable_page(self):
        """以前は list.json の "json"（生データのファイル名）に当たり、
        ブラウザで開くとパーサーの値が出るだけのページになっていた。"""
        url = eq._item_detail_url({"eid": "20260824125441", "json": "20260824125723_..._VXSE5k_1.json"})
        self.assertIsNotNone(url)
        self.assertIn("map.html", url)
        self.assertIn("20260824125441", url)
        self.assertNotIn(".json", url)

    def test_missing_eid_gives_no_url(self):
        self.assertIsNone(eq._item_detail_url({"json": "x.json"}))


class EmbedTests(unittest.TestCase):
    def test_unknown_values_are_omitted_not_written_as_unknown(self):
        embed = eq._build_embed(QUAKE_FOREIGN, -1)
        rendered = embed.description + "".join(f.name + str(f.value) for f in embed.fields)
        self.assertNotIn("不明", rendered)
        self.assertIn("地震がありました", embed.description)

    def test_known_values_are_shown(self):
        embed = eq._build_embed(QUAKE_551, 40)
        names = [f.name for f in embed.fields]
        self.assertIn("震源", names)
        self.assertIn("規模", names)
        self.assertIn("深さ", names)

    def test_eew_cancellation_is_announced(self):
        """取り消しを黙って捨てると、外れた警報を訂正できない。"""
        embed = eq._build_eew_embed(
            {"code": 556, "cancelled": True, "earthquake": {"hypocenter": {"name": "茨城県沖"}}}
        )
        self.assertIn("取り消", embed.title)

    def test_detection_only_event_does_not_invent_fields(self):
        """554 は earthquake を持たない検出通知。埋められない欄は出さない。"""
        embed = eq._build_eew_embed({"code": 554, "type": "Full"})
        self.assertNotIn("不明", embed.description)
        self.assertEqual(embed.fields, [])

    def test_serial_comes_from_issue(self):
        embed = eq._build_eew_embed(
            {
                "code": 556,
                "issue": {"serial": 3},
                "earthquake": {
                    "originTime": "2026/08/24 12:00:00",
                    "hypocenter": {"name": "茨城県沖", "magnitude": 5.0},
                },
            }
        )
        self.assertIn("第3報", embed.title)


class DevTestNotifyTests(unittest.TestCase):
    """開発者パネルの通知テスト。本番設定なしで全種類が確かめられること。"""

    def setUp(self):
        from services import dev_test_notify

        self.dt = dev_test_notify
        self.sent = []

        channel = Mock(spec=discord.TextChannel)
        channel.id = 555

        async def send(content=None, embed=None, **kwargs):
            self.sent.append({"content": content, "embed": embed})
            message = Mock()

            async def add_reaction(emoji):
                self.sent.append({"reaction": emoji})

            message.add_reaction = add_reaction
            return message

        channel.send = send
        self.channel = channel

        role = Mock()
        role.mention = "@ロール"
        guild = Mock()
        guild.id = 1
        guild.name = "テスト鯖"
        guild.member_count = 7
        guild.me = None
        guild.members = []
        guild.get_channel.side_effect = lambda i: channel if int(i) == 555 else None
        guild.get_role.side_effect = lambda i: role if i else None
        self.guild = guild
        self.bot = bot_with(guild)

        self.empty = patch.multiple(
            "services.settings_store",
            get_welcome_settings=Mock(return_value={}),
            get_goodbye_settings=Mock(return_value={}),
            get_vc_notify_channel_id=Mock(return_value=0),
            get_sticky_messages=Mock(return_value={}),
            get_reaction_roles=Mock(return_value={}),
        )

    def test_every_kind_sends_without_production_config(self):
        """全種類が、本番のチャンネル設定なしで送信先を指定して確かめられること。"""
        for kind in self.dt.KINDS:
            with self.subTest(kind=kind):
                self.sent.clear()
                with self.empty, patch("services.tts_store.get_tts_settings", return_value={}):
                    asyncio.run(self.dt.run_test(self.bot, kind, 1, 555))
                self.assertTrue(self.sent, f"{kind} が何も送っていない")

    def test_every_kind_reports_one_reason_when_unconfigured(self):
        for kind in self.dt.KINDS:
            with self.subTest(kind=kind):
                with (
                    self.empty,
                    patch("services.logging_service.get_log_settings", return_value={}),
                    self.assertLogs(self.dt.logger, level="WARNING") as captured,
                ):
                    asyncio.run(self.dt.run_test(self.bot, kind, 1, None))
                reasons = [m for m in captured.output if "送れませんでした" in m]
                self.assertEqual(len(reasons), 1)
                self.assertIn("未設定", reasons[0])

    def test_goodbye_uses_the_production_default(self):
        with self.empty:
            asyncio.run(self.dt.run_test(self.bot, "goodbye", 1, 555))
        self.assertIn("去っていった", self.sent[0]["content"])

    def test_logging_reuses_the_production_embed(self):
        with patch("services.logging_service.get_log_settings", return_value={"log_level": "WARNING"}):
            asyncio.run(self.dt.run_test(self.bot, "logging", 1, 555))
        embed = self.sent[0]["embed"]
        self.assertIn("ボットログ", embed.title)
        self.assertIn("WARNING", embed.title)

    def test_reaction_roles_actually_adds_the_emoji(self):
        """絵文字がもう使えない、が主な故障なので一覧表示では確かめられない。"""
        mappings = {"m1": {"emoji": "👍", "role_id": 42, "channel_id": 555}}
        with patch("services.settings_store.get_reaction_roles", return_value=mappings):
            asyncio.run(self.dt.run_test(self.bot, "reaction_roles", 1, 555))
        self.assertIn("👍", [s.get("reaction") for s in self.sent])

    def test_sticky_calls_the_production_path(self):
        called = []

        async def fake_post(channel, guild_id):
            called.append((channel.id, guild_id))

        entry = {"555": {"content": "固定文", "message_id": None}}
        with (
            patch("services.settings_store.get_sticky_messages", return_value=entry),
            patch("services.sticky_service.post_sticky", fake_post),
        ):
            asyncio.run(self.dt.run_test(self.bot, "sticky", 1, 555))
        self.assertEqual(called, [(555, 1)])

    def test_tts_forwards_the_real_bot_to_enqueue_message(self):
        """enqueue_message に None を渡すと、新しく立つ _player_loop が
        bot.get_guild() で AttributeError を起こして黙って死に、キューに
        入れた音声が二度と再生されない（テストは「成功」を返すのに無音）。"""
        received = {}
        self.guild.me = Mock()  # スピーカーが取れないと enqueue_message まで到達しない

        async def fake_enqueue(bot, guild, member, text):
            received["bot"] = bot

        with (
            patch("services.tts_store.get_tts_settings", return_value={"enabled": True, "vc_channel_id": 999}),
            patch("services.tts_service.enqueue_message", fake_enqueue),
        ):
            asyncio.run(self.dt.run_test(self.bot, "tts", 1, 555))

        self.assertIs(received.get("bot"), self.bot)

    def test_unknown_kind_is_reported(self):
        with self.assertLogs(self.dt.logger, level="WARNING") as captured:
            asyncio.run(self.dt.run_test(self.bot, "nope", 1, 555))
        self.assertIn("未知の種類", "\n".join(captured.output))


class TtsDictionaryTests(unittest.TestCase):
    """読み上げ辞書の当て方。

    1語ずつ str.replace() を重ねていたため、前の規則の「出力」に次の規則が
    当たっていた。設定した本人にはまず理解できない読み方になるうえ、結果が
    登録順に依存していた。
    """

    def setUp(self):
        from services.tts_service import _apply_dictionary

        self.apply = _apply_dictionary

    def test_a_reading_is_not_replaced_again(self):
        # 「鈴木→すずき」と「すずき→スズキ」は、どちらも単独では正しい登録。
        forward = {"鈴木": "すずき", "すずき": "スズキ"}
        self.assertEqual(self.apply("鈴木さん", forward), "すずきさん")

        # 登録した順で結果が変わらないこと
        backward = {"すずき": "スズキ", "鈴木": "すずき"}
        self.assertEqual(self.apply("鈴木さん", backward), "すずきさん")

        # 登録どおりの単独変換は当然そのまま効く
        self.assertEqual(self.apply("すずきさん", forward), "スズキさん")

    def test_the_longer_entry_wins(self):
        """短い語が先に当たると、長い語の登録が意味を持たなくなる。"""
        dictionary = {"AI": "エーアイ", "AI研": "エーアイけん"}
        self.assertEqual(self.apply("AI研に行く", dictionary), "エーアイけんに行く")
        self.assertEqual(self.apply("AIの話", dictionary), "エーアイの話")

    def test_plain_cases_still_work(self):
        self.assertEqual(self.apply("そのまま", {}), "そのまま")
        self.assertEqual(self.apply("wwwすごい", {"w": "わら"}), "わらわらわらすごい")
        # 正規表現の記号を含む見出し語をそのまま扱えること
        self.assertEqual(self.apply("a.b を読む", {"a.b": "エービー"}), "エービー を読む")
        self.assertEqual(self.apply("axb を読む", {"a.b": "エービー"}), "axb を読む")


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self.guild_id = 4242

    def test_guild_settings_roundtrip(self):
        store.update_guild_settings(self.guild_id, {"probe": "値"})
        self.assertEqual(store.get_guild_settings(self.guild_id)["probe"], "値")

    def test_unknown_guild_returns_empty_dict_not_an_error(self):
        """通知先の判定はこれを前提に書かれている（例外だと全体が止まる）。"""
        self.assertEqual(store.get_earthquake_settings(999_999_999), {})

    def test_notify_types_key_order_is_stable(self):
        """順序が実行ごとに変わると、管理画面が「未保存」を誤検知し続ける。

        frozenset は文字列ハッシュのランダム化で反復順序が毎回変わるため、
        tuple で持っている。
        """
        first = list(store.get_earthquake_notify_types(self.guild_id))
        self.assertEqual(first, list(store._NOTIFY_TYPE_KEYS))
        self.assertEqual(first, list(store.get_earthquake_notify_types(self.guild_id + 1)))

    def test_notify_types_default_to_enabled(self):
        self.assertTrue(all(store.get_earthquake_notify_types(self.guild_id).values()))

    def test_unknown_notify_type_keys_are_dropped(self):
        store.set_earthquake_notify_types(self.guild_id, {"quake_info": False, "nope": True})
        saved = store.get_earthquake_notify_types(self.guild_id)
        self.assertFalse(saved["quake_info"])
        self.assertNotIn("nope", saved)

    def test_news_feed_state_keeps_only_recent_hashes(self):
        store.add_news_feed(self.guild_id, "feed1", 100, "クエリ", 60)
        store.update_news_feed_state(self.guild_id, "feed1", 1.0, [str(i) for i in range(150)])
        seen = store.get_news_feeds(self.guild_id)["feed1"]["seen_hashes"]
        self.assertEqual(len(seen), 100)
        self.assertEqual(seen[-1], "149")

    def test_async_write_matches_the_sync_one(self):
        store.add_news_feed(self.guild_id, "feed2", 100, "クエリ", 60)
        asyncio.run(store.aupdate_news_feed_state(self.guild_id, "feed2", 9.0, ["a"]))
        row = store.get_news_feeds(self.guild_id)["feed2"]
        self.assertEqual(row["last_run"], 9.0)
        self.assertEqual(row["seen_hashes"], ["a"])

    def test_missing_or_broken_int_setting_falls_back_to_zero(self):
        """整数の設定は「未設定なら 0」。0 は「無効」として全体で読まれている。

        通知チャンネル・メンションロール・フィルターロールの取得は、どれも
        この 1 つのヘルパー（_get_int_setting）に集約されている。既定値が
        0 以外に変わると、未設定のギルドが「ID 0 のチャンネルが設定済み」
        として扱われ、全ギルドの分岐が一斉にずれる。集約した以上、その
        既定値はここで押さえておく。
        """
        fresh = self.guild_id + 7
        self.assertEqual(store.get_vc_notify_channel_id(fresh), 0)
        self.assertEqual(store.get_vc_notify_role_id(fresh), 0)
        self.assertEqual(store.get_vc_notify_filter_role_id(fresh), 0)
        self.assertEqual(store.get_response_channel_id(fresh), 0)

        # 数値にできない値が入っていても 0 に倒す（例外を投げない）
        store.update_guild_settings(fresh, {"vc_notify_channel_id": "ちゃんねる"})
        self.assertEqual(store.get_vc_notify_channel_id(fresh), 0)

    def test_int_setting_reads_the_saved_value(self):
        """0 に倒す挙動が、保存済みの値まで潰していないこと。"""
        fresh = self.guild_id + 8
        store.set_vc_notify_channel_id(fresh, 123456)
        self.assertEqual(store.get_vc_notify_channel_id(fresh), 123456)

    def test_missing_dict_setting_returns_an_empty_dict_copy(self):
        """辞書の設定は「未設定なら空 dict」。返すのは複製であること。

        _get_dict_setting も複数の設定で共有している。呼び出し側が受け取った
        dict を書き換えても、保存済みの設定が道連れにならないことが前提。
        """
        fresh = self.guild_id + 9
        self.assertEqual(store.get_welcome_settings(fresh), {})

        store.update_guild_settings(fresh, {"welcome": {"channel_id": 1}})
        got = store.get_welcome_settings(fresh)
        got["channel_id"] = 999
        self.assertEqual(store.get_welcome_settings(fresh)["channel_id"], 1)


class SettingsLockLoggingTests(unittest.TestCase):
    """settings.json のファイルロック。永続化に関わるので、握りつぶさず
    理由を残すこと（他プロセスが最大 _SETTINGS_LOCK_STALE_SEC 待たされる）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="settings-lock-"))
        self.lock_path = self.tmp / "settings.json.lock"
        self._orig_dir = store._SETTINGS_DIR
        self._orig_lock_file = store._SETTINGS_LOCK_FILE
        store._SETTINGS_DIR = self.tmp
        store._SETTINGS_LOCK_FILE = self.lock_path

    def tearDown(self):
        store._SETTINGS_DIR = self._orig_dir
        store._SETTINGS_LOCK_FILE = self._orig_lock_file

    def test_stale_check_failure_is_logged_not_silent(self):
        """経過時間を確認できないと、恒久的な原因でも最後は無言の
        TimeoutError にしかならない。理由だけは残すこと。"""
        self.lock_path.write_text("someone-else", encoding="utf-8")  # 既存ロック
        real_stat = Path.stat
        lock_path = self.lock_path

        def fake_stat(self, *args, **kwargs):
            if self == lock_path:
                raise OSError("boom")
            return real_stat(self, *args, **kwargs)

        with patch.object(Path, "stat", fake_stat), self.assertLogs(store.logger, level="DEBUG") as captured:
            with self.assertRaises(TimeoutError):
                with store._settings_file_lock(timeout_sec=0.05):
                    pass
        self.assertTrue(any("経過時間を確認できません" in m for m in captured.output), captured.output)

    def test_read_owner_failure_on_release_is_logged(self):
        lock_path = self.lock_path
        real_read_text = Path.read_text

        def fake_read_text(self, *args, **kwargs):
            if self == lock_path:
                raise OSError("boom")
            return real_read_text(self, *args, **kwargs)

        with (
            patch.object(Path, "read_text", fake_read_text),
            self.assertLogs(store.logger, level="WARNING") as captured,
        ):
            with store._settings_file_lock(timeout_sec=1.0):
                pass
        self.assertTrue(any("所有者を確認できません" in m for m in captured.output), captured.output)

    def test_unlink_failure_on_release_is_logged(self):
        lock_path = self.lock_path
        real_unlink = Path.unlink

        def fake_unlink(self, *args, **kwargs):
            if self == lock_path:
                raise OSError("boom")
            return real_unlink(self, *args, **kwargs)

        with patch.object(Path, "unlink", fake_unlink), self.assertLogs(store.logger, level="WARNING") as captured:
            with store._settings_file_lock(timeout_sec=1.0):
                pass
        self.assertTrue(any("削除できません" in m for m in captured.output), captured.output)


class WelcomeTemplateTests(unittest.TestCase):
    """開発者パネルのテスト送信と本番が同じ描画を使うこと。"""

    def test_placeholders_are_replaced(self):
        out = render_template("{user}/{username}/{server}/{count}", user="U", username="N", server="S", count=3)
        self.assertEqual(out, "U/N/S/3")

    def test_missing_member_count_does_not_render_none(self):
        self.assertEqual(render_template("{count}", user="", username="", server="", count=None), "0")

    def test_defaults_are_shared(self):
        self.assertIn("{user}", DEFAULT_WELCOME)
        self.assertIn("{username}", DEFAULT_GOODBYE)


class UrlSafetyTests(unittest.TestCase):
    def test_public_url_passes(self):
        validate_public_http_url("https://example.com/path")

    def test_private_and_loopback_are_blocked(self):
        for url in (
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/",
            "http://localhost/",
            "http://[::1]/",
        ):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                validate_public_http_url(url)

    def test_non_http_schemes_are_blocked(self):
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/"):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                validate_public_http_url(url)

    def test_credentials_in_the_url_are_blocked(self):
        with self.assertRaises(URLSafetyError):
            validate_public_http_url("https://user:pass@example.com/")

    def test_missing_scheme_is_blocked(self):
        with self.assertRaises(URLSafetyError):
            validate_public_http_url("example.com")

    def test_ipv4_mapped_public_address_is_allowed(self):
        """公開IPv4を指す ::ffff: 形式を弾かないこと。"""
        validate_public_http_url("https://[::ffff:142.251.150.119]/path")

    def test_ipv4_mapped_is_judged_by_the_embedded_ipv4(self):
        """::ffff:a.b.c.d は a.b.c.d そのものとして判定すること。

        この1行が無いと、判定が Python のバージョンに依存する。3.12.4 未満の
        ipaddress は ::ffff:0:0/96 を丸ごと private に数えるため、公開IPv4を
        指すアドレスが is_global=False になる。手元(3.13)では通り、本番・
        CI(3.11)だけ non_public_ip で落ちる——という最も追いにくい形になり、
        実際に VirusTotal のスキャンが黙ってスキップされていた。
        """
        import ipaddress as _ip

        from services.url_safety import _unwrap_ipv4_mapped

        self.assertEqual(
            _unwrap_ipv4_mapped(_ip.ip_address("::ffff:142.251.150.119")),
            _ip.ip_address("142.251.150.119"),
        )
        # IPv4-mapped でないものは触らない
        raw = _ip.ip_address("2606:4700::6810:85e5")
        self.assertIs(_unwrap_ipv4_mapped(raw), raw)

    def test_is_public_ip_consults_the_embedded_ipv4_not_the_ipv6_flag(self):
        """判定が is_global そのままに戻されたら気づけること。

        手元の Python では ::ffff: の is_global が既に True なので、実物を
        渡すだけでは修正を外しても落ちない（実際に外して確認した）。
        3.12 未満の ipaddress を模した値を渡して、埋め込まれた IPv4 のほうを
        見ていることを、バージョンに依存せず押さえる。
        """
        import ipaddress as _ip

        from services.url_safety import _is_public_ip

        class _OldStyleMapped:
            """::ffff: を private と数えていた頃の ipaddress を模した値。"""

            is_global = False
            ipv4_mapped = _ip.ip_address("142.251.150.119")

        self.assertTrue(_is_public_ip(_OldStyleMapped()))

        class _OldStyleMappedPrivate:
            is_global = False
            ipv4_mapped = _ip.ip_address("10.0.0.5")

        self.assertFalse(_is_public_ip(_OldStyleMappedPrivate()))

    def test_ipv4_mapped_private_address_is_still_blocked(self):
        """↑の緩和が、内部アドレスへの抜け道になっていないこと。

        ::ffff:10.0.0.5 は 10.0.0.5 そのもの。IPv6 の皮をかぶせるだけで
        SSRF 対策を回避できるなら、この検査は無いのと同じになる。
        """
        for url in (
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.5]/",
            "http://[::ffff:192.168.1.1]/",
            "http://[::ffff:169.254.169.254]/",
        ):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                validate_public_http_url(url)

    def test_one_private_address_rejects_the_whole_hostname(self):
        """名前解決の結果に1つでも内部アドレスがあれば拒否すること（fail-close）。

        DNS を握られていれば「公開IPも返しつつ、実際の接続先は内部IP」に
        できる。「1つでも公開なら可」にすると、その一手で素通りする。
        """
        import socket as _socket

        infos = [
            (_socket.AF_INET, None, None, "", ("142.251.150.119", 0)),
            (_socket.AF_INET, None, None, "", ("10.0.0.5", 0)),
        ]
        with patch("services.url_safety.socket.getaddrinfo", return_value=infos) as gai:
            with self.assertRaises(URLSafetyError):
                validate_public_http_url("https://mixed.example/")
        self.assertTrue(gai.called, "getaddrinfo が差し替わっていない")


class NewsFaviconTests(unittest.TestCase):
    def test_domain_becomes_a_favicon_url(self):
        url = _favicon_url("https://www.example.co.jp")
        self.assertIn("www.example.co.jp", url)

    def test_www_prefix_is_kept_intact(self):
        """lstrip("www.") は文字集合を剥がすため 'wsj.com' が 'sj.com' になる。"""
        self.assertIn("www.wsj.com", _favicon_url("https://www.wsj.com"))

    def test_no_domain_gives_none(self):
        self.assertIsNone(_favicon_url(""))
        self.assertIsNone(_favicon_url("not a url"))


class UserStateDbSecretFileTests(unittest.TestCase):
    """*_PASSWORD_FILE が読めないと、次の候補（さらには既定パスワード）へ
    静かに落ちる。設定ミスの可能性が高いので理由を残すこと。"""

    def setUp(self):
        import services.user_state_db as user_state_db

        self.udb = user_state_db

    def test_missing_file_is_logged_not_silent(self):
        with self.assertLogs(self.udb.logger, level="WARNING") as captured:
            result = self.udb._read_secret_file("/definitely/does/not/exist")
        self.assertIsNone(result)
        self.assertTrue(any("読めませんでした" in m for m in captured.output), captured.output)

    def test_no_path_configured_is_not_an_error(self):
        """そもそも *_FILE が指定されていないだけなら、警告は不要。"""
        with self.assertRaises(AssertionError):
            with self.assertLogs(self.udb.logger, level="WARNING"):
                self.udb._read_secret_file(None)

    def test_pooled_int_prefers_primary_without_warning_about_unused_fallback(self):
        """primary が有効なら、無関係な fallback 側の壊れた値について
        （env_int を無条件に入れ子にすると出てしまう）筋違いの警告を出さない。"""
        import envutil

        os.environ["_TEST_PRIMARY_POOL"] = "20"
        os.environ["_TEST_FALLBACK_POOL"] = "oops"
        try:
            with self.assertRaises(AssertionError):
                with self.assertLogs(envutil.logger, level="WARNING"):
                    self.udb._pooled_int("_TEST_PRIMARY_POOL", "_TEST_FALLBACK_POOL", 5, minimum=1)
            self.assertEqual(
                self.udb._pooled_int("_TEST_PRIMARY_POOL", "_TEST_FALLBACK_POOL", 5, minimum=1),
                20,
            )
        finally:
            os.environ.pop("_TEST_PRIMARY_POOL", None)
            os.environ.pop("_TEST_FALLBACK_POOL", None)


class DjaudioCacheAtomicWriteTests(unittest.TestCase):
    """配信キャッシュのメタJSON書き込み。

    CDN（cdn_main.py）は Bot とは別プロセスで、同じディレクトリの .json を
    直接 glob/read する。直接 open("w") で上書きすると、読む側が書き込み
    途中のファイルを掴んで JSONDecodeError になりうる。
    """

    def setUp(self):
        import services.djaudio_cache as djaudio_cache

        self.dc = djaudio_cache

    def _register(self) -> str:
        src_dir = Path(tempfile.mkdtemp(prefix="djaudio-src-"))
        src = src_dir / "x.mp3"
        src.write_bytes(b"fake-mp3-bytes")
        return self.dc.register_file(src, "http://example.com/x", "タイトル", 999, ttl=600)

    def test_register_and_update_leave_no_tmp_file_behind(self):
        token = self._register()
        self.dc.update_discord_message(token, 111, 222)

        meta = self.dc.get_meta(token)
        self.assertEqual(meta["discord_channel_id"], "111")
        leftover = list(self.dc.DJAUDIO_CACHE_DIR.glob(f"{token}.json.tmp"))
        self.assertEqual(leftover, [], "tmp ファイルが残っている（replace されていない）")

    def test_corrupt_metadata_is_logged_not_silently_treated_as_expired(self):
        """壊れているのか本当に期限切れなのかが、ログでしか見分けられない。"""
        token = "deadbeefdeadbeefdeadbeefdeadbeef"
        bad_path = self.dc.DJAUDIO_CACHE_DIR / f"{token}.json"
        bad_path.write_text("{not valid json", encoding="utf-8")

        with self.assertLogs(self.dc.logger, level="WARNING") as captured:
            result = self.dc.get_meta(token)

        self.assertIsNone(result)
        self.assertTrue(any("壊れています" in m for m in captured.output), captured.output)

    def test_orphaned_tmp_file_is_eventually_swept(self):
        """_write_meta_atomic が tmp.replace() の前に落ちると .tmp が残る。
        *.json の glob には引っかからないので、専用の掃除が要る。"""
        old_tmp = self.dc.DJAUDIO_CACHE_DIR / "orphan.json.tmp"
        old_tmp.write_text("{}", encoding="utf-8")
        old_time = time.time() - (self.dc._TMP_ORPHAN_MAX_AGE_SEC + 60)
        os.utime(old_tmp, (old_time, old_time))

        asyncio.run(self.dc._cleanup_expired(None))

        self.assertFalse(old_tmp.exists())

    def test_a_fresh_tmp_file_mid_write_is_left_alone(self):
        """書き込み中（一瞬）の tmp を誤って消さないこと。"""
        fresh_tmp = self.dc.DJAUDIO_CACHE_DIR / "inflight.json.tmp"
        fresh_tmp.write_text("{}", encoding="utf-8")

        asyncio.run(self.dc._cleanup_expired(None))

        self.assertTrue(fresh_tmp.exists())
        fresh_tmp.unlink()


class DjaudioSiteDetectionTests(unittest.TestCase):
    def setUp(self):
        import services.djaudio_site_detection as sd

        self.sd = sd

    def test_allowed_host_passes(self):
        self.assertTrue(self.sd.is_djaudio_allowed_url("https://www.youtube.com/watch?v=1"))

    def test_unlisted_host_is_rejected(self):
        self.assertFalse(self.sd.is_djaudio_allowed_url("https://example.com/x"))

    def test_malformed_url_is_rejected_and_logged(self):
        """「未対応」と「URLとして壊れている」は呼び出し元からは同じ拒否に
        見えるが、原因を追えるようログだけは残すこと。"""
        with self.assertLogs(self.sd.logger, level="DEBUG") as captured:
            result = self.sd.is_djaudio_allowed_url("http://[::1")
        self.assertFalse(result)
        self.assertTrue(any("解釈できませんでした" in m for m in captured.output), captured.output)


class DjaudioReactionSafeTests(unittest.TestCase):
    """進捗の絵文字リアクションが付けられなくても処理は止めないが、
    黙って何もしないのではなく理由をログへ残すこと。"""

    def setUp(self):
        import services.djaudio_service as djaudio

        self.dj = djaudio

    def test_add_reaction_failure_is_logged(self):
        message = Mock(spec=discord.Message)

        async def boom(emoji):
            raise discord.HTTPException(Mock(status=404), "Unknown Message")

        message.add_reaction = boom
        with self.assertLogs(self.dj.logger, level="DEBUG") as captured:
            asyncio.run(self.dj._add_reaction_safe(message, "⏳"))
        self.assertTrue(any("リアクション追加に失敗" in m for m in captured.output))

    def test_remove_reaction_failure_is_logged(self):
        message = Mock(spec=discord.Message)

        async def boom(emoji, member):
            raise discord.HTTPException(Mock(status=404), "Unknown Message")

        message.remove_reaction = boom
        bot = Mock()
        bot.user = Mock()
        with self.assertLogs(self.dj.logger, level="DEBUG") as captured:
            asyncio.run(self.dj._remove_reaction_safe(message, "⏳", bot))
        self.assertTrue(any("リアクション除去に失敗" in m for m in captured.output))

    def test_remove_reaction_without_bot_user_is_logged_not_silent(self):
        message = Mock(spec=discord.Message)
        bot = Mock()
        bot.user = None
        with self.assertLogs(self.dj.logger, level="DEBUG") as captured:
            asyncio.run(self.dj._remove_reaction_safe(message, "⏳", bot))
        self.assertTrue(any("bot.user が未確定" in m for m in captured.output))


class VoiceSessionTests(unittest.TestCase):
    """読み上げと録音がひとつの接続を共有するための層。"""

    def setUp(self):
        from services import voice_session

        self.vs = voice_session
        self.vs._clients.clear()
        self.vs._holds.clear()
        self.vs._locks.clear()

    def test_hold_prevents_release(self):
        """録音中に読み上げ側の「VCが空になったら切る」で落とされないこと。"""
        client = Mock(spec=discord.VoiceClient)
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        self.assertFalse(asyncio.run(self.vs.release(1)))
        client.disconnect.assert_not_called()
        self.assertIn(1, self.vs._clients)

    def test_release_works_once_the_hold_is_gone(self):
        client = Mock(spec=discord.VoiceClient)
        client.disconnect = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")
        self.vs.unhold(1, "recording")

        self.assertTrue(asyncio.run(self.vs.release(1)))
        self.assertNotIn(1, self.vs._clients)

    def test_force_release_ignores_the_hold(self):
        client = Mock(spec=discord.VoiceClient)
        client.disconnect = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        self.assertTrue(asyncio.run(self.vs.release(1, force=True)))
        self.assertFalse(self.vs.is_held(1))

    def test_multiple_holders_each_have_to_let_go(self):
        self.vs.hold(1, "recording")
        self.vs.hold(1, "something-else")
        self.vs.unhold(1, "recording")
        self.assertTrue(self.vs.is_held(1))
        self.vs.unhold(1, "something-else")
        self.assertFalse(self.vs.is_held(1))

    def test_release_logs_when_disconnect_fails(self):
        """切断失敗を黙って握りつぶすと、_clients からは既に消えているのに
        実際の接続だけ生き残る（bot が VC に居座る）ことに誰も気づけない。"""

        async def boom(force=True):
            raise RuntimeError("ネットワークが死んでいる")

        client = Mock(spec=discord.VoiceClient)
        client.disconnect = boom
        self.vs._clients[1] = client

        with self.assertLogs(self.vs.logger, level="WARNING") as captured:
            result = asyncio.run(self.vs.release(1))

        self.assertTrue(result)  # _clients からは pop 済みなので戻り値自体は True
        self.assertNotIn(1, self.vs._clients)
        self.assertTrue(any("切断に失敗" in m for m in captured.output), captured.output)

    def test_held_connection_is_not_moved_to_another_channel(self):
        """録音中に読み上げの都合で別VCへ連れ出されると録音が途切れる。"""
        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=10)
        client.move_to = Mock()
        self.vs._clients[1] = client
        self.vs.hold(1, "recording")

        guild = Mock()
        guild.id = 1
        got = asyncio.run(self.vs.acquire(guild, 99, purpose="tts"))

        self.assertIs(got, client)
        client.move_to.assert_not_called()

    def test_unheld_connection_moves_normally(self):
        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=10)
        client.move_to = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client

        target = Mock(spec=discord.VoiceChannel)
        guild = Mock()
        guild.id = 1
        guild.get_channel.return_value = target

        got = asyncio.run(self.vs.acquire(guild, 99, purpose="tts"))
        self.assertIs(got, client)
        client.move_to.assert_called_once()

    def test_release_does_not_drop_the_guild_lock(self):
        """release() が _locks を pop すると、同時に走っている acquire() の
        排他が効かなくなる（新しい Lock が作られ、別タスクが素通りできる）。"""
        lock_before = self.vs._locks.setdefault(1, asyncio.Lock())
        client = Mock(spec=discord.VoiceClient)
        client.disconnect = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client

        asyncio.run(self.vs.release(1))

        self.assertIs(self.vs._locks.get(1), lock_before)


class RecordingTests(unittest.TestCase):
    """録音のトラック生成。ffmpeg を実際に動かして中身を確かめる。"""

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.work = Path(tempfile.mkdtemp(prefix="rectest-"))
        self._encode_log = ""
        self._last_probe_stderr = ""

    def _tone(self, seconds: float, freq: float = 440.0) -> bytes:
        import math
        import struct

        out = bytearray()
        for i in range(int(self.rec.SAMPLE_RATE * seconds)):
            v = int(12000 * math.sin(2 * math.pi * freq * i / self.rec.SAMPLE_RATE))
            out += struct.pack("<hh", v, v)
        return bytes(out)

    def _duration(self, path: Path) -> float:
        """mp3 の長さを ffmpeg でデコードして測る。

        **最後の time= を採ること。** ffmpeg は進捗を time= の行で流すが、
        何行出るかはビルドによって違う。6.x は復号を始める前に
        `time=00:00:00.00` を1行出してから、終了時にもう1行出す。ここで
        re.search（最初の一致）を使うと、その開始時の 0 秒を長さとして
        読んでしまう。

        手元の ffmpeg（Windows のビルド）は time= を1行しか出さないので
        最初と最後が同じになり、この取り違えが表に出なかった。Linux の CI で
        だけ「5秒のはずの mp3 が 0.0 秒」で落ちて発覚した。mp3 自体は
        どちらでも正しく5秒で作られている。
        """
        import re
        import subprocess
        from config import DJAUDIO_FFMPEG_PATH

        out = subprocess.run(
            [DJAUDIO_FFMPEG_PATH, "-i", str(path), "-f", "null", "-"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self._last_probe_stderr = out.stderr
        matches = re.findall(r"time=(\d+):(\d+):(\d+\.\d+)", out.stderr)
        if not matches:
            return -1.0
        hours, minutes, seconds = matches[-1]
        return int(hours) * 3600 + int(minutes) * 60 + float(seconds)

    def _track_report(self, writer, path: Path) -> str:
        """トラックが期待どおりで無かったときに、原因を追える材料を並べる。

        「0.0 != 5.0」だけでは、ffmpeg が起動しなかったのか、符号化器が無いのか、
        パイプが途中で折れたのかが区別できない。実際 Linux の CI でだけこの
        assert が落ち、この情報が無いために手元（Windows）から先へ進めなかった。
        """
        size = path.stat().st_size if path.exists() else None
        return (
            f"\n  ファイル: {path.name} = {size if size is not None else '存在しない'} バイト"
            f"\n  書き込み: written_bytes={writer.written_bytes} failed={writer.failed}"
            f"\n  ffmpeg: {self._ffmpeg_path()}"
            f"\n  符号化時のログ:\n{self._indent(self._encode_log)}"
            f"\n  長さ測定時の ffmpeg stderr:\n{self._indent(getattr(self, '_last_probe_stderr', ''))}"
        )

    @staticmethod
    def _ffmpeg_path() -> str:
        from config import DJAUDIO_FFMPEG_PATH

        return DJAUDIO_FFMPEG_PATH

    @staticmethod
    def _indent(text: str) -> str:
        lines = (text or "(出力なし)").strip().splitlines() or ["(出力なし)"]
        return "\n".join("    " + line for line in lines[-20:])

    @contextlib.contextmanager
    def _capture_recording_log(self):
        """recording_service の警告を溜める。

        ffmpeg の終了コードと stderr は close() の中で warning に落ちるだけで、
        テストからは見えない。落ちたときにいちばん効く情報なので拾っておく。
        """
        import logging

        collected: list[str] = []
        handler = logging.Handler()
        handler.emit = lambda record: collected.append(record.getMessage())
        logger = logging.getLogger("services.recording_service")
        logger.addHandler(handler)
        try:
            yield collected
        finally:
            logger.removeHandler(handler)

    def test_tracks_are_padded_onto_one_timeline(self):
        """喋った時刻が違っても、全トラックが同じ長さ・同じ時間軸に揃うこと。

        受信できるのは発話中のパケットだけなので、素直に繋ぐと無音が詰まって
        トラック同士がずれる。ずれると重ねて編集できず、マルチトラックの意味が無い。

        このテストだけが「ffmpeg が実際に音を符号化できているか」を見ている。
        落ちたときに何も分からないと困るので、失敗時は ffmpeg の言い分ごと出す。
        """
        started = time.monotonic()
        with self._capture_recording_log() as log:
            early = self.rec._TrackWriter(1, "A", self.work / "01-A.mp3", started)
            late = self.rec._TrackWriter(2, "B", self.work / "02-B.mp3", started)

            early.write(self._tone(0.5), 0.0)  # A は冒頭で発話
            late.write(self._tone(0.5), 3.0)  # B は3秒後に発話
            early.close(5.0)
            late.close(5.0)
        self._encode_log = "\n".join(log)

        a = self._duration(self.work / "01-A.mp3")
        self.assertAlmostEqual(a, 5.0, delta=0.3, msg=self._track_report(early, self.work / "01-A.mp3"))
        b = self._duration(self.work / "02-B.mp3")
        self.assertAlmostEqual(b, 5.0, delta=0.3, msg=self._track_report(late, self.work / "02-B.mp3"))
        self.assertAlmostEqual(a, b, delta=0.3)

    def test_voiced_time_excludes_the_padding(self):
        started = time.monotonic()
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", started)
        track.write(self._tone(1.0), 0.0)
        track.write(self._tone(1.0), 4.0)
        track.close(6.0)
        self.assertAlmostEqual(track.voiced_seconds, 2.0, delta=0.05)

    def _session(self, **kwargs):
        defaults = dict(
            guild_id=999,
            channel_id=555,
            channel_name="雑談",
            started_by_id=1,
            started_by_name="すずき",
            started_at=time.monotonic(),
            max_seconds=3600,
            retention_days=7,
        )
        defaults.update(kwargs)
        return self.rec.RecordingSession(**defaults)

    def test_excluded_users_get_no_track(self):
        session = self._session(excluded_user_ids={3})
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        session.feed(Mock(id=3, display_name="除外された人"), self._tone(0.2))
        self.assertEqual(sorted(session.tracks), [1])
        self.rec._finalize(session, 1.0, "テスト")

    def test_finalize_builds_a_zip_with_one_track_per_speaker(self):
        session = self._session()
        for user_id, name in ((1, "すずき"), (2, "たなか")):
            session.feed(Mock(id=user_id, display_name=name), self._tone(0.2))

        result = self.rec._finalize(session, 2.0, "テスト停止")
        self.assertEqual(result["track_count"], 2)

        from services.djaudio_cache import get_meta, payload_path

        meta = get_meta(result["token"])
        self.assertEqual(meta["kind"], "recording")
        self.assertEqual(meta["extension"], ".zip")

        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            names = archive.namelist()
            info = json.loads(archive.read("info.json").decode("utf-8"))
        self.assertEqual(len([n for n in names if n.endswith(".mp3")]), 2)
        self.assertIn("info.txt", names)
        self.assertEqual({t["名前"] for t in info["トラック"]}, {"すずき", "たなか"})

    def test_peaks_follow_the_speech_on_the_timeline(self):
        """波形が「いつ喋ったか」を表すこと。

        ミキサーは無音を詰めずに時間軸へ揃えて描く。波形が発話位置とずれると、
        誰がいつ喋ったかを目で追えなくなり、時系列表示の意味が無くなる。
        """
        started = time.monotonic()
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", started)
        track.write(self._tone(1.0), 0.0)  # 0〜1秒だけ発話
        track.pad_until(4.0)  # 残りは無音で埋まる

        series = track.peak_series()
        bucket = self.rec.PEAK_BUCKET_SECONDS
        self.assertAlmostEqual(len(series) * bucket, 4.0, delta=bucket)
        voiced = series[: int(1.0 / bucket)]
        silent = series[int(1.5 / bucket) :]
        self.assertTrue(all(v > 0.2 for v in voiced), series[:6])
        self.assertTrue(all(v == 0 for v in silent), series)
        track.close(4.0)

    def test_peak_series_downsamples_and_pads_as_told(self):
        """間引き幅と点数は呼び出し側が決める。

        以前はトラックが自分の長さから間引き幅を決めていたため、長さの違う
        トラック同士で1点あたりの秒数が変わり、同じ時間軸に並べられなかった。
        """
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", time.monotonic())
        track.peaks = [32767] * 20000
        series = track.peak_series(group=10, points=2000)
        self.assertEqual(len(series), 2000)
        self.assertTrue(all(v == 1.0 for v in series))  # 間引いても山は残る

        # 短いトラックは末尾を無音で埋めて、長いものと同じ点数に揃える。
        track.peaks = [32767] * 50
        padded = track.peak_series(group=10, points=2000)
        self.assertEqual(len(padded), 2000)
        self.assertTrue(all(v == 1.0 for v in padded[:5]))
        self.assertTrue(all(v == 0.0 for v in padded[5:]))
        track.close(0.0)

    def test_manifest_lines_the_tracks_up_for_the_mixer(self):
        session = self._session()
        for user_id, name in ((1, "すずき"), (2, "たなか")):
            session.feed(Mock(id=user_id, display_name=name), self._tone(0.3))
        result = self.rec._finalize(session, 2.0, "テスト")

        from services.djaudio_cache import get_meta, payload_path

        meta = get_meta(result["token"])
        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            manifest = json.loads(archive.read(self.rec.MANIFEST_NAME).decode("utf-8"))

        self.assertAlmostEqual(manifest["duration_seconds"], 2.0, delta=0.1)
        self.assertEqual(manifest["bucket_seconds"], self.rec.PEAK_BUCKET_SECONDS)
        self.assertEqual([s["index"] for s in manifest["stems"]], [0, 1])
        self.assertEqual({s["name"] for s in manifest["stems"]}, {"すずき", "たなか"})
        self.assertTrue(all(s["peaks"] for s in manifest["stems"]))
        self.assertTrue(all(s["size_bytes"] > 0 for s in manifest["stems"]))

    def test_waveform_covers_the_whole_recording_however_long_it_is(self):
        """索引の bucket_seconds × 点数 が録音の長さと一致すること。

        以前はトラックが自分の長さで間引くのに索引には間引く前の 0.25 秒を
        書いていた。12.5分を超える録音では波形が時間軸の先頭へ圧縮され
        （6時間なら全体が先頭12.4分ぶんに潰れる）、長さの違うトラック同士でも
        縮尺が食い違っていた。実際の録音を6時間ぶん流すのは重いので、
        目盛りを直接置いて書き出しだけを通す。
        """
        session = self._session()
        for user_id, name in ((1, "すずき"), (2, "たなか")):
            session.feed(Mock(id=user_id, display_name=name), self._tone(0.3))

        duration = 6 * 3600.0
        buckets = int(duration / self.rec.PEAK_BUCKET_SECONDS)
        tracks = list(session.tracks.values())
        tracks[0].peaks = [32767] * buckets
        # 途中で書き込みに失敗して短く終わったトラック。長いほうに揃うこと。
        tracks[1].peaks = [32767] * (buckets // 3)

        # 6時間ぶんを本当に書くと、末尾の穴埋めだけで1トラック 4GB を ffmpeg へ
        # 流すことになる。ここで見たいのは目盛りの縮尺だけなので、穴埋めと
        # 声の判定は省く（mp3 の書き出し自体は通す）。
        with (
            patch.object(self.rec._TrackWriter, "pad_until", lambda self, *a, **k: None),
            patch.object(self.rec, "measure_voice", return_value=None),
        ):
            result = self.rec._finalize(session, duration, "テスト")

        from services.djaudio_cache import get_meta, payload_path

        meta = get_meta(result["token"])
        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            manifest = json.loads(archive.read(self.rec.MANIFEST_NAME).decode("utf-8"))

        stems = manifest["stems"]
        bucket = manifest["bucket_seconds"]
        self.assertGreater(bucket, self.rec.PEAK_BUCKET_SECONDS)  # 間引かれている
        lengths = {len(s["peaks"]) for s in stems}
        self.assertEqual(len(lengths), 1, "トラックごとに点数が違うと縮尺がずれる")
        points = lengths.pop()
        self.assertLessEqual(points, self.rec.PEAK_MAX_POINTS)
        # 1点あたりの秒数 × 点数 が録音全体を覆っていること（誤差は1点ぶん）。
        # 直す前はここが 12.4 分ぶんにしかならなかった。
        self.assertAlmostEqual(points * bucket, duration, delta=bucket)
        self.assertTrue(all(s["bucket_seconds"] == bucket for s in stems))

    def test_mp3_go_in_uncompressed_so_the_mixer_can_seek(self):
        """ZIP を展開せずに Range で読むため、mp3 は無圧縮で入れる。"""
        session = self._session()
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.3))
        result = self.rec._finalize(session, 1.0, "テスト")

        from services.djaudio_cache import get_meta, payload_path

        meta = get_meta(result["token"])
        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            stored = {i.filename: i.compress_type for i in archive.infolist()}
        mp3 = {n: t for n, t in stored.items() if n.endswith(".mp3")}
        self.assertTrue(mp3)
        self.assertTrue(all(t == zipfile.ZIP_STORED for t in mp3.values()), mp3)

    def test_a_noisy_track_is_flagged_before_anyone_listens(self):
        """長さも件数も正しいのに中身が雑音、という壊れ方を実際にした。

        落として聞くまで気づけないのでは遅い。書き出し時に測って印を付ける。
        """
        import random
        import struct

        rng = random.Random(5)
        noise = bytearray()
        for _ in range(int(self.rec.SAMPLE_RATE * 1.0)):
            v = rng.randint(-9000, 9000)
            noise += struct.pack("<hh", v, v)

        session = self._session()
        session.feed(Mock(id=1, display_name="すずき"), self._tone(1.0))
        session.feed(Mock(id=2, display_name="たなか"), bytes(noise))
        result = self.rec._finalize(session, 2.0, "テスト")

        self.assertEqual(
            result["suspect_tracks"], ["たなか"], f"周期性の判定が効いていない: {result['suspect_tracks']}"
        )

        from services.djaudio_cache import get_meta, payload_path

        meta = get_meta(result["token"])
        with zipfile.ZipFile(payload_path(result["token"], meta)) as archive:
            manifest = json.loads(archive.read(self.rec.MANIFEST_NAME).decode("utf-8"))
        by_name = {s["name"]: s for s in manifest["stems"]}
        self.assertLess(by_name["たなか"]["periodicity"], manifest["periodicity_min"], by_name["たなか"])
        self.assertGreaterEqual(by_name["すずき"]["periodicity"], manifest["periodicity_min"], by_name["すずき"])

    def test_a_silent_track_is_not_called_broken(self):
        """無音しか入っていないトラックは、良し悪しを判定できない。

        判定できないものを「壊れている」と言うと、警告が信用されなくなる。
        """
        session = self._session()
        session.feed(Mock(id=1, display_name="すずき"), bytes(4 * self.rec.SAMPLE_RATE))
        result = self.rec._finalize(session, 1.0, "テスト")
        self.assertEqual(result["suspect_tracks"], [])

    def test_retention_days_control_the_link_lifetime(self):
        session = self._session(retention_days=3)
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        result = self.rec._finalize(session, 1.0, "テスト")

        from services.djaudio_cache import get_meta

        remaining = get_meta(result["token"])["expires_at"] - time.time()
        self.assertAlmostEqual(remaining, 3 * 24 * 3600, delta=60)

    def test_workdir_is_cleaned_up(self):
        session = self._session()
        session.feed(Mock(id=1, display_name="すずき"), self._tone(0.2))
        workdir = session.workdir
        self.rec._finalize(session, 1.0, "テスト")
        self.assertFalse(workdir.exists())

    def test_state_file_lets_the_admin_process_see_the_session(self):
        """管理画面は別プロセスなので、状態はファイル越しにしか見えない。"""
        session = self._session()
        self.rec._sessions[999] = session
        try:
            self.rec._write_state()
            state = self.rec.read_state()
        finally:
            self.rec._sessions.pop(999, None)
        self.assertIn("999", state["sessions"])
        self.assertEqual(state["sessions"]["999"]["channel_name"], "雑談")

    def test_state_file_ignores_an_empty_settings_dir(self):
        """SETTINGS_DIR=""（宣言だけで空）は Path("") = カレントディレクトリに
        ならないこと。Bot と管理画面のカレントディレクトリが違うと、
        書いた場所と読む場所がずれて「録音中」の表示が更新されなくなる。"""
        with patch.dict(os.environ, {"SETTINGS_DIR": ""}):
            path = self.rec._state_file()
        self.assertNotEqual(path.parent, Path("."))
        self.assertTrue(path.is_absolute())

    def test_start_refuses_without_the_receive_extension(self):
        """受信拡張が無い環境では、黙って失敗せず理由を返すこと。"""
        from services import voice_session

        guild = Mock()
        guild.id = 999
        with patch.object(voice_session, "RECEIVE_AVAILABLE", False):
            with self.assertRaises(self.rec.RecordingError) as caught:
                asyncio.run(
                    self.rec.start_recording(
                        Mock(),
                        guild,
                        Mock(spec=discord.VoiceChannel),
                        started_by=Mock(),
                    )
                )
        self.assertIn("受信", str(caught.exception))


class RecordingSettingsTests(unittest.TestCase):
    def test_defaults_match_the_agreed_limits(self):
        settings = store.get_recording_settings(4243)
        self.assertEqual(settings["max_minutes"], 360)  # 6時間
        self.assertEqual(settings["retention_days"], 7)
        self.assertEqual(settings["excluded_user_ids"], [])

    def test_unknown_keys_are_dropped(self):
        store.set_recording_settings(4243, {"max_minutes": 60, "nope": "x"})
        settings = store.get_recording_settings(4243)
        self.assertEqual(settings["max_minutes"], 60)
        self.assertNotIn("nope", settings)

    def test_excluded_users_survive_a_reread(self):
        store.set_recording_excluded_users(4243, [111, 222])
        self.assertEqual(store.get_recording_settings(4243)["excluded_user_ids"], [111, 222])


class DurationWidgetTests(unittest.TestCase):
    """期間の入力。保存は秒のまま、入力と表示だけ単位を付ける。"""

    def setUp(self):
        from webapp_admin.schema import duration
        from webapp_admin.schema.registry import PANEL_BY_ID

        self.duration = duration
        self.field = PANEL_BY_ID["djaudio"].field("cache_ttl")

    def test_largest_whole_unit_is_used(self):
        cases = {60: "1分", 600: "10分", 3600: "1時間", 86400: "1日", 2592000: "30日", 90: "90秒", 5400: "90分"}
        for seconds, expected in cases.items():
            with self.subTest(seconds=seconds):
                self.assertEqual(self.duration.humanize(seconds), expected)

    def test_cache_ttl_accepts_thirty_days(self):
        """30日まで指定できること。以前は 86400 秒（1日）で頭打ちだった。"""
        self.assertEqual(self.field.widget.value, "duration")
        self.assertEqual(self.field.max, 30 * 86400)
        self.assertEqual(validate_field(self.field, 30 * 86400, {}), 2592000)

    def test_over_the_limit_is_reported_in_days_not_seconds(self):
        """「2592000 以下」では何日なのか読み取れない。"""
        with self.assertRaises(InvalidValue) as caught:
            validate_field(self.field, 30 * 86400 + 1, {})
        self.assertIn("30日", str(caught.exception))
        self.assertNotIn("2592000", str(caught.exception))

    def test_below_the_minimum_is_reported_in_minutes(self):
        with self.assertRaises(InvalidValue) as caught:
            validate_field(self.field, 59, {})
        self.assertIn("1分", str(caught.exception))

    def test_non_numeric_is_rejected(self):
        with self.assertRaises(InvalidValue):
            validate_field(self.field, "しばらく", {})

    def test_store_and_schema_share_the_same_ceiling(self):
        """片方だけ古いと、画面で入れた値が黙って丸められる。

        以前は同じ数値を2箇所に手で書いており、この検査だけが両者を
        結び付けていた。いまはパネルが store の表（DJAUDIO_LIMITS）を
        読んで min/max を作るので、ずれようがない。表の側が壊れていない
        ことを見る。
        """
        self.assertEqual(store.DJAUDIO_LIMITS["cache_ttl"], (self.field.min, self.field.max))

    def test_thirty_days_survives_a_save_and_reread(self):
        store.set_djaudio_settings(4244, {"cache_ttl": 30 * 86400})
        self.assertEqual(store.get_djaudio_cache_ttl(4244), 2592000)

    def test_values_beyond_the_ceiling_are_clamped(self):
        store.set_djaudio_settings(4244, {"cache_ttl": 99_999_999})
        self.assertEqual(store.get_djaudio_cache_ttl(4244), 30 * 86400)

    def test_existing_second_values_still_load(self):
        """保存形式は秒のままなので、以前の設定がそのまま読めること。"""
        store.set_djaudio_settings(4245, {"cache_ttl": 600})
        self.assertEqual(store.get_djaudio_cache_ttl(4245), 600)

    def test_client_and_server_split_durations_the_same_way(self):
        """widgets.js の単位表と webapp_admin/schema/duration.py がずれていないこと。"""
        js = Path(__file__).resolve().parent.parent / "webapp_admin/static/js/forms/widgets.js"
        text = js.read_text(encoding="utf-8")
        for label, factor in self.duration.UNITS:
            with self.subTest(unit=label):
                self.assertIn(f'["{label}", {factor}]', text)


class UnlimitedRecordingTests(unittest.TestCase):
    """max_minutes=0 は「時間では止めない」。VC が無人になるまで録り続ける。"""

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording

    def _session(self, max_seconds):
        return self.rec.RecordingSession(
            guild_id=999,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=time.monotonic(),
            max_seconds=max_seconds,
            retention_days=7,
        )

    def test_zero_means_unlimited(self):
        self.assertTrue(self._session(0).is_unlimited)
        self.assertTrue(self._session(self.rec.UNLIMITED).is_unlimited)

    def test_a_real_limit_is_not_unlimited(self):
        self.assertFalse(self._session(3600).is_unlimited)

    def test_status_carries_the_flag_to_the_admin_screen(self):
        """管理画面は別プロセスなので、状態ファイル越しに伝わる必要がある。"""
        self.assertTrue(self._session(0).status()["unlimited"])
        self.assertFalse(self._session(3600).status()["unlimited"])

    def test_negative_settings_do_not_become_a_huge_limit(self):
        """設定が壊れていても「負の上限」で即停止したりしないこと。"""
        self.assertTrue(self._session(-60).is_unlimited)

    def test_empty_vc_is_detected(self):
        """無人判定。bot だけ残っている状態を「無人」とみなす。"""
        session = self._session(0)
        human = Mock()
        human.bot = False
        robot = Mock()
        robot.bot = True

        for members, expected in (
            (None, False),
            ([], True),
            ([robot], True),
            ([human], False),
            ([human, robot], False),
        ):
            with self.subTest(members=members):
                channel = Mock()
                channel.members = members
                guild = Mock()
                guild.get_channel.return_value = channel
                bot = Mock()
                bot.get_guild.return_value = guild
                self.assertIs(self.rec._vc_is_empty(bot, session), expected)

    def test_unknown_guild_is_not_treated_as_empty(self):
        """判断できないときに止めてしまうと、録音が勝手に切れる。"""
        bot = Mock()
        bot.get_guild.return_value = None
        self.assertFalse(self.rec._vc_is_empty(bot, self._session(0)))


class RecordingSettingsRangeTests(unittest.TestCase):
    def test_zero_is_accepted_and_kept(self):
        store.set_recording_settings(4246, {"max_minutes": 0})
        self.assertEqual(store.get_recording_settings(4246)["max_minutes"], 0)


class _FakeResponse:
    def __init__(self, status=200, retry_after=None, payload=None):
        self.status = status
        self.headers = {"Retry-After": retry_after} if retry_after else {}
        self._payload = (
            payload
            if payload is not None
            else [
                {"id": "1", "name": "general", "type": 0, "position": 0},
                {"id": "2", "name": "雑談VC", "type": 2, "position": 1},
            ]
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    async def json(self):
        return self._payload


class GuildChannelCacheTests(unittest.TestCase):
    """チャンネル一覧の取得。Discord のレート制限に当たらないこと。

    以前はテキストとボイスで別々に同じエンドポイントを叩き、キャッシュも
    無かったため、5秒おきに更新する画面を開いているだけで 429 を返され続けた。
    """

    def setUp(self):
        import webapp_admin.auth as auth

        self.auth = auth
        auth._guild_channels_cache.clear()
        auth._guild_channels_cooldown.clear()
        auth._guild_channels_locks.clear()
        self.calls = []

    def _quiet(self):
        """意図して失敗させる試験なので、その警告は出さない。"""
        return patch.object(self.auth.logger, "warning")

    def _patch_session(self, **response_kwargs):
        calls = self.calls

        class Session:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def get(self, url, **kwargs):
                calls.append(url)
                return _FakeResponse(**response_kwargs)

        return patch.object(
            self.auth.aiohttp,
            "ClientSession",
            Session,
            create=False,
        )

    def test_text_and_voice_share_one_request(self):
        """同じエンドポイントから両方取れるのに2回叩いていた。"""
        with self._patch_session():
            text = asyncio.run(self.auth.get_guild_channels(1))
            voice = asyncio.run(self.auth.get_guild_voice_channels(1))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([c["name"] for c in text], ["general"])
        self.assertEqual([c["name"] for c in voice], ["雑談VC"])

    def test_repeated_polling_hits_discord_once(self):
        with self._patch_session():
            for _ in range(12):
                asyncio.run(self.auth.get_guild_channels(1))
                asyncio.run(self.auth.get_guild_voice_channels(1))
        self.assertEqual(len(self.calls), 1)

    def test_concurrent_callers_do_not_duplicate_the_fetch(self):
        async def race():
            return await asyncio.gather(*(self.auth.get_guild_channels(1) for _ in range(10)))

        with self._patch_session():
            asyncio.run(race())
        self.assertEqual(len(self.calls), 1)

    def test_rate_limit_starts_a_cooldown(self):
        """429 のあとも叩き続けると、解除がさらに遠のく。"""
        with self._quiet(), self._patch_session(status=429, retry_after="5"):
            asyncio.run(self.auth.get_guild_channels(1))
            first = len(self.calls)
            for _ in range(10):
                asyncio.run(self.auth.get_guild_channels(1))
        self.assertEqual(first, 1)
        self.assertEqual(len(self.calls), 1)

    def test_stale_list_is_served_when_the_refresh_fails(self):
        """空を返すとドロップダウンが消えて設定できなくなる。"""
        with self._patch_session():
            good = asyncio.run(self.auth.get_guild_channels(1))
        # TTL を切らして、次の取得を 429 にする
        channels, _ = self.auth._guild_channels_cache[1]
        self.auth._guild_channels_cache[1] = (channels, 0.0)
        with self._quiet(), self._patch_session(status=429, retry_after="5"):
            stale = asyncio.run(self.auth.get_guild_channels(1))
        self.assertEqual(stale, good)

    def test_no_cache_and_a_failure_gives_an_empty_list(self):
        with self._quiet(), self._patch_session(status=500):
            self.assertEqual(asyncio.run(self.auth.get_guild_channels(1)), [])

    def test_cooldown_is_cleared_after_a_success(self):
        self.auth._guild_channels_cooldown[1] = 0.0  # 期限切れのクールダウン
        with self._patch_session():
            asyncio.run(self.auth.get_guild_channels(1))
        self.assertNotIn(1, self.auth._guild_channels_cooldown)


class StreamAssemblerTests(unittest.TestCase):
    """順不同・欠落した受信パケットを並べ直すこと。

    voice_recv のジッタバッファは、順番待ちの穴が空いた瞬間にバッファ全体を
    捨てて1つだけ返す（router 側が timeout=0 で pop するため）。本番ログでは
    こうなっていた:

        8 packets were lost being flushed in decoder-18295
         --> (last=5487) [5491, 5482, 5492, 5484, 5485, 5486, 5490, 5488, 5489]

    順不同のまま Opus に渡すと、直前の状態を使って復号するので音が壊れる。
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.stream = recording._StreamAssembler(18295)

    def _push(self, seq, now=0.0):
        self.stream.push(seq, seq * 960, bytes([seq % 251]), now)

    def _seqs(self, drained):
        # drain() は (RTPタイムスタンプ, opus, 受信時刻) を返す
        return [ts // 960 for ts, _payload, _at in drained]

    def test_out_of_order_packets_come_back_in_order(self):
        for seq in (5, 3, 1, 4, 2):
            self._push(seq)
        self.assertEqual(self._seqs(self.stream.flush()), [1, 2, 3, 4, 5])

    def test_the_logged_ordering_is_repaired(self):
        """本番ログに出ていた並びをそのまま流す。"""
        for seq in (5491, 5482, 5492, 5484, 5485, 5486, 5490, 5488, 5489):
            self._push(seq)
        got = self._seqs(self.stream.flush())
        self.assertEqual(got[0], 5482)
        self.assertEqual(sorted(got), got, got)  # 昇順であること

    def test_nothing_is_emitted_before_the_hold_window(self):
        """先に届いたものから出すと、あとから届く若い番号を全部捨てることになる。"""
        self._push(10, now=0.0)
        self.assertEqual(self.stream.drain(0.0), [])
        self._push(8, now=0.01)
        self._push(9, now=0.02)
        got = self._seqs(self.stream.drain(1.0))
        self.assertEqual(got, [8, 9, 10])

    def test_a_gap_is_given_up_on_after_the_hold_window(self):
        self._push(1, now=0.0)
        self._push(3, now=0.0)
        self.assertEqual(self._seqs(self.stream.drain(1.0))[:1], [1])
        # 2 は来なかった。待ち続けずに 3 へ進む。
        self.assertIn(3, self._seqs(self.stream.drain(2.0)) or [3])
        self.assertGreaterEqual(self.stream.lost, 1)

    def test_a_late_packet_is_not_wedged_back_in(self):
        """出し終えた位置より後ろへは差し込めない。数えて捨てる。"""
        self._push(1)
        self._push(2)
        self.stream.flush()
        self._push(1)
        self.assertEqual(self.stream.flush(), [])
        self.assertEqual(self.stream.late, 1)

    def test_a_full_buffer_is_emitted_not_discarded(self):
        """抱えすぎたときに古いほうを捨てると、いちばん欲しい音から消える。"""
        for seq in range(1, self.rec._REORDER_MAX + 40):
            self._push(seq, now=0.0)
        got = self._seqs(self.stream.drain(0.0))
        self.assertTrue(got, "溢れたまま何も出てこない")
        self.assertEqual(got[0], 1)
        self.assertEqual(sorted(got), got)

    def test_lost_frames_are_concealed_not_skipped(self):
        """飛ばしたままだとデコーダの状態がずれて継ぎ目が濁る。"""
        self._push(1, now=0.0)
        self._push(5, now=0.0)  # 2〜4 は来なかった
        drained = self.stream.drain(1.0)
        concealed = [payload for _ts, payload, _at in drained if payload is None]
        self.assertEqual(len(concealed), 3, drained)
        self.assertEqual(self._seqs(drained)[0], 1)
        self.assertEqual(self._seqs(drained)[-1], 5)
        self.assertEqual(self.stream.lost, 3)

    def test_sequence_numbers_wrap_around(self):
        """RTP のシーケンス番号は 16bit で折り返す。"""
        for seq in (65534, 0, 65535, 1):
            self._push(seq)
        got = self._seqs(self.stream.flush())
        self.assertEqual(len(got), 4)
        self.assertEqual(self.stream.lost, 0)

    def test_silence_packets_do_not_enter_the_reorder_buffer(self):
        """voice_recv の SilencePacket は sequence が常に -1（rtp.py）。

        連番で並べ直す仕組みにこれを入れると、すべて同じ鍵で衝突したうえ、
        次に来る本物のパケットとの差が数万になる。実測では lost が 27700 まで
        膨らみ、位置合わせの基準（RTP タイムスタンプの起点）ごと作り直される。
        中身は無音なので、時間軸の穴埋めに任せて数えるだけにする。
        """
        session = self.rec.RecordingSession(
            guild_id=999,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        sink = self.rec._make_sink_class()(session)
        user = Mock(id=1, display_name="すずき")

        def send(sequence, timestamp, payload):
            data = SimpleNamespace(packet=SimpleNamespace(ssrc=1, sequence=sequence, timestamp=timestamp), opus=payload)
            sink.write(user, data)

        from discord.ext.voice_recv.rtp import OPUS_SILENCE

        send(-1, 5_000_000, OPUS_SILENCE)  # 発話の切れ目
        send(27700, 5_000_000, bytes(20))  # そのあとの本物

        stream = sink._streams[1]
        self.assertEqual(stream.silence, 1)
        self.assertEqual(stream.lost, 0, "無音パケットで欠落が水増しされている")

    def test_timestamps_place_audio_on_the_timeline(self):
        """到着時刻ではなく RTP タイムスタンプで位置を決めること。"""
        base = 1_000_000
        first = self.stream.offset_for(base, 10.0)
        later = self.stream.offset_for(base + 48000 * 3, 10.05)  # 音は3秒ぶん先
        self.assertAlmostEqual(first, 10.0, delta=0.001)
        self.assertAlmostEqual(later, 13.0, delta=0.001)

    def test_a_jumped_timestamp_falls_back_to_the_clock(self):
        """相手側の時計が飛んでも、何時間ぶんもの無音を書かない。"""
        self.stream.offset_for(1_000_000, 5.0)
        with self.assertLogs("services.recording_service", level="WARNING"):
            offset = self.stream.offset_for(1_000_000 + 48000 * 9999, 5.02)
        self.assertAlmostEqual(offset, 5.02, delta=0.001)

    def test_the_timeline_starts_from_when_the_packet_arrived(self):
        """並べ直しで抱えていたぶん、トラックまるごとずれないこと。

        drain() は誰かのパケットが届いたときにしか回らない。ある人が一言だけ
        話して黙ると、その声は「次に誰かが話すまで」抱えられたままになる。
        起点を「出したときの時刻」で取っていたため、そのときの時刻が起点に
        なっていた。実測では 5.00 秒に話した声が 20.00 秒の位置へ書き込まれた。

        しかも起点は最初のパケットで決まるので、以後その人の音は全部同じだけ
        ずれる（だんだんずれるのではなく、最初から位置が違う）。ずれ幅は
        「次に誰かが話した時刻」で決まるため、トラックごとに違う。
        """
        frame = bytes(self.rec.FRAME_BYTES)
        clock = {"t": 0.0}
        placed: list[tuple[int, float]] = []

        with (
            patch.object(self.rec.time, "monotonic", lambda: clock["t"]),
            patch.object(self.rec._StreamAssembler, "decode", lambda self, encoded: frame),
        ):
            session = self.rec.RecordingSession(
                guild_id=999,
                channel_id=555,
                channel_name="雑談VC",
                started_by_id=1,
                started_by_name="すずき",
                started_at=0.0,
                max_seconds=0,
                retention_days=7,
            )
            session.feed = lambda user, pcm, at=None: placed.append((int(user.id), at))
            sink = self.rec._make_sink_class()(session)

            def speak(user_id, ssrc, at, timestamp):
                user = Mock(id=user_id, display_name=f"u{user_id}")
                for i in range(5):
                    clock["t"] = at + i * 0.02
                    sink.write(
                        user,
                        SimpleNamespace(
                            packet=SimpleNamespace(ssrc=ssrc, sequence=i, timestamp=timestamp + i * 960),
                            opus=b"\x01" * 20,
                        ),
                    )

            # それぞれ一言ずつ、間隔をばらばらにする
            speak(1, 101, at=5.0, timestamp=1_000_000)
            speak(2, 102, at=20.0, timestamp=2_000_000)
            speak(3, 103, at=95.0, timestamp=3_000_000)
            sink.flush_pending()

        first: dict[int, float] = {}
        for user_id, at in placed:
            first.setdefault(user_id, at)
        self.assertEqual(set(first), {1, 2, 3}, placed)
        for user_id, spoke_at in ((1, 5.0), (2, 20.0), (3, 95.0)):
            self.assertAlmostEqual(
                first[user_id],
                spoke_at,
                delta=0.05,
                msg=f"user{user_id} の声が {first[user_id]:.2f} 秒に置かれた" f"（発話は {spoke_at:.2f} 秒）",
            )


class OpusResilienceTests(unittest.TestCase):
    """壊れた Opus パケットで録音が止まらないこと。

    voice_recv にデコードさせると、1つでも壊れたパケットに当たった時点で
    受信スレッドが OpusError で落ち、stop_listening() まで呼ばれる
    （router.py の run/finally）。つまり録音が黙って止まる。
    こちらでデコードして、そのパケットだけ捨てる。
    """

    CORRUPT = b"\xff" * 40  # opus_decode が corrupted stream を返す並び

    def setUp(self):
        import discord.opus as opus
        import services.recording_service as recording

        # discord.py の opus は遅延読み込み。生成を試みるまで is_loaded() は False。
        if not opus.is_loaded():
            try:
                opus._load_default()
            except Exception:
                pass
        if not opus.is_loaded():
            self.skipTest("libopus が読み込めない環境です")
        self.opus = opus
        self.rec = recording
        self.session = recording.RecordingSession(
            guild_id=999,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        self.sink = recording._make_sink_class()(self.session)
        self.user = Mock(id=1, display_name="すずき")

    def _frame(self, freq=440.0):
        import math
        import struct

        pcm = bytearray()
        for i in range(960):  # 20ms
            v = int(12000 * math.sin(2 * math.pi * freq * i / self.rec.SAMPLE_RATE))
            pcm += struct.pack("<hh", v, v)
        return self.opus.Encoder().encode(bytes(pcm), 960)

    def _packet(self, payload, *, ssrc=18295):
        """本物と同じ形（SSRC・連番・タイムスタンプつき）のパケットを作る。

        並べ直しはこの3つを見て動くので、Mock で済ませると素通りしてしまう。
        """
        self._seq = getattr(self, "_seq", 1000) + 1
        packet = SimpleNamespace(ssrc=ssrc, sequence=self._seq % 65536, timestamp=(self._seq * 960) % (2**32))
        return SimpleNamespace(opus=payload, packet=packet)

    def _drain(self):
        """並べ直しを待たずに、抱えているぶんを書き出させる。"""
        self.sink.flush_pending()

    def test_library_is_not_asked_to_decode(self):
        """wants_opus() が False だと、壊れたパケットで受信スレッドごと落ちる。"""
        self.assertTrue(self.sink.wants_opus())

    def test_corrupt_payload_really_raises(self):
        """前提の確認。これが例外にならないなら、このテストは意味を持たない。"""
        with self.assertRaises(Exception):
            self.opus.Decoder().decode(self.CORRUPT, fec=False)

    def test_corrupt_packet_is_skipped_not_raised(self):
        self.sink.write(self.user, self._packet(self._frame()))
        self.sink.write(self.user, self._packet(self.CORRUPT))  # 例外が出たら失敗
        self._drain()
        self.assertEqual(self.session.dropped_packets, 1)

    def test_recording_continues_after_a_corrupt_packet(self):
        self.sink.write(self.user, self._packet(self._frame()))
        self.sink.write(self.user, self._packet(self.CORRUPT))
        self._drain()
        before = self.session.tracks[1].voiced_bytes
        self.sink.write(self.user, self._packet(self._frame()))
        self._drain()
        self.assertGreater(self.session.tracks[1].voiced_bytes, before)

    def test_a_flood_of_corrupt_packets_is_survivable(self):
        self.sink.write(self.user, self._packet(self._frame()))
        for _ in range(200):
            self.sink.write(self.user, self._packet(self.CORRUPT))
        self._drain()
        self.assertEqual(self.session.dropped_packets, 200)
        self.assertIn(1, self.session.tracks)

    def test_excluded_users_are_not_decoded(self):
        self.session.excluded_user_ids = {1}
        self.sink.write(self.user, self._packet(self._frame()))
        self._drain()
        self.assertEqual(self.session.tracks, {})

    def test_empty_payload_is_ignored(self):
        self.sink.write(self.user, self._packet(b""))
        self.sink.write(self.user, self._packet(None))
        self._drain()
        self.assertEqual(self.session.dropped_packets, 0)
        self.assertEqual(self.session.tracks, {})

    def test_dropped_count_reaches_the_result(self):
        self.sink.write(self.user, self._packet(self._frame()))
        self.sink.write(self.user, self._packet(self.CORRUPT))
        self._drain()
        result = self.rec._finalize(self.session, 1.0, "テスト")
        self.assertEqual(result["dropped_packets"], 1)

    def test_result_embed_warns_only_when_something_was_lost(self):
        base = {
            "token": "t" * 32,
            "title": "x",
            "track_count": 1,
            "duration_seconds": 60,
            "size_bytes": 1024,
            "retention_days": 7,
            "channel_id": 1,
            "channel_name": "雑談VC",
            "reason": "手動停止",
            "speakers": ["A"],
        }
        quiet = self.rec.build_result_embed(1, {**base, "dropped_packets": 0})
        noisy = self.rec.build_result_embed(1, {**base, "dropped_packets": 42})
        self.assertFalse(any("取りこぼし" in f.name for f in quiet.fields))
        self.assertTrue(any("取りこぼし" in f.name for f in noisy.fields))


class RecordingSinkShapeTests(unittest.TestCase):
    """_make_sink_class() が返すクラスの、外から見える姿を固定する。

    213行ある `_make_sink_class` を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    受け取り側の挙動（壊れたパケット・除外ユーザー・並べ直し）は
    OpusResilienceTests が押さえているが、**次の3つは誰も見ていなかった。**

      1. voice_recv が受け取れる型であること
         `listen(sink)` は AudioSink のサブクラスしか受けない。継承の形を
         変えると、テストは全部通るのに**本番で録音を始めた瞬間に落ちる**。
      2. 停止時の要約
         33行あるのに1件もテストが無かった。壊れても録音そのものは動くので、
         「あとからログを読む人」だけが困る（そして誰も気づかない）。
      3. cleanup() が参照を手放すこと
         手放さないとセッションのたびにメモリが積み上がる。動きはする。
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.cls = recording._make_sink_class()
        self.session = recording.RecordingSession(
            guild_id=999,
            channel_id=555,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=7,
        )
        self.sink = self.cls(self.session)
        self.user = Mock(id=1, display_name="すずき")
        self._seq = 1000

    def tearDown(self):
        import shutil

        # ffmpeg のパイプを開いたまま作業ディレクトリを消すと、後始末の順序で
        # BrokenPipeError の警告がテスト出力へ混ざる。先に閉じる。
        for track in self.session.tracks.values():
            with contextlib.suppress(Exception):
                track.close(0.0, timeout=5.0)
        shutil.rmtree(self.session.workdir, ignore_errors=True)

    def _packet(self, ssrc=18295):
        """本物と同じ形（SSRC・連番・タイムスタンプ・ペイロード種別つき）。"""
        self._seq += 1
        packet = SimpleNamespace(
            ssrc=ssrc,
            sequence=self._seq % 65536,
            timestamp=(self._seq * 960) % (2**32),
            payload=120,
        )
        return SimpleNamespace(opus=b"\xfc\xff\xfe" + b"\x00" * 20, packet=packet)

    def test_the_sink_is_a_subclass_of_the_library_audio_sink(self):
        """voice_recv.AudioSink のサブクラスであること。

        `listen()` はこの型しか受け取らない。継承の形を変えると、単体テストは
        sink を直接呼ぶので全部通るが、本番では録音の開始そのものが失敗する。
        """
        from discord.ext import voice_recv

        self.assertTrue(issubclass(self.cls, voice_recv.AudioSink))
        self.assertIsInstance(self.sink, voice_recv.AudioSink)

    def test_the_method_surface_is_unchanged(self):
        """クラスが持つメソッドの顔ぶれが変わらないこと。

        `write` / `cleanup` / `wants_opus` はライブラリが呼ぶ側の約束で、
        残りは録音側から呼ぶ。移し替えのときに1つ落としても、呼ばれるまで
        分からない（`cleanup` は停止時にしか呼ばれない）。
        """
        surface = sorted(name for name in dir(self.cls) if not name.startswith("__") and name != "_abc_impl")
        for expected in ("write", "cleanup", "wants_opus", "flush_pending", "log_summary", "_emit", "_stream_for"):
            self.assertIn(expected, surface)

    def test_the_summary_reports_every_counter_for_each_stream(self):
        """停止時の要約に、ストリームごとの内訳が全部出ること。

        数だけ見ても何が起きたか分からないので内訳を並べている。項目が1つ
        減っても録音は動くため、**ログを読む段になって初めて足りないと気づく**。
        """
        self.sink.write(self.user, self._packet())
        self.sink.write(self.user, self._packet())
        with self.assertLogs(self.rec.logger, level="INFO") as captured:
            self.sink.flush_pending()

        summary = [line for line in captured.output if "ssrc=" in line]
        self.assertEqual(len(summary), 1, captured.output)
        self.assertIn(
            "ssrc=18295 (すずき) 受信=2 成功=2 失敗=0 E2EE復号=0 E2EE不可=0 "
            "詰め物=0 欠落=0 手遅れ=0 無音=0 RTP種別={120: 2}",
            summary[0],
        )

    def test_cleanup_releases_the_streams_and_the_users(self):
        """cleanup() が抱えていた参照を手放すこと。

        手放さないと、録音セッションのたびに SSRC ごとの状態とユーザー
        オブジェクトが積み上がる。動きはするので、長く動かして初めて効く。
        """
        self.sink.write(self.user, self._packet())
        self.assertTrue(self.sink._streams)
        self.assertTrue(self.sink._users)

        self.sink.cleanup()
        self.assertFalse(self.sink._streams)
        self.assertFalse(self.sink._users)


class ReceiverHealthTests(unittest.TestCase):
    """受信が止まったことに気づけること。

    voice_recv は内部エラーで stop_listening() を呼ぶが、こちらのセッションは
    「録音中」のまま残る。放っておくと、途中で切れた録音が最後まで録れたように
    見えてしまう。
    """

    def setUp(self):
        import services.recording_service as recording
        from services import voice_session

        self.rec = recording
        self.vs = voice_session
        self.vs._clients.clear()

    def tearDown(self):
        self.vs._clients.clear()

    def test_listening_client_is_healthy(self):
        client = Mock()
        client.is_listening = Mock(return_value=True)
        self.vs._clients[1] = client
        self.assertTrue(self.rec._is_receiving(1))

    def test_stopped_listening_is_detected(self):
        client = Mock()
        client.is_listening = Mock(return_value=False)
        self.vs._clients[1] = client
        self.assertFalse(self.rec._is_receiving(1))

    def test_missing_connection_is_not_receiving(self):
        self.assertFalse(self.rec._is_receiving(1))

    def test_client_without_the_method_is_left_alone(self):
        """判断できないものを「止まっている」と決めつけて録音を切らないこと。"""
        client = Mock(spec=discord.VoiceClient)  # is_listening を持たない
        self.vs._clients[1] = client
        self.assertTrue(self.rec._is_receiving(1))

    def test_is_listening_raising_is_logged_but_still_treated_as_healthy(self):
        """is_listening() 自体が例外を投げるのは想定外。方針（判断できないなら
        止めない）は変えないが、黙って握りつぶさず理由を残すこと。"""
        client = Mock()
        client.is_listening = Mock(side_effect=RuntimeError("boom"))
        self.vs._clients[1] = client
        with self.assertLogs(self.rec.logger, level="DEBUG") as captured:
            self.assertTrue(self.rec._is_receiving(1))
        self.assertTrue(any("is_listening" in m for m in captured.output))


class AutoRecordingTests(unittest.TestCase):
    """録音と読み上げを独立したスイッチとして扱えること。

    両方オンなら同じ音声接続で両方動く。片方オフならその機能だけ止まる。
    """

    GUILD = 4400
    TTS_VC = 700
    REC_VC = 800

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        store.set_recording_settings(
            self.GUILD,
            {
                "enabled": True,
                "auto_start": False,
                "vc_channel_id": None,
            },
        )

    def _target(self, tts_vc=TTS_VC):
        with (
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (tts_vc, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            return self.rec.auto_start_channel_id(self.GUILD)

    def test_off_by_default(self):
        """勝手に録られていた、という状態を既定にしない。"""
        self.assertFalse(store.get_recording_settings(self.GUILD)["auto_start"])
        self.assertIsNone(self._target())

    def test_follows_the_tts_channel_when_unset(self):
        """両方オンにするのに、VC を2箇所書かせない。"""
        store.set_recording_settings(self.GUILD, {"auto_start": True})
        self.assertEqual(self._target(), self.TTS_VC)

    def test_explicit_channel_wins(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._target(), self.REC_VC)

    def test_disabled_switch_overrides_auto(self):
        """録音そのものを切ったら、自動録音も走らない。"""
        store.set_recording_settings(
            self.GUILD,
            {
                "enabled": False,
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertIsNone(self._target())

    def test_no_target_when_neither_is_configured(self):
        store.set_recording_settings(self.GUILD, {"auto_start": True})
        self.assertIsNone(self._target(tts_vc=None))

    def test_preferred_vc_ignores_the_auto_switch(self):
        """手動で始めるときの初期値。自動録音のオン/オフとは無関係に返す。

        以前は「録音するVC」の欄が常に空で、毎回選び直す必要があった。
        """
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": False,
                "vc_channel_id": self.REC_VC,
            },
        )
        with (
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (self.TTS_VC, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            self.assertEqual(self.rec.preferred_vc_channel_id(self.GUILD), self.REC_VC)
            self.assertIsNone(self.rec.auto_start_channel_id(self.GUILD))

    def test_preferred_vc_falls_back_to_the_tts_channel(self):
        store.set_recording_settings(self.GUILD, {"vc_channel_id": None})
        with (
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (self.TTS_VC, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            self.assertEqual(self.rec.preferred_vc_channel_id(self.GUILD), self.TTS_VC)

    def test_preferred_vc_is_none_when_nothing_is_configured(self):
        store.set_recording_settings(self.GUILD, {"vc_channel_id": None})
        with (
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (None, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            self.assertIsNone(self.rec.preferred_vc_channel_id(self.GUILD))

    # ── 入室したときの挙動 ──────────────────────────────────

    def _member(self, *, is_bot=False):
        guild = Mock()
        guild.id = self.GUILD
        guild.me = Mock()
        member = Mock()
        member.bot = is_bot
        member.guild = guild
        return member

    def _channel(self, channel_id):
        return self._voice_channel(channel_id)

    def _run_join(self, member, channel, *, receive=True, start=None):
        from services import voice_session

        started = []

        async def fake_start(bot, guild, ch, *, started_by, announce_to=None):
            started.append((guild.id, ch.id))
            return Mock()

        with (
            patch.object(self.rec, "start_recording", start or fake_start),
            patch.object(voice_session, "RECEIVE_AVAILABLE", receive),
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (self.TTS_VC, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            asyncio.run(self.rec.maybe_auto_start(Mock(), member, channel))
        return started

    def _voice_channel(self, channel_id, members=None):
        channel = Mock(spec=discord.VoiceChannel)
        channel.id = channel_id
        channel.name = "雑談VC"
        if members is None:
            human = Mock()
            human.bot = False
            members = [human]
        channel.members = members
        return channel

    def _run_for_channel(self, channel, *, receive=True):
        from services import voice_session

        started = []

        async def fake_start(bot, guild, ch, *, started_by, announce_to=None):
            started.append(ch.id)
            return Mock()

        guild = Mock()
        guild.id = self.GUILD
        guild.me = Mock()

        with (
            patch.object(self.rec, "start_recording", fake_start),
            patch.object(voice_session, "RECEIVE_AVAILABLE", receive),
            patch("services.tts_service.get_effective_vc_watch", lambda gid, settings: (self.TTS_VC, [])),
            patch("services.tts_store.get_tts_settings", lambda g: {}),
        ):
            asyncio.run(self.rec.maybe_start_for_channel(Mock(), guild, channel))
        return started

    def test_a_tts_join_also_starts_recording(self):
        """/tts join のように、人の入室以外の入口からでも始まること。

        入室イベントだけを入口にしていると、既に人がいる VC へ手動で
        参加させたときに録音が始まらない。
        """
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._run_for_channel(self._voice_channel(self.REC_VC)), [self.REC_VC])

    def test_an_empty_channel_is_not_recorded(self):
        """bot だけが入っている VC を録りに行かない。"""
        robot = Mock()
        robot.bot = True
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._run_for_channel(self._voice_channel(self.REC_VC, members=[robot])), [])
        self.assertEqual(self._run_for_channel(self._voice_channel(self.REC_VC, members=[])), [])

    def test_join_to_the_target_starts_recording(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(
            self._run_join(self._member(), self._channel(self.REC_VC)),
            [(self.GUILD, self.REC_VC)],
        )

    def test_other_channels_are_ignored(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._run_join(self._member(), self._channel(999)), [])

    def test_bots_do_not_trigger_recording(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._run_join(self._member(is_bot=True), self._channel(self.REC_VC)), [])

    def test_does_not_start_twice(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.rec._sessions[self.GUILD] = Mock()
        try:
            started = self._run_join(self._member(), self._channel(self.REC_VC))
        finally:
            self.rec._sessions.pop(self.GUILD, None)
        self.assertEqual(started, [])

    def test_nothing_happens_without_the_receive_extension(self):
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )
        self.assertEqual(self._run_join(self._member(), self._channel(self.REC_VC), receive=False), [])

    def test_a_failed_start_does_not_escape(self):
        """自動で走る経路なので、失敗しても入室処理を巻き込まない。"""
        store.set_recording_settings(
            self.GUILD,
            {
                "auto_start": True,
                "vc_channel_id": self.REC_VC,
            },
        )

        async def boom(*args, **kwargs):
            raise self.rec.RecordingError("テスト用の失敗")

        with self.assertLogs(self.rec.logger, level="WARNING"):
            started = self._run_join(self._member(), self._channel(self.REC_VC), start=boom)
        self.assertEqual(started, [])


class ReleaseAfterRecordingTests(unittest.TestCase):
    """録音が終わったあと、VC に残るか出るか。

    録音だけのために入った接続を掴んだままにすると bot が VC に居座る。
    逆に読み上げが使っている最中に切ると、そちらを巻き添えにする。
    """

    GUILD = 6600
    VC = 950

    def setUp(self):
        import services.recording_service as recording
        from services import voice_session

        self.rec = recording
        self.vs = voice_session
        self.vs._clients.clear()
        self.vs._holds.clear()
        self.vs._locks.clear()

    def tearDown(self):
        self.vs._clients.clear()
        self.vs._holds.clear()

    def _connect(self, holds=()):
        disconnected = []

        async def disconnect(force=False):
            disconnected.append(True)

        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=self.VC)
        client.disconnect = disconnect
        self.vs._clients[self.GUILD] = client
        for holder in holds:
            self.vs.hold(self.GUILD, holder)
        return disconnected

    def _release(self, *, tts_enabled, tts_vc, holds=()):
        disconnected = self._connect(holds)
        with (
            patch("services.tts_store.get_tts_settings", lambda g: {"enabled": tts_enabled, "vc_channel_id": tts_vc}),
            patch("services.tts_service.get_effective_vc_watch", lambda g, s: (tts_vc, [])),
        ):
            asyncio.run(self.rec._release_if_unused(self.GUILD))
        return bool(disconnected)

    def test_stays_while_tts_uses_the_same_channel(self):
        self.assertFalse(self._release(tts_enabled=True, tts_vc=self.VC))

    def test_leaves_when_tts_is_disabled(self):
        self.assertTrue(self._release(tts_enabled=False, tts_vc=self.VC))

    def test_leaves_when_tts_watches_another_channel(self):
        self.assertTrue(self._release(tts_enabled=True, tts_vc=777))

    def test_leaves_when_tts_has_no_channel(self):
        self.assertTrue(self._release(tts_enabled=True, tts_vc=None))

    def test_stays_while_something_else_holds_the_connection(self):
        self.assertFalse(self._release(tts_enabled=False, tts_vc=self.VC, holds=("something",)))


class RecordingLimitConstantsTests(unittest.TestCase):
    """設定の許容範囲が、管理画面とスラッシュコマンドで食い違わないこと。

    片方だけ古いと、入れられた値が黙って弾かれたり丸められたりする
    （キャッシュ保持時間で実際に起きた種類の不具合）。
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording

    def test_api_uses_the_shared_constants(self):
        import inspect
        import webapp_admin.api.recording as api

        source = inspect.getsource(api)
        self.assertIn("MAX_MINUTES_LIMIT", source)
        self.assertIn("RETENTION_DAYS_MAX", source)

    def test_commands_use_the_shared_constants(self):
        source = _record_command_source()
        self.assertIn("MAX_MINUTES_LIMIT", source)
        self.assertIn("RETENTION_DAYS_MAX", source)

    def test_unlimited_is_inside_the_accepted_range(self):
        self.assertEqual(self.rec.UNLIMITED, 0)
        self.assertGreater(self.rec.MAX_MINUTES_LIMIT, 0)
        self.assertLessEqual(self.rec.RETENTION_DAYS_MIN, self.rec.RETENTION_DAYS_MAX)

    def test_defaults_sit_inside_the_limits(self):
        defaults = store.get_recording_settings(9910)
        self.assertLessEqual(defaults["max_minutes"], self.rec.MAX_MINUTES_LIMIT)
        self.assertGreaterEqual(defaults["retention_days"], self.rec.RETENTION_DAYS_MIN)
        self.assertLessEqual(defaults["retention_days"], self.rec.RETENTION_DAYS_MAX)


class PublicDocumentTests(unittest.TestCase):
    """録音は個人情報を扱うので、公開ページの記載を消さないよう固定する。"""

    def _read(self, name):
        root = Path(__file__).resolve().parent.parent
        return (root / "webapp_admin" / "templates" / name).read_text(encoding="utf-8")

    def test_privacy_states_the_government_only_limitation(self):
        text = self._read("privacy.html")
        self.assertIn("政府機関への提供が必要な場合を除き", text)
        self.assertIn("個人情報保護法", text)

    def test_privacy_explains_notice_and_opt_out(self):
        text = self._read("privacy.html")
        self.assertIn("/record exclude", text)
        self.assertIn("無効にすることはできません", text)

    def test_privacy_states_the_recording_retention(self):
        text = self._read("privacy.html")
        self.assertIn("既定7日、最長30日", text)

    def test_terms_put_lawful_use_on_the_operator(self):
        text = self._read("terms.html")
        self.assertIn("適用される法令に則って", text)
        self.assertIn("個人情報保護法", text)


class AnnounceChannelTests(unittest.TestCase):
    """通知チャンネルの設定が実際に効くこと。

    以前は保存も表示もされていたのに、通知を送る側が一度も読んでいなかった
    （設定しても何も起きない、書くだけの設定になっていた）。
    """

    GUILD = 7700
    NOTICE = 700

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.sent = []
        store.set_recording_settings(self.GUILD, {"announce_channel_id": None})

    def _messageable(self, channel_id, label):
        channel = Mock(spec=discord.TextChannel)
        channel.id = channel_id
        channel.name = label

        async def send(**kwargs):
            self.sent.append(label)
            return Mock()

        channel.send = send
        return channel

    def _guild(self, *, notice_exists=True):
        notice = self._messageable(self.NOTICE, "通知ch")
        guild = Mock()
        guild.id = self.GUILD
        guild.get_channel = lambda i: notice if (notice_exists and int(i) == self.NOTICE) else None
        return guild

    def _voice(self, guild):
        voice = Mock(spec=discord.VoiceChannel)
        voice.id = 800
        voice.name = "雑談VC"
        voice.guild = guild

        async def send(**kwargs):
            self.sent.append("VCチャット")
            return Mock()

        voice.send = send
        return voice

    def _session(self):
        return self.rec.RecordingSession(
            guild_id=self.GUILD,
            channel_id=800,
            channel_name="雑談VC",
            started_by_id=1,
            started_by_name="すずき",
            started_at=0.0,
            max_seconds=0,
            retention_days=7,
        )

    def _announce(self, *, configured, announce_to, notice_exists=True):
        store.set_recording_settings(self.GUILD, {"announce_channel_id": configured})
        guild = self._guild(notice_exists=notice_exists)
        asyncio.run(self.rec._announce_start(self._voice(guild), self._session(), announce_to))
        return self.sent

    def test_configured_channel_wins(self):
        command_channel = self._messageable(900, "コマンド実行ch")
        self.assertEqual(self._announce(configured=self.NOTICE, announce_to=command_channel), ["通知ch"])

    def test_falls_back_to_the_command_channel(self):
        command_channel = self._messageable(900, "コマンド実行ch")
        self.assertEqual(self._announce(configured=None, announce_to=command_channel), ["コマンド実行ch"])

    def test_falls_back_to_the_voice_chat(self):
        self.assertEqual(self._announce(configured=None, announce_to=None), ["VCチャット"])

    def test_a_missing_configured_channel_does_not_swallow_the_notice(self):
        """設定先が消えていても、黙って告知しないのは避ける。"""
        command_channel = self._messageable(900, "コマンド実行ch")
        with self.assertLogs(self.rec.logger, level="WARNING"):
            sent = self._announce(configured=999, announce_to=command_channel, notice_exists=False)
        self.assertEqual(sent, ["コマンド実行ch"])

    def test_resolver_returns_the_fallback_without_a_setting(self):
        fallback = self._messageable(123, "代替")
        self.assertIs(self.rec.resolve_announce_channel(self._guild(), fallback=fallback), fallback)

    def test_resolver_handles_a_missing_guild(self):
        self.assertIsNone(self.rec.resolve_announce_channel(None))


class RecordingPrivilegeTests(unittest.TestCase):
    """録音の開始・停止が管理者に限られていること。

    /tts join・/tts leave は誰でも打てるコマンド。そこから録音を動かせると、
    /record start・/record stop の管理者限定を迂回できてしまう。
    """

    def _interaction(self, *, admin, in_guild=True):
        interaction = Mock()
        interaction.guild = Mock() if in_guild else None
        permissions = Mock()
        permissions.administrator = admin
        interaction.user = Mock()
        interaction.user.guild_permissions = permissions
        return interaction

    def test_is_admin_distinguishes_the_two(self):
        from commands.guards import is_admin

        self.assertTrue(is_admin(self._interaction(admin=True)))
        self.assertFalse(is_admin(self._interaction(admin=False)))

    def test_is_admin_is_false_outside_a_guild(self):
        from commands.guards import is_admin

        self.assertFalse(is_admin(self._interaction(admin=True, in_guild=False)))

    def test_is_admin_is_false_when_permissions_are_unavailable(self):
        from commands.guards import is_admin

        interaction = Mock()
        interaction.guild = Mock()
        interaction.user = Mock(spec=[])  # guild_permissions を持たない
        self.assertFalse(is_admin(interaction))

    def test_tts_join_gates_the_recording_side_effect(self):
        """一般利用者の /tts join で録音が始まらないこと。"""
        import inspect
        import commands.tts_commands as cmds

        source = inspect.getsource(cmds.tts_join.callback)
        self.assertIn("is_admin(interaction)", source)
        # 録音開始がガードの内側にあること
        guard_at = source.index("is_admin(interaction)")
        start_at = source.index("maybe_start_for_channel")
        self.assertLess(guard_at, start_at)

    def test_tts_leave_gates_stopping_the_recording(self):
        import inspect
        import commands.tts_commands as cmds

        source = inspect.getsource(cmds.tts_leave.callback)
        self.assertIn("is_admin(interaction)", source)
        guard_at = source.index("is_admin(interaction)")
        stop_at = source.index("stop_recording")
        self.assertLess(guard_at, stop_at)

    def test_record_commands_require_admin(self):
        """/record の管理系サブコマンドが素通りしないこと。"""
        source = _record_command_source()
        for name in ("record_start", "record_stop", "record_auto", "record_config"):
            with self.subTest(command=name):
                body = source[source.index(f"async def {name}(") :]
                body = body[: body.index("@group.command") if "@group.command" in body else len(body)]
                self.assertIn("_ensure_admin(interaction)", body)


class TTLCacheTests(unittest.TestCase):
    """期限つきキャッシュ。放置しても膨らまないこと。

    読み出し時に期限を見るだけで追い出しをしないキャッシュが各所にあり、鍵の空間が
    広いもの（地震のイベント単位・記事単位・利用者単位）は動かし続けるほど増えていた。
    """

    def setUp(self):
        from services.ttl_cache import TTLCache

        self.TTLCache = TTLCache

    def test_entries_expire_on_read(self):
        cache = self.TTLCache(ttl=0.05, max_entries=10)
        cache.set("a", 1)
        self.assertEqual(cache.get("a"), 1)
        time.sleep(0.08)
        self.assertIsNone(cache.get("a"))
        self.assertEqual(len(cache), 0)

    def test_count_stays_under_the_limit(self):
        cache = self.TTLCache(ttl=60, max_entries=3)
        for i in range(50):
            cache.set(i, i)
        self.assertEqual(len(cache), 3)

    def test_recently_used_entries_survive(self):
        cache = self.TTLCache(ttl=60, max_entries=3)
        for i in range(3):
            cache.set(i, i)
        cache.get(0)  # 0 を使う
        cache.set(99, 99)  # あふれさせる
        self.assertIsNotNone(cache.get(0))
        self.assertIsNone(cache.get(1))  # 一番使われていないものが落ちる

    def test_pop_and_clear(self):
        cache = self.TTLCache(ttl=60, max_entries=10)
        cache.set("a", 1)
        self.assertEqual(cache.pop("a"), 1)
        self.assertIsNone(cache.pop("a"))
        cache.set("b", 2)
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            self.TTLCache(ttl=0, max_entries=10)
        with self.assertRaises(ValueError):
            self.TTLCache(ttl=60, max_entries=0)

    def test_leaky_caches_were_converted(self):
        """鍵の空間が広いキャッシュが上限つきになっていること。"""
        import services.djaudio_service as djaudio
        import services.earthquake_service as earthquake
        import services.news_service as news
        import services.virustotal_service as virustotal
        import webapp_admin.auth as auth

        for owner, name in (
            (earthquake, "_jma_detail_url_cache"),
            (news, "_summary_cache"),
            (djaudio, "_user_cooldown"),
            (auth, "_user_info_cache"),
            (virustotal, "_vt_cache"),
        ):
            with self.subTest(cache=name):
                cache = getattr(owner, name)
                self.assertIsInstance(cache, self.TTLCache)
                self.assertGreater(cache.max_entries, 0)


class TtsLatencyLoggingTests(unittest.TestCase):
    """読み上げにかかった時間が、あとから読める形で残ること。

    「TTS が遅い」という報告に対して、**手元には測った値が1つも無かった**。
    合成が遅いのか、キューで待っているのか、VC 接続が遅いのかを区別できない
    と、直す場所を当てずっぽうで選ぶことになる。

    測るのは2つ。

      合成 … TTS サーバへ投げて音声URLが返るまで
      待ち … 合成が終わってから実際に音が出るまで（キュー・VC接続・ffmpeg）

    失敗したときも測る。**いちばん知りたいのは、失敗するまでに何秒待たされた
    か**（30秒の制限まで粘ったのか、すぐ断られたのか）である。
    """

    def setUp(self):
        import services.tts_service as tts

        self.tts = tts

    def _fake_session(self, *, status=200, payload=None, elapsed=1.5):
        """POST を1回だけ受ける aiohttp セッションの代わり。

        time.monotonic を進めることで、経過時間の計測そのものを確かめる
        （固定値を返しているだけなら、この差分は出ない）。
        """
        clock = {"now": 100.0}

        class FakeResponse:
            def __init__(self):
                self.status = status

            async def __aenter__(self):
                clock["now"] += elapsed
                return self

            async def __aexit__(self, *exc):
                return False

            async def json(self):
                return payload or {"url": "/audio/x.wav"}

            async def text(self):
                return "エラー本文"

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            def post(self, *a, **k):
                return FakeResponse()

        return FakeSession, lambda: clock["now"]

    def test_a_successful_synthesis_reports_how_long_it_took(self):
        """合成が成功したら、URL と所要ミリ秒を返してログにも出すこと。"""
        FakeSession, clock = self._fake_session(elapsed=1.5)
        with (
            patch.object(self.tts.aiohttp, "ClientSession", FakeSession),
            patch.object(self.tts.time, "monotonic", clock),
            self.assertLogs(self.tts.logger, level="INFO") as captured,
        ):
            url, ms = asyncio.run(self.tts._synthesize("こんにちは", "ja-JP-NanamiNeural", 0))

        self.assertTrue(url.endswith("/audio/x.wav"))
        self.assertEqual(ms, 1500)
        self.assertTrue(any("合成 1500ms" in line for line in captured.output), captured.output)

    def test_a_failed_synthesis_still_reports_how_long_it_waited(self):
        """失敗しても所要時間を返すこと。

        30秒の制限まで粘って落ちたのか、すぐ断られたのかで、疑う場所が
        変わる。None だけ返すと、その区別が消える。
        """
        FakeSession, clock = self._fake_session(status=503, elapsed=4.0)
        with (
            patch.object(self.tts.aiohttp, "ClientSession", FakeSession),
            patch.object(self.tts.time, "monotonic", clock),
            self.assertLogs(self.tts.logger, level="ERROR") as captured,
        ):
            url, ms = asyncio.run(self.tts._synthesize("こんにちは", "ja-JP-NanamiNeural", 0))

        self.assertIsNone(url)
        self.assertEqual(ms, 4000)
        self.assertTrue(any("4000ms" in line for line in captured.output), captured.output)

    def test_the_playback_start_reports_the_wait(self):
        """実際に音が出た時点で、合成と待ちの両方をログへ出すこと。

        合成の時間だけ見ても「投稿から喋り出すまで」は分からない。キューの
        待ち・VC接続・ffmpeg の起動がここに乗る。**INFO で出すこと**まで
        見ているのは、DEBUG へ落とすと本番のログから消えるため（本番は
        INFO で回している）。
        """
        guild_id = 8
        queue = asyncio.Queue()
        self.tts._queues[guild_id] = queue
        self.addCleanup(self.tts._queues.pop, guild_id, None)

        voice_client = Mock()
        voice_client.is_playing.return_value = False
        voice_client.play.side_effect = lambda source, after: after(None)

        async def one_round():
            """1件だけ流して、ループが待ちに入ったところで打ち切る。"""
            await queue.put(self.tts._Utterance("http://x/a.wav", 99, 1234, time.monotonic() - 0.5))
            task = asyncio.get_running_loop().create_task(self.tts._player_loop(Mock(), guild_id))
            await queue.join()
            task.cancel()

        with (
            patch.object(self.tts, "_connect_or_move", AsyncMock(return_value=voice_client)),
            patch.object(self.tts.discord, "FFmpegPCMAudio", Mock()),
            self.assertLogs(self.tts.logger, level="INFO") as captured,
        ):
            asyncio.run(one_round())

        started = [line for line in captured.output if "再生開始" in line]
        self.assertEqual(len(started), 1, captured.output)
        self.assertIn("合成=1234ms", started[0])
        # 0.5秒前にキューへ入れた1件なので、待ちは500ms前後になるはず。
        # 「待ち=」の有無だけ見ていると、0 を書くだけの変異で素通りする。
        import re

        waited = int(re.search(r"待ち=(\d+)ms", started[0]).group(1))
        self.assertGreaterEqual(waited, 400, started[0])

    def test_the_queued_item_carries_the_synthesis_time(self):
        """キューへ流す1件が、合成にかかった時間を持って行くこと。

        合成の時間は合成した側にしか、待ち時間は再生する側にしか分からない。
        一緒に運ばないと「喋り出すまで何ミリ秒か」が言えない。
        """
        guild = SimpleNamespace(id=7)
        member = SimpleNamespace(id=1, display_name="すずき")
        self.tts._queues.pop(7, None)
        self.addCleanup(self.tts._queues.pop, 7, None)
        # 設定の取得は関数の中で import している（循環を避けるため）ので、
        # モジュール属性ではなく tts_store 側を差し替える。
        with (
            patch.object(self.tts, "_synthesize", AsyncMock(return_value=("http://x/a.wav", 1234))),
            patch("services.tts_store.get_tts_settings", lambda gid: {"enabled": True, "vc_channel_id": 99}),
            patch("services.tts_store.get_tts_dictionary", lambda gid: {}),
            patch("services.tts_store.get_user_tts_settings", lambda gid, uid: {}),
            patch.object(self.tts, "get_effective_vc_watch", lambda gid, settings: (99, [])),
            patch.object(self.tts.asyncio, "create_task", lambda coro: coro.close()),
        ):
            asyncio.run(self.tts.enqueue_message(Mock(), guild, member, "やあ"))

        queue = self.tts._queues[7]
        item = queue.get_nowait()
        self.assertIsInstance(item, self.tts._Utterance)
        self.assertEqual(item.synth_ms, 1234)
        self.assertEqual(item.vc_channel_id, 99)


class VirusTotalTimeoutAndFailureCacheTests(unittest.TestCase):
    """VirusTotal へ到達できないとき、待ち続けず・叩き直さないこと。

    本番のログにこれが出ていた。

        10:26:59 [VT] Content-Type https://.../h1565493.html ->
        10:27:30 [VT] URL scan exception: Cannot connect to host www.virustotal.com:443

    **31秒の空白。** そのあいだスキャンは `asyncio.to_thread` の中で待って
    いて、既定のスレッドプール（16本）を1本占める。詰まると `awrite`
    （設定の書き込み）など他の to_thread も後ろに並ぶ。

    さらに `on_message` は5つのハンドラを待ってから
    `bot.process_commands()` を呼ぶので、プレフィックスコマンドの応答も
    そのぶん遅れる。

    2つの欠陥がある。

      1. `vt.Client` に timeout を渡していない → **vt-py の既定は300秒**
      2. 失敗した結果をキャッシュしない → 同じ死んだURLを毎回叩き直す

    どちらも「危険と判定するか」には影響しない（失敗は元から
    malicious=0 として扱われる）。**遅いだけ**なので、動いている限り
    気づけない類の欠陥である。
    """

    def setUp(self):
        import services.virustotal_service as virustotal

        self.vt_service = virustotal
        # キーが無いと実際に叩く前に skip で戻るため、テストの間だけ差し替える。
        key_patch = patch.object(virustotal, "VIRUSTOTAL_API_KEY", "dummy-key")
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.vt_service._vt_cache.clear()
        self.vt_service._vt_failure_cache.clear()
        self.addCleanup(self.vt_service._vt_cache.clear)
        self.addCleanup(self.vt_service._vt_failure_cache.clear)

    def _client_factory(self, *, side_effect):
        """vt.Client の代わり。渡された引数を控え、scan_url で side_effect を起こす。"""
        seen: list[dict] = []

        class FakeClient:
            def __init__(self, apikey, **kwargs):
                seen.append(kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def scan_url(self, url, wait_for_completion=False):
                raise side_effect

        return FakeClient, seen

    def test_the_client_is_given_a_timeout(self):
        """vt.Client に timeout を渡すこと。

        渡さないと vt-py の既定 300秒 が効く。到達できない相手を5分待つ
        あいだ、スレッドプールの1本が塞がる。
        """
        FakeClient, seen = self._client_factory(side_effect=OSError("Cannot connect"))
        with patch.object(self.vt_service.vt, "Client", FakeClient):
            asyncio.run(self.vt_service.vt_check_url("https://example.com/a"))

        self.assertTrue(seen, "vt.Client が作られていない")
        self.assertIn("timeout", seen[0], "timeout を渡していない（既定の300秒が効く）")
        self.assertLessEqual(seen[0]["timeout"], 60, "300秒の既定と大差ない値になっている")

    def test_a_failed_scan_is_not_retried_for_every_message(self):
        """失敗したURLを、次のメッセージでまた叩きに行かないこと。

        到達できない相手なら、次も到達できない。毎回30秒待つと、リンクを
        含むメッセージが流れるだけでスレッドプールが埋まる。
        """
        FakeClient, seen = self._client_factory(side_effect=OSError("Cannot connect"))
        with patch.object(self.vt_service.vt, "Client", FakeClient):
            first = asyncio.run(self.vt_service.vt_check_url("https://example.com/b"))
            second = asyncio.run(self.vt_service.vt_check_url("https://example.com/b"))

        self.assertEqual(len(seen), 1, f"2回叩いている（{len(seen)}回）")
        self.assertEqual(first["status"], "error")
        self.assertEqual(second["status"], "error")

    def test_a_cached_failure_still_reports_nothing_malicious(self):
        """失敗をキャッシュしても、判定が甘くならないこと。

        失敗は**元から** malicious=0 / suspicious=0 として扱われている
        （_run_vt_scans は数だけを見る）。キャッシュしても同じものを返す
        だけで、危険を見逃す方向へは動かない。
        """
        FakeClient, _ = self._client_factory(side_effect=OSError("Cannot connect"))
        with patch.object(self.vt_service.vt, "Client", FakeClient):
            asyncio.run(self.vt_service.vt_check_url("https://example.com/c"))
            cached = asyncio.run(self.vt_service.vt_check_url("https://example.com/c"))

        self.assertEqual(cached["malicious"], 0)
        self.assertEqual(cached["suspicious"], 0)

    def test_the_failure_cache_expires_much_sooner_than_the_success_cache(self):
        """失敗の保持は短くすること。

        成功は6時間持つが、失敗を同じだけ持つと、復旧しても6時間スキャン
        しない状態が続く。一時的な不通と恒久的な不通を区別できない以上、
        短く持って様子を見るほうへ倒す。
        """
        self.assertLess(self.vt_service._vt_failure_cache.ttl, self.vt_service._vt_cache.ttl)
        self.assertLessEqual(self.vt_service._vt_failure_cache.ttl, 60 * 30)

    def test_a_success_after_the_failure_window_replaces_the_cached_error(self):
        """復旧したら、成功の結果で上書きされること。"""
        FakeClient, _ = self._client_factory(side_effect=OSError("Cannot connect"))
        with patch.object(self.vt_service.vt, "Client", FakeClient):
            asyncio.run(self.vt_service.vt_check_url("https://example.com/d"))

        self.vt_service._vt_failure_cache.clear()  # 期限切れの代わり

        class OkClient:
            def __init__(self, apikey, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def scan_url(self, url, wait_for_completion=False):
                return SimpleNamespace(stats={"malicious": 0, "suspicious": 0})

        with patch.object(self.vt_service.vt, "Client", OkClient):
            result = asyncio.run(self.vt_service.vt_check_url("https://example.com/d"))
        self.assertEqual(result["status"], "ok")


class SecurityFailSafeTests(unittest.TestCase):
    """バイパス判定に失敗したときに破壊的操作へ進まないこと。

    全ロール剥奪は元に戻せない。信頼済みかどうかが分からないまま実行すると、
    設定を読めなかっただけで管理者のロールが消える。見逃すより、取り返しが
    つかないほうを避ける。
    """

    def setUp(self):
        import services.security_service as security

        self.sec = security

    def _member(self):
        member = Mock()
        member.id = 5
        member.bot = False
        member.guild = Mock()
        member.guild.id = 1
        member.roles = []
        member.mention = "@user"
        return member

    @staticmethod
    def _boom(_):
        raise RuntimeError("設定が読めない")

    def _voice_channel(self):
        channel = Mock(spec=discord.VoiceChannel)
        channel.id = 10
        channel.name = "雑談VC"
        channel.mention = "<#10>"
        return channel

    # ── 判定の3状態 ──────────────────────────────────────────

    def test_trusted_user_is_bypassed(self):
        with (
            patch.object(self.sec, "get_trusted_user_ids", lambda g: [5]),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
        ):
            result = self.sec.is_security_bypassed(self._member())
        self.assertTrue(result.bypassed)
        self.assertEqual(result.reason, "trusted_user")
        self.assertFalse(result.check_failed)

    def test_ordinary_user_is_not_bypassed(self):
        with (
            patch.object(self.sec, "get_trusted_user_ids", lambda g: []),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
        ):
            result = self.sec.is_security_bypassed(self._member())
        self.assertFalse(result.bypassed)
        self.assertFalse(result.check_failed)

    def test_a_failed_check_is_distinguishable(self):
        """「判定できなかった」を「バイパスなし」と同じ扱いにしない。"""
        with (
            patch.object(self.sec, "get_trusted_user_ids", self._boom),
            self.assertLogs(self.sec.logger, level="ERROR"),
        ):
            result = self.sec.is_security_bypassed(self._member())
        self.assertFalse(result.bypassed)  # 検査自体は続ける
        self.assertTrue(result.check_failed)  # ただし強制措置には進ませない

    # ── VC レイド時の措置 ────────────────────────────────────

    def _run_voice_join(self, *, trusted, raid):
        stripped = []
        logged = []

        async def fake_strip(member):
            stripped.append(member.id)
            return True, "removed"

        async def fake_log(bot, guild_id, level, message, **kwargs):
            logged.append(message)

        before = Mock()
        before.channel = None
        after = Mock()
        after.channel = self._voice_channel()

        with (
            patch.object(self.sec, "get_trusted_user_ids", trusted),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
            patch.object(self.sec, "check_vc_raid", lambda m, c: raid),
            patch.object(self.sec, "strip_roles", fake_strip),
            patch.object(self.sec, "log_action", fake_log),
            patch.object(self.sec.logger, "error"),
        ):
            asyncio.run(self.sec.handle_security_for_voice_join(Mock(), self._member(), before, after))
        return stripped, logged

    def test_raid_strips_roles_when_the_check_worked(self):
        stripped, _ = self._run_voice_join(trusted=lambda g: [], raid=True)
        self.assertEqual(stripped, [5])

    def test_raid_does_not_strip_when_the_check_failed(self):
        stripped, logged = self._run_voice_join(trusted=self._boom, raid=True)
        self.assertEqual(stripped, [])
        self.assertTrue(any("要確認" in m for m in logged), logged)

    def test_no_raid_means_no_action_either_way(self):
        stripped, logged = self._run_voice_join(trusted=self._boom, raid=False)
        self.assertEqual(stripped, [])
        self.assertEqual(logged, [])

    # ── メッセージ側 ─────────────────────────────────────────
    #
    # ここには `inspect.getsource()` でソースの文字列を調べるテストがあった。
    # 「`if danger and bypass.check_failed:` が `await message.delete()` より
    # 前に現れること」を見るもので、**振る舞いは何も見ていなかった。**
    #
    # 実際、変異を当てると次の3つを取り逃がしていた。
    #
    #     危険でもロールを剥がさない          → 落ちない
    #     バイパス適用でも検査を続ける        → 落ちない
    #     GPT の DANGEROUS を拾わない         → 落ちない
    #
    # 逆に、判定を別の関数へ移しただけ（振る舞いは同じ）で落ちる。
    # 実際に走らせて結末を見る MessageSecurityOutcomeTests へ置き換えた。


class MessageSecurityOutcomeTests(unittest.TestCase):
    """handle_security_for_message を実際に通し、結末を固定する。

    167行ある関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

    これまでこの経路を見ていたのは `inspect.getsource()` でソースの文字列を
    調べるテスト1件だけだった。**あれは振る舞いを何も見ていない。** 判定の
    分岐を別の関数へ移すだけで、中身が壊れていても通ってしまうし、逆に
    正しく割っただけでも落ちる。実際に走らせて結末を見る形へ置き換える。

    見るのは4つの結末。

      危険 ＋ バイパス判定に失敗 … **削除も剥奪もしない**。要確認を残す
      危険 ＋ 判定できた         … 削除して剥奪する
      バイパス適用               … 検査そのものをしない（GPT も呼ばない）
      安全                       … 何もしない

    1つ目がこの関数のいちばん大事な性質で、**壊れても例外は出ず、ログも
    出る**（消えるのは「消さなかった」という事実だけ）。
    """

    def setUp(self):
        import services.security_service as security

        self.sec = security
        self.deleted = []
        self.stripped = []
        self.logged = []

    def _message(self, content="ふつうの発言"):
        """author が Member として通る、最小のメッセージ。"""
        member = Mock(spec=discord.Member)
        member.id = 5
        member.bot = False
        member.guild = Mock()
        member.guild.id = 1
        member.roles = []
        member.mention = "@user"
        member.voice = None
        member.joined_at = None

        message = Mock(spec=discord.Message)
        message.author = member
        message.guild = member.guild
        message.channel = Mock()
        message.channel.id = 77
        message.content = content
        message.attachments = []
        message.delete = AsyncMock(side_effect=lambda: self.deleted.append(True))
        return message

    def _run(self, *, trusted, gpt="SAFE", content="ふつうの発言"):
        """本物の handle_security_for_message を、外部呼び出しだけ差し替えて回す。"""

        async def fake_strip(member):
            self.stripped.append(member.id)
            return True, "removed"

        async def fake_log(bot, guild_id, level, message, **kwargs):
            self.logged.append(message)

        message = self._message(content)
        with (
            patch.object(self.sec, "get_trusted_user_ids", trusted),
            patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
            patch.object(self.sec, "get_response_channel_id", lambda g: None),
            patch.object(self.sec, "check_spam", lambda g, u: (False, 0, 0.0)),
            patch.object(self.sec, "gpt_assess", AsyncMock(return_value=gpt)),
            patch.object(self.sec, "check_vc_raid", lambda m, c: False),
            patch.object(self.sec, "strip_roles", fake_strip),
            patch.object(self.sec, "log_action", fake_log),
            patch.object(self.sec, "send_log_embed", AsyncMock()),
            patch.object(self.sec.logger, "error"),
        ):
            asyncio.run(self.sec.handle_security_for_message(Mock(), message))
        return message

    @staticmethod
    def _boom(_):
        raise RuntimeError("設定が読めない")

    def test_a_dangerous_message_is_left_alone_when_the_bypass_check_failed(self):
        """危険と判定しても、バイパス判定に失敗していれば消さない・剥がさない。

        全ロール剥奪は元に戻せない。信頼済みかどうかが分からないまま実行すると、
        設定を読めなかっただけで管理者のロールが消える。**壊れても例外は出ず、
        ログも出る**ので、この検査が無いと気づけない。
        """
        self._run(trusted=self._boom, gpt="DANGEROUS")

        self.assertEqual(self.deleted, [], "バイパス判定に失敗しているのに削除した")
        self.assertEqual(self.stripped, [], "バイパス判定に失敗しているのにロールを剥がした")
        self.assertTrue(any("要確認" in m for m in self.logged), self.logged)

    def test_a_dangerous_message_is_removed_when_the_check_worked(self):
        """判定できたうえで危険なら、削除して剥奪すること。

        上の見送りを「常に見送る」に変えても、片方だけでは気づけない。
        """
        self._run(trusted=lambda g: [], gpt="DANGEROUS")

        self.assertEqual(self.deleted, [True])
        self.assertEqual(self.stripped, [5])
        self.assertFalse(any("要確認" in m for m in self.logged), self.logged)

    def test_a_bypassed_member_is_not_scanned_at_all(self):
        """バイパス対象なら、GPT にも問い合わせずに戻ること。

        バイパスは「信頼しているので見ない」であって「見たうえで許す」では
        ない。外部への問い合わせが走っていたら、そこが崩れている。
        """
        with patch.object(self.sec, "gpt_assess", AsyncMock(return_value="SAFE")) as gpt:
            with (
                patch.object(self.sec, "get_trusted_user_ids", lambda g: [5]),
                patch.object(self.sec, "get_bypass_role_ids", lambda g: []),
                patch.object(self.sec, "get_response_channel_id", lambda g: None),
                patch.object(self.sec, "log_action", AsyncMock(side_effect=self._remember)),
            ):
                asyncio.run(self.sec.handle_security_for_message(Mock(), self._message()))

        gpt.assert_not_awaited()
        self.assertEqual(self.deleted, [])
        self.assertTrue(any("スキップ" in m for m in self.logged), self.logged)

    def test_a_safe_message_is_left_alone(self):
        """安全なら何もしないこと。"""
        self._run(trusted=lambda g: [], gpt="SAFE")

        self.assertEqual(self.deleted, [])
        self.assertEqual(self.stripped, [])
        self.assertFalse(any("要確認" in m for m in self.logged), self.logged)

    async def _remember(self, bot, guild_id, level, message, **kwargs):
        """log_action の代わり。呼ばれた見出しだけ控える。"""
        self.logged.append(message)


class GptUnknownReportingTests(unittest.TestCase):
    """gpt_assess が失敗を意味する "UNKNOWN" を返したとき、埋め込みが
    「問題なし」に化けないこと（判定できなかったことを隠さない）。"""

    def setUp(self):
        import services.security_service as security

        self.sec = security

    def test_gpt_icon_treats_unknown_as_a_warning_not_safe(self):
        self.assertEqual(self.sec.gpt_icon("UNKNOWN"), self.sec.WARN_ICON)

    def test_final_embed_does_not_report_all_clear_when_gpt_is_unknown(self):
        embed = self.sec.build_final_embed([], "UNKNOWN", ["GPT:UNKNOWN"], ["ログ"])
        self.assertNotEqual(embed.color, __import__("discord").Color.green())
        self.assertNotIn("問題なし", embed.title)

    def test_final_embed_still_reports_all_clear_when_gpt_is_safe(self):
        embed = self.sec.build_final_embed([], "SAFE", ["GPT:SAFE"], ["ログ"])
        self.assertEqual(embed.color, __import__("discord").Color.green())


class TrackCloseTests(unittest.TestCase):
    """書き出しの終了処理。本番（Linux）でだけ落ちていた経路。

    close() が stdin を先に閉じてから communicate() を呼んでいたため、POSIX の
    communicate() 内の stdin.flush() が ValueError（flush of closed file）になり、
    録音が保存されず失われていた。Windows の communicate() は閉じ済み stdin を
    許容するので、こちらで動かしても再現しない。
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.work = Path(tempfile.mkdtemp(prefix="closetest-"))

    def _tone(self, seconds=0.2):
        import math
        import struct

        out = bytearray()
        for i in range(int(self.rec.SAMPLE_RATE * seconds)):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / self.rec.SAMPLE_RATE))
            out += struct.pack("<hh", v, v)
        return bytes(out)

    def test_stdin_is_not_closed_before_communicate(self):
        """POSIX ではここが閉じていると communicate() の flush が落ちる。"""
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", time.monotonic())
        track.write(self._tone(), 0.0)

        seen = {}
        original = track._process.communicate

        def spy(*args, **kwargs):
            stdin = track._process.stdin
            seen["ok"] = stdin is None or not stdin.closed
            return original(*args, **kwargs)

        track._process.communicate = spy
        track.close(0.5)
        self.assertTrue(seen.get("ok"), "communicate() の時点で stdin が閉じている")

    def test_close_does_not_call_stdin_close(self):
        import inspect

        source = inspect.getsource(self.rec._TrackWriter.close)
        self.assertNotIn("stdin.close()", source)

    def test_an_already_closed_pipe_does_not_raise(self):
        """書き込み失敗などで既に閉じていても、停止処理を巻き添えにしない。"""
        track = self.rec._TrackWriter(2, "B", self.work / "b.mp3", time.monotonic())
        track.write(self._tone(), 0.0)
        track._process.stdin.close()

        with patch.object(self.rec.logger, "warning"):
            track.close(0.5)  # 例外が出たら失敗
        self.assertTrue(track.failed)

    def test_writing_to_a_closed_pipe_is_caught(self):
        """閉じたパイプへの書き込みは ValueError で来る（OSError ではない）。"""
        track = self.rec._TrackWriter(3, "C", self.work / "c.mp3", time.monotonic())
        track._process.stdin.close()

        with patch.object(self.rec.logger, "warning"):
            track.write(self._tone(), 0.0)  # 例外が出たら失敗
        self.assertTrue(track.failed)
        track.close(0.5)

    def test_output_is_still_produced_normally(self):
        track = self.rec._TrackWriter(4, "D", self.work / "d.mp3", time.monotonic())
        track.write(self._tone(0.3), 0.0)
        track.close(1.0)
        out = self.work / "d.mp3"
        self.assertTrue(out.exists())
        self.assertGreater(out.stat().st_size, 0)


class WaveformTests(unittest.TestCase):
    """波形データ。録音しながら拾う（書き出し後に読み直さない）。"""

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording
        self.work = Path(tempfile.mkdtemp(prefix="peaktest-"))

    def _tone(self, seconds, amplitude=12000):
        import math
        import struct

        out = bytearray()
        for i in range(int(self.rec.SAMPLE_RATE * seconds)):
            v = int(amplitude * math.sin(2 * math.pi * 440 * i / self.rec.SAMPLE_RATE))
            out += struct.pack("<hh", v, v)
        return bytes(out)

    def test_peaks_follow_the_timeline(self):
        track = self.rec._TrackWriter(1, "A", self.work / "a.mp3", time.monotonic())
        track.write(self._tone(0.5), 0.0)  # 0.0〜0.5 に音
        track.write(self._tone(0.5, 30000), 2.0)  # 2.0〜2.5 に大きい音
        track.close(4.0)

        peaks = track.peak_series()
        self.assertEqual(len(peaks), int(4.0 / self.rec.PEAK_BUCKET_SECONDS))
        self.assertGreater(peaks[0], 0.2)  # 冒頭は鳴っている
        self.assertEqual(peaks[4], 0.0)  # 1.0秒地点は無音
        self.assertGreater(peaks[8], peaks[0])  # 2.0秒地点のほうが大きい

    def test_silence_only_track_is_flat(self):
        track = self.rec._TrackWriter(2, "B", self.work / "b.mp3", time.monotonic())
        track.close(2.0)
        self.assertTrue(all(v == 0.0 for v in track.peak_series()))

    def test_long_recordings_are_downsampled(self):
        track = self.rec._TrackWriter(3, "C", self.work / "c.mp3", time.monotonic())
        track.peaks = [1000] * 90_000  # 6時間ぶん相当
        group = 30
        series = track.peak_series(group=group, points=3000)
        self.assertLessEqual(len(series), self.rec.PEAK_MAX_POINTS)
        self.assertTrue(all(0.0 <= v <= 1.0 for v in series))
        track._process.stdin.close()
        track._process.stdin = None
        track._process.kill()

    def test_values_are_normalised(self):
        self.assertEqual(self.rec._peak_of(b""), 0)
        loud = self.rec._peak_of(self._tone(0.05, 32000))
        quiet = self.rec._peak_of(self._tone(0.05, 1000))
        self.assertGreater(loud, quiet)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()


class EndToEndEncryptionTests(unittest.TestCase):
    """端から端まで暗号化された音声（DAVE）を、雑音として録らないこと。

    Discord は 2024年9月から音声を E2EE している。暗号文をそのまま Opus に
    食わせると、多くは例外にならずに雑音が返る。「録れているのに聞けない」
    という一番たちの悪い壊れ方になるため、入り口で外して正直に止める。

    仕様（https://github.com/discord/dave-protocol）:
      [暗号文][認証タグ 8][nonce ULEB128][平文範囲 ULEB128][補助データ長 1][0xFAFA 2]
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording

    def test_the_frames_seen_in_production_are_recognised(self):
        """本番のログに出た末尾をそのまま判定させる。

        末尾=c8db040cfafa      長さ 0x0c=12 = タグ8 + nonce1 + 長さ1 + マーカー2
        末尾=010dfafa0202      末尾は RTP パディング（voice_recv は剥がさない）
        """
        first = bytes(87) + bytes.fromhex("c8db040cfafa")
        self.assertTrue(self.rec.is_dave_frame(first), first[-6:].hex())

        padded = bytes(96) + bytes.fromhex("010dfafa0202")
        self.assertTrue(self.rec.is_dave_frame(padded), padded[-6:].hex())

    def test_ordinary_opus_is_not_mistaken_for_encrypted(self):
        import discord.opus as opus

        if not opus.is_loaded():
            try:
                opus._load_default()
            except Exception:
                self.skipTest("libopus が読み込めない環境です")
        import math
        import struct

        pcm = bytearray()
        for i in range(960):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / self.rec.SAMPLE_RATE))
            pcm += struct.pack("<hh", v, v)
        frame = opus.Encoder().encode(bytes(pcm), 960)
        self.assertFalse(self.rec.is_dave_frame(frame), frame[-6:].hex())

    def test_a_stray_magic_marker_is_not_enough(self):
        """偶然 0xFAFA が並んだだけのフレームを暗号化扱いしない。

        補助データ長が筋の通る値かどうかまで見る。
        """
        bogus = bytes(40) + bytes.fromhex("0000fafa")  # 長さバイトが 0
        self.assertFalse(self.rec.is_dave_frame(bogus))
        self.assertFalse(self.rec.is_dave_frame(b""))
        self.assertFalse(self.rec.is_dave_frame(None))

    def test_a_session_is_only_judged_after_enough_frames(self):
        """切り替わりの途中で数フレームだけ暗号化されていることがある。"""
        session = self.rec.RecordingSession(
            guild_id=999,
            channel_id=1,
            channel_name="VC",
            started_by_id=1,
            started_by_name="t",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=1,
        )
        for _ in range(5):
            session.note_encrypted()
        self.assertFalse(session.is_end_to_end_encrypted, "少ない件数で決めつけている")

        for _ in range(self.rec._DAVE_MIN_SAMPLES):
            session.note_encrypted()
        self.assertTrue(session.is_end_to_end_encrypted)

    def test_encrypted_frames_never_reach_a_track(self):
        """暗号文が音として書き込まれないこと。"""
        session = self.rec.RecordingSession(
            guild_id=999,
            channel_id=1,
            channel_name="VC",
            started_by_id=1,
            started_by_name="t",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=1,
        )
        sink = self.rec._make_sink_class()(session)
        user = Mock(id=1, display_name="すずき")
        payload = bytes(87) + bytes.fromhex("c8db040cfafa")
        data = SimpleNamespace(packet=SimpleNamespace(ssrc=1, sequence=100, timestamp=48000, payload=120), opus=payload)
        for _ in range(10):
            sink.write(user, data)
        sink.flush_pending()
        self.assertEqual(session.tracks, {}, "暗号文からトラックが作られている")
        self.assertEqual(session.encrypted_frames, 10)
        self.assertEqual(session.dropped_packets, 0, "デコードを試している")


class DaveDecryptionTests(unittest.TestCase):
    """E2EE(DAVE)の受信側。

    鍵交換（MLS）は discord.py 2.7.1 が実装済みで、davey が入っていれば
    自動で成立する。足りないのは受信側の復号だけなので、そこを繋ぐ。
    """

    def setUp(self):
        from services import dave

        self.dave = dave

    def test_davey_is_installed(self):
        """入っていないと音声接続そのものが 4017 で拒否される。"""
        self.assertTrue(self.dave.AVAILABLE, "davey が入っていない")
        self.assertGreaterEqual(self.dave.MAX_PROTOCOL_VERSION, 1)

    def test_discord_py_picks_up_davey(self):
        """discord.py が davey を見つけていないと、版 0 を申告してしまう。"""
        import discord.voice_state as voice_state

        self.assertTrue(voice_state.has_dave)

    def test_a_session_is_ignored_until_the_keys_are_shared(self):
        """鍵が揃う前に復号を試すと例外になる。ready を見て避ける。"""
        import davey

        session = davey.DaveSession(davey.DAVE_PROTOCOL_VERSION, 111, 222)
        self.assertFalse(session.ready)

        client = SimpleNamespace(_connection=SimpleNamespace(dave_session=session))
        self.assertIsNone(self.dave.session_of(client))

        payload = bytes(87) + bytes.fromhex("c8db040cfafa")
        self.assertIsNone(self.dave.decrypt_opus(client, 111, payload))

    def test_no_client_is_handled(self):
        self.assertIsNone(self.dave.session_of(None))
        self.assertIsNone(self.dave.decrypt_opus(None, 111, b"x" * 40))

    def test_the_reason_names_the_actual_problem(self):
        """「録音できません」だけでは、何をすれば直るのか分からない。"""
        reason = self.dave.unavailable_reason()
        self.assertIn("暗号化", reason)
        # davey が入っているので、原因は鍵の共有側だと伝わること
        self.assertIn("鍵", reason)

    def test_decryption_is_attempted_before_giving_up(self):
        """復号できるなら、平文として録れること。"""
        import services.recording_service as recording

        session = recording.RecordingSession(
            guild_id=999,
            channel_id=1,
            channel_name="VC",
            started_by_id=1,
            started_by_name="t",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=1,
        )
        sink = recording._make_sink_class()(session)
        user = Mock(id=1, display_name="すずき")

        import discord.opus as opus

        if not opus.is_loaded():
            try:
                opus._load_default()
            except Exception:
                self.skipTest("libopus が読み込めない環境です")
        import math
        import struct

        pcm = bytearray()
        for i in range(960):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / recording.SAMPLE_RATE))
            pcm += struct.pack("<hh", v, v)
        plain = opus.Encoder().encode(bytes(pcm), 960)
        encrypted = bytes(87) + bytes.fromhex("c8db040cfafa")

        data = SimpleNamespace(
            packet=SimpleNamespace(ssrc=1, sequence=100, timestamp=48000, payload=120), opus=encrypted
        )
        with patch.object(recording.dave, "decrypt_opus", return_value=plain):
            for i in range(5):
                data.packet.sequence = 100 + i
                data.packet.timestamp = 48000 + i * 960
                sink.write(user, data)
            sink.flush_pending()

        stream = sink._streams[1]
        self.assertEqual(stream.decrypted, 5, "復号を試していない")
        self.assertEqual(stream.encrypted, 0, "復号できたのに諦めている")
        self.assertIn(1, session.tracks, "復号した音がトラックになっていない")
        for track in session.tracks.values():
            track.close(1.0)


class RtpPaddingTests(unittest.TestCase):
    """RTP のパディングを取り除くこと。

    voice_recv は剥がさない（rtp.py に「discord はこのビットを使っていない
    ようだ」と書かれている）。実際には使われていて、本番でこう届いていた:

        247 バイト、全部 0xF7 … 0xF7 = 247 = 全体の長さ
        255 バイト、全部 0xFF … 0xFF = 255 = 全体の長さ

    RFC 3550 では最終バイトがパディング長（自身を含む）。全体の長さと等しい
    なら音声は1バイトも入っていない（帯域推定のための探査パケット）。
    """

    def setUp(self):
        import services.recording_service as recording

        self.rec = recording

    def _packet(self, padding=True):
        return SimpleNamespace(ssrc=1, sequence=1, timestamp=0, payload=120, padding=padding)

    def test_the_probe_packets_seen_in_production_are_dropped(self):
        for size in (247, 255):
            payload = bytes([size]) * size
            self.assertIsNone(
                self.rec.strip_rtp_padding(self._packet(), payload), f"{size} バイトの詰め物を音声として扱っている"
            )

    def test_they_are_dropped_even_without_the_header_bit(self):
        """ヘッダのビットが立っていない実装もある。長さで判断できる。"""
        payload = bytes([255]) * 255
        self.assertIsNone(self.rec.strip_rtp_padding(self._packet(padding=False), payload))

    def test_partial_padding_is_trimmed(self):
        """E2EE のフレームは末尾のマーカーがパディングに隠れる。

        本番で ... 010dfafa0202 として観測した形。剥がすとマーカーが末尾に来る。
        """
        payload = bytes(96) + bytes.fromhex("010dfafa0202")
        trimmed = self.rec.strip_rtp_padding(self._packet(), payload)
        self.assertEqual(trimmed[-2:], b"\xfa\xfa", trimmed[-6:].hex())
        self.assertEqual(len(trimmed), len(payload) - 2)

    def test_ordinary_opus_is_untouched(self):
        import discord.opus as opus

        if not opus.is_loaded():
            try:
                opus._load_default()
            except Exception:
                self.skipTest("libopus が読み込めない環境です")
        import math
        import struct

        pcm = bytearray()
        for i in range(960):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / self.rec.SAMPLE_RATE))
            pcm += struct.pack("<hh", v, v)
        frame = opus.Encoder().encode(bytes(pcm), 960)
        self.assertEqual(self.rec.strip_rtp_padding(self._packet(padding=False), frame), frame)

    def test_a_broken_length_is_left_alone(self):
        """壊れた値で音を削らない。"""
        payload = bytes(20) + bytes([200])  # 長さより大きいパディング長
        self.assertEqual(self.rec.strip_rtp_padding(self._packet(), payload), payload)
        self.assertEqual(self.rec.strip_rtp_padding(self._packet(), b""), b"")

    def test_probe_packets_never_reach_a_track(self):
        session = self.rec.RecordingSession(
            guild_id=999,
            channel_id=1,
            channel_name="VC",
            started_by_id=1,
            started_by_name="t",
            started_at=time.monotonic(),
            max_seconds=0,
            retention_days=1,
        )
        sink = self.rec._make_sink_class()(session)
        user = Mock(id=1, display_name="すずき")
        data = SimpleNamespace(packet=self._packet(), opus=bytes([255]) * 255)
        for _ in range(8):
            sink.write(user, data)
        sink.flush_pending()
        self.assertEqual(session.tracks, {}, "詰め物からトラックが作られている")
        self.assertEqual(session.dropped_packets, 0, "詰め物をデコードしている")
        self.assertEqual(sink._streams[1].padding_only, 8)


class SettingsWriteOffloadTests(unittest.TestCase):
    """設定の書き込みが、イベントループの上で行われていないこと。

    settings.json の書き込みはファイルロックを取り、空くのを待つ間は
    time.sleep(0.05) のポーリングで最大10秒待つ。Bot と管理画面は別プロセスで
    同じファイルを共有しているので、競合は実際に起きる。

    async の中から同期のセッターを直に呼ぶと、その間イベントループ全体が
    止まる。Bot なら Discord のハートビートと全ギルドの処理が、管理画面
    （既定 workers=1）ならヘルスチェックを含む全 HTTP 応答が固まる。

    直呼びは見た目では気付けない（普通の関数呼び出しにしか見えない）ので、
    構文木から機械的に見つける。非同期から書き込むときは
    services.settings_store.awrite() か asyncio.to_thread を通すこと。
    """

    ROOT = Path(__file__).resolve().parent.parent
    SKIP_DIRS = {".git", "tests", "migrations", "__pycache__", ".venv", "venv"}

    def _writers(self) -> set[str]:
        """settings.json を書き換える同期の公開関数を、実装から求める。

        名前を並べた表を持つと、関数が増えたときに更新を忘れる。
        _mutate_settings から辿れるものを、その都度たどる。
        """
        tree = ast.parse((self.ROOT / "services/settings_store.py").read_text(encoding="utf-8"))
        calls_of, async_names = {}, set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls_of[node.name] = {
                    n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                }
                if isinstance(node, ast.AsyncFunctionDef):
                    async_names.add(node.name)

        reached = {"_mutate_settings"}
        while True:
            grew = False
            for name, called in calls_of.items():
                if name in reached or name in async_names:
                    continue
                if called & reached:
                    reached.add(name)
                    grew = True
            if not grew:
                break
        return {name for name in reached if not name.startswith("_")}

    def _direct_calls(self, tree: ast.AST, names: set[str]) -> list[tuple[int, str]]:
        """async 関数の本体で直接呼ばれているものだけを返す。

        async の中に def を書いた場合、その中は同期の文脈なので対象外。
        ast.walk では境界を越えて拾ってしまうので、自分で降りる。
        """
        found: list[tuple[int, str]] = []

        def scan(node, inside_async: bool):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.AsyncFunctionDef):
                    scan(child, True)
                    continue
                if isinstance(child, (ast.FunctionDef, ast.Lambda)):
                    scan(child, False)
                    continue
                if (
                    inside_async
                    and isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name)
                    and child.func.id in names
                ):
                    found.append((child.lineno, child.func.id))
                scan(child, inside_async)

        scan(tree, False)
        return found

    def test_awrite_lets_the_event_loop_keep_running(self):
        """awrite が実際に待ちをイベントループの外へ出していること。

        構文木の検査は「直呼びが無いこと」しか見ない。仕組みそのものが効いて
        いるかは、実際に止めてみて確かめる。書き込みが 0.3 秒かかる状況を作り、
        その間に別のコルーチンが進めるかを数える。
        """
        import time

        from services import settings_store

        def slow_write(_guild_id):
            time.sleep(0.3)

        async def count_ticks(offload: bool) -> int:
            ticks = 0

            async def ticker():
                nonlocal ticks
                while True:
                    await asyncio.sleep(0.01)
                    ticks += 1

            task = asyncio.ensure_future(ticker())
            await asyncio.sleep(0.02)  # 先に動かしておく
            if offload:
                await settings_store.awrite(slow_write, 1)
            else:
                slow_write(1)  # 直呼び（比較用）
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return ticks

        offloaded = asyncio.run(count_ticks(True))
        blocking = asyncio.run(count_ticks(False))

        self.assertGreater(offloaded, 5, f"awrite でもループが止まっている（{offloaded} 回）")
        self.assertLess(blocking, 5, f"直呼びが止めていない。比較にならない（{blocking} 回）")

    def test_the_writer_list_is_actually_found(self):
        """探し方が壊れていたら、この検査は何も見なくなる。"""
        writers = self._writers()
        self.assertIn("set_welcome_channel", writers)
        self.assertIn("add_reaction_role", writers)
        self.assertIn("replace_guild_settings", writers)
        self.assertGreater(len(writers), 20, writers)
        # 非同期版そのものは対象に含めない
        self.assertNotIn("awrite", writers)
        self.assertNotIn("amutate_settings", writers)

    def test_no_async_function_writes_settings_directly(self):
        writers = self._writers()
        offenders = []
        for path in sorted(self.ROOT.rglob("*.py")):
            if any(part in self.SKIP_DIRS for part in path.relative_to(self.ROOT).parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for line, name in self._direct_calls(tree, writers):
                offenders.append(f"{path.relative_to(self.ROOT)}:{line} {name}()")

        joined = chr(10).join(offenders)
        self.assertEqual(
            offenders,
            [],
            "async から設定を直接書いています。" "await awrite(関数, 引数...) を通してください:" + chr(10) + joined,
        )


class ReactionRoleEmojiTests(unittest.TestCase):
    """カスタム絵文字でも、保存した形と実際のリアクションが一致すること。

    保存側（管理画面・スラッシュコマンド）は入力された文字列をそのまま
    キーにしていたが、照合側は PartialEmoji から `str(emoji.id)` を作って
    引いていた。`<:name:123>` と `123` は一致しないので、カスタム絵文字の
    リアクションロールはログも残さず一切動いていなかった。ユニコード絵文字は
    両者が同じ文字列になるため偶然動いていて、気付きにくかった。
    """

    def setUp(self):
        from services import reaction_role_service

        self.rr = reaction_role_service

    def test_every_way_of_writing_a_custom_emoji_lands_on_the_same_key(self):
        same = ["<:kusa:123456789012345678>", "kusa:123456789012345678", "123456789012345678"]
        keys = {self.rr.emoji_key(v) for v in same}
        self.assertEqual(keys, {"123456789012345678"})
        # アニメーション絵文字（<a:...>）も同じ規則で読む
        self.assertEqual(self.rr.emoji_key("<a:spin:987654321098765432>"), "987654321098765432")

    def test_a_unicode_emoji_is_left_alone(self):
        self.assertEqual(self.rr.emoji_key("👍"), "👍")
        self.assertEqual(self.rr.emoji_key("  🎉 "), "🎉")

    def test_a_partial_emoji_object_uses_its_id(self):
        custom = Mock(id=555)
        self.assertEqual(self.rr.emoji_key(custom), "555")
        unicode_emoji = Mock(id=None)
        unicode_emoji.__str__ = Mock(return_value="👍")
        self.assertEqual(self.rr.emoji_key(unicode_emoji), "👍")

    def test_settings_saved_in_the_old_form_still_match(self):
        """入れ直してもらわずに動くこと。

        すでに `<:name:123>` の形で保存されている設定を、移行作業なしで
        拾えること。ここが効かないと「直したのに直っていない」になる。
        """
        mapping = {"<:kusa:123456789012345678>": 42, "👍": 7}
        custom = Mock(id=123456789012345678)
        self.assertEqual(self.rr._role_id_for(mapping, custom), 42)

        unicode_emoji = Mock(id=None)
        unicode_emoji.__str__ = Mock(return_value="👍")
        self.assertEqual(self.rr._role_id_for(mapping, unicode_emoji), 7)

    def test_an_unmapped_emoji_still_returns_nothing(self):
        mapping = {"123456789012345678": 42}
        other = Mock(id=999999999999999999)
        self.assertIsNone(self.rr._role_id_for(mapping, other))


class LosslessJitterBufferTests(unittest.TestCase):
    """順番待ちの穴に当たったとき、ライブラリが中身を捨てないこと。

    voice_recv は穴に当たると、抱えていたパケットのうち先頭1個だけを返して
    残りを捨てる。捨てられたぶんは sink まで来ないので、こちらの並べ直し
    （_StreamAssembler）では取り返せず、そのまま録音の穴になる。本番のログでは
    録音中ずっと「1 packets were lost being flushed in decoder-1148」が出ていた。

    ライブラリの実物（HeapJitterBuffer / PacketDecoder）を動かして確かめる。
    自前で真似た版を相手にすると、直しているつもりの相手が居なくなる。
    """

    SSRC = 1148

    def setUp(self):
        from discord.ext.voice_recv import opus as vr_opus

        from services import voice_jitter

        self.vr_opus = vr_opus
        self.vj = voice_jitter
        # install() は差し替え済みかどうかをモジュールに持つ。テスト間で
        # 持ち越すと、順番によって結果が変わる。
        self.addCleanup(setattr, vr_opus, "JitterBuffer", vr_opus.JitterBuffer)
        self.addCleanup(setattr, voice_jitter, "_installed", voice_jitter._installed)
        voice_jitter.reset_stats()

    def _packet(self, sequence: int, ssrc: int | None = None):
        """RTP のヘッダを組んで本物の RTPPacket を作る。

        FakePacket は使えない。__bool__ が False なので、PacketDecoder が
        「欠落ぶんの穴埋め」と誤解して別のパケットに差し替えてしまう。
        """
        import struct

        from discord.ext.voice_recv.rtp import RTPPacket

        header = struct.pack(">BBHII", 0x80, 120, sequence % (1 << 16), (960 * sequence) % (1 << 32), ssrc or self.SSRC)
        return RTPPacket(header + b"\x00" * 20)

    def _decoder(self, buffer_cls):
        """buffer_cls を使う PacketDecoder と、その waiter を作る。

        router / sink は Mock で足りる（wants_opus() が真なら、ライブラリ側は
        デコードしないので opus も要らない）。waiter だけは本物を使う。
        router が「どの decoder を見に行くか」を決めているのがこれで、
        真似ると穴のときの取りこぼしが再現しない。
        """
        from discord.ext.voice_recv.opus import PacketDecoder
        from discord.ext.voice_recv.utils import MultiDataEvent

        router = Mock()
        router.waiter = MultiDataEvent()
        with patch.object(self.vr_opus, "JitterBuffer", buffer_cls):
            decoder = PacketDecoder(router, self.SSRC)
        return decoder, router.waiter

    def _drive(self, buffer_cls, arrivals):
        """届いた順に押し込み、router と同じ回し方で取り出す。

        返すのは (sink へ届いた番号, まだ抱えている番号)。抱えているぶんは
        まだ捨てられていないので、損失に数えない。
        """
        decoder, waiter = self._decoder(buffer_cls)
        delivered: list[int] = []
        for packet in arrivals:
            decoder.push_packet(packet)
            for _ in range(64):  # 暴走止め。実際は数回で waiter が空になる
                if not waiter.is_ready():
                    break
                for ready in waiter.items:
                    data = ready.pop_data()  # router._do_run と同じ timeout=0
                    if data is not None:
                        delivered.append(data.packet.sequence)
        held = [p.sequence for p in decoder._buffer.flush()]
        return delivered, held

    def test_the_stock_buffer_throws_away_the_packets_behind_a_gap(self):
        """まず、直す相手が実在することを押さえる。

        ライブラリ側がこれを直したら、このテストが落ちて教えてくれる。
        そのときは差し替え（services/voice_jitter.py）を外してよい。
        """
        from discord.ext.voice_recv.buffer import HeapJitterBuffer

        seqs = [s for s in range(20295, 20316) if s not in (20300, 20301)]
        delivered, held = self._drive(HeapJitterBuffer, [self._packet(s) for s in seqs])

        lost = sorted(set(seqs) - set(delivered) - set(held))
        self.assertEqual(lost, [20303], f"捨てられた番号が想定と違う: {lost}")

    def test_no_packet_is_thrown_away_when_a_gap_appears(self):
        """差し替えた版では、穴の後ろのパケットが1つも消えないこと。

        消えたぶんは録音の穴になり、あとから取り返す方法が無い。
        """
        seqs = [s for s in range(20295, 20316) if s not in (20300, 20301)]
        delivered, held = self._drive(self.vj._LosslessJitterBuffer, [self._packet(s) for s in seqs])

        lost = sorted(set(seqs) - set(delivered) - set(held))
        self.assertEqual(lost, [], f"捨てられた: {lost}")

    def test_a_burst_of_out_of_order_packets_survives(self):
        """話者が入れ替わった直後の、順不同で届く塊も落とさないこと。

        本番では、この形で1回に6個捨てていた（decoder-1352 の
        「6 packets were lost being flushed」）。ここがいちばん実害が大きい。
        """
        seqs = [16761, 16762, 16764, 16765, 16766, 16768, 16769, 16781, 16782, 16783, 16784, 16785, 16786]
        delivered, held = self._drive(self.vj._LosslessJitterBuffer, [self._packet(s) for s in seqs])

        lost = sorted(set(seqs) - set(delivered) - set(held))
        self.assertEqual(lost, [], f"捨てられた: {lost}")

    def test_the_order_out_is_still_ascending(self):
        """取り出す順序を変えていないこと。

        Opus は直前の状態を使って復号するので、順不同で渡すと音が壊れる
        （実測で 440Hz が 719Hz に化けた）。捨てないようにしただけで、
        順番まで変えたつもりは無い、ということを固定する。
        """
        seqs = [s for s in range(4000, 4030) if s not in (4007, 4008, 4019)]
        delivered, _ = self._drive(self.vj._LosslessJitterBuffer, [self._packet(s) for s in seqs])

        self.assertEqual(delivered, sorted(delivered), f"昇順でない: {delivered}")

    def test_install_replaces_the_class_the_decoder_builds(self):
        """差し替えが、実際に decoder の作る型まで届いていること。

        PacketDecoder は JitterBuffer() を自分で作る。モジュール属性を
        置き換えられていなければ、install() が True を返しても効かない。
        """
        from discord.ext.voice_recv.opus import PacketDecoder
        from discord.ext.voice_recv.utils import MultiDataEvent

        self.vj._installed = False
        self.assertTrue(self.vj.install())

        router = Mock()
        router.waiter = MultiDataEvent()
        decoder = PacketDecoder(router, self.SSRC)
        self.assertIsInstance(decoder._buffer, self.vj._LosslessJitterBuffer)

    def test_install_refuses_when_the_library_lost_the_hook(self):
        """差し替え先が無くなっていたら、黙って続けないこと。

        voice_recv 側の作りが変わったときに素通りさせると、「差し替えた
        つもりで、穴のたびに捨て続ける」状態になる。これは元より悪い
        （直っていると思って測るのをやめるため）。
        """
        self.vj._installed = False
        before = self.vr_opus.JitterBuffer
        # _update_has_item を持たない型に差し替えて、「作りが変わった」状態を作る
        with patch.object(self.vj, "HeapJitterBuffer", object):
            with self.assertLogs("services.voice_jitter", level="WARNING") as logs:
                self.assertFalse(self.vj.install())
        self.assertIs(self.vr_opus.JitterBuffer, before, "差し替えてしまっている")
        self.assertFalse(self.vj.stats()["installed"])
        self.assertIn("_update_has_item", logs.output[0])

    def test_one_packet_alone_is_kept_as_a_cushion(self):
        """1個しか抱えていないあいだは出さないこと。

        prefsize の1個は、すぐ後ろに順不同で届くぶんと並べ替えるための遊び。
        捨てないようにしただけで、この遊びまで詰めたつもりは無い。

        なお `len(self._buffer) <= self.prefsize` を `<` に変える変異は、
        どのテストでも落ちない。router は「2個以上抱えている decoder」しか
        見に来ないので、1個のときの旗の状態は誰も読まないためで、これは
        等価な変異である（落ちないから守れていない、ではない）。
        """
        delivered, held = self._drive(self.vj._LosslessJitterBuffer, [self._packet(7000)])

        self.assertEqual(delivered, [])
        self.assertEqual(held, [7000])

    def test_packets_that_arrive_too_late_are_counted(self):
        """遅すぎて受け取れなかったぶんを数えていること。

        ここが 0 でないなら、こちらの並べ直しを延ばしても届かない領域の
        損失が残っている、と分かる。数えていないと「直った」と言い切れない。
        """
        buf = self.vj._LosslessJitterBuffer()
        for seq in (5000, 5001, 5002, 5003):
            buf.push(self._packet(seq))
        while buf.pop(timeout=0) is not None:
            pass

        self.assertEqual(self.vj.stats()["late_rejected"], 0)
        buf.push(self._packet(4990))  # もう出した所より後ろ
        self.assertEqual(self.vj.stats()["late_rejected"], 1)
