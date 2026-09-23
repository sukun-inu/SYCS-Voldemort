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
import io
import gzip
import json
from datetime import datetime, timedelta, timezone
import logging
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

# services/* は読み込み時に SETTINGS_DIR を解決するため、import より前に差し替える。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="services-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
# 配信キャッシュは SETTINGS_DIR とは別の設定なので、明示的に隔離する。
# 忘れるとテストの書き出しがリポジトリの data/djaudio_cache に溜まり続ける。
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="services-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402

import services.earthquake_service as eq  # noqa: E402
from services import settings_store as store  # noqa: E402
from services.news_service import _favicon_url  # noqa: E402
from services.url_safety import (  # noqa: E402
    URLSafetyError,
    validate_public_http_url,
    validate_public_http_url_async,
)
from services.welcome_service import DEFAULT_GOODBYE, DEFAULT_WELCOME, render_template  # noqa: E402
from webapp_admin.schema.validation import InvalidValue, validate_field  # noqa: E402


def _command_body(source: str, name: str) -> str:
    """`async def name(` の本体を原文から切り出す。1行の委譲なら委譲先も繋げる。

    コマンドの中身をモジュール直下の関数へ出すと、`@group.command` の下に
    残るのは `await _apply_xxx(...)` の1行だけになる。ガードの有無を原文で
    見るテストは、その1行の先まで追わないと**割った瞬間に嘘をつく**。
    """
    body = source[source.index(f"async def {name}(") :]
    body = body[: body.index("@group.command") if "@group.command" in body else len(body)]
    delegated = re.findall(r"await (_[a-z_]+)\(", body)
    for callee in delegated:
        marker = f"async def {callee}("
        if marker in source:
            tail = source[source.index(marker) :]
            sep = chr(10) * 3  # 空行2つ＝次のトップレベル定義の始まり
            body += tail[: tail.index(sep) if sep in tail else len(tail)]
    return body


def _calls_in_async_bodies(tree: ast.AST, names: set[str]) -> list[tuple[int, str]]:
    """async 関数の本体で直接呼ばれているものだけを返す。

    async の中に def を書いた場合、その中は同期の文脈なので対象外。
    ast.walk では境界を越えて拾ってしまうので、自分で降りる。

    「同期のまま呼ぶとイベントループが止まる関数」を探す検査が2つ（設定の
    書き込みと、URL の安全性検査）あり、探し方は同じなのでここに置く。
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


class _NullSession:
    """aiohttp.ClientSession の代わり。地図生成を差し替えているので中身は要らない。"""

    def __init__(self, *a, **k):
        """引数は受け取るだけ。"""

    async def __aenter__(self):
        """自分を返す。"""
        return self

    async def __aexit__(self, *exc):
        """例外は握らない。"""
        return False


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


class GuildRetentionTests(unittest.TestCase):
    """ギルドのデータをいつ消すか。

    方針は**「消すのは利用者が決める」**。使っている限り、何年経っても
    勝手には消えない。自動で消すのは放棄されたものだけで、条件は
    「Bot がもう居ない」かつ「最終更新から10年」の**両方**である。

      - 片方だけでは消さないこと
      - 触られた時刻の無い設定は消さないこと
      - 中身が変わったギルドにだけ時刻を押すこと
      - 利用者の削除では、設定と監査履歴をまとめて消すこと
      - 監査履歴を消せなくても、設定は消すこと

    2つ目が要。この仕組みを入れる前から在る設定には時刻が無い。**無いものを
    「ずっと前」と読むと、既存の設定が条件を満たした瞬間に一斉に消える。**
    """

    def setUp(self):
        import services.guild_retention as retention

        self.retention = retention
        self.store = store
        # 設定ファイルはテスト間で持ち越さない。
        for guild_id in self.store.known_guild_ids():
            self.store.delete_guild_settings(guild_id)
        self.addCleanup(self._clear)

    def _clear(self):
        """このテストで作った設定を片付ける。"""
        for guild_id in self.store.known_guild_ids():
            self.store.delete_guild_settings(guild_id)

    def _aged(self, guild_id, days_ago):
        """指定した日数前に触られたことにする。"""
        self.store.update_guild_settings(guild_id, {"log_channel_id": 1})
        stamp = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        self.store.update_guild_settings(guild_id, {store.TOUCHED_AT_KEY: stamp})

    def test_a_guild_the_bot_still_belongs_to_is_never_purged(self):
        """Bot が居るギルドは、何年経っても消さないこと。

        設定して放置しているだけの現役サーバーがある。**触っていない＝
        使っていない、ではない。**
        """
        self._aged(1, days_ago=365 * 50)

        self.assertFalse(self.retention.is_abandoned(1, present=True))
        self.assertTrue(self.retention.is_abandoned(1, present=False))

    def test_a_guild_left_recently_is_not_purged_either(self):
        """退出済みでも、最近触られていれば消さないこと。

        「一時的に外して入れ直す」運用がある。退出しただけで消すと、
        戻したときに設定が初期化されている。
        """
        self._aged(2, days_ago=30)

        self.assertFalse(self.retention.is_abandoned(2, present=False))

    def test_settings_without_a_timestamp_are_left_alone(self):
        """触られた時刻の無い設定は消さないこと。

        この仕組みより前から在る設定には時刻が無い。**無いものを
        「ずっと前」と読むと、既存の設定が一斉に消える。** 次に何か
        書き換えられた時点で時刻が入る。
        """
        self.store.update_guild_settings(3, {"log_channel_id": 1})
        self.store.update_guild_settings(3, {store.TOUCHED_AT_KEY: None})

        self.assertIsNone(self.store.touched_at(3))
        self.assertFalse(self.retention.is_abandoned(3, present=False))

    def test_only_the_guild_that_changed_gets_a_fresh_timestamp(self):
        """中身が変わったギルドにだけ時刻を押すこと。

        全ギルドへ毎回押すと「10年触られていない」がどのギルドについても
        成立しなくなり、**掃除が永久に動かない。**
        """
        self._aged(4, days_ago=365 * 20)
        old = self.store.touched_at(4)

        self.store.update_guild_settings(5, {"log_channel_id": 9})

        self.assertEqual(self.store.touched_at(4), old, "触っていないギルドの時刻が動いた")
        self.assertIsNotNone(self.store.touched_at(5))

    def test_writing_the_same_value_does_not_move_the_timestamp(self):
        """同じ値で上書きしても、時刻は動かさないこと。

        値が変わっていないなら触られていない。定期ジョブが同じ値を
        書き戻すだけで**永久に「最近触られた」ことになる。**
        """
        self.store.update_guild_settings(6, {"log_channel_id": 1})
        first = self.store.touched_at(6)

        self.store.update_guild_settings(6, {"log_channel_id": 1})

        self.assertEqual(self.store.touched_at(6), first)

    def test_purging_skips_every_guild_the_bot_is_in(self):
        """掃除は、Bot が居るギルドを1つも消さないこと。"""
        self._aged(10, days_ago=365 * 20)
        self._aged(11, days_ago=365 * 20)

        removed = asyncio.run(self.retention.purge_abandoned_guilds({10}))

        self.assertEqual(removed, [11])
        self.assertNotEqual(self.store.get_guild_settings(10), {})
        self.assertEqual(self.store.get_guild_settings(11), {})

    def test_the_user_delete_takes_the_audit_history_with_it(self):
        """利用者の削除では、設定と監査履歴をまとめて消すこと。

        別々の口にすると、「このサーバーのデータを消したい」と思った人に
        **消し残しがあることを覚えていてもらう**ことになる。
        """
        self.store.update_guild_settings(20, {"log_channel_id": 1})
        with patch(
            "services.user_state_service.delete_guild_user_states",
            AsyncMock(return_value={"events": 7, "states": 3}),
        ) as purge:
            removed = asyncio.run(self.retention.delete_guild_data(20))

        purge.assert_awaited_once_with(20)
        self.assertEqual(removed, {"settings": 1, "events": 7, "states": 3})
        self.assertEqual(self.store.get_guild_settings(20), {})

    def test_the_settings_go_even_if_the_history_cannot_be_deleted(self):
        """監査履歴を消せなくても、設定は消すこと。

        逆にすると、**DB が落ちているあいだは設定も消せない。**
        「消してくれ」と言われて何も消えないより、消せるほうから消す。
        """
        self.store.update_guild_settings(21, {"log_channel_id": 1})
        with (
            patch(
                "services.user_state_service.delete_guild_user_states",
                AsyncMock(side_effect=RuntimeError("DBが落ちている")),
            ),
            self.assertLogs("services.guild_retention", level="ERROR"),
        ):
            removed = asyncio.run(self.retention.delete_guild_data(21))

        self.assertEqual(removed["settings"], 1)
        self.assertEqual(self.store.get_guild_settings(21), {})


class TrustedProxyTests(unittest.TestCase):
    """リバースプロキシの向こう側にいる、本当のアクセス元が分かること。

    プロキシ経由だと TCP の接続元はプロキシ自身（127.0.0.1）になる。
    **アクセスログもレート制限も全部 127.0.0.1 として記録されていた。**
    攻撃元も、よく使っている人も、区別が付かない。

    直し方は `X-Forwarded-For` を見ることだが、**そのヘッダは誰でも自分で
    付けられる。** 直接つないできた相手が信頼する帯域に入っているときだけ
    見ること。ここを緩めると、外から直接叩いてヘッダを偽装するだけで
    別人になりすませる（レート制限もIPで数えている）。
    """

    def setUp(self):
        from services import log_setup

        self.log_setup = log_setup

    def test_the_default_covers_the_docker_bridge_but_not_the_lan(self):
        """既定はループバック＋Docker のブリッジ帯域。LAN は入れないこと。

        ループバックだけでは**足りなかった。** compose 構成では、プロキシから
        見た接続元は Docker のブリッジゲートウェイ（172.19.0.1 など）になる。
        127.0.0.1/32 しか信頼していなかったので uvicorn が X-Forwarded-For を
        捨て、**アクセスログが 172.19.0.1 で埋まっていた**（直す前と同じ状態）。

        LAN でよく使う 192.168/16 と 10/8 は入れない。このアプリはポートを
        公開するので、同じ LAN から直接叩いて偽装できてしまう。
        """
        from uvicorn.middleware.proxy_headers import _TrustedHosts

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRUSTED_PROXY_CIDRS", None)
            allow = self.log_setup.trusted_proxies()

        self.assertNotIn("*", allow)
        hosts = _TrustedHosts(allow)
        self.assertIn("172.19.0.1", hosts)  # Docker のブリッジゲートウェイ
        self.assertIn("172.18.0.5", hosts)  # 同じネットワーク上の別コンテナ
        self.assertIn("127.0.0.1", hosts)
        self.assertNotIn("192.168.1.5", hosts)
        self.assertNotIn("10.1.2.3", hosts)
        self.assertNotIn("8.8.8.8", hosts)

    def test_an_ignored_forwarded_header_says_what_to_add(self):
        """信頼していない相手からのヘッダを捨てたら、1回だけ警告を出すこと。

        **この設定の間違いは、黙って元に戻る形で失敗する。** ヘッダが
        捨てられるだけで例外も出ず、ログにはプロキシのIPが並び続ける。
        実際に「直したはずなのに変わらない」状態になった。何を足せばよいかを
        名指しで出す。

        同じ相手では1回しか出さない。毎リクエスト出すと本当の異常が埋もれる。
        """
        self.log_setup._WARNED_PEERS.clear()
        self.addCleanup(self.log_setup._WARNED_PEERS.clear)

        with self.assertLogs("services.log_setup", level="WARNING") as captured:
            self.log_setup.warn_if_forwarded_ignored("172.19.0.1", "203.0.113.9")
        line = captured.output[0]
        self.assertIn("172.19.0.1", line)
        self.assertIn("TRUSTED_PROXY_CIDRS", line)

        # 2回目は出さない（assertLogs は1行も出ないと落ちる）
        with self.assertRaises(AssertionError):
            with self.assertLogs("services.log_setup", level="WARNING"):
                self.log_setup.warn_if_forwarded_ignored("172.19.0.1", "203.0.113.9")

    def test_no_warning_when_there_is_no_forwarded_header(self):
        """ヘッダが来ていない相手には警告しないこと。

        直に叩いている利用者は普通に居る。**それを毎回「設定が間違って
        いる」と言うと、本当に間違っているときに読まれなくなる。**
        """
        self.log_setup._WARNED_PEERS.clear()
        self.addCleanup(self.log_setup._WARNED_PEERS.clear)

        with self.assertRaises(AssertionError):
            with self.assertLogs("services.log_setup", level="WARNING"):
                self.log_setup.warn_if_forwarded_ignored("203.0.113.9", None)

    def test_the_same_env_var_as_the_rate_limiter_is_used(self):
        """レート制限と同じ環境変数を読むこと。

        片方だけ広げると、**レート制限とアクセスログが別のIPを見る**。
        どちらが本当の接続元なのか、後から突き合わせられなくなる。
        """
        from webapp.security import load_trusted_proxy_cidrs

        with patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}):
            self.assertEqual(self.log_setup.trusted_proxies(), "10.0.0.0/8")
            self.assertEqual(load_trusted_proxy_cidrs(), ["10.0.0.0/8"])

    def test_an_empty_setting_still_trusts_something_concrete(self):
        """空文字を渡されても `*` にはしないこと。

        「誰も信頼しない」つもりの空指定が「全員を信頼する」に化けると、
        設定を厳しくしたつもりが**いちばん緩い状態**になる。
        """
        with patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "   "}):
            allow = self.log_setup.trusted_proxies()

        self.assertEqual(allow, "127.0.0.1")

    def test_uvicorn_accepts_the_cidr_form(self):
        """uvicorn 側が、CIDR の書き方をそのまま受け取れること。

        `forwarded_allow_ips` に IP しか書けない版だと、`10.0.0.0/8` は
        「そういう名前のホスト」として扱われて**一致しなくなる**。
        黙って全部のヘッダが捨てられ、また 127.0.0.1 に戻る。
        """
        from uvicorn.middleware.proxy_headers import _TrustedHosts

        hosts = _TrustedHosts(self.log_setup.trusted_proxies())
        self.assertIn("127.0.0.1", hosts)

        with patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}):
            hosts = _TrustedHosts(self.log_setup.trusted_proxies())
        self.assertIn("10.1.2.3", hosts)
        self.assertNotIn("192.0.2.1", hosts)

    def test_every_web_facing_entry_point_turns_proxy_headers_on(self):
        """3つの入口すべてで proxy_headers を有効にしていること。

        1つでも忘れると、そのプロセスのログだけ 127.0.0.1 のまま残る。
        入口は独立したファイルなので、片方を直したときにもう片方を
        忘れやすい。原文を読んで確かめる。
        """
        for name in ("admin_main.py", "cdn_main.py", "web_main.py"):
            with self.subTest(entry=name):
                lines = Path(name).read_text(encoding="utf-8").splitlines()
                # コメントは落とす。「以前はこう書いていた」という説明が
                # 本文と同じ扱いになると、直した証拠が読めなくなる。
                source = chr(10).join(line for line in lines if not line.lstrip().startswith("#"))
                self.assertIn("proxy_headers=True", source)
                self.assertIn("forwarded_allow_ips=allow", source)
                self.assertIn("trusted_proxies()", source)
                self.assertNotIn('forwarded_allow_ips="*"', source)


class LogRetentionTests(unittest.TestCase):
    """ログを日付で回して10年保管すること。

    以前は 1MB × 4世代のサイズ回転で、**混んだ日は半日ぶんも残らなかった。**
    落ちた原因を翌日調べようとしても、そのころにはもう流れている。

      - 日付で回すこと（サイズではなく）
      - 既定で 3,650 日ぶん保管すること
      - 回したファイルを gzip で畳むこと
      - **畳んだ名前と、掃除が探す名前が一致すること**
      - 同じファイルへ二重にハンドラを付けないこと

    4つ目が要。畳んだ結果が `bot.log.2026-09-03.gz` なのに掃除が
    `bot.log.2026-09-03` を探すと、**1件も見つからず10年ぶんが永久に残る。**
    ディスクが埋まるまで誰も気づかない。
    """

    def setUp(self):
        from services import log_setup

        self.log_setup = log_setup
        self.dir = Path(tempfile.mkdtemp(prefix="logtest-"))
        self._root_handlers = list(logging.getLogger().handlers)
        self.addCleanup(self._restore)

    def _restore(self):
        """テストで足したハンドラを外す。残すと以後のテストの出力が混ざる。"""
        root = logging.getLogger()
        for handler in list(root.handlers):
            if handler not in self._root_handlers:
                handler.close()
                root.removeHandler(handler)

    def _installed(self):
        """いま足したハンドラを取り出す。"""
        from logging.handlers import TimedRotatingFileHandler

        root = logging.getLogger()
        return [h for h in root.handlers if isinstance(h, TimedRotatingFileHandler)][-1]

    def test_the_log_rolls_by_date_and_keeps_ten_years(self):
        """日付で回し、既定で 3,650 世代を保つこと。

        サイズで回すと、混んだ日ほど短い期間しか残らない。**いちばん
        調べたい日のログが、いちばん先に消える。**
        """
        from logging.handlers import TimedRotatingFileHandler

        path = self.log_setup.install_file_logging(self.dir, "bot.log")
        handler = self._installed()

        self.assertEqual(path, self.dir / "bot.log")
        self.assertIsInstance(handler, TimedRotatingFileHandler)
        self.assertEqual(handler.when, "MIDNIGHT")
        self.assertEqual(handler.backupCount, 3650)

    def test_the_retention_can_be_shortened_by_env(self):
        """LOG_RETENTION_DAYS で日数を変えられること。"""
        with patch.dict(os.environ, {"LOG_RETENTION_DAYS": "30"}):
            self.log_setup.install_file_logging(self.dir, "bot.log")

        self.assertEqual(self._installed().backupCount, 30)

    def test_a_rolled_file_is_gzipped_and_the_live_one_is_not(self):
        """回したファイルは畳み、いま書いているものは畳まないこと。

        いま書いているファイルまで畳むと `tail -f` で追えなくなる。
        """
        self.log_setup.install_file_logging(self.dir, "bot.log")
        handler = self._installed()
        # root の既定は WARNING。INFO を落とすには logger 側も開けておく。
        writer = logging.getLogger("logtest")
        writer.setLevel(logging.INFO)
        self.addCleanup(writer.setLevel, logging.NOTSET)
        writer.info("いちにち目")
        handler.doRollover()
        writer.info("ふつか目")
        handler.flush()

        packed = sorted(self.dir.glob("bot.log.*.gz"))
        self.assertEqual(len(packed), 1, sorted(p.name for p in self.dir.iterdir()))
        self.assertIn("いちにち目", gzip.open(packed[0], "rt", encoding="utf-8").read())
        # 素のまま残っていないこと（畳んだあとに元を消している）
        self.assertEqual(sorted(p.name for p in self.dir.glob("bot.log.2*") if p.suffix != ".gz"), [])
        self.assertIn("ふつか目", (self.dir / "bot.log").read_text(encoding="utf-8"))

    def test_the_cleanup_finds_the_gzipped_files(self):
        """掃除が、畳んだファイルを見つけられること。

        `getFilesToDelete()` は「namer が付けた名前」でディスクを探す。
        畳んだ結果が `.gz` なのに namer が `.gz` を返さないと、**1件も
        見つからず、保管日数を過ぎても消えない。** ディスクが埋まるまで
        誰も気づかない。
        """
        with patch.dict(os.environ, {"LOG_RETENTION_DAYS": "1"}):
            self.log_setup.install_file_logging(self.dir, "bot.log")
        handler = self._installed()

        for day in ("2026-09-01", "2026-09-02", "2026-09-03"):
            with gzip.open(self.dir / f"bot.log.{day}.gz", "wt", encoding="utf-8") as f:
                f.write("古いログ\n")

        doomed = [Path(p).name for p in handler.getFilesToDelete()]
        self.assertEqual(doomed, ["bot.log.2026-09-01.gz", "bot.log.2026-09-02.gz"], doomed)

    def test_installing_twice_does_not_double_up(self):
        """同じファイルへ2回入れても、ハンドラは1つのままであること。

        二重に付くと**同じ行が2度書かれる。** uvicorn の reload や、
        テストでの再 import で実際に起きる。
        """
        from logging.handlers import TimedRotatingFileHandler

        self.log_setup.install_file_logging(self.dir, "bot.log")
        self.log_setup.install_file_logging(self.dir, "bot.log")

        root = logging.getLogger()
        mine = [
            h
            for h in root.handlers
            if isinstance(h, TimedRotatingFileHandler) and Path(h.baseFilename).parent == self.dir
        ]
        self.assertEqual(len(mine), 1)


class LogCategoryTests(unittest.TestCase):
    """ログ1行ごとに「どの機能から出たか」が分かること。

    以前は分類が各ファイルの手打ち接頭辞だけで、**同じ機能が別名で出ていた**
    （`[SECURITY]` と `[security]`、`[TTS]` と `[tts_service]`、`[BOT]` と
    `[BOT_SETUP]`）。カテゴリで絞る画面を作っても、片方しか引っかからない。

    ここで固定するのは3つ。

      - ロガー名（＝モジュール名）から機械的に引くこと。呼び出し側は書かない
      - 長い接頭辞が勝つこと（`services.djaudio_cdn` は djaudio ではなく cdn）
      - **リポジトリ内の全ロガーが、どれかのカテゴリに入ること**

    3つ目が要。新しいモジュールを足したとき、分類表への追加を忘れると
    そのモジュールのログだけ静かに `other` へ落ちる。カテゴリで絞って
    見ている運用者からは、**そのログは存在しないのと同じになる。**
    """

    def setUp(self):
        from services import log_setup

        self.log_setup = log_setup

    def test_the_category_comes_from_the_module_name(self):
        """呼び出し側が何も書かなくても、モジュール名から分類されること。"""
        self.assertEqual(self.log_setup.category_for("services.tts_service"), "tts")
        self.assertEqual(self.log_setup.category_for("events.voice"), "voice")
        self.assertEqual(self.log_setup.category_for("webapp_admin.app"), "admin")

    def test_the_longest_prefix_wins(self):
        """系列の中の例外を、長い接頭辞で拾えること。

        `services.djaudio_cdn` は名前こそ djaudio 系列だが、動いている
        プロセスは CDN。`services.djaudio` が先に当たると、**配信の障害を
        DJAudio のカテゴリで探すことになる。**
        """
        self.assertEqual(self.log_setup.category_for("services.djaudio_service"), "djaudio")
        self.assertEqual(self.log_setup.category_for("services.djaudio_cdn"), "cdn")

    def test_an_unknown_logger_falls_to_other(self):
        """表に無いロガーは other になること（それらしい名前を名乗らせない）。"""
        self.assertEqual(self.log_setup.category_for("some.third.party"), self.log_setup.DEFAULT_CATEGORY)

    def test_every_logger_in_the_repository_is_categorised(self):
        """本体の全モジュールが分類表に載っていること。

        載っていないと、そのモジュールのログはカテゴリで絞る画面から
        消える。**「足したのに出てこない」は、原因を追うのがいちばん
        難しい壊れ方**なので、ここで機械的に止める。

        失敗したときは services/log_setup.py の CATEGORY_RULES へ足すこと。
        """
        root = Path(__file__).resolve().parent.parent
        skip = {"tests", "tools", "migrations", "scripts", ".venv", "venv", "__pycache__"}
        uncategorised = []
        for path in root.rglob("*.py"):
            parts = path.relative_to(root).with_suffix("").parts
            if skip & set(parts):
                continue
            if "getLogger(__name__)" not in path.read_text(encoding="utf-8", errors="replace"):
                continue
            name = ".".join(part for part in parts if part != "__init__")
            if self.log_setup.category_for(name) == self.log_setup.DEFAULT_CATEGORY:
                uncategorised.append(name)
        self.assertEqual(uncategorised, [], f"CATEGORY_RULES に無いモジュール: {uncategorised}")

    def test_the_text_format_carries_the_category(self):
        """テキストログの各行にカテゴリが入ること。

        端末から grep でカテゴリを絞れるかどうかがここで決まる。整形器では
        なく Filter で付けると、**親ロガーへ伝播した記録には掛からず**、
        `%(category)s` が KeyError になって行ごと消える。
        """
        record = logging.LogRecord("services.tts_service", logging.INFO, "f.py", 1, "読み上げ開始", None, None)
        formatted = self.log_setup.CategoryFormatter(self.log_setup.LOG_FORMAT).format(record)
        self.assertIn("[tts]", formatted)
        self.assertIn("読み上げ開始", formatted)


class StructuredLogTests(unittest.TestCase):
    """管理画面が絞り込むための JSONL を、テキストと並べて書くこと。

    テキストを正規表現で割る方式は、**本文に改行が入った瞬間に崩れる。**
    例外のスタックトレースは必ず改行を含むので、「レベルで色を分ける」
    程度でも既に破綻していた。カテゴリで絞る・期間で切る・本文を検索する、
    のどれもが構造を要求するため、最初から構造で書き出す。

    固定するのは、

      - 1件が必ず1行に収まること（例外を含んでいても）
      - JSON にできない extra を捨てても、**ログ自体は消えないこと**
      - テキストと JSONL の両方へ、同じ1件が届くこと
      - 回し方・保管日数がテキストと同じであること
    """

    def setUp(self):
        from services import log_setup

        self.log_setup = log_setup
        self.dir = Path(tempfile.mkdtemp(prefix="jsonl-test-"))
        self._root_handlers = list(logging.getLogger().handlers)
        self.writer = logging.getLogger("services.tts_service")
        self.writer.setLevel(logging.INFO)
        self.addCleanup(self.writer.setLevel, logging.NOTSET)
        self.addCleanup(self._restore)

    def _restore(self):
        """テストで足したハンドラを外す。残すと以後のテストの出力が混ざる。"""
        root = logging.getLogger()
        for handler in list(root.handlers):
            if handler not in self._root_handlers:
                handler.close()
                root.removeHandler(handler)

    def _rows(self, filename="bot.jsonl"):
        """書き出した JSONL を読んで、辞書の一覧にする。"""
        text = (self.dir / filename).read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line]

    def test_one_event_is_one_line_even_with_a_traceback(self):
        """例外を含む1件が、改行で割れず1行に収まること。

        ここが崩れると、管理画面は1件を複数件として数え、しかも**割れた
        断片は JSON として読めないので捨てられる**——例外だけが一覧から
        消えるという、いちばん困る形で壊れる。
        """
        self.log_setup.install_structured_logging(self.dir, "bot.jsonl")
        try:
            raise ValueError("書き出しに失敗")
        except ValueError:
            self.writer.exception("音声を合成できませんでした")

        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["category"], "tts")
        self.assertEqual(rows[0]["level"], "ERROR")
        self.assertIn("ValueError: 書き出しに失敗", rows[0]["exc"])
        self.assertIn("\n", rows[0]["exc"])

    def test_extra_values_that_cannot_be_json_are_dropped_without_losing_the_line(self):
        """JSON にできない extra があっても、その1件は書かれること。

        任意のオブジェクトを json.dumps へ渡すと TypeError になり、logging は
        それを握りつぶして標準エラーへ吐くだけ——**ログの行は消える。**
        載せられない値だけ捨てて、記録そのものは残す。
        """
        self.log_setup.install_structured_logging(self.dir, "bot.jsonl")
        self.writer.info("開始", extra={"guild_id": 42, "sink": object()})

        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["guild_id"], 42)
        self.assertNotIn("sink", rows[0])

    def test_the_text_log_and_the_jsonl_get_the_same_event(self):
        """端末から読むテキストと、画面が絞る JSONL の両方へ届くこと。

        片方に寄せると、障害のときに端末から素早く読む手段か、カテゴリで
        絞る手段のどちらかが無くなる。
        """
        self.log_setup.install_file_logging(self.dir, "bot.log")
        self.log_setup.install_structured_logging(self.dir, "bot.jsonl")
        self.writer.info("読み上げを開始しました")

        self.assertIn("[tts]", (self.dir / "bot.log").read_text(encoding="utf-8"))
        self.assertEqual(self._rows()[0]["message"], "読み上げを開始しました")

    def test_the_jsonl_rolls_and_is_gzipped_like_the_text_log(self):
        """JSONL もテキストと同じ条件で回り、畳まれること。

        保管日数や畳み方を別々に持つと、**テキストには残っているのに JSON
        には無い日**ができ、端末と画面で見える範囲が食い違う。
        """
        from logging.handlers import TimedRotatingFileHandler

        with patch.dict(os.environ, {"LOG_RETENTION_DAYS": "30"}):
            self.log_setup.install_structured_logging(self.dir, "bot.jsonl")
        handler = [h for h in logging.getLogger().handlers if isinstance(h, TimedRotatingFileHandler)][-1]

        self.assertEqual(handler.backupCount, 30)
        self.writer.info("いちにち目")
        handler.doRollover()
        self.writer.info("ふつか目")
        handler.flush()

        packed = sorted(self.dir.glob("bot.jsonl.*.gz"))
        self.assertEqual(len(packed), 1, sorted(p.name for p in self.dir.iterdir()))
        self.assertIn("いちにち目", gzip.open(packed[0], "rt", encoding="utf-8").read())
        self.assertEqual(self._rows()[0]["message"], "ふつか目")


class LoopStallWatchdogTests(unittest.TestCase):
    """イベントループが止まったとき、止めている場所が名指しで残ること。

    「たまにえらく重い」は**再現しないので静的解析では追えない。** 実際、
    配信キャッシュの掃除が 60 秒ごとにループを 600ms 止めていた件は、async
    関数の本体を構文木で走査しても引っかからなかった（`for ...: path.open()`
    という形で、「await の付いていない重い呼び出し」という分類に入らない）。
    定期実行の中身を1つずつ読んで、ようやく見つかっている。

    同じものが他にもある前提で、次に起きたときは本番が自分で名乗るようにする。
    ここで固定するのは、

      - 止まったことに気づき、**止めている関数名がスタックに出ること**
      - 同じ場所で止まり続けているなら、警告が1行だけ出ること
        （気づくたび書くとログが埋まる）
      - **場所が移った停止では、移った先も出ること**（1本のスタックでは
        足りない停止がある。下の docstring を参照）
      - スタックにアプリの行が無い停止で、通信の相手が名指しされること
      - 解けたときに、実際に何 ms 止まっていたかが出ること
      - 環境変数で切れること
      - 二重に仕掛からないこと（on_ready は再接続のたびに呼ばれる）
    """

    def setUp(self):
        from services import loop_watchdog

        self.wd = loop_watchdog
        # 先に畳んでから始める。**見張りはモジュール変数で「もう仕掛かって
        # いる」を覚えている**ので、別のテストファイルが on_ready を通すと
        # （tests/test_events_handlers.py がそうする）ここでの install() が
        # 何もせずに False を返し、単体では通るのに全体では落ちる。
        self.wd.shutdown()
        self.addCleanup(self.wd.shutdown)

    def _run_with_stall(self, stall_sec, warn_ms="100", check_ms="20"):
        """見張りを入れ、わざと stall_sec 秒止めて、出たログを返す。"""

        async def scenario():
            self.wd.install()
            await asyncio.sleep(0.08)
            self._the_blocking_call(stall_sec)
            await asyncio.sleep(0.25)

        with patch.dict(os.environ, {"LOOP_STALL_WARN_MS": warn_ms, "LOOP_STALL_CHECK_MS": check_ms}):
            with self.assertLogs(self.wd.logger, level="INFO") as captured:
                asyncio.run(scenario())
        return captured.output

    @staticmethod
    def _the_blocking_call(seconds):
        """イベントループを止める張本人。この名前がログに出てほしい。"""
        time.sleep(seconds)

    @staticmethod
    def _the_other_blocking_call(seconds):
        """1回の停止のうち、後半を止める張本人。こちらも出てほしい。"""
        time.sleep(seconds)

    def test_it_names_the_function_that_is_blocking_the_loop(self):
        """「遅い」ではなく「どの行で止まっているか」が出ること。

        所要時間だけ出しても、**どこを直せばよいか分からない。** 停止中に
        ループのスレッドのスタックを取れているかどうかがここで決まる。
        """
        output = self._run_with_stall(0.5)
        stalls = [line for line in output if "止まっています" in line]

        self.assertEqual(len(stalls), 1, output)
        self.assertIn("_the_blocking_call", stalls[0])
        self.assertIn("time.sleep(seconds)", stalls[0])

    def test_one_stall_produces_one_warning(self):
        """1回の停止で、警告が1行だけ出ること。

        見張りは 20ms ごとに起きる。気づくたびに書くと 500ms の停止で
        20行以上並び、**本当に知りたい最初の1行が埋もれる。**
        """
        output = self._run_with_stall(0.5)

        self.assertEqual(len([line for line in output if "止まっています" in line]), 1, output)

    def test_a_stall_that_stays_put_is_still_one_line(self):
        """同じところで止まり続けているなら、書き足さないこと。

        場所が変わったら書き足す仕組みを入れた以上、**変わっていないのに
        書き足さない**ことを押さえないと、20ms ごとの追記でログが埋まる。
        """
        output = self._run_with_stall(0.5)

        self.assertEqual([line for line in output if "今度はここにいます" in line], [], output)

    def test_a_stall_that_moves_gets_a_second_stack(self):
        """1回の停止のうちに場所が移ったら、移った先も残ること。

        本番の 1016ms の停止は、いちばん深いところが asyncio の TLS 読み出し
        で、アプリのフレームが1行も無かった。**この形は「1つの呼び出しが
        長い」のではなく「短いコールバックが切れ目なく続く」ことが多く、
        1本のスタックはくじ引きにしかならない。**

        止める場所を途中で変えて、2本目が出ることを見る。1本しか取らない
        実装へ戻すと、後半の名前がどこにも出なくなる。
        """

        async def scenario():
            self.wd.install()
            await asyncio.sleep(0.08)
            self._the_blocking_call(0.4)
            self._the_other_blocking_call(0.3)
            await asyncio.sleep(0.25)

        with patch.dict(os.environ, {"LOOP_STALL_WARN_MS": "100", "LOOP_STALL_CHECK_MS": "20"}):
            with self.assertLogs(self.wd.logger, level="INFO") as captured:
                asyncio.run(scenario())

        first = [line for line in captured.output if "止まっています" in line]
        extra = [line for line in captured.output if "今度はここにいます" in line]
        self.assertEqual(len(first), 1, captured.output)
        self.assertGreaterEqual(len(extra), 1, captured.output)
        named = " ".join(first + extra)
        self.assertIn("_the_blocking_call", named)
        self.assertIn("_the_other_blocking_call", named)

    def test_it_names_the_connection_when_the_stack_has_no_app_frame(self):
        """スタックが asyncio の内部で終わる停止で、通信の相手が出ること。

        本番で 1016ms 止まったとき、残ったのは sslproto の `_do_read` までで、
        **どの接続の話なのかが分からなかった。** 行番号からは何も決まらない
        ので、内部フレームの self から相手を引き出す。
        """

        class _FakeSSLProtocol:
            """asyncio の SSLProtocol が、読み出し中に持っている形。"""

            def __init__(self):
                self._sslobj = SimpleNamespace(server_hostname="cdn.example.com")
                self._transport = SimpleNamespace(
                    get_extra_info=lambda key: ("203.0.113.9", 443) if key == "peername" else None
                )
                self._app_protocol = SimpleNamespace(_payload=SimpleNamespace(total_bytes=6 * 1024 * 1024))

        def _do_read(self, probe):
            """フレームが生きているうちに覗かせる（抜けると局所変数が消える）。"""
            return probe(sys._getframe())

        described = _do_read(_FakeSSLProtocol(), self.wd._peer_of)
        self.assertIn("cdn.example.com", described)
        self.assertIn("203.0.113.9:443", described)
        self.assertIn("6144 KB", described)

        # 通信と関係のない停止に、ありもしない相手を書かないこと
        self.assertEqual(self.wd._peer_of(sys._getframe()), "")

        # 見つけた相手が、実際に停止のログへ載ること（繋ぎ忘れの検査）
        with patch.object(self.wd, "_peer_of", return_value="cdn.example.com / 203.0.113.9:443"):
            output = self._run_with_stall(0.4)
        stalls = [line for line in output if "止まっています" in line]
        self.assertEqual(len(stalls), 1, output)
        self.assertIn("相手: cdn.example.com / 203.0.113.9:443", stalls[0])

    def test_the_asyncio_attributes_it_reads_still_exist(self):
        """覗いている属性名が asyncio 側で変わっていないこと。

        偽物で組んだ検査は、**名前が変わった瞬間に嘘をつく**（偽物の方は
        変わらないので緑のまま）。本物の原文に名前があることを確かめる。
        """
        import asyncio.selector_events
        import asyncio.sslproto
        import inspect

        ssl_source = inspect.getsource(asyncio.sslproto.SSLProtocol)
        for name in ("_sslobj", "_transport", "_app_protocol"):
            self.assertIn(f"self.{name}", ssl_source, name)

        transport_source = inspect.getsource(asyncio.selector_events._SelectorTransport)
        self.assertIn("self._sock", transport_source)
        self.assertIn("self._protocol", transport_source)

    def test_the_total_duration_is_reported_when_it_recovers(self):
        """解けたときに、実際の停止時間が出ること。

        最初の警告に出せるのは「しきい値を超えた時点までの時間」だけで、
        **本当に何 ms 止まったかは解けるまで分からない。** 500ms 止めた
        ものが 100ms と記録されると、影響の大きさを読み違える。
        """
        output = self._run_with_stall(0.5)
        recovered = [line for line in output if "解けました" in line]

        self.assertEqual(len(recovered), 1, output)
        milliseconds = int(re.search(r"（約 (\d+) ms）", recovered[0]).group(1))
        self.assertGreater(milliseconds, 300, recovered[0])

    def test_it_can_be_switched_off(self):
        """LOOP_STALL_WARN_MS=0 で仕掛からないこと。

        停止が常態化している環境では警告がログを埋め尽くしうる。直すべきは
        停止の方だが、直すまでのあいだログを読めなくすると**直すための情報
        まで失う。**
        """

        async def scenario():
            return self.wd.install()

        with patch.dict(os.environ, {"LOOP_STALL_WARN_MS": "0"}):
            self.assertFalse(asyncio.run(scenario()))

    def test_installing_twice_does_not_add_a_second_watchdog(self):
        """二重に仕掛からないこと。

        on_ready は**再接続のたびに**呼ばれる。素通しにすると、切断が
        起きるたびに見張りスレッドと心拍タスクが増えていく。
        """
        before = threading.active_count()

        async def scenario():
            first = self.wd.install()
            second = self.wd.install()
            return first, second

        with patch.dict(os.environ, {"LOOP_STALL_WARN_MS": "100", "LOOP_STALL_CHECK_MS": "20"}):
            first, second = asyncio.run(scenario())

        self.assertTrue(first)
        self.assertFalse(second)
        self.assertLessEqual(threading.active_count() - before, 1)

    def test_a_quiet_loop_produces_no_warning(self):
        """止まっていないときは何も出さないこと。

        誤検知が出ると、**本物の停止を見ても信じなくなる。**
        """

        async def scenario():
            self.wd.install()
            await asyncio.sleep(0.4)

        with patch.dict(os.environ, {"LOOP_STALL_WARN_MS": "100", "LOOP_STALL_CHECK_MS": "20"}):
            with self.assertLogs(self.wd.logger, level="INFO") as captured:
                asyncio.run(scenario())

        self.assertEqual([line for line in captured.output if "止まっています" in line], [], captured.output)


class EarthquakeTileDecodeTests(unittest.TestCase):
    """地図タイルの復号が、イベントループの上で行われていないこと。

    地図の合成（塗り替え・描画・PNG 保存）は最初からスレッドへ逃がしてあった
    のに、**タイルの復号だけが取得側に残っていた。** `Image.open` 自体は
    ヘッダを読むだけだが、続く `convert("L")` が全画素を復号する。1枚 0.40ms、
    1枚の地図は 6x4 = 24 枚で 8.2ms。しかも並行取得した全枚数ぶんが、
    **緊急地震速報を全ギルドへ配信しようとしているまさにその瞬間**に固まって
    走る。余震が続けば短時間に何度も起きる。

    復号を _paste_tiles（既にスレッドの向こう側）へ移した。

    ここで固定するのは、

      - 取得側が復号しないこと（バイト列のまま返す）
      - 貼る側がバイト列を復号して、**実際に地図へ反映すること**
      - 壊れた1枚で地図ごと落ちないこと

    2つ目が要。取り違えて全枚数を捨てるようにしても、**地図は海色のまま
    出来上がるので例外は出ない。** 既存の地図テストはタイル無し（[None]）で
    描いているため、全部通ってしまう。
    """

    def setUp(self):
        import services.earthquake_service as eq

        self.eq = eq

    def _tile_png(self, line_value=0):
        """白地図タイル相当（白い面に黒い線）の PNG バイト列。"""
        from PIL import Image

        tile = Image.new("L", (self.eq._TILE_SZ, self.eq._TILE_SZ), 255)
        for i in range(self.eq._TILE_SZ):
            tile.putpixel((0, i), line_value)
        buf = io.BytesIO()
        tile.convert("RGB").save(buf, format="PNG")
        return buf.getvalue()

    def test_the_fetcher_does_not_decode(self):
        """取得側が Image を作らないこと。

        構文木で見る。ここに `convert` が戻ると、**戻ったこと自体は何も
        壊さない**（型が違うだけで _paste_tiles が黙って捨てる）ので、
        地図が海色になるまで誰も気づかない。
        """
        root = Path(__file__).resolve().parent.parent
        tree = ast.parse((root / "services/earthquake_service.py").read_text(encoding="utf-8"))
        fetch = next(
            node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == "_fetch_tile"
        )
        names = {
            inner.func.attr if isinstance(inner.func, ast.Attribute) else getattr(inner.func, "id", "")
            for inner in ast.walk(fetch)
            if isinstance(inner, ast.Call)
        }

        self.assertNotIn("convert", names)
        self.assertNotIn("open", names)

    def test_the_paster_decodes_the_bytes_and_paints_them(self):
        """貼る側がバイト列を復号し、地図に反映すること。

        海色のままでないこと＝タイルが本当に貼られたこと。
        """
        raw = self._tile_png()
        image = self.eq._paste_tiles([(0, 0)], [raw], 0.0, 0.0)

        # 白い面は陸の色へ、線は線の色へ塗り替わる
        self.assertEqual(image.getpixel((10, 10)), self.eq._MAP_LAND)
        self.assertEqual(image.getpixel((0, 10)), self.eq._MAP_LINE)

    def test_a_missing_tile_leaves_the_sea_colour(self):
        """取れなかった枚は、その枡が海色のまま残ること。"""
        image = self.eq._paste_tiles([(0, 0)], [None], 0.0, 0.0)

        self.assertEqual(image.getpixel((10, 10)), self.eq._MAP_SEA)

    def test_a_broken_tile_does_not_take_the_whole_map_down(self):
        """壊れた1枚があっても、他の枚は貼られること。

        以前は復号が取得側の try/except の中にあったので、壊れたタイルは
        そこで None になっていた。復号を移したぶん、**移した先で握らないと
        地図の生成ごと落ちる。**
        """
        good = self._tile_png()
        image = self.eq._paste_tiles(
            [(0, 0), (1, 0)],
            ["PNG ではない壊れたバイト列".encode("utf-8"), good],
            0.0,
            0.0,
        )

        # 壊れた枡は海色、隣の正しい枡は陸色
        self.assertEqual(image.getpixel((10, 10)), self.eq._MAP_SEA)
        self.assertEqual(image.getpixel((self.eq._TILE_SZ + 10, 10)), self.eq._MAP_LAND)

    def test_an_exception_from_gather_is_skipped(self):
        """gather(return_exceptions=True) が混ぜてくる例外を飛ばせること。

        タイル取得は例外をそのまま並びへ入れる作りなので、貼る側は
        バイト列以外を必ず素通りしなければならない。
        """
        image = self.eq._paste_tiles([(0, 0)], [RuntimeError("取得に失敗")], 0.0, 0.0)

        self.assertEqual(image.getpixel((10, 10)), self.eq._MAP_SEA)


class NotifyAllGuildsTests(unittest.TestCase):
    """通知の組み立て順と、失敗の握り方を固定する。

    114行ある _notify_all_guilds を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    直接の既存テストは「震度不明ならバッジを作らない」1本だけだった。

      - 送信先が0件なら、リンクもバッジも地図も作らずに返すこと
      - バッジ・地図の生成が落ちても、通知そのものは出すこと
      - 地図を貼るときは embed 側にも画像を差すこと
      - 0件の警告は only_guild_id 指定のときだけ出すこと

    1つ目が崩れると、**誰も受け取らない地震のたびにタイル25枚を取りに行く。**
    地震は1日に何度も来るので、そのぶんの通信と描画が丸ごと無駄になる。
    例外は出ず、通知の中身も変わらないので、外から見て気づく手立てが無い。
    """

    def setUp(self):
        self.channel = text_channel()
        self.bot = bot_with(guild_with(self.channel))

    def _patched(self, stack, *, targets=True, badge=None, quake_map=None):
        """外の重い処理を全部差し替え、呼ばれたかどうかを控える。"""
        called = {"jma": 0, "badge": 0, "map": 0}

        async def jma(event, scale):
            """JMA 詳細リンクの解決。"""
            called["jma"] += 1
            return "https://example.invalid/jma"

        def generate_badge(scale):
            """バッジの生成。"""
            called["badge"] += 1
            if isinstance(badge, Exception):
                raise badge
            return io.BytesIO(b"badge")

        async def generate_map(session, lat, lon, points, title, subtitle):
            """震度マップの生成。"""
            called["map"] += 1
            if isinstance(quake_map, Exception):
                raise quake_map
            return io.BytesIO(b"map")

        settings = {"channel_id": 555, "min_scale": -1} if targets else {}
        stack.enter_context(patch.object(eq, "_resolve_jma_detail_url", jma))
        stack.enter_context(patch.object(eq, "_generate_badge", generate_badge))
        stack.enter_context(patch.object(eq, "_generate_intensity_map", generate_map))
        stack.enter_context(patch.object(eq, "get_all_guild_ids", lambda: [1]))
        stack.enter_context(patch.object(eq, "get_earthquake_settings", lambda g: settings))
        stack.enter_context(patch.object(eq, "get_earthquake_notify_types", lambda g: {}))
        stack.enter_context(patch.object(eq.aiohttp, "ClientSession", _NullSession))
        sent = stack.enter_context(patch.object(eq, "_dispatch", AsyncMock(return_value=1)))
        return called, sent

    def test_nothing_heavy_runs_when_no_one_would_receive_it(self):
        """送信先が0件なら、リンクもバッジも地図も作らずに返すこと。

        以前は JMA 詳細リンクの取得・バッジ生成・震度マップ生成
        （タイル25枚のHTTP取得）を対象判定より先に走らせていた。**誰も
        受け取らない地震でも毎回そのぶんの通信と描画が発生していた。**
        地震は1日に何度も来る。
        """
        with contextlib.ExitStack() as stack:
            called, sent = self._patched(stack, targets=False)
            count = asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551))

        self.assertEqual(count, 0)
        self.assertEqual(called, {"jma": 0, "badge": 0, "map": 0})
        sent.assert_not_awaited()

    def test_a_failed_badge_does_not_stop_the_notification(self):
        """バッジ生成が落ちても、通知そのものは出すこと。

        画像が1枚足りないだけで**地震の通知が丸ごと消える**のは割に合わない。
        落ちるのは PIL 側の都合なので、平常時のテストでは再現しない。
        """
        with contextlib.ExitStack() as stack:
            _, sent = self._patched(stack, badge=RuntimeError("PILが落ちた"))
            stack.enter_context(self.assertLogs(eq.logger, level="ERROR"))
            count = asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551))

        self.assertEqual(count, 1)
        names = [name for name, _ in sent.call_args.kwargs["attachments"]]
        self.assertNotIn("intensity_badge.png", names)

    def test_a_failed_map_does_not_stop_the_notification(self):
        """地図生成が落ちても、通知そのものは出すこと。

        地図はタイル25枚の取得を伴うので、外の都合で落ちる余地が最も大きい。
        ここで例外が抜けると、**取りに行けなかった日は通知が全部消える。**
        """
        with contextlib.ExitStack() as stack:
            _, sent = self._patched(stack, quake_map=RuntimeError("タイルが取れない"))
            stack.enter_context(self.assertLogs(eq.logger, level="ERROR"))
            count = asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551))

        self.assertEqual(count, 1)
        names = [name for name, _ in sent.call_args.kwargs["attachments"]]
        self.assertEqual(names, ["intensity_badge.png"])

    def test_the_map_is_attached_and_shown_in_the_embed(self):
        """地図を添えるときは、embed 側にも画像を差すこと。

        添付だけして set_image を忘れると、**ファイルは付いているのに
        埋め込みには出ない。** 送信は成功するので、見た人が「地図が無い」
        と言うまで分からない。
        """
        with contextlib.ExitStack() as stack:
            _, sent = self._patched(stack)
            asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551))

        kwargs = sent.call_args.kwargs
        names = [name for name, _ in kwargs["attachments"]]
        self.assertEqual(names, ["intensity_badge.png", "earthquake_map.png"])
        self.assertEqual(kwargs["embed"].image.url, "attachment://earthquake_map.png")

    def test_an_empty_replay_says_why_nothing_was_sent(self):
        """開発者パネルのリプレイで0件なら、理由をログに残すこと。

        押した側には「受信・完了」のログしか見えず、何も届かない理由が
        分からない。**全ギルド一斉（本番の WS 経由）では毎回ほぼ全ギルドが
        対象外になるのが通常**なので、そちらでは出さない。
        """
        with contextlib.ExitStack() as stack:
            self._patched(stack, targets=False)
            captured = stack.enter_context(self.assertLogs(eq.logger, level="WARNING"))
            asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551, only_guild_id=1))

        self.assertTrue(any("送信先が0件" in line for line in captured.output), captured.output)

    def test_a_broadcast_with_no_targets_stays_quiet(self):
        """全ギルド一斉で0件のときは、警告を出さないこと。

        ほとんどの地震はほとんどのギルドの閾値を下回る。毎回警告を出すと
        **ログが警告で埋まり、本当の異常が見えなくなる。**
        """
        with contextlib.ExitStack() as stack:
            self._patched(stack, targets=False)
            with self.assertRaises(AssertionError):
                # 1行も出ないことを、assertLogs が空で落ちることで見る
                with self.assertLogs(eq.logger, level="WARNING"):
                    asyncio.run(eq._notify_all_guilds(self.bot, QUAKE_551))


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

    def _box(self, name):
        """地名ラベルの寸法。_label_box は版（canvas）から字の幅を測るので、
        測るためだけの小さな版を渡す（描画には使わない）。
        """
        from PIL import Image

        return eq._label_box(Image.new("RGBA", (8, 8)), name)

    def _labels_of(self, plot, lat, lon, *, zoom=9, centre=None):
        """地名ラベルの置き場所を控えながら描く。[(x, y, 名前), ...] を返す。

        画像から文字の位置を読み取るのは難しいので、描画の直前を捕まえる。
        """
        placed = []

        def record(canvas, x, y, name):
            """_draw_place_label の代わり。位置と名前だけ控える。"""
            placed.append((x, y, name))

        with patch.object(eq, "_draw_place_label", record):
            self._render(plot, lat, lon, zoom=zoom, centre=centre)
        return placed

    def test_a_point_whose_badge_was_dropped_gets_no_name(self):
        """札が置けなかった点に、地名だけを出さないこと。

        重なりで札を落とした点の名前をそのまま描くと、**何も無い場所を
        指す地名**が地図に残る。読む人には「そこに観測点がある」ように
        見えるが、震度は書かれていない。画像としては成立してしまうので、
        見ても気づけない。

        144行あるこの関数を割る前に押さえる
        （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
        """
        # 札は重なって片方しか置けないが、**地名の置き場所は空いている**
        # 配置にする（弱い方を左へ約40px）。同じ座標に重ねると地名の側も
        # 重なり避けで落ちてしまい、placed_at の判定を通らずに緑になる。
        plot = [(38.700, 141.000, 60, "つよい"), (38.700, 140.945, 10, "よわい")]
        placed = self._labels_of(plot, 40.0, 143.0, centre=(38.70, 141.00))

        names = [name for _, _, name in placed]
        self.assertIn("つよい", names)
        self.assertNotIn("よわい", names, "札の無い点に地名だけ出ている")

    def test_a_name_is_placed_to_the_right_of_its_badge_when_there_is_room(self):
        """空いていれば、地名は札の右へ置くこと。

        右→左→上→下の順に空きを探す。左右だけを見ていたころは、震源印の
        そばにある最大震度の地名がどちらにも置けず、**名前なしで**出ていた。
        順序が変わっても図は成立するので、置き場所そのものを固定する。
        """
        # 震源は札から離す（震源の座は「空けておく枠」なので、重なると
        # 右が埋まって別の向きが選ばれる）。
        plot = [(38.70, 141.00, 40, "宮城県")]
        placed = self._labels_of(plot, 36.00, 138.00, zoom=8, centre=(38.70, 141.00))

        self.assertEqual(len(placed), 1, placed)
        x, y, _ = placed[0]
        cx, cy = eq._MAP_W * eq._MAP_SS / 2, eq._MAP_H * eq._MAP_SS / 2
        self.assertGreater(x, cx, "地名が札の右へ置かれていない")
        self.assertAlmostEqual(y + self._box("宮城県")[1] / 2, cy, delta=eq._MAP_SS * 8)

    def test_a_name_never_runs_off_the_canvas(self):
        """地名が画面の外へはみ出さないこと。

        右へ置けない端の点で右を選ぶと、文字が切れて読めなくなる。
        画像は出てくるので、切れていること自体は誰も検知しない。
        """
        # 右へ置くと版からはみ出す位置。ここで左が選ばれること自体を見る。
        plot = [(38.70, 142.50, 40, "みぎはし")]
        placed = self._labels_of(plot, 36.00, 138.00, centre=(38.70, 141.00))

        self.assertEqual(len(placed), 1, placed)

        for x, _, name in placed:
            width = self._box(name)[0]
            self.assertGreaterEqual(x, 0, f"左へはみ出している: {x}")
            self.assertLessEqual(x + width, eq._MAP_W * eq._MAP_SS, f"右へはみ出している: {x}")

    def test_the_badges_are_drawn_from_the_weakest_to_the_strongest(self):
        """札は弱い順に描くこと。

        札には落ち影が付いている。強い方を先に描くと、あとから描いた弱い札の
        影が**強い札の上に乗って数字を暗くする。** 速報で最初に読む値なので、
        そこだけは他の影に潰されてはいけない。順序を入れ替えても札は全部
        出るため、枚数を数えるだけの検査では気づけない。
        """
        drawn = []
        real = eq._scale_badge

        def record(scale, size):
            """_scale_badge の代わり。描く順に震度を控えてから本物を呼ぶ。"""
            drawn.append(scale)
            return real(scale, size)

        plot = [(38.70, 141.00, 60, "つよい"), (36.30, 139.00, 20, "よわい"), (34.70, 135.50, 40, "なか")]
        with patch.object(eq, "_scale_badge", record):
            self._render(plot, 38.70, 141.00, zoom=6, centre=(36.5, 138.0))

        self.assertEqual(drawn, sorted(drawn), f"弱い順に描いていない: {drawn}")

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


class TtsDictionaryCoverageTests(unittest.TestCase):
    """辞書が本文だけでなく、名前と入退室の読み上げにも効くこと。

    辞書には名前の読みを登録することが多い。本文でだけ効いて、入退室の
    「〇〇が退出しました」や発言の頭の名前で効かないと、登録が効いていない
    ように聞こえる。
    """

    def setUp(self):
        from services import tts_service as tts

        self.tts = tts
        self.tts._queues.pop(7, None)
        self.addCleanup(self.tts._queues.pop, 7, None)

    def _spoken(self, run, settings):
        synth = AsyncMock(return_value=("http://x/a.wav", 1))
        with (
            patch.object(self.tts, "_synthesize", synth),
            patch("services.tts_store.get_tts_settings", lambda gid: settings),
            patch("services.tts_store.get_tts_dictionary", lambda gid: {"鈴木": "すずき"}),
            patch("services.tts_store.get_user_tts_settings", lambda gid, uid: {}),
            patch.object(self.tts, "get_effective_vc_watch", lambda gid, s: (99, [])),
            patch.object(self.tts.asyncio, "create_task", lambda coro: coro.close()),
        ):
            asyncio.run(run())
        synth.assert_awaited_once()
        return synth.await_args.args[0]

    def test_vc_join_and_leave_use_the_dictionary(self):
        guild = SimpleNamespace(id=7)
        member = SimpleNamespace(id=1, display_name="鈴木")
        settings = {"enabled": True, "vc_notify": True, "vc_channel_id": 99}
        for event, expected in (("join", "すずきが参加しました"), ("leave", "すずきが退出しました")):
            with self.subTest(event=event):
                spoken = self._spoken(lambda: self.tts.enqueue_vc_event(Mock(), guild, member, event), settings)
                self.assertEqual(spoken, expected)

    def test_the_name_before_a_message_uses_the_dictionary(self):
        guild = SimpleNamespace(id=7)
        member = SimpleNamespace(id=1, display_name="鈴木")
        settings = {"enabled": True, "vc_channel_id": 99}
        spoken = self._spoken(lambda: self.tts.enqueue_message(Mock(), guild, member, "やあ"), settings)
        self.assertEqual(spoken, "すずき。やあ")


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
        指すアドレスが is_global=False になる。手元(3.13)では通り、当時の本番・
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

    def test_async_resolution_leaves_the_event_loop_running(self):
        """非同期版の名前解決が、イベントループを止めないこと。

        socket.getaddrinfo は返るまでスレッドを止める。ループの上で直に呼ぶと
        DNS が返るまで全部が止まり、本番では 509ms / 720ms の停止として
        観測された（services/loop_watchdog.py の [stall] ログ）。

        「遅い DNS を模して、そのあいだにループ上の別タスクが動けるか」を
        見る。同期呼び出しへ戻すと、待つ相手（resumed を立てるタスク）が
        動けないので、この差し替えが時間切れで落ちる。
        """
        import socket as _socket

        seen: dict[str, int] = {}
        resumed = threading.Event()

        def fake_getaddrinfo(*_args, **_kwargs):
            seen["thread"] = threading.get_ident()
            if not resumed.wait(5):
                raise RuntimeError("名前解決の最中にイベントループが止まっていた")
            return [(_socket.AF_INET, None, None, "", ("142.251.150.119", 0))]

        async def scenario() -> int:
            async def keep_going():
                # 解決の待ちに入ったあとで動く。ループが生きている証拠。
                await asyncio.sleep(0)
                resumed.set()

            task = asyncio.create_task(keep_going())
            with patch("services.url_safety.socket.getaddrinfo", fake_getaddrinfo):
                await validate_public_http_url_async("https://example.test/")
            await task
            return threading.get_ident()

        loop_thread = asyncio.run(scenario())
        self.assertIn("thread", seen, "getaddrinfo が呼ばれていない")
        self.assertNotEqual(seen["thread"], loop_thread, "名前解決がループのスレッドで走っている")

    def test_async_version_applies_the_same_judgement(self):
        """非同期版でも判定が同じであること（片方だけ緩まないこと）。"""
        import socket as _socket

        infos = [
            (_socket.AF_INET, None, None, "", ("142.251.150.119", 0)),
            (_socket.AF_INET, None, None, "", ("10.0.0.5", 0)),
        ]
        with patch("services.url_safety.socket.getaddrinfo", return_value=infos):
            with self.assertRaises(URLSafetyError):
                asyncio.run(validate_public_http_url_async("https://mixed.example/"))

        for url in ("http://127.0.0.1/", "http://localhost/", "file:///etc/passwd", "example.com"):
            with self.subTest(url=url), self.assertRaises(URLSafetyError):
                asyncio.run(validate_public_http_url_async(url))

        # 名前解決の要らない公開アドレスは、非同期版でも通る
        asyncio.run(validate_public_http_url_async("https://[::ffff:142.251.150.119]/path"))

    def test_sync_version_on_the_event_loop_names_its_caller(self):
        """ループの上で同期版を呼んだら、停止として現れる前に警告を残すこと。"""
        import socket as _socket

        infos = [(_socket.AF_INET, None, None, "", ("142.251.150.119", 0))]

        async def scenario():
            with patch("services.url_safety.socket.getaddrinfo", return_value=infos):
                validate_public_http_url("https://example.test/")

        with self.assertLogs("services.url_safety", level="WARNING") as logs:
            asyncio.run(scenario())
        joined = " ".join(logs.output)
        self.assertIn("[stall]", joined)
        self.assertIn("validate_public_http_url_async", joined)
        self.assertIn("test_services.py", joined, "呼び出し元のファイルが出ていない")


class SyncUrlValidationInAsyncTests(unittest.TestCase):
    """async の中から同期の validate_public_http_url を呼んでいないこと。

    この関数の実体は socket.getaddrinfo で、返るまでスレッドを止める。async の
    中から直に呼ぶと、DNS が返るまでイベントループ全体が固まる。本番では
    DJ-Audio の URL 検査が 509ms / 720ms の停止として観測された
    （services/loop_watchdog.py の [stall] ログ）。

    直呼びは見た目では気付けない（普通の関数呼び出しにしか見えない）ので、
    設定の書き込みと同じやり方で構文木から機械的に見つける。非同期からは
    validate_public_http_url_async を await すること。
    """

    ROOT = Path(__file__).resolve().parent.parent
    SKIP_DIRS = {".git", "tests", "migrations", "__pycache__", ".venv", "venv"}
    BLOCKING = {"validate_public_http_url"}

    def _offenders(self) -> list[str]:
        offenders: list[str] = []
        for path in sorted(self.ROOT.rglob("*.py")):
            if any(part in self.SKIP_DIRS for part in path.relative_to(self.ROOT).parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for line, name in _calls_in_async_bodies(tree, self.BLOCKING):
                offenders.append(f"{path.relative_to(self.ROOT)}:{line} {name}()")
        return offenders

    def test_no_async_function_validates_urls_synchronously(self):
        offenders = self._offenders()
        self.assertEqual(
            offenders,
            [],
            "async から同期の URL 検査を呼んでいます。"
            "await validate_public_http_url_async(...) を通してください:" + chr(10) + chr(10).join(offenders),
        )

    def test_the_search_actually_finds_a_direct_call(self):
        """探し方が壊れていたら、この検査は何も見なくなる。"""
        tree = ast.parse("async def f(url):" + chr(10) + "    validate_public_http_url(url)" + chr(10))
        self.assertEqual(_calls_in_async_bodies(tree, self.BLOCKING), [(2, "validate_public_http_url")])
        # await 付きの非同期版は対象外
        ok = ast.parse("async def f(url):" + chr(10) + "    await validate_public_http_url_async(url)" + chr(10))
        self.assertEqual(_calls_in_async_bodies(ok, self.BLOCKING), [])


class _FakeRssResponse:
    """aiohttp の応答の代わり。**本文をどう取ったか**を覚えておく。"""

    status = 200

    def __init__(self, raw: bytes):
        """バイト列を持たせるだけ。"""
        self._raw = raw
        self.text_called = False

    async def read(self) -> bytes:
        """バイト列のまま返す（本命の経路）。"""
        return self._raw

    async def text(self, *_args, **_kwargs) -> str:
        """呼ばれたら記録する。文字コード推定が起きる経路。"""
        self.text_called = True
        return self._raw.decode("utf-8")

    async def __aenter__(self):
        """async with 用。"""
        return self

    async def __aexit__(self, *_exc):
        """async with 用。握りつぶさない。"""
        return False


class _FakeRssSession:
    """aiohttp.ClientSession の代わり。返す応答は1つだけ。"""

    def __init__(self, response: _FakeRssResponse):
        """応答を持たせるだけ。"""
        self._response = response

    def get(self, *_args, **_kwargs):
        """async with に渡せるものを返す。"""
        return self._response


class NewsFeedParseOffloadTests(unittest.TestCase):
    """RSS の復号とパースが、イベントループの上で走らないこと。

    ニュースの巡回は5分ごとに、全ギルド・全フィードぶん回る。`resp.text()` は
    Content-Type に charset が無いと**本文全体を舐めて文字コードを推定する**し、
    続く XML のパースと記事1件ずつの HTML 除去も、記事100件ぶんがループの上で
    固まって走っていた。地図タイルの復号を _paste_tiles へ移したのと同じ形。

    ここで固定するのは、

      - パースがループのスレッドで走らないこと
      - 本文をバイト列で受けること（`resp.text()` を呼ばない＝推定を起こさない）
      - 移したあとも、記事の中身が同じであること
    """

    SAMPLE = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel>'
        "<item>"
        "<title>台風が接近 - 気象新聞</title>"
        "<link>https://news.example/1</link>"
        "<pubDate>Tue, 09 Sep 2025 12:00:00 GMT</pubDate>"
        "<description>&lt;p&gt;本文の抜粋&lt;/p&gt;</description>"
        '<source url="https://kisho.example/">気象新聞</source>'
        "</item>"
        "</channel></rss>"
    ).encode("utf-8")

    def setUp(self):
        import services.news_service as news

        self.news = news

    def test_the_articles_survive_the_move(self):
        """スレッドへ移したあとも、記事の中身が同じであること。"""
        articles = self.news._parse_rss(self.SAMPLE)

        self.assertEqual(len(articles), 1, articles)
        self.assertEqual(articles[0]["title"], "台風が接近")
        self.assertEqual(articles[0]["source"], "気象新聞")
        self.assertEqual(articles[0]["sourceUrl"], "https://kisho.example/")
        self.assertEqual(articles[0]["link"], "https://news.example/1")
        self.assertEqual(articles[0]["desc"], "本文の抜粋")

    def test_a_broken_feed_gives_an_empty_list(self):
        """壊れた XML で例外を投げないこと（1フィードで巡回を止めない）。"""
        self.assertEqual(self.news._parse_rss(b"<rss><channel"), [])

    def test_the_body_is_taken_as_bytes(self):
        """`resp.text()` を呼ばないこと。**呼べば文字コード推定がループの上で走る。**"""
        response = _FakeRssResponse(self.SAMPLE)

        articles = asyncio.run(self.news._fetch_articles(_FakeRssSession(response), "台風"))

        self.assertEqual(len(articles), 1, articles)
        self.assertFalse(response.text_called, "resp.text() を呼んでいる（文字コード推定が走る）")

    def test_the_parse_does_not_run_on_the_event_loop_thread(self):
        """パースの最中も、ループが他の仕事を進められること。

        遅いパースを模して、そのあいだにループ上の別タスクが動けるかを見る。
        同期呼び出しへ戻すと、待つ相手が動けないので時間切れで落ちる。
        """
        seen: dict[str, int] = {}
        resumed = threading.Event()

        def fake_parse(raw: bytes) -> list[dict]:
            seen["thread"] = threading.get_ident()
            if not resumed.wait(5):
                raise RuntimeError("パースの最中にイベントループが止まっていた")
            return [{"title": "dummy"}]

        async def scenario():
            async def keep_going():
                # パースの待ちに入ったあとで動く。ループが生きている証拠。
                await asyncio.sleep(0)
                resumed.set()

            task = asyncio.create_task(keep_going())
            with patch.object(self.news, "_parse_rss", fake_parse):
                articles = await self.news._fetch_articles(_FakeRssSession(_FakeRssResponse(self.SAMPLE)), "台風")
            await task
            return articles, threading.get_ident()

        articles, loop_thread = asyncio.run(scenario())
        self.assertEqual(articles, [{"title": "dummy"}])
        self.assertIn("thread", seen, "_parse_rss が呼ばれていない")
        self.assertNotEqual(seen["thread"], loop_thread, "パースがループのスレッドで走っている")


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


class DjaudioCacheSweepOffloadTests(unittest.TestCase):
    """配信キャッシュの掃除が、イベントループの上で行われていないこと。

    _cleanup_expired は 60 秒ごとに回る。以前はキャッシュ件数ぶんの
    `open()` + `json.load()` をイベントループ上で直に回していて、**Bot 全体が
    その時間だけ止まっていた。** 実測（Windows / Python 3.13）:

        件数    掃除の所要   他タスクの最大遅延
         100     16.6 ms         14.9 ms
        1000    250.5 ms        164.1 ms
        3000    795.5 ms        624.1 ms

    音声が途切れ、コマンドの応答が遅れ、ハートビートまで遅延する。しかも
    **件数に比例する**ので、使われるほど重くなる。1分に1回きっかり起きる
    ので「たまにえらく重い」という形で出る——起動時ではないため、
    起動の計測をいくらしても見つからなかった。

    通信（Discord のメッセージ削除）はループ側で await する。そちらを
    スレッドへ送っても速くならないうえ、discord.py のオブジェクトを
    別スレッドから触ることになる。
    """

    ROOT = Path(__file__).resolve().parent.parent
    OFFLOADED = {"_scan_expired", "_delete_entries", "_cleanup_orphaned_tmp_files"}

    def setUp(self):
        import services.djaudio_cache as djaudio_cache

        self.dc = djaudio_cache

    def test_the_filesystem_work_is_only_reachable_through_to_thread(self):
        """走査・削除・一時ファイル掃除が、直呼びされていないこと。

        直呼びは見た目では気付けない（普通の関数呼び出しにしか見えない）
        ので、構文木から機械的に見る。**元の実装はまさにこの形で、
        レビューを何度も通っていた。**
        """
        tree = ast.parse((self.ROOT / "services/djaudio_cache.py").read_text(encoding="utf-8"))
        target = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_cleanup_expired"
        )

        offloaded, direct = set(), []
        for call in ast.walk(target):
            if not isinstance(call, ast.Call):
                continue
            name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            if name == "to_thread":
                offloaded.update(arg.id for arg in call.args if isinstance(arg, ast.Name) and arg.id in self.OFFLOADED)
            elif name in self.OFFLOADED:
                direct.append((call.lineno, name))

        self.assertEqual(direct, [], f"イベントループ上で直に呼んでいる: {direct}")
        self.assertEqual(offloaded, self.OFFLOADED, f"to_thread へ渡されていない: {self.OFFLOADED - offloaded}")

    def test_other_tasks_keep_running_while_the_sweep_is_slow(self):
        """掃除が遅いときでも、他のコルーチンが動き続けること。

        実ファイルの速さに依存させないため、走査を「同期で 0.3 秒かかる
        もの」に差し替えて測る。ループ上で走っていれば、その間 ticker は
        1回も進めない。
        """
        ticks = []

        def slow_scan(now):
            """0.3 秒かかる走査のふり。"""
            time.sleep(0.3)
            return []

        async def scenario():
            """掃除と ticker を同時に走らせる。"""

            async def ticker():
                while True:
                    await asyncio.sleep(0.01)
                    ticks.append(1)

            task = asyncio.create_task(ticker())
            await self.dc._cleanup_expired(None)
            task.cancel()

        with patch.object(self.dc, "_scan_expired", slow_scan):
            asyncio.run(scenario())

        # 0.3 秒あれば 10ms 間隔で 20 回以上は進めるはず。ループが止まって
        # いれば 0 回になる。速さではなく「進めたかどうか」を見る。
        self.assertGreater(len(ticks), 5, "掃除の間、他のコルーチンが1つも進めていない")

    def test_an_expired_entry_and_its_discord_message_are_both_removed(self):
        """期限切れの実体・メタ・返信メッセージが揃って消えること。

        ファイル削除をスレッドへ移した際に、削除そのものを落としていないか
        を見る（速くなっても消えなくなっては意味がない）。
        """
        src_dir = Path(tempfile.mkdtemp(prefix="djaudio-sweep-"))
        src = src_dir / "x.mp3"
        src.write_bytes(b"fake-mp3-bytes")
        token = self.dc.register_file(src, "http://example.com/x", "タイトル", 999, ttl=-1)
        self.dc.update_discord_message(token, 111, 222)

        message = Mock()
        message.delete = AsyncMock()
        channel = Mock()
        channel.fetch_message = AsyncMock(return_value=message)
        bot = Mock()
        bot.get_channel = Mock(return_value=channel)

        asyncio.run(self.dc._cleanup_expired(bot))

        message.delete.assert_awaited_once()
        # get_meta() では確かめられない。**あれは期限切れを見た時点で自分でも
        # _delete_entry を呼ぶ**ので、掃除が何もしていなくても None を返し、
        # ついでにファイルまで消してしまう（最初この形で書いて、削除を
        # 丸ごと落とす変異を素通しした）。実ファイルだけを見る。
        self.assertEqual(list(self.dc.DJAUDIO_CACHE_DIR.glob(f"{token}.*")), [])

    def test_one_broken_metadata_file_does_not_stop_the_sweep(self):
        """壊れたメタが1件あっても、他の期限切れは消えること。

        走査を分離したときに例外の握り方を変えると、**1件の破損で掃除が
        丸ごと止まり、期限切れが延々と残る。**
        """
        (self.dc.DJAUDIO_CACHE_DIR / "broken.json").write_text("{壊れている", encoding="utf-8")
        src_dir = Path(tempfile.mkdtemp(prefix="djaudio-sweep2-"))
        src = src_dir / "y.mp3"
        src.write_bytes(b"fake")
        token = self.dc.register_file(src, "http://example.com/y", "タイトル", 999, ttl=-1)

        with self.assertLogs(self.dc.logger, level="WARNING"):
            asyncio.run(self.dc._cleanup_expired(None))

        # ここも get_meta ではなく実ファイルで見る（上のテストの理由と同じ）
        self.assertEqual(list(self.dc.DJAUDIO_CACHE_DIR.glob(f"{token}.*")), [])
        (self.dc.DJAUDIO_CACHE_DIR / "broken.json").unlink(missing_ok=True)


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
    """VC接続を1ギルド1本に集約する層。"""

    def setUp(self):
        from services import voice_session

        self.vs = voice_session
        self.vs._clients.clear()
        self.vs._locks.clear()

    def test_a_new_connection_uses_the_plain_voice_client(self):
        """音声の受信は使わないので、discord.py 本体の VoiceClient で繋ぐこと。"""
        client = Mock(spec=discord.VoiceClient)
        channel = Mock(spec=discord.VoiceChannel)
        channel.connect = AsyncMock(return_value=client)
        guild = Mock()
        guild.id = 1
        guild.voice_client = None
        guild.get_channel.return_value = channel

        got = asyncio.run(self.vs.acquire(guild, 99))

        self.assertIs(got, client)
        channel.connect.assert_awaited_once_with(cls=discord.VoiceClient)
        self.assertIs(self.vs._clients[1], client)

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

    def test_a_connection_in_another_channel_is_moved(self):
        client = Mock(spec=discord.VoiceClient)
        client.is_connected.return_value = True
        client.channel = Mock(id=10)
        client.move_to = Mock(return_value=asyncio.sleep(0))
        self.vs._clients[1] = client

        target = Mock(spec=discord.VoiceChannel)
        guild = Mock()
        guild.id = 1
        guild.get_channel.return_value = target

        got = asyncio.run(self.vs.acquire(guild, 99))
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


class _FakeAiohttpSession:
    """使い回すセッションの代わり。VT スキャンを差し替えるので中身は使わない。"""

    def __init__(self, *a, **k):
        """引数は受け取るだけ。"""


class SharedHttpSessionTests(unittest.TestCase):
    """HTTP のセッションを使い回すこと。

    呼び出しのたびに `aiohttp.ClientSession()` を作ると、毎回 DNS 解決・
    TCP 接続・TLS ハンドシェイクからやり直す。手元で測ると1リクエストあたり
    **49.3ms → 13.5ms**（HTTPS の外部相手・中央値）だった。読み上げ1発話、
    ログ埋め込み1件、リンク1本ごとにこれが乗っていた。

    使い回すぶん、閉じ方と作り直しの条件を間違えると**次の呼び出しが全部
    落ちる**ので、そこを固定する。
    """

    def setUp(self):
        from services import http_client

        self.http = http_client
        self.addCleanup(self._drop)

    def _drop(self):
        """テスト間でセッションを持ち越さない。"""
        self.http._session = None
        self.http._loop = None

    def test_the_same_session_comes_back_within_one_loop(self):
        """同じループの中では、同じセッションを返すこと。"""

        async def twice():
            first = self.http.get_session()
            second = self.http.get_session()
            await self.http.close_session()
            return first is second

        self.assertTrue(asyncio.run(twice()))

    def test_a_new_loop_gets_a_new_session(self):
        """ループが変わったら作り直すこと。

        `aiohttp.ClientSession` は作られたときのループに縛られている。
        別のループから使うと "attached to a different loop" で落ちるので、
        使い回してはいけない。**閉じた覚えが無いのに落ちる**種類の壊れ方。
        """

        async def grab():
            session = self.http.get_session()
            # そのループの中で閉じておく。閉じずに捨てると
            # "Unclosed client session" がテスト出力へ混ざる。
            await self.http.close_session()
            return session

        first = asyncio.run(grab())
        second = asyncio.run(grab())
        self.assertIsNot(first, second)

    def test_a_closed_session_is_replaced(self):
        """閉じられていたら作り直すこと。

        停止処理のあとに何かが呼ばれても、"Session is closed" にせず
        新しいものを渡す。
        """

        async def close_then_get():
            first = self.http.get_session()
            await self.http.close_session()
            second = self.http.get_session()
            await self.http.close_session()
            return first, second

        first, second = asyncio.run(close_then_get())
        self.assertIsNot(first, second)
        self.assertTrue(first.closed)

    def test_a_session_closed_from_outside_is_replaced(self):
        """こちらを通さずに閉じられていても、次は新しいものを渡すこと。

        `async with get_session()` と書くと、抜けるときに共有セッションが
        閉じられる（docstring で禁じているが、書けてしまう）。そのあと
        `_session` は None にならないので、**閉じたかどうかを見ていないと
        以降の呼び出しが全部「Session is closed」で落ちる。**
        """

        async def close_from_outside():
            first = self.http.get_session()
            await first.close()  # close_session() を通さずに閉じる
            second = self.http.get_session()
            # 使える状態かどうかは**閉じる前に**見る（あとで見ると、後始末で
            # 閉じたものを見ることになって必ず True になる）。
            usable = not second.closed
            await self.http.close_session()
            return first is second, usable

        same, usable = asyncio.run(close_from_outside())
        self.assertFalse(same, "閉じられたセッションをそのまま返している")
        self.assertTrue(usable, "作り直したのに閉じたままになっている")

    def test_closing_twice_is_harmless(self):
        """2回閉じても落ちないこと。停止経路が二重に走ることはある。"""

        async def twice():
            self.http.get_session()
            await self.http.close_session()
            await self.http.close_session()

        asyncio.run(twice())

    def test_a_failure_while_closing_does_not_escape(self):
        """閉じるのに失敗しても、停止処理そのものは止めないこと。

        後始末の失敗で、本筋の後始末まで巻き添えにしない。
        """

        async def boom():
            session = self.http.get_session()
            with patch.object(session, "close", AsyncMock(side_effect=RuntimeError("閉じられない"))):
                await self.http.close_session()  # 例外が外へ出たら失敗
            # 実際には閉じられていないので、ここで閉じておく
            # （放っておくと "Unclosed client session" がテスト出力へ混ざる）。
            await session.close()

        asyncio.run(boom())


class VirusTotalScanConcurrencyTests(unittest.TestCase):
    """複数のリンクを、直列に1本ずつ待たないこと。

    1リンクごとに VirusTotal を待つので、5本貼られたら待ち時間も5倍になる。
    到達できないときは1本あたり制限いっぱい（30秒）かかるため、**リンクを
    並べるだけで security ハンドラが返らなくなる。**

    ただし無制限に並べてはいけない。スキャンは `asyncio.to_thread` の中で
    走り、既定のスレッドプールは「CPU数 + 4、最大32本」しかない。ここを
    埋めると設定の書き込みなど**他の to_thread が全部後ろに並ぶ**ので、
    同時数に上限を置く。
    """

    def setUp(self):
        import services.security_service as security

        self.sec = security

    def _scan_recorder(self, *, delay=0.05):
        """スキャン1件の代わり。同時に何本走ったかを記録する。"""
        state = {"running": 0, "peak": 0, "order": []}

        async def scan(session, url):
            state["running"] += 1
            state["peak"] = max(state["peak"], state["running"])
            await asyncio.sleep(delay)
            state["running"] -= 1
            state["order"].append(url)
            return {"status": "ok", "malicious": 0, "suspicious": 0}

        return scan, state

    def _run(self, links, *, scan):
        logs: list[str] = []
        with (
            patch.object(self.sec, "vt_scan_target", scan),
            patch.object(self.sec, "send_log_embed", AsyncMock(return_value=None)),
            patch.object(self.sec, "get_session", lambda: _FakeAiohttpSession()),
        ):
            return asyncio.run(self.sec._run_vt_scans(Mock(), 1, links, [], logs)), logs

    def test_several_links_are_scanned_at_the_same_time(self):
        """5本のリンクが、1本ずつ順番待ちにならないこと。"""
        scan, state = self._scan_recorder()
        links = [f"https://example.com/{i}" for i in range(5)]
        self._run(links, scan=scan)

        self.assertGreater(state["peak"], 1, "1本ずつしか走っていない")

    def test_the_number_running_at_once_is_capped(self):
        """同時に走る本数に上限があること。

        上限が無いと、リンクを並べただけでスレッドプールを食い尽くせる。
        """
        scan, state = self._scan_recorder()
        links = [f"https://example.com/{i}" for i in range(20)]
        self._run(links, scan=scan)

        self.assertLessEqual(state["peak"], self.sec.VT_SCAN_CONCURRENCY)

    def test_the_results_keep_the_order_of_the_links(self):
        """結果の並びは、貼られた順のままであること。

        ログの行と `vt_results` の順序が入れ替わると、「どのURLがどの結果か」
        が読めなくなる。**終わった順ではなく、貼られた順**で並べる。
        """

        async def scan(session, url):
            # 後ろのURLほど速く終わるようにして、完了順と入力順をずらす。
            await asyncio.sleep(0.05 / (int(url[-1]) + 1))
            return {"status": "ok", "malicious": int(url[-1]), "suspicious": 0}

        links = [f"https://example.com/{i}" for i in range(4)]
        (results, _, _, _), logs = self._run(links, scan=scan)

        self.assertEqual([r["malicious"] for r in results], [0, 1, 2, 3])
        self.assertEqual([line.split(" ")[1] for line in logs], links)

    def test_one_dangerous_link_still_marks_the_whole_message(self):
        """1本でも閾値を超えていれば、これまでどおり危険と判定すること。"""

        async def scan(session, url):
            return {"status": "ok", "malicious": 99 if url.endswith("2") else 0, "suspicious": 0}

        links = [f"https://example.com/{i}" for i in range(4)]
        (_, _, flags, danger), _ = self._run(links, scan=scan)

        self.assertTrue(danger)
        self.assertIn("VT_DANGEROUS", flags)


class GptAssessCallReductionTests(unittest.TestCase):
    """LLM へ投げる回数を、判定を弱めずに減らすこと。

    `gpt_assess` は**メッセージ1件ごとに**呼ばれる。Groq 側は
    「同時3件・最小間隔0.25秒」で絞ってあるので、混んだチャンネルでは
    順番待ちが積み上がり、そのあいだ security ハンドラが返らない。

    減らしてよいのは、**判定の中身が変わらない場合だけ**である。

      1. 判じるものが何も無い（本文が空で、VirusTotal の結果も無い）
      2. 直前とまったく同じ入力（連投・コピペ荒らしはこの形になる）

    「短いから安全だろう」といった推測では減らさない。文字数の閾値を置くと
    それは**判定を弱める設定**になり、どこで線を引いても根拠が無い。
    """

    def setUp(self):
        import services.content_moderation as moderation

        self.mod = moderation
        # キーが無いと早期 return する。またクライアントの生成は
        # create_chat_completion の「引数」なので、差し替えないと呼ぶ前に落ちる。
        for target, value in (("GROQ_API_KEY", "dummy-key"), ("_get_groq_client", lambda: Mock())):
            patcher = patch.object(moderation, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.mod._verdict_cache.clear()
        self.addCleanup(self.mod._verdict_cache.clear)

    def _reply(self, text="SAFE"):
        """Groq の応答オブジェクトの代わり。"""
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])

    def test_an_empty_post_is_not_sent_to_the_llm(self):
        """本文が空で VirusTotal の結果も無いなら、呼ばずに SAFE。

        画像だけの投稿などで実際に起きる。空の本文を「危険か」と尋ねても
        judgement の材料が無く、返ってくるのは常に SAFE である。
        """
        with patch.object(self.mod, "create_chat_completion", AsyncMock()) as call:
            verdict = asyncio.run(self.mod.gpt_assess("   ", []))

        call.assert_not_awaited()
        self.assertEqual(verdict, "SAFE")

    def test_an_empty_post_with_vt_results_still_goes_to_the_llm(self):
        """VirusTotal の結果があるなら、本文が空でも判じさせること。

        添付ファイルだけの投稿でも、スキャン結果は判断材料になる。
        「本文が空なら呼ばない」を素朴に適用すると、ここが抜ける。
        """
        vt_results = [{"status": "ok", "malicious": 0, "suspicious": 0}]
        with patch.object(self.mod, "create_chat_completion", AsyncMock(return_value=self._reply())) as call:
            asyncio.run(self.mod.gpt_assess("", vt_results))

        call.assert_awaited_once()

    def test_the_same_post_is_judged_once(self):
        """同じ入力なら、2回目は前の判定を使い回すこと。

        連投・コピペ荒らしはまさにこの形で来る。同じ文字列に同じモデルが
        違う答えを返す前提は置いていないので、**判定は変わらない**。
        """
        with patch.object(self.mod, "create_chat_completion", AsyncMock(return_value=self._reply("DANGEROUS"))) as call:
            first = asyncio.run(self.mod.gpt_assess("儲かる話があります http://x", []))
            second = asyncio.run(self.mod.gpt_assess("儲かる話があります http://x", []))

        self.assertEqual(call.await_count, 1, "2回とも呼んでいる")
        self.assertEqual(first, "DANGEROUS")
        self.assertEqual(second, "DANGEROUS")

    def test_a_different_signal_is_judged_again(self):
        """同じ本文でも、付随する状況が変われば judge し直すこと。

        スパム回数や新規メンバーかどうかはプロンプトに入る。同じ文でも
        「新規メンバーの連投」なら別の答えが出うるので、使い回さない。
        """
        with patch.object(self.mod, "create_chat_completion", AsyncMock(return_value=self._reply())) as call:
            asyncio.run(self.mod.gpt_assess("こんにちは", []))
            asyncio.run(self.mod.gpt_assess("こんにちは", [], spam_count=5))

        self.assertEqual(call.await_count, 2)

    def test_a_failed_judgement_is_not_cached(self):
        """判定できなかった（UNKNOWN）ものは覚えないこと。

        一時的な失敗をキャッシュすると、**次の同じ投稿も判定されないまま
        通る**。失敗は「判定を弱めない」原則に反するので持ち越さない。
        """
        with patch.object(self.mod, "create_chat_completion", AsyncMock(side_effect=RuntimeError("落ちた"))) as call:
            first = asyncio.run(self.mod.gpt_assess("同じ本文", []))
        self.assertEqual(first, "UNKNOWN")

        with patch.object(self.mod, "create_chat_completion", AsyncMock(return_value=self._reply())) as call:
            second = asyncio.run(self.mod.gpt_assess("同じ本文", []))

        call.assert_awaited_once()
        self.assertEqual(second, "SAFE")

    def test_virustotal_still_short_circuits_before_everything(self):
        """VirusTotal が既に危険と言っているなら、これまでどおり即断すること。"""
        with patch.object(self.mod, "create_chat_completion", AsyncMock()) as call:
            verdict = asyncio.run(self.mod.gpt_assess("なんでも", [{"malicious": 99, "suspicious": 0}]))

        call.assert_not_awaited()
        self.assertEqual(verdict, "DANGEROUS")


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
            patch.object(self.tts, "get_session", lambda: FakeSession()),
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
            patch.object(self.tts, "get_session", lambda: FakeSession()),
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


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()


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

        探し方そのものは URL 検査の同じ形の検査と共有している。
        """
        return _calls_in_async_bodies(tree, names)

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
