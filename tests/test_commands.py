"""スラッシュコマンドの振る舞い。

    python -m unittest discover -s tests -t .

Discord へは繋がないので、Interaction を差し替えて呼び出しの順序と権限だけを見る。
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="commands-test-"))
os.environ.setdefault("TTS_BASE_URL", "http://127.0.0.1:9")
os.environ.setdefault("DJAUDIO_CACHE_DIR", tempfile.mkdtemp(prefix="commands-cache-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discord  # noqa: E402


def make_interaction(*, administrator: bool = True, guild: bool = True):
    """応答の呼ばれ方を記録する Interaction。"""
    calls: list[str] = []
    interaction = Mock(
        spec_set=[
            "guild",
            "guild_id",
            "user",
            "client",
            "channel",
            "response",
            "followup",
        ]
    )
    interaction.guild = Mock(id=999) if guild else None
    interaction.guild_id = 999 if guild else None
    interaction.user = Mock(id=1, display_name="tester")
    interaction.user.guild_permissions = Mock(administrator=administrator)
    interaction.client = Mock()
    interaction.channel = Mock(mention="#general")

    done = {"value": False}
    response = Mock()
    response.is_done = Mock(side_effect=lambda: done["value"])

    async def _defer(*a, **k):
        calls.append("defer")
        done["value"] = True

    async def _send(*a, **k):
        calls.append("response.send_message")
        done["value"] = True

    response.defer = _defer
    response.send_message = _send
    interaction.response = response

    async def _followup(*a, **k):
        calls.append("followup.send")

    interaction.followup = Mock()
    interaction.followup.send = _followup
    return interaction, calls


class MetalDeferTests(unittest.TestCase):
    """外部APIを待つ前に defer すること。

    Discord は最初の応答まで3秒しか待たない。金属価格は外部APIから取るので、
    先に取りに行くと「アプリケーションが応答しませんでした」になる。
    """

    def setUp(self):
        import commands.metal_commands as metal
        from config import METAL_COMMANDS

        self.metal = metal
        self.spec = next(iter(METAL_COMMANDS.values()))

    def test_defer_happens_before_the_price_lookup(self):
        seen = []

        async def slow_price(*args, **kwargs):
            seen.append(list(self.calls))  # 呼ばれた時点の応答状況
            return {"買取価格": 1000}

        interaction, self.calls = make_interaction()
        with (
            patch.object(self.metal, "calculate_metal_value", slow_price),
            patch.object(self.metal, "log_action", AsyncMock()),
        ):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))

        self.assertTrue(seen, "価格取得が呼ばれていない")
        self.assertIn("defer", seen[0], f"取得前の応答: {seen[0]}")

    def test_the_result_is_sent_after_deferring(self):
        interaction, calls = make_interaction()
        with (
            patch.object(self.metal, "calculate_metal_value", AsyncMock(return_value={"買取価格": 1000})),
            patch.object(self.metal, "log_action", AsyncMock()),
        ):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))
        # defer 済みなので、結果は followup で送られる
        self.assertEqual(calls, ["defer", "followup.send"], str(calls))

    def test_a_bad_amount_answers_without_calling_the_api(self):
        interaction, calls = make_interaction()
        called = Mock()
        with patch.object(self.metal, "calculate_metal_value", called):
            asyncio.run(self.metal._handle_single_metal(interaction, 0, self.spec))
        called.assert_not_called()
        self.assertEqual(calls, ["response.send_message"], str(calls))

    def test_defer_failure_does_not_break_the_command(self):
        """defer 自体が失敗しても、処理は続けられること。"""
        interaction, calls = make_interaction()

        async def boom(*a, **k):
            raise discord.HTTPException(Mock(status=500), "boom")

        interaction.response.defer = boom

        with (
            patch.object(self.metal, "calculate_metal_value", AsyncMock(return_value={"買取価格": 1000})),
            patch.object(self.metal, "log_action", AsyncMock()),
            self.assertLogs("commands.metal_commands", level="WARNING"),
        ):
            asyncio.run(self.metal._handle_single_metal(interaction, 1.0, self.spec))
        self.assertIn("response.send_message", calls, str(calls))


class AdminGuardTests(unittest.TestCase):
    """ドキュメントで管理者専用としているものに、実際にガードがあること。

    録音の状況は「誰が録音されていて、どれだけ喋ったか」を含む。
    """

    def _tree(self):
        """コマンドを登録して、名前から呼び出せるようにする。"""
        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def command(self, *, name, description=""):
                def wrap(fn):
                    registry[name] = fn
                    return fn

                return wrap

        return registry, FakeGroup

    def test_record_status_refuses_non_admins(self):
        # commands/recording_commands.py はトピック別モジュール（commands/record/
        # 以下）へ分割済みで、/record status の実処理と recording_service 参照は
        # commands.record.session 側にある。パッチ対象もそちらに合わせる
        # （分割の経緯は commands/record/__init__.py を参照）。
        import commands.record.session as rs
        import commands.recording_commands as rc

        registry, FakeGroup = self._tree()
        with patch.object(rc.app_commands, "Group", FakeGroup):
            rc.register_recording_commands(Mock())

        interaction, calls = make_interaction(administrator=False)
        with patch.object(rs.recording, "get_session", Mock()) as get_session:
            asyncio.run(registry["status"](interaction))
        get_session.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_record_status_answers_admins(self):
        import commands.record.session as rs
        import commands.recording_commands as rc

        registry, FakeGroup = self._tree()
        with patch.object(rc.app_commands, "Group", FakeGroup):
            rc.register_recording_commands(Mock())

        interaction, calls = make_interaction(administrator=True)
        with patch.object(rs.recording, "get_session", Mock(return_value=None)):
            asyncio.run(registry["status"](interaction))
        self.assertTrue(calls, "何も返していない")

    def test_tts_status_refuses_non_admins(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction(administrator=False)
        with patch.object(tc, "get_tts_settings", Mock()) as settings:
            asyncio.run(tc.tts_status.callback(interaction))
        settings.assert_not_called()
        self.assertTrue(calls, "何も返していない")


class GuardHelperTests(unittest.TestCase):
    def test_is_admin_is_false_outside_a_guild(self):
        from commands.guards import is_admin

        interaction, _ = make_interaction(guild=False)
        self.assertFalse(is_admin(interaction))

    def test_ensure_admin_explains_why_it_refused(self):
        from commands.guards import ensure_admin

        interaction, calls = make_interaction(administrator=False)
        self.assertFalse(asyncio.run(ensure_admin(interaction)))
        self.assertTrue(calls, "断った理由を返していない")


class MetalRegistrationShapeTests(unittest.TestCase):
    """register_metal_commands が何をどう登録するかを固定する。

    107行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。

      - グループの名前・説明、コマンドの名前・説明・並び順
      - 金属ごとのコマンドが、**その金属**を見ていること
      - 監査ログより先に defer すること
      - グループが bot のコマンドツリーへ渡されること

    2つ目が要。ループの中で直接 `@group.command` を定義すると、Python の
    クロージャは遅延束縛なので**全コマンドが最後の spec を共有する。**
    /metal gold も /metal silver もプラチナの値段を返すことになるが、
    コマンドは3つとも登録され、例外も出ず、値段もそれらしく返る。
    """

    def _register(self):
        """名前・説明・関数を控える群へ登録し、bot も返す。"""
        import commands.metal_commands as metal

        registered = []
        functions = {}

        class RecordingGroup:
            """作られ方と、渡されたコマンドを控えるだけの群。"""

            def __init__(self, **kwargs):
                """グループの作成引数を控える。"""
                created.append(kwargs)

            def command(self, *, name, description=""):
                """デコレータを返す。関数はそのまま返す。"""

                def wrap(fn):
                    registered.append((name, description))
                    functions[name] = fn
                    return fn

                return wrap

        created = []
        bot = Mock()
        with patch.object(metal.app_commands, "Group", RecordingGroup):
            metal.register_metal_commands(bot)
        return metal, created, registered, functions, bot

    def test_the_group_and_its_commands_are_registered(self):
        """グループの作り方と、コマンドの名前・説明・並び順を固定する。"""
        _, created, registered, _, _ = self._register()

        self.assertEqual(created, [{"name": "metal", "description": "貴金属の現在価格"}])
        self.assertEqual(
            registered,
            [
                ("gold", "金の現在価格を表示します"),
                ("silver", "銀の現在価格を表示します"),
                ("platinum", "プラチナの現在価格を表示します"),
                ("all", "金・銀・プラチナの現在価格をまとめて表示します"),
            ],
        )

    def test_each_metal_command_looks_at_its_own_metal(self):
        """/metal gold が金を、/metal silver が銀を見ること。

        ループの中で直接コマンドを定義すると、遅延束縛で**全部が最後の
        spec（プラチナ）を共有する。** 3つとも登録されるし例外も出ないし
        値段もそれらしく返るので、打ってみて金額の桁が違うと気づくまで
        分からない。
        """
        metal, _, _, functions, _ = self._register()
        interaction, _ = make_interaction()

        seen = []
        with (
            patch.object(metal, "_handle_single_metal", AsyncMock(side_effect=lambda i, g, s: seen.append(s.key))),
            patch.object(metal, "log_action", AsyncMock()),
            patch.object(metal, "_defer", AsyncMock()),
        ):
            for key in ("gold", "silver", "platinum"):
                asyncio.run(functions[key](interaction, 1.0))

        self.assertEqual(seen, ["gold", "silver", "platinum"])

    def test_the_reply_is_deferred_before_the_audit_log_is_sent(self):
        """監査ログを送る前に defer すること。

        監査ログも Discord への往復で、混んでいれば待たされる。3秒の持ち時間を
        そこで使い切ると、**コマンドそのものが「応答なし」で失敗する。**
        ログが速い平常時には起きないので、順番を入れ替えても普段は誰も
        気づかない。
        """
        metal, _, _, functions, _ = self._register()
        interaction, _ = make_interaction()

        order = []
        with (
            patch.object(metal, "_defer", AsyncMock(side_effect=lambda i: order.append("defer"))),
            patch.object(metal, "log_action", AsyncMock(side_effect=lambda *a, **k: order.append("log"))),
            patch.object(metal, "_handle_single_metal", AsyncMock()),
        ):
            asyncio.run(functions["gold"](interaction, 1.0))

        self.assertEqual(order, ["defer", "log"])

    def test_a_non_positive_gram_is_refused_before_deferring(self):
        """0 以下のグラム数は、defer より前に断ること。

        defer したあとでは ephemeral な初回応答を使えない。断り文句が
        **全員に見える形**で出てしまう。
        """
        metal, _, _, functions, _ = self._register()
        interaction, _ = make_interaction()

        order = []
        with (
            patch.object(metal, "_defer", AsyncMock(side_effect=lambda i: order.append("defer"))),
            patch.object(metal, "_respond_error", AsyncMock(side_effect=lambda *a: order.append("error"))),
            patch.object(metal, "calculate_metal_value", AsyncMock()) as calc,
        ):
            asyncio.run(functions["all"](interaction, 0.0))

        self.assertEqual(order, ["error"])
        calc.assert_not_awaited()

    def test_the_group_is_handed_to_the_command_tree(self):
        """bot.tree.add_command(group) を呼ぶこと。

        ここが抜けると Discord 側にコマンドが1つも現れない。関数の中では
        全部組み上がっているので、**例外も出ず、単体テストも通る。**
        """
        _, _, _, _, bot = self._register()

        bot.tree.add_command.assert_called_once()


class MetalAllControlFlowTests(unittest.TestCase):
    """/metal all: 成功時に誤ってエラー文言を送らないこと、一人称が統一されていること。

    以前 except ブロック内の1行だけインデントが外れ、_respond_error が成功時にも
    無条件で呼ばれるリグレッションが一瞬入ったため、固定化しておく。
    """

    def _register(self):
        import commands.metal_commands as metal

        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                pass

            def command(self, *, name, description=""):
                def wrap(fn):
                    registry[name] = fn
                    return fn

                return wrap

            def add_command(self, *a, **k):
                pass

        with patch.object(metal.app_commands, "Group", FakeGroup):
            metal.register_metal_commands(Mock())
        return metal, registry

    def test_success_does_not_send_the_error_message(self):
        metal, registry = self._register()
        interaction, calls = make_interaction()
        with (
            patch.object(metal, "calculate_metal_value", AsyncMock(return_value={"買取価格": 1000})),
            patch.object(metal, "log_action", AsyncMock()),
            patch.object(metal, "_respond_error", AsyncMock()) as respond_error,
        ):
            asyncio.run(registry["all"](interaction, 1.0))
        respond_error.assert_not_called()

    def test_error_message_uses_the_bot_persona(self):
        """一人称は「余」で統一。「俺」「俺様」は使わない（config.py の口調ルール）。"""
        metal, registry = self._register()
        interaction, calls = make_interaction()
        with (
            patch.object(metal, "calculate_metal_value", AsyncMock(side_effect=RuntimeError("boom"))),
            patch.object(metal, "log_action", AsyncMock()),
            patch.object(metal, "_respond_error", AsyncMock()) as respond_error,
        ):
            asyncio.run(registry["all"](interaction, 1.0))
        respond_error.assert_called_once()
        message = respond_error.call_args.args[1]
        self.assertIn("余の力", message)
        self.assertNotIn("俺", message)

    def test_single_metal_error_message_uses_the_bot_persona(self):
        from config import METAL_COMMANDS
        import commands.metal_commands as metal

        spec = next(iter(METAL_COMMANDS.values()))
        interaction, calls = make_interaction()
        with (
            patch.object(metal, "calculate_metal_value", AsyncMock(side_effect=metal.MetalPriceError("boom"))),
            patch.object(metal, "log_action", AsyncMock()),
            patch.object(metal, "_respond_error", AsyncMock()) as respond_error,
        ):
            asyncio.run(metal._handle_single_metal(interaction, 1.0, spec))
        respond_error.assert_called_once()
        message = respond_error.call_args.args[1]
        self.assertIn("余の力", message)
        self.assertNotIn("俺", message)


class TtsValidationTests(unittest.TestCase):
    """空白のみの入力は strip 後に空文字として保存されてしまう。

    辞書エントリなら「何にでもマッチする空パターン」に、声設定なら
    settings.get(key, default) がキー存在扱いになり既定値へ落ちない、という
    形で後段を壊すため、コマンド側で弾く。
    """

    def test_dict_add_rejects_whitespace_only_word(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction()
        with patch.object(tc, "add_tts_dictionary_entry") as add_entry:
            asyncio.run(tc.dict_add.callback(interaction, "   ", "reading"))
        add_entry.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_dict_add_accepts_a_normal_entry_and_strips_it(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction()
        with patch.object(tc, "add_tts_dictionary_entry") as add_entry:
            asyncio.run(tc.dict_add.callback(interaction, " 単語 ", " たんご "))
        add_entry.assert_called_once_with(999, "単語", "たんご")

    def test_default_voice_rejects_whitespace_only(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction(administrator=True)
        with patch.object(tc, "set_tts_default_voice") as set_voice:
            asyncio.run(tc.tts_default_voice_cmd.callback(interaction, "   "))
        set_voice.assert_not_called()

    def test_voice_set_treats_whitespace_only_voice_as_unspecified(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction()
        with patch.object(tc, "set_user_tts_settings") as set_settings:
            asyncio.run(tc.voice_set.callback(interaction, "   ", None))
        set_settings.assert_not_called()
        self.assertTrue(calls, "何も返していない")

    def test_voice_set_still_accepts_and_strips_a_real_voice(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction()
        with patch.object(tc, "set_user_tts_settings") as set_settings:
            asyncio.run(tc.voice_set.callback(interaction, " Kyoko ", None))
        set_settings.assert_called_once_with(999, 1, voice="Kyoko", rate=None)


class TtsJoinDeferTests(unittest.TestCase):
    """/tts join: VC接続前にdeferすること。

    temp_join はVC接続を伴い、管理者なら録音の自動開始判定も続く。どちらも
    Discordとの往復があり、defer無しでは3秒の持ち時間を超えて
    「アプリケーションが応答しませんでした」になりうる。
    """

    def test_defer_happens_before_the_vc_connect(self):
        import commands.tts_commands as tc

        interaction, calls = make_interaction()
        seen_before_join = []

        async def slow_join(*a, **k):
            seen_before_join.append(list(calls))

        with (
            patch.object(tc, "get_tts_settings", Mock(return_value={"enabled": True})),
            patch.object(tc.tts_service, "temp_join", slow_join),
            patch.object(tc, "is_admin", Mock(return_value=False)),
        ):
            asyncio.run(tc.tts_join.callback(interaction, Mock(mention="#vc")))

        self.assertTrue(seen_before_join, "temp_join が呼ばれていない")
        self.assertIn("defer", seen_before_join[0], f"接続前の応答: {seen_before_join[0]}")
        self.assertEqual(calls, ["defer", "followup.send"], str(calls))


class RecordingListCapTests(unittest.TestCase):
    """録音の除外リスト・参加者リストは、件数が多くても省略件数を隠さない。"""

    def _register(self):
        # /record config の実処理は commands/record/ への分割で
        # commands.record.config へ移った。get_recording_settings を patch する
        # 先もそちらでなければならない（分割の経緯は
        # commands/record/__init__.py を参照）。recording_commands 側へ
        # 再エクスポートして AttributeError だけ消すと、patch が実際の
        # 呼び出し先へ届かないまま既定の設定を読み、除外0人の経路を通って
        # 何も確かめずに緑になる。
        import commands.record.config as rcfg
        import commands.recording_commands as rc

        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                pass

            def command(self, *, name, description=""):
                def wrap(fn):
                    registry[name] = fn
                    return fn

                return wrap

            def add_command(self, *a, **k):
                pass

        with patch.object(rc.app_commands, "Group", FakeGroup):
            rc.register_recording_commands(Mock())
        return rcfg, registry

    def test_excluded_list_shows_the_omitted_count(self):
        rcfg, registry = self._register()
        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send

        excluded_ids = list(range(30))
        with (
            patch.object(
                rcfg,
                "get_recording_settings",
                Mock(
                    return_value={
                        "enabled": True,
                        "auto_start": False,
                        "max_minutes": 60,
                        "retention_days": 7,
                        "excluded_user_ids": excluded_ids,
                    }
                ),
            ),
            patch.object(rcfg.recording, "preferred_vc_channel_id", Mock(return_value=None)),
        ):
            asyncio.run(registry["config"](interaction))

        field = next(f for f in sent["embed"].fields if f.name == "録音しない人")
        self.assertIn("…他10人", field.value)


class ServerNewsListTests(unittest.TestCase):
    """/news add のクエリ長・/news list の一覧表示。"""

    def _register(self):
        # commands/server_commands.py はトピック別モジュール（commands/server/ 以下）
        # へ分割済みで、ニュース関連の実処理と get_news_feeds 参照は
        # commands.server.news 側にある。パッチ対象もそちらに合わせる
        # （分割の経緯は commands/server/__init__.py を参照）。app_commands.Group
        # は discord.py 側のシングルトンモジュール属性なので、ここで1回パッチ
        # すれば分割後のどのトピックモジュールにも効く。
        import commands.server.news as sc
        import commands.server_commands as sc_entry

        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                pass

            def command(self, *, name, description=""):
                def wrap(fn):
                    fn.autocomplete = lambda param: (lambda g: g)
                    registry[name] = fn
                    return fn

                return wrap

            def add_command(self, *a, **k):
                pass

        with patch.object(discord.app_commands, "Group", FakeGroup):
            sc_entry.register_server_commands(Mock())
        return sc, registry

    def test_news_query_has_a_length_cap(self):
        """クエリの長さが無制限だと、フィード数を10件までに絞っても
        /news list の一覧だけでメッセージ上限(2000文字)を超えうる。"""
        import inspect

        _, registry = self._register()
        annotation = inspect.signature(registry["add"]).parameters["query"].annotation
        self.assertEqual(getattr(annotation, "max_value", None), 100)

    def test_news_list_body_stays_within_the_message_limit_even_with_long_queries(self):
        """クエリ長の上限(100文字)は新規追加分にしか効かない。既存データ
        （上限導入前に登録されたもの）が長いクエリを持っていても、
        /news list 自体がメッセージ上限を超えないことの保険。"""
        sc, registry = self._register()
        interaction, calls = make_interaction()
        sent = {}

        async def fake_send(content, **k):
            sent["content"] = content

        interaction.response.send_message = fake_send

        # Range上限(100文字)導入前に登録されたデータを想定し、あえて長くする。
        feeds = {f"id{i}": {"query": "Q" * 500, "channel_id": 123, "interval": 60} for i in range(10)}
        with patch.object(sc, "get_news_feeds", Mock(return_value=feeds)):
            asyncio.run(registry["list"](interaction))
        self.assertLessEqual(len(sent["content"]), 2000)


class BotOverviewRegistrationShapeTests(unittest.TestCase):
    """commands/settings/overview.py の register が何をどう登録するかを固定する。

    105行あるこの関数を割る前に押さえるためのテスト
    （CONTRIBUTING 5.「長い関数を割る前に、不変条件テストを書く」）。
    既存のテストは /bot settings の丸め方1点だけを見ている。

      - コマンドの名前・説明・並び順
      - /bot help がコマンドを**打てる形**（qualified_name）で並べること
      - グループ自身は一覧に入れないこと
      - 20件ごとに embed を分け、見出しは最初の1枚だけに付けること
      - /bot settings は管理者限定であること
    """

    def _register(self, bot=None):
        """overview.register() だけを、名前と説明を控える群へ流す。"""
        import commands.settings.overview as overview

        registered = []
        functions = {}

        class RecordingGroup:
            """`bot_group.command` に渡された名前・説明・関数を控えるだけの群。"""

            def command(self, *, name, description=""):
                """デコレータを返す。関数はそのまま返す。"""

                def wrap(fn):
                    registered.append((name, description))
                    functions[name] = fn
                    return fn

                return wrap

        overview.register(bot or Mock(), RecordingGroup())
        return overview, registered, functions

    def _tree_with(self, *commands):
        """walk_commands() が指定の並びを返すだけの bot。"""
        bot = Mock()
        bot.tree.walk_commands = Mock(return_value=list(commands))
        return bot

    def _leaf(self, qualified_name, description="説明"):
        """葉のコマンド1つぶん。name は葉の名前しか持たない。"""
        return SimpleNamespace(
            qualified_name=qualified_name, name=qualified_name.split(" ")[-1], description=description
        )

    def test_the_two_commands_are_registered(self):
        """settings と help が、この名前・この説明・この順で並ぶこと。"""
        _, registered, _ = self._register()

        self.assertEqual(
            registered,
            [
                ("settings", "【管理者】Bot設定を一覧表示します"),
                ("help", "利用可能なスラッシュコマンド一覧を表示します"),
            ],
        )

    def test_help_lists_commands_by_the_name_you_actually_type(self):
        """同じ葉の名前を持つコマンドが、両方とも一覧に出ること。

        walk_commands() が返す cmd.name は**葉の名前しか持たない。** 素直に
        name で集めると `/log channel` と `/quake channel` が同じ鍵になり、
        **片方が黙って消える。** 一覧は出るし件数も自然なので、無くなった
        コマンドを探しに来た人が困るまで気づけない。
        """
        import discord

        bot = self._tree_with(
            self._leaf("log channel", "ログの投稿先"),
            self._leaf("quake channel", "地震の投稿先"),
        )
        _, _, functions = self._register(bot)

        interaction, _ = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            """送られた embeds を控える。"""
            sent["embeds"] = k.get("embeds")

        interaction.response.send_message = fake_send
        asyncio.run(functions["help"](interaction))

        body = "\n".join(e.description or "" for e in sent["embeds"])
        self.assertIn("/log channel", body)
        self.assertIn("/quake channel", body)
        self.assertIsInstance(sent["embeds"][0], discord.Embed)

    def test_help_leaves_the_groups_themselves_out(self):
        """グループ自身は一覧に入れないこと。

        walk_commands() はグループも返す。混ぜると `/log` のように**打っても
        何も起きない行**が並び、一覧の信用が落ちる。
        """
        from discord import app_commands

        group = Mock(spec=app_commands.Group)
        group.qualified_name = "log"
        group.description = "ログの設定"
        bot = self._tree_with(group, self._leaf("log channel"))
        _, _, functions = self._register(bot)

        interaction, _ = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            """送られた embeds を控える。"""
            sent["embeds"] = k.get("embeds")

        interaction.response.send_message = fake_send
        asyncio.run(functions["help"](interaction))

        body = "\n".join(e.description or "" for e in sent["embeds"])
        self.assertIn("/log channel", body)
        self.assertNotIn("`/log`", body)

    def test_help_splits_into_pages_of_twenty_with_one_heading(self):
        """20件ごとに embed を分け、見出しは最初の1枚だけに付けること。

        embed の description は4096文字までで、コマンドが増えるとそのうち
        超える。分けずに1枚へ詰めると、**ある日を境に /bot help が丸ごと
        失敗する。** 見出しを全ページに付けると、同じ題が何度も並ぶ。
        """
        bot = self._tree_with(*[self._leaf(f"cmd{i:02d}") for i in range(45)])
        _, _, functions = self._register(bot)

        interaction, _ = make_interaction()
        sent = {}

        async def fake_send(*a, **k):
            """送られた embeds を控える。"""
            sent["embeds"] = k.get("embeds")

        interaction.response.send_message = fake_send
        asyncio.run(functions["help"](interaction))

        embeds = sent["embeds"]
        self.assertEqual(len(embeds), 3)  # 45件 → 20 + 20 + 5
        self.assertEqual(embeds[0].title, "余が授けたコマンドの一覧")
        self.assertIsNone(embeds[1].title)
        self.assertIsNone(embeds[2].title)

    def test_settings_refuses_non_admins(self):
        """/bot settings は管理者限定であること。

        ログの投稿先も信頼済みユーザーも並ぶので、誰でも読めると
        **監視の抜け道がそのまま見える。**
        """
        overview, _, functions = self._register()
        interaction, calls = make_interaction(administrator=False)

        with patch.object(overview, "get_log_settings", Mock(return_value={})) as getter:
            asyncio.run(functions["settings"](interaction))

        getter.assert_not_called()
        self.assertTrue(calls)

    def test_bypass_roles_are_capped_the_same_way_as_trusted_users(self):
        """バイパスロールも、信頼済みユーザーと同じ丸め方をすること。

        embed の1フィールドは1024文字まで。片方だけ丸めても、もう片方が
        多いギルドでは**そのフィールドだけ落ちて表示が壊れる。**
        """
        overview, _, functions = self._register()
        interaction, _ = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            """送られた embed を控える。"""
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send
        with (
            patch.object(overview, "get_log_settings", Mock(return_value={})),
            patch.object(overview, "get_response_channel_id", Mock(return_value=None)),
            patch.object(overview, "get_trusted_user_ids", Mock(return_value=[])),
            patch.object(overview, "get_bypass_role_ids", Mock(return_value=list(range(20)))),
        ):
            asyncio.run(functions["settings"](interaction))

        field = next(f for f in sent["embed"].fields if "バイパスロール" in f.name)
        self.assertIn("…他5個", field.value)
        self.assertIn("（20個）", field.name)


class LoggingSettingsListDedupTests(unittest.TestCase):
    """/bot settings の一覧表示が cap_list_for_message に統一されていること。"""

    def test_settings_shows_the_omitted_count_via_the_shared_helper(self):
        import commands.logging_commands as lc

        # /bot settings の実処理は register_logging_commands の分割で
        # commands/settings/overview.py へ移った。設定取得を patch する先も
        # そちらでなければならない。logging_commands 側へ再エクスポートして
        # AttributeError だけ消すと、patch が実際の呼び出し先へ届かないまま
        # 「未設定なので一覧は空」の経路を通り、何も確かめずに緑になる。
        import commands.settings.overview as overview

        registry = {}

        class FakeGroup:
            def __init__(self, **kwargs):
                pass

            def command(self, *, name, description=""):
                def wrap(fn):
                    registry[name] = fn
                    return fn

                return wrap

            def add_command(self, *a, **k):
                pass

        with patch.object(lc.app_commands, "Group", FakeGroup):
            lc.register_logging_commands(Mock())

        interaction, calls = make_interaction(administrator=True)
        sent = {}

        async def fake_send(*a, **k):
            sent["embed"] = k.get("embed")

        interaction.response.send_message = fake_send

        with (
            patch.object(overview, "get_log_settings", Mock(return_value={})),
            patch.object(overview, "get_response_channel_id", Mock(return_value=None)),
            patch.object(overview, "get_trusted_user_ids", Mock(return_value=list(range(20)))),
            patch.object(overview, "get_bypass_role_ids", Mock(return_value=[])),
        ):
            asyncio.run(registry["settings"](interaction))

        field = next(f for f in sent["embed"].fields if "信頼済みユーザー" in f.name)
        self.assertIn("…他5名", field.value)


if __name__ == "__main__":
    unittest.main()


class CommandTreeTests(unittest.TestCase):
    """実際に登録されるコマンドツリーの形。

    名前の付け替えは「そう書いたつもり」では足りない。Discord に載る形と、
    ドキュメントに書いてある形が一致していることを確かめる。
    """

    @classmethod
    def setUpClass(cls):
        import discord
        from discord import app_commands
        from discord.ext import commands as dpy
        from commands import register_all_commands

        bot = dpy.Bot(command_prefix="!", intents=discord.Intents.default())
        register_all_commands(bot)
        cls.app_commands = app_commands
        cls.tree = bot.tree
        cls.top = list(bot.tree.get_commands())
        cls.leaves = {c.qualified_name: c for c in bot.tree.walk_commands() if not isinstance(c, app_commands.Group)}

    def test_every_command_lives_under_a_group(self):
        """平坦な名前を並べると、/ の一覧が長くなり関連するものが離れる。"""
        loose = [name for name in self.leaves if " " not in name]
        self.assertEqual(loose, [], f"グループに属していない: {loose}")

    def test_the_command_picker_stays_short(self):
        self.assertLessEqual(len(self.top), 25, f"トップレベル {len(self.top)} 個")

    def test_group_children_stay_within_the_discord_limit(self):
        """Discord はグループの子を 25 個までしか受け付けない。"""
        for cmd in self.top:
            if isinstance(cmd, self.app_commands.Group):
                self.assertLessEqual(len(cmd.commands), 25, f"/{cmd.name}")

    def test_names_are_valid_for_discord(self):
        """英小文字・数字・アンダースコア・ハイフンのみ、32文字まで。"""
        import re

        pattern = re.compile(r"^[a-z0-9_-]{1,32}$")
        for cmd in self.tree.walk_commands():
            self.assertRegex(cmd.name, pattern, f"/{cmd.qualified_name}")

    def test_nothing_is_lost_in_the_rename(self):
        """グループ化で機能が減っていないこと。"""
        self.assertEqual(len(self.leaves), 64, sorted(self.leaves))

    def test_the_docs_list_exactly_what_is_registered(self):
        """ドキュメントと実装のずれは、読んだ人の理解と挙動のずれになる。"""
        import re

        doc = (Path(__file__).resolve().parent.parent / "docs" / "COMMANDS.ja.md").read_text(encoding="utf-8")
        # <details> の中は旧名からの対応表。いまのコマンドではないので外す。
        doc = re.sub(r"<details>.*?</details>", "", doc, flags=re.S)

        # `/dict add word` の "word" は引数。コマンド名の切れ目は引数と
        # 区別がつかないので、登録されている名前の側から探しにいく。
        missing = sorted(name for name in self.leaves if not re.search(rf"`/{re.escape(name)}(?=[ `\[<])", doc))
        self.assertEqual(missing, [], f"実装にあるがドキュメントに無い: {missing}")

        known = {c.qualified_name for c in self.tree.walk_commands()}
        mentioned = re.findall(r"`/([a-z0-9_]+(?: [a-z0-9_]+)*)", doc)
        stale = sorted({m for m in mentioned if not any(m == k or m.startswith(k + " ") for k in known)})
        self.assertEqual(stale, [], f"ドキュメントにあるが実装に無い: {stale}")

    def test_the_help_command_shows_the_full_path(self):
        """/log channel と /quake channel が衝突して消えないこと。"""
        listed = {}
        for cmd in self.tree.walk_commands():
            if isinstance(cmd, self.app_commands.Group):
                continue
            listed[cmd.qualified_name] = cmd.description
        self.assertEqual(len(listed), len(self.leaves))
        self.assertIn("log channel", listed)
        self.assertIn("quake channel", listed)


class CapListBudgetTests(unittest.TestCase):
    """cap_list_for_message が名乗りどおり文字数の上限を守ること。

    以前は items[:limit] と件数だけで打ち切っており、docstring が名乗る
    「2000文字に収まる」を実際には保証していなかった（1件の長さが可変な
    /news list や、embed field(1024) に流用した /record status で破れる）。
    件数ではなく文字数を最終的な保証にしたので、そこを境界で押さえる。
    """

    def test_worst_case_call_sites_stay_within_budget(self):
        from commands.interaction_utils import (
            EMBED_FIELD_BUDGET,
            MESSAGE_BUDGET,
            cap_list_for_message,
        )

        cases = [
            # /sticky list: 1行 = "<#"+19桁+">: "+content[:50]。チャンネル数に上限が無い
            (
                "sticky",
                [f"<#{'9' * 19}>: {'あ' * 50}" for _ in range(500)],
                MESSAGE_BUDGET,
                "**スティッキー一覧**\n",
                25,
                "件",
                "\n",
            ),
            # /record status: 表示名は最大32文字。embed field なので上限は 1024
            (
                "speakers",
                [f"・{'名' * 32}（発話 1時間23分45秒）" for _ in range(200)],
                EMBED_FIELD_BUDGET,
                "",
                20,
                "人",
                "\n",
            ),
            # /log settings: embed field に読点区切りで並べる
            ("trusted", [f"<@{'9' * 19}>" for _ in range(300)], EMBED_FIELD_BUDGET, "", 15, "名", ", "),
        ]
        for label, items, budget, header, limit, unit, joiner in cases:
            with self.subTest(label):
                body = cap_list_for_message(
                    items,
                    budget=budget,
                    header=header,
                    limit=limit,
                    omitted_unit=unit,
                    joiner=joiner,
                )
                self.assertLessEqual(len(header) + len(body), budget)

    def test_omission_line_growth_is_accounted_for(self):
        """省略件数が桁上がりして省略行自体が伸びても予算を超えないこと。

        末尾に省略行を足してから溢れる、という壊れ方をしやすい箇所。
        """
        from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message

        body = cap_list_for_message(
            [f"<@{'9' * 19}>" for _ in range(1500)],
            budget=MESSAGE_BUDGET,
            omitted_unit="名",
        )
        self.assertLessEqual(len(body), MESSAGE_BUDGET)
        self.assertRegex(body, r"…他\d+名$")

    def test_header_is_charged_against_the_budget(self):
        """ヘッダの長さも予算から引かれること（ヘッダ込みで上限を守る）。"""
        from commands.interaction_utils import cap_list_for_message

        header = "H" * 40
        body = cap_list_for_message(
            ["abc"] * 50,
            budget=60,
            header=header,
            omitted_unit="件",
        )
        self.assertLessEqual(len(header) + len(body), 60)

    def test_no_omission_line_when_everything_fits(self):
        from commands.interaction_utils import MESSAGE_BUDGET, cap_list_for_message

        self.assertEqual(
            cap_list_for_message(["a", "b"], budget=MESSAGE_BUDGET, omitted_unit="件"),
            "a\nb",
        )
        self.assertEqual(
            cap_list_for_message([], budget=MESSAGE_BUDGET, omitted_unit="件"),
            "",
        )

    def test_every_call_site_passes_a_budget(self):
        """呼び出し側が budget を渡し忘れていないこと。

        budget はキーワード必須引数なので、渡し忘れると実行時に TypeError で
        コマンドごと落ちる（実際に移行の途中でそうなっていた）。静的に押さえる。
        """
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "commands"
        missing = []
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if getattr(node.func, "id", None) != "cap_list_for_message":
                    continue
                if not any(kw.arg == "budget" for kw in node.keywords):
                    missing.append(f"{path.name}:{node.lineno}")
        self.assertEqual(missing, [])
