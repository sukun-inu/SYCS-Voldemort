"""設定パネルの定義の書き出し（rust/apps/admin/tests/fixtures/schema/generate.py）が、PANELS を漏れなく写すこと。

    python -m unittest discover -s tests -t .

Rust の管理画面は、設定の画面を Python と同じ宣言（webapp_admin/schema/panels/）から動かすために、この書き出し
（schema.json）を読む。**書き出しから漏れたパネル・入力欄・一覧は、Rust の管理画面では黙って無くなる。** ここでは、
PANELS の全部が並びのまま写っていること、画面へ返す形（Panel.to_json()）がキーの並びまで同じこと、値を出し入れする
関数の名前が 1 つずつ区別できて、どの services の関数に行き着くかが読めることを確かめる。

schema.json がリポジトリにあれば、いまの宣言から作ったものと同じであることも確かめる（違えば CI の「基準」も
落ちる。作り直し方はそちらの成果物か、generate.py の先頭）。
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="admin-schema-export-test-"))

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webapp_admin.schema.registry import PANELS  # noqa: E402
from webapp_admin.schema.types_def import IMPLIED_SOURCE, ChoiceSource, Widget  # noqa: E402

GENERATOR = ROOT / "rust" / "apps" / "admin" / "tests" / "fixtures" / "schema" / "generate.py"
STORED = GENERATOR.parent / "schema.json"


def _load_generator():
    """書き出しの道具を、ファイルの場所から読み込む（rust/ の下はパッケージではないため）。"""
    spec = importlib.util.spec_from_file_location("admin_schema_generate", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wire_text(value) -> str:
    """管理画面の JSON 応答と同じ書き方（starlette の JSONResponse: 詰めた区切り・日本語はそのまま）。"""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class SchemaExportTests(unittest.TestCase):
    """書き出しが PANELS を漏れなく、区別できる名前で写していること。"""

    @classmethod
    def setUpClass(cls):
        cls.generator = _load_generator()
        cls.document = cls.generator.build()
        # ファイルに書いて読み戻したもの（Rust が読むのはこちら）。
        cls.loaded = json.loads(cls.generator.render(cls.document))
        cls.panels = {panel["id"]: panel for panel in cls.loaded["panels"]}
        cls.functions = cls.loaded["functions"]

    def test_every_panel_is_exported_in_the_declared_order(self):
        """並びはスタートメニューの並びそのもの。抜けても入れ替わっても困る。"""
        self.assertEqual([panel["id"] for panel in self.loaded["panels"]], [panel.id for panel in PANELS])

    def test_wire_is_what_the_api_serves_down_to_the_key_order(self):
        """GET /admin/api/apps/{id} の本文の土台。Rust がこれをそのまま返せば、画面には同じ文字列が届く。"""
        for panel in PANELS:
            with self.subTest(panel=panel.id):
                self.assertEqual(_wire_text(self.panels[panel.id]["wire"]), _wire_text(panel.to_json()))

    def test_tiles_match_the_start_menu_without_counting_badges(self):
        """タイルは数を数えずに写す（数は Rust が実行時に数える）。数える関数は badge に名前で残る。"""
        for panel in PANELS:
            with self.subTest(panel=panel.id):
                exported = self.panels[panel.id]
                tile = exported["tile"]
                self.assertEqual(
                    tile,
                    {
                        "id": panel.id,
                        "title": panel.title,
                        "icon": panel.icon,
                        "url": panel.path,
                        "badge": None,
                        "window": {"w": panel.window[0], "h": panel.window[1]},
                    },
                )
                self.assertEqual(exported["badge"] is None, panel.badge is None)
                self.assertEqual(exported["dev_only"], panel.dev_only)
                self.assertEqual(exported["custom"], panel.custom)

    def test_every_field_and_collection_is_exported_with_its_section(self):
        """入力欄と一覧が、どの節にあるかまで漏れなく写っていること。"""
        for panel in PANELS:
            with self.subTest(panel=panel.id):
                exported = self.panels[panel.id]
                self.assertEqual(
                    [(field["section"], field["key"]) for field in exported["fields"]],
                    [(index, field.key) for index, section in enumerate(panel.sections) for field in section.fields],
                )
                self.assertEqual(
                    [(entry["section"], entry["key"], entry["item_fields"]) for entry in exported["collections"]],
                    [
                        (index, collection.key, [item.key for item in collection.item_fields])
                        for index, section in enumerate(panel.sections)
                        for collection in section.collections
                    ],
                )
        self.assertEqual(
            sum(len(panel["fields"]) for panel in self.loaded["panels"]),
            sum(len(panel.fields) for panel in PANELS),
        )

    def test_every_value_function_is_named_and_described(self):
        """get・set・list・add・update・remove・badge の全部に名前があり、手がかりの表に載っていること。"""
        for panel in PANELS:
            exported = self.panels[panel.id]
            for entry, field in zip(exported["fields"], panel.fields):
                for role, fn in (("get", field.get), ("set", field.set)):
                    with self.subTest(panel=panel.id, field=field.key, role=role):
                        self.assertEqual(entry[role], self.generator.ref_name(fn, f"{panel.id}.{field.key}.{role}"))
                        self.assertIn(entry[role], self.functions)
            for entry, collection in zip(exported["collections"], panel.collections):
                for role in ("list", "add", "update", "remove"):
                    with self.subTest(panel=panel.id, collection=collection.key, role=role):
                        fn = getattr(collection, role)
                        if fn is None:
                            self.assertIsNone(entry[role])
                            continue
                        expected = self.generator.ref_name(fn, f"{panel.id}.{collection.key}.{role}")
                        self.assertEqual(entry[role], expected)
                        self.assertIn(entry[role], self.functions)
            if panel.badge is not None:
                self.assertIn(exported["badge"], self.functions)

    def test_names_never_stand_for_two_functions(self):
        """同じ名前が別の関数を指すと、Rust の側でどれを写せばよいか決まらない。"""
        seen = {}
        for panel in PANELS:
            pairs = [(field.get, f"{panel.id}.{field.key}.get") for field in panel.fields]
            pairs += [(field.set, f"{panel.id}.{field.key}.set") for field in panel.fields]
            for collection in panel.collections:
                for role in ("list", "add", "update", "remove"):
                    pairs.append((getattr(collection, role), f"{panel.id}.{collection.key}.{role}"))
            pairs.append((panel.badge, f"{panel.id}.badge"))
            for fn, role in pairs:
                if fn is None:
                    continue
                name = self.generator.ref_name(fn, role)
                self.assertIs(seen.setdefault(name, fn), fn, name)
        # DJAudio の上限 3 つは同じ工場（_set_limit）で作る。閉じ込めた鍵で区別されていること。
        setters = {
            field["key"]: field["set"]
            for field in self.panels["djaudio"]["fields"]
            if field["key"] in ("cache_ttl", "cooldown", "max_urls")
        }
        self.assertEqual(len(set(setters.values())), 3)
        for key, name in setters.items():
            self.assertTrue(name.endswith(f"[key={key}]"), name)

    def test_every_value_function_leads_to_a_service(self):
        """値を出し入れする関数は、自分が services の関数か、services の関数を呼んでいること。"""
        for panel in self.loaded["panels"]:
            names = [field[role] for field in panel["fields"] for role in ("get", "set")]
            names += [entry[role] for entry in panel["collections"] for role in ("list", "add", "update", "remove")]
            for name in names:
                if name is None:
                    continue
                with self.subTest(name=name):
                    entry = self.functions[name]
                    self.assertTrue(entry["module"].startswith("services.") or entry["calls"], entry)

    def test_calls_from_the_panel_side_are_described_too(self):
        """パネル側の関数が呼ぶ services の関数は、表にも載っている（鍵らしい文字列が読める）。"""
        for name, entry in self.functions.items():
            if not entry["module"].startswith("webapp_admin.schema."):
                continue
            for call in entry["calls"] + entry["helpers"]:
                with self.subTest(name=name, call=call):
                    self.assertIn(call, self.functions)

    def test_settings_keys_can_be_read_off_the_description(self):
        """どの設定の鍵かが、名前か手がかりから読めること（いくつかの例で）。"""
        functions = self.functions
        fields = {(panel["id"], field["key"]): field for panel in self.loaded["panels"] for field in panel["fields"]}

        vc_set = fields[("vc-notify", "vc_notify_channel_id")]["set"]
        self.assertEqual(vc_set, "services.settings_store.set_vc_notify_channel_id")
        self.assertIn("vc_notify_channel_id", functions[vc_set]["identifiers"])

        welcome_get = fields[("welcome", "welcome_channel_id")]["get"]
        self.assertEqual(functions[welcome_get]["calls"], ["services.settings_store.get_welcome_settings"])
        self.assertIn("channel_id", functions[welcome_get]["identifiers"])
        self.assertIn("welcome", functions["services.settings_store.get_welcome_settings"]["identifiers"])

        ttl_set = fields[("djaudio", "cache_ttl")]["set"]
        self.assertEqual(functions[ttl_set]["bound"], {"key": "cache_ttl"})
        self.assertEqual(functions[ttl_set]["calls"], ["services.settings_store.set_djaudio_settings"])

        notify_set = fields[("earthquake", "notify_types")]["set"]
        self.assertIn("NOTIFY_TYPES", functions[notify_set]["constants"])

        # 片方だけ変えるときにもう片方を読み直す setter は、読む側の関数まで手がかりに出る。
        max_length_set = fields[("tts", "max_length")]["set"]
        self.assertIn("services.tts_store.get_tts_settings", functions[max_length_set]["calls"])
        self.assertIn("services.tts_store.set_tts_max_lengths", functions[max_length_set]["calls"])

    def test_vocabulary_matches_the_schema_types(self):
        """Rust の列挙と突き合わせる語の一覧が、Python の型と同じこと。"""
        vocabulary = self.loaded["vocabulary"]
        self.assertEqual(vocabulary["widgets"], [widget.value for widget in Widget])
        self.assertEqual(vocabulary["choice_sources"], [source.value for source in ChoiceSource])
        self.assertEqual(
            vocabulary["implied_sources"],
            {widget.value: source.value for widget, source in IMPLIED_SOURCE.items()},
        )

    def test_declarations_have_no_problems(self):
        """宣言の不整合（registry.validate）が無いこと。あれば書き出しても Rust が困る。"""
        self.assertEqual(self.loaded["problems"], [])

    def test_output_does_not_change_between_runs(self):
        """同じ宣言から作れば、毎回同じ文字列になること（CI の「基準」が差分で落ちないように）。"""
        self.assertEqual(self.generator.render(self.generator.build()), self.generator.render(self.document))

    def test_stored_schema_matches_the_declarations(self):
        """リポジトリの schema.json が、いまの宣言から作ったものと同じこと（無ければ飛ばす）。"""
        if not STORED.exists():
            self.skipTest(f"{STORED.relative_to(ROOT)} がまだ無い（CI の「基準」が作る）")
        stored = STORED.read_text(encoding="utf-8").replace("\r\n", "\n")
        self.assertEqual(
            stored,
            self.generator.render(self.document),
            f"{STORED.relative_to(ROOT)} が宣言と食い違っています。"
            f"{GENERATOR.relative_to(ROOT)} で作り直してください。",
        )


if __name__ == "__main__":
    unittest.main()
