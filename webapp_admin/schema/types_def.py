"""管理UIの設定スキーマを表す型。

このモジュールと webapp_admin/schema/panels/ の宣言が、「管理UIにどんな設定が
存在するか」の単一の情報源になる。フォーム描画・検証・API・スタートメニューの
タイル・ドキュメントはすべてここから派生させ、個別に定義しない。

設計上の約束:
  - スキーマは settings.json の構造を知らない。値の読み書きは Field.get /
    Field.set が指す services/* の関数に委ねる。Bot 側も同じ関数を読むため、
    管理UIとBotで設定の解釈がズレない。
  - 選択肢（チャンネル・ロール・声）は実行時に Discord / TTS API から解決するため、
    スキーマには「どの供給元か」だけを持たせる。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class Widget(str, Enum):
    """入力欄の種類。クライアントの描画とサーバの検証が同じ語彙を使う。"""

    TEXT = "text"
    TEXTAREA = "textarea"
    INT = "int"
    DURATION = "duration"  # 値は秒。入力と表示だけ単位を付ける
    BOOL = "bool"
    SELECT = "select"
    CHANNEL = "channel"
    VOICE_CHANNEL = "voice_channel"
    ROLE = "role"
    CHECKLIST = "checklist"
    SNOWFLAKE = "snowflake"


class ChoiceSource(str, Enum):
    """実行時に解決する選択肢の供給元。"""

    CHANNELS = "channels"
    VOICE_CHANNELS = "voice_channels"
    ROLES = "roles"
    TTS_VOICES = "tts_voices"


# ウィジェットから供給元が自明なものは、宣言側で choices を書かなくてよい。
IMPLIED_SOURCE: dict[Widget, ChoiceSource] = {
    Widget.CHANNEL: ChoiceSource.CHANNELS,
    Widget.VOICE_CHANNEL: ChoiceSource.VOICE_CHANNELS,
    Widget.ROLE: ChoiceSource.ROLES,
}

# 値を「Discord の ID」として扱うウィジェット。JSON では文字列、set へ渡すときは int。
_ID_WIDGETS = {Widget.CHANNEL, Widget.VOICE_CHANNEL, Widget.ROLE, Widget.SNOWFLAKE}


@dataclass(frozen=True)
class Choice:
    value: str
    label: str


@dataclass(frozen=True)
class Field:
    """1つの設定項目。

    get / set はパネル直下の項目では必須。コレクションの入力欄として使う場合は
    値の出し入れをコレクション側が行うため省略する。
    """

    key: str
    label: str
    widget: Widget
    get: Callable[[int], Any] | None = None
    set: Callable[[int, Any], Any] | None = None
    default: Any = None
    help: str | None = None
    min: int | None = None
    max: int | None = None
    max_len: int | None = None
    choices: tuple[Choice, ...] | ChoiceSource | None = None
    nullable: bool = True
    required: bool = False
    free_text: bool = False
    enabled_when: str | None = None

    @property
    def choice_source(self) -> ChoiceSource | None:
        """choices を明示していないウィジェット（CHANNEL 等）でも動的解決を効かせる。

        IMPLIED_SOURCE で引けるものは choices を書かなくてよいという設計
        （各パネルの宣言を見ればチャンネル系フィールドに choices が無いのは
        このため）。choices に ChoiceSource を直接書いた場合はそちらを優先する。
        """
        if isinstance(self.choices, ChoiceSource):
            return self.choices
        return IMPLIED_SOURCE.get(self.widget)

    @property
    def static_choices(self) -> tuple[Choice, ...] | None:
        """choices が固定リストとして書かれている場合だけ返す。動的解決分は含めない。"""
        return self.choices if isinstance(self.choices, tuple) else None

    def to_json_value(self, value: Any) -> Any:
        """保存されている値を、クライアントが選択肢と比較できる形へ正規化する。"""
        if self.widget in _ID_WIDGETS:
            # 未設定は None に統一する（settings.json 上は 0 / None / 欠落が混在する）。
            if value in (None, 0, "0", ""):
                return None
            return str(value)
        if self.widget is Widget.BOOL:
            return bool(value)
        if self.widget is Widget.CHECKLIST:
            if isinstance(value, dict):
                return [str(k) for k, enabled in value.items() if enabled]
            if isinstance(value, (list, tuple, set)):
                return [str(v) for v in value]
            return []
        # DURATION は秒の整数。画面側も数値として読み返すので、ここで文字列に
        # すると開いた瞬間に「未保存の変更」として数えられてしまう（実際に
        # DJAudio-DL のパネルが、何も触っていないのに常に1件変更ありになって
        # いた）。INT と同じ扱いにして、型を1箇所で決める。
        if self.widget in (Widget.INT, Widget.DURATION):
            try:
                return int(value)
            except (TypeError, ValueError):
                return self.default
        if value is None:
            return None
        return str(value)

    def coerce(self, value: Any) -> Any:
        """クライアントから受け取った値を set() に渡せる型へ寄せる。

        HTMLフォーム由来の値は全て文字列で届く（チェックボックスは "on" 等）。
        型合わせを1箇所に閉じ込め、各パネルの setter は素直な型だけを受け取る。
        """
        if self.widget in _ID_WIDGETS:
            if value in (None, "", "0", 0):
                return None
            return int(value)
        if self.widget is Widget.BOOL:
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "on", "yes")
            return bool(value)
        if self.widget in (Widget.INT, Widget.DURATION):
            if value in (None, "") and self.default is not None:
                return int(self.default)
            return int(value)
        if self.widget is Widget.CHECKLIST:
            if isinstance(value, dict):
                return [str(k) for k, enabled in value.items() if enabled]
            return [str(v) for v in (value or [])]
        if value is None:
            return None
        text = str(value)
        if self.max_len is not None:
            text = text[: self.max_len]
        return text or (None if self.nullable else text)

    def to_json(self) -> dict[str, Any]:
        """クライアントの描画・検証が読む形へ変換する。get/set は含めない。

        Callable を混ぜると JSON エンコードで TypeError になるので機械的にも
        除外が要るが、それだけの理由ではない。get/set は services/* の関数
        そのものなので、含めてしまうと実装の参照をクライアントに渡すことになる
        （値そのものは _read_values 側が呼び出して渡す設計）。
        """
        payload: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "widget": self.widget.value,
            "nullable": self.nullable,
            "required": self.required,
        }
        for name in ("help", "min", "max", "max_len", "default", "enabled_when"):
            value = getattr(self, name)
            if value is not None:
                payload[name] = value
        if self.free_text:
            payload["free_text"] = True
        if self.static_choices is not None:
            payload["choices"] = [{"value": c.value, "label": c.label} for c in self.static_choices]
        elif self.choice_source is not None:
            payload["choice_source"] = self.choice_source.value
        return payload


@dataclass(frozen=True)
class Collection:
    """可変長の設定（一覧に対する追加・更新・削除）。

    追加/削除はパネルの「保存」に含めず即時実行する。まとめ保存に混ぜると、
    どこまで反映されたのかが利用者から見えなくなるため。
    """

    key: str
    label: str
    item_fields: tuple[Field, ...]
    list: Callable[[int], list[dict[str, Any]]]
    add: Callable[[int, dict[str, Any]], Any] | None = None
    remove: Callable[[int, str], Any] | None = None
    update: Callable[[int, str, dict[str, Any]], Any] | None = None
    id_key: str = "id"
    item_label: str = "項目"
    max_items: int | None = None
    help: str | None = None

    def to_json(self) -> dict[str, Any]:
        """can_add/can_remove/can_update はクライアントがボタンを出すかどうかの判定材料でしかない。

        実際に操作を受け付けるかどうかは api/apps.py の add_item/update_item/
        remove_item が改めて collection.add/update/remove is None を見て 405 に
        している（このフラグを直接は信用していない）。ここを True にしても
        サーバ側で対応する callable が無ければ実行できない。
        """
        payload: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "id_key": self.id_key,
            "item_label": self.item_label,
            "fields": [f.to_json() for f in self.item_fields],
            "can_add": self.add is not None,
            "can_remove": self.remove is not None,
            "can_update": self.update is not None,
        }
        if self.max_items is not None:
            payload["max_items"] = self.max_items
        if self.help:
            payload["help"] = self.help
        return payload


@dataclass(frozen=True)
class Section:
    title: str
    fields: tuple[Field, ...] = ()
    collections: tuple[Collection, ...] = ()
    help: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Field/Collection の to_json をそのまま束ねるだけで、独自の整形は持たない。

        モジュール docstring のとおり Field/Collection が JSON 形状の単一の
        情報源なので、Section 側で個別の変換を書き足すとその前提が崩れる。
        """
        payload: dict[str, Any] = {
            "title": self.title,
            "fields": [f.to_json() for f in self.fields],
            "collections": [c.to_json() for c in self.collections],
        }
        if self.help:
            payload["help"] = self.help
        return payload


@dataclass(frozen=True)
class Panel:
    """デスクトップUIの1アプリ = 1つの設定画面。"""

    id: str
    title: str
    icon: str
    group: str
    # 既存ページのURL。デスクトップへの集約（直接アクセスのリダイレクト）と、
    # 未移行パネルの埋め込み先に使う。ネイティブ実装のパネルは持たない。
    path: str | None = None
    sections: tuple[Section, ...] = ()
    window: tuple[int, int] = (760, 620)
    badge: Callable[[int], int | None] | None = None
    dev_only: bool = False
    custom: bool = False
    # custom パネルの中身をクライアントがどう描くか。
    # "iframe" は既存ページの埋め込み（移行途中）、それ以外は専用モジュール。
    client: str = "iframe"
    # "auto" はセクション数で決める。項目の多いパネル（TTS など）はウィンドウ内タブ、
    # 少ないパネルは縦に並べる。判断規則をここ1箇所に置き、クライアントは結果だけ見る。
    layout: str = "auto"

    @property
    def resolved_layout(self) -> str:
        """ "auto" を実際の描画方式へ確定する。しきい値（4セクション）はここ1箇所だけに置く。

        layout フィールドの直上コメントにあるとおり、クライアントはこの結果
        しか見ない。タブ/縦並びの境目を変えるときはここだけ直せばよく、
        クライアント側の判定と二重に持たない。
        """
        if self.layout != "auto":
            return self.layout
        return "tabs" if len(self.sections) >= 4 else "stack"

    @property
    def fields(self) -> list[Field]:
        """全セクションの Field を平坦化する。panel.field()/choice_sources() が使う内部表現。"""
        return [f for section in self.sections for f in section.fields]

    @property
    def collections(self) -> list[Collection]:
        """全セクションの Collection を平坦化する。fields と同じ理由で用意している。"""
        return [c for section in self.sections for c in section.collections]

    def field(self, key: str) -> Field | None:
        """key からトップレベル Field を引く。api/apps.py の保存処理が変更キーごとに呼ぶ。

        見つからない場合は None を返すだけで例外にしない。呼び出し側
        （validate_values）が「不明な設定項目です」という利用者向けエラーに
        変換する前提のため、ここで例外にすると分岐が二重になる。
        """
        return next((f for f in self.fields if f.key == key), None)

    def collection(self, key: str) -> Collection | None:
        """field() と同じ設計。_collection_or_404 が None を 404 に変換する。"""
        return next((c for c in self.collections if c.key == key), None)

    def choice_sources(self) -> set[ChoiceSource]:
        """パネル全体が必要とする供給元の集合。get_app（パネルを開く時）専用。

        保存時は変更された項目だけで済む（_choices_for_keys）が、パネルを開く
        ときは全フィールドの選択肢を一度に描画する必要があるため、こちらは
        item_fields も含めて洗い出す。集合にしているのは、複数フィールドが
        同じ供給元（例: チャンネル）を使っても resolve() 側で1回にまとめるため。
        """
        sources: set[ChoiceSource] = set()
        for f in self.fields:
            if f.choice_source:
                sources.add(f.choice_source)
        for c in self.collections:
            for f in c.item_fields:
                if f.choice_source:
                    sources.add(f.choice_source)
        return sources

    def tile(self, guild_id: int) -> dict[str, Any]:
        """スタートメニュー/タスクバーのタイル1枚分。"""
        badge = None
        if self.badge is not None:
            try:
                badge = self.badge(guild_id) or None
            except Exception:
                badge = None
        return {
            "id": self.id,
            "title": self.title,
            "icon": self.icon,
            "url": self.path,
            "badge": badge,
            "window": {"w": self.window[0], "h": self.window[1]},
        }

    def to_json(self) -> dict[str, Any]:
        """get_app が返すパネル本体。custom パネルでは sections が空のまま返る。

        custom パネル（DEV/SQL 等）は自前のAPIで状態を持つため、ここでは
        「どのクライアントモジュールで描くか」（client）だけを渡し、
        values/collections は付けない（get_app 側も custom なら早期リターンする）。
        client を schema パネルでは常に None にしているのは、iframe/専用モジュール
        の区別が custom パネルにしか意味を持たないため。
        """
        return {
            "id": self.id,
            "title": self.title,
            "icon": self.icon,
            "group": self.group,
            "path": self.path,
            "kind": "custom" if self.custom else "schema",
            "client": self.client if self.custom else None,
            "layout": self.resolved_layout,
            "window": {"w": self.window[0], "h": self.window[1]},
            "sections": [s.to_json() for s in self.sections],
        }
