"""TTS 読み上げパネル。

TTS だけは専用ストア (services/tts_store.py) を経由する。watch_channel_ids の
int 化など、settings.json を直接触ると壊れる整合性がそこに入っているため。
"""

from __future__ import annotations

from typing import Any

from services.tts_store import (
    add_tts_dictionary_entry,
    get_tts_dictionary,
    get_tts_settings,
    remove_tts_dictionary_entry,
    reset_user_tts_settings,
    set_tts_channels,
    set_tts_default_rate,
    set_tts_default_voice,
    set_tts_enabled,
    set_tts_max_lengths,
    set_tts_read_name,
    set_tts_vc_notify,
)
from webapp_admin.schema.types_def import ChoiceSource, Collection, Field, Panel, Section, Widget

DEFAULT_VOICE = "Kyoko"
DEFAULT_RATE = 200
DEFAULT_MAX_LENGTH = 100
DEFAULT_SPEAK_MAX_LENGTH = 200


def _watch_ids(guild_id: int) -> list[int]:
    """読み上げ対象チャンネルIDの一覧。他の getter と違い単独の Field には出ず、_watch_* 群の共通基盤。

    壊れた値（数値化できない要素）は無視して読み飛ばす。1件の不正値のせいで
    一覧全体が読めなくなる（＝パネルごとエラー表示になる）のを避けるため。
    """
    settings = get_tts_settings(guild_id)
    ids: list[int] = []
    for cid in settings.get("watch_channel_ids", []) or []:
        try:
            ids.append(int(cid))
        except (TypeError, ValueError):
            continue
    return ids


def _enabled(guild_id: int) -> bool:
    """enabled フィールドの Field.get。"""
    return bool(get_tts_settings(guild_id).get("enabled", False))


def _vc_notify(guild_id: int) -> bool:
    """vc_notify フィールドの Field.get。"""
    return bool(get_tts_settings(guild_id).get("vc_notify", False))


def _read_name(guild_id: int) -> bool:
    """read_name フィールドの Field.get。既定値は True（他の BOOL 項目と違い、未設定なら読む側に倒す）。"""
    return bool(get_tts_settings(guild_id).get("read_name", True))


def _vc_channel(guild_id: int):
    """vc_channel_id フィールドの Field.get。未設定を None に寄せる。"""
    return get_tts_settings(guild_id).get("vc_channel_id") or None


def _set_vc_channel(guild_id: int, value) -> None:
    """vc_channel_id フィールドの Field.set。

    set_tts_channels() は監視チャンネル一覧と VC をセットで受け取る形なので、
    自分が変更する VC 以外の値（監視チャンネル）を _watch_ids() で読んで
    渡し直す必要がある。省略すると監視チャンネルが空で上書きされる。
    """
    vc_id = int(value) if value not in (None, "", "0", 0) else None
    set_tts_channels(guild_id, _watch_ids(guild_id), vc_id)


def _voice(guild_id: int) -> str:
    """default_voice フィールドの Field.get。"""
    return str(get_tts_settings(guild_id).get("default_voice") or DEFAULT_VOICE)


def _set_voice(guild_id: int, value) -> None:
    """default_voice フィールドの Field.set。

    空文字（free_text で消去を試みた場合）は無視して既存値を残す。default_voice
    は nullable=False なので、ここで保存を許すと「声が未設定」という
    Bot 側が想定していない状態を作ってしまう。
    """
    voice = str(value or "").strip()
    if voice:
        set_tts_default_voice(guild_id, voice)


def _int_setting(key: str, fallback: int):
    """settings.json の1キーだけを読む Field.get をキーごとに作るファクトリ。

    default_rate/max_length/speak_max_length の3項目で「壊れた値は fallback」
    という同じ復旧ロジックを共有するために切り出した。_set_limit（djaudio.py）
    と対になる get 側の版。
    """

    def getter(guild_id: int) -> int:
        """_int_setting(key, fallback) が返す実体。key/fallback はクロージャで束縛済み。"""
        try:
            return int(get_tts_settings(guild_id).get(key, fallback))
        except (TypeError, ValueError):
            return fallback

    return getter


_max_length = _int_setting("max_length", DEFAULT_MAX_LENGTH)
_speak_max_length = _int_setting("speak_max_length", DEFAULT_SPEAK_MAX_LENGTH)


# 上限2項目は set_tts_max_lengths() が両方まとめて受け取るため、
# 片方だけ変更するときはもう片方の現在値を読んで渡す。
def _set_max_length(guild_id: int, value) -> None:
    """max_length フィールドの Field.set。_set_vc_channel と同じ理由で speak_max_length を読んで渡し直す。"""
    set_tts_max_lengths(guild_id, int(value), _speak_max_length(guild_id))


def _set_speak_max_length(guild_id: int, value) -> None:
    """speak_max_length フィールドの Field.set。_set_max_length と対称の処理。"""
    set_tts_max_lengths(guild_id, _max_length(guild_id), int(value))


def _set_rate(guild_id: int, value) -> None:
    """default_rate フィールドの Field.set。"""
    set_tts_default_rate(guild_id, int(value))


# ── コレクション: 読み上げ対象チャンネル ──────────────────────


def _watch_list(guild_id: int) -> list[dict[str, Any]]:
    """watch_channels コレクションの Collection.list。"""
    return [{"id": str(cid), "channel_id": str(cid)} for cid in _watch_ids(guild_id)]


def _watch_add(guild_id: int, data: dict[str, Any]) -> str:
    """watch_channels コレクションの Collection.add。

    _set_vc_channel と対称に、こちらは vc_channel_id 側を素通しで渡し直す。
    重複追加は無視する（同じチャンネルを2回登録しても一覧上は1件のまま）。
    """
    channel_id = int(data["channel_id"])
    ids = _watch_ids(guild_id)
    if channel_id not in ids:
        ids.append(channel_id)
    set_tts_channels(guild_id, ids, get_tts_settings(guild_id).get("vc_channel_id"))
    return str(channel_id)


def _watch_remove(guild_id: int, item_id: str) -> None:
    """watch_channels コレクションの Collection.remove。"""
    channel_id = int(item_id)
    ids = [cid for cid in _watch_ids(guild_id) if cid != channel_id]
    set_tts_channels(guild_id, ids, get_tts_settings(guild_id).get("vc_channel_id"))


# ── コレクション: 読み上げ辞書 ────────────────────────────────


def _dict_list(guild_id: int) -> list[dict[str, Any]]:
    """dictionary コレクションの Collection.list。id_key="word" なので単語自体が項目ID。"""
    return [{"id": word, "word": word, "reading": reading} for word, reading in get_tts_dictionary(guild_id).items()]


def _dict_add(guild_id: int, data: dict[str, Any]) -> str:
    """dictionary コレクションの Collection.add。update は定義していないため、既存の単語への追加は上書きになる。"""
    word = str(data["word"]).strip()
    add_tts_dictionary_entry(guild_id, word, str(data["reading"]).strip())
    return word


def _dict_remove(guild_id: int, item_id: str) -> bool:
    """dictionary コレクションの Collection.remove。戻り値は実際に削除できたか（存在しない単語なら False）。"""
    return remove_tts_dictionary_entry(guild_id, str(item_id))


# ── コレクション: ユーザー個別設定（閲覧とリセットのみ） ───────


def _user_list(guild_id: int) -> list[dict[str, Any]]:
    """user_settings コレクションの Collection.list。add/update を持たない閲覧専用一覧（PANEL 定義参照）。

    空の cfg（設定が全部リセット済み等）は一覧に出さない。「個別設定している
    人」の一覧という体裁上、実質何も設定していないユーザーまで出すと
    件数バッジ（利用予定があれば）や一覧の意味が崩れる。
    """
    rows: list[dict[str, Any]] = []
    for user_id, cfg in (get_tts_settings(guild_id).get("user_settings") or {}).items():
        if not isinstance(cfg, dict) or not cfg:
            continue
        rows.append(
            {
                "id": str(user_id),
                "user_id": str(user_id),
                "voice": cfg.get("voice"),
                "rate": cfg.get("rate"),
            }
        )
    return rows


def _user_reset(guild_id: int, item_id: str) -> None:
    """user_settings コレクションの Collection.remove。実体は削除ではなくリセット（PANEL の help 文言参照）。

    利用者が /voice コマンドで作った個別設定を管理画面から作ることはできず、
    リセットのみ許可する設計（PANEL 定義の item_fields に add/update が無い）。
    """
    reset_user_tts_settings(guild_id, int(item_id))


PANEL = Panel(
    id="tts",
    title="TTS 読み上げ",
    icon="bi-soundwave",
    group="メディア",
    path="/admin/settings/tts",
    window=(860, 700),
    sections=(
        Section(
            "有効化",
            fields=(
                Field(
                    "enabled",
                    "TTS 読み上げを有効にする",
                    Widget.BOOL,
                    get=_enabled,
                    set=set_tts_enabled,
                    default=False,
                    nullable=False,
                ),
                Field(
                    "vc_notify",
                    "VC の参加・退出をアナウンスする",
                    Widget.BOOL,
                    get=_vc_notify,
                    set=set_tts_vc_notify,
                    default=False,
                    nullable=False,
                    enabled_when="enabled",
                ),
            ),
        ),
        Section(
            "接続先 VC",
            fields=(
                Field(
                    "vc_channel_id",
                    "読み上げを流すボイスチャンネル",
                    Widget.VOICE_CHANNEL,
                    get=_vc_channel,
                    set=_set_vc_channel,
                    enabled_when="enabled",
                    help="未設定の場合は自動参加しません。",
                ),
            ),
        ),
        Section(
            "読み上げ対象チャンネル",
            collections=(
                Collection(
                    key="watch_channels",
                    label="読み上げ対象",
                    item_label="チャンネル",
                    id_key="channel_id",
                    list=_watch_list,
                    add=_watch_add,
                    remove=_watch_remove,
                    help="ここに追加したテキストチャンネルの投稿を読み上げます。",
                    item_fields=(Field("channel_id", "チャンネル", Widget.CHANNEL, required=True, nullable=False),),
                ),
            ),
        ),
        Section(
            "デフォルト声設定",
            fields=(
                Field(
                    "default_voice",
                    "声",
                    Widget.SELECT,
                    get=_voice,
                    set=_set_voice,
                    default=DEFAULT_VOICE,
                    nullable=False,
                    choices=ChoiceSource.TTS_VOICES,
                    free_text=True,
                    help="TTS API に接続できないときは声の名前を直接入力できます。",
                ),
                Field(
                    "default_rate",
                    "読み上げ速度（語/分）",
                    Widget.INT,
                    get=_int_setting("default_rate", DEFAULT_RATE),
                    set=_set_rate,
                    default=DEFAULT_RATE,
                    min=100,
                    max=400,
                    nullable=False,
                ),
                Field(
                    "max_length",
                    "メッセージ字数制限",
                    Widget.INT,
                    get=_max_length,
                    set=_set_max_length,
                    default=DEFAULT_MAX_LENGTH,
                    min=10,
                    max=500,
                    nullable=False,
                    help="本文の読み上げ上限。超過分は「以下省略」と読まれます。",
                ),
                Field(
                    "speak_max_length",
                    "読み上げ最大文字数",
                    Widget.INT,
                    get=_speak_max_length,
                    set=_set_speak_max_length,
                    default=DEFAULT_SPEAK_MAX_LENGTH,
                    min=10,
                    max=500,
                    nullable=False,
                    help="「名前。本文」全体の上限です。",
                ),
                Field(
                    "read_name",
                    "発言者名を読み上げる",
                    Widget.BOOL,
                    get=_read_name,
                    set=set_tts_read_name,
                    default=True,
                    nullable=False,
                ),
            ),
        ),
        Section(
            "読み上げ辞書",
            collections=(
                Collection(
                    key="dictionary",
                    label="辞書",
                    item_label="単語",
                    id_key="word",
                    list=_dict_list,
                    add=_dict_add,
                    remove=_dict_remove,
                    help="登録した単語は読み上げ時に置き換えられます。",
                    item_fields=(
                        Field("word", "単語", Widget.TEXT, required=True, nullable=False, max_len=50),
                        Field("reading", "読み", Widget.TEXT, required=True, nullable=False, max_len=100),
                    ),
                ),
            ),
        ),
        Section(
            "ユーザー個別設定",
            collections=(
                Collection(
                    key="user_settings",
                    label="個別に声を設定しているユーザー",
                    item_label="ユーザー設定",
                    id_key="user_id",
                    list=_user_list,
                    remove=_user_reset,
                    help="利用者が /voice コマンドで設定した内容です。ここではリセットのみ行えます。",
                    item_fields=(
                        Field("user_id", "ユーザーID", Widget.SNOWFLAKE, nullable=False),
                        Field("voice", "声", Widget.TEXT),
                        Field("rate", "速度", Widget.INT),
                    ),
                ),
            ),
        ),
    ),
)
