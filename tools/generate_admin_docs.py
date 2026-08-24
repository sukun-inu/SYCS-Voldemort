#!/usr/bin/env python3
"""管理UIの設定一覧を docs/ADMIN.ja.md に生成する。

    python tools/generate_admin_docs.py          # 生成して書き込む
    python tools/generate_admin_docs.py --check   # 差分があれば 1 を返す（CI 向け）

webapp_admin/schema/panels/ の宣言だけを見て表を作るので、設定を増やしたら
このコマンドを実行するだけでドキュメントが追従する。手で表を書き足さない。
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# schema をインポートすると services 層が SETTINGS_DIR を解決するため、
# 生成時は本物の設定ディレクトリに触れないよう一時ディレクトリを渡す。
os.environ.setdefault("SETTINGS_DIR", tempfile.mkdtemp(prefix="admin-docs-"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webapp_admin.schema.duration import humanize  # noqa: E402
from webapp_admin.schema.registry import PANELS  # noqa: E402
from webapp_admin.schema.types import Collection, Field, Panel, Widget  # noqa: E402

DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "ADMIN.ja.md"
BEGIN = "<!-- BEGIN generated: settings -->"
END = "<!-- END generated: settings -->"

WIDGET_LABELS: dict[Widget, str] = {
    Widget.TEXT: "テキスト",
    Widget.TEXTAREA: "本文",
    Widget.INT: "数値",
    Widget.BOOL: "オン/オフ",
    Widget.SELECT: "選択",
    Widget.CHANNEL: "テキストチャンネル",
    Widget.VOICE_CHANNEL: "ボイスチャンネル",
    Widget.ROLE: "ロール",
    Widget.CHECKLIST: "複数選択",
    Widget.SNOWFLAKE: "Discord ID",
    Widget.DURATION: "期間",
}


def _constraint(field: Field) -> str:
    parts: list[str] = []
    if field.widget is Widget.DURATION:
        # 秒のまま「60〜2592000」と載せても何日なのか読み取れない
        if field.min is not None and field.max is not None:
            parts.append(f"{humanize(field.min)}〜{humanize(field.max)}")
        if field.default is not None:
            parts.append(f"既定 {humanize(field.default)}")
    elif field.widget is Widget.INT:
        if field.min is not None and field.max is not None:
            parts.append(f"{field.min}〜{field.max}")
        if field.default is not None:
            parts.append(f"既定 {field.default}")
    elif field.static_choices:
        parts.append(" / ".join(choice.label for choice in field.static_choices))
    elif field.choice_source:
        source = {
            "channels": "テキストチャンネル一覧から選択",
            "voice_channels": "ボイスチャンネル一覧から選択",
            "roles": "ロール一覧から選択",
            "tts_voices": "TTS API から取得した声",
        }.get(field.choice_source.value, field.choice_source.value)
        parts.append(source)
        if field.free_text:
            parts.append("取得できないときは直接入力")
    elif field.widget is Widget.TEXTAREA or field.widget is Widget.TEXT:
        if field.max_len:
            parts.append(f"{field.max_len} 文字まで")
    if field.nullable:
        parts.append("未設定可")
    return "、".join(parts) or "—"


def _escape(text: str | None) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


def _field_rows(fields: tuple[Field, ...]) -> list[str]:
    return [
        f"| {_escape(field.label)} | {WIDGET_LABELS.get(field.widget, field.widget.value)} "
        f"| {_escape(_constraint(field))} | {_escape(field.help)} |"
        for field in fields
    ]


def _collection_block(collection: Collection) -> list[str]:
    limit = f"（最大 {collection.max_items} 件）" if collection.max_items else ""
    actions = [
        name for name, enabled in (
            ("追加", collection.add), ("編集", collection.update), ("削除", collection.remove)
        ) if enabled
    ]
    lines = [
        "",
        f"**{collection.label}**{limit} — {'・'.join(actions) or '閲覧のみ'}"
        + (f"　{_escape(collection.help)}" if collection.help else ""),
        "",
        "| 入力 | 種類 | 条件 |",
        "|---|---|---|",
    ]
    lines += [
        f"| {_escape(field.label)} | {WIDGET_LABELS.get(field.widget, field.widget.value)} "
        f"| {_escape(_constraint(field))} |"
        for field in collection.item_fields
    ]
    return lines


def _panel_block(panel: Panel) -> list[str]:
    lines = [f"### {panel.title}", ""]
    meta = [f"グループ: {panel.group}"]
    if panel.path:
        meta.append(f"旧URL: `{panel.path}`（デスクトップの該当ウィンドウへ転送）")
    lines += ["　/　".join(meta), ""]

    if panel.custom:
        lines += ["スキーマからではなく専用画面で表示します。", ""]
        return lines

    for section in panel.sections:
        # 一覧だけの節は、直後にコレクション名が続いて見出しが重複するので省く
        if section.fields or len(section.collections) != 1:
            lines.append(f"**{section.title}**")
        if section.fields:
            lines += ["", "| 項目 | 種類 | 条件 | 説明 |", "|---|---|---|---|"]
            lines += _field_rows(section.fields)
        for collection in section.collections:
            lines += _collection_block(collection)
        lines.append("")
    return lines


def render() -> str:
    lines = [
        BEGIN,
        "",
        "<!-- この節は tools/generate_admin_docs.py が webapp_admin/schema/ から生成します。",
        "     直接編集しても次の生成で消えます。設定を増やしたら再実行してください。 -->",
        "",
        f"設定画面は {sum(1 for p in PANELS if not p.custom)} 枚。"
        f"単一項目が {sum(len(p.fields) for p in PANELS)} 個、"
        f"一覧が {sum(len(p.collections) for p in PANELS)} 個あります。",
        "",
    ]
    for panel in PANELS:
        lines += _panel_block(panel)
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    check_only = "--check" in sys.argv
    current = DOC_PATH.read_text(encoding="utf-8")

    if BEGIN not in current or END not in current:
        print(f"{DOC_PATH.name} に生成マーカー（{BEGIN}）がありません。")
        return 1

    head, _, rest = current.partition(BEGIN)
    _, _, tail = rest.partition(END)
    updated = head + render() + tail

    if check_only:
        if updated != current:
            print("ドキュメントがスキーマと一致していません。tools/generate_admin_docs.py を実行してください。")
            return 1
        print("ドキュメントはスキーマと一致しています。")
        return 0

    if updated == current:
        print("変更はありません。")
        return 0

    DOC_PATH.write_text(updated, encoding="utf-8")
    print(f"更新しました: {DOC_PATH.relative_to(DOC_PATH.parent.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
