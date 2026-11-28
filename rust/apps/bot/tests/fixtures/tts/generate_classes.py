"""Python の `re` が文字の種類をどう見るかの表（`src/python_char_classes.tsv`）を作る。

読み上げる文の整え方（`services/tts_service.py` の `_clean_text`）は、`re` の `\\w`（語の文字）・`\\d`（数字）・
`\\S`（空白でない文字）を使う。Rust の正規表現の同じ記号とは、含む文字が少し違う（結合文字・つなぎの記号・
区切りの制御文字など）ので、Python 3.13 の判定そのものを表にして Rust に持たせる。

1 行に 1 つの範囲（種類・始め・終わり。始めと終わりは 16 進）。種類は w・d・s（s は空白。`\\S` はその外）:

    python generate_classes.py > python_char_classes.tsv
"""

import re

CLASSES = {"w": re.compile(r"\w"), "d": re.compile(r"\d"), "s": re.compile(r"\s")}


def ranges(pattern):
    """その種類に入る文字の範囲を、始めと終わりの組で返す（サロゲートは Rust の文字列に入らないので除く）。"""
    out = []
    start = None
    for code in range(0x110000):
        inside = not (0xD800 <= code <= 0xDFFF) and pattern.fullmatch(chr(code)) is not None
        if inside and start is None:
            start = code
        if not inside and start is not None:
            out.append((start, code - 1))
            start = None
    if start is not None:
        out.append((start, 0x10FFFF))
    return out


def main():
    """種類ごとの範囲を書き出す。"""
    for name, pattern in CLASSES.items():
        for start, end in ranges(pattern):
            print(f"{name}\t{start:X}\t{end:X}")


main()
