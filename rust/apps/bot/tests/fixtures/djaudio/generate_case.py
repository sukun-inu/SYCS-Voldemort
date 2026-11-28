"""Python の `str.lower()` の表（`src/python_case.tsv`）を作る。

DJAudio の題の組み立て（`services/djaudio_service.py` の `_format_title_from_metadata`）は、`str.lower()` で比べる。
Rust の `to_lowercase` は Unicode の版が Python 3.13（Unicode 15.1）と違うので、Python の答えそのものを表にして
Rust に持たせる。`Σ` だけは前後の文字で小文字が変わる（語の終わりなら `ς`）。その判定に要る「大文字小文字がある
文字（Cased）」と「大文字小文字を見るときに飛ばす文字（Case_Ignorable）」も、Python に答えさせて表にする。

- Cased は、1 文字の `islower()`・`isupper()`・`istitle()` のどれかが真の文字
- Case_Ignorable は Python から直には引けないので、`Σ` の小文字で調べる。`"A" + c + "Σ"` の `Σ` が `ς` になり、
  `"1" + c + "Σ"` の `Σ` が `σ` になる文字（`c` を飛ばして前の文字を見ている）

1 行に 1 つ。`l`（小文字。元の文字と、小文字にした文字の並び。16 進）・`c`（Cased の範囲）・`i`
（Case_Ignorable の範囲）:

    python generate_case.py > python_case.tsv
"""

SIGMA = "Σ"
FINAL = "ς"


def code_points():
    """Rust の文字列に入る全部の符号位置（サロゲートを除く）。"""
    return (c for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)


def ranges(test):
    """test が真になる文字の範囲を、始めと終わりの組で返す。"""
    out = []
    start = None
    last = None
    for code in code_points():
        inside = test(chr(code))
        if inside and start is None:
            start = code
        if not inside and start is not None:
            out.append((start, last))
            start = None
        last = code
    if start is not None:
        out.append((start, last))
    return out


def cased(c):
    """大文字小文字がある文字か（Unicode の Cased）。"""
    return c.islower() or c.isupper() or c.istitle()


def case_ignorable(c):
    """大文字小文字を見るときに飛ばす文字か（Unicode の Case_Ignorable）。"""
    return ("A" + c + SIGMA).lower()[-1] == FINAL and ("1" + c + SIGMA).lower()[-1] != FINAL


def main():
    """小文字の表と、2 つの範囲の表を書き出す。"""
    for code in code_points():
        c = chr(code)
        if c == SIGMA:
            continue
        lowered = c.lower()
        if lowered != c:
            print("l\t%X\t%s" % (code, " ".join("%X" % ord(x) for x in lowered)))
    for start, end in ranges(cased):
        print(f"c\t{start:X}\t{end:X}")
    for start, end in ranges(case_ignorable):
        print(f"i\t{start:X}\t{end:X}")


main()
