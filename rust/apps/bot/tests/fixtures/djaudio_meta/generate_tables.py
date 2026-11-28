"""DJAudio のメタデータの補い（`services/djaudio_isrc_meta.py`）が使う Python の文字の扱いを表にする。

曲名の比べ方（`_normalize_for_compare`）は `unicodedata.normalize("NFKD")`・`unicodedata.combining`・`str.lower()`
を使い、題の整え方（`_clean_title`）は `re.IGNORECASE` で英字を比べる。Rust の標準や crate は Unicode の版も
規則も Python 3.13（Unicode 15.1）と違うので、Python の結果そのものを表にして Rust に持たせる。

    python generate_tables.py src/djaudio_meta/python_text.tsv tests/fixtures/djaudio_meta/table_digests.json

表（1 行 1 項目、値は 16 進）:

    L  文字  小文字（str.lower() の 1 文字ずつの結果。Σ の語末の扱いは下の C・I で Rust が決める）
    N  文字  NFKD に分けて結合文字（combining が 0 でないもの）を除いた残り（空なら消える）。ハングルの音節は除く
    C  始め  終わり   「大文字小文字のある文字」（語末の Σ の判定。case-ignorable でないものについて）
    I  始め  終わり   case-ignorable（語末の Σ の判定で飛ばす文字）
    E  文字  IGNORECASE でその文字に当たる文字（パターンに出る英字だけ）

あわせて、全部の符号位置について Python の結果を並べたもののハッシュ（Rust のテストが同じものを作って比べる）を
JSON に書く。
"""

import hashlib
import json
import re
import sys
import unicodedata

# 題の整え方のパターンに出る英字（_NOISE_BRACKET・_FEAT_BARE・_TOPIC_SUFFIX）。
PATTERN_LETTERS = "abcdefghijklmnopqrstuvwxyz"
# パターンに出る英字以外の文字。IGNORECASE でも自分にしか当たらないことを確かめる。
PATTERN_OTHERS = "()[]【】/.48日本語英語한국어中文字幕-－—–"


def code_points():
    """サロゲートを除く全部の符号位置（Rust の文字列に入るもの）。"""
    for code in range(0x110000):
        if not 0xD800 <= code <= 0xDFFF:
            yield code


def strip_marks(text):
    """`_normalize_for_compare` の前半（NFKD に分けて結合文字を除く）。"""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def sigma_bits(ch):
    """語末の Σ の判定に使う 2 つの性質を、str.lower() の振る舞いから引く。

    "A" + ch + "Σ" の Σ が語末形になるのは、ch が飛ばされる（case-ignorable）か、ch が大文字小文字のある文字の
    とき。ch + "Σ" の Σ が語末形になるのは、ch が飛ばされず、かつ大文字小文字のある文字のとき。
    """
    first = ("A" + ch + "Σ").lower()[-1] == "ς"
    second = (ch + "Σ").lower()[-1] == "ς"
    ignorable = first and not second
    return ignorable, second


def ranges(codes):
    """並んだ符号位置を、続いているところで範囲にまとめる。"""
    out = []
    for code in codes:
        if out and out[-1][1] + 1 == code:
            out[-1][1] = code
        else:
            out.append([code, code])
    return out


def hexes(text):
    """文字列を、空白で区切った 16 進の並びにする。"""
    return " ".join(f"{ord(c):X}" for c in text)


def ignorecase_matches(char):
    """IGNORECASE のときに、その 1 文字のパターンに当たる文字を全部返す。"""
    pattern = re.compile(re.escape(char), re.IGNORECASE)
    return [code for code in code_points() if pattern.fullmatch(chr(code))]


def check_classes(equivalents):
    """`[s]`・`[sz]` のような括弧の中の文字も、1 文字ずつの和と同じに当たることを確かめる。"""
    for chars in ("s", "sz"):
        pattern = re.compile(f"[{chars}]", re.IGNORECASE)
        got = {code for code in code_points() if pattern.fullmatch(chr(code))}
        want = set()
        for c in chars:
            want |= set(equivalents.get(c, [ord(c)]))
        assert got == want, chars


def digest(items):
    """符号位置ごとの結果のバイト列を区切って並べ、SHA-256 にする。"""
    h = hashlib.sha256()
    for part in items:
        h.update(part)
        h.update(b"\xff")
    return h.hexdigest()


def main():
    """表とハッシュを書き出す。"""
    tsv_path, digest_path = sys.argv[1], sys.argv[2]
    lines = []
    cased, ignorable = [], []
    lower_parts, strip_parts, sigma_parts, decimal_parts = [], [], [], []
    for code in code_points():
        ch = chr(code)
        low = ch.lower()
        if low != ch:
            lines.append(f"L\t{code:X}\t{hexes(low)}")
        stripped = strip_marks(ch)
        if stripped != ch and not 0xAC00 <= code <= 0xD7A3:
            lines.append(f"N\t{code:X}\t{hexes(stripped)}")
        ign, cas = sigma_bits(ch)
        if ign:
            ignorable.append(code)
        if cas:
            cased.append(code)
        lower_parts.append(low.encode("utf-8"))
        strip_parts.append(stripped.encode("utf-8"))
        sigma_parts.append(bytes([int(ign), int(cas)]))
        decimal_parts.append(bytes([unicodedata.decimal(ch, 255)]))
    for start, end in ranges(cased):
        lines.append(f"C\t{start:X}\t{end:X}")
    for start, end in ranges(ignorable):
        lines.append(f"I\t{start:X}\t{end:X}")
    equivalents = {}
    for char in PATTERN_LETTERS:
        matches = ignorecase_matches(char)
        equivalents[char] = matches
        lines.append(f"E\t{ord(char):X}\t{' '.join(f'{m:X}' for m in matches)}")
    for char in PATTERN_OTHERS:
        assert ignorecase_matches(char) == [ord(char)], char
    check_classes(equivalents)
    with open(tsv_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    digests = {
        "unicode_version": unicodedata.unidata_version,
        "lower": digest(lower_parts),
        "strip_marks": digest(strip_parts),
        "sigma": digest(sigma_parts),
        "decimal": digest(decimal_parts),
    }
    with open(digest_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(digests, f, ensure_ascii=False, indent=1)
        f.write("\n")


main()
