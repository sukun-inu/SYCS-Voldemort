"""Python が「空白」「10 進の数字」と見る文字の表（server_tables.json）を、本物の Python から作る。

/reactionrole のメッセージ ID は `int()` で、絵文字とフィードの ID は `str.strip()` で読まれる。どの文字を空白・
数字と見るかを Rust でも同じにするため、全部の文字について Python に答えさせたものを基準にする。

- ``spaces``: `str.isspace()` が真になる文字（コードポイント）
- ``decimal_zeros``: 10 進の数字の「0」にあたる文字。どの文字体系でも、そこから 9 までが続き番号で並ぶ
  （並んでいなければ、ここで落とす）

    python generate_server_tables.py > server_tables.json
"""

import json
import sys
import unicodedata

spaces = [code for code in range(sys.maxunicode + 1) if chr(code).isspace()]
decimals = {}
for code in range(sys.maxunicode + 1):
    value = unicodedata.decimal(chr(code), None)
    if value is not None:
        decimals[code] = value
zeros = [code for code, value in decimals.items() if value == 0]
covered = {zero + offset: offset for zero in zeros for offset in range(10)}
assert covered == decimals, "10 進の数字が、0 から 9 までの続き番号で並んでいない文字体系がある"
# int() が数字と見る文字は、この表と同じであること（Python の中で食い違っていないこと）。
for code, value in decimals.items():
    assert int(chr(code)) == value, hex(code)
print(json.dumps({"unicode": unicodedata.unidata_version, "spaces": spaces, "decimal_zeros": zeros}))
