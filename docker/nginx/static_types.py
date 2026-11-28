"""nginx が返す静的ファイルの Content-Type を、Python（starlette の StaticFiles）と同じにする設定を作る。

starlette の StaticFiles は、標準ライブラリの mimetypes.guess_type でファイル名から型を決め、text/ で始まる型には
「; charset=utf-8」を付け、分からなければ text/plain にする。nginx は自分の mime.types を持っていて、.js などの
答えが違う（nginx は application/javascript、Python 3.13 は text/javascript）。そこで nginx のイメージを作るときに、
焼き込むファイルの拡張子ごとに Python の答えを聞き、nginx の types の設定に書き出す。

docker/nginx/Dockerfile の assets の段で、本番の Python のイメージと同じ python:3.13-slim の上で動かす:

    python docker/nginx/static_types.py webapp_admin/static webapp/static > static-types.conf
"""

import mimetypes
import os
import sys


def extensions(roots):
    """roots の下のファイルの拡張子（小文字・点なし）を、名前の順に返す。"""
    found = set()
    for root in roots:
        for _dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext:
                    found.add(ext[1:])
    return sorted(found)


def render(roots):
    """nginx の設定（types・default_type・charset・charset_types）の文字を返す。"""
    by_type = {}
    for ext in extensions(roots):
        guessed = mimetypes.guess_type("x." + ext)[0]
        if guessed:
            by_type.setdefault(guessed, []).append(ext)
    lines = [
        "# docker/nginx/static_types.py が、Python の mimetypes から作った（starlette の StaticFiles と同じ型）。",
        "types {",
    ]
    for mime, exts in sorted(by_type.items()):
        lines.append(f"    {mime} {' '.join(exts)};")
    lines.append("}")
    # 分からない拡張子は、starlette と同じく text/plain（に charset）。
    lines.append("default_type text/plain;")
    text_types = sorted({mime for mime in by_type if mime.startswith("text/")} | {"text/plain"})
    lines.append("charset utf-8;")
    lines.append(f"charset_types {' '.join(text_types)};")
    return "\n".join(lines) + "\n"


def main(roots):
    """設定を標準出力に書く。"""
    if not roots:
        raise SystemExit("使い方: python docker/nginx/static_types.py <静的ファイルの置き場>...")
    sys.stdout.write(render(roots))


if __name__ == "__main__":
    main(sys.argv[1:])
