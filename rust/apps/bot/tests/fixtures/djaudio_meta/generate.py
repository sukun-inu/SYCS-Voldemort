"""DJAudio のメタデータの補い（services/djaudio_isrc_meta.py）の基準を、本物の Python で作る。

python:3.13-slim ＋ apt の ffmpeg ＋ 本番と同じ依存（mutagen 1.48.1・aiohttp 3.14.5・yt-dlp）で、リポジトリを
/app に置いて動かす（Deezer・YouTube にはつながない。Deezer は偽物を立てる）:

    python generate.py all   # mp3 → text → tags → flow の順に全部
    python generate.py text  # 文の整え方・点・検索語だけ（text_cases.json）

作るもの（この置き場）:
    mp3/            入力の MP3（yt-dlp の後処理で作ったものと、手で組み立てたタグのもの）
    images.json     テストで使う画像（base64）
    text_cases.json 文の整え方・点・検索語
    tags_cases.json と tags_out/  ID3 タグの書き方（書いたあとの MP3）
    flow_cases.json と flow_out/  Deezer の呼び方を含む全体（届いた要求・結果・書いたあとの MP3）
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("SYCS_REPO", "/app"))

import gen_flow  # noqa: E402
import gen_mp3  # noqa: E402
import gen_tags  # noqa: E402
import gen_text  # noqa: E402


def write_json(name, obj):
    """JSON を書く（文字は UTF-8 のまま、行末は LF）。"""
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")


def read_json(name):
    """JSON を読む。"""
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def main():
    """引数のとおりに作る。"""
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    mp3_dir = os.path.join(HERE, "mp3")
    if what in ("all", "mp3"):
        names, images = gen_mp3.make_all(mp3_dir)
        write_json("images.json", {"inputs": names, **images})
    if what in ("all", "text"):
        write_json("text_cases.json", gen_text.make())
    meta_info = read_json("images.json")
    if what in ("all", "tags"):
        cases = gen_tags.make(mp3_dir, os.path.join(HERE, "tags_out"), meta_info["inputs"], meta_info)
        write_json("tags_cases.json", cases)
    if what in ("all", "flow"):
        write_json("flow_cases.json", gen_flow.make(mp3_dir, os.path.join(HERE, "flow_out"), meta_info))


main()
