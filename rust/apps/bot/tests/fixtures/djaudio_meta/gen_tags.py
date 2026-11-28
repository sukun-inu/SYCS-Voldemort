"""ID3 タグの書き方の基準を作る（`generate.py tags`）。

入力の MP3（mp3/）の写しに、本物の `_write_tags`（mutagen 1.48.1）で Deezer の値とカバー画像を書く。
書いたあとのファイルが元と違えば tags_out/ に置き、結果（成功か例外の名前）と並べて tags_cases.json に書く。
"""

import base64
import os
import shutil

from services import djaudio_isrc_meta as meta

FULL = {
    "title": "Deezer Title",
    "artist": {"name": "Deezer Artist"},
    "album": {"title": "Deezer Album"},
    "release_date": "2021-03-04",
    "track_position": 5,
    "disk_number": 1,
}

DATA = {
    "full": FULL,
    "jp": {
        "title": "夜に駆ける",
        "artist": {"name": "YOASOBI"},
        "album": {"title": "THE BOOK"},
        "release_date": "2021-01-06",
        "track_position": 2,
        "disk_number": 1,
    },
    "emoji": {"title": "😀 Smile 𝔘", "artist": {"name": "Ärtîst ✓"}, "album": {"title": "Ålbum"}},
    "empty": {},
    "falsy": {"title": "", "artist": None, "album": None, "release_date": "", "track_position": 0, "disk_number": 0},
    "title_nul": {"title": "a\x00b\x00"},
    "title_int": {"title": 5},
    "title_float": {"title": 1.5},
    "title_true": {"title": True},
    "title_list": {"title": ["a", 1, None, 2.5, True, ["x"], {"k": "v"}]},
    "title_dict": {"title": {"a": 1}},
    "artist_str": {"artist": "plain string"},
    "artist_list": {"artist": ["a"]},
    "artist_name_int": {"artist": {"name": 3}},
    "artist_name_list": {"artist": {"name": ["x", 2]}},
    "artist_empty_dict": {"artist": {}},
    "album_str": {"album": "not a dict"},
    "album_title_float": {"album": {"title": 2.0}},
    "album_title_list": {"album": {"title": ["A", "B"]}},
    "date_year": {"release_date": "2020"},
    "date_short": {"release_date": "20"},
    "date_letters": {"release_date": "abcd"},
    "date_fullwidth": {"release_date": "２０２０-01"},
    "date_arabic": {"release_date": "٢٠٢٠"},
    "date_plus": {"release_date": "+123"},
    "date_underscore": {"release_date": "1_23"},
    "date_comma": {"release_date": "20,1"},
    "date_dash": {"release_date": "20-1"},
    "date_space": {"release_date": " 20 "},
    "date_slash": {"release_date": "1/2/"},
    "date_list": {"release_date": ["2020-01-02", "x", "1999", "2000", "2001"]},
    "date_list_int": {"release_date": ["2020", 5]},
    "date_list_empty_str": {"release_date": [""]},
    "date_int": {"release_date": 2020},
    "date_true": {"release_date": True},
    "date_dict": {"release_date": {"y": 1}},
    "track_str": {"track_position": "1"},
    "track_part": {"track_position": "3/12"},
    "track_float": {"track_position": 1.5},
    "track_true": {"track_position": True},
    "track_negative": {"track_position": -1},
    "track_255": {"track_position": 255},
    "track_256": {"track_position": 256},
    "track_300": {"track_position": 300},
    "track_zero_str": {"track_position": "0"},
    "track_padded": {"track_position": " 07 "},
    "track_arabic": {"track_position": "٥"},
    "track_letters": {"track_position": "x"},
    "track_list": {"track_position": [1, 2]},
    "track_dict": {"track_position": {"a": 1}},
    "track_big": {"track_position": 12345678901234567},
    "track_exp": {"track_position": 1e3},
    "disk_str": {"disk_number": "2/2"},
    "disk_float": {"disk_number": 0.5},
    "not_dict_list": ["title"],
    "not_dict_str": "title",
    "tcon_untouched": {"title": "T"},
}


def covers(images):
    """カバー画像の種類（None は渡さない）。"""
    jpeg = base64.b64decode(images["jpeg"])
    return {
        "jpeg": jpeg,
        "jpeg2": base64.b64decode(images["jpeg2"]),
        "png": base64.b64decode(images["png"]),
        "short": b"\xff\xd8",
        "magic_only": b"\xff\xd8\xff",
        "empty": b"",
        "none": None,
    }


def case_list(inputs):
    """(入力, 値の名前, 画像の名前) の組。"""
    cases = []
    for name in inputs:
        cases.append((name, "full", "jpeg"))
        cases.append((name, "empty", "none"))
    for name in ["yt_basic", "notag"]:
        for data_name in DATA:
            if data_name not in ("full", "empty"):
                cases.append((name, data_name, "jpeg"))
    for name in ["yt_basic", "v24_basic", "zoo_v22"]:
        for cover in ["jpeg2", "png", "short", "magic_only", "empty", "none"]:
            cases.append((name, "full", cover))
    return cases


def make(mp3_dir, out_dir, inputs, images):
    """全部の例を書いて、基準の一覧を返す。"""
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    cover_bytes = covers(images)
    results = []
    for i, (name, data_name, cover_name) in enumerate(case_list(inputs)):
        work = f"/tmp/tagcase_{i}.mp3"
        shutil.copyfile(f"{mp3_dir}/{name}.mp3", work)
        with open(work, "rb") as f:
            before = f.read()
        try:
            meta._write_tags(work, DATA[data_name], cover_bytes[cover_name])
            result = "ok"
        except Exception as e:  # Python がここで出す例外（enrich_metadata は False を返す）
            result = type(e).__name__
        with open(work, "rb") as f:
            after = f.read()
        case_id = f"{i:03d}_{name}_{data_name}_{cover_name}"
        if after != before:
            with open(f"{out_dir}/{case_id}.mp3", "wb") as f:
                f.write(after)
        results.append(
            {
                "id": case_id,
                "input": name,
                "data": DATA[data_name],
                "cover": cover_name,
                "result": result,
                "changed": after != before,
            }
        )
    return results
