"""Deezer の呼び方を含む全体（`enrich_metadata`）の基準を作る（`generate.py flow`）。

偽物の Deezer（fake_deezer.py）を立て、本物の `enrich_metadata` の Deezer の場所（`_DEEZER_ISRC`・
`_DEEZER_SEARCH`）だけをそこへ向けて回す。届いた要求の行（パスとクエリのバイト列そのまま）・順番・結果
（True・False・外へ抜けた例外の名前）・書いたあとの MP3 を基準にする。

時間切れ（Python は 10 秒・15 秒）は、`aiohttp.ClientTimeout` を SCALE 倍に縮めて試す。Python が頼んだ
時間切れの秒は、縮める前の値で記録する（Rust の既定の値と比べる）。
"""

import asyncio
import base64
import json
import os
import shutil
from pathlib import Path

import aiohttp

from fake_deezer import FakeDeezer
from services import djaudio_isrc_meta as meta
from services.djaudio_site_detection import detect_site

SCALE = 0.3
SLOW = 9


def ok(obj):
    """200 で JSON を返す応答。"""
    return {"status": 200, "body": json.dumps(obj, ensure_ascii=False)}


def raw(body, status=200, **extra):
    """本文をそのまま返す応答。"""
    return {"status": status, "body": body, **extra}


def album(xl=True, big=True, small=True, title="Album"):
    """Deezer の album（カバーの URL は偽物を指す）。"""
    out = {"title": title}
    if xl:
        out["cover_xl"] = "{BASE}/cover/xl.jpg"
    if big:
        out["cover_big"] = "{BASE}/cover/big.jpg"
    if small:
        out["cover"] = "{BASE}/cover/small.jpg"
    return out


def item(title, artist, **extra):
    """Deezer の検索結果の 1 件。"""
    return {"id": 1, "title": title, "artist": {"name": artist}, "album": album(), **extra}


def full_track(**extra):
    """`/track/isrc:…` が返す曲（年・トラック番号・ディスク番号つき）。"""
    out = item("Deezer Title", "Deezer Artist", release_date="2021-03-04", track_position=5, disk_number=1)
    out.update(extra)
    return out


def cover_rules(images):
    """カバー画像の規則（xl・big は JPEG、small は PNG）。"""
    jpeg = {"status": 200, "body_b64": images["jpeg"], "headers": {"Content-Type": "image/jpeg"}}
    jpeg2 = {"status": 200, "body_b64": images["jpeg2"], "headers": {"Content-Type": "image/jpeg"}}
    png = {"status": 200, "body_b64": images["png"], "headers": {"Content-Type": "image/png"}}
    return [
        {"path": "/cover/xl.jpg", "response": jpeg},
        {"path": "/cover/big.jpg", "response": jpeg2},
        {"path": "/cover/small.jpg", "response": png},
        {"path": "/cover/final.jpg", "response": jpeg2},
    ]


def queries_for(info):
    """enrich_metadata が投げる検索語（台本の q を決めるため）。"""
    title = info.get("track") or info.get("title") or info.get("alt_title")
    artist = info.get("artist") or info.get("album_artist") or info.get("creator") or info.get("uploader")
    return meta._build_search_queries(title, artist, detect_site(info), info)


def case(cid, info, mp3="yt_basic", isrc=None, search=None, rules=(), cover=None):
    """1 つの例。search は {検索語の番号: 応答}、cover は追加のカバーの規則（先に当たる）。"""
    out_rules = list(rules)
    if cover:
        out_rules += cover
    if isrc is not None:
        out_rules.append({"path_prefix": "/track/isrc:", "response": isrc})
    if search:
        qs = queries_for(info)
        for index, response in search.items():
            out_rules.append({"path": "/search", "q": qs[index], "response": response})
    return {"id": cid, "info": info, "mp3": mp3, "rules": out_rules}


YT = {"title": "Song Name", "artist": "Artist", "extractor": "youtube", "uploader": "Artist - Topic"}
HIGH = item("Song Name", "Artist")
MID = item("Song Name (Live)", "Someone Else")
LOW = item("Totally Different", "Nobody")


def isrc_cases():
    """ISRC で引く例。"""
    base = {"isrc": "JPU901800001", "title": "Song Name", "artist": "Artist", "extractor": "youtube"}
    high = {0: ok({"data": [HIGH]})}
    return [
        case("isrc_found", base, isrc=ok(full_track())),
        case("isrc_404_then_search", base, isrc=raw("", 404), search=high),
        case("isrc_error_body", base, isrc=ok({"error": {"type": "DataException", "code": 800}}), search=high),
        case("isrc_list", base, isrc=ok([1, 2]), search=high),
        case("isrc_list_with_error", base, isrc=ok(["error", 1]), search=high),
        case("isrc_empty_list", base, isrc=ok([]), search=high),
        case("isrc_empty_dict", base, isrc=ok({}), search=high),
        case("isrc_string_error", base, isrc=ok("an error happened"), search=high),
        case("isrc_string", base, isrc=ok("abc"), search=high),
        case("isrc_null", base, isrc=raw("null"), search=high),
        case("isrc_empty_body", base, isrc=raw(""), search=high),
        case("isrc_whitespace_body", base, isrc=raw(" \n\x0b\x0c\t "), search=high),
        case("isrc_broken_json", base, isrc=raw("{"), search=high),
        case("isrc_number", base, isrc=raw("5"), search=high),
        case("isrc_true", base, isrc=raw("true"), search=high),
        case("isrc_bad_utf8", base, isrc={"status": 200, "body_b64": base64.b64encode(b'{"t":"\xff"}').decode()}),
        case("isrc_bom", base, isrc=raw("﻿{}"), search=high),
        case("isrc_charset", base, isrc={**ok(full_track()), "headers": {"Content-Type": "text/plain; charset=UTF-8"}}),
        case("isrc_timeout", base, isrc=raw("{}", delay=SLOW), search=high),
        case("isrc_body_timeout", base, isrc=raw("{}", body_delay=SLOW), search=high),
        case("isrc_close", base, isrc={"close": True}, search=high),
        case("isrc_500", base, isrc=raw("{}", 500), search=high),
        case("isrc_weird_chars", {**base, "isrc": "AB CD/../é%2F%zz%4?x=1&y#frag"}, isrc=raw("", 404), search=high),
        case("isrc_dot_segments", {**base, "isrc": "../../search"}, isrc=raw("", 404), search=high),
        case("isrc_int", {**base, "isrc": 12345}, isrc=ok(full_track())),
        case("isrc_float", {**base, "isrc": 1.5}, isrc=raw("", 404), search=high),
        case("isrc_list_value", {**base, "isrc": ["a", "b"]}, isrc=raw("", 404), search=high),
        case("isrc_true_value", {**base, "isrc": True}, isrc=raw("", 404), search=high),
        case("isrc_zero_value", {**base, "isrc": 0}, search=high),
        case("isrc_odd_types", base, isrc=ok(full_track(title=["A", 1], track_position="3/12", release_date="2020"))),
        case("isrc_artist_str", base, isrc=ok({"title": "T", "artist": "str"})),
        case("isrc_album_str", base, isrc=ok({"title": "T", "album": "x"})),
        case("isrc_no_album", base, isrc=ok({"title": "Only Title", "track_position": 0})),
        case("isrc_only_no_title", {"isrc": "X1"}, isrc=raw("", 404)),
    ]


def search_cases():
    """検索で探す例。"""
    bad = {"data": ["x"]}
    return [
        case("search_high_first", YT, search={0: ok({"data": [HIGH]})}),
        case("search_high_second", YT, search={0: ok({"data": [MID]}), 1: ok({"data": [HIGH]})}),
        case("search_best_after_all", YT, search={0: ok({"data": [LOW, MID]}), 2: ok({"data": [MID]})}),
        case("search_below_min", YT, search={0: ok({"data": [LOW]}), 1: ok({"data": [LOW]})}),
        case("search_non200", YT, search={0: raw("{}", 404), 1: raw("{}", 503), 2: ok({"data": [HIGH]})}),
        case("search_data_missing", YT, search={0: ok({"total": 0}), 1: ok({"data": [HIGH]})}),
        case("search_data_falsy", YT, search={0: ok({"data": None}), 1: ok({"data": 0}), 2: ok({"data": ""})}),
        case("search_data_dict", YT, search={0: ok({"data": {"k": 1}})}),
        case("search_data_empty_dict", YT, search={0: ok({"data": {}}), 1: ok({"data": [HIGH]})}),
        case("search_data_string", YT, search={0: ok({"data": "abc"})}),
        case("search_data_number", YT, search={0: ok({"data": 5})}),
        case("search_data_true", YT, search={0: ok({"data": True})}),
        case("search_toplevel_list", YT, search={0: ok([1])}),
        case("search_toplevel_null", YT, search={0: raw("null")}),
        case("search_item_not_dict", YT, search={0: ok(bad)}),
        case("search_item_artist_str", YT, search={0: ok({"data": [{"title": "x", "artist": "str"}]})}),
        case("search_item_title_int", YT, search={0: ok({"data": [{"title": 5}]})}),
        case("search_item_name_int", YT, search={0: ok({"data": [{"title": "Song Name", "artist": {"name": 5}}]})}),
        case(
            "search_item_name_int_no_ref",
            {"title": "Song Name", "extractor": "soundcloud"},
            search={0: ok({"data": [{"title": "Song Name", "artist": {"name": 5}}]})},
        ),
        case("search_broken_json", YT, search={0: raw("{]")}),
        case("search_timeout_then_ok", YT, search={0: raw("{}", delay=SLOW), 1: ok({"data": [HIGH]})}),
        case("search_close_then_ok", YT, search={0: {"close": True}, 1: ok({"data": [HIGH]})}),
        case("search_quota", YT, search={0: ok({"error": {"message": "Quota limit exceeded", "code": 4}})}),
        case("search_tie_first_wins", YT, search={0: ok({"data": [MID, dict(MID, id=2, album=album(xl=False))]})}),
        case("search_high_before_bad", YT, search={0: ok({"data": [LOW, HIGH, "bad"]})}),
        case("search_bad_before_high", YT, search={0: ok({"data": [LOW, "bad", HIGH]})}),
        case("search_empty_items", YT, search={0: ok({"data": [{}, {"title": ""}]})}),
        # 点がちょうど 0.80（アーティストが無いので題だけ。"abcde" と "abcdx" は 2×4/10）。Python は `>=` なので、
        # 1 つ目の検索語で採って、2 つ目（1.0 になる候補）は投げない。
        case(
            "search_exactly_high",
            {"title": "abcde", "extractor": "soundcloud"},
            search={0: ok({"data": [item("abcdx", "X")]}), 1: ok({"data": [item("abcde", "Y")]})},
        ),
    ]


def cover_cases(images):
    """カバー画像の取り方の例。"""
    one = YT

    def with_album(**kw):
        """その album を持つ高い点の検索結果を返す台本。"""
        return {0: ok({"data": [dict(HIGH, album=kw)]})}

    return [
        case("cover_fallback_big", one, search=with_album(title="A", cover_big="{BASE}/cover/big.jpg")),
        case("cover_fallback_small", one, search=with_album(title="A", cover="{BASE}/cover/small.jpg")),
        case("cover_empty_xl", one, search=with_album(cover_xl="", cover_big="{BASE}/cover/big.jpg")),
        case("cover_404", one, search=with_album(cover_xl="{BASE}/cover/missing.jpg")),
        case("cover_timeout", one, search=with_album(cover_xl="{BASE}/cover/slow.jpg"), cover=slow_cover()),
        case("cover_int", one, search=with_album(cover_xl=5)),
        case("cover_list", one, search=with_album(cover_xl=["{BASE}/cover/xl.jpg"])),
        case("cover_no_host", one, search=with_album(cover_xl="http://")),
        case("cover_ftp", one, search=with_album(cover_xl="ftp://127.0.0.1/x.jpg")),
        case("cover_relative", one, search=with_album(cover_xl="/cover/xl.jpg")),
        case("cover_weird_url", one, search=with_album(cover_xl="{BASE}/cover/a b/é/./x/../y.jpg?k=a b&q='z'%zz#f")),
        case("cover_redirect", one, search=with_album(cover_xl="{BASE}/cover/redirect.jpg"), cover=redirects()),
        case("cover_redirect_relative", one, search=with_album(cover_xl="{BASE}/cover/rel.jpg"), cover=redirects()),
        case(
            "cover_redirect_no_location", one, search=with_album(cover_xl="{BASE}/cover/noloc.jpg"), cover=redirects()
        ),
        case("cover_album_falsy", one, search={0: ok({"data": [dict(HIGH, album=None)]})}),
        case("cover_album_str", one, search={0: ok({"data": [dict(HIGH, album="x")]})}),
    ]


def slow_cover():
    """遅いカバー画像。"""
    return [{"path": "/cover/slow.jpg", "response": raw("", delay=SLOW)}]


def redirects():
    """転送するカバー画像。"""
    return [
        {"path": "/cover/redirect.jpg", "response": raw("", 302, headers={"Location": "{BASE}/cover/final.jpg"})},
        {"path": "/cover/rel.jpg", "response": raw("", 301, headers={"Location": "/cover/final.jpg"})},
        {"path": "/cover/noloc.jpg", "response": raw("", 302, headers={"Content-Type": "text/plain"})},
    ]


def site_cases():
    """媒体ごとの検索語と、info の形の例。"""
    high = {0: ok({"data": [HIGH]})}
    return [
        case(
            "youtube_topic", {"title": "Song Name", "uploader": "Artist - Topic", "extractor": "youtube"}, search=high
        ),
        case(
            "youtube_dash",
            {"title": "Artist - Song Name (Official Video)", "webpage_url": "https://youtu.be/x"},
            search={2: ok({"data": [HIGH]})},
        ),
        case(
            "youtube_dash_with_artist",
            {"title": "Abc Def - Song Name", "artist": "Zzyzx Qwerty", "extractor": "youtube"},
            search={0: ok({"data": [item("Song Name", "Zzyzx Qwerty")]})},
        ),
        case(
            "soundcloud",
            {"title": "Song Name", "artist": "Artist", "extractor": "soundcloud"},
            search={1: ok({"data": [HIGH]})},
        ),
        case(
            "bandcamp",
            {"title": "Song Name", "artist": "Artist", "album": "LP", "extractor": "Bandcamp"},
            search={1: ok({"data": [HIGH]})},
        ),
        case(
            "tiktok",
            {
                "title": "original sound - x",
                "music_title": "Song Name",
                "music_author": "Artist",
                "extractor": "TikTok",
            },
            search={0: ok({"data": [HIGH]})},
        ),
        case(
            "nicovideo",
            {"title": "【初音ミク】Song Name【オリジナル】", "extractor": "niconico"},
            search={1: ok({"data": [HIGH]})},
        ),
        case("generic", {"title": "Song Name", "webpage_url": "https://example.com/a"}, search=high),
        case("no_isrc_no_title", {"extractor": "youtube"}),
        case("title_int", {"title": 5}),
        case("title_list", {"title": ["x"]}),
        case("artist_list_with_items", {"title": "Song Name", "artist": ["a", "b"]}, search={0: ok({"data": [HIGH]})}),
        case("artist_list_no_items", {"title": "Song Name", "artist": ["a", "b"]}),
        case("artist_int_with_items", {"title": "Song Name", "artist": 7}, search={0: ok({"data": [HIGH]})}),
        case("info_not_dict", ["title"]),
        case("alt_title_only", {"alt_title": "Song Name", "creator": "Artist"}, search=high),
        case(
            "unicode_query",
            {"title": "Don't Stop Me Now & 100% + = # ? / 'q' \"dq\" ; 日本語 😀 ~*!$()", "artist": "Qu&en"},
            search={0: ok({"data": [HIGH]})},
        ),
        case("write_failure", YT, mp3="text_file", search=high),
        case("write_v25", YT, mp3="v25_with_v1", search=high),
        case("chapters_file", {**YT, "isrc": "JPU901800001"}, mp3="yt_basic", isrc=ok(full_track())),
        case("music_file", {**YT, "isrc": "JPU901800001"}, mp3="yt_music", isrc=ok(full_track(title="夜に駆ける"))),
    ]


def all_cases(images):
    """全部の例。"""
    return isrc_cases() + search_cases() + cover_cases(images) + site_cases()


async def run_case(c, images, mp3_dir, out_dir, timeouts):
    """1 つの例を本物の enrich_metadata で回す。"""
    fake = FakeDeezer(c["rules"] + cover_rules(images))
    await fake.start()
    meta._DEEZER_ISRC = fake.base + "/track/isrc:{}"
    meta._DEEZER_SEARCH = fake.base + "/search"
    work = f"/tmp/flow_{c['id']}.mp3"
    shutil.copyfile(f"{mp3_dir}/{c['mp3']}.mp3", work)
    with open(work, "rb") as f:
        before = f.read()
    timeouts.clear()
    try:
        result = await meta.enrich_metadata(Path(work), c["info"])
    except Exception as e:  # Python の enrich_metadata から外へ抜けた例外
        result = type(e).__name__
    asked = list(timeouts)
    await fake.stop()
    with open(work, "rb") as f:
        after = f.read()
    if after != before:
        with open(f"{out_dir}/{c['id']}.mp3", "wb") as f:
            f.write(after)
    site = detect_site(c["info"]) if isinstance(c["info"], dict) else "generic"
    return {
        **c,
        "site": site,
        "requests": fake.requests,
        "result": result,
        "changed": after != before,
        "timeouts": asked,
    }


def make(mp3_dir, out_dir, images):
    """全部の例を回して、基準の一覧を返す。"""
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    real_timeout = aiohttp.ClientTimeout
    timeouts = []

    def scaled(total):
        """縮めた時間切れを返し、頼まれた秒を覚える。"""
        timeouts.append(total)
        return real_timeout(total=total * SCALE)

    aiohttp.ClientTimeout = scaled
    try:
        results = [asyncio.run(run_case(c, images, mp3_dir, out_dir, timeouts)) for c in all_cases(images)]
    finally:
        aiohttp.ClientTimeout = real_timeout
    return {"scale": SCALE, "cases": results}
