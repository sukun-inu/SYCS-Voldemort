#!/usr/bin/env python3
"""管理UIのデスクトップを実ブラウザで操作して確認する。

  python tools/check_admin_ui.py

使い捨ての設定ディレクトリで管理UIを起動し、Chromium で
「開く・保存する・一覧に追加する・タブを切り替える・閉じる」まで一通り操作する。
本物の settings.json やログイン中のセッションには触らない。

playwright が入っていない環境ではスキップする（インストールは
`pip install playwright && playwright install chromium`）。
"""

import base64
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="shell-check-")
os.environ["ADMIN_FLASK_SECRET_KEY"] = "x" * 64
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"
os.environ["DEV_USER_ID"] = "1"  # 開発者パネルも検証対象にする
os.environ.setdefault("DISCORD_CLIENT_ID", "0" * 18)  # 公開ページに招待ボタンを出す

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import itsdangerous  # noqa: E402
import uvicorn  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # 検証環境にブラウザが無い場合はスキップする
    print("playwright が見つからないためスキップします。")
    raise SystemExit(0)

from webapp_admin.app import app  # noqa: E402
from services.logging_service import get_log_settings  # noqa: E402
import webapp_admin.api.users as users_api  # noqa: E402
import webapp_admin.auth as admin_auth  # noqa: E402
from services import settings_store as settings_store  # noqa: E402

# チャンネル一覧は Discord を叩くので差し替える。既定は「取れなかった」状態に
# しておく（手入力へ落ちることを確かめる既存の検証がこれに依存している）。
_STUB_CHANNELS: list[dict] = []


async def _stub_guild_channels(guild_id):
    return list(_STUB_CHANNELS)


admin_auth._fetch_guild_channels = _stub_guild_channels


def _serve_channels(channels):
    """この先の画面にだけチャンネル一覧を出す。キャッシュも捨てる。"""
    _STUB_CHANNELS[:] = channels
    admin_auth._guild_channels_cache.clear()
    admin_auth._guild_channels_cooldown.clear()

# 一覧に出てこないチャンネルを指定した状態を作っておく（消えた／Bot から
# 見えない／種類が違う、を模す）。プルダウンが空欄になって設定が消えないこと。
_ORPHAN_CHANNEL = "1541471185798307800"
# 実在するチャンネルの ID（19桁）。JavaScript の数値では桁が落ちるので、
# 文字列で届かないとプルダウンが「一覧にありません」になる。
_REAL_VC = "1342455482031542302"
GUILD_ID = 999

# ユーザー状態監査は Postgres を使う。ここでは画面の確認が目的なので、
# services 層をサンプルデータに差し替えて描画だけを見る。
_SAMPLE_USER = {
    "guild_id": 999, "user_id": 555, "username": "member", "display_name": "サンプル太郎",
    "avatar_url": None, "status": "active", "is_in_guild": True, "is_banned": False,
    "is_timed_out": False, "timed_out_until": None,
    "roles": [{"id": 1, "name": "常連"}], "abilities": {"trusted_user": True},
    "last_event_type": "member_join", "last_event_at": datetime(2026, 8, 21, 3, 0, tzinfo=timezone.utc),
    "first_seen_at": None, "last_joined_at": None, "last_left_at": None, "updated_at": None,
}
_SAMPLE_EVENT = {
    "id": 1, "event_type": "member_join", "status_after": "active", "actor_user_id": None,
    "actor_name": None, "reason": None,
    "event_at": datetime(2026, 8, 21, 3, 0, tzinfo=timezone.utc), "payload": {},
}


async def _fake_list(guild_id, *, query=None, limit=50, offset=0):
    if offset:
        return []
    rows = [_SAMPLE_USER, {**_SAMPLE_USER, "user_id": 556, "display_name": "サンプル花子"}]
    if query:
        rows = [r for r in rows if query in str(r["display_name"]) or query in str(r["user_id"])]
    return rows


async def _fake_count(guild_id, *, query=None):
    return len(await _fake_list(guild_id, query=query))


async def _fake_detail(guild_id, user_id, *, event_limit=200):
    return {"current": {**_SAMPLE_USER, "user_id": user_id}, "events": [_SAMPLE_EVENT]}


users_api.list_recent_user_states = _fake_list
users_api.count_user_states = _fake_count
users_api.get_user_state_detail = _fake_detail

PORT = 5099
BASE = f"http://127.0.0.1:{PORT}"
SHOT = str(Path(tempfile.gettempdir()) / "admin-desktop.png")
SHOT_PUBLIC = str(Path(tempfile.gettempdir()) / "admin-public.png")
SHOT_NARROW = str(Path(tempfile.gettempdir()) / "admin-narrow.png")

failures = []


def check(label, condition, extra=""):
    if not condition:
        failures.append(label)
    print(f"  [{'OK' if condition else 'NG'}] {label}" + (f"  ({extra})" if extra else ""))


def session_cookie():
    payload = {
        "user": {"id": "1", "username": "tester", "global_name": "Tester", "avatar": None},
        "admin_guilds": [{"id": "999", "name": "テストサーバー", "icon": None}],
        "guild_id": 999,
        "guild_name": "テストサーバー",
        "guild_icon": None,
        "_csrf_token": "t" * 64,
    }
    data = base64.b64encode(json.dumps(payload).encode())
    return itsdangerous.TimestampSigner("x" * 64).sign(data).decode()


def main():
    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    check("サーバー起動", server.started)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1360, "height": 860})
        context.add_cookies([
            {"name": "admin_session", "value": session_cookie(), "domain": "127.0.0.1", "path": "/"}
        ])
        page = context.new_page()

        console_errors = []
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(str(e)))

        page.goto(f"{BASE}/admin/overview", wait_until="networkidle")

        # ── シェル ──
        check("Bootstrap CSS を読み込んでいない", "bootstrap.min.css" not in page.content())
        check("Bootstrap JS を読み込んでいない", "bootstrap.bundle" not in page.content())
        check("タスクバーが出る", page.locator(".taskbar").is_visible())
        check("スタートメニューが自動で開く", page.locator("#start-menu").is_visible())

        tiles = page.locator(".app-tile")
        # 枚数はパネル定義から数える（パネルを増やすたびにここを直すのは無駄なので）
        from webapp_admin.schema.registry import visible_panels
        expected_tiles = len(visible_panels(is_dev=True))
        check(f"タイルが{expected_tiles}枚（開発者パネル・SQL エディタ込み）",
              tiles.count() == expected_tiles, str(tiles.count()))

        # ── 検索 ──
        page.fill("#start-search", "ログ")
        page.wait_for_timeout(150)
        visible = page.locator(".app-tile:visible").count()
        check("検索で絞り込める", visible == 1, f"{visible} 枚")
        page.fill("#start-search", "")

        # ── ウィンドウを開く ──
        page.click('.app-tile[data-app-id="logging"]')
        page.wait_for_selector(".window .section", timeout=5000)
        check("ウィンドウが開く", page.locator(".window").count() == 1)
        check("タイトルが入る", page.locator(".window-title").inner_text() == "ログ設定",
              page.locator(".window-title").inner_text())
        check("iframe ではなく DOM で描かれている", page.locator(".window iframe").count() == 0)
        check("セクションが2つ", page.locator(".window .section").count() == 2)
        check("タスクバーにピルが出る", page.locator(".taskbar-app").count() == 1)

        fields = page.locator(".window .field")
        check("フィールドが3つ", fields.count() == 3, str(fields.count()))
        check("保存ボタンは初期状態で無効",
              page.locator(".savebar .btn-primary").is_disabled())

        # ── 明示保存 ──
        page.select_option('.window .field[data-key="log_level"] select', "DEBUG")
        page.wait_for_timeout(100)
        check("変更すると保存ボタンが有効になる",
              not page.locator(".savebar .btn-primary").is_disabled())
        check("未保存の印がタイトルバーに出る", page.locator(".window-dirty").is_visible())
        check("状態表示が変わる", "未保存の変更 1 件" in page.locator(".savebar-status").inner_text(),
              page.locator(".savebar-status").inner_text())

        page.click(".savebar .btn-primary")
        page.wait_for_selector(".toast", timeout=5000)
        check("保存でトーストが出る", "保存しました" in page.locator(".toast").inner_text(),
              page.locator(".toast").inner_text())
        check("保存後は変更なしに戻る", page.locator(".savebar-status").inner_text() == "変更はありません",
              page.locator(".savebar-status").inner_text())
        check("サーバー側にも反映されている", get_log_settings(999).get("level") == "DEBUG",
              str(get_log_settings(999)))

        # ── 一覧が取得できない環境では手入力に切り替わる ──
        check("チャンネル欄が手入力にフォールバックする",
              page.locator('.window .field[data-key="log_channel_id"] input').count() == 1)

        # ── コレクションのあるパネル ──
        page.click("#start-button")
        page.click('.app-tile[data-app-id="news-feeds"]')
        page.wait_for_selector('.window[data-app-id="news-feeds"] .empty', timeout=5000)
        check("空の一覧が案内される",
              "まだありません" in page.locator('.window[data-app-id="news-feeds"] .empty').inner_text())

        feed_window = '.window[data-app-id="news-feeds"] '
        page.fill(feed_window + '.field[data-key="channel_id"] input', "123456789012345678")
        page.fill(feed_window + '.field[data-key="query"] input', "生成AI")
        page.click(feed_window + ".btn-primary")
        page.wait_for_selector(feed_window + ".list-row", timeout=5000)
        check("一覧に追加できる", page.locator(feed_window + ".list-row").count() == 1)
        check("追加内容が表示される", "生成AI" in page.locator(feed_window + ".list-row").inner_text(),
              page.locator(feed_window + ".list-row").inner_text())

        # ── 検証エラーは該当欄の直下に出る ──
        page.fill(feed_window + '.field[data-key="channel_id"] input', "not-a-number")
        page.fill(feed_window + '.field[data-key="query"] input', "テスト")
        page.click(feed_window + ".btn-primary")
        page.wait_for_selector(feed_window + ".field.has-error", timeout=5000)
        check("不正な入力は項目の直下にエラーが出る",
              "ID" in page.locator(feed_window + '.field[data-key="channel_id"] .field-error').inner_text(),
              page.locator(feed_window + '.field[data-key="channel_id"] .field-error').inner_text())
        check("エラー時は一覧が増えない", page.locator(feed_window + ".list-row").count() == 1)

        # ── 一覧の更新と上限 ──
        # 更新なのに「追加しました」と出ていた（resetForm が編集状態を消してから判定していた）
        page.click(feed_window + '.list-row .btn:not(.btn-danger)')  # 編集
        page.wait_for_timeout(100)
        check("編集を押すとボタンが更新に変わる",
              "更新" in page.locator(feed_window + ".btn-primary").inner_text(),
              page.locator(feed_window + ".btn-primary").inner_text())
        page.fill(feed_window + '.field[data-key="query"] input', "生成AI（更新後）")
        page.click(feed_window + ".btn-primary")
        page.wait_for_function(
            """() => document.querySelector('.window[data-app-id="news-feeds"] .list-row')
                     ?.textContent.includes('更新後')""", timeout=5000)
        check("更新すると更新したと伝える", "更新しました" in page.locator(".toast").last.inner_text(),
              " ".join(page.locator(".toast").last.inner_text().split()))

        limit = page.evaluate("""async () => {
          const r = await fetch('/admin/api/apps/news-feeds', { headers: { Accept: 'application/json' } });
          const j = await r.json();
          return j.sections.flatMap(s => s.collections)[0].max_items;
        }""")
        for i in range(2, limit + 1):
            page.fill(feed_window + '.field[data-key="channel_id"] input', f"12345678901234567{i % 10}")
            page.fill(feed_window + '.field[data-key="query"] input', f"埋め{i}")
            page.click(feed_window + ".btn-primary")
            # 追加は往復するので、件数が増えるのを待つ（時間で待つと取りこぼす）
            page.wait_for_function(
                """n => document.querySelectorAll('.window[data-app-id="news-feeds"] .list-row').length === n""",
                arg=i, timeout=5000)
        check("上限まで登録すると追加ボタンが押せなくなる",
              page.locator(feed_window + ".list-row").count() == limit
              and page.locator(feed_window + ".btn-primary").is_disabled(),
              f'{page.locator(feed_window + ".list-row").count()} / {limit} 件')

        # ── タブ表示のパネル ──
        page.click("#start-button")
        page.click('.app-tile[data-app-id="tts"]')
        page.wait_for_selector('.window[data-app-id="tts"] .tabs', timeout=8000)
        tabs = page.locator('.window[data-app-id="tts"] .tab')
        check("TTS はタブで表示される", tabs.count() == 6, f"{tabs.count()} タブ")
        tabs.nth(3).click()
        page.wait_for_timeout(100)
        check("タブを切り替えられる", "デフォルト声設定" in tabs.nth(3).inner_text(), tabs.nth(3).inner_text())
        check("TTS API 不通なら声欄が手入力になる",
              page.locator('.window[data-app-id="tts"] .field[data-key="default_voice"] input').count() == 1)

        # ── VC録音のパネル ──
        _serve_channels([
            {"id": "111", "name": "general", "type": 0},
            {"id": "333", "name": "雑談VC", "type": 2},
        ])
        settings_store.set_recording_settings(GUILD_ID, {
            "enabled": True, "auto_start": True, "max_minutes": 0, "retention_days": 30,
            "announce_channel_id": int(_ORPHAN_CHANNEL), "vc_channel_id": None,
        })
        page.click("#start-button")
        page.click('.app-tile[data-app-id="recording"]')
        page.wait_for_selector('.window[data-app-id="recording"]', timeout=8000)
        page.wait_for_timeout(1500)
        rec_window = '.window[data-app-id="recording"] '
        rec_body = page.locator('.window[data-app-id="recording"]').inner_text()

        check("録音が無いときにミキサーの入口が説明される",
              "録音を停止すると" in rec_body and "ミキサー" in rec_body)

        # select.value に一覧へ無い値を入れても、ブラウザは黙って無視して空欄にする。
        # そのまま保存すると設定が消える（実際に起きた）。
        picked = page.evaluate(
            """() => Array.from(
                 document.querySelectorAll('.window[data-app-id="recording"] select'))
                 .filter((s) => !s.hidden)
                 .map((s) => ({ value: s.value,
                                text: s.selectedOptions[0] ? s.selectedOptions[0].textContent : "" }))""")
        orphan = next((x for x in picked if x["value"] == _ORPHAN_CHANNEL), None)
        check("一覧に無いチャンネルでもプルダウンが空にならない", orphan is not None,
              str([x["value"] for x in picked]))
        check("一覧に無いと分かる表示になっている",
              bool(orphan) and "一覧にありません" in orphan["text"],
              orphan["text"] if orphan else "")

        page.locator(rec_window + 'button:has-text("設定を保存")').click()
        page.wait_for_timeout(1200)
        saved = settings_store.get_recording_settings(GUILD_ID)["announce_channel_id"]
        check("そのまま保存しても設定が消えない", str(saved) == _ORPHAN_CHANNEL, f"保存後={saved}")

        # 実在するチャンネルが名前で出ること。JSON に数値で入れると
        # 1342455482031542302 → 1342455482031542300 と桁が落ちて一致しない。
        _serve_channels([
            {"id": "111", "name": "general", "type": 0},
            {"id": _REAL_VC, "name": "室内(4LDK)", "type": 2},
        ])
        settings_store.set_recording_settings(GUILD_ID, {
            "vc_channel_id": int(_REAL_VC), "announce_channel_id": None,
        })
        page.locator('.window[data-app-id="recording"] .window-control').last.click()
        page.wait_for_timeout(300)
        page.click("#start-button")
        page.click('.app-tile[data-app-id="recording"]')
        page.wait_for_selector('.window[data-app-id="recording"]', timeout=8000)
        page.wait_for_timeout(1500)

        picked = page.evaluate(
            """() => Array.from(
                 document.querySelectorAll('.window[data-app-id="recording"] select'))
                 .filter((s) => !s.hidden)
                 .map((s) => ({ value: s.value,
                                text: s.selectedOptions[0] ? s.selectedOptions[0].textContent : "" }))""")
        check("19桁のIDが桁落ちせず名前で出る",
              any(x["value"] == _REAL_VC and "室内(4LDK)" in x["text"] for x in picked),
              str(picked))

        # チェックボックスは、スキーマ駆動の画面と同じ並びにする
        boxes = page.evaluate(
            """() => Array.from(
                 document.querySelectorAll('.window[data-app-id="recording"] input[type=checkbox]'))
                 .map((b) => {
                   const label = b.closest('label.check');
                   const text = label && label.querySelector('.check-text');
                   if (!text) return { paired: false };
                   const bb = b.getBoundingClientRect(), tb = text.getBoundingClientRect();
                   return { paired: true, sameRow: Math.abs(bb.top - tb.top) < 12,
                            left: Math.round(bb.left) };
                 })""")
        check("チェックと文字が横並びになっている",
              bool(boxes) and all(b["paired"] and b["sameRow"] for b in boxes), str(boxes))
        check("チェックの左端がそろっている",
              len({b.get("left") for b in boxes if b.get("paired")}) == 1, str(boxes))

        # このあとのウィンドウ操作は開いている枚数を数えるので、閉じておく。
        page.locator('.window[data-app-id="recording"] .window-control').last.click()
        page.wait_for_timeout(400)

        # ── ウィンドウの移動とリサイズ ──
        # ここが壊れても画面は正常に見えるため、必ず実際に動かして確かめる
        win = page.locator('.window[data-app-id="logging"]')
        before = win.bounding_box()

        bar = page.locator('.window[data-app-id="logging"] .window-titlebar')
        bar_box = bar.bounding_box()
        page.mouse.move(bar_box["x"] + 120, bar_box["y"] + 12)
        page.mouse.down()
        page.mouse.move(bar_box["x"] + 220, bar_box["y"] + 92, steps=8)
        page.mouse.up()
        moved = win.bounding_box()
        check("タイトルバーでウィンドウを動かせる",
              abs(moved["x"] - before["x"]) > 50 and abs(moved["y"] - before["y"]) > 40,
              f'{int(before["x"])},{int(before["y"])} -> {int(moved["x"])},{int(moved["y"])}')

        handle = page.locator('.window[data-app-id="logging"] .window-resize')
        grip = handle.bounding_box()
        check("リサイズのつまみが右下の角にある",
              grip is not None
              and abs((grip["x"] + grip["width"]) - (moved["x"] + moved["width"])) < 12
              and abs((grip["y"] + grip["height"]) - (moved["y"] + moved["height"])) < 12,
              f'つまみ {int(grip["x"])},{int(grip["y"])} / 窓右下 '
              f'{int(moved["x"] + moved["width"])},{int(moved["y"] + moved["height"])}' if grip else "つまみ無し")

        page.mouse.move(grip["x"] + grip["width"] / 2, grip["y"] + grip["height"] / 2)
        page.mouse.down()
        page.mouse.move(grip["x"] + 140, grip["y"] + 110, steps=8)
        page.mouse.up()
        resized = win.bounding_box()
        check("つまみでリサイズできる",
              resized["width"] - moved["width"] > 80 and resized["height"] - moved["height"] > 60,
              f'{int(moved["width"])}x{int(moved["height"])} -> {int(resized["width"])}x{int(resized["height"])}')

        # ── 最大化ボタンは押したあとも「戻す」として見えていること ──
        # アイコンの差し替え先がスプライトに無いと、ボタンが無言で空になる
        maximize = page.locator('.window[data-app-id="logging"] .window-control.maximize')
        maximize.click()
        page.wait_for_timeout(300)
        box = maximize.locator(".icon").bounding_box()
        check("最大化してもボタンのアイコンが残る",
              maximize.is_visible() and box and box["width"] > 4,
              f'{int(box["width"]) if box else 0}px / {maximize.get_attribute("title")}')
        # タイトルの頭と本文の1行目の頭は同じ位置から始める。ガラスの枠(1) と
        # 余白(7)、本文の枠(1) と余白(14) を足した 23px が基準で、最大化して
        # 枠が消えれば 14px になる。どちらの状態でも合っているか実測で見る。
        title_align = """() => {
          const win = document.querySelector('.window[data-app-id="logging"]');
          const body = win.querySelector('.window-body');
          const b = body.getBoundingClientRect(), s = getComputedStyle(body);
          const round = v => Math.round(v * 10) / 10;
          return {
            left: round(win.querySelector('.window-icon').getBoundingClientRect().left
                        - (b.left + parseFloat(s.borderLeftWidth) + parseFloat(s.paddingLeft))),
            right: round(win.querySelector('.window-control.close .icon').getBoundingClientRect().right
                         - (b.right - parseFloat(s.borderRightWidth) - parseFloat(s.paddingRight))),
          };
        }"""
        # 最大化・復元は FLIP（拡大縮小）で動く。動いている間は実寸が歪むので待つ
        settled = """() => {
          const win = document.querySelector('.window[data-app-id="logging"]');
          return !!win && win.getAnimations().length === 0;
        }"""
        page.wait_for_function(settled, timeout=3000)
        big = page.evaluate(title_align)
        check("最大化でもタイトルと本文の左右が揃う",
              abs(big["left"]) <= 1 and abs(big["right"]) <= 1.5,
              f'左 {big["left"]}px / 右 {big["right"]}px')

        maximize.click()
        page.wait_for_timeout(300)
        box = maximize.locator(".icon").bounding_box()
        check("元に戻したあともアイコンが残る", box and box["width"] > 4,
              f'{int(box["width"]) if box else 0}px / {maximize.get_attribute("title")}')

        page.wait_for_function(settled, timeout=3000)
        normal = page.evaluate(title_align)
        check("タイトルと本文の左右が揃う",
              abs(normal["left"]) <= 1 and abs(normal["right"]) <= 1.5,
              f'左 {normal["left"]}px / 右 {normal["right"]}px')

        # ── ウィンドウ操作 ──
        check("ウィンドウが3枚開いている", page.locator(".window").count() == 3)
        page.locator('.window[data-app-id="tts"] .window-control').first.click()  # 最小化
        # 最小化はタスクバーへ吸い込む動きのぶん遅れて確定する。時間ではなく状態を待つ
        page.wait_for_selector(".taskbar-app.is-minimized", timeout=3000)
        check("最小化するとタスクバーが薄くなる",
              page.locator('.taskbar-app.is-minimized').count() == 1)
        page.locator(".taskbar-app.is-minimized").click()
        page.wait_for_timeout(100)
        check("タスクバーから復元できる", page.locator(".taskbar-app.is-minimized").count() == 0)

        # ── 未保存のまま閉じると確認される ──
        page.select_option('.window[data-app-id="logging"] .field[data-key="log_level"] select', "ERROR")
        page.wait_for_timeout(50)
        page.once("dialog", lambda d: d.dismiss())
        page.locator('.window[data-app-id="logging"] .window-control.close').click()
        page.wait_for_timeout(200)
        check("未保存なら閉じるのを止められる",
              page.locator('.window[data-app-id="logging"]').count() == 1)

        # ── ネイティブ実装の custom パネル（システム監視） ──
        page.click("#start-button")
        page.click('.app-tile[data-app-id="monitoring"]')
        page.wait_for_selector('.window[data-app-id="monitoring"] .metric', timeout=8000)
        metrics = page.locator('.window[data-app-id="monitoring"] .metric')
        check("システム監視が描画される", metrics.count() == 4, f"{metrics.count()} 指標")
        check("iframe ではない", page.locator('.window[data-app-id="monitoring"] iframe').count() == 0)
        check("監視履歴も出る",
              page.locator('.window[data-app-id="monitoring"] .section').count() == 2)

        # ── ユーザー状態監査（ネイティブ / サーバ側ページング） ──
        page.click("#start-button")
        page.click('.app-tile[data-app-id="user-state"]')
        page.wait_for_selector('.window[data-app-id="user-state"] .list-row', timeout=8000)
        us = '.window[data-app-id="user-state"] '
        check("ユーザー一覧が描画される", page.locator(us + ".list-row").count() == 2,
              f'{page.locator(us + ".list-row").count()} 行')
        check("iframe ではない", page.locator(us + "iframe").count() == 0)
        check("状態がラベル化されている", "在籍" in page.locator(us + ".list-row .chip").first.inner_text(),
              page.locator(us + ".list-row .chip").first.inner_text())
        # 状態ごとの色をサーバが返しているのに、クライアントが青と赤に潰していた
        tones = page.evaluate(f"""() => [...document.querySelectorAll('{us.strip()} .list-row .chip')]
          .map(c => c.className.replace('chip', '').trim())""")
        check("状態の色が状態ごとに分かれている", "success" in tones,
              " / ".join(tones) or "色なし")

        page.fill(us + 'input[type="search"]', "花子")
        page.keyboard.press("Enter")
        page.wait_for_timeout(400)
        check("サーバー側で絞り込める", page.locator(us + ".list-row").count() == 1,
              f'{page.locator(us + ".list-row").count()} 行')

        page.click(us + ".list-row .btn")
        page.wait_for_selector(us + ".section:not([hidden]) .list-row", timeout=8000)
        check("詳細に履歴が出る", "サーバー参加" in page.locator(us).inner_text())

        # ── 開発者パネル（ネイティブ・タブ構成） ──
        page.click("#start-button")
        page.click('.app-tile[data-app-id="dev"]')
        page.wait_for_selector('.window[data-app-id="dev"] .tab', timeout=8000)
        dev = '.window[data-app-id="dev"] '
        check("開発者パネルが8タブで開く", page.locator(dev + ".tab").count() == 8,
              f'{page.locator(dev + ".tab").count()} タブ')
        check("iframe ではない", page.locator(dev + "iframe").count() == 0)
        check("DEV ONLY の表示がある", "DEV ONLY" in page.locator(dev).inner_text())

        page.locator(dev + ".tab").nth(2).click()  # タスク
        page.wait_for_timeout(150)
        check("タスク一覧が出る", "ニュースフィード" in page.locator(dev).inner_text())

        # ── ログ表示 ──
        # 開いた時点で勝手に読み込み、窓の高さいっぱいに広がること。
        # （以前は「読み込む」を押すまで空で、押しても 320px しか映らなかった）
        log_file = Path(os.environ["SETTINGS_DIR"]) / "logs" / "bot.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text(
            "".join(
                f"2026-08-24 03:{i:02d}:00 [{level}] services.test: 行 {i}\n"
                for i, level in enumerate(["INFO", "DEBUG", "WARNING", "ERROR"] * 30)
            ),
            encoding="utf-8",
        )
        page.locator(dev + ".tab").nth(7).click()  # ログ
        page.wait_for_function(
            """() => document.querySelectorAll('.log-pane .log-line').length > 0""", timeout=8000
        )
        check("ログはタブを開くだけで読み込まれる",
              page.locator(dev + ".log-pane .log-line").count() >= 100,
              f'{page.locator(dev + ".log-pane .log-line").count()} 行')

        shape = page.evaluate("""() => {
          const view = document.querySelector('.log-pane .log-view').getBoundingClientRect();
          const body = document.querySelector('.window[data-app-id="dev"] .window-body').getBoundingClientRect();
          const tabs = document.querySelector('.dev-panel > .tabbed > .tabs').getBoundingClientRect();
          const v = document.querySelector('.log-pane .log-view');
          return {
            ratio: Math.round((view.height / body.height) * 100),
            spare: Math.round(body.bottom - view.bottom),
            tabs: Math.round(tabs.height),
            atBottom: v.scrollHeight - v.scrollTop - v.clientHeight < 24,
            levels: ['is-error', 'is-warn', 'is-debug']
              .map(c => document.querySelectorAll('.log-line.' + c).length),
          };
        }""")
        check("ログが窓の高さに合わせて伸びる", shape["ratio"] >= 55 and shape["spare"] < 40,
              f'本文の {shape["ratio"]}%・下の余り {shape["spare"]}px')
        # 縦に伸ばした煽りでタブの帯が潰れて消えたことがある
        check("タブの帯は潰れない", shape["tabs"] >= 28, f'{shape["tabs"]}px')
        check("最新の行が見えている", shape["atBottom"])
        check("重大度で色が分かれる", all(n > 0 for n in shape["levels"]),
              f'エラー/警告/デバッグ = {shape["levels"]}')

        # ── SQL エディタ（開発者専用） ──
        # この検証環境に Postgres は無い。繋がらないときに白紙にならず、
        # 理由が出てエディタは触れる、という状態までを見る。
        page.click("#start-button")
        page.click('.app-tile[data-app-id="sql"]')
        page.wait_for_selector(".sql-app", timeout=15000)
        page.wait_for_timeout(1500)
        sql = '.window[data-app-id="sql"] '
        check("SQL エディタが開く",
              page.locator(sql + ".sql-input").is_visible() and page.locator("#sql-css").count() == 1)
        check("既定は読み取り専用", "読み取り専用" in page.locator(sql + ".sql-mode").inner_text(),
              page.locator(sql + ".sql-mode").inner_text())
        # 接続の失敗が確定するまで待つ（読み込み中の表示のままでは見張れていない）
        try:
            page.wait_for_function(
                """() => {
                  const tree = document.querySelector('.sql-tree');
                  return tree && tree.textContent.trim() && !tree.textContent.includes('読み込み中');
                }""",
                timeout=15000,
            )
        except Exception:
            pass
        tree_text = page.locator(sql + ".sql-tree").inner_text().strip()
        check("繋がらないときは理由を出す（白紙にしない）",
              bool(tree_text) and "読み込み中" not in tree_text,
              " ".join(tree_text[:60].split()))
        page.fill(sql + ".sql-input", "select 1, 'a' -- c")
        page.wait_for_timeout(200)
        painted = page.evaluate("""() => ({
          keywords: document.querySelectorAll('.sql-highlight .tok-k').length,
          strings: document.querySelectorAll('.sql-highlight .tok-s').length,
          comments: document.querySelectorAll('.sql-highlight .tok-c').length,
          lines: document.querySelectorAll('.sql-gutter-line').length,
        })""")
        check("SQL が色分けされ、行番号が出る",
              painted["keywords"] >= 1 and painted["strings"] == 1
              and painted["comments"] == 1 and painted["lines"] == 1,
              json.dumps(painted))
        # 下地（色付き）と入力欄がずれると、二重写しに見えて字が読めなくなる
        overlay = page.evaluate("""() => {
          const pre = document.querySelector('.sql-highlight');
          const ta = document.querySelector('.sql-input');
          const a = pre.getBoundingClientRect(), b = ta.getBoundingClientRect();
          const s = getComputedStyle(pre), t = getComputedStyle(ta);
          return {
            dx: Math.round((a.left - b.left) * 100) / 100,
            dy: Math.round((a.top - b.top) * 100) / 100,
            same: s.fontFamily === t.fontFamily && s.fontSize === t.fontSize
                  && s.lineHeight === t.lineHeight && s.paddingLeft === t.paddingLeft
                  && s.paddingTop === t.paddingTop,
          };
        }""")
        check("色分けの層と入力欄がぴったり重なる",
              abs(overlay["dx"]) < 0.5 and abs(overlay["dy"]) < 0.5 and overlay["same"],
              json.dumps(overlay))
        page.locator(sql + ".window-control.close").click()
        page.wait_for_timeout(300)

        # ── 配置の保存 ──
        stored = page.evaluate("() => window.localStorage.getItem('voldemort.desktop.layout.v1')")
        check("ウィンドウ配置が保存されている", stored and "news-feeds" in stored, (stored or "")[:80])

        # 最小化中は実測できない（display:none で 0×0）。そのまま保存すると、
        # 次に開いたときに前回の位置と大きさが失われる。
        # いちばん手前の窓（開発者パネル）を最小化して、保存された配置を見る
        page.locator('.window[data-app-id="dev"] .window-control').first.click()
        page.wait_for_selector('.taskbar-app.is-minimized', timeout=3000)
        saved = page.evaluate("""() => {
          const layout = JSON.parse(window.localStorage.getItem('voldemort.desktop.layout.v1'));
          return layout.windows.find(w => w.appId === 'dev') || null;
        }""")
        check("最小化中でも元の大きさを保存する",
              bool(saved) and saved["minimized"] and saved["w"] >= 320 and saved["h"] >= 200,
              f'{saved["w"]}x{saved["h"]} at {saved["x"]},{saved["y"]}' if saved else "保存なし")
        page.locator(".taskbar-app.is-minimized").click()  # 元に戻す
        page.wait_for_timeout(300)

        # ── 選択肢を持たない項目に「取得できませんでした」と出さない ──
        # メッセージID(snowflake) は元から一覧を引かない。壊れていないのに壊れて見えていた。
        page.click("#start-button")
        page.click('.app-tile[data-app-id="reaction-roles"]')
        page.wait_for_selector('.window[data-app-id="reaction-roles"] .field', timeout=8000)
        notes = page.evaluate("""() => {
          const out = {};
          for (const field of document.querySelectorAll('.window[data-app-id="reaction-roles"] .field')) {
            const key = field.dataset.key || '';
            out[key] = [...field.querySelectorAll('.field-help')]
              .some(p => p.textContent.includes('取得できませんでした'));
          }
          return out;
        }""")
        check("一覧を引かない項目に取得失敗の断りを出さない",
              notes.get("message_id") is False and notes.get("role_id") is True,
              json.dumps(notes, ensure_ascii=False))

        # ── タスクバーの中身が帯の中心に来るか ──
        # 上端の 1px の枠は内容の領域を 1px 下げる。行の高さが 1.7 のままだと
        # ピルの高さも 34.09px のような半端な値になり、上下の余白が 1px 割れる。
        pills = page.evaluate("""() => {
          const bar = document.querySelector('.taskbar').getBoundingClientRect();
          const mid = r => (r.top + r.bottom) / 2;
          const out = {};
          for (const sel of ['.start-button', '.taskbar-app', '.tray-button']) {
            const el = document.querySelector(sel);
            if (!el) continue;
            const r = el.getBoundingClientRect();
            out[sel] = { d: Math.round((mid(r) - mid(bar)) * 100) / 100, h: r.height };
          }
          return out;
        }""")
        check("タスクバーのピルが帯の中心に整数の高さで並ぶ",
              bool(pills) and all(abs(v["d"]) <= 0.5 and v["h"] % 1 == 0 for v in pills.values()),
              " / ".join(f'{k} {v["h"]:g}px {v["d"]:+g}' for k, v in pills.items()))

        # ── アイコンが実際に描かれているか（スプライト参照の確認） ──
        icon_count = page.locator(".icon").count()
        box = page.locator(".icon").first.bounding_box()
        check("アイコンがスプライトから描画される", icon_count > 10 and box and box["width"] > 0,
              f'{icon_count} 個 / {box["width"] if box else 0}px')

        page.screenshot(path=SHOT, full_page=False)



        # ── リロードで配置が戻る / ディープリンク ──
        page.reload(wait_until="networkidle")
        page.wait_for_selector(".window", timeout=8000)
        restored = page.locator(".window").count()
        check("リロード後にウィンドウが復元される", restored >= 4, f"{restored} 枚")

        page.goto(f"{BASE}/admin/overview#security", wait_until="networkidle")
        page.wait_for_selector('.window[data-app-id="security"]', timeout=8000)
        check("ハッシュでアプリを開ける", page.locator('.window[data-app-id="security"]').count() == 1)

        page.goto(f"{BASE}/admin/settings/djaudio", wait_until="networkidle")
        page.wait_for_selector('.window[data-app-id="djaudio"]', timeout=8000)
        check("設定ページへの直接アクセスがデスクトップに集約される",
              page.locator('.window[data-app-id="djaudio"]').count() == 1
              and "open=" not in page.url, page.url)

        # ── 通知（トースト） ──
        toast = page.evaluate("""async () => {
          const m = await import('/static/js/lib/toast.js');
          const node = m.toast('設定を保存しました', 'success', { duration: 0 });
          const s = getComputedStyle(node);
          const alpha = (s.backgroundColor.match(/[\\d.]+/g) || [])[3];
          // 中身は1行目の中心に置く。閉じるボタンが箱の高さを決めてしまうと、
          // 1行の通知でも文章が上へ寄る（上 13px / 下 19px に割れていた）。
          const mid = r => (r.top + r.bottom) / 2;
          const box = node.getBoundingClientRect();
          const text = document.createRange();
          text.selectNodeContents(node.querySelector('.grow'));
          const line = text.getBoundingClientRect();
          const round = v => Math.round(v * 100) / 100;
          return {
            glass: s.backdropFilter !== 'none' || s.webkitBackdropFilter !== 'none',
            alpha: alpha === undefined ? 1 : Number(alpha),
            lens: node.classList.contains('lens'),
            width: Math.round(node.getBoundingClientRect().width),
            icon: round(mid(node.querySelector(':scope > .icon').getBoundingClientRect()) - mid(line)),
            close: round(mid(node.querySelector('.toast-close').getBoundingClientRect()) - mid(line)),
            above: round(line.top - box.top),
            below: round(box.bottom - line.bottom),
          };
        }""")
        check("通知がガラス（背後が透ける）",
              toast["glass"] and toast["alpha"] < 0.9 and toast["lens"],
              f'不透明度 {toast["alpha"]:.2f} / 幅 {toast["width"]}px')
        check("通知の中身が1行目の中心に並ぶ",
              abs(toast["icon"]) <= 1 and abs(toast["close"]) <= 1
              and abs(toast["above"] - toast["below"]) <= 1,
              f'アイコン {toast["icon"]:+g} / 閉じる {toast["close"]:+g} / '
              f'上下 {toast["above"]:g}:{toast["below"]:g}')

        # ── 公開ページ（新CSSへ移行済み） ──
        for path_, needle in [("/", ".landing-hero"), ("/guide", ".doc-wrap"),
                              ("/privacy", ".doc-section"), ("/terms", ".doc-section")]:
            page.goto(f"{BASE}{path_}", wait_until="networkidle")
            visible = page.locator(needle).first.is_visible()
            icons = page.locator(".icon").count()
            check(f"公開ページ {path_}", visible and icons > 0, f'アイコン {icons} 個')

            # ブランドのマークと文字は中心を揃える。<img> をインラインのまま
            # <span> に入れると、行boxの descent ぶん（14px × 1.7 で約 7.8px）
            # 入れ物だけ背が高くなり、マークが文字より約 4px 上へずれる。
            brand = page.evaluate("""() => {
              const link = document.querySelector('.brand-link');
              const img = link.querySelector('.brand-mark-image').getBoundingClientRect();
              const r = document.createRange();
              r.selectNodeContents(link.querySelector('.brand-name'));
              const t = r.getBoundingClientRect();
              const mid = b => (b.top + b.bottom) / 2;
              return Math.round((mid(img) - mid(t)) * 100) / 100;
            }""")
            check(f"ブランドのマークと文字の中心が揃う {path_}", abs(brand) <= 1, f'{brand:+g}px')

            if path_ == "/":
                page.screenshot(path=SHOT_PUBLIC, full_page=False)

                # 機能カードの枠。罫線は 1px の隙間から下地を覗かせて引くので、
                #   - セルが埋まっていないと、そこだけ罫線色の塊が出る
                #   - 隙間が無いと、罫線そのものが1本も見えない（実際にそうなっていた）
                # の両方を実測で見る。
                grid = page.evaluate("""() => {
                  const grid = document.querySelector('.feature-grid');
                  const cs = getComputedStyle(grid);
                  const g = grid.getBoundingClientRect();
                  const inner = (g.width - parseFloat(cs.borderLeftWidth) - parseFloat(cs.borderRightWidth))
                              * (g.height - parseFloat(cs.borderTopWidth) - parseFloat(cs.borderBottomWidth));
                  const cards = [...grid.children].map(c => c.getBoundingClientRect());
                  const covered = cards.reduce((sum, r) => sum + r.width * r.height, 0);
                  let seams = 0;
                  for (const a of cards) for (const b of cards) {
                    if (a === b) continue;
                    const dx = b.left - a.right, dy = b.top - a.bottom;
                    if (dx >= 0.9 && dx <= 1.6) seams++;
                    if (dy >= 0.9 && dy <= 1.6) seams++;
                  }
                  return {
                    cols: cs.gridTemplateColumns.split(' ').length,
                    coverage: covered / inner,
                    seams,
                    ruled: cs.backgroundColor !== getComputedStyle(grid.firstElementChild).backgroundColor,
                  };
                }""")
                check("機能カードの枠に空きセルが残らない", grid["coverage"] > 0.985,
                      f'{grid["cols"]} 列 / 埋まり {grid["coverage"] * 100:.1f}%')
                check("機能カードの間に罫線が見える", grid["seams"] > 0 and grid["ruled"],
                      f'継ぎ目 {grid["seams"]} 箇所 / 下地の塗り分け {grid["ruled"]}')

            if path_ == "/":
                body = page.locator("body").inner_text()
                check("トップに VC録音 が載っている", "VC録音" in body)
                check("録音対象から外れる手段がトップに書いてある",
                      "/record exclude" in body)

            if path_ == "/guide":
                body = page.locator("body").inner_text()
                # 録音は個人に紐づく情報を扱う。参加者が「自分は対象から
                # 外れられる」と知る手段が公開ページに無いと具合が悪い。
                check("使い方に VC録音 の節がある", "VC録音" in body)
                check("録音が必ず通知されると書いてある", "必ず投稿されます" in body)
                check("/record exclude が誰でも使えると分かる",
                      "/record exclude" in body and "誰でも使えます" in body)
                check("録音データの保存期限が書いてある",
                      "7 日" in body and "30 日" in body)
                check("政府機関以外に使わない旨がある",
                      "政府機関への提供が必要な場合を除き" in body)
                check("ミキサーの説明がある", "ミキサー" in body and "波形" in body)
                # コマンド名をグループ化したので、旧名が残っていないこと
                stale = [n for n in ("/metal_", "/server_info", "/user_info",
                                     "/bot_help") if n in body]
                check("旧コマンド名が残っていない", not stale, str(stale))
                check("新コマンド名になっている",
                      "/metal gold" in body and "/info server" in body)

                # 読み物ページは1本の柱で組む。見出し・本文・コマンド一覧・
                # 箇条書き・ボタンの左端がすべて同じ位置から始まること。
                # （コマンド一覧だけ 4px 内側に入り、罫線だけ全幅で伸びていた）
                doc = page.evaluate("""() => {
                  const wrap = document.querySelector('.doc-wrap');
                  const L = wrap.getBoundingClientRect().left
                          + parseFloat(getComputedStyle(wrap).paddingLeft);
                  const left = sel => {
                    const el = document.querySelector(sel);
                    return el ? Math.round((el.getBoundingClientRect().left - L) * 10) / 10 : null;
                  };
                  const links = document.querySelector('.doc-links').getBoundingClientRect();
                  const legal = document.querySelector('.doc-legal').getBoundingClientRect();
                  const icon = document.querySelector('.doc-section h2 .icon').getBoundingClientRect();
                  return {
                    cols: {
                      'セクション': left('.doc-section'),
                      '見出し': left('.doc-section h2 .icon'),
                      'コマンド': left('.doc-cmd-name'),
                      '箇条書き': left('.doc-section ul > li'),
                      'ボタン': left('.doc-links .btn'),
                    },
                    gap: Math.round((legal.top - links.bottom) * 10) / 10,
                    iconWidth: Math.round(icon.width * 10) / 10,
                  };
                }""")
                check("読み物ページの左端が1本に揃う",
                      set(doc["cols"].values()) == {0},
                      " / ".join(f"{k} {v}" for k, v in doc["cols"].items()))
                # 罫線を持つ帯に上の余白が無いと、直前のボタンの下端に線が接する
                check("末尾の罫線がボタンに接しない", doc["gap"] >= 24, f'{doc["gap"]:g}px')
                # .doc-section h2 .icon は body.public h2 .icon に負けやすい
                check("見出しのアイコンが指定どおりの大きさ", doc["iconWidth"] == 17,
                      f'{doc["iconWidth"]:g}px')

            if path_ in ("/", "/guide"):
                # 手順リスト。li を flex にすると、地の文と <strong> が
                # それぞれ別の列に分かれて文章が崩れる（実際に壊れていた）。
                steps = page.evaluate("""() => {
                  const li = document.querySelector('.step-list li');
                  if (!li) return null;
                  const s = getComputedStyle(li);
                  const marker = getComputedStyle(li, '::before');
                  return {
                    display: s.display,
                    padding: parseFloat(s.paddingLeft),
                    markerPosition: marker.position,
                    lines: li.getClientRects().length,
                  };
                }""")
                check(f"{path_} の手順が1つの文として流れる",
                      steps is not None
                      and steps["display"] not in ("flex", "grid", "inline-flex")
                      and steps["markerPosition"] == "absolute"
                      and steps["padding"] >= 24,
                      f'display:{steps and steps["display"]} / 番号:{steps and steps["markerPosition"]}')

        # ログイン画面はセッションが無い状態でしか出ない（ある場合はデスクトップへ飛ぶ）
        anon = browser.new_context(viewport={"width": 1360, "height": 860})
        anon_page = anon.new_page()
        anon_page.goto(f"{BASE}/admin/login", wait_until="networkidle")
        check("ログイン画面", anon_page.locator(".login-card").is_visible()
              and anon_page.locator(".icon").count() > 0,
              f'アイコン {anon_page.locator(".icon").count()} 個')
        anon.close()
        # ── 動き ──
        # 動きを抑える設定のときに止まるかどうかは、CSS と JS の両方で担保している。
        # 片方だけ直しても気付けないので、実際に開いて測る。
        motion = browser.new_context(viewport={"width": 1360, "height": 860})
        motion.add_cookies([
            {"name": "admin_session", "value": session_cookie(), "domain": "127.0.0.1", "path": "/"}
        ])
        mpage = motion.new_page()
        mpage.goto(f"{BASE}/admin/overview", wait_until="networkidle")
        mpage.wait_for_selector(".app-tile", timeout=8000)
        mpage.click('.app-tile[data-app-id="logging"]')
        mpage.wait_for_selector(".window", timeout=8000)
        moving = mpage.evaluate("""() => {
          const s = getComputedStyle(document.querySelector('.window'));
          const bar = getComputedStyle(document.querySelector('.taskbar'));
          return { window: s.animationName, duration: s.animationDuration, taskbar: bar.animationName };
        }""")
        check("ウィンドウとタスクバーに動きが付いている",
              moving["window"] == "window-open" and moving["taskbar"] == "taskbar-rise"
              and moving["duration"] not in ("0s", "0.001ms"),
              f'{moving["window"]} {moving["duration"]} / {moving["taskbar"]}')
        motion.close()

        calm = browser.new_context(viewport={"width": 1360, "height": 860}, reduced_motion="reduce")
        calm.add_cookies([
            {"name": "admin_session", "value": session_cookie(), "domain": "127.0.0.1", "path": "/"}
        ])
        cpage = calm.new_page()
        cpage.goto(f"{BASE}/admin/overview", wait_until="networkidle")
        cpage.wait_for_selector(".app-tile", timeout=8000)
        cpage.click('.app-tile[data-app-id="logging"]')
        cpage.wait_for_selector(".window", timeout=8000)
        duration = cpage.evaluate("""() => {
          const value = getComputedStyle(document.querySelector('.window')).animationDuration;
          return parseFloat(value) * (value.endsWith('ms') ? 0.001 : 1);
        }""")
        check("動きを抑える設定では動かさない（CSS）", duration < 0.01, f"{duration}s")
        cpage.locator(".window-control").first.click()  # 最小化
        # play() が降りていれば、待たずに最小化が確定する
        cpage.wait_for_selector(".taskbar-app.is-minimized", timeout=400)
        check("動きを抑える設定では待たされない（JS）", True)
        calm.close()

        # ── 狭い画面（スマートフォン相当） ──
        narrow = browser.new_context(viewport={"width": 390, "height": 844})
        narrow.add_cookies([
            {"name": "admin_session", "value": session_cookie(), "domain": "127.0.0.1", "path": "/"}
        ])
        npage = narrow.new_page()
        npage.goto(f"{BASE}/admin/overview", wait_until="networkidle")
        npage.wait_for_selector(".app-tile", timeout=8000)
        npage.click('.app-tile[data-app-id="logging"]')
        npage.wait_for_selector(".window .section", timeout=8000)
        npage.click("#start-button")
        npage.click('.app-tile[data-app-id="welcome"]')
        npage.wait_for_timeout(700)

        start_box = npage.locator("#start-button").bounding_box()
        check("狭い画面でスタートボタンが折れない", start_box["height"] < 40,
              f'高さ {int(start_box["height"])}px')

        bar = npage.locator(".taskbar").bounding_box()
        tray = npage.locator(".taskbar-tray").bounding_box()
        check("トレイが画面内に収まる", tray["x"] + tray["width"] <= bar["width"] + 2,
              f'右端 {int(tray["x"] + tray["width"])} / 画面 {int(bar["width"])}')

        check("常に最大化される画面では最大化ボタンを出さない",
              npage.locator(".window-control.maximize").first.is_hidden())

        win_box = npage.locator(".window").first.bounding_box()
        check("窓が画面いっぱいに開く", win_box["width"] >= 388, f'{int(win_box["width"])}px')

        npage.screenshot(path=str(SHOT_NARROW))

        # ── 狭い画面の公開ページ ──
        # ランディングはハンバーガーに畳むが、ガイド・規約・ポリシーはボタンが
        # 出たまま。横に詰めると文字が縦に折れて読めなくなる（実際にそうなっていた）。
        for path_ in ("/", "/guide", "/terms", "/privacy"):
            npage.goto(f"{BASE}{path_}", wait_until="networkidle")
            bar = npage.evaluate("""() => {
              const visible = el => el && el.getClientRects().length > 0;
              const brand = document.querySelector('.brand-name');
              const btns = [...document.querySelectorAll('.topbar-actions .btn')].filter(visible);
              return {
                brand: Math.round(brand.getBoundingClientRect().height),
                btns: btns.map(b => Math.round(b.getBoundingClientRect().height)),
                overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
              };
            }""")
            check(f"狭い画面の上部バーが折れない {path_}",
                  bar["brand"] <= 30 and all(h <= 44 for h in bar["btns"]) and not bar["overflow"],
                  f'ブランド {bar["brand"]}px / ボタン {bar["btns"]}')

        # 開いたモバイルナビが、画面を広げたあとも残らないこと
        npage.goto(f"{BASE}/", wait_until="networkidle")
        npage.click(".landing-menu-toggle")
        npage.wait_for_timeout(150)
        opened = npage.locator(".landing-mobile-nav").is_visible()
        npage.set_viewport_size({"width": 1200, "height": 844})
        npage.wait_for_timeout(200)
        check("モバイルナビは狭い画面でだけ開く",
              opened and not npage.locator(".landing-mobile-nav").is_visible(),
              f'狭い画面で開く {opened}')

        narrow.close()

        # この検証環境に由来するものは除外する:
        #   422 = 検証エラー表示のテストで意図的に出したもの
        #   500 = ユーザー状態監査ページが Postgres を必要とするため（埋め込み経路の確認が目的）
        #   502 = SQL エディタの接続先（Postgres）がこの環境に無いため
        #   Failed to fetch = テストが次のページへ遷移したことによる中断
        ignorable = ("422", "500", "502", "Failed to fetch")
        unexpected = [e for e in console_errors if not any(token in e for token in ignorable)]
        check("コンソールエラーなし", not unexpected, "; ".join(unexpected[:3]))

        browser.close()

    print()
    print(f"スクリーンショット: {SHOT} / {SHOT_PUBLIC} / {SHOT_NARROW}")
    print("RESULT:", "all passed" if not failures else f"{len(failures)} 件失敗")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
