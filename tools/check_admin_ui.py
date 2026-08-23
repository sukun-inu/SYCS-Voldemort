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
        check("タイルが13枚（開発者パネル込み）", tiles.count() == 13, str(tiles.count()))

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
        maximize.click()
        page.wait_for_timeout(300)
        box = maximize.locator(".icon").bounding_box()
        check("元に戻したあともアイコンが残る", box and box["width"] > 4,
              f'{int(box["width"]) if box else 0}px / {maximize.get_attribute("title")}')

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

        page.locator(dev + ".tab").nth(7).click()  # ログ
        page.wait_for_timeout(150)
        page.locator(dev + ".btn").last.click()
        page.wait_for_timeout(600)
        check("ログを読み込める", len(page.locator(dev + ".log-view").last.inner_text()) > 0,
              " ".join(page.locator(dev + ".log-view").last.inner_text()[:40].split()))

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
          return {
            glass: s.backdropFilter !== 'none' || s.webkitBackdropFilter !== 'none',
            alpha: alpha === undefined ? 1 : Number(alpha),
            lens: node.classList.contains('lens'),
            width: Math.round(node.getBoundingClientRect().width),
          };
        }""")
        check("通知がガラス（背後が透ける）",
              toast["glass"] and toast["alpha"] < 0.9 and toast["lens"],
              f'不透明度 {toast["alpha"]:.2f} / 幅 {toast["width"]}px')

        # ── 公開ページ（新CSSへ移行済み） ──
        for path_, needle in [("/", ".landing-hero"), ("/guide", ".doc-wrap"),
                              ("/privacy", ".doc-section"), ("/terms", ".doc-section")]:
            page.goto(f"{BASE}{path_}", wait_until="networkidle")
            visible = page.locator(needle).first.is_visible()
            icons = page.locator(".icon").count()
            check(f"公開ページ {path_}", visible and icons > 0, f'アイコン {icons} 個')
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
        #   Failed to fetch = テストが次のページへ遷移したことによる中断
        ignorable = ("422", "500", "Failed to fetch")
        unexpected = [e for e in console_errors if not any(token in e for token in ignorable)]
        check("コンソールエラーなし", not unexpected, "; ".join(unexpected[:3]))

        browser.close()

    print()
    print(f"スクリーンショット: {SHOT} / {SHOT_PUBLIC} / {SHOT_NARROW}")
    print("RESULT:", "all passed" if not failures else f"{len(failures)} 件失敗")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
