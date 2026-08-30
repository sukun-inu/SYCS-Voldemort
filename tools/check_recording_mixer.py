#!/usr/bin/env python3
"""録音ミキサーを実ブラウザで確かめる。

  python tools/check_recording_mixer.py

見ているのは2つ。どちらも単体テストでは捕まえられない（描画と <audio> の
挙動はブラウザの中でしか起きない）。

  1. 波形が録音全体に渡って描かれること
     録音側は点数が多くなりすぎないよう目盛りを間引くが、間引いたことを索引に
     書いていなかったため、12.5分を超える録音では波形が時間軸の先頭へ圧縮
     されていた（6時間なら全体が先頭12.4分ぶんに潰れる）。

  2. 全トラックが同じ位置を再生していること
     読み込みが終わっていない <audio> は currentTime への代入を黙って捨てる。
     待たずに再生していたため、そのトラックだけ 0 秒から鳴っていた。

     ただし断っておくと、こちらは「壊れていないこと」を守るための検査で、
     報告されたずれを再現するものではない。headless Chromium では3本の
     <audio> がほとんど離れないため、直す前のコード（0.25秒ずれるまで放置し、
     直し方は毎回の頭出し）でもこの検査は通ってしまう。実機で会話が二重に
     聞こえる状態を再現するには、実際の録音と実際のブラウザが要る。

使い捨ての設定ディレクトリで管理UIを起動し、その上でミキサーを直接読み込む。
本物の settings.json やログイン中のセッションには触らない。
playwright / ffmpeg が無い環境ではスキップする。
"""

import json
import math
import os
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

os.environ["SETTINGS_DIR"] = tempfile.mkdtemp(prefix="mixer-check-")
os.environ["DJAUDIO_CACHE_DIR"] = tempfile.mkdtemp(prefix="mixer-cache-")
os.environ["ADMIN_FLASK_SECRET_KEY"] = "x" * 64
os.environ["TTS_BASE_URL"] = "http://127.0.0.1:9"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright が見つからないためスキップします。")
    raise SystemExit(0)

from config import DJAUDIO_FFMPEG_PATH  # noqa: E402
from webapp_admin.app import app  # noqa: E402

GUILD_ID = 999
PORT = 8899
BASE = f"http://127.0.0.1:{PORT}"

_failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'NG'}] {label}{(' … ' + detail) if detail else ''}")
    if not ok:
        _failures.append(f"{label}{(' … ' + detail) if detail else ''}")


# ── 録音アーカイブを作る ─────────────────────────────────────


def _tone(seconds: float, hz: int, amplitude: int = 12000) -> bytes:
    from services.recording_service import SAMPLE_RATE

    out = bytearray()
    for i in range(int(SAMPLE_RATE * seconds)):
        v = int(amplitude * math.sin(2 * math.pi * hz * i / SAMPLE_RATE))
        out += struct.pack("<hh", v, v)
    return bytes(out)


def _session(recording, channel_name: str):
    return recording.RecordingSession(
        guild_id=GUILD_ID,
        channel_id=1,
        channel_name=channel_name,
        started_by_id=1,
        started_by_name="検査",
        started_at=time.monotonic(),
        max_seconds=0,
        retention_days=1,
    )


def build_long_recording() -> str:
    """2時間ぶんの目盛りを持つ録音。波形の縮尺を見るためのもの。

    2時間ぶんの無音を本当に ffmpeg へ流すと数GBになるので、目盛りだけ直接
    置いて書き出しを通す（描画に使うのは索引の中の目盛りだけ）。
    """
    from services import recording_service as recording

    session = _session(recording, "長い録音")
    for user_id, name, hz in ((1, "あかり", 220), (2, "ひかる", 330), (3, "みなと", 440)):
        session.feed(Mock(id=user_id, display_name=name), _tone(0.4, hz))

    duration = 2 * 3600.0
    buckets = int(duration / recording.PEAK_BUCKET_SECONDS)
    tracks = list(session.tracks.values())
    # 全員が最後まで喋っている状態にする（末尾に波形が来るはず）。
    for track in tracks:
        track.peaks = [30000] * buckets
    # 途中（60%）で書き込みが止まったトラック。長いほうの縮尺に揃うこと。
    tracks[-1].peaks = [30000] * int(buckets * 0.6)

    with (
        patch.object(recording._TrackWriter, "pad_until", lambda self, *a, **k: None),
        patch.object(recording, "measure_voice", return_value=None),
    ):
        result = recording._finalize(session, duration, "検査")
    return result["token"]


def build_playable_recording() -> str:
    """実際に鳴らせる録音。再生位置の一致を見るためのもの。"""
    from services import recording_service as recording

    session = _session(recording, "短い録音")
    for user_id, name, hz in ((1, "あかり", 220), (2, "ひかる", 330), (3, "みなと", 440)):
        # 20秒。3本とも同じ長さ・同じ時間軸に揃う。
        session.feed(Mock(id=user_id, display_name=name), _tone(20.0, hz))

    with patch.object(recording, "measure_voice", return_value=None):
        result = recording._finalize(session, 20.0, "検査")
    return result["token"]


# ── ブラウザ ─────────────────────────────────────────────────

HARNESS = """<!doctype html><meta charset="utf-8">
<link rel="stylesheet" href="/static/css/tokens.css">
<link rel="stylesheet" href="/static/css/base.css">
<link rel="stylesheet" href="/static/css/components.css">
<style>#stage{width:900px;height:520px}</style>
<div id="stage"></div>
<script type="module">
  import { createMixer } from "/static/js/apps/mixer.js";
  window.__ready = createMixer(document.getElementById("stage"), {
    manifestUrl: TOKEN_URL + "/mixer",
    clipUrl: TOKEN_URL + "/clip",
    analysisUrl: TOKEN_URL + "/analysis",
  }).then((handle) => { window.__mixer = handle; return true; });
</script>"""


def open_mixer(page, token: str):
    url = f"/dlaudio/files/{GUILD_ID}/{token}"
    html = HARNESS.replace("TOKEN_URL", json.dumps(url))
    page.route(
        f"{BASE}/__mixer_check__",
        lambda route: route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html),
    )
    page.goto(f"{BASE}/__mixer_check__")
    page.wait_for_function("window.__ready !== undefined")
    page.evaluate("window.__ready")
    page.wait_for_function("window.__mixer !== undefined", timeout=20000)
    # 最初の描画（zoomToFit）が終わるまで待つ
    page.wait_for_timeout(400)


def inked_ratio(page) -> list[float]:
    """いま見えている範囲の何割に波形が描かれているか（トラックごと）。

    レーンには波形のほかに時間の罫線と中心線も引かれる。どちらも上下いっぱいに
    伸びるので「その位置に何か描かれているか」では区別できない（最初これで
    常に 1.0 になり、検査が何も見ていなかった）。罫線は灰色、波形はトラックの
    色なので、彩度で選り分ける。
    """
    return page.evaluate(
        """() => {
      const out = [];
      for (const canvas of document.querySelectorAll(".daw-lane-canvas")) {
        const ctx = canvas.getContext("2d");
        const { width, height } = canvas;
        if (!width || !height) { out.push(0); continue; }
        const data = ctx.getImageData(0, 0, width, height).data;
        let inked = 0;
        for (let x = 0; x < width; x += 1) {
          for (let y = 0; y < height; y += 2) {
            const i = (y * width + x) * 4;
            if (data[i + 3] < 40) continue;
            const r = data[i], g = data[i + 1], b = data[i + 2];
            if (Math.max(r, g, b) - Math.min(r, g, b) > 30) { inked += 1; break; }
          }
        }
        out.push(inked / width);
      }
      return out;
    }"""
    )


def scroll_to(page, seconds_fraction: float) -> None:
    """時間軸の指定した割合の位置まで横スクロールする（利用者と同じ操作）。"""
    page.evaluate(
        """(fraction) => {
      const scroller = document.querySelector(".daw-scroll");
      const spacer = document.querySelector(".daw-spacer");
      const total = parseFloat(spacer.style.width) || scroller.scrollWidth;
      scroller.scrollLeft = Math.max(0, total * fraction - scroller.clientWidth / 2);
      scroller.dispatchEvent(new Event("scroll"));
    }""",
        seconds_fraction,
    )
    page.wait_for_timeout(250)


def main() -> int:
    if not Path(DJAUDIO_FFMPEG_PATH).exists() and not DJAUDIO_FFMPEG_PATH == "ffmpeg":
        print("ffmpeg が見つからないためスキップします。")
        return 0

    print("録音アーカイブを作成中…")
    long_token = build_long_recording()
    play_token = build_playable_recording()

    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--autoplay-policy=no-user-gesture-required"])
            page = browser.new_page(viewport={"width": 1200, "height": 800})
            page.on("pageerror", lambda e: _failures.append(f"ページ内の例外: {e}"))

            print("\n== 1. 長い録音の波形が全体に渡ること（2時間） ==")
            open_mixer(page, long_token)
            # 1・2本目は最後まで喋っている。3本目は録音の途中（60%）で
            # 書き込みが止まった作りにしてある。索引の縮尺が合っていれば、
            # スクロールした先に「止まったところまで」が正しく現れる。
            # 合っていないと、どのトラックも冒頭のごく一部に潰れて、
            # 中盤から先はまるごと空白になる。
            for fraction, label in ((0.0, "冒頭"), (0.5, "中間"), (0.95, "終盤")):
                scroll_to(page, fraction)
                ratios = inked_ratio(page)
                full = ratios[:2]
                check(
                    f"{label}に波形が描かれている（最後まで喋っている2本）",
                    len(full) == 2 and min(full) > 0.8,
                    f"塗り={['%.2f' % r for r in ratios]}",
                )

            # 途中で終わったトラックが、同じ時間軸の上で正しく終わっていること。
            # 縮尺が自分の長さ基準だと、ここが横に引き伸ばされて最後まで
            # 波形が続いてしまう（他のトラックと位置が合わない）。
            scroll_to(page, 0.3)
            early = inked_ratio(page)[2]
            check("途中で終わったトラックも、終わるまでは同じ位置に描かれる", early > 0.8, f"30%地点の塗り={early:.2f}")
            scroll_to(page, 0.95)
            late = inked_ratio(page)[2]
            check("途中で終わったトラックは、その先が空になる", late < 0.05, f"95%地点の塗り={late:.2f}")
            page.evaluate("window.__mixer.destroy()")

            print("\n== 2. 区切り配信での再生（時計が1つ） ==")
            open_mixer(page, play_token)
            played = page.evaluate(
                r"""async () => {
              const stage = document.getElementById("stage");
              const clockText = () => stage.querySelector(".daw-clock").textContent || "";
              const clock = () => {
                const head = clockText().split("/")[0].trim();
                const m = head.match(/(?:(\d+):)?(\d+):(\d+)\.(\d+)/) || head.match(/(\d+):(\d+)\.(\d+)/);
                if (!m) return 0;
                const parts = m.slice(1).filter((v) => v !== undefined).map(Number);
                const cents = parts.pop();
                let seconds = 0;
                for (const p of parts) seconds = seconds * 60 + p;
                return seconds + cents / 100;
              };
              const lane = document.querySelector(".daw-lanes");
              const box = lane.getBoundingClientRect();
              lane.dispatchEvent(new PointerEvent("pointerdown", {
                clientX: box.left + box.width * 0.5, clientY: box.top + 20, bubbles: true,
              }));
              await new Promise((r) => setTimeout(r, 300));
              const afterSeek = clock();
              [...stage.querySelectorAll("button")]
                .find((b) => b.textContent.includes("再生")).click();
              await new Promise((r) => setTimeout(r, 2000));
              return { afterSeek, whilePlaying: clock(), raw: clockText(),
                       audios: document.querySelectorAll("audio").length };
            }"""
            )
            check(
                "トラックごとの <audio> を持たない（音源が1つ）",
                played["audios"] == 0,
                f"<audio> が {played['audios']} 本ある",
            )
            check("頭出しが効く", played["afterSeek"] > 0.5, f"{played['afterSeek']:.2f} 秒 / 時計={played['raw']}")
            check(
                "再生位置が進む",
                played["whilePlaying"] > played["afterSeek"] + 0.5,
                f"{played['afterSeek']:.2f} -> {played['whilePlaying']:.2f} 秒",
            )
            page.evaluate("window.__mixer.destroy()")

            print("\n== 3. 従来経路（区切り配信が使えない古いアーカイブ） ==")
            # 索引から segment_url を落として、トラックごとに <audio> を持つ経路を
            # 通す。読み込みの遅いトラックを1本作り、待たずに再生しても 0 秒から
            # 始まらないことを見る。
            slowed = {"done": False}

            def strip_segment(route):
                body = route.fetch().json()
                body.pop("segment_url", None)
                route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

            def slow_first(route):
                if not slowed["done"]:
                    slowed["done"] = True
                    time.sleep(1.5)
                route.continue_()

            page.route(f"{BASE}/dlaudio/files/{GUILD_ID}/{play_token}/mixer", strip_segment)
            page.route(f"{BASE}/dlaudio/files/{GUILD_ID}/{play_token}/stem/1", slow_first)
            open_mixer(page, play_token)
            late = page.evaluate(
                """async () => {
              const audios = [...document.querySelectorAll("audio")];
              const stage = document.getElementById("stage");
              const lane = document.querySelector(".daw-lanes");
              const box = lane.getBoundingClientRect();
              lane.dispatchEvent(new PointerEvent("pointerdown", {
                clientX: box.left + box.width * 0.5, clientY: box.top + 20, bubbles: true,
              }));
              [...stage.querySelectorAll("button")]
                .find((b) => b.textContent.includes("再生")).click();
              await new Promise((r) => setTimeout(r, 2500));
              return { at: audios.map((a) => a.currentTime),
                       paused: audios.map((a) => a.paused) };
            }"""
            )
            check("従来経路に落ちている", bool(late["at"]), f"<audio> が {len(late['at'])} 本")
            check(
                "遅れて読めたトラックも 0 秒から始まっていない",
                bool(late["at"]) and min(late["at"]) > 0.5,
                f"位置={['%.2f' % v for v in late['at']]}",
            )
            check(
                "トラック同士が揃っている",
                bool(late["at"]) and max(late["at"]) - min(late["at"]) < 0.15,
                f"最大差={max(late['at']) - min(late['at']):.3f} 秒",
            )
            page.evaluate("window.__mixer.destroy()")
            page.unroute(f"{BASE}/dlaudio/files/{GUILD_ID}/{play_token}/mixer")
            page.unroute(f"{BASE}/dlaudio/files/{GUILD_ID}/{play_token}/stem/1")

            print("\n== 4. 区切り配信で、チャンネルとトラックが対応すること ==")
            # 全トラックを1つの多チャンネル音源として受け取り、ChannelSplitter で
            # 分ける経路。順序が入れ替わると「別人の声にフェーダーが効く」ので、
            # トラックごとに違う高さの音を入れて、ソロにして確かめる。
            open_mixer(page, play_token)
            mode = page.evaluate(
                """() => ({
              segment: document.querySelectorAll('audio').length === 0,
              audios: document.querySelectorAll('audio').length,
            })"""
            )
            check("区切り配信の経路が選ばれている", mode["segment"], f"<audio> が {mode['audios']} 本ある")

            if mode["segment"]:
                # チャンネルの並び自体は、この検査の外で確かめてある
                #   - 送り出す WAV の各チャンネルが stems の順であること（ffmpeg で確認）
                #   - 多チャンネル WAV がブラウザで順序を保つこと（8ch で確認）
                # ここで見るのは「分けたあとが各トラックに配線されているか」。
                # ソロにしたトラックのメーターだけが振れること。
                levels = page.evaluate(
                    """async () => {
                  const stage = document.getElementById("stage");
                  const buttons = [...stage.querySelectorAll("button")];
                  buttons.find((b) => b.textContent.includes("再生")).click();
                  // メーターはコンソール画面で描かれる
                  buttons.find((b) => b.textContent === "ミキサー").click();
                  await new Promise((r) => setTimeout(r, 1200));

                  const strips = [...stage.querySelectorAll(".daw-strip:not(.is-master)")];
                  const solos = strips.map((s) => [...s.querySelectorAll("button")]
                    .find((b) => b.textContent === "S"));
                  const inked = (canvas) => {
                    const ctx = canvas.getContext("2d");
                    const { width, height } = canvas;
                    if (!width || !height) return 0;
                    const data = ctx.getImageData(0, 0, width, height).data;
                    let lit = 0;
                    for (let i = 0; i < data.length; i += 4) {
                      // メーターの帯は緑〜赤。灰色の下地と枠は数えない
                      if (data[i + 3] > 40 &&
                          Math.max(data[i], data[i+1], data[i+2]) -
                          Math.min(data[i], data[i+1], data[i+2]) > 40) lit += 1;
                    }
                    return lit;
                  };
                  const out = [];
                  for (let i = 0; i < solos.length; i += 1) {
                    solos.forEach((s, j) => {
                      if ((j === i) !== s.classList.contains("is-on")) s.click();
                    });
                    await new Promise((r) => setTimeout(r, 600));
                    out.push(strips.map((s) => inked(s.querySelector(".daw-meter"))));
                  }
                  return out;
                }"""
                )
                ok = True
                for i, row in enumerate(levels or []):
                    loud = [j for j, v in enumerate(row) if v > 0]
                    if loud != [i]:
                        ok = False
                    print(f"      トラック{i} をソロ -> 振れているメーター {loud}")
                check(
                    "ソロにしたトラックのメーターだけが振れる",
                    bool(levels) and ok,
                    "配線がトラックとずれている" if not ok else "",
                )
            page.evaluate("window.__mixer.destroy()")

            print()
            print("== 5. 声の解析が、選んだ区間を見に行くこと ==")
            # 自動で録音全体から抜き出す方式は、長い録音ほど喋っている所へ
            # 当たらない（4時間22分の実録音5本では、5本とも判定不能になった）。
            # どこを見るかは波形を見ている人が決める。ここで確かめるのは、
            # 時間目盛りで選んだ区間が実際にリクエストへ乗ることまで。
            open_mixer(page, play_token)
            asked: list[str] = []
            page.on("request", lambda r: asked.append(r.url) if "/analysis/" in r.url else None)

            # 区間を選ばずに押したとき
            page.evaluate(
                """() => {
              document.querySelector(".daw-head-buttons button[title^='声を調べる']").click();
            }"""
            )
            page.wait_for_function(
                "() => { const p = document.querySelector('.daw-inspect');"
                " return p && !p.hidden && !p.querySelector('.loading'); }",
                timeout=15000,
            )
            check(
                "区間を選ばなければ、これまでどおり全体を見る",
                len(asked) == 1 and "start=" not in asked[-1],
                asked[-1].split("/analysis/")[-1] if asked else "呼ばれていない",
            )

            # 時間目盛りを横にドラッグして区間を決める
            dragged = page.evaluate(
                """async () => {
              const ruler = document.querySelector(".daw-ruler");
              const box = ruler.getBoundingClientRect();
              const at = (fx) => ({
                clientX: box.left + box.width * fx, clientY: box.top + 10,
                bubbles: true, pointerId: 1,
              });
              ruler.setPointerCapture = () => {};
              ruler.hasPointerCapture = () => true;
              ruler.dispatchEvent(new PointerEvent("pointerdown", at(0.25)));
              ruler.dispatchEvent(new PointerEvent("pointermove", at(0.60)));
              ruler.dispatchEvent(new PointerEvent("pointerup", at(0.60)));
              await new Promise((r) => setTimeout(r, 200));
              const band = document.querySelector(".daw-loop");
              return { shown: !band.hidden, width: band.style.width };
            }"""
            )
            check("ドラッグした区間が帯として出る", dragged["shown"], f"幅={dragged['width']}")

            armed = page.evaluate(
                """() => {
              const b = document.querySelector(".daw-head-buttons button[title$='の声を調べる']");
              return b ? { title: b.title, armed: b.classList.contains("is-armed") } : null;
            }"""
            )
            check(
                "押す前に、どの区間を見るかがボタンに出る",
                bool(armed) and armed["armed"],
                armed["title"] if armed else "説明が変わっていない",
            )

            page.evaluate(
                """() => {
              document.querySelector(".daw-head-buttons button[title$='の声を調べる']").click();
            }"""
            )
            # 固定時間で待つと、解析が遅れたときに「まだ読み込み中」の中身を
            # 見て落ちる（実際に一度そうなった）。読み込みが終わるまで待つ。
            page.wait_for_function(
                "() => { const p = document.querySelector('.daw-inspect');"
                " return p && !p.hidden && !p.querySelector('.loading'); }",
                timeout=15000,
            )
            last = asked[-1] if asked else ""
            check(
                "選んだ区間がリクエストに乗る",
                len(asked) == 2 and "start=" in last and "end=" in last,
                last.split("/analysis/")[-1] if last else "呼ばれていない",
            )

            shown = page.evaluate(
                """() => {
              const panel = document.querySelector(".daw-inspect");
              return { open: panel && !panel.hidden,
                       text: panel ? panel.innerText.slice(0, 300) : "" };
            }"""
            )
            check(
                "結果に「どこを調べたか」が出る", shown["open"] and "調べた区間" in shown["text"], shown["text"][:120]
            )

            # ミュートとソロが同じ色にならないこと（見出しの並びに「?」を
            # 足したとき、:last-child で色を当てていたソロが赤に化けた）
            colours = page.evaluate(
                """async () => {
              const head = document.querySelector(".daw-head-buttons");
              const [mute, solo] = [...head.querySelectorAll("button")];
              mute.click(); solo.click();
              await new Promise((r) => setTimeout(r, 100));
              const bg = (b) => getComputedStyle(b).backgroundColor;
              return { mute: bg(mute), solo: bg(solo) };
            }"""
            )
            check(
                "ミュートとソロが違う色で点く",
                colours["mute"] != colours["solo"],
                f"ミュート={colours['mute']} ソロ={colours['solo']}",
            )

            page.evaluate("window.__mixer.destroy()")

            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    print()
    if _failures:
        print("RESULT: 失敗")
        for line in _failures:
            print("  -", line)
        return 1
    print("RESULT: 全て通過")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
