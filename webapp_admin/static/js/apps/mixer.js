/* 録音ミキサー。DAW のように、時間軸に並べて確認しながら混ぜる。

   画面は2つ。
     アレンジ … トラックごとの波形を共通の時間軸に並べる。頭出し・ループ区間。
     ミキサー … 縦のチャンネルストリップ。フェーダー・パン・レベルメーター。

   音の経路（トラックごと）:
     <audio> → Gain(フェーダー) → StereoPanner → Analyser(メーター)
             → マスター Gain → マスター Analyser → 出力

   <audio> を土台にしているのは、decodeAudioData で全部展開すると長い録音
   （数時間×人数）でメモリが破綻するため。音量・パン・ミュートは Web Audio 側で
   効かせる。

   波形は「表示している範囲だけ」描く。6時間を 40px/秒 で並べると 86万px になり、
   キャンバスの幅の上限（ブラウザによって 32767px 前後）を超えるため。 */

import { el, icon, clear, loading } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const LANE_HEIGHT = 72;
const RULER_HEIGHT = 26;

// 拡大率（1秒あたりの画素数）。端は「全体を眺める」と「波形の粒が見える」。
const ZOOM_MIN = 1;
const ZOOM_MAX = 400;
// 1回で 1.7 倍。決め打ちの段だと、いまの倍率のすぐ隣に着地して
// 「押したのに変わらない」ことがある。
const ZOOM_FACTOR = 1.7;

// フェーダー。3/4 の位置が 0dB という DAW の慣習に合わせる。
const FADER_UNITY = 0.75;
const FADER_TOP_DB = 6;
const FADER_FLOOR_DB = -60;      // これより下は無音として扱う

// メーターの表示範囲
const METER_MIN_DB = -54;
const METER_MAX_DB = 6;
const PEAK_HOLD_MS = 1200;
const PEAK_FALL_DB_PER_SEC = 24;

// 再生位置の追従。ずれてきたら黙って引き戻す。
const SYNC_TOLERANCE = 0.25;

const TRACK_COLORS = [
  "#4fa9ff", "#33cfcf", "#ff9a3c", "#a78bfa",
  "#5ad48a", "#ff6b9d", "#e0c341", "#7fd1ff",
];

// ── 単位の変換 ────────────────────────────────────────────────

function formatTime(seconds, withMillis = false) {
  const value = Math.max(0, seconds || 0);
  const total = Math.floor(value);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0");
  const ss = String(s).padStart(2, "0");
  const head = h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
  if (!withMillis) return head;
  return `${head}.${String(Math.floor((value - total) * 100)).padStart(2, "0")}`;
}

/** フェーダーの位置(0〜1)を dB に。0 は無音。 */
function positionToDb(position) {
  if (position <= 0.001) return -Infinity;
  const db = 40 * Math.log10(position / FADER_UNITY);
  return db <= FADER_FLOOR_DB ? -Infinity : Math.min(db, FADER_TOP_DB);
}

function dbToGain(db) {
  return db === -Infinity ? 0 : 10 ** (db / 20);
}

function formatDb(db) {
  if (db === -Infinity) return "-∞";
  return `${db > 0 ? "+" : ""}${db.toFixed(1)}`;
}

/** 目盛りの間隔を拡大率から決める（線が詰まりすぎないように）。 */
function tickStep(pixelsPerSecond) {
  for (const step of [0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600]) {
    if (step * pixelsPerSecond >= 70) return step;
  }
  return 3600;
}

function cssVar(name, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name);
  return value.trim() || fallback;
}

// ── 描画 ──────────────────────────────────────────────────────

/** キャンバスを親の大きさと画面の細かさに合わせる。 */
function fitCanvas(canvas, height) {
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(1, Math.floor(canvas.clientWidth));
  if (canvas.width !== Math.floor(width * ratio) ||
      canvas.height !== Math.floor(height * ratio)) {
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  return { ctx, width, height };
}

/** 時間目盛り。表示している範囲だけ描く。 */
function drawRuler(canvas, view) {
  const { ctx, width, height } = fitCanvas(canvas, RULER_HEIGHT);
  ctx.clearRect(0, 0, width, height);

  const ink = cssVar("--fg-subtle", "#8c959f");
  const rule = cssVar("--border-muted", "#dce1e6");
  const step = tickStep(view.pxPerSecond);
  const first = Math.floor(view.start / step) * step;

  ctx.font = "10px ui-monospace, monospace";
  ctx.textBaseline = "bottom";

  for (let t = first; t <= view.end + step; t += step) {
    if (t < 0) continue;
    const x = Math.round((t - view.start) * view.pxPerSecond) + 0.5;
    if (x < -40 || x > width + 40) continue;

    // 主目盛りと副目盛りで長さを変える
    const major = Math.abs(t % (step * 5)) < 1e-6;
    ctx.strokeStyle = rule;
    ctx.beginPath();
    ctx.moveTo(x, major ? height - 14 : height - 7);
    ctx.lineTo(x, height);
    ctx.stroke();

    if (major || step * view.pxPerSecond >= 110) {
      ctx.fillStyle = ink;
      ctx.fillText(formatTime(t), x + 4, height - 15);
    }
  }
}

/** 波形1本。表示範囲に対応する目盛りだけを読み、上下対称の帯として塗る。 */
function drawWaveform(canvas, track, view) {
  const { ctx, width, height } = fitCanvas(canvas, LANE_HEIGHT);
  ctx.clearRect(0, 0, width, height);

  // 時間の縦線。目盛りと同じ位置に引くと、どこを見ているか追いやすい。
  const step = tickStep(view.pxPerSecond);
  ctx.strokeStyle = cssVar("--border-muted", "#dce1e6");
  ctx.globalAlpha = 0.55;
  ctx.beginPath();
  for (let t = Math.floor(view.start / step) * step; t <= view.end + step; t += step) {
    if (t < 0) continue;
    const gx = Math.round((t - view.start) * view.pxPerSecond) + 0.5;
    if (gx < 0 || gx > width) continue;
    ctx.moveTo(gx, 0);
    ctx.lineTo(gx, height);
  }
  ctx.stroke();
  ctx.globalAlpha = 1;

  const middle = height / 2;
  ctx.beginPath();
  ctx.moveTo(0, middle + 0.5);
  ctx.lineTo(width, middle + 0.5);
  ctx.stroke();

  const peaks = track.peaks;
  if (!peaks || !peaks.length) return;

  const bucket = view.bucketSeconds || 0.25;
  const usable = height - 10;

  ctx.fillStyle = track.color;
  ctx.globalAlpha = track.dimmed ? 0.25 : 1;

  // 1画素ずつ、その画素が受け持つ時間範囲の最大振幅を拾う。
  // 拡大しても目盛りより細かくはならないが、粗いより詰まって見えるほうが読める。
  const top = [];
  for (let x = 0; x < width; x += 1) {
    const from = view.start + x / view.pxPerSecond;
    const to = view.start + (x + 1) / view.pxPerSecond;
    let peak = 0;
    const firstBucket = Math.floor(from / bucket);
    const lastBucket = Math.floor((to - 1e-9) / bucket);
    for (let b = firstBucket; b <= lastBucket; b += 1) {
      if (b < 0 || b >= peaks.length) continue;
      if (peaks[b] > peak) peak = peaks[b];
    }
    top.push(peak);
  }

  ctx.beginPath();
  ctx.moveTo(0, middle);
  for (let x = 0; x < top.length; x += 1) {
    ctx.lineTo(x, middle - (top[x] * usable) / 2);
  }
  for (let x = top.length - 1; x >= 0; x -= 1) {
    ctx.lineTo(x, middle + (top[x] * usable) / 2);
  }
  ctx.closePath();
  ctx.fill();
  ctx.globalAlpha = 1;
}

/** レベルメーター1本。RMS を帯で、ピークを線で。 */
function drawMeter(canvas, level) {
  const { ctx, width, height } = fitCanvas(canvas, canvas.clientHeight || 120);
  ctx.clearRect(0, 0, width, height);

  const toY = (db) => {
    const clamped = Math.max(METER_MIN_DB, Math.min(METER_MAX_DB, db));
    return height - ((clamped - METER_MIN_DB) / (METER_MAX_DB - METER_MIN_DB)) * height;
  };

  ctx.fillStyle = cssVar("--canvas-inset", "#eef1f4");
  ctx.fillRect(0, 0, width, height);

  // 0dB の線。ここを超えたら歪む。
  ctx.strokeStyle = cssVar("--border", "#d0d7de");
  ctx.beginPath();
  ctx.moveTo(0, Math.round(toY(0)) + 0.5);
  ctx.lineTo(width, Math.round(toY(0)) + 0.5);
  ctx.stroke();

  if (level.rmsDb > METER_MIN_DB) {
    const y = toY(level.rmsDb);
    const gradient = ctx.createLinearGradient(0, height, 0, 0);
    gradient.addColorStop(0, "#3fb950");
    gradient.addColorStop(0.72, "#7ee787");
    gradient.addColorStop(0.88, "#d29922");
    gradient.addColorStop(1, "#f85149");
    ctx.fillStyle = gradient;
    ctx.fillRect(1, y, width - 2, height - y);
  }

  if (level.holdDb > METER_MIN_DB) {
    ctx.fillStyle = level.holdDb >= 0 ? "#f85149" : cssVar("--fg", "#1f2328");
    ctx.fillRect(1, Math.max(0, toY(level.holdDb) - 1), width - 2, 2);
  }
}

// ── 部品 ──────────────────────────────────────────────────────

/** 縦フェーダー。つまみを掴んで動かす。 */
function createFader(initial, onChange) {
  const fill = el("div", { class: "daw-fader-fill" });
  const knob = el("div", { class: "daw-fader-knob" });
  const track = el("div", { class: "daw-fader-track" }, fill, knob);
  // dB の目盛り。どこが 0dB なのかを見て分かるようにする。
  const scale = el("div", { class: "daw-fader-scale" },
    [6, 0, -6, -12, -24, -48].map((db) => {
      const position = db === FADER_TOP_DB
        ? 1 : FADER_UNITY * 10 ** (db / 40);
      return el("span", {
        class: `daw-fader-mark${db === 0 ? " is-unity" : ""}`,
        style: { bottom: `${Math.min(100, position * 100)}%` },
        text: db > 0 ? `+${db}` : String(db),
      });
    }));
  const root = el("div", { class: "daw-fader", tabindex: "0",
                           role: "slider", "aria-label": "音量" }, scale, track);
  let position = initial;

  function apply(next, notify = true) {
    position = Math.max(0, Math.min(1, next));
    const percent = position * 100;
    fill.style.height = `${percent}%`;
    knob.style.bottom = `calc(${percent}% - 6px)`;
    root.setAttribute("aria-valuetext", `${formatDb(positionToDb(position))} dB`);
    if (notify) onChange(position);
  }

  function fromEvent(event) {
    const box = track.getBoundingClientRect();
    apply(1 - (event.clientY - box.top) / box.height);
  }

  root.addEventListener("pointerdown", (event) => {
    root.setPointerCapture(event.pointerId);
    fromEvent(event);
    event.preventDefault();
  });
  root.addEventListener("pointermove", (event) => {
    if (root.hasPointerCapture(event.pointerId)) fromEvent(event);
  });
  root.addEventListener("dblclick", () => apply(FADER_UNITY));
  root.addEventListener("keydown", (event) => {
    const step = event.shiftKey ? 0.01 : 0.05;
    if (event.key === "ArrowUp") { apply(position + step); event.preventDefault(); }
    if (event.key === "ArrowDown") { apply(position - step); event.preventDefault(); }
  });

  apply(initial, false);
  return { root, set: (value) => apply(value, false), get: () => position };
}

/** パンつまみ。上下のドラッグで左右に振る。 */
function createPanKnob(onChange) {
  const pointer = el("div", { class: "daw-knob-pointer" });
  const root = el("div", { class: "daw-knob", tabindex: "0",
                           role: "slider", "aria-label": "パン" }, pointer);
  let value = 0;   // -1(左) 〜 +1(右)
  let dragFrom = null;

  function apply(next, notify = true) {
    value = Math.max(-1, Math.min(1, next));
    pointer.style.transform = `rotate(${value * 135}deg)`;
    const label = value === 0 ? "中央"
      : `${value < 0 ? "左" : "右"}${Math.round(Math.abs(value) * 100)}`;
    root.setAttribute("aria-valuetext", label);
    root.title = `パン: ${label}（ダブルクリックで中央）`;
    if (notify) onChange(value);
  }

  root.addEventListener("pointerdown", (event) => {
    root.setPointerCapture(event.pointerId);
    dragFrom = { y: event.clientY, value };
    event.preventDefault();
  });
  root.addEventListener("pointermove", (event) => {
    if (!dragFrom || !root.hasPointerCapture(event.pointerId)) return;
    apply(dragFrom.value + (dragFrom.y - event.clientY) / 120);
  });
  root.addEventListener("pointerup", () => { dragFrom = null; });
  root.addEventListener("dblclick", () => apply(0));
  root.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") { apply(value - 0.1); event.preventDefault(); }
    if (event.key === "ArrowRight") { apply(value + 0.1); event.preventDefault(); }
  });

  apply(0, false);
  return { root, get: () => value };
}

// ── 本体 ──────────────────────────────────────────────────────

/** ミキサーを container の中に組み立てる。
 *
 *  ウィンドウはアプリIDで一意なので、録音ごとに窓を開くことができない。
 *  代わりに録音パネルの中身を差し替えて使う。後片付けは呼び出し側が
 *  destroy() を呼んで行う。 */
export async function createMixer(container, options = {}) {
  const { manifestUrl, clipUrl } = options;
  const idle = { destroy() {} };
  if (!manifestUrl) {
    clear(container).append(el("div", { class: "empty", text: "録音が指定されていません。" }));
    return idle;
  }

  clear(container).append(loading("録音を読み込み中…"));

  let manifest;
  try {
    const response = await fetch(manifestUrl, { credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    manifest = await response.json();
  } catch (error) {
    clear(container).append(
      el("div", { class: "empty", text: `録音を読み込めませんでした（${error.message}）` })
    );
    return idle;
  }

  const stems = manifest.stems || [];
  if (!stems.length) {
    clear(container).append(el("div", { class: "empty", text: "トラックがありません。" }));
    return idle;
  }

  const duration = Number(manifest.duration_seconds) || 0;
  const bucketSeconds = Number(manifest.bucket_seconds) || 0.25;
  const periodicityMin = Number(manifest.periodicity_min) || 0;

  const context = new (window.AudioContext || window.webkitAudioContext)();
  const masterGain = context.createGain();
  const masterAnalyser = context.createAnalyser();
  masterAnalyser.fftSize = 1024;
  masterGain.connect(masterAnalyser).connect(context.destination);

  const tracks = [];
  let soloActive = false;
  let playing = false;
  let looping = false;
  let loopRegion = null;      // {start, end}
  let dragging = null;       // 並べ替えで掴んでいるトラック

  const view = { start: 0, pxPerSecond: 10, end: 0, bucketSeconds, width: 1 };

  // ── トラックを組み立てる ────────────────────────────────
  stems.forEach((stem, index) => {
    const color = TRACK_COLORS[index % TRACK_COLORS.length];
    const periodicity = stem.periodicity;
    const suspect = periodicity !== null && periodicity !== undefined
      && periodicityMin > 0 && periodicity < periodicityMin;

    // DOM に置いておく（hidden）。切り離したままだと、閉じたときの後片付けや
    // デバッグで追いにくい。
    const audio = el("audio", {
      src: stem.url, preload: "metadata", hidden: true,
      dataset: { stem: String(stem.index) },
    });
    audio.crossOrigin = "use-credentials";

    const source = context.createMediaElementSource(audio);
    const gain = context.createGain();
    const panner = context.createStereoPanner();
    const analyser = context.createAnalyser();
    analyser.fftSize = 1024;
    source.connect(gain).connect(panner).connect(analyser).connect(masterGain);

    tracks.push({
      stem, audio, gain, panner, analyser, color, suspect,
      name: stem.name, peaks: stem.peaks || [],
      muted: false, solo: false, dimmed: false,
      faderPosition: FADER_UNITY, pan: 0,
      samples: new Float32Array(analyser.fftSize),
      level: { rmsDb: -Infinity, holdDb: -Infinity, holdAt: 0 },
      laneCanvas: null, strip: null, head: null, meterCanvas: null,
    });
  });

  const master = {
    analyser: masterAnalyser,
    samples: new Float32Array(masterAnalyser.fftSize),
    level: { rmsDb: -Infinity, holdDb: -Infinity, holdAt: 0 },
    meterCanvas: null,
    faderPosition: FADER_UNITY,
    strip: null,
  };

  function applyRouting() {
    soloActive = tracks.some((t) => t.solo);
    for (const track of tracks) {
      const silenced = track.muted || (soloActive && !track.solo);
      track.dimmed = silenced;
      const db = positionToDb(track.faderPosition);
      track.gain.gain.value = silenced ? 0 : dbToGain(db);
      track.panner.pan.value = track.pan;
      if (track.strip) {
        track.strip.mute.classList.toggle("is-on", track.muted);
        track.strip.solo.classList.toggle("is-on", track.solo);
        track.strip.db.textContent = formatDb(db);
        track.strip.root.classList.toggle("is-silenced", silenced);
      }
      if (track.head) {
        track.head.mute.classList.toggle("is-on", track.muted);
        track.head.solo.classList.toggle("is-on", track.solo);
        track.head.root.classList.toggle("is-silenced", silenced);
      }
    }
    masterGain.gain.value = dbToGain(positionToDb(master.faderPosition));
    if (master.strip) master.strip.db.textContent = formatDb(positionToDb(master.faderPosition));
    drawLanes();
  }

  // ── 再生 ────────────────────────────────────────────────
  function positionOf() {
    return tracks.length ? tracks[0].audio.currentTime || 0 : 0;
  }

  function seek(seconds) {
    const target = Math.max(0, Math.min(duration || Infinity, seconds));
    for (const track of tracks) {
      try { track.audio.currentTime = target; } catch { /* まだ読めていない */ }
    }
    followPlayhead(target);
    render();
  }

  async function play() {
    if (context.state === "suspended") await context.resume();
    const base = positionOf();
    for (const track of tracks) {
      try { track.audio.currentTime = base; } catch { /* noop */ }
    }
    await Promise.allSettled(tracks.map((t) => t.audio.play()));
    playing = true;
    clear(playButton).append(icon("bi-pause-fill"), "一時停止");
  }

  function pause() {
    for (const track of tracks) track.audio.pause();
    playing = false;
    clear(playButton).append(icon("bi-play-fill"), "再生");
  }

  async function toggle() {
    try {
      if (playing) pause();
      else await play();
    } catch (error) {
      toast(`再生できませんでした（${error.message}）`, "danger", { duration: 6000 });
    }
  }

  // ── 上の操作列 ──────────────────────────────────────────
  const playButton = el("button", { class: "btn btn-primary", type: "button",
                                    onclick: () => toggle() },
                        icon("bi-play-fill"), "再生");
  const stopButton = el("button", { class: "btn", type: "button",
                                    onclick: () => { pause(); seek(0); } },
                        icon("bi-stop-fill"), "停止");
  const clock = el("span", { class: "daw-clock mono" });
  const loopButton = el("button", {
    class: "btn", type: "button", title: "ループ（時間目盛りをドラッグして範囲を決める）",
    onclick: () => { looping = !looping; loopButton.classList.toggle("is-on", looping); },
  }, icon("bi-arrow-clockwise"), "ループ");

  const exportButton = el("button", {
    class: "btn", type: "button", disabled: true,
    title: "時間目盛りを横にドラッグして区間を決めると押せます",
    onclick: () => exportRegion(),
  }, icon("bi-download"), "区間を書き出す");

  function exportRegion() {
    if (!loopRegion || !clipUrl) return;
    const url = `${clipUrl}?start=${loopRegion.start.toFixed(3)}`
              + `&end=${loopRegion.end.toFixed(3)}`;
    // 落とすのは普通の遷移でよい（添付として返ってくる）。
    window.location.href = url;
    toast(`${formatTime(loopRegion.start)} 〜 ${formatTime(loopRegion.end)} を書き出します`,
          "success", { duration: 4000 });
  }

  const zoomOut = el("button", { class: "btn btn-sm", type: "button",
                                 title: "縮小", onclick: () => zoomBy(-1) }, "−");
  const zoomIn = el("button", { class: "btn btn-sm", type: "button",
                                title: "拡大", onclick: () => zoomBy(1) }, "＋");
  const zoomFit = el("button", { class: "btn btn-sm", type: "button",
                                 title: "全体を表示", onclick: () => zoomToFit() }, "全体");

  const tabArrange = el("button", { class: "daw-tab is-on", type: "button",
                                    onclick: () => showView("arrange") }, "アレンジ");
  const tabConsole = el("button", { class: "daw-tab", type: "button",
                                    onclick: () => showView("console") }, "ミキサー");

  const transport = el("div", { class: "daw-transport" },
    playButton, stopButton, loopButton, exportButton,
    clock,
    el("span", { class: "grow" }),
    el("div", { class: "daw-tabs" }, tabArrange, tabConsole),
    el("div", { class: "daw-zoom" }, zoomOut, zoomFit, zoomIn));

  // ── アレンジ ────────────────────────────────────────────
  const headColumn = el("div", { class: "daw-heads" });
  const rulerCanvas = el("canvas", { class: "daw-ruler-canvas" });
  const loopBand = el("div", { class: "daw-loop", hidden: true });
  const rulerArea = el("div", { class: "daw-ruler" }, rulerCanvas, loopBand);
  const laneStack = el("div", { class: "daw-lanes" });
  const playhead = el("div", { class: "daw-playhead" });
  const scrollSpacer = el("div", { class: "daw-spacer" });
  const scroller = el("div", { class: "daw-scroll" }, scrollSpacer);
  const viewport = el("div", { class: "daw-viewport" }, rulerArea, laneStack, playhead);
  const arrange = el("div", { class: "daw-arrange" },
    el("div", { class: "daw-head-col" },
       el("div", { class: "daw-head-spacer" }), headColumn),
    el("div", { class: "daw-track-area" }, viewport, scroller));

  tracks.forEach((track) => {
    const mute = el("button", { class: "daw-btn", type: "button", title: "ミュート",
                                onclick: () => { track.muted = !track.muted; applyRouting(); } }, "M");
    const solo = el("button", { class: "daw-btn", type: "button", title: "ソロ",
                                onclick: () => { track.solo = !track.solo; applyRouting(); } }, "S");
    const root = el("div", { class: "daw-head" },
      el("span", { class: "daw-head-color", style: { background: track.color } }),
      el("div", { class: "daw-head-body" },
         el("div", { class: "daw-head-name truncate", title: track.name },
            track.name,
            track.suspect
              ? el("span", { class: "chip danger daw-warn",
                             title: "自動判定です。波形と再生で確かめてください。",
                             text: "要確認" })
              : null),
         el("div", { class: "daw-head-sub",
                     text: `発話 ${formatTime(track.stem.voiced_seconds || 0)}` })),
      el("div", { class: "daw-head-buttons" }, mute, solo));
    root.draggable = true;
    root.addEventListener("dragstart", (event) => {
      dragging = track;
      root.classList.add("is-dragging");
      event.dataTransfer.effectAllowed = "move";
      // Firefox は何か入れないとドラッグが始まらない
      event.dataTransfer.setData("text/plain", track.name);
    });
    root.addEventListener("dragend", () => {
      dragging = null;
      root.classList.remove("is-dragging");
      for (const t of tracks) t.head.root.classList.remove("is-drop-target");
    });
    root.addEventListener("dragover", (event) => {
      if (!dragging || dragging === track) return;
      event.preventDefault();
      root.classList.add("is-drop-target");
    });
    root.addEventListener("dragleave", () => root.classList.remove("is-drop-target"));
    root.addEventListener("drop", (event) => {
      event.preventDefault();
      root.classList.remove("is-drop-target");
      if (dragging && dragging !== track) moveTrack(dragging, track);
    });

    track.head = { root, mute, solo };
    headColumn.append(root);

    const lane = el("div", { class: "daw-lane" },
                    el("canvas", { class: "daw-lane-canvas" }), track.audio);
    track.lane = lane;
    track.laneCanvas = lane.firstChild;
    laneStack.append(lane);
  });

  /** 掴んだトラックを、落とした先の位置へ入れ替える。
   *
   *  並びは見るためのものなので、画面の中だけで完結させる（保存しない）。
   *  ヘッダ・波形・ストリップの3箇所を同じ順序に保つ。 */
  function moveTrack(from, to) {
    const order = tracks.slice();
    order.splice(order.indexOf(from), 1);
    order.splice(order.indexOf(to), 0, from);
    tracks.length = 0;
    tracks.push(...order);
    for (const track of tracks) {
      headColumn.append(track.head.root);
      laneStack.append(track.lane);
      if (track.strip) stripRow.insertBefore(track.strip.root, master.strip.root);
    }
    drawLanes();
  }

  // ── ミキサー ────────────────────────────────────────────
  function buildStrip(target, label, color, isMaster) {
    const meterCanvas = el("canvas", { class: "daw-meter" });
    target.meterCanvas = meterCanvas;

    const fader = createFader(target.faderPosition, (position) => {
      target.faderPosition = position;
      applyRouting();
    });
    const db = el("span", { class: "daw-strip-db mono" });

    let pan = null;
    let mute = null;
    let solo = null;
    if (!isMaster) {
      pan = createPanKnob((value) => { target.pan = value; applyRouting(); });
      mute = el("button", { class: "daw-btn", type: "button", title: "ミュート",
                            onclick: () => { target.muted = !target.muted; applyRouting(); } }, "M");
      solo = el("button", { class: "daw-btn", type: "button", title: "ソロ",
                            onclick: () => { target.solo = !target.solo; applyRouting(); } }, "S");
    }

    const root = el("div", { class: `daw-strip${isMaster ? " is-master" : ""}` },
      el("div", { class: "daw-strip-top" },
         el("span", { class: "daw-strip-color", style: { background: color } }),
         el("span", { class: "daw-strip-name truncate", title: label, text: label })),
      pan ? el("div", { class: "daw-strip-pan" }, pan.root) : null,
      el("div", { class: "daw-strip-body" }, fader.root, meterCanvas),
      db,
      mute ? el("div", { class: "daw-strip-buttons" }, mute, solo) : null);

    target.strip = { root, fader, db, mute, solo, pan };
    return root;
  }

  const stripRow = el("div", { class: "daw-strips" });
  tracks.forEach((track) => stripRow.append(buildStrip(track, track.name, track.color, false)));
  stripRow.append(buildStrip(master, "マスター", cssVar("--fg-subtle", "#8c959f"), true));
  const consoleView = el("div", { class: "daw-console", hidden: true }, stripRow);

  // ── 表示の切り替え ──────────────────────────────────────
  let currentView = "arrange";
  function showView(name) {
    currentView = name;
    arrange.hidden = name !== "arrange";
    consoleView.hidden = name !== "console";
    tabArrange.classList.toggle("is-on", name === "arrange");
    tabConsole.classList.toggle("is-on", name === "console");
    if (name === "arrange") layout();
  }

  // ── 拡大と巻き取り ──────────────────────────────────────
  function totalWidth() {
    return Math.max(1, duration * view.pxPerSecond);
  }

  function layout() {
    view.width = viewport.clientWidth || 1;
    scrollSpacer.style.width = `${totalWidth()}px`;
    view.start = scroller.scrollLeft / view.pxPerSecond;
    view.end = view.start + view.width / view.pxPerSecond;
    drawRuler(rulerCanvas, view);
    drawLanes();
    paintLoop();
    render();
  }

  function drawLanes() {
    for (const track of tracks) {
      if (track.laneCanvas) drawWaveform(track.laneCanvas, track, view);
    }
  }

  function zoomToFit() {
    const width = viewport.clientWidth || 1;
    view.pxPerSecond = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, width / Math.max(duration, 0.1)));
    scroller.scrollLeft = 0;
    layout();
  }

  function zoomBy(direction) {
    const centre = view.start + (view.width / 2) / view.pxPerSecond;
    const next = direction > 0
      ? view.pxPerSecond * ZOOM_FACTOR
      : view.pxPerSecond / ZOOM_FACTOR;
    view.pxPerSecond = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, next));
    scrollSpacer.style.width = `${totalWidth()}px`;
    scroller.scrollLeft = Math.max(0, centre * view.pxPerSecond - view.width / 2);
    layout();
  }

  /** 再生位置が画面から出そうなら巻き取る。 */
  function followPlayhead(at) {
    if (currentView !== "arrange") return;
    const x = (at - view.start) * view.pxPerSecond;
    if (x < 0 || x > view.width - 40) {
      scroller.scrollLeft = Math.max(0, at * view.pxPerSecond - view.width * 0.35);
      layout();
    }
  }

  scroller.addEventListener("scroll", () => {
    view.start = scroller.scrollLeft / view.pxPerSecond;
    view.end = view.start + view.width / view.pxPerSecond;
    drawRuler(rulerCanvas, view);
    drawLanes();
    paintLoop();
    render();
  });

  // 波形の上をクリックで頭出し。目盛りの上はドラッグでループ区間。
  function timeAt(event, element) {
    const box = element.getBoundingClientRect();
    return view.start + (event.clientX - box.left) / view.pxPerSecond;
  }

  laneStack.addEventListener("pointerdown", (event) => {
    seek(timeAt(event, laneStack));
  });

  let loopDrag = null;
  rulerArea.addEventListener("pointerdown", (event) => {
    rulerArea.setPointerCapture(event.pointerId);
    loopDrag = timeAt(event, rulerArea);
    loopRegion = null;
    paintLoop();
  });
  rulerArea.addEventListener("pointermove", (event) => {
    if (loopDrag === null || !rulerArea.hasPointerCapture(event.pointerId)) return;
    const to = timeAt(event, rulerArea);
    const region = { start: Math.min(loopDrag, to), end: Math.max(loopDrag, to) };
    loopRegion = region.end - region.start < 0.05 ? null : region;
    paintLoop();
  });
  rulerArea.addEventListener("pointerup", (event) => {
    if (loopDrag !== null && loopRegion === null) seek(timeAt(event, rulerArea));
    loopDrag = null;
    if (loopRegion) { looping = true; loopButton.classList.add("is-on"); }
  });

  function paintLoop() {
    exportButton.disabled = !loopRegion || !clipUrl;
    exportButton.title = loopRegion
      ? `${formatTime(loopRegion.start)} 〜 ${formatTime(loopRegion.end)} を ZIP で落とす`
      : "時間目盛りを横にドラッグして区間を決めると押せます";
    if (!loopRegion) { loopBand.hidden = true; return; }
    loopBand.hidden = false;
    loopBand.style.left = `${(loopRegion.start - view.start) * view.pxPerSecond}px`;
    loopBand.style.width = `${(loopRegion.end - loopRegion.start) * view.pxPerSecond}px`;
  }

  // ── メーターと再生位置 ──────────────────────────────────
  function measure(target, now) {
    target.analyser.getFloatTimeDomainData(target.samples);
    let sum = 0;
    let peak = 0;
    for (let i = 0; i < target.samples.length; i += 1) {
      const value = target.samples[i];
      sum += value * value;
      const absolute = Math.abs(value);
      if (absolute > peak) peak = absolute;
    }
    const rms = Math.sqrt(sum / target.samples.length);
    const level = target.level;
    level.rmsDb = rms > 0 ? 20 * Math.log10(rms) : -Infinity;
    const peakDb = peak > 0 ? 20 * Math.log10(peak) : -Infinity;

    if (peakDb >= level.holdDb) {
      level.holdDb = peakDb;
      level.holdAt = now;
    } else if (now - level.holdAt > PEAK_HOLD_MS) {
      level.holdDb -= (PEAK_FALL_DB_PER_SEC * (now - level.holdAt)) / 1000;
      level.holdAt = now;
    }
    if (target.meterCanvas) drawMeter(target.meterCanvas, level);
  }

  function render() {
    const at = positionOf();
    const x = (at - view.start) * view.pxPerSecond;
    playhead.style.transform = `translateX(${x}px)`;
    playhead.hidden = x < -2 || x > view.width + 2;
    clock.textContent = `${formatTime(at, true)} / ${formatTime(duration)}`;
  }

  let raf = null;
  function tick(now) {
    render();
    if (currentView === "console" || playing) {
      for (const track of tracks) measure(track, now);
      measure(master, now);
    }
    if (playing) {
      const base = tracks[0]?.audio.currentTime || 0;
      // ずれてきたら先頭トラックに合わせ直す
      for (const track of tracks.slice(1)) {
        if (Math.abs(track.audio.currentTime - base) > SYNC_TOLERANCE) {
          try { track.audio.currentTime = base; } catch { /* noop */ }
        }
      }
      if (looping && loopRegion && base >= loopRegion.end) seek(loopRegion.start);
      else if (duration && base >= duration - 0.05) pause();
      else followPlayhead(base);
    }
    raf = window.requestAnimationFrame(tick);
  }

  // ── キーボード ──────────────────────────────────────────
  function onKeyDown(event) {
    const tag = (event.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (!container.isConnected) return;
    if (event.key === " ") { toggle(); event.preventDefault(); }
    else if (event.key === "Home") { seek(0); event.preventDefault(); }
    else if (event.key === "ArrowLeft") { seek(positionOf() - (event.shiftKey ? 10 : 2)); event.preventDefault(); }
    else if (event.key === "ArrowRight") { seek(positionOf() + (event.shiftKey ? 10 : 2)); event.preventDefault(); }
    else if (event.key === "+" || event.key === "=") { zoomBy(1); event.preventDefault(); }
    else if (event.key === "-") { zoomBy(-1); event.preventDefault(); }
  }
  window.addEventListener("keydown", onKeyDown);

  // ── 組み立て ────────────────────────────────────────────
  clear(container).append(
    el("div", { class: "daw" },
       transport,
       arrange,
       consoleView,
       el("p", { class: "field-help", text:
         "スペースで再生／停止、←→ で移動、＋− で拡大。M＝ミュート、S＝ソロ。" +
         "フェーダーはダブルクリックで 0dB、つまみは上下ドラッグでパン。" +
         "時間目盛りを横にドラッグするとループ区間になり、その範囲だけ書き出せます。" +
         "トラックの名前をドラッグすると並べ替えられます。" +
         "各トラックは同じ時間軸に揃えてあるので、途中から参加した人は冒頭が、" +
         "途中で抜けた人は末尾が無音になります。" }))
  );

  const onResize = () => layout();
  window.addEventListener("resize", onResize);

  // レイアウトが決まってから描く
  window.requestAnimationFrame(() => {
    zoomToFit();
    applyRouting();
    raf = window.requestAnimationFrame(tick);
  });

  return {
    destroy() {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("keydown", onKeyDown);
      if (raf) window.cancelAnimationFrame(raf);
      for (const track of tracks) {
        track.audio.pause();
        track.audio.src = "";
      }
      context.close().catch(() => { /* 既に閉じている */ });
    },
  };
}
