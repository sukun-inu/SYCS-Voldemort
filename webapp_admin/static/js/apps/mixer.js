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

import { el, icon, clear, loading, append } from "../lib/dom.js";
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

// トラック同士の同期。<audio> は1本ずつ別の時計で動くので、放っておくと
// 少しずつ離れていく。以前は 0.25 秒ずれるまで放置したうえ、直し方が毎回の
// 頭出しだった。0.25 秒は会話としてはっきり聞こえるずれで、しかも頭出しは
// 音が途切れるため、ずれるたびに鳴り直す状態になっていた。
//   小さいずれ … 再生速度をわずかに変えて、聞こえないうちに追いつかせる
//   大きいずれ … 速度では追いつかないので頭出しし直す
const SYNC_IGNORE_SEC = 0.02;    // これ以下は触らない（直そうとするほうが荒れる）
const SYNC_RESEEK_SEC = 0.75;    // これを超えたら頭出しし直す
const SYNC_MAX_RATE = 0.06;      // 速度の変更幅（±6%。音程は既定で保たれる）
// メタデータ待ち・頭出し待ちの上限。1本読めなくても他を止めない。
const READY_TIMEOUT_MS = 10000;
const SEEK_TIMEOUT_MS = 3000;

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

  // 1点が何秒ぶんか。全トラックで同じ値を使う（view が持っている）。
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
  const { manifestUrl, clipUrl, analysisUrl } = options;
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
  const periodicityMin = Number(manifest.periodicity_min) || 0;

  /* 波形1点が何秒ぶんか。
     録音側は点数が多くなりすぎないよう目盛りを間引くが、以前は間引いたことを
     索引に書いていなかった（bucket_seconds は間引く前の 0.25 のまま）。その
     ため 12.5 分を超える録音では波形が時間軸の先頭に圧縮されていた（6時間なら
     全体が先頭 12.4 分ぶんに潰れる）。録音側は直したので新しい録音は
     stem.bucket_seconds を持つ。それが無い古いアーカイブは、長さと点数から
     割り戻して描く（索引の値をそのまま信じるより実態に合う）。 */
  const declared = Number(stems[0].bucket_seconds) || 0;
  const maxPoints = Math.max(0, ...stems.map((s) => (s.peaks || []).length));
  const bucketSeconds = declared
    || (maxPoints > 0 && duration > 0 ? duration / maxPoints : 0)
    || Number(manifest.bucket_seconds)
    || 0.25;

  const context = new (window.AudioContext || window.webkitAudioContext)();
  const masterGain = context.createGain();
  const masterAnalyser = context.createAnalyser();
  masterAnalyser.fftSize = 1024;
  masterGain.connect(masterAnalyser).connect(context.destination);

  /* 音の入口を2通り持つ。

     区切り配信（segment_url）が使えるなら、全トラックを「1トラック＝1
     チャンネル」の1つの音源として受け取り、ChannelSplitter で分ける。
     音源が1つなので時計も1つしかなく、トラック同士がずれようがない。

     使えないのは、圧縮されたまま入っている古いアーカイブと、人数が
     ChannelSplitter の上限（32）を超える録音。そのときは従来どおり
     トラックごとに <audio> を持ち、ずれを補正しながら鳴らす。 */
  const SPLITTER_MAX = 32;
  const useSegments = Boolean(manifest.segment_url) && stems.length <= SPLITTER_MAX;
  const splitter = useSegments ? context.createChannelSplitter(stems.length) : null;
  if (splitter) {
    splitter.channelCountMode = "explicit";
    splitter.channelInterpretation = "discrete";
  }

  const tracks = [];
  let soloActive = false;
  let playing = false;
  let looping = false;
  let loopRegion = null;      // {start, end}
  let dragging = null;       // 並べ替えで掴んでいるトラック
  // 頭出しで指示された位置。メタデータが読めていないあいだは <audio> が
  // 覚えてくれないので、こちらで持っておいて読めた時点で当て直す。
  let desiredPosition = 0;

  const view = { start: 0, pxPerSecond: 10, end: 0, bucketSeconds, width: 1 };

  // ── トラックを組み立てる ────────────────────────────────
  stems.forEach((stem, index) => {
    const color = TRACK_COLORS[index % TRACK_COLORS.length];
    const periodicity = stem.periodicity;
    const suspect = periodicity !== null && periodicity !== undefined
      && periodicityMin > 0 && periodicity < periodicityMin;

    // 音の入口は2通りある（→ createSegmentTransport / createElementTransport）。
    // 区切り配信が使えるときは <audio> を作らない。
    let audio = null;
    if (!useSegments) {
      // DOM に置いておく（hidden）。切り離したままだと、閉じたときの後片付けや
      // デバッグで追いにくい。
      //
      // preload は metadata のまま（auto にすると数時間ぶんを人数分まとめて
      // 落としにいく）。ただし読めるまでは currentTime への代入が黙って捨てられる
      // ので、頭出しと再生の前に loadedmetadata を待つこと（whenReady）。
      audio = el("audio", {
        src: stem.url, preload: "metadata", hidden: true,
        dataset: { stem: String(stem.index) },
      });
      audio.crossOrigin = "use-credentials";
      audio.preservesPitch = true;   // 同期のための速度調整で音程を変えない
    }

    const gain = context.createGain();
    const panner = context.createStereoPanner();
    const analyser = context.createAnalyser();
    analyser.fftSize = 1024;
    gain.connect(panner).connect(analyser).connect(masterGain);
    if (audio) context.createMediaElementSource(audio).connect(gain);
    else splitter.connect(gain, index);

    const track = {
      stem, audio, gain, panner, analyser, color, suspect,
      name: stem.name, peaks: stem.peaks || [],
      muted: false, solo: false, dimmed: false,
      faderPosition: FADER_UNITY, pan: 0,
      samples: new Float32Array(analyser.fftSize),
      level: { rmsDb: -Infinity, holdDb: -Infinity, holdAt: 0 },
      laneCanvas: null, strip: null, head: null, meterCanvas: null,
    };
    tracks.push(track);

    // 読み込みが終わる前に指示された頭出しを、読めた時点で当て直す。
    // これが無いと、そのトラックだけ 0 秒から鳴り始める。
    // （区切り配信のときは <audio> を持たないので不要）
    if (audio) {
      audio.addEventListener("loadedmetadata", () => {
        if (!playing && desiredPosition > 0) applySeek(track, desiredPosition);
      }, { once: true });
    }
  });

  /* 同期の基準にするトラック。
     並べ替えは tracks を並べ替えるので、tracks[0] を基準にしていると
     ドラッグしただけで基準が入れ替わり、再生位置が別のトラックの時計へ飛ぶ。
     最初の並びを別に取っておき、読めなかったときだけ次へ譲る。 */
  const syncOrder = tracks.slice();
  let syncMaster = syncOrder[0] || null;

  function masterAudio() {
    if (!syncMaster || syncMaster.audio.error) {
      syncMaster = syncOrder.find((t) => !t.audio.error) || syncOrder[0] || null;
    }
    return syncMaster ? syncMaster.audio : null;
  }

  /** メタデータが読めるまで待つ（読めなかった場合もそのまま進む）。 */
  function whenReady(track) {
    const audio = track.audio;
    if (audio.readyState >= 1 || audio.error) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        audio.removeEventListener("loadedmetadata", done);
        audio.removeEventListener("error", done);
        resolve();
      };
      audio.addEventListener("loadedmetadata", done);
      audio.addEventListener("error", done);
      window.setTimeout(done, READY_TIMEOUT_MS);
    });
  }

  /** 1本を target 秒へ動かす。読めていなければ何もしない（後で当て直す）。 */
  function applySeek(track, target) {
    const audio = track.audio;
    if (audio.error || audio.readyState < 1) return Promise.resolve();
    const limit = Number.isFinite(audio.duration) ? audio.duration : target;
    const to = Math.max(0, Math.min(target, limit));
    audio.playbackRate = 1;
    if (Math.abs(audio.currentTime - to) < 0.01) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => { audio.removeEventListener("seeked", done); resolve(); };
      audio.addEventListener("seeked", done);
      window.setTimeout(done, SEEK_TIMEOUT_MS);
      try { audio.currentTime = to; } catch { done(); }
    });
  }

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

  /* ── 区切り配信での再生 ──────────────────────────────────

     先の区間を少しずつ取ってきて、AudioContext の時計の上に並べる。
     位置は「鳴らし始めた時刻からの経過」で持つので、トラックごとの
     時計を突き合わせる必要が無い。 */
  const SEGMENT_SECONDS = 6;        // 1回に取る長さ
  const SEGMENT_LOOKAHEAD = 12;     // これだけ先まで用意しておく
  const SEGMENT_RETRY_MS = 1500;
  const segmentFormat = manifest.segment_format || {};
  const segmentRate = Number(segmentFormat.sample_rate) || 48000;
  const segmentChannels = Number(segmentFormat.channels) || stems.length;

  /** 生の PCM（16bit LE のインターリーブ）を AudioBuffer にする。
   *
   *  コンテナに入れて decodeAudioData に任せると、チャンネルの扱いが復号器
   *  次第になる。実測では Opus(WebM) が順序を入れ替え、WAV は人数が3人の
   *  ときだけ復号を拒んだ（ffmpeg が 2.1 のレイアウトを書くため）。
   *  生の PCM なら、並びは書いた順そのもの。 */
  function pcmToBuffer(bytes) {
    const samples = new Int16Array(bytes);
    const frames = Math.floor(samples.length / segmentChannels);
    const buffer = context.createBuffer(segmentChannels, frames, segmentRate);
    for (let channel = 0; channel < segmentChannels; channel += 1) {
      const target = buffer.getChannelData(channel);
      for (let i = 0; i < frames; i += 1) {
        target[i] = samples[i * segmentChannels + channel] / 32768;
      }
    }
    return buffer;
  }

  const segmentTransport = {
    origin: 0,          // 鳴らし始めたときの context.currentTime
    base: 0,            // そのときの再生位置
    filled: 0,          // どこまで並べ終えたか（再生位置）
    playing: false,
    sources: new Set(),
    fetching: false,
    generation: 0,      // 頭出しのたびに増やす。古い取得結果を捨てるため

    position() {
      if (!this.playing) return this.base;
      return this.base + (context.currentTime - this.origin);
    },

    stopSources() {
      for (const source of this.sources) {
        try { source.stop(); } catch { /* もう終わっている */ }
        try { source.disconnect(); } catch { /* noop */ }
      }
      this.sources.clear();
    },

    seek(seconds) {
      this.generation += 1;
      this.stopSources();
      this.base = seconds;
      this.filled = seconds;
      this.origin = context.currentTime;
    },

    async start() {
      if (context.state === "suspended") await context.resume();
      this.origin = context.currentTime;
      this.filled = this.base;
      this.playing = true;
      this.pump();
    },

    stop() {
      if (this.playing) this.base = this.position();
      this.playing = false;
      this.generation += 1;
      this.stopSources();
      this.filled = this.base;
    },

    /** 足りなくなったぶんを取りに行く。1つずつ順に並べる。 */
    async pump() {
      if (!this.playing || this.fetching) return;
      if (duration && this.filled >= duration) return;
      if (this.filled - this.position() >= SEGMENT_LOOKAHEAD) return;

      const generation = this.generation;
      const start = this.filled;
      const length = Math.min(SEGMENT_SECONDS,
                              duration ? duration - start : SEGMENT_SECONDS);
      if (length <= 0.01) return;

      this.fetching = true;
      try {
        const response = await fetch(
          `${manifest.segment_url}?start=${start.toFixed(3)}&length=${length.toFixed(3)}`,
          { credentials: "same-origin" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const buffer = pcmToBuffer(await response.arrayBuffer());
        // 頭出しが挟まっていたら、この区間はもう要らない
        if (generation !== this.generation || !this.playing) return;

        const source = context.createBufferSource();
        source.buffer = buffer;
        source.connect(splitter);
        // 並べる位置。既に過ぎていたら、その場から鳴らす（取得が間に合わなかった）
        const when = this.origin + (start - this.base);
        const late = context.currentTime - when;
        if (late > 0) source.start(context.currentTime, Math.min(late, buffer.duration));
        else source.start(when);
        source.onended = () => { this.sources.delete(source); };
        this.sources.add(source);
        this.filled = start + buffer.duration;
      } catch (error) {
        // 取れなかった区間は少し待って取り直す。黙って無音にしない。
        console.warn("[mixer] 区切りを取得できませんでした", error);
        window.setTimeout(() => this.pump(), SEGMENT_RETRY_MS);
        return;
      } finally {
        this.fetching = false;
      }
      this.pump();
    },
  };

  // ── 再生 ────────────────────────────────────────────────
  function positionOf() {
    if (useSegments) return segmentTransport.position();
    const audio = masterAudio();
    if (!audio || audio.readyState < 1) return desiredPosition;
    return audio.currentTime || 0;
  }

  function seek(seconds) {
    const target = Math.max(0, Math.min(duration || Infinity, seconds));
    desiredPosition = target;
    if (useSegments) {
      segmentTransport.seek(target);
      if (playing) segmentTransport.start();
    } else {
      for (const track of tracks) applySeek(track, target);
    }
    followPlayhead(target);
    render();
  }

  async function play() {
    // 待つ前に読む。待っているあいだに基準を読み直すと、まだ 0 秒のトラックが
    // 基準になって頭出しした位置を失う。
    const base = positionOf();
    if (useSegments) {
      segmentTransport.base = base;
      await segmentTransport.start();
      playing = true;
      clear(playButton).append(icon("bi-pause-fill"), "一時停止");
      return;
    }
    if (context.state === "suspended") await context.resume();
    // 全部のメタデータが揃うまで待ってから位置を合わせる。読めていない
    // <audio> は currentTime を受け取らないので、待たずに鳴らすと、そのトラック
    // だけ 0 秒から始まる（人数が多い・録音が長いほど当たりやすい）。
    await Promise.all(tracks.map(whenReady));
    await Promise.all(tracks.map((track) => applySeek(track, base)));
    await Promise.allSettled(tracks.map((t) => t.audio.play()));
    playing = true;
    clear(playButton).append(icon("bi-pause-fill"), "一時停止");
  }

  function pause() {
    if (useSegments) {
      segmentTransport.stop();
    } else {
      for (const track of tracks) {
        track.audio.pause();
        track.audio.playbackRate = 1;   // 同期のための速度調整を持ち越さない
      }
    }
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
    const mute = el("button", { class: "daw-btn is-mute", type: "button", title: "ミュート",
                                "aria-label": `${track.name} をミュート`,
                                onclick: () => { track.muted = !track.muted; applyRouting(); } }, "M");
    const solo = el("button", { class: "daw-btn is-solo", type: "button", title: "ソロ",
                                "aria-label": `${track.name} をソロ`,
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
      el("div", { class: "daw-head-buttons" }, mute, solo,
         analysisUrl
           ? (track.inspectButton = el("button", {
               class: "daw-btn", type: "button", title: "声を調べる",
               "aria-label": `${track.name} の声を調べる`,
               onclick: () => inspect(track),
             }, "?"))
           : null));
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
      mute = el("button", { class: "daw-btn is-mute", type: "button", title: "ミュート",
                            "aria-label": `${label} をミュート`,
                            onclick: () => { target.muted = !target.muted; applyRouting(); } }, "M");
      solo = el("button", { class: "daw-btn is-solo", type: "button", title: "ソロ",
                            "aria-label": `${label} をソロ`,
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

  // ── 声の解析 ────────────────────────────────────────────
  // 「加工されているか」までを出す。「誰か」は出さない（出せない）。
  const inspectBody = el("div", { class: "stack" });
  const inspectPanel = el("div", { class: "daw-inspect", hidden: true },
    el("div", { class: "daw-inspect-head" },
       el("strong", { class: "grow", text: "声の解析" }),
       el("button", { class: "btn btn-sm", type: "button",
                      onclick: () => { inspectPanel.hidden = true; } }, "閉じる")),
    inspectBody);

  function row(label, value) {
    return el("div", { class: "list-row" },
              el("span", { class: "grow", text: label }),
              el("span", { class: "mono", text: value }));
  }

  async function inspect(track) {
    /* 押した時点の選択範囲を控える。応答を待つあいだに範囲を動かされても、
       結果に添える「どこを調べたか」がずれないようにする。 */
    const region = loopRegion ? { ...loopRegion } : null;

    inspectPanel.hidden = false;
    clear(inspectBody).append(loading(
      region
        ? `${formatTime(region.start)} 〜 ${formatTime(region.end)} の声を調べています…`
        : "録音全体から抜き出して調べています…"));

    /* 範囲を選んであればそこだけを調べる。自動で抜き出す方式は、長い録音
       になるほど喋っている所へ当たらない（4時間の実録音では全トラックが
       判定不能になった）。どこを見るかは、波形を見ている人が決めるのが
       いちばん確かなので、選択範囲をそのまま渡す。 */
    const query = region
      ? `?start=${region.start.toFixed(3)}&end=${region.end.toFixed(3)}`
      : "";

    let result;
    try {
      const response = await fetch(`${analysisUrl}/${track.stem.index}${query}`, {
        credentials: "same-origin", headers: { Accept: "application/json" },
      });
      /* 本文が JSON とは限らない（プロキシや前段が HTML のエラーページを
         返すことがある）。先に json() を呼ぶと、断られた理由ではなく
         「Unexpected token '<'」が利用者に出る。文字列で受けてから試す。 */
      const body = await response.text();
      try {
        result = JSON.parse(body);
      } catch {
        throw new Error(response.ok ? "応答を解釈できませんでした" : `HTTP ${response.status}`);
      }
      if (!response.ok) throw new Error(result.detail || `HTTP ${response.status}`);
    } catch (error) {
      clear(inspectBody).append(
        el("div", { class: "empty", text: `調べられませんでした（${error.message}）` }));
      return;
    }

    const verdict = {
      natural: ["加工の形跡なし", ""],
      suspect: ["加工の形跡あり", "danger"],
      // CSS 側の名前は .chip.warning（.chip.warn は存在しない）。
      // 綴りが違うと、無色の既定チップとして出て注意色にならない。
      unknown: ["判定できず", "warning"],
    }[result.verdict] || ["判定できず", "warning"];

    const rows = [];
    // 「どこを調べたか」を最初に出す。結果だけ見せると、選び直せば変わる値
    // だということが伝わらない。
    if (result.range) {
      rows.push(row("調べた区間",
                    `${formatTime(result.range.start)} 〜 ${formatTime(result.range.end)}`
                    + `（${result.analysed_seconds} 秒）`));
    } else if (result.analysed_seconds) {
      rows.push(row("調べた音", `録音全体から抜き出した ${result.analysed_seconds} 秒`));
    }
    if (result.f0_hz) rows.push(row("声の高さ（基本周波数）", `${result.f0_hz} Hz`));
    if (result.formants_hz && result.formants_hz.length) {
      rows.push(row("フォルマント", result.formants_hz.map((v) => `${v}`).join(" / ") + " Hz"));
    }
    if (result.formant_spacing_hz) {
      rows.push(row("フォルマントの間隔", `${result.formant_spacing_hz} Hz`));
    }
    if (result.vocal_tract_cm) {
      // 中央値だけを出すと、値の硬さが分からない。同じ区間の中でどこまで
      // 散らばっていたかを併記する。
      const band = (result.vocal_tract_low_cm && result.vocal_tract_high_cm)
        ? `${result.vocal_tract_cm} cm`
          + `（この区間では ${result.vocal_tract_low_cm}〜${result.vocal_tract_high_cm} cm）`
        : `${result.vocal_tract_cm} cm`;
      rows.push(row("そこから求めた声道長", band));
    }
    if (result.expected_vocal_tract_cm) {
      rows.push(row("この声の高さなら", `${result.expected_vocal_tract_cm} cm 前後`));
    }
    if (result.frames) rows.push(row("調べたフレーム数", String(result.frames)));

    // 範囲を選ばずに呼んだときは、次にどうすればよいかを添える。
    const hint = result.range ? null : el("p", { class: "field-help", text:
      "時間目盛りを横にドラッグしてその人が喋っている区間を選んでから調べると、"
      + "確かな値が出ます。区間を選ばない場合は録音全体から少しずつ抜き出すため、"
      + "長い録音ではほとんど当たりません。" });

    // clear() が返すのは素の DOM ノードで、その append は null を文字列
    // "null" にしてしまう。dom.js の append は飛ばしてくれる。
    append(clear(inspectBody), [
      el("div", { class: "row" },
         el("strong", { text: result.name || track.name }),
         el("span", { class: `chip ${verdict[1]}`, text: verdict[0] })),
      el("p", { class: "field-help", text: result.reason || "" }),
      hint,
      rows.length ? el("div", { class: "list" }, rows) : null,
      result.restorable ? restoreControls(track, result, region) : null,
      el("p", { class: "field-help", text:
        "この解析が言えるのは「加工されているか」までです。誰の声かは判定していません"
        + "（できません）。RVC のように声質そのものを別人へ置き換える方式では、"
        + "元の声は失われているため復元もできません。" }),
    ]);
  }

  function restoreControls(track, result, region) {
    const suggested = Math.min(2, Math.max(0.5, result.estimated_factor || 1));
    const value = el("span", { class: "mono", text: suggested.toFixed(2) });
    const slider = el("input", {
      class: "input", type: "range", min: "50", max: "200",
      "aria-label": "打ち消す倍率（百分率）",
      value: String(Math.round(suggested * 100)),
      oninput: () => { value.textContent = (slider.value / 100).toFixed(2); },
    });
    const play = el("button", { class: "btn btn-sm", type: "button", onclick: () => {
      // 元のトラックと差し替えず、別に鳴らす（比べられるように）。
      // 調べた区間と同じ所だけを返してもらう。全体を変換させると、4時間の
      // 録音では数秒を聞くために長々と待つことになる。
      const factor = (slider.value / 100).toFixed(3);
      const span = region
        ? `&start=${region.start.toFixed(3)}&end=${region.end.toFixed(3)}`
        : "";
      const audio = new Audio(`${result.restore_url}?factor=${factor}${span}`);
      audio.play().catch((e) => toast(`再生できません（${e.message}）`, "danger"));
      toast(region
        ? `${formatTime(region.start)} 〜 ${formatTime(region.end)} を ${factor} 倍で打ち消して再生します`
        : `${factor} 倍を打ち消して再生します`, "success", { duration: 3000 });
    } }, icon("bi-play-fill"), "打ち消して聞く");

    return el("div", { class: "stack" },
      el("p", { class: "field-help", text:
        "打ち消す倍率は耳で合わせてください。本人の地声が分からない以上、"
        + "正しい倍率を機械が決めることはできません（下の値は出発点の目安です）。" }),
      el("div", { class: "row" }, slider, value, play));
  }

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

    /* 「声を調べる」は区間の有無で見るものが変わる。押す前に分かるように、
       説明をここで書き換える（結果の中だけに書いても、押したあとにしか
       読めない）。 */
    const span = loopRegion
      ? `${formatTime(loopRegion.start)} 〜 ${formatTime(loopRegion.end)}`
      : null;
    for (const track of tracks) {
      if (!track.inspectButton) continue;
      track.inspectButton.classList.toggle("is-armed", Boolean(loopRegion));
      track.inspectButton.title = span
        ? `${span} の声を調べる`
        : "声を調べる（時間目盛りをドラッグして区間を選ぶと確かになります）";
      track.inspectButton.setAttribute(
        "aria-label",
        span ? `${track.name} の ${span} の声を調べる` : `${track.name} の声を調べる`);
    }

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
  let destroyed = false;
  function tick(now) {
    if (destroyed) return;
    render();
    if (currentView === "console" || playing) {
      for (const track of tracks) measure(track, now);
      measure(master, now);
    }
    if (playing && useSegments) {
      // 音源が1つなので、トラック同士を突き合わせる必要が無い。
      // 先の区間を切らさないことだけ見る。
      segmentTransport.pump();
      const base = segmentTransport.position();
      if (looping && loopRegion && base >= loopRegion.end) seek(loopRegion.start);
      else if (duration && base >= duration - 0.05) pause();
      else followPlayhead(base);
    } else if (playing) {
      const reference = masterAudio();
      const base = reference ? reference.currentTime || 0 : 0;
      // 基準からのずれを直す。小さいうちは速度で吸収し、頭出しは最後の手段に
      // する（頭出しは音が途切れるので、細かいずれのたびにやると鳴り直しに
      // なって、かえって聞けたものではなくなる）。
      for (const track of tracks) {
        const audio = track.audio;
        if (audio === reference || audio.error || audio.readyState < 1 || audio.seeking) continue;
        const drift = audio.currentTime - base;   // 正なら進みすぎ
        const size = Math.abs(drift);
        if (size > SYNC_RESEEK_SEC) {
          applySeek(track, base);
        } else if (size > SYNC_IGNORE_SEC) {
          audio.playbackRate =
            1 + Math.max(-SYNC_MAX_RATE, Math.min(SYNC_MAX_RATE, -drift));
        } else if (audio.playbackRate !== 1) {
          audio.playbackRate = 1;
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
       inspectPanel,
       arrange,
       consoleView,
       el("p", { class: "field-help", text:
         "スペースで再生／停止、←→ で移動、＋− で拡大。M＝ミュート、S＝ソロ。" +
         "フェーダーはダブルクリックで 0dB、つまみは上下ドラッグでパン。" +
         "時間目盛りを横にドラッグするとループ区間になり、その範囲だけ書き出せます。" +
         "声を調べるときも同じ区間を見ます（その人がはっきり喋っている所を" +
         "選んでから「?」を押してください）。" +
         "トラックの名前をドラッグすると並べ替えられます。" +
         "各トラックは同じ時間軸に揃えてあるので、途中から参加した人は冒頭が、" +
         "途中で抜けた人は末尾が無音になります。" }))
  );

  const onResize = () => layout();
  window.addEventListener("resize", onResize);

  // レイアウトが決まってから描く。
  // このハンドルも raf に入れておくこと。入れていなかったときは、最初の1コマが
  // 来る前に destroy() されると（一覧へ戻るのを続けて押した等）取り消せず、
  // 閉じたあとに描画ループが立ち上がっていた。
  raf = window.requestAnimationFrame(() => {
    if (destroyed) return;
    zoomToFit();
    applyRouting();
    raf = window.requestAnimationFrame(tick);
  });

  return {
    destroy() {
      if (destroyed) return;
      destroyed = true;
      playing = false;
      window.removeEventListener("resize", onResize);
      window.removeEventListener("keydown", onKeyDown);
      if (raf) window.cancelAnimationFrame(raf);
      raf = null;
      segmentTransport.stop();
      for (const track of tracks) {
        if (!track.audio) continue;
        track.audio.pause();
        track.audio.src = "";
      }
      context.close().catch(() => { /* 既に閉じている */ });
    },
  };
}
