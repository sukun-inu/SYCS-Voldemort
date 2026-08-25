/* 録音ミキサー。トラックごとに波形を並べ、同じ時間軸で再生する。

   音は <audio> を1トラック1つ持ち、Web Audio の GainNode を通して鳴らす。
   全部を decodeAudioData で展開する作りにすると、長い録音（数時間×人数）で
   メモリが破綻するため、ストリーミング再生できる <audio> を土台にしている。
   音量・ミュート・ソロは GainNode 側で効かせる。 */

import { el, icon, clear, loading } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const LANE_HEIGHT = 56;
const HEADER_WIDTH = 200;
// 再生位置の追従。ずれてきたら黙って引き戻す。
const SYNC_TOLERANCE = 0.25;

function formatTime(seconds) {
  const total = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0");
  const ss = String(s).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** 目盛りの間隔を、全体の長さから決める（線が詰まりすぎないように）。 */
function tickStep(duration) {
  for (const step of [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600]) {
    if (duration / step <= 12) return step;
  }
  return 3600;
}

/** 波形を1レーンぶん描く。peaks は 0..1 の配列。 */
function drawWaveform(canvas, peaks, color) {
  const ctx = canvas.getContext("2d");
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 1;
  const height = canvas.clientHeight || LANE_HEIGHT;
  canvas.width = Math.floor(width * ratio);
  canvas.height = Math.floor(height * ratio);
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const middle = height / 2;
  ctx.strokeStyle = "rgba(255,255,255,.12)";
  ctx.beginPath();
  ctx.moveTo(0, middle);
  ctx.lineTo(width, middle);
  ctx.stroke();

  if (!peaks || !peaks.length) return;

  ctx.fillStyle = color;
  const step = width / peaks.length;
  const barWidth = Math.max(1, step - 0.5);
  for (let i = 0; i < peaks.length; i += 1) {
    const amplitude = Math.max(0, Math.min(1, peaks[i]));
    if (amplitude <= 0) continue;
    const barHeight = Math.max(1, amplitude * (height - 6));
    ctx.fillRect(i * step, middle - barHeight / 2, barWidth, barHeight);
  }
}

const LANE_COLORS = [
  "#4fa9ff", "#33cfcf", "#ff9a3c", "#a78bfa",
  "#5ad48a", "#ff6b9d", "#e0c341", "#7fd1ff",
];

/** ミキサーを container の中に組み立てる。
 *
 *  ウィンドウはアプリIDで一意なので、録音ごとに窓を開くことができない。
 *  代わりに録音パネルの中身を差し替えて使う。後片付けは呼び出し側が
 *  destroy() を呼んで行う。 */
export async function createMixer(container, options = {}) {
  const { manifestUrl } = options;
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
  // 書き出し時に測った「声として成立しているか」。判定のしきい値も索引から
  // 受け取る（同じ判定を画面側にも書くと、片方だけ変わって食い違う）。
  const periodicityMin = Number(manifest.periodicity_min) || 0;
  const context = new (window.AudioContext || window.webkitAudioContext)();
  const lanes = [];
  let playing = false;
  let soloActive = false;

  // ── 各トラック ──────────────────────────────────────────
  const laneList = el("div", { class: "mixer-lanes" });

  stems.forEach((stem, index) => {
    const color = LANE_COLORS[index % LANE_COLORS.length];

    // DOM に置いておく（hidden）。切り離したままだと、ウィンドウを閉じたときの
    // 後片付けやデバッグで追いにくい。
    const audio = el("audio", {
      src: stem.url, preload: "metadata", hidden: true,
      dataset: { stem: String(stem.index) },
    });
    audio.crossOrigin = "use-credentials";

    const source = context.createMediaElementSource(audio);
    const gain = context.createGain();
    source.connect(gain).connect(context.destination);

    const muteButton = el("button", { class: "btn btn-sm", type: "button" }, "M");
    const soloButton = el("button", { class: "btn btn-sm", type: "button" }, "S");
    const volume = el("input", {
      class: "mixer-volume", type: "range", min: "0", max: "150", value: "100",
    });
    const canvas = el("canvas", { class: "mixer-wave" });

    // 雑音になっているトラックは、聞く前に分かるようにしておく。
    const periodicity = stem.periodicity;
    const suspect = periodicity !== null && periodicity !== undefined
      && periodicityMin > 0 && periodicity < periodicityMin;

    const lane = {
      stem, audio, gain, muted: false, solo: false,
      volume: 1, canvas, peaks: stem.peaks || [], color,
      muteButton, soloButton, suspect,
    };

    const applyGain = () => {
      const silenced = lane.muted || (soloActive && !lane.solo);
      gain.gain.value = silenced ? 0 : lane.volume;
      muteButton.classList.toggle("btn-danger", lane.muted);
      soloButton.classList.toggle("btn-primary", lane.solo);
      lane.canvas.style.opacity = silenced ? "0.25" : "1";
    };
    lane.applyGain = applyGain;

    muteButton.addEventListener("click", () => { lane.muted = !lane.muted; refreshGains(); });
    soloButton.addEventListener("click", () => {
      lane.solo = !lane.solo;
      soloActive = lanes.some((l) => l.solo);
      refreshGains();
    });
    volume.addEventListener("input", () => {
      lane.volume = Number(volume.value) / 100;
      applyGain();
    });

    lanes.push(lane);
    laneList.append(
      el("div", { class: "mixer-lane" },
         el("div", { class: "mixer-lane-head" },
            el("div", { class: "mixer-lane-name truncate", title: stem.name },
               stem.name,
               suspect
                 ? el("span", {
                     class: "chip danger mixer-warn",
                     title: "自動判定です。波形と再生で確かめてください。",
                     text: "音が壊れている可能性",
                   })
                 : null),
            el("div", { class: "mixer-lane-controls" }, muteButton, soloButton, volume),
            el("div", { class: "mixer-lane-sub",
                        text: `発話 ${formatTime(stem.voiced_seconds || 0)}` })),
         el("div", { class: "mixer-lane-wave" }, canvas),
         audio)
    );
  });

  function refreshGains() {
    soloActive = lanes.some((l) => l.solo);
    lanes.forEach((lane) => lane.applyGain());
  }

  // ── 時間軸 ──────────────────────────────────────────────
  const ruler = el("div", { class: "mixer-ruler" });
  function drawRuler() {
    clear(ruler);
    if (duration <= 0) return;
    const step = tickStep(duration);
    for (let t = 0; t <= duration; t += step) {
      ruler.append(
        el("span", { class: "mixer-tick", style: { left: `${(t / duration) * 100}%` } },
           formatTime(t))
      );
    }
  }

  const playhead = el("div", { class: "mixer-playhead" });
  const scrubber = el("div", { class: "mixer-scrub" }, playhead);

  // ── 操作 ────────────────────────────────────────────────
  const playButton = el("button", { class: "btn btn-primary", type: "button" },
                        icon("bi-play-fill"), "再生");
  const stopButton = el("button", { class: "btn", type: "button" },
                        icon("bi-stop-fill"), "停止");
  const clock = el("span", { class: "mixer-clock mono", text: `0:00 / ${formatTime(duration)}` });

  function positionOf() {
    const lane = lanes[0];
    return lane ? lane.audio.currentTime || 0 : 0;
  }

  function seek(seconds) {
    const target = Math.max(0, Math.min(duration || Infinity, seconds));
    lanes.forEach((lane) => {
      try { lane.audio.currentTime = target; } catch { /* まだ読めていない */ }
    });
    render();
  }

  async function play() {
    if (context.state === "suspended") await context.resume();
    const base = positionOf();
    lanes.forEach((lane) => {
      try { lane.audio.currentTime = base; } catch { /* noop */ }
    });
    await Promise.allSettled(lanes.map((lane) => lane.audio.play()));
    playing = true;
    clear(playButton).append(icon("bi-pause-fill"), "一時停止");
  }

  function pause() {
    lanes.forEach((lane) => lane.audio.pause());
    playing = false;
    clear(playButton).append(icon("bi-play-fill"), "再生");
  }

  playButton.addEventListener("click", async () => {
    try {
      if (playing) pause();
      else await play();
    } catch (error) {
      toast(`再生できませんでした（${error.message}）`, "danger", { duration: 6000 });
    }
  });
  stopButton.addEventListener("click", () => { pause(); seek(0); });

  scrubber.addEventListener("click", (event) => {
    if (!duration) return;
    const box = scrubber.getBoundingClientRect();
    seek(((event.clientX - box.left) / box.width) * duration);
  });

  // ── 描画ループ ──────────────────────────────────────────
  function render() {
    const at = positionOf();
    const ratio = duration ? Math.min(1, at / duration) : 0;
    playhead.style.left = `${ratio * 100}%`;
    clock.textContent = `${formatTime(at)} / ${formatTime(duration)}`;
  }

  let raf = null;
  function tick() {
    render();
    if (playing) {
      // ずれてきたら先頭トラックに合わせ直す
      const base = lanes[0]?.audio.currentTime || 0;
      lanes.slice(1).forEach((lane) => {
        if (Math.abs(lane.audio.currentTime - base) > SYNC_TOLERANCE) {
          try { lane.audio.currentTime = base; } catch { /* noop */ }
        }
      });
      if (duration && base >= duration - 0.05) { pause(); }
    }
    raf = window.requestAnimationFrame(tick);
  }

  // ── 組み立て ────────────────────────────────────────────
  clear(container).append(
    el("div", { class: "stack mixer" },
       el("div", { class: "row mixer-transport" },
          playButton, stopButton, clock,
          el("span", { class: "grow" }),
          el("span", { class: "list-sub", text: `${stems.length} トラック` })),
       el("div", { class: "mixer-timeline" },
          el("div", { class: "mixer-timeline-head" }),
          el("div", { class: "mixer-timeline-body" }, ruler, scrubber)),
       laneList,
       el("p", { class: "field-help", text:
         "M＝ミュート / S＝ソロ。スライダーは音量です。波形をクリックすると頭出しできます。" +
         "各トラックは同じ時間軸に揃えてあるので、途中から参加した人は冒頭が、" +
         "途中で抜けた人は末尾が無音になります。" }))
  );

  function redraw() {
    lanes.forEach((lane) => drawWaveform(lane.canvas, lane.peaks, lane.color));
    drawRuler();
  }

  // レイアウトが決まってから描く
  window.requestAnimationFrame(() => {
    redraw();
    refreshGains();
    tick();
  });

  const onResize = () => redraw();
  window.addEventListener("resize", onResize);

  return {
    destroy() {
      window.removeEventListener("resize", onResize);
      if (raf) window.cancelAnimationFrame(raf);
      lanes.forEach((lane) => { lane.audio.pause(); lane.audio.src = ""; });
      context.close().catch(() => { /* 既に閉じている */ });
    },
  };
}
