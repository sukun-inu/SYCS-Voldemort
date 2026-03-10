const CURRENT_URL = new URL(window.location.href);
const APP_BASE = new URL(
  CURRENT_URL.pathname.endsWith("/") ? CURRENT_URL.pathname : `${CURRENT_URL.pathname}/`,
  CURRENT_URL.origin
);

const METALS = {
  gold: {
    label: "金 (Gold)",
    borderColor: "#B28704",
    fillColor: "rgba(178,135,4,0.18)",
    deltaColor: "rgba(178,135,4,0.42)",
    canvasId: "goldChart",
  },
  silver: {
    label: "銀 (Silver)",
    borderColor: "#5D6A75",
    fillColor: "rgba(93,106,117,0.18)",
    deltaColor: "rgba(93,106,117,0.42)",
    canvasId: "silverChart",
  },
  platinum: {
    label: "プラチナ (Platinum)",
    borderColor: "#0A7D88",
    fillColor: "rgba(10,125,136,0.18)",
    deltaColor: "rgba(10,125,136,0.42)",
    canvasId: "platinumChart",
  },
};

const charts = {};
let purityOptions = {};
let swRegistration = null;
let pushEnabledByServer = false;
let pushPublicKey = null;
let pushNotifyTimeJst = "11:00";
let latestHistoryPayload = null;
let lastChartMobileMode = null;

const CHART_CDN_LIST = [
  "https://cdn.jsdelivr.net/npm/chart.js@4.5.0/dist/chart.umd.min.js",
  "https://unpkg.com/chart.js@4.5.0/dist/chart.umd.min.js",
];
const CHART_MIN_WIDTH_DESKTOP_PX = 640;
const CHART_MAX_WIDTH_DESKTOP_PX = 2000;
const CHART_MIN_WIDTH_MOBILE_PX = 420;
const CHART_MAX_WIDTH_MOBILE_PX = 1200;
const CHART_PX_PER_DAY_DESKTOP = 5;
const CHART_PX_PER_DAY_MOBILE = 3;
const CHART_DPR_CAP = 1.75;

function appUrl(path) {
  return new URL(path.replace(/^\/+/, ""), APP_BASE).toString();
}

function appScopePath() {
  return new URL("./", APP_BASE).pathname;
}

function isMobileChartViewport() {
  return window.matchMedia("(max-width: 860px)").matches;
}

function resolveChartTrackWidth(days, isMobile) {
  const pxPerDay = isMobile ? CHART_PX_PER_DAY_MOBILE : CHART_PX_PER_DAY_DESKTOP;
  const minWidth = isMobile ? CHART_MIN_WIDTH_MOBILE_PX : CHART_MIN_WIDTH_DESKTOP_PX;
  const maxWidth = isMobile ? CHART_MAX_WIDTH_MOBILE_PX : CHART_MAX_WIDTH_DESKTOP_PX;
  return Math.min(maxWidth, Math.max(minWidth, days * pxPerDay));
}

function loadExternalScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.crossOrigin = "anonymous";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`script load failed: ${src}`));
    document.head.appendChild(script);
  });
}

async function ensureChartLibrary() {
  if (window.Chart) {
    return;
  }

  let lastError = null;
  for (const src of CHART_CDN_LIST) {
    try {
      await loadExternalScript(src);
      if (window.Chart) {
        return;
      }
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Chart.jsの読み込みに失敗しました。");
}

function formatYen(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return `${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value)} 円/g`;
}

function formatYenInt(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return `${new Intl.NumberFormat("ja-JP").format(value)} 円`;
}

function formatDelta(value) {
  if (value === null || value === undefined) {
    return "初回データ";
  }
  const sign = value > 0 ? "+" : "";
  return `${sign}${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value)} 円`;
}

function parseIsoDate(isoDate) {
  const [year, month, day] = isoDate.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day));
}

function toIsoDate(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function enumerateDailyAxis(startIso, endIso) {
  const start = parseIsoDate(startIso);
  const end = parseIsoDate(endIso);
  const dates = [];
  for (let cursor = start; cursor.getTime() <= end.getTime(); cursor = new Date(cursor.getTime() + 86400000)) {
    dates.push(toIsoDate(cursor));
  }
  return dates;
}

function formatDailyLabel(isoDate) {
  const [, month, day] = isoDate.split("-");
  return `${Number(month)}/${Number(day)}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function buildSummary(latest) {
  const root = document.getElementById("summaryCards");
  root.innerHTML = "";
  Object.entries(METALS).forEach(([key, meta]) => {
    const data = latest[key] || {};
    const delta = data.delta_from_previous;
    const deltaClass = delta > 0 ? "delta-up" : delta < 0 ? "delta-down" : "";
    const card = document.createElement("article");
    card.className = "summary-card";
    card.innerHTML = `
      <h3>${meta.label}</h3>
      <div class="summary-price">${formatYen(data.price_per_gram)}</div>
      <div class="summary-delta ${deltaClass}">前日差: ${formatDelta(delta)}</div>
      <div class="meta">基準日: ${data.date || "-"}</div>
    `;
    root.appendChild(card);
  });
}

function fillMetalSelector() {
  const selector = document.getElementById("calcMetal");
  selector.innerHTML = "";
  Object.entries(purityOptions).forEach(([key, item]) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = `${item.display_name} (${key})`;
    selector.appendChild(option);
  });
}

function renderPurityResult(payload) {
  const rows = Object.entries(payload.by_purity || {})
    .map(([grade, value]) => `<tr><td>${escapeHtml(grade)}</td><td>${formatYenInt(value)}</td></tr>`)
    .join("");
  document.getElementById("calcResult").innerHTML = `
    <table class="calc-table">
      <thead>
        <tr><th>純度</th><th>価格</th></tr>
      </thead>
      <tbody>
        <tr><td>純金属換算</td><td>${formatYenInt(payload.pure_value)}</td></tr>
        ${rows}
      </tbody>
    </table>
  `;
}

async function loadPurityOptions() {
  const response = await fetch(appUrl("api/purity/options"));
  if (!response.ok) {
    throw new Error("純度情報の取得に失敗しました。");
  }
  const payload = await response.json();
  purityOptions = payload.metals || {};
  fillMetalSelector();
}

async function calculatePurityPrice() {
  const metal = document.getElementById("calcMetal").value;
  const grams = Number(document.getElementById("calcGrams").value);
  const meta = document.getElementById("calcMeta");
  if (!metal || Number.isNaN(grams) || grams <= 0) {
    meta.textContent = "グラムは 0 より大きい値を入力してください。";
    return;
  }

  const query = new URLSearchParams({ metal, grams: String(grams) });
  const response = await fetch(`${appUrl("api/prices/calculate")}?${query.toString()}`);
  if (!response.ok) {
    let message = "純度計算に失敗しました。";
    try {
      const errorPayload = await response.json();
      if (errorPayload.detail) {
        message = String(errorPayload.detail);
      }
    } catch (_) {}
    throw new Error(message);
  }

  const payload = await response.json();
  meta.textContent = `基準価格日: ${payload.snapshot_date} / 単価: ${formatYen(payload.price_per_gram)} / グラム: ${payload.grams}g`;
  renderPurityResult(payload);
}

function renderMetalChart(metalKey, history, dailyAxis) {
  const meta = METALS[metalKey];
  if (!meta || !window.Chart) {
    return;
  }

  const dailyMap = new Map(history.map((item) => [item.date, item]));
  const labels = dailyAxis.map((date) => formatDailyLabel(date));
  const prices = dailyAxis.map((date) => dailyMap.get(date)?.price_per_gram ?? null);
  const deltas = dailyAxis.map((date) => dailyMap.get(date)?.delta_from_previous ?? null);
  const canvas = document.getElementById(meta.canvasId);
  if (!canvas) {
    return;
  }
  const chartTrack = canvas.closest(".chart-track");
  const isMobile = isMobileChartViewport();
  const chartWidth = resolveChartTrackWidth(dailyAxis.length, isMobile);
  if (chartTrack) {
    chartTrack.style.width = `${chartWidth}px`;
  }

  const context = canvas.getContext("2d");
  if (!context) {
    return;
  }
  const xMaxTicks = isMobile ? 7 : 11;
  const chartDpr = Math.min(window.devicePixelRatio || 1, CHART_DPR_CAP);

  const existing = charts[metalKey];
  if (existing) {
    existing.data.labels = labels;
    if (existing.data.datasets?.[0]) {
      existing.data.datasets[0].data = prices;
      existing.data.datasets[0].pointRadius = dailyAxis.length <= 120 ? 1 : 0;
    }
    if (existing.data.datasets?.[1]) {
      existing.data.datasets[1].data = deltas;
    }
    if (!existing.options) {
      existing.options = {};
    }
    existing.options.devicePixelRatio = chartDpr;
    if (!existing.options.scales) {
      existing.options.scales = {};
    }
    if (!existing.options.scales.x) {
      existing.options.scales.x = { type: "category", ticks: {} };
    }
    if (!existing.options.scales.x.ticks) {
      existing.options.scales.x.ticks = {};
    }
    existing.options.scales.x.ticks.autoSkip = true;
    existing.options.scales.x.ticks.maxTicksLimit = xMaxTicks;
    existing.options.scales.x.ticks.maxRotation = 0;
    existing.options.scales.x.ticks.minRotation = 0;

    if (!existing.options.plugins) {
      existing.options.plugins = {};
    }
    if (!existing.options.plugins.tooltip) {
      existing.options.plugins.tooltip = {};
    }
    if (!existing.options.plugins.tooltip.callbacks) {
      existing.options.plugins.tooltip.callbacks = {};
    }
    existing.options.plugins.tooltip.callbacks.title = (items) => (items.length ? dailyAxis[items[0].dataIndex] : "");
    existing.update("none");
    return;
  }

  charts[metalKey] = new window.Chart(context, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "価格 (円/g)",
          data: prices,
          borderColor: meta.borderColor,
          backgroundColor: meta.fillColor,
          tension: 0,
          stepped: true,
          spanGaps: false,
          fill: true,
          pointRadius: dailyAxis.length <= 120 ? 1.5 : 0,
          yAxisID: "yPrice",
        },
        {
          label: "前日差 (円)",
          type: "bar",
          data: deltas,
          backgroundColor: meta.deltaColor,
          borderWidth: 0,
          yAxisID: "yDelta",
        },
      ],
    },
    options: {
      devicePixelRatio: chartDpr,
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        yPrice: {
          type: "linear",
          position: "left",
          ticks: {
            callback: (value) => new Intl.NumberFormat("ja-JP").format(value),
          },
        },
        yDelta: {
          type: "linear",
          position: "right",
          grid: { drawOnChartArea: false },
          ticks: {
            callback: (value) => new Intl.NumberFormat("ja-JP").format(value),
          },
        },
        x: {
          type: "category",
          ticks: {
            autoSkip: true,
            maxTicksLimit: xMaxTicks,
            maxRotation: 0,
            minRotation: 0,
          },
        },
      },
      plugins: {
        tooltip: {
          callbacks: {
            title: (items) => (items.length ? dailyAxis[items[0].dataIndex] : ""),
          },
        },
        legend: { labels: { boxWidth: 10 } },
      },
    },
  });
}

async function loadDashboard() {
  await ensureChartLibrary();
  const days = Number(document.getElementById("daysSelect").value || 30);
  const response = await fetch(`${appUrl("api/prices/history")}?days=${days}`);
  if (!response.ok) {
    throw new Error("データ取得に失敗しました。");
  }

  const payload = await response.json();
  latestHistoryPayload = payload;
  renderDashboardFromPayload(payload);
}

function renderDashboardFromPayload(payload) {
  if (!payload) {
    return;
  }
  lastChartMobileMode = isMobileChartViewport();
  const dailyAxis = enumerateDailyAxis(payload.range_start, payload.range_end);
  document.getElementById("generatedAt").textContent =
    `更新頻度: 1日1回 (JST 00:00) / 表示期間: ${payload.range_start} - ${payload.range_end}`;
  buildSummary(payload.latest || {});

  Object.keys(METALS).forEach((key) => {
    renderMetalChart(key, payload.metals?.[key] || [], dailyAxis);
  });
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replaceAll("-", "+").replaceAll("_", "/");
  const rawData = atob(base64);
  return Uint8Array.from(rawData.split("").map((char) => char.charCodeAt(0)));
}

function setPushStatus(message) {
  document.getElementById("pushStatus").textContent = message;
}

function setPushButtonState({ subscribed, disabled }) {
  const button = document.getElementById("pushButton");
  button.dataset.subscribed = subscribed ? "true" : "false";
  button.disabled = !!disabled;
  button.textContent = subscribed ? "Push通知を無効化" : "Push通知を有効化";
}

async function syncPushSubscription(subscription) {
  const response = await fetch(appUrl("api/push/subscribe"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(subscription.toJSON()),
  });
  if (!response.ok) {
    throw new Error("Push購読情報の保存に失敗しました。");
  }
}

async function removePushSubscription(subscription) {
  const response = await fetch(appUrl("api/push/unsubscribe"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoint: subscription.endpoint }),
  });
  if (!response.ok) {
    throw new Error("Push購読解除情報の保存に失敗しました。");
  }
}

async function enablePushNotifications() {
  if (!window.isSecureContext) {
    throw new Error("Push通知はHTTPS接続でのみ有効化できます。");
  }
  if (!swRegistration || !pushPublicKey) {
    throw new Error("Push通知は現在利用できません。");
  }
  if (Notification.permission === "denied") {
    throw new Error("通知権限がブラウザで拒否されています。");
  }

  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    throw new Error("通知権限が許可されませんでした。");
  }

  let subscription = await swRegistration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await swRegistration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(pushPublicKey),
    });
  }

  await syncPushSubscription(subscription);
  setPushButtonState({ subscribed: true, disabled: false });
  setPushStatus(`Push通知を有効化しました。毎日 ${pushNotifyTimeJst} (JST) に通知します。`);
}

async function disablePushNotifications() {
  if (!swRegistration) {
    return;
  }
  const subscription = await swRegistration.pushManager.getSubscription();
  if (subscription) {
    try {
      await removePushSubscription(subscription);
    } catch (_) {}
    await subscription.unsubscribe();
  }
  setPushButtonState({ subscribed: false, disabled: false });
  setPushStatus("Push通知を無効化しました。");
}

async function initializePwaAndPush() {
  const notifyChip = document.getElementById("notifyTimeChip");
  if (!("serviceWorker" in navigator)) {
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("このブラウザはService Workerに未対応です。");
    return;
  }

  try {
    swRegistration = await navigator.serviceWorker.register(appUrl("sw.js"), { scope: appScopePath() });
    await navigator.serviceWorker.ready;
  } catch (error) {
    console.error(error);
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Service Workerの登録に失敗しました。");
    return;
  }

  try {
    const response = await fetch(appUrl("api/push/public-key"));
    if (!response.ok) {
      throw new Error("Push設定の取得に失敗しました。");
    }
    const payload = await response.json();
    pushEnabledByServer = !!payload.enabled;
    pushPublicKey = payload.public_key || null;
    pushNotifyTimeJst = payload.notify_time_jst || "11:00";
    const serverReason = payload.reason || null;
    notifyChip.textContent = `通知: JST ${pushNotifyTimeJst}`;
    if (serverReason && !pushEnabledByServer) {
      setPushStatus(`Push通知は無効です: ${serverReason}`);
    }
  } catch (error) {
    console.error(error);
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Push設定の取得に失敗しました。");
    return;
  }

  if (!window.isSecureContext) {
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Push通知はHTTPS接続でのみ有効です。");
    return;
  }
  if (!("PushManager" in window) || !pushEnabledByServer || !pushPublicKey) {
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Push通知はサーバー側で未設定です。");
    return;
  }

  const existing = await swRegistration.pushManager.getSubscription();
  if (existing) {
    try {
      await syncPushSubscription(existing);
    } catch (_) {}
    setPushButtonState({ subscribed: true, disabled: false });
    setPushStatus(`Push通知は有効です。毎日 ${pushNotifyTimeJst} (JST) に通知します。`);
  } else {
    setPushButtonState({ subscribed: false, disabled: false });
    setPushStatus(`Push通知を有効化すると、毎日 ${pushNotifyTimeJst} (JST) に通知します。`);
  }
}

document.getElementById("reloadButton").addEventListener("click", () => {
  loadDashboard().catch((err) => {
    console.error(err);
    alert(err.message || "ダッシュボードの更新に失敗しました。");
  });
});

document.getElementById("daysSelect").addEventListener("change", () => {
  loadDashboard().catch((err) => {
    console.error(err);
    alert(err.message || "ダッシュボードの更新に失敗しました。");
  });
});

document.getElementById("calcButton").addEventListener("click", () => {
  calculatePurityPrice().catch((err) => {
    console.error(err);
    document.getElementById("calcMeta").textContent = err.message || "純度計算でエラーが発生しました。";
  });
});

document.getElementById("pushButton").addEventListener("click", async () => {
  const button = document.getElementById("pushButton");
  if (!pushEnabledByServer) {
    setPushStatus("Push通知はサーバー側で未設定です。");
    return;
  }

  button.disabled = true;
  try {
    if (button.dataset.subscribed === "true") {
      await disablePushNotifications();
    } else {
      await enablePushNotifications();
    }
  } catch (err) {
    console.error(err);
    setPushStatus(err.message || "Push通知設定でエラーが発生しました。");
  } finally {
    button.disabled = !pushEnabledByServer;
  }
});

window.addEventListener("resize", () => {
  const mode = isMobileChartViewport();
  if (lastChartMobileMode === null) {
    lastChartMobileMode = mode;
    return;
  }
  if (mode !== lastChartMobileMode) {
    lastChartMobileMode = mode;
    renderDashboardFromPayload(latestHistoryPayload);
  }
});

loadDashboard().catch((err) => {
  console.error(err);
  alert(err.message || "初期ロードに失敗しました。");
});

loadPurityOptions()
  .then(() => calculatePurityPrice())
  .catch((err) => {
    console.error(err);
    document.getElementById("calcMeta").textContent = err.message || "純度計算の初期化に失敗しました。";
  });

initializePwaAndPush().catch((err) => {
  console.error(err);
  setPushStatus(err.message || "PWA初期化に失敗しました。");
});
