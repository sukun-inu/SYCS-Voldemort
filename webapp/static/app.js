const METALS = {
  gold: {
    label: "金 (Gold)",
    borderColor: "#D49A00",
    fillColor: "rgba(212,154,0,0.20)",
    deltaColor: "rgba(212,154,0,0.45)",
    canvasId: "goldChart",
  },
  silver: {
    label: "銀 (Silver)",
    borderColor: "#6F7D89",
    fillColor: "rgba(111,125,137,0.20)",
    deltaColor: "rgba(111,125,137,0.45)",
    canvasId: "silverChart",
  },
  platinum: {
    label: "プラチナ (Platinum)",
    borderColor: "#0F7D8B",
    fillColor: "rgba(15,125,139,0.20)",
    deltaColor: "rgba(15,125,139,0.45)",
    canvasId: "platinumChart",
  },
};

const charts = {};
let purityOptions = {};
let swRegistration = null;
let pushEnabledByServer = false;
let pushPublicKey = null;
let pushNotifyTimeJst = "11:00";

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replaceAll("-", "+").replaceAll("_", "/");
  const rawData = atob(base64);
  return Uint8Array.from(rawData.split("").map((char) => char.charCodeAt(0)));
}

function setPushStatus(message) {
  const status = document.getElementById("pushStatus");
  status.textContent = message;
}

function setPushButtonState({ subscribed, disabled }) {
  const button = document.getElementById("pushButton");
  button.dataset.subscribed = subscribed ? "true" : "false";
  button.disabled = !!disabled;
  button.textContent = subscribed ? "Push通知を無効化" : "Push通知を有効化";
}

async function syncPushSubscription(subscription) {
  const response = await fetch("/api/push/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(subscription.toJSON()),
  });
  if (!response.ok) {
    throw new Error("Push購読情報の保存に失敗しました。");
  }
}

async function removePushSubscription(subscription) {
  const response = await fetch("/api/push/unsubscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoint: subscription.endpoint }),
  });
  if (!response.ok) {
    throw new Error("Push購読解除情報の保存に失敗しました。");
  }
}

async function enablePushNotifications() {
  if (!swRegistration || !pushPublicKey) {
    throw new Error("Push通知は現在利用できません。");
  }

  if (Notification.permission === "denied") {
    throw new Error("通知権限がブラウザ設定で拒否されています。");
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
    } catch (_) {
      // サーバーの削除失敗でもブラウザ側解除は継続する。
    }
    await subscription.unsubscribe();
  }
  setPushButtonState({ subscribed: false, disabled: false });
  setPushStatus("Push通知を無効化しました。");
}

async function initializePwaAndPush() {
  if (!("serviceWorker" in navigator)) {
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("このブラウザはService Worker未対応です。");
    return;
  }

  try {
    swRegistration = await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
  } catch (error) {
    console.error(error);
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Service Workerの登録に失敗しました。");
    return;
  }

  try {
    const response = await fetch("/api/push/public-key");
    if (!response.ok) {
      throw new Error("Push設定の取得に失敗しました。");
    }
    const payload = await response.json();
    pushEnabledByServer = !!payload.enabled;
    pushPublicKey = payload.public_key || null;
    pushNotifyTimeJst = payload.notify_time_jst || "11:00";
  } catch (error) {
    console.error(error);
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Push設定の取得に失敗しました。");
    return;
  }

  if (!("PushManager" in window) || !pushEnabledByServer || !pushPublicKey) {
    setPushButtonState({ subscribed: false, disabled: true });
    setPushStatus("Push通知は現在無効です。");
    return;
  }

  const existing = await swRegistration.pushManager.getSubscription();
  if (existing) {
    try {
      await syncPushSubscription(existing);
    } catch (_) {
      // 既存購読の再同期に失敗してもUIは継続する。
    }
    setPushButtonState({ subscribed: true, disabled: false });
    setPushStatus(`Push通知は有効です。毎日 ${pushNotifyTimeJst} (JST) に通知します。`);
  } else {
    setPushButtonState({ subscribed: false, disabled: false });
    setPushStatus(`Push通知を有効化すると、毎日 ${pushNotifyTimeJst} (JST) に通知します。`);
  }
}

function formatYen(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value) + " 円/g";
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

function formatYenInt(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return new Intl.NumberFormat("ja-JP").format(value) + " 円";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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
  const root = document.getElementById("calcResult");
  const rows = Object.entries(payload.by_purity || {});
  const items = rows
    .map(
      ([grade, value]) =>
        `<tr><td>${escapeHtml(grade)}</td><td>${formatYenInt(value)}</td></tr>`
    )
    .join("");

  root.innerHTML = `
    <table class="calc-table">
      <thead>
        <tr><th>純度</th><th>価格</th></tr>
      </thead>
      <tbody>
        <tr><td>純金属換算</td><td>${formatYenInt(payload.pure_value)}</td></tr>
        ${items}
      </tbody>
    </table>
  `;
}

async function loadPurityOptions() {
  const response = await fetch("/api/purity/options");
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
  const response = await fetch(`/api/prices/calculate?${query.toString()}`);
  if (!response.ok) {
    let message = "純度計算に失敗しました。";
    try {
      const errorPayload = await response.json();
      if (errorPayload.detail) {
        message = String(errorPayload.detail);
      }
    } catch (_) {
      // ignore
    }
    throw new Error(message);
  }

  const payload = await response.json();
  meta.textContent = `基準価格日: ${payload.snapshot_date} / 単価: ${formatYen(payload.price_per_gram)} / グラム: ${payload.grams}g`;
  renderPurityResult(payload);
}

function renderMetalChart(metalKey, history, dailyAxis) {
  const meta = METALS[metalKey];
  if (!meta) {
    return;
  }

  const dailyMap = new Map(history.map((item) => [item.date, item]));
  const labels = dailyAxis.map((date) => formatDailyLabel(date));
  const prices = dailyAxis.map((date) => dailyMap.get(date)?.price_per_gram ?? null);
  const deltas = dailyAxis.map((date) => dailyMap.get(date)?.delta_from_previous ?? null);
  const tickStep = Math.max(1, Math.ceil(dailyAxis.length / 10));
  const context = document.getElementById(meta.canvasId).getContext("2d");

  if (charts[metalKey]) {
    charts[metalKey].destroy();
  }

  charts[metalKey] = new Chart(context, {
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
      responsive: true,
      maintainAspectRatio: false,
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
            autoSkip: false,
            callback: (_, index) => {
              if (index % tickStep === 0 || index === labels.length - 1) {
                return labels[index];
              }
              return "";
            },
          },
        },
      },
      plugins: {
        tooltip: {
          callbacks: {
            title: (items) => {
              if (!items.length) {
                return "";
              }
              return dailyAxis[items[0].dataIndex];
            },
          },
        },
        legend: {
          labels: {
            boxWidth: 10,
          },
        },
      },
    },
  });
}

async function loadDashboard() {
  const days = Number(document.getElementById("daysSelect").value || 365);
  const response = await fetch(`/api/prices/history?days=${days}`);
  if (!response.ok) {
    throw new Error("データ取得に失敗しました。");
  }
  const payload = await response.json();
  const dailyAxis = enumerateDailyAxis(payload.range_start, payload.range_end);

  document.getElementById("generatedAt").textContent =
    `更新頻度: 1日1回 (JST 00:00) / 表示期間: ${payload.range_start} - ${payload.range_end}`;
  buildSummary(payload.latest || {});

  Object.keys(METALS).forEach((key) => {
    renderMetalChart(key, payload.metals?.[key] || [], dailyAxis);
  });
}

document.getElementById("calcButton").addEventListener("click", () => {
  calculatePurityPrice().catch((err) => {
    console.error(err);
    document.getElementById("calcMeta").textContent = err.message || "純度計算でエラーが発生しました。";
  });
});

document.getElementById("pushButton").addEventListener("click", async () => {
  const button = document.getElementById("pushButton");
  if (!pushEnabledByServer) {
    setPushStatus("Push通知は現在無効です。");
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

document.getElementById("reloadButton").addEventListener("click", () => {
  loadDashboard().catch((err) => {
    console.error(err);
    alert("データの読み込みでエラーが発生しました。");
  });
});

document.getElementById("daysSelect").addEventListener("change", () => {
  loadDashboard().catch((err) => {
    console.error(err);
    alert("データの読み込みでエラーが発生しました。");
  });
});

loadDashboard().catch((err) => {
  console.error(err);
  alert("初期読み込みでエラーが発生しました。");
});

loadPurityOptions()
  .then(() => calculatePurityPrice())
  .catch((err) => {
    console.error(err);
    document.getElementById("calcMeta").textContent = err.message || "純度計算の初期化でエラーが発生しました。";
  });

initializePwaAndPush().catch((err) => {
  console.error(err);
  setPushStatus("PWA初期化でエラーが発生しました。");
});
