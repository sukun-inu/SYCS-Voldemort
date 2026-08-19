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
let latestForecastPayload = null;
let lastChartMobileMode = null;
let lastForecastGeneratedAt = null;
let forecastRefreshTimerId = null;
let forecastRefreshInFlight = false;

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
const SW_SCRIPT_VERSION = "20260310-2";
const FORECAST_AUTO_REFRESH_INTERVAL_MS = 5 * 60 * 1000;

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

function formatPercent(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "-";
  }
  const sign = value > 0 ? "+" : "";
  return `${sign}${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: digits }).format(value)}%`;
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

function loadingInlineMarkup(text) {
  return `<span class="d-inline-flex align-items-center gap-2"><span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>${escapeHtml(text)}</span>`;
}

function setMarketView(view) {
  const summaryButton = document.getElementById("marketViewSummary");
  const forecastButton = document.getElementById("marketViewForecast");
  const summaryPane = document.getElementById("marketPaneSummary");
  const forecastPane = document.getElementById("marketPaneForecast");
  if (!summaryButton || !forecastButton || !summaryPane || !forecastPane) {
    return;
  }

  const normalizedView = view === "forecast" ? "forecast" : "summary";
  const isSummary = normalizedView === "summary";
  summaryButton.classList.toggle("is-active", isSummary);
  forecastButton.classList.toggle("is-active", !isSummary);
  summaryButton.setAttribute("aria-selected", isSummary ? "true" : "false");
  forecastButton.setAttribute("aria-selected", isSummary ? "false" : "true");
  summaryButton.setAttribute("tabindex", isSummary ? "0" : "-1");
  forecastButton.setAttribute("tabindex", isSummary ? "-1" : "0");
  summaryPane.hidden = !isSummary;
  forecastPane.hidden = isSummary;
}

function initializeMarketToggle() {
  const buttons = document.querySelectorAll(".market-toggle-button[data-market-view]");
  if (!buttons.length) {
    return;
  }

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      setMarketView(button.dataset.marketView);
    });
    button.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
        return;
      }
      event.preventDefault();
      const nextView = event.key === "ArrowRight" ? "forecast" : "summary";
      setMarketView(nextView);
      document.querySelector(`.market-toggle-button[data-market-view="${nextView}"]`)?.focus();
    });
  });

  setMarketView("summary");
}

function compareIsoDate(a, b) {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function renderSummarySkeleton() {
  const root = document.getElementById("summaryCards");
  if (!root) {
    return;
  }
  root.setAttribute("aria-busy", "true");
  root.innerHTML = "";
  Object.keys(METALS).forEach(() => {
    const col = document.createElement("div");
    col.className = "col-md-4";
    col.innerHTML = `
      <article class="card summary-card h-100 shadow-sm placeholder-glow">
        <div class="card-body">
          <span class="placeholder col-6 mb-2"></span>
          <div class="placeholder col-8" style="height:1.5rem;"></div>
          <span class="placeholder col-5 mt-2"></span>
          <span class="placeholder col-7 mt-2"></span>
        </div>
      </article>
    `;
    root.appendChild(col);
  });
}

function renderForecastSkeleton() {
  const root = document.getElementById("forecastCards");
  if (!root) {
    return;
  }
  root.setAttribute("aria-busy", "true");
  root.innerHTML = "";
  Object.keys(METALS).forEach(() => {
    const col = document.createElement("div");
    col.className = "col-md-4";
    col.innerHTML = `
      <article class="card summary-card h-100 shadow-sm placeholder-glow">
        <div class="card-body">
          <span class="placeholder col-6 mb-2"></span>
          <div class="placeholder col-8" style="height:1.5rem;"></div>
          <span class="placeholder col-5 mt-2"></span>
          <span class="placeholder col-7 mt-2"></span>
          <span class="placeholder col-9 mt-2"></span>
        </div>
      </article>
    `;
    root.appendChild(col);
  });
}

function setChartLoadingState(isLoading) {
  Object.values(METALS).forEach(({ canvasId }) => {
    const canvas = document.getElementById(canvasId);
    const card = canvas?.closest(".chart-card");
    if (!card) {
      return;
    }
    card.classList.toggle("is-loading", !!isLoading);
    card.setAttribute("aria-busy", isLoading ? "true" : "false");
  });
}

function setForecastLoadingState() {
  const meta = document.getElementById("forecastMeta");
  if (meta) {
    meta.innerHTML = loadingInlineMarkup("予測データを読み込み中...");
  }
  renderForecastSkeleton();
  const source = document.getElementById("forecastSource");
  if (source) {
    source.innerHTML = loadingInlineMarkup("予想ソースを取得中...");
  }
}

function setDashboardLoadingState() {
  const generated = document.getElementById("generatedAt");
  if (generated) {
    generated.innerHTML = loadingInlineMarkup("価格データを読み込み中...");
  }
  renderSummarySkeleton();
  setForecastLoadingState();
  setChartLoadingState(true);
}

function setCalcLoadingState() {
  const meta = document.getElementById("calcMeta");
  const result = document.getElementById("calcResult");
  if (meta) {
    meta.innerHTML = loadingInlineMarkup("純度計算データを読み込み中...");
  }
  if (result) {
    result.setAttribute("aria-busy", "true");
    result.innerHTML =
      '<div class="d-inline-flex align-items-center gap-2 text-muted small"><span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>計算中...</div>';
  }
}

function buildSummary(latest) {
  const root = document.getElementById("summaryCards");
  root.innerHTML = "";
  root.setAttribute("aria-busy", "false");
  Object.entries(METALS).forEach(([key, meta]) => {
    const data = latest[key] || {};
    const delta = data.delta_from_previous;
    const deltaClass = delta > 0 ? "text-success" : delta < 0 ? "text-danger" : "text-muted";
    const deltaIcon = delta > 0 ? "bi-arrow-up-short" : delta < 0 ? "bi-arrow-down-short" : "bi-dash";
    const col = document.createElement("div");
    col.className = "col-md-4";
    col.innerHTML = `
      <article class="card summary-card h-100 shadow-sm" data-metal="${key}">
        <div class="card-body">
          <h3 class="summary-card-title">${meta.label}</h3>
          <div class="summary-price">${formatYen(data.price_per_gram)}</div>
          <div class="summary-delta ${deltaClass}"><i class="bi ${deltaIcon}"></i>前日差: ${formatDelta(delta)}</div>
          <div class="text-muted small mt-2">基準日: ${data.date || "-"}</div>
        </div>
      </article>
    `;
    root.appendChild(col);
  });
}

function setForecastError(message) {
  const meta = document.getElementById("forecastMeta");
  const root = document.getElementById("forecastCards");
  if (meta) {
    meta.textContent = message;
  }
  if (root) {
    root.setAttribute("aria-busy", "false");
    root.innerHTML = "";
  }
  const source = document.getElementById("forecastSource");
  if (source) {
    source.textContent = "予想ソース: 取得に失敗しました";
  }
}

function updateForecastSourceFooter(payload) {
  const source = document.getElementById("forecastSource");
  if (!source) {
    return;
  }
  const usdSource = payload?.signals?.usd_jpy?.source || "Stooq";
  const newsSource = payload?.signals?.news?.source || "Google News RSS";
  const llm = payload?.signals?.llm || {};
  const llmLabel = llm?.available
    ? `・AI判定(${llm.model || "gpt-4.1-mini"})`
    : "";
  const asOfDate = payload?.as_of_date || "-";
  source.textContent = `予想ソース: USD/JPY(${usdSource})・ニュース(${newsSource})${llmLabel} / 基準日: ${asOfDate}`;
}

function renderWeeklyForecast(payload) {
  const root = document.getElementById("forecastCards");
  const meta = document.getElementById("forecastMeta");
  if (!root || !meta) {
    return;
  }

  root.setAttribute("aria-busy", "false");
  const usdJpy = payload?.signals?.usd_jpy || {};
  const horizonDays = Number(payload?.horizon_days || 7);
  const generatedAt = payload?.generated_at || "-";
  const fxText = usdJpy.available
    ? `USD/JPY 週次: ${formatPercent(Number(usdJpy.weekly_change_pct || 0), 3)}`
    : "USD/JPY: 取得失敗";
  meta.textContent = `生成時刻: ${generatedAt} / 予測期間: ${horizonDays}日 / ${fxText}`;
  updateForecastSourceFooter(payload);

  root.innerHTML = "";
  Object.entries(METALS).forEach(([key, metal]) => {
    const item = payload?.forecast?.[key];
    if (!item) {
      return;
    }
    const changePct = Number(item.projected_change_pct_7d || 0);
    const deltaClass = changePct > 0 ? "text-success" : changePct < 0 ? "text-danger" : "text-muted";
    const deltaIcon = changePct > 0 ? "bi-arrow-up-short" : changePct < 0 ? "bi-arrow-down-short" : "bi-dash";
    const confidencePct = Number(item.confidence || 0) * 100;
    const drivers = Array.isArray(item.drivers) ? item.drivers.slice(0, 2) : [];

    const col = document.createElement("div");
    col.className = "col-md-4";
    col.innerHTML = `
      <article class="card summary-card h-100 shadow-sm" data-metal="${key}">
        <div class="card-body">
          <h3 class="summary-card-title">${metal.label} / 7日予測</h3>
          <div class="summary-price">${formatYen(item.projected_price_per_gram)}</div>
          <div class="summary-delta ${deltaClass}"><i class="bi ${deltaIcon}"></i>予測変化: ${formatPercent(changePct, 3)}</div>
          <div class="text-muted small mt-2">信頼度: ${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 1 }).format(confidencePct)}%</div>
          <div class="forecast-driver">${drivers.map((line) => escapeHtml(line)).join("<br>")}</div>
        </div>
      </article>
    `;
    root.appendChild(col);
  });
}

async function loadWeeklyForecast() {
  const response = await fetch(appUrl("api/prices/forecast-weekly?days=7"));
  if (!response.ok) {
    let message = "1週間予測データの取得に失敗しました。";
    try {
      const payload = await response.json();
      if (payload?.detail) {
        message = String(payload.detail);
      }
    } catch (_) {}
    throw new Error(message);
  }
  return await response.json();
}

async function refreshForecastSnapshot({ forceApply = false } = {}) {
  if (forecastRefreshInFlight || !latestHistoryPayload) {
    return;
  }
  forecastRefreshInFlight = true;
  try {
    const forecastPayload = await loadWeeklyForecast();
    const generatedAt = String(forecastPayload?.generated_at || "");
    const hasChanged = forceApply || !latestForecastPayload || generatedAt !== lastForecastGeneratedAt;
    latestForecastPayload = forecastPayload;
    lastForecastGeneratedAt = generatedAt;
    if (hasChanged) {
      renderWeeklyForecast(forecastPayload);
      renderDashboardFromPayload(latestHistoryPayload, forecastPayload);
    }
  } catch (error) {
    console.error(error);
  } finally {
    forecastRefreshInFlight = false;
  }
}

function startForecastAutoRefresh() {
  if (forecastRefreshTimerId !== null) {
    window.clearInterval(forecastRefreshTimerId);
  }
  forecastRefreshTimerId = window.setInterval(() => {
    if (document.visibilityState !== "visible") {
      return;
    }
    refreshForecastSnapshot().catch((error) => {
      console.error(error);
    });
  }, FORECAST_AUTO_REFRESH_INTERVAL_MS);
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
    <div class="table-responsive">
      <table class="table table-striped table-hover align-middle mb-0">
        <thead>
          <tr><th>純度</th><th>価格</th></tr>
        </thead>
        <tbody>
          <tr><td>純金属換算</td><td>${formatYenInt(payload.pure_value)}</td></tr>
          ${rows}
        </tbody>
      </table>
    </div>
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

// APIの `detail` はサーバーの実装次第で「文字列」または「バリデーションエラーのオブジェクト配列」
// (FastAPI/Pydanticが自動生成する形式) のどちらかになり得る。無条件に String() 化すると
// 配列の場合に "[object Object]" のような表示になってしまうため、形に応じて安全に取り出す。
function extractErrorMessage(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const first = detail[0];
    if (first && typeof first === "object" && typeof first.msg === "string") {
      return first.msg;
    }
    return "";
  }
  if (typeof detail === "object" && typeof detail.msg === "string") {
    return detail.msg;
  }
  return "";
}

async function calculatePurityPrice() {
  const metal = document.getElementById("calcMetal").value;
  const grams = Number(document.getElementById("calcGrams").value);
  const meta = document.getElementById("calcMeta");
  const result = document.getElementById("calcResult");
  if (!metal || Number.isNaN(grams) || grams <= 0) {
    meta.textContent = "グラムは 0 より大きい値を入力してください。";
    return;
  }

  setCalcLoadingState();
  const query = new URLSearchParams({ metal, grams: String(grams) });
  const response = await fetch(`${appUrl("api/prices/calculate")}?${query.toString()}`);
  if (!response.ok) {
    let message = "純度計算に失敗しました。";
    try {
      const errorPayload = await response.json();
      message = extractErrorMessage(errorPayload.detail) || message;
    } catch (_) {}
    throw new Error(message);
  }

  const payload = await response.json();
  result?.setAttribute("aria-busy", "false");
  meta.textContent = `基準価格日: ${payload.snapshot_date} / 単価: ${formatYen(payload.price_per_gram)} / グラム: ${payload.grams}g`;
  renderPurityResult(payload);
}

function renderMetalChart(metalKey, history, dailyAxis, forecastItem = null, historyEndDate = null) {
  const meta = METALS[metalKey];
  if (!meta || !window.Chart) {
    return;
  }

  const dailyMap = new Map(history.map((item) => [item.date, item]));
  const labels = dailyAxis.map((date) => formatDailyLabel(date));
  const prices = dailyAxis.map((date) => dailyMap.get(date)?.price_per_gram ?? null);
  const deltas = dailyAxis.map((date) => dailyMap.get(date)?.delta_from_previous ?? null);
  const forecastMap = new Map(
    Array.isArray(forecastItem?.daily)
      ? forecastItem.daily.map((item) => [item.date, item.price_per_gram])
      : []
  );
  const forecastPrices = dailyAxis.map(() => null);
  const anchorDate = historyEndDate || (history.length ? history[history.length - 1].date : null);
  const anchorIndex = anchorDate ? dailyAxis.indexOf(anchorDate) : -1;
  if (anchorIndex >= 0 && prices[anchorIndex] !== null && prices[anchorIndex] !== undefined && forecastMap.size > 0) {
    forecastPrices[anchorIndex] = prices[anchorIndex];
  }
  dailyAxis.forEach((date, index) => {
    const value = forecastMap.get(date);
    if (value !== undefined) {
      forecastPrices[index] = value;
    }
  });
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
    if (existing.data.datasets?.[2]) {
      existing.data.datasets[2].data = forecastPrices;
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
        {
          label: "7日予測 (円/g)",
          data: forecastPrices,
          borderColor: meta.borderColor,
          backgroundColor: "transparent",
          borderDash: [6, 5],
          borderWidth: 2,
          tension: 0,
          spanGaps: false,
          fill: false,
          pointRadius: 1.5,
          pointHoverRadius: 3,
          yAxisID: "yPrice",
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
  setDashboardLoadingState();
  try {
    await ensureChartLibrary();
    const days = Number(document.getElementById("daysSelect").value || 30);
    const response = await fetch(`${appUrl("api/prices/history")}?days=${days}`);
    if (!response.ok) {
      throw new Error("データ取得に失敗しました。");
    }

    const payload = await response.json();
    latestHistoryPayload = payload;
    renderDashboardFromPayload(payload, null);
    setChartLoadingState(false);

    try {
      const forecastPayload = await loadWeeklyForecast();
      latestForecastPayload = forecastPayload;
      lastForecastGeneratedAt = String(forecastPayload?.generated_at || "");
      renderWeeklyForecast(forecastPayload);
      renderDashboardFromPayload(payload, forecastPayload);
    } catch (error) {
      console.error(error);
      latestForecastPayload = null;
      lastForecastGeneratedAt = null;
      setForecastError(error.message || "1週間予測の取得に失敗しました。");
    }
  } finally {
    setChartLoadingState(false);
  }
}

function renderDashboardFromPayload(payload, forecastPayload = latestForecastPayload) {
  if (!payload) {
    return;
  }
  lastChartMobileMode = isMobileChartViewport();
  let axisEnd = payload.range_end;
  if (forecastPayload?.forecast) {
    Object.keys(METALS).forEach((metalKey) => {
      const daily = forecastPayload.forecast?.[metalKey]?.daily;
      if (!Array.isArray(daily) || daily.length === 0) {
        return;
      }
      const lastDate = daily[daily.length - 1]?.date;
      if (lastDate && compareIsoDate(lastDate, axisEnd) > 0) {
        axisEnd = lastDate;
      }
    });
  }
  const dailyAxis = enumerateDailyAxis(payload.range_start, axisEnd);
  document.getElementById("generatedAt").textContent =
    `更新頻度: 1日1回 (JST 00:00) / 表示期間: ${payload.range_start} - ${payload.range_end}`;
  buildSummary(payload.latest || {});

  Object.keys(METALS).forEach((key) => {
    renderMetalChart(
      key,
      payload.metals?.[key] || [],
      dailyAxis,
      forecastPayload?.forecast?.[key] || null,
      payload.range_end
    );
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
    swRegistration = await navigator.serviceWorker.register(
      appUrl(`sw.js?v=${SW_SCRIPT_VERSION}`),
      { scope: appScopePath() }
    );
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
    document.getElementById("calcResult").setAttribute("aria-busy", "false");
    document.getElementById("calcResult").innerHTML = "";
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
    renderDashboardFromPayload(latestHistoryPayload, latestForecastPayload);
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    refreshForecastSnapshot().catch((error) => {
      console.error(error);
    });
  }
});

initializeMarketToggle();
startForecastAutoRefresh();

loadDashboard().catch((err) => {
  console.error(err);
  alert(err.message || "初期ロードに失敗しました。");
});

setCalcLoadingState();
loadPurityOptions()
  .then(() => calculatePurityPrice())
  .catch((err) => {
    console.error(err);
    document.getElementById("calcMeta").textContent = err.message || "純度計算の初期化に失敗しました。";
    document.getElementById("calcResult").setAttribute("aria-busy", "false");
    document.getElementById("calcResult").innerHTML = "";
  });

initializePwaAndPush().catch((err) => {
  console.error(err);
  setPushStatus(err.message || "PWA初期化に失敗しました。");
});
