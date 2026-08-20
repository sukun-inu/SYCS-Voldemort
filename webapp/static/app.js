const CURRENT_URL = new URL(window.location.href);
const APP_BASE = new URL(
  CURRENT_URL.pathname.endsWith("/") ? CURRENT_URL.pathname : `${CURRENT_URL.pathname}/`,
  CURRENT_URL.origin
);

const METALS = {
  gold: {
    label: "金 (Gold)",
    icon: "bi-coin",
    lineColor: "#B28704",
    fillColor: "rgba(178,135,4,0.18)",
    containerId: "goldChart",
  },
  silver: {
    label: "銀 (Silver)",
    icon: "bi-award",
    lineColor: "#5D6A75",
    fillColor: "rgba(93,106,117,0.18)",
    containerId: "silverChart",
  },
  platinum: {
    label: "プラチナ (Platinum)",
    icon: "bi-gem",
    lineColor: "#0A7D88",
    fillColor: "rgba(10,125,136,0.18)",
    containerId: "platinumChart",
  },
};

// metalKeyごとに { chart, priceSeries, deltaSeries, forecastSeries, maSeries, forecastBoundary } を保持する。
const charts = {};
let purityOptions = {};
let swRegistration = null;
let pushEnabledByServer = false;
let pushPublicKey = null;
let pushNotifyTimeJst = "11:00";
let latestHistoryPayload = null;
let latestForecastPayload = null;
let lastForecastGeneratedAt = null;
let forecastRefreshTimerId = null;
let forecastRefreshInFlight = false;
let currentMarketView = "summary";

// 外部CDNへは依存せず、自ホストにバンドルしたLightweight Chartsのみを読み込む
// (CSPをdefault-src 'self'寄りに保つため)。
const CHART_CDN_LIST = [
  "static/vendor/lightweight-charts/lightweight-charts.standalone.production.js?v=5.2.1",
];
const SW_SCRIPT_VERSION = "20260820-12";
const FORECAST_AUTO_REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const THEME_STORAGE_KEY = "metalDailyTheme";
const DAYS_RANGE_STORAGE_KEY = "metalDailyDaysRange";

function appUrl(path) {
  return new URL(path.replace(/^\/+/, ""), APP_BASE).toString();
}

function appScopePath() {
  return new URL("./", APP_BASE).pathname;
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
  if (window.LightweightCharts) {
    return;
  }

  let lastError = null;
  for (const src of CHART_CDN_LIST) {
    try {
      await loadExternalScript(src);
      if (window.LightweightCharts) {
        return;
      }
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Lightweight Chartsの読み込みに失敗しました。");
}

function formatYen(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return `${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value)} 円/g`;
}

function formatYenPlain(value) {
  // レンジ表示で「◯◯ 〜 ◯◯ 円/g」と繋げるため、単位を付けない数値だけを返す。
  if (value === null || value === undefined) {
    return "-";
  }
  return new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value);
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

const JST_DATETIME_FORMATTER = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

function formatJstDateTime(isoString) {
  if (!isoString) {
    return "-";
  }
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return JST_DATETIME_FORMATTER.format(date);
}

const JST_DATE_PARTS_FORMATTER = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Asia/Tokyo",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

function todayJstIso() {
  // en-CAロケールはYYYY-MM-DD形式を返すため、そのままISO日付として使える。
  return JST_DATE_PARTS_FORMATTER.format(new Date());
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
  if (!summaryButton || !forecastButton) {
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

  currentMarketView = normalizedView;
  const meta = document.getElementById("forecastMeta");
  if (meta) {
    meta.hidden = isSummary;
  }
  updateMarketWidgets();

  // 7日予測線は「最新価格」表示中はノイズになるため、予測モードの時だけ出す。
  Object.values(charts).forEach((entry) => {
    if (!entry?.forecastSeries) {
      return;
    }
    entry.forecastSeries.applyOptions({ visible: !isSummary });
    // 赤い境界線も予測線と同じ表示状態に揃える。最新価格表示では実績だけを見せるため、
    // 境界ラベルも残さない。
    entry.forecastBoundary?.setBoundary(
      entry.forecastStartDate,
      !isSummary,
      entry.forecastAnchorDate
    );
    entry.forecastBand?.setBand(entry.forecastBandPoints, !isSummary);
  });
}

function getStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (_) {
    return null;
  }
}

function setStoredTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (_) {}
}

function getPreferredTheme() {
  const stored = getStoredTheme();
  if (stored === "light" || stored === "dark") {
    return stored;
  }
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

// Chart.jsはCSSを見てくれないため、テーマ切り替え時は軸・凡例の色をJS側で明示的に渡し直す。
function getChartThemeColors() {
  const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
  return {
    text: isDark ? "#98a2b3" : "#5c6b7a",
    grid: isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)",
    background: isDark ? "#1e222a" : "#ffffff",
    crosshair: isDark ? "#5c6b7a" : "#9aa4b5",
  };
}

function applyChartsTheme() {
  const colors = getChartThemeColors();
  Object.values(charts).forEach((entry) => {
    if (!entry?.chart) {
      return;
    }
    entry.chart.applyOptions({
      layout: {
        textColor: colors.text,
        background: { type: "solid", color: colors.background },
      },
      grid: {
        vertLines: { color: colors.grid },
        horzLines: { color: colors.grid },
      },
      crosshair: {
        vertLine: { color: colors.crosshair },
        horzLine: { color: colors.crosshair },
      },
    });
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-bs-theme", theme);
  const toggle = document.getElementById("themeToggle");
  if (toggle) {
    const icon = toggle.querySelector("i");
    if (icon) {
      icon.className = theme === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
    }
    toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
  }
  applyChartsTheme();
}

function initializeThemeToggle() {
  applyTheme(getPreferredTheme());

  const toggle = document.getElementById("themeToggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      setStoredTheme(next);
      applyTheme(next);
    });
  }

  // ユーザーが一度も手動切り替えしていない間だけ、OS側のテーマ変更に追従する。
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (event) => {
      if (!getStoredTheme()) {
        applyTheme(event.matches ? "dark" : "light");
      }
    });
  }
}

function initializeChartTools() {
  document.querySelectorAll(".chart-ma-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = charts[button.dataset.chart];
      if (!entry?.maSeries) {
        return;
      }
      const nextVisible = !entry.maSeries.options().visible;
      entry.maSeries.applyOptions({ visible: nextVisible });
      button.classList.toggle("active", nextVisible);
      button.setAttribute("aria-pressed", nextVisible ? "true" : "false");
    });
  });

  document.querySelectorAll(".chart-delta-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = charts[button.dataset.chart];
      if (!entry?.deltaSeries) {
        return;
      }
      const nextVisible = !entry.deltaSeries.options().visible;
      entry.deltaSeries.applyOptions({ visible: nextVisible });
      button.classList.toggle("active", nextVisible);
      button.setAttribute("aria-pressed", nextVisible ? "true" : "false");
    });
  });

  document.querySelectorAll(".chart-zoom-reset").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = charts[button.dataset.chart];
      if (entry?.chart) {
        entry.chart.timeScale().fitContent();
      }
    });
  });
}

// 「別ウィンドウで最大化」の代わりに、同一ページ内のフルスクリーンモーダルへ
// .chart-block(チャート本体+統計バー)そのものをDOM移動する方式にしている。
// Lightweight Chartsのインスタンスを再生成しないため、ズーム位置・Δ/MA7の表示状態・
// 予測開始の境界線などがすべてそのまま維持される。autoSize:trueのResizeObserverが
// コンテナのサイズ変化を検知して自動で拡縮するので、明示的なresize呼び出しも不要。
let maximizedChartState = null; // { metalKey, parent, nextSibling } | null

function restoreMaximizedChartBlock() {
  if (!maximizedChartState) {
    return;
  }
  const { parent, nextSibling } = maximizedChartState;
  const slot = document.getElementById("chartMaximizeSlot");
  const block = slot?.firstElementChild || null;
  maximizedChartState = null;
  if (block && parent) {
    parent.insertBefore(block, nextSibling || null);
  }
}

function openChartMaximize(metalKey) {
  const meta = METALS[metalKey];
  const block = document.querySelector(`.chart-block[data-chart-block="${metalKey}"]`);
  const modalEl = document.getElementById("chartMaximizeModal");
  const slot = document.getElementById("chartMaximizeSlot");
  if (!meta || !block || !modalEl || !slot || typeof bootstrap === "undefined") {
    return;
  }

  // 通常はモーダルを閉じてからでないと次を開けないが、念のため先に元へ戻しておく。
  restoreMaximizedChartBlock();

  maximizedChartState = {
    metalKey,
    parent: block.parentElement,
    nextSibling: block.nextElementSibling,
  };
  slot.append(block);

  const titleEl = document.getElementById("chartMaximizeModalTitle");
  const iconEl = document.getElementById("chartMaximizeModalIcon");
  if (titleEl) {
    titleEl.textContent = meta.label;
  }
  if (iconEl) {
    iconEl.className = `bi ${meta.icon || "bi-graph-up"}`;
  }

  bootstrap.Modal.getOrCreateInstance(modalEl).show();
}

function initializeChartMaximize() {
  document.querySelectorAll(".chart-maximize-btn").forEach((button) => {
    button.addEventListener("click", () => openChartMaximize(button.dataset.chart));
  });

  // モーダルを閉じた瞬間(バックドロップクリック・ESC・×ボタンいずれも同じイベント)に
  // 元の位置へ戻す。開いている間にウィンドウが閉じられる操作は無いため、この1箇所で十分。
  const modalEl = document.getElementById("chartMaximizeModal");
  if (modalEl) {
    modalEl.addEventListener("hidden.bs.modal", restoreMaximizedChartBlock);
  }
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

  setMarketView("forecast");
}

function compareIsoDate(a, b) {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function setChartLoadingState(isLoading) {
  Object.values(METALS).forEach(({ containerId }) => {
    const container = document.getElementById(containerId);
    const card = container?.closest(".market-widget");
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

function buildTicker(latest) {
  const track = document.getElementById("priceTickerTrack");
  if (!track) {
    return;
  }
  const itemsHtml = Object.entries(METALS)
    .map(([key, meta]) => {
      const data = latest[key] || {};
      const delta = data.delta_from_previous;
      const deltaClass = delta > 0 ? "is-up" : delta < 0 ? "is-down" : "is-flat";
      const deltaIcon = delta > 0 ? "bi-caret-up-fill" : delta < 0 ? "bi-caret-down-fill" : "bi-dash";
      return `
        <span class="price-ticker-item" data-metal="${key}">
          <i class="bi ${meta.icon || "bi-gem"}" aria-hidden="true"></i>
          <span class="price-ticker-label">${meta.label}</span>
          <span class="price-ticker-value">${formatYen(data.price_per_gram)}</span>
          <span class="price-ticker-delta ${deltaClass}"><i class="bi ${deltaIcon}"></i>${formatDelta(delta)}</span>
        </span>
      `;
    })
    .join("");
  // マーキー表示のため2セット連結し、CSSアニメーションで-50%スクロールしてループさせる。
  track.innerHTML = itemsHtml + itemsHtml;
}

// summaryCards/forecastCardsという別カードには分けず、マーケットビュートグルの状態に応じて
// 各金属のチャートウィジェット(価格行)を書き換える一つの関数に統合している(情報の重複を避けるため)。
function renderForecastReasonBox(noteEl, metalKey, item) {
  if (!noteEl) {
    return;
  }

  const drivers = Array.isArray(item?.drivers)
    ? item.drivers.map((driver) => String(driver || "").trim()).filter(Boolean)
    : [];
  // 保存済みの旧予測には drivers がない場合があるため、AI所見があれば理由として補う。
  const llmRationale = String(latestForecastPayload?.signals?.llm?.rationales?.[metalKey] || "").trim();
  if (llmRationale && !drivers.some((driver) => driver.includes(llmRationale))) {
    drivers.push(`AI判定所見: ${llmRationale}`);
  }
  // SARIMAXの係数や合成シグナル値など専門的な箇条書きは分かりにくいというフィードバックを
  // 受け、Groqが生成した平易な要約文(item.summary)があればそちらを主表示にする。
  // 要約が無い(生成失敗/無効化/旧キャッシュ)場合は従来通り箇条書きをそのまま見せる。
  const summary = String(item?.summary || "").trim();
  const breakdown = Array.isArray(item?.driver_breakdown) ? item.driver_breakdown : [];

  noteEl.replaceChildren();
  noteEl.hidden = drivers.length === 0 && breakdown.length === 0 && !summary;
  if (noteEl.hidden) {
    return;
  }

  const title = document.createElement("div");
  title.className = "market-widget-forecast-note-title";
  const icon = document.createElement("i");
  icon.className = "bi bi-lightbulb";
  icon.setAttribute("aria-hidden", "true");
  const titleText = document.createElement("span");
  titleText.textContent = "予測の根拠";
  title.append(icon, titleText);
  noteEl.append(title);

  // 構造化された内訳(driver_breakdown)があれば役割ごとに描き分ける。
  // role: primary=実際に予測値を決めた要因 / signal=寄与した入力シグナル /
  //       reference=参考値(今回の計算には直接効いていない)
  // 以前は全部を同じ箇条書きで並べていたため、「項目はほぼプラスなのに予測はマイナス」
  // という状態が理解不能に見えていた。
  const ROLE_LABEL = { primary: "決定要因", signal: "寄与シグナル", reference: "参考値" };

  const buildBreakdownList = () => {
    const list = document.createElement("ul");
    list.className = "market-widget-forecast-note-list is-structured";
    breakdown.slice(0, 9).forEach((row) => {
      const role = ROLE_LABEL[row.role] ? row.role : "reference";
      const listItem = document.createElement("li");
      listItem.className = `forecast-driver forecast-driver-${role}`;

      const badge = document.createElement("span");
      badge.className = "forecast-driver-role";
      badge.textContent = ROLE_LABEL[role];

      const label = document.createElement("span");
      label.className = "forecast-driver-label";
      label.textContent = row.label ?? "";

      listItem.append(badge, label);

      const value = row.value_pct_per_day;
      if (typeof value === "number" && Number.isFinite(value)) {
        const valueEl = document.createElement("span");
        const cls = value > 0 ? "is-up" : value < 0 ? "is-down" : "is-flat";
        valueEl.className = `forecast-driver-value ${cls}`;
        valueEl.textContent = `${value > 0 ? "+" : ""}${value.toFixed(3)}%/日`;
        listItem.append(valueEl);
      }

      if (row.detail) {
        const detail = document.createElement("span");
        detail.className = "forecast-driver-detail";
        detail.textContent = row.detail;
        listItem.append(detail);
      }
      list.append(listItem);
    });
    return list;
  };

  const buildPlainList = () => {
    const list = document.createElement("ul");
    list.className = "market-widget-forecast-note-list";
    // 旧キャッシュ(構造化内訳が無い)向けのフォールバック表示。
    drivers.slice(0, 9).forEach((driver) => {
      const listItem = document.createElement("li");
      listItem.textContent = driver;
      list.append(listItem);
    });
    return list;
  };

  const buildList = () => (breakdown.length > 0 ? buildBreakdownList() : buildPlainList());

  if (summary) {
    const summaryEl = document.createElement("p");
    summaryEl.className = "market-widget-forecast-note-summary";
    summaryEl.textContent = summary;
    noteEl.append(summaryEl);

    if (drivers.length > 0 || breakdown.length > 0) {
      const details = document.createElement("details");
      details.className = "market-widget-forecast-note-details";
      const detailsLabel = document.createElement("summary");
      detailsLabel.textContent = "詳細を見る";
      details.append(detailsLabel, buildList());
      noteEl.append(details);
    }
  } else {
    noteEl.append(buildList());
  }
}

function updateMarketWidgets() {
  const latest = latestHistoryPayload?.latest || {};
  const forecast = latestForecastPayload?.forecast || {};
  const isForecast = currentMarketView === "forecast";

  Object.keys(METALS).forEach((key) => {
    const priceEl = document.getElementById(`${key}WidgetPrice`);
    const deltaEl = document.getElementById(`${key}WidgetDelta`);
    const metaEl = document.getElementById(`${key}WidgetMeta`);
    const noteEl = document.getElementById(`${key}WidgetForecastNote`);
    if (!priceEl || !deltaEl || !metaEl) {
      return;
    }

    if (isForecast) {
      const item = forecast[key];
      if (!item) {
        priceEl.textContent = "-";
        deltaEl.textContent = "-";
        deltaEl.className = "market-widget-delta-pill";
        metaEl.textContent = "予測データがありません";
        if (noteEl) {
          noteEl.hidden = true;
          noteEl.replaceChildren();
        }
        return;
      }
      // 点予測は実測でランダムウォークに負けていたため、レンジを主表示にして
      // 中心値は参考として小さく添える(1週間先の向きは断定できないという事実を素直に出す)。
      const changePct = Number(item.projected_change_pct_7d || 0);
      const confidencePct = Number(item.confidence || 0) * 100;
      const lower = item.projected_lower_per_gram;
      const upper = item.projected_upper_per_gram;
      const lowerPct = item.projected_lower_change_pct;
      const upperPct = item.projected_upper_change_pct;
      const hasRange = Number.isFinite(lower) && Number.isFinite(upper);
      const intervalPct = Math.round(Number(item.interval_prob || 0.8) * 100);

      if (hasRange) {
        priceEl.classList.add("is-range");
        priceEl.textContent = `${formatYenPlain(lower)} 〜 ${formatYenPlain(upper)} 円/g`;
        // レンジが0をまたぐなら向きを断定しない。
        const straddles = Number(lowerPct) < 0 && Number(upperPct) > 0;
        const rangeClass = straddles ? "is-flat" : Number(lowerPct) > 0 ? "is-up" : "is-down";
        const rangeIcon = straddles
          ? "bi-arrows-expand-vertical"
          : Number(lowerPct) > 0 ? "bi-arrow-up-short" : "bi-arrow-down-short";
        deltaEl.className = `market-widget-delta-pill ${rangeClass}`;
        deltaEl.innerHTML =
          `<i class="bi ${rangeIcon}"></i>${intervalPct}%の確率で ` +
          `${formatPercent(Number(lowerPct), 1)} 〜 ${formatPercent(Number(upperPct), 1)}`;
      } else {
        // 区間を持たない旧キャッシュ向けのフォールバック。
        priceEl.classList.remove("is-range");
        const deltaClass = changePct > 0 ? "is-up" : changePct < 0 ? "is-down" : "is-flat";
        const deltaIcon = changePct > 0 ? "bi-arrow-up-short" : changePct < 0 ? "bi-arrow-down-short" : "bi-dash";
        priceEl.textContent = formatYen(item.projected_price_per_gram);
        deltaEl.className = `market-widget-delta-pill ${deltaClass}`;
        deltaEl.innerHTML = `<i class="bi ${deltaIcon}"></i>予測変化: ${formatPercent(changePct, 3)}`;
      }

      const confidenceText = `信頼度: ${new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 1 }).format(confidencePct)}%`;
      metaEl.textContent = hasRange
        ? `中心 ${formatYen(item.projected_price_per_gram)} / ${confidenceText}`
        : confidenceText;
      renderForecastReasonBox(noteEl, key, item);
    } else {
      const data = latest[key] || {};
      const delta = data.delta_from_previous;
      const deltaClass = delta > 0 ? "is-up" : delta < 0 ? "is-down" : "is-flat";
      const deltaIcon = delta > 0 ? "bi-arrow-up-short" : delta < 0 ? "bi-arrow-down-short" : "bi-dash";

      priceEl.textContent = formatYen(data.price_per_gram);
      deltaEl.className = `market-widget-delta-pill ${deltaClass}`;
      deltaEl.innerHTML = `<i class="bi ${deltaIcon}"></i>前日差: ${formatDelta(delta)}`;
      metaEl.textContent = `基準日: ${data.date || "-"}`;
      if (noteEl) {
        noteEl.hidden = true;
        noteEl.replaceChildren();
      }
    }
  });
}

function setForecastError(message) {
  const meta = document.getElementById("forecastMeta");
  if (meta) {
    meta.textContent = message;
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
  const usdSource = payload?.signals?.usd_jpy?.source || "Frankfurter (ECB)";
  const newsSource = payload?.signals?.news?.source || "Google News RSS";
  const llm = payload?.signals?.llm || {};
  const llmLabel = llm?.available
    ? `・AI判定(${llm.model || "openai/gpt-oss-120b"})`
    : "";
  const asOfDate = payload?.as_of_date || "-";
  source.textContent = `予想ソース: USD/JPY(${usdSource})・ニュース(${newsSource})${llmLabel} / 基準日: ${asOfDate}`;
}

function updateForecastMeta(payload) {
  const meta = document.getElementById("forecastMeta");
  if (!meta) {
    return;
  }
  const usdJpy = payload?.signals?.usd_jpy || {};
  const horizonDays = Number(payload?.horizon_days || 7);
  const generatedAt = formatJstDateTime(payload?.generated_at);
  const fxAvailable = !!usdJpy.available;
  const fxValue = Number(usdJpy.weekly_change_pct || 0);
  const fxClass = fxAvailable ? (fxValue > 0 ? "is-up" : fxValue < 0 ? "is-down" : "") : "";
  const fxText = fxAvailable ? formatPercent(fxValue, 2) : "取得失敗";

  meta.innerHTML = [
    `<span class="forecast-meta-chip"><i class="bi bi-clock-history" aria-hidden="true"></i>生成 ${escapeHtml(generatedAt)} (JST)</span>`,
    `<span class="forecast-meta-chip"><i class="bi bi-calendar-range" aria-hidden="true"></i>予測期間 ${horizonDays}日</span>`,
    `<span class="forecast-meta-chip ${fxClass}"><i class="bi bi-currency-exchange" aria-hidden="true"></i>USD/JPY週次 ${escapeHtml(fxText)}</span>`,
  ].join("");
  updateForecastSourceFooter(payload);
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
      updateForecastMeta(forecastPayload);
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

function computeMovingAverage(values, windowSize) {
  const result = new Array(values.length).fill(null);
  for (let i = windowSize - 1; i < values.length; i++) {
    let sum = 0;
    let hasGap = false;
    for (let j = i - windowSize + 1; j <= i; j++) {
      const value = values[j];
      if (value === null || value === undefined) {
        hasGap = true;
        break;
      }
      sum += value;
    }
    result[i] = hasGap ? null : sum / windowSize;
  }
  return result;
}

function updateChartStats(metalKey, prices) {
  const values = prices.filter((value) => value !== null && value !== undefined);
  const highEl = document.getElementById(`${metalKey}ChartHigh`);
  const lowEl = document.getElementById(`${metalKey}ChartLow`);
  const avgEl = document.getElementById(`${metalKey}ChartAvg`);
  if (!values.length) {
    if (highEl) highEl.textContent = "-";
    if (lowEl) lowEl.textContent = "-";
    if (avgEl) avgEl.textContent = "-";
    return;
  }
  const high = Math.max(...values);
  const low = Math.min(...values);
  const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (highEl) highEl.textContent = formatYen(high);
  if (lowEl) lowEl.textContent = formatYen(low);
  if (avgEl) avgEl.textContent = formatYen(avg);
}

// Lightweight Chartsの各シリーズは [{time, value}, ...] の疎データ配列を受け取る形式のため、
// Chart.js時代の「日付ごとに値かnullが並ぶ配列」からnullを除いて変換する。
function toSeriesData(dailyAxis, values) {
  const points = [];
  dailyAxis.forEach((date, index) => {
    const value = values[index];
    if (value === null || value === undefined) {
      return;
    }
    points.push({ time: date, value });
  });
  return points;
}

function toDeltaSeriesData(dailyAxis, deltas) {
  const points = [];
  dailyAxis.forEach((date, index) => {
    const value = deltas[index];
    if (value === null || value === undefined) {
      return;
    }
    points.push({
      time: date,
      value,
      color: value >= 0 ? "rgba(26, 187, 156, 0.55)" : "rgba(231, 76, 60, 0.55)",
    });
  });
  return points;
}

// Lightweight ChartsのTime型は "YYYY-MM-DD" 文字列で渡すと内部でBusinessDayオブジェクトに
// 変換されて返ってくることがあるため、両方の形をISO文字列へ正規化する。
function lightweightTimeToIsoDate(time) {
  if (typeof time === "string") {
    return time;
  }
  if (time && typeof time === "object" && "year" in time) {
    const month = String(time.month).padStart(2, "0");
    const day = String(time.day).padStart(2, "0");
    return `${time.year}-${month}-${day}`;
  }
  return null;
}

function initializeChartTooltip(metalKey, chart, priceSeries, deltaSeries) {
  const tooltipEl = document.getElementById(`${metalKey}ChartTooltip`);
  const container = document.getElementById(METALS[metalKey].containerId);
  if (!tooltipEl || !container) {
    return;
  }

  chart.subscribeCrosshairMove((param) => {
    const priceData = param.point && param.time ? param.seriesData.get(priceSeries) : null;
    if (!param.point || !param.time || !priceData || param.point.x < 0 || param.point.y < 0) {
      tooltipEl.hidden = true;
      return;
    }

    const isoDate = lightweightTimeToIsoDate(param.time);
    let html = `<div class="chart-tooltip-date">${escapeHtml(isoDate || "")}</div>` +
      `<div class="chart-tooltip-price">${escapeHtml(formatYen(priceData.value))}</div>`;

    if (deltaSeries.options().visible) {
      const deltaData = param.seriesData.get(deltaSeries);
      if (deltaData) {
        const deltaClass = deltaData.value >= 0 ? "text-success" : "text-danger";
        html += `<div class="chart-tooltip-delta ${deltaClass}">前日差: ${escapeHtml(formatDelta(deltaData.value))}</div>`;
      }
    }

    tooltipEl.innerHTML = html;
    tooltipEl.hidden = false;

    const containerWidth = container.clientWidth;
    const tooltipWidth = tooltipEl.offsetWidth;
    let left = param.point.x + 14;
    if (left + tooltipWidth > containerWidth) {
      left = param.point.x - tooltipWidth - 14;
    }
    tooltipEl.style.left = `${Math.max(0, left)}px`;
    tooltipEl.style.top = `${Math.max(0, param.point.y - 10)}px`;
  });

  container.addEventListener("mouseleave", () => {
    tooltipEl.hidden = true;
  });
}

// 「1週間予測」表示時、実績データと予測データが同じ線でつながって見えるため、予測値を
// 本日の実績と誤認しやすいというフィードバックを受けて追加した境界線プリミティブ。
// Lightweight Charts v5のプラグインAPI(attachPrimitive)で価格系列に重ね描画する。
const FORECAST_BOUNDARY_COLOR = "#e74c3c"; // CSS変数 --down と同じ赤(テーマ間で不変)。

function createForecastBoundaryPrimitive() {
  let chartRef = null;
  let requestUpdateFn = null;
  const state = { forecastStartTime: null, anchorTime: null, visible: false, x: null };

  const paneView = {
    zOrder() {
      return "top";
    },
    update() {
      if (!chartRef || !state.visible || state.forecastStartTime === null) {
        state.x = null;
        return;
      }

      const forecastX = chartRef.timeScale().timeToCoordinate(state.forecastStartTime);
      const anchorX =
        state.anchorTime !== null ? chartRef.timeScale().timeToCoordinate(state.anchorTime) : null;
      // 実績最終日と予測初日のちょうど中間に置くことで、どちらの点にも重ならない
      // 「区切り線」として見える。実績側の座標が取れない場合は予測初日に合わせる。
      state.x =
        forecastX !== null && forecastX !== undefined && anchorX !== null && anchorX !== undefined
          ? (forecastX + anchorX) / 2
          : forecastX;
    },
    renderer() {
      const { x, visible } = state;
      return {
        draw(target) {
          if (!visible || x === null || x === undefined) {
            return;
          }
          target.useMediaCoordinateSpace(({ context, mediaSize }) => {
            context.save();
            context.strokeStyle = FORECAST_BOUNDARY_COLOR;
            context.lineWidth = 1.5;
            context.setLineDash([4, 3]);
            context.beginPath();
            context.moveTo(x + 0.5, 0);
            context.lineTo(x + 0.5, mediaSize.height);
            context.stroke();

            context.setLineDash([]);
            const label = "予測開始";
            context.font =
              "600 11px 'Segoe UI', 'Hiragino Kaku Gothic ProN', 'Hiragino Sans', Meiryo, sans-serif";
            const textWidth = context.measureText(label).width;
            const paddingX = 6;
            const boxWidth = textWidth + paddingX * 2;
            const boxHeight = 18;
            const boxX = Math.max(2, Math.min(x - boxWidth / 2, mediaSize.width - boxWidth - 2));
            context.fillStyle = FORECAST_BOUNDARY_COLOR;
            context.fillRect(boxX, 2, boxWidth, boxHeight);
            context.fillStyle = "#ffffff";
            context.textBaseline = "middle";
            context.fillText(label, boxX + paddingX, 2 + boxHeight / 2 + 1);
            context.restore();
          });
        },
      };
    },
  };

  return {
    attached({ chart, requestUpdate }) {
      chartRef = chart;
      requestUpdateFn = requestUpdate;
      paneView.update();
    },
    detached() {
      chartRef = null;
      requestUpdateFn = null;
    },
    updateAllViews() {
      paneView.update();
    },
    paneViews() {
      return [paneView];
    },
    // forecastStartTime: 予測初日のISO日付。anchorTime: 最終実績日のISO日付。
    // visible: この瞬間に線を描画するか。
    setBoundary(forecastStartTime, visible, anchorTime = null) {
      state.forecastStartTime = forecastStartTime || null;
      state.anchorTime = anchorTime || null;
      state.visible = Boolean(visible && state.forecastStartTime);
      paneView.update();
      if (requestUpdateFn) {
        requestUpdateFn();
      }
    },
  };
}

// 予測レンジ(予測区間)をチャート上に帯として塗るプリミティブ。
// 点予測はランダムウォークに負けることが実測で分かったため、UI上も「幅」を主役にする。
// 境界線プリミティブと同じ Lightweight Charts v5 のプラグイン方式。価格→座標の変換に
// series.priceToCoordinate() を使うため、価格系列に attach して用いる。
const FORECAST_BAND_FILL = "rgba(52, 152, 219, 0.16)";
const FORECAST_BAND_EDGE = "rgba(52, 152, 219, 0.45)";

function createForecastBandPrimitive() {
  let chartRef = null;
  let seriesRef = null;
  let requestUpdateFn = null;
  const state = { points: [], visible: false, coords: [] };

  const paneView = {
    zOrder() {
      return "bottom";
    },
    update() {
      if (!chartRef || !seriesRef || !state.visible || state.points.length === 0) {
        state.coords = [];
        return;
      }
      const timeScale = chartRef.timeScale();
      const coords = [];
      state.points.forEach((point) => {
        const x = timeScale.timeToCoordinate(point.time);
        const lower = seriesRef.priceToCoordinate(point.lower);
        const upper = seriesRef.priceToCoordinate(point.upper);
        if (x !== null && lower !== null && upper !== null) {
          coords.push({ x, lower, upper });
        }
      });
      state.coords = coords;
    },
    renderer() {
      const coords = state.coords;
      const visible = state.visible;
      return {
        draw(target) {
          if (!visible || coords.length < 2) {
            return;
          }
          target.useMediaCoordinateSpace(({ context }) => {
            context.save();
            context.beginPath();
            context.moveTo(coords[0].x, coords[0].upper);
            for (let i = 1; i < coords.length; i++) {
              context.lineTo(coords[i].x, coords[i].upper);
            }
            for (let i = coords.length - 1; i >= 0; i--) {
              context.lineTo(coords[i].x, coords[i].lower);
            }
            context.closePath();
            context.fillStyle = FORECAST_BAND_FILL;
            context.fill();

            context.strokeStyle = FORECAST_BAND_EDGE;
            context.lineWidth = 1;
            context.setLineDash([3, 3]);
            for (const edge of ["upper", "lower"]) {
              context.beginPath();
              context.moveTo(coords[0].x, coords[0][edge]);
              for (let i = 1; i < coords.length; i++) {
                context.lineTo(coords[i].x, coords[i][edge]);
              }
              context.stroke();
            }
            context.restore();
          });
        },
      };
    },
  };

  return {
    attached({ chart, series, requestUpdate }) {
      chartRef = chart;
      seriesRef = series;
      requestUpdateFn = requestUpdate;
      paneView.update();
    },
    detached() {
      chartRef = null;
      seriesRef = null;
      requestUpdateFn = null;
    },
    updateAllViews() {
      paneView.update();
    },
    paneViews() {
      return [paneView];
    },
    // points: [{ time, lower, upper }, ...] / visible: この瞬間に帯を描くか
    setBand(points, visible) {
      state.points = Array.isArray(points) ? points : [];
      state.visible = Boolean(visible && state.points.length >= 2);
      paneView.update();
      if (requestUpdateFn) {
        requestUpdateFn();
      }
    },
  };
}

function buildForecastBandPoints(forecastItem, anchorDate, anchorPrice) {
  const daily = Array.isArray(forecastItem?.daily) ? forecastItem.daily : [];
  const points = [];
  // 実績最終日を起点に含めると帯が価格線から連続して見える。
  if (anchorDate && Number.isFinite(anchorPrice)) {
    points.push({ time: anchorDate, lower: anchorPrice, upper: anchorPrice });
  }
  daily.forEach((item) => {
    const lower = item?.lower_price_per_gram;
    const upper = item?.upper_price_per_gram;
    if (item?.date && Number.isFinite(lower) && Number.isFinite(upper)) {
      points.push({ time: item.date, lower, upper });
    }
  });
  return points.length >= 2 ? points : [];
}

function renderMetalChart(metalKey, history, dailyAxis, forecastItem = null, historyEndDate = null) {
  const meta = METALS[metalKey];
  if (!meta || !window.LightweightCharts) {
    return;
  }

  const dailyMap = new Map(history.map((item) => [item.date, item]));
  const prices = dailyAxis.map((date) => dailyMap.get(date)?.price_per_gram ?? null);
  const deltas = dailyAxis.map((date) => dailyMap.get(date)?.delta_from_previous ?? null);
  const movingAverage = computeMovingAverage(prices, 7);
  updateChartStats(metalKey, prices);

  const forecastMap = new Map(
    Array.isArray(forecastItem?.daily)
      ? forecastItem.daily.map((item) => [item.date, item.price_per_gram])
      : []
  );
  const forecastPrices = dailyAxis.map(() => null);
  const latestActual = [...history]
    .reverse()
    .find((item) => item?.date && item.price_per_gram !== null && item.price_per_gram !== undefined);
  const anchorDate =
    historyEndDate && dailyMap.get(historyEndDate)?.price_per_gram !== null &&
    dailyMap.get(historyEndDate)?.price_per_gram !== undefined
      ? historyEndDate
      : latestActual?.date || null;
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
  const forecastStartDate = Array.isArray(forecastItem?.daily)
    ? forecastItem.daily.find(
        (item) =>
          item?.date &&
          item.price_per_gram !== null &&
          item.price_per_gram !== undefined &&
          (!anchorDate || compareIsoDate(item.date, anchorDate) > 0)
      )?.date || null
    : null;

  const container = document.getElementById(meta.containerId);
  if (!container) {
    return;
  }

  const anchorPrice = anchorIndex >= 0 ? prices[anchorIndex] : null;
  const bandPoints = buildForecastBandPoints(forecastItem, anchorDate, anchorPrice);

  const priceData = toSeriesData(dailyAxis, prices);
  const deltaData = toDeltaSeriesData(dailyAxis, deltas);
  const forecastData = toSeriesData(dailyAxis, forecastPrices);
  const maData = toSeriesData(dailyAxis, movingAverage);

  const existing = charts[metalKey];
  if (existing) {
    existing.priceSeries.setData(priceData);
    existing.deltaSeries.setData(deltaData);
    existing.forecastSeries.setData(forecastData);
    existing.forecastSeries.applyOptions({ visible: currentMarketView === "forecast" });
    existing.maSeries.setData(maData);
    existing.chart.timeScale().fitContent();
    existing.forecastStartDate = forecastStartDate;
    existing.forecastAnchorDate = anchorDate;
    existing.forecastBoundary?.setBoundary(
      forecastStartDate,
      currentMarketView === "forecast",
      anchorDate
    );
    existing.forecastBandPoints = bandPoints;
    existing.forecastBand?.setBand(bandPoints, currentMarketView === "forecast");
    return;
  }

  const themeColors = getChartThemeColors();
  const LC = window.LightweightCharts;
  const chart = LC.createChart(container, {
    // autoSize: コンテナのResizeObserverをライブラリ側が内蔵しており、サイドバー開閉や
    // ウィンドウ幅変更に自動追従してくれる(固定幅+横スクロールだった従来方式が丸ごと不要になる)。
    autoSize: true,
    layout: {
      textColor: themeColors.text,
      background: { type: "solid", color: themeColors.background },
      fontFamily:
        "'Segoe UI', 'Hiragino Kaku Gothic ProN', 'Hiragino Sans', Meiryo, -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif",
      attributionLogo: false,
    },
    grid: {
      vertLines: { color: themeColors.grid },
      horzLines: { color: themeColors.grid },
    },
    crosshair: {
      mode: LC.CrosshairMode.Normal,
      vertLine: { color: themeColors.crosshair, labelBackgroundColor: meta.lineColor },
      horzLine: { color: themeColors.crosshair, labelBackgroundColor: meta.lineColor },
    },
    rightPriceScale: { borderVisible: false },
    timeScale: {
      borderVisible: false,
      tickMarkFormatter: (time) => formatDailyLabel(lightweightTimeToIsoDate(time) || ""),
    },
    localization: {
      priceFormatter: (value) => new Intl.NumberFormat("ja-JP").format(value),
    },
  });

  const priceSeries = chart.addSeries(LC.AreaSeries, {
    lineType: LC.LineType.WithSteps,
    lineColor: meta.lineColor,
    topColor: meta.fillColor,
    bottomColor: "rgba(0, 0, 0, 0)",
    lineWidth: 2,
    priceScaleId: "right",
    priceLineVisible: false,
    crosshairMarkerRadius: 3,
  });

  // 前日差は価格と桁が違うため専用スケールに分離している(スケール自体は常に非表示にし、
  // 軸ラベルは出さずツールチップでのみ値を見せる)。Δ・MA7とも初期状態から情報量を
  // 最大化する方針でデフォルト表示にしている(Δボタン/MA7ボタンでいつでも非表示にできる)。
  const deltaSeries = chart.addSeries(LC.HistogramSeries, {
    priceScaleId: "delta",
    priceLineVisible: false,
    lastValueVisible: false,
    visible: true,
  });
  chart.priceScale("delta").applyOptions({
    scaleMargins: { top: 0.75, bottom: 0 },
    visible: false,
  });

  const forecastSeries = chart.addSeries(LC.LineSeries, {
    color: meta.lineColor,
    lineStyle: LC.LineStyle.Dashed,
    lineWidth: 2,
    priceScaleId: "right",
    priceLineVisible: false,
    lastValueVisible: false,
    visible: currentMarketView === "forecast",
  });

  const maSeries = chart.addSeries(LC.LineSeries, {
    color: "#3498db",
    lineStyle: LC.LineStyle.Dashed,
    lineWidth: 1,
    priceScaleId: "right",
    priceLineVisible: false,
    lastValueVisible: false,
    visible: true,
  });

  priceSeries.setData(priceData);
  deltaSeries.setData(deltaData);
  forecastSeries.setData(forecastData);
  maSeries.setData(maData);
  chart.timeScale().fitContent();

  // v5以降ではプリミティブを系列へ安全に重ねられる。古いライブラリが読み込まれた場合は
  // 境界線なしで通常のチャート表示を続け、画面全体の初期化を失敗させない。
  const supportsPrimitives = typeof priceSeries.attachPrimitive === "function";
  const forecastBoundary = createForecastBoundaryPrimitive();
  const forecastBand = createForecastBandPrimitive();
  if (supportsPrimitives) {
    // 帯を先にattachして価格線より下に来るようにする(zOrderもbottom指定)。
    priceSeries.attachPrimitive(forecastBand);
    priceSeries.attachPrimitive(forecastBoundary);
    forecastBand.setBand(bandPoints, currentMarketView === "forecast");
    forecastBoundary.setBoundary(forecastStartDate, currentMarketView === "forecast", anchorDate);
  }

  charts[metalKey] = {
    chart,
    priceSeries,
    deltaSeries,
    forecastSeries,
    maSeries,
    forecastBoundary: supportsPrimitives ? forecastBoundary : null,
    forecastBand: supportsPrimitives ? forecastBand : null,
    forecastStartDate,
    forecastAnchorDate: anchorDate,
    forecastBandPoints: bandPoints,
  };
  initializeChartTooltip(metalKey, chart, priceSeries, deltaSeries);
}

async function loadDashboard() {
  setDashboardLoadingState();
  try {
    await ensureChartLibrary();
    const historyQuery = buildRangeQuery(currentRangeState);
    const response = await fetch(`${appUrl("api/prices/history")}?${historyQuery}`);
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
      updateForecastMeta(forecastPayload);
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
    `表示期間: ${payload.range_start} - ${payload.range_end}`;
  buildTicker(payload.latest || {});
  updateMarketWidgets();

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
  const dot = document.getElementById("notifyDot");
  if (dot) {
    dot.classList.toggle("d-none", !subscribed);
  }
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

const DEFAULT_RANGE_STATE = { mode: "all" };
let currentRangeState = { ...DEFAULT_RANGE_STATE };

function buildRangeQuery(state) {
  if (state.mode === "all") {
    return "all=true";
  }
  if (state.mode === "custom" && state.start && state.end) {
    return `start=${encodeURIComponent(state.start)}&end=${encodeURIComponent(state.end)}`;
  }
  return `days=${Number(state.days) || 30}`;
}

function getRangeLabel(state) {
  if (state.mode === "all") {
    return "全期間";
  }
  if (state.mode === "custom" && state.start && state.end) {
    const shorten = (iso) => iso.replaceAll("-", "/").slice(2);
    return `${shorten(state.start)}〜${shorten(state.end)}`;
  }
  return `${Number(state.days) || 30}日`;
}

function isValidRangeState(state) {
  if (!state || typeof state !== "object") {
    return false;
  }
  if (state.mode === "all") {
    return true;
  }
  if (state.mode === "preset") {
    return [30, 90, 180, 365].includes(Number(state.days));
  }
  if (state.mode === "custom") {
    return typeof state.start === "string" && typeof state.end === "string" && state.start <= state.end;
  }
  return false;
}

function syncRangeUi(state) {
  const label = document.getElementById("rangeDropdownLabel");
  if (label) {
    label.textContent = getRangeLabel(state);
  }
  document.querySelectorAll(".range-preset-btn").forEach((button) => {
    const isMatch =
      (state.mode === "all" && button.dataset.rangeDays === "all") ||
      (state.mode === "preset" && button.dataset.rangeDays === String(state.days));
    button.classList.toggle("is-active", isMatch);
  });
  if (state.mode === "custom") {
    const startInput = document.getElementById("rangeStartInput");
    const endInput = document.getElementById("rangeEndInput");
    if (startInput) {
      startInput.value = state.start;
    }
    if (endInput) {
      endInput.value = state.end;
    }
  }
}

function closeRangeDropdown() {
  const button = document.getElementById("rangeDropdownButton");
  if (!button || typeof bootstrap === "undefined") {
    return;
  }
  const instance = bootstrap.Dropdown.getOrCreateInstance(button);
  instance.hide();
}

function applyRangeState(state) {
  if (!isValidRangeState(state)) {
    return;
  }
  currentRangeState = state;
  try {
    localStorage.setItem(DAYS_RANGE_STORAGE_KEY, JSON.stringify(state));
  } catch (_) {}
  syncRangeUi(state);
  closeRangeDropdown();
  loadDashboard().catch((err) => {
    console.error(err);
    alert(err.message || "ダッシュボードの更新に失敗しました。");
  });
}

function restoreStoredRangeState() {
  const todayIso = todayJstIso();
  const startInput = document.getElementById("rangeStartInput");
  const endInput = document.getElementById("rangeEndInput");
  if (startInput) {
    startInput.max = todayIso;
  }
  if (endInput) {
    endInput.max = todayIso;
  }

  let stored = null;
  try {
    const raw = localStorage.getItem(DAYS_RANGE_STORAGE_KEY);
    stored = raw ? JSON.parse(raw) : null;
  } catch (_) {
    stored = null;
  }
  const state = isValidRangeState(stored) ? stored : { ...DEFAULT_RANGE_STATE };
  currentRangeState = state;
  syncRangeUi(state);
}

document.querySelectorAll(".range-preset-btn").forEach((button) => {
  button.addEventListener("click", () => {
    const { rangeDays } = button.dataset;
    applyRangeState(rangeDays === "all" ? { mode: "all" } : { mode: "preset", days: Number(rangeDays) });
  });
});

document.getElementById("rangeApplyButton").addEventListener("click", () => {
  const startInput = document.getElementById("rangeStartInput");
  const endInput = document.getElementById("rangeEndInput");
  const errorEl = document.getElementById("rangeCustomError");
  const start = startInput?.value || "";
  const end = endInput?.value || "";
  const todayIso = todayJstIso();

  let errorMessage = "";
  if (!start || !end) {
    errorMessage = "開始日と終了日の両方を指定してください。";
  } else if (start > end) {
    errorMessage = "開始日は終了日より前の日付を指定してください。";
  } else if (end > todayIso) {
    errorMessage = "終了日は今日以前の日付を指定してください。";
  }

  if (errorMessage) {
    if (errorEl) {
      errorEl.textContent = errorMessage;
      errorEl.hidden = false;
    }
    return;
  }
  if (errorEl) {
    errorEl.hidden = true;
  }
  applyRangeState({ mode: "custom", start, end });
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

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    refreshForecastSnapshot().catch((error) => {
      console.error(error);
    });
  }
});

initializeThemeToggle();
initializeMarketToggle();
initializeChartTools();
initializeChartMaximize();
restoreStoredRangeState();
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
