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

function renderMetalChart(metalKey, history) {
  const meta = METALS[metalKey];
  if (!meta) {
    return;
  }

  const labels = history.map((item) => item.date);
  const prices = history.map((item) => item.price_per_gram);
  const deltas = history.map((item) => item.delta_from_previous);
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
          tension: 0.24,
          fill: true,
          pointRadius: 0,
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
          ticks: {
            maxTicksLimit: 8,
          },
        },
      },
      plugins: {
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

  document.getElementById("generatedAt").textContent = `最終生成: ${payload.generated_at} (${payload.timezone})`;
  buildSummary(payload.latest || {});

  Object.keys(METALS).forEach((key) => {
    renderMetalChart(key, payload.metals?.[key] || []);
  });
}

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

