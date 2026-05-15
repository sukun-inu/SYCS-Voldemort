/* dev panel – external script */

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ── タブ状態をセッションストレージで保持（URLハッシュをフォールバックに使用） ── */
(function () {
  const TAB_KEY = "devActiveTab";
  const tabEl = document.getElementById("devTabs");
  if (!tabEl) return;
  const saved = sessionStorage.getItem(TAB_KEY) || location.hash || "";
  if (saved) {
    const btn = tabEl.querySelector(`[data-bs-target="${saved}"]`);
    if (btn) bootstrap.Tab.getOrCreateInstance(btn).show();
  }
  tabEl.addEventListener("shown.bs.tab", e => {
    sessionStorage.setItem(TAB_KEY, e.target.dataset.bsTarget);
  });
})();

/* ── インラインイベント置換: import ボタンと data-confirm フォーム処理 ── */
(function () {
  // Import モーダルを開くボタン (.import-open)
  document.querySelectorAll('.import-open').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.guildId;
      const name = btn.dataset.guildName || '';
      openImport(id, name);
    });
  });

  // フォームに data-confirm が付いている場合、submit イベントで確認ダイアログを出す
  document.addEventListener('submit', function (e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const msg = form.dataset.confirm;
    if (msg && !confirm(msg)) {
      e.preventDefault();
    }
  }, true);

  // フォーム以外の要素に data-confirm が付いている場合のフォールバック（リンクなど）
  document.addEventListener('click', function (e) {
    const el = e.target.closest('[data-confirm]');
    if (!el) return;
    if (el.tagName && el.tagName.toLowerCase() === 'form') return;
    const msg = el.dataset.confirm;
    if (msg && !confirm(msg)) e.preventDefault();
  });
})();

/* ── expires_at Unix タイムスタンプ → 日本語表示 ── */
document.querySelectorAll("[data-ts]").forEach(el => {
  const ts = parseInt(el.dataset.ts, 10);
  if (ts) el.textContent = new Date(ts * 1000).toLocaleString("ja-JP", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit"
  });
});

/* ── チャンネルID 検索ヘルパー ── */
(function () {
  const guildSel  = document.getElementById("helperGuildSelect");
  const fetchBtn  = document.getElementById("helperFetchBtn");
  const listWrap  = document.getElementById("helperChannelList");
  const listItems = document.getElementById("helperChannelItems");
  const guildName = document.getElementById("helperGuildName");
  if (!guildSel || !fetchBtn) return;

  fetchBtn.addEventListener("click", async () => {
    const guildId = guildSel.value;
    if (!guildId) {
      guildSel.classList.add("is-invalid");
      setTimeout(() => guildSel.classList.remove("is-invalid"), 1500);
      return;
    }

    fetchBtn.disabled = true;
    fetchBtn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>読み込み中…';

    try {
      const res = await fetch(`/admin/dev/api/channels?guild_id=${guildId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const channels = data.channels || [];

      listItems.innerHTML = "";
      if (channels.length === 0) {
        listItems.innerHTML = '<div class="dev-channel-row"><span style="color:var(--text-tertiary)">チャンネルが見つかりませんでした（Botがサーバーに参加しているか確認してください）</span></div>';
      } else {
        channels.forEach(ch => {
          const row = document.createElement("div");
          row.className = "dev-channel-row";
          row.innerHTML = `
            <span class="dev-channel-name"><i class="bi bi-hash me-1" style="opacity:.5"></i>${escHtml(ch.name)}</span>
            <span class="dev-channel-id">${escHtml(ch.id)}</span>`;
          row.addEventListener("click", () => {
            document.querySelectorAll("input.ch-target").forEach(inp => {
              inp.value = ch.id;
            });
            row.style.background = "var(--success-soft)";
            setTimeout(() => row.style.background = "", 800);
          });
          listItems.appendChild(row);
        });
      }

      guildName.textContent = guildSel.options[guildSel.selectedIndex].text;
      listWrap.hidden = false;
    } catch (err) {
      listItems.innerHTML = `<div class="dev-channel-row"><span style="color:var(--danger)">取得に失敗しました: ${escHtml(String(err))}</span></div>`;
      listWrap.hidden = false;
    } finally {
      fetchBtn.disabled = false;
      fetchBtn.innerHTML = '<i class="bi bi-list-ul me-1"></i>チャンネル一覧';
    }
  });
})();

/* ── インポートモーダル ── */
function openImport(guildId, guildName) {
  document.getElementById("importGuildName").textContent = guildName;
  document.getElementById("importForm").action = `/admin/dev/settings/${guildId}/import`;
  bootstrap.Modal.getOrCreateInstance(document.getElementById("importModal")).show();
}

/* ── Discord ユーザー検索 ── */
(function () {
  const btn    = document.getElementById("userLookupBtn");
  const input  = document.getElementById("userLookupId");
  const result = document.getElementById("userLookupResult");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const uid = input.value.trim();
    if (!/^\d+$/.test(uid)) {
      result.innerHTML = '<p class="small" style="color:var(--danger)">User ID は数値のみです。</p>';
      result.hidden = false;
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>検索中…';
    try {
      const res  = await fetch(`/admin/dev/api/user?user_id=${uid}`);
      const data = await res.json();
      if (data.error) {
        result.innerHTML = `<p class="small" style="color:var(--danger)">${escHtml(data.error)}</p>`;
      } else {
        const avatar = data.avatar
          ? `<img src="https://cdn.discordapp.com/avatars/${escHtml(data.id)}/${escHtml(data.avatar)}.webp?size=64" width="48" height="48" class="rounded-circle me-3" alt="">`
          : `<div class="rounded-circle me-3 d-flex align-items-center justify-content-center" style="width:48px;height:48px;background:var(--surface-elevated)"><i class="bi bi-person" style="font-size:20px"></i></div>`;
        const created = data._created_at ? new Date(data._created_at).toLocaleString("ja-JP") : "—";
        result.innerHTML = `
          <div class="d-flex align-items-center gap-3 p-3 rounded" style="background:var(--surface-elevated)">
            ${avatar}
            <div>
              <div class="fw-bold">${escHtml(data.global_name || data.username || "—")}</div>
              <div class="small font-monospace" style="color:var(--text-secondary)">@${escHtml(data.username || "—")} · ID: ${escHtml(data.id)}</div>
              <div class="small" style="color:var(--text-tertiary)">アカウント作成: ${created}</div>
              ${data.bot ? '<span class="badge-soft ms-0 mt-1" style="display:inline-block">BOT</span>' : ''}
            </div>
          </div>`;
      }
    } catch {
      result.innerHTML = '<p class="small" style="color:var(--danger)">取得に失敗しました。</p>';
    } finally {
      result.hidden = false;
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-search me-1"></i>検索';
    }
  });
  input.addEventListener("keydown", e => { if (e.key === "Enter") btn.click(); });
})();

/* ── ログビューア ── */
(function () {
  const content    = document.getElementById("logContent");
  const pathLabel  = document.getElementById("logPathLabel");
  const lineCount  = document.getElementById("logLineCount");
  const refreshBtn = document.getElementById("logRefreshBtn");
  const autoToggle = document.getElementById("logAutoRefresh");
  if (!content) return;

  let autoTimer = null;

  async function loadLogs() {
    const source = document.querySelector('input[name="logSource"]:checked')?.value || "bot";
    const lines  = document.getElementById("logLines")?.value || "200";
    try {
      const res  = await fetch(`/admin/dev/api/logs?source=${source}&lines=${lines}`);
      const data = await res.json();
      const text = (data.lines || []).join("\n") || "(ログがありません)";
      content.textContent = text;
      pathLabel.textContent = data.path || "—";
      lineCount.textContent = `${(data.lines || []).length} 行`;
      content.scrollTop = content.scrollHeight;
    } catch {
      content.textContent = "ログの取得に失敗しました。";
    }
  }

  refreshBtn?.addEventListener("click", loadLogs);
  document.querySelectorAll('input[name="logSource"]').forEach(r => r.addEventListener("change", loadLogs));
  document.getElementById("logLines")?.addEventListener("change", loadLogs);

  autoToggle?.addEventListener("change", () => {
    clearInterval(autoTimer);
    if (autoToggle.checked) autoTimer = setInterval(loadLogs, 10000);
  });

  document.getElementById("tab-logs-tab")?.addEventListener("shown.bs.tab", loadLogs);
})();
