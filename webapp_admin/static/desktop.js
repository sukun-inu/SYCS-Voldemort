'use strict';

/* ============================================================
   SYCS Voldemort — Desktop window manager
   各ウィンドウの中身は既存のページをそのまま <iframe> で読み込む。
   埋め込み判定はサーバー側で Sec-Fetch-Dest: iframe ヘッダから行うため、
   ここでは通常の URL をそのまま渡すだけでよい。
   ============================================================ */

(function () {
  const desktop = document.getElementById('desktop');
  const windowLayer = document.getElementById('windowLayer');
  const taskbarApps = document.getElementById('taskbarApps');
  if (!desktop || !windowLayer || !taskbarApps) return;

  const MIN_W = 320;
  const MIN_H = 220;

  /** @type {Map<string, {el: HTMLElement, pillEl: HTMLElement, appId: string, minimized: boolean, maximized: boolean, prevRect: object|null}>} */
  const windows = new Map();
  const windowByApp = new Map();
  let zCounter = 10;
  let focusedId = null;
  let seq = 0;

  function clamp(v, min, max) { return Math.max(min, Math.min(v, max)); }

  function desktopSize() {
    const rect = desktop.getBoundingClientRect();
    return { w: rect.width, h: rect.height };
  }

  function defaultRect(index) {
    const { w: dw, h: dh } = desktopSize();
    const w = clamp(Math.round(dw * 0.62), MIN_W, 900);
    const h = clamp(Math.round(dh * 0.72), MIN_H, 680);
    const offset = (index % 8) * 26;
    const x = clamp(60 + offset, 0, Math.max(0, dw - w));
    const y = clamp(30 + offset, 0, Math.max(0, dh - h));
    return { x, y, w, h };
  }

  function isMobile() {
    return window.matchMedia('(max-width: 760px)').matches;
  }

  function openWindow({ id, title, icon, url }) {
    // 同じアプリが既に開いていればそれをフォーカス/復元するだけにする（多重起動しない）
    const existing = windowByApp.get(id);
    if (existing && windows.has(existing)) {
      restoreAndFocus(existing);
      closeStartMenu();
      return;
    }

    const winId = `win-${++seq}`;
    const rect = defaultRect(windows.size);

    const el = document.createElement('div');
    el.className = 'app-window';
    el.dataset.winId = winId;
    el.style.left = `${rect.x}px`;
    el.style.top = `${rect.y}px`;
    el.style.width = `${rect.w}px`;
    el.style.height = `${rect.h}px`;

    el.innerHTML = `
      <div class="window-titlebar">
        <i class="bi ${icon} window-icon"></i>
        <span class="window-title"></span>
        <div class="window-controls">
          <button type="button" class="window-control-btn window-minimize" aria-label="最小化" title="最小化"><i class="bi bi-dash-lg"></i></button>
          <button type="button" class="window-control-btn window-maximize" aria-label="最大化" title="最大化/元に戻す"><i class="bi bi-square"></i></button>
          <button type="button" class="window-control-btn window-close" aria-label="閉じる" title="閉じる"><i class="bi bi-x-lg"></i></button>
        </div>
      </div>
      <div class="window-body">
        <div class="window-loading"><span class="spinner-border spinner-border-sm"></span>読み込み中…</div>
        <iframe src="${url}" title="${title}" loading="eager"></iframe>
      </div>
      <div class="window-resize-handle" title="ドラッグでリサイズ"></div>
    `;
    el.querySelector('.window-title').textContent = title;

    const iframe = el.querySelector('iframe');
    const body = el.querySelector('.window-body');
    iframe.addEventListener('load', () => body.classList.add('is-loaded'), { once: true });

    windowLayer.appendChild(el);

    const pillEl = document.createElement('button');
    pillEl.type = 'button';
    pillEl.className = 'taskbar-app';
    pillEl.innerHTML = `<i class="bi ${icon}"></i><span></span>`;
    pillEl.querySelector('span').textContent = title;
    pillEl.addEventListener('click', () => toggleMinimizeOrFocus(winId));
    taskbarApps.appendChild(pillEl);

    windows.set(winId, { el, pillEl, appId: id, minimized: false, maximized: false, prevRect: null });
    windowByApp.set(id, winId);

    wireWindowChrome(winId);
    if (isMobile()) maximizeWindow(winId, { silent: true });
    focusWindow(winId);
    closeStartMenu();
  }

  function wireWindowChrome(winId) {
    const w = windows.get(winId);
    if (!w) return;
    const { el } = w;

    el.addEventListener('pointerdown', () => focusWindow(winId));
    el.querySelector('.window-close').addEventListener('click', (e) => { e.stopPropagation(); closeWindow(winId); });
    el.querySelector('.window-minimize').addEventListener('click', (e) => { e.stopPropagation(); minimizeWindow(winId); });
    el.querySelector('.window-maximize').addEventListener('click', (e) => {
      e.stopPropagation();
      w.maximized ? restoreWindow(winId) : maximizeWindow(winId);
    });

    const titlebar = el.querySelector('.window-titlebar');
    titlebar.addEventListener('dblclick', (e) => {
      if (e.target.closest('.window-controls')) return;
      w.maximized ? restoreWindow(winId) : maximizeWindow(winId);
    });
    titlebar.addEventListener('pointerdown', (e) => {
      if (e.target.closest('.window-controls') || w.maximized) return;
      startDrag(winId, e);
    });

    const handle = el.querySelector('.window-resize-handle');
    handle.addEventListener('pointerdown', (e) => startResize(winId, e));
  }

  function startDrag(winId, ev) {
    const w = windows.get(winId);
    if (!w) return;
    ev.preventDefault();
    focusWindow(winId);
    desktop.classList.add('is-interacting');

    const { el } = w;
    const startX = ev.clientX;
    const startY = ev.clientY;
    const startLeft = el.offsetLeft;
    const startTop = el.offsetTop;
    const { w: dw, h: dh } = desktopSize();

    function onMove(e) {
      const nx = clamp(startLeft + (e.clientX - startX), -el.offsetWidth + 80, dw - 80);
      const ny = clamp(startTop + (e.clientY - startY), 0, dh - 32);
      el.style.left = `${nx}px`;
      el.style.top = `${ny}px`;
    }
    function onUp() {
      desktop.classList.remove('is-interacting');
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
    }
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
  }

  function startResize(winId, ev) {
    const w = windows.get(winId);
    if (!w) return;
    ev.preventDefault();
    ev.stopPropagation();
    focusWindow(winId);
    desktop.classList.add('is-interacting');

    const { el } = w;
    const startX = ev.clientX;
    const startY = ev.clientY;
    const startW = el.offsetWidth;
    const startH = el.offsetHeight;
    const { w: dw, h: dh } = desktopSize();

    function onMove(e) {
      const nw = clamp(startW + (e.clientX - startX), MIN_W, dw - el.offsetLeft);
      const nh = clamp(startH + (e.clientY - startY), MIN_H, dh - el.offsetTop);
      el.style.width = `${nw}px`;
      el.style.height = `${nh}px`;
    }
    function onUp() {
      desktop.classList.remove('is-interacting');
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
    }
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
  }

  function focusWindow(winId) {
    const w = windows.get(winId);
    if (!w || w.minimized) return;
    zCounter += 1;
    w.el.style.zIndex = String(zCounter);
    windows.forEach((other, id) => {
      other.el.classList.toggle('is-focused', id === winId);
      other.pillEl.classList.toggle('is-active', id === winId && !other.minimized);
    });
    focusedId = winId;
  }

  function restoreAndFocus(winId) {
    const w = windows.get(winId);
    if (!w) return;
    if (w.minimized) {
      w.minimized = false;
      w.el.classList.remove('is-minimized');
      w.pillEl.classList.remove('is-minimized');
    }
    focusWindow(winId);
  }

  function toggleMinimizeOrFocus(winId) {
    const w = windows.get(winId);
    if (!w) return;
    if (w.minimized) {
      restoreAndFocus(winId);
    } else if (focusedId === winId) {
      minimizeWindow(winId);
    } else {
      focusWindow(winId);
    }
  }

  function minimizeWindow(winId) {
    const w = windows.get(winId);
    if (!w) return;
    w.minimized = true;
    w.el.classList.add('is-minimized');
    w.pillEl.classList.add('is-minimized');
    w.pillEl.classList.remove('is-active');
    if (focusedId === winId) {
      focusedId = null;
      const next = [...windows.keys()].reverse().find((id) => !windows.get(id).minimized && id !== winId);
      if (next) focusWindow(next);
    }
  }

  function minimizeAll() {
    windows.forEach((_, id) => minimizeWindow(id));
  }
  window.desktopMinimizeAll = minimizeAll;

  function maximizeWindow(winId, opts = {}) {
    const w = windows.get(winId);
    if (!w) return;
    if (!w.maximized) {
      w.prevRect = { left: w.el.style.left, top: w.el.style.top, width: w.el.style.width, height: w.el.style.height };
    }
    w.maximized = true;
    w.el.classList.add('is-maximized');
    w.el.querySelector('.window-maximize i').className = 'bi bi-copy';
    if (!opts.silent) focusWindow(winId);
  }

  function restoreWindow(winId) {
    const w = windows.get(winId);
    if (!w) return;
    w.maximized = false;
    w.el.classList.remove('is-maximized');
    w.el.querySelector('.window-maximize i').className = 'bi bi-square';
    if (w.prevRect) {
      Object.assign(w.el.style, w.prevRect);
    }
    focusWindow(winId);
  }

  function closeWindow(winId) {
    const w = windows.get(winId);
    if (!w) return;
    w.el.remove();
    w.pillEl.remove();
    windows.delete(winId);
    if (windowByApp.get(w.appId) === winId) windowByApp.delete(w.appId);
    if (focusedId === winId) {
      focusedId = null;
      const next = [...windows.keys()].reverse().find((id) => !windows.get(id).minimized);
      if (next) focusWindow(next);
    }
  }

  /* ── アプリタイル → openWindow ── */
  document.querySelectorAll('.app-tile').forEach((tile) => {
    tile.addEventListener('click', () => {
      openWindow({
        id: tile.dataset.appId,
        title: tile.dataset.appTitle,
        icon: tile.dataset.appIcon,
        url: tile.dataset.appUrl,
      });
    });
  });

  /* ── スタートメニュー開閉 ── */
  const startButton = document.getElementById('startButton');
  const startMenu = document.getElementById('startMenu');
  const startMenuBackdrop = document.getElementById('startMenuBackdrop');
  const startMenuSearch = document.getElementById('startMenuSearch');

  function openStartMenu() {
    startMenu.hidden = false;
    startMenuBackdrop.hidden = false;
    startButton.setAttribute('aria-expanded', 'true');
    startMenuSearch.value = '';
    filterStartMenu('');
    startMenuSearch.focus();
  }
  function closeStartMenu() {
    startMenu.hidden = true;
    startMenuBackdrop.hidden = true;
    startButton.setAttribute('aria-expanded', 'false');
  }
  window.closeStartMenu = closeStartMenu;

  startButton?.addEventListener('click', () => {
    startMenu.hidden ? openStartMenu() : closeStartMenu();
  });
  startMenuBackdrop?.addEventListener('click', closeStartMenu);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeStartMenu();
  });

  function filterStartMenu(query) {
    const q = query.trim().toLowerCase();
    document.querySelectorAll('.start-menu-group').forEach((group) => {
      let visibleCount = 0;
      group.querySelectorAll('.app-tile').forEach((tile) => {
        const match = !q || tile.dataset.appTitle.toLowerCase().includes(q);
        tile.classList.toggle('dt-row-hidden', !match);
        if (match) visibleCount += 1;
      });
      group.style.display = visibleCount === 0 ? 'none' : '';
    });
  }
  startMenuSearch?.addEventListener('input', () => filterStartMenu(startMenuSearch.value));

  /* ── タスクバー時計 ── */
  const clockEl = document.getElementById('taskbarClock');
  function updateClock() {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' });
  }
  updateClock();
  setInterval(updateClock, 10000);

  /* ── 通知ベル: 監視履歴カウントをミラーし、クリックで全ウィンドウ最小化(デスクトップを表示) ── */
  const notifyButton = document.getElementById('notifyButton');
  const notifyBadge = document.getElementById('notifyBadge');
  const incidentsCountEl = document.querySelector('[data-incidents-count]');
  if (incidentsCountEl && notifyBadge) {
    const syncBadge = () => {
      const n = parseInt(incidentsCountEl.textContent, 10);
      if (Number.isFinite(n) && n > 0) {
        notifyBadge.textContent = n > 99 ? '99+' : String(n);
        notifyBadge.hidden = false;
      } else {
        notifyBadge.hidden = true;
      }
    };
    new MutationObserver(syncBadge).observe(incidentsCountEl, { childList: true, characterData: true, subtree: true });
    syncBadge();
  }
  notifyButton?.addEventListener('click', () => {
    minimizeAll();
    closeStartMenu();
  });

  /* ── ウィンドウリサイズ時、デスクトップ外にはみ出したウィンドウを引き戻す ── */
  window.addEventListener('resize', () => {
    const { w: dw, h: dh } = desktopSize();
    windows.forEach((w) => {
      if (w.maximized) return;
      const el = w.el;
      const left = clamp(el.offsetLeft, 0, Math.max(0, dw - 80));
      const top = clamp(el.offsetTop, 0, Math.max(0, dh - 32));
      el.style.left = `${left}px`;
      el.style.top = `${top}px`;
    });
  });
})();
