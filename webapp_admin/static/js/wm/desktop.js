/* ウィンドウマネージャ本体。
   ウィンドウの開閉・重なり順・タスクバー・スタートメニュー・配置の保存を持つ。
   中身の描画は forms/panel.js に委ねる。 */

import { el, icon, clear } from "../lib/dom.js";
import { DUR, EASE_IN, play, stopAnimations } from "../lib/motion.js";
import { AppWindow } from "./window.js";
import { mountPanel } from "../forms/panel.js";

const LAYOUT_KEY = "voldemort.desktop.layout.v1";

export class Desktop {
  /** 閉じる動きの世代。開き直されたときに、古い動きの後始末で隠さないための番号。 */
  static #menuTicket = 0;

  constructor({ groups }) {
    this.groups = groups;
    this.windows = new Map();
    this.zIndex = 10;
    this.focused = null;

    this.root = document.getElementById("desktop");
    this.layer = document.getElementById("window-layer");
    this.taskbarApps = document.getElementById("taskbar-apps");
    this.startButton = document.getElementById("start-button");
    this.startMenu = document.getElementById("start-menu");
    this.startSearch = document.getElementById("start-search");
    this.startGroups = document.getElementById("start-groups");

    this.apps = new Map();
    for (const group of groups) {
      for (const app of group.apps) this.apps.set(app.id, app);
    }

    this.#buildStartMenu();
    this.#wireStartMenu();
    this.#wireClock();
    this.#wireUserMenu();
    this.#wireResize();
  }

  /* ── アプリを開く ─────────────────────────────────────── */

  async open(appId, rect = null) {
    const app = this.apps.get(appId);
    if (!app) return null;

    const existing = this.windows.get(appId);
    if (existing) {
      if (existing.minimized) existing.restore();
      else existing.focus();
      this.closeStartMenu();
      return existing;
    }

    const win = new AppWindow({
      appId: app.id,
      title: app.title,
      iconName: app.icon,
      width: app.window?.w,
      height: app.window?.h,
      rect: rect || this.#cascadeRect(app),
      layer: this.layer,
      manager: this,
    });

    this.windows.set(appId, win);
    this.#addTaskbarPill(win, app);
    this.focus(win);
    this.closeStartMenu();
    this.root.classList.add("has-windows");
    this.#syncHash();
    this.persist();

    mountPanel(win, app).catch((error) => {
      console.error(error);
      clear(win.body).append(
        el("div", { class: "empty" }, `画面を読み込めませんでした（${error.message}）`)
      );
    });

    return win;
  }

  #cascadeRect(app) {
    const bounds = this.layer.getBoundingClientRect();
    const w = Math.min(app.window?.w || 760, Math.max(320, bounds.width - 40));
    const h = Math.min(app.window?.h || 620, Math.max(200, bounds.height - 40));
    const offset = (this.windows.size % 8) * 26;
    return {
      x: Math.max(0, Math.min(40 + offset, bounds.width - w)),
      y: Math.max(0, Math.min(24 + offset, bounds.height - h)),
      w,
      h,
    };
  }

  /* ── 重なり順とフォーカス ─────────────────────────────── */

  focus(win) {
    if (!win || win.minimized) return;
    this.zIndex += 1;
    win.el.style.zIndex = String(this.zIndex);
    this.focused = win;
    for (const other of this.windows.values()) {
      other.el.classList.toggle("is-focused", other === win);
    }
    this.updateTaskbar();
    this.#syncHash();
  }

  focusNext(exclude = null) {
    // 開いた順ではなく重なり順で選ぶ。閉じた直後は、いちばん手前の窓が前に出る。
    const candidates = [...this.windows.values()]
      .filter((w) => !w.minimized && w !== exclude)
      .sort((a, b) => Number(a.el.style.zIndex || 0) - Number(b.el.style.zIndex || 0));
    if (candidates.length) this.focus(candidates[candidates.length - 1]);
    else {
      this.focused = null;
      this.#syncHash();
    }
  }

  afterMinimize(win) {
    if (this.focused === win) this.focusNext(win);
  }

  afterClose(win) {
    this.windows.delete(win.appId);
    const pill = win.pill;
    if (pill) {
      pill.style.pointerEvents = "none";
      play(pill, [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "scale(.85)" }],
           { duration: DUR.fast, easing: EASE_IN }).then(() => pill.remove());
    }
    if (this.focused === win) this.focusNext(win);
    this.root.classList.toggle("has-windows", this.windows.size > 0);
    this.updateTaskbar();
    this.persist();
  }

  setInteracting(active) {
    this.root.classList.toggle("is-interacting", active);
  }

  /* ── タスクバー ───────────────────────────────────────── */

  #addTaskbarPill(win, app) {
    const pill = el(
      "button",
      {
        class: "taskbar-app",
        type: "button",
        onclick: () => {
          if (win.minimized) win.restore();
          else if (this.focused === win) win.minimize();
          else win.focus();
        },
      },
      icon(app.icon),
      el("span", { text: app.title })
    );
    win.pill = pill;
    this.taskbarApps.append(pill);
  }

  updateTaskbar() {
    for (const win of this.windows.values()) {
      if (!win.pill) continue;
      const active = this.focused === win && !win.minimized;
      // 狭い画面ではピルの帯が横スクロールする。今使っているウィンドウの
      // ピルが画面外にいると押せないので、見える位置まで送る。
      if (active && !win.pill.classList.contains("is-active")) {
        win.pill.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
      win.pill.classList.toggle("is-active", active);
      win.pill.classList.toggle("is-minimized", win.minimized);
      const label = win.pill.querySelector("span");
      label.textContent = win.dirty ? `${win.title} ●` : win.title;
    }
  }

  /* ── スタートメニュー ─────────────────────────────────── */

  #buildStartMenu() {
    clear(this.startGroups);
    let index = 0;
    for (const group of this.groups) {
      this.startGroups.append(
        el(
          "div",
          { class: "start-group" },
          el("p", { class: "start-group-label", text: group.label }),
          el(
            "div",
            { class: "start-tiles" },
            group.apps.map((app) => {
              const tile = el(
                "button",
                {
                  class: "app-tile",
                  type: "button",
                  dataset: { appId: app.id, appTitle: app.title },
                  onclick: () => this.open(app.id),
                },
                el(
                  "span",
                  { class: "app-tile-icon" },
                  icon(app.icon),
                  app.badge ? el("span", { class: "app-tile-badge", text: String(app.badge) }) : null
                ),
                el("span", { text: app.title })
              );
              // 開くときに左上から順に立ち上がる（motion.css がこの値を遅延に使う）
              tile.style.setProperty("--i", String(index++));
              return tile;
            })
          )
        )
      );
    }
    this.emptyEl = el("p", { class: "start-empty", text: "一致するアプリがありません。", hidden: true });
    this.startGroups.append(this.emptyEl);
  }

  #wireStartMenu() {
    this.startButton.addEventListener("click", () => {
      this.#isOpen(this.startMenu) ? this.closeStartMenu() : this.openStartMenu();
    });
    this.startSearch.addEventListener("input", () => this.#filterStartMenu(this.startSearch.value));
    document.addEventListener("keydown", (event) => {
      // 開いているものを閉じる。スタートだけでなくユーザーメニューも対象にする
      if (event.key !== "Escape") return;
      this.closeStartMenu();
      this.closeUserMenu();
    });
  }

  /** 閉じる動きの最中は「開いている」とは数えない（押し直しで開き直せるように）。 */
  #isOpen(node) {
    return !node.hidden && !node.classList.contains("is-closing");
  }

  #showMenu(node) {
    stopAnimations(node);
    node.classList.remove("is-closing");
    node.dataset.closing = "";
    node.hidden = false;
  }

  /** 消える動きを見せてから hidden にする。途中で開き直されたら隠さない。 */
  #hideMenu(node) {
    if (node.hidden || node.classList.contains("is-closing")) return;
    const token = String(++Desktop.#menuTicket);
    node.dataset.closing = token;
    node.classList.add("is-closing");
    play(node, [{ opacity: 1, transform: "none" },
                { opacity: 0, transform: "translateY(8px) scale(.98)" }],
         { duration: DUR.fast, easing: EASE_IN }).then(() => {
      if (node.dataset.closing !== token) return;
      node.hidden = true;
      node.classList.remove("is-closing");
    });
  }

  openStartMenu() {
    this.#showMenu(this.startMenu);
    this.startButton.setAttribute("aria-expanded", "true");
    this.startSearch.value = "";
    this.#filterStartMenu("");
    this.startSearch.focus();
    this.#openBackdrop(() => this.closeStartMenu());
  }

  closeStartMenu() {
    this.#hideMenu(this.startMenu);
    this.startButton.setAttribute("aria-expanded", "false");
    this.#closeBackdrop();
  }

  #filterStartMenu(query) {
    const q = query.trim().toLowerCase();
    let visible = 0;
    for (const group of this.startGroups.querySelectorAll(".start-group")) {
      let shown = 0;
      for (const tile of group.querySelectorAll(".app-tile")) {
        const match = !q || tile.dataset.appTitle.toLowerCase().includes(q);
        tile.hidden = !match;
        if (match) shown += 1;
      }
      group.hidden = shown === 0;
      visible += shown;
    }
    this.emptyEl.hidden = visible > 0;
  }

  /* ── ユーザーメニュー ─────────────────────────────────── */

  #wireUserMenu() {
    const button = document.getElementById("user-button");
    const menu = document.getElementById("user-menu");
    if (!button || !menu) return;
    this.userButton = button;
    this.userMenu = menu;
    button.addEventListener("click", () => {
      if (this.#isOpen(menu)) {
        this.closeUserMenu();
        return;
      }
      const rect = button.getBoundingClientRect();
      menu.style.right = `${Math.max(8, window.innerWidth - rect.right)}px`;
      menu.style.bottom = `${window.innerHeight - rect.top + 8}px`;
      this.#showMenu(menu);
      button.setAttribute("aria-expanded", "true");
      this.#openBackdrop(() => this.closeUserMenu());
    });
  }

  closeUserMenu() {
    if (!this.userMenu) return;
    this.#hideMenu(this.userMenu);
    this.userButton?.setAttribute("aria-expanded", "false");
    this.#closeBackdrop();
  }

  #openBackdrop(onClose) {
    this.#closeBackdrop();
    this.backdrop = el("div", { class: "menu-backdrop", onclick: () => { onClose(); this.#closeBackdrop(); } });
    document.body.append(this.backdrop);
  }

  #closeBackdrop() {
    this.backdrop?.remove();
    this.backdrop = null;
  }

  /* ── 時計 ─────────────────────────────────────────────── */

  #wireClock() {
    const clock = document.getElementById("taskbar-clock");
    if (!clock) return;
    const tick = () => {
      const now = new Date();
      clock.textContent = now.toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit" });
      // 分が変わった瞬間に合わせて次を予約する（一定間隔だと最大その分だけ遅れて見える）
      const delay = 60000 - (now.getSeconds() * 1000 + now.getMilliseconds());
      window.setTimeout(tick, Math.max(1000, delay));
    };
    tick();
  }

  #wireResize() {
    window.addEventListener("resize", () => {
      const bounds = this.layer.getBoundingClientRect();
      for (const win of this.windows.values()) {
        if (win.maximized) continue;
        win.el.style.left = `${Math.max(0, Math.min(win.el.offsetLeft, bounds.width - 80))}px`;
        win.el.style.top = `${Math.max(0, Math.min(win.el.offsetTop, bounds.height - 32))}px`;
      }
    });
  }

  /* ── 配置の保存と復元（端末ごと） ─────────────────────── */

  persist() {
    try {
      const layout = [...this.windows.values()].map((win) => win.geometry());
      window.localStorage.setItem(LAYOUT_KEY, JSON.stringify({ v: 1, windows: layout }));
    } catch {
      /* プライベートウィンドウなど保存できない環境では諦める */
    }
  }

  static loadLayout() {
    try {
      const raw = window.localStorage.getItem(LAYOUT_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed?.windows) ? parsed.windows : [];
    } catch {
      return [];
    }
  }

  async restore(layout) {
    for (const rect of layout) {
      if (!this.apps.has(rect.appId)) continue;
      await this.open(rect.appId, rect);
    }
  }

  /* ── ディープリンク（#tts で TTS を開く） ─────────────── */

  #syncHash() {
    const id = this.focused?.appId;
    const next = id ? `#${id}` : "";
    if (window.location.hash !== next) {
      window.history.replaceState(null, "", window.location.pathname + next);
    }
  }
}
