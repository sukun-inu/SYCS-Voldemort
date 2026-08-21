/* ウィンドウ本体。中身は iframe ではなく DOM なので、
   未保存の変更を持ったまま閉じようとしたら確認できる。 */

import { el, icon } from "../lib/dom.js";

const MIN_W = 320;
const MIN_H = 200;

const clamp = (value, min, max) => Math.max(min, Math.min(value, max));

export class AppWindow {
  constructor({ appId, title, iconName, width, height, layer, rect, manager }) {
    this.appId = appId;
    this.title = title;
    this.manager = manager;
    this.minimized = false;
    this.maximized = false;
    this.dirty = false;
    this.prevRect = null;
    /** 閉じる前に確認したいときに差し替える。false を返すと閉じない。 */
    this.beforeClose = null;
    /** 閉じたときに止めたい処理（タイマーなど）を登録する。 */
    this.cleanups = [];

    const bounds = layer.getBoundingClientRect();
    const w = clamp(rect?.w ?? width ?? 760, MIN_W, Math.max(MIN_W, bounds.width));
    const h = clamp(rect?.h ?? height ?? 620, MIN_H, Math.max(MIN_H, bounds.height));
    const x = clamp(rect?.x ?? 0, 0, Math.max(0, bounds.width - w));
    const y = clamp(rect?.y ?? 0, 0, Math.max(0, bounds.height - h));

    this.titleEl = el("span", { class: "window-title truncate", text: title });
    this.dirtyEl = el("span", { class: "window-dirty", hidden: true, title: "未保存の変更があります" }, "●");
    this.body = el("div", { class: "window-body" });

    this.el = el(
      "div",
      {
        class: "window lens",
        style: { left: `${x}px`, top: `${y}px`, width: `${w}px`, height: `${h}px` },
        dataset: { appId },
      },
      el(
        "div",
        { class: "window-titlebar", "data-specular": "" },
        icon(iconName || "bi-app", "window-icon"),
        this.titleEl,
        this.dirtyEl,
        el(
          "div",
          { class: "window-controls" },
          el("button", { class: "window-control", type: "button", title: "最小化", "aria-label": "最小化",
                         onclick: (e) => { e.stopPropagation(); this.minimize(); } }, icon("bi-dash-lg")),
          el("button", { class: "window-control maximize", type: "button", title: "最大化 / 元に戻す",
                         "aria-label": "最大化", onclick: (e) => { e.stopPropagation(); this.toggleMaximize(); } },
             icon("bi-square")),
          el("button", { class: "window-control close", type: "button", title: "閉じる", "aria-label": "閉じる",
                         onclick: (e) => { e.stopPropagation(); this.close(); } }, icon("bi-x-lg"))
        )
      ),
      this.body,
      el("div", { class: "window-resize", title: "ドラッグでリサイズ" })
    );

    layer.append(this.el);
    this.#wire();

    if (rect?.maximized || this.#isNarrow()) this.maximize({ silent: true });
    if (rect?.minimized) this.minimize({ silent: true });
  }

  #isNarrow() {
    return window.matchMedia("(max-width: 760px)").matches;
  }

  #wire() {
    this.el.addEventListener("pointerdown", () => this.focus(), true);

    const titlebar = this.el.querySelector(".window-titlebar");
    titlebar.addEventListener("dblclick", (event) => {
      if (event.target.closest(".window-controls")) return;
      this.toggleMaximize();
    });
    titlebar.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".window-controls") || this.maximized) return;
      this.#startDrag(event);
    });

    this.el.querySelector(".window-resize").addEventListener("pointerdown", (event) => {
      this.#startResize(event);
    });
  }

  #dragBounds() {
    const layer = this.el.parentElement.getBoundingClientRect();
    return { w: layer.width, h: layer.height };
  }

  #startDrag(event) {
    event.preventDefault();
    this.focus();
    this.manager.setInteracting(true);

    const startX = event.clientX;
    const startY = event.clientY;
    const startLeft = this.el.offsetLeft;
    const startTop = this.el.offsetTop;
    const { w, h } = this.#dragBounds();

    const onMove = (e) => {
      this.el.style.left = `${clamp(startLeft + e.clientX - startX, 0, Math.max(0, w - this.el.offsetWidth))}px`;
      this.el.style.top = `${clamp(startTop + e.clientY - startY, 0, Math.max(0, h - this.el.offsetHeight))}px`;
    };
    const onUp = () => {
      this.manager.setInteracting(false);
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      this.manager.persist();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  #startResize(event) {
    event.preventDefault();
    event.stopPropagation();
    this.focus();
    this.manager.setInteracting(true);

    const startX = event.clientX;
    const startY = event.clientY;
    const startW = this.el.offsetWidth;
    const startH = this.el.offsetHeight;
    const { w, h } = this.#dragBounds();

    const onMove = (e) => {
      this.el.style.width = `${clamp(startW + e.clientX - startX, MIN_W, w - this.el.offsetLeft)}px`;
      this.el.style.height = `${clamp(startH + e.clientY - startY, MIN_H, h - this.el.offsetTop)}px`;
    };
    const onUp = () => {
      this.manager.setInteracting(false);
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      this.manager.persist();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  #setMaximizeIcon(name) {
    const button = this.el.querySelector(".maximize");
    button.replaceChildren(icon(name));
  }

  focus() {
    this.manager.focus(this);
  }

  setDirty(dirty) {
    this.dirty = dirty;
    this.dirtyEl.hidden = !dirty;
    this.manager.updateTaskbar();
  }

  setTitle(title) {
    this.title = title;
    this.titleEl.textContent = title;
    this.manager.updateTaskbar();
  }

  minimize({ silent = false } = {}) {
    this.minimized = true;
    this.el.classList.add("is-minimized");
    if (!silent) this.manager.afterMinimize(this);
    this.manager.updateTaskbar();
    this.manager.persist();
  }

  restore() {
    this.minimized = false;
    this.el.classList.remove("is-minimized");
    this.focus();
    this.manager.persist();
  }

  maximize({ silent = false } = {}) {
    if (!this.maximized) {
      this.prevRect = {
        left: this.el.style.left,
        top: this.el.style.top,
        width: this.el.style.width,
        height: this.el.style.height,
      };
    }
    this.maximized = true;
    this.el.classList.add("is-maximized");
    this.#setMaximizeIcon("copy");
    if (!silent) this.focus();
    this.manager.persist();
  }

  unmaximize() {
    this.maximized = false;
    this.el.classList.remove("is-maximized");
    this.#setMaximizeIcon("square");
    if (this.prevRect) Object.assign(this.el.style, this.prevRect);
    this.focus();
    this.manager.persist();
  }

  toggleMaximize() {
    this.maximized ? this.unmaximize() : this.maximize();
  }

  async close({ force = false } = {}) {
    if (!force && typeof this.beforeClose === "function") {
      const proceed = await this.beforeClose();
      if (!proceed) return false;
    }
    for (const cleanup of this.cleanups) {
      try {
        cleanup();
      } catch (error) {
        console.error(error);
      }
    }
    this.cleanups = [];
    this.el.remove();
    this.manager.afterClose(this);
    return true;
  }

  addCleanup(fn) {
    this.cleanups.push(fn);
  }

  geometry() {
    return {
      appId: this.appId,
      x: this.el.offsetLeft,
      y: this.el.offsetTop,
      w: this.el.offsetWidth,
      h: this.el.offsetHeight,
      maximized: this.maximized,
      minimized: this.minimized,
    };
  }
}
