/* ウィンドウ本体。中身は iframe ではなく DOM なので、
   未保存の変更を持ったまま閉じようとしたら確認できる。 */

import { el, icon } from "../lib/dom.js";
import { DUR, EASE_IN, EASE_OUT, deltaTransform, play, stopAnimations } from "../lib/motion.js";

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
    /** 最大化・最小化していないときの矩形。保存と「元に戻す」の行き先になる。
        最小化中は display:none で offsetWidth が 0 になるため、実測は使えない。 */
    this.normalRect = null;
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
             icon("bi-fullscreen")),
          el("button", { class: "window-control close", type: "button", title: "閉じる", "aria-label": "閉じる",
                         onclick: (e) => { e.stopPropagation(); this.close(); } }, icon("bi-x-lg"))
        )
      ),
      this.body,
      el("div", {
        class: "window-resize",
        title: "ドラッグでリサイズ（矢印キーでも変えられます）",
        // マウス以外でも大きさを変えられるようにする。最大化・最小化は
        // ボタンで押せるが、任意の大きさにする手段がドラッグしか無かった。
        tabindex: "0",
        role: "slider",
        "aria-label": "ウィンドウの大きさ",
      })
    );

    layer.append(this.el);
    this.#remember();
    this.#wire();

    if (rect?.maximized || this.#isNarrow()) this.maximize({ silent: true, animate: false });
    if (rect?.minimized) this.minimize({ silent: true, animate: false });
  }

  #isNarrow() {
    return window.matchMedia("(max-width: 760px)").matches;
  }

  /** いまの見た目の矩形を「通常時の姿」として覚える。 */
  #remember() {
    if (this.maximized || this.minimized) return;
    this.normalRect = {
      x: this.el.offsetLeft,
      y: this.el.offsetTop,
      w: this.el.offsetWidth,
      h: this.el.offsetHeight,
    };
  }

  /** タスクバーのピルへ吸い込む / から出てくる変形。ピルが無ければその場で縮む。 */
  #pillTransform() {
    const from = this.el.getBoundingClientRect();
    const pill = this.pill?.getBoundingClientRect();
    if (!from.width || !pill?.width) return "scale(.9)";
    const dx = pill.left + pill.width / 2 - (from.left + from.width / 2);
    const dy = pill.top + pill.height / 2 - (from.top + from.height / 2);
    return `translate(${dx}px, ${dy}px) scale(.12)`;
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

    const grip = this.el.querySelector(".window-resize");
    grip.addEventListener("pointerdown", (event) => {
      this.#startResize(event);
    });
    grip.addEventListener("keydown", (event) => this.#resizeByKey(event));
  }

  /** 矢印キーでの大きさ変更。Shift で粗く動かす。
   *
   *  つまみは pointerdown だけで動いていたので、キーボードだけの利用者は
   *  ウィンドウを任意の大きさにできなかった（最大化・最小化はボタンで
   *  できる）。フェーダーやパンつまみと同じ扱いに揃える。 */
  #resizeByKey(event) {
    const STEP = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    const move = STEP[event.key];
    if (!move) return;
    event.preventDefault();

    const amount = event.shiftKey ? 48 : 12;
    const { w, h } = this.#dragBounds();
    this.el.style.width =
      `${clamp(this.el.offsetWidth + move[0] * amount, MIN_W, Math.max(MIN_W, w - this.el.offsetLeft))}px`;
    this.el.style.height =
      `${clamp(this.el.offsetHeight + move[1] * amount, MIN_H, Math.max(MIN_H, h - this.el.offsetTop))}px`;
    this.#remember();
    this.manager.persist();
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
      this.#remember();
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
      this.#remember();
      this.manager.persist();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  /** 最大化/復帰の切り替えを、対のアイコンで示す。
      名前は "bi-" 付きで渡すこと（tools/build_icon_sprite.py がこの書式で
      参照を集めるため、接頭辞が無いとスプライトに含まれず無言で消える）。 */
  #setMaximizeIcon(name) {
    const button = this.el.querySelector(".maximize");
    button.replaceChildren(icon(name));
    button.title = name === "bi-fullscreen-exit" ? "元のサイズに戻す" : "最大化";
    button.setAttribute("aria-label", button.title);
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

  async minimize({ silent = false, animate = true } = {}) {
    if (this.minimized) return;
    this.#remember();
    if (animate) {
      stopAnimations(this.el);
      // タスクバーのピルへ吸い込んでから消す。先に display:none にすると行き先が測れない
      await play(this.el, [{ transform: "none", opacity: 1 },
                           { transform: this.#pillTransform(), opacity: 0 }],
                 { duration: DUR.move, easing: EASE_IN });
      stopAnimations(this.el);
    }
    this.minimized = true;
    this.el.classList.add("is-minimized");
    if (!silent) this.manager.afterMinimize(this);
    this.manager.updateTaskbar();
    this.manager.persist();
  }

  restore() {
    if (!this.minimized) return;
    this.minimized = false;
    this.el.classList.remove("is-minimized");
    stopAnimations(this.el);
    play(this.el, [{ transform: this.#pillTransform(), opacity: 0 },
                   { transform: "none", opacity: 1 }],
         { duration: DUR.move, easing: EASE_OUT });
    this.focus();
    this.manager.persist();
  }

  maximize({ silent = false, animate = true } = {}) {
    this.#remember();
    this.maximized = true;
    this.#resize(() => this.el.classList.add("is-maximized"), animate);
    this.#setMaximizeIcon("bi-fullscreen-exit");
    if (!silent) this.focus();
    this.manager.persist();
  }

  unmaximize({ animate = true } = {}) {
    this.maximized = false;
    this.#resize(() => {
      this.el.classList.remove("is-maximized");
      const rect = this.normalRect;
      if (rect) {
        Object.assign(this.el.style, {
          left: `${rect.x}px`, top: `${rect.y}px`,
          width: `${rect.w}px`, height: `${rect.h}px`,
        });
      }
    }, animate);
    this.#setMaximizeIcon("bi-fullscreen");
    this.focus();
    this.manager.persist();
  }

  /** 大きさが変わる操作を、変化前後の矩形を測って滑らかにつなぐ（FLIP）。 */
  #resize(apply, animate) {
    if (!animate) {
      apply();
      return;
    }
    const from = this.el.getBoundingClientRect();
    stopAnimations(this.el);
    apply();
    const to = this.el.getBoundingClientRect();
    if (!to.width || !to.height) return;
    play(this.el, [{ transform: deltaTransform(from, to), transformOrigin: "top left" },
                   { transform: "none", transformOrigin: "top left" }],
         { duration: DUR.move, easing: EASE_OUT });
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
    stopAnimations(this.el);
    await play(this.el, [{ transform: "none", opacity: 1 },
                         { transform: "scale(.94) translateY(8px)", opacity: 0 }],
               { duration: DUR.base, easing: EASE_IN });
    this.el.remove();
    this.manager.afterClose(this);
    return true;
  }

  addCleanup(fn) {
    this.cleanups.push(fn);
  }

  /** 保存する配置。最大化・最小化中は実測が使えないので、通常時の矩形を返す
      （最小化中は display:none で 0×0、最大化中は画面いっぱいになるため）。 */
  geometry() {
    this.#remember();
    const rect = this.normalRect || { x: 0, y: 0, w: MIN_W, h: MIN_H };
    return {
      appId: this.appId,
      x: rect.x,
      y: rect.y,
      w: rect.w,
      h: rect.h,
      maximized: this.maximized,
      minimized: this.minimized,
    };
  }
}
