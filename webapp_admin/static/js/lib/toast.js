/* 操作結果の通知。保存の成否はここで伝える（サーバ側 flash の置き換え）。

   デスクトップでは、この「器」自体が液体ガラスの板になる。ライブラリは
   初期化後にガラス要素を足せないため、器は常設して中身だけ入れ替える。
   中身が増減したら toast:changed を投げ、ガラス側に描き直させる。 */

import { el, icon } from "./dom.js";

const ICONS = {
  success: "bi-check-circle-fill",
  danger: "bi-exclamation-circle-fill",
  info: "bi-info-circle-fill",
};

/** 器を用意する。デスクトップではガラスのルート直下に置く必要がある。 */
export function ensureToastStack() {
  let node = document.querySelector(".toast-stack");
  if (!node) {
    node = el("div", { class: "toast-stack", "aria-live": "polite" });
    const mount = document.getElementById("window-layer") || document.body;
    mount.append(node);
  }
  return node;
}

function sync(node) {
  node.classList.toggle("has-toasts", node.childElementCount > 0);
  node.dispatchEvent(new CustomEvent("toast:changed", { bubbles: true }));
}

export function toast(message, variant = "info", { duration = 4000 } = {}) {
  const stack = ensureToastStack();

  const node = el(
    "div",
    { class: `toast ${variant}`, role: "status" },
    icon(ICONS[variant] || ICONS.info),
    el("div", { class: "grow", text: message }),
    el(
      "button",
      {
        class: "btn btn-quiet btn-sm toast-close",
        type: "button",
        "aria-label": "閉じる",
        onclick: () => remove(),
      },
      icon("bi-x")
    )
  );

  function remove() {
    if (!node.isConnected) return;
    node.remove();
    sync(stack);
  }

  stack.append(node);
  sync(stack);

  if (duration > 0) window.setTimeout(remove, duration);
  return node;
}
