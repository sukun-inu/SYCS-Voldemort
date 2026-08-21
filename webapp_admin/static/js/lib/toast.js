/* 操作結果の通知。保存の成否はここで伝える（サーバ側 flash の置き換え）。 */

import { el, icon } from "./dom.js";

const ICONS = {
  success: "bi-check-circle-fill",
  danger: "bi-exclamation-circle-fill",
  info: "bi-info-circle-fill",
};

function stack() {
  let node = document.querySelector(".toast-stack");
  if (!node) {
    node = el("div", { class: "toast-stack", "aria-live": "polite" });
    document.body.append(node);
  }
  return node;
}

export function toast(message, variant = "info", { duration = 4000 } = {}) {
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
        onclick: () => node.remove(),
      },
      icon("bi-x")
    )
  );

  stack().append(node);
  if (duration > 0) window.setTimeout(() => node.remove(), duration);
  return node;
}
