/* ウィンドウ内タブ。項目の多いパネル（TTS・開発者パネル）で使う。 */

import { el } from "./dom.js";

/**
 * @param {{title: string, node: Node, badge?: string|number}[]} items
 * @returns {{el: HTMLElement, select: (index:number)=>void, setBadge: (index:number, value:any)=>void}}
 */
export function createTabs(items) {
  const badges = [];
  const buttons = items.map((item, index) => {
    const badge = el("span", { class: "chip", hidden: item.badge === undefined || item.badge === null },
                     String(item.badge ?? ""));
    badges.push(badge);
    return el(
      "button",
      {
        class: `tab${index === 0 ? " is-active" : ""}`,
        type: "button",
        role: "tab",
        "aria-selected": index === 0 ? "true" : "false",
        onclick: () => select(index),
      },
      item.title,
      badge
    );
  });

  const panels = items.map((item, index) => {
    item.node.hidden = index !== 0;
    return item.node;
  });

  function select(index) {
    buttons.forEach((button, i) => {
      button.classList.toggle("is-active", i === index);
      button.setAttribute("aria-selected", i === index ? "true" : "false");
    });
    panels.forEach((panel, i) => { panel.hidden = i !== index; });
    items[index]?.onShow?.();
  }

  function setBadge(index, value) {
    const badge = badges[index];
    if (!badge) return;
    const empty = value === undefined || value === null || value === 0 || value === "";
    badge.hidden = empty;
    badge.textContent = empty ? "" : String(value);
  }

  return {
    el: el("div", { class: "tabbed" },
           el("div", { class: "tabs", role: "tablist" }, buttons),
           el("div", { class: "tabpanel" }, panels)),
    select,
    setBadge,
  };
}
