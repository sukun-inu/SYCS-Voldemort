/* DOM 生成の小さなヘルパー。
   文字列 HTML は組み立てない（テキストは必ず textContent 経由）。
   サーバから来る名前や利用者の入力をそのまま innerHTML に流さないための方針。 */

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "style") Object.assign(node.style, value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }

  append(node, children);
  return node;
}

export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

const SPRITE_URL = "/static/icons/sprite.svg";
const SVG_NS = "http://www.w3.org/2000/svg";

/** アイコン。webfont ではなく、同梱した SVG スプライトを参照する。
    名前は "bi-x-lg" でも "x-lg" でも受け付ける。 */
export function icon(name, extraClass = "") {
  const id = String(name || "app").replace(/^bi-/, "");
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", `icon${extraClass ? " " + extraClass : ""}`);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `${SPRITE_URL}#${id}`);
  svg.append(use);
  return svg;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

export function loading(message = "読み込み中…") {
  return el("div", { class: "loading" }, el("span", { class: "spinner" }), message);
}
