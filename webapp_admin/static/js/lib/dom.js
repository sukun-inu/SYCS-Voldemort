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

/* 入力欄1つぶんの枠。ラベル・入力欄・補足を縦に並べる。

   ラベルは必ず <label for> で入力欄に結び付ける。ただの <span> にすると、
   見た目は同じでも、読み上げでは「編集（空欄）」としか読まれず、ラベルを
   押してもフォーカスが移らない。開発者パネルと録音パネルが、それぞれ自前で
   同じ field() を <span> で持っていて、両方ともこの状態だった（スキーマ駆動の
   forms/widgets.js は最初から <label for> を使っている）。

   同じものを2箇所に置くと、片方だけ直して取りこぼす。ここ1つにまとめる。 */
let fieldSequence = 0;

const CONTROLS = "input, select, textarea";

export function field(label, control, help) {
  const tail = help ? el("p", { class: "field-help", text: help }) : null;

  // 入力欄そのものを渡された場合。素直に <label for> で結ぶ。
  if (typeof control.matches === "function" && control.matches(CONTROLS)) {
    if (!control.id) control.id = `fld${++fieldSequence}`;
    return el("div", { class: "field" },
      el("label", { class: "field-label", for: control.id, text: label }),
      control, tail);
  }

  /* 入れ物を渡された場合（一覧から選ぶ <select> と、一覧を取れないときの
     手入力 <input> を切り替えて使う欄など）。<label for> は1つしか指せず、
     しかも指した先が隠れているほうかもしれないので、中のそれぞれに名前を
     付ける。見出しは <span> のままにする（何も指さない <label> を置くと、
     押しても反応しない見せかけの関連付けになる）。 */
  const inner = control.querySelectorAll ? control.querySelectorAll(CONTROLS) : [];
  for (const node of inner) {
    if (!node.getAttribute("aria-label")) node.setAttribute("aria-label", label);
  }
  return el("div", { class: "field" },
    el("span", { class: "field-label", text: label }),
    control, tail);
}

/* スクロールバーが場所を取るかどうかは端末で違う。

   Windows の Chrome は幅を持つ（実測 10px）。macOS や headless の Chromium は
   中身に重ねて描くので 0px。この差が、送り先の外にある要素との間にズレを生む
   ——保存バーは送り先の外にあるので幅いっぱいに伸びるが、中の設定項目は
   スクロールバーのぶん狭くなり、右端が 10px ずれる。

   headless では 0px なので、検査では気づけなかった。値を1回測って CSS 変数に
   渡し、外側の要素も同じだけ内側へ寄せる。 */
export function measureScrollbar() {
  // 測る側も .panel-scroll と同じ条件にすること。scrollbar-gutter: stable を
  // 付けずに測ると、中身に重ねて描く環境で 0px と出るのに、実際の送り先は
  // 溝を確保していて食い違う（headless がまさにそうだった）。
  const probe = el("div", {
    style: {
      position: "absolute", top: "-9999px", width: "100px", height: "100px",
      overflow: "scroll", scrollbarGutter: "stable", visibility: "hidden",
    },
  });
  document.body.append(probe);
  const width = probe.offsetWidth - probe.clientWidth;
  probe.remove();
  document.documentElement.style.setProperty("--scrollbar", `${width}px`);
  return width;
}
