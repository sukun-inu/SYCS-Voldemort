/* スキーマの1項目を入力欄にする。
   widget ごとの差はここだけに閉じ込め、呼び出し側は get/set/setError だけを使う。 */

import { el } from "../lib/dom.js";

const ID_WIDGETS = new Set(["channel", "voice_channel", "role", "snowflake"]);

/* 期間の単位。大きい順に見て、割り切れる一番大きい単位で表示する。
   サーバ側 webapp_admin/schema/duration.py と同じ規則。 */
const DURATION_UNITS = [["日", 86400], ["時間", 3600], ["分", 60], ["秒", 1]];

function splitDuration(seconds) {
  const value = Math.max(0, Math.round(seconds));
  if (value <= 0) return [value, "秒"];
  for (const [label, factor] of DURATION_UNITS) {
    if (value % factor === 0) return [value / factor, label];
  }
  return [value, "秒"];
}

function humanizeDuration(seconds) {
  const [value, label] = splitDuration(seconds);
  return `${value}${label}`;
}

let sequence = 0;
const nextId = (key) => `f${++sequence}-${key}`;

function optionsFor(field, choices) {
  if (Array.isArray(field.choices)) return field.choices;
  if (field.choice_source) return choices[field.choice_source] || [];
  return [];
}

/**
 * @returns {{el: HTMLElement, get: Function, set: Function, setError: Function,
 *            setEnabled: Function, onInput: Function}}
 */
export function createWidget(field, value, choices) {
  const id = nextId(field.key);
  const errorEl = el("p", { class: "field-error", id: `${id}-error` });
  const helpEl = field.help ? el("p", { class: "field-help", text: field.help }) : null;
  const wrapper = el("div", { class: "field", dataset: { key: field.key } });

  let control;
  let read;
  let write;
  const listeners = [];
  const notify = () => listeners.forEach((fn) => fn());

  const options = optionsFor(field, choices);
  const isSelectLike = field.widget === "select" || ID_WIDGETS.has(field.widget);
  // 一覧を取得できないとき、ID項目と free_text を許した項目は手入力へ切り替える。
  // （空のドロップダウンだけを出すと、設定する手段が無くなってしまう）
  const isFreeTextFallback =
    isSelectLike && options.length === 0 && (field.free_text || ID_WIDGETS.has(field.widget));
  // そもそも選択肢を持たない項目（メッセージIDなどの snowflake）に
  // 「一覧を取得できませんでした」と出すと、壊れていないのに壊れて見える。
  const expectsChoices = Boolean(field.choice_source) || Array.isArray(field.choices);
  let noteEl = null;

  if (field.widget === "bool") {
    control = el("input", { type: "checkbox", id, oninput: notify });
    wrapper.append(
      el("label", { class: "check", for: id }, control, el("span", { class: "check-text", text: field.label }))
    );
    read = () => control.checked;
    write = (v) => { control.checked = Boolean(v); };
  } else if (field.widget === "checklist") {
    const boxes = options.map((option) =>
      el(
        "label",
        { class: "check" },
        el("input", { type: "checkbox", value: option.value, oninput: notify }),
        el("span", { class: "check-text", text: option.label })
      )
    );
    control = el("div", { class: "check-list", id }, boxes);
    wrapper.append(el("span", { class: "field-label", text: field.label }), control);
    read = () =>
      [...control.querySelectorAll("input")].filter((box) => box.checked).map((box) => box.value);
    write = (v) => {
      const selected = new Set((v || []).map(String));
      for (const box of control.querySelectorAll("input")) box.checked = selected.has(box.value);
    };
  } else if (isSelectLike && !isFreeTextFallback) {
    control = el("select", { class: "select", id, oninput: notify });
    if (field.nullable) control.append(el("option", { value: "", text: "未設定" }));
    for (const option of options) {
      control.append(el("option", { value: option.value, text: option.label }));
    }
    // 一覧に無い値（別サーバーの残骸など）でも、現在値は選択肢として残して見せる。
    if (value !== null && value !== undefined && !options.some((o) => o.value === String(value))) {
      control.append(el("option", { value: String(value), text: `${value}（一覧にありません）` }));
    }
    wrapper.append(el("label", { class: "field-label", for: id, text: field.label }), control);
    if (options.length === 0 && expectsChoices) {
      noteEl = el("p", { class: "field-help", text: "選択肢を取得できませんでした。" });
    }
    read = () => (control.value === "" ? null : control.value);
    write = (v) => { control.value = v === null || v === undefined ? "" : String(v); };
  } else if (field.widget === "textarea") {
    control = el("textarea", { class: "textarea", id, rows: 4, oninput: notify });
    if (field.max_len) control.setAttribute("maxlength", field.max_len);
    wrapper.append(el("label", { class: "field-label", for: id, text: field.label }), control);
    read = () => (control.value.trim() === "" ? null : control.value);
    write = (v) => { control.value = v === null || v === undefined ? "" : String(v); };
  } else if (field.widget === "int") {
    control = el("input", { class: "input", type: "number", id, oninput: notify });
    if (field.min !== undefined) control.setAttribute("min", field.min);
    if (field.max !== undefined) control.setAttribute("max", field.max);
    wrapper.append(el("label", { class: "field-label", for: id, text: field.label }), control);
    read = () => (control.value === "" ? null : Number(control.value));
    write = (v) => { control.value = v === null || v === undefined ? "" : String(v); };
  } else if (field.widget === "duration") {
    // 値は秒でやり取りする（保存形式を変えないため）。入力だけ単位を分ける。
    // 30日を秒で打たせると 2592000 になり、桁を数える作業になってしまう。
    const amount = el("input", { class: "input", type: "number", id, min: "0", oninput: notify });
    const unit = el("select", { class: "select", oninput: notify },
                    DURATION_UNITS.map(([label]) => el("option", { value: label, text: label })));
    const factorOf = (label) => (DURATION_UNITS.find(([l]) => l === label) || ["秒", 1])[1];

    control = amount;
    wrapper.append(
      el("label", { class: "field-label", for: id, text: field.label }),
      el("div", { class: "row" }, amount, unit)
    );

    read = () => (amount.value === "" ? null : Math.round(Number(amount.value) * factorOf(unit.value)));
    write = (v) => {
      if (v === null || v === undefined || v === "") { amount.value = ""; return; }
      const [value, label] = splitDuration(Number(v));
      amount.value = String(value);
      unit.value = label;
    };
    // 許容範囲は単位付きで添える（秒のままだと何日なのか分からない）。
    // 項目そのものの説明を先に出したいので、help と同じ「後ろに置く」枠を使う。
    if (field.min !== undefined || field.max !== undefined) {
      const parts = [];
      if (field.min !== undefined) parts.push(`${humanizeDuration(field.min)} 以上`);
      if (field.max !== undefined) parts.push(`${humanizeDuration(field.max)} 以下`);
      noteEl = el("p", { class: "field-help", text: parts.join(" / ") });
    }
  } else {
    // text / snowflake / 選択肢を取得できなかった select のフォールバック
    control = el("input", { class: "input", type: "text", id, oninput: notify });
    if (field.max_len) control.setAttribute("maxlength", field.max_len);
    if (ID_WIDGETS.has(field.widget)) {
      control.setAttribute("inputmode", "numeric");
      control.setAttribute("placeholder", "18桁前後の数字ID");
    }
    wrapper.append(el("label", { class: "field-label", for: id, text: field.label }), control);
    if (isFreeTextFallback && expectsChoices) {
      noteEl = el("p", {
        class: "field-help",
        text: ID_WIDGETS.has(field.widget)
          ? "一覧を取得できませんでした。ID を直接入力できます。"
          : "一覧を取得できませんでした。値を直接入力できます。",
      });
    }
    read = () => (control.value.trim() === "" ? null : control.value.trim());
    write = (v) => { control.value = v === null || v === undefined ? "" : String(v); };
  }

  // 項目そのものの説明が先。取得できなかったという断り書きはその後ろに置く。
  if (helpEl) wrapper.append(helpEl);
  if (noteEl) wrapper.append(noteEl);
  wrapper.append(errorEl);
  write(value);

  return {
    el: wrapper,
    field,
    get: read,
    set: (v) => { write(v); },
    onInput: (fn) => listeners.push(fn),
    setError(message) {
      wrapper.classList.toggle("has-error", Boolean(message));
      errorEl.textContent = message || "";
      if (message) control.setAttribute("aria-describedby", `${id}-error`);
      else control.removeAttribute("aria-describedby");
    },
    setEnabled(enabled) {
      wrapper.classList.toggle("is-disabled", !enabled);
      for (const input of wrapper.querySelectorAll("input, select, textarea")) {
        input.disabled = !enabled;
      }
    },
    focus() {
      (control.querySelector?.("input") || control).focus?.();
    },
  };
}
