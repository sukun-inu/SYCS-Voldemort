/* プルダウンの中身と選択値。

   select.value に一覧へ無い値を入れても、ブラウザは黙って無視して空欄にする。
   そのまま保存すると、設定していた値が消える。実際に「通知チャンネルを設定して
   あるのにプルダウンが空」という形で起きた。

   値が一覧に無いときは、その値そのものを選択肢として足しておく。
   （スキーマ駆動の欄では forms/widgets.js が同じことをしている。
     判定が散ると片方だけ直る取りこぼしになるので、ここに寄せる。） */

import { el, clear } from "./dom.js";

/** 一覧に無い値を選ぶための、控えの選択肢。 */
function orphanOption(value) {
  return el("option", { value: String(value), text: `${value}（一覧にありません）` });
}

/**
 * プルダウンを組み立てる。
 *
 * @param {HTMLSelectElement} select
 * @param {{value: string, label: string}[]} options
 * @param {{placeholder?: string, value?: string|number|null}} opts
 */
export function fillSelect(select, options, { placeholder, value } = {}) {
  clear(select);
  if (placeholder !== undefined) {
    select.append(el("option", { value: "", text: placeholder }));
  }
  // DOM の append は配列を平坦化しない（dom.js の el() 経由とは別物）。展開して渡す。
  select.append(...options.map((o) => el("option", { value: o.value, text: o.label })));
  if (value !== undefined) selectValue(select, value);
  return select;
}

/**
 * 選択値を入れる。一覧に無ければ、その値の選択肢を足してから選ぶ。
 * 空欄になって設定が消える、という壊れ方をさせない。
 *
 * @returns {boolean} 一覧に無い値だったか
 */
export function selectValue(select, value) {
  const wanted = value === null || value === undefined ? "" : String(value);
  if (!wanted) {
    select.value = "";
    return false;
  }
  const known = Array.from(select.options).some((o) => o.value === wanted);
  if (!known) select.append(orphanOption(wanted));
  select.value = wanted;
  return !known;
}
