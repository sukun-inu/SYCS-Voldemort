/* サーバーのデータ。何を持っていて、どうすれば消えるかを1枚にする。

   消す口（DELETE /admin/api/guild-data）は先に入っていたが、叩く画面が無く、
   ドキュメントに書いてある「管理UIの『このサーバーのデータを削除』」がどこにも
   無い状態だった。ここがその画面。

   **確認はサーバーIDそのものを打たせる。** 押す前に番号を写しているあいだ、
   どのサーバーを消そうとしているのかを見ることになる。はい/いいえの窓を
   重ねて出さないのは、それが「読まずに押す」操作だから——写して打つより
   弱い確認を足しても、強くはならない。

   判断はサーバーが最終的にやり直す（打った文字列は confirm として送られ、
   API 側で guild_id と突き合わせる）。ここで押せなくしているのは、間違いを
   送る前に気づかせるための補助でしかない。 */

import * as api from "../lib/api.js";
import { el, icon, clear, field } from "../lib/dom.js";
import { toast } from "../lib/toast.js";

const ENDPOINT = "/admin/api/guild-data";

/** シェルが <meta> に埋めた値を読む。無ければ空文字。 */
function meta(name) {
  const node = document.querySelector(`meta[name="${name}"]`);
  return node ? node.getAttribute("content") || "" : "";
}

/** 「設定 1 件 / 履歴 42 件」のように、消えた実数を並べる。
 *
 *  0 件のものも省かずに出す。「履歴」の行が無いと、履歴が元から無かったのか
 *  消し損ねたのかが読み手には分からない。 */
function removedRows(removed) {
  const counts = removed || {};
  return [
    ["設定", counts.settings, "settings.json のこのサーバー分"],
    ["監査履歴", counts.events, "入退室・ロール変更などの記録"],
    ["現在の状態", counts.states, "ユーザーごとの最新の状態"],
  ].map(([label, count, note]) =>
    el("div", { class: "list-row" },
       el("div", { class: "grow list-main" },
          el("div", { text: label }),
          el("div", { class: "list-sub", text: note })),
       el("span", { class: "mono nowrap", text: `${Number(count) || 0} 件` })));
}

export function mount(win) {
  const guildId = meta("guild-id");
  const guildName = meta("guild-name") || "このサーバー";

  // ── 何を持っているか ──────────────────────────────────
  const stored = el(
    "section", { class: "section" },
    el("div", { class: "section-head", "data-specular": "" },
       el("h2", { class: "section-title", text: "このサーバーについて保存しているもの" })),
    el("div", { class: "section-body" },
       el("div", { class: "list" },
          el("div", { class: "list-row" },
             el("div", { class: "grow list-main" },
                el("div", { text: "設定" }),
                el("div", { class: "list-sub", text:
                  "各画面で保存した内容（通知先・ロール・読み上げ・録音など）" }))),
          el("div", { class: "list-row" },
             el("div", { class: "grow list-main" },
                el("div", { text: "ユーザー状態の監査履歴" }),
                el("div", { class: "list-sub", text:
                  "入退室・ロール変更・タイムアウトなどの記録と、その最新の状態" })))),
       el("p", { class: "field-help", text:
         "使っている限り、何年経っても勝手には消えません。自動で消えるのは "
         + "「Bot がこのサーバーに居ない」かつ「設定が10年間まったく触られていない」"
         + "ものだけです。片方だけでは消しません。" }))
  );

  // ── 消す ──────────────────────────────────────────────
  const confirmInput = el("input", {
    class: "input mono", type: "text", inputMode: "numeric", autocomplete: "off",
    // 見本として ID そのものを placeholder に置かない。空欄なのに入力済みに
    // 見えて、押せないボタンの理由が「打っていないから」だと分からなくなる。
    placeholder: "サーバーIDを入力", "aria-label": "確認のためのサーバーID",
  });
  const deleteButton = el("button", {
    class: "btn btn-danger", type: "button", disabled: true,
    // 押せない理由を title に置く。理由の書いていない無効なボタンは、
    // 「壊れている」のか「まだ条件を満たしていない」のかが区別できない。
    title: "上のサーバーIDを一字一句そのまま入力すると押せます",
  }, icon("bi-trash"), "このサーバーのデータを削除");

  const dangerBody = el(
    "div", { class: "section-body" },
    el("p", { class: "field-help", text:
      "設定と監査履歴をまとめて消します。監査履歴だけを消す方法は用意していません"
      + "——消したつもりで消し残る、という形にしないためです。" }),
    el("div", { class: "list" },
       el("div", { class: "list-row" },
          el("div", { class: "grow list-main" },
             el("div", { class: "truncate", text: guildName }),
             el("div", { class: "list-sub", text: "いま開いているサーバー" })),
          el("code", { class: "mono nowrap guild-id", text: guildId }))),
    field("確認のため、上のサーバーIDを入力してください", confirmInput,
          "一字でも違うと削除のボタンは押せません。"),
    el("div", { class: "row" }, el("span", { class: "grow" }), deleteButton)
  );

  const danger = el(
    "section", { class: "section is-danger" },
    el("div", { class: "section-head", "data-specular": "" },
       el("h2", { class: "section-title", text: "このサーバーのデータを削除" }),
       el("p", { class: "section-help", text: "取り消しはできません。" })),
    dangerBody
  );

  clear(win.body).append(el("div", { class: "stack" }, stored, danger));

  /** 打たれた文字列が ID と1文字も違わないときだけ押せるようにする。 */
  function refresh() {
    deleteButton.disabled = confirmInput.value.trim() !== guildId;
  }
  confirmInput.addEventListener("input", refresh);

  /** 消えたあとの画面。**同じ操作をもう一度できる形で残さない。**
   *
   *  設定はもう無いので、この窓に居続けても意味が無い。何がいくつ消えたかを
   *  出して、サーバー選択へ戻る道だけを置く。 */
  function showResult(removed) {
    clear(dangerBody).append(
      el("p", { class: "field-help", text: `${guildName}（${guildId}）のデータを削除しました。` }),
      el("div", { class: "list" }, removedRows(removed)),
      el("div", { class: "row" },
         el("span", { class: "grow" }),
         el("a", { class: "btn", href: "/admin/guilds" },
            icon("bi-arrow-left-right"), "サーバー選択へ戻る"))
    );
  }

  async function remove() {
    /* 押してから返ってくるまでの手応えを出す。監査履歴は別のデータベースに
       あるので、そちらが遠い/落ちているときは数秒から数十秒かかる。無言で
       止まると、押せていないと思って押し直すことになる。 */
    deleteButton.disabled = true;
    deleteButton.replaceChildren(el("span", { class: "spinner" }), document.createTextNode("削除中…"));
    try {
      const result = await api.del(`${ENDPOINT}?confirm=${encodeURIComponent(confirmInput.value.trim())}`);
      showResult(result.removed);
      toast("このサーバーのデータを削除しました", "success", { duration: 8000 });
    } catch (error) {
      toast(`削除できませんでした（${error.message}）`, "danger", { duration: 0 });
      deleteButton.replaceChildren(icon("bi-trash"), document.createTextNode("このサーバーのデータを削除"));
      refresh();
    }
  }
  deleteButton.addEventListener("click", remove);

  refresh();
}
