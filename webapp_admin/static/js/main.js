/* デスクトップの起動。
   タイル一覧を API から取り、前回の配置を復元し、ディープリンクを開く。 */

import * as api from "./lib/api.js";
import { el, measureScrollbar } from "./lib/dom.js";
import { toast } from "./lib/toast.js";
import { Desktop } from "./wm/desktop.js";
import { attachSpecular } from "./wm/specular.js";

function targetFromLocation() {
  // 設定ページへ直接アクセスした場合、サーバが /admin/overview?open=<id> へ寄せる。
  // 以降のディープリンクはハッシュ（#tts）で扱う。
  const params = new URLSearchParams(window.location.search);
  const opened = params.get("open");
  if (opened) {
    params.delete("open");
    const query = params.toString();
    window.history.replaceState(null, "", window.location.pathname + (query ? `?${query}` : ""));
    return opened;
  }
  return window.location.hash.replace("#", "");
}

async function boot() {
  // スクロールバーの太さを CSS へ渡す（送り先の外にある要素を揃えるため）
  measureScrollbar();

  const target = targetFromLocation();

  let groups;
  try {
    ({ groups } = await api.get("/admin/api/apps"));
  } catch (error) {
    document.getElementById("desktop").append(
      el("div", { class: "empty" }, `アプリ一覧を取得できませんでした（${error.message}）`)
    );
    return;
  }

  const desktop = new Desktop({ groups });
  attachSpecular();

  const layout = Desktop.loadLayout();
  if (layout.length) {
    await desktop.restore(layout);
  }
  // open() は存在しない/権限が無い appId なら null を返す（トーストは open() 側で出す）。
  // その場合にスタートメニューも出さずに終わると、何も開かれていないのに
  // 真っ白な画面のまま放置される。
  const targetOpened = target ? Boolean(await desktop.open(target)) : false;
  if (!desktop.windows.size && !layout.length && (!target || !targetOpened)) {
    desktop.openStartMenu();
  }

  window.addEventListener("hashchange", () => {
    const id = window.location.hash.replace("#", "");
    if (id) desktop.open(id);
  });
}

boot().catch((error) => {
  console.error(error);
  toast(`起動に失敗しました（${error.message}）`, "danger", { duration: 0 });
});
