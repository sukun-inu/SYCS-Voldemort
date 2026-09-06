/* デスクトップ以外の Aero ページ（ログイン / サーバー選択 / エラー）で
   鏡面ハイライトだけを有効にする。 */

import { attachSpecular } from "./wm/specular.js";

attachSpecular();

/* エラーページの「前のページへ」。CSP が script-src 'self' で
   'unsafe-inline' も 'unsafe-hashes' も許していないため、onclick="" は
   ブラウザにブロックされて押しても何も起きない。ここから結び付ける。

   テンプレート側では hidden で出してあり、外せるのはこの行が動いたときだけ
   ＝押せるボタンしか見えない。戻り先が無い（リンクを直接開いた・新しい
   タブで開いた）ときも history.back() は何もしないので、その場合も出さない。 */
for (const button of document.querySelectorAll("[data-history-back]")) {
  if (window.history.length <= 1) continue;
  button.hidden = false;
  button.addEventListener("click", () => window.history.back());
}
