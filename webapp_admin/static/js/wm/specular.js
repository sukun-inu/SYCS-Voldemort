/* ポインタに追従する鏡面ハイライト。

   ガラスを「板」ではなく「レンズ」に見せるための光。座標だけを CSS 変数に
   渡し、見た目は CSS 側（[data-specular]::after）が決める。
   動きを抑える設定の環境では何もしない。 */

const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)");

export function attachSpecular(root = document) {
  if (REDUCED_MOTION.matches) return;

  let pending = null;

  root.addEventListener(
    "pointermove",
    (event) => {
      const target = event.target.closest?.("[data-specular]");
      if (!target) return;

      // 1フレームに1回だけ更新する（pointermove は毎ピクセル飛んでくる）
      if (pending) return;
      const { clientX, clientY } = event;
      pending = window.requestAnimationFrame(() => {
        pending = null;
        const rect = target.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        target.style.setProperty("--spec-x", `${((clientX - rect.left) / rect.width) * 100}%`);
        target.style.setProperty("--spec-y", `${((clientY - rect.top) / rect.height) * 100}%`);
      });
    },
    { passive: true }
  );
}
