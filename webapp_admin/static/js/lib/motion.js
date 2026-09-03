/* 行き先を測ってから動かすアニメーション。

   CSS だけで書けるものは motion.css に置く。ここに来るのは、
   「タスクバーのピルの位置」「最大化前の矩形」のように、
   実際に測らないと終点が決まらない動きだけ。

   動きを抑える設定では即座に終わったものとして扱う（CSS 側は base.css が潰すが、
   Web Animations API はメディアクエリを見ないため、ここで明示的に降りる）。 */

const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)");

/** tokens.css の --dur-* と揃える。片方だけ変えると拍がずれる。 */
export const DUR = { fast: 120, base: 180, move: 260 };
export const EASE_OUT = "cubic-bezier(.16, 1, .3, 1)";
export const EASE_IN = "cubic-bezier(.4, 0, .9, .6)";

export const reducedMotion = () => REDUCED.matches;

/**
 * 要素を動かし、終わったら解決する Promise を返す。
 * 動きを抑える設定・アニメーション未対応の環境では、何もせず即座に解決する。
 * @returns {Promise<void>}
 */
export function play(node, keyframes, { duration = DUR.base, easing = EASE_OUT, fill = "both" } = {}) {
  if (!node || REDUCED.matches || typeof node.animate !== "function") return Promise.resolve();
  const animation = node.animate(keyframes, { duration, easing, fill });
  return animation.finished.catch(() => {}).then(() => {
    // fill を残したままだと以降の style 変更が効かなくなる
    try {
      animation.cancel();
    } catch {
      /* すでに要素が外れている */
    }
  });
}

/** 走っている動きを止める。次の動きを始める前に呼び、途中の姿勢を残さない。 */
export function stopAnimations(node) {
  if (!node || typeof node.getAnimations !== "function") return;
  for (const animation of node.getAnimations()) {
    try {
      animation.cancel();
    } catch {
      /* 終了済み */
    }
  }
}

/** 矩形 from から to への差分を transform で表す（FLIP の F と I）。 */
export function deltaTransform(from, to) {
  const sx = from.width / Math.max(to.width, 1);
  const sy = from.height / Math.max(to.height, 1);
  return `translate(${from.left - to.left}px, ${from.top - to.top}px) scale(${sx}, ${sy})`;
}
