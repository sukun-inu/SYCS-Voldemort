/* デスクトップ以外の Aero ページ（ログイン / サーバー選択 / エラー）。

   ログイン画面は「静的な壁紙 + 浮いたカード1枚」なので、WebGL のガラスが
   最も素直に効く。使えない環境では CSS のガラスがそのまま残る。 */

import { attachSpecular } from "./wm/specular.js";

attachSpecular();

const root = document.getElementById("aero-root");
const card = root?.querySelector(":scope > .login-card");

if (root && card) {
  import("../vendor/liquidglass/liquidglass.js")
    .then(({ LiquidGlass }) =>
      LiquidGlass.init({
        root,
        glassElements: [card],
        // 壁紙が平坦なので、屈折だけでは板が見えない。
        // すりガラスとしての厚み（ぼかし・淡い色味・明るさ）を足す。
        defaults: {
          blurAmount: 0.6,
          refraction: 0.7,
          chromAberration: 0.04,
          edgeHighlight: 0.65,
          specular: 0.5,
          fresnel: 1,
          cornerRadius: 22,
          zRadius: 20,
          opacity: 1,
          saturation: 0.35,
          tintStrength: 0.26,
          brightness: 0.1,
          shadowOpacity: 0.4,
          shadowSpread: 34,
          shadowOffsetY: 20,
        },
      })
    )
    .then(() => document.body.classList.add("is-liquid"))
    .catch((error) => console.warn("液体ガラスを初期化できませんでした:", error));
}
