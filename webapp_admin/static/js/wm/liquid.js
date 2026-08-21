/* WebGL による液体ガラス（同梱: vendor/liquidglass, MIT）。

   ウィンドウの枠を、CSS の半透明ではなく実際の屈折で描く。背後の壁紙を
   テクスチャとして取り込み、シェーダで屈折・色収差・鏡面反射・縁の光を作る。

   ライブラリ側の制約に合わせている:
     - ガラス要素はルート直下でなければならない → ルートは #window-layer
     - ルート自身の背景は捕捉されない → 壁紙は .desktop-scene という実体にした
     - 初期化後に要素を足せない → ウィンドウの開閉でまとめて張り直す
   WebGL が使えない環境では何もしない（CSS のガラスがそのまま残る）。 */

import { LiquidGlass } from "../../vendor/liquidglass/liquidglass.js";

/** ウィンドウ1枚のガラスの質感。CSS の角丸と必ず揃えること。 */
const WINDOW_GLASS = {
  blurAmount: 0.14,
  refraction: 0.62,
  chromAberration: 0.03,
  edgeHighlight: 0.45,
  specular: 0.4,
  fresnel: 0.95,
  distortion: 0,
  cornerRadius: 18,
  zRadius: 14,
  opacity: 1,
  saturation: 0.2,
  tintStrength: 0.03,
  brightness: 0,
  shadowOpacity: 0.34,
  shadowSpread: 26,
  shadowOffsetY: 16,
};

const REBUILD_DELAY = 120;

export class LiquidSurfaces {
  constructor({ root, desktop }) {
    this.root = root;
    this.desktop = desktop;
    this.instance = null;
    this.timer = 0;
    this.available = supportsWebGL();
  }

  /** ガラスを張り直す。ウィンドウが増減したら呼ぶ（まとめて1回になる）。 */
  schedule() {
    if (!this.available) return;
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => this.#rebuild(), REBUILD_DELAY);
  }

  /** 壁紙側が変わったときに再取り込みさせる。 */
  invalidate() {
    this.instance?.markChanged();
  }

  async #rebuild() {
    const targets = [...this.root.querySelectorAll(":scope > .window")];

    this.instance?.destroy();
    this.instance = null;

    if (!targets.length) {
      this.desktop.classList.remove("is-liquid");
      return;
    }

    try {
      this.instance = await LiquidGlass.init({
        root: this.root,
        glassElements: targets,
        defaults: WINDOW_GLASS,
      });
      this.desktop.classList.add("is-liquid");
    } catch (error) {
      // 失敗したら CSS のガラスに任せる。以後は試さない。
      console.warn("液体ガラスを初期化できませんでした:", error);
      this.available = false;
      this.desktop.classList.remove("is-liquid");
    }
  }

  destroy() {
    window.clearTimeout(this.timer);
    this.instance?.destroy();
    this.instance = null;
    this.desktop.classList.remove("is-liquid");
  }
}

function supportsWebGL() {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl") || canvas.getContext("experimental-webgl"));
  } catch {
    return false;
  }
}
