/* 公開ページ（ランディング）の小さな挙動。
   モバイルナビの開閉のみ。Bootstrap の collapse を置き換えたもの。 */

const toggle = document.querySelector(".landing-menu-toggle");
const nav = document.querySelector(".landing-mobile-nav");

if (toggle && nav) {
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
}
