//! 地震の画像の文字の口。Python（Pillow）の `ImageDraw.text`・`textbbox`・`textlength` にあたる。
//!
//! 中身は `sycs-text`（`rust/crates/sycs-text`）にある。Pillow と画素まで同じに描く部品で、画素を回す処理
//! なので、最適化を効かせられるよう別の crate にしてある。Bot の中からは、ここを通して同じ名前で使う。
//!
//! - [`FontSpec`]・[`Anchor`]・[`TextPainter`]: 文字を描く口（札も地図も、この口を通して描く）。
//! - [`PillowText`]: 本物（フォントは `fonts-noto-cjk` の NotoSansCJK。Python と同じファイル）。
//!   フォント（1 本 約 20MB）をメモリに持つので、画像を 1 枚作る間だけ作って、終わったら捨てる。

pub use sycs_text::{Anchor, FontError, FontSpec, PillowText, TextMask, TextPainter};
