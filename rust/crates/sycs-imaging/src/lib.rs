//! Pillow（Python の画像ライブラリ）13.0.0 と **画素まで同じ結果** を出す画像処理。
//!
//! Python の Bot（discord.py）を Rust へ移す間、地震の画像（震度の地図など）は「Python が作るものと見た目が
//! 1 画素も違わない」ことが求められている。ここにあるのは、そのために Pillow の C のコード
//! （`src/libImaging/`）と Python のコード（`PIL/ImageDraw.py` など）を、計算の型と順をそのままに写したもの。
//!
//! - [`draw`]   図形（多角形・線・四角・楕円・角丸の四角）。`ImageDraw` にあたる
//! - [`raster`] 重ね合わせ・貼り付け・LANCZOS の拡大縮小・ガウスぼかし・色の形の変換
//!
//! 写したのは、地震の画像が使うものだけ（RGBA・RGB の 8 ビット。色は上書きで、混ぜる描き方は無い）。
//!
//! Pillow と同じことは、Bot の側のテスト（`apps/bot/tests/earthquake_map_golden.rs`）が、本物の Pillow に
//! 描かせた基準と比べて毎回確かめる。
//!
//! この crate は、開発・テストのビルドでも最適化する（`rust/Cargo.toml` の `[profile.dev.package.sycs-imaging]`）。
//! 画素を 1 つずつ回すので、最適化なしだと地図 1 枚に 5 秒かかり、CI（QEMU）ではその数倍になる。
//!
//! # 元にしたもの
//!
//! Pillow 13.0.0（<https://github.com/python-pillow/Pillow>）。MIT-CMU ライセンス:
//!
//! > The Python Imaging Library (PIL) is
//! >
//! > Copyright © 1997-2011 by Secret Labs AB
//! >
//! > Copyright © 1995-2011 by Fredrik Lundh and contributors
//! >
//! > Pillow is the friendly PIL fork. It is
//! >
//! > Copyright © 2010 by Jeffrey 'Alex' Clark and contributors
//! >
//! > Like PIL, Pillow is licensed under the open source MIT-CMU License:
//! >
//! > By obtaining, using, and/or copying this software and/or its associated
//! > documentation, you agree that you have read, understood, and will comply
//! > with the following terms and conditions:
//! >
//! > Permission to use, copy, modify and distribute this software and its
//! > documentation for any purpose and without fee is hereby granted,
//! > provided that the above copyright notice appears in all copies, and that
//! > both that copyright notice and this permission notice appear in supporting
//! > documentation, and that the name of Secret Labs AB or the author not be
//! > used in advertising or publicity pertaining to distribution of the software
//! > without specific, written prior permission.
//! >
//! > SECRET LABS AB AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
//! > SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
//! > IN NO EVENT SHALL SECRET LABS AB OR THE AUTHOR BE LIABLE FOR ANY SPECIAL,
//! > INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
//! > LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
//! > OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
//! > PERFORMANCE OF THIS SOFTWARE.

pub mod draw;
pub mod raster;
