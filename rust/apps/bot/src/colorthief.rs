//! 画像の代表色を取る。Python の colorthief 0.2.1（`ColorThief.get_color`）をそのまま移したもの。
//!
//! ログの Embed の色に、ユーザーのアバターの代表色を使っている（Python の
//! `logging_service._user_avatar_color`）。移行の途中で Python と Rust の Bot が並ぶので、
//! 同じアバターから同じ色を出す。中身は MMCQ（色空間を箱に分けて、画素の多い箱を中央で
//! 割り続ける）で、**結果が Python と一致するように、次のところまで写してある。**
//!
//! - 箱の並べ替えは安定ソート（Python の `list.sort`）。同じ値の箱の順が結果を変える
//! - Python は 0 を偽として扱う（`while not partialsum.get(d2, False)` は「無い」と「0」の両方で進む）
//! - 平均色は浮動小数で、Python と同じ順に掛けて足す（順を変えると丸めが変わる）
//! - パレットは並べ替えずに積んだ順で返す（`CMap.palette` は `map` で、並べ替えない）
//!
//! 一致は、同じ画像を Python と Rust に読ませて突き合わせて確かめた（変更のコミットに記録）。

use std::collections::HashMap;

const SIGBITS: i32 = 5;
const RSHIFT: i32 = 8 - SIGBITS;
const MAX_ITERATION: usize = 1000;
const FRACT_BY_POPULATIONS: f64 = 0.75;
/// `get_color` が内部で作るパレットの色数（Python の `get_palette(5, quality)`）。
const PALETTE_SIZE: usize = 5;

/// RGBA の画素の並び（1 画素 4 バイト、左上から行ごと）から代表色を取る。
///
/// `quality` は何画素おきに見るか（Python の既定と同じく 10 を渡す）。半透明（α < 125）と
/// ほぼ白（3 色とも 250 超）の画素は数えない。数える画素が無ければ `None`
/// （Python は例外を投げ、呼び出し側が「色なし」にしている）。
pub fn dominant_color(rgba: &[u8], quality: usize) -> Option<(u8, u8, u8)> {
    let step = quality.max(1);
    // 4 バイトに満たない端は画素として数えない（RGBA の並びなら端は出ない）。
    let (whole, _) = rgba.as_chunks::<4>();
    let pixels: Vec<(u8, u8, u8)> = whole
        .iter()
        .step_by(step)
        .filter(|p| p[3] >= 125 && !(p[0] > 250 && p[1] > 250 && p[2] > 250))
        .map(|p| (p[0], p[1], p[2]))
        .collect();
    quantize(&pixels, PALETTE_SIZE)?.into_iter().next()
}

fn color_index(r: i32, g: i32, b: i32) -> i32 {
    (r << (2 * SIGBITS)) + (g << SIGBITS) + b
}

/// 量子化した色ごとの画素数。Python は辞書で持ち、無い色は 0 として読む。
struct Histo(HashMap<i32, u64>);

impl Histo {
    fn get(&self, index: i32) -> u64 {
        self.0.get(&index).copied().unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct VBox {
    r1: i32,
    r2: i32,
    g1: i32,
    g2: i32,
    b1: i32,
    b2: i32,
    /// 箱の中の画素数。Python は初めて読んだときに覚える（cached_property）。箱の境界は
    /// 覚える前にしか変えないので、作ったときに数えて同じになる。
    count: u64,
    volume: i64,
}

impl VBox {
    fn new(bounds: [i32; 6], histo: &Histo) -> Self {
        let [r1, r2, g1, g2, b1, b2] = bounds;
        let mut count = 0;
        for i in r1..=r2 {
            for j in g1..=g2 {
                for k in b1..=b2 {
                    count += histo.get(color_index(i, j, k));
                }
            }
        }
        let volume = i64::from(r2 - r1 + 1) * i64::from(g2 - g1 + 1) * i64::from(b2 - b1 + 1);
        Self {
            r1,
            r2,
            g1,
            g2,
            b1,
            b2,
            count,
            volume,
        }
    }

    fn bounds(&self) -> [i32; 6] {
        [self.r1, self.r2, self.g1, self.g2, self.b1, self.b2]
    }

    /// 箱の平均色。Python の `VBox.avg` と同じ式・同じ順で計算する。
    fn avg(&self, histo: &Histo) -> (u8, u8, u8) {
        let mut ntot: u64 = 0;
        let mult = f64::from(1_i32 << (8 - SIGBITS));
        let (mut r_sum, mut g_sum, mut b_sum) = (0.0_f64, 0.0_f64, 0.0_f64);
        for i in self.r1..=self.r2 {
            for j in self.g1..=self.g2 {
                for k in self.b1..=self.b2 {
                    let hval = histo.get(color_index(i, j, k));
                    ntot += hval;
                    // Python: hval * (i + 0.5) * mult（左から順に）
                    let h = hval as f64;
                    r_sum += h * (f64::from(i) + 0.5) * mult;
                    g_sum += h * (f64::from(j) + 0.5) * mult;
                    b_sum += h * (f64::from(k) + 0.5) * mult;
                }
            }
        }
        // int() は 0 へ向けて切り捨てる（値は負にならないので as と同じ）。
        let (r, g, b) = if ntot > 0 {
            let n = ntot as f64;
            ((r_sum / n) as i64, (g_sum / n) as i64, (b_sum / n) as i64)
        } else {
            let m = 1_i64 << (8 - SIGBITS);
            (
                m * i64::from(self.r1 + self.r2 + 1) / 2,
                m * i64::from(self.g1 + self.g2 + 1) / 2,
                m * i64::from(self.b1 + self.b2 + 1) / 2,
            )
        };
        (clamp_u8(r), clamp_u8(g), clamp_u8(b))
    }
}

fn clamp_u8(v: i64) -> u8 {
    v.clamp(0, 255) as u8
}

/// Python の `PQueue`。並べ替えは取り出す直前にだけ行い、取り出すのは末尾（鍵の最大）。
struct PQueue {
    contents: Vec<VBox>,
    sorted: bool,
    key: fn(&VBox) -> i128,
}

impl PQueue {
    fn new(key: fn(&VBox) -> i128) -> Self {
        Self {
            contents: Vec::new(),
            sorted: false,
            key,
        }
    }

    fn push(&mut self, vbox: VBox) {
        self.contents.push(vbox);
        self.sorted = false;
    }

    fn pop(&mut self) -> Option<VBox> {
        if !self.sorted {
            // sort_by_key は安定ソート（Python の list.sort と同じ）。
            self.contents.sort_by_key(self.key);
            self.sorted = true;
        }
        self.contents.pop()
    }

    fn size(&self) -> usize {
        self.contents.len()
    }
}

fn by_count(v: &VBox) -> i128 {
    i128::from(v.count)
}

fn by_count_and_volume(v: &VBox) -> i128 {
    i128::from(v.count) * i128::from(v.volume)
}

/// 箱を中央で 2 つに割る。Python の `MMCQ.median_cut_apply`。割れなければ `None`。
fn median_cut_apply(histo: &Histo, vbox: &VBox) -> Option<(VBox, Option<VBox>)> {
    if vbox.count == 0 {
        return None;
    }
    let rw = vbox.r2 - vbox.r1 + 1;
    let gw = vbox.g2 - vbox.g1 + 1;
    let bw = vbox.b2 - vbox.b1 + 1;
    let maxw = rw.max(gw).max(bw);
    if vbox.count == 1 {
        return Some((*vbox, None));
    }

    // 割る向き（r・g・b の順に、いちばん幅のある辺）。bounds の何番目が dim1・dim2 か。
    let (dim1, dim2) = if maxw == rw {
        (0, 1)
    } else if maxw == gw {
        (2, 3)
    } else {
        (4, 5)
    };
    let bounds = vbox.bounds();
    let (lo, hi) = (bounds[dim1], bounds[dim2]);

    let mut total: u64 = 0;
    let mut partialsum: HashMap<i32, u64> = HashMap::new();
    for i in lo..=hi {
        let mut sum = 0;
        // 割る向きの値を i に固定して、残りの 2 辺を全部足す。
        let (rr, gg, bb) = match dim1 {
            0 => ((i, i), (vbox.g1, vbox.g2), (vbox.b1, vbox.b2)),
            2 => ((vbox.r1, vbox.r2), (i, i), (vbox.b1, vbox.b2)),
            _ => ((vbox.r1, vbox.r2), (vbox.g1, vbox.g2), (i, i)),
        };
        for r in rr.0..=rr.1 {
            for g in gg.0..=gg.1 {
                for b in bb.0..=bb.1 {
                    sum += histo.get(color_index(r, g, b));
                }
            }
        }
        total += sum;
        partialsum.insert(i, total);
    }
    let lookaheadsum: HashMap<i32, u64> =
        partialsum.iter().map(|(&i, &d)| (i, total - d)).collect();
    // Python の「真」: 鍵があって 0 でない。
    let truthy = |m: &HashMap<i32, u64>, k: i32| m.get(&k).is_some_and(|&v| v != 0);

    for i in lo..=hi {
        // partialsum[i] > total / 2（Python は浮動小数で比べる。整数なら 2 倍して比べるのと同じ）
        if 2 * partialsum[&i] > total {
            let left = i - lo;
            let right = hi - i;
            // Python の int() は 0 へ向けて切り捨てる。
            let mut d2 = if left <= right {
                (hi - 1).min((f64::from(i) + f64::from(right) / 2.0).trunc() as i32)
            } else {
                lo.max((f64::from(i) - 1.0 - f64::from(left) / 2.0).trunc() as i32)
            };
            while !truthy(&partialsum, d2) {
                d2 += 1;
            }
            let mut count2 = lookaheadsum.get(&d2).copied();
            while count2.is_none_or(|c| c == 0) && truthy(&partialsum, d2 - 1) {
                d2 -= 1;
                count2 = lookaheadsum.get(&d2).copied();
            }
            let mut b1 = bounds;
            let mut b2 = bounds;
            b1[dim2] = d2;
            b2[dim1] = d2 + 1;
            return Some((VBox::new(b1, histo), Some(VBox::new(b2, histo))));
        }
    }
    None
}

/// 箱を割り続ける。Python の `quantize` の中の `iter_`。割れない箱に当たったら `None`
/// （Python は例外を投げる）。
fn iterate(queue: &mut PQueue, target: f64, histo: &Histo) -> Option<()> {
    let mut n_color = 1;
    let mut n_iter = 0;
    while n_iter < MAX_ITERATION {
        let vbox = queue.pop()?;
        if vbox.count == 0 {
            queue.push(vbox);
            n_iter += 1;
            continue;
        }
        let (vbox1, vbox2) = median_cut_apply(histo, &vbox)?;
        queue.push(vbox1);
        if let Some(vbox2) = vbox2 {
            queue.push(vbox2);
            n_color += 1;
        }
        if f64::from(n_color) >= target {
            return Some(());
        }
        if n_iter > MAX_ITERATION {
            return Some(());
        }
        n_iter += 1;
    }
    Some(())
}

/// パレットを作る。Python の `MMCQ.quantize(pixels, max_color).palette`。
fn quantize(pixels: &[(u8, u8, u8)], max_color: usize) -> Option<Vec<(u8, u8, u8)>> {
    if pixels.is_empty() || !(2..=256).contains(&max_color) {
        return None;
    }
    let shifted = |p: &(u8, u8, u8)| {
        (
            i32::from(p.0) >> RSHIFT,
            i32::from(p.1) >> RSHIFT,
            i32::from(p.2) >> RSHIFT,
        )
    };
    let mut histo = HashMap::new();
    let (mut rmin, mut rmax, mut gmin, mut gmax, mut bmin, mut bmax) =
        (1_000_000, 0, 1_000_000, 0, 1_000_000, 0);
    for p in pixels {
        let (r, g, b) = shifted(p);
        *histo.entry(color_index(r, g, b)).or_insert(0) += 1;
        rmin = rmin.min(r);
        rmax = rmax.max(r);
        gmin = gmin.min(g);
        gmax = gmax.max(g);
        bmin = bmin.min(b);
        bmax = bmax.max(b);
    }
    let histo = Histo(histo);

    let mut pq = PQueue::new(by_count);
    pq.push(VBox::new([rmin, rmax, gmin, gmax, bmin, bmax], &histo));
    iterate(&mut pq, FRACT_BY_POPULATIONS * max_color as f64, &histo)?;

    let mut pq2 = PQueue::new(by_count_and_volume);
    while let Some(v) = pq.pop() {
        pq2.push(v);
    }
    let target = max_color as f64 - pq2.size() as f64;
    iterate(&mut pq2, target, &histo)?;

    // CMap は積んだ順のまま返す（Python の palette は並べ替えない）。
    let mut palette = Vec::new();
    while let Some(v) = pq2.pop() {
        palette.push(v.avg(&histo));
    }
    Some(palette)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgba(pixels: &[(u8, u8, u8, u8)]) -> Vec<u8> {
        pixels
            .iter()
            .flat_map(|&(r, g, b, a)| [r, g, b, a])
            .collect()
    }

    /// 1 色だけの画像は、その色（量子化の箱の中央）になること。
    #[test]
    fn a_single_colour_comes_back_as_its_box_average() {
        let img = rgba(&[(200, 40, 10, 255); 100]);
        // 200>>3=25 → (25+0.5)*8 = 204、40>>3=5 → 44、10>>3=1 → 12
        assert_eq!(dominant_color(&img, 1), Some((204, 44, 12)));
    }

    /// 半透明とほぼ白の画素は数えず、それしか無ければ色なしになること。
    #[test]
    fn transparent_and_near_white_pixels_are_ignored() {
        let only_ignored = rgba(&[(10, 10, 10, 124), (251, 251, 251, 255)]);
        assert_eq!(dominant_color(&only_ignored, 1), None);
        let mixed = rgba(&[
            (10, 10, 10, 0),
            (251, 251, 251, 255),
            (0, 0, 200, 255),
            (0, 0, 200, 255),
        ]);
        assert_eq!(dominant_color(&mixed, 1), Some((4, 4, 204)));
        // α がちょうど 125 なら数える（125 未満を捨てる）。
        let edge = rgba(&[(0, 0, 200, 125)]);
        assert_eq!(dominant_color(&edge, 1), Some((4, 4, 204)));
        // 白でも 1 色が 250 以下なら数える。
        let almost = rgba(&[(251, 251, 250, 255)]);
        assert_eq!(dominant_color(&almost, 1), Some((252, 252, 252)));
    }

    /// quality 画素おきにしか見ないこと（Python の range(0, n, quality)）。
    #[test]
    fn only_every_quality_th_pixel_is_sampled() {
        let mut px = vec![(0, 200, 0, 255); 10];
        px[0] = (200, 0, 0, 255);
        // 0 番目だけを見る → 赤。
        assert_eq!(dominant_color(&rgba(&px), 10), Some((204, 4, 4)));
    }

    /// 多い色が代表色になること（2 色で 9:1）。
    #[test]
    fn the_more_common_colour_wins() {
        let mut px = vec![(0, 0, 200, 255); 90];
        px.extend(vec![(200, 0, 0, 255); 10]);
        assert_eq!(dominant_color(&rgba(&px), 1), Some((4, 4, 204)));
    }

    /// 取り出すたびに、鍵の最大の箱が出てくること。同じ鍵なら後に並んでいた方（安定ソート）。
    ///
    /// 同じ鍵の箱が多い列で確かめる。Rust の不安定ソートは 20 個以下だと挿入ソートになり、
    /// 安定ソートと見分けが付かない（いまの使い方では箱が 10 個程度なので結果も変わらないが、
    /// 安定であることが Python と一致する前提なので、崩れたら分かるようにしておく）。
    #[test]
    fn the_queue_pops_the_largest_and_keeps_ties_in_order() {
        let h = Histo(HashMap::new());
        let mut q = PQueue::new(|v| i128::from(v.r1));
        let n = 100;
        for tag in 0..n {
            // 鍵は 0〜2 の 3 通りだけ（同じ鍵がたくさん並ぶ）。g1 に積んだ順を持たせる。
            q.push(VBox::new([tag % 3, tag % 3, tag, tag, 0, 0], &h));
        }
        let mut popped = Vec::new();
        while let Some(v) = q.pop() {
            popped.push((v.r1, v.g1));
        }
        // 安定ソートを末尾から取り出した順: 鍵の大きい順、同じ鍵の中では後に積んだ順。
        let mut expected: Vec<(i32, i32)> = (0..n).map(|t| (t % 3, t)).collect();
        expected.sort_by_key(|&(key, _)| key);
        expected.reverse();
        assert_eq!(popped, expected);
    }
}
