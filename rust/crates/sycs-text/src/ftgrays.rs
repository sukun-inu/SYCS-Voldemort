//! 輪郭を塗る。FreeType 2.14.3 の smooth ラスタライザ（`src/smooth/ftgrays.c`）の写し。
//!
//! Pillow の文字は FreeType のこの処理で塗られている。同じ濃さ（0〜255）を出すには、同じ整数の計算を
//! 同じ順でする必要があるので、式は C のまま写してある（変数の名前も合わせた）。写したのは、64 ビットの
//! 整数がある環境の経路（`FT_INT64` あり。x86-64 の Linux はこちら）:
//!
//! - `gray_render_line`（`prod` でセルの出口を決める版）・`gray_render_conic`（差分で刻む版）・
//!   `gray_render_cubic`（2 分割）・`gray_sweep`・`FT_FILL_RULE`（0 でない巻き数を塗る）
//! - `FT_Outline_Decompose`（`src/base/ftoutln.c`。点の並びを「移動・線・曲線」に直す）
//!
//! FreeType は、メモリを節約するために絵を帯に分けて塗る（`gray_convert_glyph`）。帯の分け方は結果に
//! 効かない（線 1 本ごとの計算は帯によらず同じで、帯の外のセルは捨てるだけ）ので、ここでは絵の全体を
//! 1 つの帯として塗る。本物は 403 px の字で帯を 4 つ以上に分けるが、それでも全画素が一致することを
//! 突き合わせで確かめてある。

/// 1 画素を何ビットで刻むか（`PIXEL_BITS`）。
const PIXEL_BITS: u32 = 8;
/// 1 画素の長さ（`ONE_PIXEL`）。
const ONE_PIXEL: i32 = 1 << PIXEL_BITS;

/// 点の種類（`FT_CURVE_TAG_*`）: 輪郭の上の点。
pub const TAG_ON: u8 = 1;
/// 点の種類: 2 次の曲線の制御点。
pub const TAG_CONIC: u8 = 0;
/// 点の種類: 3 次の曲線の制御点。
pub const TAG_CUBIC: u8 = 2;

/// FreeType の `FT_Outline` と同じ形の輪郭（座標は 26.6 の固定小数）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outline {
    /// 点（x, y）。y は上が正。
    pub points: Vec<(i32, i32)>,
    /// 点ごとの種類（[`TAG_ON`]・[`TAG_CONIC`]・[`TAG_CUBIC`]）。
    pub tags: Vec<u8>,
    /// 輪郭ごとの「最後の点の番号」。
    pub contours: Vec<usize>,
}

/// セル 1 つ（`TCell`）。`cover` はこのセルを横切った高さ、`area` は左側の面積の 2 倍。
#[derive(Clone, Copy)]
struct Cell {
    x: i32,
    cover: i32,
    area: i32,
}

/// 塗りの作業台（`gray_TWorker`）。
struct Worker {
    /// 横の範囲（`min_ex`〜`max_ex`）。
    max_ex: i32,
    /// 縦の範囲（`min_ey`〜`max_ey`）。
    max_ey: i32,
    /// 行ごとのセル（x の小さい順）。
    rows: Vec<Vec<Cell>>,
    /// いまのセル（行・その中の位置）。範囲の外なら `None`（C では捨て場のセル）。
    cell: Option<(usize, usize)>,
    /// いまの位置（24.8 の固定小数）。
    x: i64,
    y: i64,
}

/// `TRUNC`。
fn trunc(v: i64) -> i32 {
    (v >> PIXEL_BITS) as i32
}

/// `FRACT`。
fn fract(v: i64) -> i32 {
    (v & i64::from(ONE_PIXEL - 1)) as i32
}

/// `UPSCALE`（26.6 → 24.8）。
fn upscale(v: i32) -> i64 {
    i64::from(v) * i64::from(ONE_PIXEL >> 6)
}

/// `FT_UDIV`（割り算を、先に作った逆数との掛け算で済ませる。C と同じ切り捨てになるよう、そのまま写す）。
fn udiv(a: i64, reciprocal: i64) -> i32 {
    ((a as u64).wrapping_mul(reciprocal as u64) >> 32) as i32
}

impl Worker {
    /// `gray_set_cell`。いまのセルを (ex, ey) に移す。無ければ作る。
    fn set_cell(&mut self, ex: i32, ey: i32) {
        if ey < 0 || ey >= self.max_ey || ex >= self.max_ex {
            self.cell = None;
            return;
        }
        // 左にはみ出したセルは、すぐ左の 1 つにまとめる（`min_ex - 1`。ここでは min_ex は 0）。
        let ex = ex.max(-1);
        let row = &mut self.rows[ey as usize];
        let at = match row.binary_search_by(|cell| cell.x.cmp(&ex)) {
            Ok(at) => at,
            Err(at) => {
                row.insert(
                    at,
                    Cell {
                        x: ex,
                        cover: 0,
                        area: 0,
                    },
                );
                at
            }
        };
        self.cell = Some((ey as usize, at));
    }

    /// `FT_INTEGRATE`。いまのセルに、高さ `a` と面積 `a * b` を足す。
    fn integrate(&mut self, a: i32, b: i32) {
        if let Some((row, at)) = self.cell {
            let cell = &mut self.rows[row][at];
            cell.cover = cell.cover.wrapping_add(a);
            cell.area = cell.area.wrapping_add(a.wrapping_mul(b));
        }
    }

    /// `gray_render_line`（`FT_INT64` がある版）。いまの位置から (to_x, to_y) までの線を、通るセルに配る。
    fn render_line(&mut self, to_x: i64, to_y: i64) {
        let mut ey1 = trunc(self.y);
        let ey2 = trunc(to_y);
        // 縦に範囲の外なら何もしない。
        if !((ey1 >= self.max_ey && ey2 >= self.max_ey) || (ey1 < 0 && ey2 < 0)) {
            let mut ex1 = trunc(self.x);
            let ex2 = trunc(to_x);
            let mut fx1 = fract(self.x);
            let mut fy1 = fract(self.y);
            let dx = to_x - self.x;
            let dy = to_y - self.y;
            let one = i64::from(ONE_PIXEL);
            let mut finish = true;
            if ex1 == ex2 && ey1 == ey2 {
                // 1 つのセルの中
            } else if dy == 0 {
                // 横線
                self.set_cell(ex2, ey2);
                finish = false;
            } else if dx == 0 {
                if dy > 0 {
                    // 縦線（上へ）
                    loop {
                        let fy2 = ONE_PIXEL;
                        self.integrate(fy2 - fy1, fx1 * 2);
                        fy1 = 0;
                        ey1 += 1;
                        self.set_cell(ex1, ey1);
                        if ey1 == ey2 {
                            break;
                        }
                    }
                } else {
                    // 縦線（下へ）
                    loop {
                        let fy2 = 0;
                        self.integrate(fy2 - fy1, fx1 * 2);
                        fy1 = ONE_PIXEL;
                        ey1 -= 1;
                        self.set_cell(ex1, ey1);
                        if ey1 == ey2 {
                            break;
                        }
                    }
                }
            } else {
                // 斜めの線。`prod` が、いまのセルをどの辺から出るかと、その位置を決める。
                let mut prod = dx * i64::from(fy1) - dy * i64::from(fx1);
                let dx_r: i64 = if ex1 != ex2 { 0xFFFF_FFFF / dx } else { 0 };
                let dy_r: i64 = if ey1 != ey2 { 0xFFFF_FFFF / dy } else { 0 };
                loop {
                    if prod - dx * one > 0 && prod <= 0 {
                        // 左へ出る
                        let fx2 = 0;
                        let fy2 = udiv(-prod, -dx_r);
                        prod -= dy * one;
                        self.integrate(fy2 - fy1, fx1 + fx2);
                        fx1 = ONE_PIXEL;
                        fy1 = fy2;
                        ex1 -= 1;
                    } else if prod - dx * one + dy * one > 0 && prod - dx * one <= 0 {
                        // 上へ出る
                        prod -= dx * one;
                        let fx2 = udiv(-prod, dy_r);
                        let fy2 = ONE_PIXEL;
                        self.integrate(fy2 - fy1, fx1 + fx2);
                        fx1 = fx2;
                        fy1 = 0;
                        ey1 += 1;
                    } else if prod + dy * one >= 0 && prod - dx * one + dy * one <= 0 {
                        // 右へ出る
                        prod += dy * one;
                        let fx2 = ONE_PIXEL;
                        let fy2 = udiv(prod, dx_r);
                        self.integrate(fy2 - fy1, fx1 + fx2);
                        fx1 = 0;
                        fy1 = fy2;
                        ex1 += 1;
                    } else {
                        // 下へ出る
                        let fx2 = udiv(prod, -dy_r);
                        let fy2 = 0;
                        prod += dx * one;
                        self.integrate(fy2 - fy1, fx1 + fx2);
                        fx1 = fx2;
                        fy1 = ONE_PIXEL;
                        ey1 -= 1;
                    }
                    self.set_cell(ex1, ey1);
                    if ex1 == ex2 && ey1 == ey2 {
                        break;
                    }
                }
            }
            if finish {
                let fx2 = fract(to_x);
                let fy2 = fract(to_y);
                self.integrate(fy2 - fy1, fx1 + fx2);
            }
        }
        self.x = to_x;
        self.y = to_y;
    }

    /// 曲線の全部の点が、縦に範囲の外か（`short-cut the arc that crosses the current band`）。
    fn outside(&self, ys: &[i64]) -> bool {
        ys.iter().all(|y| trunc(*y) >= self.max_ey) || ys.iter().all(|y| trunc(*y) < 0)
    }

    /// `gray_render_conic`（`FT_INT64` がある版）。2 次の曲線を、差分を足しながら短い線に刻む。
    fn render_conic(&mut self, control: (i32, i32), to: (i32, i32)) {
        let p0 = (self.x, self.y);
        let p1 = (upscale(control.0), upscale(control.1));
        let p2 = (upscale(to.0), upscale(to.1));
        if self.outside(&[p0.1, p1.1, p2.1]) {
            self.x = p2.0;
            self.y = p2.1;
            return;
        }
        let bx = p1.0 - p0.0;
        let by = p1.1 - p0.1;
        let ax = p2.0 - p1.0 - bx;
        let ay = p2.1 - p1.1 - by;
        let mut dx = ax.abs().max(ay.abs());
        if dx <= i64::from(ONE_PIXEL / 4) {
            self.render_line(p2.0, p2.1);
            return;
        }
        // 2 つに割るたびに、ずれはちょうど 1/4 になる。要る本数は先に決まる。
        let mut shift = 16u32;
        loop {
            dx >>= 2;
            shift -= 1;
            if dx <= i64::from(ONE_PIXEL / 4) {
                break;
            }
        }
        let mut count = 0x10000u32 >> shift;
        let left = |a: i64, b: u32| ((a as u64) << b) as i64;
        let mut rx = left(ax, shift + shift);
        let mut ry = left(ay, shift + shift);
        let mut qx = left(bx, shift + 17).wrapping_add(rx);
        let mut qy = left(by, shift + 17).wrapping_add(ry);
        rx = rx.wrapping_mul(2);
        ry = ry.wrapping_mul(2);
        let mut px = left(p0.0, 32);
        let mut py = left(p0.1, 32);
        loop {
            px = px.wrapping_add(qx);
            py = py.wrapping_add(qy);
            qx = qx.wrapping_add(rx);
            qy = qy.wrapping_add(ry);
            self.render_line(px >> 32, py >> 32);
            count -= 1;
            if count == 0 {
                break;
            }
        }
    }

    /// `gray_render_cubic`。3 次の曲線を、十分まっすぐになるまで 2 つに割って線にする。
    fn render_cubic(&mut self, control1: (i32, i32), control2: (i32, i32), to: (i32, i32)) {
        // C と同じ深さの置き場（`bez_stack[16 * 3 + 1]`）。
        let mut bez = [(0i64, 0i64); 16 * 3 + 1];
        let mut arc = 0usize;
        bez[0] = (upscale(to.0), upscale(to.1));
        bez[1] = (upscale(control2.0), upscale(control2.1));
        bez[2] = (upscale(control1.0), upscale(control1.1));
        bez[3] = (self.x, self.y);
        if self.outside(&[bez[0].1, bez[1].1, bez[2].1, bez[3].1]) {
            self.x = bez[0].0;
            self.y = bez[0].1;
            return;
        }
        let half = i64::from(ONE_PIXEL / 2);
        loop {
            let (a0, a1, a2, a3) = (bez[arc], bez[arc + 1], bez[arc + 2], bez[arc + 3]);
            // 制御点が、弦を 3 等分する点に十分近づいたら線で描く。
            let flat = (2 * a0.0 - 3 * a1.0 + a3.0).abs() <= half
                && (2 * a0.1 - 3 * a1.1 + a3.1).abs() <= half
                && (a0.0 - 3 * a2.0 + 2 * a3.0).abs() <= half
                && (a0.1 - 3 * a2.1 + 2 * a3.1).abs() <= half;
            // 置き場が尽きたら割らずに描く（C は尽きない前提。座標が 32 ビットに収まる限り尽きない）。
            if !flat && arc + 6 < bez.len() {
                split_cubic(&mut bez[arc..arc + 7]);
                arc += 3;
                continue;
            }
            self.render_line(a0.0, a0.1);
            if arc == 0 {
                return;
            }
            arc -= 3;
        }
    }

    /// `gray_move_to`。
    fn move_to(&mut self, to: (i32, i32)) {
        let x = upscale(to.0);
        let y = upscale(to.1);
        self.set_cell(trunc(x), trunc(y));
        self.x = x;
        self.y = y;
    }

    /// `gray_line_to`。
    fn line_to(&mut self, to: (i32, i32)) {
        self.render_line(upscale(to.0), upscale(to.1));
    }

    /// `gray_sweep`。行ごとにセルを左から足し上げて、濃さを書く。`target` は上の行が先。
    fn sweep(&self, target: &mut [u8], width: usize) {
        let height = self.rows.len();
        for (y, cells) in self.rows.iter().enumerate() {
            // FreeType の y は下が 0。絵は上の行が先。
            let line = &mut target[(height - 1 - y) * width..(height - y) * width];
            let mut x = 0i32;
            let mut cover = 0i32;
            for cell in cells {
                if cover != 0 && cell.x > x {
                    line[x as usize..cell.x as usize].fill(fill_rule(cover));
                }
                cover = cover.wrapping_add(cell.cover.wrapping_mul(ONE_PIXEL * 2));
                let area = cover.wrapping_sub(cell.area);
                if area != 0 && cell.x >= 0 {
                    line[cell.x as usize] = fill_rule(area);
                }
                x = cell.x + 1;
            }
            if cover != 0 {
                // 右へはみ出した分（切り取られたときだけ）。
                line[x as usize..].fill(fill_rule(cover));
            }
        }
    }
}

/// `FT_FILL_RULE`（0 でない巻き数を塗る方）。面積を 0〜255 の濃さにする。
fn fill_rule(area: i32) -> u8 {
    let mut coverage = area >> (PIXEL_BITS * 2 + 1 - 8);
    if coverage < 0 {
        coverage = !coverage;
    }
    if coverage > 255 {
        coverage = 255;
    }
    coverage as u8
}

/// `gray_split_cubic`。3 次の曲線を真ん中で 2 つに割る（`base[0..4]` → `base[0..7]`）。
fn split_cubic(base: &mut [(i64, i64)]) {
    /// 1 つの軸ぶん。
    fn axis(p: [i64; 4]) -> [i64; 7] {
        let mut a = p[0] + p[1];
        let b = p[1] + p[2];
        let mut c = p[2] + p[3];
        let b5 = c >> 1;
        c += b;
        let b4 = c >> 2;
        let b1 = a >> 1;
        a += b;
        let b2 = a >> 2;
        let b3 = (a + c) >> 3;
        [p[0], b1, b2, b3, b4, b5, p[3]]
    }
    let xs = axis([base[0].0, base[1].0, base[2].0, base[3].0]);
    let ys = axis([base[0].1, base[1].1, base[2].1, base[3].1]);
    for (i, point) in base.iter_mut().enumerate().take(7) {
        *point = (xs[i], ys[i]);
    }
}

/// `FT_Outline_Decompose`。点の並びを「移動・線・曲線」に直して作業台に渡す。
///
/// 形の崩れた輪郭（3 次の制御点で始まる・制御点の数が合わない）は `false`（FreeType はその字を
/// 描かずに誤りを返す）。
fn decompose(outline: &Outline, worker: &mut Worker) -> bool {
    let points = &outline.points;
    let tags = &outline.tags;
    let mut first = 0usize;
    for &last in &outline.contours {
        if last < first || last >= points.len() || tags.len() != points.len() {
            return false;
        }
        // C のポインタと同じ動きをする番号。制御点で始まる輪郭では、最初の点の 1 つ前から始める。
        let mut point = first as isize;
        let mut limit = last as isize;
        let mut v_start = points[first];
        match tags[first] & 3 {
            TAG_CUBIC => return false,
            TAG_CONIC => {
                if tags[last] & 3 == TAG_ON {
                    // 最後の点が輪郭の上なら、そこから始める。
                    v_start = points[last];
                    limit -= 1;
                } else {
                    // 最初も最後も制御点なら、2 点の真ん中から始める。
                    let v_last = points[last];
                    v_start = ((v_start.0 + v_last.0) / 2, (v_start.1 + v_last.1) / 2);
                }
                point -= 1;
            }
            _ => {}
        }
        worker.move_to(v_start);
        let mut closed = false;
        'contour: while point < limit {
            point += 1;
            match tags[point as usize] & 3 {
                TAG_ON => worker.line_to(points[point as usize]),
                TAG_CONIC => {
                    let mut v_control = points[point as usize];
                    loop {
                        if point >= limit {
                            worker.render_conic(v_control, v_start);
                            closed = true;
                            break 'contour;
                        }
                        point += 1;
                        let vec = points[point as usize];
                        match tags[point as usize] & 3 {
                            TAG_ON => {
                                worker.render_conic(v_control, vec);
                                continue 'contour;
                            }
                            TAG_CONIC => {
                                // 制御点が続くときは、間に「輪郭の上の点」があるものとして扱う。
                                let middle = ((v_control.0 + vec.0) / 2, (v_control.1 + vec.1) / 2);
                                worker.render_conic(v_control, middle);
                                v_control = vec;
                            }
                            _ => return false,
                        }
                    }
                }
                _ => {
                    // 3 次の制御点は 2 つ続く。
                    if point + 1 > limit || tags[(point + 1) as usize] & 3 != TAG_CUBIC {
                        return false;
                    }
                    point += 2;
                    let vec1 = points[(point - 2) as usize];
                    let vec2 = points[(point - 1) as usize];
                    if point <= limit {
                        worker.render_cubic(vec1, vec2, points[point as usize]);
                        continue;
                    }
                    worker.render_cubic(vec1, vec2, v_start);
                    closed = true;
                    break 'contour;
                }
            }
        }
        if !closed {
            // 線で閉じる。
            worker.line_to(v_start);
        }
        first = last + 1;
    }
    true
}

/// 輪郭を幅 `width`・高さ `rows` の絵（上の行が先、1 画素 1 バイト）に塗る。`gray_raster_render`。
///
/// 輪郭は、絵の左下を原点とする座標に移してあること（`ft_smooth_render` が塗る前にずらすのと同じ）。
pub fn render(outline: &Outline, width: usize, rows: usize) -> Vec<u8> {
    let mut target = vec![0u8; width * rows];
    if outline.points.is_empty() || outline.contours.is_empty() || width == 0 || rows == 0 {
        return target;
    }
    let mut worker = Worker {
        max_ex: width as i32,
        max_ey: rows as i32,
        rows: vec![Vec::new(); rows],
        cell: None,
        x: 0,
        y: 0,
    };
    if decompose(outline, &mut worker) {
        worker.sweep(&mut target, width);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 輪郭を作る（全部の点が輪郭の上）。
    fn polygon(points: &[(i32, i32)]) -> Outline {
        Outline {
            points: points.to_vec(),
            tags: vec![TAG_ON; points.len()],
            contours: vec![points.len() - 1],
        }
    }

    /// 画素にぴったりの四角は、中が 255・外が 0 になること。
    #[test]
    fn a_pixel_aligned_square_is_solid() {
        let square = polygon(&[(64, 64), (64, 192), (192, 192), (192, 64)]);
        let got = render(&square, 4, 4);
        #[rustfmt::skip]
        let want = [
            0, 0, 0, 0,
            0, 255, 255, 0,
            0, 255, 255, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(got, want);
    }

    /// 半画素ずれた四角の縁は、覆った割合の濃さになること（FreeType では、半分は 128、4 分の 1 は 64）。
    #[test]
    fn a_half_pixel_square_has_proportional_edges() {
        let square = polygon(&[(32, 32), (32, 160), (160, 160), (160, 32)]);
        let got = render(&square, 3, 3);
        #[rustfmt::skip]
        let want = [
            64, 128, 64,
            128, 255, 128,
            64, 128, 64,
        ];
        assert_eq!(got, want);
    }

    /// 向きを逆にしても、ほぼ同じ絵になること（0 でない巻き数を塗る）。
    ///
    /// FreeType は負の面積を「ビット反転」で正にするので、向きが逆だと濃さが 1 だけ違うことがある。
    /// それも含めて写してある（基準は本物の FreeType の出力で確かめている）。
    #[test]
    fn winding_direction_changes_coverage_by_at_most_one() {
        let a = polygon(&[(10, 20), (30, 200), (220, 180), (190, 15)]);
        let mut b = a.clone();
        b.points.reverse();
        let (one, other) = (render(&a, 4, 4), render(&b, 4, 4));
        assert_eq!(
            one,
            [
                13, 5, 0, 0, 154, 254, 232, 77, 183, 255, 255, 50, 144, 186, 192, 8
            ]
        );
        for (p, q) in one.iter().zip(&other) {
            assert!(p.abs_diff(*q) <= 1, "{one:?} / {other:?}");
        }
        assert_ne!(one, other, "負の面積の丸めの違いが出る例");
    }

    /// 斜めの線の三角は、上の行が先で、左下の半分が塗られること。
    #[test]
    fn a_triangle_fills_the_lower_left_half() {
        let triangle = polygon(&[(0, 0), (0, 128), (128, 0)]);
        // 上の行（y=1〜2）は左の 1 画素が半分、下の行は左が全部・右が半分。
        assert_eq!(render(&triangle, 2, 2), [128, 0, 255, 128]);
    }

    /// 3 次の曲線の円が塗られること（中は塗りつぶし、角は半端な濃さ、左右・上下でほぼ同じ）。
    #[test]
    fn a_cubic_circle_is_filled() {
        // 半径 2 画素の円（中心 (128, 128)）。制御点までの長さは半径 × 0.5523。
        let (c, r, k) = (128, 128, 71);
        let circle = Outline {
            points: vec![
                (c + r, c),
                (c + r, c + k),
                (c + k, c + r),
                (c, c + r),
                (c - k, c + r),
                (c - r, c + k),
                (c - r, c),
                (c - r, c - k),
                (c - k, c - r),
                (c, c - r),
                (c + k, c - r),
                (c + r, c - k),
            ],
            tags: [TAG_ON, TAG_CUBIC, TAG_CUBIC].repeat(4),
            contours: vec![11],
        };
        let got = render(&circle, 4, 4);
        for y in 0..4 {
            for x in 0..4 {
                assert!(
                    got[y * 4 + x].abs_diff(got[y * 4 + (3 - x)]) <= 1,
                    "左右 ({x}, {y})"
                );
                assert!(
                    got[y * 4 + x].abs_diff(got[(3 - y) * 4 + x]) <= 1,
                    "上下 ({x}, {y})"
                );
            }
        }
        assert_eq!(
            [got[5], got[6], got[9], got[10]],
            [255; 4],
            "中は塗りつぶし"
        );
        assert_eq!(got[0], 73, "角は半端な濃さ");
        // 円の面積は π × 2²＝12.57 画素（× 256 で 3217）。FreeType は曲線を粗く刻む（1/8 画素までのずれを
        // 許す）ので、内側に寄って少し小さくなる。その値まで同じであること。
        let total: u32 = got.iter().map(|v| u32::from(*v)).sum();
        assert_eq!(total, 3124);
    }

    /// 2 次の曲線も塗れること（制御点だけの輪郭＝TrueType の丸）。
    #[test]
    fn conic_contours_are_filled() {
        let round = Outline {
            points: vec![(0, 0), (256, 0), (256, 256), (0, 256)],
            tags: vec![TAG_CONIC; 4],
            contours: vec![3],
        };
        let got = render(&round, 4, 4);
        assert_eq!([got[5], got[6], got[9], got[10]], [255; 4]);
        for corner in [got[0], got[3], got[12], got[15]] {
            assert!(corner.abs_diff(102) <= 1, "{got:?}");
        }
        // 制御点で始まり、最後が輪郭の上の点の輪郭（最後の点から始める）。
        let from_last = Outline {
            points: vec![(256, 0), (256, 256), (0, 256), (0, 0)],
            tags: vec![TAG_CONIC, TAG_ON, TAG_ON, TAG_ON],
            contours: vec![3],
        };
        let got = render(&from_last, 4, 4);
        // 左下から右下の角を回って右上へ丸く進み、上の辺と左の辺はまっすぐ。右下の角だけが欠ける。
        #[rustfmt::skip]
        let want = [
            255, 255, 255, 237,
            255, 255, 255, 197,
            255, 255, 255, 76,
            237, 197, 77, 0,
        ];
        assert_eq!(got, want);
    }

    /// 形の崩れた輪郭は描かないこと（落ちない）。
    #[test]
    fn malformed_outlines_draw_nothing() {
        let starts_with_cubic = Outline {
            points: vec![(0, 0), (64, 64), (128, 0)],
            tags: vec![TAG_CUBIC, TAG_CUBIC, TAG_ON],
            contours: vec![2],
        };
        assert_eq!(render(&starts_with_cubic, 2, 2), [0; 4]);
        let lonely_cubic = Outline {
            points: vec![(0, 0), (64, 64), (128, 0)],
            tags: vec![TAG_ON, TAG_CUBIC, TAG_ON],
            contours: vec![2],
        };
        assert_eq!(render(&lonely_cubic, 2, 2), [0; 4]);
        let bad_end = Outline {
            points: vec![(0, 0), (64, 64)],
            tags: vec![TAG_ON, TAG_ON],
            contours: vec![5],
        };
        assert_eq!(render(&bad_end, 2, 2), [0; 4]);
        assert_eq!(render(&Outline::default(), 2, 2), [0; 4]);
    }

    /// 絵からはみ出す輪郭は、はみ出した分を捨てること（左にはみ出した分は、塗りの足し上げには効く）。
    #[test]
    fn outlines_are_clipped_to_the_bitmap() {
        // 左へ 1 画素・上へ 1 画素はみ出した四角。見えるのは左上の 1 画素ぶん。
        let square = polygon(&[(-64, 64), (-64, 192), (64, 192), (64, 64)]);
        assert_eq!(render(&square, 2, 2), [255, 0, 0, 0]);
        // 右へはみ出す。
        let square = polygon(&[(64, 0), (64, 64), (256, 64), (256, 0)]);
        assert_eq!(render(&square, 2, 2), [0, 0, 0, 255]);
    }
}
