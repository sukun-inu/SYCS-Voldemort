//! Pillow 13.0.0 の図形の描画の写し（`src/libImaging/Draw.c`・`src/_imaging.c` の `_draw_*`・
//! `PIL/ImageDraw.py` の `polygon`・`line`・`rectangle`・`ellipse`・`rounded_rectangle`）。
//!
//! 地震の地図（Python の `_generate_intensity_map`）を、Python が作るものと画素まで同じにするためのもの。
//! **原典の計算の型（int・float・double）と順をそのまま写している。** 読みやすく書き直すと丸めが変わって
//! 画素がずれるので、式の形を変えないこと（変えるなら `tests/earthquake_map_golden.rs` が見張っている）。
//!
//! 描く先は RGBA の画像。Pillow の `ImageDraw.Draw(RGBA の画像)` と同じく、色は **上書き** する（混ぜない。
//! アルファもそのまま書く）。座標は Pillow と同じく小数で受け、C に渡すところで 0 の方へ切り捨てる
//! （`(int)xy[i]`）。画像の外にはみ出す分は描かない。

use image::RgbaImage;

/// 色（R・G・B・A）。
pub type Ink = [u8; 4];

/// 図形が描けなかった理由（Pillow が例外にするもの）。地図は、これが出たら作るのをやめる（Python も例外で
/// 地図なしになる）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeError {
    /// 右が左より小さい（`x1 must be greater than or equal to x0`）。
    XOrder,
    /// 下が上より小さい（`y1 must be greater than or equal to y0`）。
    YOrder,
    /// 点が足りない（`coordinate list must contain at least 2 coordinates`）。
    TooFewPoints,
}

/// C の `(int)` と同じ切り捨て（0 の方へ）。
fn c_int(v: f64) -> i32 {
    v as i32
}

/// `ROUND_UP(f)`（f が float のとき）。0 から遠い方へ丸める。正の数は float のまま 0.5 を足し、負の数は
/// double で足す（C の式 `floor((f) + 0.5F)` と `-floor(fabs(f) + 0.5F)` の型の違いをそのまま写す）。
fn round_up_f32(f: f32) -> i32 {
    if f >= 0.0 {
        f64::from(f + 0.5_f32).floor() as i32
    } else {
        (-(f64::from(f).abs() + 0.5).floor()) as i32
    }
}

/// `ROUND_DOWN(f)`（f が float のとき）。0 に近い方へ丸める。
fn round_down_f32(f: f32) -> i32 {
    if f >= 0.0 {
        f64::from(f - 0.5_f32).ceil() as i32
    } else {
        (-(f64::from(f).abs() - 0.5).ceil()) as i32
    }
}

/// `ROUND_UP(f)`（f が double のとき）。
fn round_up_f64(f: f64) -> i32 {
    if f >= 0.0 {
        (f + 0.5).floor() as i32
    } else {
        (-(f.abs() + 0.5).floor()) as i32
    }
}

/// `ROUND_DOWN(f)`（f が double のとき）。
fn round_down_f64(f: f64) -> i32 {
    if f >= 0.0 {
        (f - 0.5).ceil() as i32
    } else {
        (-(f.abs() - 0.5).ceil()) as i32
    }
}

/// 1 点（`point32`）。画像の外なら何もしない。
fn point(img: &mut RgbaImage, x: i32, y: i32, ink: Ink) {
    if x >= 0 && y >= 0 && (x as u32) < img.width() && (y as u32) < img.height() {
        img.put_pixel(x as u32, y as u32, image::Rgba(ink));
    }
}

/// 横の 1 本（`hline32`）。`x0` から `x1` まで（両端を含む）。
fn hline(img: &mut RgbaImage, mut x0: i32, y: i32, mut x1: i32, ink: Ink) {
    let (width, height) = (img.width() as i32, img.height() as i32);
    if y < 0 || y >= height {
        return;
    }
    if x0 < 0 {
        x0 = 0;
    } else if x0 >= width {
        return;
    }
    if x1 < 0 {
        return;
    } else if x1 >= width {
        x1 = width - 1;
    }
    if x0 > x1 {
        return;
    }
    let row = y as usize * width as usize * 4;
    let buffer: &mut [u8] = img;
    let (pixels, _) =
        buffer[row + x0 as usize * 4..row + (x1 as usize + 1) * 4].as_chunks_mut::<4>();
    pixels.fill(ink);
}

/// 太さ 1 の線（`line`。ブレゼンハム）。終わりの点は描かない。
fn thin_line(img: &mut RgbaImage, mut x0: i32, mut y0: i32, x1: i32, y1: i32, ink: Ink) {
    let mut dy = y1 - y0;
    let ys;
    if dy < 0 {
        dy = -dy;
        ys = -1;
    } else if dy == 0 {
        // 横の線。
        if x1 > x0 {
            hline(img, x0, y0, x1 - 1, ink);
        } else if x0 > x1 {
            hline(img, x1 + 1, y0, x0, ink);
        }
        return;
    } else {
        ys = 1;
    }
    let mut dx = x1 - x0;
    let xs;
    if dx < 0 {
        dx = -dx;
        xs = -1;
    } else {
        xs = 1;
    }
    if dx == 0 {
        // 縦の線。
        for _ in 0..dy {
            point(img, x0, y0, ink);
            y0 += ys;
        }
    } else if dx > dy {
        // 横に寝た線。
        let n = dx;
        dy += dy;
        let mut e = dy - dx;
        dx += dx;
        for _ in 0..n {
            point(img, x0, y0, ink);
            if e >= 0 {
                y0 += ys;
                e -= dx;
            }
            e += dy;
            x0 += xs;
        }
    } else {
        // 縦に立った線。
        let n = dy;
        dx += dx;
        let mut e = dx - dy;
        dy += dy;
        for _ in 0..n {
            point(img, x0, y0, ink);
            if e >= 0 {
                x0 += xs;
                e -= dy;
            }
            e += dx;
            y0 += ys;
        }
    }
}

/// 多角形の辺（`Edge`）。
#[derive(Clone, Copy, Debug, Default)]
struct Edge {
    x0: i32,
    y0: i32,
    xmin: i32,
    ymin: i32,
    xmax: i32,
    ymax: i32,
    dx: f32,
}

/// 辺を作る（`add_edge`）。
fn edge(x0: i32, y0: i32, x1: i32, y1: i32) -> Edge {
    let (xmin, xmax) = if x0 <= x1 { (x0, x1) } else { (x1, x0) };
    let (ymin, ymax) = if y0 <= y1 { (y0, y1) } else { (y1, y0) };
    let dx = if y0 == y1 {
        0.0
    } else {
        (x1 - x0) as f32 / (y1 - y0) as f32
    };
    Edge {
        x0,
        y0,
        xmin,
        ymin,
        xmax,
        ymax,
        dx,
    }
}

/// 辺 `e` の、高さ `y` での x（float の計算のまま）。
fn edge_x(e: &Edge, y: i32) -> f32 {
    (y - e.y0) as f32 * e.dx + e.x0 as f32
}

/// 塗りつぶした多角形（`polygon_generic` の、色を混ぜない側）。走査線ごとに辺との交点を並べて、対ごとに塗る。
fn polygon_generic(img: &mut RgbaImage, edges: &[Edge], ink: Ink) {
    if edges.is_empty() {
        return;
    }
    let ysize = img.height() as i32;
    let mut ymin = ysize - 1;
    let mut ymax = 0;
    let mut table: Vec<&Edge> = Vec::with_capacity(edges.len());
    for e in edges {
        if ymin > e.ymin {
            ymin = e.ymin;
        }
        if ymax < e.ymax {
            ymax = e.ymax;
        }
        if e.ymin == e.ymax {
            // 横の辺は、その場で 1 本描く。
            hline(img, e.xmin, e.ymin, e.xmax, ink);
            continue;
        }
        table.push(e);
    }
    if ymin < 0 {
        ymin = 0;
    }
    if ymax > ysize {
        ymax = ysize;
    }
    let mut xx: Vec<f32> = Vec::with_capacity(table.len() * 2);
    for y in ymin..=ymax {
        xx.clear();
        for (i, current) in table.iter().enumerate() {
            if y < current.ymin || y > current.ymax {
                continue;
            }
            xx.push(edge_x(current, y));
            if y == current.ymax && y < ymax {
                // 辺の終わりは 2 回数える（つながった多角形を崩さないため）。
                let last = xx[xx.len() - 1];
                xx.push(last);
            } else if (y == current.ymin || y == current.ymax) && current.dx != 0.0 {
                // 離れて見える角をつなぐ。
                let j = xx.len() - 1;
                for other in &table[..i] {
                    if (y != other.ymin && y != other.ymax) || other.dx == 0.0 {
                        continue;
                    }
                    if xx[j].round() != edge_x(other, y).round() {
                        continue;
                    }
                    // 2 つの辺が角を作っている。次の行（最後の行なら前の行）での位置を見る。
                    let offset = if y == current.ymax { -1 } else { 1 };
                    let adjacent = edge_x(current, y + offset);
                    if y + offset >= other.ymin && y + offset <= other.ymax {
                        let adjacent_other = edge_x(other, y + offset);
                        if xx[j] > adjacent + 1.0 && xx[j] > adjacent_other + 1.0 {
                            xx[j] = (f64::from(adjacent).max(f64::from(adjacent_other)) as f32)
                                .round()
                                + 1.0;
                        } else if xx[j] < adjacent - 1.0 && xx[j] < adjacent_other - 1.0 {
                            xx[j] = (f64::from(adjacent).min(f64::from(adjacent_other)) as f32)
                                .round()
                                - 1.0;
                        }
                        break;
                    }
                }
            }
        }
        xx.sort_by(f32::total_cmp);
        for [left, right] in xx.as_chunks::<2>().0 {
            hline(img, round_up_f32(*left), y, round_down_f32(*right), ink);
        }
    }
}

/// 塗りつぶした多角形（`ImagingDrawPolygon` の fill の側）。`xy` は x・y の順に並べた整数。
fn fill_polygon(img: &mut RgbaImage, xy: &[i32], ink: Ink) {
    let count = xy.len() / 2;
    if count == 0 {
        return;
    }
    let mut edges: Vec<Edge> = Vec::with_capacity(count);
    for i in 0..count - 1 {
        let (x0, y0, x1, y1) = (xy[i * 2], xy[i * 2 + 1], xy[i * 2 + 2], xy[i * 2 + 3]);
        if y0 == y1 && i != 0 && y0 == xy[i * 2 - 1] {
            // 横の辺が続いている。同じ向きなら、前の辺を伸ばすだけにする。
            let previous_x = xy[i * 2 - 2];
            if let Some(last) = edges.last_mut() {
                if x1 > x0 && x0 > previous_x {
                    last.xmax = x1;
                    continue;
                } else if x1 < x0 && x0 < previous_x {
                    last.xmin = x1;
                    continue;
                }
            }
        }
        edges.push(edge(x0, y0, x1, y1));
    }
    let last = (count - 1) * 2;
    if xy[last] != xy[0] || xy[last + 1] != xy[1] {
        edges.push(edge(xy[last], xy[last + 1], xy[0], xy[1]));
    }
    polygon_generic(img, &edges, ink);
}

/// 太い線（`ImagingDrawWideLine`）。4 つの角を持つ多角形として塗る。
fn wide_line(img: &mut RgbaImage, x0: i32, y0: i32, x1: i32, y1: i32, ink: Ink, width: i32) {
    let (dx, dy) = (x1 - x0, y1 - y0);
    if dx == 0 && dy == 0 {
        point(img, x0, y0, ink);
        return;
    }
    let big_hypotenuse = f64::from(dx).hypot(f64::from(dy));
    let small_hypotenuse = f64::from(width - 1) / 2.0;
    let ratio_max = f64::from(round_up_f64(small_hypotenuse)) / big_hypotenuse;
    let ratio_min = f64::from(round_down_f64(small_hypotenuse)) / big_hypotenuse;
    let dxmin = round_down_f64(ratio_min * f64::from(dy));
    let dxmax = round_down_f64(ratio_max * f64::from(dy));
    let dymin = round_down_f64(ratio_min * f64::from(dx));
    let dymax = round_down_f64(ratio_max * f64::from(dx));
    let v = [
        (x0 - dxmin, y0 + dymax),
        (x1 - dxmin, y1 + dymax),
        (x1 + dxmax, y1 - dymin),
        (x0 + dxmax, y0 - dymin),
    ];
    let edges = [
        edge(v[0].0, v[0].1, v[1].0, v[1].1),
        edge(v[1].0, v[1].1, v[2].0, v[2].1),
        edge(v[2].0, v[2].1, v[3].0, v[3].1),
        edge(v[3].0, v[3].1, v[0].0, v[0].1),
    ];
    polygon_generic(img, &edges, ink);
}

/// 四角（`ImagingDrawRectangle`）。`fill` なら塗り、でなければ太さ `width` の枠。
fn c_rectangle(img: &mut RgbaImage, bounds: [i32; 4], ink: Ink, fill: bool, mut width: i32) {
    let [x0, mut y0, x1, mut y1] = bounds;
    if y0 > y1 {
        std::mem::swap(&mut y0, &mut y1);
    }
    let ysize = img.height() as i32;
    if fill {
        if y0 < 0 {
            y0 = 0;
        } else if y0 >= ysize {
            return;
        }
        if y1 < 0 {
            return;
        } else if y1 > ysize {
            y1 = ysize;
        }
        for y in y0..=y1 {
            hline(img, x0, y, x1, ink);
        }
    } else {
        if width == 0 {
            width = 1;
        }
        for i in 0..width {
            hline(img, x0, y0 + i, x1, ink);
            hline(img, x0, y1 - i, x1, ink);
            thin_line(img, x1 - i, y0 + width, x1 - i, y1 - width + 1, ink);
            thin_line(img, x0 + i, y0 + width, x0 + i, y1 - width + 1, ink);
        }
    }
}

// ── 楕円（`quarter_*`・`ellipse_*`） ─────────────────────────

/// 楕円の右上の 4 分の 1 を、2 刻みの格子の上でたどる（`quarter_state`）。
#[derive(Clone, Copy, Debug, Default)]
struct Quarter {
    cx: i32,
    cy: i32,
    ex: i32,
    ey: i32,
    a2: i64,
    b2: i64,
    a2b2: i64,
    finished: bool,
}

impl Quarter {
    /// `quarter_init`。
    fn new(a: i32, b: i32) -> Self {
        if a < 0 || b < 0 {
            return Self {
                finished: true,
                ..Self::default()
            };
        }
        let (a2, b2) = (i64::from(a) * i64::from(a), i64::from(b) * i64::from(b));
        Self {
            cx: a,
            cy: b % 2,
            ex: a % 2,
            ey: b,
            a2,
            b2,
            a2b2: a2 * b2,
            finished: false,
        }
    }

    /// 点が楕円の線からどれだけ離れているか（`quarter_delta`）。
    fn delta(&self, x: i64, y: i64) -> i64 {
        (self.a2 * y * y + self.b2 * x * x - self.a2b2).abs()
    }

    /// 次の点（`quarter_next`）。終わっていれば `None`。
    fn next(&mut self) -> Option<(i32, i32)> {
        if self.finished {
            return None;
        }
        let result = (self.cx, self.cy);
        if self.cx == self.ex && self.cy == self.ey {
            self.finished = true;
        } else {
            let mut nx = self.cx;
            let mut ny = self.cy + 2;
            let mut ndelta = self.delta(i64::from(nx), i64::from(ny));
            if nx > 1 {
                let diagonal = self.delta(i64::from(self.cx - 2), i64::from(self.cy + 2));
                if ndelta > diagonal {
                    nx = self.cx - 2;
                    ny = self.cy + 2;
                    ndelta = diagonal;
                }
                let sideways = self.delta(i64::from(self.cx - 2), i64::from(self.cy));
                if ndelta > sideways {
                    nx = self.cx - 2;
                    ny = self.cy;
                }
            }
            self.cx = nx;
            self.cy = ny;
        }
        Some(result)
    }
}

/// 太さのある楕円を、横の切れ端の並びとして出す（`ellipse_state`）。座標は 2 刻みの格子。
#[derive(Clone, Copy, Debug, Default)]
struct Ellipse {
    outer: Quarter,
    inner: Quarter,
    py: i32,
    pl: i32,
    pr: i32,
    cy: [i32; 4],
    cl: [i32; 4],
    cr: [i32; 4],
    bufcnt: usize,
    finished: bool,
    leftmost: i32,
}

impl Ellipse {
    /// `ellipse_init`。
    fn new(a: i32, b: i32, w: i32) -> Self {
        let mut s = Self {
            leftmost: a % 2,
            outer: Quarter::new(a, b),
            ..Self::default()
        };
        let first = if w < 1 { None } else { s.outer.next() };
        match first {
            None => s.finished = true,
            Some((x, y)) => {
                s.pr = x;
                s.py = y;
                s.inner = Quarter::new(a - 2 * (w - 1), b - 2 * (w - 1));
                s.pl = s.leftmost;
            }
        }
        s
    }

    /// 次の切れ端（左・高さ・右。`ellipse_next`）。
    fn next(&mut self) -> Option<(i32, i32, i32)> {
        if self.bufcnt == 0 {
            if self.finished {
                return None;
            }
            let y = self.py;
            let mut l = self.pl;
            let r = self.pr;
            // 外側を、次の高さに進むまでたどる。
            let mut reached = None;
            while let Some((cx, cy)) = self.outer.next() {
                if cy > y {
                    reached = Some((cx, cy));
                    break;
                }
            }
            match reached {
                None => self.finished = true,
                Some((cx, cy)) => {
                    self.pr = cx;
                    self.py = cy;
                }
            }
            // 内側も同じ高さまでたどる（たどった最後の x が、この高さの左の端）。
            let mut reached = None;
            while let Some((cx, cy)) = self.inner.next() {
                if cy > y {
                    reached = Some(cx);
                    break;
                }
                l = cx;
            }
            self.pl = reached.unwrap_or(self.leftmost);

            let mut push = |cl: i32, cy: i32, cr: i32| {
                self.cl[self.bufcnt] = cl;
                self.cy[self.bufcnt] = cy;
                self.cr[self.bufcnt] = cr;
                self.bufcnt += 1;
            };
            let has_right = l > 0 || l < r;
            let right_from = if l == 0 { 2 } else { l };
            if has_right && y > 0 {
                push(right_from, y, r);
            }
            if y > 0 {
                push(-r, y, -l);
            }
            if has_right {
                push(right_from, -y, r);
            }
            push(-r, -y, -l);
        }
        self.bufcnt -= 1;
        Some((
            self.cl[self.bufcnt],
            self.cy[self.bufcnt],
            self.cr[self.bufcnt],
        ))
    }
}

/// 楕円（`ellipseNew`）。`fill` なら塗り、でなければ太さ `width` の輪。
fn c_ellipse(img: &mut RgbaImage, bounds: [i32; 4], ink: Ink, fill: bool, mut width: i32) {
    let [x0, y0, x1, y1] = bounds;
    let (a, b) = (x1 - x0, y1 - y0);
    if a < 0 || b < 0 {
        return;
    }
    if fill {
        width = a + b;
    }
    let mut state = Ellipse::new(a, b, width);
    while let Some((left, y, right)) = state.next() {
        hline(
            img,
            x0 + (left + a) / 2,
            y0 + (y + b) / 2,
            x0 + (right + a) / 2,
            ink,
        );
    }
}

// ── 楕円を半平面で切る（弧・扇形。`clip_*`） ─────────────────────

/// 切り方の木の節の種類（`clip_type`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClipKind {
    /// 両方に入る部分。
    And,
    /// どちらかに入る部分。
    Or,
    /// 半平面 `a*x + b*y + c >= 0` で切る。
    Clip,
}

/// 切り方の木の節（`clip_node`）。子は `nodes` の中の番号。
#[derive(Clone, Copy, Debug)]
struct ClipNode {
    kind: ClipKind,
    a: f64,
    b: f64,
    c: f64,
    l: Option<usize>,
    r: Option<usize>,
}

impl ClipNode {
    /// 半平面の節。
    fn half_plane(a: f64, b: f64, c: f64) -> Self {
        Self {
            kind: ClipKind::Clip,
            a,
            b,
            c,
            l: None,
            r: None,
        }
    }

    /// 2 つをまとめる節。
    fn combine(kind: ClipKind, l: usize, r: usize) -> Self {
        Self {
            kind,
            a: 0.0,
            b: 0.0,
            c: 0.0,
            l: Some(l),
            r: Some(r),
        }
    }
}

/// 切れ端の端（x と、始まり = 1・終わり = -1）。
type Event = (i32, i8);

/// 横の切れ端 `x0..x1`（高さ `y`）を木で切る（`clip_tree_do_clip`）。残った切れ端の端を x の順に返す。
fn clip_segment(nodes: &[ClipNode], root: Option<usize>, x0: i32, y: i32, x1: i32) -> Vec<Event> {
    let Some(index) = root else {
        return vec![(x0, 1), (x1, -1)];
    };
    let node = nodes[index];
    if node.kind == ClipKind::Clip {
        let eps = 1e-9;
        let (a, b, c) = (node.a, node.b, node.c);
        let (mut x0, mut x1) = (x0, x1);
        let yf = f64::from(y);
        if a.abs() < eps {
            if b * yf + c < -eps {
                x0 = 1;
                x1 = 0;
            }
        } else {
            // 境の線と交わる x。
            let ix = -(b * yf + c) / a;
            if a * f64::from(x0) + b * yf + c < eps {
                x0 = f64::from(x0).max(ix).round() as i32;
            }
            if a * f64::from(x1) + b * yf + c < eps {
                x1 = f64::from(x1).min(ix).round() as i32;
            }
        }
        return if x0 <= x1 {
            vec![(x0, 1), (x1, -1)]
        } else {
            Vec::new()
        };
    }
    let left = clip_segment(nodes, node.l, x0, y, x1);
    let right = clip_segment(nodes, node.r, x0, y, x1);
    let mut out: Vec<Event> = Vec::new();
    let (mut i1, mut i2) = (0, 0);
    let (mut k1, mut k2) = (0_i32, 0_i32);
    while i1 < left.len() || i2 < right.len() {
        let take_left = i2 >= right.len()
            || (i1 < left.len()
                && (left[i1].0 < right[i2].0
                    || (left[i1].0 == right[i2].0 && left[i1].1 > right[i2].1)));
        let t = if take_left {
            let t = left[i1];
            k1 += i32::from(t.1);
            i1 += 1;
            t
        } else {
            let t = right[i2];
            k2 += i32::from(t.1);
            i2 += 1;
            t
        };
        let tail = out.last().map(|event| event.1);
        let keep = match node.kind {
            ClipKind::Or => (t.1 == 1 && tail != Some(1)) || (t.1 == -1 && k1 == 0 && k2 == 0),
            _ => {
                (t.1 == 1 && tail != Some(1) && k1 > 0 && k2 > 0)
                    || (t.1 == -1 && tail == Some(1) && (k1 == 0 || k2 == 0))
            }
        };
        if keep {
            out.push(t);
        }
    }
    out
}

/// 切った楕円（`clip_ellipse_state`）。
struct ClippedEllipse {
    state: Ellipse,
    nodes: Vec<ClipNode>,
    root: Option<usize>,
}

impl ClippedEllipse {
    /// 残った切れ端を全部描く（`clipEllipseNew` の中の繰り返し）。
    fn draw(mut self, img: &mut RgbaImage, x0: i32, y0: i32, a: i32, b: i32, ink: Ink) {
        while let Some((left, y, right)) = self.state.next() {
            let events = clip_segment(&self.nodes, self.root, left, y, right);
            for [start, end] in events.as_chunks::<2>().0 {
                hline(
                    img,
                    x0 + (start.0 + a) / 2,
                    y0 + (y + b) / 2,
                    x0 + (end.0 + a) / 2,
                    ink,
                );
            }
        }
    }
}

/// 角度を `0 <= al < 360`・`al <= ar <= al + 360` にそろえる（`normalize_angles`）。
fn normalize_angles(al: &mut f32, ar: &mut f32) {
    if *ar - *al >= 360.0 {
        *al = 0.0;
        *ar = 360.0;
    } else {
        let start = if *al < 0.0 {
            360.0 - (f64::from(-*al) % 360.0)
        } else {
            f64::from(*al)
        };
        *al = (start % 360.0) as f32;
        let sweep = if *ar < *al {
            360.0 - (f64::from(*al - *ar) % 360.0)
        } else {
            f64::from(*ar - *al)
        };
        *ar = (f64::from(*al) + sweep % 360.0) as f32;
    }
}

/// 度を弧度に（C の式 `al * M_PI / 180.0` のまま）。
fn degrees(al: f32) -> f64 {
    f64::from(al) * std::f64::consts::PI / 180.0
}

/// 弧（`arc_init`）。端は楕円の線に直角に切る。
fn arc_init(a: i32, b: i32, w: i32, mut al: f32, mut ar: f32) -> ClippedEllipse {
    if a < b {
        // 縦長は、横長にして作ってから軸を入れ替える。
        let mut s = arc_init(b, a, w, 90.0 - ar, 90.0 - al);
        s.state = Ellipse::new(a, b, w);
        for node in &mut s.nodes {
            if node.kind == ClipKind::Clip {
                std::mem::swap(&mut node.a, &mut node.b);
            }
        }
        return s;
    }
    let state = Ellipse::new(a, b, w);
    normalize_angles(&mut al, &mut ar);
    let mut nodes: Vec<ClipNode> = Vec::with_capacity(7);
    if ar == al + 360.0 {
        return ClippedEllipse {
            state,
            nodes,
            root: None,
        };
    }
    let (af, bf) = (f64::from(a), f64::from(b));
    // C は int のまま a*a - b*b を計算する。
    let focal = f64::from(a.wrapping_mul(a).wrapping_sub(b.wrapping_mul(b)));
    let pi = std::f64::consts::PI;
    let lc = ClipNode::half_plane(
        -af * degrees(al).sin(),
        bf * degrees(al).cos(),
        focal * (f64::from(al) * pi / 90.0).sin() / 2.0,
    );
    let rc = ClipNode::half_plane(
        af * degrees(ar).sin(),
        -bf * degrees(ar).cos(),
        -focal * (f64::from(ar) * pi / 90.0).sin() / 2.0,
    );
    nodes.push(lc);
    nodes.push(rc);
    let narrow = if ar - al < 180.0 {
        ClipKind::And
    } else {
        ClipKind::Or
    };
    let half_turns = |angle: f32| (angle / 180.0) as i32;
    let root = if f64::from(al) % 180.0 == 0.0 || f64::from(ar) % 180.0 == 0.0 {
        nodes.push(ClipNode::combine(narrow, 0, 1));
        2
    } else if (half_turns(al) + half_turns(ar)) % 2 == 1 {
        let side = |angle: f32| {
            if half_turns(angle) % 2 == 0 {
                1.0
            } else {
                -1.0
            }
        };
        nodes.push(ClipNode::half_plane(0.0, side(al), 0.0)); // 2
        nodes.push(ClipNode::half_plane(0.0, side(ar), 0.0)); // 3
        nodes.push(ClipNode::combine(ClipKind::And, 2, 0)); // 4
        nodes.push(ClipNode::combine(ClipKind::And, 3, 1)); // 5
        nodes.push(ClipNode::combine(ClipKind::Or, 4, 5)); // 6
        6
    } else {
        nodes.push(ClipNode::combine(narrow, 0, 1)); // 2
        let b_side = if ar < 180.0 || ar > 540.0 { 1.0 } else { -1.0 };
        nodes.push(ClipNode::half_plane(0.0, b_side, 0.0)); // 3
        nodes.push(ClipNode::combine(narrow, 2, 3)); // 4
        4
    };
    ClippedEllipse {
        state,
        nodes,
        root: Some(root),
    }
}

/// 扇形（`pie_init`）。
fn pie_init(a: i32, b: i32, w: i32, al: f32, ar: f32) -> ClippedEllipse {
    let state = Ellipse::new(a, b, w);
    let (af, bf) = (f64::from(a), f64::from(b));
    let (xl, xr) = (af * degrees(al).cos(), af * degrees(ar).cos());
    let (yl, yr) = (bf * degrees(al).sin(), bf * degrees(ar).sin());
    let mut nodes = vec![
        ClipNode::half_plane(-yl, xl, 0.0),
        ClipNode::half_plane(yr, -xr, 0.0),
    ];
    let kind = if ar - al < 180.0 {
        ClipKind::And
    } else {
        ClipKind::Or
    };
    nodes.push(ClipNode::combine(kind, 0, 1));
    let mut root = 2;
    if ar - al < 90.0 {
        // とがった先が飛び出さないように、もう 1 つ半平面で切る。
        nodes.push(ClipNode::half_plane((xl + xr) / 2.0, (yl + yr) / 2.0, 0.0));
        nodes.push(ClipNode::combine(ClipKind::And, 2, 3));
        root = 4;
    }
    ClippedEllipse {
        state,
        nodes,
        root: Some(root),
    }
}

/// 弧（`ImagingDrawArc`）。
fn c_arc(
    img: &mut RgbaImage,
    bounds: [i32; 4],
    mut start: f32,
    mut end: f32,
    ink: Ink,
    width: i32,
) {
    normalize_angles(&mut start, &mut end);
    if start + 360.0 == end {
        c_ellipse(img, bounds, ink, false, width);
        return;
    }
    if start == end {
        return;
    }
    let [x0, y0, x1, y1] = bounds;
    let (a, b) = (x1 - x0, y1 - y0);
    if a < 0 || b < 0 {
        return;
    }
    arc_init(a, b, width, start, end).draw(img, x0, y0, a, b, ink);
}

/// 塗りつぶした扇形（`ImagingDrawPieslice` の fill の側）。
fn c_pieslice_fill(img: &mut RgbaImage, bounds: [i32; 4], mut start: f32, mut end: f32, ink: Ink) {
    normalize_angles(&mut start, &mut end);
    if start + 360.0 == end {
        c_ellipse(img, bounds, ink, true, 0);
        return;
    }
    if start == end {
        return;
    }
    let [x0, y0, x1, y1] = bounds;
    let (a, b) = (x1 - x0, y1 - y0);
    if a < 0 || b < 0 {
        return;
    }
    pie_init(a, b, x1 + y1 - x0 - y0, start, end).draw(img, x0, y0, a, b, ink);
}

// ── Python の側（`_imaging.c` の `_draw_*` と `ImageDraw.py`） ─────────────

/// 2 点の箱を C の整数にする。左右・上下が逆なら Pillow と同じく断る。
fn int_box(xy: [f64; 4]) -> Result<[i32; 4], ShapeError> {
    if xy[2] < xy[0] {
        return Err(ShapeError::XOrder);
    }
    if xy[3] < xy[1] {
        return Err(ShapeError::YOrder);
    }
    Ok([c_int(xy[0]), c_int(xy[1]), c_int(xy[2]), c_int(xy[3])])
}

/// `draw.draw_rectangle(xy, ink, 1)`（塗った四角）。
fn draw_rectangle_fill(img: &mut RgbaImage, xy: [f64; 4], ink: Ink) -> Result<(), ShapeError> {
    c_rectangle(img, int_box(xy)?, ink, true, 0);
    Ok(())
}

/// `ImageDraw.polygon(xy, fill=…)`。塗りつぶした多角形。
pub fn polygon(img: &mut RgbaImage, xy: &[(f64, f64)], fill: Ink) -> Result<(), ShapeError> {
    if xy.len() < 2 {
        return Err(ShapeError::TooFewPoints);
    }
    let ints: Vec<i32> = xy.iter().flat_map(|p| [c_int(p.0), c_int(p.1)]).collect();
    fill_polygon(img, &ints, fill);
    Ok(())
}

/// `ImageDraw.line(xy, fill=…, width=…)`。点を順につないだ線。
pub fn line(img: &mut RgbaImage, xy: &[(f64, f64)], fill: Ink, width: i32) {
    if width == 0 {
        return;
    }
    let points: Vec<(i32, i32)> = xy.iter().map(|p| (c_int(p.0), c_int(p.1))).collect();
    if width == 1 {
        for pair in points.windows(2) {
            thin_line(img, pair[0].0, pair[0].1, pair[1].0, pair[1].1, fill);
        }
        // 最後の点は別に打つ。
        if points.len() >= 2 {
            let last = points[points.len() - 1];
            point(img, last.0, last.1, fill);
        }
    } else {
        for pair in points.windows(2) {
            wide_line(img, pair[0].0, pair[0].1, pair[1].0, pair[1].1, fill, width);
        }
    }
}

/// `ImageDraw.rectangle(xy, fill=…, outline=…, width=…)`。
pub fn rectangle(
    img: &mut RgbaImage,
    xy: [f64; 4],
    fill: Option<Ink>,
    outline: Option<Ink>,
    width: i32,
) -> Result<(), ShapeError> {
    if let Some(ink) = fill {
        draw_rectangle_fill(img, xy, ink)?;
    }
    if let Some(ink) = outline
        && Some(ink) != fill
        && width != 0
    {
        c_rectangle(img, int_box(xy)?, ink, false, width);
    }
    Ok(())
}

/// `ImageDraw.ellipse(xy, fill=…, outline=…, width=…)`。
pub fn ellipse(
    img: &mut RgbaImage,
    xy: [f64; 4],
    fill: Option<Ink>,
    outline: Option<Ink>,
    width: i32,
) -> Result<(), ShapeError> {
    if let Some(ink) = fill {
        c_ellipse(img, int_box(xy)?, ink, true, 0);
    }
    if let Some(ink) = outline
        && Some(ink) != fill
        && width != 0
    {
        c_ellipse(img, int_box(xy)?, ink, false, width);
    }
    Ok(())
}

/// Python の `round()`（ちょうど半分は偶数の方へ）。
fn python_round(v: f64) -> f64 {
    v.round_ties_even()
}

/// `ImageDraw.rounded_rectangle(xy, radius=…, fill=…, outline=…, width=…)`（4 つの角を全部丸める）。
///
/// Pillow は、角を扇形（塗り）と弧（枠）で描き、間を四角で埋める。角どうしがつながる大きさなら半円 2 つ、
/// 全部つながるなら楕円、丸みが無ければただの四角にする。
pub fn rounded_rectangle(
    img: &mut RgbaImage,
    xy: [f64; 4],
    radius: f64,
    fill: Option<Ink>,
    outline: Option<Ink>,
    width: i32,
) -> Result<(), ShapeError> {
    if xy[2] < xy[0] {
        return Err(ShapeError::XOrder);
    }
    if xy[3] < xy[1] {
        return Err(ShapeError::YOrder);
    }
    let mut d = (xy[2] - xy[0]).min(xy[3] - xy[1]).min(radius * 2.0);
    let (x0, y0, x1, y1) = (
        python_round(xy[0]),
        python_round(xy[1]),
        python_round(xy[2]),
        python_round(xy[3]),
    );
    let full_x = d >= x1 - x0 - 1.0;
    if full_x {
        // 左の 2 つの角と右の 2 つの角がつながる。
        d = x1 - x0;
    }
    let full_y = d >= y1 - y0 - 1.0;
    if full_y {
        // 上の 2 つの角と下の 2 つの角がつながる。
        d = y1 - y0;
    }
    if full_x && full_y {
        return ellipse(img, xy, fill, outline, width);
    }
    if d == 0.0 {
        return rectangle(img, xy, fill, outline, width);
    }
    let r = (d / 2.0).floor();
    let parts: Vec<([f64; 4], f32, f32)> = if full_x {
        vec![
            ([x0, y0, x0 + d, y0 + d], 180.0, 360.0),
            ([x0, y1 - d, x0 + d, y1], 0.0, 180.0),
        ]
    } else if full_y {
        vec![
            ([x0, y0, x0 + d, y0 + d], 90.0, 270.0),
            ([x1 - d, y0, x1, y0 + d], 270.0, 90.0),
        ]
    } else {
        vec![
            ([x0, y0, x0 + d, y0 + d], 180.0, 270.0),
            ([x1 - d, y0, x1, y0 + d], 270.0, 360.0),
            ([x1 - d, y1 - d, x1, y1], 0.0, 90.0),
            ([x0, y1 - d, x0 + d, y1], 90.0, 180.0),
        ]
    };
    if let Some(ink) = fill {
        for (part, start, end) in &parts {
            c_pieslice_fill(img, int_box(*part)?, *start, *end, ink);
        }
        if full_x {
            draw_rectangle_fill(img, [x0, y0 + r + 1.0, x1, y1 - r - 1.0], ink)?;
        } else if x1 - r - 1.0 >= x0 + r + 1.0 {
            draw_rectangle_fill(img, [x0 + r + 1.0, y0, x1 - r - 1.0, y1], ink)?;
        }
        if !full_x && !full_y {
            draw_rectangle_fill(img, [x0, y0 + r + 1.0, x0 + r, y1 - r - 1.0], ink)?;
            draw_rectangle_fill(img, [x1 - r, y0 + r + 1.0, x1, y1 - r - 1.0], ink)?;
        }
    }
    if let Some(ink) = outline
        && Some(ink) != fill
        && width != 0
    {
        for (part, start, end) in &parts {
            c_arc(img, int_box(*part)?, *start, *end, ink, width);
        }
        let w = f64::from(width);
        if !full_x {
            draw_rectangle_fill(img, [x0 + r + 1.0, y0, x1 - r - 1.0, y0 + w - 1.0], ink)?;
            draw_rectangle_fill(img, [x0 + r + 1.0, y1 - w + 1.0, x1 - r - 1.0, y1], ink)?;
        }
        if !full_y {
            draw_rectangle_fill(img, [x0, y0 + r + 1.0, x0 + w - 1.0, y1 - r - 1.0], ink)?;
            draw_rectangle_fill(img, [x1 - w + 1.0, y0 + r + 1.0, x1, y1 - r - 1.0], ink)?;
        }
    }
    Ok(())
}
