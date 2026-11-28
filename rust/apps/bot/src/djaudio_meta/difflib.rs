//! Python 3.13 の `difflib.SequenceMatcher(None, a, b).ratio()` の写し（`_similarity` が使う）。
//!
//! 一致の取り方（`find_longest_match` の「最初に見つけた最長」・両端への伸ばし方）と、b が 200 文字以上のときの
//! autojunk（b の中で `len(b) // 100 + 1` 回より多く出る文字を「よく出る文字」として探す対象から外す）まで
//! そのまま写す。junk の指定（isjunk）は None なので、junk の集合は空。

use std::collections::HashMap;

/// `SequenceMatcher.find_longest_match(alo, ahi, blo, bhi)`。(i, j, 長さ) を返す。
fn find_longest_match(
    a: &[char],
    b: &[char],
    b2j: &HashMap<char, Vec<usize>>,
    (alo, ahi, blo, bhi): (usize, usize, usize, usize),
) -> (usize, usize, usize) {
    let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0);
    // j2len[j] = a[i-1] と b[j] で終わる一致の長さ。
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (i, ch) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut newj2len = HashMap::new();
        if let Some(js) = b2j.get(ch) {
            for &j in js {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j
                    .checked_sub(1)
                    .and_then(|p| j2len.get(&p))
                    .copied()
                    .unwrap_or(0)
                    + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }
    // 探す対象から外した「よく出る文字」も、両端に続いていれば一致に含める（junk は無いので後半の 2 つの輪は空回り）。
    while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
        besti -= 1;
        bestj -= 1;
        bestsize += 1;
    }
    while besti + bestsize < ahi
        && bestj + bestsize < bhi
        && a[besti + bestsize] == b[bestj + bestsize]
    {
        bestsize += 1;
    }
    (besti, bestj, bestsize)
}

/// `SequenceMatcher(None, a, b).ratio()`。
pub fn ratio(a: &[char], b: &[char]) -> f64 {
    let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
    for (j, &c) in b.iter().enumerate() {
        b2j.entry(c).or_default().push(j);
    }
    // autojunk（Python の __chain_b）。
    if b.len() >= 200 {
        let ntest = b.len() / 100 + 1;
        b2j.retain(|_, idxs| idxs.len() <= ntest);
    }
    // get_matching_blocks の一致の長さの和（並べ直し・つなぎ直しは和を変えない）。
    let mut matches = 0usize;
    let mut queue = vec![(0, a.len(), 0, b.len())];
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest_match(a, b, &b2j, (alo, ahi, blo, bhi));
        if k > 0 {
            matches += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    let length = a.len() + b.len();
    if length == 0 {
        1.0
    } else {
        2.0 * matches as f64 / length as f64
    }
}
