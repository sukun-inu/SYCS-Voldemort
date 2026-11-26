//! 期限と件数の上限があるキャッシュ。Python の `services/ttl_cache.py` と同じ働き。
//!
//! - 期限（秒）を過ぎたものは、読んだときに取り除く（読まれないものも、書くたびにまとめて取り除く）
//! - 件数の上限を超えたら、最後に使われたのが古いものから捨てる（読んでも使ったことになる）
//!
//! 時刻は呼ぶ側が渡す（テストで時刻を進められるように）。スレッドをまたいで使うときは `Mutex` に入れる。

use std::hash::Hash;

use indexmap::IndexMap;

/// 期限と件数の上限があるキャッシュ。
pub struct TtlCache<K, V> {
    ttl: f64,
    max_entries: usize,
    /// 並びが「最後に使われた順」（先頭がいちばん古い）。値と、書いた時刻。
    items: IndexMap<K, (V, f64)>,
}

impl<K: Hash + Eq + Clone, V: Clone> TtlCache<K, V> {
    /// 作る。期限は正の秒数、上限は 1 以上（Python と同じく、意味を成さない値は受け付けない）。
    pub fn new(ttl_seconds: f64, max_entries: usize) -> Self {
        assert!(ttl_seconds > 0.0, "ttl は正の秒数で指定してください。");
        assert!(max_entries > 0, "max_entries は 1 以上で指定してください。");
        Self {
            ttl: ttl_seconds,
            max_entries,
            items: IndexMap::new(),
        }
    }

    /// 読む。期限切れなら取り除いて `None`。当たったら「最近使った」側へ移す。
    pub fn get(&mut self, key: &K, now: f64) -> Option<V> {
        let index = self.items.get_index_of(key)?;
        let stored_at = self.items[index].1;
        if now - stored_at >= self.ttl {
            self.items.shift_remove_index(index);
            return None;
        }
        let last = self.items.len() - 1;
        self.items.move_index(index, last);
        Some(self.items[last].0.clone())
    }

    /// 書く（同じ鍵なら上書きして「最近使った」側へ）。書くたびに期限切れを取り除き、上限まで減らす。
    pub fn set(&mut self, key: K, value: V, now: f64) {
        self.items.shift_remove(&key);
        self.items.insert(key, (value, now));
        let ttl = self.ttl;
        self.items.retain(|_, (_, at)| now - *at < ttl);
        while self.items.len() > self.max_entries {
            self.items.shift_remove_index(0);
        }
    }

    /// 取り出して消す。
    pub fn pop(&mut self, key: &K) -> Option<V> {
        self.items.shift_remove(key).map(|(v, _)| v)
    }

    /// 入っている件数（期限切れでまだ取り除いていないものも数える。Python の `len` と同じ）。
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 期限を過ぎたら読めず、取り除かれていること（ちょうど期限の時刻で切れる）。
    #[test]
    fn entries_expire_at_the_ttl() {
        let mut c = TtlCache::new(10.0, 5);
        c.set("a", 1, 100.0);
        assert_eq!(c.get(&"a", 109.9), Some(1));
        assert_eq!(c.get(&"a", 110.0), None);
        assert!(c.is_empty(), "期限切れが残っている");
    }

    /// 上限を超えたら、最後に使われたのが古いものから捨てること（読んでも使ったことになる）。
    #[test]
    fn the_least_recently_used_goes_first() {
        let mut c = TtlCache::new(100.0, 2);
        c.set("a", 1, 0.0);
        c.set("b", 2, 1.0);
        assert_eq!(c.get(&"a", 2.0), Some(1));
        c.set("c", 3, 3.0);
        assert_eq!(c.get(&"b", 4.0), None, "最近使っていない b が残った");
        assert_eq!(c.get(&"a", 4.0), Some(1));
        assert_eq!(c.get(&"c", 4.0), Some(3));
    }

    /// 書くたびに、読まれていない期限切れもまとめて取り除くこと。上書きは時刻も新しくする。
    #[test]
    fn writing_sweeps_expired_entries() {
        let mut c = TtlCache::new(10.0, 100);
        c.set("old", 1, 0.0);
        c.set("x", 2, 5.0);
        c.set("x", 3, 9.0);
        c.set("new", 4, 10.0);
        assert_eq!(c.len(), 2, "期限切れの old が残っている");
        assert_eq!(
            c.get(&"x", 18.0),
            Some(3),
            "上書きで時刻が新しくなっていない"
        );
        assert_eq!(c.pop(&"new"), Some(4));
        assert_eq!(c.pop(&"new"), None);
    }
}
