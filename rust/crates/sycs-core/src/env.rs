//! 環境変数を安全に読む。Python の `envutil.py` と同じ規則にしてある。
//!
//! 移行中は Python と Rust のプロセスが同じ compose の環境変数を読む。読み方が
//! 違うと、同じ `X=` が片方では「未設定」、もう片方では「空文字」になり、片方だけが
//! 起動しない・片方だけ既定値で動く、という形で食い違う。だから規則を揃える。
//!
//! - 未設定・空文字・空白だけは、どれも「未設定」として扱う
//! - **例外（panic）を出さない。** 読めない値は理由を警告に残して既定値へ倒す
//! - 範囲を外れた値は丸め、丸めたことを警告に残す（黙って値が変わらないように）
//! - 小数の NaN と無限大は弾く（範囲の確認をすり抜けて後段を壊すため）
//!
//! Python と違うところ: 整数の `1_000` は読めない（Python の `int()` は読む）。
//! compose にその書き方は無いので、揃えるための手間をかけていない。

use std::path::PathBuf;

use tracing::warn;

const TRUTHY: [&str; 4] = ["1", "true", "yes", "on"];
const FALSY: [&str; 4] = ["0", "false", "no", "off"];

type Lookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// 環境変数の読み手。
///
/// テストでプロセスの環境変数を書き換えずに済むよう、引き方を差し替えられる形にしてある
/// （プロセスの環境変数はスレッド間で共有されるので、並行に走るテストが互いを壊す）。
pub struct Env {
    lookup: Lookup,
}

impl Env {
    /// このプロセスの環境変数を読む。
    pub fn from_process() -> Self {
        Self {
            lookup: Box::new(|key| std::env::var(key).ok()),
        }
    }

    /// 引き方を渡して作る（テスト用）。
    pub fn from_fn(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self {
            lookup: Box::new(lookup),
        }
    }

    /// 生の値。未設定・空文字・空白だけなら `None`。前後の空白は落とす。
    pub fn raw(&self, key: &str) -> Option<String> {
        let value = (self.lookup)(key)?;
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    /// 文字列として読む。未設定なら `default`。
    pub fn string(&self, key: &str, default: &str) -> String {
        self.raw(key).unwrap_or_else(|| default.to_string())
    }

    /// 真偽値として読む。`1/true/yes/on` と `0/false/no/off`（大文字小文字は問わない）。
    pub fn boolean(&self, key: &str, default: bool) -> bool {
        let Some(raw) = self.raw(key) else {
            return default;
        };
        let lowered = raw.to_lowercase();
        if TRUTHY.contains(&lowered.as_str()) {
            return true;
        }
        if FALSY.contains(&lowered.as_str()) {
            return false;
        }
        warn!(
            "環境変数 {key} の値 {raw:?} を真偽値として解釈できません。既定値 {default} を使います。"
        );
        default
    }

    /// 整数として読む。`min` / `max` を渡すと範囲へ丸める。
    pub fn int(&self, key: &str, default: i64, min: Option<i64>, max: Option<i64>) -> i64 {
        let Some(raw) = self.raw(key) else {
            return clamp(key, default, min, max, true);
        };
        match raw.parse::<i64>() {
            Ok(value) => clamp(key, value, min, max, false),
            Err(_) => {
                warn!(
                    "環境変数 {key} の値 {raw:?} を整数として解釈できません。既定値 {default} を使います。"
                );
                clamp(key, default, min, max, true)
            }
        }
    }

    /// 小数として読む。挙動は [`Env::int`] と同じ。NaN と無限大は既定値へ倒す。
    pub fn float(&self, key: &str, default: f64, min: Option<f64>, max: Option<f64>) -> f64 {
        let Some(raw) = self.raw(key) else {
            return clamp(key, default, min, max, true);
        };
        match raw.parse::<f64>() {
            Ok(value) if value.is_finite() => clamp(key, value, min, max, false),
            Ok(_) => {
                warn!(
                    "環境変数 {key} の値 {raw:?} は有限の数値ではありません。既定値 {default} を使います。"
                );
                clamp(key, default, min, max, true)
            }
            Err(_) => {
                warn!(
                    "環境変数 {key} の値 {raw:?} を数値として解釈できません。既定値 {default} を使います。"
                );
                clamp(key, default, min, max, true)
            }
        }
    }

    /// パスとして読む。空文字はカレントディレクトリではなく既定値へ倒す。
    ///
    /// 空文字をそのままパスにすると、キャッシュやログがプロセスの作業ディレクトリへ
    /// 書き出される（Python 側で実際に起きかけた）。
    pub fn path(&self, key: &str, default: impl Into<PathBuf>) -> PathBuf {
        self.raw(key)
            .map(PathBuf::from)
            .unwrap_or_else(|| default.into())
    }
}

/// 範囲へ丸める。丸めたら警告を残す。
///
/// `from_default` は「環境変数は未設定で、コード上の既定値が範囲に収まらなかった」場合。
/// 上下限が別の設定に連動していると起きる。文面を分けているのは、こちらのほうが
/// 「コードにはこう書いてあるのに、実際は違う値で動いている」という気づきにくい状態だから。
fn clamp<T>(key: &str, value: T, min: Option<T>, max: Option<T>, from_default: bool) -> T
where
    T: PartialOrd + Copy + std::fmt::Display,
{
    let mut clamped = value;
    if let Some(lo) = min
        && clamped < lo
    {
        clamped = lo;
    }
    if let Some(hi) = max
        && clamped > hi
    {
        clamped = hi;
    }
    if clamped != value {
        let lo = min.map_or("-".to_string(), |v| v.to_string());
        let hi = max.map_or("-".to_string(), |v| v.to_string());
        if from_default {
            warn!(
                "環境変数 {key} は未設定のため既定値 {value} を使う想定でしたが、許容範囲({lo}〜{hi}、他の設定値に連動している場合あり)に収まらないため {clamped} に丸めました。"
            );
        } else {
            warn!(
                "環境変数 {key} の値 {value} は許容範囲外です。{clamped} に丸めました（許容: {lo}〜{hi}）。"
            );
        }
    }
    clamped
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Env::from_fn(move |key| map.get(key).cloned())
    }

    /// 空文字と空白だけは「未設定」になること。
    ///
    /// compose で `X=${X}` と書いて X を渡さないと、空文字が入る。これを値として
    /// 扱うと、数値なら既定値に倒れず、パスならカレントディレクトリになる。
    #[test]
    fn empty_and_blank_values_count_as_unset() {
        let e = env(&[("EMPTY", ""), ("BLANK", "   "), ("SET", "  value  ")]);
        assert_eq!(e.raw("EMPTY"), None);
        assert_eq!(e.raw("BLANK"), None);
        assert_eq!(e.raw("MISSING"), None);
        assert_eq!(e.raw("SET").as_deref(), Some("value"));
        assert_eq!(e.path("EMPTY", "/fallback"), PathBuf::from("/fallback"));
    }

    /// 真偽値は Python と同じ 8 つの綴りだけを読み、読めなければ既定値へ倒れること。
    #[test]
    fn booleans_read_the_same_words_as_python() {
        let e = env(&[("A", "Yes"), ("B", "off"), ("C", "maybe")]);
        assert!(e.boolean("A", false));
        assert!(!e.boolean("B", true));
        assert!(e.boolean("C", true));
        assert!(!e.boolean("C", false));
    }

    /// 読めない整数は既定値、範囲外は丸めること。panic しないこと。
    #[test]
    fn integers_fall_back_and_clamp_instead_of_panicking() {
        let e = env(&[("BAD", "abc"), ("LOW", "-5"), ("HIGH", "999"), ("OK", "42")]);
        assert_eq!(e.int("BAD", 7, None, None), 7);
        assert_eq!(e.int("LOW", 7, Some(1), None), 1);
        assert_eq!(e.int("HIGH", 7, None, Some(100)), 100);
        assert_eq!(e.int("OK", 7, Some(1), Some(100)), 42);
    }

    /// 既定値そのものが範囲外なら、既定値も丸めること（上下限が他の設定に連動するとき）。
    #[test]
    fn a_default_outside_the_range_is_clamped_too() {
        let e = env(&[]);
        assert_eq!(e.int("UNSET", 20, Some(25), None), 25);
        assert_eq!(e.float("UNSET", 20.0, Some(25.0), None), 25.0);
    }

    /// NaN と無限大は既定値へ倒れること。範囲の比較をすり抜けて後段を壊すため。
    #[test]
    fn non_finite_floats_fall_back_to_the_default() {
        let e = env(&[("NAN", "NaN"), ("INF", "inf"), ("OK", "1.5")]);
        assert_eq!(e.float("NAN", 3.0, Some(0.0), Some(10.0)), 3.0);
        assert_eq!(e.float("INF", 3.0, Some(0.0), Some(10.0)), 3.0);
        assert_eq!(e.float("OK", 3.0, Some(0.0), Some(10.0)), 1.5);
    }
}
