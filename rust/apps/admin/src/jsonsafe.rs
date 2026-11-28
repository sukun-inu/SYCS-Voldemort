//! JavaScript が壊さずに読める JSON の答え。Python の `webapp_admin/api/jsonsafe.py`（`SafeJSONResponse`）。
//!
//! Discord の ID は 19 桁あり、JavaScript の数（`Number.MAX_SAFE_INTEGER` = 2^53-1 まで正確）に入れると桁が落ちる。
//! 管理画面の API は、出口で、安全な範囲を超える整数だけを文字にして返す（真偽と小数はそのまま）。
//! 利用者の状態（A4）・設定パネル（A5）・開発者パネル（A8）が同じものを使う。

use serde_json::{Number, Value};

use crate::app::Reply;

/// JavaScript の `Number.MAX_SAFE_INTEGER`（Python の `JS_SAFE_MAX`）。
pub const JS_SAFE_MAX: u64 = (1 << 53) - 1;

/// 整数が安全な範囲を超えるか（Python の `abs(value) > JS_SAFE_MAX`）。小数は整数ではないので見ない。
fn is_unsafe_integer(number: &Number) -> bool {
    if let Some(i) = number.as_i64() {
        return i.unsigned_abs() > JS_SAFE_MAX;
    }
    number.as_u64().is_some_and(|u| u > JS_SAFE_MAX)
}

/// `stringify_big_ints`。安全な範囲を超える整数だけを 10 進の文字に置き換える（並びと辞書の中も）。
pub fn stringify_big_ints(value: Value) -> Value {
    match value {
        Value::Number(number) if is_unsafe_integer(&number) => Value::String(number.to_string()),
        Value::Array(items) => Value::Array(items.into_iter().map(stringify_big_ints).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, stringify_big_ints(item)))
                .collect(),
        ),
        other => other,
    }
}

/// `SafeJSONResponse(content, status_code=status)`。
pub fn reply(status: u16, value: Value) -> Reply {
    Reply::json(status, &stringify_big_ints(value))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 2^53-1 までは数のまま、超えたら（負の側も）文字になり、真偽と小数は変わらないこと。
    #[test]
    fn only_unsafe_integers_become_text() {
        let value = json!({
            "safe": 9_007_199_254_740_991_u64,
            "big": 9_007_199_254_740_992_u64,
            "negative": -9_007_199_254_740_992_i64,
            "edge": -9_007_199_254_740_991_i64,
            "max": u64::MAX,
            "flag": true,
            "ratio": 1e300,
            "nested": [{"id": 1_234_567_890_123_456_789_u64}, 5],
        });
        assert_eq!(
            stringify_big_ints(value),
            json!({
                "safe": 9_007_199_254_740_991_u64,
                "big": "9007199254740992",
                "negative": "-9007199254740992",
                "edge": -9_007_199_254_740_991_i64,
                "max": "18446744073709551615",
                "flag": true,
                "ratio": 1e300,
                "nested": [{"id": "1234567890123456789"}, 5],
            })
        );
        let answer = reply(201, json!({"id": 9_007_199_254_740_993_u64}));
        assert_eq!(answer.status, 201);
        assert_eq!(answer.body, br#"{"id":"9007199254740993"}"#);
    }
}
