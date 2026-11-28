//! URL のパスを、uvicorn と同じく `%XX` を戻した文字列にする。
//!
//! Starlette は、uvicorn が戻したあとのパス（`scope["path"]`）で経路を引く。だから `%2F` は `/` として区切りになり、
//! `%0A` は改行になる。axum の経路は戻す前のパスで引くので、Python と同じ答えを出したい経路では、ここで戻した
//! パスを使って自分で引く（配信の `apps/cdn` がそうしている）。

use percent_encoding::percent_decode_str;

/// 戻したパス。uvicorn の `urllib.parse.unquote(raw_path)`（UTF-8 として読めない並びは U+FFFD にする）。
///
/// `%` のあとに 16 進が 2 つ続かないものは、そのまま残す（Python も同じ）。`+` は空白にしない（`unquote_plus` ではない）。
pub fn decoded(raw: &str) -> String {
    percent_decode_str(raw).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 区切りの `/`・改行・日本語・読めない並び・壊れた `%`・`+` が、Python の unquote と同じに戻ること。
    #[test]
    fn paths_are_decoded_like_uvicorn() {
        assert_eq!(decoded("/a%2Fb"), "/a/b");
        assert_eq!(decoded("/x%0A"), "/x\n");
        assert_eq!(decoded("/%E3%81%82"), "/あ");
        assert_eq!(decoded("/%e3%81%82"), "/あ");
        assert_eq!(decoded("/%FF"), "/\u{fffd}");
        assert_eq!(decoded("/%zz%4"), "/%zz%4");
        assert_eq!(decoded("/a+b"), "/a+b");
    }
}
