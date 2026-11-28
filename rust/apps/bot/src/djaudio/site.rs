//! どのサービスの URL か。Python の `services/djaudio_site_detection.py`。
//!
//! - [`is_unsupported_url`] … 音声を落とせないと分かっているサービス（Spotify など）なら、その理由
//! - [`is_djaudio_allowed_url`] … 受け付けるドメイン（許可の一覧）か
//! - [`detect_site`] … yt-dlp の info.json から、どのサービスのものか（題の組み立て方を変える）

use serde_json::{Map, Value};
use sycs_core::url_safety::hostname_of;

use crate::commands::settings::python_truthy;
use crate::python_repr::python_str;

/// 受け付けるドメイン（`www.` を外して比べる）。ほかに `*.bandcamp.com` も受け付ける。
const ALLOWED_HOSTS: [&str; 11] = [
    "youtube.com",
    "youtu.be",
    "music.youtube.com",
    "soundcloud.com",
    "on.soundcloud.com",
    "nicovideo.jp",
    "nico.ms",
    "tiktok.com",
    "vm.tiktok.com",
    "vt.tiktok.com",
    "bandcamp.com",
];

/// DJAudio が受け付けるドメインか。Python の `is_djaudio_allowed_url`（許可の一覧。分解できない URL は受け付けない）。
pub fn is_djaudio_allowed_url(url: &str) -> bool {
    let Ok(host) = hostname_of(url) else {
        return false;
    };
    let host = host.unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    ALLOWED_HOSTS.contains(&host) || host.ends_with(".bandcamp.com")
}

/// 落とせないサービスの見分け方（Python の正規表現。大文字小文字を見ない）と、断るときの理由。
const UNSUPPORTED: [(&[&str], &str); 3] = [
    (
        &["open.spotify.com"],
        "Spotify は著作権保護のため音声をダウンロードできません。YouTube Music などの代替 URL をお試しください。",
    ),
    (
        &["music.apple.com"],
        "Apple Music は著作権保護のため音声をダウンロードできません。",
    ),
    (
        &["music.amazon.co.jp", "music.amazon.com"],
        "Amazon Music は著作権保護のため音声をダウンロードできません。",
    ),
];

/// Python の `re.IGNORECASE` で、文字 `c` が英小文字 `p` に当たるか。
///
/// `re` は両方を小文字にして比べ（`İ`〔U+0130〕の小文字は `i`、`K`〔ケルビン U+212A〕は `k`）、さらに `i` には
/// `ı`（U+0131）、`s` には `ſ`（U+017F）も当てる（`re/_casefix.py`）。英字でない文字（`.`）はそのまま比べる。
fn ignorecase_eq(c: char, p: char) -> bool {
    if c == p || c.to_ascii_lowercase() == p && c.is_ascii() {
        return true;
    }
    matches!(
        (p, c),
        ('i', '\u{130}' | '\u{131}') | ('s', '\u{17f}') | ('k', '\u{212a}')
    )
}

/// `text` のどこかに `pattern`（英小文字と `.`）が、大文字小文字を見ずに現れるか。Python の `re.search`。
fn search_ignorecase(text: &[char], pattern: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    text.windows(pattern.len())
        .any(|w| w.iter().zip(&pattern).all(|(c, p)| ignorecase_eq(*c, *p)))
}

/// 落とせないサービスの URL なら、断るときの理由。Python の `is_unsupported_url`。
pub fn is_unsupported_url(url: &str) -> Option<&'static str> {
    let chars: Vec<char> = url.chars().collect();
    UNSUPPORTED
        .iter()
        .find(|(patterns, _)| patterns.iter().any(|p| search_ignorecase(&chars, p)))
        .map(|(_, reason)| *reason)
}

/// Python の `str(info.get(a) or info.get(b) or "").lower()`。
fn first_text(info: &Map<String, Value>, keys: [&str; 2]) -> String {
    keys.iter()
        .map(|key| info.get(*key))
        .find(|v| python_truthy(*v))
        .flatten()
        .map(python_str)
        .unwrap_or_default()
        .to_lowercase()
}

/// info.json から、どのサービスのものか。Python の `detect_site`（抽出器の名前、無ければ URL を見る）。
pub fn detect_site(info: &Map<String, Value>) -> &'static str {
    let extractor = first_text(info, ["extractor", "extractor_key"]);
    for (needle, site) in [
        ("youtube", "youtube"),
        ("soundcloud", "soundcloud"),
        ("bandcamp", "bandcamp"),
        ("nicovideo", "nicovideo"),
        ("nico", "nicovideo"),
        ("tiktok", "tiktok"),
    ] {
        if extractor.contains(needle) {
            return site;
        }
    }
    let url = first_text(info, ["webpage_url", "url"]);
    for (needle, site) in [
        ("youtube.com", "youtube"),
        ("youtu.be", "youtube"),
        ("soundcloud.com", "soundcloud"),
        ("bandcamp.com", "bandcamp"),
        ("nicovideo.jp", "nicovideo"),
        ("tiktok.com", "tiktok"),
    ] {
        if url.contains(needle) {
            return site;
        }
    }
    "generic"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 許可の一覧と bandcamp の下のドメインだけを受け付け、www. は外して比べること。
    #[test]
    fn allowed_hosts_follow_python() {
        for url in [
            "https://www.youtube.com/watch?v=x",
            "https://YOUTU.BE/x",
            "https://artist.bandcamp.com/track/a",
            "https://user@nico.ms:443/sm9",
        ] {
            assert!(is_djaudio_allowed_url(url), "{url}");
        }
        for url in [
            "https://youtube.com.evil.example/",
            "https://bandcamp.com.evil/",
            "https://[abc/",
            "nothost",
            "https://www.www.youtube.com/",
        ] {
            assert!(!is_djaudio_allowed_url(url), "{url}");
        }
    }

    /// 落とせないサービスは、大文字小文字（Python の当て方）を見ずに、URL のどこにあっても見つけること。
    #[test]
    fn unsupported_services_are_found_anywhere() {
        assert!(
            is_unsupported_url("https://OPEN.SPOTIFY.COM/track/1")
                .unwrap()
                .starts_with("Spotify")
        );
        assert!(
            is_unsupported_url("https://x.example/?u=music.amazon.co.jp")
                .unwrap()
                .starts_with("Amazon")
        );
        // ſ は s に、ı は i に当たる（Python の re と同じ）。
        assert!(is_unsupported_url("https://open.ſpotıfy.com/").is_some());
        assert!(is_unsupported_url("https://music.apple.co/").is_none());
        assert!(is_unsupported_url("https://openXspotify.com/").is_none());
    }

    /// 抽出器の名前を先に、無ければ URL を見て、どのサービスかを決めること。
    #[test]
    fn site_is_detected_like_python() {
        let map = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(
            detect_site(&map(json!({"extractor": "Youtube:tab"}))),
            "youtube"
        );
        assert_eq!(
            detect_site(&map(
                json!({"extractor": "", "extractor_key": "NiconicoIE"})
            )),
            "nicovideo"
        );
        assert_eq!(
            detect_site(&map(
                json!({"extractor": 0, "webpage_url": "https://x.tiktok.com/"})
            )),
            "tiktok"
        );
        assert_eq!(
            detect_site(&map(json!({"url": "https://example.com"}))),
            "generic"
        );
    }
}
