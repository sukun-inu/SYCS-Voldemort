"""静的アセットのキャッシュバスティング用バージョンを、ファイル内容のハッシュから
自動生成する。

従来は index.html の `?v=YYYYMMDD-N` と sw.js の CACHE_NAME を手作業で更新する運用
だったが、更新を忘れると「コードは新しいのに配信は古いまま」という事故になる
(実際に一度発生した)。ここでは配信時にファイル内容のハッシュを埋め込むことで、
中身が変われば必ずURL/キャッシュ名も変わる状態を機械的に保証する。

ハッシュ計算はファイルの mtime/size が変わったときだけ行い、通常は stat のみで
済ませる(1リクエストあたり数マイクロ秒)。
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# index.html 内の `static/app.js?v=...` / `static/styles.css?v=...` を書き換えるための
# パターン。クエリが無い記述にも対応できるよう `?v=...` 部分を任意扱いにしている。
_ASSET_QUERY_PATTERNS = {
    "app.js": re.compile(r"(static/app\.js)(\?v=[^\"']*)?"),
    "styles.css": re.compile(r"(static/styles\.css)(\?v=[^\"']*)?"),
}
_CACHE_NAME_PATTERN = re.compile(r'(const\s+CACHE_NAME\s*=\s*")[^"]*(")')

_render_cache: dict[str, tuple[object, str]] = {}


def _stat_stamp(paths: list[Path]) -> tuple:
    """内容ハッシュを再計算すべきかを判断するための軽量な指紋。"""
    stamp = []
    for path in paths:
        try:
            st = path.stat()
            stamp.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            stamp.append((str(path), None, None))
    return tuple(stamp)


def _content_hash(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        try:
            digest.update(path.read_bytes())
        except OSError:
            # 読めないファイルがあってもバージョン生成自体は失敗させない
            # (存在しないパスは空として扱い、他のファイルの変化は検出できる)。
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def _render(key: str, source: Path, deps: list[Path], transform) -> str:
    """source を transform で書き換えた結果を返す。deps または source が
    変化していない限りは前回の結果を再利用する。"""
    stamp = _stat_stamp([source, *deps])
    cached = _render_cache.get(key)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    version = _content_hash(deps)
    rendered = transform(source.read_text(encoding="utf-8"), version)
    _render_cache[key] = (stamp, rendered)
    return rendered


def render_index_html(index_file: Path, app_js: Path, styles_css: Path) -> str:
    """index.html の app.js / styles.css の `?v=` を内容ハッシュへ置き換えて返す。"""

    def transform(text: str, version: str) -> str:
        for name, pattern in _ASSET_QUERY_PATTERNS.items():
            text = pattern.sub(rf"\1?v={version}", text)
        return text

    return _render("index.html", index_file, [app_js, styles_css], transform)


def render_service_worker(sw_file: Path, app_js: Path, styles_css: Path) -> str:
    """sw.js の CACHE_NAME を内容ハッシュ入りの名前へ置き換えて返す。

    CACHE_NAME が変わると activate 時に古いキャッシュが削除されるため、アセットが
    変わったときだけ確実に Service Worker のキャッシュが作り直される。
    """

    def transform(text: str, version: str) -> str:
        return _CACHE_NAME_PATTERN.sub(rf"\g<1>metal-tracker-{version}\g<2>", text)

    return _render("sw.js", sw_file, [app_js, styles_css, sw_file], transform)


def asset_version(app_js: Path, styles_css: Path) -> str:
    """現在のアセット内容に対応するバージョン文字列。"""
    return _content_hash([app_js, styles_css])
