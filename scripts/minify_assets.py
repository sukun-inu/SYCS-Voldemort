#!/usr/bin/env python3
"""Minify static CSS/JS assets in-place. Run during Docker image build.

css/ と js/ の下は入れ子になっているため rglob で再帰的に探す。
（glob のままだと直下のファイルしか圧縮されない）
"""

import sys
from pathlib import Path

try:
    import rcssmin
    import rjsmin
except ImportError:
    print("rcssmin/rjsmin not installed — skipping")
    sys.exit(0)

static_dir = Path(__file__).parent.parent / "webapp_admin" / "static"
total_saved = 0

for path in sorted(static_dir.rglob("*.css")):
    src = path.read_text(encoding="utf-8")
    out = rcssmin.cssmin(src, keep_bang_comments=False)
    saved = len(src) - len(out)
    total_saved += saved
    path.write_text(out, encoding="utf-8")
    print(f"  css {path.name}: {len(src):,} → {len(out):,} bytes (-{saved/len(src)*100:.1f}%)")

for path in sorted(static_dir.rglob("*.js")):
    src = path.read_text(encoding="utf-8")
    out = rjsmin.jsmin(src, keep_bang_comments=False)
    saved = len(src) - len(out)
    total_saved += saved
    path.write_text(out, encoding="utf-8")
    print(f"  js  {path.name}: {len(src):,} → {len(out):,} bytes (-{saved/len(src)*100:.1f}%)")

print(f"Total saved: {total_saved:,} bytes")
