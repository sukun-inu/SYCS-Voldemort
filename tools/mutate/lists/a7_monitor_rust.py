"""A7（管理画面の監視と /metrics。rust-06）の Rust の変異。

/metrics の接続元の判定と本文が Python と同じであること（基準 rust/apps/admin/tests/fixtures/prometheus/。本物の
uvicorn の ProxyHeadersMiddleware → 管理画面に通した答え）、Valkey の読み方が SharedCache.scan_values と同じであること
（同じ基準の scan を、テストの中の偽物の Valkey に置いて読む）、/admin/api/metrics・incidents・整形の関数・/proc の
読み方・監視の巡回が Python と同じであること（基準 monitor/）を、rust/apps/admin/tests/prometheus_golden.rs・
monitor_golden.rs とユニットテストが確かめている。下の壊れを、そのどれかがそれぞれ捕まえること。

いちばん大事なのは最初の 3 つ（nginx の後ろで TCP の相手を見る・CF-Connecting-IP や X-Forwarded-For をそのまま信じる）。
"""

KIND = "rust"
APP = "rust/apps/admin/src/app.rs"
P = "rust/apps/admin/src/monitor/prometheus.rs"
F = "rust/apps/admin/src/monitor/pyfloat.rs"
D = "rust/apps/admin/src/monitor/dashboard.rs"
H = "rust/apps/admin/src/monitor/host.rs"
W = "rust/apps/admin/src/monitor/watch.rs"
V = "rust/apps/admin/src/monitor/valkey.rs"
X = "rust/crates/sycs-web/src/proxy.rs"
MUTS = [
    ("変異なし（通るはず）", P, 'pub const METRIC_PREFIX: &str = "sycs";', 'pub const METRIC_PREFIX: &str = "sycs";'),
    (
        "接続元を TCP の相手（nginx）にする",
        APP,
        "            client: forwarded.client.clone(),",
        "            client: incoming.peer.clone(),",
    ),
    (
        "CF-Connecting-IP を信じて判定する",
        P,
        "    if !client_allowed(req.client.as_deref(), &settings.allowed) {",
        '    if !client_allowed(req.header("cf-connecting-ip").or(req.client.clone()).as_deref(), &settings.allowed) {',
    ),
    (
        "X-Forwarded-For をそのまま信じて判定する",
        P,
        "    if !client_allowed(req.client.as_deref(), &settings.allowed) {",
        '    if !client_allowed(req.header("x-forwarded-for").or(req.client.clone()).as_deref(), &settings.allowed) {',
    ),
    ("許す帯域の外でも通す", P, "    allowed.iter().any(|network| network.contains(peer))", "    !allowed.is_empty()"),
    (
        "IP として読めない接続元を通す",
        P,
        "    let Some(peer) = proxy::ip_address(client) else {\n        return false;",
        "    let Some(peer) = proxy::ip_address(client) else {\n        return true;",
    ),
    (
        "空の項目で帯域を全部捨てる",
        P,
        "        if token.is_empty() {\n            continue;",
        "        if token.is_empty() {\n            return Vec::new();",
    ),
    (
        "帯域の余りのビットを落とさない",
        X,
        "            address: IpAddr::V4(Ipv4Addr::from(masked)),",
        "            address: IpAddr::V4(v4),",
    ),
    (
        "古さの境（90 秒ちょうど）も生きているにする",
        P,
        "if seconds < stale_after { 1.0 } else { 0.0 }",
        "if seconds <= stale_after { 1.0 } else { 0.0 }",
    ),
    (
        "未来の心拍の秒数を負のまま出す",
        P,
        "            let seconds = py_max(0.0, now - value);",
        "            let seconds = now - value;",
    ),
    ('ラベルの値の " を逃がさない', P, '        .replace(\'"\', "\\\\\\"")', '        .replace(\'"\', "\\"")'),
    (
        "Valkey を使えるかをいつも 1 にする",
        P,
        "    let available = if scan.available { 1.0 } else { 0.0 };",
        "    let available = 1.0;",
    ),
    ("系列をラベルの順に並べない", P, "    series.sort_by(|a, b| a.0.iter().cmp(b.0.iter()));", "    // 並べない"),
    (
        "バックアップの置き場ではなくファイルの有無で見る",
        P,
        "        Some(parent) => parent.is_dir(),",
        "        Some(_) => path.is_file(),",
    ),
    (
        "NaN を例外にせず書く",
        F,
        '        return Err(Crash::new("ValueError", "cannot convert float NaN to integer"));',
        '        return Ok("NaN".to_string());',
    ),
    (
        "ちょうど半分をいつも切り上げる",
        F,
        "|| head.last().is_some_and(|d| (d - b'0') % 2 == 1)",
        "|| true",
    ),
    (
        "g の小数の形の下の境をずらす",
        F,
        "    let body = if (-4..PRECISION).contains(&exponent) {",
        "    let body = if (-5..PRECISION).contains(&exponent) {",
    ),
    ("Neumaier の補正を足さない", F, "    if compensation != 0.0 && compensation.is_finite() {", "    if false {"),
    (
        "マイクロ秒の繰り上がりを秒に足さない（月の境と画面の時刻）",
        D,
        "    if micros >= 1e6 {\n        seconds += 1;",
        "    if micros >= 1e6 {\n        seconds += 0;",
    ),
    ("使える量が合計より多いとき free にしない", H, "        avail = free;", "        avail = total;"),
    ("CPU の合計から guest を引かない", H, "        total -= guest;", "        total -= 0.0;"),
    ("停止の猶予ちょうども停止にする", W, "    if downtime <= grace {", "    if downtime < grace {"),
    (
        "しきい値ちょうどは警告しない",
        W,
        "            if percent < threshold {",
        "            if percent <= threshold {",
    ),
    ("警告の間隔をあけない", W, "            if now - last_at < cooldown {", "            if false {"),
    (
        "読めなかったら遮断器を開かない",
        V,
        "        breaker.blocked_until = Some(now + self.cooldown);",
        "        breaker.blocked_until = None;",
    ),
    (
        "途中で失敗したら読めた分も捨てる",
        V,
        "                            *self.conn.lock().await = None;",
        "                            *self.conn.lock().await = None;\n                            items.clear();",
    ),
]
