"""スキーマから描けない画面。

デスクトップUIのタイルとしては他のパネルと同列に扱うが、中身は専用の実装を
持つ（フェーズ3で個別に移行する）。ここに置くのは、スタートメニューの並びを
1箇所で管理するため。
"""

from __future__ import annotations

from webapp_admin.schema.types import Panel

MONITORING = Panel(
    id="monitoring",
    title="システム監視",
    icon="bi-activity",
    group="概要",
    window=(720, 620),
    custom=True,
    # 既存ページを持たない。クライアントの apps/monitor.js が
    # /admin/api/metrics と /admin/api/incidents を読んで描く。
    client="monitor",
)

USER_STATE = Panel(
    id="user-state",
    title="ユーザー状態監査",
    icon="bi-person-lines-fill",
    group="概要",
    path="/admin/users/state",
    window=(980, 720),
    custom=True,
    # 一覧・検索・ページ送りは /admin/api/users/state を読んで
    # apps/user_state.js が描く（path は旧URLからの誘導にだけ使う）。
    client="user_state",
)

DEV = Panel(
    id="dev",
    title="開発者パネル",
    icon="bi-bug-fill",
    group="開発者",
    path="/admin/dev",
    window=(1000, 760),
    custom=True,
    dev_only=True,
    client="dev",
)
