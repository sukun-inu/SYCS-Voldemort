"""サーバーのデータを消すための画面。

設定項目ではないので、スキーマからは描けない（Field は「値を出し入れする欄」
であって、「押すと消える操作」を表せない）。custom パネルとして宣言し、中身は
static/js/apps/guild_data.js が組み立てる。叩く先は
`DELETE /admin/api/guild-data`（webapp_admin/api/apps.py）。

保管方針そのものは services/guild_retention.py にある。**消すのは利用者が
決める**——この画面がその入口で、自動で消えるのは放棄されたものだけ。

グループを「基本設定」の末尾に置いてあるのは、探すときに真っ先に見る場所で
ありながら、日常的に触るタイル（ログ・ウェルカム・VC通知）より後ろに来る
ため。取り消しの効かない操作を、並びの先頭に置かない。
"""

from __future__ import annotations

from webapp_admin.schema.types_def import Panel

PANEL = Panel(
    id="guild-data",
    title="サーバーのデータ",
    icon="bi-trash",
    group="基本設定",
    window=(680, 730),
    custom=True,
    client="guild_data",
)
