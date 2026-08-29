"""setup_events() 分割後にモジュールをまたいで共有する実行時状態。

以前は setup_events(bot) 内の1つの巨大なクロージャが、これらを nonlocal で
書き換えることでモジュール分割なしに共有していた。イベントハンドラをファイルへ
分けるにあたり、nonlocal の代わりにインスタンスを1つ作って各
register(bot, state) へ渡す形にした（属性の書き換えは nonlocal 宣言なしで
できるため）。フィールドの意味・初期値は元のクロージャ変数のものをそのまま
保っている。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class EventState:
    """setup_events(bot) の呼び出し1回につき1つ作られる、イベントハンドラ間の共有状態。"""

    # ステータス更新タスクが直前に送った表示文字列。実際に変わった時だけ
    # 送るための比較用（元は _last_status_text）。
    last_status_text: str | None = None

    # 再接続のたびに None/done() なら作り直すバックグラウンドタスクの参照。
    # 保持しないと実行中に GC でタスクごと消えることがある。
    ws_task: asyncio.Task | None = None
    user_state_sync_task: asyncio.Task | None = None
    user_state_repair_task: asyncio.Task | None = None
    djaudio_cleanup_task: asyncio.Task | None = None

    # on_ready は再接続のたびに何度でも発火するため、多重起動を防ぐフラグが要る。
    user_state_sync_started: bool = False
    user_state_repair_started: bool = False

    # 定期同期（auto_repair）・起動時同期・手動シグナル（dev_signal_task）が
    # 同時に走らないようにする排他ロック。
    user_state_sync_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
