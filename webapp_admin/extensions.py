import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# 既定は memory:// のまま。**ここを Valkey にしてはいけない。**
# このモジュールは import 時に Limiter を作るので、既定を redis:// にすると
# redis パッケージも Valkey も無い環境（テスト、手元での実行）で
# webapp_admin を import した時点で落ちる。
#
# 本番の値は docker-compose.yml が ADMIN_LIMITER_STORAGE_URI で渡す
# （redis://valkey:6379/1）。memory:// だとワーカーごとに別で数えるので、
# ADMIN_WORKERS を2以上にした瞬間に上限が実質2倍になる。
_LIMITER_STORAGE_URI = os.getenv("ADMIN_LIMITER_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300/minute"],
    storage_uri=_LIMITER_STORAGE_URI,
    # Valkey が落ちたときに、レート制限の故障で管理画面が 500 を返さないようにする。
    swallow_errors=True,
    # ただし swallow_errors だけだと、落ちている間は制限が丸ごと無くなる。
    # プロセス内の計数へ落として、緩くはなるが効いている状態を保つ。
    #
    # 「落ちたら制限なし」と「落ちたら管理画面が使えない」のどちらも取らない、
    # というのがここの意図。管理画面は Discord OAuth の内側にあるので、
    # 一時的に緩くなる側の危険は受け入れられる。
    in_memory_fallback_enabled=True,
    in_memory_fallback=["300/minute"],
)
