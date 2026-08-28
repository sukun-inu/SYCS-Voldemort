import logging
import os

import uvicorn

from envutil import env_int
from webapp_admin.core.config import resolve_session_secret

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


if __name__ == "__main__":
    # int(os.environ.get(...)) は値が空文字や数値以外だと起動時に ValueError で
    # 落ちる。envutil 経由にして安全側（既定値へフォールバック）に倒す。
    port = env_int("ADMIN_PORT", 5001, minimum=1, maximum=65535)
    workers = env_int("ADMIN_WORKERS", 1, minimum=1)

    if workers > 1:
        # ホストメトリクス(TPS)・監視スレッド・レート制限はいずれもプロセスローカルで、
        # ワーカー間で共有されない。2ワーカーならTPSは実測の約半分が表示され、
        # 監視スレッドが二重に走り、レート制限は実効的に2倍になる。
        logging.warning(
            "ADMIN_WORKERS=%d: メトリクス・監視・レート制限はワーカーごとに独立するため "
            "表示値が実態とズレます。複数ワーカーで運用する場合は "
            "ADMIN_LIMITER_STORAGE_URI に Redis を指定してください。",
            workers,
        )

    # ワーカー spawn 前にシークレットを env に確定させる。
    # 全ワーカーが同じキーを継承するため、ワーカー間でセッションが壊れない。
    os.environ["ADMIN_FLASK_SECRET_KEY"] = resolve_session_secret()

    uvicorn.run("webapp_admin.app:app", host="0.0.0.0", port=port, reload=False, workers=workers)
