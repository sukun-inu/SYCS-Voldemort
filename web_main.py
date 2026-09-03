"""貴金属の公開サイト（webapp）を起動する。"""

import logging
from pathlib import Path

import uvicorn

from envutil import env_int, env_path
from services.log_setup import LOG_FORMAT, install_file_logging, trusted_proxies

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
install_file_logging(env_path("SETTINGS_DIR", Path(__file__).resolve().parent / "data") / "logs", "web.log")


if __name__ == "__main__":
    # int(os.getenv(...)) は値が空文字や数値以外だと起動時に ValueError で
    # 落ちる。envutil 経由にして安全側（既定値へフォールバック）に倒す。
    workers = env_int("WEB_WORKERS", 2, minimum=1)
    # 以前はここが `forwarded_allow_ips="*"` だった。**誰の X-Forwarded-For でも
    # 信じる**という意味で、外から直接叩ける構成ならヘッダを付け替えるだけで
    # 別人になりすませる（レート制限もIPで数えている）。信頼する帯域を
    # TRUSTED_PROXY_CIDRS で絞る——webapp/security.py と同じ環境変数を読むので、
    # レート制限とアクセスログが同じIPを見る。
    allow = trusted_proxies()
    logging.info("信頼するプロキシ: %s（X-Forwarded-For をここからだけ受け取る）", allow)
    uvicorn.run(
        "webapp.app:app",
        host="0.0.0.0",
        port=env_int("WEB_PORT", 8000, minimum=1, maximum=65535),
        proxy_headers=True,
        forwarded_allow_ips=allow,
        workers=workers,
    )
