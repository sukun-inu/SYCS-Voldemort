"""
DJAudio-DL CDN サーバー。
webadmin とは独立したプロセスで動き、MP3 ファイルの配信のみを担当する。

環境変数:
  CDN_PORT    : 待ち受けポート (デフォルト: 5002)
  CDN_WORKERS : uvicorn ワーカー数 (デフォルト: 2)

起動例:
  python cdn_main.py
  CDN_PORT=5002 python cdn_main.py
"""

import logging
import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


def create_cdn_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None)

    from services.djaudio_cdn import dlaudio_router
    app.include_router(dlaudio_router, prefix="/dlaudio")

    @app.get("/")
    async def root():
        return JSONResponse({"service": "DJAudio-DL CDN", "status": "ok"})

    return app


app = create_cdn_app()


if __name__ == "__main__":
    port = int(os.environ.get("CDN_PORT", "5002"))
    workers = max(1, int(os.environ.get("CDN_WORKERS", "2")))
    logger.info("CDN サーバーを起動します: port=%d workers=%d", port, workers)
    uvicorn.run("cdn_main:app", host="0.0.0.0", port=port, reload=False, workers=workers)
