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
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from envutil import env_int, env_path
from services.log_setup import LOG_FORMAT, install_file_logging, trusted_proxies

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
install_file_logging(env_path("SETTINGS_DIR", Path(__file__).resolve().parent / "data") / "logs", "cdn.log")

logger = logging.getLogger(__name__)


def create_cdn_app() -> FastAPI:
    """配信専用の FastAPI アプリを組み立てる。

    docs_url / redoc_url を落としてあるのは、このプロセスが外部へ公開
    される唯一の口で、内部のルート一覧を晒す必要が無いため。
    """
    app = FastAPI(docs_url=None, redoc_url=None)

    from services.djaudio_cdn import dlaudio_router

    app.include_router(dlaudio_router, prefix="/dlaudio")

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """エラーを、相手が読める形（HTML か JSON）で返し分ける。

        返し分けを誤るとミキサー側が理由を読めなくなる。判定を置く場所に
        ついては下のコメント。
        """
        # ブラウザで直接開かれる配信リンクには簡易HTMLの案内ページを返す。
        # ただし /dlaudio/files/ の下には、ミキサーが fetch する索引・解析・
        # 切り出しも同居している。パスの接頭辞で決めていたころは、そちらにも
        # HTML を返していたため、ミキサーは断られた理由を読めなかった
        # （JSON として解釈できず「Unexpected token '<'」になる）。
        # 判定は services/djaudio_cdn.wants_json に1つだけ置く。
        from services.djaudio_cdn import render_link_error_page, wants_json

        if request.url.path.startswith("/dlaudio/files/") and not wants_json(request):
            return HTMLResponse(
                render_link_error_page(exc.status_code, exc.detail),
                status_code=exc.status_code,
            )
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.get("/")
    async def root():
        """稼働確認用。配信そのものは /dlaudio 以下にある。"""
        return JSONResponse({"service": "DJAudio-DL CDN", "status": "ok"})

    return app


app = create_cdn_app()


if __name__ == "__main__":
    # int(os.environ.get(...)) は値が空文字や数値以外だと起動時に ValueError で
    # 落ちる。envutil 経由にして安全側（既定値へフォールバック）に倒す。
    port = env_int("CDN_PORT", 5002, minimum=1, maximum=65535)
    workers = env_int("CDN_WORKERS", 2, minimum=1)
    allow = trusted_proxies()
    logger.info("CDN サーバーを起動します: port=%d workers=%d 信頼するプロキシ=%s", port, workers, allow)
    uvicorn.run(
        "cdn_main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        workers=workers,
        proxy_headers=True,
        forwarded_allow_ips=allow,
    )
