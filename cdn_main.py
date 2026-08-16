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
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

_ERROR_TITLES = {
    403: "アクセスできません",
    404: "リンクが見つかりません",
    410: "リンクの有効期限切れ",
}


def _render_error_page(status_code: int, detail: object) -> str:
    title = _ERROR_TITLES.get(status_code, "エラーが発生しました")
    message = detail if isinstance(detail, str) and detail else "この操作を完了できませんでした。"
    return f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - DJAudio-DL</title>
<style>
  :root {{ color-scheme: dark light; }}
  body {{
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #10120f; color: #e9ece4;
    font-family: "Hiragino Sans", "Yu Gothic UI", "Noto Sans JP", "Meiryo", system-ui, sans-serif;
    padding: 24px;
  }}
  .card {{
    max-width: 420px; width: 100%; background: #181c15; border: 1px solid #2c3126;
    border-radius: 16px; padding: 32px 28px; text-align: center;
  }}
  .code {{ font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12.5px;
           letter-spacing: .08em; color: #7fbf8f; margin: 0 0 10px; }}
  h1 {{ font-size: 20px; margin: 0 0 12px; }}
  p {{ font-size: 14.5px; line-height: 1.7; color: #b7bfae; margin: 0; }}
</style>
</head>
<body>
  <div class="card">
    <p class="code">DJAudio-DL &middot; {status_code}</p>
    <h1>{title}</h1>
    <p>{message}</p>
  </div>
</body>
</html>"""


def create_cdn_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None)

    from services.djaudio_cdn import dlaudio_router
    app.include_router(dlaudio_router, prefix="/dlaudio")

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # ブラウザで直接開かれる配信リンク (/dlaudio/files/...) だけ、簡易HTMLの案内ページを返す。
        # /dlaudio/info/... 等のAPIエンドポイントは従来どおりJSONを返す。
        if request.url.path.startswith("/dlaudio/files/"):
            return HTMLResponse(
                _render_error_page(exc.status_code, exc.detail),
                status_code=exc.status_code,
            )
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

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
