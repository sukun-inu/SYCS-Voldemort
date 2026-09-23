"""
DJAudio-DL CDN 配信ルーター。
- /dlaudio/files/<guild_id>/<token>  → MP3 配信
- /dlaudio/info/<guild_id>/<token>   → ファイル情報 JSON
- /dlaudio/health                    → ヘルスチェック

webapp_admin にも cdn_main にも依存せず、どちらからでも import できる。
"""

import html
import logging

from fastapi import APIRouter, HTTPException
from starlette.responses import FileResponse, JSONResponse
from datetime import datetime, timezone

from services.djaudio_cache import content_type_for, get_meta, payload_path

logger = logging.getLogger(__name__)

dlaudio_router = APIRouter()


def _validate_token(token: str) -> bool:
    """トークンの形（uuid4.hex と同じ32文字の英数字）だけを見る。
    実在の照合は get_meta() 側で行うため、ここでは明らかに不正な値を
    ファイルシステムへ渡す前に弾くだけでよい。
    """
    return token.isalnum() and len(token) == 32


def _validate_guild_id(guild_id: str) -> bool:
    """URLの guild_id が数字だけか。不正な値をそのまま比較・ログへ通さない
    ための最低限の検査。
    """
    return guild_id.isdigit()


@dlaudio_router.get("/health")
async def dlaudio_health():
    """CDNプロセスが生きているかだけを返す。認証も状態確認もしない。"""
    return JSONResponse({"status": "ok"})


_LINK_INVALID = "リンクが正しくありません。Discordに投稿されたリンクをそのまま開いてください。"
_LINK_EXPIRED = "このリンクの有効期限が切れました。Discordでもう一度URLを投稿して、新しいリンクを取得してください。"
_LINK_WRONG_GUILD = "このリンクは別のサーバー向けに発行されたものです。"


@dlaudio_router.get("/files/{guild_id}/{token}")
async def serve_file(guild_id: str, token: str):
    """MP3等を配信するDJAudio-DLの本体。

    404/410/403 をエラー内容ごとに使い分けているのは、利用者に見せる文面
    （_LINK_INVALID/_LINK_EXPIRED/_LINK_WRONG_GUILD）を状態ごとに変える
    ため。guild_id の不一致は、リンクを他サーバーへ転送された場合の
    アクセス制御なので、期限切れとは別に検知してログへ残す。
    """
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        logger.warning("guild_id 不一致: URL=%s meta=%s token=%s", guild_id, meta.get("guild_id"), token)
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

    # 拡張子はメタから決める（メタに無い旧エントリは .mp3）。
    extension = str(meta.get("extension") or ".mp3")
    path = payload_path(token, meta)
    if path is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    raw_name = meta.get("filename", f"{token}{extension}")
    safe_name = "".join(c for c in raw_name if c.isalnum() or c in " ._-").strip() or f"{token}{extension}"
    if not safe_name.endswith(extension):
        safe_name += extension

    logger.info("配信: guild=%s token=%s → %s", guild_id, token, safe_name)
    return FileResponse(str(path), media_type=content_type_for(extension), filename=safe_name)


@dlaudio_router.get("/info/{guild_id}/{token}")
async def file_info(guild_id: str, token: str):
    """ファイル本体は落とさず、残り時間などのメタ情報だけを返す。
    ダウンロード前に「あと何分で切れるか」をUIへ出すためのエンドポイント。
    """
    if not _validate_guild_id(guild_id) or not _validate_token(token):
        raise HTTPException(status_code=404, detail=_LINK_INVALID)

    meta = get_meta(token)
    if meta is None:
        raise HTTPException(status_code=410, detail=_LINK_EXPIRED)

    if meta.get("guild_id") != guild_id:
        raise HTTPException(status_code=403, detail=_LINK_WRONG_GUILD)

    now = datetime.now(timezone.utc).timestamp()
    remaining = max(0, int(meta["expires_at"] - now))
    return JSONResponse(
        {
            "token": token,
            "title": meta.get("title", ""),
            "filename": meta.get("filename", ""),
            "expires_at": meta.get("expires_at"),
            "remaining_seconds": remaining,
            "remaining_minutes": remaining // 60,
        }
    )


def wants_json(request) -> bool:
    """エラーを JSON で返すべき相手か。

    配信リンクはブラウザが直接開くが、スクリプトから fetch されることもある。
    パスの接頭辞では区別できないので Accept で見る。ブラウザの遷移は
    text/html を要求し、fetch する側は application/json を指定する。

    ここを1箇所に置いて、管理画面（webapp_admin/app.py）と単体の配信プロセス
    （cdn_main.py）の両方から使う。別々に書いていたころは、同じ URL でも
    どちらのプロセスが応答したかで JSON と HTML が入れ替わっていた。
    """
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


# 配信リンクのエラーページに出す見出し。status ごとの一言で、detail はこの下に添える。
_LINK_ERROR_TITLES = {
    400: "リクエストが正しくありません",
    403: "アクセスできません",
    404: "リンクが見つかりません",
    405: "この URL では受け付けていない操作です",
    410: "リンクの有効期限切れ",
    416: "要求された範囲を返せません",
    429: "アクセスが集中しています",
    500: "処理に失敗しました",
}


def render_link_error_page(status_code: int, detail: object) -> str:
    """配信リンクをブラウザで直接開いた人に見せる案内ページ。

    ページを**外部の資材へ一切頼らない形**にしてあるのは、返す先が配信の
    ホストだからだ。そこへ通っているのは /dlaudio/ だけで、管理画面の
    /static/ は届かない。管理画面のテンプレート（error.html）を返していた
    ころは、そこが読む CSS 4本・aero.js・アイコンのスプライトが揃って 404
    になり、素の HTML が縦に並ぶだけの画面が出ていた。しかも「管理画面へ」
    のリンクつきで——Discord のリンクを踏んだ人に見せる先ではない。

    wants_json と同じく、置き場所はここ1箇所だけにする。管理画面
    （webapp_admin/app.py）と単体の配信プロセス（cdn_main.py）の両方が
    これを呼ぶ。別々に持っていたころは、同じ URL でもどちらのプロセスが
    応答したかで見た目も案内も変わっていた。

    detail が空でも「この操作を完了できませんでした」に倒し、白紙を返さない。
    """
    title = _LINK_ERROR_TITLES.get(status_code, "エラーが発生しました")
    message = detail if isinstance(detail, str) and detail else "この操作を完了できませんでした。"
    # detail は今のところ全部このモジュール内の定数だが、埋め込む側で
    # 逃がしておく。ここへ外から来た文字列を渡す変更が入っても、
    # そのままタグとして解釈されることはない。
    title_html = html.escape(title)
    message_html = html.escape(message)
    return f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_html} - DJAudio-DL</title>
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
  h1 {{ font-size: 20px; margin: 0 0 12px; }}
  /* 番号は見出しと同じ行に置く。別の行に「DJAudio-DL ・ 410」と出していた
     ころは、区切りの中黒だけが浮いて見えた。
     番号と見出しの間隔は h1 の中の空白1つぶんだけで、ここでは足さない。 */
  h1 .code {{ font-family: ui-monospace, "SF Mono", Consolas, monospace;
              letter-spacing: .08em; color: #7fbf8f; }}
  p {{ font-size: 14.5px; line-height: 1.7; color: #b7bfae; margin: 0; }}
</style>
</head>
<body>
  <div class="card">
    <h1><span class="code">{status_code}</span> {title_html}</h1>
    <p>{message_html}</p>
  </div>
</body>
</html>"""
