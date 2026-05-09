import logging
import os
import secrets
from pathlib import Path

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def _resolve_session_secret() -> str:
    """セッションシークレットキーを解決する。

    優先順位:
      1. ADMIN_FLASK_SECRET_KEY 環境変数（本番では固定値を推奨）
      2. SETTINGS_DIR/.admin_session_secret ファイル（初回起動時に自動生成・以降は再利用）
    """
    env_secret = os.environ.get("ADMIN_FLASK_SECRET_KEY", "").strip()
    if env_secret:
        return env_secret

    settings_dir = Path(os.environ.get("SETTINGS_DIR", "data"))
    secret_file = settings_dir / ".admin_session_secret"

    # 既存ファイルから読み込む
    try:
        content = secret_file.read_text(encoding="utf-8").strip()
        if len(content) >= 32:
            logging.info("セッションシークレットをファイルから読み込みました: %s", secret_file)
            return content
    except OSError:
        pass

    # 初回: 新規生成してファイルに保存
    new_secret = secrets.token_hex(32)
    try:
        settings_dir.mkdir(parents=True, exist_ok=True)
        # O_CREAT|O_EXCL で原子的に作成（競合プロセスがいても安全）
        fd = os.open(str(secret_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_secret)
        logging.info("セッションシークレットを初回生成して保存しました: %s", secret_file)
    except FileExistsError:
        # 別プロセスが先に作成した場合は読み直す
        try:
            content = secret_file.read_text(encoding="utf-8").strip()
            if len(content) >= 32:
                return content
        except OSError:
            pass
        logging.warning("セッションシークレットファイルの読み込みに失敗しました。一時キーを使用します。")
    except OSError as e:
        logging.warning(
            "セッションシークレットの保存に失敗しました (%s)。"
            "再起動するとセッションが無効になります。ADMIN_FLASK_SECRET_KEY を設定してください。",
            e,
        )

    return new_secret


if __name__ == "__main__":
    port = int(os.environ.get("ADMIN_PORT", 5001))
    workers = max(1, int(os.environ.get("ADMIN_WORKERS", "2")))

    # ワーカー spawn 前にシークレットを env に確定させる。
    # 全ワーカーが同じキーを継承するため、ワーカー間でセッションが壊れない。
    os.environ["ADMIN_FLASK_SECRET_KEY"] = _resolve_session_secret()

    uvicorn.run("webapp_admin.app:app", host="0.0.0.0", port=port, reload=False, workers=workers)
