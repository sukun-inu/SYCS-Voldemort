"""管理UIの実行時設定を解決するモジュール。

環境変数の読み取りと、プロセス間で共有すべき値（セッション署名キー・データ
ディレクトリ）の解決をここ1箇所にまとめる。
以前は admin_main.py と webapp_admin/app.py に同じ実装が二重に存在していた。
"""

import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

_SECRET_ENV = "ADMIN_FLASK_SECRET_KEY"
_SECRET_FILENAME = ".admin_session_secret"
_MIN_SECRET_LEN = 32


def settings_dir() -> Path:
    """設定・ログ・監視データの保存先ディレクトリ。"""
    default_dir = Path(__file__).resolve().parent.parent.parent / "data"
    return Path(os.getenv("SETTINGS_DIR", str(default_dir)))


def _read_secret_file(path: Path) -> str | None:
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return content if len(content) >= _MIN_SECRET_LEN else None


def resolve_session_secret() -> str:
    """セッション署名キーを解決する。

    優先順位:
      1. ADMIN_FLASK_SECRET_KEY 環境変数（本番では固定値を推奨）
      2. SETTINGS_DIR/.admin_session_secret ファイル
         （初回起動時に自動生成し、以降は再利用する）

    どちらも使えない場合のみ一時キーを返す。この場合は再起動でセッションが失効する。
    """
    env_secret = os.environ.get(_SECRET_ENV, "").strip()
    if env_secret:
        return env_secret

    target_dir = settings_dir()
    secret_file = target_dir / _SECRET_FILENAME

    existing = _read_secret_file(secret_file)
    if existing:
        return existing

    new_secret = secrets.token_hex(32)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        # O_CREAT|O_EXCL で原子的に作成する。複数プロセスが同時に起動しても、
        # 先に作成できた側のキーを全プロセスが共有する。
        fd = os.open(str(secret_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_secret)
        logger.info("セッションシークレットを生成して保存しました: %s", secret_file)
        return new_secret
    except FileExistsError:
        # 別プロセスが先に作成した場合は、そちらのキーを読み直して合わせる。
        existing = _read_secret_file(secret_file)
        if existing:
            return existing
        logger.warning("セッションシークレットファイルを読み込めませんでした。一時キーを使用します。")
    except OSError as e:
        logger.warning(
            "セッションシークレットの保存に失敗しました (%s)。%s を設定してください。"
            "設定しない場合、再起動やワーカー切り替えでセッションが失効します。",
            e,
            _SECRET_ENV,
        )

    return new_secret
