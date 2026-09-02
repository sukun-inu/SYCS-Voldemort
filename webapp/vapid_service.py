import base64
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from envutil import env_bool

logger = logging.getLogger(__name__)
DEFAULT_VAPID_SUBJECT = "mailto:admin@example.com"
_VAPID_SUBJECT_PATTERN = re.compile(
    r"^(mailto:.+@((localhost|[%\w-]+(\.[%\w-]+)+|([0-9a-f]{1,4}):+([0-9a-f]{1,4})?)))"
    r"|https:\/\/(localhost|[\w-]+\.[\w\.-]+|([0-9a-f]{1,4}:+)+([0-9a-f]{1,4})?)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VapidConfig:
    public_key: str | None
    private_key: str | None
    subject: str


def _b64url_no_padding(value: bytes) -> str:
    """Web Push仕様が要求する形（base64url、'='パディング無し）に変換する。

    標準の base64 と違い、末尾の '=' を残すとブラウザ側の購読処理が
    鍵として受理しない実装がある。
    """
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public_key_to_vapid(public_key: ec.EllipticCurvePublicKey) -> str:
    """公開鍵を非圧縮点形式(0x04 + X + Y、各32byte)にしてから文字列化する。

    Web Push の VAPID 公開鍵はこの形式で配信することが仕様で決まって
    おり、圧縮形式や別のエンコードで渡すとブラウザが鍵として解釈
    できない。
    """
    numbers = public_key.public_numbers()
    raw = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return _b64url_no_padding(raw)


def _load_private_key_from_pem(path: Path):
    """PEMから秘密鍵を読む。EC鍵でなければ例外にする。

    VAPID署名はEC(P-256)前提で、別種の鍵（RSA等）が置かれていても
    ファイルとしては読めてしまう。ここで弾かないと、実際に署名しようと
    した送信時になって初めて分かりにくいエラーになる。
    """
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("VAPID private key is not an EC private key.")
    return key


def _ensure_generated_keys() -> tuple[str, str]:
    """VAPID鍵が無ければ生成し、あれば使い回す。既存鍵はファイルへ永続化して共有する。

    ブラウザの購読(PushSubscription)は「購読した時点の公開鍵」に紐付く。
    ここで毎回新しい鍵を生成すると、コンテナを再起動しただけで既存の
    購読が全部無効になり、ユーザーは気づかないまま通知を受け取れなく
    なる。/shared/vapid に置くのは、複数プロセス（Webとバッチ等）が
    同じ鍵を見られるようにするため。
    """
    keys_dir = Path(os.getenv("VAPID_KEYS_DIR", "/shared/vapid"))
    private_key_file = keys_dir / "private_key.pem"
    public_key_file = keys_dir / "public_key.txt"

    keys_dir.mkdir(parents=True, exist_ok=True)

    if private_key_file.exists():
        private_key = _load_private_key_from_pem(private_key_file)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_file.write_bytes(private_pem)
        os.chmod(private_key_file, 0o600)

    if public_key_file.exists():
        public_key = public_key_file.read_text(encoding="utf-8").strip()
        if public_key:
            return public_key, str(private_key_file)

    public_key = _public_key_to_vapid(private_key.public_key())
    public_key_file.write_text(public_key + "\n", encoding="utf-8")
    os.chmod(public_key_file, 0o644)
    return public_key, str(private_key_file)


def _is_valid_vapid_subject(subject: str) -> bool:
    """`mailto:` か `https:` で始まる形式かを見る。VAPIDのJWTクレーム(sub)の要件。

    形式外の値を送ると push サービス側（ブラウザベンダ）がリクエストを
    拒否し、通知が一切届かなくなる。
    """
    return _VAPID_SUBJECT_PATTERN.match(subject) is not None


def _normalize_vapid_subject(raw_subject: str | None) -> str:
    """未設定・不正な形式なら既定値へ倒す。ここで弾かないと起動時ではなく送信時に落ちる。"""
    subject = (raw_subject or "").strip()
    if not subject:
        return DEFAULT_VAPID_SUBJECT

    if ":" not in subject and "@" in subject:
        subject = f"mailto:{subject}"

    if _is_valid_vapid_subject(subject):
        return subject

    logger.warning(
        "VAPID_SUBJECT format is invalid (%s). Falling back to default subject: %s",
        subject,
        DEFAULT_VAPID_SUBJECT,
    )
    return DEFAULT_VAPID_SUBJECT


def load_vapid_config() -> VapidConfig:
    """鍵の取得元を、環境変数 → 自動生成 → 無効、の順で決める。

    環境変数を優先するのは、複数環境（本番・検証）で同じ鍵を固定したい
    場合に対応するため。両方揃っていないと片方だけの鍵として使われ、
    署名が壊れるので「両方揃っている」ことを条件にしている。
    VAPID_AUTO_GENERATE を false にした環境で鍵ファイルも無い場合は、
    push機能自体を無効（public_key/private_keyがNone）として返す。
    """
    subject = _normalize_vapid_subject(os.getenv("VAPID_SUBJECT"))
    env_public = (os.getenv("VAPID_PUBLIC_KEY") or "").strip()
    env_private = (os.getenv("VAPID_PRIVATE_KEY") or "").strip()
    if env_public and env_private:
        return VapidConfig(public_key=env_public, private_key=env_private, subject=subject)

    if not env_bool("VAPID_AUTO_GENERATE", True):
        return VapidConfig(public_key=None, private_key=None, subject=subject)

    generated_public, generated_private = _ensure_generated_keys()
    return VapidConfig(public_key=generated_public, private_key=generated_private, subject=subject)
