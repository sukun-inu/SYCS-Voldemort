import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class VapidConfig:
    public_key: str | None
    private_key: str | None
    subject: str


def _read_env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _b64url_no_padding(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public_key_to_vapid(public_key: ec.EllipticCurvePublicKey) -> str:
    numbers = public_key.public_numbers()
    raw = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return _b64url_no_padding(raw)


def _load_private_key_from_pem(path: Path):
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("VAPID private key is not an EC private key.")
    return key


def _ensure_generated_keys() -> tuple[str, str]:
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


def load_vapid_config() -> VapidConfig:
    subject = (os.getenv("VAPID_SUBJECT") or "mailto:admin@example.com").strip()
    env_public = (os.getenv("VAPID_PUBLIC_KEY") or "").strip()
    env_private = (os.getenv("VAPID_PRIVATE_KEY") or "").strip()
    if env_public and env_private:
        return VapidConfig(public_key=env_public, private_key=env_private, subject=subject)

    if not _read_env_bool("VAPID_AUTO_GENERATE", True):
        return VapidConfig(public_key=None, private_key=None, subject=subject)

    generated_public, generated_private = _ensure_generated_keys()
    return VapidConfig(public_key=generated_public, private_key=generated_private, subject=subject)

