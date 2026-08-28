import uvicorn

from envutil import env_int


if __name__ == "__main__":
    # int(os.getenv(...)) は値が空文字や数値以外だと起動時に ValueError で
    # 落ちる。envutil 経由にして安全側（既定値へフォールバック）に倒す。
    workers = env_int("WEB_WORKERS", 2, minimum=1)
    uvicorn.run(
        "webapp.app:app",
        host="0.0.0.0",
        port=env_int("WEB_PORT", 8000, minimum=1, maximum=65535),
        proxy_headers=True,
        forwarded_allow_ips="*",
        workers=workers,
    )
