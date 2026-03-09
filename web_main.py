import os

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "webapp.app:app",
        host="0.0.0.0",
        port=int(os.getenv("WEB_PORT", "8000")),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

