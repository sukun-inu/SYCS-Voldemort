import logging
import os

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if __name__ == "__main__":
    port = int(os.environ.get("ADMIN_PORT", 5001))
    workers = max(1, int(os.environ.get("ADMIN_WORKERS", "2")))
    uvicorn.run("webapp_admin.app:app", host="0.0.0.0", port=port, reload=False, workers=workers)
