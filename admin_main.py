import logging
import os

from webapp_admin.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("ADMIN_PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
