# =============================================================================
# run.py — Application Entry Point
#
# Development:  python run.py
# Production:   gunicorn run:app -c gunicorn.conf.py
#
# Never set debug=True here — it is controlled by config.py via FLASK_ENV.
# =============================================================================

import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    # Development only — Gunicorn is used in production.
    app.run(
        host  = "0.0.0.0",
        port  = int(os.environ.get("PORT", 5000)),
        debug = app.config.get("DEBUG", False),
    )