import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS

db      = SQLAlchemy()
migrate = Migrate()


def create_app(config_name: str = None) -> Flask:
    from config import config

    # --- THE FIX: Force absolute paths for templates and static folders ---
    base_dir = os.path.abspath(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    # ----------------------------------------------------------------------

    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app.config.from_object(config[config_name])

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app, resources={r"/api/*": {
        "origins":      app.config.get("CORS_ORIGINS", "*"),
        "methods":      ["GET", "POST", "DELETE", "OPTIONS"],
        "allow_headers":["Content-Type", "Authorization"],
    }})

    # Blueprints
    _register_blueprints(app)

    # Make models visible to Flask-Migrate
    with app.app_context():
        from app import models  # noqa: F401

    # Background scheduler (feeds + AI processing)
    if not app.config.get("TESTING", False):
        try:
            from app.services.scheduler import start_scheduler
            start_scheduler(app)
        except Exception as e:
            app.logger.warning("Scheduler failed to start: %s", e)

    return app


def _register_blueprints(app: Flask) -> None:
    from app.blueprints.auth  import auth_bp
    from app.blueprints.news  import news_bp
    from app.blueprints.admin import admin_bp
    from app.blueprints.api   import api_bp

    app.register_blueprint(auth_bp)           # /login  /logout
    app.register_blueprint(news_bp)           # /  /iocs  /incidents
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp,   url_prefix="/api")