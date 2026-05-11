import os
from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY not set. Run: python -c \"import secrets; print(secrets.token_hex(32))\"")

    _db_url = os.environ.get("DATABASE_URL", "sqlite:///cybernews_dev.db")
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    SESSION_COOKIE_SECURE    = False
    PERMANENT_SESSION_LIFETIME = 86400  # 24 h

    BEARER_TOKEN = os.environ.get("BEARER_TOKEN")
    if not BEARER_TOKEN:
        raise ValueError("BEARER_TOKEN not set in .env")

    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    SCHEDULER_INTERVAL_MINUTES = int(os.environ.get("SCHEDULER_INTERVAL_MINUTES", 30))
    SCHEDULER_MAX_ARTICLES_PER_RUN = 10


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_ECHO = False


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False


config = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig,
    "default":     DevelopmentConfig,
}