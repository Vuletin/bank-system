import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev")
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(Config):
    # Use SQLite for local dev
    SQLALCHEMY_DATABASE_URI = "sqlite:///local.db"


class ProductionConfig(Config):
    # Use Postgres on Render (DATABASE_URL will be set in env)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")  # or sqlite:///bank.db