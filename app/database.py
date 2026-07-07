from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

# Pull the database URL from the .env file so we can swap databases (e.g. Postgres in prod)
# without touching code. Falls back to a local SQLite file if the var is missing.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./auth.db")

# connect_args is SQLite-specific — it lets multiple threads share one connection,
# which FastAPI needs because it handles requests concurrently.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Each instance of SessionLocal is one database transaction.
# autocommit=False means we control when changes are saved.
# autoflush=False means SQLAlchemy won't auto-sync before every query.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the parent class all ORM models inherit from.
# SQLAlchemy uses it to track which tables exist.
Base = declarative_base()


def get_db():
    """
    FastAPI dependency that hands a database session to a route function,
    then closes it automatically when the request is done — even if an
    exception is raised. Using 'yield' makes it a context manager under the hood.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
