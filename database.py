# database.py
import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# Prefer DATABASE_URL from environment; default to local PostgreSQL now
# Examples:
#   Postgres: postgresql+psycopg2://user:password@host:5432/dbname
#   (override via env var DATABASE_URL)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:1970@127.0.0.1:5432/User",
)

# For SQLite, need special connect_args; not needed for Postgres
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to provide a DB session and ensure cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
