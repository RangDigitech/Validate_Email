# models.py
from database import Base
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, Text,
    UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True) # SQLAlchemy handles auto-increment automatically
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# models.py (additions)

class UserCredits(Base):
    __tablename__ = "user_credits"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    remaining_credits = Column(Integer, nullable=False, default=0)
    used_credits = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", backref="credits_obj", uselist=False)

class EmailsChecked(Base):
    __tablename__ = "emails_checked"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_checked_at = Column(DateTime(timezone=True), server_default=func.now())
    total_checks = Column(Integer, nullable=False, default=0)
    last_status = Column(String, nullable=True)
    last_score = Column(Integer, nullable=True)

    user = relationship("User", backref="emails_checked")

    __table_args__ = (
        UniqueConstraint("user_id", "email", name="uq_emails_checked_user_email"),
        Index("ix_emails_checked_user_email", "user_id", "email"),
    )

class EmailVerification(Base):
    __tablename__ = "email_verifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # minimal indexed fields for fast filtering in UI:
    status = Column(String, index=True)        # "valid"/"risky"/"invalid"
    state = Column(String, index=True)         # "Deliverable"/"Risky"/"Undeliverable"
    reason = Column(String)
    score = Column(Integer, index=True)
    domain = Column(String, index=True)
    local_part = Column(String)
    free = Column(Boolean)
    role = Column(Boolean)
    disposable = Column(Boolean)
    accept_all = Column(Boolean)
    smtp_provider = Column(String)
    mx_record = Column(String)
    catch_all = Column(Boolean)
    smtp_ok = Column(Boolean)
    # store the full raw result JSON as text (works on SQLite/Postgres)
    result_json = Column(Text, nullable=False)

    user = relationship("User", backref="verifications")

# --- Bulk grouping to separate bulk results from recent singles ---

class BulkJob(Base):
    __tablename__ = "bulk_jobs"
    # Use string job id (uuid hex) so we can reuse the jobid returned by API
    id = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name = Column(String, nullable=True)
    total_emails = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", backref="bulk_jobs")

class BulkItem(Base):
    __tablename__ = "bulk_items"
    id = Column(Integer, primary_key=True)
    job_id = Column(String, ForeignKey("bulk_jobs.id", ondelete="CASCADE"), index=True, nullable=False)
    verification_id = Column(Integer, ForeignKey("email_verifications.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)

    job = relationship("BulkJob", backref="items")
    verification = relationship("EmailVerification", backref="bulk_item")
