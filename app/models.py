from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    """
    The core user record. Every registered account maps to one row here.

    Note on 'hashed_password': the column is deliberately named this way even though
    v1 stores plaintext. This avoids a schema migration when v2 introduces real hashing —
    we only change what we write into the column, not the column's name.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)

    # SECURITY DEBT: storing plaintext in v1 — will be replaced with bcrypt hash in v2.
    hashed_password = Column(String, nullable=False)

    # 'customer' is the least-privileged role; admins will be seeded separately.
    role = Column(String, nullable=False, default="customer")

    # server_default lets the DB engine set this, so it's always populated even if
    # the application layer forgets to pass a value.
    created_at = Column(DateTime(timezone=True), server_default=func.now())
