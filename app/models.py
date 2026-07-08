from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    """
    The core user record. Every registered account maps to one row here.

    'hashed_password' stores a bcrypt hash — the column name was chosen from the start
    so that upgrading from plaintext (v1) to real hashing (v2) required no schema migration,
    only a change to what gets written into it.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)

    # Stores a bcrypt hash — never the raw password. ASVS V2.4.1.
    hashed_password = Column(String, nullable=False)

    # 'customer' is the least-privileged role; admins will be seeded separately.
    role = Column(String, nullable=False, default="customer")

    # server_default lets the DB engine set this, so it's always populated even if
    # the application layer forgets to pass a value.
    created_at = Column(DateTime(timezone=True), server_default=func.now())