from datetime import datetime, timezone

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

    # Stores a bcrypt hash — never the raw password. ASVS V6.2 — Password Security.
    hashed_password = Column(String, nullable=False)

    # 'customer' is the least-privileged role; admins will be seeded separately.
    role = Column(String, nullable=False, default="customer")

    # server_default lets the DB engine set this, so it's always populated even if
    # the application layer forgets to pass a value.
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TokenBlacklist(Base):
    """
    V3 ADDED: Tracks revoked refresh tokens so that logout is truly terminal.
    In v2, logout only cleared the browser cookie — a captured token string
    remained valid until expiry. This table closes that gap.
    ASVS V7.4.1 — Session Termination: server-side invalidation of revoked tokens.
    """
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True)

    # jti (JWT ID) is a unique identifier embedded in every token we issue.
    # Indexed for fast lookups on every authenticated request.
    jti = Column(String, unique=True, nullable=False, index=True)

    # We store the expiry so a background cleanup job can prune stale rows later
    # without needing to decode the token again.
    expires_at = Column(DateTime, nullable=False)


class AuditLog(Base):
    """
    V5 ADDED: Persistent, append-only security audit trail.

    Every auditable event — login attempt, access control decision, logout,
    token refresh — writes one row here. The table is intentionally write-once:
    the application layer never runs UPDATE or DELETE against it. If you're
    ever tempted to prune old rows, add a separate archival job rather than
    deleting from this table.

    SQLite doesn't enforce column lengths the way PostgreSQL does, but the limits
    are documented here so a future migration won't silently truncate values.
    ASVS V16 — Security Logging and Error Handling: centralised audit log that cannot be cleared by application code.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)

    # Indexed so the admin endpoint can sort newest-first without a full table scan.
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Short, consistent category — keeps log queries predictable and grep-friendly.
    event_type = Column(String(50), nullable=False)

    # Username of the actor. NULL when the request never reached authentication
    # (e.g. a completely unauthenticated probe with no Bearer header).
    username = Column(String(50), nullable=True)

    # Role at the time of the event. NULL mirrors the same condition as username above.
    role = Column(String(20), nullable=True)

    # HTTP method (GET / POST / …) and the matched route path, not the raw URL.
    # Using the route path means query-string values — which could contain PII —
    # are never written here.
    method = Column(String(10), nullable=False)
    route  = Column(String(200), nullable=False)

    # "success", "denied", "failed", or "blocked" — kept short and consistent.
    outcome = Column(String(20), nullable=False)

    # The HTTP status code the server actually sent back to the client.
    http_status = Column(Integer, nullable=False)

    # Source IP for rate-limit analysis and anomaly detection.
    # 45 chars covers the longest valid IPv6 address with port.
    ip_address = Column(String(45), nullable=False)
