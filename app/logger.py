import json
import logging
import sys
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

# V4 ADDED: A dedicated logger instance keeps security events separate from
# uvicorn's general request logs. In production you'd ship these to a SIEM
# (Splunk, Datadog, etc.) — for now they go to stdout alongside the server logs.
security_logger = logging.getLogger("security")
logging.basicConfig(level=logging.INFO)


def _sanitise(value: Optional[str], max_len: int, fallback: str = "unknown") -> str:
    """
    Trim a value to a safe maximum length and strip surrounding whitespace.

    We rely on SQLAlchemy's parameterised queries for SQL injection prevention —
    this function only guards against unexpectedly large strings bloating the DB
    row or appearing in structured log output.
    If the value is None or empty, the fallback is returned instead.
    """
    if not value:
        return fallback
    return str(value).strip()[:max_len]


def _write_to_db(
    event_type: str,
    username: Optional[str],
    ip: str,
    outcome: str,
    role: Optional[str],
    route: str,
    method: str,
    http_status: int,
) -> None:
    """
    Open a short-lived DB session and insert exactly one audit log row.

    This function intentionally never raises. A broken audit trail is bad, but
    crashing the application and denying service to all users just because the
    log table is temporarily unavailable is worse. Any failure goes to stderr so
    it's visible in the server logs without ever reaching the HTTP response.

    The session is opened independently of the request's session so that an
    in-progress transaction rollback in the caller cannot discard the log entry —
    the audit record is committed before the error response is sent.
    ASVS V1.7.2 — log integrity must be maintained even when the request fails.
    """
    # Imported here to avoid a circular import: logger is imported by auth and main,
    # which are themselves imported during app initialisation before the DB is ready.
    from app.database import SessionLocal
    from app import models

    db: Session = SessionLocal()
    try:
        entry = models.AuditLog(
            timestamp   = datetime.now(timezone.utc),
            event_type  = _sanitise(event_type, 50),
            # username and role are nullable — a completely unauthenticated probe
            # won't have either, and logging "unknown" there would be misleading.
            username    = _sanitise(username, 50) if username else None,
            role        = _sanitise(role, 20)     if role     else None,
            route       = _sanitise(route,  200),
            method      = _sanitise(method,  10),
            outcome     = _sanitise(outcome, 20),
            http_status = int(http_status) if http_status else 0,
            ip_address  = _sanitise(ip, 45),
        )
        db.add(entry)
        db.commit()
        # No db.refresh() needed — we never read the row back immediately after write.
    except Exception as exc:
        # Swallow silently in the caller's view; write the failure to stderr so
        # it still surfaces in the server logs for operations teams to see.
        print(f"[audit-log] DB write failed: {exc}", file=sys.stderr)
    finally:
        db.close()


def log_event(
    event_type: str,
    username: str,
    ip: str,
    outcome: str,
    *,
    role: Optional[str] = None,
    route: str = "unknown",
    method: str = "unknown",
    http_status: int = 0,
) -> None:
    """
    V4 ADDED: Emit a structured security audit event to both stdout and the DB.

    All callers pass the positional fields (event_type, username, ip, outcome).
    The keyword-only arguments were added in V5 to give each log row enough context
    to reconstruct what happened without needing to cross-reference access logs:
      role        — the actor's role at the time of the event
      route       — the matched URL path (NOT the raw URL — avoids logging query PII)
      method      — HTTP verb
      http_status — the response code the server sent back

    Fields deliberately absent: passwords, tokens, email addresses, session IDs.
    If you ever need to debug a specific token, log its jti claim instead.
    ASVS V7.1.1 — sensitive fields are never logged.
    ASVS V7.1.2 — all authentication events are logged regardless of outcome.
    """
    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "event":       event_type,
        "username":    username,
        "role":        role,
        "method":      method,
        "route":       route,
        "outcome":     outcome,
        "http_status": http_status,
        "source_ip":   ip,
        # NOTE: password, token, and PII fields are deliberately excluded here.
        # If you're ever tempted to log a token for debugging, log the jti instead.
    }

    security_logger.info(json.dumps(entry))

    # Write to the persistent audit log table. This survives server restarts,
    # unlike the old in-memory buffer which was wiped on every uvicorn reload.
    _write_to_db(event_type, username, ip, outcome, role, route, method, http_status)


def get_recent_logs(db: Session) -> List[dict]:
    """
    V5 ADDED: Query the audit_log table and return the 100 most recent entries,
    newest first. Using the DB means the log survives server restarts — the old
    in-memory buffer was cleared every time uvicorn reloaded.

    100 rows is enough for a demo dashboard. A production system would add
    pagination (LIMIT / OFFSET) and date-range filtering here.
    """
    from app import models

    rows = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "timestamp":   row.timestamp.isoformat() if row.timestamp else None,
            "event":       row.event_type,
            "username":    row.username,
            "role":        row.role,
            "method":      row.method,
            "route":       row.route,
            "outcome":     row.outcome,
            "http_status": row.http_status,
            "source_ip":   row.ip_address,
        }
        for row in rows
    ]
