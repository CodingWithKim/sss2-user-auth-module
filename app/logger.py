import json
import logging
from datetime import datetime, timezone

# V4 ADDED: A dedicated logger instance keeps security events separate from
# uvicorn's general request logs. In production you'd ship these to a SIEM
# (Splunk, Datadog, etc.) — for now they go to stdout alongside the server logs.
security_logger = logging.getLogger("security")
logging.basicConfig(level=logging.INFO)


def log_event(event_type: str, username: str, ip: str, outcome: str) -> None:
    """
    V4 ADDED: Emit a structured JSON audit log entry for any security-relevant event.

    Fields are deliberately minimal — no passwords, no tokens, no PII beyond username.
    The goal is enough context to investigate an incident without creating a new one.
    ASVS V7.1.1 — sensitive fields (password, token, email) are never logged.
    ASVS V7.1.2 — all authentication events produce a log entry regardless of outcome.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "username": username,
        "source_ip": ip,
        "outcome": outcome,
        # NOTE: password, token, and PII fields are deliberately excluded here.
        # If you're ever tempted to log a token for debugging, don't — log the jti instead.
    }
    security_logger.info(json.dumps(entry))