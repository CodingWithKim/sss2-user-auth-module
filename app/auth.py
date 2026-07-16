from datetime import datetime, timedelta, timezone
import os
from typing import Optional
import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app import models

# V2 ADDED: CryptContext tells passlib to use bcrypt as the hashing algorithm.
# ASVS V6.2 — Password Security: bcrypt is an adaptive hashing function; its cost
# factor makes GPU-based brute-force attacks impractical even if the DB is leaked.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# V2 ADDED: HTTPBearer tells Swagger UI to show a simple token input field.
# We use this instead of OAuth2PasswordBearer because our /login accepts JSON,
# not form data — OAuth2PasswordBearer's Swagger flow sends form data and would
# cause a 422 mismatch.
# V5 ADDED: auto_error=False disables the built-in 403 that FastAPI raises for a
# missing Authorization header. RFC 7235 says a missing credential is a 401, not
# 403 — 403 means "authenticated but not allowed". We raise the correct 401 ourselves
# in get_current_user() below. ASVS V8.2.1 — General Authorization Design: fail-safe.
http_bearer = HTTPBearer(auto_error=False)

# V2 ADDED: Pull JWT settings from .env so we never hardcode secrets in source code.
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-dev-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def hash_password(plain_password: str) -> str:
    """
    V2 ADDED: Run the plain password through bcrypt and return the hash string.
    The hash includes the salt, so each call produces a different output even
    for the same input — we never need to store the salt separately.
    """
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    V2 ADDED: Re-hash the incoming password and compare it against the stored hash.
    Never do plain string comparison for passwords — this is the correct way.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    """
    V2 ADDED: Sign a short-lived JWT for API access. The 15-minute window limits
    the blast radius if a token is intercepted — it becomes useless quickly.
    ASVS V9.2.1 — Token Content: token carries an 'exp' claim so it self-expires.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire, "type": "access"})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """
    V2 ADDED: Sign a longer-lived JWT stored in an HttpOnly cookie, used only to
    issue new access tokens. Keeping it separate from the access token means we
    can revoke sessions without forcing the user to log in every 15 minutes.
    ASVS V9.2.1 — Token Content: token carries an 'exp' claim.
    NEW: token now embeds a unique 'jti' claim so it can be individually blacklisted
    on logout or rotation. ASVS V7.4.1 — Session Termination.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    # V3 ADDED: jti (JWT ID) makes every token uniquely identifiable, which is what
    # allows us to invalidate a specific token without touching any others.
    payload.update({"exp": expire, "type": "refresh", "jti": generate_jti()})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def generate_jti() -> str:
    """
    V3 ADDED: Generate a random unique ID to embed in every refresh token.
    uuid4 gives us 122 bits of randomness — collision probability is negligible.
    """
    return uuid.uuid4().hex


def blacklist_token(jti: str, expires_at: datetime, db: Session) -> None:
    """
    V3 ADDED: Insert a revoked token's jti into the blacklist table so subsequent
    requests carrying that token are rejected even if it hasn't expired yet.
    ASVS V7.4.1 — Session Termination: server-side invalidation of revoked tokens.
    """
    entry = models.TokenBlacklist(jti=jti, expires_at=expires_at)
    db.add(entry)
    db.commit()


def is_token_blacklisted(jti: str, db: Session) -> bool:
    """
    V3 ADDED: Check whether a token's jti has been revoked. Called on every
    /token/refresh and /logout attempt before doing anything else.
    The jti column is indexed so this lookup stays fast even with many rows.
    """
    return db.query(models.TokenBlacklist).filter(
        models.TokenBlacklist.jti == jti
    ).first() is not None


def decode_token(token: str) -> dict:
    """
    V2 ADDED: Verify the JWT signature and expiry, then return the payload.
    Raises 401 on any failure — expired, tampered, wrong signature, etc.
    We don't tell the client WHY it failed to avoid leaking implementation details.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer), db: Session = Depends(get_db)):
    """
    V2 ADDED: FastAPI dependency that extracts and validates the Bearer token from
    the Authorization header, then loads and returns the matching User from the DB.
    Any route that uses Depends(get_current_user) is effectively a protected endpoint.
    V5 ADDED: credentials is now Optional because http_bearer uses auto_error=False.
    Missing or malformed Authorization headers raise 401 (not 403) per RFC 7235.
    ASVS V8.2.1 — General Authorization Design: any failure path denies access.
    """
    # credentials is None when the Authorization header is absent entirely.
    # Raising 401 here (not 403) matches RFC 7235: 401 = "you haven't identified
    # yourself", 403 = "I know who you are but you're not allowed".
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_token(token)

    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing subject claim",
        )

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User belonging to this token no longer exists",
        )

    return user


def require_role(*allowed_roles: str):
    """
    V4 ADDED: Factory that returns a FastAPI dependency enforcing role-based access.
    Usage: Depends(require_role("admin")) or Depends(require_role("admin", "support")).

    Deny-by-default means any role not explicitly listed is rejected with a 403,
    so forgetting to add a role restriction is safe — it just blocks everyone until
    you wire it up. ASVS V8.2.1 / V8.3.1 — General Authorization Design / Operation Level Authorization.
    """
    def dependency(request: Request, current_user: models.User = Depends(get_current_user)) -> models.User:
        # V5 ADDED: Treat a missing or unexpected role as a denial, not an exception.
        # The `not current_user.role` guard is the fail-safe: if a row somehow lands
        # in the DB with role=NULL, the outcome is a 403, not an unhandled AttributeError
        # and certainly not accidental access. ASVS V4.1.1 — errors default to denial.
        if not current_user.role or current_user.role not in allowed_roles:
            # V4 ADDED: Log the attempt before raising — we want a trail even for
            # blocked requests. The attacker doesn't get a reason; we do.
            # ASVS V8.2.1 — General Authorization Design: deny by default, log the attempt.
            from app.logger import log_event
            log_event(
                event_type="unauthorized_access_attempt",
                username=current_user.username,
                ip=request.client.host if request.client else "unknown",
                outcome="denied",
                role=current_user.role or "none",
                route=request.url.path,
                method=request.method,
                http_status=403,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user
    return dependency
