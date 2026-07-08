from datetime import datetime, timedelta, timezone
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app import models

# V2 ADDED: CryptContext tells passlib to use bcrypt as the hashing algorithm.
# ASVS V2.4.1 — bcrypt is specifically recommended because it's slow by design,
# which makes GPU-based brute-force attacks impractical even if the DB is leaked.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# V2 ADDED: HTTPBearer tells Swagger UI to show a simple token input field.
# We use this instead of OAuth2PasswordBearer because our /login accepts JSON,
# not form data — OAuth2PasswordBearer's Swagger flow sends form data and would
# cause a 422 mismatch.
http_bearer = HTTPBearer()

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
    ASVS V3.2.1 — token carries an 'exp' claim so it self-expires.
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
    ASVS V3.2.1 — token carries an 'exp' claim.
    # ASVS V3.3.1 — note: this token is not yet tracked server-side; logout only
    # clears the browser cookie. A captured token stays valid until expiry.
    # Server-side blacklisting is added in v3.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload.update({"exp": expire, "type": "refresh"})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


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


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer), db: Session = Depends(get_db)):
    """
    V2 ADDED: FastAPI dependency that extracts and validates the Bearer token from
    the Authorization header, then loads and returns the matching User from the DB.
    Any route that uses Depends(get_current_user) is effectively a protected endpoint.
    """
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