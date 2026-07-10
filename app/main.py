from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app.database import engine, get_db
from app import models
from app.schemas import UserRegister, UserLogin, TokenResponse, UserResponse
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    blacklist_token,
    is_token_blacklisted,
    require_role,
)
from app.logger import log_event

# Create all database tables on startup if they don't exist yet.
# In production you'd typically use Alembic migrations instead, but
# create_all() is fine for local dev and keeps the setup friction low.
models.Base.metadata.create_all(bind=engine)

# V4 ADDED: Rate limiter keyed by the caller's IP address.
# get_remote_address reads X-Forwarded-For when behind a proxy, falling back
# to the direct connection IP — works correctly in both local dev and production.
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Secure Auth API",
    description="User authentication module — v4: RBAC + rate limiting + audit logging + error hardening.",
    version="4.0.0",
)

# V4 ADDED: Attach the limiter to the app state so slowapi's middleware can find it.
app.state.limiter = limiter


# V4 ADDED: Catch slowapi's RateLimitExceeded and return a clean 429 response.
# Without this handler the default exception would bubble up as an ugly 500.
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(_request: Request, _exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"error": "Too many requests — please slow down and try again later"},
    )


# V4 ADDED: Catch-all for any unhandled exception. Returns a generic message so
# stack traces and internal details never leak to the client. ASVS V1.7.2.
@app.exception_handler(Exception)
async def global_error_handler(_request: Request, _exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An unexpected error occurred"},
    )


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user account.

    Checks for duplicate username/email first so we return a clean 409
    rather than letting the database raise a unique-constraint error (which
    would bubble up as a confusing 500). Password is bcrypt-hashed before storage.
    """
    # Check if username is already taken
    existing_username = db.query(models.User).filter(
        models.User.username == user_data.username
    ).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered"
        )

    # Check if email is already in use
    existing_email = db.query(models.User).filter(
        models.User.email == user_data.email
    ).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    # Password is hashed by hash_password() before hitting the DB — the raw string
    # never gets written anywhere. ASVS V2.4.1.
    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username,
    }


@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, credentials: UserLogin, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate a user with username + password.

    Verifies credentials with bcrypt, then issues an access token in the JSON body
    and a refresh token in an HttpOnly cookie. The two-token split keeps the
    long-lived credential out of JS reach entirely.
    NEW: rate-limited to 5 attempts per minute per IP to mitigate brute-force attacks.
    Audit logs emitted on both success and failure.
    """
    ip = request.client.host if request.client else "unknown"

    user = db.query(models.User).filter(
        models.User.username == credentials.username
    ).first()

    if not user:
        # Return the same message for wrong username vs wrong password so we
        # don't leak which one failed (user enumeration prevention).
        # V4 ADDED: Log failed attempts — repeated failures from one IP are a brute-force signal.
        log_event("login_failure", credentials.username, ip, "user_not_found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # verify_password() does a constant-time bcrypt comparison — never use plain == for passwords.
    if not verify_password(credentials.password, user.hashed_password):
        # V4 ADDED: Log wrong-password failures separately from user-not-found
        # so we can distinguish credential stuffing from username enumeration in the logs.
        log_event("login_failure", credentials.username, ip, "wrong_password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Issue both tokens — short-lived access token in the body, long-lived refresh
    # token in an HttpOnly cookie so JS can never read it.
    access_token = create_access_token(data={"sub": user.username})
    new_refresh_token = create_refresh_token(data={"sub": user.username})

    # HttpOnly prevents JS from reading the cookie, which blocks XSS-based
    # token theft. SameSite=strict blocks CSRF. Secure=True enforces HTTPS in production.
    # ASVS V3.4.2/3/5
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    # V4 ADDED: Successful logins are just as important to log as failures —
    # they establish the baseline of normal activity for anomaly detection.
    log_event("login_success", user.username, ip, "success")

    return TokenResponse(access_token=access_token)


@app.get("/profile", response_model=UserResponse)
def profile(current_user: models.User = Depends(get_current_user)):
    """
    Protected endpoint — requires a valid Bearer token in the Authorization header.
    Returns the authenticated user's public profile.
    If the token is missing, expired, or tampered with, get_current_user
    raises a 401 before this function body even runs.
    """
    return current_user


@app.post("/token/refresh", response_model=TokenResponse)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Issue a new access token using the refresh token stored in the HttpOnly cookie.
    The client never touches the refresh token directly —
    the browser just sends the cookie automatically with every request to this URL.
    Checks the blacklist before issuing, and immediately blacklists the
    old refresh token after rotation so it can't be reused. ASVS V3.3.3.
    NEW: emits an audit log on successful token refresh.
    """
    ip = request.client.host if request.client else "unknown"

    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cookie is missing",
        )

    payload = decode_token(token)

    # Make sure this is actually a refresh token and not an access token
    # being reused here — both are JWTs signed with the same key, so we need the
    # 'type' claim to tell them apart.
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    jti = payload.get("jti")

    # Reject the token if it was already used or explicitly revoked.
    # This blocks parallel session reuse — if an attacker captured the refresh token
    # and tries to use it after the legitimate user already rotated it, they get a 401.
    if jti and is_token_blacklisted(jti, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    username = payload.get("sub")
    new_access_token = create_access_token(data={"sub": username})
    new_refresh_token = create_refresh_token(data={"sub": username})

    # Blacklist the old refresh token immediately after issuing a new one.
    # ASVS V3.3.3 — rotation means each refresh token is single-use.
    if jti:
        expires_at = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
        blacklist_token(jti, expires_at, db)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    # V4 ADDED: Log successful token refreshes — a spike in refresh activity from
    # one IP can indicate token theft or session hijacking attempts.
    log_event("token_refresh", username, ip, "success")

    return TokenResponse(access_token=new_access_token)


@app.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Clear the refresh token cookie from the browser, and blacklist the refresh
    token server-side so even a captured token string becomes useless immediately.
    ASVS V3.3.1.
    NEW: emits an audit log on logout.
    """
    ip = request.client.host if request.client else "unknown"
    username = "anonymous"

    token = request.cookies.get("refresh_token")
    if token:
        payload = decode_token(token)
        username = payload.get("sub", "unknown")
        jti = payload.get("jti")

        # Blacklist the token before deleting the cookie — the cookie deletion handles
        # the browser; the blacklist handles anyone who may have copied the raw token string.
        if jti and not is_token_blacklisted(jti, db):
            expires_at = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
            blacklist_token(jti, expires_at, db)

    response.delete_cookie("refresh_token")

    # V4 ADDED: Log logouts so we can correlate them with subsequent suspicious activity
    # (e.g. a refresh attempt right after a logout is a red flag).
    log_event("logout", username, ip, "success")

    return {"message": "Logged out successfully"}


@app.get("/admin/dashboard")
def admin_dashboard(current_user: models.User = Depends(require_role("admin"))):
    """
    V4 ADDED: Admin-only endpoint. require_role("admin") rejects anyone whose role
    is not "admin" with a 403 before the function body runs — deny by default.
    ASVS V4.1.1/4.1.3.
    """
    return {
        "message": f"Welcome to the admin dashboard, {current_user.username}",
        "role": current_user.role,
    }


@app.get("/support/users")
def support_users(current_user: models.User = Depends(require_role("admin", "support"))):
    """
    V4 ADDED: Admin and support staff can access this endpoint; customers cannot.
    Passing multiple roles to require_role() is the idiomatic way to express
    "any of these roles is acceptable." ASVS V4.1.1.
    """
    users = []
    return {
        "message": f"User list accessed by {current_user.username} ({current_user.role})",
        "users": users,
    }