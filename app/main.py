from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
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
)

# Create all database tables on startup if they don't exist yet.
# In production you'd typically use Alembic migrations instead, but
# create_all() is fine for local dev and keeps the setup friction low.
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Auth API",
    description="User authentication module — v2: bcrypt hashing + JWT dual-token.",
    version="2.0.0",
)


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user account.

    Checks for duplicate username/email first so we return a clean 409
    rather than letting the database raise a unique-constraint error (which
    would bubble up as a confusing 500).
    NEW: password is now hashed with bcrypt before being stored.
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
def login(credentials: UserLogin, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate a user with username + password.

    Verifies credentials with bcrypt, then issues an access token in the JSON body
    and a refresh token in an HttpOnly cookie. The two-token split keeps the
    long-lived credential out of JS reach entirely.
    """
    user = db.query(models.User).filter(
        models.User.username == credentials.username
    ).first()

    if not user:
        # Return the same message for wrong username vs wrong password so we
        # don't leak which one failed (user enumeration prevention).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # verify_password() does a constant-time bcrypt comparison — never use plain == for passwords.
    if not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Issue both tokens — short-lived access token in the body, long-lived refresh
    # token in an HttpOnly cookie so JS can never read it.
    access_token = create_access_token(data={"sub": user.username})
    new_refresh_token = create_refresh_token(data={"sub": user.username})

    # V2 ADDED: HttpOnly prevents JS from reading the cookie, which blocks XSS-based
    # token theft. SameSite=strict blocks CSRF. Secure=True enforces HTTPS in production.
    # ASVS V3.4.2/3/5
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    return TokenResponse(access_token=access_token)


@app.get("/profile", response_model=UserResponse)
def profile(current_user: models.User = Depends(get_current_user)):
    """
    V2 ADDED: Protected endpoint — requires a valid Bearer token in the
    Authorization header. Returns the authenticated user's public profile.
    If the token is missing, expired, or tampered with, get_current_user
    raises a 401 before this function body even runs.
    """
    return current_user


@app.post("/token/refresh", response_model=TokenResponse)
def refresh_token(request: Request):
    """
    V2 ADDED: Issue a new access token using the refresh token stored in the
    HttpOnly cookie. The client never touches the refresh token directly —
    the browser just sends the cookie automatically with every request to this URL.
    """
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cookie is missing",
        )

    payload = decode_token(token)

    # V2 ADDED: Make sure this is actually a refresh token and not an access token
    # being reused here — both are JWTs signed with the same key, so we need the
    # 'type' claim to tell them apart.
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    username = payload.get("sub")
    new_access_token = create_access_token(data={"sub": username})

    return TokenResponse(access_token=new_access_token)


@app.post("/logout")
def logout(response: Response):
    """
    V2 ADDED: Clear the refresh token cookie from the browser.
    Note: this only removes the cookie on the client side. If someone already
    captured the refresh token string, it remains valid until expiry — server-side
    blacklisting is the fix, and it's coming in v3.
    """
    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}