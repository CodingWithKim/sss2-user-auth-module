from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import engine, get_db
from app import models
from app.schemas import UserRegister, UserLogin

# Create all database tables on startup if they don't exist yet.
# In production you'd typically use Alembic migrations instead, but
# create_all() is fine for local dev and keeps the setup friction low.
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Auth API",
    description="User authentication module — v1 baseline (intentionally insecure, for demonstration).",
    version="1.0.0",
)


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user account.

    Checks for duplicate username/email first so we return a clean 409
    rather than letting the database raise a unique-constraint error (which
    would bubble up as a confusing 500).
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

    # SECURITY DEBT: storing the password in plaintext — this is intentional for
    # the v1 baseline so we can demonstrate the vulnerability before fixing it in v2.
    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=user_data.password,  # plaintext — fixed in v2
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username,
    }


@app.post("/login")
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate a user with username + password.

    Returns a simple success message for now. No tokens are issued in v1 —
    that's the second deliberate security gap we'll fix in v2 (bcrypt + JWT).
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

    # SECURITY DEBT: plain equality check with no hashing — fixed in v2.
    if user.hashed_password != credentials.password:  # plaintext compare — fixed in v2
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # SECURITY DEBT: no token returned — any subsequent request has no way to
    # prove the user is authenticated. JWT dual-token flow added in v2.
    return {
        "message": "Login successful",
        "username": user.username,
        "role": user.role,
    }
