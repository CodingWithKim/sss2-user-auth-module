from pydantic import BaseModel, EmailStr, field_validator


class UserRegister(BaseModel):
    """
    Request body for POST /register.

    The password validator runs before the data reaches the route handler,
    so the database never sees a weak password. This is an early-exit pattern —
    fail fast, fail cheap.
    """
    username: str
    email: EmailStr
    password: str

    # ASVS V2.1.1 — passwords must meet minimum complexity so they resist
    # dictionary attacks even before we add proper hashing in v2.
    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")

        special_chars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\"
        if not any(c in special_chars for c in v):
            raise ValueError("Password must contain at least one special character")

        return v


class UserLogin(BaseModel):
    """
    Request body for POST /login.
    Kept intentionally minimal — v1 only needs credentials, no token machinery yet.
    """
    username: str
    password: str
