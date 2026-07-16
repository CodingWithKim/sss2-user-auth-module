from typing import Literal
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegister(BaseModel):
    """
    Request body for POST /register.

    Validators run before the data reaches the route handler, so the database
    never sees a weak password or an injection payload. Fail fast, fail cheap.
    Username enforces a strict regex that rejects SQL metacharacters at the schema
    layer before any query is built. ASVS V2.2 — Input Validation.
    """
    # Pattern rejects anything outside alphanumeric + underscore, so characters
    # like ', ", --, ; used in SQL injection payloads never reach the DB.
    # ASVS V2.2 — Input Validation: rejects metacharacters at the boundary.
    username: str = Field(..., pattern=r'^[a-zA-Z0-9_]{3,30}$')
    email: EmailStr
    password: str

    # V5 ADDED: Optional role selection at registration time. Defaults to 'customer'
    # so existing clients that don't send this field are unaffected.
    # Literal enforces the allowed set — any other value is rejected with a 422
    # before the route handler even runs.
    role: Literal["customer", "support", "admin"] = "customer"

    # ASVS V6.2.1 — Password Security: passwords must meet minimum complexity so they resist
    # dictionary attacks. Combined with bcrypt storage in v2, weak passwords
    # are rejected before they ever reach the database.
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
    The request shape is intentionally unchanged from v1 — only what the server
    does with these credentials has changed (bcrypt verify + dual-token response).
    """
    username: str
    password: str


class TokenResponse(BaseModel):
    """
    V2 ADDED: Response shape for POST /login and POST /token/refresh.
    Only the access token travels in the JSON body — the refresh token is set
    as an HttpOnly cookie by the route handler and never appears here.
    """
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """
    V2 ADDED: Safe public representation of a User — deliberately excludes
    hashed_password, created_at, and any other fields we don't want clients to see.
    """
    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}
