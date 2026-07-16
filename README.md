# Secure Auth — User Authentication & Authorisation Module

An iterative Python/FastAPI authentication module built across five branches. Each branch is a cumulative superset of the previous — old code is never deleted, only hardened.

**Tech stack:**
```
Python 3.11
FastAPI
SQLite + SQLAlchemy
passlib[bcrypt]
python-jose
slowapi
Vanilla HTML/CSS/JS
```

---

## Branch Overview

| Branch | What it adds |
|--------|-------------|
| `version1` | Baseline scaffold — register + login, **plaintext password storage, no tokens** (intentional insecurity for demonstration) |
| `version2` | Bcrypt password hashing + JWT dual-token (short-lived access token + long-lived HttpOnly refresh cookie) |
| `version3` | Server-side token blacklist + refresh token rotation + Pydantic input validation (blocks SQL metacharacters) |
| `version4` | Role-based access control (RBAC) + rate limiting on login + sanitised audit logging + generic error responses |
| `version5` | Frontend demo panel + CSS/JS split + role registration + CORS + SQLite audit log DB + fail-safe hardening + 5 abuse-case tests |

Every branch runs independently — once cloned, switch to any version and run it locally:

```bash
git checkout version2
python -m uvicorn app.main:app --reload
# open http://127.0.0.1:8000/docs
```

---

## Quick Start

```bash
# 0. Clone the repository
git clone https://github.com/CodingWithKim/sss2-user-auth-module.git
cd sss2-user-auth-module

# 1. Choose which version to run (see Branch Overview above)
#    version5 / main is checked out by default after cloning.
#    To test an earlier stage, switch branches first, e.g.:
git checkout version2

# 2. Create and activate a virtual environment
#    (or let your IDE, e.g. PyCharm, create/detect one automatically)
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
copy .env.example .env         # Windows
# cp .env.example .env         # macOS / Linux
# Then open .env and set a strong SECRET_KEY for production use

# 5. Start the server
python -m uvicorn app.main:app --reload

# 6. Open in browser
# Frontend:   http://127.0.0.1:8000
# Swagger UI: http://127.0.0.1:8000/docs
```

> **Note on `.env`:** This step is optional for local development — the server falls back to a hardcoded dev key if `.env` is missing. Never deploy with the default `SECRET_KEY`; always replace it with a strong random value in any non-local environment.

> **Windows note**: If `python` is not recognised, use `py` instead (e.g. `py -m venv venv`).

---

## Environment Variables

The server reads its configuration from a `.env` file (loaded via `python-dotenv`). Copy `.env.example` to `.env` and edit as needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `fallback-dev-key-change-in-production` | HMAC key used to sign JWTs — **must be changed before any deployment** |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime in minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days |

All four variables have safe fallback defaults, so the server starts without a `.env` file during development. In production, set at minimum `SECRET_KEY` to a cryptographically random string (e.g. `openssl rand -hex 32`).

---

## Project Structure

```
sss2-user-auth-module/
├── app/
│   ├── auth.py          # JWT helpers, bcrypt, HTTPBearer, require_role()
│   ├── database.py      # SQLAlchemy engine + SessionLocal factory
│   ├── logger.py        # Sanitised audit logger → stdout + SQLite DB
│   ├── main.py          # FastAPI routes, CORS, rate limiter, error handlers
│   ├── models.py        # User, TokenBlacklist, AuditLog (SQLAlchemy ORM)
│   └── schemas.py       # Pydantic validators — password strength, username regex
├── frontend/
│   ├── index.html       # HTML structure — auth card + 8-card security test suite
│   ├── style.css        # Dark theme, CSS variables, responsive grid
│   └── app.js           # Frontend logic — token in JS memory, fetch calls, test runner
├── tests/
│   └── abuse_cases.py   # 5 abuse-case tests (SQL injection · weak password ·
│                        # forged token · privilege escalation · brute force)
├── .env.example         # Environment variable template
├── requirements.txt
└── README.md
```

---

## API Endpoints

| Method | Route | Auth required | Roles | Description |
|--------|-------|--------------|-------|-------------|
| POST | `/register` | No | — | Create a new user account (role selectable: customer / support / admin) |
| POST | `/login` | No | — | Authenticate and receive an access token; sets HttpOnly refresh cookie |
| GET | `/profile` | Bearer token | Any authenticated | Return the current user's profile |
| POST | `/token/refresh` | HttpOnly cookie | Any authenticated | Exchange refresh token for a new access token (old token is blacklisted) |
| POST | `/logout` | HttpOnly cookie | Any authenticated | Revoke refresh token server-side and clear cookie |
| GET | `/admin/dashboard` | Bearer token | `admin` | Admin-only dashboard |
| GET | `/support/users` | Bearer token | `admin`, `support` | User list for admin and support staff |
| GET | `/admin/audit-log` | Bearer token | `admin` | 100 most recent security events from the persistent audit log DB |

---

## Running the Abuse-Case Tests

Make sure the server is running first (`python -m uvicorn app.main:app --reload`), then:

```bash
python tests/abuse_cases.py
```

The script runs five scenarios in a fixed order (brute force always last so the rate limiter doesn't block earlier tests) and asserts the expected HTTP status code for each:

| # | Test | Expected | ASVS |
|---|------|----------|------|
| 1 | SQL injection payload at `/register` | `422` | V2.2 — Input Validation |
| 2 | Weak password (no uppercase / digit / symbol) | `422` | V6.2.1 — Password Security |
| 3 | Forged JWT token at `/profile` | `401` | V9.1.1 — Token Source and Integrity |
| 4 | Customer token on `/admin/dashboard` | `403` | V8.2.1 — General Authorization Design |
| 5 | 6 rapid login attempts (brute force) | `429` on 6th | V6.3.1 — General Authentication Security |

---

## ASVS 5.0.0 Compliance Summary

| # | ASVS 5.0.0 Requirement | Implemented in | Branch |
|---|---|---|---|
| 1 | **V6.2.1** — Password Security: passwords must be at least 8 characters in length | `schemas.py` `password_strength` validator | v1 |
| 2 | **V9.1.1** — Token Source and Integrity: self-contained tokens validated using digital signature before accepting contents | `auth.py` `decode_access_token()` JWT verification | v2 |
| 3 | **V9.1.2** — Token Source and Integrity: only allowlisted algorithms used; 'None' algorithm excluded | `auth.py` `ALGORITHM = "HS256"` | v2 |
| 4 | **V9.2.1** — Token Content: token accepted only if verification time is within the validity timespan (`exp` / `nbf`) | `auth.py` `create_access_token()` with 15-minute `exp` claim | v2 |
| 5 | **V3.3.1** — Cookie Setup: cookies have the `Secure` attribute set | `main.py` `/login` `set_cookie(secure=True)` | v2 |
| 6 | **V3.3.2** — Cookie Setup: each cookie's `SameSite` attribute set according to the purpose of the cookie | `main.py` `/login` `set_cookie(samesite="strict")` | v2 |
| 7 | **V3.3.4** — Cookie Setup: cookies not accessible to client-side scripts have the `HttpOnly` attribute set | `main.py` `/login` `set_cookie(httponly=True)` | v2 |
| 8 | **V7.4.1** — Session Termination: when termination is triggered, the application disallows any further use of the session (blacklist for self-contained tokens) | `auth.py` `is_token_blacklisted()` + `main.py` `/logout` | v3 |
| 9 | **V2.4.1** — Anti-automation: controls in place to protect against excessive calls to application functions | `main.py` slowapi rate limiter | v4 |
| 10 | **V6.3.1** — General Authentication Security: controls to prevent credential stuffing and password brute force implemented | `main.py` slowapi (5 req/min/IP on `/login`) | v4 |
| 11 | **V8.2.1** — General Authorization Design: function-level access restricted to consumers with explicit permissions | `auth.py` `require_role()` — deny-by-default | v4 |
| 12 | **V8.3.1** — Operation Level Authorization: application enforces authorisation rules at a trusted service layer, not client-side | `auth.py` server-side `Depends(require_role(...))` | v4 |
| 13 | **V3.4.2** — Browser Security Mechanism Headers: CORS `Access-Control-Allow-Origin` validated against an allowlist of trusted origins | `main.py` `CORSMiddleware(allow_origins=[...])` | v5 |
