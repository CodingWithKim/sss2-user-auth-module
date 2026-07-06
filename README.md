# Secure Auth — User Authentication & Authorisation Module

An iterative Python/FastAPI authentication module built across five branches. Each branch is a cumulative superset of the previous — old code is never deleted, only hardened.

**Tech stack Used (Previewed, May Update Later):** 
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

## Branch Overview (Preview)

| Branch                   | What it adds                                                                                                           |
|--------------------------|------------------------------------------------------------------------------------------------------------------------|
| `version1`               | Basic feature (register + login), **plaintext password storage, no tokens** (intentional insecurity for demonstration) |
| `version2`               | Bcrypt password hashing + JWT dual-token (short-lived access token + long-lived HttpOnly refresh cookie)               |
| `version3`               | Server-side token blacklist + refresh token rotation + Pydantic input validation (blocks SQL metacharacters)           |
| `version4`               | Role-based access control (RBAC) + rate limiting on login + sanitised audit logging + generic error responses          |
| `version5 (main branch)` | Frontend demo panel (register, login, profile, security demos) + CORS + abuse-case test script                         |

Every branch runs independently, once cloned, you can run any version on your pc using the command below:
```bash
git checkout version2
uvicorn app.main:app --reload
# open http://127.0.0.1:8000/docs
```

---

## Quick Start (Preview)

```bash
# 0. Clone the repository
git clone https://github.com/CodingWithKim/sss2-user-auth-module.git
cd sss2-user-auth-module

# 1. Choose which version to run (see Branch Overview above)
#    main / version5 is checked out by default after cloning.
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

# 5. Start the server
uvicorn app.main:app --reload

# 6. Open in browser
# Frontend:   http://127.0.0.1:8000
# Swagger UI: http://127.0.0.1:8000/docs
```