"""
Abuse-case test script for the Secure Auth API.

Run with:
    python tests/abuse_cases.py

Make sure the server is running first:
    uvicorn app.main:app --reload

Test cases
----------
[1] SQL Injection            — 422  (abuse)
[2] Weak Password Rejection  — 422  (negative)
[3] Invalid Token Access     — 401  (negative)
[4] Privilege Escalation     — 403  (negative / RBAC)
[5] Brute Force Attack       — 429  (abuse)

Brute force is always last because it hammers the rate limiter and
would lock out /login for the other tests if run first.
"""
import requests

BASE = "http://127.0.0.1:8000"


def test_sql_injection():
    """
    Send a classic SQL injection payload as the username at /register.
    Pydantic's regex validator ([a-zA-Z0-9_]{3,30}) should reject it at
    the schema layer and return 422 — the DB query is never built.
    ASVS V2.2 — Input Validation.
    """
    print("\n[1] SQL Injection")

    res = requests.post(f"{BASE}/register", json={
        "username": "' OR '1'='1",
        "email":    "inject@test.com",
        "password": "Test1234!",
    })
    print(f"  SQLi payload response: {res.status_code}")
    assert res.status_code == 422, f"Expected 422, got {res.status_code}"
    print("  PASS — injection payload rejected before reaching the database")


def test_weak_password():
    """
    Attempt to register with a password that fails the complexity rules
    (no uppercase, no digit, no special character).
    The Pydantic field_validator should return 422 before the user is created.
    ASVS V6.2.1 — Password Security.
    """
    print("\n[2] Weak Password Rejection")

    res = requests.post(f"{BASE}/register", json={
        "username": "weakpassuser",
        "email":    "weak@test.com",
        "password": "password",   # fails: no uppercase, no digit, no special char
    })
    print(f"  Weak password response: {res.status_code}")
    assert res.status_code == 422, f"Expected 422, got {res.status_code}"
    print("  PASS — weak password rejected at schema validation layer")


def test_invalid_token():
    """
    Access a protected endpoint (/profile) with a forged Bearer token.
    The server verifies the HMAC-SHA256 signature — a single altered
    character makes the token invalid and must return 401 Unauthorised.
    ASVS V9.1.1 — Token Source and Integrity.
    """
    print("\n[3] Invalid Token Access")

    fake_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.FORGEDSIGNATURE"
    res = requests.get(
        f"{BASE}/profile",
        headers={"Authorization": f"Bearer {fake_token}"},
    )
    print(f"  Forged token response: {res.status_code}")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print("  PASS — forged token correctly rejected by signature verification")


def test_privilege_escalation():
    """
    Log in as a customer, then attempt to access /admin/dashboard.
    RBAC (require_role) should deny it with 403 Forbidden — deny by default.
    ASVS V8.2.1 / V8.3.1 — General Authorization Design / Operation Level Authorization.
    """
    print("\n[4] Privilege Escalation (RBAC)")

    # Register a fresh customer account (ignore 409 if already exists)
    requests.post(f"{BASE}/register", json={
        "username": "testcustomer",
        "email":    "testcustomer@example.com",
        "password": "Customer1!",
    })

    # Log in to get an access token
    login_res = requests.post(f"{BASE}/login", json={
        "username": "testcustomer",
        "password": "Customer1!",
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.status_code}"
    token = login_res.json()["access_token"]

    # Attempt to hit an admin-only endpoint with a customer token
    admin_res = requests.get(
        f"{BASE}/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"  /admin/dashboard as customer: {admin_res.status_code}")
    assert admin_res.status_code == 403, f"Expected 403, got {admin_res.status_code}"
    print("  PASS — customer was denied access to admin dashboard")


def test_brute_force():
    """
    Fire 6 rapid login attempts with wrong credentials.
    slowapi rate limiter (5 req/min/IP) should return 429 on the 6th attempt.
    ASVS V6.3.1 — General Authentication Security (mitigates credential stuffing / brute-force attacks).
    """
    print("\n[5] Brute Force Attack")
    last_status = None

    for i in range(1, 7):
        res = requests.post(f"{BASE}/login", json={
            "username": "hacker",
            "password": f"wrongpass{i}",
        })
        last_status = res.status_code
        print(f"  Attempt {i}: {res.status_code}")
        if res.status_code == 429:
            break

    assert last_status == 429, f"Expected 429 on attempt 6, got {last_status}"
    print("  PASS — rate limiter blocked the attack")


if __name__ == "__main__":
    print("=" * 50)
    print("  Secure Auth — Abuse Case Tests")
    print("=" * 50)

    # Run in this order so the rate limiter on /login doesn't interfere with
    # tests 3 and 4 which need a successful login.
    test_sql_injection()
    test_weak_password()
    test_invalid_token()
    test_privilege_escalation()
    test_brute_force()

    print("\nAll 5 tests passed.")
