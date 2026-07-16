// Access token lives only in this JS variable — never localStorage or sessionStorage.
// Storing a token in Web Storage exposes it to any injected script (XSS), because
// JS on the same origin can read it freely. Memory-only means the token is gone the
// moment the tab closes, and there's no persistent surface an attacker can harvest.
// ASVS V3.4.2.
let accessToken = null;
let currentUser  = null;  // populated by fetchProfile() after a successful login


// ── Tab switching ─────────────────────────────────────────────────────────────

function switchTab(name) {
    document.getElementById('tab-login').classList.toggle('active',     name === 'login');
    document.getElementById('tab-register').classList.toggle('active',  name === 'register');
    document.getElementById('pane-login').classList.toggle('hidden',    name !== 'login');
    document.getElementById('pane-register').classList.toggle('hidden', name !== 'register');
    clearMsg();
}


// ── Auth message helpers ──────────────────────────────────────────────────────

function showMsg(text, type) {
    const el = document.getElementById('auth-msg');
    // Always use textContent here — the message may contain server-returned strings
    // and we never want those interpreted as HTML. ASVS V5.3.3.
    el.textContent = text;
    el.className = 'auth-msg show ' + type;
}

function clearMsg() {
    const el = document.getElementById('auth-msg');
    el.textContent = '';
    el.className = 'auth-msg';
}

// The API returns errors in three different shapes depending on which layer
// produced the response:
//   { "detail": "string" }         — FastAPI HTTPException (401, 403, 409…)
//   { "detail": [ { msg, … } ] }   — Pydantic validation errors (422)
//   { "error": "string" }          — slowapi rate limiter (429) and global handler (500)
// This helper normalises all three into a single human-readable string so
// callers don't need to know which format they received.
function extractMsg(data) {
    if (typeof data.detail === 'string') return data.detail;
    if (Array.isArray(data.detail))
        return data.detail.map(e => e.msg).join(' · ');
    if (typeof data.error === 'string') return data.error;
    return JSON.stringify(data);
}


// ── Register ──────────────────────────────────────────────────────────────────

async function doRegister() {
    const username = document.getElementById('reg-username').value.trim();
    const email    = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const role     = document.getElementById('reg-role').value;

    if (!username || !email || !password) {
        showMsg('Please fill in all fields.', 'err');
        return;
    }

    try {
        const res  = await fetch('/register', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ username, email, password, role }),
        });
        const data = await res.json();

        if (res.ok) {
            // Switch straight to the login tab so the user doesn't have to navigate
            // manually — pre-fill the username as a small quality-of-life touch.
            showMsg('Account created! You can now log in.', 'ok');
            switchTab('login');
            document.getElementById('login-username').value = username;
        } else {
            showMsg(extractMsg(data), 'err');
        }
    } catch {
        showMsg('Network error — is the server running?', 'err');
    }
}


// ── Login ─────────────────────────────────────────────────────────────────────

async function doLogin() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showMsg('Please enter username and password.', 'err');
        return;
    }

    try {
        const res  = await fetch('/login', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            // credentials: 'include' tells the browser to accept the Set-Cookie header
            // from /login so the HttpOnly refresh_token cookie is stored automatically.
            // Without this flag, same-origin credentialled responses are still sent
            // but the cookie is silently dropped. ASVS V3.4.2/3/5.
            credentials: 'include',
            body:    JSON.stringify({ username, password }),
        });
        const data = await res.json();

        if (res.ok) {
            accessToken = data.access_token;
            await fetchProfile();
            onLoggedIn();
        } else {
            showMsg(extractMsg(data), 'err');
        }
    } catch {
        showMsg('Network error — is the server running?', 'err');
    }
}


// ── Fetch /profile ────────────────────────────────────────────────────────────

async function fetchProfile() {
    // Called right after login to populate currentUser — the RBAC test cases
    // need the role field to decide which outcome counts as a pass.
    const res = await fetch('/profile', {
        headers: { 'Authorization': 'Bearer ' + accessToken },
    });
    if (res.ok) currentUser = await res.json();
}


// ── Post-login UI state ───────────────────────────────────────────────────────

function onLoggedIn() {
    if (!currentUser) return;

    // Populate the sticky header badge. textContent is used throughout — if a
    // username contained HTML tags it would be rendered as literal text, not markup.
    document.getElementById('badge-username').textContent = currentUser.username;
    const roleEl = document.getElementById('badge-role');
    roleEl.textContent = currentUser.role;
    roleEl.className = 'role-chip chip-' + currentUser.role;
    document.getElementById('user-badge').classList.add('show');

    document.getElementById('auth-footer').classList.add('show');

    // Remove the lock overlay to reveal the test suite.
    document.getElementById('lock-overlay').classList.add('unlocked');
    document.getElementById('lock-tag').textContent =
        '✓ Logged in as ' + currentUser.username + ' (' + currentUser.role + ')';

    showMsg('Welcome, ' + currentUser.username + '! Scroll down to run the test suite.', 'ok');
}


// ── Logout ────────────────────────────────────────────────────────────────────

async function doLogout() {
    try {
        // credentials: 'include' sends the HttpOnly cookie so the server can
        // blacklist the refresh token's jti immediately. Deleting the cookie on the
        // client alone is not enough — an attacker who copied the raw token string
        // before logout could still use it without the server-side blacklist. ASVS V3.3.1.
        await fetch('/logout', { method: 'POST', credentials: 'include' });
    } catch {
        // Network failure on logout is non-fatal — clear the local state regardless
        // so the UI doesn't get stuck in a logged-in appearance.
    }

    accessToken = null;
    currentUser  = null;

    document.getElementById('user-badge').classList.remove('show');
    document.getElementById('auth-footer').classList.remove('show');
    document.getElementById('lock-overlay').classList.remove('unlocked');
    document.getElementById('lock-tag').textContent = '🔒 Login to unlock';

    // Reset all test card borders, status badges and result outputs so the next
    // session starts with a clean slate rather than showing stale results.
    document.querySelectorAll('.tc').forEach(c => { c.style.borderColor = ''; });
    document.querySelectorAll('.tc-status').forEach(el => {
        el.className = 'tc-status';
        el.textContent = '';
    });
    document.querySelectorAll('.tc-result').forEach(el => {
        el.textContent = '';
        el.classList.remove('show');
    });

    showMsg('Logged out.', 'ok');
}


// ── Test case definitions ─────────────────────────────────────────────────────
//
// Each object describes one test card. Fields:
//   id              — card number displayed as T1…T8
//   name            — short display title
//   type            — 'positive' | 'rbac' | 'negative' | 'abuse' (drives the colour badge)
//   endpoint        — HTTP method + path under test
//   desc            — explanation of what the test proves
//   expectedOutcome — expected HTTP response in plain English
//   asvs            — OWASP ASVS clause this validates
//   passLabel       — badge text on success (static; RBAC tests override via run())
//   failLabel       — badge text when the security control did NOT behave as expected
//   run()           — async function; returns { status, body, pass, label? }
//                     RBAC tests return a dynamic label ('✓ Access Granted' or
//                     '✓ Access Denied') because both outcomes count as a pass.

const TESTS = [
    {
        id: 1, name: 'View Profile', type: 'positive',
        endpoint: 'GET /profile',
        desc: 'Sends the access token as a Bearer header. The server decodes and verifies the JWT, then returns the authenticated user\'s own data. Confirms the active session is valid.',
        expectedOutcome: '200 OK — user object (id, username, email, role)',
        asvs: 'V3.2.1 — access tokens carry expiry claim',
        passLabel: '✓ Pass', failLabel: '✗ Unexpected Response',
        async run() {
            const res  = await fetch('/profile', {
                headers: { 'Authorization': 'Bearer ' + accessToken },
            });
            const body = await res.json();
            return { status: res.status, body, pass: res.status === 200 };
        },
    },

    {
        id: 2, name: 'Token Refresh', type: 'positive',
        endpoint: 'POST /token/refresh',
        desc: 'The browser sends the HttpOnly refresh token cookie automatically — JS never reads the cookie value. A new short-lived access token is issued and replaces the old one in memory.',
        expectedOutcome: '200 OK — new access_token issued; in-memory token rotated',
        asvs: 'V3.3.3 — refresh tokens are single-use (rotation)',
        passLabel: '✓ Pass', failLabel: '✗ Unexpected Response',
        async run() {
            const res  = await fetch('/token/refresh', {
                method:      'POST',
                // The browser attaches the HttpOnly refresh_token cookie automatically
                // when credentials is set to 'include'. JS cannot read the cookie value
                // directly — it is opaque to the application layer. ASVS V3.4.2.
                credentials: 'include',
            });
            const body = await res.json();
            // Rotate the in-memory access token so subsequent test calls use the
            // freshly issued token rather than the previous one.
            if (res.ok && body.access_token) accessToken = body.access_token;
            return { status: res.status, body, pass: res.status === 200 };
        },
    },

    {
        id: 3, name: 'Admin Dashboard (RBAC)', type: 'rbac',
        endpoint: 'GET /admin/dashboard',
        desc: 'Access is restricted to the admin role only. Non-admin users receive 403 Forbidden regardless of whether they supply a valid token — the server enforces deny-by-default at the route level.',
        expectedOutcome: '200 Access Granted (admin) · 403 Forbidden (customer / support)',
        asvs: 'V4.1.1 — access control enforced on every request, deny by default',
        failLabel: '✗ Access Control Failed',
        async run() {
            const res  = await fetch('/admin/dashboard', {
                headers: { 'Authorization': 'Bearer ' + accessToken },
            });
            const body = await res.json();
            const role = currentUser?.role;
            // Both outcomes are correct — admin getting in (200) and non-admin being
            // blocked (403) both prove that the access control is working as intended.
            const pass = (role === 'admin' && res.status === 200) ||
                         (role !== 'admin' && res.status === 403);
            const label = res.status === 200 ? '✓ Access Granted' : '✓ Access Denied';
            return { status: res.status, body, pass, label };
        },
    },

    {
        id: 4, name: 'Support Users (RBAC)', type: 'rbac',
        endpoint: 'GET /support/users',
        desc: 'Admin and support roles may access this endpoint; customers are blocked. Tests that a multi-role allow-list is enforced server-side and cannot be bypassed by the client.',
        expectedOutcome: '200 Access Granted (admin / support) · 403 Forbidden (customer)',
        asvs: 'V4.1.1 — access control enforced on every request, deny by default',
        failLabel: '✗ Access Control Failed',
        async run() {
            const res  = await fetch('/support/users', {
                headers: { 'Authorization': 'Bearer ' + accessToken },
            });
            const body = await res.json();
            const role = currentUser?.role;
            const pass = (['admin', 'support'].includes(role) && res.status === 200) ||
                         (role === 'customer' && res.status === 403);
            const label = res.status === 200 ? '✓ Access Granted' : '✓ Access Denied';
            return { status: res.status, body, pass, label };
        },
    },

    {
        id: 5, name: 'Audit Log (RBAC)', type: 'rbac',
        endpoint: 'GET /admin/audit-log',
        desc: 'Security event logs must be visible to administrators only. Exposing them to lower-privileged roles would violate least-privilege and help an attacker understand the system\'s defences.',
        expectedOutcome: '200 Access Granted (admin) · 403 Forbidden (customer / support)',
        asvs: 'V7.1.1 — security events are logged; V4.1.3 — least privilege enforced',
        failLabel: '✗ Access Control Failed',
        async run() {
            const res  = await fetch('/admin/audit-log', {
                headers: { 'Authorization': 'Bearer ' + accessToken },
            });
            const body = await res.json();
            const role = currentUser?.role;
            const pass = (role === 'admin' && res.status === 200) ||
                         (role !== 'admin' && res.status === 403);
            const label = res.status === 200 ? '✓ Access Granted' : '✓ Access Denied';
            return { status: res.status, body, pass, label };
        },
    },

    {
        id: 6, name: 'Forged Token', type: 'negative',
        endpoint: 'GET /profile',
        desc: 'A manually crafted JWT with a fake HMAC-SHA256 signature is submitted as the Bearer token. Even a single altered character invalidates the signature — the server must reject the request without revealing internal details.',
        expectedOutcome: '401 Unauthorised — JWT signature verification fails',
        asvs: 'V3.2.1 — tokens verified for signature and expiry on every request',
        passLabel: '✓ Token Rejected', failLabel: '✗ Forged Token Accepted',
        async run() {
            // A structurally valid JWT (header.payload) but with a fabricated
            // signature — the server's HMAC verification will fail immediately.
            const fakeToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.FORGEDSIGNATUREXYZ123';
            const res  = await fetch('/profile', {
                headers: { 'Authorization': 'Bearer ' + fakeToken },
            });
            const body = await res.json();
            return { status: res.status, body, pass: res.status === 401 };
        },
    },

    {
        id: 7, name: 'SQL Injection', type: 'abuse',
        endpoint: 'POST /register',
        desc: "Sends the classic SQL injection payload ' OR '1'='1 as the username. Pydantic's regex validator [a-zA-Z0-9_]{3,30} rejects SQL metacharacters at the schema layer — the database query is never constructed.",
        expectedOutcome: '422 Unprocessable Entity — payload blocked at schema layer',
        asvs: 'V5.1.3 — input validation rejects metacharacters at the boundary',
        passLabel: '✓ Attack Blocked', failLabel: '✗ Injection Not Blocked',
        async run() {
            const res  = await fetch('/register', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({
                    username: "' OR '1'='1",
                    email:    'inject@evil.com',
                    password: 'Test1234!',
                }),
            });
            const body = await res.json();
            return { status: res.status, body, pass: res.status === 422 };
        },
    },

    {
        id: 8, name: 'Brute Force Attack', type: 'abuse',
        endpoint: 'POST /login',
        desc: 'Fires 6 rapid login attempts with wrong credentials. The slowapi rate limiter (5 requests / minute / IP) must block at least one attempt with 429 Too Many Requests to mitigate credential stuffing. A 429 on attempt 1 from a prior run still counts as a pass.',
        expectedOutcome: '429 Too Many Requests — rate limiter intervenes',
        asvs: 'V2.1 — brute-force and credential stuffing mitigated by rate limiting',
        passLabel: '✓ Rate Limited', failLabel: '✗ Rate Limiter Not Triggered',
        async run() {
            const log = [];
            let got429 = false;
            for (let i = 1; i <= 6; i++) {
                const res = await fetch('/login', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ username: 'bftest_attacker', password: 'wrong' + i }),
                });
                log.push({ attempt: i, status: res.status });
                // Stop as soon as the rate limiter fires — no point hammering
                // further once we've confirmed it's active.
                if (res.status === 429) { got429 = true; break; }
            }
            const last = log[log.length - 1];
            return { status: last.status, body: { attempts: log }, pass: got429 };
        },
    },
];


// ── Render test cards ─────────────────────────────────────────────────────────

// Helper that creates a two-row field block: a small uppercase key label on top
// and the value below. Used for Endpoint, Expected Outcome, and ASVS Alignment.
function makeField(keyText, valText, valClass) {
    const wrap = document.createElement('div');
    wrap.className = 'tc-field';

    const key = document.createElement('span');
    key.className = 'tc-field-key';
    key.textContent = keyText;

    const val = document.createElement('span');
    val.className = 'tc-field-val' + (valClass ? ' ' + valClass : '');
    // textContent only — valText comes from our own TESTS array so it's trusted,
    // but keeping this consistent with the rest of the codebase is good practice.
    val.textContent = valText;

    wrap.append(key, val);
    return wrap;
}

function renderTests() {
    const grid = document.getElementById('test-grid');

    TESTS.forEach(t => {
        const card = document.createElement('div');
        card.className = 'tc';
        card.id = 'tc-' + t.id;

        const hdr = document.createElement('div');
        hdr.className = 'tc-header';

        const numEl = document.createElement('span');
        numEl.className = 'tc-num';
        numEl.textContent = 'T' + t.id;

        const nameEl = document.createElement('span');
        nameEl.className = 'tc-name';
        nameEl.textContent = t.name;

        const nameWrap = document.createElement('div');
        nameWrap.style.cssText = 'display:flex;align-items:center;gap:6px;flex:1;min-width:0';
        nameWrap.append(numEl, nameEl);

        const badgeEl = document.createElement('span');
        badgeEl.className = 'type-badge type-' + t.type;
        badgeEl.textContent = t.type;

        hdr.append(nameWrap, badgeEl);

        const descEl = document.createElement('p');
        descEl.className = 'tc-desc';
        descEl.textContent = t.desc;

        const actions = document.createElement('div');
        actions.className = 'tc-actions';

        const runBtn = document.createElement('button');
        runBtn.className = 'btn-run';
        runBtn.id = 'run-' + t.id;
        runBtn.textContent = 'Run';
        runBtn.onclick = () => runTest(t);

        const statusEl = document.createElement('span');
        statusEl.className = 'tc-status';
        statusEl.id = 'status-' + t.id;

        actions.append(runBtn, statusEl);

        const resultEl = document.createElement('pre');
        resultEl.className = 'tc-result';
        resultEl.id = 'result-' + t.id;

        card.append(
            hdr,
            makeField('Tested Endpoint',  t.endpoint,        'endpoint'),
            descEl,
            makeField('Expected Outcome', t.expectedOutcome, 'outcome'),
            makeField('ASVS Alignment',   t.asvs,            'asvs'),
            actions,
            resultEl
        );
        grid.appendChild(card);
    });
}


// ── Run a single test ─────────────────────────────────────────────────────────

async function runTest(t) {
    const runBtn = document.getElementById('run-'    + t.id);
    const statEl = document.getElementById('status-' + t.id);
    const resEl  = document.getElementById('result-' + t.id);
    const card   = document.getElementById('tc-'     + t.id);

    runBtn.disabled    = true;
    statEl.textContent = 'Running…';
    statEl.className   = 'tc-status running';
    resEl.textContent  = '';
    resEl.classList.remove('show');
    card.style.borderColor = '';

    try {
        const { status, body, pass, label } = await t.run();

        // Server-returned JSON may contain user-supplied data (e.g. the username
        // echoed back), so render it with textContent not innerHTML. ASVS V5.3.3.
        resEl.textContent = 'HTTP ' + status + '\n' + JSON.stringify(body, null, 2);
        resEl.classList.add('show');

        // RBAC tests return a dynamic label from run() ('✓ Access Granted' /
        // '✓ Access Denied') because both are valid pass outcomes. All other tests
        // fall back to the static passLabel / failLabel on the test definition.
        const displayLabel = pass
            ? (label || t.passLabel || '✓ Pass')
            : (t.failLabel || '✗ Fail');

        statEl.textContent = displayLabel;
        statEl.className   = 'tc-status ' + (pass ? 'pass' : 'fail');
        card.style.borderColor = pass ? 'var(--success)' : 'var(--danger)';
    } catch (err) {
        resEl.textContent = 'Error: ' + err.message;
        resEl.classList.add('show');
        statEl.textContent = '✗ Error';
        statEl.className   = 'tc-status fail';
    } finally {
        runBtn.disabled = false;
    }
}


// ── Init ──────────────────────────────────────────────────────────────────────

// Build all 8 test cards as soon as the script loads. The script tag sits at the
// bottom of <body>, so the DOM is guaranteed to be ready at this point.
renderTests();
