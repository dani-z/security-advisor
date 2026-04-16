# Python — brief playbook

Read this for Python projects (FastAPI, Django, Flask, or standalone). This reference is deliberately terse — expand it on demand if the user runs the skill on a Python-heavy codebase and you find gaps.

---

## Deserialization / code execution

**Always CRITICAL:**
- `pickle.loads(untrusted)` — RCE by design. Never safe with untrusted input.
- `yaml.load(untrusted)` without `Loader=yaml.SafeLoader` — RCE. Use `yaml.safe_load`.
- `eval(untrusted)`, `exec(untrusted)`, `compile(untrusted)` — obvious.
- `subprocess.run(cmd, shell=True)` with user input — shell injection.
- `os.system(cmd)` with user input — shell injection.

**Safe:**
- `subprocess.run(['binary', arg1, arg2])` — args as list, no shell.
- `json.loads` — safe.
- `yaml.safe_load` — safe.

---

## SQL injection

- Any f-string / `%` format / `.format()` building SQL with user input = CRITICAL.
- Safe: parameterised queries (`cursor.execute("... WHERE id = %s", (user_id,))`) or ORM queries.
- Django ORM: `objects.raw("... WHERE id = " + id)` is bad. `objects.raw("... WHERE id = %s", [id])` is safe.
- SQLAlchemy `text("... WHERE id = " + id)` is bad. Parameterised `text("... WHERE id = :id")` is safe.

---

## Web frameworks

### FastAPI
- Dependency injection auth: verify every protected route has an auth `Depends(...)` parameter. A route without = public.
- Pydantic models handle input validation well — but check that routes actually use them, not raw `dict` bodies.
- CORS middleware — audit allowed origins / methods / credentials.

### Django
- `CSRF_COOKIE_HTTPONLY = True`, `SECURE_SSL_REDIRECT = True`, `SESSION_COOKIE_SECURE = True` in production settings.
- `ALLOWED_HOSTS` not wildcard in production.
- `DEBUG = False` in production (debug mode leaks stack traces + settings).
- Middleware order — `SecurityMiddleware` early, `CsrfViewMiddleware` before any view middleware that auths.
- `mark_safe` / `|safe` template filter with user content = XSS.
- Raw SQL paths (see SQL injection above).

### Flask
- No CSRF by default — verify `flask-wtf` CSRFProtect is registered, or JWT auth with SameSite cookies.
- `render_template_string(userInput)` — SSTI (server-side template injection) = CRITICAL RCE.
- `send_from_directory(dir, user_filename)` — path traversal risk; Flask's built-in safeguards help but verify.

---

## SSRF

Same principle as Node:
- `requests.get(url)` / `httpx.get(url)` with user-controlled URL.
- Allowlist hosts + protocols; reject private IP ranges.
- AWS IMDS (169.254.169.254) is the classic SSRF-to-RCE pivot on EC2.

---

## Weak crypto

- `hashlib.md5`, `hashlib.sha1` for anything security-relevant (passwords, signatures, tokens) = CRITICAL.
- Passwords: `passlib` with bcrypt/argon2/scrypt; `werkzeug.security.generate_password_hash` (Flask) is OK.
- JWT: `pyjwt` — verify `algorithms=[...]` is explicit on `decode()`. Missing = CRITICAL.

---

## Common checks in order

1. Framework detection (FastAPI vs Django vs Flask vs other).
2. Grep for `pickle.loads`, `yaml.load` (not `safe_load`), `eval`, `exec`, `shell=True` — each is a finding.
3. Grep for f-string SQL / `.format(` near `execute(` / `raw(` — SQL injection.
4. Framework-specific debug/production config (Django DEBUG, Flask ENV).
5. Dependency audit: `pip audit` / `safety check` / `poetry export` + feed to audit.
6. JWT misuse.
7. Check `.env`, `settings.py`, secrets.

---

## If this file isn't enough

If you find yourself hitting patterns this file doesn't cover (async web frameworks like Starlette, Tornado; data frameworks like FastAPI+SQLAlchemy+Celery combos; ML serving), tell the user: "Python coverage in this skill is brief — I'll apply general OWASP principles and flag anything that looks off, but a Python-specific security linter like `bandit` would complement this review well."
