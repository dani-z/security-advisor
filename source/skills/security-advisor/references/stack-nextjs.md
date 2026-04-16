# Next.js — the 2025/2026 security playbook

Read this when the target project has `next` in `package.json`. Covers Next.js App Router specifically (Pages Router is legacy; still flag issues there but the 2025 CVE list changes).

---

## 1. Current CVEs to check (Pass C)

Start by reading `package.json` + the lockfile. Find the installed Next.js version. Match it against this table. If installed version is below the fixed version, it is a finding.

| CVE | CVSS | Fixed in | Exploit class | Check |
|-----|------|----------|---------------|-------|
| **CVE-2025-29927** | 9.1 | 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 | Middleware bypass via `x-middleware-subrequest` header — fully skips middleware.ts (auth, rewrites, headers) | Check installed version; if self-hosted (not Vercel), also verify proxy strips header |
| **CVE-2025-55182** | High | current | React + Next.js Server Functions insecure deserialization → unauth RCE on App Router | Check version + search for Server Function endpoints |
| **CVE-2025-55184** | Medium | current | DoS via malformed RSC payload | Version check |
| **CVE-2025-55183** | Medium | current | Source-code exposure | Version check |
| **CVE-2025-66478** | Medium | current | Dec 11 2025 patch | Version check |

Sources: [Next.js security bulletins](https://nextjs.org/blog), [NVD CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927), [Akamai on CVE-2025-55182](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce).

**CVE-2025-29927 special note:** If the target is self-hosted Next.js (not on Vercel / Netlify / Cloudflare Workers), the proxy/load balancer MUST strip the `x-middleware-subrequest` header on all inbound requests. Presence of middleware.ts + self-hosted + no strip rule = CRITICAL. On Vercel-hosted apps, the platform strips it; note as INFORMATIONAL only.

---

## 2. Server actions — the #1 source of real auth bugs in 2024-2025

**The core problem:** Server actions are **public POST endpoints**. Anything exported with `"use server"` can be invoked by anyone who knows the action's ID — no form submission, no session, no page render required. The wrapping page's `redirect()` or middleware does *not* protect the action.

**What you must verify:**

Every exported server action function re-authenticates inside itself. Either:
- Uses `next-safe-action` with an authed client wrapper (e.g. `authActionClient.schema(...).action(...)`), OR
- Manually calls `auth()` / `getSession()` inside the handler before any database work.

**Grep patterns:**

```
// find all exported server actions
grep -rn "^\"use server\"" --include="*.ts" --include="*.tsx" src/
// for each file, check for auth
grep -n "authActionClient\|orgActionClient\|adminActionClient\|auth()\|getSession" <file>
```

**Findings you're hunting for:**
- A server action using the raw `createSafeActionClient()` / bare action — no auth middleware. **HIGH**.
- A server action file where some actions use `authActionClient` and others use a bare client. **HIGH** for the bare ones.
- A server action that reads `userId` / `organizationId` from `parsedInput` (i.e. the request body) instead of `ctx.user.id` / session. **CRITICAL** — IDOR across tenants.
- An action that returns full user/org objects (with sensitive fields) to the client. **MEDIUM** — info disclosure.

**Exploit example (template):**

```
1. Attacker signs up a normal account with email attacker@x.com.
2. Attacker opens Network tab on their own dashboard, finds the POST
   endpoint for "delete QR code" — notes the action ID in the request.
3. Attacker crafts a POST to that endpoint with id: "<victim's QR code id>".
4. If the action reads the id from parsedInput and only scopes by that id
   (not by session.org.id), the victim's QR is deleted.
```

**Reference:** Next.js own data-security docs — https://nextjs.org/docs/app/guides/data-security

---

## 3. Prisma patterns

### Raw SQL
- `$queryRaw` with tagged template literal: **safe**, params are escaped.
- `$executeRaw` with tagged template literal: **safe**.
- `$queryRawUnsafe(string)`, `$executeRawUnsafe(string)` with user input concatenated: **CRITICAL SQL injection**. No exceptions.

Grep:
```
grep -rn "queryRawUnsafe\|executeRawUnsafe" --include="*.ts" src/
```

### Mass assignment
Any `prisma.<model>.create({ data: body })` or `.update({ data: { ...body } })` where `body` is a request body is a **HIGH** finding. The client can set `role`, `isAdmin`, `organizationId`, `stripeCustomerId`, anything the schema allows. Schemas must whitelist fields explicitly (Zod `.pick()` before passing to Prisma).

Grep:
```
grep -rn "data: \({\s*\.\.\.\|body\)" --include="*.ts" src/
```

### Tenant scoping
Every multi-tenant query (`where: { userId }`, `where: { organizationId }`, `where: { teamId }`) must source the scoping value from the authenticated session, never from request input. Verify by reading the callers.

### Good patterns to confirm, not flag
- `const user = await requireUser(); prisma.x.findFirst({ where: { userId: user.id, id } })` — good.
- `prisma.x.findFirst({ where: { id, user: { id: session.user.id } } })` — also good.

---

## 4. Stripe webhooks

In Next.js App Router, the raw-body handling is easy to get wrong. Check the webhook handler for:

1. **Raw body** — `await req.text()` before any JSON parse. Using `await req.json()` breaks the HMAC.
2. **Signature verification** — `stripe.webhooks.constructEvent(rawBody, signature, secret)`. No manual HMAC. No skipping.
3. **Secret source** — `process.env.STRIPE_WEBHOOK_SECRET`, not hardcoded, not test value in prod.
4. **Test vs live secret mismatch** — if the project has both `STRIPE_WEBHOOK_SECRET` and `STRIPE_WEBHOOK_SECRET_LIVE`, confirm the production config points at the live one.
5. **Idempotency** — `event.id` stored somewhere (database, Redis, idempotency key) and checked before processing. Stripe retries on non-2xx, so duplicate delivery is common.
6. **Response timing** — handler returns 2xx within seconds; long work deferred to a queue. Otherwise Stripe times out and retries, causing duplicates.

**Finding patterns:**
- No `constructEvent` call in the handler. **CRITICAL** — anyone can POST any event.
- `constructEvent` wrapped in try/catch that swallows the error and proceeds. **CRITICAL** — same as missing it.
- JSON parse before raw body read. **HIGH** — verification will always fail, so the dev probably disabled it.

Reference: https://docs.stripe.com/webhooks

---

## 5. better-auth — common misconfigurations

If the project uses `better-auth`:

- **CSRF / origin checks** — never disabled. The default origin check is load-bearing. Grep for `originCheck: false` or `csrfProtection: false` — any match is HIGH.
- **OAuth providers** — must use PKCE. Check the provider config.
- **Email as subject identifier** — never trust email as a stable ID across OAuth providers (same email, different providers, different humans). Verify the user identity is keyed on the provider + provider-assigned subject ID.
- **Session cookie** — default SameSite=Lax is fine. If the code sets SameSite=None without a strong reason, flag as MEDIUM.
- **Password hashing** — better-auth default is scrypt. If custom hasher is configured, verify it's bcrypt/argon2/scrypt at reasonable parameters. MD5/SHA1/PBKDF2 with low iterations = CRITICAL.

Reference: https://better-auth.com/docs/reference/security

---

## 6. Middleware (middleware.ts)

- **CVE-2025-29927** — covered above.
- **Middleware as security boundary** — flag if middleware is the *only* check (no inner route/action check). Server actions bypass middleware in some configurations; defence in depth required.
- **Regex matchers** — `matcher: ['/admin/:path*']` can be bypassed with path-encoding tricks in some Next.js versions. Add a secondary check inside the route.

---

## 7. Security headers

Check `next.config.ts` / `next.config.js` for a `headers()` function.

Minimum expected on a web app:

- `Content-Security-Policy` — at least a basic default-src 'self'. Missing = MEDIUM.
- `Strict-Transport-Security` — `max-age=63072000; includeSubDomains; preload`. Missing = MEDIUM.
- `X-Content-Type-Options: nosniff` — MEDIUM if absent.
- `X-Frame-Options: DENY` or `SAMEORIGIN` (or CSP `frame-ancestors`). Missing = MEDIUM (unless the app intentionally embeds).
- `Referrer-Policy: strict-origin-when-cross-origin` — LOW/INFORMATIONAL if absent.
- `Permissions-Policy` — INFORMATIONAL; flag only if the app handles payments or camera/mic.

**Calibration:** A single missing header is MEDIUM max. An entire absent `headers()` function on a customer-facing production app is HIGH (aggregate of all of the above).

---

## 8. API route handlers (app/api/**/route.ts)

For each route handler:

- **Authentication** — does it call the session resolver? Route handlers do NOT auto-inherit page-level auth. Public routes should be explicitly intentional.
- **Method guards** — if only POST is expected, does the handler reject GET/PUT/DELETE? Otherwise it may leak state-change semantics.
- **Input validation** — body parsed through Zod / yup / similar? Raw `await req.json()` passed into business logic unvalidated = HIGH.
- **Return values** — are errors sanitised? Error messages that include stack traces or DB errors in production = MEDIUM info disclosure.

---

## 9. Dynamic route params + user input

- `[slug]`, `[id]`, `[...path]` — any route handler using these must validate the param. Empty string, very long string, non-ASCII, path-traversal (`..`), newline injection.
- File serving from a dynamic route with user-supplied path is a classic LFI — grep for `readFile(path.join(...params))` patterns.

---

## 10. ISR / cache keys

- `unstable_cache` / `cacheTag` with user-supplied data in the key can lead to cache poisoning. Verify the cache key components are all server-derived (session user ID, admin-set tenant ID) not client-supplied.

---

## 11. Quick wins checklist (run these in order on any Next.js project)

1. Read `package.json` + lockfile → compare Next.js version against CVE table above.
2. Read `middleware.ts` (if exists) → is it the only auth layer? Self-hosted + CVE-29927 at proxy?
3. `ls src/actions/**/*.ts` → read each → does every exported action use an authed client wrapper?
4. Grep for `queryRawUnsafe`, `executeRawUnsafe` → zero matches expected.
5. Grep for `data: { ...` in Prisma calls → verify no mass assignment from request bodies.
6. Find the Stripe webhook handler → verify raw body + `constructEvent` + idempotency.
7. Read `next.config.ts` → check for security headers function.
8. Grep for `"use server"` files in route handlers (legacy) or bare `createSafeActionClient()` (no auth wrapper).
9. Check `.env.example` → does it have real-looking values? Check `git log -p -- .env.example`.
10. Grep `NEXT_PUBLIC_` → does any entry look like a server secret?

These ten checks hit 80% of the real Next.js security bugs shipped in 2024-2025.
