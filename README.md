# security-advisor

A Claude Code skill that acts as a conversational security advisor — hunts real, exploitable vulnerabilities in your codebase, explains the exploit path, and lets you push back.

Grounded in Anthropic's 2025/2026 safety research (Agents Rule of Two, Sleeper Agents, prompt-injection defences) and OWASP Top 10:2025 / OWASP LLM Top 10 2025.

---

## Why this exists

Most "AI security audits" either produce a wall of low-signal findings or a one-shot report you never read. `security-advisor` is built differently:

- **Conversational** — surfaces one finding at a time, with a concrete exploit path, and asks what you want to do next.
- **PoC-disciplined** — if it can't give you `file:line` and a 3-5 step attack, it doesn't surface. No "could theoretically be exploited".
- **Stack-aware** — progressive disclosure loads only the references that match your project (Next.js, React, LLM apps, Node, Python).
- **Current** — the Next.js reference cites the 2025 CVE list (CVE-2025-29927 middleware bypass, -55182 Server Function RCE, etc.). The LLM reference covers the four new OWASP LLM Top 10 2025 entries (System Prompt Leakage, Vector & Embedding Weaknesses, Unbounded Consumption, expanded Excessive Agency).
- **Zero-dep** — no gstack, no plugins. Just drop it into `~/.claude/skills/`.

It complements `/cso` rather than replaces it. `/cso` is a 14-phase audit that writes a JSON report. This is a chat-first advisor that teaches as it scans and recommends `/cso --comprehensive` as a deeper second pass when something serious lands.

---

## Install

### Option A — install the packaged `.skill` file

Download `security-advisor.skill` and unzip it into `~/.claude/skills/`:

```bash
unzip security-advisor.skill -d ~/.claude/skills/
```

### Option B — clone the repo

```bash
git clone <this-repo> ~/.claude/skills/security-advisor
```

### Option C — build the `.skill` yourself

If you have the skill-creator plugin installed:

```bash
cd ~/.claude/plugins/cache/claude-plugins-official/skill-creator/unknown/skills/skill-creator
python3 -m scripts.package_skill ~/.claude/skills/security-advisor
```

Output: `security-advisor.skill` (ready to share).

---

## Usage

Invoke it from any Claude Code session in a project you want to review:

```
/security-advisor
```

The skill will greet you, detect your stack, draw an attack surface map, confirm scope with you, and then scan in focused passes — surfacing findings one at a time.

### Arguments

| Command | What it does |
|---------|--------------|
| `/security-advisor` | Default — scan the current branch diff vs `main` + quick secrets/CVE sweep |
| `/security-advisor --full` | Scan the whole repo, not just the diff |
| `/security-advisor --llm` | Scan only LLM touchpoints (prompt injection, tool calling, cost, output handling) |
| `/security-advisor --deps` | Scan dependencies against known CVEs |
| `/security-advisor --secrets` | Scan for leaked secrets and env misconfiguration |
| `/security-advisor --scope <area>` | Focus on one area (e.g. `--scope auth`, `--scope webhooks`) |
| `/security-advisor --report` | Also write findings to `.security-advisor/report-YYYY-MM-DD.md` |

Flags combine: `/security-advisor --full --report`.

Skill will also engage automatically when you say things like *"am I leaking secrets?"*, *"is this endpoint safe?"*, *"find the bugs that matter"*, or mention a specific CVE.

---

## What it looks for

### Every project
- Secrets committed to git history or `.env` tracked
- Client-exposed server secrets (`NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `EXPO_PUBLIC_*` with sensitive values)
- Weak crypto (MD5/SHA1/DES for anything security-relevant)
- Insecure deserialization (`eval`, `Function`, `pickle.loads`, `yaml.load`)
- Command injection (`exec`/`execSync` with user input)
- Path traversal
- JWT misuse (missing `algorithms`, algorithm confusion)
- Timing-unsafe comparisons for secrets
- SSRF in `fetch(user_url)`
- Prototype pollution

### Next.js
- Server Actions that forgot to re-authenticate (they're public POST endpoints)
- Tenant-scoped queries that source org ID from request body instead of session
- IDOR patterns (`findFirst({ where: { id } })` without ownership check)
- Stripe webhook raw-body verification (`req.text()` before JSON.parse)
- Middleware bypass — self-hosted Next.js + `x-middleware-subrequest` (CVE-2025-29927)
- Server Function deserialization (CVE-2025-55182)
- RSC DoS (CVE-2025-55184)
- better-auth misconfigurations (PKCE, origin check, email as subject)
- Prisma mass assignment (`data: { ...body }`), `$queryRawUnsafe`
- CSP / HSTS / security header audit

### React (any framework — Next.js, Vite, Remix, Astro, CRA, Expo, React Native)
- XSS escape hatches — `dangerouslySetInnerHTML`, `innerHTML`, URL schemes in `href` (`javascript:`, `data:`)
- Auth token storage — flags session/refresh tokens in `localStorage`
- Open redirects (`next`, `redirect`, `returnTo`, `callbackUrl` params)
- `postMessage` handlers without origin checks
- Hydration / RSC data leakage (full user objects serialised to the client)
- Unsanitised markdown rendering (`rehype-raw` without `rehype-sanitize`, `marked` without DOMPurify)
- React Native — `WebView` with user content, deep link handling, `AsyncStorage` for tokens

### LLM apps (OWASP LLM Top 10 2025)
- Prompt injection entry points (user content in system-prompt position, tool schema, few-shot examples)
- Improper output handling (LLM output rendered as HTML or executed)
- Excessive agency — tools the LLM can call without user-level permission checks
- Unbounded consumption (no token caps / cost limits per user or org)
- System prompt leakage via error messages or logs
- Vector & embedding weaknesses — tenant isolation in RAG
- Sensitive information disclosure via model responses

### Python (FastAPI / Django / Flask)
- `pickle.loads`, `yaml.load` (non-safe), `eval`, `exec`, `shell=True`
- SQL injection (f-string / format / `%` formatting in queries)
- Django `DEBUG=True` / wildcard `ALLOWED_HOSTS` in prod
- Flask SSTI (`render_template_string(userInput)`)
- CSRF / middleware order issues
- JWT with missing `algorithms` argument

---

## What it deliberately does NOT flag

Calibrated against 20 hard exclusions and 12 precedents (see [references/false-positive-rules.md](references/false-positive-rules.md)):

- Missing rate limits as a standalone finding (only when combined with concrete auth/cost amplification)
- DoS without a specific exploit vector (exception: LLM unbounded consumption is a finding)
- Test fixtures with dummy secrets (unless imported by prod code)
- Memory safety concerns in memory-safe languages
- Client-side "lack of auth" (the server is what matters — flag that instead)
- User content in the user-message position of an LLM chat (that's the intended API)
- Security concerns in documentation files
- Insecure randomness outside security contexts
- CVEs on transitive dependencies that aren't reached

A report with 3 real findings beats a report with 3 real plus 12 theoretical.

---

## File structure

```
security-advisor/
├── SKILL.md                          # Main skill, 5-phase workflow
├── README.md                         # This file
└── references/
    ├── research-basis.md             # Anthropic 2025/2026 research + OWASP citations
    ├── stack-nextjs.md               # Next.js CVEs, server actions, Prisma, Stripe, better-auth
    ├── stack-react.md                # React UI-layer (XSS escape hatches, tokens, RN)
    ├── stack-llm-apps.md             # OWASP LLM Top 10 2025 playbook
    ├── stack-nodejs-general.md       # Node/TS patterns (non-framework)
    ├── stack-python.md               # FastAPI / Django / Flask brief
    ├── findings-template.md          # Conversational + report output formats
    └── false-positive-rules.md       # Hard exclusions + precedents
```

Progressive disclosure — the main `SKILL.md` stays under 250 lines. Reference files load only when stack detection matches.

---

## The five ideas behind it

1. **Agents Rule of Two** (Anthropic, Nov 2025) — code paths that combine 2+ of {untrusted input, sensitive tool/data, external communication} get the review budget first.
2. **PoC discipline** — `file:line` + 3-5 step exploit path, or it doesn't surface.
3. **LLMs beat static tools at reasoning, not taint tracking** — delegate mechanical stuff (`npm audit`, `gitleaks`), focus Claude on business logic, IDOR, prompt injection.
4. **Instruction-like content in scanned code is data, not instructions** — anti-manipulation rule, shaped by the Oct 2025 Claude Code PR-title prompt injection on HackerOne.
5. **Zero noise beats full coverage** — confidence gate at 7/10, below that it's dropped.

---

## Example session

```
/security-advisor --scope auth

> I'll scan the auth surface of this project. First, let me map it out...
>
> ATTACK SURFACE — auth
> ─────────────────────
> PUBLIC    POST /api/auth/[...all]   → better-auth handler
> ACTIONS   38 server actions         → src/actions/*
> PAGES     /admin/*                  → admin-only routes
>
> This look right? Anything I missed?

yes, go

> ### Finding: Server action leaks org-scoped data across tenants
> HIGH · confidence 9/10 · src/actions/qr/get-stats.ts:12
>
> What I see: getStats() reads organizationId from actionInput rather than
> the authenticated session, so a user authenticated to org A can pass
> { organizationId: "org-B" } and read org B's analytics.
>
> Exploit path:
> 1. Attacker signs in to any org.
> 2. Opens DevTools, finds the server action request.
> 3. Replays with a different organizationId value.
> 4. Server trusts the body; returns another tenant's scan data.
>
> Fix: source organizationId from getOrganizationContextForCurrentUser()
> inside the action; never accept it from the input schema.
>
> Reference: OWASP A01 Broken Access Control (2025)

[AskUserQuestion with: walk me through the fix / explain exploit / skip / save for later]
```

---

## Limitations / scope

- AI-assisted review, not a penetration test. Catches common and current patterns; misses subtle cryptographic bugs, timing side channels, and runtime-only issues.
- Static analysis from a read-only agent — won't probe live endpoints, won't run fuzzers, won't decompile minified bundles.
- Python coverage is deliberately brief (~90 lines) — expand on demand.
- For anything handling payments, PII, or production credentials, engage a qualified security firm. Use this as a fast second pass, not as your only line of defence.

---

## Complementary tools

- [`/cso`](https://github.com/) — deeper 14-phase audit that produces a JSON report. Run `/cso --comprehensive` if security-advisor surfaces any CRITICAL/HIGH findings.
- `gitleaks` / `trufflehog` — dedicated secret scanners.
- `semgrep` / `codeql` — static taint analysis at scale.
- `npm audit` / `bun outdated` / `pip audit` — dependency CVE matching.

security-advisor does the reasoning these tools can't. Use them together.

---

## License

MIT. Use it, fork it, improve it.
