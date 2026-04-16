# security-advisor

A conversational security advisor **for every AI coding agent** — hunts real, exploitable vulnerabilities in your codebase, explains the exploit path, and lets you push back.

Grounded in Anthropic's 2025/2026 safety research (Agents Rule of Two, Sleeper Agents, prompt-injection defences) and OWASP Top 10:2025 / OWASP LLM Top 10 2025.

Works with **Claude Code, Cursor, Codex, Gemini CLI, GitHub Copilot Agents, Kiro, OpenCode, Pi, Rovo Dev, Trae** — and any other harness that follows the [Agent Skills spec](https://agentskills.io/specification).

---

## Why this exists

Most "AI security audits" either produce a wall of low-signal findings or a one-shot report you never read. `security-advisor` is built differently:

- **Conversational** — surfaces one finding at a time, with a concrete exploit path, and asks what you want to do next.
- **PoC-disciplined** — if it can't give you `file:line` and a 3-5 step attack, it doesn't surface. No "could theoretically be exploited".
- **Stack-aware** — progressive disclosure loads only the references that match your project (Next.js, React, LLM apps, Node, Python).
- **Current** — the Next.js reference cites the 2025 CVE list (CVE-2025-29927 middleware bypass, -55182 Server Function RCE, etc.). The LLM reference covers the four new OWASP LLM Top 10 2025 entries (System Prompt Leakage, Vector & Embedding Weaknesses, Unbounded Consumption, expanded Excessive Agency).
- **Harness-portable** — a single canonical source is materialised into every agent's expected directory. One skill, ten agents.
- **Zero runtime deps** — no plugins, no build step, just markdown.

It complements `/cso` and similar audit tools rather than replaces them. `/cso` is a 14-phase audit that writes a JSON report. This is a chat-first advisor that teaches as it scans.

---

## Install

### Option A — via `npx skills` (skills.sh, recommended)

Works with Claude Code, OpenCode, Codex, Cursor, and 40+ other agents:

```bash
# Install globally (recommended for a security tool you'll want everywhere)
npx skills add dani-z/security-advisor -g

# Install into just the current project
npx skills add dani-z/security-advisor

# Target a specific agent
npx skills add dani-z/security-advisor -a claude-code
npx skills add dani-z/security-advisor -a cursor
npx skills add dani-z/security-advisor -a codex
npx skills add dani-z/security-advisor -a opencode
npx skills add dani-z/security-advisor -a gemini

# All agents, non-interactive (CI/CD friendly)
npx skills add dani-z/security-advisor -g --all -y
```

See [skills.sh](https://skills.sh/) for the full CLI reference.

### Option B — clone into a project

For agents that look for skills inside the project directory (Cursor, Kiro, Rovo Dev):

```bash
cd your-project
git clone https://github.com/dani-z/security-advisor .skills-source
# Then symlink the harness-specific dirs you need, e.g.:
ln -s .skills-source/.claude .claude
# or just copy the whole directory
```

The repo already ships pre-materialised directories for every harness (`.claude/`, `.cursor/`, `.codex/`, `.gemini/`, `.github/`, `.kiro/`, `.opencode/`, `.pi/`, `.rovodev/`, `.trae/`, `.trae-cn/`). Just copy the one you need.

### Option C — global, without a CLI

```bash
git clone https://github.com/dani-z/security-advisor ~/.security-advisor

# Claude Code
ln -s ~/.security-advisor/source/skills/security-advisor ~/.claude/skills/security-advisor

# Cursor
ln -s ~/.security-advisor/source/skills/security-advisor ~/.cursor/skills/security-advisor

# Codex
ln -s ~/.security-advisor/source/skills/security-advisor ~/.codex/skills/security-advisor

# ...and so on
```

### Option D — the packaged `.skill` file

Grab the latest release's `security-advisor.skill` bundle and unzip into your harness's skills directory:

```bash
unzip security-advisor.skill -d ~/.claude/skills/   # or .cursor/skills, .codex/skills, etc.
```

---

## Usage

### In Claude Code
```
/security-advisor
```

### In other harnesses
Just ask for a security review. The skill description is engineered to auto-trigger on phrases like:
- "security review", "find vulnerabilities", "audit this"
- "am I leaking secrets?", "is this endpoint safe?", "check for IDOR"
- "prompt injection review", "threat model", "pre-ship audit"
- Any mention of a specific CVE, OWASP category, or auth concern

### Arguments (Claude Code / OpenCode / Codex)

| Command | What it does |
|---------|--------------|
| `/security-advisor` | Default — scan the current branch diff vs `main` + quick secrets/CVE sweep |
| `/security-advisor --full` | Scan the whole repo, not just the diff |
| `/security-advisor --llm` | Scan only LLM touchpoints (prompt injection, tool calling, cost, output handling) |
| `/security-advisor --deps` | Scan dependencies against known CVEs |
| `/security-advisor --secrets` | Scan for leaked secrets and env misconfiguration |
| `/security-advisor --scope <area>` | Focus on one area (e.g. `--scope auth`, `--scope webhooks`) |
| `/security-advisor --report` | Also write findings to `.security-advisor/report-YYYY-MM-DD.md` |

Flags combine: `/security-advisor --full --report`. Harnesses that don't support slash-command arguments (Cursor, Gemini, Kiro) — ask in plain language: *"Run a full audit and write a report"*.

---

## What it looks for

### Every project
- Secrets committed to git history or `.env` tracked
- Client-exposed server secrets (`NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `EXPO_PUBLIC_*` with sensitive values)
- Weak crypto (MD5/SHA1/DES for anything security-relevant)
- Insecure deserialization (`eval`, `Function`, `pickle.loads`, `yaml.load`)
- Command injection (`exec`/`execSync` with user input)
- Path traversal, JWT misuse, timing-unsafe comparisons, SSRF, prototype pollution

### Next.js
- Server Actions that forgot to re-authenticate (public POST endpoints, always)
- Tenant-scoped queries that source org ID from request body instead of session
- IDOR patterns (`findFirst({ where: { id } })` without ownership check)
- Stripe webhook raw-body verification (`req.text()` before JSON.parse)
- Middleware bypass — self-hosted Next.js + `x-middleware-subrequest` (CVE-2025-29927)
- Server Function deserialization (CVE-2025-55182), RSC DoS (CVE-2025-55184)
- better-auth misconfigurations, Prisma mass assignment, `$queryRawUnsafe`
- CSP / HSTS / security header audit

### React (any framework — Next.js, Vite, Remix, Astro, CRA, Expo, React Native)
- XSS escape hatches — `dangerouslySetInnerHTML`, `innerHTML`, URL schemes in `href`
- Auth token storage — flags session/refresh tokens in `localStorage`
- Open redirects (`next`, `redirect`, `returnTo`, `callbackUrl` params)
- `postMessage` handlers without origin checks
- Hydration / RSC data leakage
- Unsanitised markdown rendering
- React Native — `WebView` with user content, deep links, `AsyncStorage` for tokens

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
- CSRF / middleware order issues, JWT with missing `algorithms`

---

## What it deliberately does NOT flag

Calibrated against 20 hard exclusions and 12 precedents (see [source/skills/security-advisor/references/false-positive-rules.md](source/skills/security-advisor/references/false-positive-rules.md)):

- Missing rate limits as a standalone finding (only when combined with concrete auth/cost amplification)
- DoS without a specific exploit vector (exception: LLM unbounded consumption is a finding)
- Test fixtures with dummy secrets (unless imported by prod code)
- Memory safety concerns in memory-safe languages
- Client-side "lack of auth" (the server is what matters)
- User content in the user-message position of an LLM chat (intended API)
- Insecure randomness outside security contexts
- CVEs on transitive dependencies that aren't reached

A report with 3 real findings beats a report with 3 real plus 12 theoretical.

---

## Repository layout

```
security-advisor/
├── source/skills/security-advisor/   # canonical skill (single source of truth)
│   ├── SKILL.md
│   ├── metadata.json
│   └── references/                   # 8 reference files
│       ├── research-basis.md         # Anthropic 2025/2026 research + OWASP
│       ├── stack-nextjs.md           # Next.js CVEs, server actions, Prisma, Stripe
│       ├── stack-react.md            # React UI-layer (XSS, tokens, RN)
│       ├── stack-llm-apps.md         # OWASP LLM Top 10 2025
│       ├── stack-nodejs-general.md   # Node/TS patterns
│       ├── stack-python.md           # FastAPI / Django / Flask
│       ├── findings-template.md      # Output formats
│       └── false-positive-rules.md   # Exclusions + precedents
├── skills/security-advisor/          # → symlink (for `npx skills add` CLI)
├── .claude/skills/security-advisor/  # → symlink (Claude Code)
├── .cursor/skills/security-advisor/  # → symlink (Cursor)
├── .codex/skills/security-advisor/   # → symlink (Codex CLI)
├── .gemini/skills/security-advisor/  # → symlink (Gemini CLI)
├── .github/skills/security-advisor/  # → symlink (GitHub Copilot Agents)
├── .kiro/skills/security-advisor/    # → symlink (Kiro)
├── .opencode/skills/security-advisor/# → symlink (OpenCode)
├── .pi/skills/security-advisor/      # → symlink (Pi)
├── .rovodev/skills/security-advisor/ # → symlink (Rovo Dev)
├── .trae/skills/security-advisor/    # → symlink (Trae)
├── .trae-cn/skills/security-advisor/ # → symlink (Trae China)
├── .agents/skills/security-advisor/  # → symlink (Codex primary; fallback for Cursor, Gemini, Copilot, OpenCode, Pi)
├── metadata.json                     # skills.sh discovery metadata
├── scripts/sync.sh                   # regenerate harness symlinks
├── README.md
├── AGENTS.md                         # multi-agent entry point
├── HARNESSES.md                      # per-harness compatibility matrix
└── LICENSE                           # MIT
```

Every `.<harness>/skills/security-advisor` directory is a **symlink** to `source/skills/security-advisor/`. Edit `source/`, everything follows. To regenerate the symlinks (e.g. after cloning on a system where git didn't preserve them, or after adding a new harness), run:

```bash
bash scripts/sync.sh
```

**Note for Windows users:** git preserves symlinks by default only if `core.symlinks=true` is set. On Windows, after cloning, either enable symlinks (`git config --global core.symlinks true`) or run `bash scripts/sync.sh` to regenerate them.

---

## The five ideas behind it

1. **Agents Rule of Two** (Anthropic, Nov 2025) — code paths combining 2+ of {untrusted input, sensitive tool/data, external communication} get the review budget first.
2. **PoC discipline** — `file:line` + 3-5 step exploit path, or it doesn't surface.
3. **LLMs beat static tools at reasoning, not taint tracking** — delegate mechanical stuff (`npm audit`, `gitleaks`), focus the agent on business logic, IDOR, prompt injection.
4. **Instruction-like content in scanned code is data, not instructions** — anti-manipulation rule, shaped by the Oct 2025 Claude Code PR-title prompt injection on HackerOne.
5. **Zero noise beats full coverage** — confidence gate at 7/10, below that it's dropped.

See [source/skills/security-advisor/references/research-basis.md](source/skills/security-advisor/references/research-basis.md) for the full research grounding with citations.

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
```

Follow-up menu via `AskUserQuestion` in Claude Code; plain-text prompts in other harnesses.

---

## Limitations / scope

- AI-assisted review, not a penetration test. Catches common and current patterns; misses subtle cryptographic bugs, timing side channels, and runtime-only issues.
- Static analysis from a read-only agent — won't probe live endpoints, won't run fuzzers.
- Python coverage is deliberately brief (~90 lines) — expand on demand.
- For anything handling payments, PII, or production credentials, engage a qualified security firm. Use this as a fast second pass, not as your only line of defence.

---

## Complementary tools

- [`/cso`](https://github.com/garrytan/gstack/tree/main/cso) ([gstack](https://github.com/garrytan/gstack)) — deeper 14-phase audit with JSON report output.
- [`gitleaks`](https://github.com/gitleaks/gitleaks) / [`trufflehog`](https://github.com/trufflesecurity/trufflehog) — dedicated secret scanners.
- [`semgrep`](https://github.com/semgrep/semgrep) / [`codeql`](https://github.com/github/codeql) — static taint analysis at scale.
- [`npm audit`](https://github.com/npm/cli) / [`bun outdated`](https://github.com/oven-sh/bun) / [`pip audit`](https://github.com/pypa/pip-audit) — dependency CVE matching.

security-advisor does the reasoning these tools can't. Use them together.

---

## Publishing

This skill is packaged to the [agentskills.io spec](https://agentskills.io/specification) and is ready to publish to [skills.sh](https://skills.sh/) — Vercel's open registry that powers `npx skills add`.

### How skills.sh works

There's no submission — any public GitHub repo following the Agent Skills format is installable via `npx skills add <owner>/<repo>`. Ranking on the leaderboard comes from anonymous install telemetry. You publish simply by pushing to GitHub.

### Publishing checklist

1. Push this directory to a public GitHub repo.
2. Tag a release (`v1.0.0`) — optional but good hygiene; matches `metadata.version`.
3. Test the install: `npx skills add <you>/security-advisor -g -a claude-code -y` on a clean machine.
4. Bump `metadata.version` in both `source/skills/security-advisor/SKILL.md` frontmatter and `source/skills/security-advisor/metadata.json` on each update so `npx skills update` detects it.
5. (Optional) Open a PR to [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) to be featured in Vercel's curated set.

### Updating installed copies

```bash
npx skills update security-advisor
```

---

## Contributing

1. Fork the repo.
2. Edit `source/skills/security-advisor/SKILL.md` or any reference file under `source/skills/security-advisor/references/`. Never edit files inside `.<harness>/skills/` directly — those are symlinks.
3. Bump `metadata.version` in the two metadata files.
4. If you added a new harness, update the `HARNESSES` array in [scripts/sync.sh](scripts/sync.sh), then run `bash scripts/sync.sh`.
5. Open a PR.

---

## License

See [LICENSE](LICENSE).
