# AGENTS.md

This repository packages the **security-advisor** skill for multiple AI coding agents. It follows the [Agent Skills specification](https://agentskills.io/specification) so the same skill works with Claude Code, Cursor, Codex, Gemini CLI, Copilot Agents, Kiro, OpenCode, Pi, Rovo Dev, Trae, and any other harness that reads Agent Skills.

## What this skill does

A conversational security advisor that hunts real, exploitable vulnerabilities in a codebase. Surfaces findings one at a time with concrete file:line exploit paths. Grounded in Anthropic's 2025/2026 safety research and OWASP Top 10:2025 / OWASP LLM Top 10 2025.

See [source/skills/security-advisor/SKILL.md](source/skills/security-advisor/SKILL.md) for the canonical skill.

## Repository layout

```
security-advisor/
├── source/skills/security-advisor/   # canonical skill (single source of truth)
├── skills/security-advisor/          # → symlink (for `npx skills add`)
├── .claude/skills/security-advisor/  # → symlink (Claude Code)
├── .cursor/skills/security-advisor/  # → symlink (Cursor)
├── .codex/skills/security-advisor/   # → symlink (Codex CLI)
├── .gemini/skills/security-advisor/  # → symlink (Gemini CLI)
├── .github/skills/security-advisor/  # → symlink (GitHub Copilot Agents)
├── .kiro/skills/security-advisor/    # → symlink (Kiro)
├── .opencode/skills/security-advisor/# → symlink (OpenCode)
├── .pi/skills/security-advisor/      # → symlink (Pi)
├── .rovodev/skills/security-advisor/ # → symlink (Rovo Dev)
├── .trae/skills/security-advisor/    # → symlink (Trae International)
├── .trae-cn/skills/security-advisor/ # → symlink (Trae China)
├── .agents/skills/security-advisor/  # → symlink (Codex primary; fallback for many)
├── metadata.json                     # skills.sh discovery metadata
├── scripts/sync.sh                   # regenerate harness symlinks from source/
├── README.md
├── AGENTS.md                         # this file
├── HARNESSES.md                      # harness compatibility matrix
└── LICENSE                           # Apache 2.0
```

Every `.<harness>/skills/security-advisor` directory is a symlink to `source/skills/security-advisor/`. Edit `source/`, everything else follows automatically.

## For agents reading this file

If you are an AI agent reading this file because a user is asking you to use this skill:

1. Your harness may already have loaded `SKILL.md` from your `.<harness>/skills/security-advisor/` directory. Follow its instructions.
2. If not, read [source/skills/security-advisor/SKILL.md](source/skills/security-advisor/SKILL.md) — that's the canonical skill.
3. The skill is invoked conversationally. Triggers include: "security review", "find vulnerabilities", "am I leaking secrets?", "is this endpoint safe?", or any mention of a CVE, OWASP category, auth concern, webhook signature, Prisma injection, or LLM prompt injection.
4. Progressive disclosure — the main SKILL.md is short. Reference files in `references/` load only when stack detection matches (e.g. `stack-nextjs.md` for Next.js apps, `stack-react.md` for any React project, `stack-llm-apps.md` for LLM apps).

## For humans reading this file

See [README.md](README.md) for installation and usage. Short version:

```bash
# Works with any harness listed above
npx skills add dani-z/security-advisor -g
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
