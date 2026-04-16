# Harness compatibility

This skill conforms to the [Agent Skills specification](https://agentskills.io/specification) and has been tested against (or materialised for) the following harnesses.

Last verified: 2026-04-16

## Official docs

| Harness | Docs |
|---------|------|
| Claude Code | https://code.claude.com/docs/en/skills |
| Cursor | https://cursor.com/docs/context/skills |
| Gemini CLI | https://geminicli.com/docs/cli/skills/ |
| Codex CLI | https://developers.openai.com/codex/skills |
| GitHub Copilot (Agents) | https://code.visualstudio.com/docs/copilot/customization/agent-skills |
| Kiro | https://kiro.dev/docs/skills/ |
| OpenCode | https://opencode.ai/docs/skills/ |
| Pi | https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/skills.md |
| Rovo Dev | https://support.atlassian.com/rovo/docs/extend-rovo-dev-cli-with-agent-skills |
| Trae | (no official skills docs yet) |

## Where each harness looks for skills

| Harness | Native directory | Also reads |
|---------|------------------|------------|
| Claude Code | `.claude/skills/` | — |
| Cursor | `.cursor/skills/` | `.agents/skills/`, `.claude/skills/`, `.codex/skills/` |
| Gemini CLI | `.gemini/skills/` | `.agents/skills/` |
| Codex CLI | `.agents/skills/` | — |
| GitHub Copilot | `.github/skills/` | `.agents/skills/`, `.claude/skills/` |
| Kiro | `.kiro/skills/` | — |
| OpenCode | `.opencode/skills/` | `.agents/skills/`, `.claude/skills/` |
| Pi | `.pi/skills/` | `.agents/skills/` |
| Trae | `.trae/skills/` / `.trae-cn/skills/` | TBD |
| Rovo Dev | `.rovodev/skills/` | `~/.rovodev/skills/` |

This repo materialises a symlinked directory for each of the above, all pointing at the canonical skill in `source/skills/security-advisor/`.

## Frontmatter fields this skill uses

From the Agent Skills spec, this skill uses:

| Field | Value | Supported by |
|-------|-------|--------------|
| `name`* | `security-advisor` | All harnesses |
| `description`* | Pushy trigger sentence + research grounding | All harnesses |
| `license`* | `Apache-2.0` | Claude Code, Cursor, Copilot, Kiro, OpenCode, Pi, Rovo Dev |
| `metadata`* | `author`, `version` | Claude Code, Cursor, Copilot, Kiro, OpenCode, Pi, Rovo Dev |
| `allowed-tools`* | `Bash`, `Read`, `Grep`, `Glob`, `WebSearch`, `AskUserQuestion`, `Agent` | Claude Code, OpenCode, Pi, Rovo Dev |

Fields marked `*` are spec-standard. Unknown fields are silently ignored by harnesses that don't recognise them, so the skill degrades gracefully — Gemini CLI, for instance, validates only `name` and `description` and ignores the rest.

## What the skill needs at runtime

- **Read** — to inspect source code.
- **Grep** / **Glob** — to locate vulnerability patterns.
- **Bash** — to run `git log -S`, `bun outdated`, `npm audit`, `pip audit`, etc.
- **WebSearch** (optional) — to look up fresh CVEs when the internal reference is stale.
- **AskUserQuestion** (optional, Claude Code only) — for the conversational follow-up menu. Harnesses without `AskUserQuestion` fall back to plain-text offers (`"Reply with A / B / C / D..."`), which the skill handles transparently.
- **Agent / subagent** (optional) — for the "independent verification" step on CRITICAL findings. Harnesses without subagents skip this step.

None of the optional tools are required. The skill explicitly works without them.

## Known limitations per harness

- **Gemini CLI** validates only `name` and `description`; `license`, `metadata`, `allowed-tools` are parsed but ignored. No functional impact.
- **Codex CLI** uses a separate `.codex/agents/openai.yaml` sidecar for extended metadata. Not required for this skill.
- **Cursor** does not respect `allowed-tools`. Cursor runs the skill with the tool set the user has enabled globally.
- **Kiro / Rovo Dev / Trae** have less mature skill support — the skill works but some conversational affordances (AskUserQuestion follow-ups) degrade to plain text.

## Spec source

The [agentskills.io spec](https://agentskills.io/specification) is the standard. `vercel-labs/skills` (the `npx skills` CLI), `vercel-labs/agent-skills` (Vercel's curated collection), and `anthropics/skills` all conform to it.

## Re-generating harness directories

If you add or remove harness dirs, run:

```bash
bash scripts/sync.sh
```

This creates fresh symlinks from every `.<harness>/skills/security-advisor` directory back to `source/skills/security-advisor/`.
