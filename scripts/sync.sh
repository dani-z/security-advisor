#!/usr/bin/env bash
# sync.sh — regenerate per-harness symlinks from the canonical source.
#
# Run this after:
#   - adding a new harness to the HARNESSES array
#   - renaming source/skills/security-advisor
#   - cloning the repo on a system where git didn't preserve symlinks
#
# Usage:  bash scripts/sync.sh

set -euo pipefail

cd "$(dirname "$0")/.."

SKILL_NAME="security-advisor"
SOURCE_PATH="source/skills/${SKILL_NAME}"

if [[ ! -d "${SOURCE_PATH}" ]]; then
  echo "ERROR: canonical skill not found at ${SOURCE_PATH}"
  exit 1
fi

# Every harness directory that should get a materialised copy.
HARNESSES=(
  .agents
  .claude
  .codex
  .cursor
  .gemini
  .github
  .kiro
  .opencode
  .pi
  .rovodev
  .trae
  .trae-cn
)

echo "Syncing ${SKILL_NAME} to ${#HARNESSES[@]} harness directories..."

for harness in "${HARNESSES[@]}"; do
  target="${harness}/skills/${SKILL_NAME}"
  mkdir -p "${harness}/skills"
  ln -sfn "../../source/skills/${SKILL_NAME}" "${target}"
  echo "  → ${target}"
done

# Top-level skills/ symlink for skills.sh `npx skills add` CLI compatibility.
mkdir -p skills
ln -sfn "../source/skills/${SKILL_NAME}" "skills/${SKILL_NAME}"
echo "  → skills/${SKILL_NAME}"

echo ""
echo "Done. Canonical source: ${SOURCE_PATH}"
