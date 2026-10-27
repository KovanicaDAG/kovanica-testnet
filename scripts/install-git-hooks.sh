#!/usr/bin/env bash
# Install gitleaks pre-commit hook using repo-local hooks path

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/scripts/hooks"

echo "Setting git hooks path to $HOOKS_DIR"
git config core.hooksPath "$HOOKS_DIR"

echo "Done. The pre-commit hook will run gitleaks on staged changes."
echo "To skip: GITLEAKS_STRICT=0 (default) — warning only if gitleaks missing"
echo "To enforce: GITLEAKS_STRICT=1 — fail if gitleaks missing"