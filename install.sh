#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

# ---- Prerequisite check (informational only — install proceeds regardless) ----
check_tool() {
  local name="$1" tier="$2" note="$3"
  if command -v "$name" >/dev/null 2>&1; then
    printf "  %-14s %-8s %s\n" "$name" "ok" "$note"
  else
    printf "  %-14s %-8s %s\n" "$name" "MISSING" "$note"
    MISSING_TOOLS+=("$name ($tier)")
  fi
}

MISSING_TOOLS=()
echo "Prerequisite check:"
printf "  %-14s %-8s %s\n" "Tool" "Status" "Purpose"
printf "  %-14s %-8s %s\n" "----" "------" "-------"
check_tool python3     required "runner script interpreter"
check_tool ollama      required "local Qwen advisory lane (Phase 1.5)"
check_tool codex       required "Codex heavy-worker lane (Phases 5–8)"
check_tool semgrep     optional "Phase 2 — Semgrep Python/Odoo scan"
check_tool bandit      optional "Phase 2.5 — Bandit AppSec sweep"
check_tool ruff        optional "Phase 2.6 — Ruff lint"
check_tool pylint      optional "Phase 2.6 — pylint-odoo"
check_tool pip-audit   optional "Phase 4.5 — Python dependency CVEs"
check_tool osv-scanner optional "Phase 4.5 — OSV dependency scan"
check_tool codeql      optional "Phase 3 — CodeQL Python"
check_tool joern-parse optional "Phase 3.5 — Joern CPG (only with --joern)"
check_tool dot         optional "Phase 7.6 — Graphviz attack-graph render"

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo
  echo "Note: ${#MISSING_TOOLS[@]} tool(s) missing. Harness installs anyway."
  echo "Missing scanners are skipped at runtime and noted in tooling.md."
  echo "See README 'Prerequisites' for install hints."
fi
echo

mkdir -p "$CLAUDE_HOME/commands" "$CLAUDE_HOME/skills" "$HOME/.local/bin"

install_file() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" ]]; then
    cp -R "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
  fi
  cp "$src" "$dst"
}

install_dir() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" ]]; then
    cp -R "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
    rm -rf "$dst"
  fi
  cp -R "$src" "$dst"
}

install_file "$ROOT/commands/odoo-code-review.md" "$CLAUDE_HOME/commands/odoo-code-review.md"
install_dir "$ROOT/skills/odoo-code-review" "$CLAUDE_HOME/skills/odoo-code-review"

for script in odoo-review-run odoo-review-rerun odoo-review-export odoo-review-diff; do
  chmod +x "$CLAUDE_HOME/skills/odoo-code-review/scripts/$script"
  ln -sf "$CLAUDE_HOME/skills/odoo-code-review/scripts/$script" "$HOME/.local/bin/$script"
done

echo "Installed Odoo Application Security Harness into $CLAUDE_HOME"
echo "Runner:  $HOME/.local/bin/odoo-review-run"
echo "Rerun:   $HOME/.local/bin/odoo-review-rerun"
echo "Export:  $HOME/.local/bin/odoo-review-export"
echo "Diff:    $HOME/.local/bin/odoo-review-diff"
echo "Command: /odoo-code-review"

