#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

# Track missing tools
MISSING_TOOLS=()
MISSING_REQUIRED=()

echo -e "${BLUE}Odoo Application Security Harness - Installer${NC}"
echo "=============================================="
echo ""

# ---- Python version check ----
check_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}ERROR: python3 is required but not installed.${NC}"
    exit 1
  fi

  PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
  PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
  PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')

  echo "Python version: $PYTHON_VERSION"

  if [[ "$PYTHON_MAJOR" -lt 3 ]] || ([[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 9 ]]); then
    echo -e "${RED}ERROR: Python 3.9+ is required. Found $PYTHON_VERSION${NC}"
    exit 1
  fi

  if [[ "$PYTHON_MINOR" -lt 11 ]]; then
    echo -e "${YELLOW}WARNING: Python 3.11+ recommended for best compatibility (tomllib support).${NC}"
  fi

  # Check for pip
  if ! python3 -m pip --version >/dev/null 2>&1; then
    echo -e "${RED}ERROR: pip is required but not installed.${NC}"
    exit 1
  fi
}

check_python

# ---- Prerequisite check ----
check_tool() {
  local name="$1" tier="$2" note="$3"
  if command -v "$name" >/dev/null 2>&1; then
    printf "  ${GREEN}%-12s${NC} %-8s %s\n" "$name" "ok" "$note"
  else
    printf "  ${RED}%-12s${NC} %-8s %s\n" "$name" "MISSING" "$note"
    MISSING_TOOLS+=("$name ($tier)")
    if [[ "$tier" == "required" ]]; then
      MISSING_REQUIRED+=("$name")
    fi
  fi
}

echo ""
echo "Prerequisite check:"
printf "  %-12s %-8s %s\n" "Tool" "Status" "Purpose"
printf "  %-12s %-8s %s\n" "----" "------" "-------"
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

echo ""
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo -e "${YELLOW}Note: ${#MISSING_TOOLS[@]} tool(s) missing.${NC}"
  if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    echo -e "${RED}WARNING: ${#MISSING_REQUIRED[@]} required tool(s) missing: ${MISSING_REQUIRED[*]}${NC}"
    echo "Harness will install but some features will be unavailable."
  fi
  echo "Missing scanners are skipped at runtime and noted in tooling.md."
  echo "See README 'Prerequisites' for install hints."
else
  echo -e "${GREEN}All tools available!${NC}"
fi
echo ""

# ---- Install Python dependencies ----
echo "Installing Python dependencies..."
if [[ -f "$ROOT/pyproject.toml" ]]; then
  python3 -m pip install -e "$ROOT" 2>&1 | grep -v "already satisfied" || true
  echo -e "${GREEN}Python package installed.${NC}"
else
  echo -e "${YELLOW}WARNING: pyproject.toml not found. Skipping Python package install.${NC}"
fi
echo ""

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

for script in odoo-review-run odoo-review-rerun odoo-review-export odoo-review-diff odoo-review-finalize odoo-review-learn odoo-review-stock-diff odoo-review-runtime odoo-review-coverage odoo-review-validate-config odoo-deep-scan; do
  chmod +x "$CLAUDE_HOME/skills/odoo-code-review/scripts/$script"
  ln -sf "$CLAUDE_HOME/skills/odoo-code-review/scripts/$script" "$HOME/.local/bin/$script"
done

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Installed into: $CLAUDE_HOME"
echo ""
echo "Available commands:"
echo "  odoo-review-run      - Main pipeline runner"
echo "  odoo-review-rerun    - Directive dispatcher (Qwen/Codex re-task)"
echo "  odoo-review-export   - SARIF + fingerprints + bounty drafts"
echo "  odoo-review-diff     - Baseline vs current comparison"
echo "  odoo-review-finalize - Phase 8.6 wrapper (CI-friendly)"
echo "  odoo-review-learn    - Learning artifacts helper"
echo "  odoo-review-stock-diff - Stock-Claude control-lane diff"
echo "  odoo-review-runtime  - Phase 7.5 runtime helper"
echo "  odoo-review-coverage - Phase 5.6 coverage diff"
echo "  odoo-review-validate-config - Config schema validator"
echo "  odoo-deep-scan       - Standalone static deep scanner"
echo ""
echo "Claude Code command: /odoo-code-review"
echo ""

# Verify symlinks work
if command -v odoo-review-run >/dev/null 2>&1; then
  echo -e "${GREEN}✓ Commands are available in PATH${NC}"
else
  echo -e "${YELLOW}⚠ Commands not in PATH. Add this to your shell profile:${NC}"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# Show quickstart
if [[ ${#MISSING_REQUIRED[@]} -eq 0 ]]; then
  echo ""
  echo "Quick start:"
  echo "  cd /path/to/odoo-addons"
  echo "  odoo-review-run . --allow-missing-lanes"
  echo ""
  echo "Or from Claude Code:"
  echo "  /odoo-code-review /path/to/odoo-addons -ks"
fi
