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
ODOO_AGENTS_DIR="${AGENTS_HOME:-$HOME/.agents}"
ODOO_PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
ODOO_HARNESS_VENV="${ODOO_HARNESS_VENV:-${XDG_DATA_HOME:-$HOME/.local/share}/odoo-security-harness/venv}"
VENV_PY="$ODOO_HARNESS_VENV/bin/python"
# Backups live outside the agent directories: a copy left beside a skill loads as a duplicate skill.
BACKUP_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/odoo-security-harness/backups"
BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d%H%M%S)-$$"
MOVED_BACKUPS=0

# Track missing tools
MISSING_TOOLS=()
MISSING_REQUIRED=()

if [[ $# -gt 0 ]]; then
  echo "Usage: ./install.sh" >&2
  exit 2
fi

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

# ---- Install Python package into a dedicated virtual environment ----
# PEP 668 interpreters (Homebrew, Debian/Ubuntu) refuse system-wide pip installs, so the
# package and its dependencies live in their own venv and installed scripts are pinned to it.
echo "Installing Python package into $ODOO_HARNESS_VENV ..."
case "$ODOO_HARNESS_VENV" in
  *[[:space:]]*)
    echo -e "${RED}ERROR: venv path contains whitespace, which script shebangs cannot handle: $ODOO_HARNESS_VENV${NC}"
    echo "Set ODOO_HARNESS_VENV to a path without spaces and re-run."
    exit 1
    ;;
esac

if [[ -f "$ODOO_HARNESS_VENV/pyvenv.cfg" ]] && "$VENV_PY" -c 'import sys' >/dev/null 2>&1; then
  echo "Reusing existing venv."
elif [[ -e "$ODOO_HARNESS_VENV" && ! -f "$ODOO_HARNESS_VENV/pyvenv.cfg" && -n "$(ls -A "$ODOO_HARNESS_VENV")" ]]; then
  echo -e "${RED}ERROR: $ODOO_HARNESS_VENV exists but is not a virtual environment. Refusing to touch it.${NC}"
  echo "Remove it or set ODOO_HARNESS_VENV to another path."
  exit 1
elif ! python3 -m venv --clear "$ODOO_HARNESS_VENV"; then
  echo -e "${RED}ERROR: python3 -m venv failed. On Debian/Ubuntu, install the python3-venv package.${NC}"
  exit 1
fi

if ! "$VENV_PY" -m pip install --quiet --upgrade pip || ! "$VENV_PY" -m pip install --quiet -e "$ROOT"; then
  echo -e "${RED}ERROR: pip install failed. See the pip output above.${NC}"
  exit 1
fi
echo -e "${GREEN}Python package installed.${NC}"
echo ""

mkdir -p \
  "$CLAUDE_HOME/commands" \
  "$CLAUDE_HOME/skills" \
  "$ODOO_AGENTS_DIR/skills" \
  "$ODOO_PI_AGENT_DIR/prompts" \
  "$HOME/.local/bin"

# Mirror an installed path under a backup root, relative to HOME when it lives there.
backup_path() {
  local root="$1"
  local rel="${2#"$HOME"/}"
  printf '%s/%s\n' "$root" "${rel#/}"
}

backup() {
  local dst="$1"
  local bak
  bak="$(backup_path "$BACKUP_DIR" "$dst")"
  mkdir -p "$(dirname "$bak")"
  cp -R "$dst" "$bak"
}

# Older installers wrote "$dst.bak.<timestamp>" beside the installed file; move those out too.
migrate_legacy_backups() {
  local dst="$1"
  local legacy target
  for legacy in "$dst".bak.*; do
    [[ -e "$legacy" || -L "$legacy" ]] || continue
    target="$(backup_path "$BACKUP_ROOT/legacy" "$legacy")"
    if [[ -e "$target" || -L "$target" ]]; then
      echo -e "${YELLOW}WARNING: left $legacy in place because $target already exists.${NC}"
      continue
    fi
    mkdir -p "$(dirname "$target")"
    mv "$legacy" "$target"
    MOVED_BACKUPS=$((MOVED_BACKUPS + 1))
  done
}

install_file() {
  local src="$1"
  local dst="$2"
  migrate_legacy_backups "$dst"
  if [[ -e "$dst" || -L "$dst" ]]; then
    backup "$dst"
  fi
  cp "$src" "$dst"
}

install_dir() {
  local src="$1"
  local dst="$2"
  migrate_legacy_backups "$dst"
  if [[ -e "$dst" || -L "$dst" ]]; then
    backup "$dst"
    rm -rf "$dst"
  fi
  cp -R "$src" "$dst"
}

# Point an installed skill script at the harness venv instead of whatever python3 is on PATH.
pin_interpreter() {
  local script="$1"
  [[ "$(head -n 1 "$script")" == "#!/usr/bin/env python3" ]] || return 0
  { printf '#!%s\n' "$VENV_PY"; tail -n +2 "$script"; } >"$script.tmp"
  chmod 755 "$script.tmp"
  mv "$script.tmp" "$script"
}

install_file "$ROOT/commands/odoo-code-review.md" "$CLAUDE_HOME/commands/odoo-code-review.md"
install_file "$ROOT/prompts/odoo-code-review.md" "$ODOO_PI_AGENT_DIR/prompts/odoo-code-review.md"
install_dir "$ROOT/skills/odoo-code-review" "$ODOO_AGENTS_DIR/skills/odoo-code-review"
install_dir "$ROOT/skills/odoo-code-review" "$CLAUDE_HOME/skills/odoo-code-review"
if [[ $MOVED_BACKUPS -gt 0 ]]; then
  echo "Moved $MOVED_BACKUPS old backup(s) out of the agent directories into $BACKUP_ROOT/legacy"
fi

for script in odoo-review-run odoo-review-rerun odoo-review-export odoo-review-diff odoo-review-finalize odoo-review-learn odoo-review-stock-diff odoo-review-runtime odoo-review-assessment odoo-review-coverage odoo-review-validate-config odoo-deep-scan odoo-security-daily; do
  pin_interpreter "$ODOO_AGENTS_DIR/skills/odoo-code-review/scripts/$script"
  pin_interpreter "$CLAUDE_HOME/skills/odoo-code-review/scripts/$script"
  chmod +x "$ODOO_AGENTS_DIR/skills/odoo-code-review/scripts/$script"
  ln -sf "$ODOO_AGENTS_DIR/skills/odoo-code-review/scripts/$script" "$HOME/.local/bin/$script"
done

# Fail here, not mid-review, if an installed command cannot import the package.
if ! "$HOME/.local/bin/odoo-deep-scan" --help >/dev/null; then
  echo -e "${RED}ERROR: odoo-deep-scan failed to start from the installed skill copy.${NC}"
  exit 1
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Agent integration:"
echo "  Claude Code: /odoo-code-review"
echo "  Pi:          /odoo-code-review"
echo '  Codex:       $odoo-code-review'
echo ""
echo "Installed to:"
echo "  Shared skill:   $ODOO_AGENTS_DIR/skills/odoo-code-review"
echo "  Claude skill:   $CLAUDE_HOME/skills/odoo-code-review"
echo "  Claude command: $CLAUDE_HOME/commands/odoo-code-review.md"
echo "  Pi prompt:      $ODOO_PI_AGENT_DIR/prompts/odoo-code-review.md"
echo "  Python venv:    $ODOO_HARNESS_VENV"
echo "  Backups:        $BACKUP_ROOT"
echo ""
echo "Available commands:"
echo "  odoo-review-run             - Main pipeline runner"
echo "  odoo-review-rerun           - Directive dispatcher (Qwen/Codex re-task)"
echo "  odoo-review-export          - SARIF + fingerprints + bounty drafts"
echo "  odoo-review-diff            - Baseline vs current comparison"
echo "  odoo-review-finalize        - Phase 8.6 wrapper (CI-friendly)"
echo "  odoo-review-learn           - Learning artifacts helper"
echo "  odoo-review-stock-diff      - Stock-Claude control-lane diff"
echo "  odoo-review-runtime         - Phase 7.5 runtime helper"
echo "  odoo-review-assessment      - Remediation PR evidence packet"
echo "  odoo-review-coverage        - Phase 5.6 coverage diff"
echo "  odoo-review-validate-config - Config schema validator"
echo "  odoo-deep-scan              - Standalone static deep scanner"
echo "  odoo-security-daily         - Daily ORCA + source scan with isolated fix"
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
