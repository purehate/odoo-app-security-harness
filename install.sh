#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"

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
install_file "$ROOT/commands/odoo-pr-review.md" "$CLAUDE_HOME/commands/odoo-pr-review.md"
install_dir "$ROOT/skills/odoo-codereview" "$CLAUDE_HOME/skills/odoo-codereview"
install_dir "$ROOT/skills/odoo-prreview" "$CLAUDE_HOME/skills/odoo-prreview"

chmod +x "$CLAUDE_HOME/skills/odoo-codereview/scripts/odoo-review-run"
ln -sf "$CLAUDE_HOME/skills/odoo-codereview/scripts/odoo-review-run" "$HOME/.local/bin/odoo-review-run"

echo "Installed odoo-codereview harness into $CLAUDE_HOME"
echo "Runner: $HOME/.local/bin/odoo-review-run"
echo "Commands: /odoo-code-review and /odoo-pr-review"

