"""Adapters for CLI scripts that are shipped with the Codex/Claude skill."""

from __future__ import annotations

import runpy
from pathlib import Path


def run_skill_script(script_name: str) -> int:
    """Execute a skill script by name and return its process-style exit code."""
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "skills" / "odoo-code-review" / "scripts" / script_name
    namespace = runpy.run_path(str(script), run_name=f"__odoo_harness_{script_name}__")
    main = namespace.get("main")
    if not callable(main):
        raise RuntimeError(f"Skill script {script} does not define callable main()")
    result = main()
    return int(result or 0)
