"""Console entry point for odoo-review-run."""

from __future__ import annotations

from odoo_security_harness.scripts._skill_script import run_skill_script


def main() -> int:
    """Run the skill-bundled review runner."""
    return run_skill_script("odoo-review-run")
