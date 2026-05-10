"""Console entry point for odoo-review-learn."""

from __future__ import annotations

from odoo_security_harness.scripts._skill_script import run_skill_script


def main() -> int:
    """Run the skill-bundled learning helper."""
    return run_skill_script("odoo-review-learn")
