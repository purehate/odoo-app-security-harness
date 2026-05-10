"""Console entry point for odoo-review-export."""

from __future__ import annotations

from odoo_security_harness.scripts._skill_script import run_skill_script


def main() -> int:
    """Run the skill-bundled export helper."""
    return run_skill_script("odoo-review-export")
