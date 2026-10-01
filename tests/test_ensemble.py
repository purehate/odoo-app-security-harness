"""Tests for focused recall ensemble orchestration."""

from __future__ import annotations

import runpy
from argparse import Namespace
from pathlib import Path

RUN_SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "odoo-code-review" / "scripts" / "odoo-review-run"


def test_ensemble_prompt_uses_captured_final_response(tmp_path: Path) -> None:
    """Read-only workers must return content instead of attempting a file write."""
    namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
    args = Namespace(ensemble="balanced")

    prompt = namespace["ensemble_prompt"](
        "pass-01-public-sudo",
        "Public Route + sudo Boundary",
        "Inspect public routes.",
        tmp_path,
        tmp_path / ".audit",
        args,
    )

    assert "Return the complete report as your final response" in prompt
    assert "captures that\nresponse into the pass artifact" in prompt
    assert "Do not call file-write\ntools" in prompt
    assert "Output to this file only" not in prompt
