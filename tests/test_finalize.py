"""Tests for final review export and assessment orchestration."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

FINALIZE_SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills" / "odoo-code-review" / "scripts" / "odoo-review-finalize"
)


def write_json(path: Path, value: dict) -> None:
    """Write a JSON fixture with an explicit resource context."""
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle)


def test_finalize_initializes_requested_assessment_packet(tmp_path: Path, monkeypatch) -> None:
    """Assessment-mode finalization should dispatch packet creation for the chosen finding."""
    namespace = runpy.run_path(str(FINALIZE_SCRIPT), run_name="__test_odoo_finalize__")
    out = tmp_path / "audit"
    out.mkdir()
    write_json(out / "findings.json", {"findings": []})
    write_json(out / "run-mode.json", {"assessment": True, "assessment_finding": "F-7"})
    commands: list[list[str]] = []

    def fake_shell(command: list[str], log_lines: list[str]) -> int:
        commands.append(command)
        log_lines.append("test command completed")
        return 0

    monkeypatch.setitem(namespace["main"].__globals__, "shell", fake_shell)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "odoo-review-finalize",
            str(out),
            "--no-diff",
            "--no-stock-gate",
            "--fail-on",
            "none",
        ],
    )

    result = namespace["main"]()

    assessment_command = next(command for command in commands if "odoo-review-assessment" in " ".join(command))
    assert result == 0
    assert assessment_command[-2:] == ["--finding", "F-7"]
    assert "assessment_rc=0" in (out / "finalize.log").read_text(encoding="utf-8")
