"""Tests for session progress tracking."""
from __future__ import annotations

from pathlib import Path

import pytest

from odoo_security_harness.session_progress import (
    HunterPassStatus,
    PhaseRecord,
    ScannerStatus,
    SessionProgress,
    add_directive,
    add_hunter_pass,
    add_note,
    add_scanner_status,
    complete_phase,
    create_session_progress,
    fail_phase,
    get_phase_status,
    is_review_complete,
    load_session_progress,
    next_pending_phase,
    save_session_progress,
    start_phase,
)


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------

def test_session_progress_round_trip(tmp_path: Path) -> None:
    """Saving and loading should preserve all fields."""
    progress = create_session_progress("/repo", "/out", git_head="abc123")
    progress.phases = [
        PhaseRecord(phase="inventory", status="completed", findings_count=5),
        PhaseRecord(phase="scanners", status="running"),
    ]
    progress.scanner_status["raw_sql"] = ScannerStatus(
        name="raw_sql", status="completed", findings_count=3
    )
    progress.hunter_passes = [
        HunterPassStatus(name="sudo_patterns", target_files=["models/a.py"], status="pending")
    ]
    progress.directives = ["directives/D-0001-test.md"]
    progress.notes = ["Started scan"]
    progress.findings_count = 8
    progress.report_generated = False

    path = tmp_path / "session-progress.json"
    save_session_progress(progress, path)
    loaded = load_session_progress(path)

    assert loaded is not None
    assert loaded.session_id == progress.session_id
    assert loaded.repo_path == "/repo"
    assert loaded.out_path == "/out"
    assert loaded.git_head == "abc123"
    assert len(loaded.phases) == 2
    assert loaded.phases[0].phase == "inventory"
    assert loaded.phases[0].status == "completed"
    assert loaded.phases[0].findings_count == 5
    assert loaded.phases[1].phase == "scanners"
    assert loaded.phases[1].status == "running"
    assert loaded.scanner_status["raw_sql"].findings_count == 3
    assert loaded.hunter_passes[0].name == "sudo_patterns"
    assert loaded.hunter_passes[0].target_files == ["models/a.py"]
    assert loaded.directives == ["directives/D-0001-test.md"]
    assert loaded.notes == ["Started scan"]
    assert loaded.findings_count == 8
    assert loaded.report_generated is False


def test_load_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_session_progress(tmp_path / "nonexistent.json") is None


def test_load_corrupt_file_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    assert load_session_progress(path) is None


# ---------------------------------------------------------------------------
# Phase lifecycle
# ---------------------------------------------------------------------------

def test_start_phase_creates_record() -> None:
    progress = create_session_progress("/repo", "/out")
    phase = start_phase(progress, "scanners")
    assert phase.phase == "scanners"
    assert phase.status == "running"
    assert phase.started_at != ""


def test_complete_phase_updates_status() -> None:
    progress = create_session_progress("/repo", "/out")
    start_phase(progress, "scanners")
    phase = complete_phase(progress, "scanners", findings_count=12, notes=["done"])
    assert phase.status == "completed"
    assert phase.findings_count == 12
    assert phase.notes == ["done"]
    assert phase.completed_at != ""
    assert progress.findings_count == 12


def test_fail_phase_updates_status() -> None:
    progress = create_session_progress("/repo", "/out")
    phase = fail_phase(progress, "scanners", error="crash")
    assert phase.status == "failed"
    assert "crash" in phase.notes[0]


def test_get_phase_status() -> None:
    progress = create_session_progress("/repo", "/out")
    assert get_phase_status(progress, "inventory") is None
    start_phase(progress, "inventory")
    assert get_phase_status(progress, "inventory") is not None


def test_next_pending_phase() -> None:
    progress = create_session_progress("/repo", "/out")
    order = ["inventory", "scanners", "triage", "hunters", "report"]
    assert next_pending_phase(progress, order) == "inventory"

    complete_phase(progress, "inventory")
    assert next_pending_phase(progress, order) == "scanners"

    complete_phase(progress, "scanners")
    complete_phase(progress, "triage")
    complete_phase(progress, "hunters")
    assert next_pending_phase(progress, order) == "report"

    complete_phase(progress, "report")
    assert next_pending_phase(progress, order) is None


def test_is_review_complete() -> None:
    progress = create_session_progress("/repo", "/out")
    order = ["inventory", "scanners", "report"]
    assert not is_review_complete(progress, order)

    complete_phase(progress, "inventory")
    complete_phase(progress, "scanners")
    complete_phase(progress, "report")
    assert is_review_complete(progress, order)


# ---------------------------------------------------------------------------
# Scanner and hunter pass tracking
# ---------------------------------------------------------------------------

def test_add_scanner_status() -> None:
    progress = create_session_progress("/repo", "/out")
    add_scanner_status(progress, "raw_sql", "completed", findings_count=5)
    assert progress.scanner_status["raw_sql"].status == "completed"
    assert progress.scanner_status["raw_sql"].findings_count == 5

    # Update in place
    add_scanner_status(progress, "raw_sql", "failed", error="boom")
    assert progress.scanner_status["raw_sql"].status == "failed"
    assert progress.scanner_status["raw_sql"].error == "boom"


def test_add_hunter_pass() -> None:
    progress = create_session_progress("/repo", "/out")
    add_hunter_pass(progress, "sudo_patterns", ["models/a.py", "models/b.py"])
    assert len(progress.hunter_passes) == 1
    assert progress.hunter_passes[0].status == "pending"

    # Update in place
    add_hunter_pass(progress, "sudo_patterns", ["models/a.py"], status="completed")
    assert len(progress.hunter_passes) == 1
    assert progress.hunter_passes[0].status == "completed"


def test_add_directive() -> None:
    progress = create_session_progress("/repo", "/out")
    add_directive(progress, "directives/D-0001.md")
    add_directive(progress, "directives/D-0001.md")  # dedup
    add_directive(progress, "directives/D-0002.md")
    assert progress.directives == ["directives/D-0001.md", "directives/D-0002.md"]


def test_add_note() -> None:
    progress = create_session_progress("/repo", "/out")
    add_note(progress, "Checkpoint alpha")
    assert len(progress.notes) == 1
    assert "Checkpoint alpha" in progress.notes[0]


# ---------------------------------------------------------------------------
# Create / save / load integration
# ---------------------------------------------------------------------------

def test_create_session_progress_has_uuid_and_timestamps() -> None:
    progress = create_session_progress("/repo", "/out")
    assert len(progress.session_id) == 8
    assert progress.created_at != ""
    assert progress.updated_at != ""
    assert progress.git_head == ""


def test_save_updates_timestamp(tmp_path: Path) -> None:
    progress = create_session_progress("/repo", "/out")
    old_updated = progress.updated_at
    path = tmp_path / "progress.json"
    save_session_progress(progress, path)
    assert progress.updated_at != old_updated


def test_session_progress_to_dict_is_json_safe() -> None:
    progress = create_session_progress("/repo", "/out")
    start_phase(progress, "scanners")
    d = progress.to_dict()
    assert isinstance(d, dict)
    assert "session_id" in d
    assert "phases" in d
    assert isinstance(d["phases"], list)
