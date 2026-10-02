"""Session progress tracking for resumable long-running security reviews.

Inspired by Anthropic's long-running agent harness pattern:
- A feature list enumerates all work items (scanners, hunter passes)
- A progress file tracks completion state across context windows
- Each session reads progress, picks the next pending item, and updates state
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ScannerStatus:
    """Completion status for a single scanner."""

    name: str
    status: str = "pending"  # pending | running | completed | failed | skipped
    findings_count: int = 0
    elapsed_seconds: float = 0.0
    error: str = ""


@dataclass
class HunterPassStatus:
    """Completion status for a single Codex hunter pass."""

    name: str
    target_files: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | completed | failed | skipped
    findings_count: int = 0
    elapsed_seconds: float = 0.0
    token_estimate: int = 0
    error: str = ""


@dataclass
class PhaseRecord:
    """A completed or in-progress phase of the review."""

    phase: str
    status: str = "pending"  # pending | running | completed | failed
    started_at: str = ""
    completed_at: str = ""
    elapsed_seconds: float = 0.0
    findings_count: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class SessionProgress:
    """Full progress state for a review session.

    This object is designed to be JSON-serializable and human-readable
    so that a fresh Claude context can resume work by reading it.
    """

    session_id: str
    repo_path: str
    out_path: str
    git_head: str = ""
    created_at: str = ""
    updated_at: str = ""
    phases: list[PhaseRecord] = field(default_factory=list)
    scanner_status: dict[str, ScannerStatus] = field(default_factory=dict)
    hunter_passes: list[HunterPassStatus] = field(default_factory=list)
    directives: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # High-water mark: total findings at last save
    findings_count: int = 0
    # Whether the final report has been generated
    report_generated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "session_id": self.session_id,
            "repo_path": self.repo_path,
            "out_path": self.out_path,
            "git_head": self.git_head,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "phases": [
                {
                    "phase": p.phase,
                    "status": p.status,
                    "started_at": p.started_at,
                    "completed_at": p.completed_at,
                    "elapsed_seconds": p.elapsed_seconds,
                    "findings_count": p.findings_count,
                    "notes": p.notes,
                }
                for p in self.phases
            ],
            "scanner_status": {
                k: {
                    "name": v.name,
                    "status": v.status,
                    "findings_count": v.findings_count,
                    "elapsed_seconds": v.elapsed_seconds,
                    "error": v.error,
                }
                for k, v in self.scanner_status.items()
            },
            "hunter_passes": [
                {
                    "name": h.name,
                    "target_files": h.target_files,
                    "status": h.status,
                    "findings_count": h.findings_count,
                    "elapsed_seconds": h.elapsed_seconds,
                    "token_estimate": h.token_estimate,
                    "error": h.error,
                }
                for h in self.hunter_passes
            ],
            "directives": self.directives,
            "notes": self.notes,
            "findings_count": self.findings_count,
            "report_generated": self.report_generated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionProgress:
        """Deserialize from a plain dict."""
        return cls(
            session_id=data.get("session_id", ""),
            repo_path=data.get("repo_path", ""),
            out_path=data.get("out_path", ""),
            git_head=data.get("git_head", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            phases=[
                PhaseRecord(
                    phase=p["phase"],
                    status=p.get("status", "pending"),
                    started_at=p.get("started_at", ""),
                    completed_at=p.get("completed_at", ""),
                    elapsed_seconds=p.get("elapsed_seconds", 0.0),
                    findings_count=p.get("findings_count", 0),
                    notes=p.get("notes", []),
                )
                for p in data.get("phases", [])
            ],
            scanner_status={
                k: ScannerStatus(
                    name=v["name"],
                    status=v.get("status", "pending"),
                    findings_count=v.get("findings_count", 0),
                    elapsed_seconds=v.get("elapsed_seconds", 0.0),
                    error=v.get("error", ""),
                )
                for k, v in data.get("scanner_status", {}).items()
            },
            hunter_passes=[
                HunterPassStatus(
                    name=h["name"],
                    target_files=h.get("target_files", []),
                    status=h.get("status", "pending"),
                    findings_count=h.get("findings_count", 0),
                    elapsed_seconds=h.get("elapsed_seconds", 0.0),
                    token_estimate=h.get("token_estimate", 0),
                    error=h.get("error", ""),
                )
                for h in data.get("hunter_passes", [])
            ],
            directives=data.get("directives", []),
            notes=data.get("notes", []),
            findings_count=data.get("findings_count", 0),
            report_generated=data.get("report_generated", False),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_session_progress(
    repo_path: str | Path,
    out_path: str | Path,
    git_head: str = "",
) -> SessionProgress:
    """Create a new session progress record."""
    now = _now()
    return SessionProgress(
        session_id=str(uuid.uuid4())[:8],
        repo_path=str(repo_path),
        out_path=str(out_path),
        git_head=git_head,
        created_at=now,
        updated_at=now,
    )


def load_session_progress(path: str | Path) -> SessionProgress | None:
    """Load session progress from disk. Returns None if file missing or invalid."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return SessionProgress.from_dict(data)
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def save_session_progress(progress: SessionProgress, path: str | Path) -> None:
    """Save session progress to disk."""
    progress.updated_at = _now()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(progress.to_dict(), indent=2), encoding="utf-8")


def get_phase_status(progress: SessionProgress, phase_name: str) -> PhaseRecord | None:
    """Return the status record for a given phase, or None if not started."""
    for phase in progress.phases:
        if phase.phase == phase_name:
            return phase
    return None


def start_phase(progress: SessionProgress, phase_name: str) -> PhaseRecord:
    """Mark a phase as running. Creates the record if it doesn't exist."""
    existing = get_phase_status(progress, phase_name)
    if existing is not None:
        existing.status = "running"
        existing.started_at = _now()
        return existing
    phase = PhaseRecord(phase=phase_name, status="running", started_at=_now())
    progress.phases.append(phase)
    return phase


def complete_phase(
    progress: SessionProgress,
    phase_name: str,
    findings_count: int = 0,
    notes: list[str] | None = None,
) -> PhaseRecord:
    """Mark a phase as completed."""
    phase = get_phase_status(progress, phase_name)
    if phase is None:
        phase = start_phase(progress, phase_name)
    phase.status = "completed"
    phase.completed_at = _now()
    phase.findings_count = findings_count
    if notes:
        phase.notes.extend(notes)
    progress.findings_count = max(progress.findings_count, findings_count)
    return phase


def fail_phase(progress: SessionProgress, phase_name: str, error: str) -> PhaseRecord:
    """Mark a phase as failed."""
    phase = get_phase_status(progress, phase_name)
    if phase is None:
        phase = start_phase(progress, phase_name)
    phase.status = "failed"
    phase.completed_at = _now()
    phase.notes.append(f"ERROR: {error}")
    return phase


def next_pending_phase(progress: SessionProgress, phase_order: list[str]) -> str | None:
    """Return the next pending phase from the ordered list, or None if all done."""
    completed = {p.phase for p in progress.phases if p.status == "completed"}
    for phase in phase_order:
        if phase not in completed:
            return phase
    return None


def add_scanner_status(
    progress: SessionProgress,
    name: str,
    status: str,
    findings_count: int = 0,
    elapsed_seconds: float = 0.0,
    error: str = "",
) -> None:
    """Update or create a scanner status entry."""
    progress.scanner_status[name] = ScannerStatus(
        name=name,
        status=status,
        findings_count=findings_count,
        elapsed_seconds=elapsed_seconds,
        error=error,
    )


def add_hunter_pass(
    progress: SessionProgress,
    name: str,
    target_files: list[str],
    status: str = "pending",
) -> None:
    """Add or update a hunter pass entry."""
    for existing in progress.hunter_passes:
        if existing.name == name:
            existing.target_files = target_files
            existing.status = status
            return
    progress.hunter_passes.append(HunterPassStatus(name=name, target_files=target_files, status=status))


def add_directive(progress: SessionProgress, directive_path: str) -> None:
    """Record that a directive was created for targeted rerun."""
    if directive_path not in progress.directives:
        progress.directives.append(directive_path)


def add_note(progress: SessionProgress, note: str) -> None:
    """Add a free-form note to the session log."""
    progress.notes.append(f"[{_now()}] {note}")


def is_review_complete(progress: SessionProgress, phase_order: list[str]) -> bool:
    """Return True if all phases in the ordered list are completed."""
    completed = {p.phase for p in progress.phases if p.status == "completed"}
    return all(phase in completed for phase in phase_order)
