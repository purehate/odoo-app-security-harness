"""Tests for assessment evidence and remediation-PR preparation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from odoo_security_harness.assessment import main, select_finding


def write_json(path: Path, value: dict) -> None:
    """Write a JSON fixture with an explicit resource context."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle)


def git(repo: Path, *args: str) -> str:
    """Run Git for a local test repository."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def create_repo(path: Path) -> str:
    """Create a repository with one vulnerable baseline commit."""
    path.mkdir()
    git(path, "init", "--quiet")
    git(path, "config", "user.email", "assessment@example.invalid")
    git(path, "config", "user.name", "Assessment Test")
    (path / "module.py").write_text("ALLOW = True\n", encoding="utf-8")
    git(path, "add", "module.py")
    git(path, "commit", "--quiet", "-m", "test: vulnerable baseline")
    return git(path, "rev-parse", "HEAD")


def findings_document(repo: Path, commit: str) -> dict:
    """Return a complete findings fixture with one demonstrable issue."""
    return {
        "schema_version": "1.0",
        "target": {"repo": str(repo), "commit": commit},
        "findings": [
            {
                "id": "F-1",
                "title": "Authorization bypass",
                "severity": "high",
                "triage": "ACCEPT",
                "file": "module.py",
                "line": 1,
                "description": "An ordinary user can cross the approval boundary.",
                "attack_path": "ordinary user -> public method -> protected state",
                "impact": "Unauthorized state transition.",
                "fix": "Enforce the approval invariant in the public method.",
                "reproduction": "runtime/pre-fix.log",
                "poc": "See runtime/reproduce.sh",
            }
        ],
    }


def test_select_finding_prefers_reproducible_high_severity(tmp_path: Path) -> None:
    """Automatic selection should prioritize demonstrable accepted findings."""
    out = tmp_path / "audit"
    repo = tmp_path / "repo"
    out.mkdir()
    repo.mkdir()
    (out / "runtime").mkdir()
    (out / "runtime" / "proof.log").write_text("confirmed\n", encoding="utf-8")
    findings = [
        {"id": "F-1", "severity": "medium", "triage": "ACCEPT", "reproduction": "runtime/proof.log"},
        {"id": "F-2", "severity": "high", "triage": "ACCEPT", "reproduction": "runtime/proof.log"},
        {"id": "F-3", "severity": "critical", "triage": "NEEDS-MANUAL"},
    ]

    selected = select_finding(findings, None, out, repo)

    assert selected["id"] == "F-2"


def test_assessment_builds_complete_human_review_packet(tmp_path: Path) -> None:
    """A complete evidence record should produce a strict-pass PR packet."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    baseline = create_repo(repo)
    (out / "runtime").mkdir(parents=True)
    pre_fix = out / "runtime" / "pre-fix.log"
    pre_fix.write_text("vulnerable behavior reproduced\n", encoding="utf-8")
    (out / "runtime" / "reproduce.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    write_json(out / "findings.json", findings_document(repo, baseline))

    assert main([str(out), "--repo", str(repo)]) == 0
    first_status = json.loads((out / "assessment" / "status.json").read_text(encoding="utf-8"))
    assert first_status["demo_ready"] is False
    assert (out / "assessment" / "ai-remediation-brief.md").exists()

    regression = repo / "test_security.py"
    regression.write_text("def test_authorization_boundary():\n    assert True\n", encoding="utf-8")
    (repo / "module.py").write_text("ALLOW = False\n", encoding="utf-8")
    git(repo, "add", "module.py", "test_security.py")
    git(repo, "commit", "--quiet", "-m", "fix: enforce authorization boundary")
    patched = git(repo, "rev-parse", "HEAD")
    post_fix = out / "runtime" / "post-fix.log"
    legitimate = out / "runtime" / "legitimate.log"
    post_fix.write_text("attack blocked\n", encoding="utf-8")
    legitimate.write_text("authorized workflow passed\n", encoding="utf-8")

    result = main(
        [
            str(out),
            "--repo",
            str(repo),
            "--patched-ref",
            patched,
            "--post-fix",
            str(post_fix),
            "--legitimate",
            str(legitimate),
            "--regression-test",
            str(regression),
            "--test-command",
            "pytest test_security.py",
            "--ticket-url",
            "https://tracker.example.invalid/SEC-1",
            "--ci-url",
            "https://ci.example.invalid/runs/1",
            "--pre-fix-summary",
            "The unauthorized transition succeeds.",
            "--post-fix-summary",
            "The same transition is rejected.",
            "--legitimate-summary",
            "Authorized transitions still succeed.",
            "--deployment-notes",
            "No migration is required.",
            "--rollback-plan",
            "Revert the single remediation commit.",
            "--residual-risk",
            "None identified in the affected transition.",
            "--strict",
        ]
    )

    status = json.loads((out / "assessment" / "status.json").read_text(encoding="utf-8"))
    pr_description = (out / "assessment" / "pr-description.md").read_text(encoding="utf-8")
    checklist = (out / "assessment" / "reviewer-checklist.md").read_text(encoding="utf-8")
    assert result == 0
    assert status["demo_ready"] is True
    assert status["passed_gates"] == status["total_gates"]
    assert "The same transition is rejected." in pr_description
    assert patched in pr_description
    assert "[x] post-fix replay" in checklist
    assert (out / "assessment" / "remediation.diff").exists()


def test_strict_mode_rejects_an_incomplete_chain(tmp_path: Path) -> None:
    """Strict mode should prevent an incomplete evidence packet from being called ready."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    baseline = create_repo(repo)
    (out / "runtime").mkdir(parents=True)
    (out / "runtime" / "pre-fix.log").write_text("confirmed\n", encoding="utf-8")
    write_json(out / "findings.json", findings_document(repo, baseline))

    result = main([str(out), "--repo", str(repo), "--strict"])

    assert result == 4
