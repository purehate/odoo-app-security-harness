"""Tests for findings diff functionality."""

from __future__ import annotations

import hashlib
import re


def normalize_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def fingerprint_for(f: dict) -> str:
    if f.get("fingerprint"):
        return f["fingerprint"]
    parts = [
        (f.get("rule_id") or f.get("title") or "")[:80],
        f.get("file", ""),
        str(f.get("line", "")),
        normalize_line((f.get("description") or f.get("attack_path") or "")[:200]),
    ]
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def index(findings: list[dict]) -> dict[str, dict]:
    return {fingerprint_for(f): f for f in findings}


def classify(baseline_idx: dict, current_idx: dict) -> dict:
    new: list[dict] = []
    fixed: list[dict] = []
    unchanged: list[dict] = []
    changed: list[dict] = []

    for fp, cur in current_idx.items():
        if fp not in baseline_idx:
            new.append(cur)
            continue
        base = baseline_idx[fp]
        sev_changed = (base.get("severity") or "") != (cur.get("severity") or "")
        triage_changed = (base.get("triage") or "") != (cur.get("triage") or "")
        if sev_changed or triage_changed:
            changed.append(
                {
                    "current": cur,
                    "baseline": base,
                    "severity_changed": sev_changed,
                    "triage_changed": triage_changed,
                }
            )
        else:
            unchanged.append(cur)

    for fp, base in baseline_idx.items():
        if fp not in current_idx:
            fixed.append(base)

    return {"new": new, "fixed": fixed, "unchanged": unchanged, "changed": changed}


class TestFingerprintFor:
    """Test fingerprint computation for diff."""

    def test_existing_fingerprint(self) -> None:
        """Test using existing fingerprint field."""
        f = {"fingerprint": "sha256:abc123", "title": "Test"}
        assert fingerprint_for(f) == "sha256:abc123"

    def test_computed_fingerprint(self) -> None:
        """Test computing fingerprint from fields."""
        f = {"title": "Test Finding", "file": "test.py", "line": 10}
        fp = fingerprint_for(f)
        assert fp.startswith("sha256:")
        assert len(fp) == 71

    def test_fingerprint_stability(self) -> None:
        """Test same fields produce same fingerprint."""
        f = {"title": "Test", "file": "test.py", "line": 1}
        assert fingerprint_for(f) == fingerprint_for(f)


class TestIndex:
    """Test findings indexing."""

    def test_index_by_fingerprint(self) -> None:
        """Test creating index from findings."""
        findings = [
            {"id": "F-1", "fingerprint": "fp1"},
            {"id": "F-2", "fingerprint": "fp2"},
        ]
        idx = index(findings)
        assert len(idx) == 2
        assert idx["fp1"]["id"] == "F-1"
        assert idx["fp2"]["id"] == "F-2"

    def test_index_with_computed_fingerprints(self) -> None:
        """Test index computes fingerprints when missing."""
        findings = [
            {"id": "F-1", "title": "Test 1", "file": "a.py"},
            {"id": "F-2", "title": "Test 2", "file": "b.py"},
        ]
        idx = index(findings)
        assert len(idx) == 2
        for fp in idx:
            assert fp.startswith("sha256:")


class TestClassify:
    """Test findings classification."""

    def test_new_findings(self) -> None:
        """Test detecting new findings."""
        baseline = {"fp1": {"id": "F-1", "severity": "high"}}
        current = {
            "fp1": {"id": "F-1", "severity": "high"},
            "fp2": {"id": "F-2", "severity": "critical"},
        }
        result = classify(baseline, current)

        assert len(result["new"]) == 1
        assert result["new"][0]["id"] == "F-2"
        assert len(result["fixed"]) == 0
        assert len(result["unchanged"]) == 1

    def test_fixed_findings(self) -> None:
        """Test detecting fixed findings."""
        baseline = {
            "fp1": {"id": "F-1", "severity": "high"},
            "fp2": {"id": "F-2", "severity": "medium"},
        }
        current = {"fp1": {"id": "F-1", "severity": "high"}}
        result = classify(baseline, current)

        assert len(result["fixed"]) == 1
        assert result["fixed"][0]["id"] == "F-2"
        assert len(result["new"]) == 0
        assert len(result["unchanged"]) == 1

    def test_unchanged_findings(self) -> None:
        """Test unchanged findings."""
        baseline = {"fp1": {"id": "F-1", "severity": "high", "triage": "ACCEPT"}}
        current = {"fp1": {"id": "F-1", "severity": "high", "triage": "ACCEPT"}}
        result = classify(baseline, current)

        assert len(result["unchanged"]) == 1
        assert len(result["changed"]) == 0
        assert len(result["new"]) == 0
        assert len(result["fixed"]) == 0

    def test_changed_severity(self) -> None:
        """Test detecting severity changes."""
        baseline = {"fp1": {"id": "F-1", "severity": "medium"}}
        current = {"fp1": {"id": "F-1", "severity": "high"}}
        result = classify(baseline, current)

        assert len(result["changed"]) == 1
        assert result["changed"][0]["severity_changed"] is True
        assert result["changed"][0]["triage_changed"] is False
        assert len(result["unchanged"]) == 0

    def test_changed_triage(self) -> None:
        """Test detecting triage changes."""
        baseline = {"fp1": {"id": "F-1", "severity": "high", "triage": "ACCEPT"}}
        current = {"fp1": {"id": "F-1", "severity": "high", "triage": "DOWNGRADE"}}
        result = classify(baseline, current)

        assert len(result["changed"]) == 1
        assert result["changed"][0]["severity_changed"] is False
        assert result["changed"][0]["triage_changed"] is True

    def test_both_changed(self) -> None:
        """Test detecting both severity and triage changes."""
        baseline = {"fp1": {"id": "F-1", "severity": "medium", "triage": "ACCEPT"}}
        current = {"fp1": {"id": "F-1", "severity": "high", "triage": "DOWNGRADE"}}
        result = classify(baseline, current)

        assert len(result["changed"]) == 1
        assert result["changed"][0]["severity_changed"] is True
        assert result["changed"][0]["triage_changed"] is True

    def test_empty_baseline(self) -> None:
        """Test with empty baseline."""
        baseline: dict = {}
        current = {"fp1": {"id": "F-1"}}
        result = classify(baseline, current)

        assert len(result["new"]) == 1
        assert len(result["fixed"]) == 0
        assert len(result["unchanged"]) == 0

    def test_empty_current(self) -> None:
        """Test with empty current."""
        baseline = {"fp1": {"id": "F-1"}}
        current: dict = {}
        result = classify(baseline, current)

        assert len(result["new"]) == 0
        assert len(result["fixed"]) == 1
        assert len(result["unchanged"]) == 0

    def test_multiple_changes(self) -> None:
        """Test complex scenario with multiple types of changes."""
        baseline = {
            "fp1": {"id": "F-1", "severity": "low"},  # unchanged
            "fp2": {"id": "F-2", "severity": "medium"},  # fixed
            "fp3": {"id": "F-3", "severity": "high"},  # changed severity
        }
        current = {
            "fp1": {"id": "F-1", "severity": "low"},
            "fp3": {"id": "F-3", "severity": "critical"},
            "fp4": {"id": "F-4", "severity": "medium"},  # new
        }
        result = classify(baseline, current)

        assert len(result["new"]) == 1
        assert result["new"][0]["id"] == "F-4"
        assert len(result["fixed"]) == 1
        assert result["fixed"][0]["id"] == "F-2"
        assert len(result["unchanged"]) == 1
        assert result["unchanged"][0]["id"] == "F-1"
        assert len(result["changed"]) == 1
        assert result["changed"][0]["current"]["id"] == "F-3"


class TestRenderMarkdown:
    """Test markdown rendering of diff results."""

    def test_render_summary(self) -> None:
        """Test summary section rendering."""
        delta = {
            "new": [{"id": "F-1"}],
            "fixed": [{"id": "F-2"}],
            "changed": [],
            "unchanged": [{"id": "F-3"}],
        }

        lines = [
            "# Findings Delta",
            "",
            "## Summary",
            "",
            f"- New:       **{len(delta['new'])}**",
            f"- Fixed:     **{len(delta['fixed'])}**",
            f"- Changed:   **{len(delta['changed'])}**",
            f"- Unchanged: **{len(delta['unchanged'])}**",
        ]

        content = "\n".join(lines)
        assert "New:       **1**" in content
        assert "Fixed:     **1**" in content
        assert "Changed:   **0**" in content
        assert "Unchanged: **1**" in content

    def test_render_new_findings(self) -> None:
        """Test new findings table rendering."""
        delta = {
            "new": [
                {
                    "id": "F-1",
                    "severity": "critical",
                    "triage": "ACCEPT",
                    "file": "test.py",
                    "line": 10,
                    "title": "SQL Injection",
                },
            ],
            "fixed": [],
            "changed": [],
            "unchanged": [],
        }

        assert len(delta["new"]) > 0
        assert delta["new"][0]["severity"] == "critical"

    def test_no_changes_message(self) -> None:
        """Test message when no changes detected."""
        delta = {"new": [], "fixed": [], "changed": [], "unchanged": []}

        assert not any(delta.values())
        assert len(delta["new"]) == 0
        assert len(delta["fixed"]) == 0
        assert len(delta["changed"]) == 0
