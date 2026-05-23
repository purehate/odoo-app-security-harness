"""Tests for candidate ledger builder and hunter lane filter."""
from __future__ import annotations

from pathlib import Path

import pytest

from odoo_security_harness.candidate_ledger import (
    CandidateRecord,
    _is_sharp_edge_file,
    build_candidate_ledger,
    filter_files_for_hunters,
    ledger_summary,
)


# ---------------------------------------------------------------------------
# _is_sharp_edge_file
# ---------------------------------------------------------------------------

def test_sharp_edge_controller_file(tmp_path: Path) -> None:
    ctrl = tmp_path / "controllers" / "main.py"
    ctrl.parent.mkdir(parents=True)
    ctrl.write_text("from odoo import http\n", encoding="utf-8")
    is_sharp, reasons = _is_sharp_edge_file(ctrl)
    assert is_sharp
    assert any("directory:controllers" in r for r in reasons)


def test_sharp_edge_model_with_sudo(tmp_path: Path) -> None:
    model = tmp_path / "models" / "partner.py"
    model.parent.mkdir(parents=True)
    model.write_text("self.sudo().search([])\n", encoding="utf-8")
    is_sharp, reasons = _is_sharp_edge_file(model)
    assert is_sharp
    assert any("keywords" in r for r in reasons)


def test_sharp_edge_xml_with_traw(tmp_path: Path) -> None:
    tmpl = tmp_path / "views" / "template.xml"
    tmpl.parent.mkdir(parents=True)
    tmpl.write_text('<span t-raw="body"/>\n', encoding="utf-8")
    is_sharp, reasons = _is_sharp_edge_file(tmpl)
    assert is_sharp
    assert any("keywords" in r for r in reasons)


def test_not_sharp_edge_init_file(tmp_path: Path) -> None:
    init = tmp_path / "__init__.py"
    init.write_text("# empty\n", encoding="utf-8")
    is_sharp, reasons = _is_sharp_edge_file(init)
    assert not is_sharp
    assert reasons == []


def test_not_sharp_edge_utils_file(tmp_path: Path) -> None:
    utils = tmp_path / "utils.py"
    utils.write_text("def helper(): pass\n", encoding="utf-8")
    is_sharp, reasons = _is_sharp_edge_file(utils)
    assert not is_sharp
    assert reasons == []


# ---------------------------------------------------------------------------
# build_candidate_ledger
# ---------------------------------------------------------------------------

def test_ledger_skips_file_with_zero_findings_and_no_sharp_edge(tmp_path: Path) -> None:
    utils = tmp_path / "utils.py"
    utils.write_text("def helper(): pass\n", encoding="utf-8")
    ledger = build_candidate_ledger(tmp_path, [])
    assert len(ledger) == 1
    record = ledger[0]
    assert record.skip_for_hunters is True
    assert record.skip_reason == "zero_findings_no_sharp_edge"


def test_ledger_includes_sharp_edge_file_even_with_zero_findings(tmp_path: Path) -> None:
    ctrl = tmp_path / "controllers" / "main.py"
    ctrl.parent.mkdir(parents=True)
    ctrl.write_text("from odoo import http\n", encoding="utf-8")
    ledger = build_candidate_ledger(tmp_path, [])
    assert len(ledger) == 1
    record = ledger[0]
    assert record.sharp_edge is True
    assert record.skip_for_hunters is False


def test_ledger_includes_file_with_findings(tmp_path: Path) -> None:
    utils = tmp_path / "utils.py"
    utils.write_text("def helper(): pass\n", encoding="utf-8")
    findings = [
        {
            "rule_id": "odoo-test-rule",
            "severity": "medium",
            "file": str(utils),
            "line": 1,
            "source": "test",
        }
    ]
    ledger = build_candidate_ledger(tmp_path, findings)
    assert len(ledger) == 1
    record = ledger[0]
    assert record.findings_count == 1
    assert record.noise_tier == "medium"
    assert record.skip_for_hunters is False


def test_ledger_noise_tiers(tmp_path: Path) -> None:
    files = {
        "info.py": "pass",
        "low.py": "pass",
        "medium.py": "pass",
        "high.py": "pass",
        "critical.py": "pass",
    }
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")

    findings = [
        {"rule_id": "r1", "severity": "info", "file": str(tmp_path / "info.py"), "line": 1, "source": "test"},
        {"rule_id": "r2", "severity": "low", "file": str(tmp_path / "low.py"), "line": 1, "source": "test"},
        {"rule_id": "r3", "severity": "medium", "file": str(tmp_path / "medium.py"), "line": 1, "source": "test"},
        {"rule_id": "r4", "severity": "high", "file": str(tmp_path / "high.py"), "line": 1, "source": "test"},
        {"rule_id": "r5", "severity": "critical", "file": str(tmp_path / "critical.py"), "line": 1, "source": "test"},
    ]
    ledger = build_candidate_ledger(tmp_path, findings)
    tiers = {r.file: r.noise_tier for r in ledger}
    assert tiers["info.py"] == "silent"
    assert tiers["low.py"] == "low"
    assert tiers["medium.py"] == "medium"
    assert tiers["high.py"] == "high"
    assert tiers["critical.py"] == "critical"


def test_ledger_ignores_tests_directory(tmp_path: Path) -> None:
    test_file = tmp_path / "tests" / "test_foo.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("def test_foo(): pass\n", encoding="utf-8")
    ledger = build_candidate_ledger(tmp_path, [])
    assert len(ledger) == 0


def test_ledger_multiple_files_mixed(tmp_path: Path) -> None:
    """Complex case: some files sharp, some with findings, some plain."""
    (tmp_path / "plain.py").write_text("pass\n", encoding="utf-8")
    ctrl = tmp_path / "controllers" / "main.py"
    ctrl.parent.mkdir(parents=True)
    ctrl.write_text("from odoo import http\n", encoding="utf-8")
    model = tmp_path / "models" / "partner.py"
    model.parent.mkdir(parents=True)
    model.write_text("pass\n", encoding="utf-8")

    findings = [
        {"rule_id": "r1", "severity": "high", "file": str(model), "line": 1, "source": "test"},
    ]
    ledger = build_candidate_ledger(tmp_path, findings)
    by_file = {r.file: r for r in ledger}

    assert by_file["plain.py"].skip_for_hunters is True
    assert by_file["controllers/main.py"].sharp_edge is True
    assert by_file["controllers/main.py"].skip_for_hunters is False
    assert by_file["models/partner.py"].findings_count == 1
    assert by_file["models/partner.py"].skip_for_hunters is False


# ---------------------------------------------------------------------------
# filter_files_for_hunters
# ---------------------------------------------------------------------------

def test_filter_skips_plain_files_keeps_sharp_and_findings(tmp_path: Path) -> None:
    ledger = build_candidate_ledger(tmp_path, [])
    # No files -> empty result
    assert filter_files_for_hunters(ledger) == []


def test_filter_respects_min_noise_tier(tmp_path: Path) -> None:
    (tmp_path / "info.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "low.py").write_text("pass\n", encoding="utf-8")

    findings = [
        {"rule_id": "r1", "severity": "info", "file": str(tmp_path / "info.py"), "line": 1, "source": "test"},
        {"rule_id": "r2", "severity": "low", "file": str(tmp_path / "low.py"), "line": 1, "source": "test"},
    ]
    ledger = build_candidate_ledger(tmp_path, findings)

    # min_noise_tier=low: info-only file skipped, low file kept
    result = filter_files_for_hunters(ledger, min_noise_tier="low")
    assert "low.py" in result
    assert "info.py" not in result

    # min_noise_tier=medium: both skipped (no sharp edge)
    result = filter_files_for_hunters(ledger, min_noise_tier="medium")
    assert result == []


def test_filter_keeps_sharp_edge_even_below_tier(tmp_path: Path) -> None:
    ctrl = tmp_path / "controllers" / "main.py"
    ctrl.parent.mkdir(parents=True)
    ctrl.write_text("from odoo import http\n", encoding="utf-8")
    ledger = build_candidate_ledger(tmp_path, [])
    result = filter_files_for_hunters(ledger, min_noise_tier="high")
    assert "controllers/main.py" in result


# ---------------------------------------------------------------------------
# ledger_summary
# ---------------------------------------------------------------------------

def test_summary_counts_are_accurate(tmp_path: Path) -> None:
    (tmp_path / "plain.py").write_text("pass\n", encoding="utf-8")
    ctrl = tmp_path / "controllers" / "main.py"
    ctrl.parent.mkdir(parents=True)
    ctrl.write_text("from odoo import http\n", encoding="utf-8")
    model = tmp_path / "models" / "partner.py"
    model.parent.mkdir(parents=True)
    model.write_text("pass\n", encoding="utf-8")

    findings = [
        {"rule_id": "r1", "severity": "high", "file": str(model), "line": 1, "source": "test"},
    ]
    ledger = build_candidate_ledger(tmp_path, findings)
    summary = ledger_summary(ledger)

    assert summary["total_files"] == 3
    assert summary["skipped_for_hunters"] == 1  # plain.py
    assert summary["sharp_edge_files"] == 2     # controllers + models dirs
    assert summary["files_with_findings"] == 1
    assert summary["hunter_eligible_files"] == 2
    assert "entries" in summary
    assert isinstance(summary["entries"], list)


# ---------------------------------------------------------------------------
# CandidateRecord serialization
# ---------------------------------------------------------------------------

def test_record_to_dict() -> None:
    record = CandidateRecord(
        file="controllers/main.py",
        findings_count=2,
        rule_ids=["odoo-r1", "odoo-r2"],
        sources=["scanner-a"],
        severities=["high", "medium"],
        max_severity="high",
        noise_tier="high",
        sharp_edge=True,
        sharp_edge_reasons=["directory:controllers"],
        skip_for_hunters=False,
        skip_reason="",
    )
    d = record.to_dict()
    assert d["file"] == "controllers/main.py"
    assert d["findings_count"] == 2
    assert d["max_severity"] == "high"
    assert d["noise_tier"] == "high"
    assert d["sharp_edge"] is True
    assert d["skip_for_hunters"] is False
