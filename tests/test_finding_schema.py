"""Tests for finding normalization and schema validation."""

from __future__ import annotations

from odoo_security_harness.finding_schema import normalize_finding, normalize_findings, validation_report, validate_findings


def test_normalize_finding_adds_export_contract_fields() -> None:
    """Scanner findings should gain fields required by downstream exports."""
    finding = normalize_finding(
        {
            "rule_id": "odoo-deep-public-sudo",
            "title": "Public route with sudo",
            "severity": "HIGH",
            "file": "controllers/main.py",
            "line": 10,
            "message": "route uses sudo",
        },
        1,
    )

    assert finding["id"] == "F-0001"
    assert finding["severity"] == "high"
    assert finding["triage"] == "NEEDS-MANUAL"
    assert finding["description"] == "route uses sudo"
    assert finding["fingerprint"].startswith("sha256:")


def test_normalize_finding_uses_repository_sentinel_for_empty_file() -> None:
    """Repository-level findings should still have an exportable location field."""
    finding = normalize_finding(
        {
            "rule_id": "odoo-acl-missing-sensitive",
            "title": "Missing ACL for sensitive model",
            "severity": "medium",
            "file": "",
            "line": 0,
            "message": "res.users has no ACL entry",
        },
        1,
    )

    assert finding["file"] == "<repository>"
    assert validate_findings([finding]) == []


def test_validate_findings_accepts_normalized_findings() -> None:
    """Normalized findings should pass the minimum schema check."""
    findings = normalize_findings(
        [
            {
                "rule_id": "odoo-qweb-t-raw",
                "title": "QWeb t-raw bypasses escaping",
                "severity": "medium",
                "file": "views/template.xml",
                "line": 4,
                "message": "t-raw renders raw HTML",
            }
        ]
    )

    assert validate_findings(findings) == []


def test_validate_findings_reports_bad_values() -> None:
    """Validation should surface malformed records with field names."""
    issues = validate_findings(
        [
            {
                "id": "F-1",
                "title": "Bad",
                "severity": "urgent",
                "triage": "MAYBE",
                "file": "",
                "line": "ten",
                "description": "",
                "fingerprint": "bad",
            }
        ]
    )

    fields = {issue.field for issue in issues}

    assert {"severity", "triage", "file", "line", "description", "fingerprint"} <= fields


def test_validation_report_is_json_serializable_shape() -> None:
    """Validation reports should summarize issue counts."""
    report = validation_report(
        normalize_findings(
            [
                {
                    "rule_id": "odoo-loose-python-safe-eval",
                    "title": "safe_eval in loose script",
                    "severity": "high",
                    "file": "docs/server_actions/action.py",
                    "line": 2,
                    "message": "safe_eval needs review",
                }
            ]
        )
    )

    assert report == {"valid": True, "finding_count": 1, "issue_count": 0, "issues": []}
