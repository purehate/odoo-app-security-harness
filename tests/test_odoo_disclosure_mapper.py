"""Tests for Odoo Responsible Disclosure Policy mapper."""

from __future__ import annotations

from odoo_security_harness.odoo_disclosure_mapper import (
    classify_finding,
    disclosure_summary,
)


def test_sql_injection_is_qualifying() -> None:
    """SQL injection in public APIs is explicitly qualifying."""
    result = classify_finding({"rule_id": "odoo-raw-sql-injection", "severity": "critical"})
    assert result.eligibility == "qualifying"
    assert result.category == "sql_injection"
    assert "SQL injection" in result.odoo_policy_section


def test_xss_via_t_raw_is_qualifying() -> None:
    """XSS in supported browsers is qualifying."""
    result = classify_finding({"rule_id": "odoo-qweb-t-raw", "severity": "high"})
    assert result.eligibility == "qualifying"
    assert result.category == "xss"


def test_open_redirect_is_non_qualifying() -> None:
    """Odoo explicitly lists open redirects as non-qualifying."""
    result = classify_finding({"rule_id": "odoo-action-url-open-redirect", "severity": "medium"})
    assert result.eligibility == "non_qualifying"
    assert result.category == "open_redirect"
    assert "Do not report to Odoo" in result.recommendation


def test_user_enumeration_is_non_qualifying() -> None:
    """User enumeration is explicitly non-qualifying."""
    result = classify_finding({"rule_id": "odoo-user-enumeration", "severity": "low"})
    assert result.eligibility == "non_qualifying"
    assert result.category == "user_enumeration"


def test_missing_hsts_is_non_qualifying() -> None:
    """Missing HSTS is non-qualifying per Odoo policy."""
    result = classify_finding({"rule_id": "odoo-deploy-missing-hsts", "severity": "low"})
    assert result.eligibility == "non_qualifying"
    assert result.category == "missing_hsts"


def test_unknown_rule_returns_unknown() -> None:
    """Unmapped rules should return unknown, not crash."""
    result = classify_finding({"rule_id": "odoo-custom-internal-rule", "severity": "medium"})
    assert result.eligibility == "unknown"
    assert "not yet mapped" in result.reason


def test_summary_buckets_correctly() -> None:
    """disclosure_summary should partition findings into correct buckets."""
    findings = [
        {"rule_id": "odoo-raw-sql-injection", "severity": "critical", "title": "SQLi"},
        {"rule_id": "odoo-qweb-t-raw", "severity": "high", "title": "XSS"},
        {"rule_id": "odoo-action-url-open-redirect", "severity": "medium", "title": "Redirect"},
        {"rule_id": "odoo-user-enumeration", "severity": "low", "title": "Enum"},
        {"rule_id": "odoo-custom-internal-rule", "severity": "info", "title": "Custom"},
    ]
    summary = disclosure_summary(findings)
    assert summary["qualifying_count"] == 2
    assert summary["non_qualifying_count"] == 2
    assert summary["unknown_count"] == 1
    assert summary["borderline_count"] == 0
    assert summary["total"] == 5
