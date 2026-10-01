"""Tests for the auto-fix catalog."""

from __future__ import annotations

from odoo_security_harness.finding_schema import normalize_finding
from odoo_security_harness.fix_catalog import RULE_FIXES, get_fix_for_rule


class TestFixCatalog:
    def test_get_fix_returns_text_for_known_rule(self) -> None:
        fix = get_fix_for_rule("odoo-deep-raw-sql")
        assert fix is not None
        assert "parameterized" in fix.lower()

    def test_get_fix_returns_none_for_unknown_rule(self) -> None:
        assert get_fix_for_rule("odoo-unknown-rule-xyz") is None

    def test_csrf_fixes_do_not_recommend_switching_route_type(self) -> None:
        for rule_id in ("odoo-route-csrf-ignored-on-mutation", "odoo-deep-csrf-write"):
            fix = get_fix_for_rule(rule_id)

            assert fix is not None
            assert "switch" not in fix.lower()
            assert "hmac.compare_digest" in fix

    def test_all_fixes_are_non_empty_strings(self) -> None:
        for rule_id, fix in RULE_FIXES.items():
            assert isinstance(fix, str) and fix.strip(), f"Empty fix for {rule_id}"

    def test_normalize_finding_includes_fix(self) -> None:
        finding = {
            "rule_id": "odoo-deep-sudo-user-input",
            "title": "sudo() with user input",
            "severity": "high",
            "file": "test.py",
            "line": 10,
            "message": "message",
        }
        normalized = normalize_finding(finding, 1)
        assert "fix" in normalized
        assert "with_user" in normalized["fix"]

    def test_normalize_finding_preserves_existing_fix(self) -> None:
        finding = {
            "rule_id": "odoo-deep-sudo-user-input",
            "title": "sudo() with user input",
            "severity": "high",
            "file": "test.py",
            "line": 10,
            "message": "message",
            "fix": "custom fix text",
        }
        normalized = normalize_finding(finding, 1)
        assert normalized["fix"] == "custom fix text"

    def test_normalize_finding_no_fix_for_unknown_rule(self) -> None:
        finding = {
            "rule_id": "odoo-unknown-rule",
            "title": "Unknown",
            "severity": "medium",
            "file": "test.py",
            "line": 1,
            "message": "message",
        }
        normalized = normalize_finding(finding, 1)
        assert "fix" not in normalized
