"""End-to-end eval harness for Odoo security scanners.

Runs deterministic scanners against intentionally vulnerable Odoo modules
and grades whether the expected security findings are detected.

These tests validate harness *capability* ("can we find this bug?").
Run with::

    pytest tests/eval_harness/ -v

Mark:: eval — excluded from default `make test` runs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.eval_harness.graders import (
    GraderResult,
    grader_line_accuracy,
    grader_minimum_severity,
    grader_no_false_positives_on_clean_module,
    grader_rule_id_present,
    grader_rule_ids_all_present,
)

EVAL_DIR = Path(__file__).parent
FIXTURES_DIR = Path(__file__).parent.parent.parent / "eval_fixtures"

# Rules that may legitimately appear in any minimal fixture module
COMMON_ALLOWED_RULES = {
    "odoo-acl-missing-sensitive",
    "odoo-manifest-missing-license",
    "odoo-manifest-missing-acl-data",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_scan(module_dir: Path) -> list[dict]:
    """Run odoo-deep-scan against a single module and return findings."""
    output = module_dir / ".eval_findings"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "odoo_security_harness.scripts.odoo_deep_scan",
            str(module_dir),
            "--out",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Scan crashed for {module_dir.name}: {result.stderr[:500]}"
    findings_file = output / "deep-scan-findings.json"
    with findings_file.open(encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data if isinstance(data, list) else data.get("findings", [])
    return findings


def _assert_grader(result: GraderResult) -> None:
    """Assert a grader passed, with a useful message on failure."""
    assert result.passed, result.message


# ---------------------------------------------------------------------------
# Task definitions: module -> expected findings
#
# These are derived from actual deep-scan runs against the fixtures.
# If a scanner heuristic changes, update the expected rules here.
# ---------------------------------------------------------------------------

TASKS: dict[str, dict] = {
    "vuln_sql_injection": {
        "description": "SQL injection via f-string and string concatenation in cr.execute()",
        "expected_rules": {
            "odoo-raw-sql-interpolated-query",
            "odoo-raw-sql-request-derived-input",
        },
        "line_hints": {
            "odoo-raw-sql-interpolated-query": 11,
            "odoo-raw-sql-request-derived-input": 11,
        },
        "minimum_severity": "high",
    },
    "vuln_xss_traw": {
        "description": "XSS via t-raw in QWeb and Markup(f-string) on user input",
        "expected_rules": {
            "odoo-qweb-t-raw",
            "odoo-deep-markup-fstring",
        },
        "line_hints": {
            "odoo-qweb-t-raw": 3,
            "odoo-deep-markup-fstring": 18,
        },
        "minimum_severity": "medium",
    },
    "vuln_sudo_bypass": {
        "description": "Access control bypass via sudo().search([]) and with_user(admin)",
        "expected_rules": {
            "odoo-deep-empty-search-sudo",
            "odoo-mc-sudo-search-no-company",
        },
        "line_hints": {
            "odoo-deep-empty-search-sudo": 10,
            "odoo-mc-sudo-search-no-company": 10,
        },
        "minimum_severity": "high",
    },
    "vuln_csrf_disabled": {
        "description": "CSRF protection disabled on HTTP and JSON routes",
        "expected_rules": {
            "odoo-route-unsafe-csrf-disabled",
            "odoo-json-route-csrf-disabled",
        },
        "line_hints": {
            "odoo-route-unsafe-csrf-disabled": 8,
            "odoo-json-route-csrf-disabled": 15,
        },
        "minimum_severity": "medium",
    },
    "vuln_idor_browse": {
        "description": "IDOR via browse() on user-controlled ID without access checks",
        "expected_rules": {
            "odoo-deep-portal-idor-sudo-browse",
        },
        "line_hints": {
            "odoo-deep-portal-idor-sudo-browse": 14,
        },
        "minimum_severity": "high",
    },
}

# ---------------------------------------------------------------------------
# Capability evals: can we find the expected bugs?
# ---------------------------------------------------------------------------


@pytest.mark.eval
@pytest.mark.parametrize("module_name,spec", TASKS.items())
def test_capability_finds_expected_rules(module_name: str, spec: dict) -> None:
    """Each vulnerable module must trigger its expected rule IDs."""
    module_dir = FIXTURES_DIR / module_name
    findings = _run_scan(module_dir)
    expected = set(spec["expected_rules"])
    _assert_grader(grader_rule_ids_all_present(expected, findings))


@pytest.mark.eval
@pytest.mark.parametrize("module_name,spec", TASKS.items())
def test_capability_line_accuracy(module_name: str, spec: dict) -> None:
    """Findings should be reported within 3 lines of the actual vulnerability."""
    module_dir = FIXTURES_DIR / module_name
    findings = _run_scan(module_dir)
    for rule_id, expected_line in spec.get("line_hints", {}).items():
        _assert_grader(grader_line_accuracy(rule_id, expected_line, findings, tolerance=3))


@pytest.mark.eval
@pytest.mark.parametrize("module_name,spec", TASKS.items())
def test_capability_minimum_severity(module_name: str, spec: dict) -> None:
    """Expected findings should meet the minimum severity threshold."""
    module_dir = FIXTURES_DIR / module_name
    findings = _run_scan(module_dir)
    min_sev = spec.get("minimum_severity", "medium")
    for rule_id in spec["expected_rules"]:
        _assert_grader(grader_minimum_severity(rule_id, min_sev, findings))


# ---------------------------------------------------------------------------
# Regression evals: clean modules should not produce false positives
# ---------------------------------------------------------------------------


@pytest.mark.eval
@pytest.mark.skip(reason="Clean-module fixtures not yet created")
def test_regression_no_false_positives_on_known_good_code() -> None:
    """A module with safe patterns should not produce unexpected findings."""
    # TODO: Create a fixture module with zero security bugs and scan it.
    # For now this test is skipped until clean fixtures are available.
    module_dir = FIXTURES_DIR / "clean_module"
    findings = _run_scan(module_dir)
    _assert_grader(grader_no_false_positives_on_clean_module(findings, allowed_rules=COMMON_ALLOWED_RULES))


# ---------------------------------------------------------------------------
# Meta tests
# ---------------------------------------------------------------------------


@pytest.mark.eval
def test_all_fixture_modules_exist() -> None:
    """Every task must have a corresponding fixture directory."""
    for module_name in TASKS:
        module_dir = FIXTURES_DIR / module_name
        assert module_dir.exists(), f"Fixture module missing: {module_dir}"
        manifest = module_dir / "__manifest__.py"
        assert manifest.exists(), f"Manifest missing: {manifest}"


@pytest.mark.eval
def test_eval_harness_graders_work() -> None:
    """Sanity-check that graders handle edge cases correctly."""
    findings = [
        {"rule_id": "odoo-test-rule", "line": 42, "severity": "high"},
    ]
    assert grader_rule_id_present("odoo-test-rule", findings)
    assert not grader_rule_id_present("odoo-missing", findings)
    assert grader_line_accuracy("odoo-test-rule", 42, findings, tolerance=3)
    assert not grader_line_accuracy("odoo-test-rule", 100, findings, tolerance=3)
    assert grader_minimum_severity("odoo-test-rule", "medium", findings)
    assert not grader_minimum_severity("odoo-test-rule", "critical", findings)
    assert grader_no_false_positives_on_clean_module([])
    assert not grader_no_false_positives_on_clean_module(findings)
