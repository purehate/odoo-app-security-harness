"""Tests for automated PoC generation."""

from __future__ import annotations

import os
from pathlib import Path

from odoo_security_harness.poc_generator import PoCGenerator, generate_pocs, poc_coverage_report, poc_to_markdown


def test_public_route_finding_generates_curl_poc(tmp_path: Path) -> None:
    """Public route findings should produce a curl-based route probe."""
    controller = tmp_path / "controllers" / "main.py"
    controller.parent.mkdir()
    controller.write_text(
        """
from odoo import http

class TestController(http.Controller):
    @http.route('/public/orders', auth='public')
    def orders(self):
        return 'ok'
""",
        encoding="utf-8",
    )

    generator = PoCGenerator(base_url="http://odoo.test")
    poc = generator.generate_for_finding(
        {
            "id": "F-001",
            "rule_id": "odoo-deep-public-write-route",
            "title": "Public route performs state-changing ORM operation",
            "file": str(controller),
            "line": 6,
        }
    )

    assert poc is not None
    assert poc.method == "curl"
    assert "http://odoo.test/public/orders" in poc.script


def test_sql_finding_generates_python_payloads() -> None:
    """SQL findings should produce manual SQLi payload guidance."""
    poc = PoCGenerator().generate_for_finding(
        {
            "id": "F-002",
            "rule_id": "odoo-deep-sql-built-query-var",
            "title": "SQL query variable built unsafely",
        }
    )

    assert poc is not None
    assert poc.method == "python"
    assert "' OR '1'='1" in poc.script


def test_generate_pocs_writes_executable_scripts(tmp_path: Path) -> None:
    """Generated shell and Python PoCs should be written with executable bits."""
    generated = generate_pocs(
        [
            {
                "id": "F-003",
                "rule_id": "odoo-deep-sql-fstring",
                "title": "SQL query built with f-string",
            },
            {
                "id": "F-004",
                "rule_id": "odoo-qweb-t-raw",
                "title": "QWeb t-raw bypasses escaping",
            },
        ],
        tmp_path,
    )

    assert {path.name for path in generated} == {"poc-F-003.py", "poc-F-004.sh"}
    assert all(os.access(path, os.X_OK) for path in generated)


def test_generate_pocs_uses_configured_target(tmp_path: Path) -> None:
    """Generated scripts should honor caller-provided target settings."""
    generated = generate_pocs(
        [{"id": "F-010", "rule_id": "odoo-deep-sql-fstring", "title": "SQL query built with f-string"}],
        tmp_path,
        base_url="https://review.example",
        database="prod-review",
    )

    script = generated[0].read_text(encoding="utf-8")
    assert 'url = "https://review.example"' in script
    assert 'db = "prod-review"' in script


def test_generate_pocs_assigns_unique_ids_when_missing(tmp_path: Path) -> None:
    """Scanner findings without IDs should not overwrite each other's PoCs."""
    generated = generate_pocs(
        [
            {"rule_id": "odoo-deep-sql-fstring", "title": "SQL query built with f-string"},
            {"rule_id": "odoo-deep-sql-format", "title": "SQL query built with .format()"},
        ],
        tmp_path,
    )

    assert [path.name for path in generated] == [
        "poc-0001-odoo-deep-sql-fstring.py",
        "poc-0002-odoo-deep-sql-format.py",
    ]
    assert generated[0].read_text(encoding="utf-8") != generated[1].read_text(encoding="utf-8")


def test_poc_coverage_report_counts_supported_and_unsupported_findings() -> None:
    """PoC coverage should make unsupported finding classes visible."""
    report = poc_coverage_report(
        [
            {"id": "F-001", "rule_id": "odoo-deep-sql-fstring", "title": "SQL query built with f-string"},
            {"id": "F-002", "rule_id": "odoo-custom-review-only", "title": "Manual review finding"},
            {"rule_id": "odoo-qweb-t-raw", "title": "QWeb t-raw bypasses escaping"},
        ]
    )

    assert report["total_findings"] == 3
    assert report["generated_pocs"] == 2
    assert report["coverage_ratio"] == 0.6667
    assert report["unsupported_findings"] == [
        {
            "id": "F-002",
            "rule_id": "odoo-custom-review-only",
            "title": "Manual review finding",
            "file": "",
            "line": 0,
        }
    ]
    assert {
        (entry["rule_id"], entry["findings"], entry["generated_pocs"], entry["unsupported_findings"])
        for entry in report["rules"]
    } == {
        ("odoo-custom-review-only", 1, 0, 1),
        ("odoo-deep-sql-fstring", 1, 1, 0),
        ("odoo-qweb-t-raw", 1, 1, 0),
    }


def test_poc_markdown_includes_prerequisites() -> None:
    """PoC markdown should preserve reproduction context."""
    poc = PoCGenerator().generate_for_finding(
        {
            "id": "F-005",
            "rule_id": "odoo-deep-safe-eval-user-input",
            "title": "safe_eval with user input",
        }
    )

    assert poc is not None
    markdown = poc_to_markdown(poc)

    assert "## safe_eval PoC" in markdown
    assert "### Prerequisites" in markdown
    assert "Vulnerable endpoint" in markdown
