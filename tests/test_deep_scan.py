"""End-to-end tests for the deep scan CLI module."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from odoo_security_harness.scripts import odoo_deep_scan


def _exported_deep_scan_callables() -> set[str]:
    init_tree = ast.parse(Path("odoo_security_harness/__init__.py").read_text(encoding="utf-8"))
    exported: set[str] = set()
    for node in ast.walk(init_tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        exported = {
            element.value
            for element in node.value.elts
            if isinstance(element, ast.Constant)
            and isinstance(element.value, str)
            and (
                element.value.startswith("scan_")
                or element.value in {"analyze_access_control", "analyze_directory", "check_multi_company_isolation"}
            )
        }
    return exported


def test_deep_scan_calls_every_exported_scanner() -> None:
    """The comprehensive CLI should not drift from the public scanner registry."""
    deep_scan_tree = ast.parse(Path("odoo_security_harness/scripts/odoo_deep_scan.py").read_text(encoding="utf-8"))
    called = {
        node.func.id
        for node in ast.walk(deep_scan_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert _exported_deep_scan_callables() <= called


def test_scanner_source_coverage_flags_zero_and_unexpected_sources(monkeypatch) -> None:
    """Source coverage should make inactive or misspelled scanner sources visible."""
    monkeypatch.setattr(
        odoo_deep_scan,
        "_deep_scan_source_counts",
        lambda: {"active-source": 1, "silent-source": 1, "duplicate-source": 2},
    )

    scanner_sources = odoo_deep_scan._source_coverage(
        [
            {"source": "active-source"},
            {"source": "duplicate-source"},
            {"source": "unexpected-source"},
        ]
    )
    warnings = odoo_deep_scan._source_warnings(scanner_sources)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": scanner_sources,
        }
    )

    assert scanner_sources["total_sources"] == 3
    assert scanner_sources["sources_with_findings"] == 2
    assert scanner_sources["zero_finding_sources"] == ["silent-source"]
    assert scanner_sources["unexpected_sources"] == ["unexpected-source"]
    assert scanner_sources["duplicate_expected_sources"] == ["duplicate-source"]
    assert "No findings were produced by scanner sources: silent-source." in warnings
    assert "Findings used unexpected scanner sources: unexpected-source." in warnings
    assert "Scanner source labels are reused in deep scan: duplicate-source." in warnings
    assert "| active-source | 1 |" in tooling
    assert "| duplicate-source | 1 |" in tooling
    assert "| silent-source | 0 |" in tooling
    assert "| unexpected-source | 1 |" in tooling


def test_scanner_registry_coverage_flags_missing_exported_callables(monkeypatch) -> None:
    """Registry coverage should expose exported scanners omitted from the deep scan."""
    monkeypatch.setattr(
        odoo_deep_scan,
        "_exported_deep_scan_callables",
        lambda: {"scan_active", "scan_missing"},
    )
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_called_callables", lambda: {"scan_active"})
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_source_counts", lambda: {"active-source": 1})
    monkeypatch.setattr(
        odoo_deep_scan,
        "_deep_scan_manifest",
        lambda: [{"callable": "scan_active", "source": "active-source", "line": 1}],
    )

    scanner_registry = odoo_deep_scan._scanner_registry_coverage()
    warnings = odoo_deep_scan._registry_warnings(scanner_registry)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": {"entries": []},
            "scanner_registry": scanner_registry,
        }
    )

    assert scanner_registry["total_exported"] == 2
    assert scanner_registry["wired_exported"] == 1
    assert scanner_registry["source_labels"] == 1
    assert scanner_registry["source_labels_match_wired"] is True
    assert scanner_registry["missing_from_deep_scan"] == ["scan_missing"]
    assert scanner_registry["callables_without_source"] == []
    assert scanner_registry["sources_without_callable"] == []
    assert warnings == ["Exported scanner callables missing from deep scan: scan_missing."]
    assert "Scanner Registry" in tooling
    assert "Missing from deep scan: scan_missing" in tooling


def test_scanner_registry_coverage_flags_source_callable_count_mismatch(monkeypatch) -> None:
    """Registry coverage should expose unlabeled or extra-labeled scanner runs."""
    monkeypatch.setattr(odoo_deep_scan, "_exported_deep_scan_callables", lambda: {"scan_one", "scan_two"})
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_called_callables", lambda: {"scan_one", "scan_two"})
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_source_counts", lambda: {"only-source": 1})
    monkeypatch.setattr(
        odoo_deep_scan, "_deep_scan_manifest", lambda: [{"callable": "scan_one", "source": "only-source", "line": 1}]
    )

    scanner_registry = odoo_deep_scan._scanner_registry_coverage()
    warnings = odoo_deep_scan._registry_warnings(scanner_registry)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": {"entries": []},
            "scanner_registry": scanner_registry,
        }
    )

    assert scanner_registry["wired_exported"] == 2
    assert scanner_registry["source_labels"] == 1
    assert scanner_registry["source_labels_match_wired"] is False
    assert scanner_registry["callables_without_source"] == ["scan_two"]
    assert scanner_registry["sources_without_callable"] == []
    assert warnings == [
        "Scanner source labels do not match wired callables: 1 source labels for 2 wired callables.",
        "Wired scanner callables without source labels: scan_two.",
    ]
    assert "Scanner source labels: 1" in tooling
    assert "Callables without source: scan_two" in tooling


def test_scanner_registry_coverage_flags_sources_without_callables(monkeypatch) -> None:
    """Registry coverage should expose source labels that cannot be tied to scanner calls."""
    monkeypatch.setattr(odoo_deep_scan, "_exported_deep_scan_callables", lambda: {"scan_one"})
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_called_callables", lambda: {"scan_one"})
    monkeypatch.setattr(odoo_deep_scan, "_deep_scan_source_counts", lambda: {"mapped-source": 1, "orphan-source": 1})
    monkeypatch.setattr(
        odoo_deep_scan, "_deep_scan_manifest", lambda: [{"callable": "scan_one", "source": "mapped-source", "line": 1}]
    )

    scanner_registry = odoo_deep_scan._scanner_registry_coverage()
    warnings = odoo_deep_scan._registry_warnings(scanner_registry)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": {"entries": []},
            "scanner_registry": scanner_registry,
        }
    )

    assert scanner_registry["callables_without_source"] == []
    assert scanner_registry["sources_without_callable"] == ["orphan-source"]
    assert "Scanner source labels without wired callables: orphan-source." in warnings
    assert "Sources without callable: orphan-source" in tooling


def test_rule_catalog_coverage_flags_undocumented_rule_ids(monkeypatch) -> None:
    """Rule catalog coverage should expose finding rule IDs missing from harness source."""
    monkeypatch.setattr(
        odoo_deep_scan,
        "_rule_catalog",
        lambda: [
            {"rule_id": "odoo-known-rule", "file": "odoo_security_harness/known.py", "line": 10},
            {"rule_id": "odoo-silent-rule", "file": "odoo_security_harness/silent.py", "line": 20},
        ],
    )

    catalog = odoo_deep_scan._rule_catalog_coverage(
        [
            {"rule_id": "odoo-known-rule"},
            {"rule_id": "odoo-known-rule"},
            {"rule_id": "odoo-undocumented-rule"},
        ]
    )
    warnings = odoo_deep_scan._rule_catalog_warnings(catalog)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": {"entries": []},
            "scanner_registry": {},
            "rule_catalog": catalog,
        }
    )

    assert catalog["total_rules"] == 2
    assert catalog["total_occurrences"] == 2
    assert catalog["emitted_rules"] == 2
    assert catalog["unemitted_rules"] == ["odoo-silent-rule"]
    assert catalog["undocumented_rule_ids"] == ["odoo-undocumented-rule"]
    assert "Findings used undocumented rule IDs: odoo-undocumented-rule." in warnings
    assert "Rule Catalog" in tooling
    assert "Declared rule IDs: 2" in tooling
    assert "Findings with undocumented rule IDs: odoo-undocumented-rule" in tooling


def test_finding_summary_prioritizes_sources_and_rules_by_severity() -> None:
    """Finding summary should preserve severity mix and prioritize review hotspots."""
    summary = odoo_deep_scan._finding_summary(
        [
            {"source": "low-volume", "rule_id": "odoo-low", "severity": "low"},
            {"source": "critical-source", "rule_id": "odoo-critical", "severity": "critical"},
            {"source": "critical-source", "rule_id": "odoo-critical", "severity": "high"},
            {"source": "medium-source", "rule_id": "odoo-medium", "severity": "medium"},
            {"source": "unknown-severity", "rule_id": "odoo-unknown", "severity": "unexpected"},
        ]
    )
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": [],
            "scanner_sources": {"entries": []},
            "scanner_registry": {},
            "rule_catalog": {},
            "finding_summary": summary,
        }
    )

    assert summary["total_findings"] == 5
    assert summary["severity_counts"] == {"critical": 1, "high": 1, "medium": 2, "low": 1, "info": 0}
    assert summary["sources"][0]["source"] == "critical-source"
    assert summary["sources"][0]["max_severity"] == "critical"
    assert summary["top_rules"][0]["rule_id"] == "odoo-critical"
    assert summary["top_rules"][0]["findings"] == 2
    assert "Finding Summary" in tooling
    assert "Severity mix: critical=1, high=1, medium=2, low=1, info=0" in tooling
    assert "| critical-source | 1 | 1 | 0 | 0 | 0 | 2 |" in tooling
    assert "| odoo-critical | 2 | critical |" in tooling


def test_review_gate_blocks_at_configured_threshold() -> None:
    """Review gate should expose CI-blocking findings without hiding lower severity noise."""
    findings = [
        {
            "id": "F-1",
            "source": "route-security",
            "rule_id": "odoo-critical",
            "severity": "critical",
            "file": "controllers/main.py",
            "line": 10,
            "title": "Critical finding",
            "fingerprint": "sha256:critical",
        },
        {
            "id": "F-2",
            "source": "qweb",
            "rule_id": "odoo-medium",
            "severity": "medium",
            "file": "views/template.xml",
            "line": 20,
            "title": "Medium finding",
            "fingerprint": "sha256:medium",
        },
        {
            "id": "F-3",
            "source": "manifest",
            "rule_id": "odoo-low",
            "severity": "low",
            "file": "__manifest__.py",
            "line": 1,
            "title": "Low finding",
            "fingerprint": "sha256:low",
        },
    ]

    gate = odoo_deep_scan.build_review_gate(findings, fail_on="medium")

    assert gate["passed"] is False
    assert gate["blocking_findings"] == 2
    assert gate["severity_counts"] == {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0}
    assert gate["blocking_severity_counts"] == {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0}
    assert [finding["id"] for finding in gate["blocking"]] == ["F-1", "F-2"]
    assert odoo_deep_scan.build_review_gate(findings, fail_on="none")["passed"] is True


def test_taxonomy_gate_blocks_unmapped_rule_ids_when_enabled() -> None:
    """Taxonomy gate should be opt-in and expose unmapped emitted rule IDs."""
    taxonomy_coverage = {
        "total_emitted_rules": 3,
        "mapped_rules": 1,
        "unmapped_rules": 2,
        "coverage_ratio": 0.3333,
        "unmapped_rule_ids": ["odoo-new-beta", "odoo-new-alpha"],
    }

    disabled = odoo_deep_scan.build_taxonomy_gate(taxonomy_coverage)
    enabled = odoo_deep_scan.build_taxonomy_gate(taxonomy_coverage, fail_on_unmapped=True)

    assert disabled["passed"] is True
    assert disabled["blocking_rules"] == 0
    assert enabled["passed"] is False
    assert enabled["blocking_rules"] == 2
    assert enabled["blocking_rule_ids"] == ["odoo-new-alpha", "odoo-new-beta"]


def test_baseline_delta_and_gate_classify_new_fixed_changed_findings() -> None:
    """Baseline delta should classify fingerprint changes and gate only new threshold hits."""
    baseline = [
        {
            "id": "B-1",
            "fingerprint": "sha256:" + "1" * 64,
            "rule_id": "odoo-existing",
            "severity": "medium",
            "triage": "NEEDS-MANUAL",
            "file": "models.py",
            "line": 10,
            "title": "Existing",
        },
        {
            "id": "B-2",
            "fingerprint": "sha256:" + "2" * 64,
            "rule_id": "odoo-fixed",
            "severity": "high",
            "triage": "NEEDS-MANUAL",
            "file": "fixed.py",
            "line": 20,
            "title": "Fixed",
        },
    ]
    current = [
        {
            "id": "F-1",
            "fingerprint": "sha256:" + "1" * 64,
            "rule_id": "odoo-existing",
            "severity": "high",
            "triage": "NEEDS-MANUAL",
            "file": "models.py",
            "line": 10,
            "title": "Existing",
        },
        {
            "id": "F-2",
            "fingerprint": "sha256:" + "3" * 64,
            "rule_id": "odoo-new",
            "severity": "critical",
            "triage": "NEEDS-MANUAL",
            "file": "new.py",
            "line": 30,
            "title": "New",
        },
    ]

    delta = odoo_deep_scan.build_baseline_delta(baseline, current)
    gate = odoo_deep_scan.build_baseline_gate(delta, fail_on_new="high")
    report = odoo_deep_scan.generate_baseline_delta_report(delta, gate)

    assert delta["new_count"] == 1
    assert delta["fixed_count"] == 1
    assert delta["changed_count"] == 1
    assert delta["unchanged_count"] == 0
    assert gate["passed"] is False
    assert gate["blocking_new_findings"] == 1
    assert gate["blocking"][0]["rule_id"] == "odoo-new"
    assert "Deep Scan Baseline Delta" in report
    assert "| critical | odoo-new | new.py | 30 | New |" in report


def test_accepted_risks_suppress_active_and_annotate_expired(tmp_path: Path) -> None:
    """Accepted-risk matching should suppress active entries but keep expired matches visible."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")
    active_finding = {
        "id": "F-1",
        "fingerprint": "sha256:" + "1" * 64,
        "rule_id": "odoo-active",
        "severity": "high",
        "triage": "NEEDS-MANUAL",
        "file": str(repo / "controllers.py"),
        "line": 1,
        "title": "Active accepted risk",
    }
    expired_finding = {
        "id": "F-2",
        "fingerprint": "sha256:" + "2" * 64,
        "rule_id": "odoo-expired",
        "severity": "medium",
        "triage": "NEEDS-MANUAL",
        "file": str(repo / "controllers.py"),
        "line": 1,
        "title": "Expired accepted risk",
    }
    inventory = {
        "loaded_from": str(repo / ".audit-accepted-risks.yml"),
        "active": [{"id": "AR-001", "fingerprint": "1" * 16, "expires": "2099-01-01"}],
        "expired": [{"id": "AR-002", "fingerprint": "2" * 16, "expires": "2000-01-01"}],
        "errors": [],
    }

    report = odoo_deep_scan.apply_accepted_risks(repo, [active_finding, expired_finding], inventory)
    markdown = odoo_deep_scan.generate_accepted_risks_report(report)

    assert len(report["findings"]) == 1
    assert report["findings"][0]["rule_id"] == "odoo-expired"
    assert report["findings"][0]["expired_accepted_risk_ids"] == ["AR-002"]
    assert report["summary"]["suppressed_findings"] == 1
    assert report["summary"]["expired_matches"] == 1
    assert "Suppressed Findings" in markdown
    assert "AR-001" in markdown


def test_fix_list_tags_regressions_and_likely_fixed(tmp_path: Path) -> None:
    """Fix-list tracking should tag present bugs and reconcile missing entries."""
    repo = tmp_path / "repo"
    repo.mkdir()
    finding = {
        "id": "F-1",
        "fingerprint": "sha256:" + "1" * 64,
        "rule_id": "odoo-regression",
        "severity": "high",
        "triage": "NEEDS-MANUAL",
        "file": str(repo / "models.py"),
        "line": 1,
        "title": "Regression",
    }
    inventory = {
        "loaded_from": str(repo / ".audit-fix-list.yml"),
        "active": [
            {
                "id": "FIX-001",
                "fingerprint": "1" * 16,
                "status": "fixed",
                "severity": "high",
                "owner": "security@example.com",
                "title": "Regression canary",
            },
            {
                "id": "FIX-002",
                "fingerprint": "2" * 16,
                "status": "open",
                "severity": "medium",
                "owner": "security@example.com",
                "title": "Gone finding",
                "target_date": "2099-01-01",
            },
        ],
        "errors": [],
    }

    report = odoo_deep_scan.apply_fix_list(repo, [finding], inventory)
    markdown = odoo_deep_scan.generate_fix_list_report(report)

    assert report["findings"][0]["fix_list_status"] == "regression"
    assert report["findings"][0]["fix_list_id"] == "FIX-001"
    assert report["summary"]["regressions"] == 1
    assert report["summary"]["likely_fixed"] == 1
    assert report["inventory"]["buckets"]["likely_fixed"][0]["id"] == "FIX-002"
    assert "Regressions" in markdown
    assert "FIX-001" in markdown


def test_governance_gate_blocks_enabled_policy_rot() -> None:
    """Governance gate should only block enabled accepted-risk and fix-list conditions."""
    accepted = {"errors": 1, "expired_entries": 2, "expired_matches": 1}
    fixes = {"errors": 0, "overdue": 3, "regressions": 1}

    disabled = odoo_deep_scan.build_governance_gate(accepted, fixes)
    enabled = odoo_deep_scan.build_governance_gate(
        accepted,
        fixes,
        fail_on_policy_errors=True,
        fail_on_expired_accepted_risk=True,
        fail_on_overdue_fix=True,
        fail_on_fix_regression=True,
    )

    assert disabled["passed"] is True
    assert disabled["blocking_conditions"] == 0
    assert enabled["passed"] is False
    assert enabled["blocking_conditions"] == 4
    assert {condition["id"] for condition in enabled["blocking"]} == {
        "policy-errors",
        "expired-accepted-risks",
        "overdue-fixes",
        "fix-regressions",
    }


def test_deep_scan_fail_on_returns_ci_failure(tmp_path: Path, monkeypatch) -> None:
    """The CLI should return 2 when --fail-on catches blocking findings."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-deep-public-write-route",
        title="Public write route",
        severity="high",
        file=str(repo / "controllers.py"),
        line=1,
        message="Public route performs a write",
    )
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["odoo-deep-scan", str(repo), "--out", str(out), "--fail-on", "high"],
    )

    assert odoo_deep_scan.main() == 2

    gate = json.loads((out / "review-gate.json").read_text(encoding="utf-8"))
    assert gate["passed"] is False
    assert gate["fail_on"] == "high"
    assert gate["blocking_findings"] == 1
    assert gate["blocking"][0]["rule_id"] == "odoo-deep-public-write-route"


def test_deep_scan_fail_on_unmapped_taxonomy_returns_ci_failure(tmp_path: Path, monkeypatch) -> None:
    """The CLI should return 2 when taxonomy drift gating catches unmapped rule IDs."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-brand-new-unmapped-rule",
        title="Unmapped rule",
        severity="medium",
        file=str(repo / "models.py"),
        line=1,
        message="New scanner rule without taxonomy mapping",
    )
    (repo / "models.py").write_text("from odoo import models\n", encoding="utf-8")

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["odoo-deep-scan", str(repo), "--out", str(out), "--fail-on-unmapped-taxonomy"],
    )

    assert odoo_deep_scan.main() == 2

    gate = json.loads((out / "taxonomy-gate.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "inventory" / "coverage" / "matcher-coverage.json").read_text(encoding="utf-8"))
    assert gate["passed"] is False
    assert gate["fail_on_unmapped_taxonomy"] is True
    assert gate["blocking_rules"] == 1
    assert gate["blocking_rule_ids"] == ["odoo-brand-new-unmapped-rule"]
    assert coverage["taxonomy_gate"] == gate


def test_deep_scan_baseline_delta_returns_ci_failure_for_new_findings(tmp_path: Path, monkeypatch) -> None:
    """The CLI should emit delta artifacts and return 2 for new findings over threshold."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    baseline = tmp_path / "baseline.json"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-deep-public-write-route",
        title="Public write route",
        severity="high",
        file=str(repo / "controllers.py"),
        line=1,
        message="Public route performs a write",
    )
    baseline.write_text(
        json.dumps(
            [
                {
                    "id": "F-0001",
                    "fingerprint": "sha256:" + "a" * 64,
                    "rule_id": "odoo-fixed",
                    "severity": "medium",
                    "triage": "NEEDS-MANUAL",
                    "file": "old.py",
                    "line": 1,
                    "title": "Fixed finding",
                }
            ]
        ),
        encoding="utf-8",
    )
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "odoo-deep-scan",
            str(repo),
            "--out",
            str(out),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "high",
        ],
    )

    assert odoo_deep_scan.main() == 2

    delta = json.loads((out / "deep-scan-delta.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "inventory" / "coverage" / "matcher-coverage.json").read_text(encoding="utf-8"))
    artifact_manifest = json.loads((out / "inventory" / "artifacts.json").read_text(encoding="utf-8"))
    artifact_entries = {entry["path"]: entry for entry in artifact_manifest["entries"]}
    assert delta["new_count"] == 1
    assert delta["fixed_count"] == 1
    assert coverage["baseline_gate"]["passed"] is False
    assert coverage["baseline_gate"]["fail_on_new"] == "high"
    assert coverage["baseline_gate"]["blocking_new_findings"] == 1
    assert artifact_entries["deep-scan-delta.json"]["exists"] is True
    assert artifact_entries["deep-scan-delta.md"]["exists"] is True


def test_deep_scan_accepted_risks_suppresses_matching_findings(tmp_path: Path, monkeypatch) -> None:
    """The CLI should suppress active accepted-risk matches and retain audit artifacts."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    risks = tmp_path / "accepted-risks.yml"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-deep-public-write-route",
        title="Public write route",
        severity="high",
        file=str(repo / "controllers.py"),
        line=1,
        message="Public route performs a write",
    )
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")
    risks.write_text(
        """
version: 1
risks:
  - id: AR-001
    title: Public route accepted for test fixture
    file: controllers.py
    lines: 1
    match: from odoo
    reason: Accepted for deterministic deep-scan suppression coverage.
    owner: security@example.com
    accepted: 2026-01-01
    expires: 2099-01-01
""",
        encoding="utf-8",
    )

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["odoo-deep-scan", str(repo), "--out", str(out), "--accepted-risks", str(risks), "--fail-on", "high"],
    )

    assert odoo_deep_scan.main() == 0

    findings = json.loads((out / "deep-scan-findings.json").read_text(encoding="utf-8"))
    accepted = json.loads((out / "inventory" / "accepted-risks.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "inventory" / "coverage" / "matcher-coverage.json").read_text(encoding="utf-8"))
    assert findings == []
    assert accepted["summary"]["active_entries"] == 1
    assert accepted["summary"]["suppressed_findings"] == 1
    assert accepted["suppressed"][0]["accepted_risk_id"] == "AR-001"
    assert coverage["accepted_risks"]["suppressed_findings"] == 1
    assert (out / "00-accepted-risks.md").exists()


def test_deep_scan_fix_list_tags_matching_findings(tmp_path: Path, monkeypatch) -> None:
    """The CLI should tag fix-list matches and retain reconciliation artifacts."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    fixes = tmp_path / "fix-list.yml"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-deep-public-write-route",
        title="Public write route",
        severity="high",
        file=str(repo / "controllers.py"),
        line=1,
        message="Public route performs a write",
    )
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")
    fixes.write_text(
        """
version: 1
fixes:
  - id: FIX-001
    title: Public route must require auth
    file: controllers.py
    lines: 1
    severity: HIGH
    owner: security@example.com
    status: in-progress
    target_date: 2099-01-01
""",
        encoding="utf-8",
    )

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["odoo-deep-scan", str(repo), "--out", str(out), "--fix-list", str(fixes)],
    )

    assert odoo_deep_scan.main() == 0

    findings = json.loads((out / "deep-scan-findings.json").read_text(encoding="utf-8"))
    fix_list = json.loads((out / "inventory" / "fix-list.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "inventory" / "coverage" / "matcher-coverage.json").read_text(encoding="utf-8"))
    assert findings[0]["fix_list_status"] == "tracked"
    assert findings[0]["fix_list_id"] == "FIX-001"
    assert fix_list["summary"]["tracked_findings"] == 1
    assert coverage["fix_list"]["tracked_findings"] == 1
    assert (out / "00-fix-list.md").exists()


def test_deep_scan_check_only_accepted_risks_fails_on_expired_entries(tmp_path: Path, monkeypatch) -> None:
    """Policy-only accepted-risk validation should not run scanners and should fail on expired entries."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    risks = tmp_path / "accepted-risks.yml"
    repo.mkdir()
    risks.write_text(
        """
version: 1
risks:
  - id: AR-001
    title: Expired accepted risk
    file: controllers.py
    lines: 1
    reason: Accepted risk expired and needs re-review.
    owner: security@example.com
    accepted: 2025-01-01
    expires: 2025-01-02
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "odoo-deep-scan",
            str(repo),
            "--out",
            str(out),
            "--accepted-risks",
            str(risks),
            "--check-only-accepted-risks",
        ],
    )

    assert odoo_deep_scan.main() == 2

    inventory = json.loads((out / "inventory" / "accepted-risks.json").read_text(encoding="utf-8"))
    report = (out / "00-accepted-risks.md").read_text(encoding="utf-8")
    assert inventory["summary"]["expired_entries"] == 1
    assert inventory["summary"]["input_findings"] == 0
    assert "Expired Entries" in report
    assert not (out / "deep-scan-findings.json").exists()


def test_deep_scan_check_only_fix_list_fails_on_overdue_entries(tmp_path: Path, monkeypatch) -> None:
    """Policy-only fix-list validation should fail on overdue open/in-progress entries."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    fixes = tmp_path / "fix-list.yml"
    repo.mkdir()
    fixes.write_text(
        """
version: 1
fixes:
  - id: FIX-001
    title: Public route must require auth
    file: controllers.py
    lines: 1
    severity: HIGH
    owner: security@example.com
    status: in-progress
    target_date: 2025-01-02
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "odoo-deep-scan",
            str(repo),
            "--out",
            str(out),
            "--fix-list",
            str(fixes),
            "--check-only-fix-list",
        ],
    )

    assert odoo_deep_scan.main() == 2

    inventory = json.loads((out / "inventory" / "fix-list.json").read_text(encoding="utf-8"))
    report = (out / "00-fix-list.md").read_text(encoding="utf-8")
    assert inventory["summary"]["policy_overdue_entries"] == 1
    assert inventory["policy_overdue"][0]["id"] == "FIX-001"
    assert "Policy Overdue Entries" in report
    assert not (out / "deep-scan-findings.json").exists()


def test_deep_scan_governance_gate_returns_ci_failure_for_regression(tmp_path: Path, monkeypatch) -> None:
    """The CLI should fail when governance gating catches a fix-list regression."""
    repo = tmp_path / "repo"
    out = tmp_path / "audit"
    fixes = tmp_path / "fix-list.yml"
    repo.mkdir()
    finding = SimpleNamespace(
        rule_id="odoo-deep-public-write-route",
        title="Public write route",
        severity="high",
        file=str(repo / "controllers.py"),
        line=1,
        message="Public route performs a write",
    )
    (repo / "controllers.py").write_text("from odoo import http\n", encoding="utf-8")
    fixes.write_text(
        """
version: 1
fixes:
  - id: FIX-001
    title: Public route should have been fixed
    file: controllers.py
    lines: 1
    severity: HIGH
    owner: security@example.com
    status: fixed
    fixed_at: 2026-01-01
""",
        encoding="utf-8",
    )

    for name in odoo_deep_scan._exported_deep_scan_callables():
        if name == "analyze_directory":
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [finding])
        else:
            monkeypatch.setattr(odoo_deep_scan, name, lambda _repo: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "odoo-deep-scan",
            str(repo),
            "--out",
            str(out),
            "--fix-list",
            str(fixes),
            "--fail-on-fix-regression",
        ],
    )

    assert odoo_deep_scan.main() == 2

    gate = json.loads((out / "governance-gate.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "inventory" / "coverage" / "matcher-coverage.json").read_text(encoding="utf-8"))
    assert gate["passed"] is False
    assert gate["blocking_conditions"] == 1
    assert gate["blocking"][0]["id"] == "fix-regressions"
    assert coverage["governance_gate"] == gate


def test_sarif_rules_include_inferred_security_taxonomy(tmp_path: Path) -> None:
    """SARIF rules should carry CWE/CAPEC/OWASP metadata when rule shape is known."""
    finding = {
        "id": "F-1",
        "source": "qweb",
        "rule_id": "odoo-qweb-t-raw",
        "title": "QWeb t-raw renders unsafe HTML",
        "severity": "high",
        "file": "views/template.xml",
        "line": 4,
        "message": "t-raw renders attacker-controlled markup",
        "fingerprint": "sha256:qweb",
        "triage": "NEEDS-MANUAL",
    }

    sarif = odoo_deep_scan.generate_sarif_report(tmp_path, [finding])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    result = sarif["runs"][0]["results"][0]

    assert rule["properties"]["taxonomy_shape"] == "qweb_xss_t_raw"
    assert "CWE-79" in rule["properties"]["cwe"]
    assert "CAPEC-63" in rule["properties"]["capec"]
    assert rule["properties"]["owasp"] == "A03:2021 Injection"
    assert "CWE-79" in rule["properties"]["tags"]
    assert "CWE-79" in result["properties"]["cwe"]
    assert sarif["runs"][0]["taxonomies"][0]["name"] == "CWE"
    assert {"id": "CWE-79", "name": "CWE-79"} in sarif["runs"][0]["taxonomies"][0]["taxa"]


def test_taxonomy_coverage_classifies_core_analyzer_and_multicompany_rules() -> None:
    """Legacy core analyzer and multi-company rule IDs should not fall through generic buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {"source": "python", "rule_id": "odoo-deep-with-user-admin", "title": "Admin user context", "message": "with_user(superuser_id)"},
            {"source": "python", "rule_id": "odoo-deep-markup-user-input", "title": "Markup user input", "message": "Markup() wraps request or user-controlled data"},
            {"source": "python", "rule_id": "odoo-deep-html-sanitize-false", "title": "HTML sanitization disabled", "message": "fields.Html sanitize=False"},
            {"source": "multi-company", "rule_id": "odoo-mc-missing-check-company", "title": "Missing check_company", "message": "Many2one field lacks check_company"},
            {"source": "multi-company", "rule_id": "odoo-mc-check-company-disabled", "title": "check_company disabled", "message": "check_company=False"},
            {"source": "multi-company", "rule_id": "odoo-mc-search-no-company", "title": "Search lacks company scope", "message": "ORM search lacks company domain"},
            {"source": "multi-company", "rule_id": "odoo-mc-sudo-search-no-company", "title": "Sudo search lacks company scope", "message": "sudo().search without company scope"},
            {"source": "multi-company", "rule_id": "odoo-mc-with-company-user-input", "title": "Tainted with_company", "message": "User input controls with_company"},
            {"source": "multi-company", "rule_id": "odoo-mc-company-context-user-input", "title": "Tainted company context", "message": "allowed_company_ids from request data"},
            {"source": "multi-company", "rule_id": "odoo-mc-rule-missing-company", "title": "Record rule lacks company scope", "message": "ir.rule domain does not restrict company"},
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-deep-with-user-admin"] == "deep_with_user_admin"
    assert shapes["odoo-deep-markup-user-input"] == "deep_markup_user_input"
    assert shapes["odoo-deep-html-sanitize-false"] == "deep_html_sanitize_false"
    assert shapes["odoo-mc-missing-check-company"] == "multi_company_missing_check_company"
    assert shapes["odoo-mc-check-company-disabled"] == "multi_company_check_company_disabled"
    assert shapes["odoo-mc-search-no-company"] == "multi_company_search_no_company_scope"
    assert shapes["odoo-mc-sudo-search-no-company"] == "multi_company_sudo_search_no_company_scope"
    assert shapes["odoo-mc-with-company-user-input"] == "multi_company_with_company_user_input"
    assert shapes["odoo-mc-company-context-user-input"] == "multi_company_context_user_input"
    assert shapes["odoo-mc-rule-missing-company"] == "multi_company_rule_missing_company_scope"
    assert any("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_exact_rule_id_wins_over_substring_collision() -> None:
    """Exact rule IDs should beat unrelated shape hints in title/message text."""
    taxonomy = odoo_deep_scan._taxonomy_for_text(
        "odoo-model-method-onchange-cleartext-http-url title mentions model method cleartext",
        rule_id="odoo-integration-cleartext-http-url",
    )

    assert taxonomy["taxonomy_shape"] == "integration_cleartext_http_url"


def test_taxonomy_coverage_maps_all_package_finding_rule_constants() -> None:
    """All non-script package finding rule constants should have CWE taxonomy coverage."""
    seen: set[str] = set()
    findings: list[dict[str, str]] = []
    for path in sorted(Path("odoo_security_harness").glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if not node.value.startswith("odoo-") or node.value in seen:
                continue
            seen.add(node.value)
            findings.append(
                {
                    "source": path.stem,
                    "rule_id": node.value,
                    "title": node.value,
                    "message": node.value,
                }
            )

    coverage = odoo_deep_scan._taxonomy_coverage(findings)

    assert len(seen) >= 596
    assert coverage["unmapped_rule_ids"] == []


def test_taxonomy_coverage_classifies_dynamic_qweb_t_call() -> None:
    """Dynamic QWeb template rendering should not be emitted as taxonomy drift."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-dynamic-t-call",
                "source": "qweb",
                "title": "QWeb t-call uses a dynamic template expression",
                "message": "t-call='record.template_name' chooses a template dynamically",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "qweb_dynamic_template_render"
    assert "CWE-94" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_event_handler_injection() -> None:
    """Dynamic QWeb event handlers should map to JavaScript-context XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-dynamic-event-handler",
                "source": "qweb",
                "title": "Dynamic event handler attribute",
                "message": "t-attf-onclick formats a JavaScript event handler; attribute escaping is not enough for JavaScript context",
            },
            {
                "rule_id": "odoo-web-owl-qweb-dynamic-event-handler",
                "source": "web-asset",
                "title": "OWL inline template builds JavaScript event handler",
                "message": "OWL xml template contains a dynamic or inline JavaScript event handler",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"qweb_event_handler_injection"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_qweb_markup_escape_bypass() -> None:
    """Markup escape bypasses should not be emitted as taxonomy drift."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-markup-escape-bypass",
                "source": "qweb",
                "title": "QWeb Markup() bypasses escaping",
                "message": "t-out renders a Markup() value as already-safe HTML",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "qweb_markup_escape_bypass"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_inline_script_execution() -> None:
    """QWeb t-js inline scripts should map to JavaScript execution taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-t-js-inline-script",
                "source": "qweb",
                "title": "QWeb t-js inline JavaScript block",
                "message": "t-js='ctx' enables inline JavaScript in a template; verify user data cannot reach script context",
            },
            {
                "rule_id": "odoo-qweb-script-expression-context",
                "source": "qweb",
                "title": "QWeb expression rendered inside JavaScript block",
                "message": "<script> contains t-out; HTML escaping is not JavaScript-context escaping",
            },
            {
                "rule_id": "odoo-web-owl-qweb-t-js-inline-script",
                "source": "web-assets",
                "title": "OWL inline template uses QWeb t-js",
                "message": "OWL xml template contains t-js and enables inline JavaScript in template context",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {
        entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]
    } == {
        "odoo-qweb-t-js-inline-script": "qweb_inline_script_execution",
        "odoo-qweb-script-expression-context": "qweb_inline_script_execution",
        "odoo-web-owl-qweb-t-js-inline-script": "qweb_inline_script_execution",
    }
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_qweb_raw_output_mode() -> None:
    """Raw t-out mode should not be emitted as taxonomy drift."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-raw-output-mode",
                "source": "qweb",
                "title": "QWeb raw output mode disables escaping",
                "message": "t-out-mode='raw' disables normal t-out escaping",
            },
            {
                "rule_id": "odoo-web-owl-raw-output-mode",
                "source": "web-asset",
                "title": "OWL inline template disables QWeb escaping",
                "message": "OWL xml template uses t-out-mode='raw' and disables normal escaping",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"qweb_raw_output_mode"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_frontend_message_origin_validation() -> None:
    """Message handler origin validation leads should carry frontend taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-message-handler-missing-origin-check",
                "source": "web-assets",
                "title": "Message event handler lacks visible origin validation",
                "message": "message event handler reads cross-window messages without a visible event.origin allowlist",
            },
            {
                "rule_id": "odoo-web-postmessage-dynamic-origin",
                "source": "web-assets",
                "title": "postMessage uses dynamic target origin",
                "message": "postMessage uses a nonliteral or request-derived target origin",
            },
            {
                "rule_id": "odoo-web-sensitive-postmessage-payload",
                "source": "web-assets",
                "title": "Sensitive frontend value sent with postMessage",
                "message": "Frontend code sends token/session/secret-like values through postMessage across frame or window boundaries",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_message_origin_validation"}
    assert all("CWE-346" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_frontend_dom_xss() -> None:
    """Frontend DOM HTML sinks should carry DOM XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dom-xss-sink",
                "source": "web-assets",
                "title": "DOM HTML injection sink",
                "message": "DOMParser.parseFromString parses request-derived text/html in frontend code",
            },
            {
                "rule_id": "odoo-web-owl-qweb-srcdoc-html",
                "source": "web-asset",
                "title": "OWL inline template writes iframe srcdoc HTML",
                "message": "OWL xml template writes dynamic HTML into iframe srcdoc",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_dom_xss"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_qweb_srcdoc_dom_xss() -> None:
    """QWeb iframe srcdoc HTML sinks should carry DOM XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-srcdoc-html",
                "source": "qweb",
                "title": "QWeb iframe srcdoc receives dynamic HTML",
                "message": "t-att-srcdoc writes dynamic HTML into iframe srcdoc",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dom_xss"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_client_side_redirect() -> None:
    """Dynamic frontend navigation should map to open redirect taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-client-side-redirect",
                "source": "web-assets",
                "title": "Client-side navigation uses dynamic target",
                "message": "Frontend navigation sink uses a dynamic or request-derived target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "open_redirect_portal"
    assert "CWE-601" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_meta_refresh_redirect() -> None:
    """QWeb meta refresh redirects should map to open redirect taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-meta-refresh-redirect",
                "source": "qweb",
                "title": "QWeb meta refresh uses dynamic redirect target",
                "message": "content creates a client-side redirect with a dynamic target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "open_redirect_portal"
    assert "CWE-601" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_frontend_prototype_pollution() -> None:
    """Prototype pollution frontend leads should carry explicit taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-prototype-pollution-merge",
                "source": "web-assets",
                "title": "Frontend object merge uses untrusted data",
                "message": "Object.assign merges request/RPC-derived data; reject __proto__/constructor/prototype keys",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_prototype_pollution"
    assert "CWE-1321" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_frontend_unsafe_markup() -> None:
    """OWL markup() safe-marking leads should carry XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-owl-unsafe-markup",
                "source": "web-assets",
                "title": "Frontend markup() marks untrusted HTML as safe",
                "message": "OWL/QWeb markup() receives request/RPC-derived data and marks it as trusted HTML",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_unsafe_markup"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_frontend_csrf_token_missing() -> None:
    """Raw unsafe frontend HTTP calls without CSRF should map to CWE-352."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-unsafe-request-without-csrf",
                "source": "web-assets",
                "title": "Frontend unsafe HTTP request lacks visible CSRF token",
                "message": "Raw frontend HTTP request uses an unsafe method without a visible CSRF token/header",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_csrf_token_missing"
    assert "CWE-352" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_frontend_dynamic_orm_service_call() -> None:
    """Dynamic OWL ORM service calls should map to access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-orm-service-call",
                "source": "web-assets",
                "title": "Frontend ORM service call uses dynamic model, method, domain, or values",
                "message": "Client input cannot drive unintended model access or privileged mutations",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_orm_service_call"
    assert "CWE-639" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_frontend_dynamic_action_window() -> None:
    """Dynamic frontend action descriptors should map to access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-action-window",
                "source": "web-assets",
                "title": "Frontend act_window uses dynamic model, domain, context, or record selection",
                "message": "Client input cannot widen model access through request-derived res_model/domain/context data",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_action_window"
    assert "CWE-639" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_post_form_csrf_missing() -> None:
    """QWeb POST forms without visible CSRF should map to CWE-352."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-post-form-missing-csrf",
                "source": "qweb",
                "title": "QWeb POST form lacks visible CSRF token",
                "message": "QWeb template contains a POST form without a visible csrf_token field",
            },
            {
                "rule_id": "odoo-web-owl-qweb-post-form-missing-csrf",
                "source": "web-asset",
                "title": "OWL inline template POST form lacks visible CSRF token",
                "message": "OWL xml template contains a POST form without a visible csrf_token field",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_csrf_token_missing"}
    assert all("CWE-352" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_frontend_sensitive_url_exposure() -> None:
    """Frontend URL token leads should carry leakage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-url-token",
                "source": "web-assets",
                "title": "Sensitive frontend value placed in URL",
                "message": "Frontend code places token/secret/password-like data in a URL, query string, or fragment",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_url_exposure"
    assert "CWE-598" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_owl_sensitive_url_exposure() -> None:
    """Sensitive OWL inline template URLs should map to disclosure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-owl-qweb-sensitive-url-token",
                "source": "web-assets",
                "title": "OWL inline template URL exposes sensitive-looking parameter",
                "message": "OWL xml template places token, secret, password, or API-key-like data in a URL attribute",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_url_exposure"
    assert "CWE-598" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dangerous_url_scheme() -> None:
    """Executable frontend URL schemes should map to XSS/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dangerous-url-scheme",
                "source": "web-assets",
                "title": "Odoo frontend act_url uses dangerous URL scheme",
                "message": "Odoo frontend act_url action uses a literal javascript:, data:text/html, vbscript:, or file: URL",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dangerous_url_scheme"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_owl_dangerous_url_scheme() -> None:
    """Executable OWL inline template URL schemes should map to XSS/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-owl-qweb-dangerous-url-scheme",
                "source": "web-assets",
                "title": "OWL inline template URL attribute uses dangerous scheme",
                "message": "OWL xml template contains a literal javascript:, data:text/html, vbscript:, or file: URL",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dangerous_url_scheme"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_dangerous_url_scheme() -> None:
    """Executable QWeb URL schemes should map to XSS/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-js-url",
                "source": "qweb",
                "title": "Dangerous URL scheme detected",
                "message": "href='data:text/html,<script>alert(1)</script>' contains an executable or local-file URL scheme",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dangerous_url_scheme"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_website_form_dangerous_success_redirect() -> None:
    """Executable website form success redirects should keep website-form-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-website-form-dangerous-success-redirect",
                "source": "website-forms",
                "title": "Website form success redirect uses dangerous URL scheme",
                "message": "Website form success page uses dangerous URL 'javascript:alert(1)'",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "website_form_dangerous_success_redirect"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_i18n_dangerous_html() -> None:
    """Dangerous translated HTML should map to translation-specific XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-i18n-dangerous-html",
                "source": "translations",
                "title": "Translation injects dangerous HTML or scriptable URL",
                "message": "Translated msgstr contains dangerous URL schemes such as javascript:, data:text/html, vbscript:, or file:",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "i18n_dangerous_html"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_i18n_template_and_placeholder_risks() -> None:
    """Translation QWeb and placeholder changes should not map to SQL or stay unmapped."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-i18n-qweb-raw-output",
                "source": "translations",
                "title": "Translation injects raw QWeb output directive",
                "message": "Translated msgstr contains raw QWeb output directives; verify translations cannot disable escaping",
            },
            {
                "rule_id": "odoo-i18n-template-expression-injection",
                "source": "translations",
                "title": "Translation injects template expression",
                "message": "Translated msgstr introduces template expressions or QWeb control directives absent from the source string; verify translators cannot execute template logic or expose object/request data",
            },
            {
                "rule_id": "odoo-i18n-placeholder-mismatch",
                "source": "translations",
                "title": "Translation changes interpolation placeholders",
                "message": "Translated msgstr placeholders ['name'] do not match msgid placeholders ['user']; placeholder drift can drop escaped values or break rendering",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-i18n-qweb-raw-output": "i18n_qweb_raw_output",
        "odoo-i18n-template-expression-injection": "i18n_template_expression_injection",
        "odoo-i18n-placeholder-mismatch": "i18n_placeholder_mismatch",
    }
    assert any("CWE-94" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-707" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_mail_template_dangerous_url_scheme() -> None:
    """Executable mail template URL schemes should map to XSS/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-template-dangerous-url-scheme",
                "source": "mail-templates",
                "title": "Mail template contains dangerous URL scheme",
                "message": "mail.template body_html contains javascript:, data:text/html, vbscript:, or file: URLs",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dangerous_url_scheme"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_mail_template_html_injection() -> None:
    """Raw outbound email HTML should get mail-template-specific XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-template-raw-html",
                "source": "mail-templates",
                "title": "Mail template renders raw HTML",
                "message": "mail.template body_html uses raw/unsafe rendering; verify writers cannot inject scriptable HTML into outbound mail",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "mail_template_html_injection"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_mail_template_token_exposure() -> None:
    """Token-bearing email templates should map to credential exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-template-sensitive-token",
                "source": "mail-templates",
                "title": "Mail template includes token/access fields",
                "message": "Mail template references access/password/signup token fields; verify recipients are constrained and links expire appropriately",
            },
            {
                "rule_id": "odoo-mail-template-token-not-auto-deleted",
                "source": "mail-templates",
                "title": "Token-bearing mail template is retained",
                "message": "Mail template references access/password/signup token fields without auto_delete=True",
            },
            {
                "rule_id": "odoo-mail-template-token-dynamic-recipient",
                "source": "mail-templates",
                "title": "Token-bearing mail template uses dynamic recipients",
                "message": "Mail template references access/password/signup token fields while deriving recipients from expressions; verify attacker-controlled records cannot redirect capability links",
            },
            {
                "rule_id": "odoo-mail-template-external-link-sensitive",
                "source": "mail-templates",
                "title": "Sensitive template contains external link",
                "message": "Mail template for sensitive model 'account.move' includes an external URL; verify links cannot leak tokens, record identifiers, or private workflow context",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"mail_template_token_exposure"}
    assert all("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_mail_template_privileged_rendering() -> None:
    """sudo() in mail templates should not be classified as generic IDOR."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-template-sudo-expression",
                "source": "mail-templates",
                "title": "Mail template expression uses privileged context",
                "message": "mail.template expression calls sudo()/with_user(SUPERUSER_ID); verify rendered content cannot disclose fields outside the recipient's access",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "mail_template_privileged_rendering"
    assert "CWE-863" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_mail_template_recipient_control() -> None:
    """Dynamic recipients and senders need email-specific leakage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-template-dynamic-sensitive-recipient",
                "source": "mail-templates",
                "title": "Sensitive template uses dynamic recipients",
                "message": "Mail template for sensitive model 'account.move' derives recipients from expressions; verify attacker-controlled records cannot redirect private mail",
            },
            {
                "rule_id": "odoo-mail-template-dynamic-sender",
                "source": "mail-templates",
                "title": "Sensitive template uses dynamic sender or reply-to",
                "message": "Mail template for sensitive model 'account.move' derives email_from/reply_to from expressions; verify attackers cannot spoof senders or redirect replies",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"mail_template_recipient_control"}
    assert all("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_mail_alias_ingress_and_sender_policy() -> None:
    """Inbound alias exposure should map to mail-alias-specific access taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-alias-public-sensitive-model",
                "source": "mail-aliases",
                "title": "Public inbound alias targets sensitive model",
                "message": "mail.alias allows 'everyone' to create or route mail into sensitive model 'sale.order'; verify inbound email cannot create private or privileged records",
            },
            {
                "rule_id": "odoo-mail-alias-broad-contact-policy",
                "source": "mail-aliases",
                "title": "Inbound alias accepts broad senders",
                "message": "mail.alias accepts everyone or has no explicit alias_contact policy; verify spam, spoofing, and unauthorized record creation controls",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-alias-public-sensitive-model"] == "mail_alias_sensitive_model_ingress"
    assert shapes["odoo-mail-alias-broad-contact-policy"] == "mail_alias_broad_sender_policy"


def test_taxonomy_coverage_classifies_mail_alias_privileged_defaults_and_owner() -> None:
    """Alias defaults and owners should not collapse into generic sudo taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-alias-elevated-defaults",
                "source": "mail-aliases",
                "title": "Inbound alias applies privileged defaults",
                "message": "mail.alias alias_defaults appears to set users, groups, sudo/company fields, or elevated defaults; verify inbound mail cannot assign privileged ownership or access",
            },
            {
                "rule_id": "odoo-mail-alias-privileged-owner",
                "source": "mail-aliases",
                "title": "Inbound alias runs as privileged owner",
                "message": "mail.alias uses an admin/root alias_user_id; verify inbound email cannot create or route records with privileged ownership",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-alias-elevated-defaults"] == "mail_alias_privileged_defaults"
    assert shapes["odoo-mail-alias-privileged-owner"] == "mail_alias_privileged_owner"
    assert all("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_mail_alias_dynamic_defaults_and_forced_thread() -> None:
    """Dynamic defaults and forced threads need mail-alias-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-alias-dynamic-defaults",
                "source": "mail-aliases",
                "title": "Inbound alias defaults perform dynamic evaluation",
                "message": "mail.alias alias_defaults contains eval/exec/safe_eval; verify no inbound email data can affect evaluated code",
            },
            {
                "rule_id": "odoo-mail-alias-public-force-thread",
                "source": "mail-aliases",
                "title": "Broad inbound alias forces messages into an existing thread",
                "message": "mail.alias accepts broad senders and sets alias_force_thread_id; verify external senders cannot inject chatter, attachments, or state changes into an existing record",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-alias-dynamic-defaults"] == "mail_alias_dynamic_defaults"
    assert shapes["odoo-mail-alias-public-force-thread"] == "mail_alias_forced_thread_injection"


def test_taxonomy_coverage_classifies_mail_chatter_public_and_privileged_send() -> None:
    """Public and elevated mail sends should map to notification-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-chatter-public-route-send",
                "source": "mail-chatter",
                "title": "Public route posts chatter/mail notification",
                "message": "Public/unauthenticated route posts chatter or mail notifications; verify authorization, anti-spam controls, and recipient scoping",
            },
            {
                "rule_id": "odoo-mail-send-public-route",
                "source": "mail-chatter",
                "title": "Public route sends email",
                "message": "Public/unauthenticated route sends email; verify authentication, CSRF, rate limiting, and recipient restrictions",
            },
            {
                "rule_id": "odoo-mail-create-public-route",
                "source": "mail-chatter",
                "title": "Public route creates outbound mail",
                "message": "Public/unauthenticated route creates mail.mail records; verify anti-spam controls and recipient restrictions",
            },
            {
                "rule_id": "odoo-mail-chatter-sudo-post",
                "source": "mail-chatter",
                "title": "Chatter post is performed through elevated environment",
                "message": "message_post/message_notify uses sudo()/with_user(SUPERUSER_ID); verify followers and recipients cannot receive record data outside normal access rules",
            },
            {
                "rule_id": "odoo-mail-send-sudo",
                "source": "mail-chatter",
                "title": "Email send uses elevated environment",
                "message": "Mail send uses sudo()/with_user(SUPERUSER_ID); verify rendered content and recipients do not bypass record rules",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-chatter-public-route-send"] == "mail_chatter_public_notification"
    assert shapes["odoo-mail-send-public-route"] == "mail_chatter_public_notification"
    assert shapes["odoo-mail-create-public-route"] == "mail_chatter_public_notification"
    assert shapes["odoo-mail-chatter-sudo-post"] == "mail_chatter_privileged_notification"
    assert shapes["odoo-mail-send-sudo"] == "mail_chatter_privileged_notification"


def test_taxonomy_coverage_classifies_mail_chatter_follower_paths() -> None:
    """Follower subscription and raw mail.followers mutation need dedicated taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-sensitive-model-follower-subscribe",
                "source": "mail-chatter",
                "title": "Follower subscription targets sensitive model",
                "message": "Follower subscription targets sensitive model 'sale.order'; verify subscribers cannot receive private record updates outside normal access rules",
            },
            {
                "rule_id": "odoo-mail-public-follower-subscribe",
                "source": "mail-chatter",
                "title": "Public route changes record followers",
                "message": "Public/unauthenticated route subscribes followers to a record; verify users cannot subscribe arbitrary partners to private chatter or notifications",
            },
            {
                "rule_id": "odoo-mail-tainted-follower-subscribe",
                "source": "mail-chatter",
                "title": "Follower subscription uses request-controlled values",
                "message": "message_subscribe receives request-derived partner/subtype values; verify subscribers are constrained to authorized recipients",
            },
            {
                "rule_id": "odoo-mail-followers-sensitive-model-mutation",
                "source": "mail-chatter",
                "title": "mail.followers mutation targets sensitive model",
                "message": "mail.followers mutation targets sensitive model 'sale.order'; verify recipients cannot receive private record updates outside normal access rules",
            },
            {
                "rule_id": "odoo-mail-followers-public-route-mutation",
                "source": "mail-chatter",
                "title": "Public route mutates mail.followers",
                "message": "Public/unauthenticated route creates or changes mail.followers records; verify attackers cannot subscribe recipients to private records",
            },
            {
                "rule_id": "odoo-mail-followers-sudo-mutation",
                "source": "mail-chatter",
                "title": "mail.followers mutation uses elevated environment",
                "message": "mail.followers mutation uses sudo()/with_user(SUPERUSER_ID); verify follower changes cannot bypass record rules or company boundaries",
            },
            {
                "rule_id": "odoo-mail-followers-tainted-mutation",
                "source": "mail-chatter",
                "title": "mail.followers mutation uses request-controlled values",
                "message": "Request-derived values reach mail.followers fields; constrain model, record, partner, and subtype inputs before mutating subscriptions",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-sensitive-model-follower-subscribe"] == "mail_chatter_follower_subscription"
    assert shapes["odoo-mail-public-follower-subscribe"] == "mail_chatter_follower_subscription"
    assert shapes["odoo-mail-tainted-follower-subscribe"] == "mail_chatter_follower_subscription"
    assert shapes["odoo-mail-followers-sensitive-model-mutation"] == "mail_followers_mutation_exposure"
    assert shapes["odoo-mail-followers-public-route-mutation"] == "mail_followers_mutation_exposure"
    assert shapes["odoo-mail-followers-sudo-mutation"] == "mail_followers_mutation_exposure"
    assert shapes["odoo-mail-followers-tainted-mutation"] == "mail_followers_mutation_exposure"


def test_taxonomy_coverage_classifies_mail_chatter_content_and_recipients() -> None:
    """Mail body and recipient risks should not map to secrets, redirects, or SSRF."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-mail-force-send",
                "source": "mail-chatter",
                "title": "Email is force-sent synchronously",
                "message": "send_mail(..., force_send=True) bypasses normal mail queue timing; verify request latency, retries, and spam/rate controls",
            },
            {
                "rule_id": "odoo-mail-sensitive-body",
                "source": "mail-chatter",
                "title": "Chatter/mail body includes sensitive values",
                "message": "Chatter/mail body or subject references token/password/secret-like data; verify every recipient is authorized and links expire appropriately",
            },
            {
                "rule_id": "odoo-mail-tainted-body",
                "source": "mail-chatter",
                "title": "Chatter/mail body uses request-controlled content",
                "message": "Chatter/mail body or subject includes request-derived data; verify escaping, spam controls, and recipient authorization",
            },
            {
                "rule_id": "odoo-mail-tainted-recipients",
                "source": "mail-chatter",
                "title": "Chatter/mail recipients are request-controlled",
                "message": "Chatter/mail recipient fields are request-derived; verify users cannot redirect private record notifications or send arbitrary email",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-mail-force-send"] == "mail_chatter_force_send"
    assert shapes["odoo-mail-sensitive-body"] == "mail_chatter_sensitive_content"
    assert shapes["odoo-mail-tainted-body"] == "mail_chatter_tainted_content"
    assert shapes["odoo-mail-tainted-recipients"] == "mail_chatter_tainted_recipients"


def test_taxonomy_coverage_classifies_report_privileged_rendering() -> None:
    """Report sudo findings should get report-specific access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-report-sudo-enabled",
                "source": "reports",
                "title": "Report action renders with sudo",
                "message": "ir.actions.report has report_sudo enabled; verify rendered records cannot disclose private data",
            },
            {
                "rule_id": "odoo-report-sudo-render-call",
                "source": "reports",
                "title": "Report render uses sudo",
                "message": "Report render runs through sudo(); verify report contents respect recipient access rights",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-report-sudo-enabled": "report_sudo_enabled",
        "odoo-report-sudo-render-call": "report_sudo_render_call",
    }
    assert all("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_report_access_control_exposure() -> None:
    """Sensitive reports without groups and public render routes need authorization taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-report-sensitive-no-groups",
                "source": "reports",
                "title": "Sensitive report lacks groups",
                "message": "Report action for sensitive model 'account.move' lacks groups_id; verify unauthorized users cannot render it",
            },
            {
                "rule_id": "odoo-report-public-render-route",
                "source": "reports",
                "title": "Public route renders report",
                "message": "Public route renders a report; verify authorization and record ownership checks before report generation",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-report-sensitive-no-groups": "report_sensitive_no_groups",
        "odoo-report-public-render-route": "report_public_render_route",
    }
    assert all("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_report_cached_document_exposure() -> None:
    """Report attachment caching and filenames should not map to generic file bugs."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-report-dynamic-attachment-cache",
                "source": "reports",
                "title": "Report caches dynamic attachment",
                "message": "Report action uses dynamic attachment expression and attachment_use=True; verify cached PDFs cannot leak between users",
            },
            {
                "rule_id": "odoo-report-sensitive-filename-expression",
                "source": "reports",
                "title": "Sensitive report filename expression",
                "message": "Report action for sensitive model 'account.move' uses dynamic print_report_name; verify filenames do not leak tokens or private fields",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-report-dynamic-attachment-cache": "report_dynamic_attachment_cache",
        "odoo-report-sensitive-filename-expression": "report_sensitive_filename_expression",
    }
    assert all("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_report_tainted_render_selection() -> None:
    """Request-controlled report selection and records should map to IDOR taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-report-tainted-render-records",
                "source": "reports",
                "title": "Report render receives request-controlled records",
                "message": "Report render call receives request-controlled record ids; verify IDOR checks before rendering",
            },
            {
                "rule_id": "odoo-report-tainted-render-data",
                "source": "reports",
                "title": "Report render uses request-controlled data or context",
                "message": "Report rendering receives request-derived data/context options; validate report model domains, filters, and generated output",
            },
            {
                "rule_id": "odoo-report-tainted-render-action",
                "source": "reports",
                "title": "Report action receives request-controlled data",
                "message": "Report action/report_ref is request-controlled; verify attackers cannot select arbitrary reports",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-report-tainted-render-records": "report_tainted_render_records",
        "odoo-report-tainted-render-data": "report_tainted_render_data",
        "odoo-report-tainted-render-action": "report_tainted_render_action",
    }
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_action_url_unsafe_scheme() -> None:
    """Executable server-defined URL action schemes should map to XSS/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-act-url-unsafe-scheme",
                "source": "action-urls",
                "title": "URL action uses unsafe URL scheme",
                "message": "ir.actions.act_url uses URL 'vbscript:msgbox(1)' with an unsafe scheme",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "action_url_unsafe_scheme"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_action_url_external_navigation() -> None:
    """External act_url actions should map to navigation exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-act-url-public-route",
                "source": "action-urls",
                "title": "Public route returns URL action",
                "message": "Public route returns ir.actions.act_url; verify unauthenticated users cannot drive external navigation or consume one-time links",
            },
            {
                "rule_id": "odoo-act-url-external-no-groups",
                "source": "action-urls",
                "title": "External URL action has no groups",
                "message": "ir.actions.act_url 'action_external_docs' opens external URL 'https://example.com' without groups; verify only intended users can trigger this navigation",
            },
            {
                "rule_id": "odoo-act-url-external-new-window",
                "source": "action-urls",
                "title": "External URL action opens new window",
                "message": "ir.actions.act_url opens external URL 'https://example.com' with target='new'; review phishing, tabnabbing, and allowlist expectations",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-act-url-public-route": "action_url_public_route",
        "odoo-act-url-external-no-groups": "action_url_external_no_groups",
        "odoo-act-url-external-new-window": "action_url_external_new_window",
    }
    assert all("CWE-601" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_action_url_tainted_navigation() -> None:
    """Request-derived act_url targets should map to open redirect/navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-act-url-tainted-url",
                "source": "action-urls",
                "title": "URL action target uses request data",
                "message": "Returned ir.actions.act_url uses a request-derived URL; restrict to local paths or allowlisted hosts to prevent open redirect/navigation abuse",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "action_url_tainted_navigation"
    assert "CWE-601" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_action_url_sensitive_url_material() -> None:
    """Token-bearing act_url targets should map to sensitive URL exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-act-url-sensitive-url",
                "source": "action-urls",
                "title": "URL action contains sensitive URL material",
                "message": "ir.actions.act_url URL appears to contain token, secret, password, or API-key material; avoid exposing secrets in browser history and referrers",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "action_url_sensitive_url_material"
    assert "CWE-598" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_database_listing_and_manager_exposure() -> None:
    """Database list and manager routes should map to database-manager taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-database-listing-route",
                "source": "database",
                "title": "Route lists available databases",
                "message": "Controller lists database names; verify list_db/dbfilter posture and avoid exposing tenant names to unauthenticated callers",
            },
            {
                "rule_id": "odoo-database-management-call",
                "source": "database",
                "title": "Controller calls database manager operation",
                "message": "Controller invokes database create/drop/backup/restore behavior; verify this is admin-only, CSRF-protected, audited, and not reachable pre-auth",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-database-listing-route"] == "database_listing_exposure"
    assert shapes["odoo-database-management-call"] == "database_manager_exposure"


def test_taxonomy_coverage_classifies_database_tainted_selection() -> None:
    """Request-derived database selection should not map to generic SSRF."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-database-tainted-selection",
                "source": "database",
                "title": "Request-derived database selection",
                "message": "Request-derived data reaches database selection/filtering; enforce hostname dbfilter and reject user-controlled database names",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "database_tainted_selection"
    assert "CWE-284" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_database_tainted_management_input() -> None:
    """Request-derived database manager inputs should get explicit database taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-database-tainted-management-input",
                "source": "database",
                "title": "Request-derived input reaches database manager operation",
                "message": "Request-derived data reaches database create/drop/backup/restore behavior; prevent attacker-chosen database names, passwords, or backup payloads",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "database_tainted_management_input"
    assert "CWE-862" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_database_session_selection() -> None:
    """request.session.db assignment should map to database selection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-database-session-db-assignment",
                "source": "database",
                "title": "Request controls session database",
                "message": "Controller assigns request-derived value to request.session.db; verify host/dbfilter cannot be bypassed",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "database_session_selection"
    assert "CWE-284" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_object_url() -> None:
    """Blob object URLs carrying credentials should map to frontend exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-object-url",
                "source": "web-assets",
                "title": "Sensitive frontend value exposed through object URL",
                "message": "Frontend code creates a Blob object URL containing token/session/secret-like data",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_object_url"
    assert "CWE-200" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_frontend_raw_crypto_key() -> None:
    """Frontend raw WebCrypto key imports should map to hard-coded key taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-frontend-raw-crypto-key",
                "source": "web-assets",
                "title": "Frontend imports raw or hard-coded cryptographic key material",
                "message": "Frontend code imports raw/JWK cryptographic key material from hard-coded or request-derived data",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_raw_crypto_key"
    assert "CWE-321" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_credential_management() -> None:
    """Browser Credential Management API storage should carry credential storage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-credential-management",
                "source": "web-assets",
                "title": "Sensitive frontend value stored with browser Credential Management API",
                "message": "Frontend code passes password/token/session-like data to browser Credential Management APIs",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_credential_management"
    assert "CWE-522" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_history_url() -> None:
    """Browser history credential URLs should carry a specific persistence taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-history-url",
                "source": "web-assets",
                "title": "Sensitive frontend URL persisted to browser history",
                "message": "Frontend code writes a token/session/secret-like URL into browser history",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_history_url"
    assert "CWE-598" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_sensitive_url_exposure() -> None:
    """QWeb token-bearing URL leads should share sensitive URL leakage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-sensitive-url-token",
                "source": "qweb",
                "title": "QWeb URL exposes sensitive-looking parameter",
                "message": "t-attf-href places token, secret, password, or API-key-like data in a URL",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_url_exposure"
    assert "CWE-598" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_reverse_tabnabbing() -> None:
    """QWeb target blank leads should map to opener isolation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-target-blank-no-noopener",
                "source": "qweb",
                "title": "QWeb link opens new tab without opener isolation",
                "message": "QWeb link uses target='_blank' without rel='noopener' or rel='noreferrer'",
            },
            {
                "rule_id": "odoo-web-owl-qweb-target-blank-no-noopener",
                "source": "web-asset",
                "title": "OWL inline template link opens new tab without opener isolation",
                "message": "OWL xml template link uses target='_blank' without rel='noopener'",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_reverse_tabnabbing"}
    assert all("CWE-1022" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_window_open_reverse_tabnabbing() -> None:
    """JavaScript window.open opener leads should map to opener isolation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-window-open-no-noopener",
                "source": "web-asset",
                "title": "window.open opens a new context without opener isolation",
                "message": "window.open opens a new tab/window without noopener or noreferrer",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_reverse_tabnabbing"
    assert "CWE-1022" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dom_target_blank_reverse_tabnabbing() -> None:
    """JavaScript DOM target blank leads should map to opener isolation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-target-blank-no-noopener",
                "source": "web-asset",
                "title": "DOM link opens new tab without opener isolation",
                "message": "Frontend code sets target='_blank' without a nearby rel='noopener'",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_reverse_tabnabbing"
    assert "CWE-1022" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_iframe_sandbox_missing() -> None:
    """QWeb iframe sandbox leads should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-iframe-missing-sandbox",
                "source": "qweb",
                "title": "QWeb iframe lacks sandbox restrictions",
                "message": "QWeb template embeds an iframe without a sandbox attribute",
            },
            {
                "rule_id": "odoo-web-owl-qweb-iframe-missing-sandbox",
                "source": "web-asset",
                "title": "OWL inline template iframe lacks sandbox restrictions",
                "message": "OWL xml template embeds an iframe without a sandbox attribute",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_iframe_sandbox_missing"}
    assert all("CWE-693" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_iframe_sandbox_missing() -> None:
    """JavaScript DOM iframe sandbox leads should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-iframe-missing-sandbox",
                "source": "web-asset",
                "title": "DOM-created iframe lacks sandbox restrictions",
                "message": "Frontend code creates and uses an iframe without a visible sandbox assignment",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_iframe_sandbox_missing"
    assert "CWE-693" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_iframe_sandbox_escape() -> None:
    """Weak iframe sandbox token combinations should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-iframe-sandbox-escape",
                "source": "qweb",
                "title": "QWeb iframe sandbox allows script same-origin escape",
                "message": "QWeb iframe sandbox combines allow-scripts with allow-same-origin",
            },
            {
                "rule_id": "odoo-web-owl-qweb-iframe-sandbox-escape",
                "source": "web-asset",
                "title": "OWL inline template iframe sandbox allows script same-origin escape",
                "message": "OWL xml template iframe sandbox combines allow-scripts with allow-same-origin",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_iframe_sandbox_escape"}
    assert all("CWE-1021" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_iframe_sandbox_escape() -> None:
    """JavaScript weak iframe sandbox leads should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-iframe-sandbox-escape",
                "source": "web-asset",
                "title": "DOM iframe sandbox allows script same-origin escape",
                "message": "Frontend code sets iframe sandbox to allow-scripts plus allow-same-origin",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_iframe_sandbox_escape"
    assert "CWE-1021" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_iframe_broad_permissions() -> None:
    """Broad iframe feature delegation should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-iframe-broad-permissions",
                "source": "qweb",
                "title": "QWeb iframe allows sensitive browser features broadly",
                "message": "QWeb iframe allow='camera *; geolocation' grants sensitive browser features broadly",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_iframe_broad_permissions"
    assert "CWE-284" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_iframe_broad_permissions() -> None:
    """JavaScript iframe feature delegation should map to frame containment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-iframe-broad-permissions",
                "source": "web-asset",
                "title": "DOM iframe allows sensitive browser features broadly",
                "message": "Frontend code sets iframe allow permissions broadly",
            },
            {
                "rule_id": "odoo-web-owl-qweb-iframe-broad-permissions",
                "source": "web-asset",
                "title": "OWL inline template iframe allows sensitive browser features broadly",
                "message": "OWL xml template iframe allow permissions grant sensitive browser features broadly",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_iframe_broad_permissions"}
    assert all("CWE-284" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_qweb_external_script_missing_sri() -> None:
    """External script integrity leads should map to software integrity taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-external-script-missing-sri",
                "source": "qweb",
                "title": "QWeb external script lacks Subresource Integrity",
                "message": "QWeb template loads an external script without an integrity attribute",
            },
            {
                "rule_id": "odoo-web-owl-qweb-external-script-missing-sri",
                "source": "web-asset",
                "title": "OWL inline template external script lacks Subresource Integrity",
                "message": "OWL xml template loads an external script without an integrity attribute",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_external_script_missing_sri"}
    assert any("CWE-829" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_external_script_missing_sri() -> None:
    """JavaScript-generated external script integrity leads should map to software integrity taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-external-script-missing-sri",
                "source": "web-asset",
                "title": "DOM-created external script lacks Subresource Integrity",
                "message": "Frontend code creates and loads an external script without a visible integrity assignment",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_external_script_missing_sri"
    assert "CWE-353" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_external_stylesheet_missing_sri() -> None:
    """External stylesheet integrity leads should map to software integrity taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-external-stylesheet-missing-sri",
                "source": "qweb",
                "title": "QWeb external stylesheet lacks Subresource Integrity",
                "message": "QWeb template loads an external stylesheet without an integrity attribute",
            },
            {
                "rule_id": "odoo-web-owl-qweb-external-stylesheet-missing-sri",
                "source": "web-asset",
                "title": "OWL inline template external stylesheet lacks Subresource Integrity",
                "message": "OWL xml template loads an external stylesheet without an integrity attribute",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_external_stylesheet_missing_sri"}
    assert any("CWE-829" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_owl_insecure_asset_url() -> None:
    """Insecure OWL template asset URLs should map to transport/integrity taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-owl-qweb-insecure-asset-url",
                "source": "web-asset",
                "title": "OWL inline template loads insecure HTTP URL",
                "message": "OWL xml template contains a literal http:// URL in a link, frame, form, or media attribute",
            },
            {
                "rule_id": "odoo-qweb-insecure-asset-url",
                "source": "qweb",
                "title": "QWeb template loads insecure HTTP URL",
                "message": "Literal http:// URL in attribute; use HTTPS or same-origin assets",
            },
            {
                "rule_id": "odoo-manifest-insecure-remote-asset",
                "source": "manifest",
                "title": "Manifest declares insecure HTTP frontend asset",
                "message": "Manifest frontend assets reference cleartext http:// URLs",
            },
            {
                "rule_id": "odoo-manifest-protocol-relative-remote-asset",
                "source": "manifest",
                "title": "Manifest declares protocol-relative frontend asset",
                "message": "Manifest frontend assets reference protocol-relative URLs",
            },
            {
                "rule_id": "odoo-web-insecure-asset-url",
                "source": "web-asset",
                "title": "DOM-created asset loads insecure HTTP URL",
                "message": "Frontend code creates and loads a script over http://",
            },
            {
                "rule_id": "odoo-web-insecure-http-request-url",
                "source": "web-asset",
                "title": "Frontend HTTP request uses insecure URL",
                "message": "Frontend browser request targets a literal http:// URL",
            },
            {
                "rule_id": "odoo-web-insecure-live-connection-url",
                "source": "web-asset",
                "title": "Frontend live connection uses insecure URL",
                "message": "Frontend WebSocket/EventSource connection targets a literal cleartext ws:// or http:// URL",
            },
            {
                "rule_id": "odoo-mail-template-insecure-url",
                "source": "mail-templates",
                "title": "Mail template contains insecure HTTP URL",
                "message": "mail.template body_html contains a literal http:// URL",
            },
            {
                "rule_id": "odoo-i18n-insecure-url",
                "source": "translations",
                "title": "Translation introduces insecure HTTP URL",
                "message": "Translated msgstr contains a literal http:// URL",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_insecure_asset_url"}
    assert all("CWE-319" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_external_stylesheet_missing_sri() -> None:
    """JavaScript-generated external stylesheet integrity leads should map to software integrity taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-external-stylesheet-missing-sri",
                "source": "web-asset",
                "title": "DOM-created external stylesheet lacks Subresource Integrity",
                "message": "Frontend code creates and loads an external stylesheet without a visible integrity assignment",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_external_stylesheet_missing_sri"
    assert "CWE-353" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_code_import() -> None:
    """Runtime JavaScript import leads should map to dynamic code import taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-code-import",
                "source": "web-asset",
                "title": "Dynamic JavaScript import uses external or request-derived target",
                "message": "Frontend code imports JavaScript at runtime from an external or dynamic target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_code_import"
    assert "CWE-829" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_dynamic_script_src() -> None:
    """QWeb dynamic script URLs should map to dynamic code import taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-dynamic-script-src",
                "source": "qweb",
                "title": "QWeb script source uses dynamic target",
                "message": "QWeb script imports JavaScript at runtime from an external or dynamic target",
            },
            {
                "rule_id": "odoo-web-owl-qweb-dynamic-script-src",
                "source": "web-asset",
                "title": "OWL inline template script source uses dynamic target",
                "message": "OWL xml template imports JavaScript at runtime from an external or dynamic target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_dynamic_code_import"}
    assert all("CWE-829" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_dynamic_worker_script() -> None:
    """Dynamic Worker script leads should map to runtime code loading taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-worker-script",
                "source": "web-asset",
                "title": "Worker script uses external or request-derived target",
                "message": "Frontend code starts a Worker from an external or dynamic script target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_worker_script"
    assert "CWE-94" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_import_scripts() -> None:
    """Worker importScripts should map to runtime script loading taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-import-scripts",
                "source": "web-asset",
                "title": "Worker importScripts loads external or request-derived script",
                "message": "Worker code imports scripts at runtime from an external or dynamic target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_import_scripts"
    assert "CWE-829" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_service_worker() -> None:
    """Dynamic Service Worker registrations should map to persistent runtime code loading taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-service-worker",
                "source": "web-asset",
                "title": "Service Worker registration uses external or request-derived target",
                "message": "Frontend code registers a Service Worker from an external or dynamic script target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_service_worker"
    assert "CWE-829" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_wasm_loading() -> None:
    """Dynamic WebAssembly loading should map to runtime code loading taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-wasm-loading",
                "source": "web-asset",
                "title": "WebAssembly loads external or request-derived code",
                "message": "Frontend code loads WebAssembly from an external, dynamic, or request-derived source",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_wasm_loading"
    assert "CWE-829" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_css_injection() -> None:
    """Dynamic stylesheet writes should map to frontend CSS injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-css-injection",
                "source": "web-asset",
                "title": "Stylesheet injection uses request-derived CSS text",
                "message": "Frontend code writes dynamic or request-derived CSS into a stylesheet",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_css_injection"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_qweb_dynamic_style_attribute() -> None:
    """QWeb dynamic style attributes should reuse frontend CSS injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-dynamic-style-attribute",
                "source": "qweb",
                "title": "QWeb dynamic style attribute",
                "message": "QWeb t-att-style writes dynamic CSS into a style attribute",
            },
            {
                "rule_id": "odoo-web-owl-qweb-dynamic-style-attribute",
                "source": "web-asset",
                "title": "OWL inline template binds dynamic style attribute",
                "message": "OWL xml template binds dynamic CSS into a style attribute",
            },
            {
                "rule_id": "odoo-web-owl-qweb-dynamic-class-attribute",
                "source": "web-asset",
                "title": "OWL inline template binds dynamic class attribute",
                "message": "OWL xml template binds dynamic CSS classes",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_dynamic_css_injection"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_qweb_dynamic_stylesheet_href() -> None:
    """QWeb dynamic stylesheet URLs should reuse frontend CSS injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-qweb-dynamic-stylesheet-href",
                "source": "qweb",
                "title": "QWeb stylesheet href uses dynamic target",
                "message": "QWeb stylesheet href loads CSS from an external or dynamic target",
            },
            {
                "rule_id": "odoo-web-owl-qweb-dynamic-stylesheet-href",
                "source": "web-asset",
                "title": "OWL inline template stylesheet href uses dynamic target",
                "message": "OWL xml template loads CSS from an external or dynamic target",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"frontend_dynamic_css_injection"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_web_dynamic_live_connection() -> None:
    """Dynamic WebSocket/EventSource endpoints should map to frontend realtime endpoint taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-live-connection",
                "source": "web-asset",
                "title": "Frontend live connection uses external or request-derived endpoint",
                "message": "Frontend code opens a WebSocket/EventSource connection to an external or dynamic endpoint",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_live_connection"
    assert "CWE-346" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_document_domain_relaxation() -> None:
    """document.domain assignments should map to same-origin relaxation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-document-domain-relaxation",
                "source": "web-asset",
                "title": "Frontend relaxes same-origin policy with document.domain",
                "message": "Frontend code assigns document.domain, which relaxes browser origin isolation",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_document_domain_relaxation"
    assert "CWE-346" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_document_cookie() -> None:
    """JavaScript-written sensitive cookies should map to frontend cookie exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-document-cookie",
                "source": "web-asset",
                "title": "Frontend writes sensitive value to document.cookie",
                "message": "Frontend code writes a session/token/secret-like cookie through document.cookie",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_document_cookie"
    assert "CWE-1004" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_window_name() -> None:
    """Sensitive window.name writes should map to navigation-persistent browser storage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-window-name",
                "source": "web-asset",
                "title": "Sensitive frontend value written to window.name",
                "message": "Frontend code writes token/session/secret-like values to window.name",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_window_name"
    assert "CWE-922" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_indexeddb_storage() -> None:
    """Sensitive IndexedDB writes should map to frontend browser storage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-indexeddb-storage",
                "source": "web-asset",
                "title": "Sensitive value stored in IndexedDB",
                "message": "Frontend code writes token/secret/session-like data to an IndexedDB object store",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_indexeddb_storage"
    assert "CWE-922" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_cache_api_storage() -> None:
    """Sensitive Cache API writes should map to persistent browser cache taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-cache-api-storage",
                "source": "web-asset",
                "title": "Sensitive value stored in browser Cache API",
                "message": "Frontend code writes token/session-like URLs or responses to the browser Cache API",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_cache_api_storage"
    assert "CWE-524" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_console_logging() -> None:
    """Sensitive frontend console logs should map to browser logging exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-console-logging",
                "source": "web-asset",
                "title": "Sensitive frontend value logged to console",
                "message": "Frontend code logs token/session/secret-like values to the browser console",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_console_logging"
    assert "CWE-532" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_send_beacon() -> None:
    """Sensitive sendBeacon use should map to frontend exfiltration taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-send-beacon",
                "source": "web-asset",
                "title": "Sensitive frontend value sent with sendBeacon",
                "message": "Frontend code sends token/session/secret-like values through navigator.sendBeacon",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_send_beacon"
    assert "CWE-201" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_clipboard_write() -> None:
    """Sensitive clipboard writes should map to frontend exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-clipboard-write",
                "source": "web-asset",
                "title": "Sensitive frontend value written to clipboard",
                "message": "Frontend code writes token/session/secret-like values to the system clipboard",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_clipboard_write"
    assert "CWE-359" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_notification() -> None:
    """Sensitive browser notifications should map to frontend exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-notification",
                "source": "web-asset",
                "title": "Sensitive frontend value shown in browser notification",
                "message": "Frontend code displays token/session/secret-like values in browser notifications",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_notification"
    assert "CWE-359" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_sensitive_broadcast_channel() -> None:
    """Sensitive BroadcastChannel use should map to frontend exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-sensitive-broadcast-channel",
                "source": "web-asset",
                "title": "Sensitive frontend value used in BroadcastChannel",
                "message": "Frontend code uses token/session/secret-like values in BroadcastChannel names or messages",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_sensitive_broadcast_channel"
    assert "CWE-200" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_web_dynamic_bus_channel() -> None:
    """Frontend bus subscriptions should map to realtime authorization taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-web-dynamic-bus-channel",
                "source": "web-asset",
                "title": "Frontend bus service subscribes to dynamic or broad channel",
                "message": "Odoo frontend bus service subscribes to a request-derived or broad realtime channel",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "frontend_dynamic_bus_channel"
    assert "CWE-639" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_html_sanitizer_relaxed() -> None:
    """Relaxed html_sanitize calls should map to HTML sanitizer taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-deep-html-sanitize-strict-false",
                "source": "deep-analysis",
                "title": "HTML sanitizer uses non-strict mode",
                "message": "tools.html_sanitize(..., strict=False) keeps a broader HTML surface",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "html_sanitizer_relaxed"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_html_sanitizer_disabled_option() -> None:
    """Disabled html_sanitize sub-options should map to HTML sanitizer taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "rule_id": "odoo-deep-html-sanitize-relaxed-option",
                "source": "deep-analysis",
                "title": "HTML sanitizer disables sanitizer option",
                "message": "tools.html_sanitize(..., sanitize_attributes=False) disables part of HTML sanitization",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "html_sanitizer_relaxed"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_sarif_rules_classify_sensitive_model_mutation_taxonomy(tmp_path: Path) -> None:
    """Sensitive model mutation rules should not fall through to broad access/sudo shapes."""
    finding = {
        "id": "F-1",
        "source": "wizard",
        "rule_id": "odoo-wizard-sensitive-model-mutation",
        "title": "Wizard mutates sensitive model",
        "severity": "high",
        "file": "wizards/config.py",
        "line": 8,
        "message": "TransientModel wizard mutates sensitive model 'res.users'; verify action exposure, group checks, record rules, and audit trail",
        "fingerprint": "sha256:wizard-sensitive-model",
        "triage": "NEEDS-MANUAL",
    }

    sarif = odoo_deep_scan.generate_sarif_report(tmp_path, [finding])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    result = sarif["runs"][0]["results"][0]

    assert rule["properties"]["taxonomy_shape"] == "wizard_sensitive_model_mutation"
    assert "CWE-269" in rule["properties"]["cwe"]
    assert "CWE-732" in result["properties"]["cwe"]
    assert rule["properties"]["owasp"] == "A01:2021 Broken Access Control"


def test_taxonomy_coverage_classifies_wizard_upload_and_parser_risks() -> None:
    """Wizard upload/parser findings should not remain unmapped or collapse into generic upload taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-binary-import-field",
                "title": "Wizard exposes binary upload/import field",
                "message": "TransientModel wizard defines a Binary field; verify upload size, MIME/type validation, parsing safety, and attachment retention",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-upload-parser",
                "title": "Wizard parses uploaded file content",
                "message": "TransientModel wizard parses uploaded content; verify file size, formula injection, decompression bombs, parser hardening, and per-record authorization",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-upload-parser-no-size-check",
                "title": "Wizard parses uploaded content without visible size check",
                "message": "TransientModel wizard parses uploaded content without a visible file-size guard; verify large uploads cannot exhaust memory or parser resources",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-wizard-binary-import-field": "wizard_binary_import_field",
        "odoo-wizard-upload-parser": "wizard_upload_parser",
        "odoo-wizard-upload-parser-no-size-check": "wizard_upload_parser_no_size_check",
    }
    assert any("CWE-434" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-770" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_wizard_mutation_risks() -> None:
    """Wizard mutation findings need wizard-specific access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-sensitive-model-mutation",
                "title": "Wizard mutates sensitive model",
                "message": "TransientModel wizard mutates sensitive model 'res.users'; verify action exposure, group checks, record rules, and audit trail",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-sudo-mutation",
                "title": "Wizard mutates records through an elevated environment",
                "message": "TransientModel wizard chains sudo()/with_user(SUPERUSER_ID) into create/write/unlink; verify explicit access, group, and company checks before mutation",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-dynamic-active-model",
                "title": "Wizard uses context active_model dynamically",
                "message": "Wizard uses context active_model to select an env model dynamically; constrain allowed models before browsing or mutating records",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-active-ids-bulk-mutation",
                "title": "Wizard mutates records selected from active_ids",
                "message": "Wizard mutates records selected from context active_ids; verify caller access, record rules, company scope, and batch limits",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-mutation-no-access-check",
                "title": "Wizard action mutates without visible access check",
                "message": "Wizard action mutates records without visible check_access/user_has_groups guard; verify UI exposure cannot bypass workflow permissions",
            },
            {
                "source": "wizards",
                "rule_id": "odoo-wizard-long-transient-retention",
                "title": "Wizard transient records have long retention",
                "message": "TransientModel wizard sets _transient_max_hours/_transient_max_count to unlimited or high retention; verify uploaded files, tokens, active_ids, and temporary decisions are not retained longer than needed",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-wizard-sensitive-model-mutation": "wizard_sensitive_model_mutation",
        "odoo-wizard-sudo-mutation": "wizard_sudo_mutation",
        "odoo-wizard-dynamic-active-model": "wizard_dynamic_active_model",
        "odoo-wizard-active-ids-bulk-mutation": "wizard_active_ids_bulk_mutation",
        "odoo-wizard-mutation-no-access-check": "wizard_mutation_no_access_check",
        "odoo-wizard-long-transient-retention": "wizard_long_transient_retention",
    }
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_export_spreadsheet_formula_injection() -> None:
    """CSV/XLSX formula injection should not map to SSRF or SQL taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "exports",
                "rule_id": "odoo-export-csv-formula-injection",
                "title": "CSV export writes unsanitized record/request data",
                "message": "CSV export writes request/record-derived data without visible formula escaping; neutralize values beginning with =, +, -, @, tab, or CR",
            },
            {
                "source": "exports",
                "rule_id": "odoo-export-xlsx-formula-injection",
                "title": "XLSX export writes unsanitized record/request data",
                "message": "XLSX export writes request/record-derived data without visible formula escaping; force strings or neutralize formula prefixes",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"export_spreadsheet_formula_injection"}
    assert all("CWE-1236" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_export_tainted_formula() -> None:
    """Explicit XLSX formula sinks should map to spreadsheet formula injection."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "exports",
                "rule_id": "odoo-export-tainted-formula",
                "title": "XLSX formula uses request/record data",
                "message": "XLSX formula is built from request/record-derived data; verify formulas cannot execute attacker-controlled spreadsheet expressions",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "export_tainted_formula"
    assert "CWE-1236" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_export_field_controls() -> None:
    """ORM export field findings should map to export-specific data exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "exports",
                "rule_id": "odoo-export-request-controlled-fields",
                "title": "ORM export fields are request-controlled",
                "message": "ORM export/read field list is request-derived; restrict exported fields to a server-side allowlist before returning data",
            },
            {
                "source": "exports",
                "rule_id": "odoo-export-sensitive-fields",
                "title": "ORM export includes sensitive fields",
                "message": "ORM export/read includes sensitive fields ['groups_id', 'password']; verify only authorized users can retrieve these values",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-export-request-controlled-fields"] == "export_request_controlled_fields"
    assert shapes["odoo-export-sensitive-fields"] == "export_sensitive_fields"


def test_taxonomy_coverage_classifies_sensitive_default_export() -> None:
    """Sensitive default-field read/export rules should not be treated as domain injection."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "export",
                "rule_id": "odoo-export-sensitive-model-default-fields",
                "title": "Sensitive model read/export uses default fields",
                "message": "search_read on sensitive model without explicit fields",
            }
        ]
    )

    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "sensitive_model_default_export"
    assert "CWE-200" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_sensitive_default_configuration() -> None:
    """Sensitive ir.default runtime and XML model rules should keep specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "default-values",
                "rule_id": "odoo-default-sensitive-model-set",
                "title": "Sensitive model default is set at runtime",
                "message": "Runtime ir.default.set() writes a default for sensitive model 'payment.provider'",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-sensitive-model-value",
                "title": "Sensitive model default value is preconfigured",
                "message": "ir.default configures a default for sensitive model 'ir.config_parameter'",
            },
        ]
    )

    assert coverage["mapped_rules"] == 2
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {
        "default_sensitive_model_set",
        "default_sensitive_model_value",
    }
    assert all("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_default_value_persistence_risks() -> None:
    """ir.default public, sudo, tainted, scoped, and field-sensitive rules need dedicated taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "default-values",
                "rule_id": "odoo-default-public-route-set",
                "title": "Public route writes ir.default",
                "message": "Public route writes ir.default; verify unauthenticated users cannot alter persisted defaults",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-sudo-set",
                "title": "ir.default is written through privileged context",
                "message": "sudo()/with_user(SUPERUSER_ID).set() writes persisted defaults",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-request-derived-set",
                "title": "Request-derived data reaches ir.default",
                "message": "Request-derived field or value reaches ir.default.set()",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-sensitive-field-set",
                "title": "Sensitive ir.default field is set at runtime",
                "message": "Runtime ir.default.set() writes sensitive field 'groups_id'",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-global-scope",
                "title": "ir.default record has global scope",
                "message": "ir.default 'default_user_group' has no user_id or company_id",
            },
            {
                "source": "default-values",
                "rule_id": "odoo-default-sensitive-value",
                "title": "Sensitive ir.default value is preconfigured",
                "message": "ir.default 'default_user_group' configures sensitive field 'groups_id'",
            },
        ]
    )

    assert coverage["mapped_rules"] == 6
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-default-public-route-set": "default_public_route_set",
        "odoo-default-sudo-set": "default_sudo_set",
        "odoo-default-request-derived-set": "default_request_derived_set",
        "odoo-default-sensitive-field-set": "default_sensitive_field_set",
        "odoo-default-global-scope": "default_global_scope",
        "odoo-default-sensitive-value": "default_sensitive_value",
    }


def test_taxonomy_coverage_classifies_sequence_runtime_risks() -> None:
    """ir.sequence runtime use should not fall into SSRF, sudo, or generic public-route taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-public-route-next",
                "title": "Public route consumes a sequence",
                "message": "Public route /public/sequence calls next_by_code(); verify attackers cannot enumerate or exhaust business identifiers, coupons, invites, or tokens",
            },
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-tainted-code",
                "title": "Request controls sequence code",
                "message": "Request-derived data controls next_by_code(); constrain allowed sequence codes to prevent unintended counter consumption or information disclosure",
            },
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-sensitive-code-use",
                "title": "Sensitive flow uses predictable sequence",
                "message": "Sequence code 'access.token.sequence' looks security-sensitive; do not use ir.sequence for access tokens, reset codes, API keys, or invite secrets",
            },
        ]
    )

    assert coverage["mapped_rules"] == 3
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-sequence-public-route-next": "sequence_public_route_next",
        "odoo-sequence-tainted-code": "sequence_tainted_code",
        "odoo-sequence-sensitive-code-use": "sequence_sensitive_code_use",
    }
    assert any("CWE-770" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-330" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_sequence_declaration_scope() -> None:
    """ir.sequence XML declarations need predictable-counter and scoping taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-sensitive-declaration",
                "title": "Sequence appears to generate sensitive values",
                "message": "ir.sequence 'seq_invite_token' appears tied to tokens, passwords, coupons, invites, or secrets; sequences are predictable counters and should not generate security secrets",
            },
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-sensitive-global-scope",
                "title": "Sensitive sequence has global scope",
                "message": "ir.sequence 'seq_invite_token' has no company_id while appearing security-sensitive; verify scope and collision/isolation assumptions",
            },
            {
                "source": "sequences",
                "rule_id": "odoo-sequence-business-global-scope",
                "title": "Business sequence has no company scope",
                "message": "ir.sequence 'seq_sale_order' appears to generate accounting/sales/stock identifiers without company_id; verify multi-company numbering requirements",
            },
        ]
    )

    assert coverage["mapped_rules"] == 3
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-sequence-sensitive-declaration": "sequence_sensitive_declaration",
        "odoo-sequence-sensitive-global-scope": "sequence_sensitive_global_scope",
        "odoo-sequence-business-global-scope": "sequence_business_global_scope",
    }
    assert any("CWE-331" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-668" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_sensitive_public_exposure() -> None:
    """Publication and mail follower exposure rules should map to exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "publication",
                "rule_id": "odoo-publication-portal-share-sensitive",
                "title": "Portal/share record targets sensitive data",
                "message": "Portal/share wizard data targets sensitive records",
            },
            {
                "source": "mail-chatter",
                "rule_id": "odoo-mail-sensitive-model-follower-subscribe",
                "title": "Follower subscription targets sensitive model",
                "message": "Follower subscription targets sensitive model 'payment.provider'",
            },
            {
                "source": "mail-chatter",
                "rule_id": "odoo-mail-followers-sensitive-model-mutation",
                "title": "mail.followers mutation targets sensitive model",
                "message": "mail.followers mutation targets sensitive model 'sale.order'",
            },
        ]
    )

    assert coverage["mapped_rules"] == 3
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-publication-portal-share-sensitive": "publication_portal_share_sensitive",
        "odoo-mail-sensitive-model-follower-subscribe": "mail_chatter_follower_subscription",
        "odoo-mail-followers-sensitive-model-mutation": "mail_followers_mutation_exposure",
    }
    assert all(entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_publication_specific_risks() -> None:
    """Publication scanner rule IDs should not collapse into route/path/default buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "publication",
                "rule_id": "odoo-publication-public-attachment",
                "title": "Attachment is published publicly",
                "message": "ir.attachment record sets public=True; verify the binary cannot expose private customer data",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-sensitive-public-attachment",
                "title": "Sensitive-looking attachment is public",
                "message": "Public attachment name/model suggests sensitive content",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-active-public-attachment",
                "title": "Public attachment uses browser-active content type",
                "message": "Public ir.attachment record stores browser-active content (mimetype=image/svg+xml); verify sanitization, MIME allowlists, download disposition, and intended public access",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-sensitive-website-published",
                "title": "Sensitive model record is website-published",
                "message": "Record for sensitive model 'res.partner' is marked website-published",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-sensitive-default-published",
                "title": "Sensitive model defaults records to website-published",
                "message": "Sensitive model 'res.partner' defines 'website_published' with a truthy default",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-public-route-mutation",
                "title": "Public route changes website publication",
                "message": "Public/unauthenticated route writes publication flags on sensitive model 'res.partner'",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-sensitive-runtime-published",
                "title": "Sensitive model publication flag is written at runtime",
                "message": "Runtime write changes publication flags on sensitive model 'res.partner'",
            },
            {
                "source": "publication",
                "rule_id": "odoo-publication-tainted-runtime-published",
                "title": "Request-derived publication flag is written",
                "message": "Request-derived data controls publication flags on sensitive model 'res.partner'",
            },
        ]
    )

    assert coverage["mapped_rules"] == 8
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-publication-public-attachment": "publication_public_attachment",
        "odoo-publication-sensitive-public-attachment": "publication_sensitive_public_attachment",
        "odoo-publication-active-public-attachment": "publication_active_public_attachment",
        "odoo-publication-sensitive-website-published": "publication_sensitive_website_published",
        "odoo-publication-sensitive-default-published": "publication_sensitive_default_published",
        "odoo-publication-public-route-mutation": "publication_public_route_mutation",
        "odoo-publication-sensitive-runtime-published": "publication_sensitive_runtime_published",
        "odoo-publication-tainted-runtime-published": "publication_tainted_runtime_published",
    }


def test_taxonomy_coverage_classifies_attachment_metadata_specific_risks() -> None:
    """Attachment metadata rules should not collapse into SSRF or generic publication buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-public-route-mutation",
                "title": "Public route mutates attachments",
                "message": "Public/unauthenticated route mutates ir.attachment; verify upload/delete authority, record ownership, and token checks",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-sudo-mutation",
                "title": "Attachment mutation runs with elevated environment",
                "message": "ir.attachment mutation runs through sudo()/with_user(SUPERUSER_ID); verify res_model/res_id binding, ownership, company scope, and auditability",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-res-model",
                "title": "Attachment res_model is request-controlled",
                "message": "ir.attachment.create uses request-derived res_model; attackers may bind uploads to unintended protected models",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-res-id",
                "title": "Attachment res_id is request-controlled",
                "message": "ir.attachment.create uses request-derived res_id; verify ownership before binding files to existing records",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-public-orphan",
                "title": "Public attachment lacks record binding",
                "message": "ir.attachment.create sets public=True without both res_model and res_id; verify the file is intended to be world-readable",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-public-sensitive-binding",
                "title": "Public attachment is bound to sensitive model",
                "message": "ir.attachment.create sets public=True on sensitive model 'account.move'; verify no private business document is exposed",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-active-content",
                "title": "Attachment uses browser-active content type",
                "message": "ir.attachment.create stores browser-active content (mimetype=image/svg+xml); verify MIME allowlists, sanitization, download disposition, and public access",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-public-write",
                "title": "Attachment write makes file public",
                "message": "ir.attachment.write sets public=True; verify the existing file, linked record, and storage object are intentionally world-readable",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-res-model-write",
                "title": "Attachment res_model is changed from request input",
                "message": "ir.attachment.write uses request-derived res_model; attackers may rebind files to unintended protected models",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-res-id-write",
                "title": "Attachment res_id is changed from request input",
                "message": "ir.attachment.write uses request-derived res_id; verify ownership before rebinding files to existing records",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-access-token-write",
                "title": "Attachment access_token is request-controlled",
                "message": "ir.attachment.write stores a request-derived access_token; generate attachment tokens server-side",
            },
            {
                "source": "attachments",
                "rule_id": "odoo-attachment-tainted-lookup",
                "title": "Request-derived attachment lookup",
                "message": "Request-derived input selects ir.attachment records; verify ownership, res_model/res_id constraints, access_token, and record-rule behavior",
            },
        ]
    )

    assert coverage["mapped_rules"] == 12
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-attachment-public-route-mutation": "attachment_public_route_mutation",
        "odoo-attachment-sudo-mutation": "attachment_sudo_mutation",
        "odoo-attachment-tainted-res-model": "attachment_tainted_res_model",
        "odoo-attachment-tainted-res-id": "attachment_tainted_res_id",
        "odoo-attachment-public-orphan": "attachment_public_orphan",
        "odoo-attachment-public-sensitive-binding": "attachment_public_sensitive_binding",
        "odoo-attachment-active-content": "attachment_active_content",
        "odoo-attachment-public-write": "attachment_public_write",
        "odoo-attachment-tainted-res-model-write": "attachment_tainted_res_model_write",
        "odoo-attachment-tainted-res-id-write": "attachment_tainted_res_id_write",
        "odoo-attachment-tainted-access-token-write": "attachment_tainted_access_token_write",
        "odoo-attachment-tainted-lookup": "attachment_tainted_lookup",
    }
    assert any("CWE-345" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-732" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_file_upload_specific_risks() -> None:
    """File upload rules should not collapse into SSRF, IDOR, or generic attachment buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-tainted-path-write",
                "title": "Request-controlled path is opened for write",
                "message": "open() writes to a request-controlled path; validate basename, extension, destination, and traversal handling",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-base64-decode",
                "title": "Request-derived base64 upload is decoded",
                "message": "Request-derived base64 data is decoded; verify size limits, MIME validation, and storage destination",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-attachment-from-request",
                "title": "Attachment is created from request-derived upload data",
                "message": "ir.attachment is created from request-derived data; verify size, MIME, ACLs, res_model/res_id binding, and public flag",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-public-attachment-create",
                "title": "Uploaded attachment is created public",
                "message": "ir.attachment.create sets public=True; verify uploaded content is intentionally world-readable",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-active-content-attachment",
                "title": "Uploaded attachment uses browser-active content type",
                "message": "ir.attachment.create stores uploaded/browser-active content (mimetype=image/svg+xml); verify MIME allowlists, sanitization, download disposition, and public access",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-archive-extraction",
                "title": "Archive extraction requires traversal review",
                "message": "Archive extract/extractall can write files outside the intended directory through crafted member names; validate every member path before extraction",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-secure-filename-only",
                "title": "Upload path write relies on secure_filename only",
                "message": "secure_filename() normalizes a basename but does not enforce destination, extension, content type, uniqueness, or overwrite handling",
            },
            {
                "source": "file-uploads",
                "rule_id": "odoo-file-upload-unsafe-tempfile",
                "title": "Upload flow uses tempfile.mktemp",
                "message": "tempfile.mktemp() creates predictable race-prone paths; use mkstemp(), NamedTemporaryFile(), or TemporaryDirectory() with controlled permissions",
            },
        ]
    )

    assert coverage["mapped_rules"] == 8
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-file-upload-tainted-path-write": "file_upload_tainted_path_write",
        "odoo-file-upload-base64-decode": "file_upload_base64_decode",
        "odoo-file-upload-attachment-from-request": "file_upload_attachment_from_request",
        "odoo-file-upload-public-attachment-create": "file_upload_public_attachment_create",
        "odoo-file-upload-active-content-attachment": "file_upload_active_content_attachment",
        "odoo-file-upload-archive-extraction": "file_upload_archive_extraction",
        "odoo-file-upload-secure-filename-only": "file_upload_secure_filename_only",
        "odoo-file-upload-unsafe-tempfile": "file_upload_unsafe_tempfile",
    }
    assert any("CWE-434" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-377" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_binary_download_specific_risks() -> None:
    """Binary download rules should not collapse into SSRF or generic redirect buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-attachment-data-response",
                "title": "Controller returns attachment/binary data directly",
                "message": "Controller returns attachment or binary field data directly; verify record ownership, access_token handling, and response headers",
            },
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-ir-http-binary-content-sudo",
                "title": "ir.http binary_content is called with an elevated environment",
                "message": "ir.http.binary_content is reached through sudo()/with_user(SUPERUSER_ID); verify model/id/field inputs cannot bypass record rules or attachment ownership",
            },
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-tainted-binary-content-args",
                "title": "binary_content receives request-controlled arguments",
                "message": "ir.http.binary_content receives request-derived model/id/field arguments; constrain model, field, record ownership, and token semantics",
            },
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-tainted-web-content-redirect",
                "title": "Controller redirects to request-controlled web content URL",
                "message": "Controller builds a /web/content or /web/image URL from request input; verify record ownership, access_token, and allowed model/field scope",
            },
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-tainted-content-disposition",
                "title": "Download filename is request-controlled",
                "message": "content_disposition uses request-derived filename; validate CRLF, path separators, extension, and confusing Unicode/control characters",
            },
            {
                "source": "binary-downloads",
                "rule_id": "odoo-binary-active-inline-response",
                "title": "Controller serves attachment data as browser-active content",
                "message": "Controller response contains attachment/binary data with browser-active content type (content-type=image/svg+xml) without forced attachment disposition; verify sanitization, ownership, and download headers",
            },
        ]
    )

    assert coverage["mapped_rules"] == 6
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-binary-attachment-data-response": "binary_attachment_data_response",
        "odoo-binary-ir-http-binary-content-sudo": "binary_content_sudo",
        "odoo-binary-tainted-binary-content-args": "binary_tainted_content_args",
        "odoo-binary-tainted-web-content-redirect": "binary_tainted_web_content_redirect",
        "odoo-binary-tainted-content-disposition": "binary_tainted_content_disposition",
        "odoo-binary-active-inline-response": "binary_active_inline_response",
    }
    assert any("CWE-113" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-601" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_portal_route_specific_risks() -> None:
    """Portal access-token and route findings should keep portal-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-public-route",
                "title": "Portal route is publicly reachable",
                "message": "Portal-like route /my/orders uses auth='public'; verify portal tokens, ownership checks, and record rule boundaries",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-access-token-without-helper",
                "title": "Portal route accepts access_token without access helper",
                "message": "Portal route accepts an access_token argument but does not call a visible portal access helper; verify the token is actually validated before record access or rendering",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-document-check-missing-token",
                "title": "Portal access check does not pass access_token",
                "message": "Portal route accepts access_token but calls _document_check_access without passing it; shared portal links may fail open/closed inconsistently or bypass intended token validation",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-sudo-route-id-read",
                "title": "Portal route reads route-selected records through an elevated environment",
                "message": "Portal route uses a URL id to read records through sudo()/with_user(SUPERUSER_ID) without a portal access helper; verify ownership, token validation, and company isolation",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-token-exposed-without-check",
                "title": "Portal route exposes token data without access helper",
                "message": "Portal route returns or renders access_token/access_url data without an accompanying portal access helper; verify tokens are not leaked across records",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-url-generated-without-check",
                "title": "Portal URL generated without local access check",
                "message": "Portal route generates portal URLs without a nearby access helper; verify links are only created for records the caller may access",
            },
            {
                "source": "portal-routes",
                "rule_id": "odoo-portal-manual-access-token-check",
                "title": "Portal route manually compares access_token",
                "message": "Portal route manually compares access_token values instead of using a portal access helper; verify ACLs, ownership, company scope, and token semantics match Odoo's _document_check_access behavior",
            },
        ]
    )

    assert coverage["mapped_rules"] == 7
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-portal-public-route": "portal_public_route",
        "odoo-portal-access-token-without-helper": "portal_access_token_without_helper",
        "odoo-portal-document-check-missing-token": "portal_document_check_missing_token",
        "odoo-portal-sudo-route-id-read": "portal_sudo_route_id_read",
        "odoo-portal-token-exposed-without-check": "portal_token_exposed_without_check",
        "odoo-portal-url-generated-without-check": "portal_url_generated_without_check",
        "odoo-portal-manual-access-token-check": "portal_manual_access_token_check",
    }
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-345" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_oauth_missing_state_nonce() -> None:
    """OAuth callbacks without state/nonce binding should map to CSRF/replay taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "oauth",
                "rule_id": "odoo-oauth-missing-state-nonce-validation",
                "title": "OAuth callback lacks visible state or nonce validation",
                "message": "Public OAuth/OIDC callback lacks visible state or nonce validation",
            }
        ]
    )

    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "oauth_missing_state_nonce"
    assert "CWE-352" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_oauth_flow_specific_risks() -> None:
    """OAuth flow findings should not collapse into SSRF, hardcoded-secret, or domain buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-public-callback-route",
                "title": "Public OAuth callback route",
                "message": "OAuth/OIDC callback route is public; verify state/nonce validation",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-http-no-timeout",
                "title": "OAuth token/userinfo HTTP call lacks timeout",
                "message": "OAuth/OIDC token or userinfo validation performs outbound HTTP without timeout",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-http-verify-disabled",
                "title": "OAuth HTTP call disables TLS verification",
                "message": "OAuth/OIDC token or userinfo validation disables TLS verification",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-cleartext-http-url",
                "title": "OAuth token/userinfo HTTP call uses cleartext URL",
                "message": "OAuth/OIDC token or userinfo validation targets a literal http:// URL; use HTTPS so tokens and identities cannot be intercepted or downgraded",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-tainted-validation-url",
                "title": "Request-derived OAuth validation URL",
                "message": "Request-derived data controls OAuth/OIDC token or userinfo URL",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-jwt-verification-disabled",
                "title": "JWT decode disables signature or claim verification",
                "message": "OAuth/OIDC JWT decode disables verification",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-request-token-decode",
                "title": "Request-derived token is decoded",
                "message": "Request-derived OAuth/OIDC token is decoded",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-token-exchange-missing-pkce",
                "title": "OAuth authorization-code exchange lacks PKCE verifier",
                "message": "OAuth/OIDC authorization-code token exchange lacks a visible code_verifier",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-tainted-identity-write",
                "title": "Request-derived OAuth identity reaches user mutation",
                "message": "Request-derived OAuth identity data reaches res.users mutation",
            },
            {
                "source": "oauth-flows",
                "rule_id": "odoo-oauth-session-authenticate",
                "title": "OAuth flow authenticates a session",
                "message": "OAuth/OIDC flow calls request.session.authenticate",
            },
        ]
    )

    assert coverage["mapped_rules"] == 10
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-oauth-public-callback-route": "oauth_public_callback_route",
        "odoo-oauth-http-no-timeout": "oauth_http_without_timeout",
        "odoo-oauth-http-verify-disabled": "oauth_tls_verification_disabled",
        "odoo-oauth-cleartext-http-url": "oauth_cleartext_http_url",
        "odoo-oauth-tainted-validation-url": "oauth_tainted_validation_url",
        "odoo-oauth-jwt-verification-disabled": "oauth_jwt_verification_disabled",
        "odoo-oauth-request-token-decode": "oauth_request_token_decode",
        "odoo-oauth-token-exchange-missing-pkce": "oauth_token_exchange_missing_pkce",
        "odoo-oauth-tainted-identity-write": "oauth_tainted_identity_write",
        "odoo-oauth-session-authenticate": "oauth_session_authenticate",
    }
    assert any("CWE-918" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-347" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_session_cookie_weak_flags() -> None:
    """Weak session/token cookie flag rules should map to cookie hardening taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "session-auth",
                "rule_id": "odoo-session-sensitive-cookie-weak-flags",
                "title": "Session or token cookie is set without hardened flags",
                "message": "Controller sets a session/token/CSRF-shaped cookie without secure=True, httponly=True, and SameSite=Lax/Strict",
            }
        ]
    )

    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "session_cookie_weak_flags"
    assert "CWE-614" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_session_auth_specific_risks() -> None:
    """Session/auth controller rules should not fall through to generic web buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "session-auth",
                "rule_id": "odoo-session-public-authenticate",
                "title": "Public route authenticates with request-controlled credentials",
                "message": "Public/unauthenticated controller calls request.session.authenticate with request-derived credentials",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-public-user-lookup",
                "title": "Public route looks up users from request data",
                "message": "Public/unauthenticated route queries res.users with request-derived input",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-direct-uid-assignment",
                "title": "Controller directly assigns request.session.uid",
                "message": "Controller assigns request.session.uid directly; verify no request-controlled uid can create session fixation or account switching",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-direct-request-uid-assignment",
                "title": "Controller directly assigns request.uid",
                "message": "Controller assigns request.uid directly",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-update-env-superuser",
                "title": "Controller switches request environment to superuser",
                "message": "request.update_env switches the current request to a superuser/admin identity",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-update-env-tainted-user",
                "title": "request.update_env uses request-controlled user",
                "message": "request.update_env receives a request-derived user/uid",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-public-update-env",
                "title": "Public route switches request environment",
                "message": "Public/unauthenticated route calls request.update_env(user=...)",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-environment-superuser",
                "title": "Manual Environment uses superuser",
                "message": "Manual Odoo Environment is constructed with a superuser/admin identity",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-environment-tainted-user",
                "title": "Manual Environment uses request-controlled user",
                "message": "Manual Odoo Environment is constructed from request-derived uid",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-logout-weak-route",
                "title": "Logout route has weak method or CSRF posture",
                "message": "Controller exposes logout/session reset through a public/GET/csrf=False route",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-token-exposed",
                "title": "Controller response exposes session or CSRF token",
                "message": "Controller returns CSRF/session token material",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-ir-http-auth-override",
                "title": "ir.http authentication boundary is overridden",
                "message": "ir.http method participates in global request authentication",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-ir-http-superuser-auth",
                "title": "ir.http authentication override grants elevated user",
                "message": "ir.http method appears to assign or return a superuser/admin identity",
            },
            {
                "source": "session-auth",
                "rule_id": "odoo-session-ir-http-bypass",
                "title": "ir.http authentication override may bypass checks",
                "message": "ir.http method appears to return success without a visible parent authentication call",
            },
        ]
    )

    assert coverage["mapped_rules"] == 14
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-session-public-authenticate": "session_public_authenticate",
        "odoo-session-public-user-lookup": "session_public_user_lookup",
        "odoo-session-direct-uid-assignment": "session_direct_uid_assignment",
        "odoo-session-direct-request-uid-assignment": "session_direct_request_uid_assignment",
        "odoo-session-update-env-superuser": "session_update_env_superuser",
        "odoo-session-update-env-tainted-user": "session_update_env_tainted_user",
        "odoo-session-public-update-env": "session_public_update_env",
        "odoo-session-environment-superuser": "session_environment_superuser",
        "odoo-session-environment-tainted-user": "session_environment_tainted_user",
        "odoo-session-logout-weak-route": "session_logout_weak_route",
        "odoo-session-token-exposed": "session_token_exposed",
        "odoo-session-ir-http-auth-override": "session_ir_http_auth_override",
        "odoo-session-ir-http-superuser-auth": "session_ir_http_superuser_auth",
        "odoo-session-ir-http-bypass": "session_ir_http_bypass",
    }
    assert any("CWE-384" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_sensitive_cookie_cache_response() -> None:
    """Cookie-bearing public response cache rules should map to cache disclosure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "cache-headers",
                "rule_id": "odoo-cache-public-sensitive-cookie-response",
                "title": "Public response sets sensitive cookie without no-store cache-control",
                "message": "Public controller response sets a session/token/CSRF-shaped cookie without obvious Cache-Control: no-store/private headers",
            }
        ]
    )

    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "sensitive_cookie_cacheable_response"
    assert "CWE-525" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_cache_header_specific_risks() -> None:
    """Cache-control response findings should not collapse into hardcoded-secret taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "cache-headers",
                "rule_id": "odoo-cache-public-sensitive-response",
                "title": "Public sensitive response lacks no-store cache-control",
                "message": "Public controller response includes token/secret-like data without obvious Cache-Control: no-store/private headers; prevent browser/proxy caching of account or document secrets",
            },
            {
                "source": "cache-headers",
                "rule_id": "odoo-cache-public-sensitive-render",
                "title": "Public render includes token/secret-like data",
                "message": "Public route renders token/secret-like values; verify the response sets no-store/private cache headers and does not leak through shared caches or referrers",
            },
            {
                "source": "cache-headers",
                "rule_id": "odoo-cache-public-file-download",
                "title": "Public file download may be cacheable",
                "message": "Public sensitive-looking download uses send_file without cache disabling arguments; ensure private documents are not cached by browsers or proxies",
            },
            {
                "source": "cache-headers",
                "rule_id": "odoo-cache-public-cacheable-sensitive-route",
                "title": "Public sensitive route sets cacheable headers",
                "message": "Public sensitive-looking route sets cacheable Cache-Control headers; tokenized pages, invoices, exports, and downloads should use no-store/private policies",
            },
        ]
    )

    assert coverage["mapped_rules"] == 4
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-cache-public-sensitive-response": "cache_public_sensitive_response",
        "odoo-cache-public-sensitive-render": "cache_public_sensitive_render",
        "odoo-cache-public-file-download": "cache_public_file_download",
        "odoo-cache-public-cacheable-sensitive-route": "cache_public_cacheable_sensitive_route",
    }
    assert all("CWE-525" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-359" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_json_route_record_idor() -> None:
    """JSON route request-controlled record selectors should map to IDOR taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-tainted-record-mutation",
                "title": "JSON request controls record selection for mutation",
                "message": "JSON route selects records from request-controlled IDs/domains before create/write/unlink",
            },
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-tainted-record-read",
                "title": "JSON request controls record selection for read",
                "message": "JSON route reads records selected by request-controlled IDs/domains",
            },
        ]
    )

    assert coverage["mapped_rules"] == 2
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"json_route_record_idor"}
    assert all("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_json_route_surface_and_csrf() -> None:
    """JSON route exposure should not collapse into generic route or CSRF taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-public-auth",
                "title": "Public JSON route exposed",
                "message": "JSON route /public/json uses auth='public'; verify authentication, rate limiting, and CSRF/session assumptions",
            },
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-csrf-disabled",
                "title": "JSON route explicitly disables CSRF",
                "message": "JSON route /public/json sets csrf=False; verify it cannot be called cross-site with ambient session credentials",
            },
        ]
    )

    assert coverage["mapped_rules"] == 2
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-json-route-public-auth": "json_route_public_auth",
        "odoo-json-route-csrf-disabled": "json_route_csrf_disabled",
    }
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-352" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_json_route_mutation_and_domain_risks() -> None:
    """JSON route ORM risks should not map through SSRF, generic sudo, or generic domain buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-sudo-mutation",
                "title": "JSON route mutates records through an elevated environment",
                "message": "JSON route performs create/write/unlink through sudo()/with_user(SUPERUSER_ID); verify caller authorization, ownership checks, and company isolation",
            },
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-mass-assignment",
                "title": "JSON request data flows into ORM mutation",
                "message": "JSON route passes request-derived data into create/write/unlink; whitelist fields and reject privilege, workflow, ownership, and company fields",
            },
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-public-sudo-read",
                "title": "Public JSON route reads through an elevated environment",
                "message": "Public JSON route reads/searches through sudo()/with_user(SUPERUSER_ID); verify it cannot expose records outside the caller's ownership or company",
            },
            {
                "source": "json-routes",
                "rule_id": "odoo-json-route-tainted-domain",
                "title": "JSON request controls ORM search domain",
                "message": "JSON request controls search domain; validate allowed fields/operators and prevent cross-record or cross-company discovery",
            },
        ]
    )

    assert coverage["mapped_rules"] == 4
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-json-route-sudo-mutation": "json_route_sudo_mutation",
        "odoo-json-route-mass-assignment": "json_route_mass_assignment",
        "odoo-json-route-public-sudo-read": "json_route_public_sudo_read",
        "odoo-json-route-tainted-domain": "json_route_tainted_domain",
    }
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-915" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_payment_webhook_integrity() -> None:
    """Payment callback integrity rules should map to specific payment taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "payments",
                "rule_id": "odoo-payment-public-callback-no-signature",
                "title": "Public payment callback lacks visible signature validation",
                "message": "Public csrf=False payment/webhook route has no visible signature/HMAC validation",
            },
            {
                "source": "payments",
                "rule_id": "odoo-payment-weak-signature-compare",
                "title": "Payment handler compares signatures without constant-time check",
                "message": "Payment/webhook handler compares signature-like values with == or !=; use hmac.compare_digest or a provider verifier",
            },
            {
                "source": "payments",
                "rule_id": "odoo-payment-state-without-idempotency-check",
                "title": "Payment handler changes state without visible idempotency guard",
                "message": "Payment notification/webhook handler changes transaction state without visible state, duplicate event, or provider-reference idempotency checks",
            },
            {
                "source": "payments",
                "rule_id": "odoo-payment-state-without-validation",
                "title": "Payment handler changes transaction state without visible validation",
                "message": "Payment notification/webhook handler changes transaction state without visible signature/reference validation",
            },
            {
                "source": "payments",
                "rule_id": "odoo-payment-state-without-amount-currency-check",
                "title": "Payment handler changes state without amount/currency reconciliation",
                "message": "Payment notification/webhook handler finalizes transaction state without visible amount and currency checks",
            },
            {
                "source": "payments",
                "rule_id": "odoo-payment-transaction-lookup-weak",
                "title": "Payment transaction lookup lacks provider/reference scoping",
                "message": "Payment handler searches payment.transaction without visible provider/reference scoping",
            },
        ]
    )

    assert coverage["mapped_rules"] == 6
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-payment-public-callback-no-signature": "payment_public_callback_no_signature",
        "odoo-payment-weak-signature-compare": "payment_weak_signature_compare",
        "odoo-payment-state-without-idempotency-check": "payment_state_without_idempotency",
        "odoo-payment-state-without-validation": "payment_state_without_validation",
        "odoo-payment-state-without-amount-currency-check": "payment_state_without_reconciliation",
        "odoo-payment-transaction-lookup-weak": "payment_transaction_lookup_weak",
    }
    assert any("CWE-294" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-208" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_deployment_oauth_and_secret_posture() -> None:
    """Deployment OAuth and secret posture findings should not map to eval, sudo, or generic secrets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-oauth-missing-validation-endpoint",
                "title": "OAuth provider lacks validation endpoint",
                "message": "Enabled auth.oauth.provider has no validation_endpoint; verify tokens are validated against the provider before account login/signup",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-oauth-insecure-endpoint",
                "title": "OAuth provider uses insecure HTTP endpoint",
                "message": "auth.oauth.provider field 'token_endpoint' uses HTTP; OAuth tokens and identities must use HTTPS endpoints",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-oauth-client-secret-committed",
                "title": "OAuth client secret committed in module data",
                "message": "auth.oauth.provider commits client_secret in XML data; move provider secrets to environment/provisioning storage and rotate the secret",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-weak-admin-passwd",
                "title": "Odoo database manager master password is weak",
                "message": "admin_passwd is empty, short, or placeholder-like; database manager and maintenance flows require a strong environment-specific master password",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-admin-passwd-committed",
                "title": "Odoo database manager master password is committed",
                "message": "admin_passwd appears to be committed in deployment config; move it to secret storage and rotate it before production use",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-deploy-oauth-missing-validation-endpoint": "deployment_oauth_validation_missing",
        "odoo-deploy-oauth-insecure-endpoint": "deployment_oauth_insecure_endpoint",
        "odoo-deploy-oauth-client-secret-committed": "deployment_committed_secret",
        "odoo-deploy-weak-admin-passwd": "deployment_weak_master_password",
        "odoo-deploy-admin-passwd-committed": "deployment_committed_secret",
    }
    assert any("CWE-287" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-319" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_deployment_runtime_posture() -> None:
    """Deployment runtime posture findings need deployment-specific operational taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-dev-mode-enabled",
                "title": "Developer mode is enabled in deployment config",
                "message": "dev/dev_mode is enabled; production deployments should not run reload, qweb, xml, werkzeug, or all developer modes",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-list-db-enabled",
                "title": "Database listing is enabled",
                "message": "list_db is enabled; attackers can enumerate database names and target login/database-manager flows",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-wildcard-dbfilter",
                "title": "Database filter matches arbitrary database names",
                "message": "dbfilter is wildcard-like; multi-database deployments should bind databases to expected hostnames to prevent cross-database confusion",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-db-sslmode-opportunistic",
                "title": "Database TLS mode is opportunistic or disabled",
                "message": "db_sslmode does not require verified PostgreSQL TLS; production deployments should use verify-full or verify-ca when the database is remote or untrusted",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-time-limit-disabled",
                "title": "Worker execution time limit is disabled",
                "message": "limit_time_real is zero or negative; production deployments should enforce worker time limits to contain slow reports, imports, and integrations",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-debug-logging",
                "title": "Debug logging is enabled",
                "message": "Debug logging is enabled; production logs can expose SQL, request data, tokens, or PII",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-base-url-not-frozen",
                "title": "Base URL is not frozen",
                "message": "web.base.url.freeze is false; host-header or proxy mistakes can affect generated links such as portal and reset URLs",
            },
            {
                "source": "deployment",
                "rule_id": "odoo-deploy-oauth-auto-signup",
                "title": "OAuth auto-signup is enabled",
                "message": "auth_oauth.allow_signup is enabled; verify OAuth providers and domain restrictions cannot create unintended accounts",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-deploy-dev-mode-enabled": "deployment_dev_or_test_mode",
        "odoo-deploy-list-db-enabled": "deployment_database_manager_exposure",
        "odoo-deploy-wildcard-dbfilter": "deployment_dbfilter_weak",
        "odoo-deploy-db-sslmode-opportunistic": "deployment_database_tls_weak",
        "odoo-deploy-time-limit-disabled": "deployment_worker_limits_weak",
        "odoo-deploy-debug-logging": "deployment_debug_logging",
        "odoo-deploy-base-url-not-frozen": "deployment_base_url_integrity",
        "odoo-deploy-oauth-auto-signup": "deployment_open_signup",
    }
    assert any("CWE-532" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-770" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_api_key_credential_exposure() -> None:
    """API-key handling rules should map to credential exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-config-parameter-request-secret",
                "title": "Request-derived API key is stored in configuration",
                "message": "Request-derived API key/token material is persisted with ir.config_parameter.set_param()",
            },
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-returned-from-route",
                "title": "Route response appears to return API key material",
                "message": "Controller response references API-key/token material",
            },
        ]
    )

    assert coverage["mapped_rules"] == 2
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"api_key_credential_exposure"}
    assert all("CWE-522" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_api_key_mutation_risks() -> None:
    """API-key mutation findings should not map to CSRF, lifecycle, or generic credential buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-public-route-mutation",
                "title": "Public route mutates API keys",
                "message": "Public/unauthenticated route mutates res.users.apikeys; verify only the authenticated owner or administrators can create, revoke, or rename API keys",
            },
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-sudo-mutation",
                "title": "API key mutation runs with elevated environment",
                "message": "res.users.apikeys.create runs through sudo()/with_user(SUPERUSER_ID); verify caller identity, owner scoping, revocation semantics, and audit logging",
            },
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-request-derived-mutation",
                "title": "Request-derived data reaches API key mutation",
                "message": "Request-derived data reaches res.users.apikeys.create; whitelist fields and prevent callers from choosing another user_id or scope",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-api-key-public-route-mutation": "api_key_public_route_mutation",
        "odoo-api-key-sudo-mutation": "api_key_sudo_mutation",
        "odoo-api-key-request-derived-mutation": "api_key_request_derived_mutation",
    }
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_api_key_lookup_and_seeded_records() -> None:
    """API-key lookup and seeded-record findings should keep credential-specific CWE context."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-xml-record",
                "title": "API key record is declared in XML data",
                "message": "Module data declares a res.users.apikeys record; verify credentials are not seeded, exported, or recreated across databases",
            },
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-csv-record",
                "title": "API key record is declared in CSV data",
                "message": "CSV data declares a res.users.apikeys record; verify credentials are not seeded, exported, or recreated across databases",
            },
            {
                "source": "api-keys",
                "rule_id": "odoo-api-key-tainted-lookup",
                "title": "Request-derived API key lookup",
                "message": "Request-derived data is used to query API-key records; verify constant-time credential validation, hashing, and user scoping rather than raw key lookup",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-api-key-xml-record": "api_key_xml_record",
        "odoo-api-key-csv-record": "api_key_csv_record",
        "odoo-api-key-tainted-lookup": "api_key_tainted_lookup",
    }
    assert any("CWE-798" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-522" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_secret_source_and_config_values() -> None:
    """Committed secret findings should keep source/config specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "secrets",
                "rule_id": "odoo-secret-hardcoded-value",
                "title": "Hardcoded secret-like value",
                "message": "Secret-like assignment 'api_key' contains committed value sk_...; rotate and move to environment/config storage",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-config-parameter-set-param",
                "title": "Sensitive ir.config_parameter value set in code",
                "message": "Code sets ir.config_parameter 'payment.provider.secret' to committed value sk_...; avoid shipping production secrets in module code",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-private-key-block",
                "title": "Private key material committed",
                "message": "Repository contains a PEM private key block; remove it from source control, rotate the key, and move it to secret storage",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-config-parameter",
                "title": "Sensitive ir.config_parameter value committed",
                "message": "Module data commits ir.config_parameter 'payment.provider.secret' with value sk_...; module updates can overwrite production secrets/config",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-config-file-value",
                "title": "Secret-like value committed in config file",
                "message": "Config file contains 'db_password' with committed value pass...; keep real secrets out of source",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-secret-hardcoded-value": "secret_hardcoded_value",
        "odoo-secret-config-parameter-set-param": "secret_config_parameter_code_value",
        "odoo-secret-private-key-block": "secret_private_key_block",
        "odoo-secret-config-parameter": "secret_config_parameter_xml_value",
        "odoo-secret-config-file-value": "secret_config_file_value",
    }
    assert all("CWE-798" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert all("CWE-522" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_secret_password_records() -> None:
    """Committed password findings should distinguish weak and reusable credentials."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "secrets",
                "rule_id": "odoo-secret-weak-user-password-data",
                "title": "Weak user password committed in module data",
                "message": "res.users password in XML data is a weak default; remove it and rotate the account",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-user-password-data",
                "title": "User password committed in module data",
                "message": "res.users password is committed in XML data; remove it and rotate the account",
            },
            {
                "source": "secrets",
                "rule_id": "odoo-secret-weak-admin-passwd",
                "title": "Weak Odoo database manager password",
                "message": "admin_passwd is empty or 'admin'; database manager can be brute-forced or guessed",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-secret-weak-user-password-data": "secret_weak_user_password_data",
        "odoo-secret-user-password-data": "secret_user_password_data",
        "odoo-secret-weak-admin-passwd": "secret_weak_admin_passwd",
    }
    assert any("CWE-521" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert all("CWE-259" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_identity_mutation_risks() -> None:
    """Identity mutation findings should not collapse into generic route, sudo, secret, or SSRF buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "identity-mutations",
                "rule_id": "odoo-identity-public-route-mutation",
                "title": "Public route mutates users or groups",
                "message": "Public route /public/promote mutates res.users; verify only authenticated administrators can change identity, groups, and companies",
            },
            {
                "source": "identity-mutations",
                "rule_id": "odoo-identity-elevated-mutation",
                "title": "Identity mutation runs in elevated context",
                "message": "res.users mutation uses sudo()/with_user(SUPERUSER_ID); verify explicit admin checks and audit trail before privilege changes",
            },
            {
                "source": "identity-mutations",
                "rule_id": "odoo-identity-request-derived-mutation",
                "title": "Request-derived data reaches identity mutation",
                "message": "Request-derived data reaches res.users.write; whitelist allowed fields and reject privilege, company, login, and password changes",
            },
            {
                "source": "identity-mutations",
                "rule_id": "odoo-identity-privilege-field-write",
                "title": "Identity mutation writes privilege-bearing fields",
                "message": "res.users.write writes privilege-bearing field(s): company_ids, groups_id; verify group/company/user activation changes are admin-only",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-identity-public-route-mutation": "identity_public_route_mutation",
        "odoo-identity-elevated-mutation": "identity_elevated_mutation",
        "odoo-identity-request-derived-mutation": "identity_request_derived_mutation",
        "odoo-identity-privilege-field-write": "identity_privilege_field_write",
    }
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-915" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_raw_sql_injection_shapes() -> None:
    """Raw SQL injection findings should not collapse into generic SQL taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "raw-sql",
                "rule_id": "odoo-raw-sql-interpolated-query",
                "title": "Raw SQL query is built with interpolation",
                "message": "cr.execute() receives SQL built through f-strings, %, .format(), or concatenation; use bound parameters and psycopg2.sql for identifiers",
            },
            {
                "source": "raw-sql",
                "rule_id": "odoo-raw-sql-request-derived-input",
                "title": "Request-derived value reaches raw SQL",
                "message": "Request-derived data reaches cr.execute(); verify parameter binding, allowed identifiers, and domain-equivalent access checks",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-raw-sql-interpolated-query": "raw_sql_interpolated_query",
        "odoo-raw-sql-request-derived-input": "raw_sql_request_derived_input",
    }
    assert all("CWE-89" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_raw_sql_scope_and_transaction_shapes() -> None:
    """Destructive SQL and transaction-control findings need non-injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "raw-sql",
                "rule_id": "odoo-raw-sql-broad-destructive-query",
                "title": "Raw SQL performs broad destructive operation",
                "message": "Runtime cr.execute() performs destructive SQL without an obvious WHERE clause; verify tenant scoping, backups, and ORM invariants",
            },
            {
                "source": "raw-sql",
                "rule_id": "odoo-raw-sql-write-no-company-scope",
                "title": "Raw SQL write lacks company scoping",
                "message": "Runtime UPDATE/DELETE SQL has a WHERE clause but no visible company filter; verify multi-company isolation and record rule equivalence",
            },
            {
                "source": "raw-sql",
                "rule_id": "odoo-raw-sql-manual-transaction",
                "title": "Manual transaction control in runtime code",
                "message": "Runtime code calls commit()/rollback(); verify partial writes cannot bypass Odoo request, ORM, and security transaction expectations",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-raw-sql-broad-destructive-query": "raw_sql_broad_destructive_query",
        "odoo-raw-sql-write-no-company-scope": "raw_sql_write_no_company_scope",
        "odoo-raw-sql-manual-transaction": "raw_sql_manual_transaction",
    }
    assert any("CWE-639" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-664" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_loose_python_execution_shapes() -> None:
    """Server action dynamic execution should map to loose-python taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-eval-exec",
                "title": "Dynamic Python execution in loose script",
                "message": "eval()/exec() in server actions or loose scripts can become code execution if inputs are not strictly controlled",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-safe-eval",
                "title": "safe_eval in loose script",
                "message": "safe_eval() in server actions/scripts needs strict input provenance review and sandbox assumptions",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-sql-injection",
                "title": "Raw SQL built with string interpolation",
                "message": "cr.execute() receives SQL built with interpolation/concatenation; use parameters or psycopg2.sql for identifiers",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-loose-python-eval-exec": "loose_python_eval_exec",
        "odoo-loose-python-safe-eval": "loose_python_safe_eval",
        "odoo-loose-python-sql-injection": "loose_python_sql_injection",
    }
    assert any("CWE-94" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-89" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_loose_python_mutation_and_runtime_shapes() -> None:
    """Server action mutation/runtime risks should not map to action-window or safe_eval buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-sudo-write",
                "title": "Privileged mutation in loose script",
                "message": "sudo()/with_user(SUPERUSER_ID) is chained into write/create/unlink; verify this cannot bypass intended record rules or company isolation",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-sudo-method-call",
                "title": "Privileged business method call in loose script",
                "message": "sudo()/with_user(SUPERUSER_ID) is used to call a business/action method; verify workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-sensitive-model-mutation",
                "title": "Sensitive model mutation in loose script",
                "message": "Server action or loose script mutates sensitive model 'res.users'; verify actor, trigger scope, idempotency, and audit trail",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-manual-transaction",
                "title": "Manual transaction control",
                "message": "Manual commit()/rollback() can leave partial state and bypass Odoo transaction expectations",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-http-no-timeout",
                "title": "Outbound HTTP without timeout in loose script",
                "message": "Server actions or loose scripts perform outbound HTTP without timeout; review SSRF, retry behavior, and worker exhaustion risk",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-tls-verify-disabled",
                "title": "Loose script disables TLS verification",
                "message": "Server actions or loose scripts pass verify=False to outbound HTTP; privileged automation should not permit man-in-the-middle attacks",
            },
            {
                "source": "loose-python",
                "rule_id": "odoo-loose-python-cleartext-http-url",
                "title": "Loose script uses cleartext HTTP URL",
                "message": "Server actions or loose scripts outbound HTTP targets a literal http:// URL; use HTTPS to protect privileged automation payloads and response data from interception or downgrade",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-loose-python-sudo-write": "loose_python_sudo_write",
        "odoo-loose-python-sudo-method-call": "loose_python_sudo_method_call",
        "odoo-loose-python-sensitive-model-mutation": "loose_python_sensitive_model_mutation",
        "odoo-loose-python-manual-transaction": "loose_python_manual_transaction",
        "odoo-loose-python-http-no-timeout": "loose_python_http_no_timeout",
        "odoo-loose-python-tls-verify-disabled": "loose_python_tls_verification_disabled",
        "odoo-loose-python-cleartext-http-url": "loose_python_cleartext_http_url",
    }
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-664" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-918" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-295" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_runtime_config_security_misconfiguration() -> None:
    """Runtime config posture rules should map to toggle/base-url taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-tainted-security-toggle-write",
                "title": "Security-sensitive config toggle receives request-controlled value",
                "message": "set_param writes a request-derived value to security-sensitive key 'list_db'",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-tainted-base-url-write",
                "title": "Base URL config parameter receives request-controlled value",
                "message": "set_param writes request-derived web.base.url",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-security-toggle-enabled",
                "title": "Security-sensitive config toggle is enabled",
                "message": "set_param enables security-sensitive key 'auth.signup.allow_uninvited' with value 'True'; verify this is admin-only, audited, and acceptable for production",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-insecure-base-url-write",
                "title": "Base URL config parameter is set to an insecure endpoint",
                "message": "set_param writes web.base.url to HTTP or a local host; generated portal, OAuth, and password-reset links should use the public HTTPS origin",
            },
        ]
    )

    assert coverage["mapped_rules"] == 4
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-config-param-tainted-security-toggle-write": "config_parameter_security_toggle_write",
        "odoo-config-param-tainted-base-url-write": "config_parameter_base_url_write",
        "odoo-config-param-security-toggle-enabled": "config_parameter_security_toggle_write",
        "odoo-config-param-insecure-base-url-write": "config_parameter_base_url_write",
    }
    assert any("CWE-16" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-601" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_config_parameter_sensitive_read() -> None:
    """Sensitive config reads should map to data exposure rather than generic sudo taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-public-sensitive-read",
                "title": "Public route reads sensitive config parameter",
                "message": "Public route reads sensitive ir.config_parameter key 'payment.provider.secret'; verify it cannot be returned, logged, or used to authorize attacker-controlled flows",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-sudo-sensitive-read",
                "title": "Sensitive config parameter is read with elevated environment",
                "message": "sudo()/with_user(SUPERUSER_ID).get_param reads sensitive key 'jwt.signing_key'; verify callers cannot expose or misuse global secrets",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"config_parameter_sensitive_read"}
    assert all("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_config_parameter_tainted_access() -> None:
    """Request-controlled config access should get explicit ir.config_parameter taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-tainted-key-read",
                "title": "Config parameter key is request-controlled",
                "message": "get_param key is request-derived; constrain allowed keys to prevent arbitrary system-parameter disclosure",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-tainted-key-write",
                "title": "Config parameter write key is request-controlled",
                "message": "set_param key is request-derived; attackers may be able to modify arbitrary system parameters",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-tainted-value-write",
                "title": "Config parameter value is request-controlled",
                "message": "set_param writes request-derived value to key '<dynamic>'; verify authentication, authorization, validation, and auditability",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"config_parameter_tainted_access"}
    assert all("CWE-915" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_config_parameter_secret_defaults() -> None:
    """Literal secret config defaults and writes should map to hardcoded credential taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-sensitive-default",
                "title": "Sensitive config parameter has hardcoded default",
                "message": "get_param for sensitive key 'jwt.signing_key' uses a literal default; avoid deployable fallback secrets and require explicit configured values",
            },
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-hardcoded-sensitive-write",
                "title": "Sensitive config parameter is set to a hardcoded value",
                "message": "set_param writes a literal value to sensitive key 'payment.provider.api_key'; avoid committing deployable secrets and rotate any value that reached source control",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"config_parameter_secret_default"}
    assert all("CWE-798" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_config_parameter_elevated_write() -> None:
    """sudo config writes should map to config posture, not generic sudo."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "config-parameters",
                "rule_id": "odoo-config-param-sudo-write",
                "title": "Config parameter is written with elevated environment",
                "message": "sudo()/with_user(SUPERUSER_ID).set_param writes key 'auth.signup.allow_uninvited'; verify callers cannot alter global security, mail, OAuth, signup, or integration settings",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "config_parameter_elevated_write"
    assert "CWE-269" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_field_sensitive_access_control() -> None:
    """Sensitive fields without strict groups should map to field access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "field-security",
                "rule_id": "odoo-field-sensitive-no-groups",
                "title": "Sensitive field has no group restriction",
                "message": "Sensitive-looking field 'api_key' has no groups= restriction; verify only trusted users can read it",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-sensitive-public-groups",
                "title": "Sensitive field is exposed to public or portal group",
                "message": "Sensitive-looking field 'access_token' is assigned to public/portal groups; verify it cannot leak credentials or access tokens",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-related-sensitive-no-admin-groups",
                "title": "Related field exposes sensitive target without admin-only groups",
                "message": "Related field 'partner_token' projects sensitive path 'user_id.partner_id.signup_token' without admin-only groups",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"field_sensitive_access_control"}
    assert all("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_field_sensitive_persistence_leak() -> None:
    """Indexes, chatter tracking, and copies should map to persistence leakage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "field-security",
                "rule_id": "odoo-field-sensitive-indexed",
                "title": "Sensitive field is indexed",
                "message": "Sensitive-looking field 'api_key' sets index=True; review database exposure, lookup paths, and whether a hashed/tokenized value should be indexed instead",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-sensitive-tracking",
                "title": "Sensitive field is tracked in chatter",
                "message": "Sensitive-looking field 'api_token' enables mail tracking; value changes can leak into chatter, notifications, or audit exports",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-sensitive-copyable",
                "title": "Sensitive field can be copied",
                "message": "Sensitive-looking field 'refresh_token' does not set copy=False; duplicated records may clone credentials, tokens, or secrets",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"field_sensitive_persistence_leak"}
    assert all("CWE-522" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_field_compute_sudo_projection() -> None:
    """Sudo-computed fields should map to record-rule projection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "field-security",
                "rule_id": "odoo-field-compute-sudo-sensitive",
                "title": "Field computes through sudo",
                "message": "Field 'secret_count' sets compute_sudo=True; verify computed values cannot bypass record rules or company isolation",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-compute-sudo-scalar-no-admin-groups",
                "title": "Sudo-computed scalar field lacks admin-only groups",
                "message": "Scalar field 'private_summary' sets compute_sudo=True without admin-only groups; verify it cannot project private model data past record rules",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"field_compute_sudo_projection"}
    assert all("CWE-863" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_field_html_sanitizer_bypass() -> None:
    """HTML field sanitizer metadata should map to injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "field-security",
                "rule_id": "odoo-field-html-sanitizer-disabled",
                "title": "HTML field disables sanitizer protections",
                "message": "HTML field 'raw_body' disables sanitize; verify every writer and renderer is trusted",
            },
            {
                "source": "field-security",
                "rule_id": "odoo-field-html-sanitize-overridable-no-admin-groups",
                "title": "HTML sanitizer override is not admin-only",
                "message": "HTML field 'body' allows sanitizer override without admin-only groups; verify non-admin writers cannot persist unsafe markup",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"field_html_sanitizer_bypass"}
    assert all("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_field_binary_database_storage() -> None:
    """Binary attachment=False fields should map to storage exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "field-security",
                "rule_id": "odoo-field-binary-db-storage",
                "title": "Binary field disables attachment storage",
                "message": "Binary field 'payload' uses attachment=False; review database bloat, backup exposure, and access behavior",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "field_binary_database_storage"
    assert "CWE-922" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_property_field_scope_and_access() -> None:
    """Company-dependent property fields should get property-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "property-fields",
                "rule_id": "odoo-property-field-no-company-field",
                "title": "Company-dependent field on model without company_id",
                "message": "Field 'property_account_income_id' is company_dependent=True but model has no company_id field; review property fallback and cross-company behavior",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-field-default",
                "title": "Company-dependent field defines a default",
                "message": "Field 'property_journal_id' is company_dependent=True and defines default=; verify default does not mask missing company-specific properties",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-sensitive-field-no-groups",
                "title": "Sensitive company-dependent field lacks groups",
                "message": "Sensitive company-dependent field 'property_account_income_id' has no groups= restriction; verify users cannot alter company-specific accounting/security values",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-property-field-no-company-field"] == "property_field_company_scope"
    assert shapes["odoo-property-field-default"] == "property_field_company_scope"
    assert shapes["odoo-property-sensitive-field-no-groups"] == "property_field_sensitive_access"


def test_taxonomy_coverage_classifies_property_records_and_sensitive_values() -> None:
    """ir.property defaults should not remain unmapped or collapse into generic field buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "property-fields",
                "rule_id": "odoo-property-global-default",
                "title": "ir.property record has no company",
                "message": "ir.property 'property_receivable_global' has no company_id and becomes a global fallback; verify this is safe for all companies",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-no-resource-scope",
                "title": "ir.property record has no resource scope",
                "message": "ir.property 'property_receivable_global' has no res_id and may apply broadly as a default; verify intended model/company scope",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-sensitive-value",
                "title": "Sensitive ir.property value is preconfigured",
                "message": "ir.property 'property_gateway_key' configures a sensitive field 'x_provider_api_key'; verify accounting/security defaults are company-scoped",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-property-global-default"] == "property_record_global_default"
    assert shapes["odoo-property-no-resource-scope"] == "property_record_broad_scope"
    assert shapes["odoo-property-sensitive-value"] == "property_sensitive_value"


def test_taxonomy_coverage_classifies_property_runtime_mutations() -> None:
    """Runtime ir.property mutations should map to property-specific access taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "property-fields",
                "rule_id": "odoo-property-public-route-mutation",
                "title": "Public route mutates ir.property",
                "message": "Public route writes ir.property; verify unauthenticated users cannot alter company-specific accounting or configuration defaults",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-sudo-mutation",
                "title": "ir.property is mutated through privileged context",
                "message": "sudo()/with_user(SUPERUSER_ID) mutates ir.property; verify explicit admin checks and company scoping before changing property defaults",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-request-derived-mutation",
                "title": "Request-derived data reaches ir.property",
                "message": "Request-derived data reaches ir.property mutation; whitelist fields and reject accounting, company, token, and security properties",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-runtime-global-default",
                "title": "Runtime ir.property mutation has no company",
                "message": "Runtime ir.property mutation omits company_id and may create a global fallback; verify this is safe for all companies",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-runtime-no-resource-scope",
                "title": "Runtime ir.property mutation has no resource scope",
                "message": "Runtime ir.property mutation omits res_id and may apply broadly as a default; verify intended model/company scope",
            },
            {
                "source": "property-fields",
                "rule_id": "odoo-property-runtime-sensitive-value",
                "title": "Runtime ir.property writes sensitive value",
                "message": "Runtime ir.property mutation configures sensitive field 'payment.field_res_company__property_payment_provider_id'; verify accounting/security defaults are company-scoped",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-property-public-route-mutation"] == "property_public_mutation"
    assert shapes["odoo-property-sudo-mutation"] == "property_privileged_mutation"
    assert shapes["odoo-property-request-derived-mutation"] == "property_tainted_mutation"
    assert shapes["odoo-property-runtime-global-default"] == "property_record_global_default"
    assert shapes["odoo-property-runtime-no-resource-scope"] == "property_record_broad_scope"
    assert shapes["odoo-property-runtime-sensitive-value"] == "property_sensitive_value"


def test_taxonomy_coverage_classifies_manifest_security_packaging() -> None:
    """Manifest ACL and auto-install findings should not map to generic sudo taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-missing-acl-data",
                "title": "Installable module with models does not load ACL CSV",
                "message": "Module defines Python models but manifest data does not include security/ir.model.access.csv",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-auto-install-security-data",
                "title": "Auto-installed module loads security-sensitive data",
                "message": "auto_install=True modules can be installed implicitly when dependencies are present; review loaded security, group, ACL, and record-rule data for surprise privilege changes",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-auto-install-without-depends",
                "title": "Auto-installed module has no explicit dependencies",
                "message": "auto_install=True without explicit depends can install unexpectedly; verify this module is intentionally activated in target databases",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-lifecycle-hook",
                "title": "Manifest lifecycle hook requires review",
                "message": "Manifest declares post_init_hook='setup'; review install/uninstall side effects and privilege assumptions",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-manifest-missing-acl-data"] == "manifest_acl_packaging_gap"
    assert shapes["odoo-manifest-auto-install-security-data"] == "manifest_auto_install_security"
    assert shapes["odoo-manifest-auto-install-without-depends"] == "manifest_auto_install_security"
    assert shapes["odoo-manifest-lifecycle-hook"] == "migration_lifecycle_hook_review"


def test_taxonomy_coverage_classifies_manifest_demo_and_license_posture() -> None:
    """Demo data and license metadata should get manifest-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-demo-in-data",
                "title": "Demo data loaded as production data",
                "message": "Manifest data loads demo-looking files: demo/users.xml",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-application-demo-data",
                "title": "Application module ships demo data",
                "message": "Application=True modules with demo data deserve review for accidental sample users, credentials, or records",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-missing-license",
                "title": "Installable module missing license",
                "message": "Manifest omits license; review redistribution/compliance posture before shipping",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-unexpected-license",
                "title": "Manifest uses an unexpected license identifier",
                "message": "Manifest license 'Commercial' is not a known Odoo manifest license identifier; verify redistribution and app-store compliance before shipping",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-manifest-demo-in-data"] == "manifest_demo_data_exposure"
    assert shapes["odoo-manifest-application-demo-data"] == "manifest_demo_data_exposure"
    assert shapes["odoo-manifest-missing-license"] == "manifest_license_metadata"
    assert shapes["odoo-manifest-unexpected-license"] == "manifest_license_metadata"


def test_taxonomy_coverage_classifies_manifest_supply_chain_and_parse_findings() -> None:
    """Remote assets, risky dependencies, and parse errors need manifest-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-parse-error",
                "title": "Manifest cannot be parsed safely",
                "message": "Manifest is not a literal Python dictionary; verify install metadata manually",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-remote-assets",
                "title": "Manifest declares remote frontend assets",
                "message": "Manifest frontend assets reference remote URLs: https://cdn.example.com/x.js; verify supply-chain trust, pinning, CSP, and offline install behavior",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-suspicious-data-path",
                "title": "Manifest loads suspicious local file paths",
                "message": "Manifest local file paths include absolute or parent-directory traversal entries: ../shared/private.js; verify packaged data and assets cannot load files outside the module",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-risky-python-dependency",
                "title": "Manifest declares dependency with security-sensitive usage",
                "message": "Review usage of security-sensitive dependency declarations: paramiko, requests",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-risky-bin-dependency",
                "title": "Manifest declares binary dependency with security-sensitive usage",
                "message": "Review usage of security-sensitive binary dependency declarations: wkhtmltopdf, curl",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-insecure-python-dependency",
                "title": "Manifest declares insecure HTTP Python dependency",
                "message": "Manifest Python dependencies include cleartext http:// package references",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-floating-vcs-python-dependency",
                "title": "Manifest declares floating VCS Python dependency",
                "message": "Manifest Python dependencies include VCS references without immutable commit pins",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-local-python-dependency",
                "title": "Manifest declares local Python dependency path",
                "message": "Manifest Python dependencies include local filesystem paths",
            },
            {
                "source": "manifest",
                "rule_id": "odoo-manifest-local-bin-dependency",
                "title": "Manifest declares local binary dependency path",
                "message": "Manifest binary dependencies include local filesystem paths",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-manifest-parse-error"] == "manifest_parse_integrity"
    assert shapes["odoo-manifest-remote-assets"] == "manifest_remote_asset_supply_chain"
    assert shapes["odoo-manifest-suspicious-data-path"] == "manifest_path_integrity"
    assert shapes["odoo-manifest-risky-python-dependency"] == "manifest_risky_dependency"
    assert shapes["odoo-manifest-risky-bin-dependency"] == "manifest_risky_dependency"
    assert shapes["odoo-manifest-insecure-python-dependency"] == "manifest_risky_dependency"
    assert shapes["odoo-manifest-floating-vcs-python-dependency"] == "manifest_risky_dependency"
    assert shapes["odoo-manifest-local-python-dependency"] == "manifest_risky_dependency"
    assert shapes["odoo-manifest-local-bin-dependency"] == "manifest_risky_dependency"


def test_taxonomy_coverage_classifies_view_inheritance_group_and_xpath_risks() -> None:
    """Inherited-view group relaxation and broad XPath patches need view-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-broad-security-xpath",
                "title": "Inherited view uses broad XPath for security-sensitive control",
                "message": "Inherited view 'view_sale' uses broad XPath '//button' against buttons/fields; verify it cannot affect unintended secured controls",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-removes-groups",
                "title": "Inherited view removes groups restriction",
                "message": "Inherited view 'view_sale' removes groups from target '//button[@name=\"action_confirm\"]'; verify the control remains access-checked server-side",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-public-groups-sensitive-target",
                "title": "Inherited view exposes sensitive control to public/portal group",
                "message": "Inherited view 'view_user' assigns public/portal groups to sensitive target '//field[@name=\"groups_id\"]'; verify this cannot expose privilege-bearing fields or actions",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-view-inherit-broad-security-xpath"] == "view_inheritance_broad_security_xpath"
    assert shapes["odoo-view-inherit-removes-groups"] == "view_inheritance_group_relaxation"
    assert shapes["odoo-view-inherit-public-groups-sensitive-target"] == "view_inheritance_group_relaxation"


def test_taxonomy_coverage_classifies_view_inheritance_object_button_exposure() -> None:
    """Inherited-view object buttons should not map to action URL or sudo buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-replaces-object-button",
                "title": "Inherited view replaces object-method button",
                "message": "Inherited view 'view_sale' replaces object button target '//button[@type=\"object\"]'; verify groups, attrs, and server-side access checks are preserved",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-adds-public-object-button",
                "title": "Inherited view inserts public object-method button",
                "message": "Inherited view 'view_sale' inserts object button 'action_confirm' for public/portal users; verify the method enforces server-side authorization",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-adds-object-button-no-groups",
                "title": "Inherited view inserts object-method button without groups",
                "message": "Inherited view 'view_sale' inserts object button 'action_confirm' without groups; verify forged RPC calls cannot bypass workflow permissions",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"view_inheritance_object_button_exposure"}
    assert all("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_view_inheritance_sensitive_field_exposure() -> None:
    """Inherited-view sensitive field changes need field-exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-reveals-sensitive-field",
                "title": "Inherited view may reveal sensitive field/control",
                "message": "Inherited view 'view_user' changes visibility for sensitive target '//field[@name=\"signup_token\"]'; verify groups and record rules still protect it",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-replaces-sensitive-field",
                "title": "Inherited view replaces sensitive field",
                "message": "Inherited view 'view_user' replaces sensitive field target '//field[@name=\"groups_id\"]'; verify groups, readonly, and invisibility restrictions are preserved",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-adds-public-sensitive-field",
                "title": "Inherited view inserts sensitive field for public/portal users",
                "message": "Inherited view 'view_user' inserts sensitive field 'groups_id' for public/portal users; verify ACLs and record rules cannot expose secrets or privileges",
            },
            {
                "source": "view-inheritance",
                "rule_id": "odoo-view-inherit-adds-sensitive-field-no-groups",
                "title": "Inherited view inserts sensitive field without groups",
                "message": "Inherited view 'view_user' inserts sensitive field 'groups_id' without groups; verify view inheritance cannot expose secrets or privilege fields",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"view_inheritance_sensitive_field_exposure"}
    assert all("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_model_display_and_secret_persistence() -> None:
    """Model display-name and copyable-secret findings need model-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "models",
                "rule_id": "odoo-model-rec-name-sensitive",
                "title": "Model display name uses sensitive field",
                "message": "Model 'x.api' sets _rec_name to sensitive-looking field 'api_key'; display names can leak through relational widgets, chatter, exports, and logs",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-secret-copyable",
                "title": "Secret-like field is copyable",
                "message": "Field 'api_token' looks secret/token-like but does not set copy=False; duplicated records may inherit credentials or access tokens",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-log-access-disabled",
                "title": "Model disables Odoo access logging",
                "message": "Model 'x.ledger' sets _log_access=False; create/write user and timestamp audit fields will not be maintained",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-auto-false-manual-sql",
                "title": "Model uses manually managed SQL storage",
                "message": "Model 'x.sales.report' sets _auto=False; verify SQL view/table creation, ACLs, record rules, and exposed fields are reviewed explicitly",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-model-rec-name-sensitive"] == "model_sensitive_display_name"
    assert shapes["odoo-model-secret-copyable"] == "model_secret_persistence"
    assert shapes["odoo-model-log-access-disabled"] == "model_audit_metadata_disabled"
    assert shapes["odoo-model-auto-false-manual-sql"] == "model_manual_sql_storage"


def test_taxonomy_coverage_classifies_model_delegated_inheritance() -> None:
    """Delegated model risks should not fall through to sudo or action-window shapes."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "models",
                "rule_id": "odoo-model-delegated-sensitive-inherits",
                "title": "Model delegates to sensitive model",
                "message": "Model 'x.wrapper' uses _inherits to delegate 'res.users'; verify ACLs and record rules on the wrapper cannot expose delegated fields",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-delegated-link-missing",
                "title": "Delegated inheritance link field is missing",
                "message": "_inherits maps 'res.partner' through 'partner_id', but no matching Many2one field is visible in the class",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-delegated-link-not-required",
                "title": "Delegated inheritance link is not required",
                "message": "Delegated _inherits link 'partner_id' is not required=True; wrapper records may exist without the delegated record and break access assumptions",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-delegated-link-no-cascade",
                "title": "Delegated inheritance link does not cascade",
                "message": "Delegated _inherits link 'partner_id' does not set ondelete='cascade'; verify delete/orphan semantics preserve delegated-record integrity",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-delegate-sensitive-field",
                "title": "Many2one delegates sensitive model fields",
                "message": "Many2one field 'user_id' sets delegate=True to sensitive model 'res.users'; verify wrapper ACLs cannot expose delegated fields",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-model-delegated-sensitive-inherits"] == "model_delegated_inheritance_exposure"
    assert shapes["odoo-model-delegate-sensitive-field"] == "model_delegated_inheritance_exposure"
    assert shapes["odoo-model-delegated-link-missing"] == "model_delegated_link_integrity"
    assert shapes["odoo-model-delegated-link-not-required"] == "model_delegated_link_integrity"
    assert shapes["odoo-model-delegated-link-no-cascade"] == "model_delegated_link_integrity"


def test_taxonomy_coverage_classifies_model_identifier_and_monetary_integrity() -> None:
    """Model integrity findings should not map to SQL injection or generic domain buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "models",
                "rule_id": "odoo-model-identifier-missing-unique",
                "title": "Required identifier field lacks obvious SQL uniqueness",
                "message": "Required identifier field 'uuid' has no visible unique _sql_constraints entry; review duplicate business-key risk",
            },
            {
                "source": "models",
                "rule_id": "odoo-model-monetary-missing-currency",
                "title": "Monetary field lacks obvious currency field",
                "message": "Monetary field 'amount_total' has no currency_field and model has no currency_id field; review cross-company/currency correctness",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-model-identifier-missing-unique"] == "model_identifier_uniqueness"
    assert shapes["odoo-model-monetary-missing-currency"] == "model_monetary_currency_integrity"


def test_taxonomy_coverage_classifies_model_method_dynamic_and_sensitive_mutation() -> None:
    """Lifecycle model methods need precise dynamic-eval and sensitive-mutation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-dynamic-eval",
                "title": "Odoo model method performs dynamic evaluation",
                "message": "onchange model method calls eval/exec/safe_eval; verify no record field or context value can control evaluated code",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-onchange-sensitive-model-mutation",
                "title": "Odoo model method mutates sensitive model",
                "message": "onchange model method mutates sensitive model 'res.users'; verify lifecycle side effects, caller access, and audit trail",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-compute-sensitive-model-mutation",
                "title": "Odoo model method mutates sensitive model",
                "message": "compute model method mutates sensitive model 'ir.config_parameter'; verify lifecycle side effects, caller access, and audit trail",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-constraint-sensitive-model-mutation",
                "title": "Odoo model method mutates sensitive model",
                "message": "constraint model method mutates sensitive model 'ir.rule'; verify lifecycle side effects, caller access, and audit trail",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-inverse-sensitive-model-mutation",
                "title": "Odoo model method mutates sensitive model",
                "message": "inverse model method mutates sensitive model 'payment.transaction'; verify lifecycle side effects, caller access, and audit trail",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-model-method-dynamic-eval"] == "model_method_dynamic_evaluation"
    sensitive_shapes = {
        shape
        for rule_id, shape in shapes.items()
        if rule_id.startswith("odoo-model-method-") and rule_id != "odoo-model-method-dynamic-eval"
    }
    assert sensitive_shapes == {"model_method_sensitive_model_mutation"}


def test_taxonomy_coverage_classifies_model_method_sudo_and_http_side_effects() -> None:
    """Lifecycle sudo mutations and HTTP timeout gaps should not map to action-window or SSRF buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-onchange-sudo-mutation",
                "title": "Odoo model method performs elevated mutation",
                "message": "onchange model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-compute-sudo-mutation",
                "title": "Odoo model method performs elevated mutation",
                "message": "compute model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-constraint-sudo-mutation",
                "title": "Odoo model method performs elevated mutation",
                "message": "constraint model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-inverse-sudo-mutation",
                "title": "Odoo model method performs elevated mutation",
                "message": "inverse model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-onchange-http-no-timeout",
                "title": "Odoo model method performs HTTP without timeout",
                "message": "onchange model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-compute-http-no-timeout",
                "title": "Odoo model method performs HTTP without timeout",
                "message": "compute model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-constraint-http-no-timeout",
                "title": "Odoo model method performs HTTP without timeout",
                "message": "constraint model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-inverse-http-no-timeout",
                "title": "Odoo model method performs HTTP without timeout",
                "message": "inverse model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-onchange-cleartext-http-url",
                "title": "Odoo model method uses cleartext HTTP URL",
                "message": "onchange model method targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-compute-cleartext-http-url",
                "title": "Odoo model method uses cleartext HTTP URL",
                "message": "compute model method targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-constraint-cleartext-http-url",
                "title": "Odoo model method uses cleartext HTTP URL",
                "message": "constraint model method targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
            },
            {
                "source": "model-methods",
                "rule_id": "odoo-model-method-inverse-cleartext-http-url",
                "title": "Odoo model method uses cleartext HTTP URL",
                "message": "inverse model method targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert {shape for rule_id, shape in shapes.items() if rule_id.endswith("sudo-mutation")} == {
        "model_method_elevated_mutation"
    }
    assert {shape for rule_id, shape in shapes.items() if rule_id.endswith("http-no-timeout")} == {
        "model_method_http_without_timeout"
    }
    assert {shape for rule_id, shape in shapes.items() if rule_id.endswith("cleartext-http-url")} == {
        "model_method_cleartext_http_url"
    }


def test_taxonomy_coverage_classifies_constraint_runtime_behavior() -> None:
    """Constraint sudo, search, singleton, and return findings need constraint-specific shapes."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-sudo-search",
                "title": "Constraint reads through sudo",
                "message": "Constraint '_check_unique' reads through sudo()/with_user(SUPERUSER_ID); validate that uniqueness and business-rule checks cannot hide company or record-rule issues",
            },
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-unbounded-search",
                "title": "Constraint performs unbounded search",
                "message": "Constraint '_check_unique' performs search without a limit; validation can become slow or lock-prone on large tables",
            },
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-ensure-one",
                "title": "Constraint assumes a singleton recordset",
                "message": "Constraint '_check_amount' calls ensure_one(); constraints may run on multi-record recordsets during batch create/write and should validate every record",
            },
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-return-ignored",
                "title": "Constraint returns a value instead of raising",
                "message": "Constraint '_check_amount' returns False/None; Odoo constraints must raise ValidationError to block invalid records",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-constraint-sudo-search"] == "constraint_sudo_visibility_gap"
    assert shapes["odoo-constraint-unbounded-search"] == "constraint_unbounded_search"
    assert shapes["odoo-constraint-ensure-one"] == "constraint_singleton_assumption"
    assert shapes["odoo-constraint-return-ignored"] == "constraint_ineffective_return"


def test_taxonomy_coverage_classifies_constraint_registration_gaps() -> None:
    """Constraint decorator gaps should not stay unmapped."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-empty-fields",
                "title": "Constraint decorator has no fields",
                "message": "Constraint '_check_amount' has @api.constrains() without fields, so it will not run for normal field writes",
            },
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-dynamic-field",
                "title": "Constraint decorator uses dynamic field expression",
                "message": "Constraint '_check_amount' uses a non-literal @api.constrains argument; verify Odoo registers the intended fields",
            },
            {
                "source": "constraints",
                "rule_id": "odoo-constraint-dotted-field",
                "title": "Constraint decorator uses dotted field",
                "message": "Constraint '_check_partner' watches dotted field 'partner_id.email', which Odoo @api.constrains does not trigger reliably",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"constraint_registration_gap"}


def test_taxonomy_coverage_classifies_access_override_authorization_bypasses() -> None:
    """Access override findings need specific bypass taxonomy, not generic sudo/action buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "access-overrides",
                "rule_id": "odoo-access-override-missing-super",
                "title": "Access override does not call super",
                "message": "Model access override 'check_access_rule' does not call super(); verify it preserves base ACL and record-rule behavior",
            },
            {
                "source": "access-overrides",
                "rule_id": "odoo-access-override-allow-all",
                "title": "Access override returns allow-all",
                "message": "Model access override 'check_access_rights' returns True without super(); this can disable access-right or record-rule enforcement",
            },
            {
                "source": "access-overrides",
                "rule_id": "odoo-access-override-filter-self",
                "title": "Record-rule filter override returns self",
                "message": "Model access filter override '_filter_access_rules' returns self without super(); this can bypass record-rule filtering for every caller",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-access-override-missing-super"] == "access_override_missing_super"
    assert shapes["odoo-access-override-allow-all"] == "access_override_allow_all"
    assert shapes["odoo-access-override-filter-self"] == "access_override_filter_self"


def test_taxonomy_coverage_classifies_access_override_sudo_search() -> None:
    """Sudo-backed search overrides should map to access override taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "access-overrides",
                "rule_id": "odoo-access-override-sudo-search",
                "title": "Search override reads through elevated environment",
                "message": "Model search override 'search' reads through sudo()/with_user(SUPERUSER_ID); verify it cannot bypass record rules or company isolation for all callers",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "access_override_sudo_search"
    assert "CWE-863" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_record_rule_sensitive_exposure() -> None:
    """Sensitive record rules need specific exposure and mutation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-universal-domain",
                "title": "Record rule grants universal domain on sensitive model",
                "message": "Record rule 'rule_all' uses an empty or tautological domain on sensitive/security model 'res.users'; verify every permitted group should see all records",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-public-sensitive-no-owner-scope",
                "title": "Public/portal rule on sensitive/security model lacks owner scope",
                "message": "Record rule 'portal_users' targets sensitive/security model 'res.users' for public/portal users without an obvious owner, token, or company scope",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-public-sensitive-company-only-scope",
                "title": "Public/portal rule relies only on company scope",
                "message": "Record rule 'portal_company_sales' scopes sensitive/security model 'sale.order' for public/portal users by company only; verify portal users cannot list unrelated records from the same company",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-portal-write-sensitive",
                "title": "Public/portal rule enables mutation on sensitive/security model",
                "message": "Record rule 'portal_invoice_write' enables write/create/delete on sensitive/security model 'account.move' for public/portal users",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-global-sensitive-mutation",
                "title": "Global record rule enables mutation on sensitive/security model",
                "message": "Record rule 'global_invoice_write' enables write/create/delete on sensitive/security model 'account.move' without group scoping",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-record-rule-universal-domain"] == "record_rule_universal_sensitive_domain"
    assert shapes["odoo-record-rule-public-sensitive-no-owner-scope"] == ("record_rule_public_sensitive_no_owner_scope")
    assert shapes["odoo-record-rule-public-sensitive-company-only-scope"] == (
        "record_rule_public_company_only_scope"
    )
    assert shapes["odoo-record-rule-portal-write-sensitive"] == "record_rule_portal_sensitive_mutation"
    assert shapes["odoo-record-rule-global-sensitive-mutation"] == "record_rule_global_sensitive_mutation"


def test_taxonomy_coverage_classifies_record_rule_domain_logic() -> None:
    """Record-rule domain semantics should not map to safe_eval or generic sudo buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-domain-has-group",
                "title": "Record-rule domain performs group checks",
                "message": "Record rule 'rule_group_domain' calls has_group() inside domain_force; review caching, domain evaluation, and privilege-boundary assumptions",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-context-dependent-domain",
                "title": "Record-rule domain depends on context",
                "message": "Record rule 'rule_context' reads context inside domain_force; verify caller-controlled context cannot widen access or bypass company/owner scoping",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-company-child-of",
                "title": "Record rule uses company hierarchy expansion",
                "message": "Record rule 'rule_company_child' uses child_of with user companies; verify parent/child company access is intentional for this model",
            },
            {
                "source": "record-rules",
                "rule_id": "odoo-record-rule-empty-permissions",
                "title": "Record rule has all permissions disabled",
                "message": "Record rule 'rule_empty' sets every perm_* flag false and may be ineffective or misleading",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-record-rule-domain-has-group"] == "record_rule_domain_group_logic"
    assert shapes["odoo-record-rule-context-dependent-domain"] == "record_rule_context_dependent_domain"
    assert shapes["odoo-record-rule-company-child-of"] == "record_rule_company_hierarchy_expansion"
    assert shapes["odoo-record-rule-empty-permissions"] == "record_rule_empty_permissions"


def test_taxonomy_coverage_classifies_button_action_privileged_mutations() -> None:
    """Button/action mutation findings should not collapse into generic sudo or sensitive-model buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "button-actions",
                "rule_id": "odoo-button-action-sensitive-model-mutation",
                "title": "Button/action method mutates sensitive model",
                "message": "Button/action method mutates sensitive model 'res.users'; verify object-button exposure, RPC access, group checks, and audit trail",
            },
            {
                "source": "button-actions",
                "rule_id": "odoo-button-action-sudo-mutation",
                "title": "Button/action method performs sudo mutation",
                "message": "Button/action method chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify explicit group, access, and company checks before mutation",
            },
            {
                "source": "button-actions",
                "rule_id": "odoo-button-action-sensitive-state-write",
                "title": "Button/action method writes sensitive workflow state",
                "message": "Button/action method writes approval/payment/posting-like state; verify ACLs, record rules, and groups enforce the workflow boundary",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-button-action-sensitive-model-mutation"] == "button_action_sensitive_model_mutation"
    assert shapes["odoo-button-action-sudo-mutation"] == "button_action_sudo_mutation"
    assert shapes["odoo-button-action-sensitive-state-write"] == "button_action_sensitive_state_write"


def test_taxonomy_coverage_classifies_button_action_missing_guards() -> None:
    """Button/action guard gaps need object-button authorization taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "button-actions",
                "rule_id": "odoo-button-action-unlink-no-access-check",
                "title": "Button/action method unlinks without visible access check",
                "message": "Button/action method deletes records without visible check_access/user_has_groups guard; verify object button exposure cannot delete unauthorized records",
            },
            {
                "source": "button-actions",
                "rule_id": "odoo-button-action-mutation-no-access-check",
                "title": "Button/action method mutates without visible access check",
                "message": "Button/action method performs sensitive mutation without visible check_access/user_has_groups guard; verify UI and RPC calls cannot bypass workflow approvals",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-button-action-unlink-no-access-check"] == "button_action_unlink_no_access_check"
    assert shapes["odoo-button-action-mutation-no-access-check"] == "button_action_mutation_no_access_check"


def test_taxonomy_coverage_classifies_view_domain_sensitive_filters() -> None:
    """Sensitive act_window and saved-filter domains need view-domain taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "view-domains",
                "rule_id": "odoo-view-domain-sensitive-action-broad-domain",
                "title": "Sensitive action uses broad domain without groups",
                "message": "ir.actions.act_window for sensitive model 'res.users' uses a broad domain and has no groups restriction; verify menus and ACLs prevent overexposure",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-domain-global-sensitive-filter-broad-domain",
                "title": "Global saved filter has broad sensitive-model domain",
                "message": "Global ir.filters record applies a broad domain to sensitive model 'account.move'; verify it cannot overexpose records through shared favorites/search defaults",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-filter-global-default-sensitive",
                "title": "Global default saved filter affects sensitive model",
                "message": "Global default ir.filters record applies to sensitive model 'account.move'; verify shared default search behavior is intentional and cannot hide or expose records unexpectedly",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-domain-default-sensitive-filter",
                "title": "Global default saved filter affects sensitive model",
                "message": "Global default ir.filters record applies to sensitive model 'account.move'; verify default search behavior cannot expose archived or overly broad records",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-view-domain-sensitive-action-broad-domain"] == ("view_domain_sensitive_action_broad_domain")
    assert shapes["odoo-view-domain-global-sensitive-filter-broad-domain"] == (
        "view_domain_global_sensitive_filter_broad_domain"
    )
    assert shapes["odoo-view-filter-global-default-sensitive"] == "view_domain_global_default_sensitive_filter"
    assert shapes["odoo-view-domain-default-sensitive-filter"] == "view_domain_global_default_sensitive_filter"


def test_taxonomy_coverage_classifies_view_domain_context_expressions() -> None:
    """XML domain/context expressions need specific context-risk taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "view-domains",
                "rule_id": "odoo-view-domain-dynamic-eval",
                "title": "XML domain/context performs dynamic evaluation",
                "message": "XML domain/context expression contains eval/exec/safe_eval; verify no user-controlled value can affect evaluated code",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-context-active-test-disabled",
                "title": "XML context disables active_test",
                "message": "XML context sets active_test=False; archived/inactive records may become visible or processed in this flow",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-context-user-company-scope",
                "title": "XML context sets company scope from active/user values",
                "message": "XML context sets force_company/company_id/allowed_company_ids from active/user-derived values; verify company membership is enforced",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-context-privileged-default",
                "title": "XML context defaults privileged field",
                "message": "XML context sets default_user_id; verify create flows cannot prefill privilege, company, user, or portal/share-sensitive values unexpectedly",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-context-default-groups",
                "title": "XML context defaults user/group assignment",
                "message": "XML context sets default group fields; verify create flows cannot assign elevated groups unexpectedly",
            },
            {
                "source": "view-domains",
                "rule_id": "odoo-view-context-risky-framework-flag",
                "title": "XML context sets risky framework flag",
                "message": "XML context sets tracking_disable; verify this flow cannot bypass tracking, password reset, install/uninstall, or accounting validation safeguards unexpectedly",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-view-domain-dynamic-eval"] == "view_domain_dynamic_evaluation"
    assert shapes["odoo-view-context-active-test-disabled"] == "view_context_active_test_disabled"
    assert shapes["odoo-view-context-user-company-scope"] == "view_context_company_scope_control"
    assert shapes["odoo-view-context-privileged-default"] == "view_context_privileged_default"
    assert shapes["odoo-view-context-default-groups"] == "view_context_default_groups"
    assert shapes["odoo-view-context-risky-framework-flag"] == "view_context_risky_framework_flag"


def test_taxonomy_coverage_classifies_xml_data_core_and_update_integrity() -> None:
    """XML data lifecycle findings should not remain unmapped or generic XML-ID buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-core-xmlid-override",
                "title": "Module data overrides core external ID",
                "message": "Record id 'base.group_system' appears to target a core module XML ID; verify this intentionally overrides upstream data and survives upgrades",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-core-xmlid-delete",
                "title": "XML data deletes core external ID",
                "message": "XML <delete> targets core external ID 'base.group_system'; verify the module intentionally removes upstream data and remains safe across upgrades",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-forcecreate-disabled",
                "title": "XML record disables forcecreate",
                "message": "XML record uses forcecreate=False; missing records will not be recreated during updates, which can hide deleted security/config data",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-manual-ir-model-data",
                "title": "Module data writes ir.model.data directly",
                "message": "Module data creates or changes ir.model.data directly; verify XML ID ownership, noupdate, and update semantics cannot hijack records",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-data-core-xmlid-override"] == "xml_data_core_xmlid_override"
    assert shapes["odoo-data-core-xmlid-delete"] == "xml_data_core_xmlid_delete"
    assert shapes["odoo-data-forcecreate-disabled"] == "xml_data_forcecreate_disabled"
    assert shapes["odoo-data-manual-ir-model-data"] == "xml_data_manual_model_data_write"


def test_taxonomy_coverage_classifies_xml_data_sensitive_mutations() -> None:
    """Sensitive XML data deletes/functions/noupdate findings need install/update taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-noupdate-record",
                "title": "Sensitive data record is protected by noupdate",
                "message": "Sensitive model 'ir.rule' is loaded under noupdate; fixes to security data may not apply during module upgrades",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-delete",
                "title": "XML data deletes security-sensitive records",
                "message": "XML <delete> targets sensitive model 'res.users'; verify module install/update cannot remove security, identity, automation, payment, or configuration records unexpectedly",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-search-delete",
                "title": "XML data search-deletes sensitive records",
                "message": "XML <delete> uses a search domain on sensitive model 'ir.rule'; verify broad or version-dependent matches cannot remove security-critical records",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-noupdate-delete",
                "title": "Sensitive XML delete is protected by noupdate",
                "message": "Sensitive delete for model 'ir.rule' is under noupdate; future security fixes or cleanup changes may not apply during module upgrades",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-function-mutation",
                "title": "XML function mutates security-sensitive records",
                "message": "XML <function> calls res.users.write; verify module install/update cannot silently alter security, identity, automation, payment, or configuration records",
            },
            {
                "source": "data-integrity",
                "rule_id": "odoo-data-sensitive-noupdate-function",
                "title": "Sensitive XML function is protected by noupdate",
                "message": "Sensitive XML <function> for model 'ir.rule' is under noupdate; future security fixes or cleanup changes may not apply during module upgrades",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-data-sensitive-noupdate-record"] == "xml_data_sensitive_noupdate"
    assert shapes["odoo-data-sensitive-noupdate-delete"] == "xml_data_sensitive_noupdate"
    assert shapes["odoo-data-sensitive-noupdate-function"] == "xml_data_sensitive_noupdate"
    assert shapes["odoo-data-sensitive-delete"] == "xml_data_sensitive_delete"
    assert shapes["odoo-data-sensitive-search-delete"] == "xml_data_sensitive_search_delete"
    assert shapes["odoo-data-sensitive-function-mutation"] == "xml_data_sensitive_function_mutation"


def test_taxonomy_coverage_classifies_orm_context_read_and_framework_flags() -> None:
    """Python ORM context active_test/default/framework findings need dedicated taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-active-test-disabled",
                "title": "ORM context disables active record filtering",
                "message": "with_context(active_test=False) can include archived/inactive records in later ORM operations; verify this is intentional and access-safe",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-sudo-active-test-read",
                "title": "Privileged ORM read disables active record filtering",
                "message": "ORM read uses sudo()/with_user(SUPERUSER_ID) with active_test=False; archived/inactive records may be exposed outside normal record visibility",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-bin-size-disabled",
                "title": "ORM context forces binary field contents",
                "message": "with_context(bin_size=False) can make binary fields return file contents instead of size metadata; verify downstream reads cannot expose attachments or large payloads",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-sudo-bin-size-read",
                "title": "Privileged ORM read forces binary field contents",
                "message": "ORM read uses sudo()/with_user(SUPERUSER_ID) with bin_size=False; binary fields may return file contents instead of size metadata outside normal record visibility",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-accounting-validation-disabled",
                "title": "ORM context disables accounting move validation",
                "message": "with_context(check_move_validity=False) disables accounting move validation; verify the surrounding flow preserves balanced moves, taxes, and reconciliation invariants",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-privileged-mode",
                "title": "ORM context enables privileged framework mode",
                "message": "with_context(install_mode=True) enables a framework mode normally reserved for install/uninstall flows; verify it cannot bypass normal business safeguards",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-privileged-default",
                "title": "ORM context seeds privilege-bearing default",
                "message": "with_context(default_groups_id=...) seeds a privilege-bearing default; verify create flows cannot assign user, group, company, share, or active-state fields unexpectedly",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-orm-context-active-test-disabled"] == "orm_context_active_test_disabled"
    assert shapes["odoo-orm-context-sudo-active-test-read"] == "orm_context_sudo_active_test_read"
    assert shapes["odoo-orm-context-bin-size-disabled"] == "orm_context_bin_size_disabled"
    assert shapes["odoo-orm-context-sudo-bin-size-read"] == "orm_context_sudo_bin_size_read"
    assert (
        shapes["odoo-orm-context-accounting-validation-disabled"]
        == "orm_context_accounting_validation_disabled"
    )
    assert shapes["odoo-orm-context-privileged-mode"] == "orm_context_privileged_mode"
    assert shapes["odoo-orm-context-privileged-default"] == "orm_context_privileged_default"


def test_taxonomy_coverage_classifies_orm_context_request_scope() -> None:
    """request.update_context findings should not fall through to generic SSRF or action taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-active-test-disabled",
                "title": "Request context disables active record filtering",
                "message": "request.update_context(active_test=False) changes the current request environment; archived/inactive records may become visible or processed later in the route",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-bin-size-disabled",
                "title": "Request context forces binary field contents",
                "message": "request.update_context(bin_size=False) changes the request environment so later binary reads can return file contents instead of size metadata",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-accounting-validation-disabled",
                "title": "Request context disables accounting move validation",
                "message": "request.update_context(check_move_validity=False) disables accounting move validation for later route work; verify callers cannot persist unbalanced or invalid accounting entries",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-tracking-disabled",
                "title": "Request context disables chatter/tracking",
                "message": "request.update_context disables tracking or subscription context for later ORM work in the request; verify auditability and follower notifications are preserved",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-notification-disabled",
                "title": "Request context disables user notifications",
                "message": "request.update_context(no_reset_password=True) suppresses later account, password, or mail notifications in the route",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-privileged-mode",
                "title": "Request context enables privileged framework mode",
                "message": "request.update_context(install_mode=True) enables a framework mode for later ORM work in the request; verify it cannot bypass normal validation or workflow controls",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-request-privileged-default",
                "title": "Request context seeds privilege-bearing default",
                "message": "request.update_context(default_groups_id=...) seeds a privileged default for later create flows in the request",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-orm-context-request-active-test-disabled"] == "orm_context_request_active_test_disabled"
    assert shapes["odoo-orm-context-request-bin-size-disabled"] == "orm_context_request_bin_size_disabled"
    assert (
        shapes["odoo-orm-context-request-accounting-validation-disabled"]
        == "orm_context_request_accounting_validation_disabled"
    )
    assert shapes["odoo-orm-context-request-tracking-disabled"] == "orm_context_request_tracking_disabled"
    assert shapes["odoo-orm-context-request-notification-disabled"] == "orm_context_request_notification_disabled"
    assert shapes["odoo-orm-context-request-privileged-mode"] == "orm_context_request_privileged_mode"
    assert shapes["odoo-orm-context-request-privileged-default"] == "orm_context_request_privileged_default"


def test_taxonomy_coverage_classifies_orm_context_mutation_suppression() -> None:
    """Context-backed ORM mutations need audit/default/framework taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-tracking-disabled-mutation",
                "title": "ORM mutation disables chatter/tracking context",
                "message": "ORM create/write/unlink runs with tracking or subscription context disabled; verify auditability, followers, and security notifications are not suppressed for sensitive records",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-notification-disabled-mutation",
                "title": "ORM mutation disables user notification context",
                "message": "ORM create/write/unlink runs with no_reset_password=True; verify account, password, or mail notifications are not suppressed in a security-sensitive flow",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-privileged-mode-mutation",
                "title": "ORM mutation runs in privileged framework mode",
                "message": "ORM mutation runs with install_mode=True; verify install/uninstall-only behavior cannot bypass normal validation or workflow controls",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-privileged-default-mutation",
                "title": "ORM mutation uses privilege-bearing default context",
                "message": "ORM mutation runs with default_groups_id=... in context; verify callers cannot create records with elevated ownership, groups, companies, or visibility",
            },
            {
                "source": "orm-context",
                "rule_id": "odoo-orm-context-accounting-validation-disabled-mutation",
                "title": "ORM mutation disables accounting move validation",
                "message": "ORM create/write/unlink runs with check_move_validity=False; verify callers cannot persist unbalanced or invalid accounting entries",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-orm-context-tracking-disabled-mutation"] == "orm_context_tracking_disabled_mutation"
    assert shapes["odoo-orm-context-notification-disabled-mutation"] == "orm_context_notification_disabled_mutation"
    assert shapes["odoo-orm-context-privileged-mode-mutation"] == "orm_context_privileged_mode_mutation"
    assert shapes["odoo-orm-context-privileged-default-mutation"] == "orm_context_privileged_default_mutation"
    assert (
        shapes["odoo-orm-context-accounting-validation-disabled-mutation"]
        == "orm_context_accounting_validation_disabled_mutation"
    )


def test_taxonomy_coverage_classifies_orm_domain_tainted_searches() -> None:
    """Python ORM domain taint should not collapse into action-window or generic domain taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "orm-domain",
                "rule_id": "odoo-orm-domain-tainted-sudo-search",
                "title": "Request/context-controlled domain is searched through an elevated environment",
                "message": "Request or context-derived domain reaches sudo()/with_user(SUPERUSER_ID) ORM search/read; validate fields/operators, ownership, record rules, and company isolation",
            },
            {
                "source": "orm-domain",
                "rule_id": "odoo-orm-domain-tainted-search",
                "title": "Request/context-controlled domain reaches ORM search",
                "message": "Request or context-derived domain reaches ORM search/read; validate allowed fields/operators and prevent cross-record or cross-company discovery",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-orm-domain-tainted-sudo-search"] == "orm_domain_tainted_sudo_search"
    assert shapes["odoo-orm-domain-tainted-search"] == "orm_domain_tainted_search"


def test_taxonomy_coverage_classifies_orm_domain_evaluation_and_filtering() -> None:
    """Domain eval and dynamic filtered lambdas need precise Python ORM taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "orm-domain",
                "rule_id": "odoo-orm-domain-dynamic-eval",
                "title": "Request/context data is evaluated as a domain",
                "message": "Request or context-derived data reaches literal_eval/safe_eval for ORM domain construction; validate allowed fields and operators",
            },
            {
                "source": "orm-domain",
                "rule_id": "odoo-orm-domain-filtered-dynamic",
                "title": "Record filtering uses dynamic request/env logic",
                "message": "filtered(lambda ...) references request/env/context; verify Python-side filtering cannot replace record-rule or company checks",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-orm-domain-dynamic-eval"] == "orm_domain_dynamic_evaluation"
    assert shapes["odoo-orm-domain-filtered-dynamic"] == "orm_domain_filtered_dynamic_logic"


def test_taxonomy_coverage_classifies_metadata_acl_and_groups() -> None:
    """Odoo metadata ACL/group privilege findings need dedicated access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-public-write-acl",
                "title": "Public/portal ACL grants write/create/delete",
                "message": "ACL grants write/create/delete permissions to base.group_public; verify this model is explicitly safe for public or portal mutation",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-sensitive-public-read-acl",
                "title": "Public/portal ACL grants read on sensitive model",
                "message": "ACL grants read permission on sensitive model 'res.users' to base.group_portal; verify record rules prevent cross-user exposure",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-group-implies-admin",
                "title": "Group implies administrator-level privileges",
                "message": "res.groups record implies administrator/manager-level groups; verify this is intentional and not assigned by portal/signup flows",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-group-implies-internal-user",
                "title": "Group implies internal user privileges",
                "message": "res.groups record implies base.group_user; verify portal/public/signup flows cannot assign this group and become internal users",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-user-admin-group-assignment",
                "title": "User data assigns administrator-level group",
                "message": "res.users metadata assigns administrator/manager-level groups; verify module install/update or CSV imports cannot grant unintended administrator access",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-user-internal-group-assignment",
                "title": "User data assigns internal user group",
                "message": "res.users metadata assigns base.group_user; verify demo/imported/signup users are not silently promoted to internal users",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-metadata-public-write-acl"] == "metadata_public_write_acl"
    assert shapes["odoo-metadata-sensitive-public-read-acl"] == "metadata_sensitive_public_read_acl"
    assert shapes["odoo-metadata-group-implies-admin"] == "metadata_group_privilege_escalation"
    assert shapes["odoo-metadata-group-implies-internal-user"] == "metadata_group_privilege_escalation"
    assert shapes["odoo-metadata-user-admin-group-assignment"] == "metadata_user_group_assignment"
    assert shapes["odoo-metadata-user-internal-group-assignment"] == "metadata_user_group_assignment"


def test_taxonomy_coverage_classifies_metadata_sensitive_fields() -> None:
    """ir.model.fields metadata findings need field-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-sensitive-field-public-groups",
                "title": "Field metadata exposes sensitive field to public/portal groups",
                "message": "ir.model.fields record 'field_api_key' assigns public/portal groups to sensitive field 'api_key'; verify the field cannot leak credentials or tokens",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-sensitive-field-no-groups",
                "title": "Field metadata defines sensitive field without groups",
                "message": "ir.model.fields record 'field_token' defines sensitive-looking field 'access_token' without groups; verify only trusted users can read it",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-sensitive-field-readonly-disabled",
                "title": "Field metadata makes sensitive field writable",
                "message": "ir.model.fields record 'field_api_key' sets readonly=False on sensitive field 'api_key'; verify write access is explicitly restricted",
            },
            {
                "source": "metadata",
                "rule_id": "odoo-metadata-field-dynamic-compute",
                "title": "Field metadata contains dynamic compute code",
                "message": "ir.model.fields record 'field_api_key' contains dynamic compute code; verify no user-controlled data can affect evaluated or sudo behavior",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-metadata-sensitive-field-public-groups"] == "metadata_sensitive_field_exposure"
    assert shapes["odoo-metadata-sensitive-field-no-groups"] == "metadata_sensitive_field_exposure"
    assert shapes["odoo-metadata-sensitive-field-readonly-disabled"] == "metadata_sensitive_field_writable"
    assert shapes["odoo-metadata-field-dynamic-compute"] == "metadata_dynamic_compute_code"


def test_taxonomy_coverage_classifies_migration_lifecycle_and_sql() -> None:
    """Migration lifecycle and SQL findings need upgrade/install taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "migrations",
                "rule_id": "odoo-migration-lifecycle-hook",
                "title": "Manifest lifecycle hook requires review",
                "message": "Manifest declares lifecycle hook 'post_init'; review install/uninstall side effects and privilege assumptions",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-missing-lifecycle-hook",
                "title": "Manifest lifecycle hook function is missing",
                "message": "Manifest declares lifecycle hook 'post_init', but no matching Python function was found; verify install, upgrade, uninstall, and post-load behavior cannot fail or silently skip required security setup",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-interpolated-sql",
                "title": "Migration SQL uses interpolation",
                "message": "Migration or lifecycle hook executes SQL built with interpolation/formatting; use parameters or psycopg2.sql for identifiers",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-destructive-sql",
                "title": "Migration executes destructive SQL",
                "message": "Migration or lifecycle hook executes destructive SQL; verify backups, WHERE clauses, tenant filters, and rollback safety",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-migration-lifecycle-hook"] == "migration_lifecycle_hook_review"
    assert shapes["odoo-migration-missing-lifecycle-hook"] == "migration_missing_lifecycle_hook"
    assert shapes["odoo-migration-interpolated-sql"] == "migration_interpolated_sql"
    assert shapes["odoo-migration-destructive-sql"] == "migration_destructive_sql"


def test_taxonomy_coverage_classifies_migration_runtime_side_effects() -> None:
    """Migration runtime side effects should not fall through to button/action or raw SQL taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "migrations",
                "rule_id": "odoo-migration-sudo-mutation",
                "title": "Migration/hook performs elevated mutation",
                "message": "Migration or lifecycle hook chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify it cannot corrupt records across companies or tenants",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-manual-transaction",
                "title": "Migration/hook controls transactions manually",
                "message": "Migration or lifecycle hook calls commit()/rollback(); verify failures cannot leave partial security state",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-http-no-timeout",
                "title": "Migration/hook performs HTTP without timeout",
                "message": "Migration or lifecycle hook performs outbound HTTP without timeout; install/upgrade can hang workers or deployment pipelines",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-cleartext-http-url",
                "title": "Migration/hook uses cleartext HTTP URL",
                "message": "Migration or lifecycle hook outbound HTTP targets a literal http:// URL; use HTTPS to protect install/upgrade integration payloads and response data from interception or downgrade",
            },
            {
                "source": "migrations",
                "rule_id": "odoo-migration-process-execution",
                "title": "Migration/hook executes a subprocess",
                "message": "Migration or lifecycle hook executes a subprocess; review command injection, deployment portability, timeouts, and privilege assumptions",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-migration-sudo-mutation"] == "migration_sudo_mutation"
    assert shapes["odoo-migration-manual-transaction"] == "migration_manual_transaction"
    assert shapes["odoo-migration-http-no-timeout"] == "migration_http_without_timeout"
    assert shapes["odoo-migration-cleartext-http-url"] == "migration_cleartext_http_url"
    assert shapes["odoo-migration-process-execution"] == "migration_process_execution"


def test_taxonomy_coverage_classifies_runtime_module_lifecycle() -> None:
    """Runtime module install/upgrade/uninstall findings need dedicated lifecycle taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "module-lifecycle",
                "rule_id": "odoo-module-public-route-lifecycle",
                "title": "Public route changes module lifecycle",
                "message": "Public/unauthenticated route calls button_immediate_install; verify attackers cannot install, upgrade, or uninstall Odoo modules",
            },
            {
                "source": "module-lifecycle",
                "rule_id": "odoo-module-sudo-lifecycle",
                "title": "Module lifecycle operation runs with an elevated environment",
                "message": "Module lifecycle method button_immediate_upgrade runs through sudo()/with_user(SUPERUSER_ID); verify only system administrators can alter installed code and data",
            },
            {
                "source": "module-lifecycle",
                "rule_id": "odoo-module-immediate-lifecycle",
                "title": "Immediate module lifecycle operation",
                "message": "button_immediate_uninstall executes module lifecycle work immediately; verify transactional impact, migrations, access rules, and registry reload behavior",
            },
            {
                "source": "module-lifecycle",
                "rule_id": "odoo-module-tainted-selection",
                "title": "Request-derived module selection",
                "message": "Request-derived data selects an ir.module.module record before a lifecycle operation; restrict to an explicit allowlist and admin-only flow",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-module-public-route-lifecycle"] == "module_lifecycle_public_route"
    assert shapes["odoo-module-sudo-lifecycle"] == "module_lifecycle_sudo_operation"
    assert shapes["odoo-module-immediate-lifecycle"] == "module_lifecycle_immediate_operation"
    assert shapes["odoo-module-tainted-selection"] == "module_lifecycle_tainted_selection"


def test_taxonomy_coverage_classifies_automation_risks() -> None:
    """base.automation findings should not collapse into generic eval, sudo, cron, or model buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "automations",
                "rule_id": "odoo-automation-broad-sensitive-trigger",
                "title": "Broad automated action on sensitive model",
                "message": "base.automation runs on 'on_write' for sensitive model 'sale.order' without a filter_domain; verify it cannot mutate/expose every record",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-dynamic-eval",
                "title": "Automated action performs dynamic evaluation",
                "message": "base.automation code contains eval/exec/safe_eval; verify no record or user-controlled expression reaches it",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-sudo-mutation",
                "title": "Automated action performs elevated mutation",
                "message": "base.automation code chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify record rules and company isolation are not bypassed",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-sudo-method-call",
                "title": "Automated action calls elevated business method",
                "message": "base.automation code uses sudo()/with_user(SUPERUSER_ID) to call a business/action method; verify workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-sensitive-model-mutation",
                "title": "Automated action mutates sensitive model",
                "message": "base.automation code mutates a sensitive model; verify trigger scope, actor, idempotency, and audit trail",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-http-no-timeout",
                "title": "Automated action performs HTTP without timeout",
                "message": "base.automation code performs outbound HTTP without timeout; review SSRF and worker exhaustion risk",
            },
            {
                "source": "automations",
                "rule_id": "odoo-automation-cleartext-http-url",
                "title": "Automated action uses cleartext HTTP URL",
                "message": "base.automation code outbound HTTP targets a literal http:// URL; use HTTPS to protect record-triggered integration payloads and response data from interception or downgrade",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-automation-broad-sensitive-trigger"] == "automation_broad_sensitive_trigger"
    assert shapes["odoo-automation-dynamic-eval"] == "automation_dynamic_eval"
    assert shapes["odoo-automation-sudo-mutation"] == "automation_sudo_mutation"
    assert shapes["odoo-automation-sudo-method-call"] == "automation_sudo_method_call"
    assert shapes["odoo-automation-sensitive-model-mutation"] == "automation_sensitive_model_mutation"
    assert shapes["odoo-automation-http-no-timeout"] == "automation_http_without_timeout"
    assert shapes["odoo-automation-cleartext-http-url"] == "automation_cleartext_http_url"
    assert any("CWE-94" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-918" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_scheduled_job_mutation_and_eval_risks() -> None:
    """Cron mutation, eval, and transaction findings need scheduled-job-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-sudo-mutation",
                "title": "Scheduled job performs elevated mutation",
                "message": "Scheduled job mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, input trust, and retry idempotency",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-sudo-method-call",
                "title": "Scheduled job calls elevated business method",
                "message": "Scheduled job uses sudo()/with_user(SUPERUSER_ID) to call a business/action method; verify workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-sensitive-model-mutation",
                "title": "Scheduled job mutates sensitive model",
                "message": "Scheduled job mutates sensitive model 'ir.config_parameter'; verify the cron user, domain scope, idempotency, and audit trail",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-dynamic-eval",
                "title": "Scheduled job performs dynamic evaluation",
                "message": "Scheduled job calls eval/exec/safe_eval; verify no synchronized data, records, or config values can control evaluated code",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-manual-transaction",
                "title": "Scheduled job controls transactions manually",
                "message": "Scheduled job calls commit()/rollback(); verify partial progress, retry behavior, and security state cannot become inconsistent",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-scheduled-job-sudo-mutation"] == "scheduled_job_elevated_mutation"
    assert shapes["odoo-scheduled-job-sudo-method-call"] == "scheduled_job_elevated_method_call"
    assert shapes["odoo-scheduled-job-sensitive-model-mutation"] == "scheduled_job_sensitive_model_mutation"
    assert shapes["odoo-scheduled-job-dynamic-eval"] == "scheduled_job_dynamic_evaluation"
    assert shapes["odoo-scheduled-job-manual-transaction"] == "scheduled_job_manual_transaction"


def test_taxonomy_coverage_classifies_scheduled_job_integration_risks() -> None:
    """Cron HTTP, TLS, and unbounded-sync findings should not fall through to generic buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-unbounded-search",
                "title": "Scheduled job performs unbounded ORM search",
                "message": "Scheduled job searches with an empty domain and no visible limit; verify batching, locking, company scoping, and idempotency",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-http-no-timeout",
                "title": "Scheduled job performs HTTP without timeout",
                "message": "Scheduled job performs outbound HTTP without timeout; slow upstreams can exhaust cron workers and cause repeated overlap",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-tls-verify-disabled",
                "title": "Scheduled job disables TLS verification",
                "message": "Scheduled job passes verify=False to outbound HTTP; recurring integrations should not permit man-in-the-middle attacks",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-cleartext-http-url",
                "title": "Scheduled job uses cleartext HTTP URL",
                "message": "Scheduled job outbound HTTP targets a literal http:// URL; use HTTPS to protect recurring integration payloads and response data from interception or downgrade",
            },
            {
                "source": "scheduled-jobs",
                "rule_id": "odoo-scheduled-job-sync-without-limit",
                "title": "External-sync scheduled job lacks visible batch limit",
                "message": "Scheduled sync/import/fetch job searches without a visible limit; verify batching, locking, timeout, and retry behavior",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-scheduled-job-unbounded-search"] == "scheduled_job_unbounded_search"
    assert shapes["odoo-scheduled-job-http-no-timeout"] == "scheduled_job_http_without_timeout"
    assert shapes["odoo-scheduled-job-tls-verify-disabled"] == "scheduled_job_tls_verification_disabled"
    assert shapes["odoo-scheduled-job-cleartext-http-url"] == "scheduled_job_cleartext_http_url"
    assert shapes["odoo-scheduled-job-sync-without-limit"] == "scheduled_job_sync_without_limit"


def test_taxonomy_coverage_classifies_xml_cron_configuration_risks() -> None:
    """XML ir.cron findings should not collapse into SQL, XML-ID, or generic HTTP buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-admin-user",
                "title": "Cron executes as admin/root user",
                "message": "ir.cron runs under admin/root user; verify the scheduled job cannot process attacker-controlled records or external input with elevated privileges",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-root-code",
                "title": "Cron executes Python as admin/root",
                "message": "ir.cron uses state='code' under admin/root user; verify it cannot process attacker-controlled records or external input",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-http-no-timeout",
                "title": "Cron performs HTTP request without visible timeout",
                "message": "Cron code performs outbound HTTP without timeout; review SSRF and worker exhaustion risk",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-tls-verify-disabled",
                "title": "Cron disables TLS verification",
                "message": "ir.cron code passes verify=False to outbound HTTP; scheduled integrations should not permit man-in-the-middle attacks",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-cleartext-http-url",
                "title": "Cron uses cleartext HTTP URL",
                "message": "ir.cron code targets a literal http:// URL; use HTTPS to protect scheduled integration payloads and response data from interception or downgrade",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-doall-enabled",
                "title": "Cron catches up missed executions",
                "message": "ir.cron has doall=True; after downtime it may replay missed jobs in bulk, causing duplicate side effects or load spikes",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-short-interval",
                "title": "Cron runs at a very short interval",
                "message": "ir.cron runs every five minutes or less; review idempotency, locking, and external side effects",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-cron-external-sync-review",
                "title": "Cron appears to perform external sync without visible guardrails",
                "message": "ir.cron name/function/model suggests external import or sync; verify timeouts, batching, locking, and retry safety",
            },
        ]
    )

    assert coverage["mapped_rules"] == 8
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-xml-cron-admin-user": "xml_cron_admin_user",
        "odoo-xml-cron-root-code": "xml_cron_root_code",
        "odoo-xml-cron-http-no-timeout": "xml_cron_http_without_timeout",
        "odoo-xml-cron-tls-verify-disabled": "xml_cron_tls_verification_disabled",
        "odoo-xml-cron-cleartext-http-url": "xml_cron_cleartext_http_url",
        "odoo-xml-cron-doall-enabled": "xml_cron_doall_enabled",
        "odoo-xml-cron-short-interval": "xml_cron_short_interval",
        "odoo-xml-cron-external-sync-review": "xml_cron_external_sync_review",
    }
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-400" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-295" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_queue_job_enqueue_risks() -> None:
    """Delayed-job enqueue findings need queue-specific idempotency and public-route taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-missing-identity-key",
                "title": "Delayed job enqueue lacks identity key",
                "message": "with_delay/delayable enqueue has no identity_key; repeated requests can create duplicate background jobs and side effects",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-public-enqueue",
                "title": "Public route enqueues background job",
                "message": "auth='public' route enqueues a delayed job; verify authentication, CSRF, throttling, and idempotency",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-queue-job-missing-identity-key"] == "queue_job_missing_identity_key"
    assert shapes["odoo-queue-job-public-enqueue"] == "queue_job_public_enqueue"


def test_taxonomy_coverage_classifies_queue_job_execution_risks() -> None:
    """Queue job mutation, eval, and HTTP findings should not fall through to generic buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-sudo-mutation",
                "title": "Queue job performs elevated mutation",
                "message": "queue_job/delayed job mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and job input trust boundaries",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-sudo-method-call",
                "title": "Queue job calls elevated business method",
                "message": "queue_job/delayed job uses sudo()/with_user(SUPERUSER_ID) to call a business/action method; verify workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-sensitive-model-mutation",
                "title": "Queue job mutates sensitive model",
                "message": "queue_job/delayed job mutates sensitive model 'ir.config_parameter'; verify job input trust, retry idempotency, and audit trail",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-dynamic-eval",
                "title": "Queue job performs dynamic evaluation",
                "message": "queue_job/delayed job calls eval/exec/safe_eval; verify no queued payload or record field can control evaluated code",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-http-no-timeout",
                "title": "Queue job performs HTTP without timeout",
                "message": "queue_job/delayed job performs outbound HTTP without timeout; slow upstreams can exhaust workers or stall job channels",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-tls-verify-disabled",
                "title": "Queue job disables TLS verification",
                "message": "queue_job/delayed job passes verify=False to outbound HTTP; background integrations should not permit man-in-the-middle attacks",
            },
            {
                "source": "queue-jobs",
                "rule_id": "odoo-queue-job-cleartext-http-url",
                "title": "Queue job uses cleartext HTTP URL",
                "message": "queue_job/delayed job outbound HTTP targets a literal http:// URL; use HTTPS to protect background integration payloads and response data from interception or downgrade",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-queue-job-sudo-mutation"] == "queue_job_elevated_mutation"
    assert shapes["odoo-queue-job-sudo-method-call"] == "queue_job_elevated_method_call"
    assert shapes["odoo-queue-job-sensitive-model-mutation"] == "queue_job_sensitive_model_mutation"
    assert shapes["odoo-queue-job-dynamic-eval"] == "queue_job_dynamic_evaluation"
    assert shapes["odoo-queue-job-http-no-timeout"] == "queue_job_http_without_timeout"
    assert shapes["odoo-queue-job-tls-verify-disabled"] == "queue_job_tls_verification_disabled"
    assert shapes["odoo-queue-job-cleartext-http-url"] == "queue_job_cleartext_http_url"
    assert any("CWE-295" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_serialization_object_parsers() -> None:
    """Pickle/YAML object-capable parser findings need serialization-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-unsafe-deserialization",
                "title": "Unsafe deserialization sink",
                "message": "pickle.loads can execute code or instantiate attacker-controlled objects; never use it on request, attachment, or integration data",
            },
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-unsafe-yaml-load",
                "title": "Unsafe YAML load",
                "message": "yaml.load() without SafeLoader can construct arbitrary Python objects; use safe_load() or SafeLoader",
            },
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-yaml-full-load",
                "title": "YAML full_load on addon data",
                "message": "yaml.full_load() accepts a broader YAML type set than safe_load(); prefer safe_load() for request, attachment, or integration data",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-serialization-unsafe-deserialization"] == "serialization_unsafe_deserialization"
    assert shapes["odoo-serialization-unsafe-yaml-load"] == "serialization_unsafe_yaml_load"
    assert shapes["odoo-serialization-yaml-full-load"] == "serialization_yaml_full_load"


def test_taxonomy_coverage_classifies_serialization_size_and_xml_parsers() -> None:
    """Literal/JSON/XML parser findings should not collapse into SSRF, SQLi, or IDOR buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-literal-eval-tainted",
                "title": "Tainted data parsed with literal_eval",
                "message": "ast.literal_eval() parses request, attachment, or integration data; prefer JSON/schema validation and enforce size/depth limits",
            },
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-json-load-no-size-check",
                "title": "Tainted JSON parsed without visible size check",
                "message": "json.load()/loads() parses request, attachment, or integration data without a visible size guard; enforce byte limits before parsing",
            },
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-xml-fromstring-tainted",
                "title": "Tainted XML parsed without hardened parser",
                "message": "Request/attachment-derived XML is parsed with ElementTree.fromstring; review entity expansion, parser hardening, and size limits",
            },
            {
                "source": "serialization",
                "rule_id": "odoo-serialization-unsafe-xml-parser",
                "title": "XML parser enables unsafe options",
                "message": "lxml XMLParser enables DTD/entity/network/huge-tree behavior; disable entity resolution, network access, and unbounded trees for imports, integrations, and attachments",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-serialization-literal-eval-tainted"] == "serialization_literal_eval_tainted"
    assert shapes["odoo-serialization-json-load-no-size-check"] == "serialization_json_load_without_size_check"
    assert shapes["odoo-serialization-xml-fromstring-tainted"] == "serialization_xml_fromstring_tainted"
    assert shapes["odoo-serialization-unsafe-xml-parser"] == "serialization_unsafe_xml_parser"


def test_taxonomy_coverage_classifies_settings_config_field_exposure() -> None:
    """res.config.settings field exposure needs settings-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "settings",
                "rule_id": "odoo-settings-sensitive-config-field-no-admin-groups",
                "title": "Sensitive settings field lacks admin-only groups",
                "message": "Settings field 'api_secret' stores sensitive config parameter 'payment.provider.api_secret' without visible admin-only groups; verify only system administrators can read/write it",
            },
            {
                "source": "settings",
                "rule_id": "odoo-settings-config-field-public-groups",
                "title": "Settings field is exposed to public/portal groups",
                "message": "Settings field 'callback_url' maps to config parameter 'integration.callback_url' and includes public/portal groups; verify it cannot expose or alter global configuration",
            },
            {
                "source": "settings",
                "rule_id": "odoo-settings-sudo-set-param",
                "title": "Settings method writes config parameter through elevated environment",
                "message": "res.config.settings method calls sudo()/with_user(SUPERUSER_ID).set_param; verify only admin settings flows can alter global security, mail, auth, or integration parameters",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-settings-sensitive-config-field-no-admin-groups"] == (
        "settings_sensitive_config_field_no_admin_groups"
    )
    assert shapes["odoo-settings-config-field-public-groups"] == "settings_config_field_public_groups"
    assert shapes["odoo-settings-sudo-set-param"] == "settings_elevated_config_write"


def test_taxonomy_coverage_classifies_settings_security_and_module_toggles() -> None:
    """Security toggles, admin grants, and module toggles should not be unmapped."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "settings",
                "rule_id": "odoo-settings-security-toggle-no-admin-groups",
                "title": "Security-sensitive setting lacks admin-only groups",
                "message": "Settings field 'allow_uninvited_signup' maps to security-sensitive config parameter 'auth.signup.allow_uninvited' without visible admin-only groups; verify only system administrators can alter it",
            },
            {
                "source": "settings",
                "rule_id": "odoo-settings-security-toggle-unsafe-default",
                "title": "Security-sensitive setting defaults to unsafe posture",
                "message": "Settings field 'allow_uninvited_signup' maps to security-sensitive config parameter 'auth_signup.allow_uninvited' and defaults to 'True'; verify production installs cannot enable unsafe behavior by default",
            },
            {
                "source": "settings",
                "rule_id": "odoo-settings-implies-admin-group",
                "title": "Settings toggle implies administrator group",
                "message": "Settings field 'allow_admin' implies elevated group 'base.group_system'; verify only existing administrators can toggle it",
            },
            {
                "source": "settings",
                "rule_id": "odoo-settings-module-toggle-no-admin-groups",
                "title": "Module install toggle lacks admin-only groups",
                "message": "Settings field 'module_sensitive_connector' can install/uninstall modules and has no visible admin-only groups; verify only system administrators can access it",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-settings-security-toggle-no-admin-groups"] == "settings_security_toggle_no_admin_groups"
    assert shapes["odoo-settings-security-toggle-unsafe-default"] == "settings_security_toggle_unsafe_default"
    assert shapes["odoo-settings-implies-admin-group"] == "settings_implies_admin_group"
    assert shapes["odoo-settings-module-toggle-no-admin-groups"] == "settings_module_toggle_no_admin_groups"


def test_taxonomy_coverage_classifies_signup_route_and_reset_trigger() -> None:
    """Signup/reset route and helper findings need account-recovery taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-public-token-route",
                "title": "Public signup/reset token route",
                "message": "Public signup/reset route should validate token expiry, audience, redirect target, and account state before mutating identity data",
            },
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-tainted-reset-trigger",
                "title": "Request-derived signup/reset trigger",
                "message": "Request-derived data reaches signup/reset-password helper; verify rate limiting, account enumeration resistance, and token expiry",
            },
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-token-exposed",
                "title": "Signup/reset token exposed from public route",
                "message": "Public signup/reset response includes signup/access token data; avoid exposing reusable account takeover tokens in rendered values, JSON, redirects, logs, or referrers",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-signup-public-token-route"] == "signup_public_token_route"
    assert shapes["odoo-signup-tainted-reset-trigger"] == "signup_tainted_reset_trigger"
    assert shapes["odoo-signup-token-exposed"] == "signup_token_exposed_public_route"


def test_taxonomy_coverage_classifies_signup_token_lookup_and_identity_mutation() -> None:
    """Signup token lookup, expiry, sudo, and mutation findings should not use generic buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-tainted-token-lookup",
                "title": "Request-derived token lookup",
                "message": "Request-derived signup/access token is used to look up identity records; verify constant-time token checks, expiry, and ownership constraints",
            },
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-token-lookup-without-expiry",
                "title": "Signup/reset token lookup lacks expiry constraint",
                "message": "Request-derived signup/reset token lookup does not visibly constrain signup_expiration; verify expired tokens cannot authenticate or mutate accounts",
            },
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-tainted-identity-token-write",
                "title": "Request-derived signup token or password mutation",
                "message": "Request-derived data writes signup/access token or password fields on res.users/res.partner; require validated reset/signup flow state first",
            },
            {
                "source": "signup-tokens",
                "rule_id": "odoo-signup-public-sudo-identity-flow",
                "title": "Public signup/reset flow uses sudo identity access",
                "message": "Public signup/reset flow uses sudo()/with_user(SUPERUSER_ID) on res.users/res.partner; verify token checks happen before privileged reads or writes",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-signup-tainted-token-lookup"] == "signup_tainted_token_lookup"
    assert shapes["odoo-signup-token-lookup-without-expiry"] == "signup_token_lookup_without_expiry"
    assert shapes["odoo-signup-tainted-identity-token-write"] == "signup_tainted_identity_token_write"
    assert shapes["odoo-signup-public-sudo-identity-flow"] == "signup_public_sudo_identity_flow"


def test_taxonomy_coverage_classifies_controller_sensitive_response_exposure() -> None:
    """Controller token response rules should map to sensitive-data exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-sensitive-token-response",
                "title": "Controller response returns sensitive token-shaped data",
                "message": "Controller response includes token, password, API key, or secret-shaped data",
            },
        ]
    )

    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_sensitive_response_exposure"
    assert "CWE-200" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_open_redirect() -> None:
    """Controller redirects should not collapse into act_url or frontend navigation taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-open-redirect",
                "title": "Controller redirects to request-controlled URL",
                "message": "Controller redirects to a request-derived URL; restrict redirects to local paths or an allowlisted host set",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_open_redirect"
    assert "CWE-601" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_cors_wildcard_origin() -> None:
    """Permissive CORS response headers should not map through generic access-control hints."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-cors-wildcard-origin",
                "title": "Controller response allows any CORS origin",
                "message": "Controller sets Access-Control-Allow-Origin: *; verify cross-origin reads are intended and credentials, tokens, or private data cannot be exposed",
            },
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-cors-reflected-origin",
                "title": "Controller reflects request origin into CORS header",
                "message": "Controller reflects a request-derived Origin into Access-Control-Allow-Origin; require an explicit trusted-origin allowlist before enabling cross-origin reads",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"controller_cors_wildcard_origin"}
    assert all("CWE-942" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_controller_cors_credentials() -> None:
    """Credentialed CORS headers should map to CORS misconfiguration taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-cors-credentials-enabled",
                "title": "Controller enables credentialed CORS",
                "message": "Controller sets Access-Control-Allow-Credentials: true; verify allowed origins are fixed, trusted, and never wildcarded or reflected from request headers",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_cors_credentials"
    assert "CWE-942" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_response_header_injection() -> None:
    """Request-controlled headers should map to response-splitting/header injection taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-response-header-injection",
                "title": "Response header uses request-controlled value",
                "message": "Controller writes request-derived data into response headers; validate against CRLF/header injection and unsafe filenames",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_response_header_injection"
    assert "CWE-113" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_csp_header() -> None:
    """Weak CSP response headers should map to protection-mechanism taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-csp-header",
                "title": "Controller sets weak Content-Security-Policy",
                "message": "Controller sets a Content-Security-Policy with 'unsafe-inline'; tighten script/style sources before relying on CSP to limit XSS impact",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_csp_header"
    assert "CWE-693" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_frame_options() -> None:
    """Weak frame options should map to clickjacking taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-frame-options",
                "title": "Controller sets weak X-Frame-Options",
                "message": "Controller sets X-Frame-Options to 'ALLOW-FROM https://partner.example'; use DENY/SAMEORIGIN or CSP frame-ancestors to reduce clickjacking exposure",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_frame_options"
    assert "CWE-1021" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_referrer_policy() -> None:
    """Weak referrer policy headers should map to sensitive URL leakage taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-referrer-policy",
                "title": "Controller sets weak Referrer-Policy",
                "message": "Controller sets Referrer-Policy to 'unsafe-url'; use no-referrer or strict-origin-when-cross-origin to reduce tokenized URL leakage",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_referrer_policy"
    assert "CWE-200" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_hsts_header() -> None:
    """Weak HSTS response headers should map to HTTPS downgrade taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-hsts-header",
                "title": "Controller sets weak Strict-Transport-Security",
                "message": "Controller sets a weak Strict-Transport-Security header (max-age=0 disables HSTS); use a long max-age such as 31536000 and includeSubDomains where appropriate",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_hsts_header"
    assert "CWE-319" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_cross_origin_policy() -> None:
    """Weak cross-origin isolation headers should map to header posture taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-cross-origin-policy",
                "title": "Controller sets weak cross-origin isolation policy",
                "message": "Controller sets Cross-Origin-Opener-Policy to 'unsafe-none'; use explicit same-origin or require-corp style policies where cross-origin isolation is needed",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_cross_origin_policy"
    assert "CWE-346" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_weak_permissions_policy() -> None:
    """Weak browser permissions policies should map to protection-mechanism taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-weak-permissions-policy",
                "title": "Controller sets weak browser permissions policy",
                "message": "Controller allows sensitive browser feature geolocation=* in Permissions-Policy; restrict camera, microphone, geolocation, payment, USB, serial, and clipboard access to trusted origins only",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_weak_permissions_policy"
    assert "CWE-693" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_tainted_html_response() -> None:
    """Request-derived HTML responses should map to XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-html-response",
                "title": "Controller returns request-derived HTML response",
                "message": "Controller returns request-derived data as text/html; sanitize or render through trusted QWeb templates",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_tainted_html_response"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_jsonp_callback_response() -> None:
    """Request-controlled JSONP callbacks should map to XSS taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-jsonp-callback-response",
                "title": "Controller returns request-controlled JSONP callback",
                "message": "Controller builds a JavaScript/JSONP response from a request-controlled callback; remove JSONP or strictly validate callback names and response data",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "controller_jsonp_callback_response"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_controller_tainted_cookie() -> None:
    """Request-controlled cookies should map to cookie/state taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-cookie-name",
                "title": "Cookie name is request-controlled",
                "message": "Controller set_cookie name is request-derived; restrict cookie keys to fixed allowlisted names to avoid arbitrary client-side state changes",
            },
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-cookie-value",
                "title": "Cookie value is request-controlled",
                "message": "Controller set_cookie value is request-derived; verify cookie trust boundaries, signing, and fixation resistance",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"controller_tainted_cookie"}
    assert all("CWE-384" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_controller_tainted_file_response() -> None:
    """Request-controlled file responses should map to path traversal/disclosure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-file-download",
                "title": "Controller sends request-controlled file path",
                "message": "Controller send_file path is request-controlled; validate basename, attachment ownership, traversal, and storage root",
            },
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-file-read",
                "title": "Controller reads request-controlled file path",
                "message": "Controller reads from a request-controlled filesystem path; validate attachment ownership, basename, traversal, symlinks, and storage root before returning data",
            },
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-tainted-file-offload-header",
                "title": "File offload header uses request-controlled path",
                "message": "Controller sets X-Accel-Redirect/X-Sendfile from request input; validate internal path mapping and prevent arbitrary file disclosure",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"controller_tainted_file_response"}
    assert all("CWE-22" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_route_decorator_posture() -> None:
    """Route decorator posture rules should not map through broad portal, SSRF, or sudo fallbacks."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "route-security",
                "rule_id": "odoo-route-auth-none",
                "title": "Route bypasses database user authentication",
                "message": "Route /webhook uses auth='none'; verify it is needed before database selection and performs no data access or mutation",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-cors-wildcard",
                "title": "Route allows wildcard CORS",
                "message": "Route /api sets cors='*'; verify cross-origin callers cannot use ambient sessions or access sensitive data",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-cors-external-origin",
                "title": "Public route allows external CORS origin",
                "message": "Public route /api sets cors='https://partner.example.com'; verify the origin is trusted and cannot use ambient sessions unexpectedly",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-bearer-save-session",
                "title": "Bearer route explicitly saves browser session",
                "message": "Bearer route /api/token-sync sets save_session=True; verify API-token requests cannot create or persist ambient browser sessions unexpectedly",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-csrf-disabled-all-methods",
                "title": "Public route disables CSRF without method restriction",
                "message": "Public route /public/update disables CSRF and does not set methods=; constrain verbs and require a non-browser authentication token for state-changing callbacks",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-unsafe-csrf-disabled",
                "title": "Mutating route disables CSRF",
                "message": "Route /public/update disables CSRF on a mutating-looking endpoint; verify callers use a stronger non-browser token",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-public-get-mutation",
                "title": "Public route exposes mutating action over GET",
                "message": "Public route /shop/order/confirm exposes a mutating-looking action over GET; keep GET idempotent and move state changes to POST with CSRF or a non-browser token",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-public-all-methods",
                "title": "Public route does not restrict HTTP methods",
                "message": "Public route /public/thing does not set methods=; constrain allowed verbs to reduce unexpected GET/POST exposure",
            },
            {
                "source": "route-security",
                "rule_id": "odoo-route-public-sitemap-indexed",
                "title": "Public website route may be sitemap-indexed",
                "message": "Public website route /public/thing can be sitemap-indexed; verify route content is intended for discovery",
            },
        ]
    )

    assert coverage["mapped_rules"] == 9
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-route-auth-none": "route_auth_none",
        "odoo-route-cors-wildcard": "route_cors_wildcard",
        "odoo-route-cors-external-origin": "route_cors_external_origin",
        "odoo-route-bearer-save-session": "route_bearer_save_session",
        "odoo-route-csrf-disabled-all-methods": "route_csrf_disabled_all_methods",
        "odoo-route-unsafe-csrf-disabled": "route_unsafe_csrf_disabled",
        "odoo-route-public-get-mutation": "csrf_state_change_get",
        "odoo-route-public-all-methods": "route_public_all_methods",
        "odoo-route-public-sitemap-indexed": "route_public_sitemap_indexed",
    }
    assert any("CWE-306" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-942" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-352" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_action_window_sensitive_exposure() -> None:
    """Sensitive act_window routes and broad domains need access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-public-sensitive-model",
                "title": "Public route returns sensitive action window",
                "message": "Public route returns an act_window for sensitive model 'res.users'; verify authentication, groups, and record rules",
            },
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-sensitive-broad-domain",
                "title": "Action window exposes sensitive model with broad domain",
                "message": "ir.actions.act_window for sensitive model 'ir.config_parameter' uses a broad domain; verify groups and record rules",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"action_window_sensitive_exposure"}
    assert all("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_action_window_privileged_context() -> None:
    """Privilege-seeding and archived visibility contexts need action-window taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-privileged-default-context",
                "title": "Action window context sets privileged defaults",
                "message": "act_window context sets default_groups_id or sel_groups_*; verify only admins can reach this action",
            },
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-active-test-disabled",
                "title": "Action window disables active_test",
                "message": "act_window context sets active_test=False; archived records may become visible",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"action_window_privileged_context"}
    assert all("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_action_window_company_scope_context() -> None:
    """Company-scope action contexts should map to multi-company access taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-company-scope-context",
                "title": "Action window context changes company scope",
                "message": "act_window context sets allowed_company_ids or force_company; verify multi-company isolation",
            }
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert coverage["mapped_entries"][0]["shape"] == "action_window_company_scope_context"
    assert "CWE-284" in coverage["mapped_entries"][0]["cwe"]


def test_taxonomy_coverage_classifies_action_window_tainted_definition() -> None:
    """Request-controlled act_window model/domain/context should not map to generic SSRF/domain."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-tainted-res-model",
                "title": "Action window model is request-controlled",
                "message": "ir.actions.act_window res_model is request-derived; restrict actions to explicit models to avoid exposing unintended records or views",
            },
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-tainted-domain",
                "title": "Action window domain uses request-derived data",
                "message": "ir.actions.act_window domain is request-derived; validate allowed fields/operators and prevent cross-record discovery",
            },
            {
                "source": "action-windows",
                "rule_id": "odoo-act-window-tainted-context",
                "title": "Action window context is request-controlled",
                "message": "ir.actions.act_window context is request-derived; prevent forged defaults, company scope, active_test, and framework flags",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    assert {entry["shape"] for entry in coverage["mapped_entries"]} == {"action_window_tainted_definition"}
    assert all("CWE-915" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_outbound_integration_credential_forwarding() -> None:
    """Outbound auth forwarding rules should map to credential exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "integrations",
                "rule_id": "odoo-integration-tainted-auth-header",
                "title": "Outbound HTTP auth header uses request-controlled value",
                "message": "Outbound HTTP forwards request-derived Authorization header material",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-tainted-http-auth",
                "title": "Outbound HTTP auth parameter uses request-controlled value",
                "message": "Outbound HTTP auth= material is request-derived",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-hardcoded-auth-header",
                "title": "Outbound HTTP auth header is hardcoded",
                "message": "Outbound HTTP sends literal Authorization, Cookie, API key, or token header material",
            },
        ]
    )

    assert coverage["mapped_rules"] == 3
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-integration-tainted-auth-header": "outbound_integration_credential_forwarding",
        "odoo-integration-tainted-http-auth": "outbound_integration_credential_forwarding",
        "odoo-integration-hardcoded-auth-header": "integration_hardcoded_auth_header",
    }
    assert all("CWE-522" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_integration_http_risks() -> None:
    """Outbound HTTP integration rules need timeout, TLS, and SSRF-specific taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "integrations",
                "rule_id": "odoo-integration-http-no-timeout",
                "title": "Outbound HTTP call has no timeout",
                "message": "Outbound HTTP call lacks a timeout; a slow upstream can exhaust Odoo workers",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-tls-verify-disabled",
                "title": "Outbound HTTP disables TLS verification",
                "message": "Outbound HTTP call passes verify=False; this permits man-in-the-middle attacks against integration traffic",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-cleartext-http-url",
                "title": "Outbound integration uses cleartext HTTP URL",
                "message": "Outbound HTTP call targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-tainted-url-ssrf",
                "title": "Outbound HTTP URL is request-controlled",
                "message": "Outbound HTTP URL is derived from request/controller input; validate scheme, host, and private-network reachability to prevent SSRF",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-internal-url-ssrf",
                "title": "Outbound HTTP targets internal URL",
                "message": "Outbound HTTP call targets a literal loopback, private, link-local, or metadata URL; verify the integration cannot expose cloud metadata or internal Odoo/admin services",
            },
        ]
    )

    assert coverage["mapped_rules"] == 5
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-integration-http-no-timeout": "integration_http_no_timeout",
        "odoo-integration-tls-verify-disabled": "integration_tls_verify_disabled",
        "odoo-integration-cleartext-http-url": "integration_cleartext_http_url",
        "odoo-integration-tainted-url-ssrf": "integration_tainted_url_ssrf",
        "odoo-integration-internal-url-ssrf": "integration_internal_url_ssrf",
    }
    assert any("CWE-295" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-918" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_integration_command_risks() -> None:
    """Integration process findings should not collapse into SSRF or path traversal."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "integrations",
                "rule_id": "odoo-integration-subprocess-shell-true",
                "title": "Subprocess uses shell=True",
                "message": "subprocess call uses shell=True; verify no user-controlled command text can reach this sink",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-os-command-execution",
                "title": "OS command execution sink",
                "message": "os.system executes through the shell; replace with bounded subprocess argument lists and validate command inputs",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-tainted-command-args",
                "title": "Process command uses request-controlled input",
                "message": "Process command or arguments are derived from request/controller input; validate allowlisted commands, arguments, paths, and environment",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-process-no-timeout",
                "title": "Process execution has no timeout",
                "message": "Process execution lacks timeout; external converters and commands can hang Odoo workers",
            },
            {
                "source": "integrations",
                "rule_id": "odoo-integration-report-command-review",
                "title": "External report/document converter command",
                "message": "Command invokes an external report/document converter; verify input file control, output path safety, timeout, and sandboxing",
            },
        ]
    )

    assert coverage["mapped_rules"] == 5
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-integration-subprocess-shell-true": "integration_subprocess_shell_true",
        "odoo-integration-os-command-execution": "integration_os_command_execution",
        "odoo-integration-tainted-command-args": "integration_tainted_command_args",
        "odoo-integration-process-no-timeout": "integration_process_no_timeout",
        "odoo-integration-report-command-review": "integration_report_command_review",
    }
    assert any("CWE-78" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-770" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_realtime_bus_channel_authorization() -> None:
    """Realtime bus channel rules should map to specific authorization/exposure taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-broad-or-tainted-channel-subscription",
                "title": "Bus subscription accepts broad or request-controlled channel",
                "message": "Realtime bus subscription mutates channel lists with request-derived or broad channels",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-sensitive-payload",
                "title": "Bus notification may expose sensitive payload data",
                "message": "Realtime bus payload contains sensitive fields",
            },
        ]
    )

    assert coverage["mapped_rules"] == 2
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-realtime-broad-or-tainted-channel-subscription": "realtime_channel_subscription_authorization",
        "odoo-realtime-sensitive-payload": "realtime_sensitive_payload",
    }
    assert all("CWE-862" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_realtime_specific_risks() -> None:
    """Realtime bus and notification rules should not collapse into generic web/mail buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-broad-or-tainted-channel-subscription",
                "title": "Bus subscription accepts broad or request-controlled channel",
                "message": "Realtime bus subscription mutates channel lists with request-derived or broad channels; verify users can only subscribe to tenant/user-scoped channels they are authorized to receive",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-public-route-bus-send",
                "title": "Public route sends bus notification",
                "message": "Public/unauthenticated route sends realtime bus notifications; verify authorization, channel scope, and rate limiting",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-bus-send-sudo",
                "title": "Bus notification is sent through an elevated environment",
                "message": "Realtime bus notification uses sudo()/with_user(SUPERUSER_ID); verify channel recipients and payload cannot bypass record rules or company boundaries",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-broad-or-tainted-channel",
                "title": "Bus notification targets broad or request-controlled channel",
                "message": "Realtime bus channel is broad or request-derived; verify tenant/user scoping and channel entropy",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-sensitive-payload",
                "title": "Bus notification may expose sensitive payload data",
                "message": "Realtime bus payload appears request-derived or contains sensitive fields; verify recipients are authorized for every emitted field",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-notification-sudo",
                "title": "Notification is sent through an elevated environment",
                "message": "Notification/message call uses sudo()/with_user(SUPERUSER_ID); verify followers, partners, and subtype routing cannot expose private records",
            },
            {
                "source": "realtime",
                "rule_id": "odoo-realtime-tainted-notification-content",
                "title": "Notification content is request-controlled",
                "message": "Notification/message content includes request-derived data; verify escaping, recipient authorization, and spam/rate controls",
            },
        ]
    )

    assert coverage["mapped_rules"] == 7
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-realtime-broad-or-tainted-channel-subscription": "realtime_channel_subscription_authorization",
        "odoo-realtime-public-route-bus-send": "realtime_public_route_bus_send",
        "odoo-realtime-bus-send-sudo": "realtime_bus_send_sudo",
        "odoo-realtime-broad-or-tainted-channel": "realtime_broad_or_tainted_channel",
        "odoo-realtime-sensitive-payload": "realtime_sensitive_payload",
        "odoo-realtime-notification-sudo": "realtime_notification_sudo",
        "odoo-realtime-tainted-notification-content": "realtime_tainted_notification_content",
    }
    assert any("CWE-269" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-770" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_website_form_public_record_mutation() -> None:
    """Website form rules should map to specific CSRF/access-control taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-route-csrf-disabled",
                "title": "Website form route disables CSRF protection",
                "message": "Website form route disables csrf protection for a public endpoint",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-sensitive-field",
                "title": "Website form exposes sensitive model field",
                "message": "Website form exposes sensitive model field",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-sanitize-disabled",
                "title": "Website form disables input sanitization",
                "message": "Website form submits sanitize_form=false",
            },
        ]
    )

    assert coverage["mapped_rules"] == 3
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-website-form-route-csrf-disabled": "website_form_route_csrf_disabled",
        "odoo-website-form-sensitive-field": "website_form_sensitive_field",
        "odoo-website-form-sanitize-disabled": "website_form_sanitize_disabled",
    }
    assert any("CWE-352" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-79" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_website_form_specific_risks() -> None:
    """Website form scanner rule IDs should not collapse into generic upload or metadata buckets."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-public-model-create",
                "title": "Website form posts directly to an Odoo model",
                "message": "Website form submits to Odoo model creation; verify website_form allowed fields, required authentication, rate limiting, and post-create side effects",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-file-upload",
                "title": "Website form accepts file uploads",
                "message": "Public website form accepts file uploads; verify MIME/type checks, size limits, attachment visibility, and malware scanning",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-active-file-upload",
                "title": "Website form allows browser-active file uploads",
                "message": "Public website form file input accepts browser-active upload types (image/svg+xml, .html); restrict accept lists and enforce server-side MIME/content validation before creating attachments",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-missing-csrf-token",
                "title": "Website form has no visible CSRF token",
                "message": "Website form posts to model creation without a visible csrf_token input; verify Odoo CSRF protection is present and cannot be bypassed cross-site",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-get-method",
                "title": "Website form uses GET for model submission",
                "message": "Website form targets model submission with method=GET; verify state changes cannot be triggered by links, crawlers, prefetchers, or cross-site navigation",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-dangerous-success-redirect",
                "title": "Website form success redirect uses dangerous URL scheme",
                "message": "Website form success page uses dangerous URL 'javascript:alert(1)'; restrict success redirects to local routes or reviewed HTTPS destinations",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-external-success-redirect",
                "title": "Website form redirects to external success URL",
                "message": "Website form success page points to external URL 'https://evil.example/thanks'; verify it cannot become phishing, token leakage, or open-redirect surface",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-dynamic-success-redirect",
                "title": "Website form success redirect is request-derived",
                "message": "Website form success page is built from request-derived expression 'request.params.get(\"next\")'; validate against local routes or allowlisted hosts before redirecting",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-hidden-model-selector",
                "title": "Website form carries model selector in hidden input",
                "message": "Website form includes a hidden model selector; verify clients cannot tamper with submitted model/field metadata",
            },
            {
                "source": "website-forms",
                "rule_id": "odoo-website-form-field-allowlisted-sensitive",
                "title": "Sensitive field is allowlisted for website forms",
                "message": "Model field 'partner_id' sets website_form_blacklisted=False; verify public website forms cannot set ownership, workflow, company, token, privilege, or visibility fields",
            },
        ]
    )

    assert coverage["mapped_rules"] == 10
    assert coverage["unmapped_rule_ids"] == []
    assert {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]} == {
        "odoo-website-form-public-model-create": "website_form_public_model_create",
        "odoo-website-form-file-upload": "website_form_file_upload",
        "odoo-website-form-active-file-upload": "website_form_active_file_upload",
        "odoo-website-form-missing-csrf-token": "website_form_missing_csrf_token",
        "odoo-website-form-get-method": "website_form_get_method",
        "odoo-website-form-dangerous-success-redirect": "website_form_dangerous_success_redirect",
        "odoo-website-form-external-success-redirect": "website_form_external_success_redirect",
        "odoo-website-form-dynamic-success-redirect": "website_form_dynamic_success_redirect",
        "odoo-website-form-hidden-model-selector": "website_form_hidden_model_selector",
        "odoo-website-form-field-allowlisted-sensitive": "website_form_field_allowlisted_sensitive",
    }
    assert any("CWE-434" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-601" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_sarif_results_include_governance_annotations(tmp_path: Path) -> None:
    """SARIF results should preserve fix-list and expired accepted-risk context."""
    finding = {
        "id": "F-1",
        "source": "route-security",
        "rule_id": "odoo-deep-public-write-route",
        "title": "Public write route",
        "severity": "high",
        "file": "controllers/main.py",
        "line": 4,
        "message": "Public route performs a write",
        "fingerprint": "sha256:" + "1" * 64,
        "fix_list_status": "regression",
        "fix_list_id": "FIX-001",
        "expired_accepted_risk_ids": ["AR-001"],
    }

    sarif = odoo_deep_scan.generate_sarif_report(tmp_path, [finding])
    result = sarif["runs"][0]["results"][0]

    assert result["properties"]["fix_list_status"] == "regression"
    assert result["properties"]["fix_list_id"] == "FIX-001"
    assert result["properties"]["expired_accepted_risk_ids"] == ["AR-001"]
    assert result["suppressions"][0]["status"] == "rejected"
    assert "Expired accepted risk AR-001" in result["suppressions"][0]["justification"]


def test_html_report_includes_two_bucket_triage_controls() -> None:
    """HTML report should be a self-contained triage surface for accepted-risk and fix-list queues."""
    finding = {
        "id": "F-1",
        "source": "route-security",
        "rule_id": "odoo-deep-public-write-route",
        "title": "Public write route",
        "severity": "high",
        "file": "controllers/main.py",
        "line": 4,
        "message": "Public route performs a write",
        "fingerprint": "sha256:" + "1" * 64,
        "fix_list_status": "tracked",
        "fix_list_id": "FIX-001",
        "fix_list_target_date": "2099-01-01",
        "expired_accepted_risk_ids": ["AR-001"],
    }
    html = odoo_deep_scan.generate_html_report(
        [finding],
        {
            "module_risk": {
                "modules": [
                    {
                        "module": "portal_sale",
                        "band": "high",
                        "score": 10,
                        "findings": 1,
                        "public_routes": 1,
                    }
                ]
            }
        },
    )

    assert "<!doctype html>" in html
    assert 'data-fingerprint="sha256:' + "1" * 64 + '"' in html
    assert "Mark as accepted risk" in html
    assert "Add to fix-it list" in html
    assert "accepted-risk queue" in html
    assert "fix-list queue" in html
    assert "FIX-001" in html
    assert "AR-001" in html
    assert "portal_sale" in html
    assert "https://" not in html


def test_taxonomy_coverage_classifies_remaining_qweb_surface_rules() -> None:
    """QWeb HTML, URL, and sensitive render rules should carry explicit CWE taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "qweb",
                "rule_id": "odoo-qweb-dangerous-tag",
                "title": "QWeb template renders dangerous HTML tag",
                "message": "Template renders script, iframe, object, embed, or link tag",
            },
            {
                "source": "web-asset",
                "rule_id": "odoo-web-owl-qweb-dangerous-tag",
                "title": "OWL inline template renders dangerous HTML tag",
                "message": "OWL xml template contains a script, iframe, object, embed, or form tag",
            },
            {
                "source": "qweb",
                "rule_id": "odoo-qweb-html-widget",
                "title": "QWeb template renders an HTML widget",
                "message": "widget='html' renders rich text that requires sanitization review",
            },
            {
                "source": "qweb",
                "rule_id": "odoo-qweb-inline-event",
                "title": "QWeb template includes inline event handler",
                "message": "Inline event handler attribute can execute JavaScript",
            },
            {
                "source": "qweb",
                "rule_id": "odoo-qweb-sensitive-field-render",
                "title": "QWeb renders sensitive field",
                "message": "Template renders password, token, secret, API key, or bank field",
            },
            {
                "source": "web-asset",
                "rule_id": "odoo-web-owl-qweb-sensitive-field-render",
                "title": "OWL inline template renders sensitive-looking field",
                "message": "OWL xml template renders token, secret, password, or API-key-like data",
            },
            {
                "source": "qweb",
                "rule_id": "odoo-qweb-t-att-url",
                "title": "QWeb binds dynamic URL attribute",
                "message": "Dynamic href/src/action URL must reject scriptable URL schemes",
            },
            {
                "source": "web-asset",
                "rule_id": "odoo-web-owl-qweb-dynamic-url-attribute",
                "title": "OWL inline template binds dynamic URL attribute",
                "message": "OWL xml template binds a dynamic href, src, action, or similar URL attribute",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes == {
        "odoo-qweb-dangerous-tag": "qweb_dangerous_tag",
        "odoo-web-owl-qweb-dangerous-tag": "qweb_dangerous_tag",
        "odoo-qweb-html-widget": "qweb_html_widget_render",
        "odoo-qweb-inline-event": "qweb_inline_event_handler",
        "odoo-qweb-sensitive-field-render": "qweb_sensitive_field_render",
        "odoo-web-owl-qweb-sensitive-field-render": "qweb_sensitive_field_render",
        "odoo-qweb-t-att-url": "qweb_dynamic_url_attribute",
        "odoo-web-owl-qweb-dynamic-url-attribute": "qweb_dynamic_url_attribute",
    }
    assert any("CWE-601" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-200" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_frontend_and_cookie_rule_gaps() -> None:
    """Controller cookie flags and frontend storage/code execution need explicit taxonomy."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "controller-responses",
                "rule_id": "odoo-controller-cookie-missing-security-flags",
                "title": "Controller sets cookie without security flags",
                "message": "set_cookie lacks secure, httponly, or samesite",
            },
            {
                "source": "web-assets",
                "rule_id": "odoo-web-sensitive-browser-storage",
                "title": "Sensitive value read from browser storage",
                "message": "Frontend code reads token/secret/password-like data from localStorage or sessionStorage; avoid depending on XSS-readable browser storage for credentials",
            },
            {
                "source": "web-assets",
                "rule_id": "odoo-web-string-code-execution",
                "title": "Frontend executes string-built code",
                "message": "eval, Function constructor, setTimeout string, or setInterval string executes JavaScript from strings",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes == {
        "odoo-controller-cookie-missing-security-flags": "controller_cookie_missing_security_flags",
        "odoo-web-sensitive-browser-storage": "frontend_sensitive_browser_storage",
        "odoo-web-string-code-execution": "frontend_string_code_execution",
    }
    assert any("CWE-614" in entry["cwe"] for entry in coverage["mapped_entries"])
    assert any("CWE-94" in entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_classifies_ui_and_xml_privilege_rule_gaps() -> None:
    """UI exposure and XML privilege mutation rules should not remain unmapped."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-action-button-no-groups",
                "title": "UI action button has no groups",
                "message": "Button action is visible without groups",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-object-button-no-groups",
                "title": "Object button has no groups",
                "message": "Object button is visible without groups",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-public-object-button",
                "title": "Public object button",
                "message": "Object button visible to public or portal users can trigger an object method",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-action-button-no-groups",
                "title": "Sensitive action button has no groups",
                "message": "Sensitive UI entry point is visible without groups",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-action-no-groups",
                "title": "Sensitive action has no groups",
                "message": "Sensitive action is visible without groups",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-menu-no-groups",
                "title": "Sensitive menu has no groups",
                "message": "Sensitive menu is visible without groups",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-action-button-external-groups",
                "title": "Action button opens sensitive model exposed to public or portal users",
                "message": "Sensitive UI entry point is visible to public or portal users",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-action-external-groups",
                "title": "Sensitive model action exposed to public or portal users",
                "message": "Sensitive action exposed to public or portal users",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-server-action-external-groups",
                "title": "Sensitive server action exposed to public or portal users",
                "message": "Sensitive server action exposed to public or portal users",
            },
            {
                "source": "ui-exposure",
                "rule_id": "odoo-ui-sensitive-menu-external-groups",
                "title": "Sensitive menu exposed to public or portal users",
                "message": "Sensitive menu exposed to public or portal users",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-group-implies-privilege",
                "title": "XML group implies privileged group",
                "message": "Group inherits privileged group",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-function-group-implies-privilege",
                "title": "XML function implies privileged group",
                "message": "Function makes one group imply a privileged group",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-user-admin-group-assignment",
                "title": "XML assigns admin group to user",
                "message": "User group assignment grants elevated privileges",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-function-user-group-assignment",
                "title": "XML function assigns user to privileged group",
                "message": "Function assigns user to privileged group",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-function-security-model-mutation",
                "title": "XML function mutates security model",
                "message": "Function writes ir.model.access, ir.rule, res.groups, or res.users",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-public-mail-channel",
                "title": "XML declares public mail channel",
                "message": "mail.channel is public",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-server-action-tls-verify-disabled",
                "title": "Server action disables TLS verification",
                "message": "ir.actions.server code passes verify=False to outbound HTTP; install/update automation should not permit man-in-the-middle attacks",
            },
            {
                "source": "xml-data",
                "rule_id": "odoo-xml-server-action-cleartext-http-url",
                "title": "Server action uses cleartext HTTP URL",
                "message": "ir.actions.server code targets a literal http:// URL; use HTTPS to protect automation payloads and response data from interception or downgrade",
            },
        ]
    )

    assert coverage["unmapped_rule_ids"] == []
    shapes = {entry["rule_id"]: entry["shape"] for entry in coverage["mapped_entries"]}
    assert shapes["odoo-ui-action-button-no-groups"] == "ui_action_without_groups"
    assert shapes["odoo-ui-object-button-no-groups"] == "ui_action_without_groups"
    assert shapes["odoo-ui-public-object-button"] == "ui_public_object_button"
    assert shapes["odoo-ui-sensitive-action-button-no-groups"] == "ui_sensitive_action_without_groups"
    assert shapes["odoo-ui-sensitive-action-no-groups"] == "ui_sensitive_action_without_groups"
    assert shapes["odoo-ui-sensitive-menu-no-groups"] == "ui_sensitive_action_without_groups"
    assert shapes["odoo-ui-sensitive-action-button-external-groups"] == "ui_sensitive_action_external_groups"
    assert shapes["odoo-ui-sensitive-action-external-groups"] == "ui_sensitive_action_external_groups"
    assert shapes["odoo-ui-sensitive-server-action-external-groups"] == "ui_sensitive_action_external_groups"
    assert shapes["odoo-ui-sensitive-menu-external-groups"] == "ui_sensitive_action_external_groups"
    assert shapes["odoo-xml-group-implies-privilege"] == "xml_data_group_privilege_implication"
    assert shapes["odoo-xml-function-group-implies-privilege"] == "xml_data_group_privilege_implication"
    assert shapes["odoo-xml-user-admin-group-assignment"] == "xml_data_user_admin_group_assignment"
    assert shapes["odoo-xml-function-user-group-assignment"] == "xml_data_user_admin_group_assignment"
    assert shapes["odoo-xml-function-security-model-mutation"] == "xml_data_function_security_model_mutation"
    assert shapes["odoo-xml-public-mail-channel"] == "xml_data_public_mail_channel"
    assert shapes["odoo-xml-server-action-tls-verify-disabled"] == "xml_data_server_action_tls_verification_disabled"
    assert shapes["odoo-xml-server-action-cleartext-http-url"] == "xml_data_server_action_cleartext_http_url"
    assert all(entry["cwe"] for entry in coverage["mapped_entries"])


def test_taxonomy_coverage_exposes_unmapped_emitted_rules() -> None:
    """Taxonomy coverage should make missing CWE mappings visible."""
    coverage = odoo_deep_scan._taxonomy_coverage(
        [
            {"source": "qweb", "rule_id": "odoo-qweb-t-raw", "title": "QWeb t-raw", "message": "t-raw"},
            {"source": "custom", "rule_id": "odoo-custom-new-shape", "title": "Custom", "message": "custom"},
        ]
    )
    warnings = odoo_deep_scan._taxonomy_warnings(coverage)
    tooling = odoo_deep_scan.generate_tooling_report(
        {
            "surfaces": {},
            "warnings": warnings,
            "scanner_sources": {"entries": []},
            "scanner_registry": {},
            "rule_catalog": {},
            "taxonomy_coverage": coverage,
        }
    )

    assert coverage["total_emitted_rules"] == 2
    assert coverage["mapped_rules"] == 1
    assert coverage["unmapped_rule_ids"] == ["odoo-custom-new-shape"]
    assert coverage["mapped_entries"][0]["rule_id"] == "odoo-qweb-t-raw"
    assert "CWE-79" in coverage["mapped_entries"][0]["cwe"]
    assert warnings == ["Emitted rule IDs without CWE taxonomy mapping: odoo-custom-new-shape."]
    assert "Taxonomy Coverage" in tooling
    assert "Mapped rules: 1" in tooling
    assert "Unmapped emitted rule IDs: odoo-custom-new-shape" in tooling


def test_module_risk_prioritizes_modules_by_findings_and_routes(tmp_path: Path) -> None:
    """Module risk should rank Odoo addons by finding severity and public route exposure."""
    risky = tmp_path / "risky_module"
    quiet = tmp_path / "quiet_module"
    (risky / "controllers").mkdir(parents=True)
    (quiet / "models").mkdir(parents=True)
    (risky / "__manifest__.py").write_text("{'name': 'Risky'}", encoding="utf-8")
    (quiet / "__manifest__.py").write_text("{'name': 'Quiet'}", encoding="utf-8")
    (risky / "controllers" / "main.py").write_text("pass", encoding="utf-8")
    (quiet / "models" / "model.py").write_text("pass", encoding="utf-8")

    routes = [
        {
            "file": "risky_module/controllers/main.py",
            "route": "/public/risky",
            "auth": "public",
            "line": 1,
            "end_line": 1,
            "has_findings": True,
        }
    ]
    findings = [
        {
            "file": str(risky / "controllers" / "main.py"),
            "line": 1,
            "severity": "critical",
            "rule_id": "odoo-critical-route",
        },
        {
            "file": str(quiet / "models" / "model.py"),
            "line": 1,
            "severity": "low",
            "rule_id": "odoo-low-model",
        },
    ]

    risk = odoo_deep_scan._module_risk(tmp_path, [quiet, risky], routes, findings)
    markdown = odoo_deep_scan.generate_module_risk_report(risk)

    assert risk["total_modules"] == 2
    assert risk["modules"][0]["module"] == "risky_module"
    assert risk["modules"][0]["score"] > risk["modules"][1]["score"]
    assert risk["modules"][0]["public_routes"] == 1
    assert risk["modules"][0]["severity_counts"]["critical"] == 1
    assert risk["modules"][0]["top_rules"] == [{"rule_id": "odoo-critical-route", "findings": 1}]
    assert "| risky_module |" in markdown
    assert "odoo-critical-route" in markdown


def test_route_inventory_resolves_constant_backed_route_metadata(tmp_path: Path) -> None:
    """Route inventory should preserve constant-backed route path and auth metadata."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
from odoo import http

PUBLIC_AUTH = 'public'
PUBLIC_ROUTE = '/public/constant'
ROUTES = ['/public/a', '/public/b']

class TestController(http.Controller):
    @http.route(PUBLIC_ROUTE, auth=PUBLIC_AUTH)
    def first(self):
        return {}

    @http.route(routes=ROUTES, auth=PUBLIC_AUTH)
    def second(self):
        return {}
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 9,
            "end_line": 11,
            "function": "first",
            "route": "/public/constant",
            "auth": "public",
            "csrf": "True",
            "type": "http",
            "methods": "",
        },
        {
            "file": "test_module/controllers/main.py",
            "line": 13,
            "end_line": 15,
            "function": "second",
            "route": "/public/a,/public/b",
            "auth": "public",
            "csrf": "True",
            "type": "http",
            "methods": "",
        },
    ]


def test_route_inventory_resolves_class_constant_route_metadata(tmp_path: Path) -> None:
    """Route inventory should preserve class-scoped route path and auth metadata."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
from odoo import http

class TestController(http.Controller):
    AUTH_BASE = 'public'
    PUBLIC_AUTH = AUTH_BASE
    ROUTE_BASE = '/public/class'
    PUBLIC_ROUTE = ROUTE_BASE
    ROUTES = [PUBLIC_ROUTE, '/public/class-b']

    @http.route(PUBLIC_ROUTE, auth=PUBLIC_AUTH)
    def first(self):
        return {}

    @http.route(routes=ROUTES, auth=PUBLIC_AUTH)
    async def second(self):
        return {}
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])
    route_metadata = {(route["route"], route["auth"]) for route in routes}

    assert ("/public/class", "public") in route_metadata
    assert ("/public/class,/public/class-b", "public") in route_metadata


def test_route_inventory_resolves_aliased_route_kwargs_metadata(tmp_path: Path) -> None:
    """Route inventory should preserve aliased Odoo route decorator metadata."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
from odoo import http as odoo_http
from odoo.http import route as odoo_route

PUBLIC_AUTH = 'public'
ROUTE_OPTIONS = {'auth': PUBLIC_AUTH, 'methods': ['GET', 'POST'], 'type': 'json', 'csrf': False}

class TestController(odoo_http.Controller):
    PUBLIC_ROUTE = '/public/alias'

    @odoo_route(PUBLIC_ROUTE, **ROUTE_OPTIONS)
    def alias(self):
        return {}
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 11,
            "end_line": 13,
            "function": "alias",
            "route": "/public/alias",
            "auth": "public",
            "csrf": "False",
            "type": "json",
            "methods": "GET,POST",
        }
    ]


def test_route_inventory_resolves_imported_odoo_module_route_metadata(tmp_path: Path) -> None:
    """Route inventory should preserve odoo.http.route decorator metadata."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
import odoo as od

AUTH = 'public'

class TestController(od.http.Controller):
    @od.http.route('/public/imported-odoo', auth=AUTH, csrf=False)
    def imported(self):
        return {}
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 7,
            "end_line": 9,
            "function": "imported",
            "route": "/public/imported-odoo",
            "auth": "public",
            "csrf": "False",
            "type": "http",
            "methods": "",
        }
    ]


def test_route_inventory_fallback_resolves_imported_odoo_module_route_metadata(tmp_path: Path) -> None:
    """Route inventory should preserve literal route metadata in syntax-error files."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
import odoo as od

class TestController:
    @od.http.route('/public/fallback', auth='public', csrf=False, methods=['GET'])
    async def fallback(self):
        return {}

    =
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 5,
            "end_line": 5,
            "function": "fallback",
            "route": "/public/fallback",
            "auth": "public",
            "csrf": "False",
            "type": "http",
            "methods": "GET",
        }
    ]


def test_route_inventory_fallback_resolves_imported_route_alias_metadata(tmp_path: Path) -> None:
    """Route inventory fallback should preserve imported odoo.http route aliases."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
from odoo.http import route as odoo_route

class TestController:
    @odoo_route('/public/alias-fallback', auth='public', methods=['GET'])
    def fallback(self):
        return {}

    =
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 5,
            "end_line": 5,
            "function": "fallback",
            "route": "/public/alias-fallback",
            "auth": "public",
            "csrf": "True",
            "type": "http",
            "methods": "GET",
        }
    ]


def test_route_inventory_fallback_resolves_multiline_imported_route_alias_metadata(tmp_path: Path) -> None:
    """Route inventory fallback should preserve parenthesized odoo.http route imports."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
from odoo.http import (
    route as odoo_route,
)

class TestController:
    @odoo_route('/public/multiline-alias-fallback', auth='public')
    def fallback(self):
        return {}

    =
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == [
        {
            "file": "test_module/controllers/main.py",
            "line": 7,
            "end_line": 7,
            "function": "fallback",
            "route": "/public/multiline-alias-fallback",
            "auth": "public",
            "csrf": "True",
            "type": "http",
            "methods": "",
        }
    ]


def test_route_inventory_ignores_non_odoo_route_decorators(tmp_path: Path) -> None:
    """Route inventory should not count arbitrary non-Odoo route decorators."""
    controllers = tmp_path / "test_module" / "controllers"
    controllers.mkdir(parents=True)
    controller = controllers / "main.py"
    controller.write_text(
        """
class Bus:
    def route(self, path):
        return lambda func: func

bus = Bus()

class TestController:
    @bus.route('/not/odoo')
    def not_odoo(self):
        return {}
""",
        encoding="utf-8",
    )

    routes = odoo_deep_scan._route_inventory(tmp_path, [controller])

    assert routes == []


def test_deep_scan_writes_findings_report_and_pocs(tmp_path: Path, monkeypatch) -> None:
    """Deep scan should aggregate analyzers and write report/PoC artifacts."""
    repo = tmp_path / "repo"
    module = repo / "test_module"
    controllers = module / "controllers"
    migrations = module / "migrations" / "16.0.1.0"
    models = module / "models"
    views = module / "views"
    security = module / "security"
    data = module / "data"
    i18n = module / "i18n"
    static_js = module / "static" / "src" / "js"
    wizards = module / "wizards"
    server_actions = repo / "docs" / "server_actions"
    for directory in (controllers, migrations, models, views, security, data, i18n, static_js, wizards):
        directory.mkdir(parents=True)
    server_actions.mkdir(parents=True)

    (repo / "odoo.conf").write_text(
        """
[options]
list_db = True
log_level = debug
""",
        encoding="utf-8",
    )
    (module / "__manifest__.py").write_text(
        "{'name': 'Test Module', 'data': ['demo/users.xml']}",
        encoding="utf-8",
    )
    (controllers / "main.py").write_text(
        """
from odoo import api, http, models, service, SUPERUSER_ID
from odoo.http import content_disposition, request
import base64
import os
import pickle
import jwt
import tempfile
import zipfile
from werkzeug.utils import secure_filename
from lxml import etree
import requests
import subprocess

API_KEY = 'sk_live_1234567890abcdef'

class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_public(cls):
        request.uid = SUPERUSER_ID
        return True

class TestController(http.Controller):
    @http.route('/public/orders', auth='public', csrf=False)
    def orders(self, **kwargs):
        requests.get(kwargs.get('callback_url'), verify=False)
        return request.env['sale.order'].sudo().search([]).write(kwargs)

    @http.route('/health/update', auth='none')
    def health_update(self):
        return 'ok'

    @http.route('/db/drop', auth='none', csrf=False)
    def drop_db(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))

    @http.route('/db/drop/<string:database_name>', auth='none', csrf=False)
    def drop_named_db(self, database_name):
        request.session.db = database_name
        return service.db.exp_drop('master-password', database_name)

    @http.route('/public/profile', auth='public', cors='*')
    def public_profile(self):
        return '{}'

    @http.route('/api/token-sync', auth='bearer', methods=['POST'], save_session=True)
    def bearer_sync(self):
        return '{}'

    @http.route(auth='public', csrf=False, cors='*')
    def inherited_login(self, **kwargs):
        return super().web_login(**kwargs)

    @http.route('/public/form-submit', auth='public', methods=['POST'], csrf=False)
    def form_submit(self, **kwargs):
        return 'ok'

    @http.route('/shop/order/confirm', auth='public', methods=['GET'])
    def confirm_order(self):
        return 'ok'

    @http.route('/my/private-offer', auth='public', website=True)
    def private_offer(self):
        return 'ok'

    @http.route(route='/payment/test/webhook', auth='public', csrf=False)
    def payment_webhook(self, **post):
        provider_signature = post.get('signature')
        if provider_signature:
            request.env['ir.logging'].sudo().create({'name': provider_signature})
        return 'ok'

    @http.route('/payment/test/return', auth='public', csrf=False)
    def payment_return(self, **post):
        tx = request.env['payment.transaction'].sudo().search([('reference', '=', post.get('reference'))])
        tx.write({'state': post.get('state')})
        return 'ok'

    @http.route('/public/upload', auth='public', csrf=False)
    def upload(self, **kwargs):
        payload = base64.b64decode(kwargs.get('payload'))
        upload_name = secure_filename(kwargs.get('filename'))
        with open('/srv/odoo/uploads/' + upload_name, 'wb') as handle:
            handle.write(payload)
        zipfile.ZipFile(kwargs.get('archive')).extractall('/srv/odoo/imports')
        tempfile.mktemp(prefix=kwargs.get('filename'))
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('filename'),
            'datas': payload,
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('res_id'),
            'public': True,
        })

    @http.route('/public/upload/path/<path:destination>', auth='public', csrf=False)
    def upload_path(self, destination):
        with open(destination, 'wb') as handle:
            handle.write(b'data')
        return 'ok'

    @http.route('/public/orders/<int:order_id>/attach', auth='public', csrf=False)
    def attach_order(self, order_id):
        return request.env['ir.attachment'].sudo().create({
            'name': 'order.pdf',
            'datas': request.params.get('payload'),
            'res_model': 'sale.order',
            'res_id': order_id,
        })

    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = base64.b64decode(attachment.datas)
        with open(kwargs.get('path'), 'rb') as handle:
            payload += handle.read()
        raw_payload = attachment.raw
        request.make_response(raw_payload)
        attachment.write({
            'public': True,
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('res_id'),
            'access_token': kwargs.get('token'),
        })
        return request.make_response(payload, headers=[('Content-Disposition', content_disposition(kwargs.get('filename')))])

    @http.route('/public/orders/<int:order_id>/attach/<int:attachment_id>', auth='public', csrf=False)
    def update_order_attachment(self, order_id, attachment_id):
        attachment = request.env['ir.attachment'].sudo().browse(attachment_id)
        return attachment.write({
            'res_model': 'sale.order',
            'res_id': order_id,
        })

    @http.route('/public/document/<int:document_id>/binary', auth='public')
    def document_binary(self, document_id):
        return request.env['ir.http'].sudo().binary_content(
            model='ir.attachment',
            id=document_id,
            field='datas',
        )

    @http.route('/public/order/<int:order_id>/content', auth='public')
    def order_content(self, order_id):
        return request.redirect('/web/content/%s?download=1' % order_id)

    @http.route('/public/file/<int:document_id>', auth='public')
    def public_file(self, document_id):
        with open(f'/srv/odoo/private/{document_id}.pdf', 'rb') as handle:
            return request.make_response(handle.read())

    @http.route('/public/token', auth='public')
    def public_token(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        response.headers['Cache-Control'] = 'public, max-age=3600'
        response.headers.update({'X-Trace': kwargs.get('trace')})
        response.headers['Access-Control-Allow-Origin'] = request.httprequest.headers.get('Origin')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline'"
        response.headers['X-Frame-Options'] = 'ALLOW-FROM https://partner.example'
        response.headers['Referrer-Policy'] = 'unsafe-url'
        response.headers['Strict-Transport-Security'] = 'max-age=0'
        response.headers['Cross-Origin-Opener-Policy'] = 'unsafe-none'
        response.headers['Permissions-Policy'] = 'geolocation=*'
        response.headers['X-Accel-Redirect'] = kwargs.get('path')
        response.set_cookie('session_token', kwargs.get('token'))
        return response

    @http.route('/public/jsonp', auth='public')
    def public_jsonp(self, **kwargs):
        callback = kwargs.get('callback')
        return request.make_response(f"{callback}({{'ok': true}})", headers={'Content-Type': 'application/javascript'})

    @http.route('/web/reset_password/<string:reset_code>', auth='public')
    def reset_password_path_code(self, reset_code):
        return request.make_response({'value': reset_code})

    @http.route('/public/export/<string:download_name>', auth='public')
    def public_export_download_name(self, download_name):
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = download_name
        return response

    @http.route('/public/offload/<int:attachment_id>', auth='public')
    def public_offload(self, attachment_id):
        response = request.make_response('')
        response.headers['X-Accel-Redirect'] = f'/internal/attachments/{attachment_id}'
        return response

    @http.route('/public/json-token', auth='public', type='json')
    def public_json_token(self, **kwargs):
        return request.make_json_response({'access_token': kwargs.get('token')})

    @http.route('/public/realtime', auth='public')
    def realtime(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
        return 'ok'

    @http.route('/public/orders/<int:order_id>/partner/<int:partner_id>/bus', auth='public')
    def realtime_order(self, order_id, partner_id):
        request.env['bus.bus']._sendone(
            ('sale.order', order_id),
            'notification',
            {'order_id': order_id, 'partner_id': partner_id},
        )
        return 'ok'

    @http.route('/public/render', auth='public', csrf=False)
    def render_pdf(self, **kwargs):
        subprocess.run(['wkhtmltopdf', kwargs.get('url'), '/tmp/out.pdf'])
        return os.system(kwargs.get('cmd'))

    @http.route('/public/report', auth='public')
    def public_report(self, **kwargs):
        report = request.env.ref('sale.action_report_saleorder').sudo()
        return report._render_qweb_pdf([int(kwargs.get('order_id'))])

    @http.route('/public/dynamic-report', auth='public')
    def public_dynamic_report(self, **kwargs):
        report = request.env.ref(kwargs.get('report_xmlid'))
        return report._render_qweb_pdf([42])

    @http.route('/public/order-report/<int:order_id>', auth='public')
    def public_order_report(self, order_id):
        order = request.env['sale.order'].browse(order_id)
        return request.env.ref('sale.action_report_saleorder').report_action(order)

    @http.route('/public/orders/<int:order_id>/publish/<int:is_published>', auth='public', csrf=False)
    def public_publish_order(self, order_id, is_published):
        return request.env['sale.order'].sudo().browse(order_id).write({
            'website_published': is_published,
        })

    @http.route('/public/config', auth='public', csrf=False)
    def public_config(self, **kwargs):
        secret = request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
        signing_key = request.env['ir.config_parameter'].sudo().get_param('jwt.signing_key', 'dev-secret-token')
        request.env['ir.config_parameter'].sudo().set_param(kwargs.get('key'), kwargs.get('value'))
        request.env['ir.config_parameter'].sudo().set_param('payment.provider.api_key', 'sk_live_hardcoded_123456')
        request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
        return secret + signing_key

    @http.route('/public/config/<string:config_key>/<string:config_value>', auth='public', csrf=False)
    def public_config_path(self, config_key, config_value):
        return request.env['ir.config_parameter'].sudo().set_param(config_key, config_value)

    @http.route('/public/defaults/groups/<int:group_id>', auth='public', csrf=False)
    def public_default_group_path(self, group_id):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', group_id)

    @http.route('/public/properties/account/<int:account_id>', auth='public', csrf=False)
    def public_property_account_path(self, account_id):
        return request.env['ir.property'].sudo().create({
            'fields_id': 'account.field_res_partner__property_account_receivable_id',
            'value_reference': f'account.account,{account_id}',
        })

    @http.route('/public/promote', auth='public', csrf=False)
    def public_promote(self, **kwargs):
        user = request.env['res.users'].sudo().browse(int(kwargs.get('user_id')))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})

    @http.route('/public/users/<int:user_id>/company/<int:company_id>', auth='public', csrf=False)
    def public_assign_company(self, user_id, company_id):
        user = request.env['res.users'].sudo().browse(user_id)
        return user.write({'company_ids': [(4, company_id)]})

    @http.route('/public/invite-code', auth='public')
    def public_invite_code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')

    @http.route('/public/sequence/<string:sequence_code>/next', auth='public')
    def public_sequence_code_path(self, sequence_code):
        return request.env['ir.sequence'].next_by_code(sequence_code)

    @http.route('/public/json/order', auth='public', type='json', csrf=False)
    def public_json_order(self):
        payload = request.get_json_data()
        return request.env['sale.order'].sudo().create(payload)

    @http.route('/public/json/order/<int:order_id>/lines/<int:product_id>', auth='public', type='json')
    def public_json_order_line(self, order_id, product_id):
        request.env['sale.order.line'].sudo().search_read([('order_id', '=', order_id)])
        return request.env['sale.order.line'].sudo().create({
            'order_id': order_id,
            'product_id': product_id,
        })

    @http.route('/public/jsonrpc/order', auth='public', type='jsonrpc', csrf=False)
    def public_jsonrpc_order(self):
        payload = request.get_json_data()
        return request.env['sale.order'].sudo().create(payload)

    @http.route('/public/sql/partner/<int:partner_id>', auth='public')
    def public_sql_partner(self, partner_id):
        request.env.cr.execute("SELECT * FROM res_partner WHERE id = %s", (partner_id,))
        return 'ok'

    @http.route('/public/export/<string:field_names>', auth='public')
    def public_export_fields(self, field_names):
        return request.env['res.users'].sudo().search_read([], fields=field_names.split(','))

    @http.route('/public/import', auth='public', csrf=False)
    def import_payload(self, **kwargs):
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
        etree.fromstring(kwargs.get('xml'), parser=parser)
        return pickle.loads(kwargs.get('payload'))

    @http.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_path_payload(self, serialized_blob):
        return pickle.loads(serialized_blob)

    @http.route('/public/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))

    @http.route('/public/go-action', auth='public')
    def go_action(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}

    @http.route('/public/content-action/<int:attachment_id>', auth='public')
    def content_action(self, attachment_id):
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment_id}?download=1',
            'target': 'self',
        }

    @http.route('/public/window-action', auth='public')
    def window_action(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': kwargs.get('model'),
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }

    @http.route('/public/users-window', auth='public')
    def users_window(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.users',
            'domain': [],
        }

    @http.route('/public/domain-search', auth='public')
    def domain_search(self, **kwargs):
        domain = safe_eval(request.params.get('domain'))
        return request.env['res.partner'].sudo().search(domain)

    @http.route('/public/company-switch', auth='public')
    def company_switch(self, **kwargs):
        request.env['sale.order'].with_company(kwargs.get('company_id')).search([])
        request.update_context(
            active_test=False,
            tracking_disable=True,
            default_groups_id=[(4, request.env.ref('base.group_system').id)],
            module_uninstall=True,
        )
        return request.env['sale.order'].with_context({
            'allowed_company_ids': kwargs.get('company_ids'),
            'force_company': kwargs.get('company_id'),
        }).search([])

    @http.route('/public/login', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))

    @http.route('/public/impersonate', auth='public', csrf=False)
    def impersonate(self, **kwargs):
        request.uid = SUPERUSER_ID
        request.update_env(user=kwargs.get('uid'))
        request.update_env(user=SUPERUSER_ID)
        return api.Environment(request.cr, kwargs.get('uid'), {})['res.users'].browse(kwargs.get('uid'))

    @http.route('/public/impersonate/<int:target_uid>', auth='public', csrf=False)
    def impersonate_path(self, target_uid):
        request.session.uid = target_uid
        request.update_env(user=target_uid)
        return api.Environment(request.cr, target_uid, {})['res.users'].browse(target_uid)

    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def oauth_callback(self, **kwargs):
        jwt.decode(kwargs.get('id_token'), options={'verify_signature': False})
        requests.get(kwargs.get('userinfo_url'), verify=False)
        request.env['res.users'].sudo().write({'oauth_uid': kwargs.get('sub')})
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))

    @http.route('/auth/oauth/callback/<path:userinfo_endpoint>', auth='public', csrf=False)
    def oauth_path_callback(self, userinfo_endpoint):
        return requests.get(userinfo_endpoint, timeout=10)

    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        request.env['res.users'].sudo().write({
            'signup_token': kwargs.get('token'),
            'password': kwargs.get('password'),
        })
        partner.signup_token = kwargs.get('token')
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})

    @http.route('/public/users/<int:user_id>/reset', auth='public', csrf=False)
    def reset_user_path(self, user_id):
        user = request.env['res.users'].sudo().browse(user_id)
        user.password = user_id
        return 'ok'

    @http.route('/public/api-key', auth='public', csrf=False)
    def public_api_key(self, **kwargs):
        api_key = request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
        return {'api_key': api_key}

    @http.route('/public/users/<int:user_id>/api-key', auth='public', csrf=False)
    def public_api_key_for_user(self, user_id):
        return request.env['res.users.apikeys'].sudo().create({
            'name': 'path-selected',
            'user_id': user_id,
        })

    @http.route('/public/install-module', auth='public', csrf=False)
    def public_install_module(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()

    @http.route('/public/mail', auth='public')
    def public_mail(self, **kwargs):
        order = request.env['sale.order'].sudo().browse(kwargs.get('id'))
        order.sudo().message_post(
            body=f"Token {order.access_token}: {kwargs.get('body')}",
            partner_ids=kwargs.get('partner_ids'),
        )
        order.message_subscribe(
            partner_ids=kwargs.get('partner_ids'),
            subtype_ids=kwargs.get('subtype_ids'),
        )
        request.env['mail.followers'].sudo().create({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'partner_id': kwargs.get('partner_id'),
        })
        request.env.ref('sale.email_template_edi_sale').sudo().send_mail(
            int(kwargs.get('id')),
            email_values={
                'email_to': kwargs.get('email_to'),
                'body_html': kwargs.get('body'),
            },
        )
        return request.env['mail.mail'].create({
            'email_to': kwargs.get('email_to'),
            'subject': kwargs.get('subject'),
            'body_html': kwargs.get('body'),
        })

    @http.route('/public/orders/<int:order_id>/followers/<int:partner_id>', auth='public', csrf=False)
    def public_order_follower(self, order_id, partner_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        order.message_subscribe(partner_ids=[partner_id])
        return request.env['mail.followers'].sudo().create({
            'res_model': 'sale.order',
            'res_id': order_id,
            'partner_id': partner_id,
        })

    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id, access_token=None):
        order = request.env['sale.order'].sudo().browse(order_id)
        if access_token != order.access_token:
            return request.not_found()
        return request.render('sale.portal_order_page', {'order': order, 'access_token': order.access_token})
""",
        encoding="utf-8",
    )
    (migrations / "post-migrate.py").write_text(
        """
def migrate(cr, version):
    cr.execute("DROP TABLE legacy_table")
""",
        encoding="utf-8",
    )
    (models / "test_model.py").write_text(
        """
from odoo import api, fields, models
from odoo.addons.queue_job.job import job
import requests
from urllib.request import urlopen

class TestModel(models.Model):
    _name = 'test.model'
    _rec_name = 'access_token'
    company_id = fields.Many2one('res.company')
    body = fields.Html(sanitize=False)
    access_token = fields.Char(index=True)
    public_secret = fields.Char(groups='base.group_portal')
    secret_count = fields.Integer(compute='_compute_secret_count', compute_sudo=True)
    partner_token = fields.Char(related='partner_id.signup_token')
    payload = fields.Binary(attachment=False)
    property_account_income_id = fields.Many2one('account.account', company_dependent=True, default=lambda self: self.env.company.id)
    code = fields.Char(required=True)

    @job
    def sync_queue(self, record):
        record.sudo().write({'state': 'done'})
        requests.post(record.callback_url)
        urlopen(record.status_url)

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].sudo().write({'note': 'changed'})

    def action_approve(self):
        Orders, label = self.env['sale.order'].sudo(), self.name
        Orders.write({'state': 'done'})
        self.env['sale.order'].sudo().with_context(active_test=False).search([])
        self.env['sale.order'].search_read(self.env.context.get('active_domain'))
        self.with_context(tracking_disable=True).write({'state': 'approved'})
        self.env['res.users'].with_context(default_groups_id=[(4, self.env.ref('base.group_system').id)]).create({'name': 'Admin'})
        self.with_context(module_uninstall=True).unlink()
        self.env.cr.execute("DELETE FROM sale_order")
        self.env.cr.execute("UPDATE sale_order SET state = 'done' WHERE state = 'sale'")
        self.env.cr.commit()
        self.env.ref('sale.email_template_edi_sale').sudo().send_mail(self.id, force_send=True)

    def fetch_sale_callbacks(self):
        orders = self.env['sale.order'].sudo().search([])
        requests.get(self.callback_url, verify=False)
        urlopen(self.status_url)
        orders.sudo().write({'state': 'done'})
        self.env.cr.commit()

    def check_access_rights(self, operation, raise_exception=True):
        return True

    def _filter_access_rules(self, operation):
        return self

    def name_search(self, name='', args=None, operator='ilike', limit=100):
        Orders, label = self.env['sale.order'].sudo(), name
        return Orders.search([]).name_get()

    @api.constrains('partner_id.email')
    def _check_partner_email(self):
        return False

    @api.constrains('code')
    def _check_code_unique(self):
        Models, label = self.env['test.model'].sudo(), self.code
        return Models.search([('code', '=', self.code)])

class PartnerWrapper(models.Model):
    _name = 'test.partner.wrapper'
    _inherits = {'res.partner': 'partner_id'}

    partner_id = fields.Many2one('res.partner', ondelete='set null')

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        self._set_done()

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret = fields.Char(config_parameter='payment.provider.api_secret')
    callback_url = fields.Char(config_parameter='integration.callback_url', groups='base.group_portal')
    allow_uninvited_signup = fields.Boolean(config_parameter='auth.signup.allow_uninvited')
    allow_admin = fields.Boolean(implied_group='base.group_system')
    module_sensitive_connector = fields.Boolean()

    def set_values(self):
        self.env['ir.config_parameter'].sudo().set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )
    (wizards / "export.py").write_text(
        """
import base64
from odoo import fields, models

class BulkWizard(models.TransientModel):
    _name = 'bulk.wizard'
    upload = fields.Binary()

    def action_apply(self):
        base64.b64decode(self.upload)
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        elevated, note = records.sudo(), self.upload
        elevated.write({'state': 'done'})

def export(writer, records):
    for record in records:
        writer.writerow([record.name, record.email])
        writer.write_row(0, 0, [record.name, record.email])
    rows = [{'name': record.name, 'email': record.email} for record in records]
    frame = pandas.DataFrame(rows)
    frame.to_csv(writer)
""",
        encoding="utf-8",
    )
    (views / "templates.xml").write_text(
        """<odoo>
  <template id="x">
    <span t-raw="record.body"/>
    <span t-field="record.access_token"/>
    <a t-att="{'href': record.callback_url}">Callback</a>
    <form t-attf-action="/website/form/crm.lead" method="post" enctype="multipart/form-data" data-success-page="https://evil.example/thanks">
      <input name="partner_id"/>
      <input type="file" name="attachment"/>
    </form>
    <form t-attf-data-model_name="res.users" method="post">
      <input name="groups_id"/>
    </form>
  </template>
  <record id="view_test_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="partner_id" context="{'active_test': False, 'allowed_company_ids': active_ids}"/>
        <button name="action_approve" type="object"/>
        <button name="%(action_sensitive_users)d" type="action"/>
      </form>
    </field>
  </record>
  <record id="action_sensitive_users" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">res.users</field>
  </record>
  <record id="view_test_form_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//button[@type='object']" position="replace">
        <button name="action_reapprove" type="object"/>
      </xpath>
      <xpath expr="//button[@name='action_confirm']" position="attributes">
        <attribute name="groups"/>
      </xpath>
      <xpath expr="//field[@name='access_token']" position="attributes">
        <attribute name="invisible">0</attribute>
      </xpath>
    </field>
  </record>
  <record id="filter_all_partners" model="ir.filters">
    <field name="name">All partners</field>
    <field name="model_id">res.partner</field>
    <field name="domain">[]</field>
    <field name="context">{'active_test': False}</field>
    <field name="is_default">True</field>
  </record>
  <record id="filter_posted_invoices" model="ir.filters">
    <field name="name">Posted invoices</field>
    <field name="model_id">account.move</field>
    <field name="domain">[('state', '!=', 'cancel')]</field>
    <field name="is_default">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="sale_order_all" model="ir.rule">
    <field name="name">Sale state broad rule</field>
    <field name="model_id" ref="model_sale_order"/>
    <field name="domain_force">[('state', '=', 'sale')]</field>
  </record>
  <record id="portal_invoice_write" model="ir.rule">
    <field name="name">Portal invoice write</field>
    <field name="model_id" ref="account.model_account_move"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
    <field name="perm_write" eval="True"/>
  </record>
  <record id="global_invoice_write" model="ir.rule">
    <field name="name">Global invoice write</field>
    <field name="model_id" ref="account.model_account_move"/>
    <field name="domain_force">[('company_id', 'in', user.company_ids.ids)]</field>
    <field name="perm_write" eval="True"/>
  </record>
  <record id="stock_hierarchy" model="ir.rule">
    <field name="name">Stock hierarchy rule</field>
    <field name="model_id" ref="stock.model_stock_picking"/>
    <field name="domain_force">['|', ('company_id', 'child_of', user.company_ids.ids), ('id', '=', user.has_group('base.group_system'))]</field>
  </record>
  <record id="disabled_sale_rule" model="ir.rule">
    <field name="name">Disabled sale rule</field>
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
    <field name="perm_read" eval="False"/>
    <field name="perm_write" eval="False"/>
    <field name="perm_create" eval="False"/>
    <field name="perm_unlink" eval="False"/>
  </record>
  <record id="action_eval" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">
safe_eval(record.expression)
record.sudo().write({'state': 'done'})
requests.post(record.callback_url)
    </field>
  </record>
  <record id="group_adminish" model="res.groups">
    <field name="implied_ids" eval="[(4, ref('base.group_system'))]"/>
  </record>
  <record id="field_user_api_key" model="ir.model.fields">
    <field name="model_id" ref="base.model_res_users"/>
    <field name="name">api_key</field>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="readonly">0</field>
    <field name="compute">safe_eval(record.expression)</field>
  </record>
  <record id="seeded_api_key" model="res.users.apikeys">
    <field name="name">integration</field>
    <field name="user_id" ref="base.user_admin"/>
  </record>
  <record id="action_sale_report" model="ir.actions.report">
    <field name="model">sale.order</field>
    <field name="report_sudo">True</field>
    <field name="print_report_name">'SO-%s' % (object.access_token)</field>
  </record>
  <record id="template_sale_token" model="mail.template">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="email_to">${object.partner_id.email}</field>
    <field name="email_from">${object.user_id.email}</field>
    <field name="body_html">Open ${object.access_url}?token=${object.access_token} or https://evil.example.com/${object.id}</field>
  </record>
  <record id="alias_sale_public" model="mail.alias">
    <field name="alias_name">orders</field>
    <field name="alias_model_id" ref="sale.model_sale_order"/>
    <field name="alias_contact">everyone</field>
  </record>
  <record id="public_invoice_attachment" model="ir.attachment">
    <field name="name">invoice.pdf</field>
    <field name="public">True</field>
  </record>
  <record id="auto_sale_write" model="base.automation">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="trigger">on_create_or_write</field>
    <field name="code">record.sudo().write({'state': 'done'})</field>
  </record>
  <record id="cron_sale_sync" model="ir.cron">
    <field name="name">Fetch sale callbacks</field>
    <field name="user_id" ref="base.user_admin"/>
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="function">fetch_sale_callbacks</field>
    <field name="interval_number">1</field>
    <field name="interval_type">minutes</field>
    <field name="doall">True</field>
  </record>
  <record id="demo_promoted_user" model="res.users">
    <field name="login">demo-admin</field>
    <field name="groups_id" eval="[(4, ref('base.group_system'))]"/>
  </record>
  <data noupdate="1">
    <record id="base.group_system" model="res.groups">
      <field name="name">System Override</field>
    </record>
  </data>
</odoo>""",
        encoding="utf-8",
    )
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_public_partner,public partner,base.model_res_partner,base.group_public,1,0,0,0\n"
        "access_global_invoice,global invoice,account.model_account_move,,1,0,0,0\n"
        "access_user_invoice,user invoice,account.model_account_move,base.group_user,1,1,1,0\n"
        "access_portal_sale,portal sale,sale.model_sale_order,base.group_portal,1,0,0,1\n"
        "access_rules_user,rules,base.model_ir_rule,base.group_user,1,1,0,0\n",
        encoding="utf-8",
    )
    (server_actions / "cleanup.py").write_text(
        """
query = "DELETE FROM %s" % model_name
env.cr.execute(query)
requests.post(record.callback_url)
""",
        encoding="utf-8",
    )
    (data / "oauth.xml").write_text(
        """<odoo>
  <record id="oauth_partner" model="auth.oauth.provider">
    <field name="name">Partner OAuth</field>
    <field name="enabled">True</field>
    <field name="auth_endpoint">http://idp.example.com/auth</field>
    <field name="client_secret">prod-secret-1234567890</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (data / "properties.xml").write_text(
        """<odoo>
  <record id="property_receivable_global" model="ir.property">
    <field name="fields_id" ref="account.field_res_partner__property_account_receivable_id"/>
    <field name="value_reference">account.account,1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (data / "sequences.xml").write_text(
        """<odoo>
  <record id="seq_invite_token" model="ir.sequence">
    <field name="name">Invite Token</field>
    <field name="code">access.token.sequence</field>
    <field name="prefix">TOKEN-%(year)s-</field>
  </record>
  <record id="seq_sale_order" model="ir.sequence">
    <field name="name">Sale Order</field>
    <field name="code">sale.order</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (data / "url_actions.xml").write_text(
        """<odoo>
  <record id="action_external_docs" model="ir.actions.act_url">
    <field name="name">External Docs</field>
    <field name="url">https://evil.example.com/path?access_token=abc</field>
    <field name="target">new</field>
  </record>
  <record id="action_javascript" model="ir.actions.act_url">
    <field name="name">Run Script</field>
    <field name="url">javascript:alert(document.domain)</field>
    <field name="target">self</field>
  </record>
  <record id="action_scheme_relative" model="ir.actions.act_url">
    <field name="name">External CDN</field>
    <field name="url">//evil.example.com/path</field>
    <field name="target">new</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (data / "window_actions.xml").write_text(
        """<odoo>
  <record id="action_create_admin" model="ir.actions.act_window">
    <field name="res_model">res.users</field>
    <field name="domain">[]</field>
    <field name="context">{'default_groups_id': [(4, ref('base.group_system'))], 'active_test': False}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (i18n / "fr.po").write_text(
        """
msgid "Open order %(name)s"
msgstr "<a href=\\"javascript:alert(1)\\">Ouvrir %(name)s</a>"
""",
        encoding="utf-8",
    )
    (static_js / "widget.js").write_text(
        "this.el.innerHTML = payload;\njsonrpc('/my/action', {id: recordId});\n",
        encoding="utf-8",
    )

    out = tmp_path / "audit"
    monkeypatch.setattr(sys, "argv", ["odoo-deep-scan", str(repo), "--out", str(out), "--pocs"])

    assert odoo_deep_scan.main() == 0

    findings_path = out / "deep-scan-findings.json"
    validation_path = out / "deep-scan-validation.json"
    review_gate_path = out / "review-gate.json"
    taxonomy_gate_path = out / "taxonomy-gate.json"
    governance_gate_path = out / "governance-gate.json"
    coverage_path = out / "inventory" / "coverage" / "matcher-coverage.json"
    poc_coverage_path = out / "inventory" / "coverage" / "poc-coverage.json"
    module_risk_path = out / "inventory" / "module-risk.json"
    accepted_risks_path = out / "inventory" / "accepted-risks.json"
    fix_list_path = out / "inventory" / "fix-list.json"
    rule_catalog_path = out / "inventory" / "coverage" / "rule-catalog.json"
    taxonomy_coverage_path = out / "inventory" / "coverage" / "taxonomy-coverage.json"
    manifest_path = out / "inventory" / "coverage" / "scanner-manifest.json"
    artifact_manifest_path = out / "inventory" / "artifacts.json"
    accepted_risks_markdown_path = out / "00-accepted-risks.md"
    fix_list_markdown_path = out / "00-fix-list.md"
    module_risk_markdown_path = out / "module-risk.md"
    report_path = out / "deep-scan-report.md"
    html_report_path = out / "findings.html"
    sarif_path = out / "deep-scan.sarif"
    tooling_path = out / "tooling.md"
    pocs_dir = out / "pocs"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    review_gate = json.loads(review_gate_path.read_text(encoding="utf-8"))
    taxonomy_gate = json.loads(taxonomy_gate_path.read_text(encoding="utf-8"))
    governance_gate = json.loads(governance_gate_path.read_text(encoding="utf-8"))
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    poc_coverage = json.loads(poc_coverage_path.read_text(encoding="utf-8"))
    module_risk = json.loads(module_risk_path.read_text(encoding="utf-8"))
    accepted_risks = json.loads(accepted_risks_path.read_text(encoding="utf-8"))
    fix_list = json.loads(fix_list_path.read_text(encoding="utf-8"))
    rule_catalog = json.loads(rule_catalog_path.read_text(encoding="utf-8"))
    taxonomy_coverage = json.loads(taxonomy_coverage_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_manifest = json.loads(artifact_manifest_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    rule_ids = {finding["rule_id"] for finding in findings}

    assert findings_path.exists()
    assert validation_path.exists()
    assert review_gate_path.exists()
    assert taxonomy_gate_path.exists()
    assert governance_gate_path.exists()
    assert coverage_path.exists()
    assert poc_coverage_path.exists()
    assert module_risk_path.exists()
    assert accepted_risks_path.exists()
    assert fix_list_path.exists()
    assert rule_catalog_path.exists()
    assert taxonomy_coverage_path.exists()
    assert manifest_path.exists()
    assert artifact_manifest_path.exists()
    assert accepted_risks_markdown_path.exists()
    assert fix_list_markdown_path.exists()
    assert module_risk_markdown_path.exists()
    assert report_path.exists()
    assert html_report_path.exists()
    assert sarif_path.exists()
    assert tooling_path.exists()
    assert pocs_dir.exists()
    assert validation["valid"] is True
    assert validation["finding_count"] == len(findings)
    assert review_gate["passed"] is True
    assert review_gate["fail_on"] == "none"
    assert review_gate["total_findings"] == len(findings)
    assert review_gate["blocking_findings"] == 0
    assert coverage["review_gate"] == review_gate
    assert taxonomy_gate["passed"] is True
    assert taxonomy_gate["fail_on_unmapped_taxonomy"] is False
    assert taxonomy_gate["total_emitted_rules"] == coverage["taxonomy_coverage"]["total_emitted_rules"]
    assert taxonomy_gate["blocking_rules"] == 0
    assert coverage["taxonomy_gate"] == taxonomy_gate
    assert governance_gate["passed"] is True
    assert governance_gate["blocking_conditions"] == 0
    assert coverage["governance_gate"] == governance_gate
    assert poc_coverage["total_findings"] == len(findings)
    assert poc_coverage["generated_pocs"] == len(poc_coverage["generated_files"])
    assert poc_coverage["generated_pocs"] == len(list(pocs_dir.iterdir()))
    assert 0 < poc_coverage["coverage_ratio"] < 1
    assert poc_coverage["unsupported_findings"]
    assert all(path.startswith("pocs/poc-") for path in poc_coverage["generated_files"])
    assert coverage["poc_coverage"] == poc_coverage
    assert accepted_risks["summary"]["suppressed_findings"] == 0
    assert accepted_risks["summary"]["output_findings"] == len(findings)
    assert coverage["accepted_risks"] == accepted_risks["summary"]
    assert fix_list["summary"]["tracked_findings"] == 0
    assert fix_list["summary"]["regressions"] == 0
    assert coverage["fix_list"] == fix_list["summary"]
    assert coverage["surfaces"]["python_files"]["total"] >= 4
    assert coverage["surfaces"]["xml_files"]["total"] >= 7
    assert coverage["surfaces"]["modules"]["total"] == 1
    assert coverage["finding_summary"]["total_findings"] == len(findings)
    assert sum(coverage["finding_summary"]["severity_counts"].values()) == len(findings)
    assert coverage["finding_summary"]["severity_counts"]["critical"] > 0
    assert coverage["finding_summary"]["sources"][0]["max_severity"] == "critical"
    assert coverage["finding_summary"]["top_rules"]
    assert coverage["finding_summary"]["top_rules"][0]["max_severity"] == "critical"
    assert coverage["taxonomy_coverage"]["total_emitted_rules"] == coverage["rule_catalog"]["emitted_rules"]
    assert taxonomy_coverage == coverage["taxonomy_coverage"]
    assert coverage["taxonomy_coverage"]["mapped_rules"] > 0
    assert "odoo-qweb-t-raw" not in coverage["taxonomy_coverage"]["unmapped_rule_ids"]
    assert any(entry["rule_id"] == "odoo-qweb-t-raw" for entry in coverage["taxonomy_coverage"]["mapped_entries"])
    assert coverage["module_risk"] == module_risk
    assert module_risk["total_modules"] == 1
    assert module_risk["modules"][0]["module"] == "test_module"
    assert module_risk["modules"][0]["score"] > 0
    assert module_risk["modules"][0]["band"] in {"critical", "high", "medium", "low"}
    assert module_risk["modules"][0]["severity_counts"]["critical"] > 0
    assert module_risk["modules"][0]["public_routes"] >= 40
    assert module_risk["modules"][0]["top_rules"]
    assert coverage["routes"]["public_or_none"] >= 40
    assert coverage["routes"]["public_or_none_with_findings"] == coverage["surfaces"]["public_routes"]["with_findings"]
    assert coverage["routes"]["entries"]
    assert all("has_findings" in route for route in coverage["routes"]["entries"])
    assert all("end_line" in route for route in coverage["routes"]["entries"])
    assert any(route["route"] == "/public/orders" and route["has_findings"] for route in coverage["routes"]["entries"])
    source_entries = {entry["source"]: entry for entry in coverage["scanner_sources"]["entries"]}
    finding_sources = {finding["source"] for finding in findings}
    assert coverage["scanner_sources"]["total_sources"] >= 55
    assert coverage["scanner_sources"]["sources_with_findings"] >= 45
    assert finding_sources <= set(source_entries)
    assert source_entries["deep-pattern"]["findings"] > 0
    assert source_entries["route-security"]["findings"] > 0
    assert coverage["scanner_sources"]["unexpected_sources"] == []
    assert coverage["scanner_sources"]["duplicate_expected_sources"] == []
    assert coverage["scanner_registry"]["total_exported"] >= 55
    assert coverage["scanner_registry"]["wired_exported"] == coverage["scanner_registry"]["total_exported"]
    assert coverage["scanner_registry"]["source_labels"] == coverage["scanner_registry"]["wired_exported"]
    assert coverage["scanner_registry"]["source_labels_match_wired"] is True
    assert len(coverage["scanner_registry"]["manifest_entries"]) == coverage["scanner_registry"]["wired_exported"]
    assert coverage["scanner_registry"]["missing_from_deep_scan"] == []
    assert coverage["scanner_registry"]["callables_without_source"] == []
    assert coverage["scanner_registry"]["sources_without_callable"] == []
    assert manifest["total_entries"] == coverage["scanner_registry"]["wired_exported"]
    assert manifest["entries"] == coverage["scanner_registry"]["manifest_entries"]
    assert manifest["callables_without_source"] == []
    assert manifest["sources_without_callable"] == []
    artifact_entries = {entry["path"]: entry for entry in artifact_manifest["entries"]}
    assert artifact_manifest["total_artifacts"] == len(artifact_entries)
    assert artifact_manifest["missing_required"] == []
    assert artifact_entries["deep-scan-findings.json"]["exists"] is True
    assert artifact_entries["deep-scan-findings.json"]["count"] == len(findings)
    assert artifact_entries["deep-scan-validation.json"]["count"] == validation["issue_count"]
    assert artifact_entries["review-gate.json"]["exists"] is True
    assert artifact_entries["review-gate.json"]["count"] == review_gate["blocking_findings"]
    assert artifact_entries["taxonomy-gate.json"]["exists"] is True
    assert artifact_entries["taxonomy-gate.json"]["count"] == taxonomy_gate["blocking_rules"]
    assert artifact_entries["governance-gate.json"]["exists"] is True
    assert artifact_entries["governance-gate.json"]["count"] == governance_gate["blocking_conditions"]
    assert artifact_entries["inventory/coverage/matcher-coverage.json"]["exists"] is True
    assert artifact_entries["inventory/coverage/rule-catalog.json"]["count"] == rule_catalog["total_rules"]
    assert artifact_entries["inventory/coverage/taxonomy-coverage.json"]["exists"] is True
    assert artifact_entries["inventory/coverage/taxonomy-coverage.json"]["count"] == taxonomy_coverage["mapped_rules"]
    assert artifact_entries["inventory/module-risk.json"]["count"] == module_risk["total_modules"]
    assert artifact_entries["inventory/coverage/scanner-manifest.json"]["count"] == manifest["total_entries"]
    assert artifact_entries["deep-scan.sarif"]["exists"] is True
    assert artifact_entries["deep-scan.sarif"]["count"] == len(findings)
    assert artifact_entries["findings.html"]["exists"] is True
    assert artifact_entries["findings.html"]["count"] == len(findings)
    assert artifact_entries["inventory/accepted-risks.json"]["exists"] is True
    assert (
        artifact_entries["inventory/accepted-risks.json"]["count"] == accepted_risks["summary"]["suppressed_findings"]
    )
    assert artifact_entries["00-accepted-risks.md"]["exists"] is True
    assert artifact_entries["inventory/fix-list.json"]["exists"] is True
    assert artifact_entries["inventory/fix-list.json"]["count"] == 0
    assert artifact_entries["00-fix-list.md"]["exists"] is True
    assert artifact_entries["inventory/coverage/poc-coverage.json"]["exists"] is True
    assert artifact_entries["inventory/coverage/poc-coverage.json"]["required"] is False
    assert artifact_entries["inventory/coverage/poc-coverage.json"]["count"] == poc_coverage["generated_pocs"]
    assert artifact_entries["pocs"]["exists"] is True
    assert artifact_entries["pocs"]["count"] == poc_coverage["generated_pocs"]
    assert artifact_entries["inventory/artifacts.json"]["exists"] is True
    assert all(entry["bytes"] > 0 for entry in artifact_entries.values() if entry["exists"])
    assert coverage["rule_catalog"]["total_rules"] >= 250
    assert coverage["rule_catalog"]["emitted_rules"] >= 100
    assert coverage["rule_catalog"]["undocumented_rule_ids"] == []
    assert rule_catalog == coverage["rule_catalog"]
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "odoo-app-security-harness"
    assert len(sarif["runs"][0]["results"]) == len(findings)
    sarif_rules = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids <= sarif_rules
    sarif_rule_entries = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "CWE-79" in sarif_rule_entries["odoo-qweb-t-raw"]["properties"]["cwe"]
    assert sarif["runs"][0]["taxonomies"]
    first_result = sarif["runs"][0]["results"][0]
    assert first_result["ruleId"] in rule_ids
    assert first_result["level"] in {"error", "warning", "note"}
    assert first_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert first_result["partialFingerprints"]["primaryLocationLineHash"].startswith("sha256:")
    for source in coverage["scanner_sources"]["zero_finding_sources"]:
        assert source_entries[source]["findings"] == 0
    if coverage["scanner_sources"]["zero_finding_sources"]:
        assert any(
            warning.startswith("No findings were produced by scanner sources:") for warning in coverage["warnings"]
        )
    tooling_text = tooling_path.read_text(encoding="utf-8")
    assert "Surface Coverage" in tooling_text
    assert "Scanner Sources" in tooling_text
    assert "Finding Summary" in tooling_text
    assert f"Total findings: {len(findings)}" in tooling_text
    assert "| Rule | Findings | Max Severity |" in tooling_text
    assert "Review Gate" in tooling_text
    assert "Verdict: passed" in tooling_text
    assert "Fail on: none" in tooling_text
    assert "Taxonomy Gate" in tooling_text
    assert "Fail on unmapped taxonomy: False" in tooling_text
    assert "Governance Gate" in tooling_text
    assert "Blocking conditions: 0" in tooling_text
    assert "Baseline Delta" in tooling_text
    assert "Not configured" in tooling_text
    assert "Accepted Risks" in tooling_text
    assert "Suppressed findings: 0" in tooling_text
    assert "Fix List" in tooling_text
    assert "Tracked findings: 0" in tooling_text
    assert "Module Risk" in tooling_text
    assert "| test_module |" in tooling_text
    assert "Scanner Registry" in tooling_text
    assert f"Scanner source labels: {coverage['scanner_registry']['source_labels']}" in tooling_text
    assert f"Manifest entries: {len(coverage['scanner_registry']['manifest_entries'])}" in tooling_text
    assert "Missing from deep scan: None" in tooling_text
    assert "Callables without source: None" in tooling_text
    assert "Sources without callable: None" in tooling_text
    assert "Rule Catalog" in tooling_text
    assert f"Declared rule IDs: {coverage['rule_catalog']['total_rules']}" in tooling_text
    assert "Findings with undocumented rule IDs: None" in tooling_text
    assert "Taxonomy Coverage" in tooling_text
    assert f"Mapped rules: {coverage['taxonomy_coverage']['mapped_rules']}" in tooling_text
    assert "PoC Coverage" in tooling_text
    assert f"Generated PoCs: {poc_coverage['generated_pocs']}" in tooling_text
    assert f"Generated files: {len(poc_coverage['generated_files'])}" in tooling_text
    assert "Artifact Manifest" in tooling_text
    assert "Manifest: inventory/artifacts.json" in tooling_text
    if coverage["scanner_sources"]["zero_finding_sources"]:
        assert "No findings were produced by scanner sources:" in tooling_text
    module_risk_markdown = module_risk_markdown_path.read_text(encoding="utf-8")
    assert "Module Risk" in module_risk_markdown
    assert "| test_module |" in module_risk_markdown
    accepted_risks_markdown = accepted_risks_markdown_path.read_text(encoding="utf-8")
    assert "Accepted Risks" in accepted_risks_markdown
    assert "Suppressed findings: 0" in accepted_risks_markdown
    fix_list_markdown = fix_list_markdown_path.read_text(encoding="utf-8")
    assert "Fix List" in fix_list_markdown
    assert "Tracked findings: 0" in fix_list_markdown
    assert all(finding["id"].startswith("F-") for finding in findings)
    assert all(finding["fingerprint"].startswith("sha256:") for finding in findings)
    html_report = html_report_path.read_text(encoding="utf-8")
    assert "Mark as accepted risk" in html_report
    assert "Add to fix-it list" in html_report
    assert "accepted-risk queue" in html_report
    assert "fix-list queue" in html_report
    assert all(finding["triage"] == "NEEDS-MANUAL" for finding in findings)
    assert "odoo-deep-public-write-route" in rule_ids
    assert "odoo-automation-broad-sensitive-trigger" in rule_ids
    assert "odoo-automation-sudo-mutation" in rule_ids
    assert "odoo-qweb-t-raw" in rule_ids
    assert "odoo-qweb-t-att-mapping-url" in rule_ids
    assert "odoo-qweb-sensitive-field-render" in rule_ids
    assert "odoo-acl-public-read-sensitive" in rule_ids
    assert "odoo-acl-global-read-sensitive" in rule_ids
    assert "odoo-acl-sensitive-write" in rule_ids
    assert "odoo-acl-sensitive-unlink" in rule_ids
    assert "odoo-acl-security-model-non-admin" in rule_ids
    assert "odoo-acl-public-rule-sensitive-mutation" in rule_ids
    assert "odoo-access-override-missing-super" in rule_ids
    assert "odoo-access-override-allow-all" in rule_ids
    assert "odoo-access-override-filter-self" in rule_ids
    assert "odoo-access-override-sudo-search" in rule_ids
    assert "odoo-record-rule-public-sensitive-no-owner-scope" in rule_ids
    assert "odoo-record-rule-portal-write-sensitive" in rule_ids
    assert "odoo-record-rule-global-sensitive-mutation" in rule_ids
    assert "odoo-record-rule-domain-has-group" in rule_ids
    assert "odoo-record-rule-company-child-of" in rule_ids
    assert "odoo-record-rule-empty-permissions" in rule_ids
    assert "odoo-constraint-dotted-field" in rule_ids
    assert "odoo-constraint-return-ignored" in rule_ids
    assert "odoo-constraint-sudo-search" in rule_ids
    assert "odoo-constraint-unbounded-search" in rule_ids
    assert "odoo-mc-missing-check-company" in rule_ids
    assert "odoo-mc-rule-missing-company" in rule_ids
    assert "odoo-mc-company-context-user-input" in rule_ids
    assert "odoo-mc-with-company-user-input" in rule_ids
    assert "odoo-manifest-missing-acl-data" in rule_ids
    assert "odoo-manifest-demo-in-data" in rule_ids
    assert "odoo-field-sensitive-no-groups" in rule_ids
    assert "odoo-field-sensitive-public-groups" in rule_ids
    assert "odoo-field-sensitive-indexed" in rule_ids
    assert "odoo-field-compute-sudo-sensitive" in rule_ids
    assert "odoo-field-related-sensitive-no-admin-groups" in rule_ids
    assert "odoo-field-binary-db-storage" in rule_ids
    assert "odoo-property-sensitive-field-no-groups" in rule_ids
    assert "odoo-property-field-default" in rule_ids
    assert "odoo-property-global-default" in rule_ids
    assert "odoo-property-no-resource-scope" in rule_ids
    assert "odoo-property-sensitive-value" in rule_ids
    assert "odoo-property-public-route-mutation" in rule_ids
    assert "odoo-property-sudo-mutation" in rule_ids
    assert "odoo-property-request-derived-mutation" in rule_ids
    assert "odoo-property-runtime-global-default" in rule_ids
    assert "odoo-property-runtime-no-resource-scope" in rule_ids
    assert "odoo-property-runtime-sensitive-value" in rule_ids
    assert "odoo-mail-alias-public-sensitive-model" in rule_ids
    assert "odoo-mail-alias-broad-contact-policy" in rule_ids
    assert "odoo-controller-open-redirect" in rule_ids
    assert "odoo-controller-cors-reflected-origin" in rule_ids
    assert "odoo-controller-cors-credentials-enabled" in rule_ids
    assert "odoo-controller-weak-csp-header" in rule_ids
    assert "odoo-controller-weak-frame-options" in rule_ids
    assert "odoo-controller-weak-referrer-policy" in rule_ids
    assert "odoo-controller-weak-hsts-header" in rule_ids
    assert "odoo-controller-weak-cross-origin-policy" in rule_ids
    assert "odoo-controller-weak-permissions-policy" in rule_ids
    assert "odoo-controller-jsonp-callback-response" in rule_ids
    assert "odoo-controller-tainted-file-read" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-controller-tainted-file-read") >= 2
    assert "odoo-controller-tainted-file-offload-header" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-controller-tainted-file-offload-header") >= 2
    assert "odoo-controller-response-header-injection" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-controller-response-header-injection") >= 2
    assert "odoo-controller-tainted-cookie-value" in rule_ids
    assert "odoo-controller-cookie-missing-security-flags" in rule_ids
    assert "odoo-mail-template-sensitive-token" in rule_ids
    assert "odoo-mail-template-token-not-auto-deleted" in rule_ids
    assert "odoo-mail-template-dynamic-sensitive-recipient" in rule_ids
    assert "odoo-mail-template-dynamic-sender" in rule_ids
    assert "odoo-mail-template-external-link-sensitive" in rule_ids
    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-sensitive-body" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids
    assert "odoo-mail-create-public-route" in rule_ids
    assert "odoo-mail-send-public-route" in rule_ids
    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids
    assert "odoo-mail-public-follower-subscribe" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-mail-tainted-follower-subscribe") >= 2
    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-mail-followers-tainted-mutation") >= 2
    assert "odoo-metadata-group-implies-admin" in rule_ids
    assert "odoo-metadata-sensitive-field-public-groups" in rule_ids
    assert "odoo-metadata-sensitive-field-readonly-disabled" in rule_ids
    assert "odoo-metadata-field-dynamic-compute" in rule_ids
    assert "odoo-migration-destructive-sql" in rule_ids
    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids
    assert "odoo-wizard-binary-import-field" in rule_ids
    assert "odoo-wizard-upload-parser" in rule_ids
    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids
    assert "odoo-model-method-onchange-sudo-mutation" in rule_ids
    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids
    assert "odoo-settings-security-toggle-no-admin-groups" in rule_ids
    assert "odoo-settings-implies-admin-group" in rule_ids
    assert "odoo-settings-module-toggle-no-admin-groups" in rule_ids
    assert "odoo-settings-sudo-set-param" in rule_ids
    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids
    assert "odoo-orm-context-tracking-disabled-mutation" in rule_ids
    assert "odoo-orm-context-privileged-default" in rule_ids
    assert "odoo-orm-context-privileged-default-mutation" in rule_ids
    assert "odoo-orm-context-privileged-mode" in rule_ids
    assert "odoo-orm-context-privileged-mode-mutation" in rule_ids
    assert "odoo-orm-context-request-active-test-disabled" in rule_ids
    assert "odoo-orm-context-request-tracking-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-default" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids
    assert "odoo-orm-domain-tainted-sudo-search" in rule_ids
    assert "odoo-orm-domain-tainted-search" in rule_ids
    assert "odoo-orm-domain-dynamic-eval" in rule_ids
    assert "odoo-raw-sql-interpolated-query" in rule_ids
    assert "odoo-raw-sql-request-derived-input" in rule_ids
    assert "odoo-raw-sql-broad-destructive-query" in rule_ids
    assert "odoo-raw-sql-write-no-company-scope" in rule_ids
    assert "odoo-raw-sql-manual-transaction" in rule_ids
    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sync-without-limit" in rule_ids
    assert "odoo-scheduled-job-http-no-timeout" in rule_ids
    assert "odoo-scheduled-job-tls-verify-disabled" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids
    assert "odoo-scheduled-job-manual-transaction" in rule_ids
    assert "odoo-model-secret-copyable" in rule_ids
    assert "odoo-model-rec-name-sensitive" in rule_ids
    assert "odoo-model-identifier-missing-unique" in rule_ids
    assert "odoo-model-delegated-sensitive-inherits" in rule_ids
    assert "odoo-model-delegated-link-not-required" in rule_ids
    assert "odoo-data-core-xmlid-override" in rule_ids
    assert "odoo-data-sensitive-noupdate-record" in rule_ids
    assert "odoo-xml-user-admin-group-assignment" in rule_ids
    assert "odoo-payment-public-callback-no-signature" in rule_ids
    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids
    assert "odoo-payment-transaction-lookup-weak" in rule_ids
    assert "odoo-publication-public-attachment" in rule_ids
    assert "odoo-publication-sensitive-public-attachment" in rule_ids
    assert "odoo-publication-public-route-mutation" in rule_ids
    assert "odoo-publication-sensitive-runtime-published" in rule_ids
    assert "odoo-publication-tainted-runtime-published" in rule_ids
    assert "odoo-queue-job-http-no-timeout" in rule_ids
    assert "odoo-queue-job-sudo-mutation" in rule_ids
    assert "odoo-report-sudo-enabled" in rule_ids
    assert "odoo-report-sensitive-no-groups" in rule_ids
    assert "odoo-report-public-render-route" in rule_ids
    assert "odoo-report-tainted-render-records" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-report-tainted-render-records") >= 2
    assert "odoo-report-tainted-render-action" in rule_ids
    assert "odoo-report-sudo-render-call" in rule_ids
    assert "odoo-report-sensitive-filename-expression" in rule_ids
    assert "odoo-secret-hardcoded-value" in rule_ids
    assert "odoo-session-public-authenticate" in rule_ids
    assert "odoo-session-direct-uid-assignment" in rule_ids
    assert "odoo-session-direct-request-uid-assignment" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-session-update-env-tainted-user") >= 2
    assert "odoo-session-update-env-superuser" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-session-environment-tainted-user") >= 2
    assert "odoo-session-ir-http-auth-override" in rule_ids
    assert "odoo-session-ir-http-superuser-auth" in rule_ids
    assert "odoo-session-ir-http-bypass" in rule_ids
    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-http-verify-disabled" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-oauth-tainted-validation-url") >= 2
    assert "odoo-oauth-tainted-identity-write" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-signup-tainted-identity-token-write") >= 3
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids
    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-api-key-request-derived-mutation") >= 2
    assert "odoo-api-key-returned-from-route" in rule_ids
    assert "odoo-api-key-xml-record" in rule_ids
    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids
    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-database-tainted-selection") >= 2
    assert "odoo-database-listing-route" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-database-tainted-management-input") >= 2
    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-attachment-tainted-res-id") >= 2
    assert "odoo-attachment-public-write" in rule_ids
    assert "odoo-attachment-tainted-res-model-write" in rule_ids
    assert "odoo-attachment-tainted-res-id-write" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-attachment-tainted-res-id-write") >= 2
    assert "odoo-attachment-tainted-lookup" in rule_ids
    assert "odoo-attachment-tainted-access-token-write" in rule_ids
    assert "odoo-serialization-unsafe-deserialization" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-serialization-unsafe-deserialization") >= 2
    assert "odoo-serialization-unsafe-xml-parser" in rule_ids
    assert "odoo-i18n-dangerous-html" in rule_ids
    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-debug-logging" in rule_ids
    assert "odoo-deploy-oauth-insecure-endpoint" in rule_ids
    assert "odoo-deploy-oauth-missing-validation-endpoint" in rule_ids
    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sensitive-default" in rule_ids
    assert "odoo-config-param-tainted-key-write" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-config-param-tainted-key-write") >= 2
    assert "odoo-config-param-tainted-value-write" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-config-param-tainted-value-write") >= 2
    assert "odoo-config-param-sudo-write" in rule_ids
    assert "odoo-config-param-security-toggle-enabled" in rule_ids
    assert "odoo-config-param-hardcoded-sensitive-write" in rule_ids
    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-default-request-derived-set") >= 2
    assert "odoo-default-sensitive-field-set" in rule_ids
    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-tainted-code" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids
    assert "odoo-sequence-sensitive-declaration" in rule_ids
    assert "odoo-sequence-sensitive-global-scope" in rule_ids
    assert "odoo-sequence-business-global-scope" in rule_ids
    assert "odoo-act-url-tainted-url" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-act-url-tainted-url") >= 2
    assert "odoo-act-url-public-route" in rule_ids
    assert "odoo-act-url-external-no-groups" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-act-url-external-no-groups") >= 2
    assert "odoo-act-url-external-new-window" in rule_ids
    assert "odoo-act-url-unsafe-scheme" in rule_ids
    assert "odoo-act-url-sensitive-url" in rule_ids
    assert "odoo-act-window-tainted-res-model" in rule_ids
    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids
    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert "odoo-act-window-public-sensitive-model" in rule_ids
    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids
    assert "odoo-identity-public-route-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids
    assert "odoo-export-csv-formula-injection" in rule_ids
    assert "odoo-export-xlsx-formula-injection" in rule_ids
    assert "odoo-export-request-controlled-fields" in rule_ids
    assert "odoo-file-upload-base64-decode" in rule_ids
    assert "odoo-file-upload-attachment-from-request" in rule_ids
    assert "odoo-file-upload-public-attachment-create" in rule_ids
    assert "odoo-file-upload-archive-extraction" in rule_ids
    assert "odoo-file-upload-secure-filename-only" in rule_ids
    assert "odoo-file-upload-unsafe-tempfile" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-file-upload-tainted-path-write") >= 2
    assert "odoo-ui-object-button-no-groups" in rule_ids
    assert "odoo-ui-action-button-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-button-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-no-groups" in rule_ids
    assert "odoo-view-inherit-removes-groups" in rule_ids
    assert "odoo-view-inherit-replaces-object-button" in rule_ids
    assert "odoo-view-inherit-broad-security-xpath" in rule_ids
    assert "odoo-view-inherit-reveals-sensitive-field" in rule_ids
    assert "odoo-view-context-active-test-disabled" in rule_ids
    assert "odoo-view-context-user-company-scope" in rule_ids
    assert "odoo-view-domain-global-sensitive-filter-broad-domain" in rule_ids
    assert "odoo-view-filter-global-default-sensitive" in rule_ids
    assert "odoo-view-domain-default-sensitive-filter" in rule_ids
    assert "odoo-web-dom-xss-sink" in rule_ids
    assert "odoo-web-rpc-without-visible-csrf" in rule_ids
    assert "odoo-website-form-public-model-create" in rule_ids
    assert "odoo-website-form-sensitive-field" in rule_ids
    assert "odoo-website-form-file-upload" in rule_ids
    assert "odoo-website-form-missing-csrf-token" in rule_ids
    assert "odoo-website-form-external-success-redirect" in rule_ids
    assert "odoo-binary-attachment-data-response" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-binary-attachment-data-response") >= 2
    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids
    assert "odoo-binary-tainted-web-content-redirect" in rule_ids
    assert "odoo-binary-tainted-content-disposition" in rule_ids
    assert "odoo-cache-public-sensitive-response" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-cache-public-sensitive-response") >= 2
    assert "odoo-cache-public-cacheable-sensitive-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-sudo-route-id-read" in rule_ids
    assert "odoo-portal-manual-access-token-check" in rule_ids
    assert "odoo-portal-token-exposed-without-check" in rule_ids
    assert "odoo-route-auth-none" in rule_ids
    assert "odoo-route-bearer-save-session" in rule_ids
    assert "odoo-route-inherited-security-relaxed" in rule_ids
    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-csrf-disabled-all-methods" in rule_ids
    assert "odoo-route-unsafe-csrf-disabled" in rule_ids
    assert "odoo-route-public-get-mutation" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids
    assert "odoo-route-public-sitemap-indexed" in rule_ids
    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-json-route-mass-assignment") >= 2
    assert "odoo-json-route-tainted-domain" in rule_ids
    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-realtime-broad-or-tainted-channel") >= 2
    assert sum(1 for finding in findings if finding["rule_id"] == "odoo-realtime-sensitive-payload") >= 2
    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tls-verify-disabled" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids
    assert "odoo-integration-tainted-command-args" in rule_ids
    assert "odoo-integration-process-no-timeout" in rule_ids
    assert "odoo-integration-report-command-review" in rule_ids
    assert "odoo-integration-os-command-execution" in rule_ids
    assert "odoo-xml-cron-admin-user" in rule_ids
    assert "odoo-xml-cron-doall-enabled" in rule_ids
    assert "odoo-xml-cron-short-interval" in rule_ids
    assert "odoo-xml-server-action-dynamic-eval" in rule_ids
    assert "odoo-xml-server-action-sudo-mutation" in rule_ids
    assert "odoo-xml-server-action-http-no-timeout" in rule_ids
    assert "odoo-loose-python-sql-injection" in rule_ids
    assert "odoo-loose-python-http-no-timeout" in rule_ids
    assert any(path.name.startswith("poc-") for path in pocs_dir.iterdir())


def test_generate_report_groups_findings_by_source() -> None:
    """Markdown report should summarize sources and table rows."""
    report = odoo_deep_scan.generate_report(
        [
            {
                "source": "deep-pattern",
                "severity": "critical",
                "title": "Public route with sudo",
                "file": "controllers/main.py",
                "line": 10,
            },
            {
                "source": "qweb",
                "severity": "medium",
                "title": "t-raw",
                "file": "views/template.xml",
                "line": 4,
            },
        ]
    )

    assert "### Deep-Pattern" in report
    assert "### Qweb" in report
    assert "| critical | Public route with sudo | `controllers/main.py` | 10 |" in report
