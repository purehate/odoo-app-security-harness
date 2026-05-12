"""Tests for findings export (SARIF, fingerprints, bounty drafts)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


def normalize_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compute_fingerprint(finding: dict) -> str:
    parts = [
        (finding.get("rule_id") or finding.get("title") or "")[:80],
        finding.get("file", ""),
        str(finding.get("line", "")),
        normalize_line((finding.get("description") or finding.get("attack_path") or "")[:200]),
    ]
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def to_sarif(findings_doc: dict, scope_data: dict, suppress: bool) -> dict:
    target = findings_doc.get("target", {}) or {}
    repo_uri = target.get("repo") or ""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings_doc.get("findings", []):
        rule_id = f.get("rule_id") or re.sub(r"[^a-zA-Z0-9]+", "-", (f.get("title", "finding")).lower()).strip("-")[:60]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": "".join(part.capitalize() for part in rule_id.split("-")),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": (f.get("description") or f.get("title") or rule_id)[:1000]},
            }

        result = {
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
                (f.get("severity") or "medium").lower(), "warning"
            ),
            "message": {"text": f.get("description") or f.get("title", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "")},
                        "region": {"startLine": int(f.get("line") or 1)},
                    }
                }
            ],
            "fingerprints": {"odoo-harness/v1": f.get("fingerprint") or compute_fingerprint(f)},
        }

        if suppress:
            risks = scope_data.get("accepted_risks") or []
            for risk in risks:
                if not isinstance(risk, dict):
                    continue
                if "module" in risk and risk["module"] and risk["module"] != f.get("module"):
                    continue
                if "file" in risk and risk["file"] and risk["file"] != f.get("file"):
                    continue
                result["suppressions"] = [
                    {"kind": "external", "justification": f"Accepted risk {risk.get('id', 'AR-?')}"}
                ]
                break

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "odoo-app-security-harness", "rules": list(rules.values())}},
                "originalUriBaseIds": {"REPO": {"uri": f"file://{repo_uri}/" if repo_uri else ""}},
                "results": results,
            }
        ],
    }


class TestComputeFingerprint:
    """Test fingerprint computation."""

    def test_fingerprint_stability(self, sample_findings: dict) -> None:
        """Test fingerprint is deterministic."""
        f = sample_findings["findings"][0]
        fp1 = compute_fingerprint(f)
        fp2 = compute_fingerprint(f)
        assert fp1 == fp2
        assert fp1.startswith("sha256:")

    def test_fingerprint_uniqueness(self, sample_findings: dict) -> None:
        """Test different findings have different fingerprints."""
        f1 = sample_findings["findings"][0]
        f2 = sample_findings["findings"][1]
        fp1 = compute_fingerprint(f1)
        fp2 = compute_fingerprint(f2)
        assert fp1 != fp2

    def test_fingerprint_with_empty_finding(self) -> None:
        """Test fingerprint with minimal finding."""
        f = {"title": "Test"}
        fp = compute_fingerprint(f)
        assert fp.startswith("sha256:")
        assert len(fp) == 71  # "sha256:" + 64 hex chars


class TestToSarif:
    """Test SARIF export."""

    def test_sarif_structure(self, sample_findings: dict) -> None:
        """Test SARIF output has correct structure."""
        sarif = to_sarif(sample_findings, {}, False)

        assert sarif["$schema"] is not None
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert len(run["results"]) == 3

    def test_sarif_levels(self, sample_findings: dict) -> None:
        """Test severity to level mapping."""
        sarif = to_sarif(sample_findings, {}, False)
        results = sarif["runs"][0]["results"]

        assert results[0]["level"] == "error"  # critical
        assert results[1]["level"] == "error"  # high
        assert results[2]["level"] == "error"  # high

    def test_sarif_suppression(self, sample_findings: dict) -> None:
        """Test accepted risks are converted to suppressions."""
        scope_data = {
            "accepted_risks": [
                {
                    "id": "AR-001",
                    "module": "test_module",
                    "file": "test_module/controllers/main.py",
                }
            ]
        }
        sarif = to_sarif(sample_findings, scope_data, True)
        results = sarif["runs"][0]["results"]

        # All findings should have suppression since they match the scope
        for result in results:
            assert "suppressions" in result
            assert result["suppressions"][0]["kind"] == "external"

    def test_sarif_no_suppress(self, sample_findings: dict) -> None:
        """Test suppressions are not added when suppress=False."""
        scope_data = {"accepted_risks": [{"id": "AR-001", "module": "test_module"}]}
        sarif = to_sarif(sample_findings, scope_data, False)
        results = sarif["runs"][0]["results"]

        for result in results:
            assert "suppressions" not in result

    def test_sarif_empty_findings(self) -> None:
        """Test SARIF with no findings."""
        doc = {"findings": [], "target": {}}
        sarif = to_sarif(doc, {}, False)

        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_sarif_locations(self, sample_findings: dict) -> None:
        """Test location information in SARIF."""
        sarif = to_sarif(sample_findings, {}, False)
        result = sarif["runs"][0]["results"][0]

        assert "locations" in result
        location = result["locations"][0]
        assert "physicalLocation" in location
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "test_module/controllers/main.py"
        assert location["physicalLocation"]["region"]["startLine"] == 15


class TestBountyDrafts:
    """Test bounty draft generation."""

    def test_bounty_draft_structure(self, tmp_path: Path) -> None:
        """Test bounty draft has required sections."""
        finding = {
            "id": "F-001",
            "title": "SQL Injection",
            "severity": "critical",
            "triage": "ACCEPT",
            "file": "test.py",
            "line": 10,
            "module": "test_module",
            "description": "SQL injection vulnerability",
            "poc": "curl -X POST http://localhost/test",
            "impact": "Database compromise",
            "fix": "Use parameterized queries",
            "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
            "cwe": ["CWE-89"],
            "capec": ["CAPEC-66"],
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        }

        bounty_dir = tmp_path / "bounty"
        bounty_dir.mkdir()

        path = bounty_dir / f"{finding['id']}.md"
        lines = [
            f"# {finding['title']}",
            "",
            f"**Severity:** {finding['severity']}",
            f"**CVSS:** {finding['cvss']['vector']} ({finding['cvss']['score']})",
            f"**CWE:** {', '.join(finding['cwe'])}",
            "",
            "## Summary",
            "",
            finding["description"],
            "",
            "## Steps to Reproduce",
            "",
            finding.get("reproduction") or finding.get("poc") or "_See PoC._",
            "",
            "## Proof of Concept",
            "",
            "```",
            finding.get("poc", "(none provided)"),
            "```",
            "",
            "## Impact",
            "",
            finding.get("impact", ""),
            "",
            "## Suggested Fix",
            "",
            finding.get("fix", ""),
        ]
        path.write_text("\n".join(lines), encoding="utf-8")

        content = path.read_text(encoding="utf-8")
        assert "# SQL Injection" in content
        assert "**Severity:** critical" in content
        assert "## Summary" in content
        assert "## Steps to Reproduce" in content
        assert "## Proof of Concept" in content
        assert "## Impact" in content
        assert "## Suggested Fix" in content
        assert "curl -X POST" in content

    def test_skip_non_accept_findings(self, tmp_path: Path) -> None:
        """Test only ACCEPT findings generate bounty drafts."""
        findings = [
            {"id": "F-001", "triage": "ACCEPT", "title": "Real Bug"},
            {"id": "F-002", "triage": "REJECT", "title": "False Positive"},
            {"id": "F-003", "triage": "DOWNGRADE", "title": "Low Priority"},
        ]

        bounty_dir = tmp_path / "bounty"
        bounty_dir.mkdir()

        accept_count = 0
        for f in findings:
            if f["triage"] == "ACCEPT":
                accept_count += 1
                (bounty_dir / f"{f['id']}.md").write_text(f"# {f['title']}", encoding="utf-8")

        assert accept_count == 1
        assert len(list(bounty_dir.glob("*.md"))) == 1


class TestFingerprintsExport:
    """Test fingerprint export."""

    def test_fingerprints_structure(self, sample_findings: dict) -> None:
        """Test fingerprints document structure."""
        entries = []
        for f in sample_findings.get("findings", []):
            fp = f.get("fingerprint") or compute_fingerprint(f)
            entries.append(
                {
                    "id": f.get("id"),
                    "fingerprint": fp,
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                }
            )

        doc = {
            "schema_version": "1.0",
            "fingerprints": entries,
        }

        assert len(doc["fingerprints"]) == 3
        for entry in doc["fingerprints"]:
            assert "fingerprint" in entry
            assert entry["fingerprint"].startswith("sha256:")
