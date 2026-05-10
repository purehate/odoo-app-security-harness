"""Finding normalization and schema validation helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_TRIAGE = {"ACCEPT", "DOWNGRADE", "REJECT", "NEEDS-MANUAL"}


@dataclass
class FindingSchemaIssue:
    """Schema validation issue for one finding."""

    index: int
    field: str
    message: str


def normalize_finding(finding: dict[str, Any], index: int) -> dict[str, Any]:
    """Return a normalized finding suitable for exports and reports."""
    normalized = dict(finding)
    normalized.setdefault("id", f"F-{index:04d}")
    normalized["severity"] = str(normalized.get("severity") or "medium").lower()
    if not normalized.get("file"):
        normalized["file"] = "<repository>"
    normalized.setdefault("triage", "NEEDS-MANUAL")
    normalized.setdefault("description", normalized.get("message") or normalized.get("title") or "")
    normalized.setdefault("fingerprint", compute_fingerprint(normalized))
    return normalized


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize all findings in stable input order."""
    return [normalize_finding(finding, index) for index, finding in enumerate(findings, start=1)]


def validate_findings(findings: list[dict[str, Any]]) -> list[FindingSchemaIssue]:
    """Validate minimum finding fields expected by downstream tooling."""
    issues: list[FindingSchemaIssue] = []
    required = {"id", "title", "severity", "triage", "file", "line", "description", "fingerprint"}
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()

    for index, finding in enumerate(findings, start=1):
        for field in sorted(required):
            if field not in finding or finding[field] in (None, ""):
                issues.append(FindingSchemaIssue(index, field, "required field is missing or empty"))

        finding_id = str(finding.get("id") or "")
        if finding_id in seen_ids:
            issues.append(FindingSchemaIssue(index, "id", f"duplicate finding id: {finding_id}"))
        seen_ids.add(finding_id)

        severity = str(finding.get("severity") or "").lower()
        if severity and severity not in VALID_SEVERITIES:
            issues.append(FindingSchemaIssue(index, "severity", f"invalid severity: {severity}"))

        triage = str(finding.get("triage") or "")
        if triage and triage not in VALID_TRIAGE:
            issues.append(FindingSchemaIssue(index, "triage", f"invalid triage: {triage}"))

        fingerprint = str(finding.get("fingerprint") or "")
        if fingerprint:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint):
                issues.append(FindingSchemaIssue(index, "fingerprint", "fingerprint must match sha256:<64 hex>"))
            if fingerprint in seen_fingerprints:
                issues.append(FindingSchemaIssue(index, "fingerprint", f"duplicate fingerprint: {fingerprint}"))
            seen_fingerprints.add(fingerprint)

        line = finding.get("line")
        if not isinstance(line, int) or line < 0:
            issues.append(FindingSchemaIssue(index, "line", "line must be a non-negative integer"))

    return issues


def validation_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a JSON-serializable validation report."""
    issues = validate_findings(findings)
    return {
        "valid": not issues,
        "finding_count": len(findings),
        "issue_count": len(issues),
        "issues": [
            {"index": issue.index, "field": issue.field, "message": issue.message}
            for issue in issues
        ],
    }


def compute_fingerprint(finding: dict[str, Any]) -> str:
    """Compute a stable SHA-256 fingerprint for a finding."""
    parts = [
        str(finding.get("rule_id") or finding.get("title") or "")[:80],
        str(finding.get("file") or ""),
        str(finding.get("line") or ""),
        _normalize_line(str(finding.get("description") or finding.get("attack_path") or "")[:200]),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _normalize_line(text: str) -> str:
    """Normalize whitespace in text."""
    return re.sub(r"\s+", " ", text).strip()
