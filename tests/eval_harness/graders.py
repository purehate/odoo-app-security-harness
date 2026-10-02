"""Deterministic graders for the eval harness.

Grader functions take the scanner findings and expected ground truth,
then return a pass/fail result with optional diagnostic details.
"""

from __future__ import annotations

from typing import Any


class GraderResult:
    """Result of a single grader check."""

    def __init__(self, passed: bool, message: str = "") -> None:
        self.passed = passed
        self.message = message

    def __bool__(self) -> bool:
        return self.passed


def grader_rule_id_present(
    expected_rule_id: str,
    findings: list[dict[str, Any]],
) -> GraderResult:
    """Pass if at least one finding has the expected rule_id."""
    for finding in findings:
        if finding.get("rule_id") == expected_rule_id:
            return GraderResult(True)
    return GraderResult(
        False,
        f"Expected rule_id '{expected_rule_id}' not found in {len(findings)} findings",
    )


def grader_rule_ids_all_present(
    expected_rule_ids: set[str],
    findings: list[dict[str, Any]],
) -> GraderResult:
    """Pass if every expected rule_id is present in findings."""
    found = {f.get("rule_id") for f in findings if f.get("rule_id")}
    missing = expected_rule_ids - found
    if missing:
        return GraderResult(
            False,
            f"Missing rule_ids: {sorted(missing)} (found: {sorted(found & expected_rule_ids)})",
        )
    return GraderResult(True)


def grader_line_accuracy(
    expected_rule_id: str,
    expected_line: int,
    findings: list[dict[str, Any]],
    tolerance: int = 3,
) -> GraderResult:
    """Pass if a finding with the expected rule_id is within tolerance lines."""
    for finding in findings:
        if finding.get("rule_id") == expected_rule_id:
            actual_line = finding.get("line", 0)
            if actual_line and abs(actual_line - expected_line) <= tolerance:
                return GraderResult(True)
            return GraderResult(
                False,
                f"Rule '{expected_rule_id}' found at line {actual_line}, "
                f"expected within {tolerance} of {expected_line}",
            )
    return GraderResult(
        False,
        f"Rule '{expected_rule_id}' not found for line check",
    )


def grader_no_false_positives_on_clean_module(
    findings: list[dict[str, Any]],
    allowed_rules: set[str] | None = None,
) -> GraderResult:
    """Pass if no findings (or only allowed findings) on a known-clean module.

    Some scanners may legitimately emit info-level findings on any module
    (e.g., missing security headers). Use ``allowed_rules`` to permit those.
    """
    allowed = allowed_rules or set()
    unexpected = [
        f for f in findings if f.get("rule_id") not in allowed and f.get("severity", "").lower() not in ("info",)
    ]
    if unexpected:
        rules = [f.get("rule_id") for f in unexpected]
        return GraderResult(
            False,
            f"Unexpected findings on clean module: {rules}",
        )
    return GraderResult(True)


def grader_minimum_severity(
    expected_rule_id: str,
    minimum_severity: str,
    findings: list[dict[str, Any]],
) -> GraderResult:
    """Pass if the finding for expected_rule_id meets minimum severity."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_rank = severity_rank.get(minimum_severity.lower(), 2)
    for finding in findings:
        if finding.get("rule_id") == expected_rule_id:
            actual = finding.get("severity", "medium").lower()
            actual_rank = severity_rank.get(actual, 2)
            if actual_rank >= min_rank:
                return GraderResult(True)
            return GraderResult(
                False,
                f"Rule '{expected_rule_id}' severity '{actual}' " f"below minimum '{minimum_severity}'",
            )
    return GraderResult(
        False,
        f"Rule '{expected_rule_id}' not found for severity check",
    )
