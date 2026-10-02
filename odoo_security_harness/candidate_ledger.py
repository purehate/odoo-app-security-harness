"""Candidate ledger for feeding risky files into LLM hunter lanes.

Inspired by the DeepSec pattern: maintain an append-only per-file candidate
record. Files with zero scanner findings and no sharp-edge index entries are
skipped for hunter passes, saving tokens on low-signal surfaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Patterns that flag a file as a "sharp edge" (security-relevant surface)
# even when deterministic scanners emit zero findings.
_SHARP_EDGE_KEYWORDS: dict[str, list[str]] = {
    ".py": [
        r"@http\.route",
        r"\.sudo\(",
        r"with_user\(",
        r"cr\.execute",
        r"safe_eval",
        r"eval\(",
        r"exec\(",
        r"Markup\(",
        r"csrf\s*=\s*False",
        r"auth\s*=\s*['\"](public|none)['\"]",
        r"\.browse\(",
        r"\.search\(\s*\[\s*\]",
        r"env\[\s*['\"]res\.users['\"]\s*\]",
        r"SUPERUSER_ID",
        r"_sql_constraints",
        r"_inherit",
        r"_name\s*=",
    ],
    ".xml": [
        r"t-raw",
        r"t-out",
        r"t-esc",
        r"t-field",
        r"<record\s",
        r"<template\s",
        r"ir\.model\.access",
        r"ir\.rule",
        r"<function\s",
        r"eval=",
        r"model=",
    ],
    ".csv": [
        r"ir\.model\.access",
    ],
}

# Directories that are inherently security-relevant
_SHARP_EDGE_DIRS = {
    "controllers",
    "models",
    "security",
    "data",
    "migrations",
    "wizard",
    "wizards",
    "report",
    "reports",
}

# Noise tier thresholds
_NOISE_TIER_RANK = {
    "silent": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_SEVERITY_TO_TIER = {
    "info": "silent",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass
class CandidateRecord:
    """Per-file candidate record for hunter lane filtering."""

    file: str
    findings_count: int = 0
    rule_ids: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    max_severity: str = ""
    noise_tier: str = "silent"
    sharp_edge: bool = False
    sharp_edge_reasons: list[str] = field(default_factory=list)
    skip_for_hunters: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "findings_count": self.findings_count,
            "rule_ids": sorted(set(self.rule_ids)),
            "sources": sorted(set(self.sources)),
            "severities": self.severities,
            "max_severity": self.max_severity,
            "noise_tier": self.noise_tier,
            "sharp_edge": self.sharp_edge,
            "sharp_edge_reasons": self.sharp_edge_reasons,
            "skip_for_hunters": self.skip_for_hunters,
            "skip_reason": self.skip_reason,
        }


def _severity_rank(severity: str) -> int:
    return _NOISE_TIER_RANK.get(_SEVERITY_TO_TIER.get(str(severity).lower(), "silent"), 0)


def _is_sharp_edge_file(path: Path, content: str | None = None) -> tuple[bool, list[str]]:
    """Return (is_sharp_edge, reasons) for a given file path.

    A file is a sharp edge if:
    - It lives in a security-relevant directory (controllers, models, security, ...)
    - Its content matches high-risk keywords (routes, sudo, eval, t-raw, ...)
    """
    reasons: list[str] = []
    parts = {p.lower() for p in path.parts}

    # Directory-based sharp edges
    matched_dirs = parts & _SHARP_EDGE_DIRS
    if matched_dirs:
        reasons.append(f"directory:{','.join(sorted(matched_dirs))}")

    # Content-based sharp edges
    suffix = path.suffix.lower()
    patterns = _SHARP_EDGE_KEYWORDS.get(suffix, [])
    if patterns and content is None:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            content = ""

    if content and patterns:
        matched_patterns: list[str] = []
        for pattern in patterns:
            if re.search(pattern, content):
                matched_patterns.append(pattern)
        if matched_patterns:
            reasons.append(f"keywords:{len(matched_patterns)}")

    # Controller files are always sharp edges
    if suffix == ".py" and "/controllers/" in path.as_posix():
        if "directory:controllers" not in reasons:
            reasons.append("directory:controllers")

    # Migration files are always sharp edges
    if suffix == ".py" and "/migrations/" in path.as_posix():
        if "directory:migrations" not in reasons:
            reasons.append("directory:migrations")

    return bool(reasons), reasons


def build_candidate_ledger(
    repo: Path,
    findings: list[dict[str, Any]],
    file_suffixes: set[str] | None = None,
) -> list[CandidateRecord]:
    """Build a per-file candidate ledger from scanner findings + sharp-edge heuristics.

    Args:
        repo: Path to the Odoo repository.
        findings: Normalized findings from all scanners.
        file_suffixes: Which file types to include. Defaults to ``{".py", ".xml", ".csv"}``.

    Returns:
        List of ``CandidateRecord``, one per scanned file.
    """
    from odoo_security_harness.base_scanner import _should_skip

    suffixes = file_suffixes or {".py", ".xml", ".csv"}

    # Collect all scanned files
    all_files: dict[str, Path] = {}
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in suffixes:
            continue
        if _should_skip(path):
            continue
        all_files[str(path.resolve())] = path

    # Aggregate findings per file
    file_findings: dict[str, list[dict[str, Any]]] = {k: [] for k in all_files}
    for finding in findings:
        fpath = finding.get("file")
        if not fpath or fpath == "<repository>":
            continue
        resolved = str(Path(fpath).resolve())
        if resolved in file_findings:
            file_findings[resolved].append(finding)

    ledger: list[CandidateRecord] = []
    for resolved, path in sorted(all_files.items()):
        findings_for_file = file_findings.get(resolved, [])
        severities = [str(f.get("severity", "")).lower() for f in findings_for_file if f.get("severity")]
        max_rank = max((_severity_rank(s) for s in severities), default=0)
        max_severity = max(severities, key=lambda s: _severity_rank(s)) if severities else ""

        # Map max severity rank back to noise tier
        noise_tier = "silent"
        for tier, rank in _NOISE_TIER_RANK.items():
            if rank == max_rank:
                noise_tier = tier
                break

        # Sharp-edge detection
        content = None
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            pass
        is_sharp, reasons = _is_sharp_edge_file(path, content)

        # Determine hunter skip status
        skip = False
        skip_reason = ""
        if not findings_for_file and not is_sharp:
            skip = True
            skip_reason = "zero_findings_no_sharp_edge"

        record = CandidateRecord(
            file=str(path.relative_to(repo)),
            findings_count=len(findings_for_file),
            rule_ids=[str(f.get("rule_id", "")) for f in findings_for_file],
            sources=[str(f.get("source", "")) for f in findings_for_file],
            severities=severities,
            max_severity=max_severity,
            noise_tier=noise_tier,
            sharp_edge=is_sharp,
            sharp_edge_reasons=reasons,
            skip_for_hunters=skip,
            skip_reason=skip_reason,
        )
        ledger.append(record)

    return ledger


def filter_files_for_hunters(
    ledger: list[CandidateRecord],
    min_noise_tier: str = "low",
) -> list[str]:
    """Return file paths that should be sent to LLM hunter lanes.

    Filters out:
    - Files with ``skip_for_hunters=True`` (zero findings + no sharp edge)
    - Files whose ``noise_tier`` is below ``min_noise_tier``
      (unless they are sharp-edge files)

    Args:
        ledger: Candidate ledger from ``build_candidate_ledger``.
        min_noise_tier: Minimum noise tier to include. Files below this
            are skipped unless they are sharp-edge files.

    Returns:
        List of relative file paths to send to hunters.
    """
    min_rank = _NOISE_TIER_RANK.get(min_noise_tier, 1)
    results: list[str] = []

    for record in ledger:
        if record.skip_for_hunters:
            continue
        if _NOISE_TIER_RANK.get(record.noise_tier, 0) >= min_rank:
            results.append(record.file)
        elif record.sharp_edge:
            # Sharp-edge files are always included, even if low noise
            results.append(record.file)

    return results


def ledger_summary(ledger: list[CandidateRecord]) -> dict[str, Any]:
    """Return a summary dict suitable for JSON serialization."""
    total = len(ledger)
    skipped = sum(1 for r in ledger if r.skip_for_hunters)
    sharp = sum(1 for r in ledger if r.sharp_edge)
    with_findings = sum(1 for r in ledger if r.findings_count > 0)
    tier_counts: dict[str, int] = {}
    for record in ledger:
        tier_counts[record.noise_tier] = tier_counts.get(record.noise_tier, 0) + 1

    return {
        "total_files": total,
        "skipped_for_hunters": skipped,
        "sharp_edge_files": sharp,
        "files_with_findings": with_findings,
        "hunter_eligible_files": total - skipped,
        "noise_tier_distribution": tier_counts,
        "entries": [r.to_dict() for r in ledger],
    }
