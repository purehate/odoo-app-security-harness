"""Odoo Application Security Harness - Core utilities and shared functionality."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Import Odoo-specific analyzers
from odoo_security_harness.access_control import analyze_access_control
from odoo_security_harness.analyzer import analyze_directory, analyze_file
from odoo_security_harness.multi_company import check_multi_company_isolation
from odoo_security_harness.poc_generator import generate_pocs
from odoo_security_harness.qweb_scanner import scan_qweb_templates

__all__ = [
    "analyze_access_control",
    "analyze_directory",
    "analyze_file",
    "check_multi_company_isolation",
    "generate_pocs",
    "scan_qweb_templates",
]

# Configure logging
logger = logging.getLogger("odoo_security_harness")


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging for the harness."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def clean_output(text: str) -> str:
    """Strip terminal control noise from CLI/model output before logs/artifacts."""
    ansi_re = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]")
    return ansi_re.sub("", text).replace("\r", "\n")


def progress(message: str) -> None:
    """Print a progress message."""
    print(f"[odoo-review-run] {message}", flush=True)
    logger.info(message)


def rel(path: Path, root: Path) -> str:
    """Get relative path from root."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def should_skip(path: Path) -> bool:
    """Check if a path should be skipped during scanning."""
    parts = set(path.parts)
    if parts & {
        ".git",
        ".hg",
        ".svn",
        ".audit",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".worktrees",
    }:
        return True
    return any(
        part.startswith(".audit-")
        and part
        not in {
            ".audit-accepted-risks.yml",
            ".audit-accepted-risks.yaml",
            ".audit-accepted-risks.json",
            ".audit-fix-list.yml",
            ".audit-fix-list.yaml",
            ".audit-fix-list.json",
            ".audit-baseline",
        }
        for part in path.parts
    )


def normalize_line(text: str) -> str:
    """Normalize whitespace in text."""
    return re.sub(r"\s+", " ", text).strip()


def compute_fingerprint(finding: dict[str, Any]) -> str:
    """Compute stable fingerprint for cross-run deduplication."""
    import hashlib

    parts = [
        (finding.get("rule_id") or finding.get("title") or "")[:80],
        finding.get("file", ""),
        str(finding.get("line", "")),
        normalize_line((finding.get("description") or finding.get("attack_path") or "")[:200]),
    ]
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def severity_rank(sev: str | None) -> int:
    """Convert severity string to numeric rank."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (sev or "").lower(), 2
    )


def load_json(path: Path) -> dict[str, Any]:
    """Load JSON file safely."""
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text)
    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse JSON {path}: {exc}")
        raise
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        raise


def write_json(path: Path, data: dict[str, Any], indent: int = 2) -> None:
    """Write JSON file safely."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent), encoding="utf-8")


def timestamp() -> str:
    """Return ISO timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat()
