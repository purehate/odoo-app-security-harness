#!/usr/bin/env python3
"""Odoo Security Deep Scan - Runs all Odoo-specific analyzers.

Usage:
    odoo-deep-scan <repo-path> [--out <dir>] [--pocs]

Runs:
1. AST-based deep pattern analysis
2. QWeb template security scanning
3. Access control (ACL/ir.rule) analysis
4. Multi-company isolation checking
5. Automated PoC generation (optional)

Outputs findings in JSON and Markdown format.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from odoo_security_harness import (
    analyze_access_control,
    analyze_directory,
    check_multi_company_isolation,
    generate_pocs,
    scan_qweb_templates,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Odoo Security Deep Scan")
    parser.add_argument("repo", help="Path to Odoo repository")
    parser.add_argument("--out", default=".audit-deep", help="Output directory")
    parser.add_argument("--pocs", action="store_true", help="Generate PoC scripts")
    parser.add_argument("--base-url", default="http://localhost:8069", help="Base URL for PoCs")
    parser.add_argument("--database", default="odoo", help="Database name for PoCs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()

    if not repo.exists():
        print(f"Repository not found: {repo}", file=sys.stderr)
        return 1

    out.mkdir(parents=True, exist_ok=True)
    print(f"Scanning {repo}...")
    print(f"Output: {out}")
    print()

    all_findings: list[dict] = []

    # 1. Deep pattern analysis
    print("1. Running deep pattern analysis...")
    findings = analyze_directory(repo)
    deep_findings = [
        {
            "source": "deep-pattern",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
        }
        for f in findings
    ]
    all_findings.extend(deep_findings)
    print(f"   Found {len(deep_findings)} issues")

    # 2. QWeb scanning
    print("2. Scanning QWeb templates...")
    qweb_findings = scan_qweb_templates(repo)
    qweb_results = [
        {
            "source": "qweb",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "attribute": f.attribute,
        }
        for f in qweb_findings
    ]
    all_findings.extend(qweb_results)
    print(f"   Found {len(qweb_results)} issues")

    # 3. Access control analysis
    print("3. Analyzing access control...")
    acl_findings = analyze_access_control(repo)
    acl_results = [
        {
            "source": "access-control",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "group": f.group,
        }
        for f in acl_findings
    ]
    all_findings.extend(acl_results)
    print(f"   Found {len(acl_results)} issues")

    # 4. Multi-company isolation
    print("4. Checking multi-company isolation...")
    mc_findings = check_multi_company_isolation(repo)
    mc_results = [
        {
            "source": "multi-company",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
        }
        for f in mc_findings
    ]
    all_findings.extend(mc_results)
    print(f"   Found {len(mc_results)} issues")

    # Write findings
    findings_file = out / "deep-scan-findings.json"
    findings_file.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    print(f"\nWrote {len(all_findings)} total findings to {findings_file}")

    # Generate Markdown report
    report_file = out / "deep-scan-report.md"
    report = generate_report(all_findings)
    report_file.write_text(report, encoding="utf-8")
    print(f"Wrote report to {report_file}")

    # Generate PoCs if requested
    if args.pocs:
        print("\nGenerating PoC scripts...")
        pocs_dir = out / "pocs"
        generated = generate_pocs(all_findings, pocs_dir)
        print(f"Generated {len(generated)} PoC scripts in {pocs_dir}")

    # Summary
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "=" * 50)
    print("Summary:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():.<10} {count:>3}")
    print("=" * 50)

    return 0


def generate_report(findings: list[dict]) -> str:
    """Generate Markdown report from findings."""
    lines = [
        "# Odoo Security Deep Scan Report",
        "",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Findings by Source",
        "",
    ]

    # Group by source
    by_source: dict[str, list[dict]] = {}
    for f in findings:
        source = f.get("source", "unknown")
        by_source.setdefault(source, []).append(f)

    for source, source_findings in sorted(by_source.items()):
        lines.append(f"### {source.title()}")
        lines.append("")
        lines.append(f"Found {len(source_findings)} issues:")
        lines.append("")
        lines.append("| Severity | Title | File | Line |")
        lines.append("|----------|-------|------|------|")
        for f in sorted(source_findings, key=lambda x: x.get("severity", "")):
            lines.append(
                f"| {f.get('severity', '?')} | {f.get('title', '?')} | "
                f"`{f.get('file', '?')}` | {f.get('line', '?')} |"
            )
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
