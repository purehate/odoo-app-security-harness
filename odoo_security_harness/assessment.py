"""Build a reproducible AppSec assessment packet from a completed audit."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SEVERITY_SCORE = {"critical": 50, "high": 40, "medium": 30, "low": 20, "info": 10}
ARTIFACT_PATTERN = re.compile(r"(?:runtime|validation|zerocool|codex|bounty|assessment)/[A-Za-z0-9_.:/-]+")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the assessment-packet command line."""
    parser = argparse.ArgumentParser(
        description="Build and validate a discovery-to-remediation assessment evidence packet."
    )
    parser.add_argument("out", help="Completed .audit directory containing findings.json.")
    parser.add_argument("--repo", help="Target repository. Defaults to findings.json target.repo.")
    parser.add_argument("--finding", help="Finding ID. Defaults to the strongest reproducible ACCEPT finding.")
    parser.add_argument("--patched-ref", help="Patched Git commit or ref used for fix verification.")
    parser.add_argument("--diff-base", help="Git ref immediately before the focused remediation changes.")
    parser.add_argument("--pre-fix", help="Pre-fix reproduction output path.")
    parser.add_argument("--post-fix", help="Post-fix replay output path.")
    parser.add_argument("--legitimate", help="Legitimate-behavior test output path.")
    parser.add_argument("--regression-test", help="Security regression test source path.")
    parser.add_argument("--test-command", help="Exact command used for pre/post-fix verification.")
    parser.add_argument("--pr-url", help="Focused remediation pull request URL.")
    parser.add_argument("--ci-url", help="CI result URL tied to the patched commit.")
    parser.add_argument(
        "--verification-result",
        help="Recorded verification output containing the exact patched commit.",
    )
    parser.add_argument("--ticket-url", help="Finding or remediation ticket URL.")
    parser.add_argument("--root-cause", help="Concise reviewer-facing root-cause explanation.")
    parser.add_argument("--fix-summary", help="Concise reviewer-facing remediation summary.")
    parser.add_argument("--pre-fix-summary", help="Observed vulnerable behavior before the patch.")
    parser.add_argument("--post-fix-summary", help="Observed behavior after the patch.")
    parser.add_argument("--legitimate-summary", help="Legitimate behavior proven to remain available.")
    parser.add_argument("--deployment-notes", help="Deployment or migration requirements.")
    parser.add_argument("--rollback-plan", help="Safe rollback procedure.")
    parser.add_argument("--residual-risk", help="Known residual risk or explicit 'None identified'.")
    parser.add_argument(
        "--strict", action="store_true", help="Exit 4 unless the discovery-to-remediation chain is demo-ready."
    )
    return parser.parse_args(argv)


def read_json(path: Path) -> dict[str, Any]:
    """Read one JSON object using an explicit resource context."""
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    """Write deterministic JSON using an explicit resource context."""
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_text(path: Path, value: str) -> None:
    """Write text using an explicit resource context."""
    with path.open("w", encoding="utf-8") as handle:
        handle.write(value)


def sha256_bytes(value: bytes) -> str:
    """Return a prefixed SHA-256 digest."""
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a bounded, read-only Git query."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def git_value(repo: Path, *args: str) -> str:
    """Return stdout for a successful Git query, otherwise an empty string."""
    result = git(repo, *args)
    return result.stdout.strip() if result.returncode == 0 else ""


def capture_repository(repo: Path, assessment_dir: Path) -> dict[str, Any]:
    """Capture the exact tracked Git state without changing the source tree."""
    head = git_value(repo, "rev-parse", "HEAD")
    branch = git_value(repo, "branch", "--show-current")
    status = git_value(repo, "status", "--porcelain=v1", "--untracked-files=all")
    diff_result = git(repo, "diff", "--binary", "HEAD", "--")
    diff_text = diff_result.stdout if diff_result.returncode == 0 else ""
    patch_path: Path | None = None
    if diff_text:
        patch_path = assessment_dir / "vulnerable-worktree.patch"
        write_text(patch_path, diff_text)
    untracked = [line[3:] for line in status.splitlines() if line.startswith("?? ")]
    return {
        "repo": str(repo),
        "head": head,
        "branch": branch or "(detached)",
        "dirty": bool(status),
        "status": status.splitlines(),
        "untracked_paths": untracked,
        "tracked_patch": str(patch_path) if patch_path else None,
        "tracked_patch_sha256": sha256_file(patch_path) if patch_path else None,
    }


def artifact_references(finding: dict[str, Any]) -> list[str]:
    """Extract audit-relative artifact references from finding evidence fields."""
    references: list[str] = []
    for field in ("reproduction", "poc"):
        value = finding.get(field)
        if not isinstance(value, str):
            continue
        stripped = value.strip().strip("`'\"")
        if "/" in stripped and "\n" not in stripped and " " not in stripped:
            references.append(stripped)
        references.extend(match.rstrip(".,);]`") for match in ARTIFACT_PATTERN.findall(value))
    fp_check = finding.get("fp_check")
    if isinstance(fp_check, dict):
        evidence = fp_check.get("evidence")
        if isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, str):
                    references.extend(match.rstrip(".,);]`") for match in ARTIFACT_PATTERN.findall(item))
    return list(dict.fromkeys(references))


def resolve_artifact(value: str | None, out: Path, repo: Path) -> Path | None:
    """Resolve an artifact against the audit directory and repository."""
    if not value:
        return None
    candidate = Path(value).expanduser()
    paths = [candidate] if candidate.is_absolute() else [out / candidate, repo / candidate]
    return next((path.resolve() for path in paths if path.exists()), None)


def select_finding(findings: list[dict[str, Any]], requested: str | None, out: Path, repo: Path) -> dict[str, Any]:
    """Select a requested finding or rank accepted findings for demonstrability."""
    if requested:
        for finding in findings:
            if str(finding.get("id")) == requested:
                return finding
        raise ValueError(f"Finding {requested!r} was not found")

    accepted = [finding for finding in findings if str(finding.get("triage", "")).upper() == "ACCEPT"]
    if not accepted:
        raise ValueError("No ACCEPT finding is available for assessment preparation")

    def score(finding: dict[str, Any]) -> tuple[int, str]:
        value = SEVERITY_SCORE.get(str(finding.get("severity", "")).lower(), 0)
        references = artifact_references(finding)
        value += 20 if any(resolve_artifact(ref, out, repo) for ref in references) else 0
        value += 10 if finding.get("poc") else 0
        value += 5 if finding.get("second_opinion") else 0
        value += 3 if finding.get("fix") else 0
        return value, str(finding.get("id", ""))

    return max(accepted, key=score)


def initial_record(
    finding: dict[str, Any], findings_doc: dict[str, Any], snapshot: dict[str, Any], artifacts: list[Path]
) -> dict[str, Any]:
    """Create the editable remediation and verification record."""
    target = findings_doc.get("target") if isinstance(findings_doc.get("target"), dict) else {}
    return {
        "schema_version": "1.0",
        "finding_id": finding.get("id"),
        "baseline": {
            "commit": target.get("commit") or snapshot.get("head"),
            "branch": snapshot.get("branch"),
            "worktree_patch": snapshot.get("tracked_patch"),
            "worktree_patch_sha256": snapshot.get("tracked_patch_sha256"),
        },
        "remediation": {
            "patched_commit": "",
            "diff_base": "",
            "diff_artifact": "",
            "pr_url": "",
            "ticket_url": "",
        },
        "verification": {
            "test_command": "",
            "pre_fix_artifact": str(artifacts[0]) if artifacts else "",
            "post_fix_artifact": "",
            "regression_test": "",
            "legitimate_behavior_artifact": "",
            "ci_url": "",
            "result_artifact": "",
        },
        "review": {
            "root_cause": finding.get("attack_path") or "",
            "fix_summary": finding.get("fix") or "",
            "pre_fix_summary": "",
            "post_fix_summary": "",
            "legitimate_behavior_summary": "",
            "deployment_notes": "",
            "rollback_plan": "",
            "residual_risk": "",
        },
        "limitations": [],
    }


def update_record(record: dict[str, Any], args: argparse.Namespace) -> None:
    """Apply explicit CLI evidence to the persistent assessment record."""
    remediation = record.setdefault("remediation", {})
    verification = record.setdefault("verification", {})
    updates = {
        "patched_commit": args.patched_ref,
        "diff_base": args.diff_base,
        "pr_url": args.pr_url,
        "ticket_url": args.ticket_url,
    }
    for key, value in updates.items():
        if value:
            remediation[key] = value
    verification_updates = {
        "pre_fix_artifact": args.pre_fix,
        "post_fix_artifact": args.post_fix,
        "legitimate_behavior_artifact": args.legitimate,
        "regression_test": args.regression_test,
        "test_command": args.test_command,
        "ci_url": args.ci_url,
        "result_artifact": args.verification_result,
    }
    for key, value in verification_updates.items():
        if value:
            verification[key] = value
    review = record.setdefault("review", {})
    review_updates = {
        "root_cause": args.root_cause,
        "fix_summary": args.fix_summary,
        "pre_fix_summary": args.pre_fix_summary,
        "post_fix_summary": args.post_fix_summary,
        "legitimate_behavior_summary": args.legitimate_summary,
        "deployment_notes": args.deployment_notes,
        "rollback_plan": args.rollback_plan,
        "residual_risk": args.residual_risk,
    }
    for key, value in review_updates.items():
        if value:
            review[key] = value


def capture_remediation_diff(record: dict[str, Any], repo: Path, assessment_dir: Path) -> None:
    """Capture the focused baseline-to-patched Git diff when both refs resolve."""
    baseline = str(record.get("remediation", {}).get("diff_base") or record.get("baseline", {}).get("commit") or "")
    patched = str(record.get("remediation", {}).get("patched_commit") or "")
    if not baseline or not patched or baseline == patched:
        return
    result = git(repo, "diff", "--binary", f"{baseline}..{patched}", "--")
    if result.returncode != 0 or not result.stdout:
        return
    path = assessment_dir / "remediation.diff"
    write_text(path, result.stdout)
    record["remediation"]["diff_artifact"] = str(path)
    record["remediation"]["diff_sha256"] = sha256_file(path)


def artifact_gate(name: str, value: str | None, out: Path, repo: Path) -> dict[str, Any]:
    """Build a readiness gate for a referenced file artifact."""
    resolved = resolve_artifact(value, out, repo)
    return {
        "name": name,
        "status": "pass" if resolved else "missing",
        "artifact": str(resolved) if resolved else value or "",
        "sha256": sha256_file(resolved) if resolved and resolved.is_file() else None,
    }


def verification_result_gate(verification: dict[str, Any], patched: str, out: Path, repo: Path) -> dict[str, Any]:
    """Accept hosted CI or recorded output that names the exact patched commit."""
    ci_url = str(verification.get("ci_url") or "")
    if ci_url:
        return {
            "name": "CI or recorded verification tied to patched commit",
            "status": "pass",
            "artifact": ci_url,
        }
    value = str(verification.get("result_artifact") or "")
    resolved = resolve_artifact(value, out, repo)
    contains_commit = False
    if resolved and resolved.is_file() and patched:
        try:
            contains_commit = patched in resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            contains_commit = False
    return {
        "name": "CI or recorded verification tied to patched commit",
        "status": "pass" if contains_commit else "missing",
        "artifact": str(resolved) if contains_commit and resolved else value,
        "sha256": sha256_file(resolved) if contains_commit and resolved else None,
        "note": "Recorded output must name the exact patched commit." if resolved and not contains_commit else "",
    }


def build_gates(
    finding: dict[str, Any], record: dict[str, Any], out: Path, repo: Path, snapshot: dict[str, Any]
) -> list[dict[str, Any]]:
    """Evaluate the assessment chain as deterministic pass/missing gates."""
    baseline = record.get("baseline", {})
    remediation = record.get("remediation", {})
    verification = record.get("verification", {})
    baseline_ready = bool(baseline.get("commit")) and not snapshot.get("untracked_paths")
    patched = str(remediation.get("patched_commit") or "")
    patch_ready = bool(patched and patched != baseline.get("commit") and remediation.get("diff_artifact"))
    gates = [
        {
            "name": "validated finding",
            "status": "pass" if str(finding.get("triage", "")).upper() == "ACCEPT" else "missing",
            "artifact": str(out / "findings.json"),
        },
        {
            "name": "immutable vulnerable baseline",
            "status": "pass" if baseline_ready else "missing",
            "artifact": baseline.get("commit") or "",
            "note": "Untracked source files prevent exact replay." if snapshot.get("untracked_paths") else "",
        },
        artifact_gate("pre-fix reproduction", verification.get("pre_fix_artifact"), out, repo),
        {
            "name": "focused remediation diff",
            "status": "pass" if patch_ready else "missing",
            "artifact": remediation.get("diff_artifact") or "",
        },
        artifact_gate("post-fix replay", verification.get("post_fix_artifact"), out, repo),
        artifact_gate("security regression test", verification.get("regression_test"), out, repo),
        artifact_gate("legitimate behavior verification", verification.get("legitimate_behavior_artifact"), out, repo),
        {
            "name": "exact verification command",
            "status": "pass" if verification.get("test_command") else "missing",
            "artifact": verification.get("test_command") or "",
        },
        verification_result_gate(verification, patched, out, repo),
        {
            "name": "remediation delivery link",
            "status": "pass" if remediation.get("pr_url") or remediation.get("ticket_url") else "missing",
            "artifact": remediation.get("pr_url") or remediation.get("ticket_url") or "",
        },
    ]
    gates.extend(review_gates(record.get("review", {})))
    return gates


def review_gates(review: dict[str, Any]) -> list[dict[str, Any]]:
    """Return completeness gates for reviewer-facing narrative fields."""
    fields = (
        ("root_cause", "reviewer root-cause explanation"),
        ("fix_summary", "reviewer fix explanation"),
        ("pre_fix_summary", "pre-fix behavior summary"),
        ("post_fix_summary", "post-fix behavior summary"),
        ("legitimate_behavior_summary", "legitimate behavior summary"),
        ("deployment_notes", "deployment notes"),
        ("rollback_plan", "rollback plan"),
        ("residual_risk", "residual-risk statement"),
    )
    return [
        {
            "name": label,
            "status": "pass" if review.get(field) else "missing",
            "artifact": "assessment/record.json" if review.get(field) else "",
        }
        for field, label in fields
    ]


def markdown_link(path: str, base: Path) -> str:
    """Return an audit-relative Markdown link when possible."""
    if not path:
        return "—"
    candidate = Path(path)
    try:
        label = str(candidate.resolve().relative_to(base.resolve()))
    except ValueError:
        return f"`{path}`"
    return f"[{label}]({label})"


def pr_artifact(path: str, out: Path, repo: Path) -> str:
    """Render packet and repository artifacts without workstation-absolute paths."""
    if not path:
        return "—"
    candidate = Path(path).resolve()
    for base, prefix in ((out.resolve(), "packet: "), (repo.resolve(), "")):
        try:
            relative = candidate.relative_to(base)
        except ValueError:
            continue
        return f"{prefix}`{relative}`"
    return f"`{Path(path).name}`"


def reviewer_value(value: Any) -> str:
    """Render a review field without hiding incomplete evidence."""
    return str(value).strip() if value else "**PENDING — required before review**"


def render_pr_body(out: Path, repo: Path, finding: dict[str, Any], record: dict[str, Any]) -> list[str]:
    """Render a self-contained remediation PR description."""
    baseline = record.get("baseline", {})
    remediation = record.get("remediation", {})
    verification = record.get("verification", {})
    review = record.get("review", {})
    return [
        f"# fix: remediate {finding.get('id')} — {finding.get('title', '')}",
        "",
        "## Security issue",
        "",
        reviewer_value(finding.get("description")),
        "",
        f"- **Severity:** {finding.get('severity', 'unknown')}",
        f"- **Affected code:** `{finding.get('file', '')}:{finding.get('line', '')}`",
        f"- **Attack path:** {reviewer_value(finding.get('attack_path'))}",
        f"- **Impact:** {reviewer_value(finding.get('impact'))}",
        f"- **Vulnerable baseline:** `{reviewer_value(baseline.get('commit'))}`",
        "",
        "## Root cause",
        "",
        reviewer_value(review.get("root_cause")),
        "",
        "## Remediation",
        "",
        reviewer_value(review.get("fix_summary")),
        "",
        f"- **Patched commit:** `{reviewer_value(remediation.get('patched_commit'))}`",
        f"- **Focused diff base:** `{reviewer_value(remediation.get('diff_base') or baseline.get('commit'))}`",
        f"- **Focused diff:** {pr_artifact(str(remediation.get('diff_artifact') or ''), out, repo)}",
        "",
        *render_pr_verification(out, repo, verification, review),
        "",
        "## Delivery and operations",
        "",
        f"- **Remediation PR:** {reviewer_value(remediation.get('pr_url'))}",
        f"- **Ticket:** {remediation.get('ticket_url') or 'Not used; the remediation PR is the system of record.'}",
        f"- **Deployment notes:** {reviewer_value(review.get('deployment_notes'))}",
        f"- **Rollback plan:** {reviewer_value(review.get('rollback_plan'))}",
        f"- **Residual risk:** {reviewer_value(review.get('residual_risk'))}",
        "",
        "## Evidence integrity",
        "",
        "Artifact hashes and completeness gates are recorded in `assessment/status.json`; repository identity and any vulnerable worktree patch are recorded in `assessment/repository-state.json`.",
    ]


def render_pr_verification(out: Path, repo: Path, verification: dict[str, Any], review: dict[str, Any]) -> list[str]:
    """Render the before/after and test-evidence sections of a PR body."""
    ci_result = verification.get("ci_url") or "Not provided; recorded verification is supplied below."
    return [
        "## Before and after",
        "",
        "| State | Observed behavior | Evidence |",
        "| --- | --- | --- |",
        f"| Vulnerable baseline | {reviewer_value(review.get('pre_fix_summary'))} | {pr_artifact(str(verification.get('pre_fix_artifact') or ''), out, repo)} |",
        f"| Patched commit | {reviewer_value(review.get('post_fix_summary'))} | {pr_artifact(str(verification.get('post_fix_artifact') or ''), out, repo)} |",
        f"| Legitimate workflow | {reviewer_value(review.get('legitimate_behavior_summary'))} | {pr_artifact(str(verification.get('legitimate_behavior_artifact') or ''), out, repo)} |",
        "",
        "## Verification",
        "",
        f"- **Exact command:** `{reviewer_value(verification.get('test_command'))}`",
        f"- **Regression test:** {pr_artifact(str(verification.get('regression_test') or ''), out, repo)}",
        f"- **Hosted CI:** {ci_result}",
        f"- **Recorded result:** {pr_artifact(str(verification.get('result_artifact') or ''), out, repo)}",
    ]


def render_reviewer_checklist(gates: list[dict[str, Any]]) -> list[str]:
    """Render completeness and code-review checks for a human reviewer."""
    checklist = ["# Human reviewer checklist", ""]
    checklist.extend(
        f"- [{'x' if gate['status'] == 'pass' else ' '}] {gate['name']} — {gate.get('artifact') or 'missing'}"
        for gate in gates
    )
    checklist.extend(
        [
            "",
            "## Code-review focus",
            "",
            "- [ ] The patch enforces the security invariant server-side at the actual state transition.",
            "- [ ] The regression test exercises the original attacker path, not a substitute code path.",
            "- [ ] Positive tests preserve authorized and non-affected workflows.",
            "- [ ] The patch does not broaden privileges, introduce secret handling, or weaken multi-company isolation.",
            "- [ ] CI and recorded outputs identify the same patched commit shown in this PR.",
        ]
    )
    return checklist


def write_pr_materials(
    assessment_dir: Path,
    out: Path,
    repo: Path,
    finding: dict[str, Any],
    record: dict[str, Any],
    gates: list[dict[str, Any]],
) -> None:
    """Generate a self-contained PR body and human-review checklist."""
    write_text(assessment_dir / "pr-description.md", "\n".join(render_pr_body(out, repo, finding, record)) + "\n")
    write_text(assessment_dir / "reviewer-checklist.md", "\n".join(render_reviewer_checklist(gates)) + "\n")


def write_status_and_index(
    assessment_dir: Path, out: Path, finding: dict[str, Any], snapshot: dict[str, Any], gates: list[dict[str, Any]]
) -> None:
    """Write machine-readable state and the reviewer-facing evidence index."""
    missing = [gate["name"] for gate in gates if gate["status"] != "pass"]
    status = {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "finding_id": finding.get("id"),
        "demo_ready": not missing,
        "passed_gates": len(gates) - len(missing),
        "total_gates": len(gates),
        "missing": missing,
        "gates": gates,
    }
    write_json(assessment_dir / "repository-state.json", snapshot)
    write_json(assessment_dir / "status.json", status)

    rows = ["| Gate | Status | Evidence |", "| --- | --- | --- |"]
    for gate in gates:
        marker = "PASS" if gate["status"] == "pass" else "MISSING"
        rows.append(f"| {gate['name']} | {marker} | {markdown_link(str(gate.get('artifact') or ''), out)} |")
    summary = [
        "# Assessment evidence readiness",
        "",
        f"**Finding:** {finding.get('id')} — {finding.get('title', '')}",
        f"**Status:** {'DEMO READY' if not missing else 'INCOMPLETE'} ({len(gates) - len(missing)}/{len(gates)} gates)",
        "",
        *rows,
    ]
    if missing:
        summary.extend(["", "## Next actions", "", *[f"- Complete: {item}." for item in missing]])
    write_text(assessment_dir / "evidence-index.md", "\n".join(summary) + "\n")


def write_ai_brief(assessment_dir: Path, finding: dict[str, Any], record: dict[str, Any]) -> None:
    """Write the bounded remediation task consumed by the lead AI."""
    verification = record.get("verification", {})
    brief = [
        "# AI remediation brief",
        "",
        f"Remediate **{finding.get('id')} — {finding.get('title', '')}** in the authorized repository.",
        "",
        "## Evidence",
        "",
        f"- Location: `{finding.get('file', '')}:{finding.get('line', '')}`",
        f"- Attack path: {finding.get('attack_path') or finding.get('description') or ''}",
        f"- Suggested fix: {finding.get('fix') or 'Derive the smallest server-side root-cause fix.'}",
        f"- Pre-fix proof: `{verification.get('pre_fix_artifact') or '(missing)'}`",
        "",
        "## Required autonomous work",
        "",
        "1. Read the vulnerable code and adjacent tests before editing.",
        "2. Convert the reproduction into a deterministic security regression test.",
        "3. Run it against the vulnerable baseline and retain the failing/pre-fix result.",
        "4. Implement the smallest server-side root-cause fix.",
        "5. Replay the identical test after the fix and retain the result.",
        "6. Add positive tests proving legitimate behavior remains available.",
        "7. Run the affected module suite and existing repository checks.",
        "8. Commit the fix atomically, then rerun `odoo-review-assessment` with the resulting evidence.",
        "",
        "Do not push, open a PR, contact external services, or use production data without explicit authorization.",
    ]
    write_text(assessment_dir / "ai-remediation-brief.md", "\n".join(brief) + "\n")


def write_demo_runbook(assessment_dir: Path, finding: dict[str, Any], record: dict[str, Any]) -> None:
    """Write a vendor-neutral timed AppSec and SDLC assessment runbook."""
    verification = record.get("verification", {})
    runbook = [
        "# 60-minute AppSec & SDLC demo runbook",
        "",
        "- **00:00–03:00:** Scope, customer problem, authorized repository, and whether the finding was discovered or seeded.",
        "- **03:00–13:00:** Architecture, trust boundaries, data movement, access, credentials, retention, and historical backlog.",
        "- **13:00–16:00:** Runtime guardrails, one blocked action, and stop/cancel control.",
        "- **16:00–19:00:** Follow-up block 1.",
        f"- **19:00–26:00:** Open `{finding.get('id')}` in `findings.json`, then navigate to `{finding.get('file')}:{finding.get('line')}`.",
        f"- **26:00–34:00:** Replay `{verification.get('pre_fix_artifact') or '(pre-fix proof pending)'}` and explain attacker prerequisites and false-positive checks.",
        "- **34:00–38:00:** Follow-up block 2.",
        f"- **38:00–46:00:** Show `remediation.diff`; run `{verification.get('test_command') or '(verification command pending)'}`; compare pre-fix, post-fix, and legitimate behavior.",
        "- **46:00–49:00:** Follow-up block 3.",
        "- **49:00–53:00:** Show finding/ticket → patch/PR → CI → release ownership and one honestly measured outcome.",
        "- **53:00–55:00:** Open `evidence-index.md`, disclose limitations, and assign remaining checks.",
        "- **55:00–60:00:** Reviewer questions and feedback.",
        "",
        "Keep recorded outputs available as a fallback; do not spend assessment time rebuilding the environment.",
    ]
    write_text(assessment_dir / "demo-runbook.md", "\n".join(runbook) + "\n")


def write_outputs(
    assessment_dir: Path,
    out: Path,
    repo: Path,
    finding: dict[str, Any],
    record: dict[str, Any],
    snapshot: dict[str, Any],
    gates: list[dict[str, Any]],
) -> None:
    """Write machine-readable status plus AI and reviewer-facing documents."""
    write_status_and_index(assessment_dir, out, finding, snapshot, gates)
    write_ai_brief(assessment_dir, finding, record)
    write_demo_runbook(assessment_dir, finding, record)
    write_pr_materials(assessment_dir, out, repo, finding, record, gates)


def load_inputs(args: argparse.Namespace) -> tuple[Path, dict[str, Any], Path]:
    """Load the audit document and resolve its target repository."""
    out = Path(args.out).expanduser().resolve()
    findings_path = out / "findings.json"
    if not findings_path.exists():
        raise FileNotFoundError(f"{findings_path} not found")
    findings_doc = read_json(findings_path)
    target = findings_doc.get("target") if isinstance(findings_doc.get("target"), dict) else {}
    repo_value = args.repo or target.get("repo") or out.parent
    repo = Path(repo_value).expanduser().resolve()
    if not repo.exists():
        raise FileNotFoundError(f"repository not found: {repo}")
    return out, findings_doc, repo


def load_record(
    record_path: Path,
    finding: dict[str, Any],
    findings_doc: dict[str, Any],
    snapshot: dict[str, Any],
    discovered: list[Path],
) -> dict[str, Any]:
    """Load a matching assessment record or create its initial state."""
    if not record_path.exists():
        return initial_record(finding, findings_doc, snapshot, discovered)
    record = read_json(record_path)
    if record.get("finding_id") != finding.get("id"):
        raise ValueError(
            f"existing record is for {record.get('finding_id')}; use a separate OUT directory "
            "or remove the stale assessment record"
        )
    return record


def main(argv: list[str] | None = None) -> int:
    """Create or refresh an assessment evidence packet."""
    args = parse_args(argv)
    try:
        out, findings_doc, repo = load_inputs(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"assessment: cannot load inputs: {exc}", file=sys.stderr)
        return 2
    assessment_dir = out / "assessment"
    assessment_dir.mkdir(parents=True, exist_ok=True)
    try:
        snapshot = capture_repository(repo, assessment_dir)
        raw_findings = findings_doc.get("findings", [])
        findings = [item for item in raw_findings if isinstance(item, dict)]
        finding = select_finding(findings, args.finding, out, repo)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"assessment: preparation failed: {exc}", file=sys.stderr)
        return 2

    discovered = [
        resolved for ref in artifact_references(finding) if (resolved := resolve_artifact(ref, out, repo)) is not None
    ]
    record_path = assessment_dir / "record.json"
    try:
        record = load_record(record_path, finding, findings_doc, snapshot, discovered)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"assessment: cannot load record: {exc}", file=sys.stderr)
        return 2
    update_record(record, args)
    capture_remediation_diff(record, repo, assessment_dir)
    write_json(record_path, record)
    gates = build_gates(finding, record, out, repo, snapshot)
    write_outputs(assessment_dir, out, repo, finding, record, snapshot, gates)

    missing = [gate["name"] for gate in gates if gate["status"] != "pass"]
    print(f"Assessment packet: {assessment_dir}")
    print(f"Finding: {finding.get('id')} — {finding.get('title', '')}")
    print(f"Readiness: {len(gates) - len(missing)}/{len(gates)} gates")
    if missing:
        print("Missing: " + ", ".join(missing))
    return 4 if args.strict and missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
