"""One-command daily scan, remediation, integration, and promotion workflow."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from odoo_security_harness.daily_workflow import (
    DEFAULT_ORCA_CHECKS,
    DailyRun,
    DailyWorkflowError,
    compare_finding_reports,
    create_run,
    git_output,
    load_config,
    run_process,
    sha256_file,
    write_json,
    write_text,
)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the daily controller command line."""
    parser = argparse.ArgumentParser(
        description="Run outside-in and source-aware scans, prepare a fix, and gate delivery."
    )
    parser.add_argument("--config", required=True, help="Daily workflow TOML configuration")
    parser.add_argument(
        "--mode",
        choices=("plan", "scan", "remediate", "deliver"),
        default="plan",
        help="plan is read-only; deliver may push, merge to integration, and open a main PR",
    )
    parser.add_argument("--out", help="Run output directory")
    return parser.parse_args(argv)


def _run_git(run: DailyRun, name: str, *args: str) -> None:
    run_process(
        ["git", "-C", str(run.config.repo), *args],
        cwd=run.config.repo,
        log_path=run.output_dir / "logs" / f"git-{name}.log",
        timeout=run.config.timeout_seconds,
    )


def prepare_worktree(run: DailyRun) -> None:
    """Create a detached worktree and a fresh remediation branch."""
    if run.worktree.exists():
        raise DailyWorkflowError(f"worktree already exists: {run.worktree}")
    run.output_dir.mkdir(parents=True, exist_ok=False)
    _run_git(
        run,
        "worktree",
        "worktree",
        "add",
        "--detach",
        str(run.worktree),
        f"{run.config.remote}/{run.integration_branch}",
    )
    run_process(
        ["git", "switch", "-c", run.remediation_branch],
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / "git-branch.log",
        timeout=60,
    )


def _orca_command(run: DailyRun, phase: str) -> tuple[list[str], Path]:
    output = run.output_dir / "external" / phase
    command = [
        *run.config.orca_command,
        "--url",
        run.config.external_url,
        "--checks",
        DEFAULT_ORCA_CHECKS,
        "--crawl",
        "--crawl-max-pages",
        str(run.config.crawl_max_pages),
        "--crawl-depth",
        str(run.config.crawl_depth),
        "--rate",
        str(run.config.rate),
        "--threads",
        "1",
        "--verify-ssl",
        "--format",
        "json",
        "--output",
        str(output / "report.json"),
        "--evidence-dir",
        str(output / "evidence"),
    ]
    for include_path in run.config.include_paths:
        command.extend(["--include-path", include_path])
    if run.config.use_ai:
        command.append("--ai")
    return command, output


def run_external_scan(run: DailyRun, phase: str) -> Path:
    """Run one bounded ORCA scan and retain its complete evidence directory."""
    command, output = _orca_command(run, phase)
    output.mkdir(parents=True, exist_ok=True)
    run_process(
        command,
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / f"orca-{phase}.log",
        timeout=run.config.timeout_seconds,
        acceptable_codes=(0, 1, 2, 3),
    )
    report = output / "report.json"
    if not report.exists():
        raise DailyWorkflowError(f"ORCA did not create {report}")
    return report


def run_internal_scan(run: DailyRun, phase: str) -> Path:
    """Run the deterministic source scanner against the isolated worktree."""
    output = run.output_dir / "internal" / phase
    command = [
        *run.config.internal_command,
        str(run.worktree),
        "--out",
        str(output),
        "--pocs",
        "--base-url",
        run.config.external_url,
        "--fail-on",
        "none",
    ]
    run_process(
        command,
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / f"internal-scan-{phase}.log",
        timeout=run.config.timeout_seconds,
    )
    report = output / "deep-scan-findings.json"
    if not report.exists():
        raise DailyWorkflowError(f"internal scanner did not create {report}")
    return report


def run_screenshots(run: DailyRun, phase: str) -> list[Path]:
    """Run configured screenshot commands and require actual image artifacts."""
    screenshot_dir = run.output_dir / "screenshots" / phase
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "SECURITY_EVIDENCE_PHASE": phase,
        "SECURITY_EVIDENCE_DIR": str(screenshot_dir),
        "SECURITY_TARGET_URL": run.config.external_url,
    }
    for index, command in enumerate(run.config.screenshot_commands, start=1):
        run_process(
            command,
            cwd=run.worktree,
            log_path=run.output_dir / "logs" / f"screenshot-{phase}-{index}.log",
            timeout=run.config.timeout_seconds,
            env=env,
        )
    images = sorted(
        path
        for path in screenshot_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}
    )
    if run.config.require_screenshots and not images:
        raise DailyWorkflowError(f"screenshot evidence is required but none was created for phase {phase!r}")
    return images


def collect_pre_fix_evidence(run: DailyRun) -> tuple[Path, Path, list[Path]]:
    """Collect independent pre-fix evidence concurrently."""
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="security-evidence") as pool:
        external_future = pool.submit(run_external_scan, run, "pre-fix")
        internal_future = pool.submit(run_internal_scan, run, "pre-fix")
        screenshots_future = pool.submit(run_screenshots, run, "pre-fix")
        return (
            external_future.result(),
            internal_future.result(),
            screenshots_future.result(),
        )


def collect_post_integration_evidence(run: DailyRun) -> tuple[Path, list[Path]]:
    """Collect independent post-deploy outside-in evidence concurrently."""
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="security-evidence") as pool:
        external_future = pool.submit(run_external_scan, run, "post-integration")
        screenshots_future = pool.submit(run_screenshots, run, "post-integration")
        return external_future.result(), screenshots_future.result()


def write_agent_contract(run: DailyRun, internal_report: Path, external_report: Path) -> tuple[Path, Path]:
    """Write a bounded remediation prompt and structured response schema."""
    prompt = run.output_dir / "agent" / "prompt.md"
    schema = run.output_dir / "agent" / "result-schema.json"
    write_text(
        prompt,
        "\n".join(
            [
                "You are remediating one high-confidence security issue in an authorized Odoo repository.",
                "Read AGENTS.md and repository instructions before editing.",
                f"Internal findings: {internal_report}",
                f"External findings: {external_report}",
                "Correlate both reports to source. Ignore inventory-only and unsupported model conclusions.",
                "Select the highest-severity reproducible issue that is fixable in this repository.",
                "If no issue meets that bar, make no code changes and report no_action.",
                "Otherwise: reproduce it in a regression test, implement the smallest root-cause fix,",
                "run focused tests, and preserve legitimate behavior with positive/negative coverage.",
                "Do not commit, push, open PRs, merge branches, modify scan artifacts, or contact production systems.",
                "Do not claim verification that you did not execute.",
            ]
        )
        + "\n",
    )
    write_json(
        schema,
        {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "status",
                "finding_ids",
                "summary",
                "root_cause",
                "changed_files",
                "tests_run",
                "remaining_uncertainty",
            ],
            "properties": {
                "status": {"enum": ["fixed", "no_action", "blocked"]},
                "finding_ids": {"type": "array", "items": {"type": "string"}},
                "summary": {"type": "string"},
                "root_cause": {"type": "string"},
                "changed_files": {"type": "array", "items": {"type": "string"}},
                "tests_run": {"type": "array", "items": {"type": "string"}},
                "remaining_uncertainty": {"type": "array", "items": {"type": "string"}},
            },
        },
    )
    return prompt, schema


def run_remediator(run: DailyRun, prompt: Path, schema: Path) -> dict[str, Any]:
    """Run Codex in the isolated worktree and validate its structured outcome."""
    result_path = run.output_dir / "agent" / "result.json"
    command = [
        "codex",
        "exec",
        "--cd",
        str(run.worktree),
        "--sandbox",
        "workspace-write",
        "--approve-for-me",
        "--output-schema",
        str(schema),
        "--output-last-message",
        str(result_path),
        "-",
    ]
    run_process(
        command,
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / "codex-remediation.log",
        timeout=run.config.timeout_seconds,
        stdin_path=prompt,
    )
    with result_path.open("r", encoding="utf-8") as handle:
        result = json.load(handle)
    if not isinstance(result, dict):
        raise DailyWorkflowError("Codex result must be a JSON object")
    return result


def run_verification(run: DailyRun) -> list[Path]:
    """Run every configured focused test and build command."""
    commands = (*run.config.verify_commands, *run.config.build_commands)
    if not commands:
        raise DailyWorkflowError("at least one verify or build command is required")
    logs = []
    for index, command in enumerate(commands, start=1):
        log = run.output_dir / "verification" / f"command-{index}.log"
        run_process(
            command,
            cwd=run.worktree,
            log_path=log,
            timeout=run.config.timeout_seconds,
        )
        logs.append(log)
    return logs


def commit_remediation(run: DailyRun, agent_result: dict[str, Any]) -> str:
    """Commit a non-empty focused remediation after all local gates pass."""
    status = str(agent_result.get("status", ""))
    changed = git_output(run.worktree, "status", "--porcelain=v1", "--untracked-files=all")
    if status == "no_action" and not changed:
        return ""
    if status != "fixed":
        raise DailyWorkflowError(f"remediator status is {status!r}; refusing delivery")
    if not changed:
        raise DailyWorkflowError("remediator reported a fix but produced no changes")
    run_process(
        ["git", "add", "--all"],
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / "git-add.log",
        timeout=60,
    )
    run_process(
        ["git", "commit", "-m", "fix(security): remediate verified finding"],
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / "git-commit.log",
        timeout=120,
    )
    return git_output(run.worktree, "rev-parse", "HEAD")


def _artifact_manifest(run: DailyRun) -> dict[str, Any]:
    files = []
    for path in sorted(run.output_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.json" and run.worktree not in path.parents:
            files.append(
                {
                    "path": str(path.relative_to(run.output_dir)),
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                }
            )
    return {"schema_version": 1, "artifacts": files}


def write_pr_body(run: DailyRun, agent_result: dict[str, Any], patched_commit: str) -> Path:
    """Render the self-contained human promotion review body."""
    run_url = ""
    if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
        run_url = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
            f"/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        )
    findings = ", ".join(str(item) for item in agent_result.get("finding_ids", [])) or "none"
    body = run.output_dir / "pr-body.md"
    write_text(
        body,
        "\n".join(
            [
                "# Security remediation promotion",
                "",
                "## Finding and root cause",
                "",
                str(agent_result.get("summary", "")),
                "",
                f"- Finding IDs: `{findings}`",
                f"- Root cause: {agent_result.get('root_cause', '')}",
                f"- Patched commit: `{patched_commit}`",
                f"- Integration branch: `{run.integration_branch}`",
                "",
                "## Independent evidence",
                "",
                "- Outside-in ORCA scans: pre-fix and post-integration-deploy packets",
                "- Inside-out source scan: deterministic findings and generated PoCs",
                "- Finding deltas: `internal/finding-delta.json` and `external/finding-delta.json`",
                "- Verification: focused tests and configured build commands",
                "- UI evidence: before/after screenshots when required",
                f"- CI/evidence artifacts: {run_url or 'attached to the automation run for this PR'}",
                "- SHA-256 manifest: `manifest.json` in the run artifact",
                "",
                "## Human merge gate",
                "",
                "- [ ] The source finding maps to the changed code.",
                "- [ ] The same security invariant fails before and passes after the fix.",
                "- [ ] Legitimate behavior and regression coverage pass.",
                "- [ ] The integration build/deploy and post-fix ORCA scan are green.",
                "- [ ] Remaining uncertainty is acceptable.",
                "",
                "This automation never merges the promotion PR to the protected branch.",
            ]
        )
        + "\n",
    )
    return body


def _gh_output(run: DailyRun, name: str, args: Sequence[str]) -> str:
    log = run.output_dir / "logs" / f"gh-{name}.log"
    result = subprocess.run(
        ["gh", *args],
        cwd=run.worktree,
        capture_output=True,
        text=True,
        check=False,
        timeout=run.config.timeout_seconds,
    )
    write_text(log, result.stdout + result.stderr)
    if result.returncode != 0:
        raise DailyWorkflowError(f"gh {name} failed; see {log}")
    return result.stdout.strip()


def deliver_to_integration(run: DailyRun, body: Path) -> str:
    """Push the remediation, require green checks, and merge only to integration."""
    run_process(
        ["git", "push", "--set-upstream", run.config.remote, run.remediation_branch],
        cwd=run.worktree,
        log_path=run.output_dir / "logs" / "git-push.log",
        timeout=run.config.timeout_seconds,
    )
    pr_url = _gh_output(
        run,
        "create-integration-pr",
        [
            "pr",
            "create",
            "--base",
            run.integration_branch,
            "--head",
            run.remediation_branch,
            "--title",
            "fix(security): daily verified remediation",
            "--body-file",
            str(body),
        ],
    ).splitlines()[-1]
    _gh_output(run, "integration-checks", ["pr", "checks", pr_url, "--watch", "--fail-fast"])
    _gh_output(run, "merge-integration", ["pr", "merge", pr_url, "--squash", "--delete-branch"])
    return pr_url


def open_promotion_pr(run: DailyRun, body: Path) -> str:
    """Open or reuse an integration-to-main PR without merging it."""
    existing = _gh_output(
        run,
        "find-promotion-pr",
        [
            "pr",
            "list",
            "--base",
            run.config.base_branch,
            "--head",
            run.integration_branch,
            "--state",
            "open",
            "--json",
            "url",
            "--jq",
            ".[0].url // empty",
        ],
    )
    if existing:
        _gh_output(run, "update-promotion-pr", ["pr", "edit", existing, "--body-file", str(body)])
        return existing
    return _gh_output(
        run,
        "create-promotion-pr",
        [
            "pr",
            "create",
            "--base",
            run.config.base_branch,
            "--head",
            run.integration_branch,
            "--title",
            "fix(security): promote verified remediation",
            "--body-file",
            str(body),
        ],
    ).splitlines()[-1]


def write_plan(run: DailyRun, mode: str) -> None:
    """Write a reviewable plan before any worktree or network mutation."""
    plan = {
        "mode": mode,
        "repo": str(run.config.repo),
        "external_url": run.config.external_url,
        "include_paths": list(run.config.include_paths),
        "integration_branch": run.integration_branch,
        "protected_branch": run.config.base_branch,
        "remediation_branch": run.remediation_branch,
        "worktree": str(run.worktree),
        "will_push": mode == "deliver",
        "will_merge_to_integration": mode == "deliver",
        "will_merge_to_protected_branch": False,
    }
    write_json(run.output_dir / "plan.json", plan)


def execute(run: DailyRun, mode: str) -> dict[str, Any]:
    """Execute the requested workflow state transitions."""
    if mode == "plan":
        run.output_dir.mkdir(parents=True, exist_ok=False)
        write_plan(run, mode)
        return {"status": "planned", "output_dir": str(run.output_dir)}

    prepare_worktree(run)
    write_plan(run, mode)
    pre_external, internal, before_images = collect_pre_fix_evidence(run)
    if mode == "scan":
        write_json(run.output_dir / "manifest.json", _artifact_manifest(run))
        return {"status": "scanned", "output_dir": str(run.output_dir)}

    prompt, schema = write_agent_contract(run, internal, pre_external)
    agent_result = run_remediator(run, prompt, schema)
    if agent_result.get("status") == "no_action":
        write_json(run.output_dir / "manifest.json", _artifact_manifest(run))
        return {"status": "no_action", "output_dir": str(run.output_dir)}
    post_internal = run_internal_scan(run, "post-fix")
    write_json(
        run.output_dir / "internal" / "finding-delta.json",
        compare_finding_reports(internal, post_internal),
    )
    verification_logs = run_verification(run)
    patched_commit = commit_remediation(run, agent_result)
    body = write_pr_body(run, agent_result, patched_commit)
    if mode == "remediate":
        write_json(run.output_dir / "manifest.json", _artifact_manifest(run))
        return {
            "status": "remediated_locally",
            "patched_commit": patched_commit,
            "output_dir": str(run.output_dir),
        }

    integration_pr = deliver_to_integration(run, body)
    post_external, after_images = collect_post_integration_evidence(run)
    write_json(
        run.output_dir / "external" / "finding-delta.json",
        compare_finding_reports(pre_external, post_external),
    )
    body = write_pr_body(run, agent_result, patched_commit)
    promotion_pr = open_promotion_pr(run, body)
    result = {
        "status": "awaiting_human_main_merge",
        "patched_commit": patched_commit,
        "integration_pr": integration_pr,
        "promotion_pr": promotion_pr,
        "pre_external": str(pre_external),
        "post_external": str(post_external),
        "pre_internal": str(internal),
        "post_internal": str(post_internal),
        "verification_logs": [str(path) for path in verification_logs],
        "before_screenshots": [str(path) for path in before_images],
        "after_screenshots": [str(path) for path in after_images],
        "output_dir": str(run.output_dir),
    }
    write_json(run.output_dir / "result.json", result)
    write_json(run.output_dir / "manifest.json", _artifact_manifest(run))
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run the combined daily security controller."""
    args = parse_args(argv)
    try:
        config_path = Path(args.config).expanduser().resolve()
        config = load_config(config_path)
        if not config.repo.exists():
            raise DailyWorkflowError(f"repository not found: {config.repo}")
        output = (
            Path(args.out).expanduser().resolve()
            if args.out
            else config.repo.parent / "security-daily-runs" / os.urandom(8).hex()
        )
        run = create_run(config, output)
        result = execute(run, args.mode)
    except (DailyWorkflowError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"odoo-security-daily: {exc}", file=sys.stderr)
        return 4
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
