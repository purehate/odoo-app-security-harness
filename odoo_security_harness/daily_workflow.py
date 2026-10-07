"""Daily outside-in plus source-aware remediation workflow primitives."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11
    import tomli as tomllib


INTEGRATION_BRANCH_CANDIDATES = ("develop", "dev", "staging", "stage", "qa", "test")
PROTECTED_BRANCHES = {"main", "master"}
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
DEFAULT_ORCA_CHECKS = (
    "recon,endpoints,misconfig,sensitive_files,xss,idor,auth_issues,"
    "disclosure,rpc_surface,cve,reports,lfi,exposure,source_leak,page,crawler"
)


class DailyWorkflowError(RuntimeError):
    """Raised when a daily workflow safety or completeness gate fails."""


@dataclass(frozen=True)
class DailyConfig:
    """Validated configuration for one daily remediation run."""

    repo: Path
    external_url: str
    include_paths: tuple[str, ...]
    integration_branch: str | None = None
    base_branch: str = "main"
    remote: str = "origin"
    orca_command: tuple[str, ...] = ("orca",)
    internal_command: tuple[str, ...] = ("odoo-deep-scan",)
    verify_commands: tuple[tuple[str, ...], ...] = ()
    build_commands: tuple[tuple[str, ...], ...] = ()
    screenshot_commands: tuple[tuple[str, ...], ...] = ()
    require_screenshots: bool = True
    use_ai: bool = True
    rate: float = 1.0
    crawl_max_pages: int = 50
    crawl_depth: int = 2
    timeout_seconds: int = 3600


@dataclass
class DailyRun:
    """Resolved paths and state for one controller invocation."""

    config: DailyConfig
    output_dir: Path
    integration_branch: str
    remediation_branch: str
    worktree: Path
    evidence: dict[str, Any] = field(default_factory=dict)


def _string_list(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DailyWorkflowError(f"{field_name} must be an array of strings")
    return tuple(value)


def _commands(value: Any, field_name: str) -> tuple[tuple[str, ...], ...]:
    commands = _string_list(value, field_name)
    parsed = tuple(tuple(shlex.split(command)) for command in commands)
    if any(not command for command in parsed):
        raise DailyWorkflowError(f"{field_name} cannot contain an empty command")
    return parsed


def load_config(path: Path) -> DailyConfig:
    """Load and validate a daily workflow TOML file."""
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    if not isinstance(raw, dict):
        raise DailyWorkflowError("configuration root must be a table")
    workflow = raw.get("workflow", raw)
    if not isinstance(workflow, dict):
        raise DailyWorkflowError("workflow must be a table")

    repo_value = workflow.get("repo")
    external_url = workflow.get("external_url")
    if not isinstance(repo_value, str) or not repo_value.strip():
        raise DailyWorkflowError("workflow.repo is required")
    if not isinstance(external_url, str) or not external_url.strip():
        raise DailyWorkflowError("workflow.external_url is required")
    repo = Path(repo_value).expanduser().resolve()
    parsed_url = urlparse(external_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise DailyWorkflowError("workflow.external_url must be an HTTP(S) URL")

    include_paths = _string_list(workflow.get("include_paths"), "workflow.include_paths")
    if not include_paths:
        include_paths = ("/",)
    for include_path in include_paths:
        parsed_path = urlparse(include_path)
        if not include_path.startswith("/") or parsed_path.scheme or parsed_path.netloc or ".." in parsed_path.path:
            raise DailyWorkflowError(f"unsafe same-origin include path: {include_path!r}")

    tools = raw.get("tools", {})
    commands = raw.get("commands", {})
    evidence = raw.get("evidence", {})
    if not all(isinstance(table, dict) for table in (tools, commands, evidence)):
        raise DailyWorkflowError("tools, commands, and evidence must be tables")

    config = DailyConfig(
        repo=repo,
        external_url=external_url.rstrip("/"),
        include_paths=include_paths,
        integration_branch=_optional_string(workflow.get("integration_branch")),
        base_branch=str(workflow.get("base_branch", "main")),
        remote=str(workflow.get("remote", "origin")),
        orca_command=_command_value(tools.get("orca", "orca"), "tools.orca"),
        internal_command=_command_value(tools.get("internal", "odoo-deep-scan"), "tools.internal"),
        verify_commands=_commands(commands.get("verify"), "commands.verify"),
        build_commands=_commands(commands.get("build"), "commands.build"),
        screenshot_commands=_commands(commands.get("screenshots"), "commands.screenshots"),
        require_screenshots=bool(evidence.get("require_screenshots", True)),
        use_ai=bool(workflow.get("use_ai", True)),
        rate=float(workflow.get("rate", 1.0)),
        crawl_max_pages=int(workflow.get("crawl_max_pages", 50)),
        crawl_depth=int(workflow.get("crawl_depth", 2)),
        timeout_seconds=int(workflow.get("timeout_seconds", 3600)),
    )
    validate_config(config)
    return config


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DailyWorkflowError("optional branch values must be non-empty strings")
    return value.strip()


def _command_value(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value.strip():
        raise DailyWorkflowError(f"{field_name} must be a non-empty command string")
    command = tuple(shlex.split(value))
    if not command:
        raise DailyWorkflowError(f"{field_name} must be a non-empty command string")
    return command


def run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    log_path: Path,
    timeout: int,
    acceptable_codes: Iterable[int] = (0,),
    env: Mapping[str, str] | None = None,
    stdin_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command and retain its output without invoking a shell."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    with contextlib.ExitStack() as stack:
        stdin_handle = stack.enter_context(stdin_path.open("r", encoding="utf-8")) if stdin_path else None
        log_handle = stack.enter_context(log_path.open("w", encoding="utf-8"))
        result = subprocess.run(
            list(command),
            cwd=cwd,
            stdin=stdin_handle,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
            env=merged_env,
        )
    if result.returncode not in set(acceptable_codes):
        raise DailyWorkflowError(f"command failed with exit {result.returncode}; see {log_path}")
    return result


def git_output(repo: Path, *args: str) -> str:
    """Return output from a successful bounded Git query."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise DailyWorkflowError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def resolve_integration_branch(config: DailyConfig) -> str:
    """Resolve an existing remote non-production branch without guessing a new one."""
    candidates = (config.integration_branch,) if config.integration_branch else INTEGRATION_BRANCH_CANDIDATES
    for branch in candidates:
        validate_branch(branch)
        ref = f"refs/remotes/{config.remote}/{branch}"
        result = subprocess.run(
            ["git", "-C", str(config.repo), "show-ref", "--verify", "--quiet", ref],
            check=False,
            timeout=30,
        )
        if result.returncode == 0:
            return branch
    raise DailyWorkflowError("no existing integration branch found; configure workflow.integration_branch")


def validate_branch(branch: str) -> None:
    """Reject protected or syntactically unsafe branch names."""
    if branch in PROTECTED_BRANCHES:
        raise DailyWorkflowError(f"refusing to use protected branch {branch!r} as integration")
    if not BRANCH_PATTERN.fullmatch(branch) or ".." in branch or branch.endswith("/"):
        raise DailyWorkflowError(f"invalid branch name: {branch!r}")


def validate_config(config: DailyConfig) -> None:
    """Enforce controller safety bounds before any scan or Git mutation."""
    if config.base_branch not in PROTECTED_BRANCHES:
        raise DailyWorkflowError("workflow.base_branch must be main or master")
    if not BRANCH_PATTERN.fullmatch(config.remote):
        raise DailyWorkflowError("workflow.remote is invalid")
    if not 0 < config.rate <= 5:
        raise DailyWorkflowError("workflow.rate must be greater than 0 and no more than 5")
    if not 1 <= config.crawl_max_pages <= 200:
        raise DailyWorkflowError("workflow.crawl_max_pages must be between 1 and 200")
    if not 0 <= config.crawl_depth <= 5:
        raise DailyWorkflowError("workflow.crawl_depth must be between 0 and 5")
    if config.timeout_seconds < 60:
        raise DailyWorkflowError("workflow.timeout_seconds must be at least 60")
    if config.integration_branch:
        validate_branch(config.integration_branch)


def create_run(config: DailyConfig, output_dir: Path) -> DailyRun:
    """Resolve deterministic branches and paths for one isolated run."""
    integration = resolve_integration_branch(config)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    branch = f"security/daily-{stamp}"
    validate_branch(branch)
    return DailyRun(
        config=config,
        output_dir=output_dir.resolve(),
        integration_branch=integration,
        remediation_branch=branch,
        worktree=(output_dir / "worktree").resolve(),
    )


def sha256_file(path: Path) -> str:
    """Hash a file using bounded reads."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare_finding_reports(before_path: Path, after_path: Path) -> dict[str, Any]:
    """Return a stable resolved/persistent/new finding delta for two JSON reports."""
    before = _load_findings(before_path)
    after = _load_findings(after_path)
    before_by_key = {_finding_key(finding): finding for finding in before}
    after_by_key = {_finding_key(finding): finding for finding in after}
    before_keys = set(before_by_key)
    after_keys = set(after_by_key)
    return {
        "schema_version": 1,
        "before_report": str(before_path),
        "after_report": str(after_path),
        "before_count": len(before),
        "after_count": len(after),
        "resolved": _finding_summaries(before_by_key, before_keys - after_keys),
        "persistent": _finding_summaries(after_by_key, before_keys & after_keys),
        "new": _finding_summaries(after_by_key, after_keys - before_keys),
    }


def _load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    findings = value.get("findings") if isinstance(value, dict) else value
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise DailyWorkflowError(f"finding report has an unsupported schema: {path}")
    return findings


def _finding_key(finding: Mapping[str, Any]) -> str:
    for field_name in ("fingerprint", "id"):
        value = finding.get(field_name)
        if isinstance(value, str) and value:
            return f"{field_name}:{value}"
    raise DailyWorkflowError("every finding must contain a fingerprint or id")


def _finding_summaries(findings: Mapping[str, Mapping[str, Any]], keys: set[str]) -> list[dict[str, str]]:
    return [
        {
            "key": key,
            "id": str(findings[key].get("id", "")),
            "severity": str(findings[key].get("severity", "")),
            "title": str(findings[key].get("title", "")),
        }
        for key in sorted(keys)
    ]


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Write deterministic JSON through an explicit resource context."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_text(path: Path, value: str) -> None:
    """Write text through an explicit resource context."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(value)
