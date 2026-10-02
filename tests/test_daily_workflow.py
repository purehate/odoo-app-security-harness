"""Tests for the combined daily security controller."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from odoo_security_harness.daily_workflow import (
    DailyWorkflowError,
    compare_finding_reports,
    create_run,
    load_config,
    resolve_integration_branch,
)
from odoo_security_harness.scripts.odoo_security_daily import execute


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path, remote_branches: tuple[str, ...]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "Tests")
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "test")
    for branch in remote_branches:
        _git(repo, "update-ref", f"refs/remotes/origin/{branch}", "HEAD")
    return repo


def _config(path: Path, repo: Path, extra: str = "") -> Path:
    path.write_text(
        "\n".join(
            [
                "[workflow]",
                f'repo = "{repo}"',
                'external_url = "https://qa.example.test"',
                'include_paths = ["/quoteengine"]',
                'base_branch = "main"',
                "timeout_seconds = 60",
                extra,
                "",
                "[commands]",
                'verify = ["python -m pytest tests/security"]',
                'build = ["python -m compileall addon"]',
                'screenshots = ["capture-security-screenshot"]',
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_resolves_existing_integration_branch_by_preference(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ("staging", "develop"))
    config = load_config(_config(tmp_path / "daily.toml", repo))

    assert resolve_integration_branch(config) == "develop"


def test_explicit_protected_integration_branch_is_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ("main",))

    with pytest.raises(DailyWorkflowError, match="protected branch"):
        load_config(
            _config(
                tmp_path / "daily.toml",
                repo,
                'integration_branch = "main"',
            )
        )


def test_rate_above_odoo_policy_cap_is_rejected(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ("qa",))

    with pytest.raises(DailyWorkflowError, match="no more than 5"):
        load_config(_config(tmp_path / "daily.toml", repo, "rate = 5.1"))


def test_plan_is_reviewable_and_never_targets_main_for_merge(tmp_path: Path) -> None:
    repo = _repo(tmp_path, ("qa",))
    config = load_config(_config(tmp_path / "daily.toml", repo))
    output = tmp_path / "run"
    run = create_run(config, output)

    result = execute(run, "plan")

    with (output / "plan.json").open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    assert result["status"] == "planned"
    assert plan["integration_branch"] == "qa"
    assert plan["will_push"] is False
    assert plan["will_merge_to_protected_branch"] is False
    assert not run.worktree.exists()


def test_finding_delta_records_resolved_persistent_and_new(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "F-1", "fingerprint": "one", "severity": "high"},
                    {"id": "F-2", "fingerprint": "two", "severity": "low"},
                ]
            }
        ),
        encoding="utf-8",
    )
    after.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "F-2", "fingerprint": "two", "severity": "low"},
                    {"id": "F-3", "fingerprint": "three", "severity": "medium"},
                ]
            }
        ),
        encoding="utf-8",
    )

    delta = compare_finding_reports(before, after)

    assert [item["id"] for item in delta["resolved"]] == ["F-1"]
    assert [item["id"] for item in delta["persistent"]] == ["F-2"]
    assert [item["id"] for item in delta["new"]] == ["F-3"]
