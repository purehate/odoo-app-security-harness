"""Tests for the LLM lanes (Qwen triage, Codex hunters, ensemble, remediation).

The lanes shell out to the ``ollama`` and ``codex`` CLIs. These tests place fake
executables on ``PATH`` so the real subprocess wiring, command construction, and
output capture are exercised end to end without contacting a live model.
"""

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
from argparse import Namespace
from pathlib import Path

import pytest

from odoo_security_harness.daily_workflow import create_run, load_config
from odoo_security_harness.scripts.odoo_security_daily import run_remediator

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_SCRIPT = REPO_ROOT / "skills" / "odoo-code-review" / "scripts" / "odoo-review-run"

# Fake ``ollama`` prints a recognizable hint to stdout, matching ``ollama run``.
OLLAMA_SHIM = """#!/usr/bin/env python3
import sys

sys.stdout.write("QWEN_HINT_LINE\\n")
"""

# Fake ``codex exec`` writes the final report to its ``-o`` target and emits
# unrelated progress noise on stdout, matching real Codex behavior.
CODEX_SHIM = """#!/usr/bin/env python3
import json
import os
import sys

argv = sys.argv[1:]
argv_log = os.environ.get("FAKE_CODEX_ARGV")
if argv_log:
    with open(argv_log, "w", encoding="utf-8") as handle:
        json.dump(argv, handle)
if "-o" in argv:
    target = argv[argv.index("-o") + 1]
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("CODEX_FINAL_REPORT\\n")
if "--output-last-message" in argv:
    target = argv[argv.index("--output-last-message") + 1]
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump({"status": "remediated"}, handle)
    # Consume the stdin prompt so the parent write cannot block.
    sys.stdin.read()
sys.stdout.write("CODEX_PROGRESS_NOISE\\n")
"""


def _write_executable(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture()
def runner_namespace() -> dict:
    return runpy.run_path(str(RUN_SCRIPT), run_name="__test_llm_lanes__")


@pytest.fixture()
def fake_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir, "ollama", OLLAMA_SHIM)
    _write_executable(bin_dir, "codex", CODEX_SHIM)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return bin_dir


def _qwen_args() -> Namespace:
    return Namespace(no_local_qwen=False, local_model="qwen3:0.6b")


def _codex_args(**overrides: object) -> Namespace:
    base = {
        "no_codex": False,
        "codex_mode": "run",
        "codex_model": "gpt-5.3-codex",
        "codex_budget": "normal",
        "ensemble": "off",
        "ensemble_passes": 0,
        "preflight_only": False,
    }
    base.update(overrides)
    return Namespace(**base)


class TestRunQwen:
    """Phase 1.5 local Qwen triage lane."""

    def test_invokes_ollama_and_captures_notes(self, runner_namespace: dict, fake_tools: Path, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        log = out / "logs" / "runner.log"
        log.parent.mkdir()

        record = runner_namespace["run_qwen"](_qwen_args(), repo, out, log)

        assert record["status"] == "completed"
        assert [entry["pass"] for entry in record["passes"]] == [
            "module-notes.md",
            "scanner-triage.md",
            "reject-candidates.md",
        ]
        for entry in record["passes"]:
            assert entry["returncode"] == 0
            assert entry["cmd"][:3] == ["ollama", "run", "qwen3:0.6b"]
        for filename in ("module-notes.md", "scanner-triage.md", "reject-candidates.md"):
            content = (out / "local-qwen" / filename).read_text(encoding="utf-8")
            assert "QWEN_HINT_LINE" in content

    def test_skips_when_ollama_missing(
        self, runner_namespace: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()
        monkeypatch.setenv("PATH", str(empty_bin))
        out = tmp_path / "out"
        out.mkdir()

        record = runner_namespace["run_qwen"](_qwen_args(), tmp_path, out, out / "runner.log")

        assert record == {"status": "skipped", "reason": "ollama missing"}

    def test_respects_no_local_qwen_flag(self, runner_namespace: dict, fake_tools: Path, tmp_path: Path) -> None:
        out = tmp_path / "out"
        out.mkdir()

        record = runner_namespace["run_qwen"](
            Namespace(no_local_qwen=True, local_model="qwen3:0.6b"),
            tmp_path,
            out,
            out / "runner.log",
        )

        assert record == {"status": "skipped", "reason": "--no-local-qwen"}


class TestRunCodex:
    """Phase 5 Codex hunter lane."""

    def test_builds_readonly_command_and_preserves_report(
        self, runner_namespace: dict, fake_tools: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        log = out / "logs" / "runner.log"
        log.parent.mkdir()
        hunters = runner_namespace["HUNTERS"]

        records = runner_namespace["run_codex"](_codex_args(), repo, out, log)

        assert len(records) == len(hunters)
        assert all(record["returncode"] == 0 for record in records)
        first = records[0]["cmd"]
        assert first[:2] == ["codex", "exec"]
        assert "-s" in first and first[first.index("-s") + 1] == "read-only"
        assert "-m" in first and first[first.index("-m") + 1] == "gpt-5.3-codex"
        assert "-C" in first and first[first.index("-C") + 1] == str(repo)
        assert "--skip-git-repo-check" in first
        # Every hunter artifact must contain the model's final report, not the
        # progress noise Codex writes to stdout.
        for record in records:
            report = Path(record["output"])
            assert report.exists()
            assert "CODEX_FINAL_REPORT" in report.read_text(encoding="utf-8")

    def test_prepare_mode_writes_prompts_without_invoking_codex(
        self, runner_namespace: dict, fake_tools: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        log = out / "logs" / "runner.log"
        log.parent.mkdir()

        records = runner_namespace["run_codex"](_codex_args(codex_mode="prepare"), repo, out, log)

        assert all(record["status"] == "prepared" for record in records)
        assert all(Path(record["prompt"]).exists() for record in records)
        assert all(not Path(record["output"]).exists() for record in records)

    def test_skips_when_codex_missing(
        self, runner_namespace: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty_bin = tmp_path / "empty-bin"
        empty_bin.mkdir()
        monkeypatch.setenv("PATH", str(empty_bin))
        out = tmp_path / "out"
        out.mkdir()

        records = runner_namespace["run_codex"](_codex_args(), tmp_path, out, out / "runner.log")

        assert records == [{"status": "skipped", "reason": "codex missing"}]


class TestRunEnsemble:
    """Ensemble recall lane."""

    def test_runs_requested_passes_and_preserves_reports(
        self, runner_namespace: dict, fake_tools: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        log = out / "logs" / "runner.log"
        log.parent.mkdir()

        records = runner_namespace["run_ensemble"](_codex_args(ensemble="cheap", ensemble_passes=2), repo, out, log)

        assert len(records) == 2
        assert all(record["returncode"] == 0 for record in records)
        for record in records:
            report = Path(record["output"])
            assert report.exists()
            assert "CODEX_FINAL_REPORT" in report.read_text(encoding="utf-8")

    def test_disabled_ensemble_is_skipped(self, runner_namespace: dict, fake_tools: Path, tmp_path: Path) -> None:
        out = tmp_path / "out"
        out.mkdir()

        records = runner_namespace["run_ensemble"](_codex_args(ensemble="off"), tmp_path, out, out / "runner.log")

        assert records == [{"status": "skipped", "reason": "--ensemble off"}]


class TestRunRemediator:
    """Daily remediation lane in odoo_security_daily."""

    def _daily_run(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "tests@example.invalid"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Tests"],
            check=True,
            capture_output=True,
        )
        (repo / "README.md").write_text("test\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "test"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/qa", "HEAD"],
            check=True,
            capture_output=True,
        )
        config_path = tmp_path / "daily.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[workflow]",
                    f'repo = "{repo}"',
                    'external_url = "https://qa.example.test"',
                    'include_paths = ["/quoteengine"]',
                    'base_branch = "main"',
                    "timeout_seconds = 60",
                    "",
                    "[commands]",
                    'verify = ["python -m pytest tests/security"]',
                    'build = ["python -m compileall addon"]',
                    'screenshots = ["capture-security-screenshot"]',
                ]
            ),
            encoding="utf-8",
        )
        config = load_config(config_path)
        run = create_run(config, tmp_path / "run")
        # create_run only records the worktree path; create it so the codex
        # subprocess has a valid working directory.
        run.worktree.mkdir(parents=True, exist_ok=True)
        return run

    def test_invokes_codex_with_workspace_schema(
        self,
        fake_tools: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        run = self._daily_run(tmp_path)
        argv_log = tmp_path / "argv.json"
        monkeypatch.setenv("FAKE_CODEX_ARGV", str(argv_log))
        prompt = run.output_dir / "agent" / "prompt.txt"
        prompt.parent.mkdir(parents=True, exist_ok=True)
        prompt.write_text("fix the bug", encoding="utf-8")
        schema = run.output_dir / "agent" / "schema.json"
        schema.write_text("{}", encoding="utf-8")

        result = run_remediator(run, prompt, schema)

        assert result == {"status": "remediated"}
        argv = json.loads(argv_log.read_text(encoding="utf-8"))
        assert argv[:2] == ["exec", "--cd"]
        assert "--sandbox" in argv and argv[argv.index("--sandbox") + 1] == "workspace-write"
        assert "--approve-for-me" in argv
        assert "--output-schema" in argv and argv[argv.index("--output-schema") + 1] == str(schema)
        assert "--output-last-message" in argv
