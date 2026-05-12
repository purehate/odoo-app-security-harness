"""Tests for packaged console script entry points."""

from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
import zipfile
from email.parser import Parser
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import yaml


def test_project_console_script_modules_importable() -> None:
    """All pyproject console-script targets should resolve to importable callables."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    targets = pyproject["project"]["scripts"].values()

    for target in targets:
        module_name, attr = target.split(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attr))


def test_dev_extra_includes_wheel_builder_used_by_packaging_tests() -> None:
    """CI test installs should include the wheel builder exercised by packaging tests."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dev_dependencies = pyproject["project"]["optional-dependencies"]["dev"]

    assert any(dependency.startswith("hatchling") for dependency in dev_dependencies)


def test_wheel_includes_complete_skill_assets_for_wrappers_and_templates() -> None:
    """Wheel builds should include scripts, references, and CI templates."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    force_include = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    assert force_include["skills/odoo-code-review"] == "skills/odoo-code-review"
    assert Path("skills/odoo-code-review/scripts/odoo-review-run").exists()
    assert Path("skills/odoo-code-review/templates/github-action.yml").exists()
    assert Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").exists()
    assert Path("skills/odoo-code-review/references/workflow.md").exists()


def test_built_wheel_contains_skill_assets_and_executable_wrappers(tmp_path: Path) -> None:
    """The actual wheel artifact should ship the full skill command surface."""
    result = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    wheel = next(tmp_path.glob("*.whl"))
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packaged_commands = set(pyproject["project"]["scripts"])

    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
        wheel_commands = {Path(name).name for name in names if name.startswith("skills/odoo-code-review/scripts/")}

        assert "skills/odoo-code-review/SKILL.md" in names
        assert "skills/odoo-code-review/templates/github-action.yml" in names
        assert "skills/odoo-code-review/templates/deep-scan-github-action.yml" in names
        assert "skills/odoo-code-review/references/workflow.md" in names
        assert "skills/odoo-code-review/references/cwe-map.json" in names
        assert wheel_commands == packaged_commands
        assert not any("__pycache__" in name or name.endswith((".pyc", ".pyo")) for name in names)

        for command in packaged_commands:
            info = zf.getinfo(f"skills/odoo-code-review/scripts/{command}")
            mode = (info.external_attr >> 16) & 0o777
            assert mode & 0o111, command


def test_built_wheel_metadata_matches_project_runtime_contract(tmp_path: Path) -> None:
    """Wheel metadata should advertise dependencies and console scripts accurately."""
    result = subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    expected_dependencies = set(pyproject["project"]["dependencies"])
    expected_scripts = pyproject["project"]["scripts"]
    wheel = next(tmp_path.glob("*.whl"))

    with zipfile.ZipFile(wheel) as zf:
        metadata_name = next(name for name in zf.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(zf.read(metadata_name).decode("utf-8"))
        requires_dist = set(metadata.get_all("Requires-Dist", []))

        entry_points_name = next(name for name in zf.namelist() if name.endswith(".dist-info/entry_points.txt"))
        entry_points = zf.read(entry_points_name).decode("utf-8")

    assert metadata["Name"] == pyproject["project"]["name"]
    assert metadata["Requires-Python"] == pyproject["project"]["requires-python"]
    assert expected_dependencies <= requires_dist
    for command, target in expected_scripts.items():
        assert f"{command} = {target}" in entry_points


def test_packaged_skill_assets_do_not_include_python_cache_files() -> None:
    """Force-included skill assets should not ship local interpreter caches."""
    skill_root = Path("skills/odoo-code-review")
    cache_paths = sorted(
        path for path in skill_root.rglob("*") if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
    )

    assert cache_paths == []


def test_github_action_templates_are_parseable_workflows() -> None:
    """Packaged workflow templates should remain valid YAML with runnable jobs."""
    for template in sorted(Path("skills/odoo-code-review/templates").glob("*.yml")):
        workflow = yaml.safe_load(template.read_text(encoding="utf-8"))

        assert isinstance(workflow, dict), template
        assert isinstance(workflow.get("name"), str), template
        assert "on" in workflow or True in workflow, template
        assert isinstance(workflow.get("permissions"), dict), template

        jobs = workflow.get("jobs")
        assert isinstance(jobs, dict) and jobs, template
        for job in jobs.values():
            assert isinstance(job.get("runs-on"), str), template
            assert isinstance(job.get("steps"), list) and job["steps"], template


def test_runtime_ci_template_validates_review_config_before_scanning() -> None:
    """Runtime CI template should fail fast on malformed shared review config."""
    workflow = yaml.safe_load(
        Path("skills/odoo-code-review/templates/github-action.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["review"]["steps"]
    step_names = [step["name"] for step in steps]
    validate_index = step_names.index("Validate review config")
    scanner_index = step_names.index("Install scanners")
    codex_index = step_names.index("Install Codex (optional)")
    pr_review_index = step_names.index("Run review (PR scope)")
    full_review_index = step_names.index("Run review (full)")
    validate_run = steps[validate_index]["run"]

    assert scanner_index < validate_index < codex_index
    assert validate_index < pr_review_index
    assert validate_index < full_review_index
    assert "odoo-review-validate-config --check-all ." in validate_run


def test_deep_scan_ci_template_validates_review_config_before_scanning() -> None:
    """Deep-scan CI template should fail fast on malformed shared review config."""
    workflow = yaml.safe_load(
        Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["deep-scan"]["steps"]
    step_names = [step["name"] for step in steps]
    validate_index = step_names.index("Validate review config")
    install_index = step_names.index("Install harness")
    scan_index = step_names.index("Run standalone deep scan")
    validate_run = steps[validate_index]["run"]

    assert install_index < validate_index < scan_index
    assert "odoo-review-validate-config --check-all ." in validate_run


def test_repo_ci_workflow_runs_quality_gate_jobs() -> None:
    """Repository CI should keep the harness quality gates wired in."""
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))

    assert isinstance(workflow, dict)
    assert "on" in workflow or True in workflow
    jobs = workflow["jobs"]
    assert {"test", "lint", "docker", "security"} <= set(jobs)

    test_job = jobs["test"]
    matrix_versions = set(test_job["strategy"]["matrix"]["python-version"])
    assert {"3.9", "3.10", "3.11", "3.12", "3.13"} <= matrix_versions

    test_runs = "\n".join(step.get("run", "") for step in test_job["steps"])
    assert 'pip install -e ".[dev,scanners]"' in test_runs
    assert "pytest" in test_runs

    lint_runs = "\n".join(step.get("run", "") for step in jobs["lint"]["steps"])
    assert 'pip install -e ".[dev]"' in lint_runs
    assert "black --check ." in lint_runs
    assert "ruff check ." in lint_runs

    security_runs = "\n".join(step.get("run", "") for step in jobs["security"]["steps"])
    assert "bandit -r skills/odoo-code-review/scripts/" in security_runs


def test_skill_script_wrappers_match_packaged_console_scripts() -> None:
    """The packaged skill should expose the same CLI surface as pyproject."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packaged_commands = set(pyproject["project"]["scripts"])
    wrapper_commands = {
        path.name
        for path in Path("skills/odoo-code-review/scripts").iterdir()
        if path.is_file() and not path.name.startswith(".")
    }

    assert wrapper_commands == packaged_commands


def test_skill_script_wrappers_are_executable_python_commands() -> None:
    """Skill command wrappers should be directly runnable from an installed skill."""
    for wrapper in sorted(Path("skills/odoo-code-review/scripts").iterdir()):
        if not wrapper.is_file() or wrapper.name.startswith("."):
            continue

        first_line = wrapper.read_text(encoding="utf-8").splitlines()[0]
        assert first_line == "#!/usr/bin/env python3"
        assert os.access(wrapper, os.X_OK)


def test_package_importing_skill_wrappers_bootstrap_repo_root() -> None:
    """Direct wrappers that import package modules should work before package install."""
    for wrapper in sorted(Path("skills/odoo-code-review/scripts").iterdir()):
        if not wrapper.is_file() or wrapper.name.startswith("."):
            continue

        text = wrapper.read_text(encoding="utf-8")
        if "from odoo_security_harness." not in text:
            continue

        assert "Path(__file__).resolve().parents[3]" in text, wrapper.name
        assert "sys.path.insert(0, str(repo_root))" in text, wrapper.name


def test_skill_script_wrappers_show_help_from_outside_repo(tmp_path: Path) -> None:
    """Skill commands should start cleanly when invoked through their direct wrappers."""
    env = os.environ.copy()
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"

    for wrapper in sorted(Path("skills/odoo-code-review/scripts").iterdir()):
        if not wrapper.is_file() or wrapper.name.startswith("."):
            continue

        result = subprocess.run(
            [str(wrapper.resolve()), "--help"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        assert result.returncode == 0, f"{wrapper.name}: {result.stderr}"
        assert "usage:" in result.stdout.lower(), wrapper.name


def test_deep_scan_ci_template_supports_taxonomy_gate_artifact() -> None:
    """Static CI template should expose taxonomy drift gating and retain its artifact."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_FAIL_ON_UNMAPPED_TAXONOMY" in template
    assert "--fail-on-unmapped-taxonomy" in template
    assert ".audit-deep/taxonomy-gate.json" in template


def test_deep_scan_ci_template_supports_baseline_delta_artifacts() -> None:
    """Static CI template should expose baseline delta gating and retain delta artifacts."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_BASELINE" in template
    assert "ODOO_DEEP_SCAN_FAIL_ON_NEW" in template
    assert "--fail-on-new" in template
    assert ".audit-deep/deep-scan-delta.json" in template
    assert ".audit-deep/deep-scan-delta.md" in template


def test_deep_scan_ci_template_supports_accepted_risk_artifacts() -> None:
    """Static CI template should expose accepted-risk suppression and retain its report."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_ACCEPTED_RISKS" in template
    assert "--accepted-risks" in template
    assert ".audit-deep/00-accepted-risks.md" in template


def test_deep_scan_ci_template_supports_fix_list_artifacts() -> None:
    """Static CI template should expose fix-list tracking and retain its report."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_FIX_LIST" in template
    assert "--fix-list" in template
    assert ".audit-deep/00-fix-list.md" in template


def test_deep_scan_ci_template_supports_governance_gate_artifact() -> None:
    """Static CI template should expose policy health gates and retain the gate artifact."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_FAIL_ON_POLICY_ERRORS" in template
    assert "ODOO_DEEP_SCAN_FAIL_ON_FIX_REGRESSION" in template
    assert "--fail-on-policy-errors" in template
    assert "--fail-on-fix-regression" in template
    assert ".audit-deep/governance-gate.json" in template


def test_deep_scan_ci_template_supports_policy_check_only_modes() -> None:
    """Static CI template should expose governance-file-only validation modes."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert "ODOO_DEEP_SCAN_CHECK_ONLY_ACCEPTED_RISKS" in template
    assert "ODOO_DEEP_SCAN_CHECK_ONLY_FIX_LIST" in template
    assert "--check-only-accepted-risks" in template
    assert "--check-only-fix-list" in template
    assert "'.audit-deep/inventory/accepted-risks.json'" in template
    assert "'.audit-deep/inventory/fix-list.json'" in template


def test_deep_scan_ci_template_retains_html_triage_report() -> None:
    """Static CI template should retain the offline HTML triage report."""
    template = Path("skills/odoo-code-review/templates/deep-scan-github-action.yml").read_text(encoding="utf-8")

    assert ".audit-deep/findings.html" in template


def test_installer_commands_are_packaged_console_scripts() -> None:
    """install.sh should expose the same command set as package installs."""
    install_sh = Path("install.sh").read_text(encoding="utf-8")
    match = re.search(r"for script in (?P<commands>[^;]+); do", install_sh)
    assert match is not None

    installer_commands = set(match.group("commands").split())
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packaged_commands = set(pyproject["project"]["scripts"])

    assert installer_commands == packaged_commands


def test_installer_symlinks_all_advertised_commands() -> None:
    """The install loop should include every command printed in the installer summary."""
    install_sh = Path("install.sh").read_text(encoding="utf-8")
    loop = re.search(r"for script in (?P<commands>[^;]+); do", install_sh)
    assert loop is not None
    installer_commands = set(loop.group("commands").split())

    advertised = {
        "odoo-review-run",
        "odoo-review-rerun",
        "odoo-review-export",
        "odoo-review-diff",
        "odoo-review-finalize",
        "odoo-review-learn",
        "odoo-review-stock-diff",
        "odoo-review-runtime",
        "odoo-review-coverage",
        "odoo-review-validate-config",
        "odoo-deep-scan",
    }

    assert advertised <= installer_commands


def test_readme_advertises_packaged_installer_commands() -> None:
    """README command list should not lag behind packaged CLI entry points."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    packaged_commands = set(pyproject["project"]["scripts"])
    readme = Path("README.md").read_text(encoding="utf-8")

    missing = sorted(command for command in packaged_commands if f"`{command}`" not in readme)

    assert missing == []
