"""Behavioral tests for install.sh, run against a sandboxed HOME."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"
PACKAGED_COMMANDS = sorted(
    tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
)
# Variables that would point the installer, or the interpreter it builds, at real user state.
LEAKY_ENV_VARS = (
    "AGENTS_HOME",
    "CLAUDE_HOME",
    "ODOO_HARNESS_VENV",
    "PI_CODING_AGENT_DIR",
    "PYTHONHOME",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
)
# Paths below are relative to the sandboxed HOME.
BACKUP_ROOT = Path(".local/state/odoo-security-harness/backups")
INSTALLED_FILES = (
    Path(".claude/skills/odoo-code-review/SKILL.md"),
    Path(".agents/skills/odoo-code-review/SKILL.md"),
    Path(".claude/commands/odoo-code-review.md"),
    Path(".pi/agent/prompts/odoo-code-review.md"),
)
# Older installers left these beside the installed files, where agents load them as duplicates.
LEGACY_BACKUPS = (
    Path(".claude/skills/odoo-code-review.bak.20200101000000/SKILL.md"),
    Path(".agents/skills/odoo-code-review.bak.20200101000000/SKILL.md"),
    Path(".claude/commands/odoo-code-review.md.bak.20200101000000"),
    Path(".pi/agent/prompts/odoo-code-review.md.bak.20200101000000"),
)


def _sandbox_env(home: Path, **overrides: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in LEAKY_ENV_VARS}
    env["HOME"] = str(home)
    env.update(overrides)
    return env


def _run_installer(home: Path, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    home.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        ["bash", str(INSTALL_SH), *args],
        cwd=REPO_ROOT,
        env=_sandbox_env(home, **overrides),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


def _pypi_reachable() -> bool:
    try:
        with socket.create_connection(("pypi.org", 443), timeout=3):
            return True
    except OSError:
        return False


def _assert_nothing_installed(home: Path) -> None:
    assert not (home / ".agents" / "skills" / "odoo-code-review").exists()
    assert not (home / ".claude" / "skills" / "odoo-code-review").exists()
    assert not (home / ".local" / "bin" / "odoo-deep-scan").exists()


def test_installer_rejects_arguments_without_installing(tmp_path: Path) -> None:
    """Like ORCA's installer, any argument prints usage; it used to be ignored and ran a full install."""
    home = tmp_path / "home"

    result = _run_installer(home, "--help")

    assert result.returncode == 2
    assert "Usage: ./install.sh" in result.stderr
    assert not (home / ".local" / "share" / "odoo-security-harness").exists()
    _assert_nothing_installed(home)


def test_installer_rejects_venv_path_with_whitespace(tmp_path: Path) -> None:
    """Shebangs cannot quote paths, so a venv path with spaces must fail before anything is installed."""
    home = tmp_path / "home"

    result = _run_installer(home, ODOO_HARNESS_VENV=str(tmp_path / "with space" / "venv"))

    assert result.returncode != 0
    assert "whitespace" in result.stdout + result.stderr
    assert "Installation complete" not in result.stdout
    _assert_nothing_installed(home)


def test_installer_prints_plain_text_when_piped(tmp_path: Path) -> None:
    """Like ORCA's installer, colors are for terminals; piped or logged output must not carry escape codes."""
    home = tmp_path / "home"

    # A whitespace venv path stops the run after the colored banner, table and error, before any install.
    result = _run_installer(home, ODOO_HARNESS_VENV=str(tmp_path / "with space" / "venv"))

    assert result.stdout.startswith("Odoo Application Security Harness - Installer\n")
    assert "ERROR: venv path contains whitespace" in result.stdout
    assert "\x1b[" not in result.stdout + result.stderr


def test_installer_refuses_to_reuse_a_directory_that_is_not_a_venv(tmp_path: Path) -> None:
    """A pre-existing directory without pyvenv.cfg must not be cleared or installed into."""
    home = tmp_path / "home"
    target = tmp_path / "not-a-venv"
    target.mkdir()
    (target / "keep.txt").write_text("user data", encoding="utf-8")

    result = _run_installer(home, ODOO_HARNESS_VENV=str(target))

    assert result.returncode != 0
    assert "not a virtual environment" in result.stdout + result.stderr
    assert (target / "keep.txt").read_text(encoding="utf-8") == "user data"
    _assert_nothing_installed(home)


def test_installer_fails_loudly_when_pip_install_fails(tmp_path: Path) -> None:
    """A failed package install must stop the installer instead of reporting success."""
    home = tmp_path / "home"

    # Without an index pip cannot fetch the hatchling build backend, so the install fails offline.
    result = _run_installer(home, PIP_NO_INDEX="1")

    assert result.returncode != 0
    assert "Installation complete" not in result.stdout
    assert "pip install failed" in result.stdout + result.stderr
    _assert_nothing_installed(home)


@pytest.fixture(scope="module")
def installed_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install twice into a sandboxed HOME that holds legacy backups; pip needs PyPI for the build backend."""
    if not _pypi_reachable():
        pytest.skip("install.sh end-to-end tests need network access to PyPI")

    home = tmp_path_factory.mktemp("installed") / "home"
    for legacy in LEGACY_BACKUPS:
        (home / legacy).parent.mkdir(parents=True, exist_ok=True)
        (home / legacy).write_text("legacy backup\n", encoding="utf-8")

    # The second run replaces an existing install, which is the path that writes backups.
    for _ in range(2):
        result = _run_installer(home)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Installation complete" in result.stdout
    return home


@pytest.mark.integration
@pytest.mark.slow
def test_installed_skill_scripts_are_pinned_to_the_harness_venv(installed_home: Path) -> None:
    """Installed copies must run under the venv that holds the package and its dependencies."""
    venv_python = installed_home / ".local" / "share" / "odoo-security-harness" / "venv" / "bin" / "python"
    assert venv_python.exists()

    for skill_root in (installed_home / ".agents" / "skills", installed_home / ".claude" / "skills"):
        for command in PACKAGED_COMMANDS:
            script = skill_root / "odoo-code-review" / "scripts" / command
            assert script.read_text(encoding="utf-8").splitlines()[0] == f"#!{venv_python}", script
            assert os.access(script, os.X_OK), script


@pytest.mark.integration
@pytest.mark.slow
def test_install_backups_stay_out_of_agent_directories(installed_home: Path) -> None:
    """A backup beside the installed skill loads as a duplicate skill, so every backup lives in the state dir."""
    for agent_dir in (".claude/skills", ".agents/skills", ".claude/commands", ".pi/agent/prompts"):
        assert not list((installed_home / agent_dir).glob("odoo-code-review*.bak.*")), agent_dir

    backups = installed_home / BACKUP_ROOT
    for legacy in LEGACY_BACKUPS:
        assert (backups / "legacy" / legacy).read_text(encoding="utf-8") == "legacy backup\n", legacy

    reinstall_backups = [path for path in backups.iterdir() if path.name != "legacy"]
    assert len(reinstall_backups) == 1, reinstall_backups
    for installed in INSTALLED_FILES:
        assert (reinstall_backups[0] / installed).is_file(), installed


@pytest.mark.integration
@pytest.mark.slow
def test_installed_commands_start_outside_the_repo(installed_home: Path, tmp_path: Path) -> None:
    """PATH symlinks and direct skill-script calls must both work from an unrelated directory."""
    entry_points = [installed_home / ".local" / "bin" / command for command in PACKAGED_COMMANDS]
    entry_points += [
        installed_home / ".claude" / "skills" / "odoo-code-review" / "scripts" / command
        for command in PACKAGED_COMMANDS
    ]

    for entry_point in entry_points:
        result = subprocess.run(
            [str(entry_point), "--help"],
            cwd=tmp_path,
            env=_sandbox_env(installed_home),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert result.returncode == 0, f"{entry_point}: {result.stderr}"
        assert "usage:" in result.stdout.lower(), entry_point
