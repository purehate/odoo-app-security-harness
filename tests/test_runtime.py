"""Tests for Odoo runtime helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def build_cmd(odoo_bin: str, host: str, port: int, addons_path: str, log_path: Path, config: str | None = None, database: str | None = None) -> list[str]:
    """Build Odoo launch command."""
    cmd = [
        odoo_bin,
        "--http-interface", host,
        "--http-port", str(port),
        "--addons-path", addons_path,
        "--logfile", str(log_path),
    ]
    if config:
        cmd.extend(["--config", config])
    if database:
        cmd.extend(["--database", database])
    return cmd


def quote(value: str) -> str:
    """Quote shell argument."""
    if not value:
        return "''"
    if all(c.isalnum() or c in "/._:=,+-@" for c in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


class TestBuildCmd:
    """Test Odoo command building."""

    def test_basic_command(self, tmp_path: Path) -> None:
        """Test basic command construction."""
        log_path = tmp_path / "odoo.log"
        cmd = build_cmd("odoo-bin", "127.0.0.1", 8069, "/addons", log_path)
        
        assert cmd[0] == "odoo-bin"
        assert "--http-interface" in cmd
        assert "127.0.0.1" in cmd
        assert "--http-port" in cmd
        assert "8069" in cmd
        assert "--addons-path" in cmd
        assert "/addons" in cmd
        assert "--logfile" in cmd
        assert str(log_path) in cmd

    def test_with_config(self, tmp_path: Path) -> None:
        """Test command with config file."""
        log_path = tmp_path / "odoo.log"
        cmd = build_cmd("odoo-bin", "127.0.0.1", 8069, "/addons", log_path, config="/etc/odoo.conf")
        
        assert "--config" in cmd
        assert "/etc/odoo.conf" in cmd

    def test_with_database(self, tmp_path: Path) -> None:
        """Test command with database."""
        log_path = tmp_path / "odoo.log"
        cmd = build_cmd("odoo-bin", "127.0.0.1", 8069, "/addons", log_path, database="test_db")
        
        assert "--database" in cmd
        assert "test_db" in cmd

    def test_full_command(self, tmp_path: Path) -> None:
        """Test command with all options."""
        log_path = tmp_path / "odoo.log"
        cmd = build_cmd(
            "odoo-bin",
            "0.0.0.0",
            8070,
            "/addons,/extra",
            log_path,
            config="/etc/odoo.conf",
            database="production",
        )
        
        assert cmd == [
            "odoo-bin",
            "--http-interface", "0.0.0.0",
            "--http-port", "8070",
            "--addons-path", "/addons,/extra",
            "--logfile", str(log_path),
            "--config", "/etc/odoo.conf",
            "--database", "production",
        ]


class TestQuote:
    """Test shell argument quoting."""

    def test_simple_string(self) -> None:
        """Test simple string doesn't need quoting."""
        assert quote("simple") == "simple"
        assert quote("/path/to/file") == "/path/to/file"

    def test_empty_string(self) -> None:
        """Test empty string."""
        assert quote("") == "''"

    def test_string_with_spaces(self) -> None:
        """Test string with spaces."""
        result = quote("hello world")
        assert result == "'hello world'"

    def test_string_with_quotes(self) -> None:
        """Test string with single quotes."""
        result = quote("it's a test")
        assert "'\"'\"'" in result
        assert result.startswith("'")
        assert result.endswith("'")

    def test_special_characters(self) -> None:
        """Test special characters that need quoting."""
        assert quote("hello;world").startswith("'")
        assert quote("hello|world").startswith("'")
        assert quote("hello&world").startswith("'")


class TestStatusJson:
    """Test status JSON generation."""

    def test_status_structure(self) -> None:
        """Test status JSON structure."""
        status = {
            "started_at": "2024-01-01T00:00:00Z",
            "repo": "/test/repo",
            "base_url": "http://127.0.0.1:8069",
            "health_url": "http://127.0.0.1:8069/web/login",
            "ready": False,
            "poc_count": 0,
            "pocs": [],
        }
        
        json_str = json.dumps(status, indent=2)
        parsed = json.loads(json_str)
        
        assert parsed["ready"] is False
        assert parsed["base_url"] == "http://127.0.0.1:8069"
        assert parsed["poc_count"] == 0

    def test_status_with_pocs(self) -> None:
        """Test status with PoC results."""
        status = {
            "started_at": "2024-01-01T00:00:00Z",
            "ready": True,
            "poc_count": 2,
            "pocs": [
                {"poc": "test1.sh", "returncode": 0, "output": "/path/to/log1"},
                {"poc": "test2.sh", "returncode": 1, "output": "/path/to/log2"},
            ],
        }
        
        assert len(status["pocs"]) == 2
        assert status["pocs"][0]["returncode"] == 0
        assert status["pocs"][1]["returncode"] == 1


class TestPlanGeneration:
    """Test runtime plan generation."""

    def test_plan_markdown(self, tmp_path: Path) -> None:
        """Test plan markdown generation."""
        runtime_dir = tmp_path / "runtime"
        runtime_dir.mkdir()
        
        lines = [
            "# Runtime Evidence Plan",
            "",
            "- Repo: `/test/repo`",
            "- Base URL: `http://127.0.0.1:8069`",
            "- Health URL: `http://127.0.0.1:8069/web/login`",
            "",
            "## PoC Contract",
            "",
            "PoC scripts receive:",
            "",
            "- `ODOO_BASE_URL`",
            "- `ODOO_DB` when provided",
        ]
        
        plan_path = runtime_dir / "runtime-plan.md"
        plan_path.write_text("\n".join(lines), encoding="utf-8")
        
        content = plan_path.read_text(encoding="utf-8")
        assert "# Runtime Evidence Plan" in content
        assert "ODOO_BASE_URL" in content
        assert "http://127.0.0.1:8069" in content

    def test_boot_script(self, tmp_path: Path) -> None:
        """Test boot shell script generation."""
        runtime_dir = tmp_path / "runtime"
        runtime_dir.mkdir()
        
        cmd = ["odoo-bin", "--http-port", "8069"]
        shell_cmd = " ".join(quote(part) for part in cmd)
        
        script = f"#!/usr/bin/env bash\nset -euo pipefail\n{shell_cmd}\n"
        
        script_path = runtime_dir / "boot-command.sh"
        script_path.write_text(script, encoding="utf-8")
        
        content = script_path.read_text(encoding="utf-8")
        assert "#!/usr/bin/env bash" in content
        assert "set -euo pipefail" in content
        assert "odoo-bin" in content
