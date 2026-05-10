"""Tests for Odoo runtime helper."""

from __future__ import annotations

import json
import runpy
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

RUNTIME_SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "odoo-code-review" / "scripts" / "odoo-review-runtime"
RUN_SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "odoo-code-review" / "scripts" / "odoo-review-run"


def build_cmd(
    odoo_bin: str,
    host: str,
    port: int,
    addons_path: str,
    log_path: Path,
    config: str | None = None,
    database: str | None = None,
) -> list[str]:
    """Build Odoo launch command."""
    cmd = [
        odoo_bin,
        "--http-interface",
        host,
        "--http-port",
        str(port),
        "--addons-path",
        addons_path,
        "--logfile",
        str(log_path),
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
            "0.0.0.0",  # noqa: S104 - command construction fixture only
            8070,
            "/addons,/extra",
            log_path,
            config="/etc/odoo.conf",
            database="production",
        )

        assert cmd == [
            "odoo-bin",
            "--http-interface",
            "0.0.0.0",  # noqa: S104 - command construction fixture only
            "--http-port",
            "8070",
            "--addons-path",
            "/addons,/extra",
            "--logfile",
            str(log_path),
            "--config",
            "/etc/odoo.conf",
            "--database",
            "production",
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


class TestOdooMapRuntime:
    """Test optional OdooMap runtime companion behavior."""

    def test_build_odoomap_cmd_is_disabled_without_target(self, tmp_path: Path) -> None:
        """OdooMap should not run unless a target is explicit."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(odoomap_target=None, odoomap_bin="odoomap")

        cmd = namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

        assert cmd == []

    def test_build_odoomap_cmd_uses_non_bruteforce_flags(self, tmp_path: Path) -> None:
        """Runtime OdooMap integration should expose recon/enumeration without brute-force flags."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="https://qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database="review",
            odoomap_username="auditor",
            odoomap_password="test-password",  # noqa: S106 - command construction fixture only
            odoomap_modules=True,
            odoomap_cve=True,
            odoomap_enumerate=True,
            odoomap_limit=25,
        )

        cmd = namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

        assert cmd == [
            "odoomap",
            "-u",
            "https://qa.example.com",
            "-r",
            "-o",
            str(tmp_path / "odoomap.txt"),
            "-D",
            "review",
            "-U",
            "auditor",
            "-P",
            "test-password",
            "--modules",
            "--plugin",
            "cve-scanner",
            "-e",
            "-pe",
            "-l",
            "25",
        ]
        assert not {"-b", "-B", "-M", "-n", "--enum-users"} & set(cmd)

    def test_build_odoomap_cmd_can_target_local_runtime(self, tmp_path: Path) -> None:
        """The explicit self target should resolve to the booted local base URL."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="self",
            odoomap_bin="odoomap",
            odoomap_database=None,
            odoomap_username=None,
            odoomap_password=None,
            odoomap_modules=False,
            odoomap_cve=False,
            odoomap_enumerate=False,
            odoomap_limit=200,
        )

        cmd = namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

        assert cmd[:3] == ["odoomap", "-u", "http://127.0.0.1:8069"]

    def test_build_odoomap_cmd_rejects_non_http_target(self, tmp_path: Path) -> None:
        """OdooMap targets should be explicit authorized URLs or the self alias."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database=None,
            odoomap_username=None,
            odoomap_password=None,
            odoomap_modules=False,
            odoomap_cve=False,
            odoomap_enumerate=False,
            odoomap_limit=200,
        )

        with pytest.raises(ValueError, match="http\\(s\\) URL"):
            namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

    def test_build_odoomap_cmd_requires_complete_auth_for_enumeration(self, tmp_path: Path) -> None:
        """Authenticated enumeration should not be requested with partial credentials."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="https://qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database="review",
            odoomap_username="auditor",
            odoomap_password=None,
            odoomap_modules=False,
            odoomap_cve=False,
            odoomap_enumerate=True,
            odoomap_limit=25,
        )

        cmd = namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

        assert "-e" not in cmd
        assert "-pe" not in cmd
        assert "-l" not in cmd

    def test_build_odoomap_cmd_rejects_non_positive_enumeration_limit(self, tmp_path: Path) -> None:
        """Authenticated enumeration limits should not pass invalid values to OdooMap."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="https://qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database="review",
            odoomap_username="auditor",
            odoomap_password="test-password",  # noqa: S106 - command construction fixture only
            odoomap_modules=False,
            odoomap_cve=False,
            odoomap_enumerate=True,
            odoomap_limit=0,
        )

        with pytest.raises(ValueError, match="positive integer"):
            namespace["build_odoomap_cmd"](args, "http://127.0.0.1:8069", tmp_path / "odoomap.txt")

    def test_redact_odoomap_cmd_hides_password(self) -> None:
        """Credential-bearing OdooMap commands should be redacted in artifacts."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        cmd = [
            "odoomap",
            "-u",
            "https://qa.example.com",
            "-D",
            "review",
            "-U",
            "auditor",
            "-P",
            "test-password",
        ]

        redacted = namespace["redact_odoomap_cmd"](cmd)

        assert redacted == [
            "odoomap",
            "-u",
            "https://qa.example.com",
            "-D",
            "review",
            "-U",
            "auditor",
            "-P",
            "[REDACTED]",
        ]
        assert cmd[-1] == "test-password"

    def test_write_plan_redacts_odoomap_password(self, tmp_path: Path) -> None:
        """The runtime plan should not persist the OdooMap password."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        runtime_dir = tmp_path / "runtime"
        runtime_dir.mkdir()
        args = Namespace(
            health_path="/web/login",
            odoo_bin="odoo-bin",
            config=None,
            database="review",
            addons_path=None,
            run_generated_probes=False,
            odoomap_target="https://qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database="review",
            odoomap_username="auditor",
            odoomap_password="test-password",  # noqa: S106 - redaction fixture only
            odoomap_modules=True,
            odoomap_cve=False,
            odoomap_enumerate=True,
            odoomap_limit=25,
        )

        namespace["write_plan"](
            runtime_dir,
            args,
            tmp_path,
            ["odoo-bin", "--database", "review"],
            "http://127.0.0.1:8069",
        )

        content = (runtime_dir / "runtime-plan.md").read_text(encoding="utf-8")
        assert "test-password" not in content
        assert "[REDACTED]" in content

    def test_run_odoomap_redacts_status_cmd_but_executes_real_password(self, tmp_path: Path, monkeypatch) -> None:
        """Runtime status metadata should redact the password without weakening execution."""
        namespace = runpy.run_path(str(RUNTIME_SCRIPT), run_name="__test_odoo_runtime__")
        args = Namespace(
            odoomap_target="https://qa.example.com",
            odoomap_bin="odoomap",
            odoomap_database="review",
            odoomap_username="auditor",
            odoomap_password="test-password",  # noqa: S106 - redaction fixture only
            odoomap_modules=True,
            odoomap_cve=False,
            odoomap_enumerate=True,
            odoomap_limit=25,
            odoomap_timeout=30,
        )
        captured: dict[str, list[str]] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return SimpleNamespace(returncode=0, stdout="odoomap output\n")

        monkeypatch.setattr(namespace["subprocess"], "run", fake_run)

        result = namespace["run_odoomap"](args, "http://127.0.0.1:8069", tmp_path / "runtime")

        assert captured["cmd"][captured["cmd"].index("-P") + 1] == "test-password"
        assert result["cmd"][result["cmd"].index("-P") + 1] == "[REDACTED]"
        assert "test-password" not in json.dumps(result)
        assert "odoomap output" in Path(result["log"]).read_text(encoding="utf-8")


class TestOdooMapRunnerHints:
    """Test main-runner OdooMap runtime handoff artifacts."""

    def test_runner_extracts_aliased_constant_route_metadata(self, tmp_path: Path) -> None:
        """Route inventory should feed runtime probes from aliased decorators and constants."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        module_dir = tmp_path / "demo"
        controller_dir = module_dir / "controllers"
        controller_dir.mkdir(parents=True)
        controller = controller_dir / "main.py"
        controller.write_text(
            """
from odoo import http as odoo_http
from odoo.http import route as odoo_route

AUTH = 'public'
METHODS = ['GET']
ROUTE_OPTIONS = {'auth': AUTH, 'methods': METHODS, 'type': 'http', 'csrf': True}

class Demo(odoo_http.Controller):
    LOCAL_ROUTE = '/demo/local'

    @odoo_route(LOCAL_ROUTE, **ROUTE_OPTIONS)
    def local(self):
        return 'ok'
""",
            encoding="utf-8",
        )
        manifests = [{"module": "demo", "dir": "demo"}]

        routes = namespace["extract_routes"](tmp_path, manifests)

        assert len(routes) == 1
        assert routes[0]["paths"] == ["/demo/local"]
        assert routes[0]["auth"] == "'public'"
        assert routes[0]["methods"] == "['GET']"
        assert routes[0]["type"] == "'http'"
        assert routes[0]["csrf"] == "True"

    def test_runtime_probe_readme_includes_odoomap_target(self, tmp_path: Path) -> None:
        """The generated replay command should carry the requested OdooMap target."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        out = tmp_path / ".audit"
        routes = [
            {
                "paths": ["/hello"],
                "module": "demo",
                "file": "demo/controllers.py",
                "line": 12,
                "function": "hello",
                "auth": "'public'",
                "type": "'http'",
                "methods": "['GET']",
            }
        ]
        args = Namespace(runtime=True, odoomap_target="https://qa.example.com")

        namespace["write_runtime_probe_plan"](out, routes, args)

        content = (out / "runtime" / "probes" / "README.md").read_text(encoding="utf-8")
        assert "--odoomap-target https://qa.example.com" in content

    def test_runtime_probe_readme_allows_self_odoomap_target(self, tmp_path: Path) -> None:
        """The main runner should pass the runtime helper's explicit self alias through."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        out = tmp_path / ".audit"
        args = Namespace(runtime=True, odoomap_target="self")

        namespace["write_runtime_probe_plan"](out, [], args)

        content = (out / "runtime" / "probes" / "README.md").read_text(encoding="utf-8")
        assert "--odoomap-target self" in content

    def test_validate_runtime_targets_rejects_ambiguous_targets(self) -> None:
        """Runtime target flags should be explicit URLs before handoff artifacts are written."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        args = Namespace(runtime=True, zap_target="qa.example.com", odoomap_target="qa.example.com")

        errors = namespace["validate_runtime_targets"](args)

        assert "--zap-target must be an http(s) URL" in errors
        assert "--odoomap-target must be 'self' or an http(s) URL" in errors

    def test_validate_runtime_targets_accepts_http_urls_and_self(self) -> None:
        """The runner should accept the same OdooMap self alias as the runtime helper."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        args = Namespace(runtime=True, zap_target="https://qa.example.com", odoomap_target="self")

        assert namespace["validate_runtime_targets"](args) == []

    def test_run_mode_records_odoomap_target_active_flag(self, tmp_path: Path) -> None:
        """The lead-session run mode should surface OdooMap as an active runtime flag."""
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        out = tmp_path / ".audit"
        out.mkdir()
        args = Namespace(
            non_interactive=False,
            learn=False,
            learn_cap=3,
            weekly=False,
            baseline_stock_cc=False,
            project_config_loaded=None,
            model_pack="default",
            quick=False,
            joern=False,
            runtime=True,
            odoomap_target="https://qa.example.com",
            no_codex=False,
            no_local_qwen=False,
            no_breadth=False,
            no_discourse=False,
            no_export=False,
            no_html=False,
            emit_json=True,
            scope=None,
            baseline=None,
            accepted_risks=None,
            fix_list=None,
            pr=None,
            pr_repo=None,
            modules=None,
            odoo_version=None,
            codex_model="gpt-5.3-codex",
            codex_budget="normal",
            codex_mode="run",
            ensemble="off",
            ensemble_passes=0,
            local_model="qwen3:0.6b",
            breadth_budget="normal",
            breadth_max_chunks=0,
            breadth_chunk_size=40,
            phase1_min_lines_per_module=4,
            no_phase1_assert=False,
            allow_empty_scope=False,
            allow_missing_lanes=False,
            preflight_only=False,
            no_scans=False,
            no_server_actions=False,
            no_scripts=False,
        )

        namespace["write_run_mode"](out, args, tmp_path)

        mode = json.loads((out / "run-mode.json").read_text(encoding="utf-8"))
        content = (out / "00-run-mode.md").read_text(encoding="utf-8")
        assert mode["odoomap_target"] == "https://qa.example.com"
        assert "--odoomap-target https://qa.example.com" in content
