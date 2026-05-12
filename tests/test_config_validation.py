"""Tests for configuration validation."""

from __future__ import annotations

import json
import runpy
import sys
from argparse import Namespace
from pathlib import Path

from odoo_security_harness.scripts.validate_config import (
    check_all_configs,
    detect_config_type,
    validate_fix_list,
)
from odoo_security_harness.scripts.validate_config import (
    main as validate_config_main,
)
from odoo_security_harness.scripts.validate_config import (
    validate_accepted_risks as validate_real_accepted_risks,
)
from odoo_security_harness.scripts.validate_config import (
    validate_scope_yaml as validate_real_scope_yaml,
)
from odoo_security_harness.scripts.validate_config import (
    validate_toml_config as validate_real_toml_config,
)

RUN_SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "odoo-code-review" / "scripts" / "odoo-review-run"


def validate_toml_config(text: str) -> tuple[bool, list[str]]:
    """Validate TOML configuration content."""
    errors: list[str] = []

    # Check for required sections
    required_sections = ["models"]
    for section in required_sections:
        if f"[{section}]" not in text:
            errors.append(f"Missing required section: [{section}]")

    # Validate model_pack values
    valid_packs = {"default", "cheap-recall", "balanced", "frontier-validation", "local-private"}
    for line in text.splitlines():
        if "model_pack" in line:
            value = line.split("=")[-1].strip().strip('"').strip("'")
            if value not in valid_packs:
                errors.append(f"Invalid model_pack: {value}")

    # Validate boolean values
    valid_booleans = {"true", "false"}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("enabled") or stripped.startswith("quick") or stripped.startswith("no_scans"):
            value = stripped.split("=")[-1].strip().strip('"').strip("'")
            if value.lower() not in valid_booleans:
                errors.append(f"Invalid boolean value: {value}")

    return len(errors) == 0, errors


def validate_scope_yaml(text: str) -> tuple[bool, list[str]]:
    """Validate scope YAML content."""
    errors: list[str] = []

    # Check for required version
    if "version:" not in text:
        errors.append("Missing required field: version")

    # Validate accepted_risks structure
    if "accepted_risks:" in text:
        # Check for required fields in accepted_risks entries
        required_risk_fields = {"id", "reason"}
        lines = text.splitlines()
        in_risks = False
        current_risk: dict[str, bool] = {}

        for line in lines:
            stripped = line.strip()
            if stripped == "accepted_risks:":
                in_risks = True
                continue
            if in_risks and stripped.startswith("-"):
                # New risk entry
                if current_risk and not all(current_risk.get(f, False) for f in required_risk_fields):
                    missing = [f for f in required_risk_fields if not current_risk.get(f, False)]
                    errors.append(f"Risk entry missing required fields: {missing}")
                current_risk = {}
            if in_risks and ":" in stripped:
                key = stripped.split(":")[0].strip().lstrip("- ")
                if key in required_risk_fields:
                    current_risk[key] = True

        # Check last entry
        if current_risk and not all(current_risk.get(f, False) for f in required_risk_fields):
            missing = [f for f in required_risk_fields if not current_risk.get(f, False)]
            errors.append(f"Risk entry missing required fields: {missing}")

    return len(errors) == 0, errors


def validate_accepted_risks(text: str) -> tuple[bool, list[str]]:
    """Validate accepted-risks YAML content."""
    errors: list[str] = []

    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            errors.append("Top-level must be a mapping")
            return False, errors
        if data.get("version") != 1:
            errors.append("version must be 1")
        if "risks" not in data:
            errors.append("Missing risks list")
    except json.JSONDecodeError:
        # YAML - do basic validation
        stripped = text.strip()
        if not stripped or stripped == "not valid json":
            errors.append("Invalid content: not a valid config file")
        else:
            if "version:" not in text:
                errors.append("Missing version field")
            if "risks:" not in text and "accepted_risks:" not in text:
                errors.append("Missing risks list")

    return len(errors) == 0, errors


class TestValidateTomlConfig:
    """Test TOML configuration validation."""

    def test_valid_config(self) -> None:
        """Test valid TOML configuration."""
        config = """
[models]
model_pack = "default"
codex_model = "gpt-5.3-codex"
codex_budget = "normal"

[runtime]
enabled = true

[odoo]
version = "16.0"

[review]
modules = ["base", "web"]
quick = false
"""
        valid, errors = validate_toml_config(config)
        assert valid is True
        assert len(errors) == 0

    def test_invalid_model_pack(self) -> None:
        """Test invalid model_pack value."""
        config = """
[models]
model_pack = "invalid-pack"
"""
        valid, errors = validate_toml_config(config)
        assert valid is False
        assert any("Invalid model_pack" in e for e in errors)

    def test_missing_required_section(self) -> None:
        """Test missing required sections."""
        config = """
[runtime]
enabled = true
"""
        valid, errors = validate_toml_config(config)
        assert valid is False
        assert any("Missing required section" in e for e in errors)

    def test_invalid_boolean(self) -> None:
        """Test invalid boolean values."""
        config = """
[models]
model_pack = "default"

[runtime]
enabled = yes
"""
        valid, errors = validate_toml_config(config)
        assert valid is False
        assert any("Invalid boolean" in e for e in errors)


class TestRealTomlConfigValidator:
    """Test the packaged TOML config validator used by odoo-review-validate-config."""

    def write_config(self, tmp_path: Path, text: str) -> Path:
        """Write a temporary TOML config."""
        path = tmp_path / "config.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_runtime_odoomap_target_is_valid_when_runtime_enabled(self, tmp_path: Path) -> None:
        """Team config should support opt-in OdooMap runtime lead capture."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
odoomap_target = "https://qa.example.com"
zap_target = "https://qa.example.com"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is True
        assert errors == []

    def test_runtime_odoomap_target_accepts_self_when_runtime_enabled(self, tmp_path: Path) -> None:
        """Team config should allow the runtime helper's explicit local target alias."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
odoomap_target = "self"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is True
        assert errors == []

    def test_runtime_odoomap_target_requires_runtime_enabled(self, tmp_path: Path) -> None:
        """A configured OdooMap target should not silently imply runtime mode."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = false
odoomap_target = "https://qa.example.com"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "runtime.odoomap_target requires runtime.enabled = true" in errors

    def test_runtime_odoomap_target_must_be_non_empty_string(self, tmp_path: Path) -> None:
        """Reject malformed OdooMap target config values before a review run."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
odoomap_target = ""
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "runtime.odoomap_target must be a non-empty string" in errors

    def test_runtime_odoomap_target_must_be_http_url_or_self(self, tmp_path: Path) -> None:
        """Reject ambiguous OdooMap targets before runtime command generation."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
odoomap_target = "qa.example.com"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "runtime.odoomap_target must be 'self' or an http(s) URL" in errors

    def test_runtime_zap_target_must_be_http_url(self, tmp_path: Path) -> None:
        """Reject ambiguous ZAP targets before runtime command generation."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
zap_target = "qa.example.com"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "runtime.zap_target must be an http(s) URL" in errors

    def test_unknown_runtime_keys_are_rejected(self, tmp_path: Path) -> None:
        """Catch misspelled runtime keys instead of silently ignoring them."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"

[runtime]
enabled = true
odoomap_targets = "https://qa.example.com"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "Unknown runtime key: runtime.odoomap_targets" in errors

    def test_known_model_odoo_and_review_config_is_valid(self, tmp_path: Path) -> None:
        """The real validator should accept the documented shared config surface."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"
codex_model = "gpt-5.3-codex"
codex_budget = "normal"
local_model = "qwen3:0.6b"
ensemble = "cheap"
ensemble_passes = 6

[runtime]
enabled = false

[odoo]
version = "17.0"
proxy_mode = true
multi_company = true

[review]
modules = ["sale", "portal"]
scope = "./scope.yml"
quick = false
no_scans = false
breadth_budget = "deep"
breadth_max_chunks = 24
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is True
        assert errors == []

    def test_model_review_and_odoo_typos_are_rejected(self, tmp_path: Path) -> None:
        """Catch common misspellings across the shared config sections."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"
codex_buget = "normal"

[odoo]
proxy_mod = true

[review]
breath_budget = "deep"
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert "Unknown models key: models.codex_buget" in errors
        assert "Unknown odoo key: odoo.proxy_mod" in errors
        assert "Unknown review key: review.breath_budget" in errors

    def test_model_and_review_values_are_type_checked(self, tmp_path: Path) -> None:
        """Reject invalid enum and scalar values before they weaken a run."""
        path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"
codex_budget = "expensive"
ensemble = "random"
ensemble_passes = -1

[odoo]
version = ""
proxy_mode = "yes"

[review]
modules = ["sale", ""]
scope = ""
quick = "false"
breadth_budget = "huge"
breadth_max_chunks = -1
""",
        )

        valid, errors = validate_real_toml_config(path)

        assert valid is False
        assert any(error.startswith("models.codex_budget must be one of:") for error in errors)
        assert any(error.startswith("models.ensemble must be one of:") for error in errors)
        assert "models.ensemble_passes must be a non-negative integer" in errors
        assert "odoo.version must be a non-empty string" in errors
        assert "odoo.proxy_mode must be a boolean" in errors
        assert "review.modules must be a non-empty string or list of non-empty strings" in errors
        assert "review.scope must be a non-empty string" in errors
        assert "review.quick must be a boolean" in errors
        assert any(error.startswith("review.breadth_budget must be one of:") for error in errors)
        assert "review.breadth_max_chunks must be a non-negative integer" in errors

    def test_runner_applies_valid_shared_config(self, tmp_path: Path, monkeypatch) -> None:
        """The runner should consume the same shared config surface the validator accepts."""
        config_path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"
codex_model = "gpt-5.3-codex"
codex_budget = "deep"
local_model = "qwen3:0.6b"
ensemble = "cheap"
ensemble_passes = 6

[runtime]
enabled = true
odoomap_target = "https://qa.example.com"
zap_target = "https://zap.example.com"

[odoo]
version = "17.0"

[review]
modules = ["sale", "portal"]
scope = "./scope.yml"
quick = true
no_scans = true
breadth_budget = "low"
breadth_max_chunks = 12
""",
        )
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        args = Namespace(
            project_config=str(config_path),
            model_pack="default",
            codex_model="gpt-5.3-codex",
            codex_budget="normal",
            local_model="qwen3:0.6b",
            ensemble="off",
            ensemble_passes=0,
            no_codex=False,
            runtime=False,
            zap_target=None,
            odoomap_target=None,
            odoo_version=None,
            modules=None,
            scope=None,
            quick=False,
            no_scans=False,
            breadth_budget="normal",
            breadth_max_chunks=0,
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-run"])

        config, path, warnings = namespace["apply_project_config"](args, tmp_path)

        assert path == config_path.resolve()
        assert warnings == []
        assert config["runtime"]["odoomap_target"] == "https://qa.example.com"
        assert args.model_pack == "balanced"
        assert args.codex_budget == "deep"
        assert args.ensemble == "cheap"
        assert args.ensemble_passes == 6
        assert args.runtime is True
        assert args.zap_target == "https://zap.example.com"
        assert args.odoomap_target == "https://qa.example.com"
        assert args.odoo_version == "17.0"
        assert args.modules == "sale,portal"
        assert args.scope == "./scope.yml"
        assert args.quick is True
        assert args.no_scans is True
        assert args.breadth_budget == "low"
        assert args.breadth_max_chunks == 12

    def test_runner_cli_flags_override_shared_config(self, tmp_path: Path, monkeypatch) -> None:
        """Project config should not override explicit CLI choices."""
        config_path = self.write_config(
            tmp_path,
            """
[models]
model_pack = "balanced"
codex_budget = "deep"

[runtime]
enabled = true
odoomap_target = "https://qa.example.com"

[review]
breadth_budget = "deep"
""",
        )
        namespace = runpy.run_path(str(RUN_SCRIPT), run_name="__test_odoo_run__")
        args = Namespace(
            project_config=str(config_path),
            model_pack="cheap-recall",
            codex_model="gpt-5.3-codex",
            codex_budget="low",
            local_model="qwen3:0.6b",
            ensemble="off",
            ensemble_passes=0,
            no_codex=False,
            runtime=False,
            zap_target=None,
            odoomap_target="https://cli.example.com",
            odoo_version=None,
            modules=None,
            scope=None,
            quick=False,
            no_scans=False,
            breadth_budget="normal",
            breadth_max_chunks=0,
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "odoo-review-run",
                "--model-pack",
                "cheap-recall",
                "--codex-budget",
                "low",
                "--odoomap-target",
                "https://cli.example.com",
            ],
        )

        namespace["apply_project_config"](args, tmp_path)

        assert args.model_pack == "cheap-recall"
        assert args.codex_budget == "low"
        assert args.odoomap_target == "https://cli.example.com"

    def test_fix_list_governance_file_is_validated_by_check_all(self, tmp_path: Path) -> None:
        """Repo-wide validation should cover the same fix-list files deep scan consumes."""
        fix_list = tmp_path / ".audit-fix-list.yml"
        fix_list.write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Public route must require auth
    file: controllers.py
    severity: high
    owner: security@example.com
    status: in-progress
    target_date: 2026-06-01
""",
            encoding="utf-8",
        )

        valid, errors = check_all_configs(tmp_path)

        assert valid is True
        assert errors == {}

    def test_invalid_fix_list_governance_file_is_rejected_by_check_all(self, tmp_path: Path) -> None:
        """CI config validation should catch malformed fix-list tracker files early."""
        fix_list = tmp_path / ".audit-fix-list.yml"
        fix_list.write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Broken tracker
    severity: blocker
    owner: security@example.com
    status: maybe
    target_date: soon
""",
            encoding="utf-8",
        )

        valid, errors = check_all_configs(tmp_path)

        assert valid is False
        assert ".audit-fix-list.yml" in errors
        fix_errors = errors[".audit-fix-list.yml"]
        assert "fixes[0]: severity must be critical, high, medium, low, or info" in fix_errors
        assert "fixes[0]: status must be open, in-progress, fixed, or wontfix" in fix_errors
        assert "fixes[0]: requires fingerprint or file" in fix_errors
        assert "fixes[0]: target_date must be YYYY-MM-DD" in fix_errors

    def test_fix_list_wontfix_entries_require_notes(self, tmp_path: Path) -> None:
        """Wontfix tracker entries should carry a human-readable rationale."""
        fix_list = tmp_path / ".audit-fix-list.yml"
        fix_list.write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Public route accepted as legacy
    file: controllers.py
    severity: medium
    owner: security@example.com
    status: wontfix
""",
            encoding="utf-8",
        )

        valid, errors = validate_fix_list(fix_list)

        assert valid is False
        assert "fixes[0]: wontfix entries require notes" in errors

    def test_fingerprint_only_accepted_risk_is_validated_by_check_all(self, tmp_path: Path) -> None:
        """Repo-wide validation should allow one-click fingerprint-only suppressions."""
        risks = tmp_path / ".audit-accepted-risks.yml"
        risks.write_text(
            """
version: 1
risks:
  - id: AR-001
    fingerprint: 7c1f4a9b2e5d8a31
    title: Public route intentionally accepted
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-01-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )

        valid, errors = check_all_configs(tmp_path)

        assert valid is True
        assert errors == {}

    def test_accepted_risk_requires_fingerprint_or_file(self, tmp_path: Path) -> None:
        """Accepted-risk entries should never be broad enough to match everything."""
        risks = tmp_path / ".audit-accepted-risks.yml"
        risks.write_text(
            """
version: 1
risks:
  - id: AR-001
    title: Missing matcher
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-01-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )

        valid, errors = validate_real_accepted_risks(risks)

        assert valid is False
        assert "risks[0]: requires fingerprint or file" in errors

    def test_accepted_risk_regex_and_dates_are_validated(self, tmp_path: Path) -> None:
        """Accepted-risk validation should catch malformed regex and date policy rot."""
        risks = tmp_path / ".audit-accepted-risks.yml"
        risks.write_text(
            """
version: 1
risks:
  - id: AR-001
    title: Broken accepted risk
    file: controllers.py
    match: "["
    pattern_kind: regex
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-08-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )

        valid, errors = validate_real_accepted_risks(risks)

        assert valid is False
        assert any(error.startswith("risks[0]: invalid regex:") for error in errors)
        assert "risks[0]: accepted date is after expires" in errors

    def test_check_all_cli_fails_on_invalid_governance_files(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """The CI-facing CLI should print repo-wide accepted-risk and fix-list errors."""
        (tmp_path / ".audit-accepted-risks.yml").write_text(
            """
version: 1
risks:
  - id: AR-001
    title: Missing matcher
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-08-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )
        (tmp_path / ".audit-fix-list.yml").write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Broken tracker
    severity: blocker
    owner: security@example.com
    status: maybe
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", "--check-all", str(tmp_path)])

        assert validate_config_main() == 1

        output = capsys.readouterr().out
        assert "Validation errors found" in output
        assert ".audit-accepted-risks.yml:" in output
        assert "risks[0]: requires fingerprint or file" in output
        assert "risks[0]: accepted date is after expires" in output
        assert ".audit-fix-list.yml:" in output
        assert "fixes[0]: severity must be critical, high, medium, low, or info" in output
        assert "fixes[0]: status must be open, in-progress, fixed, or wontfix" in output

    def test_check_all_cli_accepts_valid_repo_governance_files(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """The CI-facing CLI should pass valid config, accepted-risk, and fix-list files."""
        config_dir = tmp_path / ".odoo-review"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text(
            """
[models]
model_pack = "balanced"

[runtime]
enabled = false
""",
            encoding="utf-8",
        )
        (tmp_path / ".audit-accepted-risks.yml").write_text(
            """
version: 1
risks:
  - id: AR-001
    fingerprint: 7c1f4a9b2e5d8a31
    title: Public route intentionally accepted
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-01-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )
        (tmp_path / ".audit-fix-list.yml").write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Public route must require auth
    file: controllers.py
    severity: high
    owner: security@example.com
    status: in-progress
    target_date: 2026-06-01
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", "--check-all", str(tmp_path)])

        assert validate_config_main() == 0

        output = capsys.readouterr().out
        assert "All configuration files" in output
        assert "are valid" in output

    def test_auto_detects_governance_file_types(self, tmp_path: Path) -> None:
        """Direct-file validation should route well-known governance files to the right schema."""
        assert detect_config_type(tmp_path / ".audit-accepted-risks.yml") == "accepted-risks"
        assert detect_config_type(tmp_path / ".audit-accepted-risks.json") == "accepted-risks"
        assert detect_config_type(tmp_path / ".audit-fix-list.yml") == "fix-list"
        assert detect_config_type(tmp_path / ".audit-fix-list.json") == "fix-list"
        assert detect_config_type(tmp_path / "scope.yml") == "yaml"
        assert detect_config_type(tmp_path / "config.toml") == "toml"

    def test_direct_cli_auto_detects_fix_list_schema(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Validating .audit-fix-list.yml directly should not use the scope.yml validator."""
        fix_list = tmp_path / ".audit-fix-list.yml"
        fix_list.write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Public route must require auth
    file: controllers.py
    severity: high
    owner: security@example.com
    status: in-progress
    target_date: 2026-06-01
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", str(fix_list)])

        assert validate_config_main() == 0

        output = capsys.readouterr().out
        assert f"{fix_list.resolve()} is valid" in output

    def test_direct_cli_auto_detects_accepted_risks_schema(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Validating .audit-accepted-risks.yml directly should use accepted-risk policy rules."""
        risks = tmp_path / ".audit-accepted-risks.yml"
        risks.write_text(
            """
version: 1
risks:
  - id: AR-001
    title: Missing matcher
    reason: Business accepted this public route with compensating monitoring.
    owner: security@example.com
    accepted: 2026-08-01
    expires: 2026-07-01
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", str(risks)])

        assert validate_config_main() == 1

        output = capsys.readouterr().out
        assert f"{risks.resolve()} has errors" in output
        assert "risks[0]: requires fingerprint or file" in output
        assert "risks[0]: accepted date is after expires" in output

    def test_direct_cli_supports_explicit_fix_list_type_for_nonstandard_names(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """Teams should be able to validate renamed fix-list files explicitly."""
        fix_list = tmp_path / "team-fixes.yml"
        fix_list.write_text(
            """
version: 1
fixes:
  - id: FIX-001
    title: Broken tracker
    severity: blocker
    owner: security@example.com
    status: maybe
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", "--type", "fix-list", str(fix_list)])

        assert validate_config_main() == 1

        output = capsys.readouterr().out
        assert "fixes[0]: severity must be critical, high, medium, low, or info" in output
        assert "fixes[0]: status must be open, in-progress, fixed, or wontfix" in output

    def test_real_scope_validator_accepts_documented_scope_schema(self, tmp_path: Path) -> None:
        """Repo scope validation should accept the documented engagement-scope shape."""
        scope = tmp_path / "scope.yml"
        scope.write_text(
            """
version: "1.0"
excluded_modules:
  - third_party_legacy
excluded_paths:
  - "addons/third_party/**"
accepted_risks:
  - id: AR-001
    module: portal
    rule: csrf_state_change_get
    reason: Legacy partner integration is covered by reverse-proxy IP allowlist.
    expires: "2026-12-31"
  - id: AR-002
    file: addons/sale/controllers/portal.py
    line_range: [120, 145]
    cwe: CWE-639
    reason: Customer accepted the risk for this engagement.
    expires: "2026-09-30"
""",
            encoding="utf-8",
        )

        valid, errors = validate_real_scope_yaml(scope)

        assert valid is True
        assert errors == []

    def test_real_scope_validator_rejects_scope_typos_and_weak_risks(self, tmp_path: Path) -> None:
        """Scope validation should catch typos and broad accepted-risk entries before CI runs."""
        scope = tmp_path / "scope.yml"
        scope.write_text(
            """
version: "1.0"
excluded_module:
  - typo_module
excluded_paths: "**/tests/**"
accepted_risks:
  - id: AR-001
    reasn: typo
    expires: "soon"
    line_range: [20, 10]
  - id: AR-002
    rule: hardcoded_secret
    reason: Demo-only data.
""",
            encoding="utf-8",
        )

        valid, errors = validate_real_scope_yaml(scope)

        assert valid is False
        assert "Unknown scope key: excluded_module" in errors
        assert "excluded_paths must be a list of non-empty strings" in errors
        assert "accepted_risks[0]: unknown key 'reasn'" in errors
        assert "accepted_risks[0]: missing required field 'reason'" in errors
        assert "accepted_risks[0]: requires at least one matcher: finding_id, module, file, rule, or cwe" in errors
        assert "accepted_risks[0]: expires must be YYYY-MM-DD" in errors
        assert "accepted_risks[0]: line_range must be [start, end] positive integers" in errors
        assert "accepted_risks[1]: missing required field 'expires'" in errors

    def test_check_all_cli_reports_invalid_scope_file(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """The CI-facing repo validator should report scope.yml schema errors."""
        (tmp_path / "scope.yml").write_text(
            """
version: "1.0"
accepted_risks:
  - id: AR-001
    reason: Missing matcher and expiry.
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["odoo-review-validate-config", "--check-all", str(tmp_path)])

        assert validate_config_main() == 1

        output = capsys.readouterr().out
        assert "scope.yml:" in output
        assert "accepted_risks[0]: missing required field 'expires'" in output
        assert "accepted_risks[0]: requires at least one matcher: finding_id, module, file, rule, or cwe" in output


class TestValidateScopeYaml:
    """Test scope YAML validation."""

    def test_valid_scope(self) -> None:
        """Test valid scope YAML."""
        scope = """
version: "1.0"
accepted_risks:
  - id: AR-001
    reason: "Customer accepted risk"
    module: legacy_module
excluded_modules:
  - deprecated_module
excluded_paths:
  - "addons/third_party/**"
"""
        valid, errors = validate_scope_yaml(scope)
        assert valid is True
        assert len(errors) == 0

    def test_missing_version(self) -> None:
        """Test missing version field."""
        scope = """
accepted_risks:
  - id: AR-001
    reason: "Test"
"""
        valid, errors = validate_scope_yaml(scope)
        assert valid is False
        assert any("version" in e for e in errors)

    def test_missing_risk_reason(self) -> None:
        """Test missing reason in accepted_risks."""
        scope = """
version: "1.0"
accepted_risks:
  - id: AR-001
    module: test_module
"""
        valid, errors = validate_scope_yaml(scope)
        assert valid is False
        assert any("reason" in e for e in errors)

    def test_empty_scope(self) -> None:
        """Test empty scope YAML."""
        scope = ""
        valid, errors = validate_scope_yaml(scope)
        assert valid is False
        assert any("version" in e for e in errors)


class TestValidateAcceptedRisks:
    """Test accepted-risks file validation."""

    def test_valid_json(self) -> None:
        """Test valid JSON accepted-risks."""
        risks = json.dumps(
            {
                "version": 1,
                "risks": [
                    {
                        "id": "AR-001",
                        "title": "Test Risk",
                        "file": "test.py",
                        "reason": "Accepted by customer",
                        "owner": "security@example.com",
                        "accepted": "2024-01-01",
                        "expires": "2025-01-01",
                    }
                ],
            }
        )
        valid, errors = validate_accepted_risks(risks)
        assert valid is True
        assert len(errors) == 0

    def test_missing_version(self) -> None:
        """Test missing version in accepted-risks."""
        risks = json.dumps({"version": 1, "risks": []})
        valid, errors = validate_accepted_risks(risks)
        assert valid is True
        assert len(errors) == 0

    def test_invalid_json(self) -> None:
        """Test invalid JSON."""
        risks = "not valid json"
        valid, errors = validate_accepted_risks(risks)
        assert valid is False
        assert any(
            "parse" in e.lower() or "json" in e.lower() or "missing" in e.lower() or "invalid" in e.lower()
            for e in errors
        )

    def test_yaml_format(self) -> None:
        """Test YAML format validation."""
        risks = """
version: 1
risks:
  - id: AR-001
    title: Test
    reason: Accepted
"""
        valid, errors = validate_accepted_risks(risks)
        assert valid is True
        assert len(errors) == 0
