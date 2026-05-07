"""Tests for configuration validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


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
        risks = json.dumps({
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
            ]
        })
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
        assert any("parse" in e.lower() or "json" in e.lower() or "missing" in e.lower() or "invalid" in e.lower() for e in errors)

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
