#!/usr/bin/env python3
"""Validate Odoo Application Security Harness configuration files.

Usage:
    odoo-review-validate-config <config-file>
    odoo-review-validate-config --type toml <config.toml>
    odoo-review-validate-config --type yaml <scope.yml>
    odoo-review-validate-config --check-all <repo-path>

Exit codes:
    0 - All files valid
    1 - Validation errors found
    2 - File not found or unreadable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def validate_toml_config(path: Path) -> tuple[bool, list[str]]:
    """Validate TOML configuration file."""
    errors: list[str] = []
    
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            errors.append("tomllib not available (Python 3.11+ required, or install tomli)")
            return False, errors
    
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        errors.append(f"Failed to parse TOML: {exc}")
        return False, errors
    
    # Validate structure
    valid_sections = {"models", "runtime", "odoo", "review"}
    for section in data:
        if section not in valid_sections:
            errors.append(f"Unknown section: [{section}]")
    
    # Validate model_pack
    if "models" in data and isinstance(data["models"], dict):
        models = data["models"]
        valid_packs = {"default", "cheap-recall", "balanced", "frontier-validation", "local-private"}
        if "model_pack" in models and models["model_pack"] not in valid_packs:
            errors.append(f"Invalid model_pack: {models['model_pack']}. Must be one of: {valid_packs}")
    
    # Validate boolean fields
    if "runtime" in data and isinstance(data["runtime"], dict):
        runtime = data["runtime"]
        if "enabled" in runtime and not isinstance(runtime["enabled"], bool):
            errors.append("runtime.enabled must be a boolean")
    
    return len(errors) == 0, errors


def validate_scope_yaml(path: Path) -> tuple[bool, list[str]]:
    """Validate scope YAML file."""
    errors: list[str] = []
    
    try:
        import yaml
    except ImportError:
        errors.append("pyyaml not installed")
        return False, errors
    
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        errors.append(f"Failed to parse YAML: {exc}")
        return False, errors
    
    if not isinstance(data, dict):
        errors.append("Top-level must be a mapping")
        return False, errors
    
    # Check version
    if "version" not in data:
        errors.append("Missing required field: version")
    
    # Validate accepted_risks
    if "accepted_risks" in data:
        risks = data["accepted_risks"]
        if not isinstance(risks, list):
            errors.append("accepted_risks must be a list")
        else:
            for idx, risk in enumerate(risks):
                if not isinstance(risk, dict):
                    errors.append(f"accepted_risks[{idx}] must be a mapping")
                    continue
                if "id" not in risk:
                    errors.append(f"accepted_risks[{idx}]: missing required field 'id'")
                if "reason" not in risk:
                    errors.append(f"accepted_risks[{idx}]: missing required field 'reason'")
    
    return len(errors) == 0, errors


def validate_accepted_risks(path: Path) -> tuple[bool, list[str]]:
    """Validate accepted-risks file."""
    errors: list[str] = []
    
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"Failed to read file: {exc}")
        return False, errors
    
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON: {exc}")
            return False, errors
    else:
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            errors.append("pyyaml not installed")
            return False, errors
        except Exception as exc:
            errors.append(f"Failed to parse YAML: {exc}")
            return False, errors
    
    if not isinstance(data, dict):
        errors.append("Top-level must be a mapping")
        return False, errors
    
    if data.get("version") != 1:
        errors.append("version must be 1")
    
    risks = data.get("risks", [])
    if not isinstance(risks, list):
        errors.append("risks must be a list")
        return False, errors
    
    seen_ids: set[str] = set()
    for idx, risk in enumerate(risks):
        if not isinstance(risk, dict):
            errors.append(f"risks[{idx}] must be a mapping")
            continue
        
        required_fields = {"id", "title", "file", "reason", "owner", "accepted", "expires"}
        for field in required_fields:
            if field not in risk or not risk[field]:
                errors.append(f"risks[{idx}]: missing required field '{field}'")
        
        risk_id = risk.get("id")
        if risk_id in seen_ids:
            errors.append(f"risks[{idx}]: duplicate id '{risk_id}'")
        elif risk_id:
            seen_ids.add(risk_id)
    
    return len(errors) == 0, errors


def check_all_configs(repo_path: Path) -> tuple[bool, dict[str, list[str]]]:
    """Check all configuration files in a repository."""
    all_errors: dict[str, list[str]] = {}
    
    # Check TOML configs
    for config_name in [".odoo-review/config.toml", ".odoo-review.toml"]:
        config_path = repo_path / config_name
        if config_path.exists():
            valid, errors = validate_toml_config(config_path)
            if not valid:
                all_errors[config_name] = errors
    
    # Check scope.yml
    scope_path = repo_path / "scope.yml"
    if scope_path.exists():
        valid, errors = validate_scope_yaml(scope_path)
        if not valid:
            all_errors["scope.yml"] = errors
    
    # Check accepted-risks
    for name in [".audit-accepted-risks.yml", ".audit-accepted-risks.yaml", ".audit-accepted-risks.json"]:
        path = repo_path / name
        if path.exists():
            valid, errors = validate_accepted_risks(path)
            if not valid:
                all_errors[name] = errors
    
    return len(all_errors) == 0, all_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate odoo-code-review configuration files")
    parser.add_argument("path", nargs="?", help="Path to config file or repo")
    parser.add_argument("--type", choices=["toml", "yaml", "json", "auto"], default="auto",
                       help="Config file type (default: auto-detect)")
    parser.add_argument("--check-all", action="store_true",
                       help="Check all config files in repository")
    args = parser.parse_args()
    
    if args.check_all:
        if not args.path:
            print("ERROR: --check-all requires a repository path", file=sys.stderr)
            return 2
        repo_path = Path(args.path).expanduser().resolve()
        if not repo_path.exists():
            print(f"ERROR: Repository not found: {repo_path}", file=sys.stderr)
            return 2
        
        valid, errors = check_all_configs(repo_path)
        if valid:
            print(f"✓ All configuration files in {repo_path} are valid")
            return 0
        else:
            print(f"✗ Validation errors found in {repo_path}:")
            for filename, file_errors in errors.items():
                print(f"\n{filename}:")
                for error in file_errors:
                    print(f"  - {error}")
            return 1
    
    if not args.path:
        print("ERROR: Please provide a file path or use --check-all", file=sys.stderr)
        return 2
    
    path = Path(args.path).expanduser().resolve()
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        return 2
    
    # Auto-detect type
    file_type = args.type
    if file_type == "auto":
        if path.suffix == ".toml":
            file_type = "toml"
        elif path.suffix in (".yml", ".yaml"):
            file_type = "yaml"
        elif path.suffix == ".json":
            file_type = "json"
        else:
            print(f"ERROR: Cannot auto-detect file type for {path}", file=sys.stderr)
            return 2
    
    # Validate based on type
    if file_type == "toml":
        valid, errors = validate_toml_config(path)
    elif file_type == "yaml":
        valid, errors = validate_scope_yaml(path)
    elif file_type == "json":
        valid, errors = validate_accepted_risks(path)
    else:
        print(f"ERROR: Unknown file type: {file_type}", file=sys.stderr)
        return 2
    
    if valid:
        print(f"✓ {path} is valid")
        return 0
    else:
        print(f"✗ {path} has errors:")
        for error in errors:
            print(f"  - {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
