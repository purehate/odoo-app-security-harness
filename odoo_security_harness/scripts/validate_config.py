#!/usr/bin/env python3
"""Validate Odoo Application Security Harness configuration files.

Usage:
    odoo-review-validate-config <config-file>
    odoo-review-validate-config --type toml <config.toml>
    odoo-review-validate-config --type yaml <scope.yml>
    odoo-review-validate-config --type accepted-risks <accepted-risks.yml>
    odoo-review-validate-config --type fix-list <fix-list.yml>
    odoo-review-validate-config --check-all <repo-path>  # TOML, scope, accepted-risk, and fix-list files

Exit codes:
    0 - All files valid
    1 - Validation errors found
    2 - File not found or unreadable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

VALID_MODEL_PACKS = {"default", "cheap-recall", "balanced", "frontier-validation", "local-private"}
VALID_CODEX_BUDGETS = {"low", "normal", "deep"}
VALID_ENSEMBLES = {"off", "cheap", "balanced"}
VALID_BREADTH_BUDGETS = {"off", "low", "normal", "deep"}
VALID_FIX_STATUSES = {"open", "in-progress", "fixed", "wontfix"}
VALID_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_SCOPE_KEYS = {"version", "excluded_modules", "excluded_paths", "accepted_risks"}
VALID_SCOPE_RISK_KEYS = {
    "id",
    "finding_id",
    "title",
    "module",
    "file",
    "rule",
    "cwe",
    "line",
    "line_range",
    "reason",
    "owner",
    "expires",
    "severity",
}
SCOPE_RISK_MATCH_KEYS = {"finding_id", "module", "file", "rule", "cwe"}


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
        elif not isinstance(data[section], dict):
            errors.append(f"[{section}] must be a table")

    # Validate model/lane settings
    if "models" in data and isinstance(data["models"], dict):
        models = data["models"]
        valid_model_keys = {
            "model_pack",
            "codex_model",
            "codex_budget",
            "local_model",
            "ensemble",
            "ensemble_passes",
        }
        for key in models:
            if key not in valid_model_keys:
                errors.append(f"Unknown models key: models.{key}")
        if "model_pack" in models and models["model_pack"] not in VALID_MODEL_PACKS:
            errors.append(f"Invalid model_pack: {models['model_pack']}. Must be one of: {VALID_MODEL_PACKS}")
        if "codex_budget" in models and models["codex_budget"] not in VALID_CODEX_BUDGETS:
            errors.append(f"models.codex_budget must be one of: {VALID_CODEX_BUDGETS}")
        if "ensemble" in models and models["ensemble"] not in VALID_ENSEMBLES:
            errors.append(f"models.ensemble must be one of: {VALID_ENSEMBLES}")
        for key in ("codex_model", "local_model"):
            if key in models and (not isinstance(models[key], str) or not models[key].strip()):
                errors.append(f"models.{key} must be a non-empty string")
        if "ensemble_passes" in models:
            value = models["ensemble_passes"]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append("models.ensemble_passes must be a non-negative integer")

    # Validate runtime settings
    if "runtime" in data and isinstance(data["runtime"], dict):
        runtime = data["runtime"]
        valid_runtime_keys = {"enabled", "zap_target", "odoomap_target"}
        for key in runtime:
            if key not in valid_runtime_keys:
                errors.append(f"Unknown runtime key: runtime.{key}")
        if "enabled" in runtime and not isinstance(runtime["enabled"], bool):
            errors.append("runtime.enabled must be a boolean")
        for key in ("zap_target", "odoomap_target"):
            if key in runtime and (not isinstance(runtime[key], str) or not runtime[key].strip()):
                errors.append(f"runtime.{key} must be a non-empty string")
        if runtime.get("enabled") is not True:
            if runtime.get("zap_target"):
                errors.append("runtime.zap_target requires runtime.enabled = true")
            if runtime.get("odoomap_target"):
                errors.append("runtime.odoomap_target requires runtime.enabled = true")

    # Validate Odoo metadata
    if "odoo" in data and isinstance(data["odoo"], dict):
        odoo = data["odoo"]
        valid_odoo_keys = {"version", "proxy_mode", "multi_company"}
        for key in odoo:
            if key not in valid_odoo_keys:
                errors.append(f"Unknown odoo key: odoo.{key}")
        if "version" in odoo and (not isinstance(odoo["version"], str) or not odoo["version"].strip()):
            errors.append("odoo.version must be a non-empty string")
        for key in ("proxy_mode", "multi_company"):
            if key in odoo and not isinstance(odoo[key], bool):
                errors.append(f"odoo.{key} must be a boolean")

    # Validate review settings
    if "review" in data and isinstance(data["review"], dict):
        review = data["review"]
        valid_review_keys = {
            "modules",
            "scope",
            "quick",
            "no_scans",
            "breadth_budget",
            "breadth_max_chunks",
        }
        for key in review:
            if key not in valid_review_keys:
                errors.append(f"Unknown review key: review.{key}")
        modules = review.get("modules")
        if modules is not None:
            valid_modules_string = isinstance(modules, str) and bool(modules.strip())
            valid_modules_list = isinstance(modules, list) and all(isinstance(item, str) and item.strip() for item in modules)
            if not valid_modules_string and not valid_modules_list:
                errors.append("review.modules must be a non-empty string or list of non-empty strings")
        if "scope" in review and (not isinstance(review["scope"], str) or not review["scope"].strip()):
            errors.append("review.scope must be a non-empty string")
        for key in ("quick", "no_scans"):
            if key in review and not isinstance(review[key], bool):
                errors.append(f"review.{key} must be a boolean")
        if "breadth_budget" in review and review["breadth_budget"] not in VALID_BREADTH_BUDGETS:
            errors.append(f"review.breadth_budget must be one of: {VALID_BREADTH_BUDGETS}")
        if "breadth_max_chunks" in review:
            value = review["breadth_max_chunks"]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append("review.breadth_max_chunks must be a non-negative integer")

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
    elif not isinstance(data["version"], (str, int, float)):
        errors.append("version must be a string or number")

    for key in data:
        if key not in VALID_SCOPE_KEYS:
            errors.append(f"Unknown scope key: {key}")

    for key in ("excluded_modules", "excluded_paths"):
        if key in data:
            values = data[key]
            if not isinstance(values, list) or not all(isinstance(item, str) and item.strip() for item in values):
                errors.append(f"{key} must be a list of non-empty strings")

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
                for key in risk:
                    if key not in VALID_SCOPE_RISK_KEYS:
                        errors.append(f"accepted_risks[{idx}]: unknown key '{key}'")
                for field in ("id", "reason", "expires"):
                    if field not in risk or not str(risk[field]).strip():
                        errors.append(f"accepted_risks[{idx}]: missing required field '{field}'")
                if not any(str(risk.get(key) or "").strip() for key in SCOPE_RISK_MATCH_KEYS):
                    errors.append(
                        f"accepted_risks[{idx}]: requires at least one matcher: finding_id, module, file, rule, or cwe"
                    )
                if risk.get("expires") and not is_iso_date(risk["expires"]):
                    errors.append(f"accepted_risks[{idx}]: expires must be YYYY-MM-DD")
                line = risk.get("line")
                if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
                    errors.append(f"accepted_risks[{idx}]: line must be a positive integer")
                line_range = risk.get("line_range")
                if line_range is not None:
                    valid_line_range = (
                        isinstance(line_range, list)
                        and len(line_range) == 2
                        and all(isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in line_range)
                        and line_range[0] <= line_range[1]
                    )
                    if not valid_line_range:
                        errors.append(f"accepted_risks[{idx}]: line_range must be [start, end] positive integers")

    return len(errors) == 0, errors


def validate_accepted_risks(path: Path) -> tuple[bool, list[str]]:
    """Validate accepted-risks file."""
    errors: list[str] = []

    data, load_errors = load_yaml_or_json(path)
    if load_errors:
        return False, load_errors

    if not isinstance(data, dict):
        errors.append("Top-level must be a mapping")
        return False, errors

    if data.get("version") != 1:
        errors.append("version must be 1")

    risks = data.get("risks", data.get("accepted_risks", []))
    if not isinstance(risks, list):
        errors.append("risks must be a list")
        return False, errors

    seen_ids: set[str] = set()
    for idx, risk in enumerate(risks):
        if not isinstance(risk, dict):
            errors.append(f"risks[{idx}] must be a mapping")
            continue

        required_fields = {"id", "title", "reason", "owner", "accepted", "expires"}
        for field in required_fields:
            if field not in risk or not risk[field]:
                errors.append(f"risks[{idx}]: missing required field '{field}'")

        risk_id = risk.get("id")
        if risk_id in seen_ids:
            errors.append(f"risks[{idx}]: duplicate id '{risk_id}'")
        elif risk_id:
            seen_ids.add(risk_id)

        fingerprint = str(risk.get("fingerprint") or "")
        file_pattern = str(risk.get("file") or "")
        if not fingerprint and not file_pattern:
            errors.append(f"risks[{idx}]: requires fingerprint or file")
        if fingerprint and not re.fullmatch(r"(sha256:)?[0-9a-f]{16,64}", fingerprint):
            errors.append(f"risks[{idx}]: fingerprint must be 16-64 hex chars")
        pattern_kind = str(risk.get("pattern_kind") or "literal")
        if pattern_kind not in {"literal", "regex"}:
            errors.append(f"risks[{idx}]: pattern_kind must be literal or regex")
        if pattern_kind == "regex" and risk.get("match"):
            try:
                re.compile(str(risk["match"]))
            except re.error as exc:
                errors.append(f"risks[{idx}]: invalid regex: {exc}")
        for field in ("accepted", "expires"):
            if risk.get(field) and not is_iso_date(risk[field]):
                errors.append(f"risks[{idx}]: {field} must be YYYY-MM-DD")
        if risk.get("accepted") and risk.get("expires") and is_iso_date(risk["accepted"]) and is_iso_date(risk["expires"]):
            accepted = date.fromisoformat(str(risk["accepted"]))
            expires = date.fromisoformat(str(risk["expires"]))
            if accepted > expires:
                errors.append(f"risks[{idx}]: accepted date is after expires")

    return len(errors) == 0, errors


def validate_fix_list(path: Path) -> tuple[bool, list[str]]:
    """Validate fix-list governance file."""
    errors: list[str] = []

    data, load_errors = load_yaml_or_json(path)
    if load_errors:
        return False, load_errors

    if not isinstance(data, dict):
        errors.append("Top-level must be a mapping")
        return False, errors

    if data.get("version") != 1:
        errors.append("version must be 1")

    fixes = data.get("fixes", data.get("fix_list", []))
    if not isinstance(fixes, list):
        errors.append("fixes must be a list")
        return False, errors

    seen_ids: set[str] = set()
    for idx, fix in enumerate(fixes):
        if not isinstance(fix, dict):
            errors.append(f"fixes[{idx}] must be a mapping")
            continue

        for field in ("id", "title", "severity", "owner", "status"):
            if field not in fix or not fix[field]:
                errors.append(f"fixes[{idx}]: missing required field '{field}'")

        fix_id = fix.get("id")
        if fix_id in seen_ids:
            errors.append(f"fixes[{idx}]: duplicate id '{fix_id}'")
        elif fix_id:
            seen_ids.add(fix_id)

        severity = str(fix.get("severity") or "").lower()
        if severity and severity not in VALID_FINDING_SEVERITIES:
            errors.append(f"fixes[{idx}]: severity must be critical, high, medium, low, or info")

        status = str(fix.get("status") or "")
        if status and status not in VALID_FIX_STATUSES:
            errors.append(f"fixes[{idx}]: status must be open, in-progress, fixed, or wontfix")
        if status == "wontfix" and not str(fix.get("notes") or "").strip():
            errors.append(f"fixes[{idx}]: wontfix entries require notes")

        if not str(fix.get("fingerprint") or "").strip() and not str(fix.get("file") or "").strip():
            errors.append(f"fixes[{idx}]: requires fingerprint or file")
        fingerprint = str(fix.get("fingerprint") or "")
        if fingerprint and not re.fullmatch(r"(sha256:)?[0-9a-f]{16,64}", fingerprint):
            errors.append(f"fixes[{idx}]: fingerprint must be 16-64 hex chars")
        for field in ("target_date", "fixed_at"):
            if fix.get(field) and not is_iso_date(fix[field]):
                errors.append(f"fixes[{idx}]: {field} must be YYYY-MM-DD")

    return len(errors) == 0, errors


def load_yaml_or_json(path: Path) -> tuple[object, list[str]]:
    """Load a JSON or YAML governance file."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return None, [f"Failed to read file: {exc}"]

    if path.suffix == ".json":
        try:
            return json.loads(text), []
        except json.JSONDecodeError as exc:
            return None, [f"Invalid JSON: {exc}"]

    try:
        import yaml

        return yaml.safe_load(text), []
    except ImportError:
        return None, ["pyyaml not installed"]
    except Exception as exc:
        return None, [f"Failed to parse YAML: {exc}"]


def is_iso_date(value: object) -> bool:
    """Return True when value is parseable as an ISO calendar date."""
    try:
        date.fromisoformat(str(value))
    except ValueError:
        return False
    return True


def detect_config_type(path: Path) -> str | None:
    """Detect config type from well-known harness filenames."""
    name = path.name
    if path.suffix == ".toml":
        return "toml"
    if name in {".audit-accepted-risks.yml", ".audit-accepted-risks.yaml", ".audit-accepted-risks.json"}:
        return "accepted-risks"
    if name in {".audit-fix-list.yml", ".audit-fix-list.yaml", ".audit-fix-list.json"}:
        return "fix-list"
    if name == "scope.yml" or name == "scope.yaml":
        return "yaml"
    if path.suffix == ".json":
        return "accepted-risks"
    if path.suffix in (".yml", ".yaml"):
        return "yaml"
    return None


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

    # Check fix-list governance files
    for name in [".audit-fix-list.yml", ".audit-fix-list.yaml", ".audit-fix-list.json"]:
        path = repo_path / name
        if path.exists():
            valid, errors = validate_fix_list(path)
            if not valid:
                all_errors[name] = errors

    return len(all_errors) == 0, all_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate odoo-code-review configuration files")
    parser.add_argument("path", nargs="?", help="Path to config file or repo")
    parser.add_argument(
        "--type",
        choices=["toml", "yaml", "json", "accepted-risks", "fix-list", "auto"],
        default="auto",
        help="Config file type (default: auto-detect)",
    )
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
        file_type = detect_config_type(path)
        if file_type is None:
            print(f"ERROR: Cannot auto-detect file type for {path}", file=sys.stderr)
            return 2

    # Validate based on type
    if file_type == "toml":
        valid, errors = validate_toml_config(path)
    elif file_type == "yaml":
        valid, errors = validate_scope_yaml(path)
    elif file_type in {"json", "accepted-risks"}:
        valid, errors = validate_accepted_risks(path)
    elif file_type == "fix-list":
        valid, errors = validate_fix_list(path)
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
