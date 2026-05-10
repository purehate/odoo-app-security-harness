"""Odoo manifest security and packaging scanner."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KNOWN_ODOO_LICENSES = {
    "AGPL-3",
    "GPL-2",
    "GPL-2 or any later version",
    "GPL-3",
    "GPL-3 or any later version",
    "LGPL-3",
    "OEEL-1",
    "OPL-1",
    "Other OSI approved licence",
    "Other proprietary",
}
SECURITY_DATA_HINTS = ("security/", "ir.model.access.csv", "ir_rule", "groups.xml", "access.xml")
LIFECYCLE_HOOK_FIELDS = ("pre_init_hook", "post_init_hook", "uninstall_hook")


@dataclass
class ManifestFinding:
    """Represents a manifest-level review finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    module: str
    message: str


def scan_manifests(repo_path: Path) -> list[ManifestFinding]:
    """Scan Odoo manifests for packaging and security review gaps."""
    findings: list[ManifestFinding] = []
    for manifest in repo_path.rglob("__manifest__.py"):
        if _should_skip(manifest):
            continue
        findings.extend(ManifestScanner(manifest).scan())
    for manifest in repo_path.rglob("__openerp__.py"):
        if _should_skip(manifest):
            continue
        findings.extend(ManifestScanner(manifest).scan())
    return findings


class ManifestScanner:
    """Scanner for one Odoo manifest file."""

    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = manifest_path
        self.module_path = manifest_path.parent
        self.module = self.module_path.name
        self.findings: list[ManifestFinding] = []

    def scan(self) -> list[ManifestFinding]:
        """Scan the manifest."""
        data = self._load_manifest()
        if data is None:
            self._add(
                "odoo-manifest-parse-error",
                "Manifest cannot be parsed safely",
                "medium",
                "Manifest is not a literal Python dictionary; verify install metadata manually",
            )
            return self.findings

        data_files = _as_string_list(data.get("data"))
        demo_files = _as_string_list(data.get("demo"))
        depends = _as_string_list(data.get("depends"))
        all_loaded_files = [*data_files, *demo_files]
        has_models = (self.module_path / "models").exists() and any((self.module_path / "models").rglob("*.py"))
        has_security_acl = any(path.endswith("ir.model.access.csv") for path in data_files)

        if data.get("installable", True) and has_models and not has_security_acl:
            self._add(
                "odoo-manifest-missing-acl-data",
                "Installable module with models does not load ACL CSV",
                "high",
                "Module defines Python models but manifest data does not include security/ir.model.access.csv",
            )

        production_demo = [
            path for path in data_files if "demo" in Path(path).parts or Path(path).name.startswith("demo")
        ]
        if production_demo:
            self._add(
                "odoo-manifest-demo-in-data",
                "Demo data loaded as production data",
                "medium",
                f"Manifest data loads demo-looking files: {', '.join(production_demo)}",
            )

        if data.get("installable", True) and "license" not in data:
            self._add(
                "odoo-manifest-missing-license",
                "Installable module missing license",
                "low",
                "Manifest omits license; review redistribution/compliance posture before shipping",
            )

        license_value = data.get("license")
        if isinstance(license_value, str) and license_value and license_value not in KNOWN_ODOO_LICENSES:
            self._add(
                "odoo-manifest-unexpected-license",
                "Manifest uses an unexpected license identifier",
                "low",
                f"Manifest license '{license_value}' is not a known Odoo manifest license identifier; verify redistribution and app-store compliance before shipping",
            )

        suspicious_paths = _suspicious_manifest_paths(all_loaded_files)
        if suspicious_paths:
            self._add(
                "odoo-manifest-suspicious-data-path",
                "Manifest loads suspicious file paths",
                "high",
                f"Manifest data/demo paths include absolute or parent-directory traversal entries: {', '.join(suspicious_paths)}; verify packaged data cannot load files outside the module",
            )

        auto_install = _is_auto_install_enabled(data.get("auto_install"))
        if auto_install and _loads_security_data(data_files):
            self._add(
                "odoo-manifest-auto-install-security-data",
                "Auto-installed module loads security-sensitive data",
                "medium",
                "auto_install=True modules can be installed implicitly when dependencies are present; review loaded security, group, ACL, and record-rule data for surprise privilege changes",
            )
        if auto_install and not depends:
            self._add(
                "odoo-manifest-auto-install-without-depends",
                "Auto-installed module has no explicit dependencies",
                "medium",
                "auto_install=True without explicit depends can install unexpectedly; verify this module is intentionally activated in target databases",
            )

        if demo_files and data.get("application") is True:
            self._add(
                "odoo-manifest-application-demo-data",
                "Application module ships demo data",
                "low",
                "Application=True modules with demo data deserve review for accidental sample users, credentials, or records",
            )

        remote_assets = _remote_asset_paths(data.get("assets"))
        remote_assets.extend(_remote_asset_paths(data.get("qweb")))
        if remote_assets:
            self._add(
                "odoo-manifest-remote-assets",
                "Manifest declares remote frontend assets",
                "high",
                f"Manifest frontend assets reference remote URLs: {', '.join(remote_assets)}; verify supply-chain trust, pinning, CSP, and offline install behavior",
            )

        external_dependencies = data.get("external_dependencies")
        if isinstance(external_dependencies, dict):
            python_deps = _as_string_list(external_dependencies.get("python"))
            risky = sorted(set(python_deps) & {"pickle", "yaml", "paramiko", "requests"})
            if risky:
                self._add(
                    "odoo-manifest-risky-python-dependency",
                    "Manifest declares dependency with security-sensitive usage",
                    "info",
                    f"Review usage of security-sensitive dependency declarations: {', '.join(risky)}",
                )

        lifecycle_hooks = [field for field in LIFECYCLE_HOOK_FIELDS if data.get(field)]
        if lifecycle_hooks:
            self._add(
                "odoo-manifest-lifecycle-hook",
                "Manifest declares install/uninstall lifecycle hook",
                "medium",
                f"Manifest declares lifecycle hook(s): {', '.join(lifecycle_hooks)}; review hook code for sudo writes, raw SQL, network calls, idempotency, and uninstall cleanup safety",
            )

        return self.findings

    def _load_manifest(self) -> dict[str, Any] | None:
        try:
            value = ast.literal_eval(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return value if isinstance(value, dict) else None

    def _add(self, rule_id: str, title: str, severity: str, message: str) -> None:
        self.findings.append(
            ManifestFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.manifest_path),
                line=1,
                module=self.module,
                message=message,
            )
        )


def _as_string_list(value: Any) -> list[str]:
    """Return a list of strings from common manifest list-ish fields."""
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def _remote_asset_paths(value: Any) -> list[str]:
    """Return remote URL strings from Odoo asset/qweb manifest declarations."""
    remote: list[str] = []
    if isinstance(value, str):
        if value.startswith(("http://", "https://", "//")):
            remote.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            remote.extend(_remote_asset_paths(item))
    elif isinstance(value, dict):
        for item in value.values():
            remote.extend(_remote_asset_paths(item))
    return remote


def _loads_security_data(data_files: list[str]) -> bool:
    """Return whether manifest data paths look like security-affecting XML/CSV."""
    return any(any(hint in path.lower() for hint in SECURITY_DATA_HINTS) for path in data_files)


def _is_auto_install_enabled(value: Any) -> bool:
    """Return whether Odoo auto_install is enabled."""
    return value is True or isinstance(value, (list, tuple))


def _suspicious_manifest_paths(paths: list[str]) -> list[str]:
    """Return manifest file paths that escape normal relative module data paths."""
    suspicious: list[str] = []
    for path in paths:
        path_obj = Path(path)
        if path_obj.is_absolute() or ".." in path_obj.parts:
            suspicious.append(path)
    return suspicious


def _should_skip(path: Path) -> bool:
    """Skip generated/cache directories."""
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules"})


def findings_to_json(findings: list[ManifestFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "module": f.module,
            "message": f.message,
        }
        for f in findings
    ]
