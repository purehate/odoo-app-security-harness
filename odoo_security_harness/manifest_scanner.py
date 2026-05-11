"""Odoo manifest security and packaging scanner."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from odoo_security_harness.base_scanner import _should_skip

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
LIFECYCLE_HOOK_FIELDS = ("pre_init_hook", "post_init_hook", "uninstall_hook", "post_load")
RISKY_PYTHON_DEPENDENCIES = {
    "aiohttp",
    "authlib",
    "azure-storage-blob",
    "boto3",
    "botocore",
    "cryptography",
    "fabric",
    "google-api-python-client",
    "google-cloud-storage",
    "grpcio",
    "httpx",
    "jwcrypto",
    "jwt",
    "ldap3",
    "lxml",
    "msal",
    "msal-extensions",
    "oauthlib",
    "openai",
    "paramiko",
    "pika",
    "pickle",
    "pycryptodome",
    "pycryptodomex",
    "pyjwt",
    "pysftp",
    "python-ldap",
    "python-jose",
    "pyyaml",
    "redis",
    "requests",
    "requests-oauthlib",
    "sentry-sdk",
    "signxml",
    "slack-sdk",
    "stripe",
    "suds",
    "twilio",
    "urllib3",
    "xmlsec",
    "zeep",
}
RISKY_BINARY_DEPENDENCIES = {
    "aws",
    "chrome",
    "chromium",
    "curl",
    "docker",
    "gcloud",
    "gpg",
    "gs",
    "kubectl",
    "node",
    "npm",
    "openssl",
    "pg_dump",
    "psql",
    "rsync",
    "ssh",
    "wkhtmltopdf",
    "wget",
}
PYTHON_DEPENDENCY_NAME_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.-]+)")
DIRECT_PYTHON_DEPENDENCY_PREFIXES = (
    "git+",
    "hg+",
    "svn+",
    "bzr+",
    "http://",
    "https://",
    "file://",
)
VCS_PYTHON_DEPENDENCY_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
LOCAL_DEPENDENCY_PATH_PREFIXES = ("file://", "./", "../", "/", "~/", ".\\", "..\\", "\\\\", "~\\")
FLOATING_VCS_REFS = {"main", "master", "develop", "dev", "trunk", "head"}
IMMUTABLE_VCS_REF_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
WINDOWS_ABSOLUTE_DEPENDENCY_RE = re.compile(r"^[a-z]:[\\/]", re.IGNORECASE)


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
        asset_files = _manifest_file_paths(data.get("assets"))
        qweb_files = _manifest_file_paths(data.get("qweb"))
        all_loaded_files = [*data_files, *demo_files]
        all_manifest_paths = [*all_loaded_files, *asset_files, *qweb_files]
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

        suspicious_paths = _suspicious_manifest_paths(all_manifest_paths)
        if suspicious_paths:
            self._add(
                "odoo-manifest-suspicious-data-path",
                "Manifest loads suspicious local file paths",
                "high",
                f"Manifest local file paths include absolute or parent-directory traversal entries: {', '.join(suspicious_paths)}; verify packaged data and assets cannot load files outside the module",
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
        insecure_remote_assets = [asset for asset in remote_assets if _is_insecure_http_url(asset)]
        if insecure_remote_assets:
            self._add(
                "odoo-manifest-insecure-remote-asset",
                "Manifest declares insecure HTTP frontend asset",
                "medium",
                f"Manifest frontend assets reference cleartext http:// URLs: {', '.join(insecure_remote_assets)}; use HTTPS or packaged same-origin assets to avoid mixed-content downgrade and interception risk",
            )
        protocol_relative_assets = [asset for asset in remote_assets if _is_protocol_relative_url(asset)]
        if protocol_relative_assets:
            self._add(
                "odoo-manifest-protocol-relative-remote-asset",
                "Manifest declares protocol-relative frontend asset",
                "medium",
                f"Manifest frontend assets reference protocol-relative URLs: {', '.join(protocol_relative_assets)}; use explicit https:// or packaged same-origin assets to avoid scheme downgrade and CSP ambiguity",
            )
        credentialed_remote_assets = [asset for asset in remote_assets if _has_url_embedded_credentials(asset)]
        if credentialed_remote_assets:
            self._add(
                "odoo-manifest-remote-asset-embedded-credentials",
                "Manifest remote frontend asset URL embeds credentials",
                "high",
                f"Manifest frontend assets embed username, password, or token material in URLs: {', '.join(credentialed_remote_assets)}; keep credentials out of browser-visible asset declarations and package trusted assets locally",
            )

        external_dependencies = data.get("external_dependencies")
        if isinstance(external_dependencies, dict):
            python_deps = _as_string_list(external_dependencies.get("python"))
            risky = _risky_python_dependencies(python_deps)
            if risky:
                self._add(
                    "odoo-manifest-risky-python-dependency",
                    "Manifest declares dependency with security-sensitive usage",
                    "info",
                    f"Review usage of security-sensitive dependency declarations: {', '.join(risky)}",
                )
            direct_refs = _direct_python_dependency_references(python_deps)
            if direct_refs:
                self._add(
                    "odoo-manifest-direct-python-dependency",
                    "Manifest declares direct Python dependency reference",
                    "medium",
                    f"Manifest Python dependencies include direct URL, VCS, or local-file references: {', '.join(direct_refs)}; pin immutable artifacts and verify dependency provenance before deployment",
                )
            insecure_direct_refs = _insecure_direct_python_dependency_references(python_deps)
            if insecure_direct_refs:
                self._add(
                    "odoo-manifest-insecure-python-dependency",
                    "Manifest declares insecure HTTP Python dependency",
                    "high",
                    f"Manifest Python dependencies include cleartext http:// package references: {', '.join(insecure_direct_refs)}; fetch dependencies over HTTPS or a trusted internal package index with immutable pins",
                )
            credentialed_direct_refs = _credentialed_python_dependency_references(python_deps)
            if credentialed_direct_refs:
                self._add(
                    "odoo-manifest-python-dependency-embedded-credentials",
                    "Manifest Python dependency URL embeds credentials",
                    "high",
                    f"Manifest Python dependencies embed username, password, or token material in URLs: {', '.join(credentialed_direct_refs)}; use credential helpers, private indexes, or deployment secrets instead of committed dependency URLs",
                )
            floating_vcs_refs = _floating_vcs_python_dependency_references(python_deps)
            if floating_vcs_refs:
                self._add(
                    "odoo-manifest-floating-vcs-python-dependency",
                    "Manifest declares floating VCS Python dependency",
                    "medium",
                    f"Manifest Python dependencies include VCS references without immutable commit pins: {', '.join(floating_vcs_refs)}; pin reviewed commit hashes to avoid unreviewed install-time code changes",
                )
            local_refs = _local_python_dependency_references(python_deps)
            if local_refs:
                self._add(
                    "odoo-manifest-local-python-dependency",
                    "Manifest declares local Python dependency path",
                    "medium",
                    f"Manifest Python dependencies include local filesystem paths: {', '.join(local_refs)}; use reviewed package indexes or immutable artifacts instead of environment-dependent install paths",
                )
            bin_deps = _as_string_list(external_dependencies.get("bin"))
            risky_bins = _risky_binary_dependencies(bin_deps)
            if risky_bins:
                self._add(
                    "odoo-manifest-risky-bin-dependency",
                    "Manifest declares binary dependency with security-sensitive usage",
                    "info",
                    f"Review usage of security-sensitive binary dependency declarations: {', '.join(risky_bins)}",
                )
            local_bins = _local_binary_dependency_references(bin_deps)
            if local_bins:
                self._add(
                    "odoo-manifest-local-bin-dependency",
                    "Manifest declares local binary dependency path",
                    "medium",
                    f"Manifest binary dependencies include local filesystem paths: {', '.join(local_bins)}; prefer named system dependencies or documented container packages over environment-specific executable paths",
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
        if _is_remote_url(value):
            remote.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            remote.extend(_remote_asset_paths(item))
    elif isinstance(value, dict):
        for item in value.values():
            remote.extend(_remote_asset_paths(item))
    return remote


def _manifest_file_paths(value: Any) -> list[str]:
    """Return local path strings from nested manifest path declarations."""
    paths: list[str] = []
    if isinstance(value, str):
        if not _is_remote_url(value):
            paths.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            paths.extend(_manifest_file_paths(item))
    elif isinstance(value, dict):
        for item in value.values():
            paths.extend(_manifest_file_paths(item))
    return paths


def _is_remote_url(value: str) -> bool:
    """Return whether a manifest string is a remote URL-like asset reference."""
    return value.startswith(("http://", "https://", "//"))


def _is_insecure_http_url(value: str) -> bool:
    """Return whether a manifest string is an insecure cleartext URL."""
    return value.lower().startswith("http://")


def _is_protocol_relative_url(value: str) -> bool:
    """Return whether a manifest string inherits the current document scheme."""
    return value.startswith("//")


def _has_url_embedded_credentials(value: str) -> bool:
    """Return whether a manifest string contains URL userinfo credentials."""
    for match in re.finditer(r"https?://[^\s'\"<>)]+", value, re.IGNORECASE):
        parsed = urlparse(match.group(0).rstrip(".,;"))
        if parsed.hostname and (parsed.username is not None or parsed.password is not None):
            return True
    return False


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


def _risky_python_dependencies(dependencies: list[str]) -> list[str]:
    """Return manifest dependencies whose usage deserves security review."""
    risky: list[str] = []
    for dependency in dependencies:
        package_name = _python_dependency_name(dependency)
        if package_name == "yaml":
            package_name = "pyyaml"
        if package_name in RISKY_PYTHON_DEPENDENCIES:
            risky.append(dependency)
    return sorted(set(risky), key=str.lower)


def _python_dependency_name(dependency: str) -> str:
    """Return a normalized package name from common manifest/requirement spellings."""
    match = PYTHON_DEPENDENCY_NAME_RE.match(dependency)
    if not match:
        return ""
    return match.group("name").lower().replace("_", "-").split("[", 1)[0]


def _direct_python_dependency_references(dependencies: list[str]) -> list[str]:
    """Return direct URL, VCS, or local-file Python dependency declarations."""
    direct: list[str] = []
    for dependency in dependencies:
        normalized = dependency.strip().lower()
        if normalized.startswith(DIRECT_PYTHON_DEPENDENCY_PREFIXES) or " @ " in normalized:
            direct.append(dependency)
    return sorted(set(direct), key=str.lower)


def _insecure_direct_python_dependency_references(dependencies: list[str]) -> list[str]:
    """Return direct Python dependency declarations fetched over cleartext HTTP."""
    insecure: list[str] = []
    for dependency in dependencies:
        normalized = dependency.strip().lower()
        if normalized.startswith("http://") or "+http://" in normalized or " @ http://" in normalized:
            insecure.append(dependency)
    return sorted(set(insecure), key=str.lower)


def _credentialed_python_dependency_references(dependencies: list[str]) -> list[str]:
    """Return Python dependency declarations with URL-embedded credentials."""
    credentialed: list[str] = []
    for dependency in dependencies:
        if _has_url_embedded_credentials(dependency):
            credentialed.append(dependency)
    return sorted(set(credentialed), key=str.lower)


def _floating_vcs_python_dependency_references(dependencies: list[str]) -> list[str]:
    """Return VCS dependency declarations that are not pinned to immutable commits."""
    floating: list[str] = []
    for dependency in dependencies:
        normalized = dependency.strip().lower()
        if not normalized.startswith(VCS_PYTHON_DEPENDENCY_PREFIXES):
            continue
        ref_source = normalized.split("#", 1)[0]
        if "@" not in ref_source:
            floating.append(dependency)
            continue
        ref = ref_source.rsplit("@", 1)[1].strip()
        if not ref or ref in FLOATING_VCS_REFS or not IMMUTABLE_VCS_REF_RE.fullmatch(ref):
            floating.append(dependency)
    return sorted(set(floating), key=str.lower)


def _local_python_dependency_references(dependencies: list[str]) -> list[str]:
    """Return direct Python dependency declarations that point at local filesystem paths."""
    local: list[str] = []
    for dependency in dependencies:
        normalized = dependency.strip().lower()
        reference = normalized.rsplit(" @ ", 1)[1].strip() if " @ " in normalized else normalized
        if reference.startswith(LOCAL_DEPENDENCY_PATH_PREFIXES) or WINDOWS_ABSOLUTE_DEPENDENCY_RE.match(reference):
            local.append(dependency)
    return sorted(set(local), key=str.lower)


def _risky_binary_dependencies(dependencies: list[str]) -> list[str]:
    """Return manifest binary dependencies whose usage deserves security review."""
    risky: list[str] = []
    for dependency in dependencies:
        package_name = Path(dependency.strip().lower()).name
        if package_name in RISKY_BINARY_DEPENDENCIES:
            risky.append(dependency)
    return sorted(set(risky), key=str.lower)


def _local_binary_dependency_references(dependencies: list[str]) -> list[str]:
    """Return binary dependency declarations that point at local filesystem paths."""
    local: list[str] = []
    for dependency in dependencies:
        normalized = dependency.strip().lower()
        if normalized.startswith(LOCAL_DEPENDENCY_PATH_PREFIXES) or WINDOWS_ABSOLUTE_DEPENDENCY_RE.match(normalized):
            local.append(dependency)
    return sorted(set(local), key=str.lower)


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
