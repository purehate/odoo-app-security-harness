"""Deployment posture scanner for Odoo configuration and XML parameters."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException


@dataclass
class DeploymentFinding:
    """Represents an insecure deployment/configuration finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    key: str = ""
    value: str = ""


CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".env"}
COMPOSE_FILENAMES = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
DOCKERFILE_NAMES = {"containerfile", "dockerfile"}
TRUTHY = {"1", "true", "yes", "y", "on"}
FALSY = {"0", "false", "no", "n", "off"}
SENSITIVE_DEBUG_LOGGERS = {"odoo.http", "odoo.sql_db", "odoo.addons", "werkzeug"}
LOW_VALUE_PLACEHOLDERS = {"changeme", "change_me", "example", "dummy", "secret", "client_secret"}
OPPORTUNISTIC_DB_SSLMODES = {"disable", "allow", "prefer"}
LOCAL_BASE_URL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}  # noqa: S104


def scan_deployment_config(repo_path: Path) -> list[DeploymentFinding]:
    """Scan Odoo deployment config and data files for insecure production posture."""
    findings: list[DeploymentFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if _looks_config_file(path):
            findings.extend(DeploymentScanner(path).scan_file())
        elif path.suffix.lower() in {".xml", ".csv"}:
            findings.extend(DeploymentScanner(path).scan_file())
    return findings


class DeploymentScanner:
    """Scanner for one deployment-related file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[DeploymentFinding] = []
        self.content = ""

    def scan_file(self) -> list[DeploymentFinding]:
        """Scan the file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        suffix = self.path.suffix.lower()
        if suffix == ".xml":
            self._scan_config_parameter_xml()
        elif suffix == ".csv":
            self._scan_config_parameter_csv()
        elif _is_compose_file(self.path):
            self._scan_compose_environment()
        elif suffix in {".yaml", ".yml"}:
            self._scan_kubernetes_environment()
        elif _is_dockerfile(self.path):
            self._scan_dockerfile_config_lines()
        else:
            self._scan_config_lines()
        return self.findings

    def _scan_config_lines(self) -> None:
        for line_number, line in enumerate(self.content.splitlines(), start=1):
            parsed = _parse_assignment(line)
            if not parsed:
                continue
            key, value = parsed
            self._scan_config_value(key, value, line_number)

    def _scan_dockerfile_config_lines(self) -> None:
        for line_number, line in enumerate(self.content.splitlines(), start=1):
            parsed = _parse_dockerfile_env_assignment(line)
            if not parsed:
                continue
            key, value = parsed
            self._scan_config_value(key, value, line_number)

    def _scan_compose_environment(self) -> None:
        try:
            document = yaml.safe_load(self.content)
        except yaml.YAMLError:
            return
        if not isinstance(document, dict):
            return
        services = document.get("services")
        if not isinstance(services, dict):
            return
        for service in services.values():
            if not isinstance(service, dict):
                continue
            environment = service.get("environment")
            for key, value in _compose_environment_items(environment):
                self._scan_config_value(key, value, _line_for(self.content, str(key)))

    def _scan_kubernetes_environment(self) -> None:
        try:
            documents = list(yaml.safe_load_all(self.content))
        except yaml.YAMLError:
            return
        for document in documents:
            if not _looks_kubernetes_manifest(document):
                continue
            for key, value in _kubernetes_environment_items(document):
                self._scan_config_value(key, value, _line_for(self.content, str(key)))

    def _scan_config_parameter_xml(self) -> None:
        try:
            root = ElementTree.fromstring(self.content)
        except (ElementTree.ParseError, DefusedXmlException):
            return

        for record in root.iter("record"):
            if record.get("model") == "auth.oauth.provider":
                self._scan_oauth_provider_xml(record)
                continue
            if record.get("model") != "ir.config_parameter":
                continue
            fields = _record_fields(record)
            key = fields.get("key", "")
            value = fields.get("value", "")
            if key:
                self._scan_config_value(key, value, _line_for(self.content, key))

    def _scan_config_parameter_csv(self) -> None:
        model = _csv_model_name(self.path)
        if model not in {"auth.oauth.provider", "ir.config_parameter"}:
            return

        for fields, line in _csv_dict_rows(self.content):
            if model == "auth.oauth.provider":
                self._scan_oauth_provider_fields(fields, fields.get("id", ""), line)
                continue
            key = fields.get("key", "")
            value = fields.get("value", "")
            if key:
                self._scan_config_value(key, value, line)

    def _scan_oauth_provider_xml(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(self.content, f'id="{record_id}"')
            if record_id
            else _line_for(self.content, "auth.oauth.provider")
        )
        self._scan_oauth_provider_fields(fields, record_id, line)

    def _scan_oauth_provider_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        enabled = fields.get("enabled", "")
        if enabled and not _is_truthy(enabled):
            return

        provider_name = fields.get("name", record_id or "auth.oauth.provider")
        endpoints = {
            "auth_endpoint": fields.get("auth_endpoint", ""),
            "validation_endpoint": fields.get("validation_endpoint", ""),
            "data_endpoint": fields.get("data_endpoint", ""),
            "token_endpoint": fields.get("token_endpoint", ""),
        }

        if not endpoints["validation_endpoint"]:
            self._add(
                "odoo-deploy-oauth-missing-validation-endpoint",
                "OAuth provider lacks validation endpoint",
                "high",
                line,
                "Enabled auth.oauth.provider has no validation_endpoint; verify tokens are validated against the provider before account login/signup",
                provider_name,
                record_id,
            )

        for key, value in endpoints.items():
            if value.strip().lower().startswith("http://"):
                self._add(
                    "odoo-deploy-oauth-insecure-endpoint",
                    "OAuth provider uses insecure HTTP endpoint",
                    "high",
                    line,
                    f"auth.oauth.provider field '{key}' uses HTTP; OAuth tokens and identities must use HTTPS endpoints",
                    key,
                    value,
                )

        client_secret = fields.get("client_secret", "")
        if client_secret and not _looks_placeholder(client_secret):
            self._add(
                "odoo-deploy-oauth-client-secret-committed",
                "OAuth client secret committed in module data",
                "high",
                line,
                "auth.oauth.provider commits client_secret in XML data; move provider secrets to environment/provisioning storage and rotate the secret",
                "client_secret",
                _redact(client_secret),
            )

    def _scan_config_value(self, key: str, value: str, line: int) -> None:
        normalized_key = _normalize_config_key(key)
        normalized_value = value.strip().strip("'\"").lower()

        if normalized_key in {"admin_passwd", "admin_password"}:
            if not normalized_value or _looks_placeholder(normalized_value) or len(normalized_value) < 12:
                self._add(
                    "odoo-deploy-weak-admin-passwd",
                    "Odoo database manager master password is weak",
                    "critical",
                    line,
                    "admin_passwd is empty, short, or placeholder-like; database manager and maintenance flows require a strong environment-specific master password",
                    key,
                    _redact(value),
                )
            else:
                self._add(
                    "odoo-deploy-admin-passwd-committed",
                    "Odoo database manager master password is committed",
                    "high",
                    line,
                    "admin_passwd appears to be committed in deployment config; move it to secret storage and rotate it before production use",
                    key,
                    _redact(value),
                )
        elif normalized_key in {"dev_mode", "dev"} and normalized_value and normalized_value not in FALSY:
            self._add(
                "odoo-deploy-dev-mode-enabled",
                "Developer mode is enabled in deployment config",
                "high",
                line,
                "dev/dev_mode is enabled; production deployments should not run reload, qweb, xml, werkzeug, or all developer modes",
                key,
                value,
            )
        elif normalized_key == "test_enable" and _is_truthy(normalized_value):
            self._add(
                "odoo-deploy-test-enable",
                "Test mode is enabled in deployment config",
                "medium",
                line,
                "test_enable is true; production deployments should not run with test hooks or test-specific behavior enabled",
                key,
                value,
            )
        elif normalized_key == "list_db" and _is_truthy(normalized_value):
            self._add(
                "odoo-deploy-list-db-enabled",
                "Database listing is enabled",
                "high",
                line,
                "list_db is enabled; attackers can enumerate database names and target login/database-manager flows",
                key,
                value,
            )
        elif normalized_key in {"database.create", "database_create"} and _is_truthy(normalized_value):
            self._add(
                "odoo-deploy-database-create-enabled",
                "Database creation is enabled",
                "high",
                line,
                "database.create is enabled; verify unauthenticated or low-privilege users cannot create new databases through database-manager flows",
                key,
                value,
            )
        elif normalized_key in {"database.drop", "database_drop"} and _is_truthy(normalized_value):
            self._add(
                "odoo-deploy-database-drop-enabled",
                "Database drop is enabled",
                "critical",
                line,
                "database.drop is enabled; verify database-manager access is disabled or strongly restricted to prevent destructive tenant/database deletion",
                key,
                value,
            )
        elif normalized_key == "dbfilter" and not normalized_value:
            self._add(
                "odoo-deploy-empty-dbfilter",
                "Database filter is empty",
                "medium",
                line,
                "dbfilter is empty; multi-database deployments can expose unexpected databases to a hostname",
                key,
                value,
            )
        elif normalized_key == "dbfilter" and _is_wildcard_dbfilter(normalized_value):
            self._add(
                "odoo-deploy-wildcard-dbfilter",
                "Database filter matches arbitrary database names",
                "medium",
                line,
                "dbfilter is wildcard-like; multi-database deployments should bind databases to expected hostnames to prevent cross-database confusion",
                key,
                value,
            )
        elif normalized_key == "proxy_mode" and _is_falsy(normalized_value):
            self._add(
                "odoo-deploy-proxy-mode-disabled",
                "Proxy mode is disabled",
                "medium",
                line,
                "proxy_mode is disabled; reverse-proxy deployments can mishandle scheme/client IP and weaken secure-cookie or URL behavior",
                key,
                value,
            )
        elif normalized_key == "db_sslmode" and normalized_value in OPPORTUNISTIC_DB_SSLMODES:
            self._add(
                "odoo-deploy-db-sslmode-opportunistic",
                "Database TLS mode is opportunistic or disabled",
                "medium",
                line,
                "db_sslmode does not require verified PostgreSQL TLS; production deployments should use verify-full or verify-ca when the database is remote or untrusted",
                key,
                value,
            )
        elif normalized_key == "workers" and _is_nonpositive_integer(normalized_value):
            self._add(
                "odoo-deploy-workers-disabled",
                "Odoo workers are disabled",
                "medium",
                line,
                "workers is zero or negative; production deployments should use prefork workers so slow requests, reports, or cron jobs do not block the whole service",
                key,
                value,
            )
        elif normalized_key in {"limit_time_cpu", "limit_time_real"} and _is_nonpositive_integer(normalized_value):
            self._add(
                "odoo-deploy-time-limit-disabled",
                "Worker execution time limit is disabled",
                "medium",
                line,
                f"{key} is zero or negative; production deployments should enforce worker time limits to contain slow reports, imports, and integrations",
                key,
                value,
            )
        elif normalized_key == "log_level" and normalized_value in {"debug", "debug_sql"}:
            self._add(
                "odoo-deploy-debug-logging",
                "Debug logging is enabled",
                "medium",
                line,
                "Debug logging is enabled; production logs can expose SQL, request data, tokens, or PII",
                key,
                value,
            )
        elif normalized_key == "log_handler" and _has_sensitive_debug_handler(value):
            self._add(
                "odoo-deploy-debug-log-handler",
                "Sensitive debug log handler is enabled",
                "medium",
                line,
                "log_handler enables DEBUG for sensitive Odoo/web loggers; production logs can expose SQL, request data, tokens, or PII",
                key,
                value,
            )
        elif normalized_key in {"web.base.url.freeze", "web_base_url_freeze"} and _is_falsy(normalized_value):
            self._add(
                "odoo-deploy-base-url-not-frozen",
                "Base URL is not frozen",
                "medium",
                line,
                "web.base.url.freeze is false; host-header or proxy mistakes can affect generated links such as portal and reset URLs",
                key,
                value,
            )
        elif normalized_key in {"web.base.url", "web_base_url"} and _is_insecure_base_url(value):
            self._add(
                "odoo-deploy-insecure-base-url",
                "Base URL uses an insecure or local endpoint",
                "medium",
                line,
                "web.base.url uses HTTP or a local host; generated portal, OAuth, and password-reset links should use the public HTTPS origin",
                key,
                value,
            )
        elif normalized_key in {"auth_signup.allow_uninvited", "auth_signup_allow_uninvited"} and _is_truthy(
            normalized_value
        ):
            self._add(
                "odoo-deploy-open-signup",
                "Uninvited public signup is enabled",
                "medium",
                line,
                "auth_signup.allow_uninvited is enabled; verify public account creation cannot grant portal/internal access unexpectedly",
                key,
                value,
            )
        elif normalized_key in {"auth_oauth.allow_signup", "auth_oauth_allow_signup"} and _is_truthy(normalized_value):
            self._add(
                "odoo-deploy-oauth-auto-signup",
                "OAuth auto-signup is enabled",
                "medium",
                line,
                "auth_oauth.allow_signup is enabled; verify OAuth providers and domain restrictions cannot create unintended accounts",
                key,
                value,
            )
        elif (
            normalized_key in {"auth_signup.invitation_scope", "auth_signup_invitation_scope"}
            and normalized_value == "b2c"
        ):
            self._add(
                "odoo-deploy-b2c-signup",
                "B2C signup scope is enabled",
                "low",
                line,
                "auth_signup.invitation_scope is b2c; confirm this module is intended to allow broad self-registration",
                key,
                value,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        key: str,
        value: str,
    ) -> None:
        self.findings.append(
            DeploymentFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                key=key,
                value=value,
            )
        )


def _parse_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";", "[")):
        return None
    key, sep, value = stripped.partition("=")
    if not sep:
        return None
    return key.strip(), value.split("#", 1)[0].split(";", 1)[0].strip()


def _parse_dockerfile_env_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    directive, sep, rest = stripped.partition(" ")
    if not sep or directive.upper() not in {"ARG", "ENV"}:
        return None
    key, equals, value = rest.strip().partition("=")
    if not equals:
        key, _, value = rest.strip().partition(" ")
    if not key or not value:
        return None
    return key.strip(), value.split("#", 1)[0].strip()


def _compose_environment_items(environment: object) -> list[tuple[str, str]]:
    if isinstance(environment, dict):
        return [(str(key), str(value)) for key, value in environment.items() if value is not None]
    if not isinstance(environment, list):
        return []
    items: list[tuple[str, str]] = []
    for entry in environment:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        if key and value:
            items.append((key, value))
    return items


def _looks_kubernetes_manifest(document: object) -> bool:
    return isinstance(document, dict) and "apiVersion" in document and "kind" in document


def _kubernetes_environment_items(document: object) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for container in _kubernetes_containers(document):
        environment = container.get("env")
        if not isinstance(environment, list):
            continue
        for entry in environment:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            value = entry.get("value")
            if name and value is not None:
                items.append((str(name), str(value)))
    return items


def _kubernetes_containers(node: object) -> list[dict[str, object]]:
    containers: list[dict[str, object]] = []
    if isinstance(node, dict):
        for key in ("containers", "initContainers"):
            values = node.get(key)
            if isinstance(values, list):
                containers.extend(item for item in values if isinstance(item, dict))
        for value in node.values():
            containers.extend(_kubernetes_containers(value))
    elif isinstance(node, list):
        for value in node:
            containers.extend(_kubernetes_containers(value))
    return containers


def _normalize_config_key(key: str) -> str:
    normalized = key.strip().lower().replace("-", "_")
    if normalized.startswith("odoo_"):
        normalized = normalized.removeprefix("odoo_")
    return normalized


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("eval") or (field.text or "").strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "auth_oauth_provider": "auth.oauth.provider",
        "auth.oauth.provider": "auth.oauth.provider",
        "ir_config_parameter": "ir.config_parameter",
        "ir.config_parameter": "ir.config_parameter",
    }
    return aliases.get(stem, stem.replace("_", "."))


def _csv_dict_rows(content: str) -> list[tuple[dict[str, str], int]]:
    try:
        reader = DictReader(StringIO(content))
    except Exception:
        return []
    if not reader.fieldnames:
        return []

    rows: list[tuple[dict[str, str], int]] = []
    try:
        for index, row in enumerate(reader, start=2):
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is None:
                    continue
                name = str(key).strip().lower()
                text = str(value or "").strip()
                normalized[name] = text
                if "/" in name:
                    normalized.setdefault(name.split("/", 1)[0], text)
                if ":" in name:
                    normalized.setdefault(name.split(":", 1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _looks_config_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return (
        suffix in CONFIG_EXTENSIONS
        or path.name.startswith(".env")
        or path.name == "odoo.conf"
        or _is_compose_file(path)
        or suffix in {".yaml", ".yml"}
        or _is_dockerfile(path)
    )


def _is_compose_file(path: Path) -> bool:
    return path.name.lower() in COMPOSE_FILENAMES


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name in DOCKERFILE_NAMES or name.startswith(("dockerfile.", "containerfile."))


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in TRUTHY


def _is_falsy(value: str) -> bool:
    return value.strip().lower() in FALSY


def _is_nonpositive_integer(value: str) -> bool:
    try:
        return int(value.strip()) <= 0
    except ValueError:
        return False


def _is_wildcard_dbfilter(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    return normalized in {".*", "^.*$", ".*$", "^.*", ".+"} or normalized.replace(" ", "") in {".*|.*", "(.*)"}


def _is_insecure_base_url(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    if normalized.startswith("http://"):
        return True
    parsed = urlparse(normalized)
    return (parsed.hostname or "") in LOCAL_BASE_URL_HOSTS


def _has_sensitive_debug_handler(value: str) -> bool:
    for part in re.split(r"[,;]", value.lower()):
        logger, _, level = part.strip().partition(":")
        if level == "debug" and (logger in SENSITIVE_DEBUG_LOGGERS or logger.startswith("odoo.")):
            return True
    return False


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in LOW_VALUE_PLACEHOLDERS or lowered.startswith(("example_", "test_", "dummy_"))


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", ".audit-deep"})


def findings_to_json(findings: list[DeploymentFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "key": f.key,
            "value": f.value,
        }
        for f in findings
    ]
