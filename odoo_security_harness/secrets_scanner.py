"""Heuristic secret and committed config scanner for Odoo repositories."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class SecretFinding:
    """Represents a secret/config finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    secret_kind: str = ""
    redacted: str = ""


SECRET_ASSIGNMENT_RE = re.compile(
    r"['\"]?(?P<name>api[_-]?key|secret|token|password|passwd|pwd|signing[_-]?key|private[_-]?key)"
    r"(?P<suffix>[\w.-]*)['\"]?\s*[:=]\s*['\"](?P<value>[^'\"]{8,})['\"]",
    re.IGNORECASE,
)
CONFIG_PARAMETER_CALL_RE = re.compile(
    r"\.set_param\(\s*['\"](?P<key>[^'\"]*(?:secret|token|password|passwd|api[_-]?key|apikey|signing[_-]?key)[^'\"]*)['\"]"
    r"\s*,\s*['\"](?P<value>[^'\"]{8,})['\"]",
    re.IGNORECASE,
)

CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".env"}
TEXT_EXTENSIONS = {".py", ".xml", ".csv", ".yml", ".yaml", ".json", ".txt", *CONFIG_EXTENSIONS}
LOW_VALUE_PLACEHOLDERS = {"changeme", "change_me", "example", "dummy", "password", "secret", "token", "admin"}
WEAK_USER_PASSWORDS = {"admin", "demo", "password", "changeme", "change_me", "odoo", "test"}


def scan_secrets(repo_path: Path) -> list[SecretFinding]:
    """Scan a repository for committed secrets and risky Odoo config records."""
    findings: list[SecretFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and not path.name.startswith(".env"):
            continue
        findings.extend(SecretScanner(path).scan_file())
    return findings


class SecretScanner:
    """Scanner for one text file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[SecretFinding] = []

    def scan_file(self) -> list[SecretFinding]:
        """Scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        self._scan_literal_assignments(content)
        if self.path.suffix.lower() == ".xml":
            self._scan_config_parameter_xml(content)
            self._scan_res_users_passwords(content)
        if self.path.suffix.lower() in CONFIG_EXTENSIONS or self.path.name.startswith(".env"):
            self._scan_odoo_config(content)
        return self.findings

    def _scan_literal_assignments(self, content: str) -> None:
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in SECRET_ASSIGNMENT_RE.finditer(line):
                value = match.group("value")
                if _looks_placeholder(value):
                    continue
                if _entropy(value) < 3.0 and len(value) < 20:
                    continue
                self._add(
                    "odoo-secret-hardcoded-value",
                    "Hardcoded secret-like value",
                    "high",
                    line_number,
                    f"Secret-like assignment '{match.group('name')}' contains committed value {_redact(value)}; rotate and move to environment/config storage",
                    secret_kind=match.group("name").lower(),
                    redacted=_redact(value),
                )
            for match in CONFIG_PARAMETER_CALL_RE.finditer(line):
                key = match.group("key")
                value = match.group("value")
                if _looks_placeholder(value):
                    continue
                self._add(
                    "odoo-secret-config-parameter-set-param",
                    "Sensitive ir.config_parameter value set in code",
                    "high",
                    line_number,
                    f"Code sets ir.config_parameter '{key}' to committed value {_redact(value)}; avoid shipping production secrets in module code",
                    secret_kind=key,
                    redacted=_redact(value),
                )

    def _scan_config_parameter_xml(self, content: str) -> None:
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return
        except Exception:
            return
        for record in root.iter("record"):
            if record.get("model") != "ir.config_parameter":
                continue
            key = ""
            value = ""
            for field in record.iter("field"):
                if field.get("name") == "key":
                    key = field.text or ""
                elif field.get("name") == "value":
                    value = field.text or ""
            if key and value and _is_sensitive_key(key) and not _looks_placeholder(value):
                self._add(
                    "odoo-secret-config-parameter",
                    "Sensitive ir.config_parameter value committed",
                    "high",
                    _line_for(content, key),
                    f"Module data commits ir.config_parameter '{key}' with value {_redact(value)}; module updates can overwrite production secrets/config",
                    secret_kind=key,
                    redacted=_redact(value),
                )

    def _scan_res_users_passwords(self, content: str) -> None:
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return
        except Exception:
            return
        for record in root.iter("record"):
            if record.get("model") != "res.users":
                continue
            values = {
                field.get("name", ""): _xml_field_literal(field) for field in record.iter("field") if field.get("name")
            }
            login = values.get("login", "")
            for field in record.iter("field"):
                if field.get("name") in {"password", "new_password"}:
                    password = _xml_field_literal(field)
                    if password and _is_weak_user_password(password, login):
                        self._add(
                            "odoo-secret-weak-user-password-data",
                            "Weak user password committed in module data",
                            "critical",
                            _line_for(content, password),
                            "res.users password in XML data is a weak default; remove it and rotate the account",
                            secret_kind="res.users.password",  # noqa: S106 - finding metadata, not a credential
                            redacted=_redact(password),
                        )
                    elif password and not _looks_placeholder(password):
                        self._add(
                            "odoo-secret-user-password-data",
                            "User password committed in module data",
                            "critical",
                            _line_for(content, password),
                            "res.users password is committed in XML data; remove it and rotate the account",
                            secret_kind="res.users.password",  # noqa: S106 - finding metadata, not a credential
                            redacted=_redact(password),
                        )

    def _scan_odoo_config(self, content: str) -> None:
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            key, sep, value = stripped.partition("=")
            if not sep:
                continue
            key = key.strip().lower()
            value = value.strip().strip("'\"")
            if key == "admin_passwd" and (not value or value.lower() == "admin"):
                self._add(
                    "odoo-secret-weak-admin-passwd",
                    "Weak Odoo database manager password",
                    "critical",
                    line_number,
                    "admin_passwd is empty or 'admin'; database manager can be brute-forced or guessed",
                    secret_kind="admin_passwd",  # noqa: S106 - finding metadata, not a credential
                    redacted=_redact(value),
                )
            elif _is_sensitive_key(key) and value and not _looks_placeholder(value):
                self._add(
                    "odoo-secret-config-file-value",
                    "Secret-like value committed in config file",
                    "high",
                    line_number,
                    f"Config file contains '{key}' with committed value {_redact(value)}; keep real secrets out of source",
                    secret_kind=key,
                    redacted=_redact(value),
                )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        secret_kind: str,
        redacted: str,
    ) -> None:
        self.findings.append(
            SecretFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                secret_kind=secret_kind,
                redacted=redacted,
            )
        )


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(
        marker in lowered for marker in ("secret", "token", "password", "passwd", "api_key", "apikey", "signing_key")
    )


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in LOW_VALUE_PLACEHOLDERS:
        return True
    return lowered.startswith(("example_", "dummy_", "test_")) or lowered.endswith(("_example", "_dummy", "_test"))


def _is_weak_user_password(password: str, login: str) -> bool:
    lowered = password.strip().lower()
    if lowered in WEAK_USER_PASSWORDS:
        return True
    login_lowered = login.strip().lower()
    if not login_lowered:
        return False
    return lowered == login_lowered or lowered == login_lowered.partition("@")[0]


def _xml_field_literal(field: ElementTree.Element) -> str:
    value = field.text or field.get("eval", "") or field.get("value", "")
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[SecretFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "secret_kind": f.secret_kind,
            "redacted": f.redacted,
        }
        for f in findings
    ]
