"""Scanner for risky Odoo XML data/external-ID integrity patterns."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class DataIntegrityFinding:
    """Represents a risky XML data integrity finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    record_id: str = ""


CORE_MODULE_PREFIXES = ("base.", "web.", "mail.", "portal.", "auth_signup.", "auth_oauth.")
SENSITIVE_MODELS = {
    "auth.oauth.provider",
    "base.automation",
    "ir.attachment",
    "ir.actions.server",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.alias",
    "payment.provider",
    "payment.transaction",
    "payment.acquirer",
    "res.groups",
    "res.users",
}


def scan_data_integrity(repo_path: Path) -> list[DataIntegrityFinding]:
    """Scan XML data files for risky external-ID and data update patterns."""
    findings: list[DataIntegrityFinding] = []
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        findings.extend(DataIntegrityScanner(path).scan_file())
    return findings


class DataIntegrityScanner:
    """Scanner for one XML data file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[DataIntegrityFinding] = []

    def scan_file(self) -> list[DataIntegrityFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        self._walk(root, inherited_noupdate=False)
        return self.findings

    def _walk(self, element: ElementTree.Element, inherited_noupdate: bool) -> None:
        current_noupdate = inherited_noupdate or _truthy(element.get("noupdate", ""))
        if element.tag == "record":
            self._scan_record(element, current_noupdate)
        elif element.tag == "delete":
            self._scan_delete(element, current_noupdate)
        elif element.tag == "function":
            self._scan_function(element, current_noupdate)
        for child in element:
            self._walk(child, current_noupdate)

    def _scan_record(self, record: ElementTree.Element, noupdate: bool) -> None:
        record_id = record.get("id", "")
        model = record.get("model", "")
        line = self._line_for_record(record)

        if _is_core_external_id(record_id):
            self._add(
                "odoo-data-core-xmlid-override",
                "Module data overrides core external ID",
                "high",
                line,
                f"Record id '{record_id}' appears to target a core module XML ID; verify this intentionally overrides upstream data and survives upgrades",
                model,
                record_id,
            )

        if noupdate and model in SENSITIVE_MODELS:
            self._add(
                "odoo-data-sensitive-noupdate-record",
                "Sensitive data record is protected by noupdate",
                "medium",
                line,
                f"Sensitive model '{model}' is loaded under noupdate; fixes to security data may not apply during module upgrades",
                model,
                record_id,
            )

        if record.get("forcecreate", "").strip().lower() == "false":
            self._add(
                "odoo-data-forcecreate-disabled",
                "XML record disables forcecreate",
                "low",
                line,
                "XML record uses forcecreate=False; missing records will not be recreated during updates, which can hide deleted security/config data",
                model,
                record_id,
            )

        if model == "ir.model.data":
            self._add(
                "odoo-data-manual-ir-model-data",
                "Module data writes ir.model.data directly",
                "high",
                line,
                "Module data creates or changes ir.model.data directly; verify XML ID ownership, noupdate, and update semantics cannot hijack records",
                model,
                record_id,
            )

    def _scan_delete(self, delete: ElementTree.Element, noupdate: bool) -> None:
        record_id = delete.get("id", "")
        model = delete.get("model", "")
        search = delete.get("search", "")
        line = self._line_for_delete(delete)

        if model in SENSITIVE_MODELS:
            self._add(
                "odoo-data-sensitive-delete",
                "XML data deletes security-sensitive records",
                "high",
                line,
                f"XML <delete> targets sensitive model '{model}'; verify module install/update cannot remove security, identity, automation, payment, or configuration records unexpectedly",
                model,
                record_id,
            )

        if _is_core_external_id(record_id):
            self._add(
                "odoo-data-core-xmlid-delete",
                "XML data deletes core external ID",
                "high",
                line,
                f"XML <delete> targets core external ID '{record_id}'; verify the module intentionally removes upstream data and remains safe across upgrades",
                model,
                record_id,
            )

        if model in SENSITIVE_MODELS and search:
            self._add(
                "odoo-data-sensitive-search-delete",
                "XML data search-deletes sensitive records",
                "critical",
                line,
                f"XML <delete> uses a search domain on sensitive model '{model}'; verify broad or version-dependent matches cannot remove security-critical records",
                model,
                record_id,
            )

        if noupdate and model in SENSITIVE_MODELS:
            self._add(
                "odoo-data-sensitive-noupdate-delete",
                "Sensitive XML delete is protected by noupdate",
                "medium",
                line,
                f"Sensitive delete for model '{model}' is under noupdate; future security fixes or cleanup changes may not apply during module upgrades",
                model,
                record_id,
            )

    def _scan_function(self, function: ElementTree.Element, noupdate: bool) -> None:
        model = function.get("model", "")
        name = function.get("name", "")
        line = self._line_for_function(function)

        if model in SENSITIVE_MODELS and name in {"create", "write", "unlink"}:
            self._add(
                "odoo-data-sensitive-function-mutation",
                "XML function mutates security-sensitive records",
                "high",
                line,
                f"XML <function> calls {model}.{name}; verify module install/update cannot silently alter security, identity, automation, payment, or configuration records",
                model,
                "",
            )

        if noupdate and model in SENSITIVE_MODELS:
            self._add(
                "odoo-data-sensitive-noupdate-function",
                "Sensitive XML function is protected by noupdate",
                "medium",
                line,
                f"Sensitive XML <function> for model '{model}' is under noupdate; future security fixes or cleanup changes may not apply during module upgrades",
                model,
                "",
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, f'model="{record.get("model", "")}"')

    def _line_for_delete(self, delete: ElementTree.Element) -> int:
        record_id = delete.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        model = delete.get("model")
        if model:
            return _line_for(self.content, f'model="{model}"')
        return _line_for(self.content, "<delete")

    def _line_for_function(self, function: ElementTree.Element) -> int:
        model = function.get("model", "")
        name = function.get("name", "")
        for needle in (f'<function model="{model}" name="{name}"', f'<function name="{name}" model="{model}"'):
            line = _line_for(self.content, needle)
            if line != 1:
                return line
        return _line_for(self.content, "<function")

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        record_id: str,
    ) -> None:
        self.findings.append(
            DataIntegrityFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                record_id=record_id,
            )
        )


def _is_core_external_id(record_id: str) -> bool:
    return record_id.startswith(CORE_MODULE_PREFIXES)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[DataIntegrityFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in findings
    ]
