"""Scanner for security-sensitive Odoo metadata records."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class MetadataFinding:
    """Represents a risky Odoo metadata/data-record finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    record_id: str = ""


PUBLIC_GROUPS = {"base.group_public", "base.group_portal"}
INTERNAL_GROUPS = {"base.group_user"}
ADMIN_GROUPS = {"base.group_system", "base.group_erp_manager", "base.group_no_one"}
MANAGER_GROUP_PATTERNS = (
    re.compile(r"\bgroup_.*manager\b"),
    re.compile(r"\bgroup_.*administrator\b"),
)
SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.message",
    "payment.provider",
    "payment.transaction",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
    "sale.order",
    "stock.picking",
}
KNOWN_MODEL_EXTERNAL_IDS = {
    "account.model_account_move": "account.move",
    "model_account_move": "account.move",
    "base.model_ir_attachment": "ir.attachment",
    "model_ir_attachment": "ir.attachment",
    "base.model_ir_config_parameter": "ir.config_parameter",
    "model_ir_config_parameter": "ir.config_parameter",
    "base.model_ir_cron": "ir.cron",
    "model_ir_cron": "ir.cron",
    "base.model_ir_model_access": "ir.model.access",
    "model_ir_model_access": "ir.model.access",
    "base.model_ir_rule": "ir.rule",
    "model_ir_rule": "ir.rule",
    "base.model_res_groups": "res.groups",
    "model_res_groups": "res.groups",
    "base.model_res_users": "res.users",
    "model_res_users": "res.users",
    "base.model_res_users_apikeys": "res.users.apikeys",
    "model_res_users_apikeys": "res.users.apikeys",
    "payment.model_payment_provider": "payment.provider",
    "model_payment_provider": "payment.provider",
    "payment.model_payment_transaction": "payment.transaction",
    "model_payment_transaction": "payment.transaction",
}
SENSITIVE_FIELD_MARKERS = (
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "secret",
    "token",
)


def scan_metadata(repo_path: Path) -> list[MetadataFinding]:
    """Scan XML/CSV data files for risky access metadata."""
    findings: list[MetadataFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix.lower() == ".xml":
            findings.extend(MetadataScanner(path).scan_xml_file())
        elif path.suffix.lower() == ".csv":
            findings.extend(MetadataScanner(path).scan_csv_file())
    return findings


class MetadataScanner:
    """Scanner for one metadata file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[MetadataFinding] = []

    def scan_xml_file(self) -> list[MetadataFinding]:
        """Scan XML data records."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            model = record.get("model", "")
            if model == "ir.model.access":
                self._scan_xml_acl(record)
            elif model == "ir.model.fields":
                self._scan_model_field_record(record)
            elif model == "res.groups":
                self._scan_group_record(record)
            elif model == "res.users":
                self._scan_user_record(record)
        return self.findings

    def scan_csv_file(self) -> list[MetadataFinding]:
        """Scan CSV data files for ACL-like records."""
        try:
            with self.path.open("r", encoding="utf-8", newline="") as handle:
                rows = [_normalize_csv_row(row) for row in csv.DictReader(handle)]
        except Exception:
            return []

        model = _csv_model_name(self.path)
        for index, row in enumerate(rows, start=2):
            if _looks_acl_row(row):
                self._scan_acl_values(row, index, row.get("id", ""))
            if model == "ir.model.fields":
                self._scan_model_field_values(row, index, row.get("id", ""))
            if model == "res.groups":
                self._scan_group_values(row, index, row.get("id", ""))
            if _looks_user_group_row(row, self.path):
                self._scan_user_group_values(row, index, row.get("id", ""))
        return self.findings

    def _scan_xml_acl(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        line = self._line_for_record(record)
        values = {
            "id": record.get("id", ""),
            "model": _normalize_model_ref(fields.get("model_id", "")),
            "group": fields.get("group_id", ""),
            "perm_read": fields.get("perm_read", ""),
            "perm_write": fields.get("perm_write", ""),
            "perm_create": fields.get("perm_create", ""),
            "perm_unlink": fields.get("perm_unlink", ""),
        }
        self._scan_acl_values(values, line, record.get("id", ""))

    def _scan_acl_values(self, values: dict[str, str], line: int, record_id: str) -> None:
        group = values.get("group", "") or values.get("group_id", "") or values.get("group_id:id", "")
        model = _normalize_model_ref(
            values.get("model", "") or values.get("model_id", "") or values.get("model_id:id", "")
        )
        write_bits = [
            _truthy(values.get("perm_write", "")),
            _truthy(values.get("perm_create", "")),
            _truthy(values.get("perm_unlink", "")),
        ]

        if group in PUBLIC_GROUPS and any(write_bits):
            self._add(
                "odoo-metadata-public-write-acl",
                "Public/portal ACL grants write/create/delete",
                "critical",
                line,
                f"ACL grants write/create/delete permissions to {group}; verify this model is explicitly safe for public or portal mutation",
                "ir.model.access",
                record_id,
            )
        elif group in PUBLIC_GROUPS and _truthy(values.get("perm_read", "")) and model in SENSITIVE_MODELS:
            self._add(
                "odoo-metadata-sensitive-public-read-acl",
                "Public/portal ACL grants read on sensitive model",
                "high",
                line,
                f"ACL grants read permission on sensitive model '{model}' to {group}; verify record rules prevent cross-user exposure",
                "ir.model.access",
                record_id,
            )

    def _scan_group_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        self._scan_group_values(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_group_values(self, values: dict[str, str], line: int, record_id: str) -> None:
        implied = values.get("implied_ids", "")
        if not implied:
            return
        if _contains_admin_group(implied):
            self._add(
                "odoo-metadata-group-implies-admin",
                "Group implies administrator-level privileges",
                "high",
                line,
                "res.groups record implies administrator/manager-level groups; verify this is intentional and not assigned by portal/signup flows",
                "res.groups",
                record_id,
            )
        if _contains_internal_group(implied):
            self._add(
                "odoo-metadata-group-implies-internal-user",
                "Group implies internal user privileges",
                "medium",
                line,
                "res.groups record implies base.group_user; verify portal/public/signup flows cannot assign this group and become internal users",
                "res.groups",
                record_id,
            )

    def _scan_user_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        self._scan_user_group_values(
            {"groups_id": groups, "id": record.get("id", "")}, self._line_for_record(record), record.get("id", "")
        )

    def _scan_user_group_values(self, values: dict[str, str], line: int, record_id: str) -> None:
        groups = " ".join(
            values.get(name, "")
            for name in ("groups_id", "groups", "groups_id:id", "groups_id/id", "group_id", "group_id:id")
        )
        if not groups:
            return
        if _contains_admin_group(groups):
            self._add(
                "odoo-metadata-user-admin-group-assignment",
                "User data assigns administrator-level group",
                "critical",
                line,
                "res.users metadata assigns administrator/manager-level groups; verify module install/update or CSV imports cannot grant unintended administrator access",
                "res.users",
                record_id,
            )
        elif _contains_internal_group(groups):
            self._add(
                "odoo-metadata-user-internal-group-assignment",
                "User data assigns internal user group",
                "high",
                line,
                "res.users metadata assigns base.group_user; verify demo/imported/signup users are not silently promoted to internal users",
                "res.users",
                record_id,
            )

    def _scan_model_field_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        self._scan_model_field_values(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_model_field_values(self, values: dict[str, str], line: int, record_id: str) -> None:
        field_name = values.get("name", "")
        model_name = _normalize_model_ref(values.get("model_id", ""))
        groups = values.get("groups", "") or values.get("groups_id", "")
        readonly = values.get("readonly", "")
        compute = values.get("compute", "")
        is_sensitive = _is_sensitive_field(field_name)

        if is_sensitive and _contains_public_group(groups):
            self._add(
                "odoo-metadata-sensitive-field-public-groups",
                "Field metadata exposes sensitive field to public/portal groups",
                "critical",
                line,
                f"ir.model.fields record '{record_id}' assigns public/portal groups to sensitive field '{field_name}'; verify the field cannot leak credentials or tokens",
                "ir.model.fields",
                record_id,
            )
        elif is_sensitive and not groups and (field_name or model_name):
            self._add(
                "odoo-metadata-sensitive-field-no-groups",
                "Field metadata defines sensitive field without groups",
                "high",
                line,
                f"ir.model.fields record '{record_id}' defines sensitive-looking field '{field_name}' without groups; verify only trusted users can read it",
                "ir.model.fields",
                record_id,
            )

        if is_sensitive and _falsey(readonly):
            self._add(
                "odoo-metadata-sensitive-field-readonly-disabled",
                "Field metadata makes sensitive field writable",
                "high",
                line,
                f"ir.model.fields record '{record_id}' sets readonly=False on sensitive field '{field_name}'; verify write access is explicitly restricted",
                "ir.model.fields",
                record_id,
            )

        if compute and _contains_dynamic_compute(compute):
            self._add(
                "odoo-metadata-field-dynamic-compute",
                "Field metadata contains dynamic compute code",
                "high",
                line,
                f"ir.model.fields record '{record_id}' contains dynamic compute code; verify no user-controlled data can affect evaluated or sudo behavior",
                "ir.model.fields",
                record_id,
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        model = record.get("model", "")
        return _line_for(self.content, f'model="{model}"')

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
            MetadataFinding(
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


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or (field.text or "").strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "ir_model_fields": "ir.model.fields",
        "ir.model.fields": "ir.model.fields",
        "res_groups": "res.groups",
        "res.groups": "res.groups",
        "res_users": "res.users",
        "res.users": "res.users",
        "ir_model_access": "ir.model.access",
        "ir.model.access": "ir.model.access",
    }
    return aliases.get(stem, stem.replace("_", "."))


def _normalize_csv_row(row: dict[str, str]) -> dict[str, str]:
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
    return normalized


def _looks_acl_row(row: dict[str, str]) -> bool:
    keys = set(row)
    return bool({"perm_read", "perm_write", "perm_create", "perm_unlink"} & keys) and bool(
        {"model_id:id", "model_id"} & keys
    )


def _looks_user_group_row(row: dict[str, str], path: Path) -> bool:
    keys = set(row)
    has_group_column = bool({"groups_id", "groups", "groups_id:id", "groups_id/id", "group_id", "group_id:id"} & keys)
    has_user_marker = (
        bool({"login", "email", "password"} & keys) or "res.users" in path.stem or "res_users" in path.stem
    )
    return has_group_column and has_user_marker


def _normalize_model_ref(value: str) -> str:
    normalized = value.strip().strip("'\"")
    if normalized in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[normalized]
    external_id = normalized.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if normalized.startswith("model_"):
        return normalized.removeprefix("model_").replace("_", ".")
    if ".model_" in normalized:
        return normalized.rsplit(".model_", 1)[1].replace("_", ".")
    return normalized


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _contains_admin_group(value: str) -> bool:
    lowered = value.lower()
    if any(group in lowered for group in ADMIN_GROUPS):
        return True
    return any(pattern.search(lowered) for pattern in MANAGER_GROUP_PATTERNS)


def _contains_internal_group(value: str) -> bool:
    lowered = value.lower()
    return any(group in lowered for group in INTERNAL_GROUPS)


def _contains_public_group(value: str) -> bool:
    return any(group in value for group in PUBLIC_GROUPS)


def _is_sensitive_field(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


def _falsey(value: str) -> bool:
    return str(value).strip().lower() in {"0", "false", "no", "n"}


def _contains_dynamic_compute(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("eval(", "exec(", "safe_eval", ".sudo(", "env[", "request."))


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[MetadataFinding]) -> list[dict[str, Any]]:
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
