"""Scanner for risky Odoo inbound mail alias records."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from odoo_security_harness.base_scanner import _record_fields, XmlScanner, _should_skip


@dataclass
class MailAliasFinding:
    """Represents a risky mail.alias finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    alias: str = ""
    model: str = ""


SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "payment.provider",
    "payment.transaction",
    "purchase.order",
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
PERMISSIVE_CONTACT_VALUES = {"everyone", "partners"}
ELEVATED_DEFAULT_HINTS = (
    "base.group_system",
    "base.group_erp_manager",
    "group_system",
    "group_erp_manager",
    "user_id",
    "sudo",
    "company_id",
)
PRIVILEGED_ALIAS_USER_HINTS = {
    "1",
    "base.user_admin",
    "base.user_root",
    "user_admin",
    "user_root",
}


def scan_mail_aliases(repo_path: Path) -> list[MailAliasFinding]:
    """Scan XML/CSV data files for risky mail.alias records."""
    findings: list[MailAliasFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = MailAliasScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class MailAliasScanner(XmlScanner):
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.findings: list[MailAliasFinding] = []

    def scan_xml(self) -> None:
        """Scan mail.alias records."""
        for record in self.root.iter("record"):
            if record.get("model") == "mail.alias":
                self._scan_alias(record)
            else:
                fields = _record_fields(record)
                if _has_alias_policy_fields(fields):
                    self._scan_alias_fields(
                        fields,
                        record.get("id", ""),
                        self._line_for_record(record),
                        owner_model=record.get("model", ""),
                    )

    def scan_csv_file(self) -> list[MailAliasFinding]:
        """Scan mail.alias CSV data records."""
        model = _csv_model_name(self.path)
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        for fields, line_number in _csv_dict_rows(self.content):
            if model == "mail.alias" or _has_alias_policy_fields(fields):
                self._scan_alias_fields(fields, fields.get("id", ""), line_number, owner_model=model)
        return self.findings

    def _scan_alias(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        alias_id = record.get("id", "")
        line = self._line_for_record(record)
        self._scan_alias_fields(fields, alias_id, line)

    def _scan_alias_fields(
        self, fields: dict[str, str], alias_id: str, line: int, *, owner_model: str = ""
    ) -> None:
        target_model = _model_value(fields.get("alias_model_id", "") or fields.get("alias_model", ""))
        if not target_model and owner_model != "mail.alias":
            target_model = owner_model
        alias_contact = fields.get("alias_contact", "").strip("'\"").lower()
        defaults = fields.get("alias_defaults", "")
        alias_user = fields.get("alias_user_id", "")
        force_thread = fields.get("alias_force_thread_id", "")

        if target_model in SENSITIVE_MODELS and alias_contact in PERMISSIVE_CONTACT_VALUES:
            self._add(
                "odoo-mail-alias-public-sensitive-model",
                "Public inbound alias targets sensitive model",
                "high",
                line,
                f"mail.alias allows '{alias_contact}' to create or route mail into sensitive model '{target_model}'; verify inbound email cannot create private or privileged records",
                alias_id,
                target_model,
            )

        if alias_contact in {"everyone", "partners", ""}:
            self._add(
                "odoo-mail-alias-broad-contact-policy",
                "Inbound alias accepts broad senders",
                "medium",
                line,
                "mail.alias accepts everyone, partners, or has no explicit alias_contact policy; verify spam, spoofing, and unauthorized record creation controls",
                alias_id,
                target_model,
            )

        if defaults and _contains_elevated_defaults(defaults):
            self._add(
                "odoo-mail-alias-elevated-defaults",
                "Inbound alias applies privileged defaults",
                "high",
                line,
                "mail.alias alias_defaults appears to set users, groups, sudo/company fields, or elevated defaults; verify inbound mail cannot assign privileged ownership or access",
                alias_id,
                target_model,
            )

        if defaults and re.search(r"\b(eval|exec|safe_eval)\s*\(", defaults):
            self._add(
                "odoo-mail-alias-dynamic-defaults",
                "Inbound alias defaults perform dynamic evaluation",
                "critical",
                line,
                "mail.alias alias_defaults contains eval/exec/safe_eval; verify no inbound email data can affect evaluated code",
                alias_id,
                target_model,
            )

        if _is_privileged_alias_user(alias_user):
            self._add(
                "odoo-mail-alias-privileged-owner",
                "Inbound alias runs as privileged owner",
                "high",
                line,
                "mail.alias uses an admin/root alias_user_id; verify inbound email cannot create or route records with privileged ownership",
                alias_id,
                target_model,
            )

        if force_thread and alias_contact in {"everyone", "partners", ""}:
            self._add(
                "odoo-mail-alias-public-force-thread",
                "Broad inbound alias forces messages into an existing thread",
                "medium",
                line,
                "mail.alias accepts broad senders and sets alias_force_thread_id; verify external senders cannot inject chatter, attachments, or state changes into an existing record",
                alias_id,
                target_model,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        alias: str,
        model: str,
    ) -> None:
        self.findings.append(
            MailAliasFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                alias=alias,
                model=model,
            )
        )


def _model_value(value: str) -> str:
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


def _contains_elevated_defaults(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in ELEVATED_DEFAULT_HINTS)


def _is_privileged_alias_user(value: str) -> bool:
    lowered = value.strip().strip("'\"").lower()
    return lowered in PRIVILEGED_ALIAS_USER_HINTS or lowered.endswith(".user_admin") or lowered.endswith(".user_root")


def _has_alias_policy_fields(fields: dict[str, str]) -> bool:
    return any(name.startswith("alias_") for name in fields) and any(
        name in fields
        for name in (
            "alias_contact",
            "alias_defaults",
            "alias_force_thread_id",
            "alias_model",
            "alias_model_id",
            "alias_user_id",
        )
    )


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    return stem.replace("_", ".")


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
                if "/" in name or ":" in name:
                    normalized.setdefault(re.split(r"[/:]", name, maxsplit=1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def findings_to_json(findings: list[MailAliasFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "alias": f.alias,
            "model": f.model,
        }
        for f in findings
    ]
