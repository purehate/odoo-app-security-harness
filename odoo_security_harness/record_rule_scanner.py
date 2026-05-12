"""Scanner for risky Odoo record-rule domain declarations."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

from odoo_security_harness.base_scanner import XmlScanner, _record_fields, _should_skip


@dataclass
class RecordRuleFinding:
    """Represents a risky record-rule finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    record_id: str = ""
    group: str = ""


SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.attachment",
    "mail.message",
    "payment.transaction",
    "purchase.order",
    "res.partner",
    "res.users",
    "sale.order",
    "stock.picking",
}
SECURITY_MODELS = {
    "ir.config_parameter",
    "ir.model.access",
    "ir.rule",
    "ir.actions.server",
    "payment.provider",
    "res.groups",
    "res.users.apikeys",
}
KNOWN_MODEL_EXTERNAL_IDS = {
    "account.model_account_move": "account.move",
    "model_account_move": "account.move",
    "base.model_ir_attachment": "ir.attachment",
    "model_ir_attachment": "ir.attachment",
    "base.model_ir_config_parameter": "ir.config_parameter",
    "model_ir_config_parameter": "ir.config_parameter",
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
PUBLIC_GROUPS = {"base.group_public", "base.group_portal"}
OWNER_SCOPE_MARKERS = (
    "user.id",
    "user.partner_id",
    "partner_id",
    "message_partner_ids",
    "commercial_partner_id",
    "access_token",
    "company_id",
    "company_ids",
)
SUBJECT_SCOPE_MARKERS = (
    "user.id",
    "user.partner_id",
    "partner_id",
    "message_partner_ids",
    "commercial_partner_id",
    "access_token",
)
COMPANY_SCOPE_MARKERS = ("company_id", "company_ids")


def scan_record_rules(repo_path: Path) -> list[RecordRuleFinding]:
    """Scan record rules for risky domain and permission patterns."""
    findings: list[RecordRuleFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = RecordRuleScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class RecordRuleScanner(XmlScanner):
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.findings: list[RecordRuleFinding] = []

    def scan_xml(self) -> None:
        """Scan record-rule declarations."""
        for record in self.root.iter("record"):
            if record.get("model") == "ir.rule":
                self._scan_rule(record)

    def scan_csv_file(self) -> list[RecordRuleFinding]:
        """Scan CSV ir.rule declarations."""
        if _csv_model_name(self.path) != "ir.rule":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_rule_fields(fields, fields.get("id", ""), line)
        return self.findings

    def _scan_rule(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = self._line_for_record(record)
        self._scan_rule_fields(fields, record_id, line)

    def _scan_rule_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        model = _normalize_model_ref(fields.get("model_id", ""))
        domain = fields.get("domain_force", "")
        groups = _extract_groups(fields.get("groups", "") or fields.get("groups_id", ""))
        group_text = ",".join(groups)
        write_perms = _truthy(fields.get("perm_write", "")) or _truthy(fields.get("perm_create", ""))
        unlink_perm = _truthy(fields.get("perm_unlink", ""))
        broadly_sensitive = _requires_strict_scope(model)

        if broadly_sensitive and _is_universal_domain(domain):
            self._add(
                "odoo-record-rule-universal-domain",
                "Record rule grants universal domain on sensitive model",
                "critical" if _has_public_scope(groups) else "high",
                line,
                f"Record rule '{record_id}' uses an empty or tautological domain on sensitive/security model '{model}'; verify every permitted group should see all records",
                model,
                record_id,
                group_text,
            )

        if broadly_sensitive and _has_public_scope(groups) and not _has_owner_scope(domain):
            self._add(
                "odoo-record-rule-public-sensitive-no-owner-scope",
                "Public/portal rule on sensitive/security model lacks owner scope",
                "critical",
                line,
                (
                    f"Record rule '{record_id}' targets sensitive/security model '{model}' for public/portal users "
                    "without an obvious owner, token, or company scope"
                ),
                model,
                record_id,
                group_text,
            )

        if (
            broadly_sensitive
            and _has_explicit_public_group(groups)
            and _has_company_scope(domain)
            and not _has_subject_or_token_scope(domain)
        ):
            self._add(
                "odoo-record-rule-public-sensitive-company-only-scope",
                "Public/portal rule relies only on company scope",
                "medium",
                line,
                (
                    f"Record rule '{record_id}' scopes sensitive/security model '{model}' for public/portal users "
                    "by company only; verify portal users cannot list unrelated records from the same company"
                ),
                model,
                record_id,
                group_text,
            )

        if broadly_sensitive and _has_public_scope(groups) and (write_perms or unlink_perm):
            self._add(
                "odoo-record-rule-portal-write-sensitive",
                "Public/portal rule enables mutation on sensitive/security model",
                "critical",
                line,
                f"Record rule '{record_id}' enables write/create/delete on sensitive/security model '{model}' for public/portal users",
                model,
                record_id,
                group_text,
            )

        if broadly_sensitive and not groups and (write_perms or unlink_perm):
            self._add(
                "odoo-record-rule-global-sensitive-mutation",
                "Global record rule enables mutation on sensitive/security model",
                "high",
                line,
                f"Record rule '{record_id}' enables write/create/delete on sensitive/security model '{model}' without group scoping",
                model,
                record_id,
                group_text,
            )

        if "has_group" in domain:
            self._add(
                "odoo-record-rule-domain-has-group",
                "Record-rule domain performs group checks",
                "medium",
                line,
                (
                    f"Record rule '{record_id}' calls has_group() inside domain_force; review caching, "
                    "domain evaluation, and privilege-boundary assumptions"
                ),
                model,
                record_id,
                group_text,
            )

        if _uses_context_domain(domain):
            self._add(
                "odoo-record-rule-context-dependent-domain",
                "Record-rule domain depends on context",
                "medium",
                line,
                (
                    f"Record rule '{record_id}' reads context inside domain_force; verify caller-controlled "
                    "context cannot widen access or bypass company/owner scoping"
                ),
                model,
                record_id,
                group_text,
            )

        if "child_of" in domain and ("user.company_id" in domain or "user.company_ids" in domain):
            self._add(
                "odoo-record-rule-company-child-of",
                "Record rule uses company hierarchy expansion",
                "medium",
                line,
                (
                    f"Record rule '{record_id}' uses child_of with user companies; verify parent/child "
                    "company access is intentional for this model"
                ),
                model,
                record_id,
                group_text,
            )

        if _explicitly_all_perms_false(fields):
            self._add(
                "odoo-record-rule-empty-permissions",
                "Record rule has all permissions disabled",
                "low",
                line,
                f"Record rule '{record_id}' sets every perm_* flag false and may be ineffective or misleading",
                model,
                record_id,
                group_text,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        record_id: str,
        group: str,
    ) -> None:
        self.findings.append(
            RecordRuleFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                record_id=record_id,
                group=group,
            )
        )


def _csv_model_name(path: Path) -> str:
    return path.stem.strip().lower().replace("_", ".")


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


def _extract_groups(value: str) -> list[str]:
    groups = re.findall(r"ref\(['\"]([^'\"]+)['\"]\)", value)
    if not groups:
        groups = re.findall(r"[A-Za-z_][\w]*\.[A-Za-z_][\w]*", value)
    if value and not groups and "." in value:
        groups.append(value)
    return groups


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


def _requires_strict_scope(model: str) -> bool:
    return model in SENSITIVE_MODELS or model in SECURITY_MODELS


def _has_public_scope(groups: list[str]) -> bool:
    return not groups or any(group in PUBLIC_GROUPS for group in groups)


def _has_explicit_public_group(groups: list[str]) -> bool:
    return any(group in PUBLIC_GROUPS for group in groups)


def _has_owner_scope(domain: str) -> bool:
    compact = re.sub(r"\s+", "", domain)
    return any(marker in compact for marker in OWNER_SCOPE_MARKERS)


def _has_subject_or_token_scope(domain: str) -> bool:
    compact = re.sub(r"\s+", "", domain)
    return any(marker in compact for marker in SUBJECT_SCOPE_MARKERS)


def _has_company_scope(domain: str) -> bool:
    compact = re.sub(r"\s+", "", domain)
    return any(marker in compact for marker in COMPANY_SCOPE_MARKERS)


def _is_universal_domain(domain: str) -> bool:
    compact = re.sub(r"\s+", "", domain).lower()
    if compact in {"", "[]", "[()]", "[(1,'=',1)]", '[(1,"=",1)]', "[('1','=','1')]", '[("1","=","1")]'}:
        return True
    return bool(
        re.search(r"\[\(?1,?['\"]={1,2}['\"]?,?1\)?\]", compact)
        or re.search(r"\[\(?true,?['\"]={1,2}['\"]?,?true\)?\]", compact)
    )


def _uses_context_domain(domain: str) -> bool:
    compact = re.sub(r"\s+", "", domain).lower()
    return "context.get(" in compact or "context[" in compact or "env.context" in compact


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _explicitly_all_perms_false(fields: dict[str, str]) -> bool:
    perm_names = {"perm_read", "perm_write", "perm_create", "perm_unlink"}
    return perm_names <= set(fields) and not any(_truthy(fields[name]) for name in perm_names)


def findings_to_json(findings: list[RecordRuleFinding]) -> list[dict[str, Any]]:
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
            "group": f.group,
        }
        for f in findings
    ]
