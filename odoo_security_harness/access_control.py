"""Access Control Analyzer - Automated analysis of Odoo ACLs and record rules.

Analyzes:
- ir.model.access.csv files for overly permissive grants
- security/*.xml files for ir.rule definitions
- Model definitions for missing ACL references
- Group hierarchy for privilege escalation
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

KNOWN_MODEL_EXTERNAL_IDS = {
    "model_ir_config_parameter": "ir.config_parameter",
}


@dataclass
class ACLFinding:
    """Represents an access control security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    module: str
    message: str
    model: str = ""
    group: str = ""


@dataclass
class ACLRow:
    """Represents a parsed ACL CSV row."""

    id: str
    name: str
    model_id: str
    group_id: str
    perm_read: bool
    perm_write: bool
    perm_create: bool
    perm_unlink: bool
    file: str
    line: int
    module: str = ""


@dataclass
class RecordRule:
    """Represents a parsed ir.rule record."""

    id: str
    name: str
    model_id: str
    domain_force: str
    groups: list[str]
    perm_read: bool
    perm_write: bool
    perm_create: bool
    perm_unlink: bool
    file: str
    line: int
    module: str = ""


class AccessControlAnalyzer:
    """Analyzer for Odoo access control configuration."""

    # Dangerous groups that shouldn't have broad access
    DANGEROUS_GROUPS = {
        "base.group_public": "anonymous public users",
        "base.group_portal": "portal users",
    }

    ADMIN_GROUPS = {
        "base.group_erp_manager",
        "base.group_system",
    }

    SECURITY_MODELS = {
        "ir.config_parameter": "System parameters",
        "ir.model.access": "Access control entries",
        "ir.rule": "Record rules",
        "ir.actions.server": "Server actions",
        "payment.provider": "Payment providers",
        "res.groups": "Security groups",
        "res.users.apikeys": "User API keys",
    }

    # Sensitive models that need strict access
    SENSITIVE_MODELS = {
        "res.users": "Users",
        "res.partner": "Partners",
        "account.move": "Accounting",
        "account.payment": "Payments",
        "sale.order": "Sales",
        "purchase.order": "Purchases",
        "payment.transaction": "Payment transactions",
        "hr.employee": "HR",
        "hr.contract": "HR contracts",
        "stock.picking": "Inventory",
        "ir.attachment": "Attachments",
        "mail.message": "Messages",
    }

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self.findings: list[ACLFinding] = []
        self.acl_rows: list[ACLRow] = []
        self.record_rules: list[RecordRule] = []

    def analyze(self) -> list[ACLFinding]:
        """Analyze all access control files in the repository."""
        self._analyze_acl_files()
        self._analyze_record_rules()
        self._check_acl_coverage()
        self._check_dangerous_permissions()
        self._check_record_rules()
        return self.findings

    def _analyze_acl_files(self) -> None:
        """Parse all ir.model.access.csv files."""
        for csv_file in self.repo_path.rglob("ir.model.access.csv"):
            module = self._get_module_name(csv_file)
            try:
                with csv_file.open("r", encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f)
                    for line_num, row in enumerate(reader, start=2):
                        acl_row = self._parse_acl_row(row, str(csv_file), line_num, module)
                        if acl_row:
                            self.acl_rows.append(acl_row)
            except Exception as exc:
                print(f"Warning: Could not parse {csv_file}: {exc}")

    def _parse_acl_row(self, row: dict[str, str], file: str, line: int, module: str) -> ACLRow | None:
        """Parse a single ACL CSV row."""
        try:
            return ACLRow(
                id=row.get("id", ""),
                name=row.get("name", ""),
                model_id=_csv_ref(row, "model_id"),
                group_id=_csv_ref(row, "group_id"),
                perm_read=_truthy_permission(row.get("perm_read", "0")),
                perm_write=_truthy_permission(row.get("perm_write", "0")),
                perm_create=_truthy_permission(row.get("perm_create", "0")),
                perm_unlink=_truthy_permission(row.get("perm_unlink", "0")),
                file=file,
                line=line,
                module=module,
            )
        except Exception:
            return None

    def _analyze_record_rules(self) -> None:
        """Parse all security XML files for ir.rule records."""
        for xml_file in self.repo_path.rglob("security/*.xml"):
            module = self._get_module_name(xml_file)
            try:
                tree = ElementTree.parse(xml_file)
                root = tree.getroot()
                self._extract_record_rules(root, str(xml_file), module)
            except ElementTree.ParseError:
                # Try regex-based extraction for malformed XML
                self._extract_record_rules_regex(xml_file, module)
            except DefusedXmlException:
                continue
            except Exception as exc:
                print(f"Warning: Could not parse {xml_file}: {exc}")

    def _extract_record_rules(self, root: ElementTree.Element, file: str, module: str) -> None:
        """Extract ir.rule records from XML."""
        for record in root.iter("record"):
            if record.get("model") == "ir.rule":
                rule = self._parse_record_rule(record, file, module)
                if rule:
                    self.record_rules.append(rule)

    def _parse_record_rule(self, record: ElementTree.Element, file: str, module: str) -> RecordRule | None:
        """Parse a single ir.rule record."""
        try:
            rule_id = record.get("id", "")
            name = ""
            model_id = ""
            domain_force = ""
            groups: list[str] = []
            perm_read = False
            perm_write = False
            perm_create = False
            perm_unlink = False

            for field in record.iter("field"):
                field_name = field.get("name", "")
                if field_name == "name":
                    name = field.text or ""
                elif field_name == "model_id":
                    model_id = field.text or ""
                    # Handle ref attribute
                    if not model_id and field.get("ref"):
                        model_id = field.get("ref", "")
                elif field_name == "domain_force":
                    domain_force = field.text or ""
                elif field_name in {"groups", "groups_id"}:
                    # Parse groups eval
                    eval_attr = field.get("eval", "")
                    groups = self._parse_groups_eval(eval_attr)
                    if field.get("ref"):
                        groups.append(field.get("ref", ""))
                elif field_name.startswith("perm_"):
                    value = field.get("eval", field.text or "")
                    if field_name == "perm_read":
                        perm_read = _truthy_permission(value)
                    elif field_name == "perm_write":
                        perm_write = _truthy_permission(value)
                    elif field_name == "perm_create":
                        perm_create = _truthy_permission(value)
                    elif field_name == "perm_unlink":
                        perm_unlink = _truthy_permission(value)

            return RecordRule(
                id=rule_id,
                name=name,
                model_id=model_id,
                domain_force=domain_force,
                groups=groups,
                perm_read=perm_read,
                perm_write=perm_write,
                perm_create=perm_create,
                perm_unlink=perm_unlink,
                file=file,
                line=0,
                module=module,
            )
        except Exception:
            return None

    def _parse_groups_eval(self, eval_str: str) -> list[str]:
        """Parse groups eval attribute like [(4, ref('base.group_user'))]."""
        groups: list[str] = []
        # Extract ref('...') patterns
        for match in re.finditer(r"ref\(['\"]([^'\"]+)['\"]\)", eval_str):
            groups.append(match.group(1))
        return groups

    def _extract_record_rules_regex(self, xml_file: Path, module: str) -> None:
        """Fallback regex-based extraction for malformed XML."""
        try:
            content = xml_file.read_text(encoding="utf-8")
            # Find ir.rule records
            for match in re.finditer(
                r'<record[^>]*model="ir.rule"[^>]*>(.*?)\u003c/record>',
                content,
                re.DOTALL,
            ):
                record_xml = match.group(1)
                # Extract domain_force
                domain_match = re.search(
                    r'<field name="domain_force"[^>]*>(.*?)\u003c/field>',
                    record_xml,
                    re.DOTALL,
                )
                if domain_match:
                    domain_force = domain_match.group(1).strip()
                    # Check for universal pass
                    if "(1, '=', 1)" in domain_force or "[('1', '=', '1')]" in domain_force:
                        line = content[: match.start()].count("\n") + 1
                        self.findings.append(
                            ACLFinding(
                                rule_id="odoo-acl-universal-pass",
                                title="Record rule with universal pass domain",
                                severity="high",
                                file=str(xml_file),
                                line=line,
                                module=module,
                                message="Record rule has domain_force=[(1,'=',1)] which allows all records",
                            )
                        )
        except Exception:
            return

    def _check_acl_coverage(self) -> None:
        """Check if sensitive models have proper ACL coverage."""
        models_with_acl: set[str] = set()
        for acl in self.acl_rows:
            models_with_acl.add(self._normalize_model_id(acl.model_id))

        for model, description in self.SENSITIVE_MODELS.items():
            if model not in models_with_acl:
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-missing-sensitive",
                        title=f"Missing ACL for sensitive model: {model}",
                        severity="medium",
                        file="",
                        line=0,
                        module="",
                        message=f"{description} model ({model}) has no ACL entries; verify access is intentional",
                        model=model,
                    )
                )

    def _check_dangerous_permissions(self) -> None:
        """Check for dangerous permission grants."""
        for acl in self.acl_rows:
            normalized_model = self._normalize_model_id(acl.model_id)
            # Check if public/portal has write access
            if acl.group_id in self.DANGEROUS_GROUPS:
                if acl.perm_read and normalized_model in self.SENSITIVE_MODELS:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-public-read-sensitive",
                            title=f"{self.DANGEROUS_GROUPS[acl.group_id]} can read sensitive model",
                            severity="high",
                            file=acl.file,
                            line=acl.line,
                            module=acl.module,
                            message=f"Group {acl.group_id} has read access on sensitive model {acl.model_id}",
                            model=acl.model_id,
                            group=acl.group_id,
                        )
                    )
                if acl.perm_write or acl.perm_create or acl.perm_unlink:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-public-write",
                            title=f"{self.DANGEROUS_GROUPS[acl.group_id]} has write access",
                            severity="high",
                            file=acl.file,
                            line=acl.line,
                            module=acl.module,
                            message=f"Group {acl.group_id} has write/create/unlink on {acl.model_id}",
                            model=acl.model_id,
                            group=acl.group_id,
                        )
                    )

            if normalized_model in self.SECURITY_MODELS and (
                acl.perm_read or acl.perm_write or acl.perm_create or acl.perm_unlink
            ):
                if acl.group_id not in self.ADMIN_GROUPS:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-security-model-non-admin",
                            title="Security metadata model ACL is not admin-scoped",
                            severity="critical",
                            file=acl.file,
                            line=acl.line,
                            module=acl.module,
                            message=f"ACL {acl.id} grants access on {self.SECURITY_MODELS[normalized_model]} model {acl.model_id} outside administrator groups; verify users cannot inspect or mutate security configuration",
                            model=acl.model_id,
                            group=acl.group_id,
                        )
                    )

            # Check for overly permissive grants (all permissions to everyone)
            if not acl.group_id and acl.perm_read and normalized_model in self.SENSITIVE_MODELS:
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-global-read-sensitive",
                        title="Global read access to sensitive model",
                        severity="high",
                        file=acl.file,
                        line=acl.line,
                        module=acl.module,
                        message=f"ACL {acl.id} grants read access on sensitive model {acl.model_id} to all internal users",
                        model=acl.model_id,
                    )
                )
            if not acl.group_id and (acl.perm_write or acl.perm_create or acl.perm_unlink):
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-global-write",
                        title="Global write access without group restriction",
                        severity="medium",
                        file=acl.file,
                        line=acl.line,
                        module=acl.module,
                        message=f"ACL {acl.id} grants write/create/unlink to all users (no group)",
                        model=acl.model_id,
                    )
                )

            if acl.perm_unlink and normalized_model in self.SENSITIVE_MODELS:
                if acl.group_id not in self.ADMIN_GROUPS:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-sensitive-unlink",
                            title="Sensitive model grants delete access outside admin groups",
                            severity="high",
                            file=acl.file,
                            line=acl.line,
                            module=acl.module,
                            message=f"ACL {acl.id} grants unlink on sensitive model {acl.model_id}; verify this is limited to trusted administrators",
                            model=acl.model_id,
                            group=acl.group_id,
                        )
                    )

            if (acl.perm_write or acl.perm_create) and normalized_model in self.SENSITIVE_MODELS:
                if acl.group_id not in self.ADMIN_GROUPS:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-sensitive-write",
                            title="Sensitive model grants write/create outside admin groups",
                            severity="high",
                            file=acl.file,
                            line=acl.line,
                            module=acl.module,
                            message=f"ACL {acl.id} grants write/create on sensitive model {acl.model_id}; verify mutation access is limited to trusted business roles",
                            model=acl.model_id,
                            group=acl.group_id,
                        )
                    )

    def _check_record_rules(self) -> None:
        """Check record rules for security issues."""
        for rule in self.record_rules:
            normalized_model = self._normalize_model_id(rule.model_id)
            # Check for universal pass
            if _is_universal_domain(rule.domain_force):
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-universal-pass",
                        title="Record rule with universal pass",
                        severity="high",
                        file=rule.file,
                        line=rule.line,
                        module=rule.module,
                        message=f"Rule '{rule.name}' allows all records with [(1,'=',1)]",
                        model=normalized_model,
                    )
                )

            if self._model_requires_strict_rule_scope(normalized_model) and (
                not rule.domain_force.strip() or _is_universal_domain(rule.domain_force)
            ):
                if any(group in self.DANGEROUS_GROUPS for group in rule.groups):
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-public-rule-broad-sensitive",
                            title="Public/portal rule broadly exposes sensitive model",
                            severity="critical",
                            file=rule.file,
                            line=rule.line,
                            module=rule.module,
                            message=f"Rule '{rule.name}' gives public/portal users a broad domain on sensitive/security model {normalized_model}",
                            model=normalized_model,
                            group=",".join(rule.groups),
                        )
                    )

            if rule.perm_unlink and self._model_requires_strict_rule_scope(normalized_model):
                if not rule.groups or any(group not in self.ADMIN_GROUPS for group in rule.groups):
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-rule-sensitive-unlink",
                            title="Record rule enables delete on sensitive model",
                            severity="high",
                            file=rule.file,
                            line=rule.line,
                            module=rule.module,
                            message=f"Rule '{rule.name}' enables unlink on sensitive/security model {normalized_model}; verify delete permission is administratively scoped",
                            model=normalized_model,
                            group=",".join(rule.groups),
                        )
                    )

            if self._model_requires_strict_rule_scope(normalized_model) and (
                rule.perm_write or rule.perm_create or rule.perm_unlink
            ):
                dangerous_groups = [group for group in rule.groups if group in self.DANGEROUS_GROUPS]
                if dangerous_groups:
                    self.findings.append(
                        ACLFinding(
                            rule_id="odoo-acl-public-rule-sensitive-mutation",
                            title="Public/portal rule enables mutation on sensitive model",
                            severity="critical",
                            file=rule.file,
                            line=rule.line,
                            module=rule.module,
                            message=f"Rule '{rule.name}' grants public/portal mutation permissions on sensitive/security model {normalized_model}; verify ownership, token checks, and write fields",
                            model=normalized_model,
                            group=",".join(dangerous_groups),
                        )
                    )

            # Check for rules without groups
            if not rule.groups:
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-rule-no-groups",
                        title="Record rule without groups",
                        severity="low",
                        file=rule.file,
                        line=rule.line,
                        module=rule.module,
                        message=f"Rule '{rule.name}' applies to all users including portal/public",
                        model=normalized_model,
                    )
                )

            # Check for missing company filter in multi-company
            if "company" in normalized_model.lower() and "company_id" not in rule.domain_force:
                self.findings.append(
                    ACLFinding(
                        rule_id="odoo-acl-missing-company-filter",
                        title="Missing company filter in multi-company rule",
                        severity="medium",
                        file=rule.file,
                        line=rule.line,
                        module=rule.module,
                        message=f"Rule '{rule.name}' on {normalized_model} doesn't filter by company_id",
                        model=normalized_model,
                    )
                )

    def _get_module_name(self, path: Path) -> str:
        """Extract module name from file path."""
        try:
            # Walk up to find the module directory
            current = path.parent
            while current != self.repo_path and current.parent != current:
                if (current / "__manifest__.py").exists() or (current / "__openerp__.py").exists():
                    return current.name
                current = current.parent
        except Exception:
            return ""
        return ""

    def _normalize_model_id(self, model_id: str) -> str:
        """Normalize Odoo model external IDs to dotted model names."""
        value = model_id.strip()
        if "." in value and not value.startswith("model_"):
            maybe_external_id = value.rsplit(".", 1)[-1]
            if maybe_external_id.startswith("model_"):
                value = maybe_external_id
        if value in KNOWN_MODEL_EXTERNAL_IDS:
            return KNOWN_MODEL_EXTERNAL_IDS[value]
        if value.startswith("model_"):
            return value.removeprefix("model_").replace("_", ".")
        return value

    def _model_requires_strict_rule_scope(self, model: str) -> bool:
        """Return whether record rules for this model deserve strict review."""
        return model in self.SENSITIVE_MODELS or model in self.SECURITY_MODELS


def _is_universal_domain(domain: str) -> bool:
    """Detect common always-true record-rule domains."""
    compact = re.sub(r"\s+", "", domain)
    return any(
        marker in compact
        for marker in {
            "[(1,'=',1)]",
            "[('1','=','1')]",
            "[(True,'=',True)]",
            "[]",
        }
    )


def _truthy_permission(value: str) -> bool:
    """Parse XML/CSV permission truthy values consistently."""
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _csv_ref(row: dict[str, str], field: str) -> str:
    """Read Odoo CSV external-id columns using import and export spellings."""
    for key in (f"{field}:id", f"{field}/id", field):
        value = row.get(key, "")
        if value:
            return value
    return ""


def analyze_access_control(repo_path: Path) -> list[ACLFinding]:
    """Analyze access control in an Odoo repository."""
    analyzer = AccessControlAnalyzer(repo_path)
    return analyzer.analyze()


def findings_to_json(findings: list[ACLFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable format."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "module": f.module,
            "message": f.message,
            "model": f.model,
            "group": f.group,
        }
        for f in findings
    ]
