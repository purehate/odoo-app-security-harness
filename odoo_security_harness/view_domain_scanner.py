"""Scanner for risky Odoo XML domain/context expressions."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class ViewDomainFinding:
    """Represents a risky XML domain/context expression finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    element: str = ""
    attribute: str = ""


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

PRIVILEGED_DEFAULT_CONTEXT_KEYS = {
    "default_active",
    "default_company_id",
    "default_company_ids",
    "default_group_id",
    "default_groups_id",
    "default_implied_ids",
    "default_share",
    "default_user_id",
}

GROUP_DEFAULT_CONTEXT_KEYS = {"default_group_id", "default_groups_id"}

RISKY_CONTEXT_FLAGS = {
    "install_mode",
    "mail_create_nosubscribe",
    "mail_notrack",
    "module_uninstall",
    "no_reset_password",
    "tracking_disable",
}


def scan_view_domains(repo_path: Path) -> list[ViewDomainFinding]:
    """Scan data files for risky domain/context expressions."""
    findings: list[ViewDomainFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = ViewDomainScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class ViewDomainScanner:
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[ViewDomainFinding] = []

    def scan_file(self) -> list[ViewDomainFinding]:
        """Scan XML domains and contexts."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for element in root.iter():
            self._scan_element_attributes(element)
            if element.tag == "record":
                self._scan_action_record(element)
                self._scan_filter_record(element)
            elif element.tag == "field" and element.get("name") in {"domain", "context", "filter_domain"}:
                self._scan_expression(element, element.get("name", ""), _field_value(element))
        return self.findings

    def scan_csv_file(self) -> list[ViewDomainFinding]:
        """Scan CSV action/filter records."""
        model = _csv_model_name(self.path)
        if model not in {"ir.actions.act_window", "ir.filters"}:
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            for attribute in ("domain", "context", "filter_domain"):
                value = fields.get(attribute, "")
                if value:
                    self._scan_expression_values(model, attribute, value, line)
            if model == "ir.actions.act_window":
                self._scan_action_fields(fields, line)
            else:
                self._scan_filter_fields(fields, line)
        return self.findings

    def _scan_element_attributes(self, element: ElementTree.Element) -> None:
        for attribute in ("domain", "context", "filter_domain"):
            value = element.get(attribute, "")
            if value:
                self._scan_expression(element, attribute, value)

    def _scan_action_record(self, record: ElementTree.Element) -> None:
        if record.get("model") != "ir.actions.act_window":
            return
        fields = _record_fields(record)
        model = _normalize_model_name(fields.get("res_model", ""))
        domain = fields.get("domain", "")
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        if model in SENSITIVE_MODELS and _is_broad_domain(domain) and not _has_group_restriction(groups):
            self._add(
                "odoo-view-domain-sensitive-action-broad-domain",
                "Sensitive action uses broad domain without groups",
                "medium",
                self._line_for_record(record),
                f"ir.actions.act_window for sensitive model '{model}' uses a broad domain and has no groups restriction; verify menus and ACLs prevent overexposure",
                "ir.actions.act_window",
                "domain",
            )

    def _scan_action_fields(self, fields: dict[str, str], line: int) -> None:
        model = _normalize_model_name(fields.get("res_model", ""))
        domain = fields.get("domain", "")
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        if model in SENSITIVE_MODELS and _is_broad_domain(domain) and not _has_group_restriction(groups):
            self._add(
                "odoo-view-domain-sensitive-action-broad-domain",
                "Sensitive action uses broad domain without groups",
                "medium",
                line,
                f"ir.actions.act_window for sensitive model '{model}' uses a broad domain and has no groups restriction; verify menus and ACLs prevent overexposure",
                "ir.actions.act_window",
                "domain",
            )

    def _scan_filter_record(self, record: ElementTree.Element) -> None:
        if record.get("model") != "ir.filters":
            return
        fields = _record_fields(record)
        self._scan_filter_fields(fields, self._line_for_record(record))

    def _scan_filter_fields(self, fields: dict[str, str], line: int) -> None:
        model = _normalize_model_name(fields.get("model_id", "") or fields.get("model", ""))
        domain = fields.get("domain", "")
        context = fields.get("context", "")
        user = fields.get("user_id", "")
        is_default = fields.get("is_default", "")

        if model in SENSITIVE_MODELS and _is_global_filter_user(user) and _is_broad_domain(domain):
            self._add(
                "odoo-view-domain-global-sensitive-filter-broad-domain",
                "Global saved filter has broad sensitive-model domain",
                "medium",
                line,
                f"Global ir.filters record applies a broad domain to sensitive model '{model}'; verify it cannot overexpose records through shared favorites/search defaults",
                "ir.filters",
                "domain",
            )

        if model in SENSITIVE_MODELS and _is_global_filter_user(user) and _truthy(is_default):
            self._add(
                "odoo-view-filter-global-default-sensitive",
                "Global default saved filter affects sensitive model",
                "medium",
                line,
                f"Global default ir.filters record applies to sensitive model '{model}'; verify shared default search behavior is intentional and cannot hide or expose records unexpectedly",
                "ir.filters",
                "is_default",
            )

        if (
            model in SENSITIVE_MODELS
            and _is_global_filter_user(user)
            and _truthy(is_default)
            and (_is_broad_domain(domain) or _disables_active_test(context))
        ):
            self._add(
                "odoo-view-domain-default-sensitive-filter",
                "Global default saved filter affects sensitive model",
                "medium",
                line,
                f"Global default ir.filters record applies to sensitive model '{model}'; verify default search behavior cannot expose archived or overly broad records",
                "ir.filters",
                "is_default",
            )

    def _scan_expression(self, element: ElementTree.Element, attribute: str, value: str) -> None:
        line = _line_for_expression(self.content, attribute, value)
        self._scan_expression_values(element.tag, attribute, value, line)

    def _scan_expression_values(self, element: str, attribute: str, value: str, line: int) -> None:
        normalized = _compact(value)
        if re.search(r"\b(eval|exec|safe_eval)\s*\(", value):
            self._add(
                "odoo-view-domain-dynamic-eval",
                "XML domain/context performs dynamic evaluation",
                "high",
                line,
                "XML domain/context expression contains eval/exec/safe_eval; verify no user-controlled value can affect evaluated code",
                element,
                attribute,
            )
        if "active_test" in value and re.search(r"['\"]active_test['\"]\s*:\s*(False|0|false)", value):
            self._add(
                "odoo-view-context-active-test-disabled",
                "XML context disables active_test",
                "low",
                line,
                "XML context sets active_test=False; archived/inactive records may become visible or processed in this flow",
                element,
                attribute,
            )
        if _has_user_controlled_company_context(value):
            self._add(
                "odoo-view-context-user-company-scope",
                "XML context sets company scope from active/user values",
                "medium",
                line,
                "XML context sets force_company/company_id/allowed_company_ids from active/user-derived values; verify company membership is enforced",
                element,
                attribute,
            )
        privileged_default_keys = _privileged_default_context_keys(normalized)
        for key in sorted(privileged_default_keys - GROUP_DEFAULT_CONTEXT_KEYS):
            self._add(
                "odoo-view-context-privileged-default",
                "XML context defaults privileged field",
                "medium",
                line,
                f"XML context sets {key}; verify create flows cannot prefill privilege, company, user, or portal/share-sensitive values unexpectedly",
                element,
                attribute,
            )
        if privileged_default_keys & GROUP_DEFAULT_CONTEXT_KEYS:
            self._add(
                "odoo-view-context-default-groups",
                "XML context defaults user/group assignment",
                "medium",
                line,
                "XML context sets default group fields; verify create flows cannot assign elevated groups unexpectedly",
                element,
                attribute,
            )
        for key in sorted(_risky_context_flags(value)):
            self._add(
                "odoo-view-context-risky-framework-flag",
                "XML context sets risky framework flag",
                "medium",
                line,
                f"XML context sets {key}; verify this flow cannot bypass tracking, password reset, install/uninstall, or accounting validation safeguards unexpectedly",
                element,
                attribute,
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, 'model="ir.actions.act_window"')

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        element: str,
        attribute: str,
    ) -> None:
        self.findings.append(
            ViewDomainFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                element=element,
                attribute=attribute,
            )
        )


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("eval") or field.get("ref") or _field_value(field)
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "ir_actions_act_window": "ir.actions.act_window",
        "ir.actions.act_window": "ir.actions.act_window",
        "ir_filters": "ir.filters",
        "ir.filters": "ir.filters",
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
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _field_value(field: ElementTree.Element) -> str:
    return "".join(field.itertext()).strip()


def _is_broad_domain(value: str) -> bool:
    compact = _compact(value)
    return compact in {"", "[]", "[(1,'=',1)]", "[('1','=','1')]"} or "(1,'=',1)" in compact


def _has_group_restriction(value: str) -> bool:
    compact = _compact(value).strip("'\"").lower()
    return compact not in {"", "[]", "()", "false", "none", "0", "[(5,0,0)]", "[(6,0,[])]", "[(6,0,())]"}


def _is_global_filter_user(value: str) -> bool:
    compact = _compact(value).strip("'\"").lower()
    return compact in {"", "false", "none", "0", "[]", "()"}


def _has_user_controlled_company_context(value: str) -> bool:
    compact = _compact(value)
    if not any(key in compact for key in ("force_company", "allowed_company_ids", "company_id")):
        return False
    return any(
        marker in compact
        for marker in (
            "active_id",
            "active_ids",
            "context.get(",
            "uid",
            "user.id",
            "user.company_id",
            "user.company_ids",
        )
    )


def _privileged_default_context_keys(normalized: str) -> set[str]:
    return {key for key in PRIVILEGED_DEFAULT_CONTEXT_KEYS if key in normalized}


def _risky_context_flags(value: str) -> set[str]:
    compact = _compact(value).lower()
    flags = {key for key in RISKY_CONTEXT_FLAGS if key in compact}
    if re.search(r"['\"]check_move_validity['\"]:(false|0)", compact):
        flags.add("check_move_validity")
    return flags


def _disables_active_test(value: str) -> bool:
    return "active_test" in value and re.search(r"['\"]active_test['\"]\s*:\s*(False|0|false)", value) is not None


def _normalize_model_name(value: str) -> str:
    stripped = value.strip().strip("'\"")
    if stripped in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[stripped]
    external_id = stripped.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if stripped.startswith("model_"):
        return stripped.removeprefix("model_").replace("_", ".")
    if ".model_" in stripped:
        return stripped.rsplit(".model_", 1)[1].replace("_", ".")
    return stripped


def _truthy(value: str) -> bool:
    return value.strip().strip("'\"").lower() in {"1", "true", "yes", "y"}


def _compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _line_for_expression(content: str, attribute: str, value: str) -> int:
    if value:
        line = _line_for(content, value[:80])
        if line != 1:
            return line
    return _line_for(content, f'name="{attribute}"') or _line_for(content, attribute)


def _line_for(content: str, needle: str) -> int:
    if not needle:
        return 1
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ViewDomainFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "attribute": f.attribute,
        }
        for f in findings
    ]
