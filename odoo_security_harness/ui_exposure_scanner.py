"""Scanner for Odoo XML UI exposure risks."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class UIExposureFinding:
    """Represents a potentially over-exposed Odoo UI entry point."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    element: str = ""
    target: str = ""


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


def scan_ui_exposure(repo_path: Path) -> list[UIExposureFinding]:
    """Scan UI definitions for broad buttons, menus, and actions."""
    findings: list[UIExposureFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = UIExposureScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())

    findings.extend(_scan_repository_menus(repo_path, _collect_repository_actions(repo_path)))
    return _dedupe_findings(findings)


class UIExposureScanner:
    """Scanner for one XML file containing Odoo UI definitions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[UIExposureFinding] = []
        self.actions: dict[str, dict[str, str]] = {}

    def scan_file(self) -> list[UIExposureFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        self._collect_actions(root)
        self._scan_buttons(root)
        self._scan_sensitive_actions()
        self._scan_menuitems(root)
        return self.findings

    def scan_csv_file(self) -> list[UIExposureFinding]:
        """Scan CSV action records for broad sensitive UI exposure."""
        model = _csv_model_name(self.path)
        if model not in {"ir.actions.act_window", "ir.actions.report", "ir.actions.server"}:
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            record_id = fields.get("id", "")
            groups = fields.get("groups_id", "") or fields.get("groups", "")
            target_model = _model_value(
                fields.get("res_model", "")
                or fields.get("model", "")
                or fields.get("binding_model_id", "")
                or fields.get("model_id", "")
            )
            if record_id:
                self.actions[record_id] = {
                    "record_model": model,
                    "target_model": target_model,
                    "groups": groups,
                    "line": str(line),
                }

        self._scan_sensitive_actions()
        return self.findings

    def _collect_actions(self, root: ElementTree.Element) -> None:
        for record in root.iter("record"):
            model = record.get("model", "")
            if model not in {"ir.actions.act_window", "ir.actions.report", "ir.actions.server"}:
                continue
            record_id = record.get("id", "")
            fields = _record_fields(record)
            groups = fields.get("groups_id", "") or fields.get("groups", "")
            target_model = _model_value(
                fields.get("res_model", "")
                or fields.get("model", "")
                or fields.get("binding_model_id", "")
                or fields.get("model_id", "")
            )
            if record_id:
                self.actions[record_id] = {
                    "record_model": model,
                    "target_model": target_model,
                    "groups": groups,
                    "line": str(_line_for(self.content, f'id="{record_id}"')),
                }

    def _scan_buttons(self, root: ElementTree.Element) -> None:
        for button in root.iter("button"):
            button_type = button.get("type", "")
            name = button.get("name", "")
            groups = button.get("groups", "")
            if button_type == "object":
                if _includes_public_group(groups):
                    self._add(
                        "odoo-ui-public-object-button",
                        "Object button exposed to public or portal users",
                        "high",
                        _line_for_button(self.content, name),
                        "View exposes an object-method button to public or portal users; verify the method enforces record access and rejects forged calls",
                        "button",
                        name,
                    )
                elif not groups:
                    self._add(
                        "odoo-ui-object-button-no-groups",
                        "Object button has no groups restriction",
                        "medium",
                        _line_for_button(self.content, name),
                        "View exposes an object-method button without groups; verify the method enforces access rights and record rules itself",
                        "button",
                        name,
                    )
            elif button_type == "action" and not groups:
                action_ref = _normalize_action_ref(name)
                action = self.actions.get(action_ref)
                target_model = action.get("target_model", "") if action else ""
                if action and target_model in SENSITIVE_MODELS and not action.get("groups", ""):
                    self._add(
                        "odoo-ui-sensitive-action-button-no-groups",
                        "Action button opens sensitive model without groups",
                        "medium",
                        _line_for_button(self.content, name),
                        f"View exposes an action button for sensitive model '{target_model}' without groups; verify the button, target action, ACLs, and record rules are intentionally reachable",
                        "button",
                        name,
                    )
                self._add(
                    "odoo-ui-action-button-no-groups",
                    "Action button has no groups restriction",
                    "low",
                    _line_for_button(self.content, name),
                    "View exposes an action button without groups; confirm the target action and model access are intentionally broad",
                    "button",
                    name,
                )

    def _scan_sensitive_actions(self) -> None:
        for action_id, action in self.actions.items():
            target_model = action.get("target_model", "")
            if target_model not in SENSITIVE_MODELS:
                continue
            if action.get("groups"):
                continue
            if action.get("record_model") == "ir.actions.server":
                self._add(
                    "odoo-ui-sensitive-server-action-no-groups",
                    "Sensitive server action has no groups restriction",
                    "high",
                    int(action.get("line", "1")),
                    f"Server action bound to sensitive model '{target_model}' has no groups_id restriction; verify only intended users can execute record code or mutations",
                    action.get("record_model", ""),
                    action_id,
                )
            self._add(
                "odoo-ui-sensitive-action-no-groups",
                "Sensitive model action has no groups restriction",
                "medium",
                int(action.get("line", "1")),
                f"Action for sensitive model '{target_model}' has no groups_id restriction; verify menus and bindings are not broadly reachable",
                action.get("record_model", ""),
                action_id,
            )

    def _scan_menuitems(self, root: ElementTree.Element) -> None:
        for menu in root.iter("menuitem"):
            groups = menu.get("groups", "")
            action_ref = _normalize_action_ref(menu.get("action", ""))
            if groups or not action_ref:
                continue
            action = self.actions.get(action_ref)
            if not action:
                continue
            target_model = action.get("target_model", "")
            if target_model not in SENSITIVE_MODELS or action.get("groups"):
                continue
            menu_id = menu.get("id", action_ref)
            self._add(
                "odoo-ui-sensitive-menu-no-groups",
                "Sensitive menu has no groups restriction",
                "medium",
                _line_for(self.content, f'id="{menu_id}"'),
                f"Menu exposes action for sensitive model '{target_model}' without groups; confirm ACLs and record rules make this intentional",
                "menuitem",
                menu_id,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        element: str,
        target: str,
    ) -> None:
        self.findings.append(
            UIExposureFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                element=element,
                target=target,
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
        "ir_actions_act_window": "ir.actions.act_window",
        "ir.actions.act_window": "ir.actions.act_window",
        "ir_actions_report": "ir.actions.report",
        "ir.actions.report": "ir.actions.report",
        "ir_actions_server": "ir.actions.server",
        "ir.actions.server": "ir.actions.server",
        "ir_ui_menu": "ir.ui.menu",
        "ir.ui.menu": "ir.ui.menu",
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


def _includes_public_group(groups: str) -> bool:
    return "base.group_public" in groups or "base.group_portal" in groups


def _normalize_action_ref(action: str) -> str:
    action = action.strip()
    match = re.fullmatch(r"%\(([^)]+)\)d", action)
    if match:
        action = match.group(1)
    if "," in action:
        action = action.rsplit(",", 1)[1]
    if "." in action:
        return action.rsplit(".", 1)[1]
    return action


def _model_value(value: str) -> str:
    value = value.strip().strip("'\"")
    if value in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[value]
    external_id = value.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if value.startswith("model_"):
        return value.removeprefix("model_").replace("_", ".")
    if ".model_" in value:
        return value.rsplit(".model_", 1)[1].replace("_", ".")
    return value


def _line_for_button(content: str, name: str) -> int:
    if name:
        return _line_for(content, f'name="{name}"')
    return _line_for(content, "<button")


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def _collect_repository_actions(repo_path: Path) -> dict[str, dict[str, str]]:
    actions: dict[str, dict[str, str]] = {}
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".xml":
            actions.update(_collect_xml_actions(path))
        elif path.suffix == ".csv":
            actions.update(_collect_csv_actions(path))
    return actions


def _collect_xml_actions(path: Path) -> dict[str, dict[str, str]]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return {}
    except Exception:
        return {}

    actions: dict[str, dict[str, str]] = {}
    for record in root.iter("record"):
        model = record.get("model", "")
        if model not in {"ir.actions.act_window", "ir.actions.report", "ir.actions.server"}:
            continue
        record_id = record.get("id", "")
        if not record_id:
            continue
        fields = _record_fields(record)
        actions[record_id] = {
            "record_model": model,
            "target_model": _model_value(
                fields.get("res_model", "")
                or fields.get("model", "")
                or fields.get("binding_model_id", "")
                or fields.get("model_id", "")
            ),
            "groups": fields.get("groups_id", "") or fields.get("groups", ""),
        }
    return actions


def _collect_csv_actions(path: Path) -> dict[str, dict[str, str]]:
    model = _csv_model_name(path)
    if model not in {"ir.actions.act_window", "ir.actions.report", "ir.actions.server"}:
        return {}
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}

    actions: dict[str, dict[str, str]] = {}
    for fields, _line in _csv_dict_rows(content):
        record_id = fields.get("id", "")
        if not record_id:
            continue
        actions[record_id] = {
            "record_model": model,
            "target_model": _model_value(
                fields.get("res_model", "")
                or fields.get("model", "")
                or fields.get("binding_model_id", "")
                or fields.get("model_id", "")
            ),
            "groups": fields.get("groups_id", "") or fields.get("groups", ""),
        }
    return actions


def _scan_repository_menus(repo_path: Path, actions: dict[str, dict[str, str]]) -> list[UIExposureFinding]:
    findings: list[UIExposureFinding] = []
    if not actions:
        return findings
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".xml":
            findings.extend(_scan_xml_menus(path, actions))
        elif path.suffix == ".csv" and _csv_model_name(path) == "ir.ui.menu":
            findings.extend(_scan_csv_menus(path, actions))
    return findings


def _scan_xml_menus(path: Path, actions: dict[str, dict[str, str]]) -> list[UIExposureFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    except Exception:
        return []

    findings: list[UIExposureFinding] = []
    for menu in root.iter("menuitem"):
        groups = menu.get("groups", "")
        action_ref = _normalize_action_ref(menu.get("action", ""))
        menu_id = menu.get("id", action_ref)
        finding = _menu_finding(
            path,
            _line_for(content, f'id="{menu_id}"'),
            menu_id,
            groups,
            action_ref,
            actions,
        )
        if finding:
            findings.append(finding)
    return findings


def _scan_csv_menus(path: Path, actions: dict[str, dict[str, str]]) -> list[UIExposureFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    findings: list[UIExposureFinding] = []
    for fields, line in _csv_dict_rows(content):
        action_ref = _normalize_action_ref(fields.get("action", "") or fields.get("action/id", ""))
        finding = _menu_finding(
            path,
            line,
            fields.get("id", action_ref),
            fields.get("groups_id", "") or fields.get("groups", ""),
            action_ref,
            actions,
        )
        if finding:
            findings.append(finding)
    return findings


def _menu_finding(
    path: Path,
    line: int,
    menu_id: str,
    groups: str,
    action_ref: str,
    actions: dict[str, dict[str, str]],
) -> UIExposureFinding | None:
    if groups or not action_ref:
        return None
    action = actions.get(action_ref)
    if not action:
        return None
    target_model = action.get("target_model", "")
    if target_model not in SENSITIVE_MODELS or action.get("groups"):
        return None
    return UIExposureFinding(
        rule_id="odoo-ui-sensitive-menu-no-groups",
        title="Sensitive menu has no groups restriction",
        severity="medium",
        file=str(path),
        line=line,
        message=f"Menu exposes action for sensitive model '{target_model}' without groups; confirm ACLs and record rules make this intentional",
        element="menuitem",
        target=menu_id,
    )


def _dedupe_findings(findings: list[UIExposureFinding]) -> list[UIExposureFinding]:
    seen: set[tuple[str, str, int, str, str]] = set()
    unique: list[UIExposureFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.element, finding.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def findings_to_json(findings: list[UIExposureFinding]) -> list[dict[str, Any]]:
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
            "target": f.target,
        }
        for f in findings
    ]
