"""Scanner for risky Odoo inherited view modifications."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from odoo_security_harness.base_scanner import _should_skip


@dataclass
class ViewInheritanceFinding:
    """Represents a risky inherited-view modification finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    element: str = ""
    target: str = ""


SENSITIVE_FIELD_NAMES = {
    "access_token",
    "api_key",
    "api_secret",
    "groups_id",
    "password",
    "signup_token",
    "token",
    "user_ids",
}
SENSITIVE_FIELD_MARKERS = (
    "access_key",
    "access_link",
    "access_token",
    "access_url",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "csrf_token",
    "hmac_secret",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "partner_signup_url",
    "password",
    "private_key",
    "reset_password_token",
    "reset_password_url",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signup_token",
    "signup_url",
    "signing_key",
    "token",
    "totp_secret",
    "webhook_secret",
)
PUBLIC_GROUPS = {"base.group_public", "base.group_portal"}


def scan_view_inheritance(repo_path: Path) -> list[ViewInheritanceFinding]:
    """Scan XML views for risky inherited-view modifications."""
    findings: list[ViewInheritanceFinding] = []
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        findings.extend(ViewInheritanceScanner(path).scan_file())
    return findings


class ViewInheritanceScanner:
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[ViewInheritanceFinding] = []

    def scan_file(self) -> list[ViewInheritanceFinding]:
        """Scan inherited view XML."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.ui.view":
                self._scan_view_record(record)
        return self.findings

    def _scan_view_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        if "inherit_id" not in fields:
            return
        record_id = record.get("id", "")
        for element in record.iter():
            if element.tag == "xpath":
                self._scan_xpath(element, record_id)
            elif element.tag in {"field", "button"} and element.get("position"):
                self._scan_direct_position(element, record_id)

    def _scan_xpath(self, element: ElementTree.Element, record_id: str) -> None:
        expr = element.get("expr", "")
        position = element.get("position", "")
        line = _line_for(self.content, expr or "<xpath")

        if position == "attributes":
            self._scan_attribute_patch(element, expr, line, record_id)
        elif position == "replace":
            self._scan_replace(element, expr, line, record_id)
        elif position in {"after", "before", "inside"}:
            self._scan_inserted_controls(element, expr, line, record_id)

        if _is_broad_security_xpath(expr):
            self._add(
                "odoo-view-inherit-broad-security-xpath",
                "Inherited view uses broad XPath for security-sensitive control",
                "medium",
                line,
                f"Inherited view '{record_id}' uses broad XPath '{expr}' against buttons/fields; verify it cannot affect unintended secured controls",
                "xpath",
                expr,
            )

    def _scan_attribute_patch(self, element: ElementTree.Element, expr: str, line: int, record_id: str) -> None:
        for attribute in element.iter("attribute"):
            name = attribute.get("name", "")
            value = "".join(attribute.itertext()).strip()
            if name == "groups" and not value:
                self._add(
                    "odoo-view-inherit-removes-groups",
                    "Inherited view removes groups restriction",
                    "high",
                    line,
                    f"Inherited view '{record_id}' removes groups from target '{expr}'; verify the control remains access-checked server-side",
                    "attribute",
                    expr,
                )
            elif (
                name == "groups"
                and _contains_public_group(value)
                and (_targets_sensitive_field(expr) or _targets_object_button(expr))
            ):
                self._add(
                    "odoo-view-inherit-public-groups-sensitive-target",
                    "Inherited view exposes sensitive control to public/portal group",
                    "critical",
                    line,
                    f"Inherited view '{record_id}' assigns public/portal groups to sensitive target '{expr}'; verify this cannot expose privilege-bearing fields or actions",
                    "attribute",
                    expr,
                )
            elif name in {"invisible", "attrs"} and _reveals_sensitive_target(expr, value):
                self._add(
                    "odoo-view-inherit-reveals-sensitive-field",
                    "Inherited view may reveal sensitive field/control",
                    "medium",
                    line,
                    f"Inherited view '{record_id}' changes visibility for sensitive target '{expr}'; verify groups and record rules still protect it",
                    "attribute",
                    expr,
                )
            elif name == "readonly" and _targets_sensitive_field(expr) and _reveals_value(value):
                self._add(
                    "odoo-view-inherit-makes-sensitive-field-editable",
                    "Inherited view may make sensitive field editable",
                    "high",
                    line,
                    f"Inherited view '{record_id}' changes readonly for sensitive target '{expr}'; verify users cannot edit privilege-bearing fields or secrets through the UI",
                    "attribute",
                    expr,
                )

    def _scan_replace(self, element: ElementTree.Element, expr: str, line: int, record_id: str) -> None:
        if _targets_object_button(expr) or any(_is_object_button(child) for child in element.iter("button")):
            self._add(
                "odoo-view-inherit-replaces-object-button",
                "Inherited view replaces object-method button",
                "medium",
                line,
                f"Inherited view '{record_id}' replaces object button target '{expr}'; verify groups, attrs, and server-side access checks are preserved",
                "xpath",
                expr,
            )
        if _targets_sensitive_field(expr) or any(_is_sensitive_field_node(child) for child in element.iter("field")):
            self._add(
                "odoo-view-inherit-replaces-sensitive-field",
                "Inherited view replaces sensitive field",
                "medium",
                line,
                f"Inherited view '{record_id}' replaces sensitive field target '{expr}'; verify groups, readonly, and invisibility restrictions are preserved",
                "xpath",
                expr,
            )

    def _scan_inserted_controls(self, element: ElementTree.Element, expr: str, line: int, record_id: str) -> None:
        for button in element.iter("button"):
            if not _is_object_button(button):
                continue
            groups = button.get("groups", "")
            target = button.get("name", expr)
            if _contains_public_group(groups):
                self._add(
                    "odoo-view-inherit-adds-public-object-button",
                    "Inherited view inserts public object-method button",
                    "critical",
                    line,
                    f"Inherited view '{record_id}' inserts object button '{target}' for public/portal users; verify the method enforces server-side authorization",
                    "button",
                    target,
                )
            elif not groups:
                self._add(
                    "odoo-view-inherit-adds-object-button-no-groups",
                    "Inherited view inserts object-method button without groups",
                    "high",
                    line,
                    f"Inherited view '{record_id}' inserts object button '{target}' without groups; verify forged RPC calls cannot bypass workflow permissions",
                    "button",
                    target,
                )

        for field in element.iter("field"):
            if not _is_sensitive_field_node(field):
                continue
            groups = field.get("groups", "")
            target = field.get("name", expr)
            if _contains_public_group(groups):
                self._add(
                    "odoo-view-inherit-adds-public-sensitive-field",
                    "Inherited view inserts sensitive field for public/portal users",
                    "critical",
                    line,
                    f"Inherited view '{record_id}' inserts sensitive field '{target}' for public/portal users; verify ACLs and record rules cannot expose secrets or privileges",
                    "field",
                    target,
                )
            elif not groups:
                self._add(
                    "odoo-view-inherit-adds-sensitive-field-no-groups",
                    "Inherited view inserts sensitive field without groups",
                    "high",
                    line,
                    f"Inherited view '{record_id}' inserts sensitive field '{target}' without groups; verify view inheritance cannot expose secrets or privilege fields",
                    "field",
                    target,
                )

    def _scan_direct_position(self, element: ElementTree.Element, record_id: str) -> None:
        position = element.get("position", "")
        if position == "attributes":
            self._scan_direct_attribute_patch(element, record_id)
            return
        if position in {"after", "before", "inside"}:
            self._scan_inserted_controls(
                element, element.get("name", ""), _line_for(self.content, f"<{element.tag}"), record_id
            )
            return
        if position != "replace":
            return
        name = element.get("name", "")
        line = _line_for(self.content, f'name="{name}"') if name else _line_for(self.content, f"<{element.tag}")
        if element.tag == "button" and element.get("type") == "object":
            self._add(
                "odoo-view-inherit-replaces-object-button",
                "Inherited view replaces object-method button",
                "medium",
                line,
                f"Inherited view '{record_id}' replaces object button '{name}'; verify groups, attrs, and server-side access checks are preserved",
                "button",
                name,
            )
        elif element.tag == "field" and _is_sensitive_name(name):
            self._add(
                "odoo-view-inherit-replaces-sensitive-field",
                "Inherited view replaces sensitive field",
                "medium",
                line,
                f"Inherited view '{record_id}' replaces sensitive field '{name}'; verify groups, readonly, and invisibility restrictions are preserved",
                "field",
                name,
            )

    def _scan_direct_attribute_patch(self, element: ElementTree.Element, record_id: str) -> None:
        name = element.get("name", "")
        line = _line_for(self.content, f'name="{name}"') if name else _line_for(self.content, f"<{element.tag}")
        target = f"{element.tag}:{name}" if name else element.tag
        for attribute in element.iter("attribute"):
            attr_name = attribute.get("name", "")
            value = "".join(attribute.itertext()).strip()
            if attr_name == "groups" and not value:
                self._add(
                    "odoo-view-inherit-removes-groups",
                    "Inherited view removes groups restriction",
                    "high",
                    line,
                    f"Inherited view '{record_id}' removes groups from direct target '{target}'; verify the control remains access-checked server-side",
                    "attribute",
                    target,
                )
            elif attr_name == "groups" and _contains_public_group(value) and _direct_target_is_sensitive(element):
                self._add(
                    "odoo-view-inherit-public-groups-sensitive-target",
                    "Inherited view exposes sensitive control to public/portal group",
                    "critical",
                    line,
                    f"Inherited view '{record_id}' assigns public/portal groups to sensitive target '{target}'; verify this cannot expose privilege-bearing fields or actions",
                    "attribute",
                    target,
                )
            elif attr_name in {"invisible", "attrs"} and _direct_target_is_sensitive(element) and _reveals_value(value):
                self._add(
                    "odoo-view-inherit-reveals-sensitive-field",
                    "Inherited view may reveal sensitive field/control",
                    "medium",
                    line,
                    f"Inherited view '{record_id}' changes visibility for sensitive direct target '{target}'; verify groups and record rules still protect it",
                    "attribute",
                    target,
                )
            elif attr_name == "readonly" and _direct_target_is_sensitive(element) and _reveals_value(value):
                self._add(
                    "odoo-view-inherit-makes-sensitive-field-editable",
                    "Inherited view may make sensitive field editable",
                    "high",
                    line,
                    f"Inherited view '{record_id}' changes readonly for sensitive direct target '{target}'; verify users cannot edit privilege-bearing fields or secrets through the UI",
                    "attribute",
                    target,
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
            ViewInheritanceFinding(
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
        values[name] = field.get("ref") or field.get("eval") or "".join(field.itertext()).strip()
    return values


def _is_broad_security_xpath(expr: str) -> bool:
    compact = re.sub(r"\s+", "", expr)
    if not compact:
        return False
    return compact in {"//button", "//field", ".//button", ".//field"} or bool(
        re.fullmatch(r"\.?//(button|field)\[@(type|groups|attrs|invisible)[^]]+\]", compact)
    )


def _reveals_sensitive_target(expr: str, value: str) -> bool:
    if not (_targets_sensitive_field(expr) or _targets_object_button(expr)):
        return False
    return _reveals_value(value)


def _reveals_value(value: str) -> bool:
    compact_value = re.sub(r"\s+", "", value).lower()
    return compact_value in {"0", "false", "{'invisible':false}", '{"invisible":false}'}


def _targets_object_button(expr: str) -> bool:
    return "button" in expr and ("@type='object'" in expr or '@type="object"' in expr or "@name=" in expr)


def _targets_sensitive_field(expr: str) -> bool:
    if "field" not in expr:
        return False
    return any(name in expr for name in SENSITIVE_FIELD_NAMES) or any(
        marker in expr.lower() for marker in SENSITIVE_FIELD_MARKERS
    )


def _is_object_button(node: ElementTree.Element) -> bool:
    return node.tag == "button" and node.get("type") == "object"


def _is_sensitive_field_node(node: ElementTree.Element) -> bool:
    return node.tag == "field" and _is_sensitive_name(node.get("name", ""))


def _direct_target_is_sensitive(node: ElementTree.Element) -> bool:
    return _is_sensitive_field_node(node) or _is_object_button(node)


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return name in SENSITIVE_FIELD_NAMES or any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


def _contains_public_group(groups: str) -> bool:
    return any(group in groups for group in PUBLIC_GROUPS)


def _line_for(content: str, needle: str) -> int:
    if not needle:
        return 1
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1



def findings_to_json(findings: list[ViewInheritanceFinding]) -> list[dict[str, Any]]:
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
