"""Scanner for risky Odoo model field security declarations."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class FieldSecurityFinding:
    """Represents a risky field security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    field: str = ""


@dataclass
class FieldDef:
    """Represents one Odoo field declaration."""

    name: str
    field_type: str
    line: int
    keywords: dict[str, ast.expr]


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
PUBLIC_GROUPS = {"base.group_public", "base.group_portal"}
ADMIN_GROUP_MARKERS = ("base.group_system", "base.group_erp_manager", "base.group_no_one")
SENSITIVE_RELATED_PARTS = ("password", "token", "secret", "api_key", "apikey", "private_key")
HTML_SANITIZER_KEYWORDS = ("sanitize", "sanitize_tags", "sanitize_attributes")


def scan_field_security(repo_path: Path) -> list[FieldSecurityFinding]:
    """Scan Odoo model fields for risky security metadata."""
    findings: list[FieldSecurityFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(FieldSecurityScanner(path).scan_file())
    return findings


class FieldSecurityScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[FieldSecurityFinding] = []
        self.constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[FieldSecurityFinding]:
        """Scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        if not _is_odoo_model(node):
            self.generic_visit(node)
            return

        model = _extract_model_name(node, self.constants)
        for field in _extract_fields(node):
            self._scan_field(model, field)

        self.generic_visit(node)

    def _scan_field(self, model: str, field: FieldDef) -> None:
        groups = _string_keyword(field, "groups", self.constants)
        is_sensitive = _is_sensitive_field(field.name)

        if is_sensitive and not groups:
            self._add(
                "odoo-field-sensitive-no-groups",
                "Sensitive field has no group restriction",
                "high",
                field.line,
                f"Sensitive-looking field '{field.name}' has no groups= restriction; verify only trusted users can read it",
                model,
                field.name,
            )
        elif is_sensitive and _contains_public_group(groups):
            self._add(
                "odoo-field-sensitive-public-groups",
                "Sensitive field is exposed to public or portal group",
                "critical",
                field.line,
                f"Sensitive-looking field '{field.name}' is assigned to public/portal groups; verify it cannot leak credentials or access tokens",
                model,
                field.name,
            )

        if is_sensitive and _kw_is_true(field, "index", self.constants):
            self._add(
                "odoo-field-sensitive-indexed",
                "Sensitive field is indexed",
                "medium",
                field.line,
                f"Sensitive-looking field '{field.name}' sets index=True; review database exposure, lookup paths, and whether a hashed/tokenized value should be indexed instead",
                model,
                field.name,
            )

        if is_sensitive and _kw_is_tracking_enabled(field, self.constants):
            self._add(
                "odoo-field-sensitive-tracking",
                "Sensitive field is tracked in chatter",
                "high",
                field.line,
                f"Sensitive-looking field '{field.name}' enables mail tracking; value changes can leak into chatter, notifications, or audit exports",
                model,
                field.name,
            )

        if is_sensitive and not _non_copyable_sensitive_field(field, self.constants):
            self._add(
                "odoo-field-sensitive-copyable",
                "Sensitive field can be copied",
                "medium",
                field.line,
                f"Sensitive-looking field '{field.name}' does not set copy=False; duplicated records may clone credentials, tokens, or secrets",
                model,
                field.name,
            )

        if _kw_is_true(field, "compute_sudo", self.constants) and (
            is_sensitive or field.field_type in {"Many2one", "One2many", "Many2many"}
        ):
            self._add(
                "odoo-field-compute-sudo-sensitive",
                "Field computes through sudo",
                "high",
                field.line,
                f"Field '{field.name}' sets compute_sudo=True; verify computed values cannot bypass record rules or company isolation",
                model,
                field.name,
            )

        if (
            _kw_is_true(field, "compute_sudo", self.constants)
            and field.field_type in {"Char", "Text", "Html", "Integer", "Float", "Monetary", "Selection"}
            and not _has_admin_only_groups(groups)
        ):
            self._add(
                "odoo-field-compute-sudo-scalar-no-admin-groups",
                "Sudo-computed scalar field lacks admin-only groups",
                "high",
                field.line,
                f"Scalar field '{field.name}' sets compute_sudo=True without admin-only groups; verify it cannot project private model data past record rules",
                model,
                field.name,
            )

        related = _string_keyword(field, "related", self.constants)
        if related and _is_sensitive_related(related) and not _has_admin_only_groups(groups):
            self._add(
                "odoo-field-related-sensitive-no-admin-groups",
                "Related field exposes sensitive target without admin-only groups",
                "high",
                field.line,
                f"Related field '{field.name}' projects sensitive path '{related}' without admin-only groups",
                model,
                field.name,
            )

        if field.field_type == "Binary" and _kw_is_false(field, "attachment", self.constants):
            self._add(
                "odoo-field-binary-db-storage",
                "Binary field disables attachment storage",
                "low",
                field.line,
                f"Binary field '{field.name}' uses attachment=False; review database bloat, backup exposure, and access behavior",
                model,
                field.name,
            )

        if field.field_type == "Html":
            disabled_sanitizers = [
                keyword for keyword in HTML_SANITIZER_KEYWORDS if _kw_is_false(field, keyword, self.constants)
            ]
            if disabled_sanitizers:
                self._add(
                    "odoo-field-html-sanitizer-disabled",
                    "HTML field disables sanitizer protections",
                    "critical" if "sanitize" in disabled_sanitizers else "high",
                    field.line,
                    f"HTML field '{field.name}' disables {', '.join(disabled_sanitizers)}; verify every writer and renderer is trusted",
                    model,
                    field.name,
                )

            if _kw_is_true(field, "sanitize_overridable", self.constants) and not _has_admin_only_groups(groups):
                self._add(
                    "odoo-field-html-sanitize-overridable-no-admin-groups",
                    "HTML sanitizer override is not admin-only",
                    "medium",
                    field.line,
                    f"HTML field '{field.name}' allows sanitizer override without admin-only groups; verify non-admin writers cannot persist unsafe markup",
                    model,
                    field.name,
                )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        field: str,
    ) -> None:
        self.findings.append(
            FieldSecurityFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                field=field,
            )
        )


def _extract_fields(node: ast.ClassDef) -> list[FieldDef]:
    fields: list[FieldDef] = []
    for item in node.body:
        field = _field_def_from_assignment(item)
        if field is not None:
            fields.append(field)
    return fields


def _field_def_from_assignment(node: ast.stmt) -> FieldDef | None:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
        target = node.targets[0]
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        if not isinstance(node.target, ast.Name) or node.value is None:
            return None
        target = node.target
        value = node.value
    else:
        return None

    if not isinstance(value, ast.Call):
        return None
    call = value
    field_type = _field_call_type(call.func)
    if not field_type:
        return None
    return FieldDef(
        name=target.id,
        field_type=field_type,
        line=node.lineno,
        keywords={kw.arg: kw.value for kw in call.keywords if kw.arg},
    )


def _field_call_type(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "fields":
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_odoo_model(node: ast.ClassDef) -> bool:
    return any(
        isinstance(base, ast.Attribute)
        and base.attr in {"Model", "TransientModel", "AbstractModel"}
        or isinstance(base, ast.Name)
        and base.id in {"Model", "TransientModel", "AbstractModel"}
        for base in node.bases
    )


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _resolve_constant(item.value, constants)
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return node.name


def _is_sensitive_field(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


def _is_sensitive_related(value: str) -> bool:
    lowered = value.lower()
    return any(part in lowered for part in SENSITIVE_RELATED_PARTS)


def _contains_public_group(groups: str) -> bool:
    return any(group in groups for group in PUBLIC_GROUPS)


def _has_admin_only_groups(groups: str) -> bool:
    return (
        bool(groups) and any(marker in groups for marker in ADMIN_GROUP_MARKERS) and not _contains_public_group(groups)
    )


def _string_keyword(field: FieldDef, keyword: str, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    value = field.keywords.get(keyword)
    value = _resolve_constant(value, constants) if value is not None else None
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _kw_is_true(field: FieldDef, keyword: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    value = field.keywords.get(keyword)
    value = _resolve_constant(value, constants) if value is not None else None
    return isinstance(value, ast.Constant) and value.value is True


def _kw_is_false(field: FieldDef, keyword: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    value = field.keywords.get(keyword)
    value = _resolve_constant(value, constants) if value is not None else None
    return isinstance(value, ast.Constant) and value.value is False


def _kw_is_tracking_enabled(field: FieldDef, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if _kw_is_true(field, "tracking", constants):
        return True
    value = field.keywords.get("track_visibility")
    value = _resolve_constant(value, constants) if value is not None else None
    return isinstance(value, ast.Constant) and value.value in {"onchange", "always"}


def _non_copyable_sensitive_field(field: FieldDef, constants: dict[str, ast.AST] | None = None) -> bool:
    if _kw_is_false(field, "copy", constants):
        return True
    return "compute" in field.keywords or "related" in field.keywords


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and _is_static_literal(statement.value):
                    constants[target.id] = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_static_literal(statement.value)
        ):
            constants[statement.target.id] = statement.value
    return constants


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        resolved = constants.get(node.id)
        if resolved is None:
            return node
        return _resolve_constant_seen(resolved, constants, {*seen, node.id})
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    return isinstance(node, ast.Constant) and isinstance(node.value, str | bool | int | float | type(None))


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[FieldSecurityFinding]) -> list[dict[str, Any]]:
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
            "field": f.field,
        }
        for f in findings
    ]
