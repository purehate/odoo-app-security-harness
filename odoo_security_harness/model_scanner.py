"""Odoo model-structure scanner.

This analyzer looks for model declarations that deserve integrity/security
review beyond generic Python scanning: copyable secrets, missing uniqueness
guards on identifier fields, secret-like display names, and monetary fields
without an obvious currency field in the model.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ModelFinding:
    """Represents a model-structure finding."""

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
    relation: str = ""


class ModelStructureScanner(ast.NodeVisitor):
    """AST scanner for Odoo model declarations."""

    IDENTIFIER_FIELDS = {"code", "ref", "reference", "external_id", "uuid", "slug"}
    SECRET_FIELD_MARKERS = (
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
        "passwd",
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
    SENSITIVE_DELEGATED_MODELS = {
        "account.move",
        "account.payment",
        "hr.contract",
        "hr.employee",
        "ir.attachment",
        "mail.message",
        "payment.transaction",
        "res.partner",
        "res.users",
        "sale.order",
        "stock.picking",
    }

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[ModelFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.field_module_names: set[str] = {"fields"}
        self.odoo_module_names: set[str] = {"odoo"}

    def scan_file(self) -> list[ModelFinding]:
        """Scan a Python file for model-structure findings."""
        try:
            source = Path(self.file_path).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except SyntaxError:
            return []
        except Exception:
            return []
        self.constants = self._module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze Odoo model classes."""
        if not self._is_odoo_model(node):
            self.generic_visit(node)
            return

        self.class_constants_stack.append(self._static_constants_from_body(node.body))
        model_name = self._extract_model_name(node)
        fields = self._extract_fields(node)
        constraints = self._extract_sql_constraints(node)
        delegated_models = self._extract_delegated_inherits(node)
        constrained_text = " ".join(constraints).lower()
        rec_name = self._extract_string_attr(node, "_rec_name")
        log_access = self._extract_bool_attr(node, "_log_access")
        auto = self._extract_bool_attr(node, "_auto")

        field_names = {field.name for field in fields}
        fields_by_name = {field.name: field for field in fields}
        if auto is False:
            self._add(
                "odoo-model-auto-false-manual-sql",
                "Model uses manually managed SQL storage",
                "medium",
                node.lineno,
                f"Model '{model_name}' sets _auto=False; verify SQL view/table creation, ACLs, record rules, and exposed fields are reviewed explicitly",
                model_name,
                "_auto",
            )

        if log_access is False:
            self._add(
                "odoo-model-log-access-disabled",
                "Model disables Odoo access logging",
                "high",
                node.lineno,
                f"Model '{model_name}' sets _log_access=False; create/write user and timestamp audit fields will not be maintained",
                model_name,
                "_log_access",
            )

        if rec_name and self._is_secret_like(rec_name):
            self._add(
                "odoo-model-rec-name-sensitive",
                "Model display name uses sensitive field",
                "high",
                node.lineno,
                f"Model '{model_name}' sets _rec_name to sensitive-looking field '{rec_name}'; display names can leak through relational widgets, chatter, exports, and logs",
                model_name,
                rec_name,
            )

        for delegated_model, link_field in delegated_models.items():
            if delegated_model in self.SENSITIVE_DELEGATED_MODELS:
                self._add(
                    "odoo-model-delegated-sensitive-inherits",
                    "Model delegates to sensitive model",
                    "high",
                    node.lineno,
                    f"Model '{model_name}' uses _inherits to delegate '{delegated_model}'; verify ACLs and record rules on the wrapper cannot expose delegated fields",
                    model_name,
                    link_field,
                )

            link = fields_by_name.get(link_field)
            if not link:
                self._add(
                    "odoo-model-delegated-link-missing",
                    "Delegated inheritance link field is missing",
                    "medium",
                    node.lineno,
                    f"_inherits maps '{delegated_model}' through '{link_field}', but no matching Many2one field is visible in the class",
                    model_name,
                    link_field,
                )
            elif not self._kw_is_true(link, "required"):
                self._add(
                    "odoo-model-delegated-link-not-required",
                    "Delegated inheritance link is not required",
                    "medium",
                    link.line,
                    f"Delegated _inherits link '{link_field}' is not required=True; wrapper records may exist without the delegated record and break access assumptions",
                    model_name,
                    link_field,
                )
            elif not self._kw_string_equals(link, "ondelete", "cascade"):
                self._add(
                    "odoo-model-delegated-link-no-cascade",
                    "Delegated inheritance link does not cascade",
                    "low",
                    link.line,
                    f"Delegated _inherits link '{link_field}' does not set ondelete='cascade'; verify delete/orphan semantics preserve delegated-record integrity",
                    model_name,
                    link_field,
                )

        for field in fields:
            lower_name = field.name.lower()
            if (
                field.field_type == "Many2one"
                and self._kw_is_true(field, "delegate")
                and field.relation in self.SENSITIVE_DELEGATED_MODELS
            ):
                self._add(
                    "odoo-model-delegate-sensitive-field",
                    "Many2one delegates sensitive model fields",
                    "high",
                    field.line,
                    f"Many2one field '{field.name}' sets delegate=True to sensitive model '{field.relation}'; verify wrapper ACLs cannot expose delegated fields",
                    model_name,
                    field.name,
                )

            if self._is_secret_like(lower_name):
                if not self._kw_is_false(field, "copy"):
                    self._add(
                        "odoo-model-secret-copyable",
                        "Secret-like field is copyable",
                        "medium",
                        field.line,
                        f"Field '{field.name}' looks secret/token-like but does not set copy=False; duplicated records may inherit credentials or access tokens",
                        model_name,
                        field.name,
                    )

            if field.name in self.IDENTIFIER_FIELDS and self._kw_is_true(field, "required"):
                if field.name not in constrained_text or "unique" not in constrained_text:
                    self._add(
                        "odoo-model-identifier-missing-unique",
                        "Required identifier field lacks obvious SQL uniqueness",
                        "medium",
                        field.line,
                        f"Required identifier field '{field.name}' has no visible unique _sql_constraints entry; review duplicate business-key risk",
                        model_name,
                        field.name,
                    )

            if field.field_type == "Monetary":
                currency_kw = field.keywords.get("currency_field")
                currency_kw = self._resolve_constant(currency_kw) if currency_kw is not None else None
                has_currency_kw = isinstance(currency_kw, ast.Constant) and bool(currency_kw.value)
                if not has_currency_kw and "currency_id" not in field_names:
                    self._add(
                        "odoo-model-monetary-missing-currency",
                        "Monetary field lacks obvious currency field",
                        "low",
                        field.line,
                        f"Monetary field '{field.name}' has no currency_field and model has no currency_id field; review cross-company/currency correctness",
                        model_name,
                        field.name,
                    )

        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.fields" and alias.asname:
                self.field_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "fields":
                    self.field_module_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _is_odoo_model(self, node: ast.ClassDef) -> bool:
        return any(
            isinstance(base, ast.Attribute)
            and base.attr in {"Model", "TransientModel", "AbstractModel"}
            or isinstance(base, ast.Name)
            and base.id in {"Model", "TransientModel", "AbstractModel"}
            for base in node.bases
        )

    def _extract_model_name(self, node: ast.ClassDef) -> str:
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                        value = self._resolve_constant(item.value)
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            return value.value
        return node.name

    def _extract_fields(self, node: ast.ClassDef) -> list[FieldDef]:
        fields: list[FieldDef] = []
        for item in node.body:
            field = self._field_def_from_assignment(item)
            if field is not None:
                fields.append(field)
        return fields

    def _field_def_from_assignment(self, node: ast.stmt) -> FieldDef | None:
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
        field_type = self._field_call_type(call.func)
        if not field_type:
            return None
        return FieldDef(
            name=target.id,
            field_type=field_type,
            line=node.lineno,
            keywords=self._call_keywords(call),
            relation=self._string_arg(call, 0),
        )

    def _call_keywords(self, node: ast.Call) -> dict[str, ast.AST]:
        keywords: dict[str, ast.AST] = {}
        for keyword in node.keywords:
            if keyword.arg is not None:
                keywords[keyword.arg] = keyword.value
                continue
            value = self._resolve_constant(keyword.value)
            if isinstance(value, ast.Dict):
                keywords.update(self._dict_keywords(value))
        return keywords

    def _dict_keywords(self, node: ast.Dict) -> dict[str, ast.AST]:
        keywords: dict[str, ast.AST] = {}
        for key, value in zip(node.keys, node.values, strict=False):
            if key is None:
                resolved_value = self._resolve_constant(value)
                if isinstance(resolved_value, ast.Dict):
                    keywords.update(self._dict_keywords(resolved_value))
                continue
            resolved_key = self._resolve_constant(key)
            if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
                keywords[resolved_key.value] = value
        return keywords

    def _field_call_type(self, node: ast.AST) -> str:
        if isinstance(node, ast.Attribute) and self._is_odoo_fields_module_expr(node.value):
            return node.attr
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _is_odoo_fields_module_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.field_module_names
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "fields"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.odoo_module_names
        )

    def _extract_sql_constraints(self, node: ast.ClassDef) -> list[str]:
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == "_sql_constraints":
                    return list(self._string_constants(item.value))
        return []

    def _extract_delegated_inherits(self, node: ast.ClassDef) -> dict[str, str]:
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == "_inherits":
                    return self._string_dict(self._resolve_constant(item.value))
        return {}

    def _extract_string_attr(self, node: ast.ClassDef, attr: str) -> str:
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == attr:
                    value = self._resolve_constant(item.value)
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        return value.value
        return ""

    def _extract_bool_attr(self, node: ast.ClassDef, attr: str) -> bool | None:
        for item in node.body:
            if isinstance(item, ast.Assign):
                targets = item.targets
                value = item.value
            elif isinstance(item, ast.AnnAssign):
                targets = [item.target]
                value = item.value
            else:
                continue
            if value is None:
                continue
            for target in targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == attr
                ):
                    resolved = self._resolve_constant(value)
                    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, bool):
                        return resolved.value
        return None

    def _is_secret_like(self, name: str) -> bool:
        lowered = name.lower()
        return any(marker in lowered for marker in self.SECRET_FIELD_MARKERS)

    def _string_dict(self, node: ast.AST) -> dict[str, str]:
        if not isinstance(node, ast.Dict):
            return {}
        values: dict[str, str] = {}
        for key, value in zip(node.keys, node.values, strict=False):
            key = self._resolve_constant(key)
            value = self._resolve_constant(value)
            if (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                values[key.value] = value.value
        return values

    def _string_arg(self, node: ast.Call, index: int) -> str:
        if len(node.args) <= index:
            return ""
        value = self._resolve_constant(node.args[index])
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
        return ""

    def _string_constants(self, node: ast.AST) -> list[str]:
        node = self._resolve_constant(node)
        values: list[str] = []
        for child in ast.walk(node):
            resolved = self._resolve_constant(child)
            if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
                values.append(resolved.value)
        return values

    def _kw_is_true(self, field: FieldDef, keyword: str) -> bool:
        value = field.keywords.get(keyword)
        value = self._resolve_constant(value) if value is not None else None
        return isinstance(value, ast.Constant) and value.value is True

    def _kw_is_false(self, field: FieldDef, keyword: str) -> bool:
        value = field.keywords.get(keyword)
        value = self._resolve_constant(value) if value is not None else None
        return isinstance(value, ast.Constant) and value.value is False

    def _kw_string_equals(self, field: FieldDef, keyword: str, expected: str) -> bool:
        value = field.keywords.get(keyword)
        value = self._resolve_constant(value) if value is not None else None
        return isinstance(value, ast.Constant) and value.value == expected

    def _module_constants(self, tree: ast.Module) -> dict[str, ast.AST]:
        return self._static_constants_from_body(tree.body)

    def _static_constants_from_body(self, statements: list[ast.stmt]) -> dict[str, ast.AST]:
        constants: dict[str, ast.AST] = {}
        for statement in statements:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and self._is_static_literal(statement.value):
                        constants[target.id] = statement.value
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.value is not None
                and self._is_static_literal(statement.value)
            ):
                constants[statement.target.id] = statement.value
        return constants

    def _resolve_constant(self, node: ast.AST | None, seen: set[str] | None = None) -> ast.AST | None:
        if isinstance(node, ast.Name):
            seen = seen or set()
            constants = self._effective_constants()
            if node.id in seen or node.id not in constants:
                return node
            seen.add(node.id)
            return self._resolve_constant(constants[node.id], seen)
        return node

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _is_static_literal(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str | bool | int | float | type(None))
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return all(self._is_static_literal(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            keys = [key for key in node.keys if key is not None]
            return all(
                self._is_static_literal(key) for key in keys
            ) and all(
                self._is_static_literal(value) for value in node.values
            )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
            return self._is_static_literal(node.operand)
        return False

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
            ModelFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=self.file_path,
                line=line,
                message=message,
                model=model,
                field=field,
            )
        )


def scan_models(repo_path: Path) -> list[ModelFinding]:
    """Scan Odoo model files in a repository."""
    findings: list[ModelFinding] = []
    for py_file in repo_path.rglob("*.py"):
        if _should_skip(py_file):
            continue
        findings.extend(ModelStructureScanner(str(py_file)).scan_file())
    return findings


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"tests", "__pycache__", ".venv", "venv", ".git", "node_modules"})


def findings_to_json(findings: list[ModelFinding]) -> list[dict[str, Any]]:
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
