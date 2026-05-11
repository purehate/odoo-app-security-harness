"""Scanner for risky Odoo model access/search overrides."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from odoo_security_harness.base_scanner import (
    _call_chain_has_attr,
    _call_chain_has_superuser_with_user,
    _call_root_name,
    _extract_model_name,
    _is_odoo_model,
    _is_static_literal,
    _module_constants,
    _returns_true,
    _should_skip,
    _static_constants_from_body,
    _target_names,
    _unpack_target_value_pairs,
)


@dataclass
class AccessOverrideFinding:
    """Represents an access/search override finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    method: str = ""


ACCESS_OVERRIDE_METHODS = {
    "_filter_access_rules",
    "_filter_access_rules_python",
    "check_access_rights",
    "check_access_rule",
}
SEARCH_OVERRIDE_METHODS = {"_search", "name_search", "search", "search_read"}
READ_METHODS = {"browse", "read", "read_group", "search", "search_count", "search_read"}


def scan_access_overrides(repo_path: Path) -> list[AccessOverrideFinding]:
    """Scan Python models for risky access/search method overrides."""
    findings: list[AccessOverrideFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(AccessOverrideScanner(path).scan_file())
    return findings


class AccessOverrideScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[AccessOverrideFinding] = []
        self.model_stack: list[str] = []
        self.method_stack: list[MethodContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.model_base_names: set[str] = set({"Model", "TransientModel", "AbstractModel"})
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[AccessOverrideFinding]:
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
        if not _is_odoo_model(node, self.model_base_names):
            self.generic_visit(node)
            return
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.model_stack.append(_extract_model_name(node, self._effective_constants()))
        self.generic_visit(node)
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.models":
            for alias in node.names:
                if alias.name in {"Model", "TransientModel", "AbstractModel"}:
                    self.model_base_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if not self.model_stack or node.name not in ACCESS_OVERRIDE_METHODS | SEARCH_OVERRIDE_METHODS:
            self.generic_visit(node)
            return
        previous_local_constants = self.local_constants
        self.local_constants = {}
        context = MethodContext(name=node.name)
        self.method_stack.append(context)
        self.generic_visit(node)
        self._finish_method(node, context)
        self.method_stack.pop()
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.method_stack:
            for target in node.targets:
                self._mark_local_constant_target(target, node.value)
            self._track_sudo_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.method_stack and node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._track_sudo_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.method_stack:
            self._mark_local_constant_target(node.target, node.value)
            self._track_sudo_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return
        context = self.method_stack[-1]
        sink = _call_name(node.func)
        if "super" in sink:
            context.has_super = True
        if context.name in SEARCH_OVERRIDE_METHODS and _is_sudo_read_call(
            node, sink, context.sudo_vars, self._effective_constants(), self.superuser_names
        ):
            self._add(
                "odoo-access-override-sudo-search",
                "Search override reads through elevated environment",
                "high",
                node.lineno,
                f"Model search override '{context.name}' reads through sudo()/with_user(SUPERUSER_ID); verify it cannot bypass record rules or company isolation for all callers",
                context.name,
            )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return
        context = self.method_stack[-1]
        if context.name in {"check_access_rights", "check_access_rule"} and _returns_true(
            node, self._effective_constants()
        ):
            context.returns_true = True
            context.return_line = node.lineno
        elif context.name.startswith("_filter_access_rules") and _returns_self(node):
            context.returns_self = True
            context.return_line = node.lineno
        self.generic_visit(node)

    def _finish_method(self, node: ast.FunctionDef | ast.AsyncFunctionDef, context: MethodContext) -> None:
        if context.name in ACCESS_OVERRIDE_METHODS and not context.has_super:
            self._add(
                "odoo-access-override-missing-super",
                "Access override does not call super",
                "medium",
                node.lineno,
                f"Model access override '{context.name}' does not call super(); verify it preserves base ACL and record-rule behavior",
                context.name,
            )
        if context.returns_true and not context.has_super:
            self._add(
                "odoo-access-override-allow-all",
                "Access override returns allow-all",
                "critical",
                context.return_line or node.lineno,
                f"Model access override '{context.name}' returns True without super(); this can disable access-right or record-rule enforcement",
                context.name,
            )
        if context.returns_self and not context.has_super:
            self._add(
                "odoo-access-override-filter-self",
                "Record-rule filter override returns self",
                "critical",
                context.return_line or node.lineno,
                f"Model access filter override '{context.name}' returns self without super(); this can bypass record-rule filtering for every caller",
                context.name,
            )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, method: str) -> None:
        self.findings.append(
            AccessOverrideFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=self.model_stack[-1] if self.model_stack else "",
                method=method,
            )
        )

    def _track_sudo_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        context = self.method_stack[-1]
        for target in targets:
            self._track_sudo_alias(target, value, context)

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST, context: MethodContext) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._track_sudo_alias(child_target, child_value, context)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for child_target in target.elts:
                self._track_sudo_alias(child_target, value, context)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value, context)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_sudo_expr(value, context.sudo_vars, self._effective_constants(), self.superuser_names):
            context.sudo_vars.add(target.id)
        else:
            context.sudo_vars.discard(target.id)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(child_target, child_value)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for name in _target_names(target):
                self.local_constants.pop(name, None)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants


@dataclass
class MethodContext:
    """Current override context."""

    name: str
    has_super: bool = False
    returns_true: bool = False
    returns_self: bool = False
    return_line: int = 0
    sudo_vars: set[str] | None = None

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()


def _is_sudo_read_call(
    node: ast.Call,
    sink: str,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return sink.rsplit(".", 1)[-1] in READ_METHODS and _is_sudo_expr(node.func, sudo_vars, constants, superuser_names)


def _is_sudo_expr(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_vars, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_sudo_expr(elt, sudo_vars, constants, superuser_names) for elt in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_vars
    )


def _returns_self(node: ast.Return) -> bool:
    return isinstance(node.value, ast.Name) and node.value.id == "self"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


def findings_to_json(findings: list[AccessOverrideFinding]) -> list[dict[str, Any]]:
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
            "method": f.method,
        }
        for f in findings
    ]
