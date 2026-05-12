"""Scanner for risky Odoo model constraint behavior."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from odoo_security_harness.base_scanner import _should_skip


@dataclass
class ConstraintFinding:
    """Represents a risky model constraint finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    method: str = ""
    field: str = ""


READ_METHODS = {"browse", "read", "read_group", "search", "search_count", "search_read"}
API_CONSTRAINT_DECORATORS = {"constrains"}


def scan_constraints(repo_path: Path) -> list[ConstraintFinding]:
    """Scan Odoo Python models for risky constraint declarations and logic."""
    findings: list[ConstraintFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ConstraintScanner(path).scan_file())
    return findings


class ConstraintScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ConstraintFinding] = []
        self.model_stack: list[str] = []
        self.method_stack: list[ConstraintContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.api_module_names: set[str] = {"api"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.api_decorator_names: set[str] = set()
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[ConstraintFinding]:
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

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.api":
                if alias.asname:
                    self.api_module_names.add(alias.asname)
                else:
                    self.odoo_module_names.add("odoo")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "api":
                    self.api_module_names.add(alias.asname or alias.name)
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.api":
            for alias in node.names:
                if alias.name in API_CONSTRAINT_DECORATORS:
                    self.api_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        if not _is_odoo_model(node):
            self.generic_visit(node)
            return
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.model_stack.append(_extract_model_name(node, self._effective_constants()))
        self.generic_visit(node)
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if not self.model_stack:
            self.generic_visit(node)
            return

        decorator = _constraint_decorator(
            node,
            self.api_module_names,
            self.odoo_module_names,
            self.api_decorator_names,
        )
        is_named_constraint = node.name.startswith("_check")
        if decorator is None and not is_named_constraint:
            self.generic_visit(node)
            return

        fields = _constraint_fields(decorator, self._effective_constants()) if decorator else []
        previous_local_constants = self.local_constants
        self.local_constants = {}
        context = ConstraintContext(name=node.name)
        self.method_stack.append(context)

        if decorator is not None:
            self._check_decorator(node, decorator, fields)

        self.generic_visit(node)
        self.method_stack.pop()
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            for target in node.targets:
                self._mark_local_constant_target(target, node.value)
                self._track_sudo_alias(target, node.value, context)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.method_stack and node.value is not None:
            context = self.method_stack[-1]
            self._mark_local_constant_target(node.target, node.value)
            self._track_sudo_alias(node.target, node.value, context)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            self._mark_local_constant_target(node.target, node.value)
            self._track_sudo_alias(node.target, node.value, context)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return

        context = self.method_stack[-1]
        sink = _call_name(node.func)
        if _is_sudo_read_call(node, sink, context.sudo_vars, self._effective_constants(), self.superuser_names):
            self._add(
                "odoo-constraint-sudo-search",
                "Constraint reads through sudo",
                "high",
                node.lineno,
                (
                    f"Constraint '{context.name}' reads through sudo()/with_user(SUPERUSER_ID); validate "
                    "that uniqueness and business-rule checks cannot hide company or record-rule issues"
                ),
                context.name,
            )
        if _is_unbounded_search(node, sink):
            self._add(
                "odoo-constraint-unbounded-search",
                "Constraint performs unbounded search",
                "medium",
                node.lineno,
                (
                    f"Constraint '{context.name}' performs search without a limit; validation can become "
                    "slow or lock-prone on large tables"
                ),
                context.name,
            )
        if sink.rsplit(".", 1)[-1] == "ensure_one":
            self._add(
                "odoo-constraint-ensure-one",
                "Constraint assumes a singleton recordset",
                "medium",
                node.lineno,
                (
                    f"Constraint '{context.name}' calls ensure_one(); constraints may run on multi-record "
                    "recordsets during batch create/write and should validate every record"
                ),
                context.name,
            )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return

        if _returns_false_or_none(node, self._effective_constants()):
            context = self.method_stack[-1]
            self._add(
                "odoo-constraint-return-ignored",
                "Constraint returns a value instead of raising",
                "medium",
                node.lineno,
                (
                    f"Constraint '{context.name}' returns False/None; Odoo constraints must raise "
                    "ValidationError to block invalid records"
                ),
                context.name,
            )

        self.generic_visit(node)

    def _check_decorator(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.Call,
        fields: list[str],
    ) -> None:
        if not decorator.args:
            self._add(
                "odoo-constraint-empty-fields",
                "Constraint decorator has no fields",
                "high",
                node.lineno,
                (
                    f"Constraint '{node.name}' has @api.constrains() without fields, so it will not run "
                    "for normal field writes"
                ),
                node.name,
            )
            return

        for arg in decorator.args:
            resolved_arg = _resolve_constant(arg, self._effective_constants())
            if not isinstance(resolved_arg, ast.Constant) or not isinstance(resolved_arg.value, str):
                self._add(
                    "odoo-constraint-dynamic-field",
                    "Constraint decorator uses dynamic field expression",
                    "medium",
                    getattr(arg, "lineno", node.lineno),
                    (
                        f"Constraint '{node.name}' uses a non-literal @api.constrains argument; verify "
                        "Odoo registers the intended fields"
                    ),
                    node.name,
                )

        for field in fields:
            if "." in field:
                self._add(
                    "odoo-constraint-dotted-field",
                    "Constraint decorator uses dotted field",
                    "high",
                    node.lineno,
                    (
                        f"Constraint '{node.name}' watches dotted field '{field}', which Odoo "
                        "@api.constrains does not trigger reliably"
                    ),
                    node.name,
                    field,
                )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        method: str,
        field: str = "",
    ) -> None:
        self.findings.append(
            ConstraintFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=self.model_stack[-1] if self.model_stack else "",
                method=method,
                field=field,
            )
        )

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST, context: ConstraintContext) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
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
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
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
class ConstraintContext:
    """Current constraint context."""

    name: str
    sudo_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()


def _constraint_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    api_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
    api_decorator_names: set[str] | None = None,
) -> ast.Call | None:
    api_module_names = api_module_names or {"api"}
    odoo_module_names = odoo_module_names or {"odoo"}
    api_decorator_names = api_decorator_names or set()
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and _is_constraint_decorator_func(
            decorator.func,
            api_module_names,
            odoo_module_names,
            api_decorator_names,
        ):
            return decorator
    return None


def _is_constraint_decorator_func(
    node: ast.AST,
    api_module_names: set[str],
    odoo_module_names: set[str],
    api_decorator_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "constrains" or node.id in api_decorator_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "constrains"
        and _is_odoo_api_module_expr(node.value, api_module_names, odoo_module_names)
    )


def _is_odoo_api_module_expr(
    node: ast.AST,
    api_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in api_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "api"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _constraint_fields(decorator: ast.Call | None, constants: dict[str, ast.AST] | None = None) -> list[str]:
    if decorator is None:
        return []
    constants = constants or {}
    fields: list[str] = []
    for arg in decorator.args:
        value = _resolve_constant(arg, constants)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            fields.append(value.value)
    return fields


def _is_odoo_model(node: ast.ClassDef) -> bool:
    return any(
        isinstance(base, ast.Attribute)
        and base.attr in {"Model", "TransientModel", "AbstractModel"}
        or isinstance(base, ast.Name)
        and base.id in {"Model", "TransientModel", "AbstractModel"}
        for base in node.bases
    )


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _resolve_constant(item.value, constants or {})
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return node.name


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
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants, superuser_names) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_vars
    )


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args)
                    or any(
                        keyword.arg in {"user", "uid"}
                        and keyword.value is not None
                        and _is_superuser_arg(keyword.value, constants, superuser_names)
                        for keyword in current.keywords
                    )
                )
            ):
                return True
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _is_unbounded_search(node: ast.Call, sink: str) -> bool:
    if sink.rsplit(".", 1)[-1] not in {"read_group", "search", "search_count", "search_read"}:
        return False
    if any(keyword.arg == "limit" for keyword in node.keywords):
        return False
    return bool(node.args)


def _returns_false_or_none(node: ast.Return, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node.value, constants or {}) if node.value is not None else None
    return value is None or isinstance(value, ast.Constant) and value.value in {False, None}


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_attr(node.value, attr)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_call_chain_has_attr(element, attr) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Attribute):
            if current.attr == attr:
                return True
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    return False


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    return set()


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


def _call_root_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _call_root_name(node.value)
    if isinstance(node, ast.Call):
        return _call_root_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_root_name(node.value)
    return ""


def _unpack_target_value_pairs(
    targets: list[ast.expr],
    values: list[ast.expr],
) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    tail_count = len(targets) - starred_index - 1
    if len(values) < starred_index + tail_count:
        return list(zip(targets, values, strict=False))

    pairs: list[tuple[ast.expr, ast.AST]] = []
    pairs.extend(zip(targets[:starred_index], values[:starred_index], strict=False))
    rest_values = values[starred_index : len(values) - tail_count if tail_count else len(values)]
    pairs.append((targets[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if tail_count:
        pairs.extend(zip(targets[-tail_count:], values[-tail_count:], strict=False))
    return pairs


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in statements:
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
        seen.add(node.id)
        return _resolve_constant_seen(resolved, constants, seen)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    return isinstance(node, ast.Name)


def findings_to_json(findings: list[ConstraintFinding]) -> list[dict[str, Any]]:
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
            "field": f.field,
        }
        for f in findings
    ]
