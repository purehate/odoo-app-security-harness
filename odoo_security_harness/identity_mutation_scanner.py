"""Scanner for risky Odoo user/group identity mutations."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from odoo_security_harness.base_scanner import _should_skip


@dataclass
class IdentityMutationFinding:
    """Represents a risky identity mutation finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    route: str = ""
    sink: str = ""


IDENTITY_MODELS = {"res.users", "res.groups"}
MUTATION_METHODS = {"create", "write", "unlink"}
TAINTED_ARG_NAMES = {"data", "kwargs", "kw", "payload", "post", "values", "vals"}
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
PRIVILEGE_FIELDS = {
    "active",
    "company_id",
    "company_ids",
    "groups_id",
    "implied_ids",
    "login",
    "oauth_uid",
    "password",
    "share",
}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")


def scan_identity_mutations(repo_path: Path) -> list[IdentityMutationFinding]:
    """Scan Python files for risky user/group create/write/unlink patterns."""
    findings: list[IdentityMutationFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(IdentityMutationScanner(path).scan_file())
    return findings


class IdentityMutationScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[IdentityMutationFinding] = []
        self.identity_vars: dict[str, str] = {}
        self.elevated_identity_vars: set[str] = set()
        self.tainted_names: set[str] = set()
        self.dict_fields_by_var: dict[str, set[str]] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[IdentityMutationFinding]:
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
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_identity_vars = dict(self.identity_vars)
        previous_elevated_identity_vars = set(self.elevated_identity_vars)
        previous_tainted = set(self.tainted_names)
        previous_dict_fields = dict(self.dict_fields_by_var)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(is_route=False)
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.identity_vars = previous_identity_vars
        self.elevated_identity_vars = previous_elevated_identity_vars
        self.tainted_names = previous_tainted
        self.dict_fields_by_var = previous_dict_fields
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_identity_vars = dict(self.identity_vars)
        previous_elevated_identity_vars = set(self.elevated_identity_vars)
        previous_dict_fields = dict(self.dict_fields_by_var)

        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_identity_target(target, node.value, previous_identity_vars, previous_elevated_identity_vars)
            self._mark_dict_fields_target(target, node.value, previous_dict_fields)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_identity_target(
                node.target,
                node.value,
                dict(self.identity_vars),
                set(self.elevated_identity_vars),
            )
            self._mark_dict_fields_target(node.target, node.value, dict(self.dict_fields_by_var))
            self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_identity_target(
            node.target,
            node.value,
            dict(self.identity_vars),
            set(self.elevated_identity_vars),
        )
        self._mark_dict_fields_target(node.target, node.value, dict(self.dict_fields_by_var))
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self.tainted_names.update(_target_names(node.target))
        else:
            _discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        self._mark_dict_fields_update_call(node)
        if method not in MUTATION_METHODS:
            self.generic_visit(node)
            return

        constants = self._effective_constants()
        model = _identity_model_in_expr(node.func, self.identity_vars, constants)
        if not model:
            self.generic_visit(node)
            return

        route = self._current_route()
        if route.is_route and route.auth in {"public", "none"}:
            self._add(
                "odoo-identity-public-route-mutation",
                "Public route mutates users or groups",
                "critical",
                node.lineno,
                f"Public route {route.display_path()} mutates {model}; "
                "verify only authenticated administrators can change identity, groups, and companies",
                model,
                route,
                sink,
            )

        if _is_elevated_call(node.func, constants, self.superuser_names) or _uses_elevated_identity_var(
            node.func, self.elevated_identity_vars
        ):
            self._add(
                "odoo-identity-elevated-mutation",
                "Identity mutation runs in elevated context",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                f"{model} mutation uses sudo()/with_user(SUPERUSER_ID); "
                "verify explicit admin checks and audit trail before privilege changes",
                model,
                route,
                sink,
            )

        if _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-identity-request-derived-mutation",
                "Request-derived data reaches identity mutation",
                "critical",
                node.lineno,
                f"Request-derived data reaches {model}.{method}; "
                "whitelist allowed fields and reject privilege, company, login, and password changes",
                model,
                route,
                sink,
            )

        privilege_fields = _privilege_fields_from_call(node, self.dict_fields_by_var, constants)
        if privilege_fields:
            fields = ", ".join(sorted(privilege_fields))
            self._add(
                "odoo-identity-privilege-field-write",
                "Identity mutation writes privilege-bearing fields",
                "critical" if {"groups_id", "implied_ids"} & privilege_fields else "high",
                node.lineno,
                f"{model}.{method} writes privilege-bearing field(s): {fields}; "
                "verify group/company/user activation changes are admin-only",
                model,
                route,
                sink,
            )

        self.generic_visit(node)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted(node.left) or any(
                self._expr_is_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_tainted(node.test)
                or self._expr_is_tainted(node.body)
                or self._expr_is_tainted(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                    for generator in node.generators
                )
            )
        return False

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_tainted_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return

        is_tainted = self._expr_is_tainted(value)
        if is_tainted:
            self.tainted_names.update(_target_names(target))
        else:
            _discard_name_target(target, self.tainted_names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return

        names = _target_names(target)
        if not names:
            return
        if isinstance(target, ast.Name) and _is_static_literal(value):
            self.local_constants[target.id] = value
            return
        for name in names:
            self.local_constants.pop(name, None)

    def _mark_identity_target(
        self,
        target: ast.AST,
        value: ast.AST,
        identity_vars: dict[str, str],
        elevated_identity_vars: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_identity_target(target_element, value_element, identity_vars, elevated_identity_vars)
            return
        if isinstance(target, ast.Starred):
            self._mark_identity_target(target.value, value, identity_vars, elevated_identity_vars)
            return

        names = _target_names(target)
        if not names:
            return

        constants = self._effective_constants()
        model = _identity_model_in_expr(value, identity_vars, constants)
        if not model:
            for name in names:
                self.identity_vars.pop(name, None)
                self.elevated_identity_vars.discard(name)
            return

        is_elevated = _is_elevated_call(value, constants, self.superuser_names) or _uses_elevated_identity_var(
            value, elevated_identity_vars
        )
        for name in names:
            self.identity_vars[name] = model
            if is_elevated:
                self.elevated_identity_vars.add(name)
            else:
                self.elevated_identity_vars.discard(name)

    def _mark_dict_fields_target(
        self,
        target: ast.AST,
        value: ast.AST,
        dict_fields_by_var: dict[str, set[str]],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_dict_fields_target(target_element, value_element, dict_fields_by_var)
            return
        if isinstance(target, ast.Starred):
            fields = _collection_dict_keys(value, self._effective_constants())
            names = _target_names(target.value)
            for name in names:
                if fields:
                    self.dict_fields_by_var[name] = fields
                else:
                    self.dict_fields_by_var.pop(name, None)
            if fields or names:
                return
            self._mark_dict_fields_target(target.value, value, dict_fields_by_var)
            return

        fields = _dict_keys(value, self._effective_constants())
        if isinstance(value, ast.Name):
            fields = dict_fields_by_var.get(value.id, fields)
        elif isinstance(value, ast.Subscript):
            fields = dict_fields_by_var.get(_call_root_name(value), fields)

        for name in _target_names(target):
            if fields:
                self.dict_fields_by_var[name] = fields
            else:
                self.dict_fields_by_var.pop(name, None)

    def _mark_dict_fields_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        root_name = _call_root_name(node.func.value)
        if not root_name:
            return

        constants = self._effective_constants()
        fields = set(self.dict_fields_by_var.get(root_name, set()))
        for arg in node.args:
            fields |= _dict_fields_for_update_expr(arg, self.dict_fields_by_var, constants)
            if self._expr_is_tainted(arg):
                self.tainted_names.add(root_name)
        for keyword in node.keywords:
            if keyword.arg is not None:
                fields.add(keyword.arg)
                if self._expr_is_tainted(keyword.value):
                    self.tainted_names.add(root_name)
                continue
            fields |= _dict_fields_for_update_expr(keyword.value, self.dict_fields_by_var, constants)
            if self._expr_is_tainted(keyword.value):
                self.tainted_names.add(root_name)
        if fields:
            self.dict_fields_by_var[root_name] = fields

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        route: RouteContext,
        sink: str,
    ) -> None:
        self.findings.append(
            IdentityMutationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                route=route.display_path() if route.is_route else "",
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current HTTP route context."""

    is_route: bool
    auth: str = "user"
    paths: tuple[str, ...] = ()

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for keyword in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword.value, constants)
                if keyword.arg == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif keyword.arg in {"route", "routes"}:
                    paths.extend(_route_values(value, constants))
        return RouteContext(is_route=True, auth=auth, paths=tuple(paths))
    return None


def _is_http_route(
    node: ast.AST,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_decorator_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_decorator_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _is_http_module_expr(
    node: ast.AST,
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _route_values(node: ast.AST, constants: dict[str, ast.AST]) -> list[str]:
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values: list[str] = []
        for item in node.elts:
            resolved = _resolve_constant(item, constants)
            if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
                values.append(resolved.value)
        return values
    return []


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
        elif isinstance(statement, ast.Expr):
            _mark_static_dict_update(statement.value, constants)
    return constants


def _mark_static_dict_update(node: ast.AST, constants: dict[str, ast.AST]) -> None:
    if not isinstance(node, ast.Call):
        return
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
        return
    if not isinstance(node.func.value, ast.Name):
        return
    name = node.func.value.id
    values_node = _resolve_static_dict(ast.Name(id=name, ctx=ast.Load()), constants)
    if values_node is None:
        return
    for arg in node.args:
        arg_values = _resolve_static_dict(arg, constants)
        if arg_values is not None:
            for keyword in _expanded_dict_keywords(arg_values, constants):
                values_node = _dict_with_field(values_node, keyword.arg, keyword.value)
    for keyword in node.keywords:
        if keyword.arg is not None:
            values_node = _dict_with_field(values_node, keyword.arg, keyword.value)
            continue
        keyword_values = _resolve_static_dict(keyword.value, constants)
        if keyword_values is not None:
            for expanded in _expanded_dict_keywords(keyword_values, constants):
                values_node = _dict_with_field(values_node, expanded.arg, expanded.value)
    constants[name] = values_node


def _dict_with_field(values_node: ast.Dict, key: str | None, value: ast.AST) -> ast.Dict:
    if key is None:
        return values_node
    keys = list(values_node.keys)
    values = list(values_node.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values[index] = value
            return ast.Dict(keys=keys, values=values)
    keys.append(ast.Constant(value=key))
    values.append(value)
    return ast.Dict(keys=keys, values=values)


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append(keyword)
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is not None:
            keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for key, dict_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(dict_value, constants)
            if value is not None:
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append(ast.keyword(arg=resolved_key.value, value=dict_value))
    return keywords


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        return _resolve_constant_seen(value, constants, {*seen, node.id})
    return node


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant_seen(node, constants, seen)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants, set(seen))
        right = _resolve_static_dict(node.right, constants, set(seen))
        if left is None or right is None:
            return None
        return ast.Dict(keys=[*left.keys, *right.keys], values=[*left.values, *right.values])
    return None


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _identity_model_in_expr(
    node: ast.AST,
    identity_vars: dict[str, str],
    constants: dict[str, ast.AST] | None = None,
) -> str:
    constants = constants or {}
    if isinstance(node, ast.Name) and node.id in identity_vars:
        return identity_vars[node.id]
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in identity_vars:
            return identity_vars[child.id]
        if isinstance(child, ast.Subscript):
            model = _env_model_name(child, constants)
            if model in IDENTITY_MODELS:
                return model
    return ""


def _env_model_name(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str:
    if not _call_name(node.value).endswith("env"):
        return ""
    slice_node = _resolve_constant(node.slice, constants or {})
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        return slice_node.value
    return ""


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _is_request_derived(
    node: ast.AST,
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"params", "jsonrequest", "httprequest"} and _is_request_expr(
            node.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            node.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_MARKERS)


def _is_request_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in request_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _unpack_target_value_pairs(
    target_elts: list[ast.expr], value_elts: list[ast.expr]
) -> list[tuple[ast.expr, ast.expr]]:
    starred_index = next(
        (index for index, element in enumerate(target_elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target_elts, value_elts, strict=False))

    after_count = len(target_elts) - starred_index - 1
    pairs = list(zip(target_elts[:starred_index], value_elts[:starred_index], strict=False))
    rest_end = len(value_elts) - after_count if after_count else len(value_elts)
    rest_values = value_elts[starred_index:rest_end]
    pairs.append((target_elts[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if after_count:
        pairs.extend(zip(target_elts[-after_count:], value_elts[-after_count:], strict=False))
    return pairs


def _is_elevated_call(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_elevated_call(element, constants, superuser_names) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _is_elevated_call(node.value, constants, superuser_names)
    text = _safe_unparse(node)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or "SUPERUSER_ID" in text
    )


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if not (isinstance(child.func, ast.Attribute) and child.func.attr == "with_user"):
            continue
        if any(_is_admin_user_arg(arg, constants, superuser_names) for arg in child.args):
            return True
        if any(
            keyword.arg in {"user", "uid"}
            and keyword.value is not None
            and _is_admin_user_arg(keyword.value, constants, superuser_names)
            for keyword in child.keywords
        ):
            return True
    return False


def _is_admin_user_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_admin_user_arg(resolved, constants, superuser_names)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_admin_user_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _uses_elevated_identity_var(node: ast.AST, elevated_identity_vars: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in elevated_identity_vars for child in ast.walk(node))


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _privilege_fields_from_call(
    node: ast.Call,
    dict_fields_by_var: dict[str, set[str]],
    constants: dict[str, ast.AST] | None = None,
) -> set[str]:
    fields: set[str] = set()
    for arg in node.args:
        fields |= _privilege_fields(arg, dict_fields_by_var, constants)
    for keyword in node.keywords:
        if keyword.value is not None:
            fields |= _privilege_fields(keyword.value, dict_fields_by_var, constants)
    return fields


def _privilege_fields(
    node: ast.AST,
    dict_fields_by_var: dict[str, set[str]],
    constants: dict[str, ast.AST] | None = None,
) -> set[str]:
    if isinstance(node, ast.Name):
        return _filter_privilege_fields(dict_fields_by_var.get(node.id, set()))
    if isinstance(node, ast.Subscript):
        return _filter_privilege_fields(dict_fields_by_var.get(_call_root_name(node), set()))
    return _filter_privilege_fields(_dict_keys(node, constants))


def _dict_fields_for_update_expr(
    node: ast.AST,
    dict_fields_by_var: dict[str, set[str]],
    constants: dict[str, ast.AST] | None = None,
) -> set[str]:
    if isinstance(node, ast.Name):
        return set(dict_fields_by_var.get(node.id, set())) or _dict_keys(node, constants)
    if isinstance(node, ast.Subscript):
        return set(dict_fields_by_var.get(_call_root_name(node), set())) or _dict_keys(node, constants)
    return _dict_keys(node, constants)


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


def _discard_name_target(node: ast.AST, names: set[str]) -> None:
    for name in _target_names(node):
        names.discard(name)


def _filter_privilege_fields(fields: set[str]) -> set[str]:
    return {field for field in fields if field in PRIVILEGE_FIELDS or field.startswith("sel_groups_")}


def _dict_keys(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> set[str]:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if not isinstance(node, ast.Dict):
        return set()
    keys: set[str] = set()
    for key in node.keys:
        resolved = _resolve_constant(key, constants) if key is not None else key
        if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
            keys.add(resolved.value)
    return keys


def _collection_dict_keys(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> set[str]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        keys: set[str] = set()
        for element in node.elts:
            keys |= _dict_keys(element, constants)
        return keys
    return _dict_keys(node, constants)


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""



def findings_to_json(findings: list[IdentityMutationFinding]) -> list[dict[str, Any]]:
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
            "route": f.route,
            "sink": f.sink,
        }
        for f in findings
    ]
