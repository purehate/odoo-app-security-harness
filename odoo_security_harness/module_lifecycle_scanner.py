"""Scanner for risky Odoo module install, upgrade, and uninstall flows."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ModuleLifecycleFinding:
    """Represents a risky module lifecycle finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


MODULE_MODEL = "ir.module.module"
MODULE_METHODS = {
    "button_immediate_install",
    "button_immediate_upgrade",
    "button_immediate_uninstall",
    "button_install",
    "button_uninstall",
    "button_upgrade",
}
IMMEDIATE_METHODS = {"button_immediate_install", "button_immediate_upgrade", "button_immediate_uninstall"}
TAINTED_ARG_NAMES = {"module", "module_name", "name", "kwargs", "kw", "post", "params", "payload"}
REQUEST_MARKERS = (
    "request.params",
    "request.get_http_params",
    "request.get_json_data",
    "request.jsonrequest",
    "request.httprequest",
    "kwargs.get",
    "kw.get",
    "post.get",
)
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}


def scan_module_lifecycle(repo_path: Path) -> list[ModuleLifecycleFinding]:
    """Scan Python files for risky runtime module lifecycle operations."""
    findings: list[ModuleLifecycleFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ModuleLifecycleScanner(path).scan_file())
    return findings


class ModuleLifecycleScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ModuleLifecycleFinding] = []
        self.module_vars: set[str] = set()
        self.sudo_module_vars: set[str] = set()
        self.tainted_names: set[str] = set()
        self.tainted_module_vars: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[ModuleLifecycleFinding]:
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_module_vars = set(self.module_vars)
        previous_sudo_module_vars = set(self.sudo_module_vars)
        previous_tainted = set(self.tainted_names)
        previous_tainted_module_vars = set(self.tainted_module_vars)
        self.route_stack.append(
            _route_info(
                node,
                self._effective_constants(),
                self.route_names,
                self.http_module_names,
                self.odoo_module_names,
            )
            or RouteContext(is_route=False)
        )

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES:
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.module_vars = previous_module_vars
        self.sudo_module_vars = previous_sudo_module_vars
        self.tainted_names = previous_tainted
        self.tainted_module_vars = previous_tainted_module_vars

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

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
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._record_target_state(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._record_target_state(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._record_target_state(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        target_names = _target_names(node.target)
        if self._expr_is_tainted(node.iter):
            for name in target_names:
                self.tainted_names.add(name)
        else:
            for name in target_names:
                self.tainted_names.discard(name)
        constants = self._effective_constants()
        if _module_model_in_expr(node.iter, self.module_vars, constants):
            for name in target_names:
                self.module_vars.add(name)
                if _uses_sudo_module_var(node.iter, self.sudo_module_vars) or _is_elevated_expr(
                    node.iter, constants, self.superuser_names
                ):
                    self.sudo_module_vars.add(name)
                else:
                    self.sudo_module_vars.discard(name)
                if self._expr_is_tainted(node.iter):
                    self.tainted_module_vars.add(name)
                else:
                    self.tainted_module_vars.discard(name)
        else:
            for name in target_names:
                self.module_vars.discard(name)
                self.sudo_module_vars.discard(name)
                self.tainted_module_vars.discard(name)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._record_tainted_container_mutation(node)
        self._scan_lifecycle_call(node)
        self.generic_visit(node)

    def _scan_lifecycle_call(self, node: ast.Call) -> None:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        if method not in MODULE_METHODS:
            return
        constants = self._effective_constants()
        if not _module_model_in_expr(node.func, self.module_vars, constants):
            return

        route = self._current_route()
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-module-public-route-lifecycle",
                "Public route changes module lifecycle",
                "critical",
                node.lineno,
                f"Public/unauthenticated route calls {method}; verify attackers cannot install, upgrade, or uninstall Odoo modules",
                route.display_path(),
                sink,
            )
        if _is_elevated_expr(node.func, constants, self.superuser_names) or _uses_sudo_module_var(
            node.func, self.sudo_module_vars
        ):
            self._add(
                "odoo-module-sudo-lifecycle",
                "Module lifecycle operation runs with an elevated environment",
                "high",
                node.lineno,
                f"Module lifecycle method {method} runs through sudo()/with_user(SUPERUSER_ID); verify only system administrators can alter installed code and data",
                route.display_path(),
                sink,
            )
        if method in IMMEDIATE_METHODS:
            self._add(
                "odoo-module-immediate-lifecycle",
                "Immediate module lifecycle operation",
                "high",
                node.lineno,
                f"{method} executes module lifecycle work immediately; verify transactional impact, migrations, access rules, and registry reload behavior",
                route.display_path(),
                sink,
            )
        if self._module_selection_is_tainted(node.func):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-module-tainted-selection",
                "Request-derived module selection",
                severity,
                node.lineno,
                "Request-derived data selects an ir.module.module record before a lifecycle operation; restrict to an explicit allowlist and admin-only flow",
                route.display_path(),
                sink,
            )

    def _module_selection_is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._module_selection_is_tainted(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._module_selection_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Attribute):
            return self._module_selection_is_tainted(node.value)
        if isinstance(node, ast.Call):
            if _call_name(node.func).rsplit(".", 1)[-1] in {"search", "browse"} and _call_has_tainted_input(
                node, self._expr_is_tainted
            ):
                return True
            return self._module_selection_is_tainted(node.func)
        if isinstance(node, ast.Subscript):
            return self._module_selection_is_tainted(node.value)
        return isinstance(node, ast.Name) and node.id in self.tainted_module_vars

    def _record_target_state(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._record_target_state(target_element, value_element)
            return

        constants = self._effective_constants()
        is_module_expr = _module_model_in_expr(value, self.module_vars, constants)
        is_tainted = self._expr_is_tainted(value)
        for name in _target_names(target):
            if is_module_expr:
                self.module_vars.add(name)
                if _is_elevated_expr(value, constants, self.superuser_names) or _uses_sudo_module_var(
                    value, self.sudo_module_vars
                ):
                    self.sudo_module_vars.add(name)
                else:
                    self.sudo_module_vars.discard(name)
                if is_tainted or _call_has_tainted_input(value, self._expr_is_tainted):
                    self.tainted_module_vars.add(name)
                else:
                    self.tainted_module_vars.discard(name)
            else:
                self.module_vars.discard(name)
                self.sudo_module_vars.discard(name)
                self.tainted_module_vars.discard(name)
            if is_tainted:
                self.tainted_names.add(name)
            else:
                self.tainted_names.discard(name)

    def _record_tainted_container_mutation(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"append", "extend", "add", "update"}:
            return
        if not self._expr_is_tainted(node):
            return
        if isinstance(node.func.value, ast.Name):
            self.tainted_names.add(node.func.value.id)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        text = _safe_unparse(node)
        if any(marker in text for marker in REQUEST_MARKERS):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
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
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(key) for key in node.keys if key is not None) or any(
                value is not None and self._expr_is_tainted(value) for value in node.values
            )
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
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
        return False

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            ModuleLifecycleFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                route=route,
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    paths: list[str] | None = None

    def display_path(self) -> str:
        return ",".join(self.paths or []) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        return RouteContext(is_route=True, auth=auth, paths=paths)
    return None


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append((keyword.arg, keyword.value))
            continue
        value = _resolve_constant(keyword.value, constants)
        if not isinstance(value, ast.Dict):
            continue
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_constant(item_value, constants)
            if isinstance(value, ast.Dict):
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append((resolved_key.value, item_value))
    return keywords


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and _is_odoo_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _route_values(node: ast.AST, constants: dict[str, ast.AST]) -> list[str]:
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values: list[str] = []
        for element in node.elts:
            resolved = _resolve_constant(element, constants)
            if isinstance(resolved, ast.Constant):
                values.append(str(resolved.value))
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
    return constants


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
    return False


def _module_model_in_expr(
    node: ast.AST,
    module_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    text = _safe_unparse(node)
    if MODULE_MODEL in text:
        return True
    for child in ast.walk(node):
        resolved = _resolve_constant(child, constants)
        if isinstance(resolved, ast.Constant) and resolved.value == MODULE_MODEL:
            return True
    if isinstance(node, ast.Starred):
        return _module_model_in_expr(node.value, module_vars, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_module_model_in_expr(element, module_vars, constants) for element in node.elts)
    if isinstance(node, ast.Name):
        return node.id in module_vars
    if isinstance(node, ast.Attribute):
        return _module_model_in_expr(node.value, module_vars, constants)
    if isinstance(node, ast.Call):
        return _module_model_in_expr(node.func, module_vars, constants)
    if isinstance(node, ast.Subscript):
        return _module_model_in_expr(node.value, module_vars, constants)
    return False


def _uses_sudo_module_var(node: ast.AST, sudo_module_vars: set[str]) -> bool:
    if isinstance(node, ast.Starred):
        return _uses_sudo_module_var(node.value, sudo_module_vars)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_uses_sudo_module_var(element, sudo_module_vars) for element in node.elts)
    if isinstance(node, ast.Name):
        return node.id in sudo_module_vars
    if isinstance(node, ast.Attribute):
        return _uses_sudo_module_var(node.value, sudo_module_vars)
    if isinstance(node, ast.Call):
        return _uses_sudo_module_var(node.func, sudo_module_vars)
    if isinstance(node, ast.Subscript):
        return _uses_sudo_module_var(node.value, sudo_module_vars)
    return False


def _call_has_tainted_input(node: ast.AST, is_tainted: Any) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _is_request_derived(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_source_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Starred):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(
            _is_request_derived(element, request_names, http_module_names, odoo_module_names) for element in node.elts
        )
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(
            node.value, request_names, http_module_names, odoo_module_names
        ) or _is_request_derived(node.slice, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names, http_module_names, odoo_module_names)
            or any(_is_request_derived(arg, request_names, http_module_names, odoo_module_names) for arg in node.args)
            or any(
                keyword.value is not None
                and _is_request_derived(keyword.value, request_names, http_module_names, odoo_module_names)
                for keyword in node.keywords
            )
        )
    return False


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
    )


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
        and _is_odoo_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _is_odoo_http_module_expr(
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


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_attr(node.value, attr)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
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


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants, superuser_names) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args)
                    or any(
                        keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
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
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_superuser_arg(resolved, constants, superuser_names)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _is_elevated_expr(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return _call_chain_has_attr(node, "sudo") or _call_chain_has_superuser_with_user(node, constants, superuser_names)


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


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        return {name for element in node.elts for name in _target_names(element)}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List, value: ast.Tuple | ast.List
) -> list[tuple[ast.AST, ast.AST]]:
    starred_index = next(
        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    after_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - after_count, starred_index)
    rest_values = value.elts[starred_index:after_values_start]
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    rest = ast.List(elts=list(rest_values), ctx=ast.Load())
    return [*before, (target.elts[starred_index], rest), *after]


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ModuleLifecycleFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in findings
    ]
