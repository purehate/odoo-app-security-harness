"""Scanner for risky Odoo JSON route patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class JsonRouteFinding:
    """Represents a JSON route finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


TAINTED_ARG_NAMES = {"data", "domain", "kwargs", "kw", "payload", "post", "values"}
MUTATION_METHODS = {"create", "write", "unlink"}
READ_METHODS = {"browse", "read", "read_group", "search", "search_count", "search_read"}
DOMAIN_READ_KEYWORDS = {"args", "domain"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")


def scan_json_routes(repo_path: Path) -> list[JsonRouteFinding]:
    """Scan Python controllers for risky JSON route patterns."""
    findings: list[JsonRouteFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(JsonRouteScanner(path).scan_file())
    return findings


class JsonRouteScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[JsonRouteFinding] = []
        self.request_names: set[str] = {"request"}
        self.tainted_names: set[str] = set()
        self.sudo_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.route_decorator_names: set[str] = {"route"}

    def scan_file(self) -> list[JsonRouteFinding]:
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

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_sudo = set(self.sudo_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(node, self._effective_constants(), self.route_decorator_names) or RouteContext(
            is_route=False
        )
        self.route_stack.append(route)

        if route.is_json and route.auth in {"public", "none"}:
            self._add(
                "odoo-json-route-public-auth",
                "Public JSON route exposed",
                "high" if route.auth == "public" else "critical",
                node.lineno,
                f"JSON route {route.display_path()} uses auth='{route.auth}'; verify authentication, rate limiting, and CSRF/session assumptions",
                route,
                "route",
            )
        if route.is_json and route.csrf is False:
            self._add(
                "odoo-json-route-csrf-disabled",
                "JSON route explicitly disables CSRF",
                "medium",
                node.lineno,
                f"JSON route {route.display_path()} sets csrf=False; verify it cannot be called cross-site with ambient session credentials",
                route,
                "route",
            )

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.sudo_names = previous_sudo
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
        self._track_sudo_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._track_sudo_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._track_sudo_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        route = self._current_route()
        if not route.is_json:
            self.generic_visit(node)
            return

        sink = _call_name(node.func)
        method = sink.split(".")[-1]
        if method in MUTATION_METHODS:
            self._scan_mutation(node, route, sink)
        elif method in READ_METHODS:
            self._scan_read(node, route, sink)
        self.generic_visit(node)

    def _scan_mutation(self, node: ast.Call, route: RouteContext, sink: str) -> None:
        if _is_sudo_expr(node.func, self.sudo_names, self._effective_constants()):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-json-route-sudo-mutation",
                "JSON route mutates records through an elevated environment",
                severity,
                node.lineno,
                "JSON route performs create/write/unlink through sudo()/with_user(SUPERUSER_ID); verify caller authorization, ownership checks, and company isolation",
                route,
                sink,
            )
        if _call_chain_has_tainted_record_selector(node.func, self._expr_is_tainted):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-json-route-tainted-record-mutation",
                "JSON request controls record selection for mutation",
                severity,
                node.lineno,
                "JSON route selects records from request-controlled IDs/domains before create/write/unlink; verify ownership, access rules, and company isolation before mutating records",
                route,
                sink,
            )
        if _call_has_tainted_input(node, self._expr_is_tainted):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-json-route-mass-assignment",
                "JSON request data flows into ORM mutation",
                severity,
                node.lineno,
                "JSON route passes request-derived data into create/write/unlink; whitelist fields and reject privilege, workflow, ownership, and company fields",
                route,
                sink,
            )

    def _scan_read(self, node: ast.Call, route: RouteContext, sink: str) -> None:
        method = sink.split(".")[-1]
        if _is_sudo_expr(node.func, self.sudo_names, self._effective_constants()) and route.auth in {"public", "none"}:
            self._add(
                "odoo-json-route-public-sudo-read",
                "Public JSON route reads through an elevated environment",
                "critical",
                node.lineno,
                "Public JSON route reads/searches through sudo()/with_user(SUPERUSER_ID); verify it cannot expose records outside the caller's ownership or company",
                route,
                sink,
            )
        if _call_chain_has_tainted_record_selector(node.func, self._expr_is_tainted):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-json-route-tainted-record-read",
                "JSON request controls record selection for read",
                severity,
                node.lineno,
                "JSON route reads records selected by request-controlled IDs/domains; verify ownership, record rules, and company isolation before returning data",
                route,
                sink,
            )
        domain_arg = _domain_read_arg(node)
        if (
            domain_arg is not None
            and self._expr_is_tainted(domain_arg)
            and method in {"search", "search_count", "search_read", "read_group"}
        ):
            self._add(
                "odoo-json-route-tainted-domain",
                "JSON request controls ORM search domain",
                "high",
                node.lineno,
                "JSON request controls search domain; validate allowed fields/operators and prevent cross-record or cross-company discovery",
                route,
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_json_request(node):
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
                self._is_json_request(node)
                or self._expr_is_tainted(node.func)
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
            return any(self._expr_is_tainted(value) for value in node.values)
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
        return False

    def _track_sudo_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        for target in targets:
            self._track_sudo_alias(target, value)

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_sudo_alias(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for target_element in target.elts:
                self._track_sudo_alias(target_element, value)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_sudo_expr(value, self.sudo_names, self._effective_constants()):
            self.sudo_names.add(target.id)
        else:
            self.sudo_names.discard(target.id)

    def _mark_tainted_target(self, target: ast.expr, value: ast.AST) -> None:
        is_tainted = self._is_json_request(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_tainted_target(target_element, value_element)
            return
        if is_tainted:
            self._mark_name_target(target, self.tainted_names)
        else:
            self._discard_name_target(target, self.tainted_names)

    def _mark_name_target(self, target: ast.expr, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
            return
        if isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)

    def _discard_name_target(self, target: ast.expr, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
            return
        if isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)

    def _mark_local_constant_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            self._discard_local_constant_target(target)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_static_literal(value):
            self.local_constants[target.id] = value
        else:
            self.local_constants.pop(target.id, None)

    def _discard_local_constant_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants and not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _is_json_request(self, node: ast.AST) -> bool:
        return _is_json_request(node, self.request_names)

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        route: RouteContext,
        sink: str,
    ) -> None:
        self.findings.append(
            JsonRouteFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                route=route.display_path(),
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    is_json: bool = False
    auth: str = "user"
    csrf: bool | None = None
    paths: tuple[str, ...] = ()

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_decorator_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or {"route"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names):
            continue
        auth = "user"
        csrf: bool | None = None
        route_type = "http"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for keyword in decorator.keywords:
                if keyword.arg is None:
                    auth, csrf, route_type, paths = _apply_route_options(
                        keyword.value,
                        constants,
                        auth,
                        csrf,
                        route_type,
                        paths,
                    )
                    continue
                auth, csrf, route_type, paths = _apply_route_keyword(
                    keyword.arg,
                    keyword.value,
                    constants,
                    auth,
                    csrf,
                    route_type,
                    paths,
                )
        return RouteContext(
            is_route=True,
            is_json=route_type in {"json", "jsonrpc"},
            auth=auth,
            csrf=csrf,
            paths=tuple(paths),
        )
    return None


def _apply_route_options(
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    csrf: bool | None,
    route_type: str,
    paths: list[str],
) -> tuple[str, bool | None, str, list[str]]:
    value = _resolve_constant(node, constants)
    if not isinstance(value, ast.Dict):
        return auth, csrf, route_type, paths
    for key, option_value in zip(value.keys, value.values, strict=False):
        key = _resolve_constant(key, constants) if key is not None else None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            auth, csrf, route_type, paths = _apply_route_keyword(
                key.value,
                option_value,
                constants,
                auth,
                csrf,
                route_type,
                paths,
            )
    return auth, csrf, route_type, paths


def _apply_route_keyword(
    keyword: str,
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    csrf: bool | None,
    route_type: str,
    paths: list[str],
) -> tuple[str, bool | None, str, list[str]]:
    value = _resolve_constant(node, constants)
    if keyword == "auth" and isinstance(value, ast.Constant):
        auth = str(value.value)
    elif keyword == "csrf" and isinstance(value, ast.Constant):
        csrf = bool(value.value)
    elif keyword == "type" and isinstance(value, ast.Constant):
        route_type = str(value.value)
    elif keyword in {"route", "routes"}:
        paths.extend(_route_values(node, constants))
    return auth, csrf, route_type, paths


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


def _is_http_route(node: ast.AST, route_decorator_names: set[str] | None = None) -> bool:
    route_decorator_names = route_decorator_names or {"route"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_decorator_names)
    if isinstance(node, ast.Name):
        return node.id in route_decorator_names
    return isinstance(node, ast.Attribute) and node.attr == "route"


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple):
        routes = []
        for item in node.elts:
            value = _resolve_constant(item, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                routes.append(value.value)
        return routes
    return []


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
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(isinstance(element, ast.Constant | ast.Name) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or isinstance(key, ast.Constant | ast.Name))
            and isinstance(value, ast.Constant | ast.Name | ast.List | ast.Tuple)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _is_json_request(node: ast.AST, request_names: set[str]) -> bool:
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "jsonrequest"
            and _is_request_expr(child.value, request_names)
        ):
            return True
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        if child.func.attr == "get_json_data" and _is_request_expr(child.func.value, request_names):
            return True
        if (
            child.func.attr == "get_json"
            and isinstance(child.func.value, ast.Attribute)
            and child.func.value.attr == "httprequest"
            and _is_request_expr(child.func.value.value, request_names)
        ):
            return True
    return False


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _domain_read_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in DOMAIN_READ_KEYWORDS:
            return keyword.value
    return None


def _call_chain_has_tainted_record_selector(node: ast.AST, is_tainted: Any) -> bool:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            method = _call_name(current.func).split(".")[-1]
            if method in {"browse", "search", "search_count", "search_read", "read_group"} and _call_has_tainted_input(
                current, is_tainted
            ):
                return True
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


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


def _is_sudo_expr(
    node: ast.AST, sudo_names: set[str], constants: dict[str, ast.AST] | None = None
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_names, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_sudo_expr(element, sudo_names, constants) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_names
    )


def _call_chain_has_superuser_with_user(
    node: ast.AST, constants: dict[str, ast.AST] | None = None
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute) and current.func.attr == "with_user":
                return any(_is_superuser_arg(arg, constants) for arg in current.args) or any(
                    keyword.value is not None and _is_superuser_arg(keyword.value, constants)
                    for keyword in current.keywords
                )
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


def _is_superuser_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


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


def _call_root_name(node: ast.AST) -> str:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Attribute):
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return ""


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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[JsonRouteFinding]) -> list[dict[str, Any]]:
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
