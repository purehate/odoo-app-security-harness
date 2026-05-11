"""Scanner for risky Odoo database selection and management routes."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from odoo_security_harness.base_scanner import _should_skip


@dataclass
class DatabaseFinding:
    """Represents a database operation security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


DB_MANAGEMENT_METHODS = {
    "create_database",
    "drop",
    "dump_db",
    "exp_backup",
    "exp_create_database",
    "exp_drop",
    "exp_duplicate_database",
    "exp_restore",
    "restore_db",
}
DB_LIST_METHODS = {"db_list", "list_db", "list_dbs"}
DB_SELECT_METHODS = {"db_filter", "db_monodb", "ensure_db"}
TAINTED_ARG_NAMES = {"db", "database", "db_name", "name", "kwargs", "kw", "post", "params"}
ROUTE_DB_ARG_RE = re.compile(r"(?:^db$|^database$|(?:^|_)db_name$|(?:^|_)database_name$|_db$|_database$)")
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


def scan_database_operations(repo_path: Path) -> list[DatabaseFinding]:
    """Scan Python controllers for database listing, selection, and manager operations."""
    findings: list[DatabaseFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(DatabaseScanner(path).scan_file())
    return findings


class DatabaseScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[DatabaseFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.tainted_names: set[str] = set()
        self.session_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[DatabaseFinding]:
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
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_session_names = set(self.session_names)
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(
            is_route=False,
        )
        self.route_stack.append(route)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_database_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.session_names = previous_session_names

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_session_names = set(self.session_names)
        for target in node.targets:
            self._mark_tainted_target(target, node.value)
            self._mark_session_target(target, node.value, previous_session_names)
            self._scan_database_session_assignment(target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            previous_session_names = set(self.session_names)
            self._mark_tainted_target(node.target, node.value)
            self._mark_session_target(node.target, node.value, previous_session_names)
            self._scan_database_session_assignment(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        previous_session_names = set(self.session_names)
        self._mark_tainted_target(node.target, node.value)
        self._mark_session_target(node.target, node.value, previous_session_names)
        self._scan_database_session_assignment(node.target, node.value, node.lineno)
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
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        route = self._current_route()

        if method in DB_LIST_METHODS or _looks_like_db_list_call(node):
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-database-listing-route",
                "Route lists available databases",
                severity,
                node.lineno,
                "Controller lists database names; verify list_db/dbfilter posture and avoid exposing tenant names to unauthenticated callers",
                route.display_path(),
                sink,
            )

        if method in DB_MANAGEMENT_METHODS or _looks_like_db_management_call(node):
            severity = "critical" if route.auth in {"public", "none"} else "high"
            self._add(
                "odoo-database-management-call",
                "Controller calls database manager operation",
                severity,
                node.lineno,
                "Controller invokes database create/drop/backup/restore behavior; verify this is admin-only, CSRF-protected, audited, and not reachable pre-auth",
                route.display_path(),
                sink,
            )

        if method in DB_SELECT_METHODS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-database-tainted-selection",
                "Request-derived database selection",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Request-derived data reaches database selection/filtering; enforce hostname dbfilter and reject user-controlled database names",
                route.display_path(),
                sink,
            )

        if (method in DB_MANAGEMENT_METHODS or _looks_like_db_management_call(node)) and _call_has_tainted_input(
            node, self._expr_is_tainted
        ):
            self._add(
                "odoo-database-tainted-management-input",
                "Request-derived input reaches database manager operation",
                "critical",
                node.lineno,
                "Request-derived data reaches database create/drop/backup/restore behavior; prevent attacker-chosen database names, passwords, or backup payloads",
                route.display_path(),
                sink,
            )

        self.generic_visit(node)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
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
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(if_expr) for if_expr in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(if_expr) for if_expr in generator.ifs)
                    for generator in node.generators
                )
            )
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._is_request_derived(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target, value):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_session_target(self, target: ast.AST, value: ast.AST, session_names: set[str]) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_session_target(target_element, value_element, session_names)
            return
        if isinstance(target, ast.Starred):
            self._mark_session_target(target.value, value, session_names)
            return

        if _is_session_expr(value, session_names, self.request_names, self.http_module_names, self.odoo_module_names):
            self._mark_name_target(target, self.session_names)
        else:
            self._discard_name_target(target, self.session_names)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)

    def _scan_database_session_assignment(self, target: ast.AST, value: ast.AST, line: int) -> None:
        if not _is_database_session_target(
            target,
            self.session_names,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        ):
            return
        route = self._current_route()
        severity = "critical" if route.auth in {"public", "none"} and self._expr_is_tainted(value) else "high"
        self._add(
            "odoo-database-session-db-assignment",
            "Controller assigns database session directly",
            severity,
            line,
            "Controller assigns request.session.db or request.db directly; verify database selection cannot be attacker-controlled across tenants",
            route.display_path(),
            _safe_unparse(target),
        )
        if self._expr_is_tainted(value):
            self._add(
                "odoo-database-tainted-selection",
                "Request-derived database selection",
                "critical" if route.auth in {"public", "none"} else "high",
                line,
                "Request-derived data controls database selection; enforce dbfilter/host mapping and avoid trusting user-supplied database names",
                route.display_path(),
                _safe_unparse(target),
            )

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            DatabaseFinding(
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
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for keyword in decorator.keywords:
                auth = _apply_route_keyword(keyword, auth, paths, constants)
        return RouteContext(is_route=True, auth=auth, paths=paths)
    return None


def _apply_route_keyword(
    keyword: ast.keyword,
    auth: str,
    paths: list[str],
    constants: dict[str, ast.AST],
) -> str:
    if keyword.arg is None:
        options = _resolve_static_dict(keyword.value, constants)
        if isinstance(options, ast.Dict):
            for key_node, value_node in zip(options.keys, options.values, strict=False):
                if key_node is None:
                    nested = _resolve_static_dict(value_node, constants)
                    if isinstance(nested, ast.Dict):
                        for nested_key, nested_value in zip(nested.keys, nested.values, strict=False):
                            key = _literal_string(nested_key, constants) if nested_key is not None else ""
                            auth = _apply_route_option(key, nested_value, auth, paths, constants)
                    continue
                key = _literal_string(key_node, constants)
                auth = _apply_route_option(key, value_node, auth, paths, constants)
        return auth
    return _apply_route_option(keyword.arg, keyword.value, auth, paths, constants)


def _apply_route_option(
    key: str,
    value_node: ast.AST,
    auth: str,
    paths: list[str],
    constants: dict[str, ast.AST],
) -> str:
    value = _resolve_constant(value_node, constants)
    if key == "auth" and isinstance(value, ast.Constant):
        return str(value.value)
    if key in {"route", "routes"}:
        paths.extend(_route_values(value_node, constants))
    return auth


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
        return _resolve_constant_seen(resolved, constants, {*seen, node.id})
    return node


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
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
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


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


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values = []
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
        return values
    return []


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_route_database_arg(name: str) -> bool:
    return bool(ROUTE_DB_ARG_RE.search(name))


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


def _is_session_expr(
    node: ast.AST,
    session_names: set[str],
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    text = _safe_unparse(node)
    if text == "request.session":
        return True
    if isinstance(node, ast.Attribute) and node.attr == "session" and _is_request_expr(
        node.value,
        request_names,
        http_module_names,
        odoo_module_names,
    ):
        return True
    if isinstance(node, ast.Name):
        return node.id in session_names
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(
            _is_session_expr(element, session_names, request_names, http_module_names, odoo_module_names)
            for element in node.elts
        )
    if isinstance(node, ast.Subscript):
        return _is_session_expr(node.value, session_names, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Attribute):
        return _is_session_expr(node.value, session_names, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return _is_session_expr(node.func, session_names, request_names, http_module_names, odoo_module_names)
    return False


def _is_database_session_target(
    node: ast.AST,
    session_names: set[str] | None = None,
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    session_names = session_names or set()
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    text = _safe_unparse(node)
    if text in {"request.session.db", "request.db"}:
        return True
    if isinstance(node, ast.Attribute) and node.attr == "db" and _is_request_expr(
        node.value,
        request_names,
        http_module_names,
        odoo_module_names,
    ):
        return True
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "db"
        and _is_session_expr(node.value, session_names, request_names, http_module_names, odoo_module_names)
    )


def _looks_like_db_list_call(node: ast.Call) -> bool:
    text = _safe_unparse(node.func)
    return "service.db" in text and any(method in text for method in DB_LIST_METHODS)


def _looks_like_db_management_call(node: ast.Call) -> bool:
    text = _safe_unparse(node.func)
    return "service.db" in text and any(method in text for method in DB_MANAGEMENT_METHODS)


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


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


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List,
    value: ast.Tuple | ast.List,
) -> list[tuple[ast.AST, ast.AST]]:
    starred_index = next(
        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    trailing_target_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - trailing_target_count, starred_index)
    starred_values = value.elts[starred_index:after_values_start]
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    rest_value = ast.List(elts=starred_values, ctx=ast.Load())
    return [*before, (target.elts[starred_index], rest_value), *after]



def findings_to_json(findings: list[DatabaseFinding]) -> list[dict[str, Any]]:
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
