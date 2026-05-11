"""Scanner for risky Odoo route decorator security posture."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class RouteSecurityFinding:
    """Represents a risky route decorator finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    attribute: str = ""


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MUTATION_ROUTE_MARKERS = (
    "add",
    "apply",
    "approve",
    "cancel",
    "confirm",
    "create",
    "delete",
    "import",
    "pay",
    "post",
    "remove",
    "reset",
    "set",
    "submit",
    "toggle",
    "unlink",
    "update",
    "upload",
    "write",
)


def scan_route_security(repo_path: Path) -> list[RouteSecurityFinding]:
    """Scan Python controllers for risky route decorator options."""
    findings: list[RouteSecurityFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(RouteSecurityScanner(path).scan_file())
    return findings


class RouteSecurityScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[RouteSecurityFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()

    def scan_file(self) -> list[RouteSecurityFinding]:
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
                if alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        for route in _route_infos(
            node,
            self._effective_constants(),
            self.route_names,
            self.http_module_names,
            self.odoo_module_names,
        ):
            self._scan_route(node, route)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def _scan_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef, route: RouteInfo) -> None:
        path = route.display_path()
        if not route.paths and _relaxes_inherited_route_security(route):
            self._add(
                "odoo-route-inherited-security-relaxed",
                "Inherited route decorator relaxes security options",
                "high" if route.auth in {"public", "none"} or route.csrf is False else "medium",
                node.lineno,
                "Route override omits an explicit path while changing auth/csrf/cors; verify the inherited route "
                "is intended to be republished with weaker security options",
                path,
                "inheritance",
            )

        if route.auth == "none":
            self._add(
                "odoo-route-auth-none",
                "Route bypasses database user authentication",
                "critical",
                node.lineno,
                f"Route {path} uses auth='none'; verify it is needed before database selection and performs no "
                "data access or mutation",
                path,
                "auth",
            )

        if route.cors and route.cors.strip() == "*":
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-route-cors-wildcard",
                "Route allows wildcard CORS",
                severity,
                node.lineno,
                f"Route {path} sets cors='*'; verify cross-origin callers cannot use ambient sessions or access "
                "sensitive data",
                path,
                "cors",
            )

        if route.auth == "bearer" and route.save_session is True:
            self._add(
                "odoo-route-bearer-save-session",
                "Bearer route explicitly saves browser session",
                "medium",
                node.lineno,
                f"Bearer route {path} sets save_session=True; verify API-token requests cannot create or persist "
                "ambient browser sessions unexpectedly",
                path,
                "save_session",
            )

        methods = route.methods or set()
        if route.auth in {"public", "none"} and route.csrf is False and not route.methods:
            self._add(
                "odoo-route-csrf-disabled-all-methods",
                "Public route disables CSRF without method restriction",
                "high",
                node.lineno,
                f"Public route {path} disables CSRF and does not set methods=; constrain verbs and require a "
                "non-browser authentication token for state-changing callbacks",
                path,
                "csrf/methods",
            )

        if route.csrf is False and (methods & UNSAFE_METHODS or _looks_mutating_route(path, node.name)):
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-route-unsafe-csrf-disabled",
                "Mutating route disables CSRF",
                severity,
                node.lineno,
                f"Route {path} disables CSRF on a mutating-looking endpoint; verify callers use a stronger "
                "non-browser token",
                path,
                "csrf",
            )

        if route.auth in {"public", "none"} and _is_get_only_route(methods) and _looks_mutating_route(path, node.name):
            self._add(
                "odoo-route-public-get-mutation",
                "Public route exposes mutating action over GET",
                "high",
                node.lineno,
                f"Public route {path} exposes a mutating-looking action over GET; keep GET idempotent and move "
                "state changes to POST with CSRF or a non-browser token",
                path,
                "methods",
            )

        if route.auth in {"public", "none"} and not route.methods:
            self._add(
                "odoo-route-public-all-methods",
                "Public route does not restrict HTTP methods",
                "medium",
                node.lineno,
                f"Public route {path} does not set methods=; constrain allowed verbs to reduce unexpected "
                "GET/POST exposure",
                path,
                "methods",
            )

        if route.auth in {"public", "none"} and route.website is True and route.sitemap is not False:
            self._add(
                "odoo-route-public-sitemap-indexed",
                "Public website route may be sitemap-indexed",
                "low",
                node.lineno,
                f"Public website route {path} can be sitemap-indexed; verify route content is intended for discovery",
                path,
                "sitemap",
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        route: str,
        attribute: str,
    ) -> None:
        self.findings.append(
            RouteSecurityFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                route=route,
                attribute=attribute,
            )
        )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


@dataclass
class RouteInfo:
    """Route decorator options."""

    paths: tuple[str, ...]
    auth: str = "user"
    csrf: bool | None = None
    cors: str = ""
    methods: set[str] | None = None
    website: bool | None = None
    sitemap: bool | None = None
    save_session: bool | None = None

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_infos(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> list[RouteInfo]:
    routes: list[RouteInfo] = []
    constants = constants or {}
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        paths: list[str] = []
        auth = "user"
        csrf: bool | None = None
        cors = ""
        methods: set[str] | None = None
        website: bool | None = None
        sitemap: bool | None = None
        save_session: bool | None = None
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key == "csrf" and isinstance(value, ast.Constant):
                    csrf = bool(value.value)
                elif key == "cors" and isinstance(value, ast.Constant):
                    cors = str(value.value)
                elif key == "methods":
                    methods = _string_set(keyword_value, constants)
                elif key == "website" and isinstance(value, ast.Constant):
                    website = bool(value.value)
                elif key == "sitemap" and isinstance(value, ast.Constant):
                    sitemap = bool(value.value)
                elif key == "save_session" and isinstance(value, ast.Constant):
                    save_session = bool(value.value)
                elif key in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        routes.append(
            RouteInfo(
                paths=tuple(paths),
                auth=auth,
                csrf=csrf,
                cors=cors,
                methods=methods,
                website=website,
                sitemap=sitemap,
                save_session=save_session,
            )
        )
    return routes


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append((keyword.arg, keyword.value))
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is None:
            continue
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(item_value, constants)
            if value is not None:
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
        ):
            if _is_static_literal(statement.value):
                constants[statement.target.id] = statement.value
    return constants


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        routes = []
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                routes.append(value.value)
        return routes
    return []


def _string_set(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> set[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values = set()
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.add(value.value.upper())
        return values
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value.upper()}
    return set()


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


def _looks_mutating_route(path: str, function_name: str) -> bool:
    haystack = f"{path} {function_name}".lower()
    return any(marker in haystack for marker in MUTATION_ROUTE_MARKERS)


def _is_get_only_route(methods: set[str]) -> bool:
    return bool(methods) and "GET" in methods and methods <= {"GET", "HEAD"}


def _relaxes_inherited_route_security(route: RouteInfo) -> bool:
    return route.auth in {"public", "none"} or route.csrf is False or route.cors.strip() == "*"


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[RouteSecurityFinding]) -> list[dict[str, Any]]:
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
            "attribute": f.attribute,
        }
        for f in findings
    ]
