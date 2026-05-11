"""Scanner for risky Odoo controller cache-control behavior."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CacheHeaderFinding:
    """Represents a cache-control response finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


SENSITIVE_MARKERS = (
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
SENSITIVE_COOKIE_MARKERS = ("csrf", "session", "sid", "token")
SENSITIVE_ROUTE_MARKERS = ("download", "export", "invoice", "portal", "reset", "signup", "token")
RESPONSE_SINKS = {
    "request.make_json_response",
    "request.make_response",
    "make_json_response",
    "make_response",
    "Response",
}
RENDER_SINKS = {"request.render", "render"}
FILE_SINKS = {"send_file", "http.send_file", "request.send_file"}
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
TAINTED_ARG_NAMES = {"kwargs", "kw", "post", "token", "access_token", "filename", "id"}


def scan_cache_headers(repo_path: Path) -> list[CacheHeaderFinding]:
    """Scan Python controllers for risky cache-control behavior."""
    findings: list[CacheHeaderFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(CacheHeaderScanner(path).scan_file())
    return findings


class CacheHeaderScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[CacheHeaderFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.route_stack: list[RouteContext] = []
        self.tainted_names: set[str] = set()
        self.response_names: set[str] = set()
        self.no_store_names: set[str] = set()
        self.sensitive_response_names: set[str] = set()
        self.sensitive_cookie_response_names: set[str] = set()
        self.assigned_response_call_ids: set[int] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()

    def scan_file(self) -> list[CacheHeaderFinding]:
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
        previous_responses = set(self.response_names)
        previous_no_store = set(self.no_store_names)
        previous_sensitive_responses = set(self.sensitive_response_names)
        previous_sensitive_cookie_responses = set(self.sensitive_cookie_response_names)
        previous_assigned_response_call_ids = set(self.assigned_response_call_ids)
        previous_local_constants = dict(self.local_constants)
        self.local_constants = {}
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
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and arg.arg not in {"self", "cls"}):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.response_names = previous_responses
        self.no_store_names = previous_no_store
        self.sensitive_response_names = previous_sensitive_responses
        self.sensitive_cookie_response_names = previous_sensitive_cookie_responses
        self.assigned_response_call_ids = previous_assigned_response_call_ids
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_responses = set(self.response_names)
        previous_no_store = set(self.no_store_names)
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_response_target(target, node.value, previous_responses, previous_no_store)
            self._mark_sensitive_response_target(target, node.value)
            self._clear_sensitive_cookie_target(target)

        for target in node.targets:
            if _is_cache_header_target(target, self._effective_constants()):
                self._scan_cache_header_value(node.value, node.lineno, "headers")
                if _is_no_store_value(node.value, self._effective_constants()):
                    response_name = _response_name_from_header_target(target)
                    if response_name:
                        self.no_store_names.add(response_name)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            previous_responses = set(self.response_names)
            previous_no_store = set(self.no_store_names)
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_response_target(node.target, node.value, previous_responses, previous_no_store)
            self._mark_sensitive_response_target(node.target, node.value)
            self._clear_sensitive_cookie_target(node.target)
            if _is_cache_header_target(node.target, self._effective_constants()):
                self._scan_cache_header_value(node.value, node.lineno, "headers")
                if _is_no_store_value(node.value, self._effective_constants()):
                    response_name = _response_name_from_header_target(node.target)
                    if response_name:
                        self.no_store_names.add(response_name)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        previous_responses = set(self.response_names)
        previous_no_store = set(self.no_store_names)
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_response_target(node.target, node.value, previous_responses, previous_no_store)
        self._mark_sensitive_response_target(node.target, node.value)
        self._clear_sensitive_cookie_target(node.target)
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
        sink = _call_name(node.func)

        if (
            self._is_response_sink(node.func)
            and id(node) not in self.assigned_response_call_ids
            and route.is_public
            and self._call_mentions_sensitive_or_tainted_public_data(node, route)
            and not _call_has_no_store(node, self._effective_constants())
        ):
            self._add(
                "odoo-cache-public-sensitive-response",
                "Public sensitive response lacks no-store cache-control",
                "high",
                node.lineno,
                "Public controller response includes token/secret-like data without obvious Cache-Control: no-store/private headers; prevent browser/proxy caching of account or document secrets",
                route.display_path(),
                sink,
            )

        if (
            self._is_render_sink(node.func)
            and route.is_public
            and self._call_mentions_sensitive_or_tainted_public_data(node, route)
        ):
            self._add(
                "odoo-cache-public-sensitive-render",
                "Public render includes token/secret-like data",
                "high",
                node.lineno,
                "Public route renders token/secret-like values; verify the response sets no-store/private cache headers and does not leak through shared caches or referrers",
                route.display_path(),
                sink,
            )

        if (
            self._is_file_sink(node.func)
            and route.is_public
            and _is_sensitive_route(route)
            and not _call_disables_file_cache(node, self._effective_constants())
        ):
            self._add(
                "odoo-cache-public-file-download",
                "Public file download may be cacheable",
                "medium",
                node.lineno,
                "Public sensitive-looking download uses send_file without cache disabling arguments; ensure private documents are not cached by browsers or proxies",
                route.display_path(),
                sink,
            )

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "setdefault"}:
            self._scan_header_mutation(node, sink)

        if route.is_public and _sets_sensitive_cookie(node, self._effective_constants()):
            response_name = _set_cookie_response_name(node.func)
            if response_name:
                self.sensitive_cookie_response_names.add(response_name)

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        route = self._current_route()
        if route.is_public and isinstance(node.value, ast.Name):
            if (
                node.value.id in self.response_names
                and node.value.id not in self.no_store_names
                and (_is_sensitive_route(route) or node.value.id in self.sensitive_response_names)
            ):
                self._add(
                    "odoo-cache-public-sensitive-response",
                    "Public sensitive response lacks no-store cache-control",
                    "medium",
                    node.lineno,
                    "Public sensitive-looking route returns a response without obvious no-store/private cache headers; verify tokenized pages and downloads cannot be cached",
                    route.display_path(),
                    "return",
                )
            if node.value.id in self.sensitive_cookie_response_names and node.value.id not in self.no_store_names:
                self._add(
                    "odoo-cache-public-sensitive-cookie-response",
                    "Public response sets sensitive cookie without no-store cache-control",
                    "high",
                    node.lineno,
                    "Public controller response sets a session/token/CSRF-shaped cookie without obvious Cache-Control: no-store/private headers; prevent auth callback and token responses from being cached",
                    route.display_path(),
                    "return",
                )
        self.generic_visit(node)

    def _scan_header_mutation(self, node: ast.Call, sink: str) -> None:
        if not _is_headers_call(node.func):
            return
        for arg in node.args:
            if isinstance(arg, ast.Dict):
                for key, value in zip(arg.keys, arg.values):
                    if _is_cache_header_key(key, self._effective_constants()):
                        self._scan_cache_header_value(value, node.lineno, sink)
                        if _is_no_store_value(value, self._effective_constants()):
                            self._mark_no_store_header_response(node.func)
        for keyword in node.keywords:
            if keyword.arg and keyword.arg.lower().replace("_", "-") == "cache-control":
                self._scan_cache_header_value(keyword.value, node.lineno, sink)
                if _is_no_store_value(keyword.value, self._effective_constants()):
                    self._mark_no_store_header_response(node.func)

    def _scan_cache_header_value(self, value: ast.AST, line: int, sink: str) -> None:
        route = self._current_route()
        if not route.is_public:
            return
        if _is_cacheable_value(value, self._effective_constants()) and _is_sensitive_route(route):
            self._add(
                "odoo-cache-public-cacheable-sensitive-route",
                "Public sensitive route sets cacheable headers",
                "high",
                line,
                "Public sensitive-looking route sets cacheable Cache-Control headers; tokenized pages, invoices, exports, and downloads should use no-store/private policies",
                route.display_path(),
                sink,
            )

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
                self._is_request_derived(node)
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

    def _call_mentions_sensitive_or_tainted_public_data(self, node: ast.Call, route: RouteContext) -> bool:
        if _call_mentions_sensitive(node):
            return True
        return _is_sensitive_route(route) and (
            any(self._expr_is_tainted(arg) for arg in node.args)
            or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
        )

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._is_request_derived(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)

    def _mark_response_target(
        self,
        target: ast.AST,
        value: ast.AST,
        response_names: set[str],
        no_store_names: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_response_target(target_element, value_element, response_names, no_store_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_response_target(target.value, value, response_names, no_store_names)
            return

        if self._is_response_expr(value, response_names):
            self._mark_name_target(target, self.response_names)
            if isinstance(value, ast.Call):
                self.assigned_response_call_ids.add(id(value))
            if _is_no_store_response_expr(value, no_store_names, self._effective_constants()):
                self._mark_name_target(target, self.no_store_names)
            else:
                self._discard_name_target(target, self.no_store_names)
        else:
            self._discard_name_target(target, self.response_names)
            self._discard_name_target(target, self.no_store_names)

    def _mark_sensitive_response_target(self, target: ast.AST, value: ast.AST) -> None:
        route = self._current_route()
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_sensitive_response_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_sensitive_response_target(target.value, value)
            return
        if not isinstance(target, ast.Name):
            return
        if (
            route.is_public
            and isinstance(value, ast.Call)
            and self._is_response_sink(value.func)
            and self._call_mentions_sensitive_or_tainted_public_data(value, route)
        ):
            self.sensitive_response_names.add(target.id)
        else:
            self.sensitive_response_names.discard(target.id)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_local_constant_target(target_element, value_element)
            else:
                for element in target.elts:
                    self._mark_local_constant_target(element, value)

    def _effective_constants(self) -> dict[str, ast.AST]:
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)

    def _clear_sensitive_cookie_target(self, target: ast.AST) -> None:
        self._discard_name_target(target, self.sensitive_cookie_response_names)

    def _mark_no_store_header_response(self, func: ast.AST) -> None:
        response_name = _response_name_from_headers_call(func)
        if response_name:
            self.no_store_names.add(response_name)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _is_response_sink(self, node: ast.AST) -> bool:
        if _call_name(node) in RESPONSE_SINKS:
            return True
        return _is_request_method(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
            {"make_response", "make_json_response"},
        )

    def _is_render_sink(self, node: ast.AST) -> bool:
        if _call_name(node) in RENDER_SINKS:
            return True
        return _is_request_method(node, self.request_names, self.http_module_names, self.odoo_module_names, {"render"})

    def _is_file_sink(self, node: ast.AST) -> bool:
        if _call_name(node) in FILE_SINKS:
            return True
        return _is_request_method(node, self.request_names, self.http_module_names, self.odoo_module_names, {"send_file"})

    def _is_response_expr(self, node: ast.AST, response_names: set[str]) -> bool:
        if isinstance(node, ast.Name) and node.id in response_names:
            return True
        if isinstance(node, ast.Subscript) and _call_root_name(node) in response_names:
            return True
        return isinstance(node, ast.Call) and self._is_response_sink(node.func)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            CacheHeaderFinding(
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
    function_name: str = ""

    @property
    def is_public(self) -> bool:
        return self.is_route and self.auth in {"public", "none"}

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
                if keyword.arg is None:
                    auth, paths = _apply_route_options(keyword.value, constants, auth, paths)
                    continue
                auth, paths = _apply_route_keyword(keyword.arg, keyword.value, constants, auth, paths)
        return RouteContext(is_route=True, auth=auth, paths=paths, function_name=node.name)
    return None


def _apply_route_options(
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    paths: list[str],
) -> tuple[str, list[str]]:
    value = _resolve_constant(node, constants)
    if not isinstance(value, ast.Dict):
        return auth, paths
    for key, option_value in zip(value.keys, value.values, strict=False):
        key = _resolve_constant(key, constants) if key is not None else None
        if key is None:
            auth, paths = _apply_route_options(option_value, constants, auth, paths)
            continue
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            auth, paths = _apply_route_keyword(key.value, option_value, constants, auth, paths)
    return auth, paths


def _apply_route_keyword(
    keyword: str,
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    paths: list[str],
) -> tuple[str, list[str]]:
    value = _resolve_constant(node, constants)
    if keyword == "auth" and isinstance(value, ast.Constant):
        auth = str(value.value)
    elif keyword in {"route", "routes"}:
        paths.extend(_route_values(node, constants))
    return auth, paths


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
            for key, value in zip(node.keys, node.values, strict=False)
            if value is not None
        )
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
        routes = []
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                routes.append(value.value)
        return routes
    return []


def _is_sensitive_route(route: RouteContext) -> bool:
    text = " ".join([route.function_name, *(route.paths or [])]).lower()
    return any(marker in text for marker in SENSITIVE_ROUTE_MARKERS)


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
            node.value, request_names, http_module_names, odoo_module_names
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            node.func.value, request_names, http_module_names, odoo_module_names
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


def _is_request_method(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
    methods: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr in methods
        and _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
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


def _call_mentions_sensitive(node: ast.Call) -> bool:
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def _call_has_no_store(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if any(_expr_has_no_store(arg, constants) for arg in node.args):
        return True
    if any(keyword.value is not None and _expr_has_no_store(keyword.value, constants) for keyword in node.keywords):
        return True
    text = _safe_unparse(node).lower()
    return "cache-control" in text and ("no-store" in text or "private" in text)


def _is_no_store_response_expr(
    node: ast.AST,
    no_store_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in no_store_names
    if isinstance(node, ast.Subscript):
        return _call_root_name(node) in no_store_names
    return isinstance(node, ast.Call) and _call_has_no_store(node, constants)


def _call_disables_file_cache(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    for keyword in node.keywords:
        value = _resolve_constant(keyword.value, constants or {})
        if keyword.arg in {"cache_timeout", "max_age"} and isinstance(value, ast.Constant):
            return value.value == 0 or value.value is False
        if keyword.arg == "conditional" and isinstance(value, ast.Constant):
            return value.value is False
    return _call_has_no_store(node, constants)


def _sets_sensitive_cookie(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    if _call_name(node.func).split(".")[-1] != "set_cookie":
        return False
    cookie_name = _set_cookie_name(node, constants)
    if cookie_name and _is_sensitive_cookie_name(cookie_name):
        return True
    return any(
        _expr_mentions_sensitive_cookie(value) for value in [*node.args, *(keyword.value for keyword in node.keywords)]
    )


def _set_cookie_response_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and node.attr == "set_cookie" and isinstance(node.value, ast.Name):
        return node.value.id
    return ""


def _set_cookie_name(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    if node.args:
        value = _resolve_constant(node.args[0], constants or {})
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    for keyword in node.keywords:
        value = _resolve_constant(keyword.value, constants or {})
        if (
            keyword.arg in {"key", "name"}
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            return value.value
    return ""


def _is_sensitive_cookie_name(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(marker in lowered for marker in SENSITIVE_COOKIE_MARKERS)


def _expr_mentions_sensitive_cookie(node: ast.AST | None) -> bool:
    if node is None:
        return False
    return any(marker in _safe_unparse(node).lower() for marker in SENSITIVE_COOKIE_MARKERS)


def _is_cache_header_target(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    return _is_headers_expr(node.value) and _is_cache_header_key(node.slice, constants)


def _response_name_from_header_target(node: ast.AST) -> str:
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
    ):
        return node.value.value.id
    return ""


def _response_name_from_headers_call(node: ast.AST) -> str:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "headers"
        and isinstance(node.value.value, ast.Name)
    ):
        return node.value.value.id
    return ""


def _is_headers_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and _is_headers_expr(node.value)


def _is_headers_expr(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "headers"


def _is_cache_header_key(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    if node is None:
        return False
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant):
        return str(value.value).lower() == "cache-control"
    return False


def _is_no_store_value(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    return _expr_has_no_store(node, constants or {})


def _expr_has_no_store(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    if isinstance(value, ast.Constant):
        return "no-store" in str(value.value).lower() or "private" in str(value.value).lower()
    if isinstance(value, ast.Dict):
        return any(
            _is_cache_header_key(key, constants) and val is not None and _expr_has_no_store(val, constants)
            for key, val in zip(value.keys, value.values, strict=False)
        )
    if isinstance(value, ast.List | ast.Tuple | ast.Set):
        return any(_expr_has_no_store(element, constants) for element in value.elts)
    return False


def _is_cacheable_value(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    if not isinstance(value, ast.Constant):
        return False
    text = str(value.value).lower()
    return "public" in text or "max-age" in text or "s-maxage" in text


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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})
