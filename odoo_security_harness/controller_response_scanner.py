"""Scanner for risky Odoo controller response handling."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ControllerResponseFinding:
    """Represents a controller response security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


TAINTED_ARG_NAMES = {
    "callback",
    "callback_url",
    "download",
    "filename",
    "next",
    "path",
    "post",
    "redirect",
    "redirect_url",
    "return_url",
    "url",
    "kwargs",
    "kw",
}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REDIRECT_SINKS = {"redirect", "request.redirect", "werkzeug.utils.redirect", "werkzeug.redirect"}
REDIRECT_TARGET_KEYWORDS = {"url", "location", "redirect_url", "target"}
FILE_RESPONSE_SINKS = {"send_file", "http.send_file", "request.send_file"}
FILE_RESPONSE_TARGET_KEYWORDS = {"filename", "file_path", "path", "src"}
FILE_READ_METHODS = {"read_bytes", "read_text"}
RESPONSE_BODY_KEYWORDS = {"body", "content", "data", "response"}
RESPONSE_FACTORY_SINKS = {
    "request.make_json_response",
    "request.make_response",
    "make_json_response",
    "make_response",
    "Response",
}
HEADER_MUTATION_METHODS = {"add", "setdefault", "update"}
SENSITIVE_COOKIE_MARKERS = ("session", "sid", "token", "auth", "csrf")
SENSITIVE_RESPONSE_MARKERS = (
    "access_token",
    "api_key",
    "apikey",
    "auth_token",
    "csrf_token",
    "password",
    "private_key",
    "refresh_token",
    "reset_password_token",
    "secret",
    "session_id",
    "session_token",
    "signup_token",
    "token",
)
FILE_OFFLOAD_HEADERS = {"x-accel-redirect", "x-sendfile"}


def scan_controller_responses(repo_path: Path) -> list[ControllerResponseFinding]:
    """Scan Python files for risky controller response handling."""
    findings: list[ControllerResponseFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ControllerResponseScanner(path).scan_file())
    return findings


class ControllerResponseScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ControllerResponseFinding] = []
        self.tainted_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.route_names: set[str] = set()
        self.function_aliases: dict[str, str] = {}
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.response_object_names: set[str] = set()

    def scan_file(self) -> list[ControllerResponseFinding]:
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
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
                elif alias.name in {"make_json_response", "make_response", "send_file"}:
                    self.function_aliases[alias.asname or alias.name] = alias.name
        elif node.module == "odoo.addons.web.controllers.main":
            for alias in node.names:
                if alias.name == "send_file":
                    self.function_aliases[alias.asname or alias.name] = "send_file"
        elif node.module == "werkzeug.utils":
            for alias in node.names:
                if alias.name == "redirect":
                    self.function_aliases[alias.asname or alias.name] = "werkzeug.utils.redirect"
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_response_objects = set(self.response_object_names)
        previous_local_constants = dict(self.local_constants)
        self.local_constants = {}
        route = _route_info(node, self._effective_constants(), self.route_names, self.http_module_names)
        route_context = route or RouteContext(is_route=False)
        self.route_stack.append(route_context)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route_context.is_route and arg.arg not in {"self", "cls"}):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.response_object_names = previous_response_objects
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_response_object_target(target, node.value)
        for target in node.targets:
            if _is_response_header_target(target) and self._expr_is_tainted(node.value):
                self._add(
                    "odoo-controller-response-header-injection",
                    "Response header uses request-controlled value",
                    "medium",
                    node.lineno,
                    "Controller writes request-derived data into response headers; validate against CRLF/header injection and unsafe filenames",
                    "headers",
                )
            header_name = _response_header_assignment_name(target, self._effective_constants())
            if header_name:
                self._scan_static_header_value(header_name, node.value, node.lineno, "headers")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_response_object_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_response_object_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = self._canonical_call_name(node.func)
        if self._is_redirect_sink(node.func) and self._redirect_target_is_tainted(node):
            route = self._current_route()
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-controller-open-redirect",
                "Controller redirects to request-controlled URL",
                severity,
                node.lineno,
                "Controller redirects to a request-derived URL; restrict redirects to local paths or an allowlisted host set",
                sink,
            )
        elif self._is_file_response_sink(node.func) and self._file_response_target_is_tainted(node):
            self._add(
                "odoo-controller-tainted-file-download",
                "Controller sends request-controlled file path",
                "high",
                node.lineno,
                "Controller send_file path is request-controlled; validate basename, attachment ownership, traversal, and storage root",
                sink,
            )
        elif self._is_tainted_file_read(node, sink):
            self._scan_tainted_file_read(node, sink)
        elif self._is_response_factory_sink(node.func):
            self._scan_response_factory(node, sink)
        elif _is_headers_mutation(node):
            self._scan_headers_mutation(node, sink)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
            self._scan_set_cookie(node, sink)

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None and not (
            isinstance(node.value, ast.Call) and self._is_response_factory_sink(node.value.func)
        ):
            self._scan_direct_html_return(node.value, "return", node.lineno)
            self._scan_response_body(node.value, "return", node.lineno)
        self.generic_visit(node)

    def _redirect_target_is_tainted(self, node: ast.Call) -> bool:
        if node.args and self._expr_is_tainted(node.args[0]):
            return True
        return any(
            keyword.arg in REDIRECT_TARGET_KEYWORDS
            and keyword.value is not None
            and self._expr_is_tainted(keyword.value)
            for keyword in node.keywords
        )

    def _file_response_target_is_tainted(self, node: ast.Call) -> bool:
        if node.args and self._expr_is_tainted(node.args[0]):
            return True
        return any(
            keyword.arg in FILE_RESPONSE_TARGET_KEYWORDS
            and keyword.value is not None
            and self._expr_is_tainted(keyword.value)
            for keyword in node.keywords
        )

    def _is_tainted_file_read(self, node: ast.Call, sink: str) -> bool:
        if not self._current_route().is_route:
            return False
        if sink == "open":
            if not node.args or not self._expr_is_tainted(node.args[0]):
                return False
            mode = _open_mode(node)
            return not any(flag in mode for flag in ("w", "a", "x", "+"))
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in FILE_READ_METHODS
            and self._expr_is_tainted(node.func.value)
        )

    def _scan_tainted_file_read(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        self._add(
            "odoo-controller-tainted-file-read",
            "Controller reads request-controlled file path",
            "high" if route.auth in {"public", "none"} else "medium",
            node.lineno,
            "Controller reads from a request-controlled filesystem path; validate attachment ownership, basename, traversal, symlinks, and storage root before returning data",
            sink,
        )

    def _scan_response_factory(self, node: ast.Call, sink: str) -> None:
        body = _response_body_arg(node)
        if body is not None:
            self._scan_response_body(body, sink, node.lineno)
            if self._expr_is_tainted(body) and _response_factory_is_html(node, self._effective_constants()):
                route = self._current_route()
                self._add(
                    "odoo-controller-tainted-html-response",
                    "Controller returns request-derived HTML response",
                    "high" if route.auth in {"public", "none"} else "medium",
                    node.lineno,
                    "Controller returns request-derived data as text/html; sanitize or render through trusted QWeb templates before sending HTML",
                    sink,
                )
        for keyword in node.keywords:
            if keyword.arg in {"headers", "header"} and self._expr_is_tainted(keyword.value):
                self._add(
                    "odoo-controller-response-header-injection",
                    "Response headers include request-controlled value",
                    "medium",
                    node.lineno,
                    "Controller response headers include request-derived data; validate against CRLF/header injection and unsafe filenames",
                    sink,
                )
            if keyword.arg in {"headers", "header"}:
                self._scan_static_headers(keyword.value, node.lineno, sink)
        if len(node.args) >= 2 and self._expr_is_tainted(node.args[1]):
            self._add(
                "odoo-controller-response-header-injection",
                "Response headers include request-controlled value",
                "medium",
                node.lineno,
                "Controller response header argument is request-derived; validate against CRLF/header injection and unsafe filenames",
                sink,
            )
        if len(node.args) >= 2:
            self._scan_static_headers(node.args[1], node.lineno, sink)

    def _scan_response_body(self, node: ast.AST, sink: str, line: int) -> None:
        if not _response_contains_sensitive_token(node, self._effective_constants()):
            return
        route = self._current_route()
        severity = "high" if route.auth in {"public", "none"} else "medium"
        self._add(
            "odoo-controller-sensitive-token-response",
            "Controller response returns sensitive token-shaped data",
            severity,
            line,
            "Controller response includes token, password, API key, or secret-shaped data; avoid returning credential material and verify the route is authenticated and authorized",
            sink,
        )

    def _scan_direct_html_return(self, node: ast.AST, sink: str, line: int) -> None:
        route = self._current_route()
        if (
            not route.is_route
            or route.route_type == "json"
            or self._is_response_object(node)
            or not self._expr_is_tainted(node)
        ):
            return
        severity = "high" if route.auth in {"public", "none"} else "medium"
        self._add(
            "odoo-controller-tainted-html-response",
            "Controller returns request-derived HTML response",
            severity,
            line,
            "Controller returns request-derived data from an HTTP route; sanitize or render through trusted QWeb templates before sending HTML",
            sink,
        )

    def _scan_headers_mutation(self, node: ast.Call, sink: str) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "update":
            if any(self._expr_is_tainted(arg) for arg in node.args) or any(
                keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords
            ):
                self._add(
                    "odoo-controller-response-header-injection",
                    "Response headers include request-controlled value",
                    "medium",
                    node.lineno,
                    "Controller response headers include request-derived data; validate against CRLF/header injection and unsafe filenames",
                    sink,
                )
            for arg in node.args:
                self._scan_static_headers(arg, node.lineno, sink)
        elif len(node.args) >= 2 and self._expr_is_tainted(node.args[1]):
            self._add(
                "odoo-controller-response-header-injection",
                "Response header uses request-controlled value",
                "medium",
                node.lineno,
                "Controller writes request-derived data into response headers; validate against CRLF/header injection and unsafe filenames",
                sink,
            )
        elif len(node.args) >= 2:
            header_name = _constant_string(node.args[0], self._effective_constants())
            if header_name:
                self._scan_static_header_value(header_name, node.args[1], node.lineno, sink)

    def _scan_static_headers(self, node: ast.AST, line: int, sink: str) -> None:
        for header_name, value in _literal_header_pairs(node, self._effective_constants()):
            self._scan_static_header_value(header_name, value, line, sink)

    def _scan_static_header_value(self, header_name: str, value: ast.AST, line: int, sink: str) -> None:
        lowered_header = header_name.lower()
        if lowered_header in FILE_OFFLOAD_HEADERS and self._expr_is_tainted(value):
            route = self._current_route()
            self._add(
                "odoo-controller-tainted-file-offload-header",
                "File offload header uses request-controlled path",
                "high" if route.auth in {"public", "none"} else "medium",
                line,
                "Controller sets X-Accel-Redirect/X-Sendfile from request input; validate internal location mapping, traversal, attachment ownership, and storage root",
                sink,
            )
        if header_name.lower() != "access-control-allow-origin":
            return
        if self._expr_is_tainted(value):
            route = self._current_route()
            self._add(
                "odoo-controller-cors-reflected-origin",
                "Controller reflects request origin into CORS header",
                "high" if route.auth in {"public", "none"} else "medium",
                line,
                "Controller reflects a request-derived Origin into Access-Control-Allow-Origin; require an explicit trusted-origin allowlist before enabling cross-origin reads",
                sink,
            )
            return
        if _constant_string(value, self._effective_constants()).strip() != "*":
            return
        route = self._current_route()
        self._add(
            "odoo-controller-cors-wildcard-origin",
            "Controller response allows any CORS origin",
            "high" if route.auth in {"public", "none"} else "medium",
            line,
            "Controller sets Access-Control-Allow-Origin: *; verify cross-origin reads are intended and credentials, tokens, or private data cannot be exposed",
            sink,
        )

    def _scan_set_cookie(self, node: ast.Call, sink: str) -> None:
        cookie_name_node = _cookie_name_node(node)
        if cookie_name_node is not None and self._expr_is_tainted(cookie_name_node):
            self._add(
                "odoo-controller-tainted-cookie-name",
                "Cookie name is request-controlled",
                "medium",
                node.lineno,
                "Controller sets a cookie whose name is request-derived; restrict cookie keys to fixed allowlisted names to avoid arbitrary client-side state changes",
                sink,
            )
        cookie_value = node.args[1] if len(node.args) >= 2 else _keyword_value(node, "value")
        if cookie_value is not None and self._expr_is_tainted(cookie_value):
            self._add(
                "odoo-controller-tainted-cookie-value",
                "Cookie value is request-controlled",
                "low",
                node.lineno,
                "Controller sets a cookie value directly from request input; verify it cannot create session fixation, tracking, or response splitting risk",
                sink,
            )
        cookie_name = (
            _constant_string(cookie_name_node, self._effective_constants()) if cookie_name_node is not None else ""
        )
        if _is_sensitive_cookie_name(cookie_name) and not _has_cookie_security_flags(
            node, self._effective_constants()
        ):
            self._add(
                "odoo-controller-cookie-missing-security-flags",
                "Sensitive cookie misses security flags",
                "medium",
                node.lineno,
                "Controller sets a session/token-like cookie without explicit HttpOnly, Secure, and SameSite flags; verify browser exposure and cross-site behavior",
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.Starred):
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
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(value) for value in node.values)
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
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
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
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                for target_element in target.elts:
                    self._discard_name_target(target_element, self.tainted_names)

    def _mark_response_object_target(self, target: ast.AST, value: ast.AST) -> None:
        if self._is_response_factory_value(value):
            self._mark_name_target(target, self.response_object_names)
        else:
            self._discard_name_target(target, self.response_object_names)

    def _is_response_object(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.response_object_names
        return isinstance(node, ast.Call) and self._is_response_factory_value(node)

    def _is_response_factory_value(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        return (
            self._is_response_factory_sink(node.func)
            or self._is_redirect_sink(node.func)
            or self._is_file_response_sink(node.func)
        )

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

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _is_redirect_sink(self, node: ast.AST) -> bool:
        if self._canonical_call_name(node) in REDIRECT_SINKS:
            return True
        return _is_request_method(node, self.request_names, {"redirect"})

    def _is_file_response_sink(self, node: ast.AST) -> bool:
        if self._canonical_call_name(node) in FILE_RESPONSE_SINKS:
            return True
        return _is_request_method(node, self.request_names, {"send_file"})

    def _is_response_factory_sink(self, node: ast.AST) -> bool:
        if self._canonical_call_name(node) in RESPONSE_FACTORY_SINKS:
            return True
        return _is_request_method(node, self.request_names, {"make_response", "make_json_response"})

    def _canonical_call_name(self, node: ast.AST) -> str:
        sink = _call_name(node)
        return self.function_aliases.get(sink, sink)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            ControllerResponseFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    route_type: str = "http"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names):
            continue
        auth = "user"
        route_type = "http"
        if isinstance(decorator, ast.Call):
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key == "type" and isinstance(value, ast.Constant):
                    route_type = str(value.value)
        return RouteContext(is_route=True, auth=auth, route_type=route_type)
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
        for key, item_value in zip(value.keys, value.values, strict=False):
            resolved_key = _resolve_constant(key, constants) if key is not None else None
            if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
                keywords.append((resolved_key.value, item_value))
    return keywords


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
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_static_literal(key) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and isinstance(node.value, ast.Name)
        and node.value.id in http_module_names
    )


def _is_request_derived(node: ast.AST, request_names: set[str] | None = None) -> bool:
    request_names = request_names or {"request"}
    if _is_request_expr(node, request_names):
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"params", "jsonrequest", "httprequest"} and _is_request_expr(node.value, request_names):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(node.func.value, request_names):
            return True
    text = _safe_unparse(node)
    return any(
        marker in text
        for marker in (
            "request.params",
            "request.httprequest",
            "request.get_http_params",
            "request.get_json_data",
            "request.jsonrequest",
            "kwargs.get",
            "kw.get",
            "post.get",
        )
    )


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _is_request_method(node: ast.AST, request_names: set[str], methods: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr in methods and _is_request_expr(node.value, request_names)


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _is_response_header_target(node: ast.AST) -> bool:
    text = _safe_unparse(node)
    return ".headers" in text or "headers[" in text


def _response_header_assignment_name(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    if not isinstance(node, ast.Subscript):
        return ""
    if not _is_response_header_target(node.value):
        return ""
    return _constant_string(node.slice, constants)


def _is_headers_mutation(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in HEADER_MUTATION_METHODS
        and _is_response_header_target(node.func.value)
    )


def _constant_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _open_mode(node: ast.Call) -> str:
    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        return node.args[1].value
    for keyword in node.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return "r"


def _literal_header_pairs(
    node: ast.AST, constants: dict[str, ast.AST] | None = None
) -> list[tuple[str, ast.AST]]:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Dict):
        pairs: list[tuple[str, ast.AST]] = []
        for key, value in zip(node.keys, node.values, strict=False):
            if value is None:
                continue
            header_name = _constant_string(key, constants)
            if header_name:
                pairs.append((header_name, value))
        return pairs
    if isinstance(node, ast.List | ast.Tuple):
        pairs = []
        for element in node.elts:
            element = _resolve_constant(element, constants)
            if not isinstance(element, ast.Tuple | ast.List) or len(element.elts) < 2:
                continue
            header_name = _constant_string(element.elts[0], constants)
            if header_name:
                pairs.append((header_name, element.elts[1]))
        return pairs
    return []


def _is_sensitive_cookie_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_COOKIE_MARKERS)


def _response_contains_sensitive_token(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for key in child.keys:
                if key is not None and _is_sensitive_response_name(_constant_string(key, constants)):
                    return True
        elif isinstance(child, ast.keyword):
            if child.arg and _is_sensitive_response_name(child.arg):
                return True
        elif isinstance(child, ast.Attribute):
            if _is_sensitive_response_name(child.attr):
                return True
        elif isinstance(child, ast.Subscript):
            if _is_sensitive_response_name(_constant_string(child.slice, constants)):
                return True
    return False


def _is_sensitive_response_name(name: str) -> bool:
    lowered = name.strip().lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in SENSITIVE_RESPONSE_MARKERS)


def _has_cookie_security_flags(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    flags = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
    return (
        _keyword_constant_is(flags, "httponly", True, constants)
        and _keyword_constant_is(flags, "secure", True, constants)
        and _samesite_is_set(flags.get("samesite"), constants)
    )


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _response_body_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in RESPONSE_BODY_KEYWORDS:
            return keyword.value
    return None


def _response_factory_is_html(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword in node.keywords:
        if keyword.arg in {"mimetype", "content_type"} and _is_html_content_type(keyword.value, constants):
            return True
        if keyword.arg in {"headers", "header"} and _headers_include_html_content_type(keyword.value, constants):
            return True
    if len(node.args) >= 2 and _headers_include_html_content_type(node.args[1], constants):
        return True
    return False


def _headers_include_html_content_type(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    for header_name, value in _literal_header_pairs(node, constants):
        if header_name.lower() in {"content-type", "content_type"} and _is_html_content_type(value, constants):
            return True
    return False


def _is_html_content_type(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    return "text/html" in _constant_string(node, constants).lower()


def _cookie_name_node(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    return _keyword_value(node, "key") or _keyword_value(node, "name")


def _keyword_constant_is(
    flags: dict[str, ast.AST], key: str, expected: bool, constants: dict[str, ast.AST] | None = None
) -> bool:
    value = flags.get(key)
    value = _resolve_constant(value, constants or {}) if value is not None else value
    return isinstance(value, ast.Constant) and value.value is expected


def _samesite_is_set(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    node = _resolve_constant(node, constants or {}) if node is not None else node
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    return node.value.lower() in {"lax", "strict", "none"}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ControllerResponseFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in findings
    ]
