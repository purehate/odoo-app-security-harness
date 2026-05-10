"""Scanner for risky Odoo binary download and attachment response handling."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class BinaryDownloadFinding:
    """Represents a binary download security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


TAINTED_ARG_NAMES = {"attachment_id", "download", "filename", "id", "kwargs", "kw", "model", "path", "post"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
WEB_CONTENT_MARKERS = {"/web/content", "/web/image"}
ATTACHMENT_BINARY_ATTRS = {"datas", "raw", "db_datas"}
RESPONSE_FACTORY_SINKS = {
    "request.make_json_response",
    "request.make_response",
    "make_json_response",
    "make_response",
    "Response",
}


def scan_binary_downloads(repo_path: Path) -> list[BinaryDownloadFinding]:
    """Scan Python files for risky Odoo binary download handling."""
    findings: list[BinaryDownloadFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(BinaryDownloadScanner(path).scan_file())
    return findings


class BinaryDownloadScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[BinaryDownloadFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.request_names: set[str] = {"request"}
        self.route_names: set[str] = {"route"}
        self.tainted_names: set[str] = set()
        self.attachment_names: set[str] = set()
        self.binary_names: set[str] = set()
        self.sudo_names: set[str] = set()
        self.model_names: dict[str, str] = {}
        self.route_stack: list[RouteContext] = []
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[BinaryDownloadFinding]:
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
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_attachments = set(self.attachment_names)
        previous_binary = set(self.binary_names)
        previous_sudo = set(self.sudo_names)
        previous_models = dict(self.model_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(node, self._effective_constants(), self.route_names) or RouteContext(is_route=False)
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
        self.tainted_names = previous_tainted
        self.attachment_names = previous_attachments
        self.binary_names = previous_binary
        self.sudo_names = previous_sudo
        self.model_names = previous_models
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_attachment_names = set(self.attachment_names)
        previous_sudo_names = set(self.sudo_names)
        previous_model_names = dict(self.model_names)
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
        if _is_attachment_lookup(node.value, self.model_names, self._effective_constants()):
            for target in node.targets:
                self._mark_name_target(target, self.attachment_names)
        for target in node.targets:
            self._mark_binary_target(target, node.value)
        self._track_aliases(
            node.targets, node.value, previous_attachment_names, previous_sudo_names, previous_model_names
        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            previous_attachment_names = set(self.attachment_names)
            previous_sudo_names = set(self.sudo_names)
            previous_model_names = dict(self.model_names)
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            if _is_attachment_lookup(node.value, self.model_names, self._effective_constants()):
                self._mark_name_target(node.target, self.attachment_names)
            self._mark_binary_target(node.target, node.value)
            self._track_aliases(
                [node.target],
                node.value,
                previous_attachment_names,
                previous_sudo_names,
                previous_model_names,
            )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        if self._expr_is_binary(node.iter):
            self._mark_name_target(node.target, self.binary_names)
        else:
            self._discard_name_target(node.target, self.binary_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        previous_attachment_names = set(self.attachment_names)
        previous_sudo_names = set(self.sudo_names)
        previous_model_names = dict(self.model_names)
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        if _is_attachment_lookup(node.value, self.model_names, self._effective_constants()):
            self._mark_name_target(node.target, self.attachment_names)
        self._mark_binary_target(node.target, node.value)
        self._track_aliases(
            [node.target],
            node.value,
            previous_attachment_names,
            previous_sudo_names,
            previous_model_names,
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        if _is_binary_content_call(node):
            self._scan_binary_content(node, sink)
        elif _is_redirect_call(node.func, self.request_names):
            self._scan_web_content_redirect(node, sink)
        elif sink in {"content_disposition", "http.content_disposition"}:
            self._scan_content_disposition(node, sink)
        elif _is_response_factory_call(node.func, self.request_names):
            self._scan_binary_response(node, sink)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None and self._expr_is_binary(node.value):
            route = self._current_route()
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-binary-attachment-data-response",
                "Controller returns attachment/binary data directly",
                severity,
                node.lineno,
                "Controller returns attachment or binary field data directly; verify record ownership, access_token handling, and response headers",
                "return",
            )
        self.generic_visit(node)

    def _scan_binary_content(self, node: ast.Call, sink: str) -> None:
        if _is_sudo_expr(node.func, self.sudo_names, self._effective_constants()):
            self._add(
                "odoo-binary-ir-http-binary-content-sudo",
                "ir.http binary_content is called with an elevated environment",
                "high",
                node.lineno,
                "ir.http.binary_content is reached through sudo()/with_user(SUPERUSER_ID); verify model/id/field inputs cannot bypass record rules or attachment ownership",
                sink,
            )
        if _call_has_tainted_input(node, self._expr_is_tainted):
            route = self._current_route()
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-binary-tainted-binary-content-args",
                "binary_content receives request-controlled arguments",
                severity,
                node.lineno,
                "ir.http.binary_content receives request-derived model/id/field arguments; constrain model, field, record ownership, and token semantics",
                sink,
            )

    def _scan_web_content_redirect(self, node: ast.Call, sink: str) -> None:
        location = _redirect_location_arg(node)
        if (
            location is not None
            and _contains_web_content(location, self._effective_constants())
            and self._expr_is_tainted(location)
        ):
            self._add(
                "odoo-binary-tainted-web-content-redirect",
                "Controller redirects to request-controlled web content URL",
                "high",
                node.lineno,
                "Controller builds a /web/content or /web/image URL from request input; verify record ownership, access_token, and allowed model/field scope",
                sink,
            )

    def _scan_content_disposition(self, node: ast.Call, sink: str) -> None:
        if _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-binary-tainted-content-disposition",
                "Download filename is request-controlled",
                "medium",
                node.lineno,
                "content_disposition uses request-derived filename; validate CRLF, path separators, extension, and confusing Unicode/control characters",
                sink,
            )

    def _scan_binary_response(self, node: ast.Call, sink: str) -> None:
        response = _response_body_arg(node)
        if response is not None and self._expr_is_binary(response):
            route = self._current_route()
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-binary-attachment-data-response",
                "Controller responds with attachment/binary data",
                severity,
                node.lineno,
                "Controller response body contains attachment or binary field data; verify access checks, token validation, and cache/header policy",
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
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
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._comprehension_is_tainted(node.elt, node.generators)
        if isinstance(node, ast.DictComp):
            return self._comprehension_is_tainted(node.key, node.generators) or self._comprehension_is_tainted(
                node.value, node.generators
            )
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _expr_is_binary(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.binary_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_binary(node.value)
        if _is_binary_content_call(node) or _is_attachment_binary_expr(node, self.attachment_names):
            return True
        if isinstance(node, ast.Call):
            return any(self._expr_is_binary(arg) for arg in node.args) or any(
                keyword.value is not None and self._expr_is_binary(keyword.value) for keyword in node.keywords
            )
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_binary(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_binary(node.test) or self._expr_is_binary(node.body) or self._expr_is_binary(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_binary(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_binary(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_binary(node.value)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._comprehension_is_binary(node.elt, node.generators)
        if isinstance(node, ast.DictComp):
            return self._comprehension_is_binary(node.key, node.generators) or self._comprehension_is_binary(
                node.value, node.generators
            )
        return False

    def _track_aliases(
        self,
        targets: list[ast.expr],
        value: ast.AST,
        attachment_names: set[str],
        sudo_names: set[str],
        model_names: dict[str, str],
    ) -> None:
        for target in targets:
            self._track_alias_target(target, value, attachment_names, sudo_names, model_names)

    def _track_alias_target(
        self,
        target: ast.expr,
        value: ast.AST,
        attachment_names: set[str],
        sudo_names: set[str],
        model_names: dict[str, str],
    ) -> None:
        if isinstance(target, ast.List | ast.Tuple) and isinstance(value, ast.List | ast.Tuple):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_alias_target(child_target, child_value, attachment_names, sudo_names, model_names)
            return
        if isinstance(target, ast.List | ast.Tuple):
            for child_target in target.elts:
                self._track_alias_target(child_target, value, attachment_names, sudo_names, model_names)
            return
        if isinstance(target, ast.Starred):
            self._track_alias_target(target.value, value, attachment_names, sudo_names, model_names)
            return
        if not isinstance(target, ast.Name):
            return

        constants = self._effective_constants()
        model_name = _model_name_in_expr(value, model_names, constants)
        if _is_sudo_expr(value, sudo_names, constants):
            self.sudo_names.add(target.id)
        else:
            self.sudo_names.discard(target.id)
        if model_name:
            self.model_names[target.id] = model_name
        else:
            self.model_names.pop(target.id, None)
        if _is_attachment_lookup(value, model_names, constants) or (
            isinstance(value, ast.Name) and value.id in attachment_names
        ):
            self.attachment_names.add(target.id)
        elif target.id in self.attachment_names:
            self.attachment_names.discard(target.id)

    def _mark_tainted_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.List | ast.Tuple) and isinstance(value, ast.List | ast.Tuple):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                if self._is_request_derived(child_value) or self._expr_is_tainted(child_value):
                    self._mark_name_target(child_target, self.tainted_names)
                else:
                    self._discard_name_target(child_target, self.tainted_names)
            return
        if self._is_request_derived(value) or self._expr_is_tainted(value):
            self._mark_name_target(target, self.tainted_names)
        else:
            self._discard_name_target(target, self.tainted_names)

    def _mark_binary_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.List | ast.Tuple) and isinstance(value, ast.List | ast.Tuple):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_binary_target(child_target, child_value)
            return
        if self._expr_is_binary(value):
            self._mark_name_target(target, self.binary_names)
        else:
            self._discard_name_target(target, self.binary_names)

    def _mark_local_constant_target(self, target: ast.expr, value: ast.AST) -> None:
        if not self.route_stack:
            return

        if isinstance(target, ast.List | ast.Tuple) and isinstance(value, ast.List | ast.Tuple):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(child_target, child_value)
            return

        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return

        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return

        if isinstance(target, ast.List | ast.Tuple):
            self._discard_local_constant_target(target)

    def _discard_local_constant_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.List | ast.Tuple):
            for element in target.elts:
                self._discard_local_constant_target(element)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants and not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _mark_name_target(self, target: ast.expr, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
            return
        if isinstance(target, ast.List | ast.Tuple):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _discard_name_target(self, target: ast.expr, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
            return
        if isinstance(target, ast.List | ast.Tuple):
            for element in target.elts:
                self._discard_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)

    def _comprehension_is_tainted(self, result: ast.AST | None, generators: list[ast.comprehension]) -> bool:
        if result is not None and self._expr_is_tainted(result):
            return True
        return any(
            self._expr_is_tainted(generator.iter)
            or any(self._expr_is_tainted(condition) for condition in generator.ifs)
            for generator in generators
        )

    def _comprehension_is_binary(self, result: ast.AST | None, generators: list[ast.comprehension]) -> bool:
        if result is not None and self._expr_is_binary(result):
            return True
        return any(
            self._expr_is_binary(generator.iter) or any(self._expr_is_binary(condition) for condition in generator.ifs)
            for generator in generators
        )

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            BinaryDownloadFinding(
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


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or {"route"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
        return RouteContext(is_route=True, auth=auth)
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


def _is_http_route(node: ast.AST, route_names: set[str] | None = None) -> bool:
    route_names = route_names or {"route"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return isinstance(node, ast.Attribute) and node.attr == "route"


def _is_request_derived(node: ast.AST, request_names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in {"params", "jsonrequest", "httprequest"}:
            if _is_request_expr(child.value, request_names):
                return True
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        if child.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            child.func.value, request_names
        ):
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


def _is_request_method(node: ast.AST, method: str, request_names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == method
        and isinstance(node.value, ast.Name)
        and node.value.id in request_names
    )


def _is_redirect_call(node: ast.AST, request_names: set[str]) -> bool:
    return _call_name(node) == "redirect" or _is_request_method(node, "redirect", request_names)


def _is_response_factory_call(node: ast.AST, request_names: set[str]) -> bool:
    if _call_name(node) in RESPONSE_FACTORY_SINKS:
        return True
    return _is_request_method(node, "make_response", request_names) or _is_request_method(
        node, "make_json_response", request_names
    )


def _redirect_location_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"location", "url", "redirect_url"}:
            return keyword.value
    return None


def _response_body_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"data", "response", "body"}:
            return keyword.value
    return None


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _is_attachment_lookup(
    node: ast.AST,
    model_names: dict[str, str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_attachment_lookup(resolved, model_names, constants)
    text = _safe_unparse(node)
    is_lookup = any(marker in text for marker in (".browse(", ".search(", ".search_read("))
    return is_lookup and (
        "ir.attachment" in text
        or any(_constant_string(child, constants) == "ir.attachment" for child in ast.walk(node))
        or (model_names is not None and _call_root_name(node) in _aliases_for_model(model_names, "ir.attachment"))
    )


def _is_binary_content_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func).endswith("binary_content")


def _is_attachment_binary_expr(node: ast.AST, attachment_names: set[str]) -> bool:
    text = _safe_unparse(node)
    if not any(f".{attr}" in text or attr in text for attr in ATTACHMENT_BINARY_ATTRS):
        return False
    return any(f"{name}.{attr}" in text for name in attachment_names for attr in ATTACHMENT_BINARY_ATTRS) or (
        "ir.attachment" in text and any(attr in text for attr in ATTACHMENT_BINARY_ATTRS)
    )


def _contains_web_content(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _contains_web_content(resolved, constants)
    for child in ast.walk(node):
        value = _constant_string(child, constants)
        if value and any(marker in value for marker in WEB_CONTENT_MARKERS):
            return True
    text = _safe_unparse(node)
    return any(marker in text for marker in WEB_CONTENT_MARKERS)


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


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


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants) for arg in current.args)
                    or any(
                        keyword.value is not None and _is_superuser_arg(keyword.value, constants)
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


def _is_superuser_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_superuser_arg(resolved, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


def _is_sudo_expr(
    node: ast.AST,
    sudo_names: set[str],
    constants: dict[str, ast.AST] | None = None,
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


def _model_name_in_expr(
    node: ast.AST,
    model_names: dict[str, str],
    constants: dict[str, ast.AST] | None = None,
) -> str:
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _model_name_in_expr(resolved, model_names, constants)
    if isinstance(node, ast.Starred):
        return _model_name_in_expr(node.value, model_names, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        for element in node.elts:
            model = _model_name_in_expr(element, model_names, constants)
            if model:
                return model
        return ""
    for child in ast.walk(node):
        if _constant_string(child, constants) == "ir.attachment":
            return "ir.attachment"
    text = _safe_unparse(node)
    if "ir.attachment" in text:
        return "ir.attachment"
    return model_names.get(_call_root_name(node), "")


def _aliases_for_model(model_names: dict[str, str], model_name: str) -> set[str]:
    return {name for name, tracked_model in model_names.items() if tracked_model == model_name}


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


def _unpack_target_value_pairs(targets: list[ast.expr], values: list[ast.expr]) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    before = list(zip(targets[:starred_index], values[:starred_index], strict=False))
    after_count = len(targets) - starred_index - 1
    after_values_start = max(len(values) - after_count, starred_index)
    rest_values = values[starred_index:after_values_start]
    rest_container: ast.expr = ast.List(elts=rest_values, ctx=ast.Load())
    after = list(zip(targets[starred_index + 1 :], values[after_values_start:], strict=False))
    return [*before, (targets[starred_index], rest_container), *after]


def _constant_string(node: ast.AST, constants: dict[str, ast.AST]) -> str:
    resolved = _resolve_constant(node, constants)
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
        return resolved.value
    return ""


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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[BinaryDownloadFinding]) -> list[dict[str, Any]]:
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
