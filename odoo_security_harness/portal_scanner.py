"""Scanner for risky Odoo portal route access-token patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PortalFinding:
    """Represents a portal route security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


READ_METHODS = {"browse", "read", "read_group", "search", "search_count", "search_read"}
ACCESS_HELPERS = {
    "_document_check_access",
    "_get_page_view_values",
    "check_access",
    "check_access_rights",
    "check_access_rule",
    "_check_access",
}


def scan_portal_routes(repo_path: Path) -> list[PortalFinding]:
    """Scan Python controllers for portal route authorization/token issues."""
    findings: list[PortalFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(PortalScanner(path).scan_file())
    return findings


class PortalScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[PortalFinding] = []
        self.request_names: set[str] = {"request"}
        self.route_names: set[str] = {"route"}
        self.route_stack: list[PortalContext] = []
        self.function_stack: list[FunctionContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[PortalFinding]:
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
        route = _route_info(node, self._effective_constants(), self.route_names) or PortalContext(is_route=False)
        arg_names = {arg.arg for arg in [*node.args.args, *node.args.kwonlyargs]}
        if node.args.vararg:
            arg_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            arg_names.add(node.args.kwarg.arg)

        context = FunctionContext(
            name=node.name,
            arg_names=arg_names,
            route_id_args={name for name in arg_names if name == "id" or name.endswith("_id")},
            has_access_token_arg="access_token" in arg_names,
        )
        self.route_stack.append(route)
        self.function_stack.append(context)

        if route.is_portal and route.auth in {"public", "none"}:
            self._add(
                "odoo-portal-public-route",
                "Portal route is publicly reachable",
                "high" if route.auth == "public" else "critical",
                node.lineno,
                f"Portal-like route {route.display_path()} uses auth='{route.auth}'; verify portal tokens, ownership checks, and record rule boundaries",
                route,
                "route",
            )

        self.generic_visit(node)
        self._finish_function(node, route, context)
        self.function_stack.pop()
        self.route_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        context = self._current_context()
        if context is not None:
            for target in node.targets:
                _mark_local_constant_target(context.local_constants, target, node.value)
            self._track_sudo_aliases(node.targets, node.value, context)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        context = self._current_context()
        if context is not None and node.value is not None:
            _mark_local_constant_target(context.local_constants, node.target, node.value)
            self._track_sudo_aliases([node.target], node.value, context)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        context = self._current_context()
        if context is not None:
            _mark_local_constant_target(context.local_constants, node.target, node.value)
            self._track_sudo_aliases([node.target], node.value, context)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        route = self._current_route()
        context = self._current_context()
        if not route.is_portal or context is None:
            self.generic_visit(node)
            return

        sink = _call_name(node.func)
        method = sink.split(".")[-1]
        constants = self._effective_constants(context)

        if method in READ_METHODS and _is_sudo_expr(node.func, context.sudo_vars, constants):
            context.sudo_read_line = context.sudo_read_line or node.lineno
            context.sudo_read_sink = context.sudo_read_sink or sink
        if method in ACCESS_HELPERS:
            context.has_access_helper = True
            if method == "_document_check_access":
                context.document_check_line = context.document_check_line or node.lineno
                context.document_check_has_token = context.document_check_has_token or _call_mentions_access_token(node)
        if _call_reads_access_token_param(node, self.request_names, constants):
            context.access_token_input_line = context.access_token_input_line or node.lineno
        if _call_reads_route_id_param(node, self.request_names, constants):
            context.route_id_input_line = context.route_id_input_line or node.lineno
        if sink.endswith("request.render") or sink == "request.render" or sink.endswith(".render"):
            if any(_expr_mentions_token(arg) for arg in node.args) or any(
                keyword.value is not None and _expr_mentions_token(keyword.value) for keyword in node.keywords
            ):
                context.token_exposure_line = context.token_exposure_line or node.lineno
                context.token_exposure_sink = context.token_exposure_sink or sink
        if sink.endswith("get_portal_url") or sink == "get_portal_url":
            context.portal_url_line = context.portal_url_line or node.lineno
            context.portal_url_sink = context.portal_url_sink or sink

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> Any:
        route = self._current_route()
        context = self._current_context()
        if route.is_portal and context is not None and _is_manual_access_token_compare(node):
            context.manual_token_check_line = context.manual_token_check_line or node.lineno
            context.manual_token_check_sink = context.manual_token_check_sink or _safe_unparse(node)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        route = self._current_route()
        context = self._current_context()
        if route.is_portal and context is not None and node.value is not None and _expr_mentions_token(node.value):
            context.token_exposure_line = context.token_exposure_line or node.lineno
            context.token_exposure_sink = context.token_exposure_sink or "return"
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        route = self._current_route()
        context = self._current_context()
        if route.is_portal and context is not None:
            key_name = _subscript_key_name(node.slice, self._effective_constants(context))
            if key_name == "access_token" and _is_request_mapping(node.value, self.request_names):
                context.access_token_input_line = context.access_token_input_line or node.lineno
            if (
                key_name
                and (key_name == "id" or key_name.endswith("_id"))
                and _is_request_mapping(node.value, self.request_names)
            ):
                context.route_id_input_line = context.route_id_input_line or node.lineno
        self.generic_visit(node)

    def _finish_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        route: PortalContext,
        context: FunctionContext,
    ) -> None:
        if not route.is_portal:
            return
        accepts_access_token = context.has_access_token_arg or bool(context.access_token_input_line)
        if accepts_access_token and not context.has_access_helper:
            self._add(
                "odoo-portal-access-token-without-helper",
                "Portal route accepts access_token without access helper",
                "medium",
                context.access_token_input_line or node.lineno,
                "Portal route accepts an access_token argument but does not call a visible portal access helper; verify the token is actually validated before record access or rendering",
                route,
                "access_token",
            )
        if accepts_access_token and context.document_check_line and not context.document_check_has_token:
            self._add(
                "odoo-portal-document-check-missing-token",
                "Portal access check does not pass access_token",
                "medium",
                context.document_check_line,
                "Portal route accepts access_token but calls _document_check_access without passing it; shared portal links may fail open/closed inconsistently or bypass intended token validation",
                route,
                "_document_check_access",
            )
        if (
            (context.route_id_args or context.route_id_input_line)
            and context.sudo_read_line
            and not context.has_access_helper
        ):
            self._add(
                "odoo-portal-sudo-route-id-read",
                "Portal route reads route-selected records through an elevated environment",
                "high",
                context.sudo_read_line,
                "Portal route uses a URL id to read records through sudo()/with_user(SUPERUSER_ID) without a portal access helper; verify ownership, token validation, and company isolation",
                route,
                context.sudo_read_sink,
            )
        if context.token_exposure_line and not context.has_access_helper:
            self._add(
                "odoo-portal-token-exposed-without-check",
                "Portal route exposes token data without access helper",
                "medium",
                context.token_exposure_line,
                "Portal route returns or renders access_token/access_url data without an accompanying portal access helper; verify tokens are not leaked across records",
                route,
                context.token_exposure_sink,
            )
        if context.portal_url_line and not context.has_access_helper:
            self._add(
                "odoo-portal-url-generated-without-check",
                "Portal URL generated without local access check",
                "low",
                context.portal_url_line,
                "Portal route generates portal URLs without a nearby access helper; verify links are only created for records the caller may access",
                route,
                context.portal_url_sink,
            )
        if context.manual_token_check_line and not context.has_access_helper:
            self._add(
                "odoo-portal-manual-access-token-check",
                "Portal route manually compares access_token",
                "high" if context.sudo_read_line or route.auth in {"public", "none"} else "medium",
                context.manual_token_check_line,
                "Portal route manually compares access_token values instead of using a portal access helper; verify ACLs, ownership, company scope, and token semantics match Odoo's _document_check_access behavior",
                route,
                context.manual_token_check_sink,
            )

    def _current_route(self) -> PortalContext:
        return self.route_stack[-1] if self.route_stack else PortalContext(is_route=False)

    def _current_context(self) -> FunctionContext | None:
        return self.function_stack[-1] if self.function_stack else None

    def _effective_constants(self, context: FunctionContext | None = None) -> dict[str, ast.AST]:
        if not self.class_constants_stack and (context is None or not context.local_constants):
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        if context is not None:
            constants.update(context.local_constants)
        return constants

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        route: PortalContext,
        sink: str,
    ) -> None:
        self.findings.append(
            PortalFinding(
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

    def _track_sudo_aliases(self, targets: list[ast.expr], value: ast.AST, context: FunctionContext) -> None:
        for target in targets:
            self._track_sudo_alias(target, value, context)

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST, context: FunctionContext) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._track_sudo_alias(target_element, value_element, context)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value, context)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for target_element in target.elts:
                self._track_sudo_alias(target_element, value, context)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_sudo_expr(value, context.sudo_vars, self._effective_constants(context)):
            context.sudo_vars.add(target.id)
        else:
            context.sudo_vars.discard(target.id)


@dataclass
class PortalContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    website: bool = False
    paths: tuple[str, ...] = ()
    function_name: str = ""

    @property
    def is_portal(self) -> bool:
        return self.is_route and (
            any(path.startswith("/my") or "/portal/" in path for path in self.paths)
            or "portal" in self.function_name.lower()
        )

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


@dataclass
class FunctionContext:
    """Per-route state accumulated during AST traversal."""

    name: str
    arg_names: set[str]
    route_id_args: set[str]
    has_access_token_arg: bool
    has_access_helper: bool = False
    access_token_input_line: int = 0
    document_check_line: int = 0
    document_check_has_token: bool = False
    route_id_input_line: int = 0
    sudo_read_line: int = 0
    sudo_read_sink: str = ""
    token_exposure_line: int = 0
    token_exposure_sink: str = ""
    portal_url_line: int = 0
    portal_url_sink: str = ""
    manual_token_check_line: int = 0
    manual_token_check_sink: str = ""
    sudo_vars: set[str] | None = None
    local_constants: dict[str, ast.AST] | None = None

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()
        if self.local_constants is None:
            self.local_constants = {}


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
) -> PortalContext | None:
    constants = constants or {}
    route_names = route_names or {"route"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names):
            continue
        auth = "user"
        website = False
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for name, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if name == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif name == "website" and isinstance(value, ast.Constant):
                    website = bool(value.value)
                elif name in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        return PortalContext(
            is_route=True,
            auth=auth,
            website=website,
            paths=tuple(paths),
            function_name=node.name,
        )
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


def _is_http_route(node: ast.AST, route_names: set[str] | None = None) -> bool:
    route_names = route_names or {"route"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return isinstance(node, ast.Attribute) and node.attr == "route"


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple):
        values: list[str] = []
        for item in node.elts:
            value = _resolve_constant(item, constants)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
        return values
    return []


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        return _resolve_constant_seen(value, constants, seen | {node.id})
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
            for key, value in zip(node.keys, node.values)
        )
    return False


def _mark_local_constant_target(constants: dict[str, ast.AST], target: ast.AST, value: ast.AST) -> None:
    if isinstance(target, ast.Name):
        if _is_static_literal(value):
            constants[target.id] = value
        else:
            constants.pop(target.id, None)
        return

    if isinstance(target, ast.Starred):
        _mark_local_constant_target(constants, target.value, value)
        return

    if isinstance(target, ast.Tuple | ast.List):
        if isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                _mark_local_constant_target(constants, target_element, value_element)
        else:
            _discard_local_constant_target(constants, target)


def _discard_local_constant_target(constants: dict[str, ast.AST], target: ast.AST) -> None:
    if isinstance(target, ast.Name):
        constants.pop(target.id, None)
    elif isinstance(target, ast.Starred):
        _discard_local_constant_target(constants, target.value)
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            _discard_local_constant_target(constants, element)


def _call_mentions_access_token(node: ast.Call) -> bool:
    return any(_expr_mentions_name(arg, "access_token") for arg in node.args) or any(
        keyword.arg == "access_token"
        or (keyword.value is not None and _expr_mentions_name(keyword.value, "access_token"))
        for keyword in node.keywords
    )


def _call_reads_access_token_param(
    node: ast.Call,
    request_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    return _call_reads_param_name(node, {"access_token"}, request_names, constants)


def _call_reads_route_id_param(
    node: ast.Call,
    request_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return False
    if not node.args:
        return False
    value = _resolve_constant(node.args[0], constants or {})
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return False
    name = value.value
    return _is_request_mapping(node.func.value, request_names) and (name == "id" or name.endswith("_id"))


def _call_reads_param_name(
    node: ast.Call,
    names: set[str],
    request_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
        return False
    if not _is_request_mapping(node.func.value, request_names):
        return False
    if not node.args:
        return False
    value = _resolve_constant(node.args[0], constants or {})
    return isinstance(value, ast.Constant) and value.value in names


def _is_request_mapping(node: ast.AST, request_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"kw", "kwargs", "post"}
    if isinstance(node, ast.Attribute) and node.attr == "params":
        return _is_request_expr(node.value, request_names)
    text = _safe_unparse(node)
    return text in {"kw", "kwargs", "post"}


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _subscript_key_name(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Index):
        return _subscript_key_name(node.value, constants)
    return ""


def _expr_mentions_token(node: ast.AST) -> bool:
    text = _safe_unparse(node)
    return "access_token" in text or "access_url" in text


def _is_manual_access_token_compare(node: ast.Compare) -> bool:
    if not any(isinstance(op, ast.Eq | ast.NotEq | ast.Is | ast.IsNot) for op in node.ops):
        return False
    expressions = [node.left, *node.comparators]
    token_sides = [_expr_mentions_name(expression, "access_token") for expression in expressions]
    if sum(1 for mentions_token in token_sides if mentions_token) < 2:
        return False
    return any(
        isinstance(expression, ast.Attribute) and expression.attr == "access_token" for expression in expressions
    )


def _expr_mentions_name(node: ast.AST, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, ast.keyword):
        return _expr_mentions_name(node.value, name)
    return name in _safe_unparse(node)


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
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_vars, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_vars
    )


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
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
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


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


def findings_to_json(findings: list[PortalFinding]) -> list[dict[str, Any]]:
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
