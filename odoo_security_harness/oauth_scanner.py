"""Scanner for risky Odoo OAuth callback and token validation flows."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class OAuthFinding:
    """Represents an OAuth/security-token finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


HTTP_METHODS = {"get", "post", "request"}
TAINTED_ARG_NAMES = {"access_token", "code", "id_token", "jwt", "oauth_uid", "state", "token", "kwargs", "kw", "post"}
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
OAUTH_ROUTE_MARKERS = ("oauth", "oidc", "openid", "sso", "signin", "callback")
TOKEN_MARKERS = ("access_token", "id_token", "oauth", "openid", "jwt")


def scan_oauth_flows(repo_path: Path) -> list[OAuthFinding]:
    """Scan Python files for risky OAuth callback and token validation behavior."""
    findings: list[OAuthFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(OAuthScanner(path).scan_file())
    return findings


class OAuthScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[OAuthFinding] = []
        self.request_names: set[str] = {"request"}
        self.tainted_names: set[str] = set()
        self.user_model_names: set[str] = set()
        self.oauth_identity_payload_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.http_module_names: set[str] = {"http"}
        self.route_decorator_names: set[str] = set()

    def scan_file(self) -> list[OAuthFinding]:
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
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_user_model_names = set(self.user_model_names)
        previous_oauth_identity_payload_names = set(self.oauth_identity_payload_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
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

        if route.is_route and _is_oauth_route(route, node.name) and route.auth in {"public", "none"}:
            self._add(
                "odoo-oauth-public-callback-route",
                "Public OAuth callback route",
                "medium",
                node.lineno,
                "OAuth/OIDC callback route is public; verify state/nonce validation, redirect URI binding, provider allowlist, and replay resistance",
                route.display_path(),
                "route",
            )
            if not _function_has_state_or_nonce_validation(node):
                self._add(
                    "odoo-oauth-missing-state-nonce-validation",
                    "OAuth callback lacks visible state or nonce validation",
                    "high",
                    node.lineno,
                    "Public OAuth/OIDC callback lacks visible state or nonce validation; verify CSRF protection, replay resistance, and ID-token nonce binding before session creation",
                    route.display_path(),
                    "route",
                )

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.user_model_names = previous_user_model_names
        self.oauth_identity_payload_names = previous_oauth_identity_payload_names
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_user_model_target(target, node.value)
            self._mark_oauth_identity_payload_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_user_model_target(node.target, node.value)
            self._mark_oauth_identity_payload_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_user_model_target(node.target, node.value)
        self._mark_oauth_identity_payload_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        route = self._current_route()
        constants = self._effective_constants()

        if _is_oauth_http_call(node) or (
            _is_oauth_route(route, "")
            and _is_http_client_call(node)
            and _call_has_tainted_url(node, self._expr_is_tainted)
        ):
            if not _has_keyword(node, "timeout"):
                self._add(
                    "odoo-oauth-http-no-timeout",
                    "OAuth token/userinfo HTTP call lacks timeout",
                    "medium",
                    node.lineno,
                    "OAuth/OIDC token or userinfo validation performs outbound HTTP without timeout; slow providers can exhaust workers",
                    route.display_path(),
                    sink,
                )
            if _has_verify_false(node, constants):
                self._add(
                    "odoo-oauth-http-verify-disabled",
                    "OAuth HTTP call disables TLS verification",
                    "critical",
                    node.lineno,
                    "OAuth/OIDC token or userinfo validation disables TLS verification; tokens and identities can be intercepted or forged",
                    route.display_path(),
                    sink,
                )
            if _call_has_tainted_url(node, self._expr_is_tainted):
                self._add(
                    "odoo-oauth-tainted-validation-url",
                    "Request-derived OAuth validation URL",
                    "critical",
                    node.lineno,
                    "Request-derived data controls OAuth/OIDC token or userinfo URL; enforce provider allowlists to avoid SSRF and token exfiltration",
                    route.display_path(),
                    sink,
                )
            if _is_authorization_code_token_exchange(node, constants) and not _call_has_code_verifier(
                node,
                constants,
            ):
                self._add(
                    "odoo-oauth-token-exchange-missing-pkce",
                    "OAuth authorization-code exchange lacks PKCE verifier",
                    "medium",
                    node.lineno,
                    "OAuth/OIDC authorization-code token exchange lacks a visible code_verifier; verify PKCE or equivalent confidential-client binding prevents code interception and replay",
                    route.display_path(),
                    sink,
                )

        if _is_jwt_decode(node):
            if _jwt_decode_disables_verification(node, constants):
                self._add(
                    "odoo-oauth-jwt-verification-disabled",
                    "JWT decode disables signature or claim verification",
                    "critical",
                    node.lineno,
                    "OAuth/OIDC JWT decode disables verification; require signature, issuer, audience, nonce, and expiry validation",
                    route.display_path(),
                    sink,
                )
            elif _call_has_tainted_input(node, self._expr_is_tainted):
                self._add(
                    "odoo-oauth-request-token-decode",
                    "Request-derived token is decoded",
                    "medium",
                    node.lineno,
                    "Request-derived OAuth/OIDC token is decoded; verify issuer, audience, nonce, expiry, algorithm, and key selection are constrained",
                    route.display_path(),
                    sink,
                )

        if _is_identity_write(
            node,
            self.user_model_names,
            self.oauth_identity_payload_names,
            constants,
        ) and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-oauth-tainted-identity-write",
                "Request-derived OAuth identity reaches user mutation",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Request-derived OAuth identity data reaches res.users mutation; verify provider validation and domain/account linking before writing oauth_uid/login/groups",
                route.display_path(),
                sink,
            )

        if (
            self._is_request_session_method(node.func, "authenticate")
            and route.auth in {"public", "none"}
            and _is_oauth_context(node)
        ):
            self._add(
                "odoo-oauth-session-authenticate",
                "OAuth flow authenticates a session",
                "high",
                node.lineno,
                "OAuth/OIDC flow calls request.session.authenticate; verify state/nonce validation and provider identity binding happen before session creation",
                route.display_path(),
                sink,
            )

        self.generic_visit(node)

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
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if self._is_request_derived(value) or self._expr_is_tainted(value):
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif self._is_request_derived(value) or self._expr_is_tainted(value):
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_user_model_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_user_model_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_user_model_target(target.value, value)
            return

        if _is_user_model_expr(value, self.user_model_names, self._effective_constants()):
            self._mark_name_target(target, self.user_model_names)
        else:
            self._discard_name_target(target, self.user_model_names)

    def _mark_oauth_identity_payload_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_oauth_identity_payload_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_oauth_identity_payload_target(target.value, value)
            return

        if _expr_mentions_oauth_identity_payload(value, self.oauth_identity_payload_names):
            self._mark_name_target(target, self.oauth_identity_payload_names)
        else:
            self._discard_name_target(target, self.oauth_identity_payload_names)

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
                self._discard_local_constant_target(target)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
        elif isinstance(target, ast.Tuple | ast.List):
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

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _is_request_session_method(self, node: ast.AST, method: str) -> bool:
        return _is_request_session_method(node, method, self.request_names)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            OAuthFinding(
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
) -> RouteContext | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names):
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
        return RouteContext(is_route=True, auth=auth, paths=paths)
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


def _is_http_route(
    node: ast.AST,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
) -> bool:
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_decorator_names, http_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_decorator_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and isinstance(node.value, ast.Name)
        and node.value.id in http_module_names
    )


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        routes = []
        for element in node.elts:
            value = _resolve_constant(element, constants)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                routes.append(value.value)
        return routes
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
            key is not None and _is_static_literal(key) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
            if value is not None
        )
    return False


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
    return any(marker in text for marker in REQUEST_MARKERS)


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _is_request_session_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "session" and _is_request_expr(node.value, request_names)


def _is_request_session_method(node: ast.AST, method: str, request_names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute) and node.attr == method and _is_request_session_expr(node.value, request_names)
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


def _is_oauth_route(route: RouteContext, function_name: str) -> bool:
    haystack = " ".join([function_name, *(route.paths or [])]).lower()
    return any(marker in haystack for marker in OAUTH_ROUTE_MARKERS)


def _function_has_state_or_nonce_validation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Compare) and _expr_mentions_state_or_nonce(child):
            return True
        if isinstance(child, ast.Call):
            sink = _call_name(child.func).lower()
            if any(marker in sink for marker in ("check", "compare", "validate", "verify")) and (
                any(_expr_mentions_state_or_nonce(arg) for arg in child.args)
                or any(
                    keyword.value is not None and _expr_mentions_state_or_nonce(keyword.value)
                    for keyword in child.keywords
                )
            ):
                return True
    return False


def _expr_mentions_state_or_nonce(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"state", "nonce"}:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            value = child.value.lower()
            if value in {"state", "nonce"} or "oauth_state" in value or "oauth_nonce" in value:
                return True
    return False


def _is_oauth_http_call(node: ast.Call) -> bool:
    if not _is_http_client_call(node):
        return False
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in TOKEN_MARKERS + ("userinfo", "validation_endpoint", "token_endpoint"))


def _is_authorization_code_token_exchange(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if not _is_http_client_call(node):
        return False
    method = _call_name(node.func).rsplit(".", 1)[-1]
    if method not in {"post", "request"}:
        return False
    text = _safe_unparse(node).lower()
    if "authorization_code" in text and "grant_type" in text:
        return True
    return "token_endpoint" in text and _call_contains_key(node, "code", constants)


def _call_has_code_verifier(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    return _call_contains_key(node, "code_verifier", constants or {})


def _call_contains_key(node: ast.Call, key_name: str, constants: dict[str, ast.AST]) -> bool:
    for arg in node.args:
        if _expr_contains_key(arg, key_name, constants):
            return True
    for keyword in node.keywords:
        if keyword.value is not None and _expr_contains_key(keyword.value, key_name, constants):
            return True
    return False


def _expr_contains_key(node: ast.AST, key_name: str, constants: dict[str, ast.AST]) -> bool:
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Dict):
        for key in node.keys:
            key = _resolve_constant(key, constants) if key is not None else None
            if isinstance(key, ast.Constant) and str(key.value) == key_name:
                return True
        return any(value is not None and _expr_contains_key(value, key_name, constants) for value in node.values)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_expr_contains_key(element, key_name, constants) for element in node.elts)
    if isinstance(node, ast.Call):
        return any(_expr_contains_key(arg, key_name, constants) for arg in node.args) or any(
            keyword.value is not None and _expr_contains_key(keyword.value, key_name, constants)
            for keyword in node.keywords
        )
    return False


def _is_http_client_call(node: ast.Call) -> bool:
    sink = _call_name(node.func)
    method = sink.rsplit(".", 1)[-1]
    return method in HTTP_METHODS and sink.startswith(("requests.", "httpx."))


def _is_user_model_expr(
    node: ast.AST,
    user_model_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name) and user_model_names and node.id in user_model_names:
        return True
    if "res.users" in _safe_unparse(node).lower():
        return True
    if isinstance(node, ast.Attribute):
        return _is_user_model_expr(node.value, user_model_names, constants)
    if isinstance(node, ast.Call):
        return _is_user_model_expr(node.func, user_model_names, constants)
    if isinstance(node, ast.Subscript):
        model = _resolve_constant(node.slice, constants)
        if isinstance(model, ast.Constant) and model.value == "res.users":
            return True
        return _is_user_model_expr(node.value, user_model_names, constants)
    return False


def _has_verify_false(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    return any(
        keyword.arg == "verify" and _is_false_constant(keyword.value, constants)
        for keyword in node.keywords
    )


def _call_has_tainted_url(node: ast.Call, is_tainted: Any) -> bool:
    if node.args and is_tainted(node.args[0]):
        return True
    return any(
        keyword.arg in {"url", "endpoint"} and keyword.value is not None and is_tainted(keyword.value)
        for keyword in node.keywords
    )


def _is_jwt_decode(node: ast.Call) -> bool:
    return (
        _call_name(node.func) in {"jwt.decode", "jose.jwt.decode", "decode"} and "token" in _safe_unparse(node).lower()
    )


def _jwt_decode_disables_verification(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    for keyword in node.keywords:
        value = _resolve_constant(keyword.value, constants or {})
        if keyword.arg == "verify" and _is_false_constant(value, constants):
            return True
        if keyword.arg == "options" and isinstance(value, ast.Dict):
            for key, option_value in zip(value.keys, value.values):
                key = _resolve_constant(key, constants or {}) if key is not None else None
                option_value = _resolve_constant(option_value, constants or {})
                if isinstance(key, ast.Constant) and str(key.value).startswith("verify_"):
                    if _is_false_constant(option_value, constants):
                        return True
    return False


def _is_false_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    return isinstance(value, ast.Constant) and value.value is False


def _is_identity_write(
    node: ast.Call,
    user_model_names: set[str] | None = None,
    oauth_identity_payload_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    sink = _call_name(node.func)
    method = sink.rsplit(".", 1)[-1]
    user_model_names = user_model_names or set()
    oauth_identity_payload_names = oauth_identity_payload_names or set()
    return (
        method in {"create", "write"}
        and (
            "res.users" in _safe_unparse(node.func)
            or sink.split(".", 1)[0] in user_model_names
            or _is_user_model_expr(node.func, user_model_names, constants)
        )
        and _call_mentions_oauth_identity_payload(node, oauth_identity_payload_names)
    )


def _call_mentions_oauth_identity_payload(node: ast.Call, oauth_identity_payload_names: set[str]) -> bool:
    for arg in node.args:
        if _expr_mentions_oauth_identity_payload(arg, oauth_identity_payload_names):
            return True
    for keyword in node.keywords:
        if keyword.value is not None and _expr_mentions_oauth_identity_payload(
            keyword.value,
            oauth_identity_payload_names,
        ):
            return True
    return False


def _expr_mentions_oauth_identity_payload(node: ast.AST, oauth_identity_payload_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in oauth_identity_payload_names
    if isinstance(node, ast.Dict):
        for key in node.keys:
            if isinstance(key, ast.Constant) and str(key.value) in {"login", "oauth_uid", "groups_id"}:
                return True
        return False
    if isinstance(node, ast.Call):
        return _expr_mentions_oauth_identity_payload(node.func, oauth_identity_payload_names) or any(
            _expr_mentions_oauth_identity_payload(arg, oauth_identity_payload_names) for arg in node.args
        )
    if isinstance(node, ast.Subscript):
        return _expr_mentions_oauth_identity_payload(node.value, oauth_identity_payload_names)
    return False


def _is_oauth_context(node: ast.Call) -> bool:
    text = " ".join(_safe_unparse(arg).lower() for arg in node.args)
    return any(marker in text for marker in TOKEN_MARKERS)


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _has_keyword(node: ast.Call, name: str) -> bool:
    return any(keyword.arg == name for keyword in node.keywords)


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


def findings_to_json(findings: list[OAuthFinding]) -> list[dict[str, Any]]:
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
