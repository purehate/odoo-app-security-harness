"""Scanner for risky Odoo signup, reset-password, and access-token flows."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SignupTokenFinding:
    """Represents a signup/reset token lifecycle finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


TAINTED_ARG_NAMES = {
    "access_token",
    "email",
    "kwargs",
    "kw",
    "login",
    "password",
    "post",
    "reset_password_token",
    "signup_token",
    "token",
}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$|^uid$|_uids?$)")
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
TOKEN_FIELD_MARKERS = (
    "access_token",
    "reset_password_token",
    "signup_expiration",
    "signup_token",
    "signup_type",
)
TOKEN_MUTATION_FIELDS = {*TOKEN_FIELD_MARKERS, "new_password", "password"}
IDENTITY_MODEL_MARKERS = ("res.partner", "res.users")
ROUTE_MARKERS = ("reset", "signup", "invite", "invitation", "activate", "auth")
RESET_SINK_MARKERS = (
    "action_reset_password",
    "reset_password",
    "signup_prepare",
    "_signup_create_user",
    "do_signup",
)


def scan_signup_tokens(repo_path: Path) -> list[SignupTokenFinding]:
    """Scan Python files for risky signup/reset/access-token handling."""
    findings: list[SignupTokenFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(SignupTokenScanner(path).scan_file())
    return findings


class SignupTokenScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[SignupTokenFinding] = []
        self.tainted_names: set[str] = set()
        self.identity_model_names: set[str] = set()
        self.identity_record_names: set[str] = set()
        self.elevated_identity_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.token_mutation_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.http_module_names: set[str] = {"http"}
        self.route_decorator_names: set[str] = set()

    def scan_file(self) -> list[SignupTokenFinding]:
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
        previous_identity_model_names = set(self.identity_model_names)
        previous_identity_record_names = set(self.identity_record_names)
        previous_elevated_identity_names = set(self.elevated_identity_names)
        previous_token_mutation_names = set(self.token_mutation_names)
        route = _route_info(
            node,
            self.path,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
        ) or RouteContext(
            is_route=False,
        )
        self.route_stack.append(route)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        if route.is_public and _is_signup_route(route, node.name):
            self._add(
                "odoo-signup-public-token-route",
                "Public signup/reset token route",
                "medium",
                node.lineno,
                "Public signup/reset route should validate token expiry, audience, redirect target, and account state before mutating identity data",
                route.display_path(),
                "route",
            )

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.identity_model_names = previous_identity_model_names
        self.identity_record_names = previous_identity_record_names
        self.elevated_identity_names = previous_elevated_identity_names
        self.token_mutation_names = previous_token_mutation_names

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_identity_model_names = set(self.identity_model_names)
        previous_identity_record_names = set(self.identity_record_names)
        previous_elevated_identity_names = set(self.elevated_identity_names)
        previous_token_mutation_names = set(self.token_mutation_names)
        for target in node.targets:
            self._mark_tainted_target(target, node.value)
            self._mark_identity_model_target(target, node.value, previous_identity_model_names)
            self._mark_identity_record_target(
                target,
                node.value,
                previous_identity_model_names,
                previous_identity_record_names,
            )
            self._mark_elevated_identity_target(
                target,
                node.value,
                previous_identity_model_names,
                previous_elevated_identity_names,
            )
            self._mark_token_mutation_target(target, node.value, previous_token_mutation_names)
        for target in node.targets:
            self._scan_identity_token_assignment(target, node.value, node.lineno)
            self._track_token_dict_subscript_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            previous_identity_model_names = set(self.identity_model_names)
            previous_identity_record_names = set(self.identity_record_names)
            previous_elevated_identity_names = set(self.elevated_identity_names)
            previous_token_mutation_names = set(self.token_mutation_names)
            self._mark_tainted_target(node.target, node.value)
            self._mark_identity_model_target(node.target, node.value, previous_identity_model_names)
            self._mark_identity_record_target(
                node.target,
                node.value,
                previous_identity_model_names,
                previous_identity_record_names,
            )
            self._mark_elevated_identity_target(
                node.target,
                node.value,
                previous_identity_model_names,
                previous_elevated_identity_names,
            )
            self._mark_token_mutation_target(node.target, node.value, previous_token_mutation_names)
            self._scan_identity_token_assignment(node.target, node.value, node.lineno)
            self._track_token_dict_subscript_assignment(node.target, node.value)
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
        previous_identity_model_names = set(self.identity_model_names)
        previous_identity_record_names = set(self.identity_record_names)
        previous_elevated_identity_names = set(self.elevated_identity_names)
        previous_token_mutation_names = set(self.token_mutation_names)
        self._mark_tainted_target(node.target, node.value)
        self._mark_identity_model_target(node.target, node.value, previous_identity_model_names)
        self._mark_identity_record_target(
            node.target,
            node.value,
            previous_identity_model_names,
            previous_identity_record_names,
        )
        self._mark_elevated_identity_target(
            node.target,
            node.value,
            previous_identity_model_names,
            previous_elevated_identity_names,
        )
        self._mark_token_mutation_target(node.target, node.value, previous_token_mutation_names)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        route = self._current_route()
        sink = _call_name(node.func)

        if _is_signup_reset_sink(node) and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-signup-tainted-reset-trigger",
                "Request-derived signup/reset trigger",
                "high" if route.is_public else "medium",
                node.lineno,
                "Request-derived data reaches signup/reset-password helper; verify rate limiting, account enumeration resistance, and token expiry",
                route.display_path(),
                sink,
            )

        if _is_token_lookup(
            node,
            self.identity_model_names,
            self._effective_constants(),
        ) and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-signup-tainted-token-lookup",
                "Request-derived token lookup",
                "critical" if route.is_public else "high",
                node.lineno,
                "Request-derived signup/access token is used to look up identity records; verify constant-time token checks, expiry, and ownership constraints",
                route.display_path(),
                sink,
            )

        if _is_signup_token_lookup_without_expiry(
            node,
            self.identity_model_names,
            self._effective_constants(),
        ) and _call_has_tainted_input(
            node,
            self._expr_is_tainted,
        ):
            self._add(
                "odoo-signup-token-lookup-without-expiry",
                "Signup/reset token lookup lacks expiry constraint",
                "critical" if route.is_public else "high",
                node.lineno,
                "Request-derived signup/reset token lookup does not visibly constrain signup_expiration; verify expired tokens cannot authenticate or mutate accounts",
                route.display_path(),
                sink,
            )

        if _is_identity_token_mutation(
            node, self.identity_model_names, self.token_mutation_names, self._effective_constants()
        ) and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-signup-tainted-identity-token-write",
                "Request-derived signup token or password mutation",
                "critical" if route.is_public else "high",
                node.lineno,
                "Request-derived data writes signup/access token or password fields on res.users/res.partner; require validated reset/signup flow state first",
                route.display_path(),
                sink,
            )

        if (
            route.is_public
            and _is_elevated_identity_access(
                node,
                self.identity_model_names,
                self.elevated_identity_names,
                self._effective_constants(),
            )
            and (_is_signup_context(node) or _is_signup_route(route, ""))
        ):
            self._add(
                "odoo-signup-public-sudo-identity-flow",
                "Public signup/reset flow uses sudo identity access",
                "high",
                node.lineno,
                "Public signup/reset flow uses sudo()/with_user(SUPERUSER_ID) on res.users/res.partner; verify token checks happen before privileged reads or writes",
                route.display_path(),
                sink,
            )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        route = self._current_route()
        if route.is_public and node.value is not None and _expr_mentions_token_field(
            node.value, self._effective_constants()
        ):
            self._add(
                "odoo-signup-token-exposed",
                "Signup/reset token exposed from public route",
                "critical",
                node.lineno,
                "Public signup/reset response includes signup/access token data; avoid exposing reusable account takeover tokens in rendered values, JSON, redirects, logs, or referrers",
                route.display_path(),
                "return",
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
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
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

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif self._is_request_derived(value) or self._expr_is_tainted(value):
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)

    def _mark_identity_model_target(
        self,
        target: ast.AST,
        value: ast.AST,
        identity_model_names: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_identity_model_target(target_element, value_element, identity_model_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_identity_model_target(target.value, value, identity_model_names)
            return

        if _is_identity_model_expr(value, identity_model_names, self._effective_constants()):
            self._mark_name_target(target, self.identity_model_names)
        else:
            self._discard_name_target(target, self.identity_model_names)

    def _mark_identity_record_target(
        self,
        target: ast.AST,
        value: ast.AST,
        identity_model_names: set[str],
        identity_record_names: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_identity_record_target(
                    target_element,
                    value_element,
                    identity_model_names,
                    identity_record_names,
                )
            return

        if isinstance(target, ast.Starred):
            self._mark_identity_record_target(
                target.value,
                value,
                identity_model_names,
                identity_record_names,
            )
            return

        if _is_identity_record_expr(
            value, identity_model_names, identity_record_names, self._effective_constants()
        ):
            self._mark_name_target(target, self.identity_record_names)
        else:
            self._discard_name_target(target, self.identity_record_names)

    def _mark_elevated_identity_target(
        self,
        target: ast.AST,
        value: ast.AST,
        identity_model_names: set[str],
        elevated_identity_names: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_elevated_identity_target(
                    target_element,
                    value_element,
                    identity_model_names,
                    elevated_identity_names,
                )
            return

        if isinstance(target, ast.Starred):
            self._mark_elevated_identity_target(target.value, value, identity_model_names, elevated_identity_names)
            return

        if _is_elevated_identity_expr(
            value, identity_model_names, elevated_identity_names, self._effective_constants()
        ):
            self._mark_name_target(target, self.elevated_identity_names)
        else:
            self._discard_name_target(target, self.elevated_identity_names)

    def _mark_token_mutation_target(
        self,
        target: ast.AST,
        value: ast.AST,
        token_mutation_names: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_token_mutation_target(target_element, value_element, token_mutation_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_token_mutation_target(target.value, value, token_mutation_names)
            return

        if _expr_mentions_token_mutation(value, token_mutation_names, self._effective_constants()):
            self._mark_name_target(target, self.token_mutation_names)
        else:
            self._discard_name_target(target, self.token_mutation_names)

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

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _scan_identity_token_assignment(self, target: ast.AST, value: ast.AST, line: int) -> None:
        if not _is_identity_token_assignment(
            target,
            self.identity_record_names,
            self._effective_constants(),
        ) or not self._expr_is_tainted(value):
            return
        route = self._current_route()
        self._add(
            "odoo-signup-tainted-identity-token-write",
            "Request-derived signup token or password mutation",
            "critical" if route.is_public else "high",
            line,
            "Request-derived data is assigned directly to signup/access token or password fields on res.users/res.partner; require validated reset/signup flow state first",
            route.display_path(),
            _safe_unparse(target),
        )

    def _track_token_dict_subscript_assignment(self, target: ast.AST, value: ast.AST) -> None:
        if not _is_token_dict_subscript(target, self._effective_constants()):
            return
        root_name = _call_root_name(target)
        if not root_name:
            return
        self.token_mutation_names.add(root_name)
        if self._expr_is_tainted(value):
            self.tainted_names.add(root_name)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            SignupTokenFinding(
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

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


@dataclass
class RouteContext:
    """Current HTTP route context."""

    is_route: bool
    auth: str = "user"
    paths: list[str] | None = None
    controller_path: bool = False

    @property
    def is_public(self) -> bool:
        return self.is_route and self.auth in {"public", "none"}

    def display_path(self) -> str:
        return ",".join(self.paths or []) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    path: Path,
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
        return RouteContext(is_route=True, auth=auth, paths=paths, controller_path="controllers" in path.parts)
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
        resolved = constants.get(node.id)
        if resolved is None:
            return node
        return _resolve_constant_seen(resolved, constants, {*seen, node.id})
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(isinstance(element, ast.Constant | ast.Name) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or isinstance(key, ast.Constant | ast.Name))
            and isinstance(value, ast.Constant | ast.Name | ast.List | ast.Tuple | ast.Set)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


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
    return any(marker in text for marker in REQUEST_MARKERS)


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


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


def _is_signup_route(route: RouteContext, function_name: str) -> bool:
    haystack = " ".join([function_name, *(route.paths or [])]).lower()
    return any(marker in haystack for marker in ROUTE_MARKERS)


def _is_signup_reset_sink(node: ast.Call) -> bool:
    sink = _call_name(node.func)
    return any(sink.endswith(marker) or sink == marker for marker in RESET_SINK_MARKERS)


def _is_identity_model_expr(
    node: ast.AST,
    identity_model_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name) and identity_model_names and node.id in identity_model_names:
        return True
    if isinstance(node, ast.Subscript) and identity_model_names and _call_root_name(node) in identity_model_names:
        return True
    if isinstance(node, ast.Subscript):
        model = _literal_string(_resolve_constant(node.slice, constants))
        if model in IDENTITY_MODEL_MARKERS:
            return True
    if isinstance(node, ast.Attribute):
        return _is_identity_model_expr(node.value, identity_model_names, constants)
    if isinstance(node, ast.Call):
        return _is_identity_model_expr(node.func, identity_model_names, constants)
    text = _safe_unparse(node).lower()
    return any(model in text for model in IDENTITY_MODEL_MARKERS)


def _is_identity_record_expr(
    node: ast.AST,
    identity_model_names: set[str] | None = None,
    identity_record_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name) and identity_record_names and node.id in identity_record_names:
        return True
    if isinstance(node, ast.Subscript) and identity_record_names and _call_root_name(node) in identity_record_names:
        return True
    sink = _call_name(node)
    method = sink.rsplit(".", 1)[-1]
    if method not in {"browse", "create", "search"}:
        return False
    text = _safe_unparse(node).lower()
    identity_model_names = identity_model_names or set()
    return (
        any(model in text for model in IDENTITY_MODEL_MARKERS)
        or sink.split(".", 1)[0] in identity_model_names
        or _is_identity_model_expr(node, identity_model_names, constants)
    )


def _is_token_lookup(
    node: ast.Call,
    identity_model_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    sink = _call_name(node.func)
    method = sink.rsplit(".", 1)[-1]
    text = _safe_unparse(node).lower()
    identity_model_names = identity_model_names or set()
    return (
        method in {"search", "search_count", "search_read", "read_group"}
        and (
            any(model in text for model in IDENTITY_MODEL_MARKERS)
            or sink.split(".", 1)[0] in identity_model_names
            or _is_identity_model_expr(node.func, identity_model_names, constants)
        )
        and _expr_mentions_token_field(node, constants)
    )


def _is_signup_token_lookup_without_expiry(
    node: ast.Call,
    identity_model_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if not _is_token_lookup(node, identity_model_names, constants):
        return False
    if not _expr_mentions_any_token_field(node, {"signup_token", "reset_password_token"}, constants):
        return False
    return not _expr_mentions_any_token_field(node, {"signup_expiration"}, constants)


def _is_identity_token_mutation(
    node: ast.Call,
    identity_model_names: set[str] | None = None,
    token_mutation_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    sink = _call_name(node.func)
    method = sink.rsplit(".", 1)[-1]
    text = _safe_unparse(node).lower()
    identity_model_names = identity_model_names or set()
    token_mutation_names = token_mutation_names or set()
    return (
        method in {"create", "write"}
        and (
            any(model in text for model in IDENTITY_MODEL_MARKERS)
            or sink.split(".", 1)[0] in identity_model_names
            or _is_identity_model_expr(node.func, identity_model_names, constants)
        )
        and (_call_mentions_token_field(node, token_mutation_names, constants) or "password" in text)
    )


def _is_identity_token_assignment(
    target: ast.AST,
    identity_record_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if not isinstance(target, ast.Attribute):
        return False
    target_field = _literal_string(_resolve_constant(ast.Name(id=target.attr, ctx=ast.Load()), constants)) or target.attr
    if target_field not in TOKEN_MUTATION_FIELDS:
        return False
    return _call_root_name(target.value) in identity_record_names


def _is_token_dict_subscript(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if not isinstance(node, ast.Subscript):
        return False
    key = _subscript_key_name(_resolve_constant(node.slice, constants))
    return key in TOKEN_MUTATION_FIELDS


def _subscript_key_name(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Index):
        return _subscript_key_name(node.value)
    return ""


def _call_mentions_token_field(
    node: ast.Call,
    token_mutation_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    for arg in node.args:
        if _expr_mentions_token_mutation(arg, token_mutation_names, constants):
            return True
    return any(
        keyword.value is not None and _expr_mentions_token_mutation(keyword.value, token_mutation_names, constants)
        for keyword in node.keywords
    )


def _expr_mentions_token_mutation(
    node: ast.AST,
    token_mutation_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name):
        return node.id in token_mutation_names
    if isinstance(node, ast.Subscript) and _call_root_name(node) in token_mutation_names:
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_expr_mentions_token_mutation(element, token_mutation_names, constants) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _expr_mentions_token_mutation(node.value, token_mutation_names, constants)
    return _dict_mentions_token_field(node, constants)


def _dict_mentions_token_field(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Dict):
        for key in node.keys:
            resolved_key = _resolve_constant(key, constants) if key is not None else None
            if isinstance(resolved_key, ast.Constant) and str(resolved_key.value) in {
                *TOKEN_FIELD_MARKERS,
                "password",
                "new_password",
            }:
                return True
    return False


def _is_elevated_identity_access(
    node: ast.Call,
    identity_model_names: set[str] | None = None,
    elevated_identity_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in {"browse", "create", "read", "read_group", "search", "search_count", "search_read", "write"}:
            return _is_elevated_identity_expr(
                node.func.value,
                identity_model_names,
                elevated_identity_names,
                constants,
            )
        return _call_root_name(node.func.value) in (elevated_identity_names or set())
    return False


def _is_elevated_identity_expr(
    node: ast.AST,
    identity_model_names: set[str] | None = None,
    elevated_identity_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name):
        return node.id in (elevated_identity_names or set())
    if isinstance(node, ast.Subscript):
        return _call_root_name(node) in (elevated_identity_names or set())
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(
            _is_elevated_identity_expr(element, identity_model_names, elevated_identity_names, constants)
            for element in node.elts
        )
    if isinstance(node, ast.Starred):
        return _is_elevated_identity_expr(node.value, identity_model_names, elevated_identity_names, constants)
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    sink = _call_name(node.func)
    text = _safe_unparse(node.func).lower()
    identity_model_names = identity_model_names or set()
    has_identity_receiver = (
        any(model in text for model in IDENTITY_MODEL_MARKERS)
        or sink.split(".", 1)[0] in identity_model_names
        or _is_identity_model_expr(node.func, identity_model_names, constants)
    )
    return has_identity_receiver and (
        node.func.attr == "sudo" or (node.func.attr == "with_user" and _call_has_superuser_arg(node, constants))
    )


def _call_has_superuser_arg(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    return any(_is_superuser_arg(arg, constants) for arg in node.args) or any(
        keyword.value is not None and _is_superuser_arg(keyword.value, constants) for keyword in node.keywords
    )


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


def _is_signup_context(node: ast.Call) -> bool:
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in (*TOKEN_FIELD_MARKERS, "signup", "reset", "password"))


def _expr_mentions_token_field(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    return _expr_mentions_any_token_field(node, set(TOKEN_FIELD_MARKERS), constants)


def _expr_mentions_any_token_field(
    node: ast.AST,
    fields: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and node.value in fields
    if isinstance(node, ast.Name):
        return node.id in fields
    if isinstance(node, ast.Dict):
        return any(
            key is not None and _expr_mentions_any_token_field(key, fields, constants) for key in node.keys
        ) or any(value is not None and _expr_mentions_any_token_field(value, fields, constants) for value in node.values)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_expr_mentions_any_token_field(element, fields, constants) for element in node.elts)
    if isinstance(node, ast.Subscript):
        return _expr_mentions_any_token_field(node.slice, fields, constants) or _expr_mentions_any_token_field(
            node.value,
            fields,
            constants,
        )
    if isinstance(node, ast.Attribute):
        return node.attr in fields or _expr_mentions_any_token_field(node.value, fields, constants)
    if isinstance(node, ast.Call):
        return _expr_mentions_any_token_field(node.func, fields, constants) or any(
            _expr_mentions_any_token_field(arg, fields, constants) for arg in node.args
        ) or any(
            keyword.value is not None and _expr_mentions_any_token_field(keyword.value, fields, constants)
            for keyword in node.keywords
        )
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in fields)


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


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
