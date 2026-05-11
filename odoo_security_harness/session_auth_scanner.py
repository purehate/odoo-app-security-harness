"""Scanner for risky Odoo controller session/authentication handling."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SessionAuthFinding:
    """Represents a session/authentication controller finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


TAINTED_ARG_NAMES = {"login", "password", "token", "uid", "user_id", "kwargs", "kw", "post", "params"}
TOKEN_MARKERS = ("csrf_token", "session_token", "session.sid", "request.session.sid")
SENSITIVE_COOKIE_MARKERS = ("csrf", "session", "sid", "token")
IR_HTTP_AUTH_METHODS = {
    "_authenticate",
    "_auth_method_bearer",
    "_auth_method_none",
    "_auth_method_public",
    "_auth_method_user",
    "_dispatch",
    "_serve_ir_http",
}
SUPERUSER_MARKERS = ("SUPERUSER_ID", "base.user_root", "base.user_admin")
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$|^uid$|_uids?$)")
SESSION_UID_KEYS = {"uid", "user_id"}


def scan_session_auth(repo_path: Path) -> list[SessionAuthFinding]:
    """Scan Python controllers for risky session/authentication handling."""
    findings: list[SessionAuthFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(SessionAuthScanner(path).scan_file())
    return findings


class SessionAuthScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[SessionAuthFinding] = []
        self.request_names: set[str] = {"request"}
        self.tainted_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.route_stack: list[RouteContext] = []
        self.class_stack: list[ClassContext] = []
        self.http_module_names: set[str] = {"http"}
        self.route_decorator_names: set[str] = set()
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.session_update_value_names: dict[str, ast.Dict] = {}

    def scan_file(self) -> list[SessionAuthFinding]:
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
        class_constants = _static_constants_from_body(node.body)
        constants = self._effective_constants(class_constants)
        context = ClassContext(
            model=_extract_model_name(node, constants),
            is_ir_http=_is_ir_http_class(node, constants),
        )
        self.class_constants_stack.append(class_constants)
        self.class_stack.append(context)
        self.generic_visit(node)
        self.class_stack.pop()
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_session_update_values = dict(self.session_update_value_names)
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
        )
        self.route_stack.append(route or RouteContext(is_route=False))
        if self._current_class().is_ir_http and node.name in IR_HTTP_AUTH_METHODS:
            self._scan_ir_http_auth_method(node)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (self.route_stack[-1].is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.session_update_value_names = previous_session_update_values

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_tainted_target(target, node.value)
            self._mark_session_update_value_target(target, node.value)
            self._mark_session_update_value_item_target(target, node.value)

        for target in node.targets:
            self._scan_uid_assignment_target(target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_tainted_target(node.target, node.value)
            self._mark_session_update_value_target(node.target, node.value)
            self._scan_uid_assignment_target(node.target, node.value, node.lineno)
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
        self._mark_tainted_target(node.target, node.value)
        self._mark_session_update_value_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        route = self._current_route()
        self._mark_session_update_value_update_call(node)

        if self._is_request_session_method(node.func, "authenticate"):
            if route.auth in {"public", "none"} and _call_has_tainted_input(node, self._expr_is_tainted):
                self._add(
                    "odoo-session-public-authenticate",
                    "Public route authenticates with request-controlled credentials",
                    "high",
                    node.lineno,
                    "Public/unauthenticated controller calls request.session.authenticate with request-derived credentials; verify rate limiting, CSRF, MFA, and redirect handling",
                    sink,
                )
        elif self._is_request_method(node.func, "update_env") or sink.endswith(".update_env"):
            self._scan_update_env(node, sink)
        elif self._is_request_session_method(node.func, "update"):
            self._scan_session_update(node, sink)
        elif sink in {"api.Environment", "Environment"}:
            self._scan_environment_ctor(node, sink)
        elif (self._is_request_session_method(node.func, "logout") or sink == "logout") and route.is_route:
            if route.auth in {"public", "none"} or not route.csrf or "GET" in route.methods or not route.methods:
                self._add(
                    "odoo-session-logout-weak-route",
                    "Logout route has weak method or CSRF posture",
                    "medium",
                    node.lineno,
                    "Controller exposes logout/session reset through a public/GET/csrf=False route; verify cross-site logout and session disruption are acceptable",
                    sink,
                )
        elif sink.endswith(".set_cookie") or sink == "set_cookie":
            if _sets_sensitive_cookie_without_flags(node, self._effective_constants()):
                severity = "high" if route.auth in {"public", "none"} else "medium"
                self._add(
                    "odoo-session-sensitive-cookie-weak-flags",
                    "Session or token cookie is set without hardened flags",
                    severity,
                    node.lineno,
                    "Controller sets a session/token/CSRF-shaped cookie without secure=True, httponly=True, and SameSite=Lax/Strict; verify it cannot be stolen, sent cross-site, or overwritten",
                    sink,
                )

        if route.auth in {"public", "none"} and _is_res_users_lookup_call(node) and _call_has_tainted_input(
            node,
            self._expr_is_tainted,
        ):
            self._add(
                "odoo-session-public-user-lookup",
                "Public route looks up users from request data",
                "medium",
                node.lineno,
                "Public/unauthenticated route queries res.users with request-derived input; verify login, reset, or token flows cannot enumerate accounts or create pre-auth timing side channels",
                sink,
            )

        if _returns_token_like_value(node, self._effective_constants()):
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-session-token-exposed",
                "Controller response exposes session or CSRF token",
                severity,
                node.lineno,
                "Controller appears to return CSRF/session token material; verify it is not exposed cross-origin or to unauthenticated users",
                sink or "response",
            )

        self.generic_visit(node)

    def _scan_update_env(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        constants = self._effective_constants()
        user_values = [
            keyword.value for keyword in node.keywords if keyword.arg in {"user", "uid"} and keyword.value is not None
        ]
        if not user_values:
            return
        if any(_expr_mentions_superuser(value, constants) for value in user_values):
            self._add(
                "odoo-session-update-env-superuser",
                "Controller switches request environment to superuser",
                "critical",
                node.lineno,
                "request.update_env switches the current request to a superuser/admin identity; verify public or user-controlled requests cannot escalate privileges",
                sink,
            )
        if any(self._expr_is_tainted(value) for value in user_values):
            self._add(
                "odoo-session-update-env-tainted-user",
                "request.update_env uses request-controlled user",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "request.update_env receives a request-derived user/uid; verify attackers cannot switch the request environment to another account",
                sink,
            )
        elif route.auth in {"public", "none"}:
            self._add(
                "odoo-session-public-update-env",
                "Public route switches request environment",
                "high",
                node.lineno,
                "Public/unauthenticated route calls request.update_env(user=...); verify authorization and account binding happen before environment switching",
                sink,
            )

    def _scan_environment_ctor(self, node: ast.Call, sink: str) -> None:
        if len(node.args) < 2:
            return
        route = self._current_route()
        uid_arg = node.args[1]
        if _expr_mentions_superuser(uid_arg, self._effective_constants()):
            self._add(
                "odoo-session-environment-superuser",
                "Manual Environment uses superuser",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Manual Odoo Environment is constructed with a superuser/admin identity; verify it cannot bypass request user, record rules, or company scoping",
                sink,
            )
        elif self._expr_is_tainted(uid_arg):
            self._add(
                "odoo-session-environment-tainted-user",
                "Manual Environment uses request-controlled user",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Manual Odoo Environment is constructed from request-derived uid; verify attackers cannot select another user's security context",
                sink,
            )

    def _scan_session_update(self, node: ast.Call, sink: str) -> None:
        constants = self._effective_constants()
        for value in self._session_update_uid_values(node, constants):
            severity = (
                "high" if self._expr_is_tainted(value) or _expr_mentions_superuser(value, constants) else "medium"
            )
            self._add(
                "odoo-session-direct-uid-assignment",
                "Controller directly updates request.session uid",
                severity,
                node.lineno,
                "Controller updates request.session uid directly; use Odoo authentication APIs and verify no request-controlled uid can create session fixation or account switching",
                sink,
            )
            return

    def _session_update_uid_values(self, node: ast.Call, constants: dict[str, ast.AST]) -> list[ast.AST]:
        values: list[ast.AST] = []
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.session_update_value_names:
                values.extend(_dict_literal_values_for_keys(self.session_update_value_names[arg.id], SESSION_UID_KEYS, constants))
            elif isinstance(arg, ast.Dict):
                values.extend(_dict_literal_values_for_keys(arg, SESSION_UID_KEYS, constants))
        for keyword in node.keywords:
            if keyword.arg in SESSION_UID_KEYS and keyword.value is not None:
                values.append(keyword.value)
        return values

    def _scan_uid_assignment_target(self, target: ast.AST, value: ast.AST, line: int) -> None:
        if self._is_session_uid_target(target):
            severity = "high" if self._expr_is_tainted(value) else "medium"
            self._add(
                "odoo-session-direct-uid-assignment",
                "Controller directly assigns request.session.uid",
                severity,
                line,
                "Controller assigns request.session.uid directly; use Odoo authentication APIs and verify no request-controlled uid can create session fixation or account switching",
                "request.session.uid",
            )
        elif self._is_request_uid_target(target):
            route = self._current_route()
            severity = (
                "critical"
                if route.auth in {"public", "none"} or _expr_mentions_superuser(value, self._effective_constants())
                else "high"
            )
            self._add(
                "odoo-session-direct-request-uid-assignment",
                "Controller directly assigns request.uid",
                severity,
                line,
                "Controller assigns request.uid directly; use Odoo authentication and environment-switching APIs only after explicit authorization checks",
                "request.uid",
            )

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None and _expr_mentions_token(node.value, self._effective_constants()):
            route = self._current_route()
            severity = "high" if route.auth in {"public", "none"} else "medium"
            self._add(
                "odoo-session-token-exposed",
                "Controller response exposes session or CSRF token",
                severity,
                node.lineno,
                "Controller returns CSRF/session token material; verify it is not exposed cross-origin or to unauthenticated users",
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
        if isinstance(target, ast.Name):
            if is_tainted:
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
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                for target_element in target.elts:
                    self._discard_name_target(target_element, self.tainted_names)

    def _mark_session_update_value_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_session_update_value_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_session_update_value_target(target.value, value)
            return
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Dict):
            self.session_update_value_names[target.id] = value
        elif isinstance(value, ast.Name) and value.id in self.session_update_value_names:
            self.session_update_value_names[target.id] = self.session_update_value_names[value.id]
        else:
            self.session_update_value_names.pop(target.id, None)

    def _mark_session_update_value_item_target(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
            return
        name = target.value.id
        values = self.session_update_value_names.get(name)
        if values is None:
            return
        key = _literal_subscript_key(_resolve_constant(target.slice, self._effective_constants()))
        if key:
            self.session_update_value_names[name] = _dict_with_field(values, key, value)

    def _mark_session_update_value_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        if not isinstance(node.func.value, ast.Name):
            return
        name = node.func.value.id
        values = self.session_update_value_names.get(name)
        if values is None:
            return
        update_values = node.args[0] if node.args else None
        if not isinstance(update_values, ast.Dict):
            return
        merged = values
        for key, value in zip(update_values.keys, update_values.values, strict=False):
            resolved_key = _resolve_constant(key, self._effective_constants()) if key is not None else None
            literal_key = _literal_subscript_key(resolved_key)
            if literal_key:
                merged = _dict_with_field(merged, literal_key, value)
        self.session_update_value_names[name] = merged

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

    def _current_class(self) -> ClassContext:
        return self.class_stack[-1] if self.class_stack else ClassContext()

    def _effective_constants(self, current_class: dict[str, ast.AST] | None = None) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not current_class:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        if current_class:
            constants.update(current_class)
        return constants

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _is_session_uid_target(self, node: ast.AST) -> bool:
        return _is_session_uid_target(node, self.request_names)

    def _is_request_uid_target(self, node: ast.AST) -> bool:
        return _is_request_uid_target(node, self.request_names)

    def _is_request_method(self, node: ast.AST, method: str) -> bool:
        return _is_request_method(node, method, self.request_names)

    def _is_request_session_method(self, node: ast.AST, method: str) -> bool:
        return _is_request_session_method(node, method, self.request_names)

    def _scan_ir_http_auth_method(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._add(
            "odoo-session-ir-http-auth-override",
            "ir.http authentication boundary is overridden",
            "high",
            node.lineno,
            f"ir.http method '{node.name}' participates in global request authentication; verify it preserves Odoo's session, API-key, public-user, and database-selection guarantees",
            node.name,
        )
        if _auth_method_grants_superuser(node, self._effective_constants()):
            self._add(
                "odoo-session-ir-http-superuser-auth",
                "ir.http authentication override grants elevated user",
                "critical",
                node.lineno,
                f"ir.http method '{node.name}' appears to assign or return a superuser/admin identity; verify unauthenticated or public requests cannot become privileged",
                node.name,
            )
        if _auth_method_bypasses_checks(node):
            self._add(
                "odoo-session-ir-http-bypass",
                "ir.http authentication override may bypass checks",
                "critical",
                node.lineno,
                f"ir.http method '{node.name}' appears to return success without a visible parent authentication call; verify it cannot bypass login, API-key, or session validation",
                node.name,
            )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            SessionAuthFinding(
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
    csrf: bool = True
    methods: set[str] | None = None


@dataclass
class ClassContext:
    """Current class context."""

    model: str = ""
    is_ir_http: bool = False


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _literal_string(_resolve_constant(item.value, constants))
                if value:
                    return value
    return ""


def _is_ir_http_class(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    model_name = _extract_model_name(node, constants)
    if model_name == "ir.http":
        return True
    return any("ir.http" in _safe_unparse(base) or _call_name(base).endswith(".Http") for base in node.bases)


def _auth_method_grants_superuser(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    for child in ast.walk(node):
        if isinstance(child, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets: list[ast.AST] = []
            if isinstance(child, ast.Assign):
                targets = list(child.targets)
                value = child.value
            elif isinstance(child, ast.AnnAssign):
                targets = [child.target]
                value = child.value
            else:
                targets = [child.target]
                value = child.value
            if any(_safe_unparse(target) in {"request.uid", "request.session.uid"} for target in targets) and (
                value is not None and _expr_mentions_superuser(value, constants)
            ):
                return True
        if isinstance(child, ast.Call) and _call_name(child.func).endswith(".update_env"):
            if any(
                keyword.arg in {"user", "uid"} and _expr_mentions_superuser(keyword.value, constants)
                for keyword in child.keywords
                if keyword.value is not None
            ):
                return True
        if isinstance(child, ast.Return) and child.value is not None and _expr_mentions_superuser(
            child.value,
            constants,
        ):
            return True
    return False


def _auth_method_bypasses_checks(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    has_parent_call = any(
        _call_name(child.func).startswith("super.") for child in ast.walk(node) if isinstance(child, ast.Call)
    )
    if has_parent_call:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Return) and _truthy_constant(child.value):
            return True
    return False


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names):
            continue
        auth = "user"
        csrf = True
        methods: set[str] | None = None
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                if keyword.arg is None:
                    auth, csrf, methods = _apply_route_options(keyword.value, constants, auth, csrf, methods)
                    continue
                auth, csrf, methods = _apply_route_keyword(
                    keyword.arg,
                    keyword.value,
                    constants,
                    auth,
                    csrf,
                    methods,
                )
        return RouteContext(is_route=True, auth=auth, csrf=csrf, methods=methods)
    return None


def _apply_route_options(
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    csrf: bool,
    methods: set[str] | None,
) -> tuple[str, bool, set[str] | None]:
    value = _resolve_constant(node, constants)
    if not isinstance(value, ast.Dict):
        return auth, csrf, methods
    for key, option_value in zip(value.keys, value.values, strict=False):
        key = _resolve_constant(key, constants) if key is not None else None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            auth, csrf, methods = _apply_route_keyword(key.value, option_value, constants, auth, csrf, methods)
    return auth, csrf, methods


def _apply_route_keyword(
    keyword: str,
    node: ast.AST,
    constants: dict[str, ast.AST],
    auth: str,
    csrf: bool,
    methods: set[str] | None,
) -> tuple[str, bool, set[str] | None]:
    value = _resolve_constant(node, constants)
    if keyword == "auth" and isinstance(value, ast.Constant):
        auth = str(value.value)
    elif keyword == "csrf" and isinstance(value, ast.Constant):
        csrf = bool(value.value)
    elif keyword == "methods":
        methods = _string_set(value)
    return auth, csrf, methods


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


def _string_set(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return set()
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return {
            str(element.value).upper()
            for element in node.elts
            if isinstance(element, ast.Constant) and element.value is not None
        }
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value.upper()}
    return set()


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


def _is_request_session_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "session" and _is_request_expr(node.value, request_names)


def _is_request_method(node: ast.AST, method: str, request_names: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == method and _is_request_expr(node.value, request_names)


def _is_request_session_method(node: ast.AST, method: str, request_names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute) and node.attr == method and _is_request_session_expr(node.value, request_names)
    )


def _is_session_uid_target(node: ast.AST, request_names: set[str]) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "uid" and _is_request_session_expr(node.value, request_names):
        return True
    if isinstance(node, ast.Subscript) and _is_request_session_expr(node.value, request_names):
        return _literal_subscript_key(node.slice) == "uid"
    return False


def _is_request_uid_target(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "uid" and _is_request_expr(node.value, request_names)


def _expr_mentions_superuser(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node)
    return any(marker in text for marker in SUPERUSER_MARKERS) or text in {"1", "True"}


def _truthy_constant(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _literal_subscript_key(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _dict_values_for_keys(
    node: ast.Call,
    keys: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> list[ast.AST]:
    constants = constants or {}
    values: list[ast.AST] = []
    for arg in node.args:
        if isinstance(arg, ast.Dict):
            values.extend(_dict_literal_values_for_keys(arg, keys, constants))
    for keyword in node.keywords:
        if keyword.arg in keys and keyword.value is not None:
            values.append(keyword.value)
    return values


def _dict_literal_values_for_keys(
    node: ast.Dict,
    keys: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> list[ast.AST]:
    constants = constants or {}
    values: list[ast.AST] = []
    for key, value in zip(node.keys, node.values, strict=False):
        if value is None:
            continue
        resolved_key = _resolve_constant(key, constants) if key is not None else None
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str) and resolved_key.value in keys:
            values.append(value)
    return values


def _dict_with_field(values: ast.Dict, key: str, value: ast.AST) -> ast.Dict:
    keys = list(values.keys)
    values_list = list(values.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values_list[index] = value
            return ast.Dict(keys=keys, values=values_list)
    keys.append(ast.Constant(value=key))
    values_list.append(value)
    return ast.Dict(keys=keys, values=values_list)


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


def _returns_token_like_value(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    return _expr_mentions_token(node, constants) and _call_name(node.func) in {
        "json.dumps",
        "request.make_response",
        "make_response",
        "Response",
    }


def _sets_sensitive_cookie_without_flags(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    cookie_name = _set_cookie_name(node, constants)
    if not cookie_name or not any(marker in cookie_name.lower() for marker in SENSITIVE_COOKIE_MARKERS):
        return False
    return not (
        _keyword_is_true(node, "secure", constants)
        and _keyword_is_true(node, "httponly", constants)
        and _samesite_is_restricted(node, constants)
    )


def _set_cookie_name(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    if node.args:
        return _literal_string(_resolve_constant(node.args[0], constants))
    for keyword in node.keywords:
        if keyword.arg in {"key", "name"}:
            return _literal_string(_resolve_constant(keyword.value, constants))
    return ""


def _is_res_users_lookup_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
        "browse",
        "read_group",
        "search",
        "search_count",
        "search_read",
    }:
        return False
    receiver = _safe_unparse(node.func.value).lower()
    return "res.users" in receiver


def _keyword_is_true(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    return any(
        keyword.arg == name
        and isinstance(_resolve_constant(keyword.value, constants), ast.Constant)
        and _resolve_constant(keyword.value, constants).value is True
        for keyword in node.keywords
        if keyword.value is not None
    )


def _samesite_is_restricted(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword in node.keywords:
        value = _resolve_constant(keyword.value, constants) if keyword.value is not None else None
        if keyword.arg == "samesite" and isinstance(value, ast.Constant):
            return str(value.value).lower() in {"lax", "strict"}
    return False


def _expr_mentions_token(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node).lower()
    if any(marker in text for marker in TOKEN_MARKERS):
        return True
    if isinstance(node, ast.Dict):
        return any(
            key is not None and _expr_mentions_token(_resolve_constant(key, constants), constants)
            for key in node.keys
        ) or any(_expr_mentions_token(value, constants) for value in node.values if value is not None)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_expr_mentions_token(element, constants) for element in node.elts)
    return False


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


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


def findings_to_json(findings: list[SessionAuthFinding]) -> list[dict[str, Any]]:
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
