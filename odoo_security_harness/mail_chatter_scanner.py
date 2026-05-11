"""Scanner for risky Odoo chatter and outbound mail usage in Python."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from odoo_security_harness.base_scanner import _should_skip


@dataclass
class MailChatterFinding:
    """Represents a chatter/mail security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


CHATTER_METHODS = {"message_post", "message_notify", "message_subscribe"}
FOLLOWER_METHODS = {"message_subscribe", "message_subscribe_users"}
MAIL_SEND_METHODS = {"send", "send_mail"}
SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.message",
    "payment.provider",
    "payment.transaction",
    "purchase.order",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
    "sale.order",
    "stock.picking",
}
TAINTED_ARG_NAMES = {
    "body",
    "email",
    "email_to",
    "kwargs",
    "kw",
    "message",
    "partner_id",
    "partner_ids",
    "post",
    "res_id",
    "res_model",
    "subject",
    "subtype_ids",
}
SENSITIVE_HINTS = {
    "access_key",
    "access_token",
    "access_url",
    "api_key",
    "apikey",
    "auth_token",
    "bank",
    "bearer_token",
    "client_secret",
    "csrf_token",
    "hmac_secret",
    "iban",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "password",
    "private_key",
    "reset_password_token",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signup_token",
    "signing_key",
    "ssn",
    "token",
    "totp_secret",
    "webhook_secret",
}
RECIPIENT_FIELDS = {"email_to", "email_cc", "partner_ids", "recipient_ids", "partner_to"}
FOLLOWER_FIELDS = {"channel_ids", "partner_id", "partner_ids", "res_id", "res_model", "subtype_ids"}
BODY_FIELDS = {"body", "body_html", "subject"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
REQUEST_TEXT_MARKERS = ("kwargs.get", "kw.get", "post.get")


def scan_mail_chatter(repo_path: Path) -> list[MailChatterFinding]:
    """Scan Python files for risky chatter/mail send behavior."""
    findings: list[MailChatterFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(MailChatterScanner(path).scan_file())
    return findings


class MailChatterScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[MailChatterFinding] = []
        self.tainted_names: set[str] = set()
        self.sudo_names: set[str] = set()
        self.model_names: dict[str, str] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_decorator_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[MailChatterFinding]:
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
        previous_tainted = set(self.tainted_names)
        previous_sudo = set(self.sudo_names)
        previous_models = dict(self.model_names)
        previous_local_constants = self.local_constants
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
        self.model_names = previous_models
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

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
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._track_tainted_target(target, node.value)
        self._track_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._track_tainted_target(node.target, node.value)
            self._track_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self.tainted_names.update(_target_names(node.target))
        else:
            self.tainted_names.difference_update(_target_names(node.target))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._track_tainted_target(node.target, node.value)
        self._track_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        if method in CHATTER_METHODS:
            self._scan_chatter_call(node, sink)
        elif _is_mail_send_call(node, sink):
            self._scan_mail_send(node, sink)
        elif _is_mail_create_call(node, sink, self.model_names):
            self._scan_mail_create(node, sink)
        elif _is_mail_followers_mutation(node, sink, self.model_names):
            self._scan_mail_followers_mutation(node, sink)
        self.generic_visit(node)

    def _scan_chatter_call(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-mail-chatter-public-route-send",
                "Public route posts chatter/mail notification",
                "high",
                node.lineno,
                "Public/unauthenticated route posts chatter or mail notifications; verify authorization, anti-spam controls, and recipient scoping",
                sink,
            )
        constants = self._effective_constants()
        if _is_sudo_expr(node.func, self.sudo_names, constants, self.superuser_names):
            self._add(
                "odoo-mail-chatter-sudo-post",
                "Chatter post is performed through elevated environment",
                "high",
                node.lineno,
                "message_post/message_notify uses sudo()/with_user(SUPERUSER_ID); verify followers and recipients cannot receive record data outside normal access rules",
                sink,
            )
        if sink.rsplit(".", 1)[-1] in FOLLOWER_METHODS:
            self._scan_follower_subscription(node, sink)
        self._scan_message_fields(node, sink)

    def _scan_mail_send(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-mail-send-public-route",
                "Public route sends email",
                "high",
                node.lineno,
                "Public/unauthenticated route sends email; verify authentication, CSRF, rate limiting, and recipient restrictions",
                sink,
            )
        constants = self._effective_constants()
        if _is_sudo_expr(node.func, self.sudo_names, constants, self.superuser_names):
            self._add(
                "odoo-mail-send-sudo",
                "Email send uses elevated environment",
                "medium",
                node.lineno,
                "Mail send uses sudo()/with_user(SUPERUSER_ID); verify rendered content and recipients do not bypass record rules",
                sink,
            )
        if _keyword_is_true(node, "force_send", constants):
            self._add(
                "odoo-mail-force-send",
                "Email is force-sent synchronously",
                "low",
                node.lineno,
                "send_mail(..., force_send=True) bypasses normal mail queue timing; verify request latency, retries, and spam/rate controls",
                sink,
            )
        self._scan_message_fields(node, sink)

    def _scan_mail_create(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-mail-create-public-route",
                "Public route creates outbound mail",
                "high",
                node.lineno,
                "Public/unauthenticated route creates mail.mail records; verify anti-spam controls and recipient restrictions",
                sink,
            )
        self._scan_message_fields(node, sink)

    def _scan_follower_subscription(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        sensitive_model = _sensitive_model_for_call(node.func, self.model_names)
        if sensitive_model:
            self._add(
                "odoo-mail-sensitive-model-follower-subscribe",
                "Follower subscription targets sensitive model",
                "high",
                node.lineno,
                f"Follower subscription targets sensitive model '{sensitive_model}'; verify subscribers cannot receive private record updates outside normal access rules",
                sink,
            )
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-mail-public-follower-subscribe",
                "Public route changes record followers",
                "high",
                node.lineno,
                "Public/unauthenticated route subscribes followers to a record; verify users cannot subscribe arbitrary partners to private chatter or notifications",
                sink,
            )
        if _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-mail-tainted-follower-subscribe",
                "Follower subscription uses request-controlled values",
                "high",
                node.lineno,
                "message_subscribe receives request-derived partner/subtype values; verify subscribers are constrained to authorized recipients",
                sink,
            )

    def _scan_mail_followers_mutation(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        constants = self._effective_constants()
        sensitive_model = _mail_followers_res_model(node, constants)
        if sensitive_model:
            self._add(
                "odoo-mail-followers-sensitive-model-mutation",
                "mail.followers mutation targets sensitive model",
                "high",
                node.lineno,
                f"mail.followers mutation targets sensitive model '{sensitive_model}'; verify recipients cannot receive private record updates outside normal access rules",
                sink,
            )
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-mail-followers-public-route-mutation",
                "Public route mutates mail.followers",
                "critical",
                node.lineno,
                "Public/unauthenticated route creates or changes mail.followers records; verify attackers cannot subscribe recipients to private records",
                sink,
            )
        if _is_sudo_expr(node.func, self.sudo_names, constants, self.superuser_names):
            self._add(
                "odoo-mail-followers-sudo-mutation",
                "mail.followers mutation uses elevated environment",
                "high",
                node.lineno,
                "mail.followers mutation uses sudo()/with_user(SUPERUSER_ID); verify follower changes cannot bypass record rules or company boundaries",
                sink,
            )
        for value in _field_values(node, FOLLOWER_FIELDS, constants):
            if value is not None and self._expr_is_tainted(value):
                self._add(
                    "odoo-mail-followers-tainted-mutation",
                    "mail.followers mutation uses request-controlled values",
                    "critical" if route.auth in {"public", "none"} else "high",
                    node.lineno,
                    "Request-derived values reach mail.followers fields; constrain model, record, partner, and subtype inputs before mutating subscriptions",
                    sink,
                )
                break

    def _scan_message_fields(self, node: ast.Call, sink: str) -> None:
        reported_sensitive_body = False
        reported_tainted_body = False
        reported_tainted_recipients = False
        constants = self._effective_constants()
        for value in _field_values(node, BODY_FIELDS, constants):
            if value is not None and _contains_sensitive_hint(value, constants) and not reported_sensitive_body:
                reported_sensitive_body = True
                self._add(
                    "odoo-mail-sensitive-body",
                    "Chatter/mail body includes sensitive values",
                    "high",
                    node.lineno,
                    "Chatter/mail body or subject references token/password/secret-like data; verify every recipient is authorized and links expire appropriately",
                    sink,
                )
            if value is not None and self._expr_is_tainted(value) and not reported_tainted_body:
                reported_tainted_body = True
                self._add(
                    "odoo-mail-tainted-body",
                    "Chatter/mail body uses request-controlled content",
                    "medium",
                    node.lineno,
                    "Chatter/mail body or subject includes request-derived data; verify escaping, spam controls, and recipient authorization",
                    sink,
                )
        for value in _field_values(node, RECIPIENT_FIELDS, constants):
            if value is not None and self._expr_is_tainted(value) and not reported_tainted_recipients:
                reported_tainted_recipients = True
                self._add(
                    "odoo-mail-tainted-recipients",
                    "Chatter/mail recipients are request-controlled",
                    "high",
                    node.lineno,
                    "Chatter/mail recipient fields are request-derived; verify users cannot redirect private record notifications or send arbitrary email",
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
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted(value) for value in node.values)
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

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _track_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        for target in targets:
            self._track_alias_target(target, value)

    def _track_alias_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._track_alias_target(child_target, child_value)
            return

        model_name = _model_name_in_expr(value, self.model_names)
        for name in _target_names(target):
            if _is_sudo_expr(value, self.sudo_names, self._effective_constants(), self.superuser_names):
                self.sudo_names.add(name)
            else:
                self.sudo_names.discard(name)
            if model_name:
                self.model_names[name] = model_name
            else:
                self.model_names.pop(name, None)

    def _track_tainted_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._track_tainted_target(child_target, child_value)
            return
        is_tainted = self._is_request_derived(value) or self._expr_is_tainted(value)
        if is_tainted:
            self.tainted_names.update(_target_names(target))
        else:
            self.tainted_names.difference_update(_target_names(target))

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(child_target, child_value)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for name in _target_names(target):
                self.local_constants.pop(name, None)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            MailChatterFinding(
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
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for keyword in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword.value, constants)
                if keyword.arg == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
        return RouteContext(is_route=True, auth=auth)
    return None


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
        and _is_odoo_http_module_expr(node.value, http_module_names, odoo_module_names)
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
            and _is_static_literal(statement.value)
        ):
            constants[statement.target.id] = statement.value
    return constants


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST:
    seen = seen or set()
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is not None:
            return _resolve_constant(value, constants, seen | {node.id})
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
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant(node, constants, seen)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants, set(seen))
        right = _resolve_static_dict(node.right, constants, set(seen))
        if left is None or right is None:
            return None
        return ast.Dict(keys=[*left.keys, *right.keys], values=[*left.values, *right.values])
    return None


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append(keyword)
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if isinstance(value, ast.Dict):
            keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for key, dict_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(dict_value, constants)
            if isinstance(value, ast.Dict):
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append(ast.keyword(arg=resolved_key.value, value=dict_value))
    return keywords


def _is_mail_send_call(node: ast.Call, sink: str) -> bool:
    return sink.rsplit(".", 1)[-1] in MAIL_SEND_METHODS and (
        "mail.template" in _safe_unparse(node.func) or sink.endswith(".send_mail") or sink.endswith(".send")
    )


def _is_mail_create_call(node: ast.Call, sink: str, model_names: dict[str, str]) -> bool:
    return sink.endswith(".create") and (
        "mail.mail" in _safe_unparse(node.func)
        or _call_root_name(node.func) in _aliases_for_model(model_names, "mail.mail")
    )


def _is_mail_followers_mutation(node: ast.Call, sink: str, model_names: dict[str, str]) -> bool:
    return sink.rsplit(".", 1)[-1] in {"create", "write"} and (
        "mail.followers" in _safe_unparse(node.func)
        or _call_root_name(node.func) in _aliases_for_model(model_names, "mail.followers")
    )


def _model_name_in_expr(node: ast.AST, model_names: dict[str, str]) -> str:
    text = _safe_unparse(node)
    for model_name in ("mail.mail", "mail.followers"):
        if model_name in text:
            return model_name
    for model_name in SENSITIVE_MODELS:
        if model_name in text:
            return model_name
    if isinstance(node, ast.Starred):
        return _model_name_in_expr(node.value, model_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return next((model for element in node.elts if (model := _model_name_in_expr(element, model_names))), "")
    if isinstance(node, ast.Subscript):
        return _model_name_in_expr(node.value, model_names)
    root_name = _call_root_name(node)
    return model_names.get(root_name, "")


def _aliases_for_model(model_names: dict[str, str], model_name: str) -> set[str]:
    return {name for name, tracked_model in model_names.items() if tracked_model == model_name}


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _field_values(
    node: ast.Call, fields: set[str], constants: dict[str, ast.AST] | None = None
) -> list[ast.AST | None]:
    constants = constants or {}
    values: list[ast.AST | None] = []
    for keyword in _expanded_keywords(node, constants):
        if keyword.arg in fields:
            values.append(keyword.value)
        if keyword.arg == "email_values":
            email_values = _resolve_static_dict(keyword.value, constants)
            if isinstance(email_values, ast.Dict):
                values.extend(_dict_field_values(email_values, fields, constants))
    for arg in node.args:
        resolved_arg = _resolve_static_dict(arg, constants)
        if isinstance(resolved_arg, ast.Dict):
            values.extend(_dict_field_values(resolved_arg, fields, constants))
    return values


def _mail_followers_res_model(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    for value in _field_values(node, {"res_model"}, constants):
        model = _literal_string(value, constants)
        if model in SENSITIVE_MODELS:
            return model
    return ""


def _dict_field_values(
    node: ast.Dict, fields: set[str], constants: dict[str, ast.AST] | None = None
) -> list[ast.AST | None]:
    constants = constants or {}
    values: list[ast.AST | None] = []
    for key, value in zip(node.keys, node.values, strict=False):
        if key is None:
            nested = _resolve_static_dict(value, constants)
            if nested is not None:
                values.extend(_dict_field_values(nested, fields, constants))
            continue
        resolved_key = _resolve_constant(key, constants) if key is not None else key
        if (
            isinstance(resolved_key, ast.Constant)
            and isinstance(resolved_key.value, str)
            and resolved_key.value in fields
        ):
            values.append(value)
    return values


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _contains_sensitive_hint(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    node = _resolve_constant(node, constants or {})
    return any(hint in _safe_unparse(node).lower() for hint in SENSITIVE_HINTS)


def _sensitive_model_in_expr(node: ast.AST) -> str:
    text = _safe_unparse(node)
    for model in SENSITIVE_MODELS:
        if model in text:
            return model
    return ""


def _sensitive_model_for_call(node: ast.AST, model_names: dict[str, str]) -> str:
    model = _sensitive_model_in_expr(node)
    if model:
        return model
    model = model_names.get(_call_root_name(node), "")
    return model if model in SENSITIVE_MODELS else ""


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _is_request_derived(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_source_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(
            node.value, request_names, http_module_names, odoo_module_names
        ) or _is_request_derived(node.slice, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names, http_module_names, odoo_module_names)
            or any(_is_request_derived(arg, request_names, http_module_names, odoo_module_names) for arg in node.args)
            or any(
                keyword.value is not None
                and _is_request_derived(keyword.value, request_names, http_module_names, odoo_module_names)
                for keyword in node.keywords
            )
        )
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_TEXT_MARKERS)


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in REQUEST_SOURCE_ATTRS:
        return _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in REQUEST_SOURCE_METHODS
        and _is_request_expr(node.func.value, request_names, http_module_names, odoo_module_names)
    ):
        return True
    return False


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
        and _is_odoo_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _is_odoo_http_module_expr(
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


def _keyword_is_true(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    return any(
        keyword.arg == name
        and isinstance((value := _resolve_constant(keyword.value, constants)), ast.Constant)
        and value.value is True
        for keyword in _expanded_keywords(node, constants)
    )


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
    sudo_names: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_names
    )


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants, superuser_names) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args)
                    or any(
                        keyword.arg in {"user", "uid"}
                        and keyword.value is not None
                        and _is_superuser_arg(keyword.value, constants, superuser_names)
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


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
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


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


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
    rest_value = ast.List(elts=value.elts[starred_index:after_values_start], ctx=ast.Load())
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    return [*before, (target.elts[starred_index], rest_value), *after]



def findings_to_json(findings: list[MailChatterFinding]) -> list[dict[str, Any]]:
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
