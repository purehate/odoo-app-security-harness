"""Scanner for risky Odoo bus/realtime notification behavior."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class RealtimeFinding:
    """Represents a realtime bus/notification finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


BUS_SEND_METHODS = {"_sendone", "_sendmany", "sendone", "sendmany"}
NOTIFY_METHODS = {
    "_notify",
    "_notify_by_email",
    "_notify_by_web_push",
    "message_post",
    "notify_danger",
    "notify_default",
    "notify_info",
    "notify_success",
    "notify_warning",
}
TAINTED_ARG_NAMES = {"channel", "channels", "kwargs", "kw", "message", "options", "payload", "post", "user_id"}
SENSITIVE_PAYLOAD_HINTS = {
    "access_token",
    "amount_total",
    "bank",
    "email",
    "invoice",
    "password",
    "partner_id",
    "phone",
    "secret",
    "ssn",
    "token",
}
PUBLIC_CHANNEL_HINTS = {"broadcast", "global", "public", "website"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
REQUEST_TEXT_MARKERS = ("kwargs.get", "kw.get", "post.get")


def scan_realtime(repo_path: Path) -> list[RealtimeFinding]:
    """Scan Python files for risky Odoo realtime notification patterns."""
    findings: list[RealtimeFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(RealtimeScanner(path).scan_file())
    return findings


class RealtimeScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[RealtimeFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.tainted_names: set[str] = set()
        self.sudo_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.route_names: set[str] = {"route"}
        self.route_stack: list[RouteContext] = []
        self.function_stack: list[str] = []

    def scan_file(self) -> list[RealtimeFinding]:
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
        route = _route_info(node, self.constants, self.route_names) or RouteContext(is_route=False)
        self.route_stack.append(route)
        self.function_stack.append(node.name)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.function_stack.pop()
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.sudo_names = previous_sudo

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_tainted_target(target, node.value)
        self._track_sudo_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_tainted_target(node.target, node.value)
            self._track_sudo_aliases([node.target], node.value)
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
        self._track_sudo_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        if _is_channel_subscription_mutation(node):
            self._scan_channel_subscription(node, sink)
        if _is_bus_send(node):
            self._scan_bus_send(node, sink)
        elif _is_notify_call(node):
            self._scan_notify(node, sink)
        self.generic_visit(node)

    def _scan_channel_subscription(self, node: ast.Call, sink: str) -> None:
        channel_arg = _channel_subscription_arg(node)
        if channel_arg is None:
            return
        if not self._expr_is_tainted(channel_arg) and not _has_public_channel_hint(channel_arg, self.constants):
            return
        route = self._current_route()
        severity = "high" if route.auth in {"public", "none"} or self._current_function() == "_poll" else "medium"
        self._add(
            "odoo-realtime-broad-or-tainted-channel-subscription",
            "Bus subscription accepts broad or request-controlled channel",
            severity,
            node.lineno,
            "Realtime bus subscription mutates channel lists with request-derived or broad channels; verify users can only subscribe to tenant/user-scoped channels they are authorized to receive",
            sink,
        )

    def _scan_bus_send(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-realtime-public-route-bus-send",
                "Public route sends bus notification",
                "high",
                node.lineno,
                "Public/unauthenticated route sends realtime bus notifications; verify authorization, channel scope, and rate limiting",
                sink,
            )

        if _is_sudo_expr(node.func, self.sudo_names, self.constants):
            self._add(
                "odoo-realtime-bus-send-sudo",
                "Bus notification is sent through an elevated environment",
                "high",
                node.lineno,
                "Realtime bus notification uses sudo()/with_user(SUPERUSER_ID); verify channel recipients and payload cannot bypass record rules or company boundaries",
                sink,
            )

        channel_arg = node.args[0] if node.args else _keyword_value(node, "channel")
        payload_arg = _payload_arg(node)
        if channel_arg is not None and (
            self._expr_is_tainted(channel_arg) or _has_public_channel_hint(channel_arg, self.constants)
        ):
            self._add(
                "odoo-realtime-broad-or-tainted-channel",
                "Bus notification targets broad or request-controlled channel",
                "medium",
                node.lineno,
                "Realtime bus channel is broad or request-derived; verify tenant/user scoping and channel entropy",
                sink,
            )
        if payload_arg is not None and (
            self._expr_is_tainted(payload_arg) or _contains_sensitive_hint(payload_arg, self.constants)
        ):
            self._add(
                "odoo-realtime-sensitive-payload",
                "Bus notification may expose sensitive payload data",
                "high",
                node.lineno,
                "Realtime bus payload appears request-derived or contains sensitive fields; verify recipients are authorized for every emitted field",
                sink,
            )
        for channel_item, payload_item in _sendmany_items(node):
            if self._expr_is_tainted(channel_item) or _has_public_channel_hint(channel_item, self.constants):
                self._add(
                    "odoo-realtime-broad-or-tainted-channel",
                    "Bus notification targets broad or request-controlled channel",
                    "medium",
                    node.lineno,
                    "Realtime bus channel is broad or request-derived; verify tenant/user scoping and channel entropy",
                    sink,
                )
            if self._expr_is_tainted(payload_item) or _contains_sensitive_hint(payload_item, self.constants):
                self._add(
                    "odoo-realtime-sensitive-payload",
                    "Bus notification may expose sensitive payload data",
                    "high",
                    node.lineno,
                    "Realtime bus payload appears request-derived or contains sensitive fields; verify recipients are authorized for every emitted field",
                    sink,
                )

    def _scan_notify(self, node: ast.Call, sink: str) -> None:
        if _is_sudo_expr(node.func, self.sudo_names, self.constants):
            self._add(
                "odoo-realtime-notification-sudo",
                "Notification is sent through an elevated environment",
                "medium",
                node.lineno,
                "Notification/message call uses sudo()/with_user(SUPERUSER_ID); verify followers, partners, and subtype routing cannot expose private records",
                sink,
            )
        if _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-realtime-tainted-notification-content",
                "Notification content is request-controlled",
                "medium",
                node.lineno,
                "Notification/message content includes request-derived data; verify escaping, recipient authorization, and spam/rate controls",
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
                for target_element in target.elts:
                    self._discard_name_target(target_element, self.tainted_names)

    def _track_sudo_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        for target in targets:
            self._track_sudo_alias(target, value)

    def _track_sudo_alias(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._track_sudo_alias(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for target_element in target.elts:
                self._track_sudo_alias(target_element, value)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_sudo_expr(value, self.sudo_names, self.constants):
            self.sudo_names.add(target.id)
        else:
            self.sudo_names.discard(target.id)

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

    def _current_function(self) -> str:
        return self.function_stack[-1] if self.function_stack else ""

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            RealtimeFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)


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
    constants: dict[str, ast.AST] = {}
    for statement in tree.body:
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
    if isinstance(node, ast.Name):
        seen = seen or set()
        if node.id in seen or node.id not in constants:
            return node
        seen.add(node.id)
        return _resolve_constant(constants[node.id], constants, seen)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        keys = [key for key in node.keys if key is not None]
        return all(_is_static_literal(key) for key in keys) and all(
            _is_static_literal(value) for value in node.values
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    return False


def _is_http_route(node: ast.AST, route_names: set[str] | None = None) -> bool:
    route_names = route_names or {"route"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return isinstance(node, ast.Attribute) and node.attr == "route"


def _is_bus_send(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr in BUS_SEND_METHODS:
        return True
    return "bus.bus" in _safe_unparse(node.func) and _call_name(node.func).split(".")[-1] in BUS_SEND_METHODS


def _is_notify_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr in NOTIFY_METHODS


def _is_channel_subscription_mutation(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"append", "extend", "insert"}:
        return False
    target = _safe_unparse(node.func.value).lower()
    return "channel" in target


def _channel_subscription_arg(node: ast.Call) -> ast.AST | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr == "insert":
        return node.args[1] if len(node.args) >= 2 else None
    if node.args:
        return node.args[0]
    return None


def _payload_arg(node: ast.Call) -> ast.AST | None:
    for keyword_name in ("message", "messages", "notification", "notifications", "payload", "values"):
        value = _keyword_value(node, keyword_name)
        if value is not None:
            return value
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"_sendone", "sendone"} and len(node.args) >= 3:
        return node.args[2]
    if len(node.args) >= 2:
        return node.args[1]
    return None


def _sendmany_items(node: ast.Call) -> list[tuple[ast.AST, ast.AST]]:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"_sendmany", "sendmany"}:
        return []
    messages = node.args[0] if node.args else _keyword_value(node, "messages")
    if not isinstance(messages, ast.List | ast.Tuple):
        return []
    items: list[tuple[ast.AST, ast.AST]] = []
    for element in messages.elts:
        if not isinstance(element, ast.Tuple | ast.List) or len(element.elts) < 2:
            continue
        payload_index = 2 if len(element.elts) >= 3 else 1
        items.append((element.elts[0], element.elts[payload_index]))
    return items


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_request_derived(node: ast.AST, request_names: set[str]) -> bool:
    if _is_request_source_expr(node, request_names):
        return True
    if isinstance(node, ast.Starred):
        return _is_request_derived(node.value, request_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_request_derived(element, request_names) for element in node.elts)
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(node.value, request_names) or _is_request_derived(node.slice, request_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names)
            or any(_is_request_derived(arg, request_names) for arg in node.args)
            or any(
                keyword.value is not None and _is_request_derived(keyword.value, request_names)
                for keyword in node.keywords
            )
        )
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_TEXT_MARKERS)


def _is_request_source_expr(node: ast.AST, request_names: set[str]) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in REQUEST_SOURCE_ATTRS:
        return _is_request_expr(node.value, request_names)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in REQUEST_SOURCE_METHODS
        and _is_request_expr(node.func.value, request_names)
    ):
        return True
    return False


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _has_public_channel_hint(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    text = _safe_unparse(_resolve_constant(node, constants or {})).lower()
    return any(hint in text for hint in PUBLIC_CHANNEL_HINTS)


def _contains_sensitive_hint(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    text = _safe_unparse(_resolve_constant(node, constants or {})).lower()
    return any(hint in text for hint in SENSITIVE_PAYLOAD_HINTS)


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
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


def findings_to_json(findings: list[RealtimeFinding]) -> list[dict[str, Any]]:
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
