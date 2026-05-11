"""Scanner for risky Odoo payment/webhook handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PaymentFinding:
    """Represents a payment/webhook review finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    handler: str = ""


CALLBACK_PATH_HINTS = ("payment", "webhook", "notify", "notification", "callback", "return", "ipn")
SIGNATURE_MARKERS = (
    "signature",
    "sign",
    "verify",
    "validate",
    "_verify",
    "_validate",
    "compare_digest",
)
PROVIDER_SIGNATURE_VALIDATORS = ("construct_event",)
PAYMENT_STATE_METHODS = {"_set_done", "_set_authorized", "_set_pending", "_set_canceled", "_set_error"}
PAYMENT_FINAL_STATES = {"authorized", "done", "pending", "cancel", "cancelled", "canceled", "error"}
NOTIFICATION_METHODS = {
    "_handle_notification_data",
    "_process_notification_data",
    "_get_tx_from_notification_data",
    "_process_payment_notification",
}
PAYMENT_TRANSACTION_LOOKUP_METHODS = {"browse", "read_group", "search", "search_count", "search_read"}


def scan_payments(repo_path: Path) -> list[PaymentFinding]:
    """Scan Python files for risky payment/webhook handlers."""
    findings: list[PaymentFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(PaymentScanner(path).scan_file())
    return findings


class PaymentScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[PaymentFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()

    def scan_file(self) -> list[PaymentFinding]:
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
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        constants = self._effective_constants()
        route = _route_info(
            node,
            constants,
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        )
        has_signature_check = _has_signature_check(node)
        has_weak_signature_compare = _has_weak_signature_compare(node)
        has_any_signature_check = has_signature_check or has_weak_signature_compare

        if has_weak_signature_compare and _is_payment_handler_function(node, route):
            self._add(
                "odoo-payment-weak-signature-compare",
                "Payment handler compares signatures without constant-time check",
                "high",
                node.lineno,
                "Payment/webhook handler compares signature-like values with == or !=; use hmac.compare_digest or a provider verifier to avoid timing leaks and malformed signature bypasses",
                node.name,
            )

        if route and _is_payment_callback(route["paths"]):
            auth = route.get("auth", "")
            csrf = route.get("csrf", True)
            if auth in {"public", "none"} and csrf is False and not has_any_signature_check:
                self._add(
                    "odoo-payment-public-callback-no-signature",
                    "Public payment callback lacks visible signature validation",
                    "critical",
                    node.lineno,
                    "Public csrf=False payment/webhook route has no visible signature/HMAC validation; verify forged provider notifications cannot update transactions",
                    node.name,
                )

        if _is_payment_handler_function(node, route):
            changes_payment_state = _calls_payment_state_transition(node, constants)
            if changes_payment_state and not has_any_signature_check:
                self._add(
                    "odoo-payment-state-without-validation",
                    "Payment handler changes transaction state without visible validation",
                    "critical",
                    node.lineno,
                    "Payment notification/webhook handler changes transaction state without visible signature/reference validation",
                    node.name,
                )

            if changes_payment_state and not _checks_amount_and_currency(node):
                self._add(
                    "odoo-payment-state-without-amount-currency-check",
                    "Payment handler changes state without amount/currency reconciliation",
                    "high",
                    node.lineno,
                    "Payment notification/webhook handler finalizes transaction state without visible amount and currency checks; verify partial, underpaid, or wrong-currency notifications cannot complete payment",
                    node.name,
                )

            if changes_payment_state and not _checks_idempotency(node):
                self._add(
                    "odoo-payment-state-without-idempotency-check",
                    "Payment handler changes state without visible idempotency guard",
                    "high",
                    node.lineno,
                    "Payment notification/webhook handler changes transaction state without visible state, duplicate event, or provider-reference idempotency checks; verify retried notifications cannot duplicate fulfillment or regress state",
                    node.name,
                )

            if _has_weak_payment_transaction_lookup(node, constants):
                self._add(
                    "odoo-payment-transaction-lookup-weak",
                    "Payment transaction lookup lacks provider/reference scoping",
                    "high",
                    node.lineno,
                    "Payment handler searches payment.transaction without visible provider/reference scoping; verify notifications cannot bind to the wrong transaction",
                    node.name,
                )

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        handler: str,
    ) -> None:
        self.findings.append(
            PaymentFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                handler=handler,
            )
        )


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> dict[str, Any] | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names):
            continue
        info: dict[str, Any] = {"paths": [], "auth": "user", "csrf": True}
        if isinstance(decorator, ast.Call):
            if decorator.args:
                info["paths"] = _route_paths(decorator.args[0], constants)
            for keyword in decorator.keywords:
                _apply_route_keyword(info, keyword, constants)
        return info
    return None


def _apply_route_keyword(info: dict[str, Any], keyword: ast.keyword, constants: dict[str, ast.AST]) -> None:
    if keyword.arg is None:
        options = _resolve_constant(keyword.value, constants)
        if isinstance(options, ast.Dict):
            for key_node, value_node in zip(options.keys, options.values, strict=False):
                if key_node is None:
                    _apply_route_keyword(info, ast.keyword(arg=None, value=value_node), constants)
                    continue
                key = _literal_string(_resolve_constant(key_node, constants)) if key_node is not None else ""
                _apply_route_option(info, key, value_node, constants)
        return
    _apply_route_option(info, keyword.arg, keyword.value, constants)


def _apply_route_option(info: dict[str, Any], key: str, value_node: ast.AST, constants: dict[str, ast.AST]) -> None:
    value = _resolve_constant(value_node, constants)
    if key == "auth" and isinstance(value, ast.Constant):
        info["auth"] = value.value
    elif key == "csrf" and isinstance(value, ast.Constant):
        info["csrf"] = value.value
    elif key in {"route", "routes"}:
        info["paths"].extend(_route_paths(value_node, constants))


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


def _route_paths(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        paths = []
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                paths.append(value.value)
        return paths
    return []


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
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _is_payment_callback(paths: list[str]) -> bool:
    return any(any(hint in path.lower() for hint in CALLBACK_PATH_HINTS) for path in paths)


def _has_signature_check(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        sink = _call_name(child.func).lower()
        func_text = _safe_unparse(child.func).lower()
        if "compare_digest" in sink:
            return True
        if any(marker in sink for marker in PROVIDER_SIGNATURE_VALIDATORS):
            return True
        if any(marker in sink for marker in SIGNATURE_MARKERS) and any(
            marker in func_text for marker in ("signature", "sign", "verify", "validate", "hmac")
        ):
            return True
    return False


def _has_weak_signature_compare(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare):
            continue
        if not any(isinstance(op, ast.Eq | ast.NotEq) for op in child.ops):
            continue
        expressions = [child.left, *child.comparators]
        if any(_expr_mentions_signature(expr) for expr in expressions) and not any(
            _expr_uses_constant_time_compare(expr) for expr in expressions
        ):
            return True
    return False


def _expr_mentions_signature(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in ("signature", "sig", "hmac", "digest"))


def _expr_uses_constant_time_compare(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return "compare_digest" in text


def _calls_payment_state_transition(
    node: ast.FunctionDef, constants: dict[str, ast.AST] | None = None
) -> bool:
    visitor = _PaymentStateTransitionVisitor(constants or {})
    visitor.visit(node)
    return visitor.changes_payment_state


class _PaymentStateTransitionVisitor(ast.NodeVisitor):
    """Tracks payment state payload aliases in one handler function."""

    def __init__(self, constants: dict[str, ast.AST]) -> None:
        self.constants = constants
        self.local_constants: dict[str, ast.AST] = {}
        self.state_payload_names: set[str] = set()
        self.changes_payment_state = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if self.state_payload_names or self.changes_payment_state:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            _mark_local_constant_target(self.local_constants, target, node.value)
            self._mark_state_payload_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            _mark_local_constant_target(self.local_constants, node.target, node.value)
            self._mark_state_payload_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        _mark_local_constant_target(self.local_constants, node.target, node.value)
        self._mark_state_payload_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in PAYMENT_STATE_METHODS:
                self.changes_payment_state = True
            elif node.func.attr in {"write", "update"} and _writes_payment_state(
                node,
                self.state_payload_names,
                self._effective_constants(),
            ):
                self.changes_payment_state = True
        self.generic_visit(node)

    def _mark_state_payload_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_state_payload_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_state_payload_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _expr_sets_payment_state(value, self.state_payload_names, self._effective_constants()):
                self.state_payload_names.add(target.id)
            else:
                self.state_payload_names.discard(target.id)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants:
            return self.constants
        return {**self.constants, **self.local_constants}


def _is_payment_handler_function(node: ast.FunctionDef, route: dict[str, Any] | None) -> bool:
    name = node.name.lower()
    return (
        node.name in NOTIFICATION_METHODS
        or any(marker in name for marker in CALLBACK_PATH_HINTS)
        or "notification" in name
        or "webhook" in name
        or bool(route and _is_payment_callback(route["paths"]))
    )


def _writes_payment_state(
    node: ast.Call,
    state_payload_names: set[str] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    state_payload_names = state_payload_names or set()
    constants = constants or {}
    for arg in node.args:
        if _expr_sets_payment_state(arg, state_payload_names, constants):
            return True
    return any(
        keyword.value is not None and _expr_sets_payment_state(keyword.value, state_payload_names, constants)
        for keyword in node.keywords
        if keyword.arg in {"vals", "values"}
    )


def _expr_sets_payment_state(
    node: ast.AST, state_payload_names: set[str], constants: dict[str, ast.AST] | None = None
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Name):
        return node.id in state_payload_names
    if isinstance(node, ast.Call):
        return _expr_sets_payment_state(node.func, state_payload_names, constants) or any(
            _expr_sets_payment_state(arg, state_payload_names, constants) for arg in node.args
        )
    if isinstance(node, ast.Subscript):
        return _expr_sets_payment_state(node.value, state_payload_names, constants)
    return _dict_sets_payment_state(node, constants)


def _dict_sets_payment_state(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values, strict=False):
        key = _resolve_constant(key, constants) if key is not None else key
        value = _resolve_constant(value, constants)
        if isinstance(key, ast.Constant) and key.value == "state":
            if isinstance(value, ast.Constant):
                return str(value.value).lower() in PAYMENT_FINAL_STATES
            return True
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
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
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


def _searches_payment_transaction(node: ast.FunctionDef) -> bool:
    return bool(_payment_transaction_search_scopes(node))


def _filters_provider_reference(node: ast.FunctionDef) -> bool:
    scopes = _payment_transaction_search_scopes(node)
    return bool(scopes) and all(scopes)


def _has_weak_payment_transaction_lookup(
    node: ast.FunctionDef, constants: dict[str, ast.AST] | None = None
) -> bool:
    scopes = _payment_transaction_search_scopes(node, constants)
    return any(not is_scoped for is_scoped in scopes)


def _payment_transaction_search_scopes(
    node: ast.FunctionDef, constants: dict[str, ast.AST] | None = None
) -> list[bool]:
    visitor = _PaymentTransactionLookupVisitor(node.name, constants or {})
    visitor.visit(node)
    return visitor.search_scopes


class _PaymentTransactionLookupVisitor(ast.NodeVisitor):
    """Inspects payment.transaction search domains in one handler function."""

    def __init__(self, function_name: str, constants: dict[str, ast.AST]) -> None:
        self.function_name = function_name
        self.constants = constants
        self.local_constants: dict[str, ast.AST] = {}
        self.domain_names: dict[str, ast.AST] = {}
        self.search_scopes: list[bool] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if self.domain_names or self.search_scopes:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            _mark_local_constant_target(self.local_constants, target, node.value)
            self._mark_domain_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            _mark_local_constant_target(self.local_constants, node.target, node.value)
            self._mark_domain_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        _mark_local_constant_target(self.local_constants, node.target, node.value)
        self._mark_domain_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        constants = self._effective_constants()
        if _is_payment_transaction_lookup_call(node, self.function_name, constants):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "browse":
                self.search_scopes.append(False)
                self.generic_visit(node)
                return
            domain = _search_domain_arg(node)
            domain = _resolve_constant(domain, constants) if domain is not None else domain
            if domain is not None and isinstance(domain, ast.Name) and domain.id in self.domain_names:
                domain = self.domain_names[domain.id]
            self.search_scopes.append(_domain_has_provider_reference_scope(domain, constants))
        self.generic_visit(node)

    def _mark_domain_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_domain_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_domain_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            constants = self._effective_constants()
            resolved = _resolve_constant(value, constants)
            if _looks_like_domain(resolved, constants):
                self.domain_names[target.id] = value
            else:
                self.domain_names.pop(target.id, None)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants:
            return self.constants
        return {**self.constants, **self.local_constants}


def _is_payment_transaction_lookup_call(
    node: ast.Call, function_name: str, constants: dict[str, ast.AST] | None = None
) -> bool:
    constants = constants or {}
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in PAYMENT_TRANSACTION_LOOKUP_METHODS:
        return False
    receiver = node.func.value
    receiver_text = _safe_unparse(receiver).lower()
    if "payment.transaction" in receiver_text:
        return True
    if _is_payment_transaction_env_receiver(receiver, constants):
        return True
    return function_name in NOTIFICATION_METHODS and _is_notification_self_search_receiver(receiver, constants)


def _is_payment_transaction_env_receiver(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    while isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"sudo", "with_user", "with_context"}:
            node = node.func.value
        else:
            break
    if not isinstance(node, ast.Subscript):
        return False
    model = _resolve_constant(node.slice, constants)
    return isinstance(model, ast.Constant) and model.value == "payment.transaction"


def _is_notification_self_search_receiver(
    node: ast.AST, constants: dict[str, ast.AST] | None = None
) -> bool:
    """Check self/self.sudo()/self.with_user(admin-root) receiver patterns."""
    constants = constants or {}
    if isinstance(node, ast.Name):
        return node.id == "self"
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "self"):
        return False
    if node.func.attr == "sudo":
        return True
    if node.func.attr != "with_user":
        return False
    return any(_is_admin_user_arg(arg, constants) for arg in node.args) or any(
        keyword.arg in {"user", "uid"}
        and keyword.value is not None
        and _is_admin_user_arg(keyword.value, constants)
        for keyword in node.keywords
    )


def _is_admin_user_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    """Check if an expression names Odoo's root/admin user."""
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_admin_user_arg(arg, constants) for arg in node.args)
    return False


def _search_domain_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"args", "domain"}:
            return keyword.value
    return None


def _looks_like_domain(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.List | ast.Tuple):
        return any(_domain_term_field(element, constants) for element in node.elts)
    if isinstance(node, ast.BoolOp | ast.BinOp | ast.Call | ast.Name):
        return True
    return False


def _domain_has_provider_reference_scope(
    node: ast.AST | None, constants: dict[str, ast.AST] | None = None
) -> bool:
    if node is None:
        return False
    constants = constants or {}
    fields = _domain_field_names(node, constants)
    if "provider_reference" in fields and fields & {"provider_id", "provider_code", "acquirer_id"}:
        return True
    text = _safe_unparse(node).lower()
    return "provider_reference" in text and ("provider_id" in text or "provider_code" in text or "acquirer_id" in text)


def _domain_field_names(node: ast.AST, constants: dict[str, ast.AST]) -> set[str]:
    node = _resolve_constant(node, constants)
    fields: set[str] = set()
    if isinstance(node, ast.Tuple | ast.List):
        field = _domain_term_field(node, constants)
        if field:
            fields.add(field)
        for element in node.elts:
            fields.update(_domain_field_names(element, constants))
    elif isinstance(node, ast.BoolOp):
        for value in node.values:
            fields.update(_domain_field_names(value, constants))
    elif isinstance(node, ast.BinOp):
        fields.update(_domain_field_names(node.left, constants))
        fields.update(_domain_field_names(node.right, constants))
    return fields


def _domain_term_field(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    if isinstance(node, ast.Tuple | ast.List) and node.elts:
        first = _resolve_constant(node.elts[0], constants)
        if isinstance(first, ast.Constant):
            return str(first.value)
    return ""


def _checks_amount_and_currency(node: ast.FunctionDef) -> bool:
    text = _safe_unparse(node).lower()
    amount_markers = ("amount", "amount_total", "amount_paid", "expected_amount")
    currency_markers = ("currency", "currency_id", "currency_code")
    return any(marker in text for marker in amount_markers) and any(marker in text for marker in currency_markers)


def _checks_idempotency(node: ast.FunctionDef) -> bool:
    text = _safe_unparse(node).lower()
    markers = (
        "event_id",
        "webhook_id",
        "is_processed",
        "processed",
        "already",
        "duplicate",
    )
    return _has_state_guard(node) or any(marker in text for marker in markers)


def _has_state_guard(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Compare) and "state" in _safe_unparse(child.left).lower():
            return True
        if isinstance(child, ast.BoolOp):
            if any("state" in _safe_unparse(value).lower() for value in child.values):
                return True
    return False


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


def findings_to_json(findings: list[PaymentFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "handler": f.handler,
        }
        for f in findings
    ]
