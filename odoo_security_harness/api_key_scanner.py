"""Scanner for risky Odoo API key creation, lookup, and exposure."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class ApiKeyFinding:
    """Represents an API-key security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""
    record_id: str = ""


API_KEY_MODELS = {"res.users.apikeys", "res.users.apikeys.description"}
MUTATION_METHODS = {"create", "write", "unlink"}
LOOKUP_METHODS = {"browse", "read_group", "search", "search_count", "search_read"}
TAINTED_ARG_NAMES = {"api_key", "apikey", "key", "token", "kwargs", "kw", "post", "params", "payload"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$|^uid$|_uids?$)")
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
KEY_RETURN_MARKERS = ("api_key", "apikey", "new_key", "access_token", "token")


def scan_api_keys(repo_path: Path) -> list[ApiKeyFinding]:
    """Scan Python and XML files for risky API-key handling."""
    findings: list[ApiKeyFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".py":
            findings.extend(ApiKeyScanner(path).scan_python_file())
        elif path.suffix == ".xml":
            findings.extend(ApiKeyScanner(path).scan_xml_file())
    return findings


class ApiKeyScanner(ast.NodeVisitor):
    """Scanner for one Python/XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[ApiKeyFinding] = []
        self.api_key_vars: set[str] = set()
        self.sudo_api_key_vars: set[str] = set()
        self.config_parameter_vars: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.tainted_names: set[str] = set()
        self.key_response_vars: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.http_module_names: set[str] = {"http"}
        self.route_decorator_names: set[str] = set()

    def scan_python_file(self) -> list[ApiKeyFinding]:
        """Scan Python code for API-key model use."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(self.content)
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

    def scan_xml_file(self) -> list[ApiKeyFinding]:
        """Scan XML records for committed API-key records."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") in API_KEY_MODELS:
                self._add(
                    "odoo-api-key-xml-record",
                    "API key record is declared in XML data",
                    "critical",
                    self._line_for_record(record),
                    "Module data declares a res.users.apikeys record; verify credentials are not seeded, exported, or recreated across databases",
                    record_id=record.get("id", ""),
                )
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_api_key_vars = set(self.api_key_vars)
        previous_sudo_api_key_vars = set(self.sudo_api_key_vars)
        previous_config_parameter_vars = set(self.config_parameter_vars)
        previous_tainted = set(self.tainted_names)
        previous_key_response_vars = set(self.key_response_vars)
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
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.api_key_vars = previous_api_key_vars
        self.sudo_api_key_vars = previous_sudo_api_key_vars
        self.config_parameter_vars = previous_config_parameter_vars
        self.tainted_names = previous_tainted
        self.key_response_vars = previous_key_response_vars
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_api_key_model_target(target, node.value)
            self._mark_config_parameter_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_key_response_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_api_key_model_target(node.target, node.value)
            self._mark_config_parameter_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_key_response_target(node.target, node.value)
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
        self._mark_api_key_model_target(node.target, node.value)
        self._mark_config_parameter_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_key_response_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        constants = self._effective_constants()
        model = _api_key_model_in_expr(node.func, self.api_key_vars, constants)
        route = self._current_route()

        if model and method in MUTATION_METHODS:
            if route.auth in {"public", "none"}:
                self._add(
                    "odoo-api-key-public-route-mutation",
                    "Public route mutates API keys",
                    "critical",
                    node.lineno,
                    f"Public/unauthenticated route mutates {model}; verify only the authenticated owner or administrators can create, revoke, or rename API keys",
                    route=route.display_path(),
                    sink=sink,
                )
            if _is_elevated_expr(node.func, self.sudo_api_key_vars, constants):
                self._add(
                    "odoo-api-key-sudo-mutation",
                    "API key mutation runs with elevated environment",
                    "high",
                    node.lineno,
                    f"{model}.{method} runs through sudo()/with_user(SUPERUSER_ID); verify caller identity, owner scoping, revocation semantics, and audit logging",
                    route=route.display_path(),
                    sink=sink,
                )
            if _call_has_tainted_input(node, self._expr_is_tainted):
                self._add(
                    "odoo-api-key-request-derived-mutation",
                    "Request-derived data reaches API key mutation",
                    "critical" if route.auth in {"public", "none"} else "high",
                    node.lineno,
                    f"Request-derived data reaches {model}.{method}; whitelist fields and prevent callers from choosing another user_id or scope",
                    route=route.display_path(),
                    sink=sink,
                )

        if model and method in LOOKUP_METHODS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-api-key-tainted-lookup",
                "Request-derived API key lookup",
                "high",
                node.lineno,
                "Request-derived data is used to query API-key records; verify constant-time credential validation, hashing, and user scoping rather than raw key lookup",
                route=route.display_path(),
                sink=sink,
            )

        if _is_config_parameter_set_param(
            node.func,
            self.config_parameter_vars,
            constants,
        ) and _set_param_stores_request_api_key(
            node,
            self._expr_is_tainted,
            constants,
        ):
            self._add(
                "odoo-api-key-config-parameter-request-secret",
                "Request-derived API key is stored in configuration",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Request-derived API key/token material is persisted with ir.config_parameter.set_param(); verify only trusted administrators can update integration credentials and that secrets are encrypted, rotated, and audited",
                route=route.display_path(),
                sink=sink,
            )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None and self._current_route().is_route and self._expr_mentions_key_return(node.value):
            route = self._current_route()
            self._add(
                "odoo-api-key-returned-from-route",
                "Route response appears to return API key material",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Controller response references API-key/token material; verify newly generated credentials are shown only once to the authenticated owner and never exposed cross-user",
                route=route.display_path(),
                sink="return",
            )
        self.generic_visit(node)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        text = _safe_unparse(node)
        if _is_request_source(node, self.request_names) or any(marker in text for marker in REQUEST_MARKERS):
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

    def _expr_mentions_key_return(self, node: ast.AST) -> bool:
        if _expr_mentions_key_return(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.key_response_vars
        if isinstance(node, ast.Subscript):
            return self._expr_mentions_key_return(node.value) or self._expr_mentions_key_return(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_mentions_key_return(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._expr_is_tainted(value)
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
                self._discard_name_target(target, self.tainted_names)

    def _mark_api_key_model_target(self, target: ast.AST, value: ast.AST) -> None:
        constants = self._effective_constants()
        model = _api_key_model_in_expr(value, self.api_key_vars, constants)
        is_sudo_api_key = _is_elevated_expr(value, self.sudo_api_key_vars, constants)
        if isinstance(target, ast.Name):
            if model:
                self.api_key_vars.add(target.id)
                if is_sudo_api_key:
                    self.sudo_api_key_vars.add(target.id)
                else:
                    self.sudo_api_key_vars.discard(target.id)
            else:
                self.api_key_vars.discard(target.id)
                self.sudo_api_key_vars.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_api_key_model_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_api_key_model_target(target_element, value_element)
            elif model:
                self._mark_name_target(target, self.api_key_vars)
                if is_sudo_api_key:
                    self._mark_name_target(target, self.sudo_api_key_vars)
            else:
                self._discard_name_target(target, self.api_key_vars)
                self._discard_name_target(target, self.sudo_api_key_vars)

    def _mark_config_parameter_target(self, target: ast.AST, value: ast.AST) -> None:
        is_config_parameter = _is_config_parameter_expr(
            value,
            self.config_parameter_vars,
            self._effective_constants(),
        )
        if isinstance(target, ast.Name):
            if is_config_parameter:
                self.config_parameter_vars.add(target.id)
            else:
                self.config_parameter_vars.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_config_parameter_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_config_parameter_target(target_element, value_element)
            elif is_config_parameter:
                self._mark_name_target(target, self.config_parameter_vars)
            else:
                self._discard_name_target(target, self.config_parameter_vars)

    def _mark_key_response_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if self._expr_mentions_key_return(value):
                self.key_response_vars.add(target.id)
            else:
                self.key_response_vars.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_key_response_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_key_response_target(target_element, value_element)
            elif self._expr_mentions_key_return(value):
                self._mark_name_target(target, self.key_response_vars)
            else:
                self._discard_name_target(target, self.key_response_vars)

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

    def _mark_local_constant_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            self._discard_local_constant_target(target)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_static_literal(value):
            self.local_constants[target.id] = value
        else:
            self.local_constants.pop(target.id, None)

    def _discard_local_constant_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
            return
        if isinstance(target, ast.Tuple | ast.List):
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

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            for index, line in enumerate(self.content.splitlines(), start=1):
                if record_id in line:
                    return index
        return 1

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        route: str = "",
        sink: str = "",
        record_id: str = "",
    ) -> None:
        self.findings.append(
            ApiKeyFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                route=route,
                sink=sink,
                record_id=record_id,
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
    http_module_names = http_module_names or {"http"}
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


def _resolve_optional_constant(node: ast.AST | None, constants: dict[str, ast.AST]) -> ast.AST | None:
    if node is None:
        return None
    return _resolve_constant(node, constants)


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


def _is_request_source(node: ast.AST, request_names: set[str]) -> bool:
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
    return False


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _api_key_model_in_expr(
    node: ast.AST,
    api_key_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> str:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node)
    for model in API_KEY_MODELS:
        if model in text:
            return model
    if isinstance(node, ast.Name) and node.id in api_key_vars:
        return "res.users.apikeys"
    if isinstance(node, ast.Attribute):
        return _api_key_model_in_expr(node.value, api_key_vars, constants)
    if isinstance(node, ast.Call):
        return _api_key_model_in_expr(node.func, api_key_vars, constants)
    if isinstance(node, ast.Subscript):
        model = _literal_string(_resolve_constant(node.slice, constants))
        if model in API_KEY_MODELS:
            return model
        return _api_key_model_in_expr(node.value, api_key_vars, constants)
    return ""


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


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _is_config_parameter_set_param(
    node: ast.AST,
    config_parameter_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node)
    if _call_name(node).split(".")[-1] != "set_param":
        return False
    return (
        "ir.config_parameter" in text
        or _call_root_name(node) in config_parameter_vars
        or _expr_uses_config_parameter_model(node, constants)
    )


def _set_param_stores_request_api_key(
    node: ast.Call,
    is_tainted: Any,
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    key_expr = (
        _resolve_constant(node.args[0], constants)
        if node.args
        else _resolve_optional_constant(_keyword_value(node, "key"), constants)
    )
    value_expr = (
        _resolve_constant(node.args[1], constants)
        if len(node.args) > 1
        else _resolve_optional_constant(_keyword_value(node, "value"), constants)
    )
    if key_expr is None or value_expr is None:
        return False
    return _expr_mentions_api_key_name(key_expr) and is_tainted(value_expr)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _expr_mentions_api_key_name(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in ("api_key", "apikey", "access_token", "secret", "token"))


def _expr_mentions_key_return(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return any(marker in text for marker in KEY_RETURN_MARKERS)


def _is_config_parameter_expr(
    node: ast.AST,
    config_parameter_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node)
    if "ir.config_parameter" in text:
        return True
    if isinstance(node, ast.Name):
        return node.id in config_parameter_vars
    if isinstance(node, ast.Attribute):
        return _is_config_parameter_expr(node.value, config_parameter_vars, constants)
    if isinstance(node, ast.Call):
        return _is_config_parameter_expr(node.func, config_parameter_vars, constants)
    if isinstance(node, ast.Subscript):
        model = _literal_string(_resolve_constant(node.slice, constants))
        return model == "ir.config_parameter" or _is_config_parameter_expr(
            node.value,
            config_parameter_vars,
            constants,
        )
    return False


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


def _is_elevated_expr(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    return (
        _expr_has_sudo(node)
        or _expr_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_vars
    )


def _expr_has_sudo(node: ast.AST) -> bool:
    return any(_call_chain_has_attr(child, "sudo") for child in ast.walk(node))


def _expr_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    return any(_call_chain_has_superuser_with_user(child, constants) for child in ast.walk(node))


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants) for arg in current.args)
                    or any(
                        keyword.arg in {"user", "uid"}
                        and keyword.value is not None
                        and _is_superuser_arg(keyword.value, constants)
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


def _expr_uses_config_parameter_model(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript):
            model = _literal_string(_resolve_constant(child.slice, constants))
            if model == "ir.config_parameter":
                return True
    return False


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
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


def findings_to_json(findings: list[ApiKeyFinding]) -> list[dict[str, Any]]:
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
            "record_id": f.record_id,
        }
        for f in findings
    ]
