"""Scanner for risky Odoo ORM domain construction."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class OrmDomainFinding:
    """Represents a risky ORM domain finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


DOMAIN_ARG_NAMES = {"args", "domain", "domains", "filter_domain", "filters", "kwargs", "kw", "post"}
REQUEST_MARKERS = (
    "request.params",
    "request.httprequest",
    "request.get_http_params",
    "request.get_json_data",
    "request.jsonrequest",
    "kwargs.get",
    "kw.get",
    "post.get",
)
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
CONTEXT_DOMAIN_MARKERS = (
    "env.context.get('domain'",
    'env.context.get("domain"',
    "env.context.get('active_domain'",
    'env.context.get("active_domain"',
    "self._context.get('domain'",
    'self._context.get("domain"',
    "self._context.get('active_domain'",
    'self._context.get("active_domain"',
)
DOMAIN_READ_METHODS = {"filtered_domain", "read_group", "search", "search_count", "search_read"}
DOMAIN_EVAL_SINKS = {"ast.literal_eval", "literal_eval", "safe_eval"}
DOMAIN_READ_KEYWORDS = {"args", "domain"}
DOMAIN_EVAL_KEYWORDS = {"expr", "expression", "source"}


def scan_orm_domains(repo_path: Path) -> list[OrmDomainFinding]:
    """Scan Python files for request/context-controlled ORM domains."""
    findings: list[OrmDomainFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(OrmDomainScanner(path).scan_file())
    return findings


class OrmDomainScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[OrmDomainFinding] = []
        self.tainted_names: set[str] = set()
        self.elevated_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[OrmDomainFinding]:
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
        previous_elevated = set(self.elevated_names)
        self.route_stack.append(
            _route_info(
                node,
                self._effective_constants(),
                self.route_names,
                self.http_module_names,
                self.odoo_module_names,
            )
            or RouteContext(is_route=False)
        )
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in DOMAIN_ARG_NAMES:
                self.tainted_names.add(arg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.elevated_names = previous_elevated

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
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        is_tainted = self._expr_is_tainted_domain(node.value)
        for target in node.targets:
            self._mark_tainted_target(target, is_tainted)
            self._track_elevated_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_tainted_target(node.target, self._expr_is_tainted_domain(node.value))
            self._track_elevated_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._mark_tainted_target(node.target, self._expr_is_tainted_domain(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_tainted_target(node.target, self._expr_is_tainted_domain(node.value))
        self._track_elevated_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]

        domain_arg = _domain_read_arg(node)
        eval_arg = _domain_eval_arg(node)

        if method in DOMAIN_READ_METHODS and domain_arg is not None and self._expr_is_tainted_domain(domain_arg):
            self._add_domain_search(node, sink)
        elif sink in DOMAIN_EVAL_SINKS and eval_arg is not None and self._expr_is_tainted_domain(eval_arg):
            self._add(
                "odoo-orm-domain-dynamic-eval",
                "Request/context data is evaluated as a domain",
                "high",
                node.lineno,
                "Request or context-derived data reaches literal_eval/safe_eval for ORM domain construction; validate allowed fields and operators",
                sink,
            )
        elif method == "filtered" and node.args and self._is_lambda_with_env_or_request(node.args[0]):
            self._add(
                "odoo-orm-domain-filtered-dynamic",
                "Record filtering uses dynamic request/env logic",
                "medium",
                node.lineno,
                "filtered(lambda ...) references request/env/context; verify Python-side filtering cannot replace record-rule or company checks",
                sink,
            )

        self.generic_visit(node)

    def _add_domain_search(self, node: ast.Call, sink: str) -> None:
        route = self._current_route()
        sudo = _is_elevated_expr(node.func, self._effective_constants(), self.superuser_names) or _uses_name(
            _call_receiver(node.func), self.elevated_names
        )
        if sudo:
            rule_id = "odoo-orm-domain-tainted-sudo-search"
            title = "Request/context-controlled domain is searched through an elevated environment"
            severity = "critical" if route.auth in {"public", "none"} else "high"
            message = (
                "Request or context-derived domain reaches sudo()/with_user(SUPERUSER_ID) ORM search/read; "
                "validate fields/operators, ownership, record rules, and company isolation"
            )
        else:
            rule_id = "odoo-orm-domain-tainted-search"
            title = "Request/context-controlled domain reaches ORM search"
            severity = "high" if route.auth in {"public", "none"} else "medium"
            message = (
                "Request or context-derived domain reaches ORM search/read; validate allowed fields/operators "
                "and prevent cross-record or cross-company discovery"
            )
        self._add(rule_id, title, severity, node.lineno, message, sink)

    def _expr_is_tainted_domain(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        text = _safe_unparse(node)
        if any(marker in text for marker in (*REQUEST_MARKERS, *CONTEXT_DOMAIN_MARKERS)):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted_domain(node.value) or self._expr_is_tainted_domain(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted_domain(node.value)
        if isinstance(node, ast.Call):
            return (
                self._expr_is_tainted_domain(node.func)
                or any(self._expr_is_tainted_domain(arg) for arg in node.args)
                or any(
                    keyword.value is not None and self._expr_is_tainted_domain(keyword.value)
                    for keyword in node.keywords
                )
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted_domain(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted_domain(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted_domain(node.left) or self._expr_is_tainted_domain(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted_domain(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted_domain(node.left) or any(
                self._expr_is_tainted_domain(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_tainted_domain(node.test)
                or self._expr_is_tainted_domain(node.body)
                or self._expr_is_tainted_domain(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted_domain(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted_domain(element) for element in node.elts)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted_domain(node.elt) or any(
                self._expr_is_tainted_domain(generator.iter)
                or any(self._expr_is_tainted_domain(condition) for condition in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted_domain(node.key)
                or self._expr_is_tainted_domain(node.value)
                or any(
                    self._expr_is_tainted_domain(generator.iter)
                    or any(self._expr_is_tainted_domain(condition) for condition in generator.ifs)
                    for generator in node.generators
                )
            )
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted_domain(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, is_tainted: bool) -> None:
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_tainted_target(element, is_tainted)
        elif isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, is_tainted)

    def _track_elevated_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in zip(target.elts, value.elts, strict=False):
                self._track_elevated_target(child_target, child_value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._track_elevated_target(element, value)
            return
        if isinstance(target, ast.Starred):
            self._track_elevated_target(target.value, value)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_elevated_expr(value, self._effective_constants(), self.superuser_names) or _uses_name(
            value, self.elevated_names
        ):
            self.elevated_names.add(target.id)
        else:
            self.elevated_names.discard(target.id)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _is_lambda_with_env_or_request(self, node: ast.AST) -> bool:
        return _is_lambda_with_env_or_request(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            OrmDomainFinding(
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
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for name, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if name == "auth" and isinstance(value, ast.Constant):
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
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_constant(item_value, constants)
            if isinstance(value, ast.Dict):
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append((resolved_key.value, item_value))
    return keywords


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
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


def _is_lambda_with_env_or_request(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    if not isinstance(node, ast.Lambda):
        return False
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    text = _safe_unparse(node.body)
    return any(marker in text for marker in ("request.", "env.context", "_context", ".sudo(", ".with_user(")) or any(
        _is_request_expr(child, request_names, http_module_names, odoo_module_names) for child in ast.walk(node.body)
    )


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
    return False


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
    )


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
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
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
                        keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
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
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_superuser_arg(resolved, constants, superuser_names)
    node = resolved
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _is_elevated_expr(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return _call_chain_has_attr(node, "sudo") or _call_chain_has_superuser_with_user(node, constants, superuser_names)


def _call_receiver(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Attribute):
        return node.value
    return node


def _domain_read_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in DOMAIN_READ_KEYWORDS:
            return keyword.value
    return None


def _domain_eval_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in DOMAIN_EVAL_KEYWORDS:
            return keyword.value
    return None


def _uses_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


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


def findings_to_json(findings: list[OrmDomainFinding]) -> list[dict[str, Any]]:
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
