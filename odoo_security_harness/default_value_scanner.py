"""Scanner for risky Odoo ir.default values and runtime writes."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class DefaultValueFinding:
    """Represents a risky ir.default finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    field: str = ""
    sink: str = ""
    record_id: str = ""


TAINTED_ARG_NAMES = {"field", "field_name", "kwargs", "kw", "post", "value", "values"}
ROUTE_DEFAULT_ARG_RE = re.compile(
    r"(?:^id$|_ids?$|^uid$|_uids?$|^field$|_field$|^field_name$|^value$|_value$|^model$|_model$)"
)
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
REQUEST_TEXT_MARKERS = ("kwargs.get", "kw.get", "post.get")
PRIVILEGE_FIELDS = {
    "active",
    "company_id",
    "company_ids",
    "groups_id",
    "implied_ids",
    "share",
    "user_id",
}
SENSITIVE_DEFAULT_MODELS = {
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "payment.provider",
    "res.groups",
    "res.users",
    "res.users.apikeys",
}
SENSITIVE_FIELD_MARKERS = (
    "account",
    "amount",
    "company",
    "discount",
    "groups",
    "implied",
    "journal",
    "password",
    "price",
    "share",
    "tax",
    "token",
    "user",
)


def scan_default_values(repo_path: Path) -> list[DefaultValueFinding]:
    """Scan Python and XML files for risky ir.default usage."""
    findings: list[DefaultValueFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".py":
            findings.extend(DefaultValueScanner(path).scan_python_file())
        elif path.suffix == ".xml":
            findings.extend(DefaultValueScanner(path).scan_xml_file())
    return findings


class DefaultValueScanner(ast.NodeVisitor):
    """Scanner for one Python/XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[DefaultValueFinding] = []
        self.default_vars: set[str] = set()
        self.elevated_default_vars: set[str] = set()
        self.tainted_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.route_decorator_names: set[str] = {"route"}
        self.constants: dict[str, ast.AST] = {}
        self.route_stack: list[RouteContext] = []
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_python_file(self) -> list[DefaultValueFinding]:
        """Scan Python code for ir.default writes."""
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

    def scan_xml_file(self) -> list[DefaultValueFinding]:
        """Scan XML data records for ir.default defaults."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.default":
                self._scan_default_record(record)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_default_vars = set(self.default_vars)
        previous_elevated_default_vars = set(self.elevated_default_vars)
        route = _route_info(node, self._effective_constants(), self.route_decorator_names) or RouteContext(
            is_route=False
        )
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_default_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.default_vars = previous_default_vars
        self.elevated_default_vars = previous_elevated_default_vars

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
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_default_vars = set(self.default_vars)
        previous_elevated_default_vars = set(self.elevated_default_vars)
        is_tainted = self._expr_is_tainted(node.value)
        for target in node.targets:
            self._mark_default_target(target, node.value, previous_default_vars, previous_elevated_default_vars)
            self._mark_tainted_target(target, node.value, is_tainted)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_default_target(
                node.target,
                node.value,
                set(self.default_vars),
                set(self.elevated_default_vars),
            )
            self._mark_tainted_target(node.target, node.value, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._mark_tainted_target(node.target, node.iter, self._expr_is_tainted(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_default_target(
            node.target,
            node.value,
            set(self.default_vars),
            set(self.elevated_default_vars),
        )
        self._mark_tainted_target(node.target, node.value, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        if sink.rsplit(".", 1)[-1] == "set" and _is_ir_default_expr(
            node.func, self.default_vars, self._effective_constants()
        ):
            self._scan_default_set(node, sink)
        self.generic_visit(node)

    def _scan_default_set(self, node: ast.Call, sink: str) -> None:
        model_node = node.args[0] if node.args else _keyword_value(node, "model")
        field_node = node.args[1] if len(node.args) >= 2 else _keyword_value(node, "field_name")
        value_node = node.args[2] if len(node.args) >= 3 else _keyword_value(node, "value")
        constants = self._effective_constants()
        model = _literal_string(model_node, constants)
        field = _literal_string(field_node, constants)
        route = self._current_route()

        if route.auth in {"public", "none"}:
            self._add(
                "odoo-default-public-route-set",
                "Public route writes ir.default",
                "critical",
                node.lineno,
                "Public route writes ir.default; verify unauthenticated users cannot alter persisted defaults for future create flows",
                model,
                field,
                sink,
            )

        if _is_elevated_expr(node.func, constants) or _uses_elevated_default_var(
            node.func, self.elevated_default_vars
        ):
            self._add(
                "odoo-default-sudo-set",
                "ir.default is written through privileged context",
                "high",
                node.lineno,
                "sudo()/with_user(SUPERUSER_ID).set() writes persisted defaults; verify explicit admin checks and user/company scoping",
                model,
                field,
                sink,
            )

        if (field_node is not None and self._expr_is_tainted(field_node)) or (
            value_node is not None and self._expr_is_tainted(value_node)
        ):
            self._add(
                "odoo-default-request-derived-set",
                "Request-derived data reaches ir.default",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Request-derived field or value reaches ir.default.set(); whitelist fields and reject user, group, company, pricing, and accounting defaults",
                model,
                field,
                sink,
            )

        if _is_sensitive_field(field):
            self._add(
                "odoo-default-sensitive-field-set",
                "Sensitive ir.default field is set at runtime",
                "high",
                node.lineno,
                f"Runtime ir.default.set() writes sensitive field '{field}'; verify scope, permissions, and company isolation",
                model,
                field,
                sink,
            )

        if model in SENSITIVE_DEFAULT_MODELS and value_node is not None:
            self._add(
                "odoo-default-sensitive-model-set",
                "Sensitive model default is set at runtime",
                "high",
                node.lineno,
                f"Runtime ir.default.set() writes a default for sensitive model '{model}'; verify this cannot seed configuration, security, payment, or identity state unexpectedly",
                model,
                field,
                sink,
            )

    def _scan_default_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(self.content, f'id="{record_id}"') if record_id else _line_for(self.content, 'model="ir.default"')
        )
        model = fields.get("model", "")
        field = fields.get("field_id", "") or fields.get("field_name", "")

        if not fields.get("user_id", "") and not fields.get("company_id", ""):
            self._add(
                "odoo-default-global-scope",
                "ir.default record has global scope",
                "medium",
                line,
                f"ir.default '{record_id}' has no user_id or company_id; verify the default is safe globally for every user and company",
                model,
                field,
                "ir.default",
                record_id,
            )

        if _is_sensitive_field(field) and (fields.get("json_value", "") or fields.get("value", "")):
            self._add(
                "odoo-default-sensitive-value",
                "Sensitive ir.default value is preconfigured",
                "high",
                line,
                f"ir.default '{record_id}' configures sensitive field '{field}'; verify it cannot seed privilege, accounting, company, or pricing values unexpectedly",
                model,
                field,
                "ir.default",
                record_id,
            )

        if model in SENSITIVE_DEFAULT_MODELS and (fields.get("json_value", "") or fields.get("value", "")):
            self._add(
                "odoo-default-sensitive-model-value",
                "Sensitive model default value is preconfigured",
                "high",
                line,
                f"ir.default '{record_id}' configures a default for sensitive model '{model}'; verify it cannot seed configuration, security, payment, or identity state unexpectedly",
                model,
                field,
                "ir.default",
                record_id,
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
        return _is_request_derived(node, self.request_names)

    def _mark_default_target(
        self,
        target: ast.AST,
        value: ast.AST,
        default_vars: set[str],
        elevated_default_vars: set[str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_default_target(target_element, value_element, default_vars, elevated_default_vars)
            return

        constants = self._effective_constants()
        is_default = _is_ir_default_expr(value, default_vars, constants)
        is_elevated_default = is_default and (
            _is_elevated_expr(value, constants) or _uses_elevated_default_var(value, elevated_default_vars)
        )
        for name in _target_names(target):
            if is_default:
                self.default_vars.add(name)
                if is_elevated_default:
                    self.elevated_default_vars.add(name)
                else:
                    self.elevated_default_vars.discard(name)
            else:
                self.default_vars.discard(name)
                self.elevated_default_vars.discard(name)

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST, is_tainted: bool) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_tainted_target(target_element, value_element, self._expr_is_tainted(value_element))
            return

        for name in _target_names(target):
            if is_tainted:
                self.tainted_names.add(name)
            else:
                self.tainted_names.discard(name)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

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
        model: str,
        field: str,
        sink: str,
        record_id: str = "",
    ) -> None:
        self.findings.append(
            DefaultValueFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                field=field,
                sink=sink,
                record_id=record_id,
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
) -> RouteContext | None:
    constants = constants or {}
    route_decorator_names = route_decorator_names or {"route"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_decorator_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                auth = _route_auth_from_keyword(keyword, auth, constants)
        return RouteContext(is_route=True, auth=auth)
    return None


def _route_auth_from_keyword(keyword: ast.keyword, auth: str, constants: dict[str, ast.AST]) -> str:
    if keyword.arg == "auth":
        value = _resolve_constant(keyword.value, constants)
        if isinstance(value, ast.Constant):
            return str(value.value)
        return auth
    if keyword.arg is None:
        options = _resolve_constant(keyword.value, constants)
        if isinstance(options, ast.Dict):
            return _route_auth_from_options(options, auth, constants)
    return auth


def _route_auth_from_options(options: ast.Dict, auth: str, constants: dict[str, ast.AST]) -> str:
    for key_node, value_node in zip(options.keys, options.values, strict=False):
        key = _literal_string(key_node, constants) if key_node is not None else ""
        if key != "auth":
            continue
        value = _resolve_constant(value_node, constants)
        if isinstance(value, ast.Constant):
            auth = str(value.value)
    return auth


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
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _is_http_route(node: ast.AST, route_decorator_names: set[str] | None = None) -> bool:
    route_decorator_names = route_decorator_names or {"route"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_decorator_names)
    if isinstance(node, ast.Name):
        return node.id in route_decorator_names
    return isinstance(node, ast.Attribute) and node.attr == "route"


def _is_ir_default_expr(
    node: ast.AST,
    default_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Name) and node.id in default_vars:
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in default_vars:
            return True
        if isinstance(child, ast.Subscript) and _env_model_name(child, constants) == "ir.default":
            return True
    return False


def _is_elevated_expr(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or "SUPERUSER_ID" in _safe_unparse(_resolve_constant(node, constants))
    )


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if not (isinstance(child.func, ast.Attribute) and child.func.attr == "with_user"):
            continue
        if any(_is_admin_user_arg(arg, constants) for arg in child.args):
            return True
        if any(
            keyword.arg in {"user", "uid"}
            and keyword.value is not None
            and _is_admin_user_arg(keyword.value, constants)
            for keyword in child.keywords
        ):
            return True
    return False


def _is_admin_user_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_admin_user_arg(arg) for arg in node.args)
    return False


def _uses_elevated_default_var(node: ast.AST, elevated_default_vars: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in elevated_default_vars for child in ast.walk(node))


def _env_model_name(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str:
    if not _call_name(node.value).endswith("env"):
        return ""
    value = _resolve_constant(node.slice, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or "".join(field.itertext()).strip()
    return values


def _is_sensitive_field(field: str) -> bool:
    lowered = field.lower()
    bare_field = lowered.rsplit("__", 1)[-1].rsplit(".", 1)[-1]
    return (
        bare_field in PRIVILEGE_FIELDS
        or bare_field.startswith("sel_groups_")
        or any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)
    )


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _looks_route_default_arg(name: str) -> bool:
    return bool(ROUTE_DEFAULT_ARG_RE.search(name))


def _is_request_derived(node: ast.AST, request_names: set[str]) -> bool:
    if _is_request_source_expr(node, request_names):
        return True
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


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_attr(node.value, attr)
    if isinstance(node, ast.Tuple | ast.List):
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


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    return set()


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


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[DefaultValueFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in findings
    ]
