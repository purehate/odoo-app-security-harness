"""Scanner for risky Odoo ir.sequence declarations and runtime use."""

from __future__ import annotations

import ast
import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from odoo_security_harness.base_scanner import _record_fields, _should_skip


@dataclass
class SequenceFinding:
    """Represents a risky sequence finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    code: str = ""
    route: str = ""
    sink: str = ""
    record_id: str = ""


TAINTED_ARG_NAMES = {"code", "kwargs", "kw", "post", "sequence_code"}
ROUTE_SEQUENCE_ARG_RE = re.compile(r"(?:^code$|_code$|^sequence$|_sequence$|^sequence_code$)")
REQUEST_MARKERS = (
    "request.params",
    "request.get_http_params",
    "request.get_json_data",
    "request.jsonrequest",
    "request.httprequest",
    "kwargs.get",
    "kw.get",
    "post.get",
)
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
SENSITIVE_SEQUENCE_MARKERS = (
    "access",
    "api",
    "auth",
    "coupon",
    "invite",
    "key",
    "otp",
    "password",
    "reset",
    "secret",
    "signup",
    "token",
)
BUSINESS_SEQUENCE_MARKERS = ("account", "invoice", "journal", "payment", "sale", "stock")


def scan_sequences(repo_path: Path) -> list[SequenceFinding]:
    """Scan Python and XML files for risky sequence behavior."""
    findings: list[SequenceFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".py":
            findings.extend(SequenceScanner(path).scan_python_file())
        elif path.suffix == ".xml":
            findings.extend(SequenceScanner(path).scan_xml_file())
        elif path.suffix == ".csv":
            findings.extend(SequenceScanner(path).scan_csv_file())
    return findings


class SequenceScanner(ast.NodeVisitor):
    """Scanner for one Python/XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[SequenceFinding] = []
        self.sequence_vars: set[str] = set()
        self.tainted_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_python_file(self) -> list[SequenceFinding]:
        """Scan Python code for sequence use."""
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

    def scan_xml_file(self) -> list[SequenceFinding]:
        """Scan XML data records for ir.sequence declarations."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.sequence":
                self._scan_sequence_record(record)
        return self.findings

    def scan_csv_file(self) -> list[SequenceFinding]:
        """Scan CSV ir.sequence declarations."""
        if _csv_model_name(self.path) != "ir.sequence":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_sequence_fields(fields, fields.get("id", ""), line)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_sequence_vars = set(self.sequence_vars)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(is_route=False)
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_sequence_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.sequence_vars = previous_sequence_vars
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
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        is_tainted = self._expr_is_tainted(node.value)
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_sequence_target(target, node.value)
            self._mark_tainted_target(target, node.value, is_tainted)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_sequence_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_sequence_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._mark_tainted_target(node.target, node.iter, self._expr_is_tainted(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        constants = self._effective_constants()
        if method in {"next_by_code", "next_by_id"} and _is_ir_sequence_expr(
            node.func, self.sequence_vars, constants
        ):
            self._scan_sequence_call(node, sink, method, constants)
        self.generic_visit(node)

    def _scan_sequence_call(
        self, node: ast.Call, sink: str, method: str, constants: dict[str, ast.AST]
    ) -> None:
        route = self._current_route()
        code_node = node.args[0] if node.args and method == "next_by_code" else _keyword_value(node, "sequence_code")
        code = _literal_string(code_node, constants)

        if route.auth in {"public", "none"}:
            self._add(
                "odoo-sequence-public-route-next",
                "Public route consumes a sequence",
                "high" if route.auth == "public" else "critical",
                node.lineno,
                f"Public route {route.display_path()} calls {method}(); verify attackers cannot enumerate or exhaust business identifiers, coupons, invites, or tokens",
                code,
                route,
                sink,
            )

        if code_node is not None and self._expr_is_tainted(code_node):
            self._add(
                "odoo-sequence-tainted-code",
                "Request controls sequence code",
                "high",
                node.lineno,
                "Request-derived data controls next_by_code(); constrain allowed sequence codes to prevent unintended counter consumption or information disclosure",
                code,
                route,
                sink,
            )

        if _is_sensitive_sequence(code):
            self._add(
                "odoo-sequence-sensitive-code-use",
                "Sensitive flow uses predictable sequence",
                "high",
                node.lineno,
                f"Sequence code '{code}' looks security-sensitive; do not use ir.sequence for access tokens, reset codes, API keys, or invite secrets",
                code,
                route,
                sink,
            )

    def _scan_sequence_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(self.content, f'id="{record_id}"')
            if record_id
            else _line_for(self.content, 'model="ir.sequence"')
        )
        self._scan_sequence_fields(fields, record_id, line)

    def _scan_sequence_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        code = fields.get("code", "")
        text = " ".join([record_id, fields.get("name", ""), code, fields.get("prefix", ""), fields.get("suffix", "")])

        if _is_sensitive_sequence(text):
            self._add(
                "odoo-sequence-sensitive-declaration",
                "Sequence appears to generate sensitive values",
                "high",
                line,
                f"ir.sequence '{record_id}' appears tied to tokens, passwords, coupons, invites, or secrets; sequences are predictable counters and should not generate security secrets",
                code,
                RouteContext(is_route=False),
                "ir.sequence",
                record_id,
            )

        if _is_sensitive_sequence(text) and not fields.get("company_id", ""):
            self._add(
                "odoo-sequence-sensitive-global-scope",
                "Sensitive sequence has global scope",
                "medium",
                line,
                f"ir.sequence '{record_id}' has no company_id while appearing security-sensitive; verify scope and collision/isolation assumptions",
                code,
                RouteContext(is_route=False),
                "ir.sequence",
                record_id,
            )

        if _is_business_sequence(text) and not fields.get("company_id", ""):
            self._add(
                "odoo-sequence-business-global-scope",
                "Business sequence has no company scope",
                "medium",
                line,
                f"ir.sequence '{record_id}' appears to generate accounting/sales/stock identifiers without company_id; verify multi-company numbering requirements",
                code,
                RouteContext(is_route=False),
                "ir.sequence",
                record_id,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        text = _safe_unparse(node)
        if any(marker in text for marker in REQUEST_MARKERS):
            return True
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
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
        return False

    def _mark_sequence_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_sequence_target(target_element, value_element)
            return

        is_sequence = _is_ir_sequence_expr(value, self.sequence_vars, self._effective_constants())
        for name in _target_names(target):
            if is_sequence:
                self.sequence_vars.add(name)
            else:
                self.sequence_vars.discard(name)

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

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(target_element, value_element)
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
        for name in _target_names(target):
            self.local_constants.pop(name, None)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        )

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

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        code: str,
        route: RouteContext,
        sink: str,
        record_id: str = "",
    ) -> None:
        self.findings.append(
            SequenceFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                code=code,
                route=route.display_path() if route.is_route else "",
                sink=sink,
                record_id=record_id,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    paths: tuple[str, ...] = ()

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        return RouteContext(is_route=True, auth=auth, paths=tuple(paths))
    return None


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append((keyword.arg, keyword.value))
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is None:
            continue
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(item_value, constants)
            if value is not None:
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


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant_seen(node, constants, seen)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants, set(seen))
        right = _resolve_static_dict(node.right, constants, set(seen))
        if left is None or right is None:
            return None
        return ast.Dict(keys=[*left.keys, *right.keys], values=[*left.values, *right.values])
    return None


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
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _is_ir_sequence_expr(
    node: ast.AST,
    sequence_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Name) and node.id in sequence_vars:
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in sequence_vars:
            return True
        if isinstance(child, ast.Subscript) and _env_model_name(child, constants) == "ir.sequence":
            return True
    return False


def _env_model_name(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str:
    if not _call_name(node.value).endswith("env"):
        return ""
    value = _resolve_constant(node.slice, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""



def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {"ir_sequence": "ir.sequence", "ir.sequence": "ir.sequence"}
    return aliases.get(stem, stem.replace("_", "."))


def _csv_dict_rows(content: str) -> list[tuple[dict[str, str], int]]:
    try:
        reader = DictReader(StringIO(content))
    except Exception:
        return []
    if not reader.fieldnames:
        return []

    rows: list[tuple[dict[str, str], int]] = []
    try:
        for index, row in enumerate(reader, start=2):
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is None:
                    continue
                name = str(key).strip().lower()
                text = str(value or "").strip()
                normalized[name] = text
                if "/" in name or ":" in name:
                    normalized.setdefault(re.split(r"[/:]", name, maxsplit=1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _is_sensitive_sequence(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_SEQUENCE_MARKERS)


def _is_business_sequence(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in BUSINESS_SEQUENCE_MARKERS)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_route_sequence_arg(name: str) -> bool:
    return bool(ROUTE_SEQUENCE_ARG_RE.search(name))


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
    if isinstance(node, ast.Starred):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(
            node.value,
            request_names,
            http_module_names,
            odoo_module_names,
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


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        return {name for element in node.elts for name in _target_names(element)}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
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
    return [*before, (target.elts[starred_index], ast.List(elts=list(rest_values), ctx=ast.Load())), *after]


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1



def findings_to_json(findings: list[SequenceFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "code": f.code,
            "route": f.route,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in findings
    ]
